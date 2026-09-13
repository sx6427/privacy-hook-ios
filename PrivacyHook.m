//
// PrivacyHook.m — v57N: 全套伪造硬件人格（内部自洽）
//
// ============ v57N 设计原理（v57L 策略修正） ============
//
// v57L 失败教训：
//   v57L 保留真机真实机型/系统，只伪装唯一标识。
//   但实测发现：同一台手机上"官方原版百度App下单也被限制"，
//   证明这台机器的真实指纹本身已在百度黑名单中。
//   → v57L 等于主动上报被拉黑的身份，必死。
//
// v57N 策略：彻底伪造一套全新且自洽的硬件人格
//   - 机型/系统版本/屏幕/状态栏/UA 全部指向同一个伪造目标
//   - 目标机型参照真机流量样本: ua=1284_2778_iphone (Pro Max 灵动岛)
//   - 关键：所有子系统读到的值必须互相印证，不能有矛盾
//     (v57k 失败正是因为 假机型4.7寸 ↔ 真屏幕6.7寸 矛盾)
//
// ⚠ 前提：本方案假设设备真实指纹已被标记。
//   长期方案仍是换一台干净设备 + 全新账号。
//
// 保留教训（不重蹈覆辙）：
//   不 hook sysctl() 旧 API（闪退）；不 hook setURL:/setHTTPBody:（签名错误）；
//   fishhook 覆盖所有非系统镜像 + dyld 回调；dyld 回调用全局 C 函数；
//   持久化用 CFPreferences 不用 NSUserDefaults；-Xlinker -no_fixup_chains。
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <Security/Security.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <string.h>
#include "fishhook.h"

#define NSLog(...)

static __thread BOOL g_inCookieHook = NO;
static BOOL g_inUDHook = NO;

// ============================================================
// ★ 伪造硬件人格（v57N 核心）
// 目标: iPhone 14 Pro Max (iPhone15,3) — 与真机样本 1284x2778 一致
// 所有值必须自洽：机型 ↔ 屏幕分辨率 ↔ 状态栏高度 ↔ UA
// ============================================================
static const char *FAKE_MACHINE   = "iPhone15,3";        // 14 Pro Max
static const char *FAKE_OSVER     = "17.6.1";            // 系统版本
static const char *FAKE_DARWIN    = "23.6.0";            // 对应 Darwin 内核版本
static const char *FAKE_PRODUCT   = "iPhone15,3";
static const char *FAKE_MODELNUM  = "MQ9G3CH/A";         // 14 Pro Max 国行型号
static const char *FAKE_UA_SUFFIX = "iPhone OS 17_6_1";  // UA 中的系统版本
static const uint64_t FAKE_MEMSIZE = 6ULL * 1024 * 1024 * 1024; // 6GB

// ============================================================
// fishhook 原函数指针
// ============================================================
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
static CFPropertyListRef (*orig_MGCopyAnswer)(CFStringRef key, CFDictionaryRef options) = NULL;
static __thread BOOL g_inMGHook = NO;

typedef unsigned int io_registry_entry_t;
static CFTypeRef (*orig_IORegistryEntryCreateCFProperty)(io_registry_entry_t, CFStringRef, CFAllocatorRef, uint32_t) = NULL;

// ============ CFNetwork C 层 Cookie API ============
// iOS SDK 未公开 CFHTTPCookie 头文件（仅 macOS 公开），手动声明类型，
// 工具函数用 dlsym 运行时解析，hook 函数的 orig 指针由 fishhook 填充
typedef struct OpaqueCFHTTPCookie *CFHTTPCookieRef;
typedef struct OpaqueCFHTTPCookieStorage *CFHTTPCookieStorageRef;

// hook 的原函数（fishhook rebind 后由 fishhook 填充真实地址）
static void (*orig_CFHTTPCookieStorageSetCookie)(CFHTTPCookieStorageRef, CFHTTPCookieRef) = NULL;
static void (*orig_CFHTTPCookieStorageSetCookies)(CFHTTPCookieStorageRef, CFArrayRef, CFURLRef) = NULL;
static CFArrayRef (*orig_CFHTTPCookieStorageCopyCookiesForURL)(CFHTTPCookieStorageRef, CFURLRef, CFURLRef) = NULL;
static CFArrayRef (*orig_CFHTTPCookieStorageCopyAllCookies)(CFHTTPCookieStorageRef) = NULL;

// 工具函数（dlsym 运行时解析，避免链接依赖）
static CFStringRef (*p_CFHTTPCookieCopyName)(CFHTTPCookieRef) = NULL;
static CFStringRef (*p_CFHTTPCookieCopyValue)(CFHTTPCookieRef) = NULL;
static CFDictionaryRef (*p_CFHTTPCookieCopyProperties)(CFHTTPCookieRef) = NULL;
static CFHTTPCookieRef (*p_CFHTTPCookieCreateWithProperties)(CFAllocatorRef, CFDictionaryRef) = NULL;

static void init_cf_cookie_syms(void) {
    if (p_CFHTTPCookieCopyName) return;
    void *h = dlopen("/System/Library/Frameworks/CFNetwork.framework/CFNetwork", RTLD_LAZY);
    if (!h) h = dlopen(NULL, RTLD_LAZY); // 兜底：在已加载镜像中查找
    if (!h) return;
    p_CFHTTPCookieCopyName = dlsym(h, "CFHTTPCookieCopyName");
    p_CFHTTPCookieCopyValue = dlsym(h, "CFHTTPCookieCopyValue");
    p_CFHTTPCookieCopyProperties = dlsym(h, "CFHTTPCookieCopyProperties");
    p_CFHTTPCookieCreateWithProperties = dlsym(h, "CFHTTPCookieCreateWithProperties");
}

// CFPreferences suite 域隔离（防 App Group 共享容器泄露设备指纹）
static CFPropertyListRef (*orig_CFPreferencesCopyAppValue)(CFStringRef, CFStringRef) = NULL;
static CFPropertyListRef (*orig_CFPreferencesCopyValue)(CFStringRef, CFStringRef, CFStringRef, CFStringRef) = NULL;
static Boolean (*orig_CFPreferencesSetValue)(CFStringRef, CFPropertyListRef, CFStringRef, CFStringRef, CFStringRef) = NULL;

// 前向声明
static NSString *getPersistent(NSString *key, NSString *(^gen)(void));
static NSString *genUUIDStr(void);
static NSString *genDeviceName(void);
static NSString *getFakeID(NSString *name);
static BOOL isDeviceCookie(NSString *cookieName);
static NSString *canonicalCookieKey(NSString *name);
static BOOL isSessionCookie(NSString *cookieName);
static void captureRealIdentity(NSString *name, NSString *value);
static NSString *rewriteIdentityString(NSString *s);
static NSData *rewriteIdentityData(NSData *d);

// ============================================================
// 全局 rebindings — dyld 回调中需要访问（不能用 block 捕获）
// ============================================================
// v57T: 回退到 9 条 —— uname/sysctl/gethostname 三条 rebind 与
// v57R/v57S 启动闪退强相关（二分定位：Q.1 可启动，R/S 均闪退，
// 剩余可疑增量只有这 3 条 rebind + dlopen）。先保证能启动，
// 后续逐条加回以精确定位。
// hook 函数本体保留（未注册不影响体积），随时可恢复。
#define REBIND_COUNT 12
static struct rebinding g_rebindings[REBIND_COUNT];

// dyld 回调 — 动态加载的非系统镜像也 hook（必须用 C 函数，不能用 block）
static void hook_new_image(const struct mach_header *header, intptr_t slide) {
    if (!header) return;
    Dl_info info;
    if (dladdr(header, &info) && info.dli_fname) {
        const char *path = info.dli_fname;
        if (strncmp(path, "/usr/lib/", 9) == 0) return;
        if (strncmp(path, "/System/", 8) == 0) return;
        if (strncmp(path, "/Developer/", 11) == 0) return;
        rebind_symbols_image((void *)header, slide, g_rebindings, REBIND_COUNT);
    }
}

// ============================================================
// sysctlbyname hook — v57N 返回伪造人格（自洽的 Pro Max）
// 关键：机型/内存/系统版本全套替换，不混用真值（避免矛盾）
// 纯 C 实现，ZERO ObjC 调用
// ============================================================
// 辅助：把 C 字符串写入 sysctl 输出缓冲（ZERO ObjC 调用）
static int hook_return_cstr(const char *val, void *oldp, size_t *oldlenp) {
    size_t need = strlen(val) + 1;
    if (oldlenp) {
        if (oldp && *oldlenp >= need) {
            memcpy(oldp, val, need);
        }
        *oldlenp = need;
    }
    return 0;
}

static int hook_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name) {
        // 机型标识
        if (strcmp(name, "hw.machine") == 0 || strcmp(name, "hw.model") == 0 ||
            strcmp(name, "hw.product") == 0 || strcmp(name, "hw.target") == 0) {
            return hook_return_cstr(FAKE_MACHINE, oldp, oldlenp);
        }
        // 系统版本
        if (strcmp(name, "kern.osproductversion") == 0) {
            return hook_return_cstr(FAKE_OSVER, oldp, oldlenp);
        }
        if (strcmp(name, "kern.osversion") == 0) {
            return hook_return_cstr("21G93", oldp, oldlenp);   // 17.6.1 build
        }
        if (strcmp(name, "kern.osrelease") == 0) {
            return hook_return_cstr(FAKE_DARWIN, oldp, oldlenp);
        }
        // 内存
        if (strcmp(name, "hw.memsize") == 0) {
            if (oldp && oldlenp && *oldlenp >= sizeof(uint64_t)) {
                *(uint64_t *)oldp = FAKE_MEMSIZE;
                *oldlenp = sizeof(uint64_t);
            } else if (oldlenp) {
                *oldlenp = sizeof(uint64_t);
            }
            return 0;
        }
        // 序列号/UUID 清空（应用本来无权限，返回空不算异常）
        if (strcmp(name, "hw.serialnumber") == 0 || strcmp(name, "hw.uuid") == 0) {
            return hook_return_cstr("", oldp, oldlenp);
        }
        // CPU 型号（A16 对应 t8120, 14 Pro 系列）
        if (strcmp(name, "hw.cputype") == 0) {
            // 保持真实（arm64 都一样）
        }
    }
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

// ============================================================
// ★★ v57R 关键补漏：uname / sysctl / gethostname ★★
//
// 二进制扫描确认：App 引用 uname 32 次、sysctl 9 次、gethostname 2 次。
// 此前只 hook 了 sysctlbyname —— 而 iOS 的 uname().machine 返回的是
// 真实机型（如 iPhone14,3），sysctl(CTL_HW, HW_MACHINE) 同理。
// 于是出现：sysctlbyname 说 iPhone15,3，uname 说 iPhone14,3 ——
// 同一设备两条通道两个答案，是最典型的篡改特征。
// 伪造人格再自洽，漏了这条通道就等于全盘暴露。
//
// 教训（务必遵守）：
//   1. 三个 hook 全部纯 C、零 ObjC 调用（可能在极早期被调用）
//   2. sysctl 只拦截明确的 MIB，其余全部透传（此前盲目 hook 闪退）
//   3. newp != NULL 是写操作，永远透传
// ============================================================
static int (*orig_uname)(struct utsname *) = NULL;
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t) = NULL;
static int (*orig_gethostname)(char *, size_t) = NULL;

static int hook_uname(struct utsname *u) {
    if (!orig_uname) return -1;                 // 防护：未绑定绝不能解引用
    if (!u) return orig_uname(u);
    int r = orig_uname(u);          // 先调真实版保证缓冲区有效，再覆盖
    if (r != 0) return r;
    strlcpy(u->sysname,  "Darwin",      sizeof(u->sysname));
    strlcpy(u->nodename, "iPhone",      sizeof(u->nodename));
    strlcpy(u->release,  FAKE_DARWIN,   sizeof(u->release));
    strlcpy(u->version,
            "Darwin Kernel Version 23.6.0: Mon Jul  8 20:36:33 PDT 2024; "
            "root:xnu-11215.141.2~1/RELEASE_ARM64_T8120",
            sizeof(u->version));
    strlcpy(u->machine,  FAKE_MACHINE,  sizeof(u->machine));
    return 0;
}

// sysctl() 旧 API —— 只拦这几项，其余透传
// MIB 常量（Darwin 稳定值，直接用数字避免头文件差异）：
//   CTL_KERN=1  CTL_HW=6
//   KERN_OSTYPE=1  KERN_OSRELEASE=2  KERN_HOSTNAME=10
//   HW_MACHINE=1   HW_MODEL=2
static int hook_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
                       void *newp, size_t newlen) {
    if (!orig_sysctl) return -1;                // 防护：未绑定绝不能解引用
    if (!name || namelen != 2 || newp != NULL) {
        return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    }
    // 防护：oldp 与 oldlenp 必须成对出现，缺一透传（调用方布局未知，不能猜）
    if (!oldlenp && oldp) {
        return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    }
    const int a = name[0], b = name[1];
    if (a == 6 && (b == 1 || b == 2)) {          // HW_MACHINE / HW_MODEL
        return hook_return_cstr(FAKE_MACHINE, oldp, oldlenp);
    }
    if (a == 1) {                                 // CTL_KERN
        if (b == 1)  return hook_return_cstr("Darwin",      oldp, oldlenp);
        if (b == 2)  return hook_return_cstr(FAKE_DARWIN,   oldp, oldlenp);
        if (b == 10) return hook_return_cstr("iPhone",      oldp, oldlenp);
    }
    return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}

static int hook_gethostname(char *name, size_t namelen) {
    if (!orig_gethostname) return -1;           // 防护：未绑定绝不能解引用
    if (!name || namelen == 0) return orig_gethostname(name, namelen);
    const char *fake = "iPhone";   // 出厂默认主机名，与 uname.nodename 一致
    // v57S: 任何分支都保证 '\0' 结尾 —— 截断后不留 '\0' 会让调用方
    // strlen() 越界读（EXC_BAD_ACCESS，且 @try 拦不住内存故障）
    size_t copy = strlen(fake);
    if (copy > namelen - 1) copy = namelen - 1;
    memcpy(name, fake, copy);
    name[copy] = '\0';
    return 0;
}

// ============================================================
// MGCopyAnswer hook — MobileGestalt 私有 API
// v57L: 只伪装唯一标识（UDID/序列号/ECID/设备名），其余全放行真实值
// （真实机型/系统与屏幕、UA 天然一致，不存在交叉矛盾）
// ============================================================
static CFPropertyListRef hook_MGCopyAnswer(CFStringRef key, CFDictionaryRef options) {
    if (!key || g_inMGHook) return orig_MGCopyAnswer(key, options);
    g_inMGHook = YES;
    @try {
        // UniqueDeviceID (UDID) — 核心唯一标识
        if (CFStringCompare(key, CFSTR("J1WLa1FfC0Dowb1A"), 0) == 0 ||
            CFStringCompare(key, CFSTR("UniqueDeviceID"), 0) == 0) {
            NSString *u = getPersistent(@"BdD1.udid", ^{ return genUUIDStr(); });
            g_inMGHook = NO;
            return (__bridge_retained CFPropertyListRef)u;
        }
        // SerialNumber — 空值（应用层本来无权限，返回空不算异常）
        if (CFStringCompare(key, CFSTR("h9jDsbgj7xIugkIB2RVp1cKoVBOyBj8r"), 0) == 0 ||
            CFStringCompare(key, CFSTR("SerialNumber"), 0) == 0) {
            g_inMGHook = NO;
            return CFRetain(CFSTR(""));
        }
        // UniqueChipID (ECID) — 64位芯片唯一码，v57k 漏掉的硬伤
        if (CFStringCompare(key, CFSTR("UniqueChipID"), 0) == 0) {
            uint64_t ecid = 0;
            NSString *s = getPersistent(@"BdD1.ecid", ^{
                uint64_t hi = ((uint64_t)arc4random() << 32) | (uint64_t)arc4random();
                return [NSString stringWithFormat:@"%llu", (unsigned long long)(hi & 0x00FFFFFFFFFFFFFFULL)];
            });
            ecid = [s longLongValue];
            g_inMGHook = NO;
            return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &ecid);
        }
        // DeviceName — 每克隆独立设备名
        if (CFStringCompare(key, CFSTR("wfiZJ9aJbL5A3hMOznwq7A"), 0) == 0 ||
            CFStringCompare(key, CFSTR("DeviceName"), 0) == 0) {
            NSString *n = getPersistent(@"BdD1.dn", ^{ return genDeviceName(); });
            g_inMGHook = NO;
            return (__bridge_retained CFPropertyListRef)n;
        }
        // ---- v57N 新增：硬件人格 key 也要伪造，与 sysctl 保持一致 ----
        // ProductType / hw.machine（"iPhone15,3"）
        // v57T: 修正复制粘贴错误 —— 之前误把序列号的 magic key 也放进了
        // ProductType 分支（该 key 在上方 SerialNumber 分支已返回，属死代码）
        if (CFStringCompare(key, CFSTR("ProductType"), 0) == 0) {
            g_inMGHook = NO;
            return CFRetain(CFSTR("iPhone15,3"));
        }
        // ModelNumber（"MQ9G3CH/A"）
        if (CFStringCompare(key, CFSTR("ModelNumber"), 0) == 0) {
            g_inMGHook = NO;
            return CFRetain(CFSTR("MQ9G3CH/A"));
        }
        // ProductVersion / 系统版本（"17.6.1"）
        if (CFStringCompare(key, CFSTR("ProductVersion"), 0) == 0 ||
            CFStringCompare(key, CFSTR("kCFSystemVersionProductVersionKey"), 0) == 0) {
            g_inMGHook = NO;
            return CFRetain(CFSTR("17.6.1"));
        }
        // BuildVersion（"21G93"）
        if (CFStringCompare(key, CFSTR("BuildVersion"), 0) == 0 ||
            CFStringCompare(key, CFSTR("ProductBuildVersion"), 0) == 0) {
            g_inMGHook = NO;
            return CFRetain(CFSTR("21G93"));
        }
        // 地区码保持 CN（真机国行）
        g_inMGHook = NO;
    } @catch (id e) {
        g_inMGHook = NO;
    }
    return orig_MGCopyAnswer(key, options);
}

// ============================================================
// IOKit hook — 只伪装 IOPlatformUUID / IOPlatformSerialNumber
// ============================================================
static CFTypeRef hook_IORegistryEntryCreateCFProperty(io_registry_entry_t entry, CFStringRef key, CFAllocatorRef allocator, uint32_t options) {
    if (key) {
        if (CFStringCompare(key, CFSTR("IOPlatformUUID"), 0) == 0) {
            NSString *u = getPersistent(@"BdD1.iouuid", ^{ return genUUIDStr(); });
            return (__bridge_retained CFTypeRef)u;
        }
        if (CFStringCompare(key, CFSTR("IOPlatformSerialNumber"), 0) == 0) {
            return CFRetain(CFSTR(""));
        }
    }
    if (!orig_IORegistryEntryCreateCFProperty) return NULL;
    return orig_IORegistryEntryCreateCFProperty(entry, key, allocator, options);
}

// ============================================================
// C 层 Cookie 清洗 — 百度 SDK 绕过 ObjC 直调 CFNetwork 时兜底
// v57U: capture=YES 时先捕获 SDK 生成的原始值（真实身份）再替换。
// 只在写入路径（SetCookie/SetCookies）传 YES；读路径（Copy*）存的是
// 已替换的伪造值，捕获会污染真实值缓存。
// ============================================================
static CFHTTPCookieRef sanitizeCFCookie(CFHTTPCookieRef ck, BOOL capture) {
    if (!ck) return ck;
    init_cf_cookie_syms();
    if (!p_CFHTTPCookieCopyName || !p_CFHTTPCookieCopyProperties || !p_CFHTTPCookieCreateWithProperties) return ck;
    CFStringRef nm = p_CFHTTPCookieCopyName(ck);
    if (!nm) return ck;
    NSString *name = (__bridge_transfer NSString *)nm; // +1 transferred
    if (!isDeviceCookie(name)) return ck;              // 返回原引用（调用方判断相同则不 release）
    if (capture && p_CFHTTPCookieCopyValue) {
        CFStringRef vv = p_CFHTTPCookieCopyValue(ck);
        if (vv) {
            NSString *val = (__bridge_transfer NSString *)vv; // +1 transferred
            captureRealIdentity(name, val);
        }
    }
    CFDictionaryRef props = p_CFHTTPCookieCopyProperties(ck);
    if (!props) return ck;
    NSMutableDictionary *md = [(__bridge_transfer NSDictionary *)props mutableCopy]; // +1 transferred
    md[@"kCFHTTPCookieValue"] = getFakeID(name);  // kCFHTTPCookieValue 运行时值即该字符串
    CFHTTPCookieRef nc = p_CFHTTPCookieCreateWithProperties(kCFAllocatorDefault, (__bridge CFDictionaryRef)md);
    return nc; // +1，调用方负责 release（若与原引用不同）
}

static void hook_CFHTTPCookieStorageSetCookie(CFHTTPCookieStorageRef storage, CFHTTPCookieRef ck) {
    if (ck) {
        CFHTTPCookieRef nc = sanitizeCFCookie(ck, YES);
        orig_CFHTTPCookieStorageSetCookie(storage, nc ? nc : ck);
        if (nc && nc != ck) CFRelease(nc);
        return;
    }
    orig_CFHTTPCookieStorageSetCookie(storage, ck);
}

static void hook_CFHTTPCookieStorageSetCookies(CFHTTPCookieStorageRef storage, CFArrayRef cookies, CFURLRef mainDoc) {
    if (cookies && CFArrayGetCount(cookies) > 0) {
        CFMutableArrayRef out = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        for (CFIndex i = 0; i < CFArrayGetCount(cookies); i++) {
            CFHTTPCookieRef ck = (CFHTTPCookieRef)CFArrayGetValueAtIndex(cookies, i);
            CFHTTPCookieRef nc = sanitizeCFCookie(ck, YES);
            if (nc) {
                CFArrayAppendValue(out, nc);
                if (nc != ck) CFRelease(nc);
            }
        }
        orig_CFHTTPCookieStorageSetCookies(storage, out, mainDoc);
        CFRelease(out);
        return;
    }
    orig_CFHTTPCookieStorageSetCookies(storage, cookies, mainDoc);
}

static CFArrayRef hook_CFHTTPCookieStorageCopyCookiesForURL(CFHTTPCookieStorageRef storage, CFURLRef url, CFURLRef mainDoc) {
    CFArrayRef arr = orig_CFHTTPCookieStorageCopyCookiesForURL(storage, url, mainDoc);
    if (!arr || CFArrayGetCount(arr) == 0) return arr;
    CFMutableArrayRef out = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    for (CFIndex i = 0; i < CFArrayGetCount(arr); i++) {
        CFHTTPCookieRef ck = (CFHTTPCookieRef)CFArrayGetValueAtIndex(arr, i);
        CFHTTPCookieRef nc = sanitizeCFCookie(ck, NO);
        if (nc) {
            CFArrayAppendValue(out, nc);
            if (nc != ck) CFRelease(nc);
        }
    }
    CFRelease(arr);
    return out;
}

static CFArrayRef hook_CFHTTPCookieStorageCopyAllCookies(CFHTTPCookieStorageRef storage) {
    CFArrayRef arr = orig_CFHTTPCookieStorageCopyAllCookies(storage);
    if (!arr || CFArrayGetCount(arr) == 0) return arr;
    CFMutableArrayRef out = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    for (CFIndex i = 0; i < CFArrayGetCount(arr); i++) {
        CFHTTPCookieRef ck = (CFHTTPCookieRef)CFArrayGetValueAtIndex(arr, i);
        CFHTTPCookieRef nc = sanitizeCFCookie(ck, NO);
        if (nc) {
            CFArrayAppendValue(out, nc);
            if (nc != ck) CFRelease(nc);
        }
    }
    CFRelease(arr);
    return out;
}

// ============================================================
// CFPreferences suite 域隔离 — App Group 共享容器防泄露
// 若克隆间共享 App Group（entitlement 泄露），SDK 可通过 group.* 域
// 读写共享设备指纹 → 全部重定向到本克隆私有域，物理隔离
// ============================================================
static BOOL isGroupDomain(CFStringRef appID) {
    if (!appID) return NO;
    NSString *dom = (__bridge NSString *)appID;
    return [dom hasPrefix:@"group."] || [dom hasPrefix:@"group:"];
}

// v57U: 出口消毒 —— 返回的字符串若含本机真实身份值则替换
// （SDK 把真实 cuid 缓存在 NSUserDefaults/CFPreferences 里，读出来
//   就拼进请求参数。按值替换，不做 key 名猜测。）
// 注意：我们自己的键（BdD1.*，含真实值缓存）必须排除，否则 rewrite
// 拿到的"真实值"会被自己换成伪造值，逻辑失效。
static CFPropertyListRef sanitizeIdentityPList(CFPropertyListRef v) {
    if (!v) return v;
    if (CFGetTypeID(v) != CFStringGetTypeID()) return v;
    NSString *s = (__bridge NSString *)v;
    NSString *r = rewriteIdentityString(s);
    if (r == s) return v;
    return (__bridge_retained CFPropertyListRef)r;   // 调用方持有 +1
}

static BOOL isOwnPrefKey(CFStringRef key) {
    if (!key) return NO;
    return [( __bridge NSString *)key hasPrefix:@"BdD1."];
}

// v57V: 按键名拦截 —— key 含 "cuid" 且值为短字符串 → 强制返回伪造 cuid
// （SAPICUIDKit 等也走 CFPreferences/NSUserDefaults 持久化 cuid）
static CFPropertyListRef sanitizePrefValueForKey(CFStringRef key, CFPropertyListRef v) {
    if (!v || !key) return v;
    if (isOwnPrefKey(key)) return v;
    if (CFGetTypeID(v) != CFStringGetTypeID()) return v;
    NSString *k = (__bridge NSString *)key;
    if ([k rangeOfString:@"cuid" options:NSCaseInsensitiveSearch].location == NSNotFound) return v;
    NSString *s = (__bridge NSString *)v;
    if (s.length < 16 || s.length > 128) return v;      // cuid 合理长度
    NSString *fake = fakeCUIDValue();
    if ([s isEqualToString:fake]) return v;             // 已是伪造值
    captureRealIdentity(@"BAIDUCUID", s);               // 顺带捕获真实值兜底
    return (__bridge_retained CFPropertyListRef)fake;   // 调用方持有 +1
}

static CFPropertyListRef hook_CFPreferencesCopyAppValue(CFStringRef key, CFStringRef appID) {
    CFPropertyListRef v;
    if (key && appID && isGroupDomain(appID)) {
        NSString *privKey = [NSString stringWithFormat:@"%@/%@", (__bridge NSString *)appID, (__bridge NSString *)key];
        v = orig_CFPreferencesCopyAppValue((__bridge CFStringRef)privKey, kCFPreferencesCurrentApplication);
    } else {
        v = orig_CFPreferencesCopyAppValue(key, appID);
    }
    if (isOwnPrefKey(key)) return v;
    v = sanitizePrefValueForKey(key, v);
    return sanitizeIdentityPList(v);
}

static CFPropertyListRef hook_CFPreferencesCopyValue(CFStringRef key, CFStringRef appID, CFStringRef user, CFStringRef host) {
    CFPropertyListRef v;
    if (key && appID && isGroupDomain(appID)) {
        NSString *privKey = [NSString stringWithFormat:@"%@/%@", (__bridge NSString *)appID, (__bridge NSString *)key];
        v = orig_CFPreferencesCopyValue((__bridge CFStringRef)privKey, kCFPreferencesCurrentApplication, user, host);
    } else {
        v = orig_CFPreferencesCopyValue(key, appID, user, host);
    }
    if (isOwnPrefKey(key)) return v;
    v = sanitizePrefValueForKey(key, v);
    return sanitizeIdentityPList(v);
}

// ============================================================
// v57U: keychain 出口消毒 — SecItemCopyMatching
// 同团队签名的 App 共享 keychain 访问组（百度系 App 全家桶），
// 克隆版能直接读到原版 App 存的本机真实设备 ID。
// 不做查询过滤（避免破坏登录凭证），只按「值」消毒：
// 返回的数据/字典里若含真实 CUID/BAIDUID → 替换为伪造值。
// ============================================================
static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef query, CFTypeRef *result) = NULL;
static OSStatus (*orig_SecItemAdd)(CFDictionaryRef attributes, CFTypeRef *result) = NULL;
static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) = NULL;

// ---- v57V: keychain 服务名精准拦截 ----
// 二进制取证发现：
//   - keychain 共享组/服务名 "B83JBVZ6M5.com.baidu.baidumobile.cuid"
//   - SAPICUIDKit（百度原生 cuid 生成器）首启从真实硬件算 cuid 存 keychain
//   - 收银台反欺诈 BDNCashierSDKAntiFraudProcotol（下单环节）
// v57U 的按值替换依赖捕获，但原生 cuid 走 keychain 不经过 cookie 写路径，
// 捕获从未发生 → 替换从未生效。
// v57V 改为按「服务名」拦截：凡 kSecAttrService 含 "cuid" 的 keychain
// 读写，值一律替换为伪造 cuid（与 cookie 伪造值同源，单一身份）。
// 不再依赖捕获；同时顺带捕获真实值（若真出现）供按值替换兜底。

// 伪造 cuid（与 cookie CUID_FAMILY 伪造值同源）
static NSString *fakeCUIDValue(void) {
    return getFakeID(@"BAIDUCUID");
}

// 判断 keychain 查询/属性字典是否为 cuid 存储（服务名/账号名含 cuid）
static BOOL isCuidServiceDict(CFDictionaryRef dict) {
    if (!dict) return NO;
    const void *keys[] = { kSecAttrService, kSecAttrAccount, kSecAttrGeneric };
    for (size_t i = 0; i < 3; i++) {
        CFTypeRef v = CFDictionaryGetValue(dict, keys[i]);
        if (v && CFGetTypeID(v) == CFStringGetTypeID()) {
            NSString *s = (__bridge NSString *)v;
            if ([s rangeOfString:@"cuid" options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
        }
    }
    return NO;
}

// 捕获真实值（仅当不是我们自己的伪造值，防自毒）并返回伪造 data
static NSData *fakeCUIDDataFrom(NSData *realData) {
    @try {
        NSString *s = [[NSString alloc] initWithData:realData encoding:NSUTF8StringEncoding];
        if (s.length >= 16 && ![s isEqualToString:fakeCUIDValue()]) {
            captureRealIdentity(@"BAIDUCUID", s);
        }
    } @catch (id e) {}
    NSString *fake = fakeCUIDValue();
    return [fake dataUsingEncoding:NSUTF8StringEncoding] ?: realData;
}

// 从字典结果里强制替换 cuid 值（kSecValueData / kSecAttrGeneric）
static void forceCuidInResultDict(CFMutableDictionaryRef md) {
    const void *valKeys[] = { kSecValueData, kSecAttrGeneric };
    for (size_t i = 0; i < 2; i++) {
        CFDataRef vd = (CFDataRef)CFDictionaryGetValue(md, valKeys[i]);
        if (vd && CFGetTypeID(vd) == CFDataGetTypeID()) {
            NSData *nd = fakeCUIDDataFrom((__bridge NSData *)vd);
            CFDictionarySetValue(md, valKeys[i], (__bridge CFDataRef)nd);
        }
    }
}

static OSStatus hook_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    OSStatus st = orig_SecItemCopyMatching(query, result);
    if (st != 0 || !result || !*result) return st;   // 0 = errSecSuccess
    @try {
        BOOL targeted = isCuidServiceDict(query);   // v57V: 按服务名精准拦截
        CFTypeRef v = *result;
        CFTypeID tid = CFGetTypeID(v);
        if (tid == CFDataGetTypeID()) {
            NSData *d = (__bridge NSData *)v;
            NSData *nd = targeted ? fakeCUIDDataFrom(d) : rewriteIdentityData(d);
            if (nd != d) {
                CFRelease(v);                                   // 释放 orig 给的 +1
                *result = (__bridge_retained CFTypeRef)nd;      // 交给调用方 +1
            }
        } else if (tid == CFDictionaryGetTypeID()) {
            if (targeted) {
                CFMutableDictionaryRef md = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, (CFDictionaryRef)v);
                forceCuidInResultDict(md);
                CFRelease(v);
                *result = (__bridge_retained CFTypeRef)md;
            } else {
                CFDataRef vd = (CFDataRef)CFDictionaryGetValue(v, kSecValueData);
                if (vd && CFGetTypeID(vd) == CFDataGetTypeID()) {
                    NSData *d = (__bridge NSData *)vd;
                    NSData *nd = rewriteIdentityData(d);
                    if (nd != d) {
                        NSMutableDictionary *md = [(__bridge NSDictionary *)v mutableCopy];
                        md[(__bridge id)kSecValueData] = nd;
                        CFRelease(v);
                        *result = (__bridge_retained CFTypeRef)md;
                    }
                }
            }
        }
    } @catch (id e) {}
    return st;
}

// v57V: 写入侧 —— cuid 服务名的 keychain 写入直接落伪造值，
// 让后续所有读取（含未 hook 的通道）天然拿到伪造值
static OSStatus hook_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    @try {
        if (isCuidServiceDict(attributes)) {
            CFMutableDictionaryRef md = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, attributes);
            forceCuidInResultDict(md);
            OSStatus st = orig_SecItemAdd(md, result);
            CFRelease(md);
            return st;
        }
    } @catch (id e) {}
    return orig_SecItemAdd(attributes, result);
}

static OSStatus hook_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    @try {
        if (isCuidServiceDict(query) || isCuidServiceDict(attributesToUpdate)) {
            if (attributesToUpdate && CFDictionaryGetCount(attributesToUpdate) > 0) {
                CFMutableDictionaryRef md = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, attributesToUpdate);
                forceCuidInResultDict(md);
                OSStatus st = orig_SecItemUpdate(query, md);
                CFRelease(md);
                return st;
            }
        }
    } @catch (id e) {}
    return orig_SecItemUpdate(query, attributesToUpdate);
}

static Boolean hook_CFPreferencesSetValue(CFStringRef key, CFPropertyListRef value, CFStringRef appID, CFStringRef user, CFStringRef host) {
    if (key && appID && isGroupDomain(appID)) {
        NSString *privKey = [NSString stringWithFormat:@"%@/%@", (__bridge NSString *)appID, (__bridge NSString *)key];
        return orig_CFPreferencesSetValue((__bridge CFStringRef)privKey, value,
                                          kCFPreferencesCurrentApplication,
                                          kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
    }
    return orig_CFPreferencesSetValue(key, value, appID, user, host);
}

// ============================================================
// Persistent fake IDs (BdD1. prefix — 构建脚本替换为 Bd63/BdC1 等)
// ============================================================
static NSString *getPersistent(NSString *key, NSString *(^gen)(void)) {
    CFStringRef cfKey = (__bridge CFStringRef)key;
    CFPropertyListRef val = CFPreferencesCopyAppValue(cfKey, kCFPreferencesCurrentApplication);
    if (val) {
        NSString *s = [(__bridge id)val isKindOfClass:[NSString class]] ? (__bridge NSString *)val : nil;
        CFRelease(val);
        if (s) return s;
    }
    NSString *newVal = gen();
    CFPreferencesSetAppValue(cfKey, (__bridge CFStringRef)newVal, kCFPreferencesCurrentApplication);
    CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
    return newVal;
}

// v57U: 持久写入（捕获本机真实身份值用）
static void setPersistent(NSString *key, NSString *val) {
    if (!key || !val || val.length == 0) return;
    CFPreferencesSetAppValue((__bridge CFStringRef)key, (__bridge CFStringRef)val,
                             kCFPreferencesCurrentApplication);
    CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
}

// ============================================================
// ★★ v57U: 单一身份原则（Identity Coherence）★★
//
// 问题：cookie 里的 CUID 我们伪造了，但百度原生 SDK 还会把
// 「SDK 自己算出来的 cuid」塞进 URL 参数 / POST body
// （二进制取证：cuid=%@ / &cuid=%@ 拼接大量存在），
// 以及从 keychain 共享组读原版 App 存的本机真实设备 ID
// （同团队 App 共享 keychain —— 这正是"更换设备之后就正常了"的原因）。
// 于是服务端看到：cookie=假，参数=真 → 矛盾 → 按真设备下单名额判限。
//
// 解法：捕获真实值，在**所有出口**统一替换为伪造值：
//   1) 捕获：SDK 写设备 cookie 时，原始值经过我们手上先存下来
//      （BdD1.real.CUID_FAMILY / BdD1.real.BAIDUID_FAMILY，持久化）
//   2) keychain 出口：SecItemCopyMatching 返回数据含真实值 → 替换
//   3) CFPreferences 出口：返回字符串含真实值 → 替换
//   4) 请求出口：NSMutableURLRequest 的 URL/body、WKWebView loadRequest
//      中的真实值 → 替换
// 只按「值」替换（真实值是稳定长字符串，碰撞概率为零），不做 key 名猜测。
// ============================================================

// 捕获真实身份值（仅 CUID/BAIDUID 两个家族；只在写入路径调用）
static void captureRealIdentity(NSString *name, NSString *value) {
    if (!name || !value || value.length < 16) return;
    @try {
        NSString *ck = canonicalCookieKey(name);
        BOOL isCUID = [ck isEqualToString:@"CUID_FAMILY"];
        BOOL isBID  = [ck isEqualToString:@"BAIDUID_FAMILY"];
        if (!isCUID && !isBID) return;
        NSString *k = [NSString stringWithFormat:@"BdD1.real.%@", ck];
        NSString *old = getPersistent(k, ^{ return @""; });
        if (old.length == 0) {
            setPersistent(k, value);   // 首次捕获，落盘
        }
        // 之后即使 SDK 换了值也不更新 —— 保持单一稳定真实值，避免
        // 读路径误捕获伪造值（读路径不捕获，这里只兜底首次）
    } @catch (id e) {}
}

// 把字符串里出现的「本机真实身份值」替换为「伪造值」（所有出口共用）
static NSString *rewriteIdentityString(NSString *s) {
    if (!s || s.length < 20) return s;
    @try {
        NSString *rc = getPersistent(@"BdD1.real.CUID_FAMILY", ^{ return @""; });
        if (rc.length >= 16 && [s rangeOfString:rc].location != NSNotFound) {
            s = [s stringByReplacingOccurrencesOfString:rc withString:getFakeID(@"BAIDUCUID")];
        }
        NSString *rb = getPersistent(@"BdD1.real.BAIDUID_FAMILY", ^{ return @""; });
        if (rb.length >= 16 && [s rangeOfString:rb].location != NSNotFound) {
            s = [s stringByReplacingOccurrencesOfString:rb withString:getFakeID(@"BAIDUID")];
        }
    } @catch (id e) {}
    return s;
}

static NSData *rewriteIdentityData(NSData *d) {
    if (!d || d.length < 16) return d;
    @try {
        NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        if (!s) return d;
        NSString *r = rewriteIdentityString(s);
        if (r == s) return d;
        NSData *nd = [r dataUsingEncoding:NSUTF8StringEncoding];
        return nd ?: d;
    } @catch (id e) { return d; }
}

static NSString *genUUIDStr(void) { return [[NSUUID UUID] UUIDString]; }

static NSString *genDeviceName(void) {
    NSArray *surnames = @[@"张", @"王", @"李", @"赵", @"刘", @"陈", @"杨", @"黄", @"周", @"吴",
                          @"徐", @"孙", @"马", @"朱", @"胡", @"林", @"郭", @"何", @"高", @"罗",
                          @"郑", @"梁", @"谢", @"宋", @"唐", @"许", @"韩", @"冯", @"邓", @"曹"];
    NSArray *givenNames = @[@"伟", @"芳", @"娜", @"洋", @"杰", @"磊", @"敏", @"强", @"婷", @"明",
                            @"超", @"丽", @"军", @"静", @"峰", @"威", @"鹏", @"勇", @"华", @"宇",
                            @"辉", @"平", @"刚", @"桂英", @"秀兰", @"建国", @"志强", @"俊杰",
                            @"雨涵", @"子轩", @"浩然", @"嘉怡"];
    NSString *surname = surnames[arc4random_uniform((uint32_t)surnames.count)];
    NSString *given = givenNames[arc4random_uniform((uint32_t)givenNames.count)];
    NSArray *formats = @[
        [NSString stringWithFormat:@"%@%@的 iPhone", surname, given],
        [NSString stringWithFormat:@"%@%@的iPhone", surname, given],
        @"iPhone"
    ];
    return formats[arc4random_uniform((uint32_t)formats.count)];
}

static NSString *genRandStr(NSUInteger len, NSString *cs) {
    NSMutableString *s = [NSMutableString stringWithCapacity:len];
    for (NSUInteger i = 0; i < len; i++)
        [s appendFormat:@"%C", [cs characterAtIndex:arc4random_uniform((uint32_t)cs.length)]];
    return s;
}

// ============================================================
// ============================================================
// UA 伪装 — v57N 必须替换（否则 UA 泄露真系统版本，与假机型矛盾）
// 真机样本 UA: Mozilla/5.0 (iPhone; CPU iPhone OS 16_1 like Mac OS X)
//              AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148
//              SP-engine/3.61.0 light/1.0(WKWebView) them...
// v57N 目标: iPhone OS 17_6_1（与伪造系统版本一致）
// ============================================================
// ★★ v57Q 关键修正：UA 必须保留 baiduboxapp/<版本> 段 ★★
//
// 血泪教训：此前 UA 被改成
//   Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15
//   (KHTML, like Gecko) Mobile/15E148 SP-engine/3.61.0 light/1.0(WKWebView) themecolor/1.0
// 里面**没有 baiduboxapp/ 段** —— 这个 UA 看起来是「WKWebView 网页」而非
// 「百度 App 内请求」。百度活动类接口（含农场 se-act.baidu.com）依赖 UA 中的
// baiduboxapp/ 识别 App 环境；缺失时服务端判定非 App 环境，返回
// 「活动太火爆，请稍后再试」这类兜底提示。
//
// 真机（农场自动化工具实测）UA 形态：
//   ... Mobile/15E148 SP-engine/3.58.0 main/1.0 baiduboxapp/15.63.0.10
// 本 App 版本为 15.69.0.10，故 UA 中 baiduboxapp 版本必须与之一致。
//
// ★ 关于 WKWebView 的三种 UA 设置方式与优先级（务必记牢）：
//
//   customUserAgent  >  NSUserDefaults["UserAgent"]  >  applicationNameForUserAgent
//
//   优先级高的生效时，低的**被完全忽略**（不是拼接）。
//   其中只有 applicationNameForUserAgent 是「追加到默认 UA 后面」，
//   另两种是「整体替换」。
//
//   因此本 hook 的设计：
//     - 三条路全部覆盖，且**全部设成同一个完整 UA**（含 baiduboxapp 段）
//     - 这样无论 App 走哪条路、无论哪个生效，最终 UA 都正确
//     - 因为生效的只有一条，不存在「两段 baiduboxapp 重复」的问题
//
//   注意 applicationNameForUserAgent 是「追加」语义：若只靠它，
//   它追加到的默认 UA 里没有 baiduboxapp，结果仍缺该段 —— 所以
//   必须再配合 customUserAgent（优先级更高，整体替换）双保险。
#define FAKE_APP_UA_FULL  @"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) " \
                          "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 " \
                          "SP-engine/3.61.0 main/1.0 baiduboxapp/15.69.0.10"

// 完整 UA（含 baiduboxapp 段）
static NSString *buildFakeUserAgent(void) {
    return FAKE_APP_UA_FULL;
}

// 判定是否为「百度系 UA」——凡是百度 App/WebView 发出的 UA 都要整体替换为
// 自洽的 App UA，避免只替换一部分造成同会话内 UA 不一致。
static BOOL isUALike(NSString *s) {
    if (!s || s.length < 20) return NO;
    return [s rangeOfString:@"iPhone OS"].location != NSNotFound ||
           [s rangeOfString:@"AppleWebKit"].location != NSNotFound ||
           [s rangeOfString:@"baiduboxapp"].location != NSNotFound ||
           [s rangeOfString:@"baidu"].location != NSNotFound;
}

// Cookie/设备标识生成（保持与真实格式一致）
//
// ★ v57M 关键修复：CUID 必须是真 base64url(随机50字节) + "mA"
//   真机样本: giHau0iA-uj6iHilluvqi_uuSigpu2i0giSLi_ucSf_4i2uhji2Pf085HOpukHMuh18mA
//   = base64url(50字节) 67字符 + "mA" 2字符 = 69字符
//   v57L 用逐字符随机 → 虽字面像 base64 但解码非法 → 百度校验即识破
// ============================================================
static NSString *b64urlEncode(NSData *data) {
    NSString *s = [data base64EncodedStringWithOptions:0];
    s = [s stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
    s = [s stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    // 去掉 padding（真机样本无 '='）
    while ([s hasSuffix:@"="]) s = [s substringToIndex:s.length - 1];
    return s;
}

static NSString *genCUID(void) {
    // 真机结构: base64url(50字节随机) + "mA"
    NSMutableData *raw = [NSMutableData dataWithLength:50];
    arc4random_buf([raw mutableBytes], 50);
    return [NSString stringWithFormat:@"%@mA", b64urlEncode(raw)];
}

static NSString *genBAIDUID(void) {
    // 真机: 32位大写HEX + ":FG=1"  (例: 5A258432900A32B53931CFE922A7AF51:FG=1)
    NSString *hexCS = @"0123456789ABCDEF";
    return [genRandStr(32, hexCS) stringByAppendingString:@":FG=1"];
}

static NSString *genTcuid(void) {
    // tcuid: 48位大写HEX（保持十六进制）
    NSString *hexCS = @"0123456789ABCDEF";
    return genRandStr(48, hexCS);
}

static NSString *genFakeCookie(NSString *name) {
    NSString *cuidCS = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    NSString *hexCS = @"0123456789abcdef";
    NSString *upperHexCS = @"0123456789ABCDEF";

    // ★ v57P：先按「身份族」归一化，保证同族 cookie 拿到同一个值
    NSString *fam = canonicalCookieKey(name);

    // —— CUID 族：BAIDUCUID / BAIDUCUID_BFESS / MAWEBCUID / cuid 全部同值 ——
    if ([fam isEqualToString:@"CUID_FAMILY"])
        return genCUID();

    // —— BAIDUID 族 ——
    if ([fam isEqualToString:@"BAIDUID_FAMILY"])
        return genBAIDUID();

    // —— fuid 族 ——
    if ([fam isEqualToString:@"FUID_FAMILY"])
        return genRandStr(32, hexCS);

    // —— ab_jid 族 ——
    if ([fam isEqualToString:@"AB_JID_FAMILY"])
        return genRandStr(40, hexCS);

    // —— ab_bid 族 ——
    if ([fam isEqualToString:@"AB_BID_FAMILY"])
        return genRandStr(40, hexCS);

    // —— 以下为各自独立的标识，不共享 ——
    if ([name isEqualToString:@"DVIF"]) {
        NSString *num = [NSString stringWithFormat:@"%lu", (unsigned long)((uint64_t)arc4random() * arc4random() % 9000000000000000ULL + 1000000000000000ULL)];
        NSMutableData *d = [NSMutableData dataWithLength:300];
        arc4random_buf([d mutableBytes], 300);
        return [NSString stringWithFormat:@"%@_%@_%@", num, [d base64EncodedStringWithOptions:0], genRandStr(6, hexCS)];
    }
    if ([name isEqualToString:@"tcuid"]) return genTcuid();
    if ([name isEqualToString:@"__bid_n"]) return genRandStr(22, hexCS);

    // ---- v57M 新增：真机样本中实际存在的设备/环境标识 ----
    // BDB2BVID: 32位hex 设备ID
    if ([name isEqualToString:@"BDB2BVID"]) return genRandStr(32, hexCS);
    // BA_HECTOR: 真机 848120240la12g8h810g04242ha1a41l73rr429 (35字符，数字+字母混合)
    if ([name isEqualToString:@"BA_HECTOR"]) return genRandStr(35, @"abcdefghijklmnopqrstuvwxyz0123456789");
    // BAIDU_WISE_UID: wapp_<13位时间戳>_<3位随机>
    if ([name isEqualToString:@"BAIDU_WISE_UID"]) {
        NSTimeInterval ts = [[NSDate date] timeIntervalSince1970] * 1000;
        return [NSString stringWithFormat:@"wapp_%.0f_%u", ts, arc4random_uniform(1000)];
    }
    // ZFY: 真机 carCl1WCG0JXAY:Bb7F4:AobXjhVWSBtT7AemD91AW0z0:C (段用冒号分隔)
    if ([name isEqualToString:@"ZFY"]) {
        NSString *cs2 = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        return [NSString stringWithFormat:@"%@:%@:%@:C",
                genRandStr(14, cs2), genRandStr(5, cs2), genRandStr(28, cs2)];
    }
    // RT: "z=1&dm=baidu.com&si=<uuid>&ss=<8位>&sl=1&tt=um&bcn=..."
    if ([name isEqualToString:@"RT"]) {
        NSString *uuid = [[NSUUID UUID] UUIDString];
        return [NSString stringWithFormat:@"\"z=1&dm=baidu.com&si=%@&ss=%@&sl=1&tt=um\"",
                [uuid lowercaseString], genRandStr(8, @"abcdefghijklmnopqrstuvwxyz0123456789")];
    }
    // H_WISE_SIDS: 数字下划线串（版本特征，非唯一标识，用固定值即可）
    //
    // ★★ v57Q 修正：AFD_IP / BAIDULOCNEW 必须「原样放行」，不碰 ★★
    //
    // 依据 38 个真机账号 cookie 实测统计：
    //   AFD_IP      出现 34/38，全部为真实公网 IP
    //   BAIDULOCNEW 出现 34/38，格式统一 __100000_317_<13位毫秒时间戳>_1
    //   其中 112.81.241.* 一个网段就有 28 个账号共用，且全部能正常进农场
    //
    // 由此确认两件事：
    //   1) 百度不校验 AFD_IP 与真实出口 IP 是否一致
    //   2) 百度不在乎多账号共用同一 IP（同 IP 是常态）
    //
    // 因此此前"清空 AFD_IP 防聚类"是无根据的，清除后反而让字段变为空值，
    // 而正常 App 从不写入空值 —— "存在但为空"本身就是篡改特征。
    // 生成假 IP 同样错误（会与真实出口 IP 矛盾，凭空制造不一致）。
    //
    // 正确处理：这两个字段不进入 isDeviceCookie 名单，本函数不会被调用，
    // 由 App 自行写入真实值。此处保留分支仅为显式文档化该决策。
    if ([name isEqualToString:@"AFD_IP"] || [name isEqualToString:@"BAIDULOCNEW"]) {
        // 不应到达此处（不在 isDeviceCookie 名单内）。若到达则原值无法获取，
        // 返回空串并依赖上层跳过改写。
        return @"";
    }
    return genRandStr(32, cuidCS);
}

static NSString *getFakeID(NSString *name) {
    return getPersistent([NSString stringWithFormat:@"BdD1.ck.%@", canonicalCookieKey(name)],
                         ^{ return genFakeCookie(name); });
}

// ============================================================
// ★ v57P 修复：Cookie 身份族归一化
//
// 问题：genFakeCookie 按 cookie 原始名生成并缓存，导致同一个「设备身份」
//       在不同 cookie 名下分裂成多个互不相干的值：
//         BAIDUCUID        -> BdD1.ck.BAIDUCUID        (值 A)
//         BAIDUCUID_BFESS  -> BdD1.ck.BAIDUCUID_BFESS  (值 B)  ✗ 应等于 A
//         MAWEBCUID        -> BdD1.ck.MAWEBCUID        (值 C)  ✗ 应等于 A
//         cuid             -> BdD1.ck.cuid             (值 D)  ✗ 应等于 A
//         CUID             -> BdD1.ck.CUID             (值 E)  ✗ 应等于 A
//       百度农场激活的硬性前置就是 BAIDUCUID，App 后续请求携带的 MAWEBCUID/
//       cuid 却是另一个值 → 服务端判定「设备身份不一致」→ 拒绝激活。
//       原版 App 能进农场，正因为它所有 CUID 名都是同一个真值。
//
// 方案：把语义等价的 cookie 名映射到同一个规范键，保证同族同值。
// ============================================================
static NSString *canonicalCookieKey(NSString *name) {
    if (!name) return @"";
    NSString *u = [name uppercaseString];

    // —— CUID 族：全部共用同一个 CUID（农场激活依赖此一致性）——
    // BAIDUCUID / BAIDUCUID_BFESS / MAWEBCUID / cuid / CUID / cuid_galaxy2
    if ([u hasPrefix:@"BAIDUCUID"]) return @"CUID_FAMILY";
    if ([u isEqualToString:@"MAWEBCUID"]) return @"CUID_FAMILY";
    if ([u hasPrefix:@"CUID"]) return @"CUID_FAMILY";

    // —— BAIDUID 族（浏览器/账号侧 ID，非设备指纹）——
    if ([u hasPrefix:@"BAIDUID"]) return @"BAIDUID_FAMILY";

    // —— fuid 族 ——
    if ([u isEqualToString:@"FUID"]) return @"FUID_FAMILY";

    // —— ab_jid 族 ——
    if ([u hasPrefix:@"AB_JID"]) return @"AB_JID_FAMILY";

    // —— ab_bid 族 ——
    if ([u hasPrefix:@"AB_BID"]) return @"AB_BID_FAMILY";

    return name;
}

// 会话凭证类：绝不伪造（伪造会直接破坏登录态与 CSRF 校验）
static BOOL isSessionCookie(NSString *cookieName) {
    if (!cookieName) return NO;
    NSString *u = [cookieName uppercaseString];
    // BDUSS / BDUSS_BFESS 是登录会话 + CSRF 镜像，篡改会导致会话失效
    if ([u hasPrefix:@"BDUSS"]) return YES;
    if ([u hasPrefix:@"STOKEN"]) return YES;
    if ([u hasPrefix:@"PTOKEN"]) return YES;
    return NO;
}

// ============================================================
// Cookie device ID detection
// ============================================================
static BOOL isDeviceCookie(NSString *cookieName) {
    if (!cookieName) return NO;
    // ★ v57P：会话凭证绝不伪造（BDUSS/BDUSS_BFESS/STOKEN/PTOKEN）
    //   篡改 BDUSS_BFESS 会破坏 CSRF 镜像 → 会话失效 → 农场/支付认证失败
    if (isSessionCookie(cookieName)) return NO;
    NSString *lk = [cookieName lowercaseString];
    NSArray *names = @[@"baiducuid", @"baiducuid_bfess", @"mawebcuid",
                       @"dvif", @"tcuid", @"__bid_n", @"fuid", @"cuid",
                       @"baiduid", @"baiduid_bfess",
                       // v57M 新增（真机样本确认存在）
                       @"bdb2bvid", @"ab_bid", @"ab_jid", @"ab_jid_bfess",
                       @"ba_hector", @"zfy", @"rt"];
    for (NSString *n in names) { if ([lk isEqualToString:n]) return YES; }
    return NO;
}

static NSArray *modifiedCookies(NSArray *cookies) {
    if (!cookies || cookies.count == 0) return cookies;
    NSMutableArray *result = [NSMutableArray array];
    for (NSHTTPCookie *cookie in cookies) {
        if (isDeviceCookie(cookie.name)) {
            NSString *fakeValue = getFakeID(cookie.name);
            NSMutableDictionary *props = [NSMutableDictionary dictionary];
            props[NSHTTPCookieName] = cookie.name;
            props[NSHTTPCookieValue] = fakeValue;
            if (cookie.domain) props[NSHTTPCookieDomain] = cookie.domain;
            if (cookie.path) props[NSHTTPCookiePath] = cookie.path;
            if (cookie.expiresDate) props[NSHTTPCookieExpires] = cookie.expiresDate;
            props[NSHTTPCookieVersion] = @(cookie.version);
            if (cookie.secure) props[NSHTTPCookieSecure] = @YES;
            NSHTTPCookie *newCookie = [[NSHTTPCookie alloc] initWithProperties:props];
            if (newCookie) [result addObject:newCookie];
            else [result addObject:cookie];
        } else {
            [result addObject:cookie];
        }
    }
    return result;
}

// ============================================================
// NSUserDefaults device key detection
// ============================================================
static BOOL isDeviceKey(NSString *key) {
    if (!key || g_inUDHook) return NO;
    if ([key hasPrefix:@"BdD1"]) return NO;
    NSArray *exactKeys = @[@"cuid", @"CUID", @"cuid_galaxy2", @"cuid_gid", @"cuid_loc",
                           @"BAIDUCUID", @"BAIDUCUID_BFESS", @"MAWEBCUID",
                           @"DVIF", @"tcuid", @"__bid_n", @"fuid",
                           @"bdudid", @"baiduid", @"baiduid_bfess", @"bdid"];
    for (NSString *k in exactKeys) { if ([key isEqualToString:k]) return YES; }
    if ([key.lowercaseString hasPrefix:@"cuid"]) return YES;
    return NO;
}

// ============================================================
// v57S: NSProcessInfo 伪造 —— 纯 C 函数 IMP（不用 imp_implementationWithBlock）
//
// ★ v57R 闪退教训：
//   operatingSystemVersion 返回 NSOperatingSystemVersion（3 个 long，
//   共 24 字节）—— 超过 16 字节走 sret 返回约定。imp_implementationWithBlock
//   对「结构体返回」的 block 没有 ABI 保证（block invoke 与 IMP 的
//   sret 布局不保证一致），该方法又在 App 启动早期被 Foundation/UIKit
//   高频调用 → 启动即崩，@try/@catch 拦不住内存故障。
//   纯 C 函数做 IMP，返回结构体的 sret 由编译器按 ABI 正确生成 —— 零风险。
// ============================================================
static NSOperatingSystemVersion my_osVersion(id self, SEL _cmd) {
    NSOperatingSystemVersion v;
    v.majorVersion = 17; v.minorVersion = 6; v.patchVersion = 1;
    return v;                                   // 与 UA 17_6_1 / uname 23.6.0 一致
}
static NSString *my_osVersionString(id self, SEL _cmd) {
    return @"Version 17.6.1 (Build 21G93)";     // 编译期常量字符串，immortal 无需 retain
}
static unsigned long long my_physicalMemory(id self, SEL _cmd) {
    return FAKE_MEMSIZE;                        // 6GB，与 sysctl hw.memsize 一致
}

// ============================================================
// Constructor — v57N
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {

        // ---- 1. v57 简单清理：Cookie storage + Keychain（仅首次） ----
        @try {
            CFPropertyListRef cleared = CFPreferencesCopyAppValue(CFSTR("BdD1.reset"), kCFPreferencesCurrentApplication);
            if (!cleared) {
                NSHTTPCookieStorage *storage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
                for (NSHTTPCookie *cookie in [storage cookies]) {
                    [storage deleteCookie:cookie];
                }
                NSArray *classes = @[(__bridge id)kSecClassGenericPassword, (__bridge id)kSecClassInternetPassword,
                                     (__bridge id)kSecClassCertificate, (__bridge id)kSecClassKey, (__bridge id)kSecClassIdentity];
                for (id cls in classes) {
                    SecItemDelete((__bridge CFDictionaryRef)@{(__bridge id)kSecClass: cls});
                }
                CFPreferencesSetAppValue(CFSTR("BdD1.reset"), kCFBooleanTrue, kCFPreferencesCurrentApplication);
                CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
            } else { CFRelease(cleared); }
        } @catch (id e) {
            CFPreferencesSetAppValue(CFSTR("BdD1.reset"), kCFBooleanTrue, kCFPreferencesCurrentApplication);
            CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
        }

        // ---- 2. UIDevice hooks — v57N 全套人格对齐（Pro Max 自洽） ----
        @try {
            Class dc = objc_getClass("UIDevice");
            if (dc) {
                Method nameM = class_getInstanceMethod(dc, @selector(name));
                if (nameM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return getPersistent(@"BdD1.dn", ^{ return genDeviceName(); });
                    });
                    class_replaceMethod(dc, @selector(name), imp, method_getTypeEncoding(nameM));
                }
                Method idfvM = class_getInstanceMethod(dc, @selector(identifierForVendor));
                if (idfvM) {
                    IMP imp = imp_implementationWithBlock(^NSUUID *(id s) {
                        return [[NSUUID alloc] initWithUUIDString:getPersistent(@"BdD1.iv", ^{ return genUUIDStr(); })];
                    });
                    class_replaceMethod(dc, @selector(identifierForVendor), imp, method_getTypeEncoding(idfvM));
                }
                // 型号字串 — 必须与 sysctl hw.machine 一致
                for (NSString *sel in @[@"model", @"localizedModel"]) {
                    SEL sl = NSSelectorFromString(sel);
                    Method m = class_getInstanceMethod(dc, sl);
                    if (m) {
                        IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                            return @"iPhone";
                        });
                        class_replaceMethod(dc, sl, imp, method_getTypeEncoding(m));
                    }
                }
                // 系统版本 — 必须与 sysctl kern.osproductversion 一致
                Method svM = class_getInstanceMethod(dc, @selector(systemVersion));
                if (svM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return [NSString stringWithUTF8String:FAKE_OSVER];
                    });
                    class_replaceMethod(dc, @selector(systemVersion), imp, method_getTypeEncoding(svM));
                }
            }
        } @catch (id e) {}

        // ---- 2b. UIScreen hooks — 屏幕分辨率对齐 Pro Max (1284x2778@3x) ----
        // ★ 这是 v57k 失败的根因：假机型 ↔ 真屏幕尺寸矛盾
        //   改为整套对齐，百度 ua=1284_2778_iphone 参数才能自洽
        @try {
            Class sc = objc_getClass("UIScreen");
            if (sc) {
                Method bM = class_getInstanceMethod(sc, @selector(bounds));
                if (bM) {
                    IMP imp = imp_implementationWithBlock(^CGRect(id s) {
                        return CGRectMake(0, 0, 430, 932);   // 14 Pro Max 逻辑尺寸
                    });
                    class_replaceMethod(sc, @selector(bounds), imp, method_getTypeEncoding(bM));
                }
                Method nsM = class_getInstanceMethod(sc, @selector(nativeBounds));
                if (nsM) {
                    IMP imp = imp_implementationWithBlock(^CGRect(id s) {
                        return CGRectMake(0, 0, 1284, 2778); // 14 Pro Max 物理分辨率
                    });
                    class_replaceMethod(sc, @selector(nativeBounds), imp, method_getTypeEncoding(nsM));
                }
                Method nsS = class_getInstanceMethod(sc, @selector(nativeScale));
                if (nsS) {
                    IMP imp = imp_implementationWithBlock(^CGFloat(id s) { return 3.0; });
                    class_replaceMethod(sc, @selector(nativeScale), imp, method_getTypeEncoding(nsS));
                }
                Method sM = class_getInstanceMethod(sc, @selector(scale));
                if (sM) {
                    IMP imp = imp_implementationWithBlock(^CGFloat(id s) { return 3.0; });
                    class_replaceMethod(sc, @selector(scale), imp, method_getTypeEncoding(sM));
                }
            }
        } @catch (id e) {}

        // ---- 2c. NSProcessInfo hooks — 系统版本/内存自洽 ----
        // v57S: 一律用纯 C 函数 IMP（见上方 my_osVersion 注释），
        // 严禁对返回结构体的方法用 imp_implementationWithBlock
        @try {
            Class piC = objc_getClass("NSProcessInfo");
            if (piC) {
                Method ovM = class_getInstanceMethod(piC, @selector(operatingSystemVersion));
                if (ovM) {
                    class_replaceMethod(piC, @selector(operatingSystemVersion),
                                        (IMP)my_osVersion, method_getTypeEncoding(ovM));
                }
                Method ovsM = class_getInstanceMethod(piC, @selector(operatingSystemVersionString));
                if (ovsM) {
                    class_replaceMethod(piC, @selector(operatingSystemVersionString),
                                        (IMP)my_osVersionString, method_getTypeEncoding(ovsM));
                }
                Method pmM = class_getInstanceMethod(piC, @selector(physicalMemory));
                if (pmM) {
                    class_replaceMethod(piC, @selector(physicalMemory),
                                        (IMP)my_physicalMemory, method_getTypeEncoding(pmM));
                }
            }
        } @catch (id e) {}

        // ---- 3. IDFA hook — 每克隆独立 ----
        @try {
            Class ac = objc_getClass("ASIdentifierManager");
            if (ac) {
                Method m = class_getInstanceMethod(ac, @selector(advertisingIdentifier));
                if (m) {
                    IMP imp = imp_implementationWithBlock(^NSUUID *(id s) {
                        return [[NSUUID alloc] initWithUUIDString:getPersistent(@"BdD1.ai", ^{ return genUUIDStr(); })];
                    });
                    class_replaceMethod(ac, @selector(advertisingIdentifier), imp, method_getTypeEncoding(m));
                }
            }
        } @catch (id e) {}

        // ---- 4. NSUserDefaults hooks — 拦截设备 ID 读取 ----
        @try {
            Class uc = objc_getClass("NSUserDefaults");
            if (uc) {
                Method ofkM = class_getInstanceMethod(uc, @selector(objectForKey:));
                if (ofkM) {
                    IMP orig = method_getImplementation(ofkM);
                    IMP imp = imp_implementationWithBlock(^id(id s, NSString *key) {
                        if (!g_inUDHook && isDeviceKey(key)) {
                            g_inUDHook = YES;
                            @try { NSString *f = getFakeID(@"cuid"); g_inUDHook = NO; return f; }
                            @catch (id e) { g_inUDHook = NO; }
                        }
                        return ((id (*)(id, SEL, NSString *))orig)(s, @selector(objectForKey:), key);
                    });
                    class_replaceMethod(uc, @selector(objectForKey:), imp, method_getTypeEncoding(ofkM));
                }
                Method sfkM = class_getInstanceMethod(uc, @selector(stringForKey:));
                if (sfkM) {
                    IMP orig = method_getImplementation(sfkM);
                    IMP imp = imp_implementationWithBlock(^NSString *(id s, NSString *key) {
                        if (!g_inUDHook && isDeviceKey(key)) {
                            g_inUDHook = YES;
                            @try { NSString *f = getFakeID(@"cuid"); g_inUDHook = NO; return f; }
                            @catch (id e) { g_inUDHook = NO; }
                        }
                        return ((NSString *(*)(id, SEL, NSString *))orig)(s, @selector(stringForKey:), key);
                    });
                    class_replaceMethod(uc, @selector(stringForKey:), imp, method_getTypeEncoding(sfkM));
                }
            }
        } @catch (id e) {}

        // ---- 5. Cookie hooks (ObjC 层) ----
        @try {
            Class cs = objc_getClass("NSHTTPCookieStorage");

            Method cfuM = class_getInstanceMethod(cs, @selector(cookiesForURL:));
            if (cfuM) {
                IMP origCFU = method_getImplementation(cfuM);
                IMP newCFU = imp_implementationWithBlock(^NSArray *(id s, NSURL *url) {
                    NSArray *cookies = ((NSArray *(*)(id, SEL, NSURL *))origCFU)(s, @selector(cookiesForURL:), url);
                    if (g_inCookieHook) return cookies;
                    g_inCookieHook = YES;
                    @try { NSArray *m = modifiedCookies(cookies); g_inCookieHook = NO; return m; }
                    @catch (id e) { g_inCookieHook = NO; return cookies; }
                });
                class_replaceMethod(cs, @selector(cookiesForURL:), newCFU, method_getTypeEncoding(cfuM));
            }

            Method allM = class_getInstanceMethod(cs, @selector(cookies));
            if (allM) {
                IMP origAll = method_getImplementation(allM);
                IMP newAll = imp_implementationWithBlock(^NSArray *(id s) {
                    NSArray *cookies = ((NSArray *(*)(id, SEL))origAll)(s, @selector(cookies));
                    if (g_inCookieHook) return cookies;
                    g_inCookieHook = YES;
                    @try { NSArray *m = modifiedCookies(cookies); g_inCookieHook = NO; return m; }
                    @catch (id e) { g_inCookieHook = NO; return cookies; }
                });
                class_replaceMethod(cs, @selector(cookies), newAll, method_getTypeEncoding(allM));
            }

            Method scM = class_getInstanceMethod(cs, @selector(setCookie:));
            if (scM) {
                IMP origSC = method_getImplementation(scM);
                IMP newSC = imp_implementationWithBlock(^void(id s, NSHTTPCookie *cookie) {
                    if (cookie && isDeviceCookie(cookie.name)) {
                        @try {
                            captureRealIdentity(cookie.name, cookie.value);   // v57U: 捕获真实值
                            NSString *fakeValue = getFakeID(cookie.name);
                            NSMutableDictionary *props = [NSMutableDictionary dictionary];
                            props[NSHTTPCookieName] = cookie.name;
                            props[NSHTTPCookieValue] = fakeValue;
                            if (cookie.domain) props[NSHTTPCookieDomain] = cookie.domain;
                            if (cookie.path) props[NSHTTPCookiePath] = cookie.path;
                            if (cookie.expiresDate) props[NSHTTPCookieExpires] = cookie.expiresDate;
                            props[NSHTTPCookieVersion] = @(cookie.version);
                            if (cookie.secure) props[NSHTTPCookieSecure] = @YES;
                            NSHTTPCookie *fakeCookie = [[NSHTTPCookie alloc] initWithProperties:props];
                            if (fakeCookie) {
                                ((void (*)(id, SEL, NSHTTPCookie *))origSC)(s, @selector(setCookie:), fakeCookie);
                                return;
                            }
                        } @catch (id e) {}
                    }
                    ((void (*)(id, SEL, NSHTTPCookie *))origSC)(s, @selector(setCookie:), cookie);
                });
                class_replaceMethod(cs, @selector(setCookie:), newSC, method_getTypeEncoding(scM));
            }

            Method scsM = class_getInstanceMethod(cs, @selector(setCookies:forURL:mainDocumentURL:));
            if (scsM) {
                IMP origSCS = method_getImplementation(scsM);
                IMP newSCS = imp_implementationWithBlock(^void(id s, NSArray *cookies, NSURL *URL, NSURL *mainDocumentURL) {
                    if (g_inCookieHook) {
                        ((void (*)(id, SEL, NSArray *, NSURL *, NSURL *))origSCS)(s, @selector(setCookies:forURL:mainDocumentURL:), cookies, URL, mainDocumentURL);
                        return;
                    }
                    g_inCookieHook = YES;
                    @try {
                        NSArray *m = modifiedCookies(cookies);
                        g_inCookieHook = NO;
                        ((void (*)(id, SEL, NSArray *, NSURL *, NSURL *))origSCS)(s, @selector(setCookies:forURL:mainDocumentURL:), m, URL, mainDocumentURL);
                        return;
                    } @catch (id e) { g_inCookieHook = NO; }
                    ((void (*)(id, SEL, NSArray *, NSURL *, NSURL *))origSCS)(s, @selector(setCookies:forURL:mainDocumentURL:), cookies, URL, mainDocumentURL);
                });
                class_replaceMethod(cs, @selector(setCookies:forURL:mainDocumentURL:), newSCS, method_getTypeEncoding(scsM));
            }
        } @catch (id e) {}

        // ---- 6. NSMutableURLRequest hooks — Cookie + UA 替换 ----
        // v57N: UA 必须替换（否则泄露真系统版本，与伪造机型矛盾）
        @try {
            Class reqClass = objc_getClass("NSMutableURLRequest");
            if (reqClass) {
                Method svM = class_getInstanceMethod(reqClass, @selector(setValue:forHTTPHeaderField:));
                if (svM) {
                    IMP origSV = method_getImplementation(svM);
                    IMP newSV = imp_implementationWithBlock(^void(id s, NSString *value, NSString *field) {
                        // UA 替换
                        if (value && field && [field caseInsensitiveCompare:@"User-Agent"] == NSOrderedSame
                            && isUALike(value)) {
                            ((void (*)(id, SEL, NSString *, NSString *))origSV)(s, @selector(setValue:forHTTPHeaderField:), buildFakeUserAgent(), field);
                            return;
                        }
                        if (value && field && [field caseInsensitiveCompare:@"Cookie"] == NSOrderedSame) {
                            NSArray *names = @[@"BAIDUCUID", @"BAIDUCUID_BFESS", @"MAWEBCUID",
                                               @"DVIF", @"tcuid", @"__bid_n", @"fuid",
                                               @"BAIDUID", @"BAIDUID_BFESS"];
                            NSString *modified = value;
                            for (NSString *name in names) {
                                NSString *fake = getFakeID(name);
                                NSRegularExpression *regex = [NSRegularExpression
                                    regularExpressionWithPattern:[NSString stringWithFormat:@"%@=[^;]+", name]
                                    options:NSRegularExpressionCaseInsensitive error:nil];
                                modified = [regex stringByReplacingMatchesInString:modified options:0
                                    range:NSMakeRange(0, modified.length)
                                    withTemplate:[NSString stringWithFormat:@"%@=%@", name, fake]];
                            }
                            NSRegularExpression *cuidRegex = [NSRegularExpression
                                regularExpressionWithPattern:@"(?<![A-Za-z_])cuid=[^;]+" options:0 error:nil];
                            modified = [cuidRegex stringByReplacingMatchesInString:modified options:0
                                range:NSMakeRange(0, modified.length)
                                withTemplate:[NSString stringWithFormat:@"cuid=%@", getFakeID(@"cuid")]];
                            ((void (*)(id, SEL, NSString *, NSString *))origSV)(s, @selector(setValue:forHTTPHeaderField:), modified, field);
                            return;
                        }
                        ((void (*)(id, SEL, NSString *, NSString *))origSV)(s, @selector(setValue:forHTTPHeaderField:), value, field);
                    });
                    class_replaceMethod(reqClass, @selector(setValue:forHTTPHeaderField:), newSV, method_getTypeEncoding(svM));
                }

                Method addValM = class_getInstanceMethod(reqClass, @selector(addValue:forHTTPHeaderField:));
                if (addValM) {
                    IMP origAddVal = method_getImplementation(addValM);
                    IMP newAddVal = imp_implementationWithBlock(^void(id s, NSString *value, NSString *field) {
                        if (value && field && [field caseInsensitiveCompare:@"User-Agent"] == NSOrderedSame
                            && isUALike(value)) {
                            ((void (*)(id, SEL, NSString *, NSString *))origAddVal)(s, @selector(addValue:forHTTPHeaderField:), buildFakeUserAgent(), field);
                            return;
                        }
                        if (value && field && [field caseInsensitiveCompare:@"Cookie"] == NSOrderedSame) {
                            NSArray *names = @[@"BAIDUCUID", @"BAIDUCUID_BFESS", @"MAWEBCUID",
                                               @"DVIF", @"tcuid", @"__bid_n", @"fuid",
                                               @"BAIDUID", @"BAIDUID_BFESS"];
                            NSString *modified = value;
                            for (NSString *name in names) {
                                NSString *fake = getFakeID(name);
                                NSRegularExpression *regex = [NSRegularExpression
                                    regularExpressionWithPattern:[NSString stringWithFormat:@"%@=[^;]+", name]
                                    options:NSRegularExpressionCaseInsensitive error:nil];
                                modified = [regex stringByReplacingMatchesInString:modified options:0
                                    range:NSMakeRange(0, modified.length)
                                    withTemplate:[NSString stringWithFormat:@"%@=%@", name, fake]];
                            }
                            NSRegularExpression *cuidRegex = [NSRegularExpression
                                regularExpressionWithPattern:@"(?<![A-Za-z_])cuid=[^;]+" options:0 error:nil];
                            modified = [cuidRegex stringByReplacingMatchesInString:modified options:0
                                range:NSMakeRange(0, modified.length)
                                withTemplate:[NSString stringWithFormat:@"cuid=%@", getFakeID(@"cuid")]];
                            ((void (*)(id, SEL, NSString *, NSString *))origAddVal)(s, @selector(addValue:forHTTPHeaderField:), modified, field);
                            return;
                        }
                        ((void (*)(id, SEL, NSString *, NSString *))origAddVal)(s, @selector(addValue:forHTTPHeaderField:), value, field);
                    });
                    class_replaceMethod(reqClass, @selector(addValue:forHTTPHeaderField:), newAddVal, method_getTypeEncoding(addValM));
                }

                // v57U: 请求出口消毒 —— URL 参数 / POST body 里的真实 cuid
                // 原生 SDK 拼请求时 cuid=%@ 直接进 query/body（不走 cookie），
                // 按值替换为本克隆伪造值，与 cookie 保持单一身份
                Method suM = class_getInstanceMethod(reqClass, @selector(setURL:));
                if (suM) {
                    IMP origSetURL = method_getImplementation(suM);
                    IMP newSetURL = imp_implementationWithBlock(^void(id s, NSURL *u) {
                        NSURL *nu = u;
                        @try {
                            if (u.absoluteString.length > 20) {
                                NSString *r = rewriteIdentityString(u.absoluteString);
                                if (r != u.absoluteString) nu = [NSURL URLWithString:r] ?: u;
                            }
                        } @catch (id e) {}
                        ((void (*)(id, SEL, NSURL *))origSetURL)(s, @selector(setURL:), nu);
                    });
                    class_replaceMethod(reqClass, @selector(setURL:), newSetURL, method_getTypeEncoding(suM));
                }
                Method sbM = class_getInstanceMethod(reqClass, @selector(setHTTPBody:));
                if (sbM) {
                    IMP origSetBody = method_getImplementation(sbM);
                    IMP newSetBody = imp_implementationWithBlock(^void(id s, NSData *body) {
                        NSData *nb = body;
                        @try { if (body) nb = rewriteIdentityData(body); } @catch (id e) {}
                        ((void (*)(id, SEL, NSData *))origSetBody)(s, @selector(setHTTPBody:), nb);
                    });
                    class_replaceMethod(reqClass, @selector(setHTTPBody:), newSetBody, method_getTypeEncoding(sbM));
                }
                Method iwM = class_getInstanceMethod(reqClass, @selector(initWithURL:));
                if (iwM) {
                    IMP origInitURL = method_getImplementation(iwM);
                    IMP newInitURL = imp_implementationWithBlock(^id(id s, NSURL *u) {
                        NSURL *nu = u;
                        @try {
                            if (u.absoluteString.length > 20) {
                                NSString *r = rewriteIdentityString(u.absoluteString);
                                if (r != u.absoluteString) nu = [NSURL URLWithString:r] ?: u;
                            }
                        } @catch (id e) {}
                        return ((id (*)(id, SEL, NSURL *))origInitURL)(s, @selector(initWithURL:), nu);
                    });
                    class_replaceMethod(reqClass, @selector(initWithURL:), newInitURL, method_getTypeEncoding(iwM));
                }
            }
        } @catch (id e) {}

        // ---- 6b. WKWebView hooks — UA 注入（v57Q 新增，农场关键） ----
        //
        // ★★ 这是「活动太火爆，请稍后再试」的真正根因 ★★
        //
        // 百度农场（se-act.baidu.com）是**跑在 WKWebView 里的 H5 页面**，
        // 不是原生 API 调用。WKWebView 发出的网络请求**完全绕过**
        // NSMutableURLRequest.setValue:forHTTPHeaderField: —— 也就是说
        // 上面第 6 节写的 UA hook 对农场页面**一次都不会触发**。
        //
        // 结果：农场页面带着 WKWebView 默认 UA 访问服务端，该 UA 里没有
        // baiduboxapp/ 段 → 服务端判定"非百度 App 环境" → 返回兜底文案
        // 「活动太火爆，请稍后再试」。
        //
        // 这正是此前 UA 里出现 light/1.0(WKWebView) 的来源：我们看到的
        // 就是 WKWebView 的原生 UA，我们的替换根本没生效。
        //
        // 正确做法：三条路**全部**设成同一个完整 UA（含 baiduboxapp 段）。
        //
        //   优先级：customUserAgent > NSUserDefaults > applicationNameForUserAgent
        //   生效的只有一条，其余被忽略 —— 所以三条都填同一个完整 UA 是安全的，
        //   不会产生重复段，同时保证「无论 App 走哪条路」结果都正确。
        //
        //   为什么必须带 customUserAgent：applicationNameForUserAgent 是
        //   「追加到默认 UA」语义，而默认 UA 里没有 baiduboxapp；只设它不够。
        //   customUserAgent 是「整体替换」语义，优先级最高，才是主力手段。
        //
        //   v57T: 移除 dlopen(WebKit) —— 已确认 App 主二进制自带
        //   LC_LOAD_DYLIB WebKit，dyld 在构造函数运行前必然已加载它，
        //   objc_getClass 不会返回 nil；dlopen 反而是 v57R/v57S 闪退的
        //   剩余可疑增量之一（二分期间先去掉）。
        @try {
            Class wkCfg = objc_getClass("WKWebViewConfiguration");
            if (wkCfg) {
                Method setAppNameM = class_getInstanceMethod(wkCfg, @selector(setApplicationNameForUserAgent:));
                if (setAppNameM) {
                    IMP origSAN = method_getImplementation(setAppNameM);
                    IMP newSAN = imp_implementationWithBlock(^void(id s, NSString *name) {
                        ((void (*)(id, SEL, NSString *))origSAN)(s, @selector(setApplicationNameForUserAgent:), FAKE_APP_UA_FULL);
                    });
                    class_replaceMethod(wkCfg, @selector(setApplicationNameForUserAgent:), newSAN, method_getTypeEncoding(setAppNameM));
                }
            }
        } @catch (id e) {}

        @try {
            Class wkView = objc_getClass("WKWebView");
            if (wkView) {
                // c1) 读取侧：getter 永远返回完整 App UA
                Method getUAM = class_getInstanceMethod(wkView, @selector(customUserAgent));
                if (getUAM) {
                    IMP newGUA = imp_implementationWithBlock(^NSString *(id s) {
                        return buildFakeUserAgent();
                    });
                    class_replaceMethod(wkView, @selector(customUserAgent), newGUA, method_getTypeEncoding(getUAM));
                }
                // c2) 写入侧：吞掉任何试图覆盖的 UA，强制为完整 App UA
                Method setUAM = class_getInstanceMethod(wkView, @selector(setCustomUserAgent:));
                if (setUAM) {
                    IMP origSUA = method_getImplementation(setUAM);
                    IMP newSUA = imp_implementationWithBlock(^void(id s, NSString *ua) {
                        ((void (*)(id, SEL, NSString *))origSUA)(s, @selector(setCustomUserAgent:), buildFakeUserAgent());
                    });
                    class_replaceMethod(wkView, @selector(setCustomUserAgent:), newSUA, method_getTypeEncoding(setUAM));
                }
                // c3) 构造侧：任何新建 WKWebView 都强制带上完整 App UA
                Method initM = class_getInstanceMethod(wkView, @selector(initWithFrame:configuration:));
                if (initM) {
                    IMP origInit = method_getImplementation(initM);
                    IMP newInit = imp_implementationWithBlock(^id(id s, CGRect frame, id config) {
                        @try {
                            if (config && [config respondsToSelector:@selector(setApplicationNameForUserAgent:)]) {
                                [config setApplicationNameForUserAgent:FAKE_APP_UA_FULL];
                            }
                        } @catch (id e) {}
                        id inst = ((id (*)(id, SEL, CGRect, id))origInit)(s, @selector(initWithFrame:configuration:), frame, config);
                        @try {
                            if (inst && [inst respondsToSelector:@selector(setCustomUserAgent:)]) {
                                [inst setCustomUserAgent:buildFakeUserAgent()];
                            }
                        } @catch (id e) {}
                        return inst;
                    });
                    class_replaceMethod(wkView, @selector(initWithFrame:configuration:), newInit, method_getTypeEncoding(initM));
                }

                // v57U: loadRequest: 出口消毒 —— App 打开 H5 活动页（含农场）
                // 时会把 SDK 计算的 cuid 等身份参数拼进 URL query，
                // 同样按值替换为本克隆伪造值
                Method lrM = class_getInstanceMethod(wkView, @selector(loadRequest:));
                if (lrM) {
                    IMP origLR = method_getImplementation(lrM);
                    IMP newLR = imp_implementationWithBlock(^void(id s, NSURLRequest *req) {
                        NSURLRequest *nr = req;
                        @try {
                            if (req.URL.absoluteString.length > 20) {
                                NSString *r = rewriteIdentityString(req.URL.absoluteString);
                                if (r != req.URL.absoluteString) {
                                    NSURL *nu = [NSURL URLWithString:r];
                                    if (nu) {
                                        nr = [NSURLRequest requestWithURL:nu];
                                    }
                                }
                            }
                        } @catch (id e) {}
                        ((void (*)(id, SEL, NSURLRequest *))origLR)(s, @selector(loadRequest:), nr);
                    });
                    class_replaceMethod(wkView, @selector(loadRequest:), newLR, method_getTypeEncoding(lrM));
                }

                // 补充：NSUserDefaults["UserAgent"] 是另一种较低优先级的设置方式，
                // 优先级低于 customUserAgent。由于我们已将 customUserAgent 全路径
                // 强制为完整 App UA，该方法即使被调用也不会生效，无需额外 hook。
            }
        } @catch (id e) {}

        // ---- 7. fishhook — hook 所有非系统镜像 + dyld 回调 ----
        // v57L rebind 清单：sysctlbyname + MGCopyAnswer + IOKit
        //                  + 4个 C 层 Cookie API + 3个 CFPreferences API
        @try {
            g_rebindings[0] = (struct rebinding){"sysctlbyname",                          (void *)hook_sysctlbyname,                          (void **)&orig_sysctlbyname};
            g_rebindings[1] = (struct rebinding){"MGCopyAnswer",                          (void *)hook_MGCopyAnswer,                          (void **)&orig_MGCopyAnswer};
            g_rebindings[2] = (struct rebinding){"IORegistryEntryCreateCFProperty",       (void *)hook_IORegistryEntryCreateCFProperty,       (void **)&orig_IORegistryEntryCreateCFProperty};
            g_rebindings[3] = (struct rebinding){"CFHTTPCookieStorageSetCookie",          (void *)hook_CFHTTPCookieStorageSetCookie,          (void **)&orig_CFHTTPCookieStorageSetCookie};
            g_rebindings[4] = (struct rebinding){"CFHTTPCookieStorageSetCookies",         (void *)hook_CFHTTPCookieStorageSetCookies,         (void **)&orig_CFHTTPCookieStorageSetCookies};
            g_rebindings[5] = (struct rebinding){"CFHTTPCookieStorageCopyCookiesForURL",  (void *)hook_CFHTTPCookieStorageCopyCookiesForURL,  (void **)&orig_CFHTTPCookieStorageCopyCookiesForURL};
            g_rebindings[6] = (struct rebinding){"CFHTTPCookieStorageCopyAllCookies",     (void *)hook_CFHTTPCookieStorageCopyAllCookies,     (void **)&orig_CFHTTPCookieStorageCopyAllCookies};
            g_rebindings[7] = (struct rebinding){"CFPreferencesCopyAppValue",             (void *)hook_CFPreferencesCopyAppValue,             (void **)&orig_CFPreferencesCopyAppValue};
            g_rebindings[8] = (struct rebinding){"CFPreferencesCopyValue",                (void *)hook_CFPreferencesCopyValue,                (void **)&orig_CFPreferencesCopyValue};
            // v57U: keychain 出口消毒（只按值替换返回内容，查询不过滤）
            g_rebindings[9]  = (struct rebinding){"SecItemCopyMatching",                  (void *)hook_SecItemCopyMatching,                   (void **)&orig_SecItemCopyMatching};
            // v57V: 写入侧也拦截，让 keychain 天然存伪造 cuid
            g_rebindings[10] = (struct rebinding){"SecItemAdd",                           (void *)hook_SecItemAdd,                            (void **)&orig_SecItemAdd};
            g_rebindings[11] = (struct rebinding){"SecItemUpdate",                        (void *)hook_SecItemUpdate,                         (void **)&orig_SecItemUpdate};
            // v57T: uname/sysctl/gethostname 三条 rebind 暂时移除（闪退二分定位）
            // g_rebindings[9]  = (struct rebinding){"uname",                              (void *)hook_uname,                                 (void **)&orig_uname};
            // g_rebindings[10] = (struct rebinding){"sysctl",                             (void *)hook_sysctl,                                (void **)&orig_sysctl};
            // g_rebindings[11] = (struct rebinding){"gethostname",                        (void *)hook_gethostname,                           (void **)&orig_gethostname};

            // 7a. hook 所有已加载的非系统镜像
            uint32_t count = _dyld_image_count();
            for (uint32_t i = 0; i < count; i++) {
                const struct mach_header *header = _dyld_get_image_header(i);
                intptr_t slide = _dyld_get_image_vmaddr_slide(i);
                const char *path = _dyld_get_image_name(i);
                if (!header || !path) continue;
                if (strncmp(path, "/usr/lib/", 9) == 0) continue;
                if (strncmp(path, "/System/", 8) == 0) continue;
                if (strncmp(path, "/Developer/", 11) == 0) continue;
                rebind_symbols_image((void *)header, slide, g_rebindings, REBIND_COUNT);
            }

            // 7b. 注册 dyld 回调（动态加载的框架也覆盖，用全局 C 函数）
            _dyld_register_func_for_add_image(hook_new_image);
        } @catch (id e) {}
    }
}
