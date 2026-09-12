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
static CFDictionaryRef (*p_CFHTTPCookieCopyProperties)(CFHTTPCookieRef) = NULL;
static CFHTTPCookieRef (*p_CFHTTPCookieCreateWithProperties)(CFAllocatorRef, CFDictionaryRef) = NULL;

static void init_cf_cookie_syms(void) {
    if (p_CFHTTPCookieCopyName) return;
    void *h = dlopen("/System/Library/Frameworks/CFNetwork.framework/CFNetwork", RTLD_LAZY);
    if (!h) h = dlopen(NULL, RTLD_LAZY); // 兜底：在已加载镜像中查找
    if (!h) return;
    p_CFHTTPCookieCopyName = dlsym(h, "CFHTTPCookieCopyName");
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

// ============================================================
// 全局 rebindings — dyld 回调中需要访问（不能用 block 捕获）
// ============================================================
#define REBIND_COUNT 9
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
        if (CFStringCompare(key, CFSTR("h9jDsbgj7xIugkIB2RVp1cKoVBOyBj8r"), 0) == 0 ||
            CFStringCompare(key, CFSTR("ProductType"), 0) == 0) {
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
// ============================================================
static CFHTTPCookieRef sanitizeCFCookie(CFHTTPCookieRef ck) {
    if (!ck) return ck;
    init_cf_cookie_syms();
    if (!p_CFHTTPCookieCopyName || !p_CFHTTPCookieCopyProperties || !p_CFHTTPCookieCreateWithProperties) return ck;
    CFStringRef nm = p_CFHTTPCookieCopyName(ck);
    if (!nm) return ck;
    NSString *name = (__bridge_transfer NSString *)nm; // +1 transferred
    if (!isDeviceCookie(name)) return ck;              // 返回原引用（调用方判断相同则不 release）
    CFDictionaryRef props = p_CFHTTPCookieCopyProperties(ck);
    if (!props) return ck;
    NSMutableDictionary *md = [(__bridge_transfer NSDictionary *)props mutableCopy]; // +1 transferred
    md[@"kCFHTTPCookieValue"] = getFakeID(name);  // kCFHTTPCookieValue 运行时值即该字符串
    CFHTTPCookieRef nc = p_CFHTTPCookieCreateWithProperties(kCFAllocatorDefault, (__bridge CFDictionaryRef)md);
    return nc; // +1，调用方负责 release（若与原引用不同）
}

static void hook_CFHTTPCookieStorageSetCookie(CFHTTPCookieStorageRef storage, CFHTTPCookieRef ck) {
    if (ck) {
        CFHTTPCookieRef nc = sanitizeCFCookie(ck);
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
            CFHTTPCookieRef nc = sanitizeCFCookie(ck);
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
        CFHTTPCookieRef nc = sanitizeCFCookie(ck);
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
        CFHTTPCookieRef nc = sanitizeCFCookie(ck);
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

static CFPropertyListRef hook_CFPreferencesCopyAppValue(CFStringRef key, CFStringRef appID) {
    if (key && appID && isGroupDomain(appID)) {
        NSString *privKey = [NSString stringWithFormat:@"%@/%@", (__bridge NSString *)appID, (__bridge NSString *)key];
        return orig_CFPreferencesCopyAppValue((__bridge CFStringRef)privKey, kCFPreferencesCurrentApplication);
    }
    return orig_CFPreferencesCopyAppValue(key, appID);
}

static CFPropertyListRef hook_CFPreferencesCopyValue(CFStringRef key, CFStringRef appID, CFStringRef user, CFStringRef host) {
    if (key && appID && isGroupDomain(appID)) {
        NSString *privKey = [NSString stringWithFormat:@"%@/%@", (__bridge NSString *)appID, (__bridge NSString *)key];
        return orig_CFPreferencesCopyValue((__bridge CFStringRef)privKey, kCFPreferencesCurrentApplication, user, host);
    }
    return orig_CFPreferencesCopyValue(key, appID, user, host);
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
static NSString *buildFakeUserAgent(void) {
    return @"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 "
            "SP-engine/3.61.0 light/1.0(WKWebView) themecolor/1.0";
}

// 判断是否 UA（含 iPhone OS 特征）
static BOOL isUALike(NSString *s) {
    if (!s || s.length < 20) return NO;
    return [s rangeOfString:@"iPhone OS"].location != NSNotFound ||
           [s rangeOfString:@"AppleWebKit"].location != NSNotFound;
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

    if ([name hasPrefix:@"BAIDUCUID"] || [name isEqualToString:@"MAWEBCUID"] || [name isEqualToString:@"cuid"])
        return genCUID();
    if ([name isEqualToString:@"BAIDUID"])
        return genBAIDUID();
    if ([name isEqualToString:@"BAIDUID_BFESS"])
        return getFakeID(@"BAIDUID");
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
    // ab_bid: 广告设备ID，40位hex（真机 0a40fcce...4d40 = 40字符）
    if ([name isEqualToString:@"ab_bid"]) return genRandStr(40, hexCS);
    // ab_jid / ab_jid_BFESS: 40位hex（真机 bc8e8270...0a40）
    if ([name hasPrefix:@"ab_jid"]) return getFakeID(@"ab_jid");
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
    // AFD_IP: 真机样本中携带真实公网IP（112.81.188.205）
    //   ★ 多实例同WiFi = 同出口IP → 百度聚类关联 → "下单人数过多"头号嫌疑
    //   此处清除（交由网络层/代理隔离，见 v57M 部署说明）
    if ([name isEqualToString:@"AFD_IP"]) return @"";
    // BAIDULOCNEW: __<loc>_<citycode>_<ts>_1 定位+时间戳，清空避免位置聚类
    if ([name isEqualToString:@"BAIDULOCNEW"]) return @"";
    return genRandStr(32, cuidCS);
}

static NSString *getFakeID(NSString *name) {
    return getPersistent([NSString stringWithFormat:@"BdD1.ck.%@", name], ^{ return genFakeCookie(name); });
}

// ============================================================
// Cookie device ID detection
// ============================================================
static BOOL isDeviceCookie(NSString *cookieName) {
    if (!cookieName) return NO;
    NSString *lk = [cookieName lowercaseString];
    NSArray *names = @[@"baiducuid", @"baiducuid_bfess", @"mawebcuid",
                       @"dvif", @"tcuid", @"__bid_n", @"fuid", @"cuid",
                       @"baiduid", @"baiduid_bfess",
                       // v57M 新增（真机样本确认存在）
                       @"bdb2bvid", @"ab_bid", @"ab_jid", @"ab_jid_bfess",
                       @"ba_hector", @"zfy", @"rt",
                       @"bdusid", @"bduss_bfess"];
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
