//
// PrivacyHook.m — v57L: 真实硬件人格 + 只伪装唯一标识符
//
// ============ v57L 设计原理（检测根因修复） ============
//
// v57k 被检测的根因不是"伪装得不够多"，而是"伪装人格自相矛盾"：
//   1. 机型↔屏幕矛盾：随机伪装 iPhone13,2(4.7寸)，但 UIScreen 分辨率是真机 → 交叉比对识破
//   2. WKWebView 默认 UA 非空 → WebView 请求带真实 iOS 版本，native 请求报假版本
//   3. MGCopyAnswer 只挡 7 个 obfuscated key，EffectiveProductType/UniqueChipID 等漏真值
//   4. C 层 CFHTTPCookieStorage 直接调用可绕过 ObjC NSHTTPCookieStorage swizzle
//
// v57L 策略反转：
//   - 硬件人格 = 真机真实值（机型/系统版本/屏幕/内存/运营商全部真实，永不矛盾）
//   - 只伪装"每台设备唯一"的标识符：
//       UDID / 序列号 / ECID / IOPlatformUUID / 设备名 / IDFA / IDFV / CUID / Cookie设备ID
//   - 30 个克隆 = 30 台同型号同系统、ID 各异的 iPhone → 无任何可交叉验证的矛盾点
//
// 注意：v57L 对"老账号"会造成指纹跳变（旧版本曾上报随机机型），建议用全新实例/新账号测试。
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
#import <CFNetwork/CFNetwork.h>
#import <objc/runtime.h>
#include <sys/sysctl.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include "fishhook.h"

#define NSLog(...)

static __thread BOOL g_inCookieHook = NO;
static BOOL g_inUDHook = NO;

// ============================================================
// 真机真实硬件值（constructor 最开始、hook 安装前缓存）
// v57L: 这些值全部保持真实，绝不伪装 —— 保证人格一致性
// ============================================================
static char g_realMachine[64] = "";
static char g_realOSVersion[32] = "";

// ============================================================
// fishhook 原函数指针
// ============================================================
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
static CFPropertyListRef (*orig_MGCopyAnswer)(CFStringRef key, CFDictionaryRef options) = NULL;
static __thread BOOL g_inMGHook = NO;

typedef unsigned int io_registry_entry_t;
static CFTypeRef (*orig_IORegistryEntryCreateCFProperty)(io_registry_entry_t, CFStringRef, CFAllocatorRef, uint32_t) = NULL;

// C 层 Cookie API（绕过 ObjC 层的百度 SDK 走这里）
static void (*orig_CFHTTPCookieStorageSetCookie)(CFHTTPCookieStorageRef, CFHTTPCookieRef) = NULL;
static void (*orig_CFHTTPCookieStorageSetCookies)(CFHTTPCookieStorageRef, CFArrayRef, CFURLRef) = NULL;
static CFArrayRef (*orig_CFHTTPCookieStorageCopyCookiesForURL)(CFHTTPCookieStorageRef, CFURLRef, CFURLRef) = NULL;
static CFArrayRef (*orig_CFHTTPCookieStorageCopyAllCookies)(CFHTTPCookieStorageRef) = NULL;

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
// sysctlbyname hook — v57L 只清空序列号/UUID（应用本来也读不到）
// 其余全部放行真实值（机型/内存/系统版本真实 → 人格一致）
// 纯 C 实现，ZERO ObjC 调用
// ============================================================
static int hook_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name && (strcmp(name, "hw.serialnumber") == 0 || strcmp(name, "hw.uuid") == 0)) {
        if (oldlenp) {
            if (oldp && *oldlenp >= 1) {
                ((char *)oldp)[0] = '\0';
                *oldlenp = 1;
            } else {
                *oldlenp = 1;
            }
        }
        return 0;
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
        g_inMGHook = NO;
    } @catch (id e) {
        g_inMGHook = NO;
    }
    // 其余 key（hw-machine/ProductVersion/ModelNumber/RegionCode 等）→ 真实值放行
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
    CFStringRef nm = CFHTTPCookieCopyName(ck);
    if (!nm) return ck;
    NSString *name = (__bridge_transfer NSString *)nm; // +1 transferred
    if (!isDeviceCookie(name)) return ck;              // 返回原引用（调用方判断相同则不 release）
    CFDictionaryRef props = CFHTTPCookieCopyProperties(ck);
    if (!props) return ck;
    NSMutableDictionary *md = [(__bridge_transfer NSDictionary *)props mutableCopy]; // +1 transferred
    md[(__bridge id)kCFHTTPCookieValue] = getFakeID(name);
    CFHTTPCookieRef nc = CFHTTPCookieCreateWithProperties(kCFAllocatorDefault, (__bridge CFDictionaryRef)md);
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
// Cookie/设备标识生成（保持与真实格式一致）
// ============================================================
static NSString *genCUID(void) {
    NSString *cs = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < 61; i++) {
        uint32_t r = arc4random_uniform(100);
        if (r < 5) {
            [s appendString:@"_"];
        } else if (r < 8) {
            [s appendString:@"-"];
        } else {
            [s appendFormat:@"%C", [cs characterAtIndex:arc4random_uniform((uint32_t)cs.length)]];
        }
    }
    [s appendString:@"mA"];
    return s;
}

static NSString *genBAIDUID(void) {
    NSString *hexCS = @"0123456789ABCDEF";
    return [genRandStr(32, hexCS) stringByAppendingString:@":FG=1"];
}

static NSString *genTcuid(void) {
    NSString *hexCS = @"0123456789ABCDEF";
    NSString *extraCS = @"ABCDEFGHIJ";
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < 48; i++) {
        uint32_t r = arc4random_uniform(100);
        if (r < 15) {
            [s appendFormat:@"%C", [extraCS characterAtIndex:arc4random_uniform((uint32_t)extraCS.length)]];
        } else {
            [s appendFormat:@"%C", [hexCS characterAtIndex:arc4random_uniform((uint32_t)hexCS.length)]];
        }
    }
    return s;
}

static NSString *genFakeCookie(NSString *name) {
    NSString *cuidCS = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    NSString *hexCS = @"0123456789abcdef";

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
    if ([name isEqualToString:@"fuid"]) return genRandStr(32, hexCS);
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
                       @"baiduid", @"baiduid_bfess"];
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
// Constructor — v57L
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {

        // ---- 0. 安装 hook 前缓存真机真实值（人格基线） ----
        size_t sz = sizeof(g_realMachine);
        sysctlbyname("hw.machine", g_realMachine, &sz, NULL, 0);
        sz = sizeof(g_realOSVersion);
        sysctlbyname("kern.osproductversion", g_realOSVersion, &sz, NULL, 0);

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

        // ---- 2. UIDevice hooks — 只伪装 设备名 + IDFV（型号/系统版本保持真实） ----
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

        // ---- 6. NSMutableURLRequest hooks — 只替换 Cookie header ----
        // v57L: UA 不再替换（真实 UA 与真实系统版本一致，替换反而制造矛盾）
        @try {
            Class reqClass = objc_getClass("NSMutableURLRequest");
            if (reqClass) {
                Method svM = class_getInstanceMethod(reqClass, @selector(setValue:forHTTPHeaderField:));
                if (svM) {
                    IMP origSV = method_getImplementation(svM);
                    IMP newSV = imp_implementationWithBlock(^void(id s, NSString *value, NSString *field) {
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
