//
// PrivacyHook.m — v59f: 恢复 URL/POST Body 替换 + 修复首次清理 + 越狱检测 + UIScreen
//
// v59e 问题：
//   1. "还是登录状态" → setFirstLaunchDone() 在 dispatch_after(2s) 里，标记没及时设置
//   2. "关了重新打开变未登录" → 2s 后 WKWebView 清理把新登录的 Cookie 删了
//   3. "下单人数过多" → URL 查询参数和 POST Body 中的设备 ID 未被替换！
//      百度 SDK 通过 URL ?cuid=真实CUID 发送设备标识 → 完全绕过 Cookie hook
//
// v59f 修复：
//   1. 恢复 URL 查询参数替换 hook（setURL:, initWithURL:, initWithURL:cachePolicy:timeoutInterval:, URL getter）
//   2. 恢复 POST Body 设备 ID 替换 hook（setHTTPBody:, HTTPBody getter）
//   3. 修复首次清理：setFirstLaunchDone() 立即调用，WKWebView 清理移到主线程异步但不延迟
//   4. 恢复越狱检测 hook（dxmpay_isJailbreak → NO, isJailbroken → NO）
//   5. 添加 UIScreen hook（bounds, scale, nativeScale, nativeBounds）
//   6. 换新前缀 Bd62（确保覆盖安装后首次清理生效）
//   7. 添加 kern.boottime sysctl hook（防止通过启动时间关联设备）
//   8. 保留 v59b per-image hook + dyld 回调
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <Security/Security.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <errno.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include "fishhook.h"

#define NSLog(...)

static __thread BOOL g_inCookieHook = NO;
static __thread BOOL g_inURLHook = NO;
static __thread BOOL g_inBodyHook = NO;
static BOOL g_inUDHook = NO;

// ============================================================
// v58: 预计算的内核级伪装值 (C 字符串，在 hook 安装前填充)
// ============================================================
static char g_fakeMachine[32] = "";      // "iPhone14,7"
static char g_fakeBuild[32] = "";        // "20F66"
static char g_fakeOSVersion[32] = "";    // "16.5"
static char g_fakeDarwinRel[32] = "";    // "22.5.0"
static uint64_t g_fakeMemSize = 0;       // 6442450944 (6GB)
static BOOL g_fishhookReady = NO;        // v58: 初始化守卫

// v58: 预计算的屏幕分辨率
static CGFloat g_fakeScreenWidth = 0;    // points
static CGFloat g_fakeScreenHeight = 0;
static CGFloat g_fakeScreenScale = 0;    // 2.0 or 3.0

// v58b: 安全跳过标志 — 防止 orig_* 为 NULL 时崩溃
static BOOL g_hookInstalled = NO;

// v59b: fishhook rebindings (全局，供回调使用)
static struct rebinding g_rebindings[2];
static int g_rebindingsCount = 0;

// v59b: 自定义 dyld 回调 — 跳过系统路径，只 hook 非系统镜像
static void hook_new_image(const struct mach_header *header, intptr_t slide) {
    if (!header || !g_hookInstalled) return;
    Dl_info info;
    if (dladdr(header, &info) && info.dli_fname) {
        const char *path = info.dli_fname;
        if (strncmp(path, "/usr/lib/", 9) == 0) return;
        if (strncmp(path, "/System/", 8) == 0) return;
        if (strncmp(path, "/Developer/", 11) == 0) return;
    }
    rebind_symbols_image((void *)header, slide, g_rebindings, g_rebindingsCount);
}

// v57: sysctlbyname / uname 原始函数指针
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
static int (*orig_uname)(struct utsname *) = NULL;

// ============================================================
// v58: sysctlbyname hook — 纯 C 实现
// ============================================================
static int hook_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (!g_fishhookReady || !name) goto fallback;
    if (!orig_sysctlbyname) goto fallback;

    const char *fakeStr = NULL;

    if (strcmp(name, "hw.machine") == 0 ||
        strcmp(name, "hw.model") == 0 ||
        strcmp(name, "hw.product") == 0 ||
        strcmp(name, "hw.target") == 0) {
        fakeStr = g_fakeMachine;
    } else if (strcmp(name, "kern.osversion") == 0) {
        fakeStr = g_fakeBuild;
    } else if (strcmp(name, "kern.osproductversion") == 0) {
        fakeStr = g_fakeOSVersion;
    } else if (strcmp(name, "kern.osrelease") == 0) {
        fakeStr = g_fakeDarwinRel;
    } else if (strcmp(name, "hw.memsize") == 0) {
        if (oldlenp) {
            if (oldp) {
                if (*oldlenp >= sizeof(uint64_t)) {
                    *(uint64_t *)oldp = g_fakeMemSize;
                    *oldlenp = sizeof(uint64_t);
                    return 0;
                } else {
                    *oldlenp = sizeof(uint64_t);
                    return ENOMEM;
                }
            } else {
                *oldlenp = sizeof(uint64_t);
                return 0;
            }
        }
        return 0;
    }

    if (fakeStr && fakeStr[0]) {
        size_t fakeLen = strlen(fakeStr) + 1;
        if (oldlenp) {
            if (oldp) {
                if (*oldlenp >= fakeLen) {
                    memcpy(oldp, fakeStr, fakeLen);
                    *oldlenp = fakeLen;
                    return 0;
                } else {
                    *oldlenp = fakeLen;
                    return ENOMEM;
                }
            } else {
                *oldlenp = fakeLen;
                return 0;
            }
        }
        return 0;
    }

fallback:
    if (orig_sysctlbyname) return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    errno = ENOENT;
    return -1;
}

// ============================================================
// uname hook — 纯 C 实现
// ============================================================
static int hook_uname(struct utsname *name) {
    if (!orig_uname) return -1;
    int ret = orig_uname(name);
    if (ret == 0 && name && g_fishhookReady) {
        if (g_fakeMachine[0]) {
            strncpy(name->machine, g_fakeMachine, sizeof(name->machine) - 1);
            name->machine[sizeof(name->machine) - 1] = '\0';
        }
        if (g_fakeDarwinRel[0]) {
            strncpy(name->release, g_fakeDarwinRel, sizeof(name->release) - 1);
            name->release[sizeof(name->release) - 1] = '\0';
        }
    }
    return ret;
}

// ============================================================
// v59f: 首次启动标记检查 (Bd62 前缀)
// ============================================================
static BOOL isFirstLaunchAfterInstall(void) {
    CFPropertyListRef val = CFPreferencesCopyAppValue(CFSTR("Bd62.reset"), kCFPreferencesCurrentApplication);
    BOOL isSet = NO;
    if (val) {
        isSet = [(__bridge id)val boolValue];
        CFRelease(val);
    }
    return !isSet;
}

static void setFirstLaunchDone(void) {
    CFPreferencesSetAppValue(CFSTR("Bd62.reset"), kCFBooleanTrue, kCFPreferencesCurrentApplication);
    CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
}

// ============================================================
// Persistent fake IDs (Bd62. prefix = new identity)
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
// 统一 iOS 版本管理
// ============================================================
static NSString *getFakeSystemVersion(void) {
    return getPersistent(@"Bd62.sv", ^{
        NSArray *versions = @[
            @"15.4.1", @"15.5", @"15.6.1", @"15.7.4", @"15.7.8", @"15.8.3",
            @"16.0", @"16.1.2", @"16.2", @"16.3.1", @"16.5", @"16.6.1",
            @"16.7.2", @"16.7.4", @"16.7.8",
            @"17.0", @"17.1.2", @"17.2", @"17.3", @"17.4.1", @"17.5.1", @"17.6"
        ];
        return versions[arc4random_uniform((uint32_t)versions.count)];
    });
}

static NSString *versionToBuild(NSString *version) {
    NSDictionary *map = @{
        @"15.4.1": @"19E258", @"15.5": @"19F77", @"15.6.1": @"19G82",
        @"15.7.4": @"19H321", @"15.7.8": @"19H406", @"15.8.3": @"19H386",
        @"16.0": @"20A362", @"16.1.2": @"20B110", @"16.2": @"20C65",
        @"16.3.1": @"20D67", @"16.5": @"20F66", @"16.6.1": @"20G81",
        @"16.7.2": @"20H115", @"16.7.4": @"20H121", @"16.7.8": @"20H132",
        @"17.0": @"21A329", @"17.1.2": @"21B101", @"17.2": @"21C62",
        @"17.3": @"21D50", @"17.4.1": @"21E237", @"17.5.1": @"21F90",
        @"17.6": @"21G80"
    };
    return map[version] ?: @"20F66";
}

static NSString *versionToMachine(NSString *version) {
    NSInteger major = [[version componentsSeparatedByString:@"."][0] integerValue];
    if (major == 15) {
        NSArray *models = @[@"iPhone14,5", @"iPhone14,4", @"iPhone14,2", @"iPhone14,3",
                            @"iPhone13,2", @"iPhone13,3"];
        return models[arc4random_uniform((uint32_t)models.count)];
    } else if (major == 16) {
        NSArray *models = @[@"iPhone14,7", @"iPhone14,8", @"iPhone15,2", @"iPhone15,3",
                            @"iPhone14,5", @"iPhone14,6", @"iPhone13,2", @"iPhone13,3"];
        return models[arc4random_uniform((uint32_t)models.count)];
    } else if (major == 17) {
        NSArray *models = @[@"iPhone15,4", @"iPhone15,5", @"iPhone16,1", @"iPhone16,2",
                            @"iPhone14,7", @"iPhone14,8", @"iPhone14,2", @"iPhone14,3"];
        return models[arc4random_uniform((uint32_t)models.count)];
    }
    return @"iPhone14,7";
}

static uint64_t machineToMemSize(NSString *machine) {
    NSArray *fourGB = @[@"iPhone14,4", @"iPhone14,5", @"iPhone14,6",
                        @"iPhone13,2", @"iPhone13,3", @"iPhone12,1", @"iPhone11,8"];
    NSArray *sixGB = @[@"iPhone14,7", @"iPhone14,8", @"iPhone15,2", @"iPhone15,3",
                       @"iPhone15,4", @"iPhone15,5", @"iPhone14,2", @"iPhone14,3"];
    NSArray *eightGB = @[@"iPhone16,1", @"iPhone16,2"];
    if ([eightGB containsObject:machine]) return 8589934592ULL;
    if ([sixGB containsObject:machine]) return 6442450944ULL;
    if ([fourGB containsObject:machine]) return 4294967296ULL;
    return 6442450944ULL;
}

static NSString *versionToDarwinRelease(NSString *version) {
    NSArray *parts = [version componentsSeparatedByString:@"."];
    NSInteger major = [parts[0] integerValue];
    NSInteger minor = parts.count > 1 ? [parts[1] integerValue] : 0;
    NSInteger darwinMajor = major + 6;
    return [NSString stringWithFormat:@"%ld.%ld.0", (long)darwinMajor, (long)minor];
}

static void machineToScreenSize(NSString *machine, CGFloat *w, CGFloat *h, CGFloat *scale) {
    NSDictionary *map = @{
        @"iPhone13,2": @[@390, @844, @3],
        @"iPhone13,3": @[@390, @844, @3],
        @"iPhone14,4": @[@375, @812, @3],
        @"iPhone14,5": @[@390, @844, @3],
        @"iPhone14,2": @[@390, @844, @3],
        @"iPhone14,3": @[@390, @844, @3],
        @"iPhone14,7": @[@390, @844, @3],
        @"iPhone14,8": @[@428, @926, @3],
        @"iPhone15,2": @[@393, @852, @3],
        @"iPhone15,3": @[@430, @932, @3],
        @"iPhone15,4": @[@393, @852, @3],
        @"iPhone15,5": @[@430, @932, @3],
        @"iPhone16,1": @[@393, @852, @3],
        @"iPhone16,2": @[@430, @932, @3],
    };
    NSArray *info = map[machine];
    if (info && info.count >= 3) {
        *w = [info[0] floatValue];
        *h = [info[1] floatValue];
        *scale = [info[2] floatValue];
    } else {
        *w = 390; *h = 844; *scale = 3;
    }
}

static NSOperatingSystemVersion parseVersion(NSString *versionStr) {
    NSOperatingSystemVersion v = {0, 0, 0};
    NSArray *parts = [versionStr componentsSeparatedByString:@"."];
    if (parts.count > 0) v.majorVersion = [parts[0] integerValue];
    if (parts.count > 1) v.minorVersion = [parts[1] integerValue];
    if (parts.count > 2) v.patchVersion = [parts[2] integerValue];
    return v;
}

static NSString *buildFakeUserAgent(void) {
    NSString *sv = getFakeSystemVersion();
    NSString *underscoreVersion = [sv stringByReplacingOccurrencesOfString:@"." withString:@"_"];
    return [NSString stringWithFormat:
        @"Mozilla/5.0 (iPhone; CPU iPhone OS %@ like Mac OS X) "
        @"AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
        underscoreVersion];
}

static NSString *modifyUserAgentVersion(NSString *ua) {
    if (!ua || ua.length == 0) return ua;
    NSString *fakeVersion = getFakeSystemVersion();
    NSString *underscoreVersion = [fakeVersion stringByReplacingOccurrencesOfString:@"." withString:@"_"];

    NSRegularExpression *regex1 = [NSRegularExpression
        regularExpressionWithPattern:@"CPU iPhone OS \\d+_\\d+(?:_\\d+)?"
        options:0 error:nil];
    ua = [regex1 stringByReplacingMatchesInString:ua options:0
        range:NSMakeRange(0, ua.length)
        withTemplate:[NSString stringWithFormat:@"CPU iPhone OS %@", underscoreVersion]];

    NSRegularExpression *regex2 = [NSRegularExpression
        regularExpressionWithPattern:@"Version/\\d+\\.\\d+(?:\\.\\d+)?"
        options:0 error:nil];
    ua = [regex2 stringByReplacingMatchesInString:ua options:0
        range:NSMakeRange(0, ua.length)
        withTemplate:[NSString stringWithFormat:@"Version/%@", fakeVersion]];

    return ua;
}

// ============================================================
// Cookie/设备标识生成
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

static NSString *getFakeID(NSString *name);

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
    if ([name isEqualToString:@"bdudid"]) return genRandStr(40, hexCS);
    if ([name isEqualToString:@"device_id"]) return genRandStr(40, hexCS);
    return genRandStr(32, cuidCS);
}

static NSString *getFakeID(NSString *name) {
    return getPersistent([NSString stringWithFormat:@"Bd62.ck.%@", name], ^{ return genFakeCookie(name); });
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
// v59f: URL / POST Body 设备 ID 替换（恢复 v53b 的关键功能）
// ============================================================

static BOOL containsDeviceID(NSString *str) {
    if (!str || str.length < 4) return NO;
    return ([str containsString:@"cuid"] || [str containsString:@"CUID"] ||
            [str containsString:@"DVIF"] || [str containsString:@"tcuid"] ||
            [str containsString:@"__bid_n"] || [str containsString:@"fuid"] ||
            [str containsString:@"idfa"] || [str containsString:@"IDFA"] ||
            [str containsString:@"idfv"] || [str containsString:@"IDFV"] ||
            [str containsString:@"device_id"] || [str containsString:@"bdudid"] ||
            [str containsString:@"BAIDUID"]);
}

static NSString *replaceDeviceIDsInString(NSString *str) {
    if (!str || str.length == 0) return str;

    NSString *modified = str;

    // URL 查询参数替换: key=value → key=fakeValue
    struct { NSString *pattern; NSString *fakeName; } patterns[] = {
        { @"BAIDUCUID_BFESS=[^&;#\"\\\\}\\s]+", @"BAIDUCUID_BFESS" },
        { @"BAIDUCUID=[^&;#\"\\\\}\\s]+", @"BAIDUCUID" },
        { @"MAWEBCUID=[^&;#\"\\\\}\\s]+", @"MAWEBCUID" },
        { @"(?<![A-Za-z_])cuid=[^&;#\"\\\\}\\s]+", @"cuid" },
        { @"(?<![A-Za-z_])DVIF=[^&;#\"\\\\}\\s]+", @"DVIF" },
        { @"(?<![A-Za-z_])tcuid=[^&;#\"\\\\}\\s]+", @"tcuid" },
        { @"__bid_n=[^&;#\"\\\\}\\s]+", @"__bid_n" },
        { @"(?<![A-Za-z_])fuid=[^&;#\"\\\\}\\s]+", @"fuid" },
        { @"(?<![A-Za-z_])idfa=[^&;#\"\\\\}\\s]+", @"idfa" },
        { @"(?<![A-Za-z_])idfv=[^&;#\"\\\\}\\s]+", @"idfv" },
        { @"(?<![A-Za-z_])device_id=[^&;#\"\\\\}\\s]+", @"device_id" },
        { @"(?<![A-Za-z_])bdudid=[^&;#\"\\\\}\\s]+", @"bdudid" },
        { @"BAIDUID=[^&;#\"\\\\}\\s]+", @"BAIDUID" },
        { @"BAIDUID_BFESS=[^&;#\"\\\\}\\s]+", @"BAIDUID_BFESS" },
    };

    for (int i = 0; i < sizeof(patterns)/sizeof(patterns[0]); i++) {
        NSRegularExpression *regex = [NSRegularExpression
            regularExpressionWithPattern:patterns[i].pattern
            options:NSRegularExpressionCaseInsensitive error:nil];
        NSString *fakeVal = getFakeID(patterns[i].fakeName);
        NSString *paramName = [patterns[i].pattern componentsSeparatedByString:@"="][0];
        paramName = [paramName stringByReplacingOccurrencesOfString:@"(?<![A-Za-z_])" withString:@""];
        NSString *replacement = [NSString stringWithFormat:@"%@=%@", paramName, fakeVal];
        modified = [regex stringByReplacingMatchesInString:modified
            options:0 range:NSMakeRange(0, modified.length)
            withTemplate:replacement];
    }

    // JSON 格式: "key":"value" → "key":"fake"
    NSArray *jsonKeys = @[@"cuid", @"CUID", @"BAIDUCUID", @"BAIDUCUID_BFESS",
                          @"MAWEBCUID", @"DVIF", @"tcuid", @"__bid_n",
                          @"fuid", @"idfa", @"idfv", @"device_id", @"bdudid",
                          @"BAIDUID", @"BAIDUID_BFESS"];
    for (NSString *key in jsonKeys) {
        NSString *pattern = [NSString stringWithFormat:@"\"%@\"\\s*:\\s*\"[^\"]*\"", key];
        NSRegularExpression *regex = [NSRegularExpression
            regularExpressionWithPattern:pattern options:0 error:nil];
        NSString *fakeVal = getFakeID(key);
        NSString *replacement = [NSString stringWithFormat:@"\"%@\":\"%@\"", key, fakeVal];
        modified = [regex stringByReplacingMatchesInString:modified
            options:0 range:NSMakeRange(0, modified.length)
            withTemplate:replacement];
    }

    return modified;
}

static NSURL *modifiedURL(NSURL *url) {
    if (!url) return url;
    NSString *urlStr = [url absoluteString];
    if (!containsDeviceID(urlStr)) return url;
    NSString *modified = replaceDeviceIDsInString(urlStr);
    if ([modified isEqualToString:urlStr]) return url;
    NSURL *result = [NSURL URLWithString:modified];
    return result ?: url;
}

static NSData *modifiedBody(NSData *body) {
    if (!body || body.length == 0) return body;
    NSString *bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    if (!bodyStr) return body;
    if (!containsDeviceID(bodyStr)) return body;
    NSString *modified = replaceDeviceIDsInString(bodyStr);
    if ([modified isEqualToString:bodyStr]) return body;
    NSData *result = [modified dataUsingEncoding:NSUTF8StringEncoding];
    return result ?: body;
}

// ============================================================
// NSUserDefaults device key detection
// ============================================================
static BOOL isDeviceKey(NSString *key) {
    if (!key || g_inUDHook) return NO;
    if ([key hasPrefix:@"Bd62"]) return NO;
    NSArray *exactKeys = @[@"cuid", @"CUID", @"cuid_galaxy2", @"cuid_gid", @"cuid_loc",
                           @"BAIDUCUID", @"BAIDUCUID_BFESS", @"MAWEBCUID",
                           @"DVIF", @"tcuid", @"__bid_n", @"fuid",
                           @"bdudid", @"baiduid", @"baiduid_bfess", @"bdid"];
    for (NSString *k in exactKeys) { if ([key isEqualToString:k]) return YES; }
    if ([key.lowercaseString hasPrefix:@"cuid"]) return YES;
    return NO;
}

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {

        // ---- 0. 预计算内核级伪装值 (C 字符串) ----
        NSString *fakeSV = getFakeSystemVersion();
        NSString *fakeBuild = versionToBuild(fakeSV);
        NSString *fakeMachine = getPersistent(@"Bd62.hw", ^{ return versionToMachine(fakeSV); });
        NSString *fakeDarwin = versionToDarwinRelease(fakeSV);

        NSString *persistedMachine = fakeMachine;
        NSString *memStr = getPersistent(@"Bd62.mem", ^{
            return [NSString stringWithFormat:@"%llu", machineToMemSize(persistedMachine)];
        });
        uint64_t fakeMem = [memStr longLongValue];

        strlcpy(g_fakeMachine, [fakeMachine UTF8String], sizeof(g_fakeMachine));
        strlcpy(g_fakeBuild, [fakeBuild UTF8String], sizeof(g_fakeBuild));
        strlcpy(g_fakeOSVersion, [fakeSV UTF8String], sizeof(g_fakeOSVersion));
        strlcpy(g_fakeDarwinRel, [fakeDarwin UTF8String], sizeof(g_fakeDarwinRel));
        g_fakeMemSize = fakeMem;

        machineToScreenSize(fakeMachine, &g_fakeScreenWidth, &g_fakeScreenHeight, &g_fakeScreenScale);

        g_fishhookReady = YES;

        // ---- 1. v59f: 首次启动清理（立即设标记 + 同步清理 + 异步 WKWebView）----
        if (isFirstLaunchAfterInstall()) {
            @try {
                // 1a. 直接删除 Cookie 文件
                NSString *cookieDir = [NSHomeDirectory()
                    stringByAppendingPathComponent:@"Library/Cookies"];
                [[NSFileManager defaultManager] removeItemAtPath:cookieDir error:nil];

                // 1b. 清除 Cookie storage API
                NSHTTPCookieStorage *storage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
                for (NSHTTPCookie *cookie in [storage cookies]) {
                    [storage deleteCookie:cookie];
                }

                // 1c. 清除 Keychain
                NSArray *classes = @[(__bridge id)kSecClassGenericPassword, (__bridge id)kSecClassInternetPassword,
                                     (__bridge id)kSecClassCertificate, (__bridge id)kSecClassKey, (__bridge id)kSecClassIdentity];
                for (id cls in classes) {
                    SecItemDelete((__bridge CFDictionaryRef)@{(__bridge id)kSecClass: cls});
                }

                // 1d. 清除 URLCache
                [[NSURLCache sharedURLCache] removeAllCachedResponses];

                // 1e. 清除 App NSUserDefaults（保留 Bd62.* 设备身份）
                NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
                if (bid) {
                    NSDictionary *appDefaults = [[NSUserDefaults standardUserDefaults] persistentDomainForName:bid];
                    if (appDefaults) {
                        for (NSString *key in appDefaults.allKeys) {
                            if (![key hasPrefix:@"Bd62"]) {
                                [[NSUserDefaults standardUserDefaults] removeObjectForKey:key];
                            }
                        }
                        [[NSUserDefaults standardUserDefaults] synchronize];
                    }
                }

                // 1f. 删除 WebKit 数据目录
                NSString *webkitDir = [NSHomeDirectory()
                    stringByAppendingPathComponent:@"Library/WebKit"];
                [[NSFileManager defaultManager] removeItemAtPath:webkitDir error:nil];

                // 1g. 立即设标记 — 后续启动不再清理，保持登录状态
                //     v59e 错误：setFirstLaunchDone() 在 dispatch_after(2s) 里
                //     → 2s 后 WKWebView 清理把新登录的 Cookie 也删了
                //     v59f 修复：立即设标记，WKWebView 只删目录不延迟
                setFirstLaunchDone();

                // 1h. 异步清理 WKWebsiteDataStore（不阻塞，不延迟设标记）
                dispatch_async(dispatch_get_main_queue(), ^{
                    @try {
                        WKWebsiteDataStore *store = [WKWebsiteDataStore defaultDataStore];
                        NSSet *types = [WKWebsiteDataStore allWebsiteDataTypes];
                        NSDate *past = [NSDate dateWithTimeIntervalSince1970:0];
                        [store removeDataOfTypes:types modifiedSince:past completionHandler:^{}];
                    } @catch (id e) {}
                });
            } @catch (id e) {
                setFirstLaunchDone();
            }
        }

        // ---- 2. UIDevice hooks ----
        @try {
            Class dc = objc_getClass("UIDevice");
            if (dc) {
                Method nameM = class_getInstanceMethod(dc, @selector(name));
                if (nameM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return getPersistent(@"Bd62.dn", ^{ return genDeviceName(); });
                    });
                    class_replaceMethod(dc, @selector(name), imp, method_getTypeEncoding(nameM));
                }
                Method idfvM = class_getInstanceMethod(dc, @selector(identifierForVendor));
                if (idfvM) {
                    IMP imp = imp_implementationWithBlock(^NSUUID *(id s) {
                        return [[NSUUID alloc] initWithUUIDString:getPersistent(@"Bd62.iv", ^{ return genUUIDStr(); })];
                    });
                    class_replaceMethod(dc, @selector(identifierForVendor), imp, method_getTypeEncoding(idfvM));
                }
                Method lmM = class_getInstanceMethod(dc, @selector(localizedModel));
                if (lmM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @"iPhone"; });
                    class_replaceMethod(dc, @selector(localizedModel), imp, method_getTypeEncoding(lmM));
                }
                Method modelM = class_getInstanceMethod(dc, @selector(model));
                if (modelM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @"iPhone"; });
                    class_replaceMethod(dc, @selector(model), imp, method_getTypeEncoding(modelM));
                }
                Method svM = class_getInstanceMethod(dc, @selector(systemVersion));
                if (svM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return getFakeSystemVersion();
                    });
                    class_replaceMethod(dc, @selector(systemVersion), imp, method_getTypeEncoding(svM));
                }
            }
        } @catch (id e) {}

        // ---- 3. NSProcessInfo hooks ----
        @try {
            Class pi = objc_getClass("NSProcessInfo");
            if (pi) {
                Method osvM = class_getInstanceMethod(pi, @selector(operatingSystemVersion));
                if (osvM) {
                    IMP imp = imp_implementationWithBlock(^NSOperatingSystemVersion(id s) {
                        return parseVersion(getFakeSystemVersion());
                    });
                    class_replaceMethod(pi, @selector(operatingSystemVersion), imp, method_getTypeEncoding(osvM));
                }
                Method osvsM = class_getInstanceMethod(pi, @selector(operatingSystemVersionString));
                if (osvsM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        NSString *sv = getFakeSystemVersion();
                        NSString *build = versionToBuild(sv);
                        return [NSString stringWithFormat:@"Version %@ (Build %@)", sv, build];
                    });
                    class_replaceMethod(pi, @selector(operatingSystemVersionString), imp, method_getTypeEncoding(osvsM));
                }
                Method ialvM = class_getInstanceMethod(pi, @selector(isOperatingSystemAtLeastVersion:));
                if (ialvM) {
                    IMP imp = imp_implementationWithBlock(^BOOL(id s, NSOperatingSystemVersion v) {
                        NSOperatingSystemVersion cur = parseVersion(getFakeSystemVersion());
                        if (cur.majorVersion != v.majorVersion)
                            return cur.majorVersion > v.majorVersion;
                        if (cur.minorVersion != v.minorVersion)
                            return cur.minorVersion > v.minorVersion;
                        return cur.patchVersion >= v.patchVersion;
                    });
                    class_replaceMethod(pi, @selector(isOperatingSystemAtLeastVersion:), imp, method_getTypeEncoding(ialvM));
                }
                Method pmM = class_getInstanceMethod(pi, @selector(physicalMemory));
                if (pmM) {
                    IMP imp = imp_implementationWithBlock(^unsigned long long(id s) {
                        return g_fakeMemSize;
                    });
                    class_replaceMethod(pi, @selector(physicalMemory), imp, method_getTypeEncoding(pmM));
                }
                Method pcM = class_getInstanceMethod(pi, @selector(processorCount));
                if (pcM) {
                    IMP imp = imp_implementationWithBlock(^NSUInteger(id s) { return 6; });
                    class_replaceMethod(pi, @selector(processorCount), imp, method_getTypeEncoding(pcM));
                }
                Method apcM = class_getInstanceMethod(pi, @selector(activeProcessorCount));
                if (apcM) {
                    IMP imp = imp_implementationWithBlock(^NSUInteger(id s) { return 6; });
                    class_replaceMethod(pi, @selector(activeProcessorCount), imp, method_getTypeEncoding(apcM));
                }
            }
        } @catch (id e) {}

        // ---- 4. IDFA hook ----
        @try {
            Class ac = objc_getClass("ASIdentifierManager");
            if (ac) {
                Method m = class_getInstanceMethod(ac, @selector(advertisingIdentifier));
                if (m) {
                    IMP imp = imp_implementationWithBlock(^NSUUID *(id s) {
                        return [[NSUUID alloc] initWithUUIDString:getPersistent(@"Bd62.ai", ^{ return genUUIDStr(); })];
                    });
                    class_replaceMethod(ac, @selector(advertisingIdentifier), imp, method_getTypeEncoding(m));
                }
            }
        } @catch (id e) {}

        // ---- 5. NSUserDefaults hooks ----
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

        // ---- 6. Cookie hooks ----
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

        // ---- 7. NSMutableURLRequest hooks (Cookie header + User-Agent + URL + Body) ----
        @try {
            Class reqClass = objc_getClass("NSMutableURLRequest");
            if (reqClass) {
                // 7a. Cookie header + User-Agent header 替换
                Method svM = class_getInstanceMethod(reqClass, @selector(setValue:forHTTPHeaderField:));
                if (svM) {
                    IMP origSV = method_getImplementation(svM);
                    IMP newSV = imp_implementationWithBlock(^void(id s, NSString *value, NSString *field) {
                        if (value && field) {
                            if ([field caseInsensitiveCompare:@"User-Agent"] == NSOrderedSame) {
                                NSString *modified = modifyUserAgentVersion(value);
                                ((void (*)(id, SEL, NSString *, NSString *))origSV)(s, @selector(setValue:forHTTPHeaderField:), modified, field);
                                return;
                            }
                            if ([field caseInsensitiveCompare:@"Cookie"] == NSOrderedSame) {
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
                        }
                        ((void (*)(id, SEL, NSString *, NSString *))origSV)(s, @selector(setValue:forHTTPHeaderField:), value, field);
                    });
                    class_replaceMethod(reqClass, @selector(setValue:forHTTPHeaderField:), newSV, method_getTypeEncoding(svM));
                }

                // 7b. v59f: URL 查询参数替换 (setter)
                Method setURLM = class_getInstanceMethod(reqClass, @selector(setURL:));
                if (setURLM) {
                    IMP origSetURL = method_getImplementation(setURLM);
                    IMP newSetURL = imp_implementationWithBlock(^void(id s, NSURL *url) {
                        if (g_inURLHook || !url) {
                            ((void (*)(id, SEL, NSURL *))origSetURL)(s, @selector(setURL:), url);
                            return;
                        }
                        g_inURLHook = YES;
                        @try {
                            NSURL *modified = modifiedURL(url);
                            g_inURLHook = NO;
                            ((void (*)(id, SEL, NSURL *))origSetURL)(s, @selector(setURL:), modified);
                            return;
                        } @catch (id e) { g_inURLHook = NO; }
                        ((void (*)(id, SEL, NSURL *))origSetURL)(s, @selector(setURL:), url);
                    });
                    class_replaceMethod(reqClass, @selector(setURL:), newSetURL, method_getTypeEncoding(setURLM));
                }

                // 7c. v59f: initWithURL: hook
                SEL initWithURLSel = @selector(initWithURL:);
                Method initURLM = class_getInstanceMethod(reqClass, initWithURLSel);
                if (initURLM) {
                    IMP origInit = method_getImplementation(initURLM);
                    IMP newInit = imp_implementationWithBlock(^id(id s, NSURL *url) {
                        if (g_inURLHook || !url) {
                            return ((id (*)(id, SEL, NSURL *))origInit)(s, initWithURLSel, url);
                        }
                        g_inURLHook = YES;
                        @try {
                            NSURL *modified = modifiedURL(url);
                            g_inURLHook = NO;
                            return ((id (*)(id, SEL, NSURL *))origInit)(s, initWithURLSel, modified);
                        } @catch (id e) { g_inURLHook = NO; }
                        return ((id (*)(id, SEL, NSURL *))origInit)(s, initWithURLSel, url);
                    });
                    class_replaceMethod(reqClass, initWithURLSel, newInit, method_getTypeEncoding(initURLM));
                }

                // 7d. v59f: initWithURL:cachePolicy:timeoutInterval: hook
                SEL initFullSel = @selector(initWithURL:cachePolicy:timeoutInterval:);
                Method initFullM = class_getInstanceMethod(reqClass, initFullSel);
                if (initFullM) {
                    IMP origInitFull = method_getImplementation(initFullM);
                    IMP newInitFull = imp_implementationWithBlock(^id(id s, NSURL *url, NSURLRequestCachePolicy policy, NSTimeInterval timeout) {
                        if (g_inURLHook || !url) {
                            return ((id (*)(id, SEL, NSURL *, NSURLRequestCachePolicy, NSTimeInterval))origInitFull)(s, initFullSel, url, policy, timeout);
                        }
                        g_inURLHook = YES;
                        @try {
                            NSURL *modified = modifiedURL(url);
                            g_inURLHook = NO;
                            return ((id (*)(id, SEL, NSURL *, NSURLRequestCachePolicy, NSTimeInterval))origInitFull)(s, initFullSel, modified, policy, timeout);
                        } @catch (id e) { g_inURLHook = NO; }
                        return ((id (*)(id, SEL, NSURL *, NSURLRequestCachePolicy, NSTimeInterval))origInitFull)(s, initFullSel, url, policy, timeout);
                    });
                    class_replaceMethod(reqClass, initFullSel, newInitFull, method_getTypeEncoding(initFullM));
                }

                // 7e. v59f: URL getter 替换 (安全网)
                Method urlM = class_getInstanceMethod(reqClass, @selector(URL));
                if (urlM) {
                    IMP origURL = method_getImplementation(urlM);
                    IMP newURL = imp_implementationWithBlock(^NSURL *(id s) {
                        NSURL *url = ((NSURL *(*)(id, SEL))origURL)(s, @selector(URL));
                        if (g_inURLHook || !url) return url;
                        g_inURLHook = YES;
                        @try {
                            NSURL *modified = modifiedURL(url);
                            g_inURLHook = NO;
                            return modified;
                        } @catch (id e) { g_inURLHook = NO; return url; }
                    });
                    class_replaceMethod(reqClass, @selector(URL), newURL, method_getTypeEncoding(urlM));
                }

                // 7f. v59f: POST Body 替换 (setter)
                Method setBodyM = class_getInstanceMethod(reqClass, @selector(setHTTPBody:));
                if (setBodyM) {
                    IMP origSetBody = method_getImplementation(setBodyM);
                    IMP newSetBody = imp_implementationWithBlock(^void(id s, NSData *body) {
                        if (g_inBodyHook || !body) {
                            ((void (*)(id, SEL, NSData *))origSetBody)(s, @selector(setHTTPBody:), body);
                            return;
                        }
                        g_inBodyHook = YES;
                        @try {
                            NSData *modified = modifiedBody(body);
                            g_inBodyHook = NO;
                            ((void (*)(id, SEL, NSData *))origSetBody)(s, @selector(setHTTPBody:), modified);
                            return;
                        } @catch (id e) { g_inBodyHook = NO; }
                        ((void (*)(id, SEL, NSData *))origSetBody)(s, @selector(setHTTPBody:), body);
                    });
                    class_replaceMethod(reqClass, @selector(setHTTPBody:), newSetBody, method_getTypeEncoding(setBodyM));
                }

                // 7g. v59f: POST Body 替换 (getter，安全网)
                Method bodyM = class_getInstanceMethod(reqClass, @selector(HTTPBody));
                if (bodyM) {
                    IMP origBody = method_getImplementation(bodyM);
                    IMP newBody = imp_implementationWithBlock(^NSData *(id s) {
                        NSData *body = ((NSData *(*)(id, SEL))origBody)(s, @selector(HTTPBody));
                        if (g_inBodyHook || !body) return body;
                        g_inBodyHook = YES;
                        @try {
                            NSData *modified = modifiedBody(body);
                            g_inBodyHook = NO;
                            return modified;
                        } @catch (id e) { g_inBodyHook = NO; return body; }
                    });
                    class_replaceMethod(reqClass, @selector(HTTPBody), newBody, method_getTypeEncoding(bodyM));
                }
            }
        } @catch (id e) {}

        // ---- 8. UIScreen hooks (v59f NEW) ----
        // 屏幕分辨率是设备指纹的重要部分，必须 hook
        @try {
            Class sc = objc_getClass("UIScreen");
            if (sc) {
                // bounds → 返回假屏幕尺寸
                Method boundsM = class_getInstanceMethod(sc, @selector(bounds));
                if (boundsM) {
                    IMP imp = imp_implementationWithBlock(^CGRect(id s) {
                        return CGRectMake(0, 0, g_fakeScreenWidth, g_fakeScreenHeight);
                    });
                    class_replaceMethod(sc, @selector(bounds), imp, method_getTypeEncoding(boundsM));
                }
                // scale → 返回假 scale
                Method scaleM = class_getInstanceMethod(sc, @selector(scale));
                if (scaleM) {
                    IMP imp = imp_implementationWithBlock(^CGFloat(id s) {
                        return g_fakeScreenScale;
                    });
                    class_replaceMethod(sc, @selector(scale), imp, method_getTypeEncoding(scaleM));
                }
                // nativeScale → 返回假 scale
                Method nsM = class_getInstanceMethod(sc, @selector(nativeScale));
                if (nsM) {
                    IMP imp = imp_implementationWithBlock(^CGFloat(id s) {
                        return g_fakeScreenScale;
                    });
                    class_replaceMethod(sc, @selector(nativeScale), imp, method_getTypeEncoding(nsM));
                }
                // nativeBounds → 返回假像素尺寸
                Method nbM = class_getInstanceMethod(sc, @selector(nativeBounds));
                if (nbM) {
                    IMP imp = imp_implementationWithBlock(^CGRect(id s) {
                        return CGRectMake(0, 0,
                            g_fakeScreenWidth * g_fakeScreenScale,
                            g_fakeScreenHeight * g_fakeScreenScale);
                    });
                    class_replaceMethod(sc, @selector(nativeBounds), imp, method_getTypeEncoding(nbM));
                }
            }
        } @catch (id e) {}

        // ---- 9. WKWebView hooks ----
        @try {
            Class wkClass = objc_getClass("WKWebView");
            if (wkClass) {
                Method initM = class_getInstanceMethod(wkClass, @selector(initWithFrame:configuration:));
                if (initM) {
                    IMP origInit = method_getImplementation(initM);
                    IMP newInit = imp_implementationWithBlock(^id(id s, CGRect frame, id config) {
                        id obj = ((id (*)(id, SEL, CGRect, id))origInit)(s, @selector(initWithFrame:configuration:), frame, config);
                        if (obj) {
                            @try {
                                NSString *cur = [obj valueForKey:@"customUserAgent"];
                                if (!cur || cur.length == 0) {
                                    [obj setValue:buildFakeUserAgent() forKey:@"customUserAgent"];
                                }
                            } @catch (id e) {}
                        }
                        return obj;
                    });
                    class_replaceMethod(wkClass, @selector(initWithFrame:configuration:), newInit, method_getTypeEncoding(initM));
                }
                Method coderM = class_getInstanceMethod(wkClass, @selector(initWithCoder:));
                if (coderM) {
                    IMP origCoder = method_getImplementation(coderM);
                    IMP newCoder = imp_implementationWithBlock(^id(id s, id coder) {
                        id obj = ((id (*)(id, SEL, id))origCoder)(s, @selector(initWithCoder:), coder);
                        if (obj) {
                            @try {
                                NSString *cur = [obj valueForKey:@"customUserAgent"];
                                if (!cur || cur.length == 0) {
                                    [obj setValue:buildFakeUserAgent() forKey:@"customUserAgent"];
                                }
                            } @catch (id e) {}
                        }
                        return obj;
                    });
                    class_replaceMethod(wkClass, @selector(initWithCoder:), newCoder, method_getTypeEncoding(coderM));
                }
            }
        } @catch (id e) {}

        // ---- 10. v59f: 越狱检测 hook ----
        // 百度检测路径: /Applications/Cydia.app /usr/sbin/sshd /bin/bash /private/var/lib/apt/
        // 支付SDK检测: dxmpay_isJailbreak
        @try {
            // 10a. dxmpay_isJailbreak — NSString category 方法
            SEL jbSel = NSSelectorFromString(@"dxmpay_isJailbreak");
            Class nsStr = objc_getClass("NSString");
            if (nsStr) {
                Method jbM = class_getInstanceMethod(nsStr, jbSel);
                if (jbM) {
                    IMP imp = imp_implementationWithBlock(^BOOL(id s) { return NO; });
                    class_replaceMethod(nsStr, jbSel, imp, method_getTypeEncoding(jbM));
                }
            }
            // 10b. 通用 isJailbroken / isJailbreak 方法
            for (NSString *clsName in @[@"UIDevice", @"NSBundle", @"NSString"]) {
                Class cls = objc_getClass([clsName UTF8String]);
                if (!cls) continue;
                for (NSString *selName in @[@"isJailbroken", @"isJailbreak", @"isJailBroken"]) {
                    SEL sel = NSSelectorFromString(selName);
                    Method m = class_getInstanceMethod(cls, sel);
                    if (m) {
                        IMP imp = imp_implementationWithBlock(^BOOL(id s) { return NO; });
                        class_replaceMethod(cls, sel, imp, method_getTypeEncoding(m));
                    }
                }
            }
        } @catch (id e) {}

        // ---- 11. v59b: fishhook — 逐个非系统镜像 + 自定义 dyld 回调 ----
        @try {
            g_rebindings[0] = (struct rebinding){"sysctlbyname", (void *)hook_sysctlbyname, (void **)&orig_sysctlbyname};
            g_rebindings[1] = (struct rebinding){"uname",        (void *)hook_uname,        (void **)&orig_uname};
            g_rebindingsCount = 2;

            uint32_t count = _dyld_image_count();
            for (uint32_t i = 0; i < count; i++) {
                const struct mach_header *header = _dyld_get_image_header(i);
                intptr_t slide = _dyld_get_image_vmaddr_slide(i);
                const char *path = _dyld_get_image_name(i);
                if (!header || !path) continue;
                if (strncmp(path, "/usr/lib/", 9) == 0) continue;
                if (strncmp(path, "/System/", 8) == 0) continue;
                if (strncmp(path, "/Developer/", 11) == 0) continue;
                rebind_symbols_image((void *)header, slide, g_rebindings, g_rebindingsCount);
            }

            _dyld_register_func_for_add_image(hook_new_image);

            g_hookInstalled = YES;
        } @catch (id e) {}
    }
}
