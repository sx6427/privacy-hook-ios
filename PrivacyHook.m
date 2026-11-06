//
// PrivacyHook.m — v66F: A 系列 v57f + group 域隔离 + Keychain accessGroup 维度隔离 + 收银台只读观测
//
// 记忆文件教训：
//   v57 成功（第一次能下单）：fishhook 只 hook 主程序，无 dyld 回调，无 URL/POST Body，简单清理
//   v58+ 闪退：hook 所有镜像、dyld 回调、URL/POST Body、SystemVersion.plist 等全部导致闪退
//
// v57e = v57 精确结构 + 仅新增 hw.serialnumber/hw.uuid/hw.target 三个 sysctlbyname key
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
static BOOL g_inUDHook = NO;

// ============================================================
// 预计算的内核级伪装值 (C 字符串，在 hook 安装前填充)
// ============================================================
static char g_fakeMachine[32] = "";
static char g_fakeBuild[32] = "";
static char g_fakeOSVersion[32] = "";
static char g_fakeDarwinRel[32] = "";
static uint64_t g_fakeMemSize = 0;

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
static int (*orig_uname)(struct utsname *) = NULL;

// 全局 rebindings — dyld 回调中需要访问（不能用 block 捕获局部变量）
#define REBIND_COUNT 10
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
// sysctlbyname hook — 纯 C 实现，ZERO ObjC 调用
// ============================================================
static int hook_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (!name) goto fallback;

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
    } else if (strcmp(name, "hw.serialnumber") == 0 ||
               strcmp(name, "hw.uuid") == 0) {
        if (oldlenp) {
            if (oldp && *oldlenp >= 1) {
                ((char *)oldp)[0] = '\0';
                *oldlenp = 1;
            } else {
                *oldlenp = 1;
            }
        }
        return 0;
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

    if (fakeStr) {
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
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

// ============================================================
// uname hook — 纯 C 实现
// ============================================================
static int hook_uname(struct utsname *name) {
    int ret = orig_uname(name);
    if (ret == 0 && name) {
        strncpy(name->machine, g_fakeMachine, sizeof(name->machine) - 1);
        name->machine[sizeof(name->machine) - 1] = '\0';
        strncpy(name->release, g_fakeDarwinRel, sizeof(name->release) - 1);
        name->release[sizeof(name->release) - 1] = '\0';
    }
    return ret;
}

// ============================================================
// v59F: 前缀运行时派生
//
// A 系列每个克隆用独立前缀（Bd62/Bd63/…），过去靠「改源码 + 重新编译」。
// 现在改成从 bundle id 末段取：com.baidu.BaiduMobile.BdF3 → "BdF3"。
// 好处：同一份 dylib 打进 F1..F10，每个克隆自动得到独立命名空间，
//       不再需要编译十次。
//
// 重入保护：本函数可能被 CFPreferences / NSUserDefaults 的 hook 在很深
// 的栈上调用（Foundation 初始化过程中），计算路径若绕回来必须直接返回
// 哨兵值，否则爆栈闪退（v63 cloneTag 踩过同样的坑）。
// ============================================================
static NSString *fpx(void) {
    static NSString *px = nil;
    if (px) return px;
    static BOOL computing = NO;
    if (computing) return @"BdF0";
    computing = YES;
    NSString *bid = nil;
    @try { bid = [[NSBundle mainBundle] bundleIdentifier]; } @catch (id e) {}
    if (bid.length == 0) bid = @"com.baidu.BaiduMobile.BdF1";
    NSString *last = [bid componentsSeparatedByString:@"."].lastObject;
    if (last.length == 0) last = @"BdF1";
    px = [last copy];
    computing = NO;
    return px;
}

static NSString *FKEY(NSString *suffix) {
    return [NSString stringWithFormat:@"%@.%@", fpx(), suffix];
}

// ============================================================
// Persistent fake IDs (BdF1..BdF10 prefix，运行时派生)
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
// iOS 版本管理
// ============================================================
static NSString *getFakeSystemVersion(void) {
    return getPersistent(FKEY(@"sv"), ^{
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

static NSOperatingSystemVersion parseVersion(NSString *versionStr) {
    NSOperatingSystemVersion v = {0, 0, 0};
    NSArray *parts = [versionStr componentsSeparatedByString:@"."];
    if (parts.count > 0) v.majorVersion = [parts[0] integerValue];
    if (parts.count > 1) v.minorVersion = [parts[1] integerValue];
    if (parts.count > 2) v.patchVersion = [parts[2] integerValue];
    return v;
}

// ★ F2 ★ 注册/登录页是 H5（WKWebView）。v57f 的 UA 只有 Mobile/15E148，
// 缺 baiduboxapp 段 —— 服务端会判定「非 App 环境」，注册直接失败。
// 这是 v57Q（2026-09-12）在农场页踩过的同一个坑，这里补回来。
#define BAIDUBOXAPP_SEGMENT @" SP-engine/3.61.0 main/1.0 baiduboxapp/15.69.0.10"

static NSString *buildFakeUserAgent(void) {
    NSString *sv = getFakeSystemVersion();
    NSString *underscoreVersion = [sv stringByReplacingOccurrencesOfString:@"." withString:@"_"];
    return [NSString stringWithFormat:
        @"Mozilla/5.0 (iPhone; CPU iPhone OS %@ like Mac OS X) "
        @"AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148%@",
        underscoreVersion, BAIDUBOXAPP_SEGMENT];
}

// 整条 UA：缺 baiduboxapp 才补，已有则原样返回
static NSString *ensureBaiduboxappSegment(NSString *ua) {
    if (!ua || ua.length == 0) return buildFakeUserAgent();
    if ([ua rangeOfString:@"baiduboxapp"].location != NSNotFound) return ua;
    return [ua stringByAppendingString:BAIDUBOXAPP_SEGMENT];
}

// applicationNameForUserAgent 是「追加段」，不能塞整条 UA，只补标记段
static NSString *ensureAppNameSegment(NSString *name) {
    if (!name || name.length == 0) return @"baiduboxapp/15.69.0.10";
    if ([name rangeOfString:@"baiduboxapp"].location != NSNotFound) return name;
    return [name stringByAppendingString:@" baiduboxapp/15.69.0.10"];
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
    return genRandStr(32, cuidCS);
}

static NSString *getFakeID(NSString *name) {
    return getPersistent(FKEY([NSString stringWithFormat:@"ck.%@", name]), ^{ return genFakeCookie(name); });
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
    if ([key hasPrefix:fpx()]) return NO;
    NSArray *exactKeys = @[@"cuid", @"CUID", @"cuid_galaxy2", @"cuid_gid", @"cuid_loc",
                           @"BAIDUCUID", @"BAIDUCUID_BFESS", @"MAWEBCUID",
                           @"DVIF", @"tcuid", @"__bid_n", @"fuid",
                           @"bdudid", @"baiduid", @"baiduid_bfess", @"bdid"];
    for (NSString *k in exactKeys) { if ([key isEqualToString:k]) return YES; }
    if ([key.lowercaseString hasPrefix:@"cuid"]) return YES;
    return NO;
}

// ============================================================
// v59F: group 域身份键隔离
//
// 背景（D 系列真机取证，2026-11）：
//   共享容器 .../Shared/AppGroup/E2DB4240.../Library/Preferences/
//       group.com.baidu.BaiduMobile.plist
//   → cuid / devuid / idfv / user_id / is_login / bdpanCookie /
//     channel_prefix / SAPI_* / kLocationIPHistoryInfoForWidget /
//     source_userid_<uid> / BNPush_*  全部在这里。
//   A 系列此前完全没隔离 group 域 → 克隆读到的仍是原机身份。
//
// 做法与 D 系列 v64 相同：
//   suite 名整体改写行不通（会把 72 个功能键一起藏掉，H5 活动页拿不到
//   渠道/活动参数），所以只把「身份键」重定向到本克隆私有域：
//       group.com.baidu.BaiduMobile.BdF3
//   非身份键继续读写共享域，功能不受影响。
// ============================================================
static BOOL isGroupDomainStr(NSString *dom) {
    if (dom.length == 0) return NO;
    return [dom hasPrefix:@"group."] || [dom hasPrefix:@"group:"];
}

static NSString *mapGroupSuite(NSString *suite) {
    if (suite.length == 0) return nil;
    if (!isGroupDomainStr(suite)) return nil;
    NSString *suf = fpx();
    if (suf.length == 0) return nil;
    if ([suite hasSuffix:suf]) return nil;          // 已映射，幂等
    return [suite stringByAppendingFormat:@".%@", suf];
}

static CFStringRef mapGroupAppID(CFStringRef appID) {
    if (!appID) return NULL;
    NSString *m = mapGroupSuite((__bridge NSString *)appID);
    if (!m) return NULL;
    return (__bridge_retained CFStringRef)m;        // 调用方负责 CFRelease
}

static BOOL isIdentityKeyStr(NSString *k) {
    if (k.length == 0) return NO;
    static NSSet *exact = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        exact = [NSSet setWithArray:@[
            @"cuid", @"devuid", @"idfv", @"user_id", @"is_login", @"bdpanCookie",
            @"BNPush_cuid", @"BNPush_cacheCuid", @"BNPush_token", @"BNPush_channelid",
            @"channel_prefix", @"zid", @"bduss", @"BDUSS", @"stoken", @"STOKEN",
            @"ptoken", @"PTOKEN", @"cuid_galaxy2", @"cuid_gid",
        ]];
    });
    if ([exact containsObject:k]) return YES;
    NSString *lk = k.lowercaseString;
    static NSArray *subs = nil;
    static dispatch_once_t once2;
    dispatch_once(&once2, ^{
        subs = @[@"cuid", @"devuid", @"idfv", @"sapi_", @"loginmodel", @"user_id",
                 @"userid", @"channel_prefix", @"locationiphistory", @"bnpush",
                 @"baiduid", @"bduss", @"stoken", @"ptoken"];
    });
    for (NSString *t in subs) {
        if ([lk rangeOfString:t].location != NSNotFound) return YES;
    }
    return NO;
}

// ---- 私有域镜像实例 ----
static IMP g_origISS = NULL;              // 原始 -[NSUserDefaults initWithSuiteName:]
static char kUDGroupSuiteKey;             // 关联对象：记录实例的 group 域名
static BOOL g_inPrivPeer = NO;            // 构造重入哨兵

static NSUserDefaults *udRaw(NSString *suite) {
    if (!g_origISS || suite.length == 0) return nil;
    Class uc = objc_getClass("NSUserDefaults");
    if (!uc) return nil;
    id o = [uc alloc];
    return ((id (*)(id, SEL, NSString *))g_origISS)(o, @selector(initWithSuiteName:), suite);
}

static NSUserDefaults *privPeerFor(id s) {
    if (!s || g_inPrivPeer) return nil;
    NSString *suite = objc_getAssociatedObject(s, &kUDGroupSuiteKey);
    if (suite.length == 0) return nil;
    NSString *mapped = mapGroupSuite(suite);
    if (mapped.length == 0) return nil;
    static NSMutableDictionary *cache = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ cache = [NSMutableDictionary new]; });
    @synchronized (cache) {
        NSUserDefaults *d = cache[mapped];
        if (d) return d;
        g_inPrivPeer = YES;
        @try {
            d = udRaw(mapped);
            if (d) cache[mapped] = d;
        } @catch (id e) {}
        g_inPrivPeer = NO;
        return d;
    }
}

// ---- CFPreferences 层（SDK 直接调公开 API 时走这条） ----
static CFPropertyListRef (*orig_CFPrefCopyAppValue)(CFStringRef, CFStringRef) = NULL;
static CFPropertyListRef (*orig_CFPrefCopyValue)(CFStringRef, CFStringRef, CFStringRef, CFStringRef) = NULL;
static Boolean (*orig_CFPrefSetValue)(CFStringRef, CFPropertyListRef, CFStringRef, CFStringRef, CFStringRef) = NULL;
static void (*orig_CFPrefSetAppValue)(CFStringRef, CFPropertyListRef, CFStringRef) = NULL;

static CFPropertyListRef hook_CFPrefCopyAppValue(CFStringRef key, CFStringRef appID) {
    @try {
        if (key && isIdentityKeyStr((__bridge NSString *)key)) {
            CFStringRef m = mapGroupAppID(appID);
            CFPropertyListRef v = orig_CFPrefCopyAppValue(key, m ? m : appID);
            if (m) CFRelease(m);
            return v;
        }
    } @catch (id e) {}
    return orig_CFPrefCopyAppValue(key, appID);
}

static CFPropertyListRef hook_CFPrefCopyValue(CFStringRef key, CFStringRef appID,
                                              CFStringRef user, CFStringRef host) {
    @try {
        if (key && isIdentityKeyStr((__bridge NSString *)key)) {
            CFStringRef m = mapGroupAppID(appID);
            CFPropertyListRef v = orig_CFPrefCopyValue(key, m ? m : appID, user, host);
            if (m) CFRelease(m);
            return v;
        }
    } @catch (id e) {}
    return orig_CFPrefCopyValue(key, appID, user, host);
}

static Boolean hook_CFPrefSetValue(CFStringRef key, CFPropertyListRef value, CFStringRef appID,
                                   CFStringRef user, CFStringRef host) {
    @try {
        if (key && isIdentityKeyStr((__bridge NSString *)key)) {
            CFStringRef m = mapGroupAppID(appID);
            Boolean ok = orig_CFPrefSetValue(key, value, m ? m : appID, user, host);
            if (m) CFRelease(m);
            return ok;
        }
    } @catch (id e) {}
    return orig_CFPrefSetValue(key, value, appID, user, host);
}

static void hook_CFPrefSetAppValue(CFStringRef key, CFPropertyListRef value, CFStringRef appID) {
    @try {
        if (orig_CFPrefSetAppValue && key && isIdentityKeyStr((__bridge NSString *)key)) {
            CFStringRef m = mapGroupAppID(appID);
            orig_CFPrefSetAppValue(key, value, m ? m : appID);
            if (m) CFRelease(m);
            return;
        }
    } @catch (id e) {}
    if (orig_CFPrefSetAppValue) orig_CFPrefSetAppValue(key, value, appID);
}

// ============================================================
// v60F: Keychain 命名空间隔离
//
// 为什么要做：
//   keychain 条目的可见范围由 entitlements 的 keychain-access-groups 决定。
//   所有 clone 与官方 App 若落在同一 access group，物理上就是同一份数据 ——
//   BAIDUCUID / BDUSS / STOKEN / 设备指纹条目全部共享。
//   F3 只隔离了 App Group 的 plist，keychain 仍是漏的。
//
// 做法（不动 access group，避免 errSecMissingEntitlement）：
//   写：service / account 追加 ".BdFn" 后缀 → 落进本克隆私有命名空间
//   读：先查私有；miss 且条目「非身份类」→ 回退共享（只读，保证推送/证书
//       等功能键不丢）；身份类一律不回退，逼出登录流程 → 干净的新身份
//   删：只删私有；无定位键的全量删除直接忽略，避免误伤官方 App / 其他 clone
//
// 说明：后缀由 fpx() 运行时派生，一份 dylib 打进 F1..F10 各自独立命名空间。
// ============================================================

static NSString *kcSuffix(void) {
    static NSString *s = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [@"." stringByAppendingString:fpx()]; });
    return s;
}

static NSArray *kcLocatorKeys(void) {
    static NSArray *a = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        a = @[(__bridge id)kSecAttrService, (__bridge id)kSecAttrAccount];
    });
    return a;
}

// v63F: 前置声明（kcPayNS 定义在后面，kcDictIsIdentity 需要先引用）
static BOOL kcPayNS(NSDictionary *d);
static BOOL kcBaiduAG(NSString *ag);

// 身份类判定：service / account / server 命中关键词即视为「账号或设备身份载体」
static BOOL kcStrIsIdentity(NSString *v) {
    if (v.length == 0) return NO;
    NSString *l = v.lowercaseString;
    static NSArray *ks = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        ks = @[@"bduss", @"stoken", @"ptoken", @"baiduid", @"cuid", @"bdudid",
               @"passport", @"baidu", @"login", @"token", @"session", @"cookie",
               @"credential", @"auth", @"account", @"user", @"uid",
               @"device", @"imei", @"oaid", @"idfa", @"idfv", @"udid", @"uuid",
               @"risk", @"secsdk", @"sfp", @"keychain"];
    });
    for (NSString *k in ks) {
        if ([l rangeOfString:k].location != NSNotFound) return YES;
    }
    return NO;
}

static BOOL kcDictIsIdentity(NSDictionary *d) {
    if (![d isKindOfClass:[NSDictionary class]]) return NO;
    // v63F: 支付 SDK 的命名空间一律不算「账号身份」。
    // 度小满的服务名常含 account / device / token / uuid，旧逻辑会把它
    // 误判成身份类而禁止回退共享域 → 读不到既有设备凭证 → 渠道列表为空。
    if (kcPayNS(d)) return NO;
    for (id k in kcLocatorKeys()) {
        id v = d[k];
        if ([v isKindOfClass:[NSString class]] && kcStrIsIdentity((NSString *)v)) return YES;
    }
    id srv = d[(__bridge id)kSecAttrServer];
    if ([srv isKindOfClass:[NSString class]] && kcStrIsIdentity((NSString *)srv)) return YES;
    return NO;
}

// 是否带了可用于定位的条件（service / account / server）
static BOOL kcHasLocator(NSDictionary *d) {
    if (![d isKindOfClass:[NSDictionary class]]) return NO;
    for (id k in kcLocatorKeys()) {
        id v = d[k];
        if ([v isKindOfClass:[NSString class]] && [(NSString *)v length] > 0) return YES;
    }
    id srv = d[(__bridge id)kSecAttrServer];
    if ([srv isKindOfClass:[NSString class]] && [(NSString *)srv length] > 0) return YES;
    return NO;
}

// 返回 +1 的新字典；无需改写时返回 NULL
static CFDictionaryRef kcRewrite(CFDictionaryRef src) {
    if (!src) return NULL;
    if (![(__bridge id)src isKindOfClass:[NSDictionary class]]) return NULL;
    NSMutableDictionary *m = [(__bridge NSDictionary *)src mutableCopy];
    NSString *sfx = kcSuffix();
    BOOL changed = NO;

    // ---- v66F: 百度共享 accessGroup 的条目，service 也注入私有前缀 ----
    // 根因：passport 把 BDUSS 存在 B83JBVZ6M5.com.baidu.shareLoginAccount 组里，
    // 它的 service / account 完全可能不含任何关键词，旧白名单判不出来 →
    // 原样透传 → 新装的 F1 直接读到 F2 写进去的登录票据（实测 F1 显示 F2 账号）。
    // 这里不依赖字符串猜测，直接看 accessGroup：属于百度账号组就加私有 service 维度。
    id agv = m[(__bridge id)kSecAttrAccessGroup];
    if ([agv isKindOfClass:[NSString class]] && kcBaiduAG((NSString *)agv)) {
        NSString *pp = [@"bdpriv." stringByAppendingFormat:@"%@.", fpx()];
        id sv = m[(__bridge id)kSecAttrService];
        NSString *svc = [sv isKindOfClass:[NSString class]] ? (NSString *)sv : @"-";
        if (![svc hasPrefix:pp]) {
            m[(__bridge id)kSecAttrService] = [pp stringByAppendingString:svc];
            changed = YES;
        }
    }

    for (id k in kcLocatorKeys()) {
        id v = m[k];
        if ([v isKindOfClass:[NSString class]] && [(NSString *)v length] > 0) {
            NSString *str = (NSString *)v;
            if (![str hasSuffix:sfx]) {
                m[k] = [str stringByAppendingString:sfx];
                changed = YES;
            }
        }
    }
    if (!changed) return NULL;
    return (__bridge_retained CFDictionaryRef)[m copy];
}

// ---- v61F: 度小满/钱包命名空间直通 ----
// 第三方支付 SDK 用自身命名空间的 keychain 条目保存软令牌与设备凭证，
// 这些是功能键而非百度账号身份，必须 1:1 保留原行为，否则收银台拿不到渠道。
static BOOL kcPayNS(NSDictionary *d) {
    if (![d isKindOfClass:[NSDictionary class]]) return NO;
    static NSArray *ks = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        ks = @[@"dxm", @"duxiaoman", @"wallet", @"paydxm", @"baidupay", @"com.baidu.pay",
               @"cashier", @"cashdesk", @"ecard", @"unionpay", @"alipay", @"weixin",
               @"tenpay", @"bep", @"bdpay", @"licai", @"youqian", @"axiamsdk", @"loan"];
    });
    NSArray *fields = @[(__bridge id)kSecAttrService,
                        (__bridge id)kSecAttrAccount,
                        (__bridge id)kSecAttrServer];
    for (id key in fields) {
        id v = d[key];
        if (![v isKindOfClass:[NSString class]]) continue;
        NSString *l = [(NSString *)v lowercaseString];
        for (NSString *k in ks) {
            if ([l rangeOfString:k].location != NSNotFound) return YES;
        }
    }
    return NO;
}

static void kcLogPay(const char *op, NSDictionary *d, OSStatus st) {
    @try {
        NSString *svc = d[(__bridge id)kSecAttrService];
        NSString *acct = d[(__bridge id)kSecAttrAccount];
        if (![svc isKindOfClass:[NSString class]]) svc = @"-";
        if (![acct isKindOfClass:[NSString class]]) acct = @"-";
        if (svc.length > 64) svc = [svc substringToIndex:64];
        if (acct.length > 64) acct = [acct substringToIndex:64];
        NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                            NSUserDomainMask, YES) firstObject];
        if (dir.length == 0) return;
        NSString *p = [dir stringByAppendingPathComponent:@"bd_pay.log"];
        FILE *f = fopen(p.UTF8String, "a");
        if (!f) return;
        NSString *ag = d[(__bridge id)kSecAttrAccessGroup];
        if (![ag isKindOfClass:[NSString class]]) ag = @"-";
        if (ag.length > 56) ag = [ag substringToIndex:56];
        fprintf(f, "[KC-%s] st=%d ag=%s svc=%s acct=%s\n", op, (int)st,
                ag.UTF8String, svc.UTF8String, acct.UTF8String);
        fclose(f);
    } @catch (id e) {}
}

// ============================================================
// v64F: Keychain 层改为「白名单隔离」
//
// v60F/v61F/v63F 都是黑名单思路：默认隔离，命中钱包关键词才放行。
// 这要求猜对度小满的 service 命名 —— 猜错就会把支付凭证挡在私有域之外，
// 收银台拿不到渠道列表（F4 实测：kc 版不能付款，F2「完全无隔离」可付款）。
//
// 白名单版：只有「百度账号登录票据」被加后缀隔离，
// 其余所有 keychain 操作（度小满、推送、证书、系统服务）1:1 原样透传。
// 多开隔离的主体仍由 A 系列的随机硬件人格承担，keychain 只兜住登录票据。
// ============================================================
static BOOL kcBaiduIDStr(NSString *v) {
    if (![v isKindOfClass:[NSString class]] || v.length == 0) return NO;
    NSString *l = v.lowercaseString;
    static NSArray *ks = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        ks = @[@"shareloginaccount", @"baiducuid", @"passport.bduss",
               @"bduss", @"stoken", @"ptoken"];
    });
    for (NSString *k in ks) {
        if ([l rangeOfString:k].location != NSNotFound) return YES;
    }
    return NO;
}

// 判定：必须是「登录票据」才隔离。
//   account 命中关键词，或 service 显式带登录语义；
//   仅凭 service = com.baidu.BaiduMobile 不隔离 —— 钱包也用这条 service。
// 百度账号共享 accessGroup 判定。
//   B83JBVZ6M5 是团队前缀；shareLoginAccount 是 passport 的共享登录组。
//   支付（度小满）虽然也可能挂 B83JBVZ6M5，但它是功能凭证，必须放行。
static BOOL kcBaiduAG(NSString *ag) {
    if (![ag isKindOfClass:[NSString class]] || ag.length == 0) return NO;
    NSString *l = ag.lowercaseString;
    if ([l rangeOfString:@"dxm"].location != NSNotFound) return NO;
    if ([l rangeOfString:@"duxiaoman"].location != NSNotFound) return NO;
    if ([l rangeOfString:@"wallet"].location != NSNotFound) return NO;
    if ([l rangeOfString:@"pay"].location != NSNotFound) return NO;
    if ([l rangeOfString:@"shareloginaccount"].location != NSNotFound) return YES;
    if ([l rangeOfString:@"passport"].location != NSNotFound) return YES;
    if ([l rangeOfString:@"baidu"].location != NSNotFound) return YES;
    return NO;
}

static BOOL kcBaiduIDDict(NSDictionary *d) {
    if (![d isKindOfClass:[NSDictionary class]]) return NO;
    if (kcPayNS(d)) return NO;
    // v66F: accessGroup 命中百度账号组 → 一律视为登录票据（不管 service/account 叫什么）
    id ag = d[(__bridge id)kSecAttrAccessGroup];
    if ([ag isKindOfClass:[NSString class]] && kcBaiduAG((NSString *)ag)) return YES;
    id acct = d[(__bridge id)kSecAttrAccount];
    if (kcBaiduIDStr(acct)) return YES;
    id svc = d[(__bridge id)kSecAttrService];
    if ([svc isKindOfClass:[NSString class]]) {
        NSString *l = [(NSString *)svc lowercaseString];
        if ([l rangeOfString:@"shareloginaccount"].location != NSNotFound) return YES;
        if ([l rangeOfString:@"passport.bduss"].location != NSNotFound) return YES;
        if ([l rangeOfString:@"baiducuid"].location != NSNotFound) return YES;
    }
    return NO;
}

// v66F: 全量枚举（只带 kSecClass，不带 service/account/accessGroup）的兜底。
// SDK 用这种查询遍历 keychain 找登录票据；原样透传会把别的 clone 的条目
// 一起交出去。这里不拦查询，只在结果里剔除「百度账号共享组」的条目。
static CFTypeRef kcFilterEnumResult(CFTypeRef res) {
    if (!res) return res;
    if (CFGetTypeID(res) != CFArrayGetTypeID()) return res;
    CFArrayRef arr = (CFArrayRef)res;
    CFIndex n = CFArrayGetCount(arr);
    CFMutableArrayRef out = CFArrayCreateMutable(NULL, n, &kCFTypeArrayCallBacks);
    if (!out) return res;
    for (CFIndex i = 0; i < n; i++) {
        CFTypeRef o = CFArrayGetValueAtIndex(arr, i);
        if (o && CFGetTypeID(o) == CFDictionaryGetTypeID()) {
            NSString *ag = (__bridge NSString *)CFDictionaryGetValue((CFDictionaryRef)o,
                                                                     kSecAttrAccessGroup);
            if ([ag isKindOfClass:[NSString class]] && kcBaiduAG(ag)) continue;
        }
        CFArrayAppendValue(out, o);
    }
    CFRelease(res);
    return out;
}

static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef *) = NULL;
static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *) = NULL;
static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef, CFDictionaryRef) = NULL;
static OSStatus (*orig_SecItemDelete)(CFDictionaryRef) = NULL;

static OSStatus hook_SecItemAdd(CFDictionaryRef attrs, CFTypeRef *result) {
    if (!orig_SecItemAdd) return errSecParam;
    // 非登录票据：原样透传
    if (!kcBaiduIDDict((__bridge NSDictionary *)attrs)) {
        if (attrs && kcPayNS((__bridge NSDictionary *)attrs)) {
            OSStatus st0 = orig_SecItemAdd(attrs, result);
            kcLogPay("ADD-PASS", (__bridge NSDictionary *)attrs, st0);
            return st0;
        }
        return orig_SecItemAdd(attrs, result);
    }
    @try {
        CFDictionaryRef ra = kcRewrite(attrs);
        if (ra) {
            OSStatus st = orig_SecItemAdd(ra, result);
            CFRelease(ra);
            return st;
        }
    } @catch (id e) {}
    return orig_SecItemAdd(attrs, result);
}

static OSStatus hook_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    if (!orig_SecItemCopyMatching) return errSecParam;
    // 非登录票据：原样透传（枚举、钱包、推送、证书一律不动）
    if (!query || !kcBaiduIDDict((__bridge NSDictionary *)query)) {
        OSStatus st0 = orig_SecItemCopyMatching(query, result);
        if (query && kcPayNS((__bridge NSDictionary *)query)) {
            kcLogPay("GET-PASS", (__bridge NSDictionary *)query, st0);
        }
        // v66F: 全量枚举剔除百度账号共享组的条目
        if (st0 == errSecSuccess && result && *result) {
            @try { *result = kcFilterEnumResult(*result); } @catch (id e) {}
        }
        return st0;
    }
    @try {
        NSDictionary *q = (__bridge NSDictionary *)query;
        CFDictionaryRef rq = kcRewrite(query);
        if (!rq) return orig_SecItemCopyMatching(query, result);
        OSStatus st = orig_SecItemCopyMatching(rq, result);
        CFRelease(rq);
        // v65F: 禁止回退共享域。
        // v64F 的回退是为了兼容升级前的老登录票据，但代价是新装 clone
        // 会读到别的 clone 写在共享域的 BDUSS（实测 F1 直接显示成 F2 的账号）。
        // 登录票据必须严格私有：读不到就当未登录，逼本 clone 自己登录一次。
        return st;
    } @catch (id e) {}
    return orig_SecItemCopyMatching(query, result);
}

static OSStatus hook_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef toUpdate) {
    if (!orig_SecItemUpdate) return errSecParam;
    if (!query || !kcBaiduIDDict((__bridge NSDictionary *)query)) {
        return orig_SecItemUpdate(query, toUpdate);
    }
    @try {
        NSDictionary *q = (__bridge NSDictionary *)query;
        CFDictionaryRef rq = kcRewrite(query);
        if (!rq) return orig_SecItemUpdate(query, toUpdate);
        // attributesToUpdate 里若也带 service/account，必须同步加后缀，
        // 否则更新后条目会「跑」回共享域
        CFDictionaryRef ru = kcRewrite(toUpdate);
        OSStatus st = orig_SecItemUpdate(rq, ru ? ru : toUpdate);
        if (ru) CFRelease(ru);
        CFRelease(rq);
        return st;
    } @catch (id e) {}
    return orig_SecItemUpdate(query, toUpdate);
}

static OSStatus hook_SecItemDelete(CFDictionaryRef query) {
    if (!orig_SecItemDelete) return errSecParam;
    if (!query || !kcBaiduIDDict((__bridge NSDictionary *)query)) {
        return orig_SecItemDelete(query);
    }
    @try {
        NSDictionary *q = (__bridge NSDictionary *)query;

        CFDictionaryRef rq = kcRewrite(query);
        if (!rq) return orig_SecItemDelete(query);
        OSStatus st = orig_SecItemDelete(rq);
        CFRelease(rq);
        return st;
    } @catch (id e) {}
    return orig_SecItemDelete(query);
}


// ============================================================
// v62F: 收银台网络只读观测（不改任何报文）
// ============================================================
#include <stdarg.h>

static NSString *pnLogPath(void) {
    static NSString *p = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                            NSUserDomainMask, YES) firstObject];
        if (dir.length) p = [dir stringByAppendingPathComponent:@"bd_pay.log"];
    });
    return p;
}

static void pnLog(NSString *fmt, ...) {
    @try {
        NSString *p = pnLogPath();
        if (p.length == 0) return;
        va_list ap;
        va_start(ap, fmt);
        NSString *body = [[NSString alloc] initWithFormat:fmt arguments:ap];
        va_end(ap);
        if (body.length == 0) return;
        NSDateFormatter *df = [NSDateFormatter new];
        df.dateFormat = @"HH:mm:ss.SSS";
        NSString *line = [NSString stringWithFormat:@"\n[%@] %@", [df stringFromDate:[NSDate date]], body];
        FILE *f = fopen(p.UTF8String, "a");
        if (!f) return;
        fputs(line.UTF8String, f);
        fclose(f);
    } @catch (id e) {}
}

static NSString *pnBodyStr(id data) {
    if (![data isKindOfClass:[NSData class]]) return @"-";
    NSData *d = (NSData *)data;
    if (d.length == 0) return @"<empty>";
    NSData *sub = d.length > 3000 ? [d subdataWithRange:NSMakeRange(0, 3000)] : d;
    NSString *t = [[NSString alloc] initWithData:sub encoding:NSUTF8StringEncoding];
    if (!t) return [NSString stringWithFormat:@"<%lu bytes binary>", (unsigned long)d.length];
    return d.length > 3000 ? [t stringByAppendingString:@"…(truncated)"] : t;
}

static BOOL pnInteresting(NSURL *u) {
    if (!u) return NO;
    NSString *h = u.host.lowercaseString ?: @"";
    NSString *path = u.path.lowercaseString ?: @"";
    if ([h containsString:@"dxmpay"] || [h containsString:@"duxiaoman"] ||
        [h containsString:@"dxmjuhe"] || [h containsString:@"paydxm"] ||
        [h containsString:@"dxmstatic"] || [h containsString:@"dxmbaoxian"]) return YES;
    if ([path containsString:@"orders/create"] || [path containsString:@"order/create"] ||
        [path containsString:@"cashier"] || [path containsString:@"cashdesk"]) return YES;
    return NO;
}

// delegate 型响应体暂存
static NSMutableDictionary *pnTaskBuf(void) {
    static NSMutableDictionary *d = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ d = [NSMutableDictionary new]; });
    return d;
}

static NSString *pnTaskKey(NSURLSessionTask *t) {
    return [NSString stringWithFormat:@"%p-%lu", (void *)t, (unsigned long)t.taskIdentifier];
}

static void pnSwizzleDelegate(id dg) {
    if (!dg) return;
    @try {
        Class c = object_getClass(dg);
        static NSMutableSet *done = nil;
        static dispatch_once_t once;
        dispatch_once(&once, ^{ done = [NSMutableSet new]; });
        NSString *ck = NSStringFromClass(c);
        @synchronized (done) {
            if ([done containsObject:ck]) return;
            [done addObject:ck];
        }
        SEL s1 = @selector(URLSession:dataTask:didReceiveData:);
        SEL s2 = @selector(URLSession:task:didCompleteWithError:);
        Method m1 = class_getInstanceMethod(c, s1);
        Method m2 = class_getInstanceMethod(c, s2);
        if (m1) {
            IMP orig = method_getImplementation(m1);
            IMP imp = imp_implementationWithBlock(^void(id me, NSURLSession *se, NSURLSessionDataTask *task, NSData *data) {
                @try {
                    if (task && data.length) {
                        NSString *k = pnTaskKey(task);
                        @synchronized (pnTaskBuf()) {
                            NSMutableData *b = pnTaskBuf()[k];
                            if (!b) { b = [NSMutableData data]; pnTaskBuf()[k] = b; }
                            [b appendData:data];
                        }
                    }
                } @catch (id e) {}
                ((void (*)(id, SEL, NSURLSession *, NSURLSessionDataTask *, NSData *))orig)(me, s1, se, task, data);
            });
            method_setImplementation(m1, imp);
        }
        if (m2) {
            IMP orig = method_getImplementation(m2);
            IMP imp = imp_implementationWithBlock(^void(id me, NSURLSession *se, NSURLSessionTask *task, NSError *err) {
                @try {
                    if (task) {
                        NSURLRequest *req = task.originalRequest ?: task.currentRequest;
                        if (pnInteresting(req.URL)) {
                            NSHTTPURLResponse *r = (NSHTTPURLResponse *)task.response;
                            NSString *k = pnTaskKey(task);
                            NSData *acc = nil;
                            @synchronized (pnTaskBuf()) {
                                acc = pnTaskBuf()[k];
                                [pnTaskBuf() removeObjectForKey:k];
                            }
                            pnLog(@"[D-RESP] %ld %@ %@\n  REQ: %@ %@\n  ERR: %@\n  BODY: %@",
                                  (long)r.statusCode, req.HTTPMethod, req.URL.absoluteString,
                                  req.HTTPMethod, req.URL.absoluteString,
                                  err.localizedDescription ?: @"-", pnBodyStr(acc));
                        }
                    }
                } @catch (id e) {}
                ((void (*)(id, SEL, NSURLSession *, NSURLSessionTask *, NSError *))orig)(me, s2, se, task, err);
            });
            method_setImplementation(m2, imp);
        }
    } @catch (id e) {}
}

static void pnInstall(void) {
    @try {
        pnLog(@"\n===== v62F PAY-NET OBSERVER INSTALLED =====");
        Class se = objc_getClass("NSURLSession");
        if (se) {
            // 1) completionHandler 型
            SEL s1 = @selector(dataTaskWithRequest:completionHandler:);
            Method m1 = class_getInstanceMethod(se, s1);
            if (m1) {
                IMP orig = method_getImplementation(m1);
                IMP imp = imp_implementationWithBlock(
                    ^NSURLSessionDataTask *(id me, NSURLRequest *req,
                                            void (^cb)(NSData *, NSURLResponse *, NSError *)) {
                        if (!pnInteresting(req.URL)) {
                            return ((NSURLSessionDataTask *(*)(id, SEL, NSURLRequest *, id))orig)(me, s1, req, cb);
                        }
                        @try {
                            pnLog(@"[C-REQ] %@ %@\n  HDR: %@\n  BODY: %@",
                                  req.HTTPMethod, req.URL.absoluteString,
                                  req.allHTTPHeaderFields, pnBodyStr(req.HTTPBody));
                        } @catch (id e) {}
                        void (^wrap)(NSData *, NSURLResponse *, NSError *) =
                        ^(NSData *data, NSURLResponse *resp, NSError *err) {
                            @try {
                                NSInteger code = [(NSHTTPURLResponse *)resp statusCode];
                                pnLog(@"[C-RESP] %ld %@\n  ERR: %@\n  BODY: %@",
                                      (long)code, req.URL.absoluteString,
                                      err.localizedDescription ?: @"-", pnBodyStr(data));
                            } @catch (id e) {}
                            if (cb) cb(data, resp, err);
                        };
                        return ((NSURLSessionDataTask *(*)(id, SEL, NSURLRequest *, id))orig)(me, s1, req, wrap);
                    });
                method_setImplementation(m1, imp);
            }
            // 2) 取 session 时挂上 delegate 观测
            SEL s2 = @selector(sessionWithConfiguration:delegate:delegateQueue:);
            Method m2 = class_getClassMethod(se, s2);
            if (m2) {
                IMP orig = method_getImplementation(m2);
                IMP imp = imp_implementationWithBlock(
                    ^NSURLSession *(id cls, NSURLSessionConfiguration *cfg, id dg, NSOperationQueue *q) {
                        pnSwizzleDelegate(dg);
                        return ((NSURLSession *(*)(id, SEL, NSURLSessionConfiguration *, id, id))orig)(cls, s2, cfg, dg, q);
                    });
                method_setImplementation(m2, imp);
            }
            SEL s3 = @selector(initWithConfiguration:delegate:delegateQueue:);
            Method m3 = class_getInstanceMethod(se, s3);
            if (m3) {
                IMP orig = method_getImplementation(m3);
                IMP imp = imp_implementationWithBlock(
                    ^id(id me, NSURLSessionConfiguration *cfg, id dg, NSOperationQueue *q) {
                        pnSwizzleDelegate(dg);
                        return ((id (*)(id, SEL, NSURLSessionConfiguration *, id, id))orig)(me, s3, cfg, dg, q);
                    });
                method_setImplementation(m3, imp);
            }
        }
        // 3) WKWebView 导航（收银台若是 H5）
        Class wv = objc_getClass("WKWebView");
        if (wv) {
            SEL s4 = @selector(loadRequest:);
            Method m4 = class_getInstanceMethod(wv, s4);
            if (m4) {
                IMP orig = method_getImplementation(m4);
                IMP imp = imp_implementationWithBlock(^id(id me, NSURLRequest *req) {
                    @try {
                        if (pnInteresting(req.URL)) {
                            pnLog(@"[WEBVIEW] %@ %@", req.HTTPMethod ?: @"GET", req.URL.absoluteString);
                        }
                    } @catch (id e) {}
                    return ((id (*)(id, SEL, NSURLRequest *))orig)(me, s4, req);
                });
                method_setImplementation(m4, imp);
            }
        }
        pnLog(@"===== observer hooks ready =====");
    } @catch (id e) {
        pnLog(@"observer install error: %@", e);
    }
}

// ============================================================
// Constructor — v57 结构：简单清理 + 只 hook 主程序
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {

        // ---- 0. 诊断标记：确认本 dylib 版本已启用 keychain 隔离 ----
        //   NSUserDefaults 里能看到 BdFn.kcv = 1
        CFPreferencesSetAppValue((__bridge CFStringRef)FKEY(@"kcv"),
                                 (__bridge CFStringRef)@"1",
                                 kCFPreferencesCurrentApplication);
        // v61F 标记：度小满 keychain 直通版
        CFPreferencesSetAppValue((__bridge CFStringRef)FKEY(@"kcp"),
                                 (__bridge CFStringRef)@"1",
                                 kCFPreferencesCurrentApplication);
        // v66F 标记：keychain 按 accessGroup 隔离（共享登录票据不再串号）
        CFPreferencesSetAppValue((__bridge CFStringRef)FKEY(@"kca"),
                                 (__bridge CFStringRef)@"1",
                                 kCFPreferencesCurrentApplication);

        // ---- 0. 预计算内核级伪装值 (C 字符串) ----
        NSString *fakeSV = getFakeSystemVersion();
        NSString *fakeBuild = versionToBuild(fakeSV);
        NSString *fakeMachine = getPersistent(FKEY(@"hw"), ^{ return versionToMachine(fakeSV); });
        NSString *fakeDarwin = versionToDarwinRelease(fakeSV);

        NSString *persistedMachine = fakeMachine;
        NSString *memStr = getPersistent(FKEY(@"mem"), ^{
            return [NSString stringWithFormat:@"%llu", machineToMemSize(persistedMachine)];
        });
        uint64_t fakeMem = [memStr longLongValue];

        strlcpy(g_fakeMachine, [fakeMachine UTF8String], sizeof(g_fakeMachine));
        strlcpy(g_fakeBuild, [fakeBuild UTF8String], sizeof(g_fakeBuild));
        strlcpy(g_fakeOSVersion, [fakeSV UTF8String], sizeof(g_fakeOSVersion));
        strlcpy(g_fakeDarwinRel, [fakeDarwin UTF8String], sizeof(g_fakeDarwinRel));
        g_fakeMemSize = fakeMem;

        // ---- 1. v57 简单清理：Cookie storage + Keychain ----
        @try {
            CFPropertyListRef cleared = CFPreferencesCopyAppValue((__bridge CFStringRef)FKEY(@"reset"), kCFPreferencesCurrentApplication);
            if (!cleared) {
                // 1a. 清除 Cookie storage
                NSHTTPCookieStorage *storage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
                for (NSHTTPCookie *cookie in [storage cookies]) {
                    [storage deleteCookie:cookie];
                }

                // 1b. v60F: 不再做全类别 SecItemDelete
                //   keychain 条目在同一 access group 内物理共享，
                //   「按 class 全删」会连带清掉官方 App 与其他 clone 的登录态。
                //   新命名空间（service/account 追加 .BdFn 后缀）天然为空，无需清理；
                //   旧的无后缀条目由读路径按「身份类不回退」拦截。

                // 1c. 设标记
                CFPreferencesSetAppValue((__bridge CFStringRef)FKEY(@"reset"), kCFBooleanTrue, kCFPreferencesCurrentApplication);
                CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
            } else { CFRelease(cleared); }
        } @catch (id e) {
            CFPreferencesSetAppValue((__bridge CFStringRef)FKEY(@"reset"), kCFBooleanTrue, kCFPreferencesCurrentApplication);
            CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
        }

        // ---- 2. UIDevice hooks ----
        @try {
            Class dc = objc_getClass("UIDevice");
            if (dc) {
                Method nameM = class_getInstanceMethod(dc, @selector(name));
                if (nameM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return getPersistent(FKEY(@"dn"), ^{ return genDeviceName(); });
                    });
                    class_replaceMethod(dc, @selector(name), imp, method_getTypeEncoding(nameM));
                }
                Method idfvM = class_getInstanceMethod(dc, @selector(identifierForVendor));
                if (idfvM) {
                    IMP imp = imp_implementationWithBlock(^NSUUID *(id s) {
                        return [[NSUUID alloc] initWithUUIDString:getPersistent(FKEY(@"iv"), ^{ return genUUIDStr(); })];
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
                        return [[NSUUID alloc] initWithUUIDString:getPersistent(FKEY(@"ai"), ^{ return genUUIDStr(); })];
                    });
                    class_replaceMethod(ac, @selector(advertisingIdentifier), imp, method_getTypeEncoding(m));
                }
            }
        } @catch (id e) {}

        // ---- 5. NSUserDefaults hooks ----
        @try {
            Class uc = objc_getClass("NSUserDefaults");
            if (uc) {
                // v59F: 只给 group 域实例打标记，域名不改（功能键仍读共享域）
                Method issM = class_getInstanceMethod(uc, @selector(initWithSuiteName:));
                if (issM) {
                    g_origISS = method_getImplementation(issM);
                    IMP impISS = imp_implementationWithBlock(^id(id s2, NSString *suite) {
                        id obj = ((id (*)(id, SEL, NSString *))g_origISS)(
                            s2, @selector(initWithSuiteName:), suite);
                        if (obj && suite.length && isGroupDomainStr(suite)) {
                            objc_setAssociatedObject(obj, &kUDGroupSuiteKey, suite,
                                                     OBJC_ASSOCIATION_RETAIN);
                        }
                        return obj;
                    });
                    class_replaceMethod(uc, @selector(initWithSuiteName:), impISS,
                                        method_getTypeEncoding(issM));
                }
                Method ofkM = class_getInstanceMethod(uc, @selector(objectForKey:));
                if (ofkM) {
                    IMP orig = method_getImplementation(ofkM);
                    IMP imp = imp_implementationWithBlock(^id(id s, NSString *key) {
                        // v59F: group 域 + 身份键 → 本克隆私有域
                        @try {
                            if (isIdentityKeyStr(key)) {
                                NSUserDefaults *p = privPeerFor(s);
                                if (p && p != s) {
                                    return ((id (*)(id, SEL, NSString *))orig)(
                                        p, @selector(objectForKey:), key);
                                }
                            }
                        } @catch (id e) {}
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
                        @try {
                            if (isIdentityKeyStr(key)) {
                                NSUserDefaults *p = privPeerFor(s);
                                if (p && p != s) {
                                    return ((NSString *(*)(id, SEL, NSString *))orig)(
                                        p, @selector(stringForKey:), key);
                                }
                            }
                        } @catch (id e) {}
                        if (!g_inUDHook && isDeviceKey(key)) {
                            g_inUDHook = YES;
                            @try { NSString *f = getFakeID(@"cuid"); g_inUDHook = NO; return f; }
                            @catch (id e) { g_inUDHook = NO; }
                        }
                        return ((NSString *(*)(id, SEL, NSString *))orig)(s, @selector(stringForKey:), key);
                    });
                    class_replaceMethod(uc, @selector(stringForKey:), imp, method_getTypeEncoding(sfkM));
                }
                // v59F: 写入侧同样分流 —— 否则 SDK 会把假身份写回共享域，
                // 下一次读取（或别的克隆）又拿回原机真值。
                Method sofkM = class_getInstanceMethod(uc, @selector(setObject:forKey:));
                if (sofkM) {
                    IMP origSet = method_getImplementation(sofkM);
                    IMP impSet = imp_implementationWithBlock(^void(id s, id obj, NSString *key) {
                        @try {
                            if (!g_inPrivPeer && isIdentityKeyStr(key)) {
                                NSUserDefaults *p = privPeerFor(s);
                                if (p && p != s) {
                                    ((void (*)(id, SEL, id, NSString *))origSet)(
                                        p, @selector(setObject:forKey:), obj, key);
                                    return;
                                }
                            }
                        } @catch (id e) {}
                        ((void (*)(id, SEL, id, NSString *))origSet)(
                            s, @selector(setObject:forKey:), obj, key);
                    });
                    class_replaceMethod(uc, @selector(setObject:forKey:), impSet,
                                        method_getTypeEncoding(sofkM));
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

        // ---- 7. NSMutableURLRequest hooks (Cookie + User-Agent) ----
        @try {
            Class reqClass = objc_getClass("NSMutableURLRequest");
            if (reqClass) {
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
            }
        } @catch (id e) {}

        // ---- 8. WKWebView hooks (customUserAgent) ----
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
                                NSString *want = ensureBaiduboxappSegment(cur);
                                if (!cur || ![cur isEqualToString:want]) {
                                    [obj setValue:want forKey:@"customUserAgent"];
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
                                NSString *want = ensureBaiduboxappSegment(cur);
                                if (!cur || ![cur isEqualToString:want]) {
                                    [obj setValue:want forKey:@"customUserAgent"];
                                }
                            } @catch (id e) {}
                        }
                        return obj;
                    });
                    class_replaceMethod(wkClass, @selector(initWithCoder:), newCoder, method_getTypeEncoding(coderM));
                }
            }
        } @catch (id e) {}

        // ---- 8b. F2: WKWebViewConfiguration.applicationNameForUserAgent ----
        // App 创建 WKWebView 时常把 App 标识走这条通道；我们若只改
        // customUserAgent，这条仍是原值或被覆盖成缺段的 UA，H5 依然判非 App。
        @try {
            Class cfgClass = objc_getClass("WKWebViewConfiguration");
            if (cfgClass) {
                Method setAppM = class_getInstanceMethod(cfgClass, @selector(setApplicationNameForUserAgent:));
                if (setAppM) {
                    IMP origSetApp = method_getImplementation(setAppM);
                    IMP newSetApp = imp_implementationWithBlock(^void(id s, NSString *name) {
                        NSString *v = ensureAppNameSegment(name);
                        ((void (*)(id, SEL, NSString *))origSetApp)(s, @selector(setApplicationNameForUserAgent:), v);
                    });
                    class_replaceMethod(cfgClass, @selector(setApplicationNameForUserAgent:), newSetApp, method_getTypeEncoding(setAppM));
                }
                Method getAppM = class_getInstanceMethod(cfgClass, @selector(applicationNameForUserAgent));
                if (getAppM) {
                    IMP origGetApp = method_getImplementation(getAppM);
                    IMP newGetApp = imp_implementationWithBlock(^NSString *(id s) {
                        NSString *v = ((NSString *(*)(id, SEL))origGetApp)(s, @selector(applicationNameForUserAgent));
                        return ensureAppNameSegment(v);
                    });
                    class_replaceMethod(cfgClass, @selector(applicationNameForUserAgent), newGetApp, method_getTypeEncoding(getAppM));
                }
            }
        } @catch (id e) {}

        // ---- 8z. v62F 收银台网络只读观测 ----
        pnInstall();
        CFPreferencesSetAppValue((__bridge CFStringRef)FKEY(@"kcn"),
                                 (__bridge CFStringRef)@"1",
                                 kCFPreferencesCurrentApplication);

        // ---- 9. fishhook — hook 所有非系统镜像 + dyld 回调 ----
        // v57 只 hook 主程序 → 百度 SDK 框架内部 sysctlbyname 绕过 hook，获取真实设备信息
        // v57c: hook 所有非系统镜像 + dyld 回调（动态加载的框架也覆盖）
        // 注意：v57c 没有闪退，闪退是 v57d 新加的 sysctl旧API/URL body/SystemVersion.plist 导致的
        @try {
            g_rebindings[0] = (struct rebinding){"sysctlbyname", (void *)hook_sysctlbyname, (void **)&orig_sysctlbyname};
            g_rebindings[1] = (struct rebinding){"uname",        (void *)hook_uname,        (void **)&orig_uname};
            // v59F: group 域身份键隔离（SDK 直接调 CFPreferences 时走这条）
            g_rebindings[2] = (struct rebinding){"CFPreferencesCopyAppValue", (void *)hook_CFPrefCopyAppValue, (void **)&orig_CFPrefCopyAppValue};
            g_rebindings[3] = (struct rebinding){"CFPreferencesCopyValue",    (void *)hook_CFPrefCopyValue,    (void **)&orig_CFPrefCopyValue};
            g_rebindings[4] = (struct rebinding){"CFPreferencesSetAppValue",  (void *)hook_CFPrefSetAppValue,  (void **)&orig_CFPrefSetAppValue};
            g_rebindings[5] = (struct rebinding){"CFPreferencesSetValue",     (void *)hook_CFPrefSetValue,     (void **)&orig_CFPrefSetValue};
            // v60F: Keychain 命名空间隔离
            g_rebindings[6] = (struct rebinding){"SecItemAdd",          (void *)hook_SecItemAdd,          (void **)&orig_SecItemAdd};
            g_rebindings[7] = (struct rebinding){"SecItemCopyMatching", (void *)hook_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching};
            g_rebindings[8] = (struct rebinding){"SecItemUpdate",       (void *)hook_SecItemUpdate,       (void **)&orig_SecItemUpdate};
            g_rebindings[9] = (struct rebinding){"SecItemDelete",       (void *)hook_SecItemDelete,       (void **)&orig_SecItemDelete};

            // 9a. hook 所有已加载的非系统镜像
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

            // 9b. 注册 dyld 回调 — 动态加载的框架也会被 hook（用 C 函数，不用 block）
            _dyld_register_func_for_add_image(hook_new_image);
        } @catch (id e) {}
    }
}
