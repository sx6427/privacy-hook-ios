//
// PrivacyHook.m — v57c: 内核级设备指纹伪装 (sysctlbyname + uname)
//
// v56 问题（用户反馈"第一次付款成功，然后又下单人数过多"）：
//   v56 hook 了 UIDevice + NSProcessInfo + User-Agent，第一次付款通过。
//   但第二次失败 → 百度在首次交易后交叉比对设备数据，发现不一致。
//
// 根因分析：
//   百度可以通过 sysctlbyname (内核级 C API) 绕过所有 ObjC hook 获取真实设备信息：
//   1. sysctlbyname("hw.machine") → 真实硬件型号 (如 "iPhone14,7") ← 未 hook!
//   2. sysctlbyname("kern.osproductversion") → 真实 iOS 版本 ← 未 hook! 可能就是 16.4
//   3. sysctlbyname("kern.osversion") → 真实 Build 号 ← 未 hook!
//   4. sysctlbyname("hw.memsize") → 真实 RAM 大小 ← 未 hook!
//   5. uname() → struct utsname.machine 真实硬件型号 ← 未 hook!
//
//   第一次付款：百度还没存储足够数据，放行
//   第二次付款：百度交叉比对 ObjC 层(假) vs 内核层(真)，发现矛盾，拦截
//
// v57c 修复：
//   1. 用 fishhook (rebind_symbols_image) 只 hook 主程序的 sysctlbyname + uname
//   2. 所有伪装值在 init 阶段预计算为 C 字符串，hook 函数中只用 C 函数
//   3. iOS 版本 → 硬件型号映射（保证一致性）
//   4. Hook NSProcessInfo.physicalMemory (RAM 大小)
//   5. 新前缀 Bd67.
//
// 安全设计：
//   - hook 函数中 ZERO ObjC 调用（避免 v48 闪退问题）
//   - 只 hook 主程序 (rebind_symbols_image, 不用 rebind_symbols)
//   - 所有值预计算为 static char[]，hook 中只做 strcmp/memcpy
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
// v57c: 预计算的内核级伪装值 (C 字符串，在 hook 安装前填充)
// ============================================================
static char g_fakeMachine[32] = "";      // "iPhone14,7"
static char g_fakeBuild[32] = "";        // "20F66"
static char g_fakeOSVersion[32] = "";    // "16.5"
static char g_fakeDarwinRel[32] = "";    // "22.5.0"
static uint64_t g_fakeMemSize = 0;       // 6442450944 (6GB)

// v57c: sysctlbyname / uname / sysctl 原始函数指针
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
static int (*orig_uname)(struct utsname *) = NULL;
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t) = NULL;

// v57c: fishhook rebindings (全局，供 dyld 回调使用)
static struct rebinding g_rebindings[3];

// v57c: dyld 回调 — 动态加载的非系统镜像也 hook
static void hook_new_image(const struct mach_header *header, intptr_t slide) {
    if (!header) return;
    Dl_info info;
    if (dladdr(header, &info) && info.dli_fname) {
        const char *path = info.dli_fname;
        if (strncmp(path, "/usr/lib/", 9) == 0) return;
        if (strncmp(path, "/System/", 8) == 0) return;
        if (strncmp(path, "/Developer/", 11) == 0) return;
        rebind_symbols_image((void *)header, slide, g_rebindings, 3);
    }
}

// ============================================================
// v57c: sysctlbyname hook — 纯 C 实现，ZERO ObjC 调用
// ============================================================
static int hook_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (!name) goto fallback;

    // 检查是否是我们需要拦截的 sysctl name
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
        // 返回空字符串，阻止设备序列号/UUID 泄露
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
        // 特殊处理：返回 uint64_t
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
        size_t fakeLen = strlen(fakeStr) + 1; // 包含 null terminator
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
// v57c: uname hook — 纯 C 实现
// ============================================================
static int hook_uname(struct utsname *name) {
    int ret = orig_uname(name);
    if (ret == 0 && name) {
        // 覆盖 machine 字段 (硬件型号)
        strncpy(name->machine, g_fakeMachine, sizeof(name->machine) - 1);
        name->machine[sizeof(name->machine) - 1] = '\0';
        // 覆盖 release 字段 (Darwin 内核版本)
        strncpy(name->release, g_fakeDarwinRel, sizeof(name->release) - 1);
        name->release[sizeof(name->release) - 1] = '\0';
    }
    return ret;
}

// ============================================================
// v57d: sysctl 旧 API hook — 纯 C 实现
// sysctl({CTL_HW, HW_MACHINE}, 2, ...) 完全绕过 sysctlbyname
// CTL_KERN=1, KERN_OSRELEASE=2, KERN_OSVERSION=3
// CTL_HW=6, HW_MACHINE=1, HW_MODEL=2, HW_MEMSIZE=24
// ============================================================
static int hook_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (!name || namelen < 1) goto sysctl_fallback;

    if (namelen == 2 && name[0] == 6 /* CTL_HW */) {
        int sub = name[1];
        if (sub == 1 /* HW_MACHINE */ || sub == 2 /* HW_MODEL */) {
            const char *fakeStr = g_fakeMachine;
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
        if (sub == 24 /* HW_MEMSIZE */) {
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
    }

    if (namelen == 2 && name[0] == 1 /* CTL_KERN */) {
        int sub = name[1];
        if (sub == 2 /* KERN_OSRELEASE (Darwin release) */) {
            const char *fakeStr = g_fakeDarwinRel;
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
        if (sub == 3 /* KERN_OSVERSION (Build number) */) {
            const char *fakeStr = g_fakeBuild;
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
    }

sysctl_fallback:
    if (orig_sysctl) return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    errno = ENOENT;
    return -1;
}

// ============================================================
// Persistent fake IDs (Bd67. prefix = new identity)
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

// v56: 更真实的设备名称（完整中文名）
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
    return getPersistent(@"Bd67.sv", ^{
        NSArray *versions = @[
            @"15.4.1", @"15.5", @"15.6.1", @"15.7.4", @"15.7.8", @"15.8.3",
            @"16.0", @"16.1.2", @"16.2", @"16.3.1", @"16.5", @"16.6.1",
            @"16.7.2", @"16.7.4", @"16.7.8",
            @"17.0", @"17.1.2", @"17.2", @"17.3", @"17.4.1", @"17.5.1", @"17.6"
        ];
        return versions[arc4random_uniform((uint32_t)versions.count)];
    });
}

// 版本到 Build 号映射
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

// v57c: iOS 版本 → 硬件型号映射 (保证一致性)
// 返回: @"iPhone14,7" 等
static NSString *versionToMachine(NSString *version) {
    NSInteger major = [[version componentsSeparatedByString:@"."][0] integerValue];
    if (major == 15) {
        // iOS 15: iPhone 12/13 系列
        NSArray *models = @[@"iPhone14,5", @"iPhone14,4", @"iPhone14,2", @"iPhone14,3",
                            @"iPhone13,2", @"iPhone13,3"];
        return models[arc4random_uniform((uint32_t)models.count)];
    } else if (major == 16) {
        // iOS 16: iPhone 14 系列 (也支持 iPhone 8/X/11/12/13)
        NSArray *models = @[@"iPhone14,7", @"iPhone14,8", @"iPhone15,2", @"iPhone15,3",
                            @"iPhone14,5", @"iPhone14,6", @"iPhone13,2", @"iPhone13,3"];
        return models[arc4random_uniform((uint32_t)models.count)];
    } else if (major == 17) {
        // iOS 17: iPhone XR 及以上 (iPhone 15 系列 + 二手旧机型)
        NSArray *models = @[@"iPhone15,4", @"iPhone15,5", @"iPhone16,1", @"iPhone16,2",
                            @"iPhone14,7", @"iPhone14,8", @"iPhone14,2", @"iPhone14,3"];
        return models[arc4random_uniform((uint32_t)models.count)];
    }
    return @"iPhone14,7";
}

// v57c: 硬件型号 → RAM 大小映射
static uint64_t machineToMemSize(NSString *machine) {
    // 4GB 设备
    NSArray *fourGB = @[@"iPhone14,4", @"iPhone14,5", @"iPhone14,6",
                        @"iPhone13,2", @"iPhone13,3", @"iPhone12,1", @"iPhone11,8"];
    // 6GB 设备
    NSArray *sixGB = @[@"iPhone14,7", @"iPhone14,8", @"iPhone15,2", @"iPhone15,3",
                       @"iPhone15,4", @"iPhone15,5", @"iPhone14,2", @"iPhone14,3"];
    // 8GB 设备
    NSArray *eightGB = @[@"iPhone16,1", @"iPhone16,2"];
    if ([eightGB containsObject:machine]) return 8589934592ULL;
    if ([sixGB containsObject:machine]) return 6442450944ULL;
    if ([fourGB containsObject:machine]) return 4294967296ULL;
    return 6442450944ULL; // 默认 6GB
}

// v57c: iOS 版本 → Darwin 内核版本
// iOS 15.x → Darwin 21.x, iOS 16.x → Darwin 22.x, iOS 17.x → Darwin 23.x
static NSString *versionToDarwinRelease(NSString *version) {
    NSArray *parts = [version componentsSeparatedByString:@"."];
    NSInteger major = [parts[0] integerValue];
    NSInteger minor = parts.count > 1 ? [parts[1] integerValue] : 0;
    NSInteger darwinMajor = major + 6; // iOS 15 → Darwin 21, iOS 16 → Darwin 22, iOS 17 → Darwin 23
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
    return genRandStr(32, cuidCS);
}

static NSString *getFakeID(NSString *name) {
    return getPersistent([NSString stringWithFormat:@"Bd67.ck.%@", name], ^{ return genFakeCookie(name); });
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
    if ([key hasPrefix:@"Bd67"]) return NO;
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

        // ---- 0. v57c: 预计算内核级伪装值 (C 字符串) ----
        // 必须在安装 fishhook 之前完成，hook 函数中不能调用 ObjC
        NSString *fakeSV = getFakeSystemVersion();
        NSString *fakeBuild = versionToBuild(fakeSV);
        NSString *fakeMachine = getPersistent(@"Bd67.hw", ^{ return versionToMachine(fakeSV); });
        NSString *fakeDarwin = versionToDarwinRelease(fakeSV);

        // 同步 RAM 大小到硬件型号
        NSString *persistedMachine = fakeMachine;
        NSString *memStr = getPersistent(@"Bd67.mem", ^{
            return [NSString stringWithFormat:@"%llu", machineToMemSize(persistedMachine)];
        });
        uint64_t fakeMem = [memStr longLongValue];

        // 填充 C 字符串缓冲区
        strlcpy(g_fakeMachine, [fakeMachine UTF8String], sizeof(g_fakeMachine));
        strlcpy(g_fakeBuild, [fakeBuild UTF8String], sizeof(g_fakeBuild));
        strlcpy(g_fakeOSVersion, [fakeSV UTF8String], sizeof(g_fakeOSVersion));
        strlcpy(g_fakeDarwinRel, [fakeDarwin UTF8String], sizeof(g_fakeDarwinRel));
        g_fakeMemSize = fakeMem;

        // ---- 1. v57c: 首次启动清理（直接删文件 + 清 NSUserDefaults）----
        @try {
            CFPropertyListRef cleared = CFPreferencesCopyAppValue(CFSTR("Bd67.reset"), kCFPreferencesCurrentApplication);
            if (!cleared) {
                // 1a. 直接删除 Cookie 文件目录（不依赖 NSHTTPCookieStorage API，太早返回空）
                NSString *cookieDir = [NSHomeDirectory()
                    stringByAppendingPathComponent:@"Library/Cookies"];
                [[NSFileManager defaultManager] removeItemAtPath:cookieDir error:nil];

                // 1b. 清除 Cookie storage API（双保险）
                NSHTTPCookieStorage *storage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
                for (NSHTTPCookie *cookie in [storage cookies]) {
                    [storage deleteCookie:cookie];
                }

                // 1c. 清除 Keychain（所有类别）
                NSArray *classes = @[(__bridge id)kSecClassGenericPassword, (__bridge id)kSecClassInternetPassword,
                                     (__bridge id)kSecClassCertificate, (__bridge id)kSecClassKey, (__bridge id)kSecClassIdentity];
                for (id cls in classes) {
                    SecItemDelete((__bridge CFDictionaryRef)@{(__bridge id)kSecClass: cls});
                }

                // 1d. 清除 URLCache
                [[NSURLCache sharedURLCache] removeAllCachedResponses];

                // 1e. 清除 NSUserDefaults（保留 Bd67.* 设备身份，删百度存的设备指纹）
                NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
                if (bid) {
                    NSDictionary *appDefaults = [[NSUserDefaults standardUserDefaults] persistentDomainForName:bid];
                    if (appDefaults) {
                        for (NSString *key in appDefaults.allKeys) {
                            if (![key hasPrefix:@"Bd67"]) {
                                [[NSUserDefaults standardUserDefaults] removeObjectForKey:key];
                            }
                        }
                        [[NSUserDefaults standardUserDefaults] synchronize];
                    }
                }

                // 1f. 立即设标记
                CFPreferencesSetAppValue(CFSTR("Bd67.reset"), kCFBooleanTrue, kCFPreferencesCurrentApplication);
                CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);

                // 1g. 异步清理 WKWebsiteDataStore（不阻塞）
                dispatch_async(dispatch_get_main_queue(), ^{
                    @try {
                        WKWebsiteDataStore *store = [WKWebsiteDataStore defaultDataStore];
                        NSSet *types = [WKWebsiteDataStore allWebsiteDataTypes];
                        NSDate *past = [NSDate dateWithTimeIntervalSince1970:0];
                        [store removeDataOfTypes:types modifiedSince:past completionHandler:^{}];
                    } @catch (id e) {}
                });
            } else { CFRelease(cleared); }
        } @catch (id e) {
            // 出错也设标记，避免每次启动都清理
            CFPreferencesSetAppValue(CFSTR("Bd67.reset"), kCFBooleanTrue, kCFPreferencesCurrentApplication);
            CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
        }

        // ---- 2. UIDevice hooks (name + IDFV + model + systemVersion) ----
        @try {
            Class dc = objc_getClass("UIDevice");
            if (dc) {
                Method nameM = class_getInstanceMethod(dc, @selector(name));
                if (nameM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return getPersistent(@"Bd67.dn", ^{ return genDeviceName(); });
                    });
                    class_replaceMethod(dc, @selector(name), imp, method_getTypeEncoding(nameM));
                }
                Method idfvM = class_getInstanceMethod(dc, @selector(identifierForVendor));
                if (idfvM) {
                    IMP imp = imp_implementationWithBlock(^NSUUID *(id s) {
                        return [[NSUUID alloc] initWithUUIDString:getPersistent(@"Bd67.iv", ^{ return genUUIDStr(); })];
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

        // ---- 3. NSProcessInfo hooks (operatingSystemVersion + physicalMemory) ----
        @try {
            Class pi = objc_getClass("NSProcessInfo");
            if (pi) {
                // 3a. operatingSystemVersion
                Method osvM = class_getInstanceMethod(pi, @selector(operatingSystemVersion));
                if (osvM) {
                    IMP imp = imp_implementationWithBlock(^NSOperatingSystemVersion(id s) {
                        return parseVersion(getFakeSystemVersion());
                    });
                    class_replaceMethod(pi, @selector(operatingSystemVersion), imp, method_getTypeEncoding(osvM));
                }
                // 3b. operatingSystemVersionString
                Method osvsM = class_getInstanceMethod(pi, @selector(operatingSystemVersionString));
                if (osvsM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        NSString *sv = getFakeSystemVersion();
                        NSString *build = versionToBuild(sv);
                        return [NSString stringWithFormat:@"Version %@ (Build %@)", sv, build];
                    });
                    class_replaceMethod(pi, @selector(operatingSystemVersionString), imp, method_getTypeEncoding(osvsM));
                }
                // 3c. isOperatingSystemAtLeastVersion:
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
                // v57c NEW: 3d. physicalMemory (RAM 大小)
                Method pmM = class_getInstanceMethod(pi, @selector(physicalMemory));
                if (pmM) {
                    IMP imp = imp_implementationWithBlock(^unsigned long long(id s) {
                        return g_fakeMemSize;
                    });
                    class_replaceMethod(pi, @selector(physicalMemory), imp, method_getTypeEncoding(pmM));
                }
                // v57c NEW: 3e. processorCount
                Method pcM = class_getInstanceMethod(pi, @selector(processorCount));
                if (pcM) {
                    IMP imp = imp_implementationWithBlock(^NSUInteger(id s) { return 6; });
                    class_replaceMethod(pi, @selector(processorCount), imp, method_getTypeEncoding(pcM));
                }
                // v57c NEW: 3f. activeProcessorCount
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
                        return [[NSUUID alloc] initWithUUIDString:getPersistent(@"Bd67.ai", ^{ return genUUIDStr(); })];
                    });
                    class_replaceMethod(ac, @selector(advertisingIdentifier), imp, method_getTypeEncoding(m));
                }
            }
        } @catch (id e) {}

        // ---- 5. NSUserDefaults hooks (CUID 等设备键) ----
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

        // ---- 6. Cookie hooks (读+写都替换) ----
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

        // ---- 7b. v57d: URL 查询参数 + POST Body 拦截 ----
        // 百度 SDK 在 URL query 和 POST body 中发送真实设备信息
        @try {
            Class reqClass = objc_getClass("NSMutableURLRequest");
            if (reqClass) {
                // 辅助：修改 URL 中的设备参数
                NSURL *(*origSetURL)(id, SEL, NSURL *);
                Method setURLM = class_getInstanceMethod(reqClass, @selector(setURL:));
                if (setURLM) {
                    IMP origSetURLImp = method_getImplementation(setURLM);
                    IMP newSetURL = imp_implementationWithBlock(^void(id s, NSURL *url) {
                        if (url) {
                            @try {
                                NSString *urlStr = url.absoluteString;
                                if (urlStr && urlStr.length > 0) {
                                    // 需要替换的设备参数列表
                                    NSDictionary *paramMap = @{
                                        @"cuid": getFakeID(@"cuid"),
                                        @"CUID": getFakeID(@"cuid"),
                                        @"BAIDUCUID": getFakeID(@"BAIDUCUID"),
                                        @"BAIDUCUID_BFESS": getFakeID(@"BAIDUCUID_BFESS"),
                                        @"MAWEBCUID": getFakeID(@"MAWEBCUID"),
                                        @"idfa": [getPersistent(@"Bd67.ai", ^{ return genUUIDStr(); }) lowercaseString],
                                        @"IDFA": getPersistent(@"Bd67.ai", ^{ return genUUIDStr(); }),
                                        @"idfv": [getPersistent(@"Bd67.iv", ^{ return genUUIDStr(); }) lowercaseString],
                                        @"IDFV": getPersistent(@"Bd67.iv", ^{ return genUUIDStr(); }),
                                        @"bdudid": getFakeID(@"bdudid"),
                                        @"bdid": getFakeID(@"bdid"),
                                        @"tcuid": getFakeID(@"tcuid"),
                                        @"DVIF": getFakeID(@"DVIF"),
                                        @"__bid_n": getFakeID(@"__bid_n"),
                                        @"fuid": getFakeID(@"fuid"),
                                    };
                                    NSString *modified = urlStr;
                                    for (NSString *param in paramMap) {
                                        NSString *fake = paramMap[param];
                                        // 替换 URL query 中的参数值: param=xxx&  或  param=xxx#  或  param=xxx$
                                        NSRegularExpression *regex = [NSRegularExpression
                                            regularExpressionWithPattern:
                                                [NSString stringWithFormat:@"([?&]%@=)[^&#\\s]*", param]
                                            options:NSRegularExpressionCaseInsensitive error:nil];
                                        modified = [regex stringByReplacingMatchesInString:modified options:0
                                            range:NSMakeRange(0, modified.length)
                                            withTemplate:[NSString stringWithFormat:@"$1%@", fake]];
                                    }
                                    // 替换 model/硬件型号参数
                                    NSString *fakeMachine = getPersistent(@"Bd67.hw", ^{ return versionToMachine(getFakeSystemVersion()); });
                                    NSArray *modelParams = @[@"model", "hwmodel", "hw_model", "devicemodel", "device_model", "hwmachine", "hw.machine"];
                                    for (NSString *mp in modelParams) {
                                        NSRegularExpression *regex = [NSRegularExpression
                                            regularExpressionWithPattern:
                                                [NSString stringWithFormat:@"([?&]%@=)[^&#\\s]*", mp]
                                            options:NSRegularExpressionCaseInsensitive error:nil];
                                        modified = [regex stringByReplacingMatchesInString:modified options:0
                                            range:NSMakeRange(0, modified.length)
                                            withTemplate:[NSString stringWithFormat:@"$1%@", fakeMachine]];
                                    }
                                    // 替换 os version 参数
                                    NSString *fakeSV = getFakeSystemVersion();
                                    NSArray *osParams = @[@"osver", "os_ver", "osversion", "os_version", "systemversion", "system_version", "iosversion", "ios_version", "ver", "os"];
                                    for (NSString *op in osParams) {
                                        NSRegularExpression *regex = [NSRegularExpression
                                            regularExpressionWithPattern:
                                                [NSString stringWithFormat:@"([?&]%@=)[^&#\\s]*", op]
                                            options:NSRegularExpressionCaseInsensitive error:nil];
                                        modified = [regex stringByReplacingMatchesInString:modified options:0
                                            range:NSMakeRange(0, modified.length)
                                            withTemplate:[NSString stringWithFormat:@"$1%@", fakeSV]];
                                    }
                                    if (![modified isEqualToString:urlStr]) {
                                        url = [NSURL URLWithString:modified];
                                    }
                                }
                            } @catch (id e) {}
                        }
                        ((void (*)(id, SEL, NSURL *))origSetURLImp)(s, @selector(setURL:), url);
                    });
                    class_replaceMethod(reqClass, @selector(setURL:), newSetURL, method_getTypeEncoding(setURLM));
                }

                // Hook setHTTPBody: — 修改 POST body 中的设备参数
                Method setBodyM = class_getInstanceMethod(reqClass, @selector(setHTTPBody:));
                if (setBodyM) {
                    IMP origSetBody = method_getImplementation(setBodyM);
                    IMP newSetBody = imp_implementationWithBlock(^void(id s, NSData *body) {
                        if (body && body.length > 0 && body.length < 100000) {
                            @try {
                                NSString *bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
                                if (bodyStr && bodyStr.length > 0) {
                                    NSString *modified = bodyStr;
                                    // 替换 form-urlencoded 格式的设备参数
                                    NSDictionary *paramMap = @{
                                        @"cuid": getFakeID(@"cuid"),
                                        @"CUID": getFakeID(@"cuid"),
                                        @"BAIDUCUID": getFakeID(@"BAIDUCUID"),
                                        @"BAIDUCUID_BFESS": getFakeID(@"BAIDUCUID_BFESS"),
                                        @"MAWEBCUID": getFakeID(@"MAWEBCUID"),
                                        @"idfa": [getPersistent(@"Bd67.ai", ^{ return genUUIDStr(); }) lowercaseString],
                                        @"IDFA": getPersistent(@"Bd67.ai", ^{ return genUUIDStr(); }),
                                        @"idfv": [getPersistent(@"Bd67.iv", ^{ return genUUIDStr(); }) lowercaseString],
                                        @"IDFV": getPersistent(@"Bd67.iv", ^{ return genUUIDStr(); }),
                                        @"bdudid": getFakeID(@"bdudid"),
                                        @"bdid": getFakeID(@"bdid"),
                                        @"tcuid": getFakeID(@"tcuid"),
                                        @"DVIF": getFakeID(@"DVIF"),
                                        @"__bid_n": getFakeID(@"__bid_n"),
                                        @"fuid": getFakeID(@"fuid"),
                                    };
                                    for (NSString *param in paramMap) {
                                        NSString *fake = paramMap[param];
                                        // form-urlencoded: param=value&  或  "param":"value"
                                        NSRegularExpression *regex1 = [NSRegularExpression
                                            regularExpressionWithPattern:
                                                [NSString stringWithFormat:@"([\"&?]%@=)[^&\"\\s]*", param]
                                            options:NSRegularExpressionCaseInsensitive error:nil];
                                        modified = [regex1 stringByReplacingMatchesInString:modified options:0
                                            range:NSMakeRange(0, modified.length)
                                            withTemplate:[NSString stringWithFormat:@"$1%@", fake]];
                                        // JSON 格式: "param":"value"
                                        NSRegularExpression *regex2 = [NSRegularExpression
                                            regularExpressionWithPattern:
                                                [NSString stringWithFormat:@"(\"%@\"\\s*:\\s*\")[^\"]*", param]
                                            options:NSRegularExpressionCaseInsensitive error:nil];
                                        modified = [regex2 stringByReplacingMatchesInString:modified options:0
                                            range:NSMakeRange(0, modified.length)
                                            withTemplate:[NSString stringWithFormat:@"$1%@", fake]];
                                    }
                                    // 替换 model/硬件型号
                                    NSString *fakeMachine = getPersistent(@"Bd67.hw", ^{ return versionToMachine(getFakeSystemVersion()); });
                                    NSArray *modelParams = @[@"model", "hwmodel", "hw_model", "devicemodel", "device_model", "hwmachine"];
                                    for (NSString *mp in modelParams) {
                                        NSRegularExpression *regex1 = [NSRegularExpression
                                            regularExpressionWithPattern:
                                                [NSString stringWithFormat:@"([\"&?]%@=)[^&\"\\s]*", mp]
                                            options:NSRegularExpressionCaseInsensitive error:nil];
                                        modified = [regex1 stringByReplacingMatchesInString:modified options:0
                                            range:NSMakeRange(0, modified.length)
                                            withTemplate:[NSString stringWithFormat:@"$1%@", fakeMachine]];
                                        NSRegularExpression *regex2 = [NSRegularExpression
                                            regularExpressionWithPattern:
                                                [NSString stringWithFormat:@"(\"%@\"\\s*:\\s*\")[^\"]*", mp]
                                            options:NSRegularExpressionCaseInsensitive error:nil];
                                        modified = [regex2 stringByReplacingMatchesInString:modified options:0
                                            range:NSMakeRange(0, modified.length)
                                            withTemplate:[NSString stringWithFormat:@"$1%@", fakeMachine]];
                                    }
                                    // 替换 os version
                                    NSString *fakeSV = getFakeSystemVersion();
                                    NSArray *osParams = @[@"osver", "os_ver", "osversion", "os_version", "systemversion", "system_version", "iosversion", "ios_version"];
                                    for (NSString *op in osParams) {
                                        NSRegularExpression *regex1 = [NSRegularExpression
                                            regularExpressionWithPattern:
                                                [NSString stringWithFormat:@"([\"&?]%@=)[^&\"\\s]*", op]
                                            options:NSRegularExpressionCaseInsensitive error:nil];
                                        modified = [regex1 stringByReplacingMatchesInString:modified options:0
                                            range:NSMakeRange(0, modified.length)
                                            withTemplate:[NSString stringWithFormat:@"$1%@", fakeSV]];
                                        NSRegularExpression *regex2 = [NSRegularExpression
                                            regularExpressionWithPattern:
                                                [NSString stringWithFormat:@"(\"%@\"\\s*:\\s*\")[^\"]*", op]
                                            options:NSRegularExpressionCaseInsensitive error:nil];
                                        modified = [regex2 stringByReplacingMatchesInString:modified options:0
                                            range:NSMakeRange(0, modified.length)
                                            withTemplate:[NSString stringWithFormat:@"$1%@", fakeSV]];
                                    }
                                    if (![modified isEqualToString:bodyStr]) {
                                        NSData *newBody = [modified dataUsingEncoding:NSUTF8StringEncoding];
                                        if (newBody) {
                                            ((void (*)(id, SEL, NSData *))origSetBody)(s, @selector(setHTTPBody:), newBody);
                                            return;
                                        }
                                    }
                                }
                            } @catch (id e) {}
                        }
                        ((void (*)(id, SEL, NSData *))origSetBody)(s, @selector(setHTTPBody:), body);
                    });
                    class_replaceMethod(reqClass, @selector(setHTTPBody:), newSetBody, method_getTypeEncoding(setBodyM));
                }

                // Hook addValue:forHTTPHeaderField: (另一个设置 header 的方式)
                Method addValM = class_getInstanceMethod(reqClass, @selector(addValue:forHTTPHeaderField:));
                if (addValM) {
                    IMP origAddVal = method_getImplementation(addValM);
                    IMP newAddVal = imp_implementationWithBlock(^void(id s, NSString *value, NSString *field) {
                        if (value && field) {
                            if ([field caseInsensitiveCompare:@"User-Agent"] == NSOrderedSame) {
                                NSString *modified = modifyUserAgentVersion(value);
                                ((void (*)(id, SEL, NSString *, NSString *))origAddVal)(s, @selector(addValue:forHTTPHeaderField:), modified, field);
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
                                ((void (*)(id, SEL, NSString *, NSString *))origAddVal)(s, @selector(addValue:forHTTPHeaderField:), modified, field);
                                return;
                            }
                        }
                        ((void (*)(id, SEL, NSString *, NSString *))origAddVal)(s, @selector(addValue:forHTTPHeaderField:), value, field);
                    });
                    class_replaceMethod(reqClass, @selector(addValue:forHTTPHeaderField:), newAddVal, method_getTypeEncoding(addValM));
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

        // ---- 8b. v57d: SystemVersion.plist 拦截 ----
        // 百度可直接读 /System/Library/CoreServices/SystemVersion.plist 获取真实 iOS 版本
        // Hook NSDictionary dictionaryWithContentsOfFile: 拦截此文件读取
        @try {
            Class nsDictClass = objc_getClass("NSDictionary");
            if (nsDictClass) {
                Method dcfopM = class_getClassMethod(nsDictClass, @selector(dictionaryWithContentsOfFile:));
                if (dcfopM) {
                    IMP origDCFOP = method_getImplementation(dcfopM);
                    IMP newDCFOP = imp_implementationWithBlock(^NSDictionary *(id s, NSString *path) {
                        NSDictionary *result = ((NSDictionary *(*)(id, SEL, NSString *))origDCFOP)(s, @selector(dictionaryWithContentsOfFile:), path);
                        if (result && path && [path containsString:@"SystemVersion.plist"]) {
                            @try {
                                NSMutableDictionary *modified = [result mutableCopy];
                                NSString *fakeSV = getFakeSystemVersion();
                                modified[@"ProductVersion"] = fakeSV;
                                modified[@"ProductBuildVersion"] = versionToBuild(fakeSV);
                                return modified;
                            } @catch (id e) {}
                        }
                        return result;
                    });
                    class_replaceMethod(object_getClass(nsDictClass), @selector(dictionaryWithContentsOfFile:), newDCFOP, method_getTypeEncoding(dcfopM));
                }
            }
        } @catch (id e) {}

        // ---- 8c. v57d: NSBundle infoDictionary 拦截 ----
        // 拦截 NSBundle 的 infoDictionary 读取（防止读取系统框架的 DTPlatformName 等）
        @try {
            Class bundleClass = objc_getClass("NSBundle");
            if (bundleClass) {
                Method idmM = class_getInstanceMethod(bundleClass, @selector(infoDictionary));
                if (idmM) {
                    IMP origIDM = method_getImplementation(idmM);
                    IMP newIDM = imp_implementationWithBlock(^NSDictionary *(id s) {
                        NSDictionary *result = ((NSDictionary *(*)(id, SEL))origIDM)(s, @selector(infoDictionary));
                        if (result) {
                            @try {
                                // 检查是否包含 DTPlatformName/DTSDKName 等构建信息
                                NSString *platformName = result[@"DTPlatformName"];
                                if (platformName && [platformName containsString:@"iphoneos"]) {
                                    NSMutableDictionary *modified = [result mutableCopy];
                                    // DTSDKName 可能包含真实 SDK 版本
                                    NSString *fakeSV = getFakeSystemVersion();
                                    NSArray *svParts = [fakeSV componentsSeparatedByString:@"."];
                                    NSString *major = svParts[0];
                                    NSString *minor = svParts.count > 1 ? svParts[1] : @"0";
                                    modified[@"DTSDKName"] = [NSString stringWithFormat:@"iphoneos%@.%@", major, minor];
                                    modified[@"DTPlatformVersion"] = fakeSV;
                                    modified[@"MinimumOSVersion"] = fakeSV;
                                    return modified;
                                }
                            } @catch (id e) {}
                        }
                        return result;
                    });
                    class_replaceMethod(bundleClass, @selector(infoDictionary), newIDM, method_getTypeEncoding(idmM));
                }
            }
        } @catch (id e) {}

        // ---- 9. v57c: fishhook — sysctlbyname + uname + sysctl (ALL non-system images) ----
        // v57 只 hook 主程序 → 百度 SDK 框架内部的 sysctlbyname 绕过 hook
        // v57c: hook 所有非系统镜像 + dyld 回调（动态加载的框架也覆盖）
        @try {
            g_rebindings[0] = (struct rebinding){"sysctlbyname", (void *)hook_sysctlbyname, (void **)&orig_sysctlbyname};
            g_rebindings[1] = (struct rebinding){"uname",        (void *)hook_uname,        (void **)&orig_uname};
            g_rebindings[2] = (struct rebinding){"sysctl",       (void *)hook_sysctl,       (void **)&orig_sysctl};

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
                rebind_symbols_image((void *)header, slide, g_rebindings, 3);
            }

            // 9b. 注册 dyld 回调 — 动态加载的框架也会被 hook
            _dyld_register_func_for_add_image(hook_new_image);
        } @catch (id e) {}
    }
}
