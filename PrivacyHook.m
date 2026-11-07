//
// PrivacyHook.m — v69F: keychain 全透传(保支付) + 共享登录组按 owned 白名单过滤
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
// v82F ★ 每克隆一台「完整设备」，不再是「真机 + 改 ID」★
//   v81F 把硬件透传真机：所有克隆硬件完全一样，服务端一次聚类就把
//   F1..F20 归成同一台设备 —— 用户反馈农场进不去正是这个原因。
//   v82F 恢复伪造，但按机型成组伪造，保证下面三层永远同一套值：
//     sysctl(hw.machine/hw.model/hw.memsize/hw.ncpu/kern.boottime)
//       == MGCopyAnswer(ProductType/HardwareModel/OSVersion/BuildVersion)
//       == uname(machine/release) == UIDevice(model/name/systemVersion)
//   机型按 bundle id 序号确定性分配（BdF7 → 池内固定一台），重装不跳变。
//   系统版本仍取真机：WKWebView/H5 的 navigator 改不了，这条必须真。
static char g_fakeHwModel[32] = "";     // 主板代号 D64AP 这类，hw.model 返回它
static uint32_t g_fakeNCpu = 0;         // CPU 核数，跟机型配套
static int64_t  g_fakeBootSec = 0;      // 开机时刻，每克隆不同且持久化
static double   g_fakeUptime = 0;
static char g_fakeHost[128] = "";       // 统一主机名（C/ObjC/MG 同值）
static long long g_diskDelta = 0;       // v81F: 每克隆磁盘总容量偏移
static NSString *g_selfBundleID = nil;

static CFPropertyListRef (*orig_MGCopyAnswer)(CFStringRef, CFDictionaryRef) = NULL;
static __thread BOOL g_inMGHook = NO;
static int (*orig_gethostname)(char *, size_t) = NULL;
static CFArrayRef (*orig_CNCopyCurrentNetworkInfo)(CFStringRef) = NULL;

// UIPasteboard 私有化（TalosPro 风控 SDK 在用，跨 App 串号）
static IMP g_origPBNamespace = NULL;
static IMP g_origPBGeneral = NULL;
static IMP g_origPBWithName = NULL;
static __thread BOOL g_inPBCall = NO;

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;

// v80F: gethostuuid —— 同一台物理设备所有进程返回同一个 UUID，
// 重装/换 bundle id 都不会变，是风控最常用的硬件兜底标识。
static NSString *agSeed(void);
static uint32_t agMix(const char *, uint32_t);
static int (*orig_gethostuuid)(uuid_t, const struct timespec *) = NULL;

static int hook_gethostuuid(uuid_t out, const struct timespec *wait) {
    if (!out) return orig_gethostuuid ? orig_gethostuuid(out, wait) : -1;
    @try {
        NSString *sd = [NSString stringWithFormat:@"%@|hostuuid", agSeed()];
        const char *pp = sd.UTF8String;
        uint32_t v[4];
        v[0] = agMix(pp, 1101u);
        v[1] = agMix(pp, 2203u);
        v[2] = agMix(pp, 3307u);
        v[3] = agMix(pp, 4409u);
        memcpy(out, v, 16);
        out[6] = (unsigned char)((out[6] & 0x0F) | 0x40);
        out[8] = (unsigned char)((out[8] & 0x3F) | 0x80);
        return 0;
    } @catch (id e) {}
    return orig_gethostuuid ? orig_gethostuuid(out, wait) : -1;
}
static int (*orig_uname)(struct utsname *) = NULL;

// 全局 rebindings — dyld 回调中需要访问（不能用 block 捕获局部变量）
#define REBIND_COUNT 14
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

    if (strcmp(name, "kern.hostname") == 0) {
        // v81F ★真名泄漏★ 真机此处是 "1-4"，所有克隆完全一致 → 设备聚类信号
        if (g_fakeHost[0]) fakeStr = g_fakeHost;
    } else if (strcmp(name, "kern.osversion") == 0) {
        if (g_fakeBuild[0]) fakeStr = g_fakeBuild;
    } else if (strcmp(name, "kern.osproductversion") == 0) {
        if (g_fakeOSVersion[0]) fakeStr = g_fakeOSVersion;
    } else if (strcmp(name, "kern.osrelease") == 0) {
        if (g_fakeDarwinRel[0]) fakeStr = g_fakeDarwinRel;
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
    } else if (strcmp(name, "hw.memsize") == 0 && g_fakeMemSize > 0) {
        if (oldlenp) {
            if (oldp && *oldlenp >= sizeof(uint64_t)) {
                *(uint64_t *)oldp = g_fakeMemSize;
                *oldlenp = sizeof(uint64_t);
                return 0;
            }
            *oldlenp = sizeof(uint64_t);
            if (oldp) return ENOMEM;
            return 0;
        }
        return 0;
    // v82F: 机型 / 主板 / 核数 / 开机时刻 全部按本克隆人格回。
    //   三条内核通道（hw.machine、hw.model、hw.ncpu）与 MG 侧必须同源，
    //   hw.model 只能给主板代号（D64AP），给机型串是物理上不可能的值。
    } else if (strcmp(name, "hw.machine") == 0) {
        if (g_fakeMachine[0]) fakeStr = g_fakeMachine;
    } else if (strcmp(name, "hw.model") == 0) {
        if (g_fakeHwModel[0]) fakeStr = g_fakeHwModel;
    } else if (strcmp(name, "hw.product") == 0 ||
               strcmp(name, "hw.target") == 0) {
        if (g_fakeHwModel[0]) fakeStr = g_fakeHwModel;
    } else if (strcmp(name, "kern.boottime") == 0) {
        struct timeval tv;
        memset(&tv, 0, sizeof(tv));
        tv.tv_sec = (time_t)(g_fakeBootSec > 0 ? g_fakeBootSec : (int64_t)time(NULL));
        tv.tv_usec = 137000;
        size_t need = sizeof(struct timeval);
        if (oldlenp) {
            if (oldp && *oldlenp >= need) { memcpy(oldp, &tv, need); *oldlenp = need; return 0; }
            *oldlenp = need;
            if (oldp) return ENOMEM;
            return 0;
        }
        return 0;
    } else if (strcmp(name, "hw.ncpu") == 0 ||
               strcmp(name, "hw.physicalcpu") == 0 ||
               strcmp(name, "hw.logicalcpu") == 0 ||
               strcmp(name, "hw.activecpu") == 0) {
        int v = g_fakeNCpu > 0 ? (int)g_fakeNCpu : 6;
        size_t need = sizeof(int);
        if (oldlenp) {
            if (oldp && *oldlenp >= need) { memcpy(oldp, &v, need); *oldlenp = need; return 0; }
            *oldlenp = need;
            if (oldp) return ENOMEM;
            return 0;
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
        // v82F: machine 与 sysctl hw.machine / MG ProductType 同一份值。
        //   release 保持真机的 Darwin 版本 —— 它跟着系统走，不跟机型走。
        if (g_fakeMachine[0]) {
            strncpy(name->machine, g_fakeMachine, sizeof(name->machine) - 1);
            name->machine[sizeof(name->machine) - 1] = '\0';
        }
        if (g_fakeHost[0]) {
            strncpy(name->nodename, g_fakeHost, sizeof(name->nodename) - 1);
            name->nodename[sizeof(name->nodename) - 1] = '\0';
        }
    }
    return ret;
}

// v81F: gethostname —— 真机 "1-4" 全克隆一致，与 kern.hostname/uname.nodename
//   必须同一份值，否则同一指标四个答案，既是泄漏也是矛盾。
static int hook_gethostname(char *name, size_t namelen) {
    if (!name || namelen == 0) return orig_gethostname ? orig_gethostname(name, namelen) : -1;
    @try {
        if (g_fakeHost[0]) {
            strlcpy(name, g_fakeHost, namelen);
            return 0;
        }
    } @catch (id e) {}
    return orig_gethostname ? orig_gethostname(name, namelen) : -1;
}

// v81F: CNCopyCurrentNetworkInfo —— SSID/BSSID 是路由器锚点，全克隆与原版一致。
//   iOS14+ 无定位权限本来也返回 NULL，返空不算异常。
static CFArrayRef hook_CNCopyCurrentNetworkInfo(CFStringRef ifName) {
    (void)ifName;
    return NULL;
}

// 前置声明 —— 以下函数在文件后段定义，C 需要先声明
static NSString *getPersistent(NSString *key, NSString *(^gen)(void));
static NSString *genDeviceName(void);
static NSString *genUUIDStr(void);
static NSString *FKEY(NSString *suffix);

// ============================================================
// v81F: MGCopyAnswer —— 只伪装唯一标识，硬件类全放行真实值
//
// 与上一版的关键差别：上一版根本没 hook MobileGestalt，于是
//   sysctl/uname 回「随机人格机型」而 MG 回真机 iPhone14,3，
//   一次交叉比对就露馅。这里反过来：机型/系统/主板全部真实，
//   只把 UDID/序列号/ECID/设备名换成每克隆唯一值。
// ============================================================
static CFPropertyListRef hook_MGCopyAnswer(CFStringRef key, CFDictionaryRef options) {
    if (!orig_MGCopyAnswer) return NULL;
    if (!key || g_inMGHook) return orig_MGCopyAnswer(key, options);
    g_inMGHook = YES;
    @try {
        if (CFStringCompare(key, CFSTR("J1WLa1FfC0Dowb1A"), 0) == 0 ||
            CFStringCompare(key, CFSTR("UniqueDeviceID"), 0) == 0) {
            NSString *u = getPersistent(FKEY(@"udid"), ^{ return genUUIDStr(); });
            g_inMGHook = NO;
            return (__bridge_retained CFPropertyListRef)u;
        }
        if (CFStringCompare(key, CFSTR("h9jDsbgj7xIugkIB2RVp1cKoVBOyBj8r"), 0) == 0 ||
            CFStringCompare(key, CFSTR("SerialNumber"), 0) == 0) {
            g_inMGHook = NO;
            return CFRetain(CFSTR(""));
        }
        if (CFStringCompare(key, CFSTR("UniqueChipID"), 0) == 0) {
            NSString *s = getPersistent(FKEY(@"ecid"), ^{
                uint64_t hi = ((uint64_t)arc4random() << 32) | (uint64_t)arc4random();
                return [NSString stringWithFormat:@"%llu", (unsigned long long)(hi & 0x00FFFFFFFFFFFFFFULL)];
            });
            uint64_t ecid = (uint64_t)[s longLongValue];
            g_inMGHook = NO;
            return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &ecid);
        }
        if (CFStringCompare(key, CFSTR("wfiZJ9aJbL5A3hMOznwq7A"), 0) == 0 ||
            CFStringCompare(key, CFSTR("DeviceName"), 0) == 0) {
            NSString *n = getPersistent(FKEY(@"dn"), ^{ return genDeviceName(); });
            g_inMGHook = NO;
            return (__bridge_retained CFPropertyListRef)n;
        }
        // v82F: 机型/主板/系统 —— 必须与 sysctl、uname、UIDevice 同一套值。
        //   v80F 漏掉这一层，sysctl 回伪机型而这里回真机 → 一次比对就露。
        if (CFStringCompare(key, CFSTR("ProductType"), 0) == 0) {
            NSString *m = g_fakeMachine[0] ? [NSString stringWithUTF8String:g_fakeMachine] : nil;
            g_inMGHook = NO;
            return m ? (__bridge_retained CFPropertyListRef)m : orig_MGCopyAnswer(key, options);
        }
        if (CFStringCompare(key, CFSTR("HardwareModel"), 0) == 0) {
            NSString *m = g_fakeHwModel[0] ? [NSString stringWithUTF8String:g_fakeHwModel] : nil;
            g_inMGHook = NO;
            return m ? (__bridge_retained CFPropertyListRef)m : orig_MGCopyAnswer(key, options);
        }
        if (CFStringCompare(key, CFSTR("OSVersion"), 0) == 0) {
            NSString *v = g_fakeOSVersion[0] ? [NSString stringWithUTF8String:g_fakeOSVersion] : nil;
            g_inMGHook = NO;
            return v ? (__bridge_retained CFPropertyListRef)v : orig_MGCopyAnswer(key, options);
        }
        if (CFStringCompare(key, CFSTR("BuildVersion"), 0) == 0) {
            NSString *v = g_fakeBuild[0] ? [NSString stringWithUTF8String:g_fakeBuild] : nil;
            g_inMGHook = NO;
            return v ? (__bridge_retained CFPropertyListRef)v : orig_MGCopyAnswer(key, options);
        }
        if (CFStringCompare(key, CFSTR("DeviceClass"), 0) == 0) {
            g_inMGHook = NO;
            return CFRetain(CFSTR("iPhone"));
        }
        g_inMGHook = NO;
    } @catch (id e) {
        g_inMGHook = NO;
    }
    return orig_MGCopyAnswer(key, options);
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
    // v81F: 系统版本不再伪造。
    //   伪造版本带来的是四处矛盾（UA 头 vs UA 尾 P2 段、原生 API vs WKWebView
    //   的 navigator、系统版本 vs 机型支撑矩阵），对「多开隔离」毫无帮助。
    //   这里直接返回真机版本，让所有通道天然自洽。
    if (g_fakeOSVersion[0]) return [NSString stringWithUTF8String:g_fakeOSVersion];
    char buf[64] = {0};
    size_t sz = sizeof(buf);
    if (sysctlbyname("kern.osproductversion", buf, &sz, NULL, 0) == 0 && buf[0])
        return [NSString stringWithUTF8String:buf];
    return @"16.1";
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
                 @"baiduid", @"bduss", @"stoken", @"ptoken",
                 // v81F: 百度统计（MTJ）设备 ID 族 —— 原版存在共享 keychain，
                 //   上一版按「非身份项」回退读入 → 与被拉黑原版共用统计 ID
                 @"mtj", @"cdid", @"umid", @"oaid", @"vaid", @"aaid"];
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

// ---- v69F: 本 clone 写过的 keychain 条目白名单 ----
// 思路：keychain 的写入/查询字段**全部原样透传**（保住度小满收银台），
// 只在「读取结果」这一层判断：属于 passport 共享登录组、且不是本 clone 写的条目，
// 一律剔除。这样既不碰支付，也不会把别的 clone 的 BDUSS 交出去。
static NSString *kcKeyOf(NSDictionary *d) {
    id svc = d[(__bridge id)kSecAttrService];
    id acct = d[(__bridge id)kSecAttrAccount];
    if (![svc isKindOfClass:[NSString class]]) svc = @"-";
    if (![acct isKindOfClass:[NSString class]]) acct = @"-";
    return [NSString stringWithFormat:@"%@\x1f%@", svc, acct];
}

static NSMutableSet *kcOwned(void) {
    static NSMutableSet *st = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        st = [NSMutableSet set];
        @try {
            CFPropertyListRef v = CFPreferencesCopyAppValue(
                (__bridge CFStringRef)FKEY(@"kcown"), kCFPreferencesCurrentApplication);
            if (v) {
                if (CFGetTypeID(v) == CFArrayGetTypeID()) {
                    for (id x in (__bridge NSArray *)v)
                        if ([x isKindOfClass:[NSString class]]) [st addObject:x];
                }
                CFRelease(v);
            }
        } @catch (id e) {}
    });
    return st;
}

static void kcRemember(NSDictionary *d) {
    @try {
        if (![d isKindOfClass:[NSDictionary class]]) return;
        NSMutableSet *st = kcOwned();
        NSString *k = kcKeyOf(d);
        if ([st containsObject:k]) return;
        [st addObject:k];
        NSArray *a = st.allObjects;
        if (a.count > 400) a = [a subarrayWithRange:NSMakeRange(a.count - 400, 400)];
        CFPreferencesSetAppValue((__bridge CFStringRef)FKEY(@"kcown"),
                                 (__bridge CFPropertyListRef)a,
                                 kCFPreferencesCurrentApplication);
        CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
    } @catch (id e) {}
}

static BOOL kcIsOwned(NSDictionary *d) {
    @try { return [kcOwned() containsObject:kcKeyOf(d)]; } @catch (id e) {}
    return NO;
}

// v71F: 清空白名单（重跑认领时用）
static void kcForgetAll(void) {
    @try {
        [kcOwned() removeAllObjects];
        CFPreferencesSetAppValue((__bridge CFStringRef)FKEY(@"kcown"),
                                 (__bridge CFArrayRef)@[],
                                 kCFPreferencesCurrentApplication);
        CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
    } @catch (id e) {}
}

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
        fprintf(f, "[KC-%s] st=%d svc=%s acct=%s\n", op, (int)st,
                svc.UTF8String, acct.UTF8String);
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
        ks = @[@"shareloginaccount", @"sapi_share_login", @"baiducuid", @"passport.bduss",
               @"bduss", @"stoken", @"ptoken",
               // v77F: keychain 里的设备 ID 组，全机共享，必须一起私有化
               @"baidumobile.cuid", @"baidumobile.maincuid"];
    });
    for (NSString *k in ks) {
        if ([l rangeOfString:k].location != NSNotFound) return YES;
    }
    return NO;
}

// 判定：必须是「登录票据」才隔离。
//   account 命中关键词，或 service 显式带登录语义；
//   仅凭 service = com.baidu.BaiduMobile 不隔离 —— 钱包也用这条 service。
static BOOL kcBaiduIDDict(NSDictionary *d) {
    if (![d isKindOfClass:[NSDictionary class]]) return NO;
    id acct = d[(__bridge id)kSecAttrAccount];
    if (kcBaiduIDStr(acct)) return YES;
    id svc = d[(__bridge id)kSecAttrService];
    if ([svc isKindOfClass:[NSString class]]) {
        NSString *l = [(NSString *)svc lowercaseString];
        if ([l rangeOfString:@"shareloginaccount"].location != NSNotFound) return YES;
        if ([l rangeOfString:@"passport.bduss"].location != NSNotFound) return YES;
        if ([l rangeOfString:@"baiducuid"].location != NSNotFound) return YES;
        // v77F: com.baidu.baidumobile.mainCUID / cuidDeviceInfo / cuidPrevious
        if ([l rangeOfString:@"baidumobile.cuid"].location != NSNotFound) return YES;
        if ([l rangeOfString:@"baidumobile.maincuid"].location != NSNotFound) return YES;
    }
    return NO;
}

static BOOL kcShareLoginItem(NSDictionary *item) {
    if (![item isKindOfClass:[NSDictionary class]]) return NO;
    id ag = item[(__bridge id)kSecAttrAccessGroup];
    if (![ag isKindOfClass:[NSString class]]) return NO;
    return [((NSString *)ag).lowercaseString rangeOfString:@"shareloginaccount"].location != NSNotFound;
}

// v77F: keychain 设备 ID 组（B83JBVZ6M5.com.baidu.baidumobile.cuid）
// 里面是 mainCUID(50 字符 32hex+18字母)、cuidDeviceInfo(机型)、cuidPrevious。
// 全机共享一份，所有 clone 上报同一个设备 ID —— 这是多开被识别的根因。
static BOOL kcCuidItem(NSDictionary *d) {
    if (![d isKindOfClass:[NSDictionary class]]) return NO;
    id ag = d[(__bridge id)kSecAttrAccessGroup];
    if (![ag isKindOfClass:[NSString class]]) return NO;
    return [((NSString *)ag).lowercaseString rangeOfString:@"baidumobile.cuid"].location != NSNotFound;
}

// 只剔除「别人写进共享登录组」的条目；本 clone 写过的放行
// ---- v73F: 实例私有 service 命名空间 ----
// 登录票据统一存到 "原名.BdFn" 下，读取时再还原成原名返回上层。
// 这样每个 clone 物理上只有自己那一份，不会互相看见，也不影响支付链路。
static BOOL kcIsPrivSvc(NSString *s) {
    if (![s isKindOfClass:[NSString class]] || s.length == 0) return NO;
    return [s hasSuffix:kcSuffix()];
}

static NSString *kcBaseStr(NSString *s) {
    if (![s isKindOfClass:[NSString class]] || s.length == 0) return s;
    NSString *t = s;
    NSString *sfx = kcSuffix();
    if ([t hasSuffix:sfx] && t.length > sfx.length)
        t = [t substringToIndex:t.length - sfx.length];
    NSString *pre = [NSString stringWithFormat:@"bdpriv.%@.", fpx()];
    if ([t hasPrefix:pre] && t.length > pre.length)
        t = [t substringFromIndex:pre.length];
    return t;
}

// 判定 service/account 是否带「别的实例」后缀（.BdF3 / .BdF4 ...）
// v73F 迁移时把这类条目也当源复制了，导致 F6 把 F3/F4 的票据也吃进来。
static BOOL kcIsForeignSvc(NSString *s) {
    if (![s isKindOfClass:[NSString class]] || s.length == 0) return NO;
    NSString *b = kcBaseStr(s);
    NSRange r = [b rangeOfString:@".BdF" options:NSBackwardsSearch];
    if (r.location == NSNotFound) return NO;
    NSString *tail = [b substringFromIndex:r.location + 4];
    if (tail.length == 0) return NO;
    for (NSUInteger i = 0; i < tail.length; i++) {
        unichar c = [tail characterAtIndex:i];
        if (c < '0' || c > '9') return NO;
    }
    return YES;
}

static BOOL kcIsPrivLogin(NSDictionary *d) {
    id svc  = d[(__bridge id)kSecAttrService];
    id acct = d[(__bridge id)kSecAttrAccount];
    // 只认 "原名.BdFn" 这一种私有形式。
    // bdpriv.BdFn.* 是 v67F 的遗留副本，仅作迁移来源，不再对外暴露。
    return (kcIsPrivSvc(svc) || kcIsPrivSvc(acct));
}

// 总是返回 +1 的新字典，service/account 去掉后缀
static CFTypeRef kcStripCopy(NSDictionary *d) {
    NSMutableDictionary *m = [d mutableCopy];
    id svc  = d[(__bridge id)kSecAttrService];
    id acct = d[(__bridge id)kSecAttrAccount];
    if ([svc isKindOfClass:[NSString class]]) {
        NSString *b = kcBaseStr((NSString *)svc);
        if (b) m[(__bridge id)kSecAttrService] = b;
    }
    if ([acct isKindOfClass:[NSString class]]) {
        NSString *b = kcBaseStr((NSString *)acct);
        if (b) m[(__bridge id)kSecAttrAccount] = b;
    }
    return (__bridge_retained CFTypeRef)[m copy];
}

// 共享登录组：只放行本实例私有条目；其它一律剔除（防串号）
static CFTypeRef kcFilterLoginShared(CFTypeRef res) {
    if (!res) return res;
    if (CFGetTypeID(res) == CFDictionaryGetTypeID()) {
        NSDictionary *d = (__bridge NSDictionary *)res;
        if ((kcShareLoginItem(d) || kcCuidItem(d)) && !kcIsPrivLogin(d)) { CFRelease(res); return NULL; }
        CFTypeRef out = kcStripCopy(d);
        CFRelease(res);
        return out;
    }
    if (CFGetTypeID(res) != CFArrayGetTypeID()) return res;
    CFArrayRef arr = (CFArrayRef)res;
    CFIndex n = CFArrayGetCount(arr);
    CFMutableArrayRef out = CFArrayCreateMutable(NULL, n, &kCFTypeArrayCallBacks);
    if (!out) return res;
    for (CFIndex i = 0; i < n; i++) {
        CFTypeRef o = CFArrayGetValueAtIndex(arr, i);
        if (!o || CFGetTypeID(o) != CFDictionaryGetTypeID()) { CFArrayAppendValue(out, o); continue; }
        NSDictionary *d = (__bridge NSDictionary *)o;
        if ((kcShareLoginItem(d) || kcCuidItem(d)) && !kcIsPrivLogin(d)) continue;
        CFTypeRef so = kcStripCopy(d);
        CFArrayAppendValue(out, so);
        CFRelease(so);
    }
    CFRelease(res);
    return out;
}

static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef *) = NULL;
static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *) = NULL;
static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef, CFDictionaryRef) = NULL;
static OSStatus (*orig_SecItemDelete)(CFDictionaryRef) = NULL;

// ============================================================
// v71F: 认领共享登录组票据（只抓本实例的）+ 诊断日志
//
// v70F 不加区分地把共享组里所有票据都认领成本实例的，结果 F3 把 F2
// 刚登录写进去的 BDUSS 也吃进来 → 直接串号。
//
// v71F 挑选顺序：
//   1. service/account 里带本实例后缀（BdF3）的 → 只认领这些；
//   2. 一条都没有时才退回全量认领（保证不掉登录）。
// 同时把共享组每条票据的 service/account/agrp 明文写进 Documents/kc_dump.log。
// ============================================================
static void kcDumpLine(NSString *line) {
    @try {
        NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                            NSUserDomainMask, YES) firstObject];
        if (dir.length == 0) return;
        NSString *p = [dir stringByAppendingPathComponent:@"kc_dump.log"];
        FILE *f = fopen(p.UTF8String, "a");
        if (!f) return;
        fprintf(f, "%s\n", line.UTF8String);
        fclose(f);
    } @catch (id e) {}
}

// ============================================================
// v73F: 把共享登录票据迁移进本实例私有命名空间（只做一次）
//
// 源优先级：
//   3  sapi_xxx.BdFn            （本实例此前已私有化，最可信）
//   2  bdpriv.BdFn.sapi_xxx.BdFn（v67F 时代留下的私有副本）
//   1  基名 sapi_xxx             （共享，最后才用）
// 每个逻辑键只取一个源，已有私有条目的跳过。
// ============================================================
// ============================================================
// v75F: cuid 组取证（只读，不改行为）
//
// keychain 里 B83JBVZ6M5.com.baidu.baidumobile.cuid 是全机共享的，
// 7 条，所有 clone 读到同一个设备 ID —— 这是「多开几个就被检测到」的直接原因。
// 先把这个组的 service/account/data 明文抓出来，再决定怎么派生独立值。
// ============================================================
static void kcDumpCuidGroup(void) {
    @try {
        NSDictionary *q = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
                            (__bridge id)kSecReturnAttributes: @YES,
                            (__bridge id)kSecReturnData: @YES};
        CFTypeRef all = NULL;
        OSStatus st = orig_SecItemCopyMatching((__bridge CFDictionaryRef)q, &all);
        if (st != errSecSuccess || !all) { if (all) CFRelease(all); return; }

        NSArray *arr = nil;
        if (CFGetTypeID(all) == CFArrayGetTypeID()) arr = (__bridge NSArray *)all;
        else if (CFGetTypeID(all) == CFDictionaryGetTypeID()) arr = @[(__bridge id)all];

        NSString *udCuid = [[NSUserDefaults standardUserDefaults] stringForKey:FKEY(@"ck.cuid")];
        NSString *udBcuid = [[NSUserDefaults standardUserDefaults] stringForKey:FKEY(@"ck.BAIDUCUID")];
        kcDumpLine([NSString stringWithFormat:@"[CUID-HEAD] fpx=%@ ud.cuid=%@ ud.BAIDUCUID=%@",
                    fpx(), udCuid ?: @"-", udBcuid ?: @"-"]);

        int n = 0;
        for (id o in arr) {
            if (![o isKindOfClass:[NSDictionary class]]) continue;
            NSDictionary *d = (NSDictionary *)o;
            id ag = d[(__bridge id)kSecAttrAccessGroup];
            if (![ag isKindOfClass:[NSString class]]) continue;
            if ([((NSString *)ag).lowercaseString rangeOfString:@"baidumobile.cuid"].location == NSNotFound) continue;

            id svc  = d[(__bridge id)kSecAttrService];
            id acct = d[(__bridge id)kSecAttrAccount];
            NSData *data = d[(__bridge id)kSecValueData];
            NSString *ds = @"-";
            NSString *extra = @"";
            if ([data isKindOfClass:[NSData class]]) {
                NSString *t = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                if (t && t.length) {
                    ds = t;
                } else {
                    ds = [data base64EncodedStringWithOptions:0];
                    NSString *u16 = [[NSString alloc] initWithData:data
                                                          encoding:NSUTF16LittleEndianStringEncoding];
                    if (u16.length && u16.length < 500)
                        extra = [NSString stringWithFormat:@" u16=%@", u16];
                    NSMutableString *hx = [NSMutableString string];
                    const uint8_t *bp = data.bytes;
                    NSUInteger lim = MIN(data.length, (NSUInteger)48);
                    for (NSUInteger i = 0; i < lim; i++) [hx appendFormat:@"%02x", bp[i]];
                    extra = [extra stringByAppendingFormat:@" hex=%@", hx];
                }
            }
            if (ds.length > 500) ds = [ds substringToIndex:500];
            kcDumpLine([NSString stringWithFormat:@"[CUID] svc=%@ acct=%@ len=%lu data=%@%@",
                        svc, acct, (unsigned long)([data isKindOfClass:[NSData class]] ? [(NSData *)data length] : 0),
                        ds, extra]);
            n++;
        }
        CFRelease(all);
        kcDumpLine([NSString stringWithFormat:@"[CUID-TAIL] total=%d", n]);
    } @catch (id e) {}
}


// ============================================================
// v78F: App Group 容器隔离 + 推送设备 ID 重写
//
// 为什么：
//   设备上 group.com.baidu.BaiduMobile 只有一个物理容器
//   （/private/var/mobile/Containers/Shared/AppGroup/BAE9285C-...），
//   所有 clone 共用同一份 Library/Preferences/group.com.baidu.BaiduMobile.plist。
//   里面 BNPush_cuid = 431D8F7F709192B450E8B66066346C917CCC81615OLJCPRRFGN，
//   格式与 keychain mainCUID 完全一致，是百度侧真正的设备 ID。
//   之前只映射了 CFPreferences 的 suite 名，SDK 只要拿 group 路径直接读文件就绕过。
//
// 做法：
//   1. hook -[NSFileManager containerURLForSecurityApplicationGroupIdentifier:]
//      → 返回 App 沙盒内 Library/PrivGroups/<group>.<BdFn> 的私有容器；
//      首次调用时把真实容器整份复制过来，此后各 clone 各自演化。
//   2. 私有容器里的 group plist 把 BNPush_cuid / BNPush_cacheCuid
//      改成本实例派生值（40 hex + 10 字母，与百度格式一致，稳定不漂移）。
//   3. 同步写入私有 CFPreferences 域，保证两条读取路径一致。
// ============================================================
static IMP g_origGroupURL = NULL;

static NSString *agSeed(void) {
    static NSString *s = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        @try {
            CFPropertyListRef v = CFPreferencesCopyAppValue(
                (__bridge CFStringRef)FKEY(@"gseed"), kCFPreferencesCurrentApplication);
            if (v) {
                if (CFGetTypeID(v) == CFStringGetTypeID()) s = [(__bridge NSString *)v copy];
                CFRelease(v);
            }
            if (s.length == 0) {
                s = [[NSUUID UUID] UUIDString];
                CFPreferencesSetAppValue((__bridge CFStringRef)FKEY(@"gseed"),
                                         (__bridge CFStringRef)s,
                                         kCFPreferencesCurrentApplication);
                CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
            }
        } @catch (id e) {}
        if (s.length == 0) s = fpx();
    });
    return s;
}

static uint32_t agMix(const char *str, uint32_t seed) {
    uint32_t h = 2166136261u ^ seed;
    if (!str) return h;
    while (*str) {
        h ^= (uint32_t)(unsigned char)(*str++);
        h *= 16777619u;
    }
    h ^= h >> 13;
    h *= 0x5bd1e995u;
    h ^= h >> 15;
    return h;
}

// 40 位大写 HEX + 10 位小写字母，与 BNPush_cuid / mainCUID 同构
static NSString *agFakeCuid(void) {
    static NSString *c = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *seed = [NSString stringWithFormat:@"%@|%@|devid", agSeed(), fpx()];
        const char *p = seed.UTF8String;
        NSMutableString *hex = [NSMutableString stringWithCapacity:40];
        for (uint32_t i = 0; i < 5; i++) [hex appendFormat:@"%08X", agMix(p, i * 0x9E3779B9u + 1)];
        NSMutableString *tail = [NSMutableString stringWithCapacity:10];
        uint32_t v = agMix(p, 0xDEADBEEFu);
        for (int i = 0; i < 10; i++) {
            uint32_t sh = (uint32_t)((i * 5) % 25);
            [tail appendFormat:@"%c", (char)('a' + ((v >> sh) & 0x1F) % 26)];
        }
        c = [hex stringByAppendingString:tail];
    });
    return c;
}

static NSString *agPrivRoot(void) {
    static NSString *r = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        r = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/PrivGroups"];
        [[NSFileManager defaultManager] createDirectoryAtPath:r
                                  withIntermediateDirectories:YES
                                                   attributes:nil
                                                        error:NULL];
    });
    return r;
}

static NSString *agPrivPath(NSString *gid) {
    NSString *safe = [gid stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    return [agPrivRoot() stringByAppendingPathComponent:
            [safe stringByAppendingFormat:@".%@", fpx()]];
}

static void agSyncPrefs(NSString *gid, NSString *devid) {
    @try {
        NSString *ms = mapGroupSuite(gid);
        if (ms.length == 0 || !orig_CFPrefSetAppValue) return;
        CFStringRef msRef = (__bridge CFStringRef)ms;
        orig_CFPrefSetAppValue((__bridge CFStringRef)@"BNPush_cuid",
                               (__bridge CFStringRef)devid, msRef);
        orig_CFPrefSetAppValue((__bridge CFStringRef)@"BNPush_cacheCuid",
                               (__bridge CFStringRef)devid, msRef);
        CFPreferencesAppSynchronize(msRef);
    } @catch (id e) {}
}

static void agRewritePlist(NSString *privBase, NSString *gid) {
    @try {
        NSString *pp = [privBase stringByAppendingPathComponent:
                        [NSString stringWithFormat:@"Library/Preferences/%@.plist", gid]];
        NSMutableDictionary *m = [NSMutableDictionary dictionaryWithContentsOfFile:pp];
        if (!m) return;
        NSString *devid = agFakeCuid();
        BOOL changed = NO;
        for (NSString *k in [m allKeys]) {
            if (![k isKindOfClass:[NSString class]]) continue;
            if ([k.lowercaseString rangeOfString:@"cuid"].location == NSNotFound) continue;
            if (![m[k] isKindOfClass:[NSString class]]) continue;
            if ([m[k] isEqualToString:devid]) continue;
            m[k] = devid;
            changed = YES;
        }
        if (changed) {
            [m writeToFile:pp atomically:YES];
            kcDumpLine([NSString stringWithFormat:@"[AG] rewrite %@ cuid=%@", gid, devid]);
        }
    } @catch (id e) {}
}

// 递归复制，跳过容器元数据（复制它一定会因 identifier 不匹配被拒）
static void agCopyTree(NSString *src, NSString *dst) {
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm createDirectoryAtPath:dst withIntermediateDirectories:YES attributes:nil error:NULL];
    NSArray *items = [fm contentsOfDirectoryAtPath:src error:NULL];
    int okN = 0, failN = 0;
    for (NSString *it in items) {
        if ([it hasPrefix:@".com.apple.mobile_container_manager"]) continue;
        NSString *sp = [src stringByAppendingPathComponent:it];
        NSString *dp = [dst stringByAppendingPathComponent:it];
        BOOL isDir = NO;
        if (![fm fileExistsAtPath:sp isDirectory:&isDir]) continue;
        if (isDir) {
            agCopyTree(sp, dp);
            okN++;
        } else {
            if (![fm fileExistsAtPath:dp]) {
                if ([fm copyItemAtPath:sp toPath:dp error:NULL]) okN++; else failN++;
            } else okN++;
        }
    }
    if (failN > 0) {
        kcDumpLine([NSString stringWithFormat:@"[AG] tree %@ ok=%d fail=%d",
                    [src lastPathComponent], okN, failN]);
    }
}

static void agPrepare(NSString *realBase, NSString *privBase, NSString *gid) {
    @try {
        NSFileManager *fm = [NSFileManager defaultManager];
        if (realBase.length == 0 || privBase.length == 0) return;

        NSString *privPrefs = [privBase stringByAppendingPathComponent:@"Library/Preferences"];
        BOOL needCopy = ![fm fileExistsAtPath:privPrefs];
        if (needCopy) {
            // v79F: v78F 用 copyItemAtPath 整目录复制，被 .metadata.plist 的权限卡住，
            // 结果私有容器一直是空的 —— SDK 读不到配置，功能反而更差。
            // 改为递归复制并跳过元数据文件。
            [fm removeItemAtPath:privBase error:NULL];
            [fm createDirectoryAtPath:agPrivRoot()
          withIntermediateDirectories:YES attributes:nil error:NULL];
            agCopyTree(realBase, privBase);
            kcDumpLine([NSString stringWithFormat:@"[AG] copy done %@ -> %@", gid, privBase]);
        }
        agRewritePlist(privBase, gid);
        agSyncPrefs(gid, agFakeCuid());
    } @catch (id e) {}
}

static NSURL *hook_groupContainerURL(id self, SEL _cmd, NSString *gid) {
    NSURL *real = NULL;
    if (g_origGroupURL)
        real = ((NSURL *(*)(id, SEL, NSString *))g_origGroupURL)(self, _cmd, gid);
    @try {
        if (gid.length && isGroupDomainStr(gid) && real.path.length) {
            NSString *priv = agPrivPath(gid);
            agPrepare(real.path, priv, gid);
            return [NSURL fileURLWithPath:priv isDirectory:YES];
        }
    } @catch (id e) {}
    return real;
}

static void kcMigrate(void) {
    @try {
        // v75F: 一次性抓 cuid 组结构
        CFPropertyListRef vd = CFPreferencesCopyAppValue(
            (__bridge CFStringRef)FKEY(@"kcvd3"), kCFPreferencesCurrentApplication);
        if (!vd) {
            if (orig_SecItemCopyMatching) kcDumpCuidGroup();
            CFPreferencesSetAppValue((__bridge CFStringRef)FKEY(@"kcvd3"),
                                     kCFBooleanTrue, kCFPreferencesCurrentApplication);
            CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
        } else { CFRelease(vd); }

        // v74F: kcv5 控制。v73F 已写过 kcv4 的机器要重跑一次清理。
        CFPropertyListRef v5 = CFPreferencesCopyAppValue(
            (__bridge CFStringRef)FKEY(@"kcv5"), kCFPreferencesCurrentApplication);
        if (v5) { CFRelease(v5); return; }
        if (!orig_SecItemCopyMatching) return;

        NSDictionary *q = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
                            (__bridge id)kSecReturnAttributes: @YES,
                            (__bridge id)kSecReturnData: @YES};
        CFTypeRef all = NULL;
        OSStatus st = orig_SecItemCopyMatching((__bridge CFDictionaryRef)q, &all);
        if (st != errSecSuccess || !all) { if (all) CFRelease(all); return; }

        NSArray *arr = nil;
        if (CFGetTypeID(all) == CFArrayGetTypeID()) arr = (__bridge NSArray *)all;
        else if (CFGetTypeID(all) == CFDictionaryGetTypeID()) arr = @[(__bridge id)all];

        // ---- 1. 先清掉 v73F 复制出来的伪私有票据 ----
        //   判据：① 带别的实例后缀（.BdF3.BdF6 这类）；
        //         ② 内容与共享池里的基名条目完全相同（说明是复制品，不是自己登录写的）。
        NSMutableDictionary *baseData = [NSMutableDictionary dictionary];
        for (id o in arr) {
            if (![o isKindOfClass:[NSDictionary class]]) continue;
            NSDictionary *d = (NSDictionary *)o;
            if (!kcShareLoginItem(d)) continue;
            id svc = d[(__bridge id)kSecAttrService], acct = d[(__bridge id)kSecAttrAccount];
            if (![svc isKindOfClass:[NSString class]] || ![acct isKindOfClass:[NSString class]]) continue;
            if (kcIsPrivSvc(svc) || [(NSString *)svc hasPrefix:@"bdpriv."]) continue;
            id v = d[(__bridge id)kSecValueData];
            if (v) baseData[[NSString stringWithFormat:@"%@\x1f%@", svc, acct]] = v;
        }

        int purged = 0;
        for (id o in arr) {
            if (![o isKindOfClass:[NSDictionary class]]) continue;
            NSDictionary *d = (NSDictionary *)o;
            if (!kcShareLoginItem(d)) continue;
            id svc = d[(__bridge id)kSecAttrService], acct = d[(__bridge id)kSecAttrAccount];
            if (![svc isKindOfClass:[NSString class]] || ![acct isKindOfClass:[NSString class]]) continue;
            if (!kcIsPrivSvc(svc) && !kcIsPrivSvc(acct)) continue;
            // v67F 的 bdpriv.BdFn.* 是真实历史副本，保留不动
            if ([(NSString *)svc hasPrefix:@"bdpriv."]) continue;

            BOOL foreign = kcIsForeignSvc((NSString *)svc) || kcIsForeignSvc((NSString *)acct);
            BOOL copied = NO;
            if (!foreign) {
                NSString *bk = [NSString stringWithFormat:@"%@\x1f%@",
                                kcBaseStr((NSString *)svc), kcBaseStr((NSString *)acct)];
                NSData *bv = baseData[bk];
                id pv = d[(__bridge id)kSecValueData];
                copied = (bv && pv && [pv isKindOfClass:[NSData class]] && [bv isEqualToData:(NSData *)pv]);
            }
            if (!foreign && !copied) continue;

            NSMutableDictionary *dq = [NSMutableDictionary dictionary];
            dq[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
            dq[(__bridge id)kSecAttrService] = svc;
            dq[(__bridge id)kSecAttrAccount] = acct;
            id ag = d[(__bridge id)kSecAttrAccessGroup];
            if (ag) dq[(__bridge id)kSecAttrAccessGroup] = ag;
            if (orig_SecItemDelete((__bridge CFDictionaryRef)dq) == errSecSuccess) purged++;
        }

        // ---- 2. 只认本实例真实私有源，不再用共享池兜底 ----
        NSString *pre = [NSString stringWithFormat:@"bdpriv.%@.", fpx()];
        NSMutableDictionary *best = [NSMutableDictionary dictionary];
        NSMutableSet *hasPriv = [NSMutableSet set];

        for (id o in arr) {
            if (![o isKindOfClass:[NSDictionary class]]) continue;
            NSDictionary *d = (NSDictionary *)o;
            if (!kcShareLoginItem(d)) continue;
            id svc = d[(__bridge id)kSecAttrService], acct = d[(__bridge id)kSecAttrAccount];
            if (![svc isKindOfClass:[NSString class]] || ![acct isKindOfClass:[NSString class]]) continue;
            if (kcIsForeignSvc((NSString *)svc) || kcIsForeignSvc((NSString *)acct)) continue;

            NSString *lsvc = kcBaseStr((NSString *)svc), *lacct = kcBaseStr((NSString *)acct);
            NSString *key = [NSString stringWithFormat:@"%@\x1f%@", lsvc, lacct];

            int pri = 0;
            if (kcIsPrivSvc((NSString *)svc) && ![(NSString *)svc hasPrefix:@"bdpriv."]) pri = 3;
            else if ([(NSString *)svc hasPrefix:pre]) pri = 2;
            if (pri == 0) continue;   // 基名与其它来源一律不用
            if (pri == 3) [hasPriv addObject:key];

            NSArray *cur = best[key];
            if (!cur || [(NSNumber *)cur[0] intValue] < pri) best[key] = @[@(pri), d];
        }

        int added = 0, skipped = 0, failed = 0;
        for (NSString *key in best) {
            if ([hasPriv containsObject:key]) { skipped++; continue; }
            NSDictionary *d = best[key][1];
            NSString *svc = d[(__bridge id)kSecAttrService], *acct = d[(__bridge id)kSecAttrAccount];
            NSMutableDictionary *a = [NSMutableDictionary dictionary];
            a[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
            a[(__bridge id)kSecAttrService] = [kcBaseStr(svc) stringByAppendingString:kcSuffix()];
            a[(__bridge id)kSecAttrAccount] = [kcBaseStr(acct) stringByAppendingString:kcSuffix()];
            id v = d[(__bridge id)kSecValueData];
            if (v) a[(__bridge id)kSecValueData] = v;
            id ag = d[(__bridge id)kSecAttrAccessGroup];
            if (ag) a[(__bridge id)kSecAttrAccessGroup] = ag;
            id acc = d[(__bridge id)kSecAttrAccessible];
            if (acc) a[(__bridge id)kSecAttrAccessible] = acc;
            OSStatus s2 = orig_SecItemAdd((__bridge CFDictionaryRef)a, NULL);
            if (s2 == errSecSuccess || s2 == errSecDuplicateItem) added++;
            else failed++;
        }
        CFRelease(all);

        kcDumpLine([NSString stringWithFormat:@"[MIGRATE2] fpx=%@ keys=%lu purged=%d added=%d skipped=%d failed=%d",
                    fpx(), (unsigned long)best.count, purged, added, skipped, failed]);

        CFPreferencesSetAppValue((__bridge CFStringRef)FKEY(@"kcv5"),
                                 kCFBooleanTrue, kCFPreferencesCurrentApplication);
        CFPreferencesSetAppValue((__bridge CFStringRef)FKEY(@"kcadopt"),
                                 kCFBooleanTrue, kCFPreferencesCurrentApplication);
        CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
    } @catch (id e) {}
}

static OSStatus hook_SecItemAdd(CFDictionaryRef attrs, CFTypeRef *result) {
    if (!orig_SecItemAdd) return errSecParam;
    // 非登录票据：原样透传
    if (!kcBaiduIDDict((__bridge NSDictionary *)attrs)) {
        OSStatus st0 = orig_SecItemAdd(attrs, result);
        if (st0 == errSecSuccess) kcRemember((__bridge NSDictionary *)attrs);
        if (attrs && kcPayNS((__bridge NSDictionary *)attrs))
            kcLogPay("ADD-PASS", (__bridge NSDictionary *)attrs, st0);
        return st0;
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
    BOOL ident = query && kcBaiduIDDict((__bridge NSDictionary *)query);
    if (!ident) {
        OSStatus st0 = orig_SecItemCopyMatching(query, result);
        if (query && kcPayNS((__bridge NSDictionary *)query))
            kcLogPay("GET-PASS", (__bridge NSDictionary *)query, st0);
        if (st0 == errSecSuccess && result && *result) {
            @try {
                CFTypeRef f = kcFilterLoginShared(*result);
                *result = f;
                if (!f) return errSecItemNotFound;
            } @catch (id e) {}
        }
        return st0;
    }
    @try {
        CFDictionaryRef rq = kcRewrite(query);
        OSStatus st = rq ? orig_SecItemCopyMatching(rq, result)
                         : orig_SecItemCopyMatching(query, result);
        if (rq) CFRelease(rq);
        // v73F: 不再回退共享域。私有域就是唯一来源，读不到即未登录，
        // 但迁移做了兜底，正常情况下登录态不会丢。
        if (st != errSecSuccess) return st;
        if (result && *result) {
            CFTypeRef f = kcFilterLoginShared(*result);
            *result = f;
            if (!f) return errSecItemNotFound;
        }
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
        // 共享登录组：只允许删本 clone 写过的条目，避免把官方/其他 clone 的登录态删掉
        @try {
            NSDictionary *q = (__bridge NSDictionary *)query;
            if (kcShareLoginItem(q) && !kcIsOwned(q)) return errSecSuccess;
        } @catch (id e) {}
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
    // v81F: 农场入口取证 —— 进不去时把这条请求的参数与回包打出来
    NSString *full = u.absoluteString.lowercaseString ?: @"";
    if ([full containsString:@"nongchang"] || [full containsString:@"farm"] ||
        [full containsString:@"orchard"] || [full containsString:@"guoyuan"]) return YES;
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
// v81F: 克隆 App 枚举过滤
//   真机上 LSApplicationWorkspace 能列出所有 BdF1..BdF20，
//   一条 -allInstalledApplications 就是「多开实锤」。这里剔掉除自己
//   以外的所有 com.baidu.BaiduMobile.* （官方原版 com.baidu.BaiduMobile
//   保留 —— 谁手机上都可能装官方版，隐藏反而不正常）。
// ============================================================
static BOOL isCloneBundleID(NSString *bid) {
    if (bid.length == 0) return NO;
    if (![bid isKindOfClass:[NSString class]]) return NO;
    if (![bid hasPrefix:@"com.baidu.BaiduMobile."]) return NO;
    if (g_selfBundleID.length && [bid isEqualToString:g_selfBundleID]) return NO;
    return YES;
}

static NSArray *filterCloneApps(NSArray *apps) {
    if (![apps isKindOfClass:[NSArray class]] || apps.count == 0) return apps;
    NSMutableArray *out = [NSMutableArray arrayWithCapacity:apps.count];
    for (id a in apps) {
        @try {
            NSString *bid = nil;
            if ([a isKindOfClass:[NSString class]]) bid = a;
            else bid = [a valueForKey:@"bundleIdentifier"];
            if (isCloneBundleID(bid)) continue;
        } @catch (id e) {}
        [out addObject:a];
    }
    return out;
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
        // v69F 标记：keychain 全透传 + owned 白名单过滤共享登录组
        CFPreferencesSetAppValue((__bridge CFStringRef)FKEY(@"kco"),
                                 (__bridge CFStringRef)@"1",
                                 kCFPreferencesCurrentApplication);

        // ---- 0. v82F: 每克隆生成一台完整设备（机型成组伪造）----
        //   构造函数早于第 9 步的 fishhook，这里 sysctlbyname 仍是系统原函数，
        //   读到的才是真机值（系统版本要用它，见下）。
        char rb[128];
        size_t rsz;

        // 系统版本 / 构建号 / Darwin：保持真机。
        //   WKWebView 的 navigator.userAgent、H5 页 JS 取的都是系统真值，
        //   改不了；机型可以随便换，系统版本跟机型不绑定，抄真值最安全。
        rsz = sizeof(rb); memset(rb, 0, sizeof(rb));
        if (sysctlbyname("kern.osproductversion", rb, &rsz, NULL, 0) == 0 && rb[0])
            strlcpy(g_fakeOSVersion, rb, sizeof(g_fakeOSVersion));
        else
            strlcpy(g_fakeOSVersion, "16.1", sizeof(g_fakeOSVersion));
        rsz = sizeof(rb); memset(rb, 0, sizeof(rb));
        if (sysctlbyname("kern.osversion", rb, &rsz, NULL, 0) == 0 && rb[0])
            strlcpy(g_fakeBuild, rb, sizeof(g_fakeBuild));
        else
            strlcpy(g_fakeBuild, "20B82", sizeof(g_fakeBuild));
        rsz = sizeof(rb); memset(rb, 0, sizeof(rb));
        if (sysctlbyname("kern.osrelease", rb, &rsz, NULL, 0) == 0 && rb[0])
            strlcpy(g_fakeDarwinRel, rb, sizeof(g_fakeDarwinRel));
        else
            strlcpy(g_fakeDarwinRel, "22.1.0", sizeof(g_fakeDarwinRel));

        // 机型池：machine / 主板代号 / 内存GB / 逻辑核数 / 最低系统版本。
        //   最后一项是关键：iPhone15,x 出厂即 iOS17，跑 16.x 是物理不可能，
        //   这种「机型×系统」矛盾比同设备更容易被判伪装。
        NSArray *pool = @[
            @[@"iPhone13,2", @"D53GAP", @4, @6, @14],   // 12
            @[@"iPhone13,3", @"D54PAP", @6, @6, @14],   // 12 Pro
            @[@"iPhone14,2", @"D63AP",  @6, @6, @15],   // 13 Pro
            @[@"iPhone14,3", @"D64AP",  @6, @6, @15],   // 13 Pro Max
            @[@"iPhone14,5", @"D16AP",  @4, @6, @15],   // 13
            @[@"iPhone14,6", @"D49AP",  @4, @6, @15],   // SE3
            @[@"iPhone14,7", @"D27AP",  @6, @6, @16],   // 14
            @[@"iPhone14,8", @"D28AP",  @6, @6, @16],   // 14 Plus
            @[@"iPhone15,2", @"D73AP",  @6, @6, @16],   // 14 Pro
            @[@"iPhone15,3", @"D74AP",  @6, @6, @16],   // 14 Pro Max
            @[@"iPhone15,4", @"D37AP",  @6, @6, @17],   // 15
            @[@"iPhone15,5", @"D38AP",  @6, @6, @17]    // 15 Plus
        ];
        NSInteger osMajor = [[[NSString stringWithUTF8String:g_fakeOSVersion]
                              componentsSeparatedByString:@"."][0] integerValue];
        if (osMajor < 14) osMajor = 16;
        NSMutableArray *usable = [NSMutableArray array];
        for (NSArray *p in pool) {
            if ([p[4] integerValue] <= osMajor) [usable addObject:p];
        }
        if (usable.count == 0) usable = [pool mutableCopy];

        NSInteger ord = 1;
        @try {
            NSString *px = fpx();
            NSInteger acc = 0;
            for (NSUInteger i = 0; i < px.length; i++) {
                unichar c = [px characterAtIndex:i];
                if (c >= '0' && c <= '9') acc = acc * 10 + (c - '0');
            }
            if (acc > 0) ord = acc;
        } @catch (id e) {}
        NSArray *persona = usable[(NSUInteger)((ord - 1) % (NSInteger)usable.count)];
        NSString *fakeMachine = persona[0];
        strlcpy(g_fakeMachine, [fakeMachine UTF8String], sizeof(g_fakeMachine));
        strlcpy(g_fakeHwModel, [persona[1] UTF8String], sizeof(g_fakeHwModel));
        g_fakeMemSize = (uint64_t)[persona[2] unsignedLongLongValue] * 1024ULL * 1024ULL * 1024ULL;
        g_fakeNCpu = (uint32_t)[persona[3] unsignedIntValue];

        // 开机时刻：每克隆一个固定偏移，且持久化 —— 每次启动都变等于「反复重启」。
        uint32_t seedA = (uint32_t)(ord * 2654435761u);
        NSString *bootStr = getPersistent(FKEY(@"boot"), ^{
            int64_t now = (int64_t)time(NULL);
            int64_t off = (int64_t)(2 * 3600 + (seedA % (36 * 3600)));
            return [NSString stringWithFormat:@"%lld", (long long)(now - off)];
        });
        g_fakeBootSec = (int64_t)[bootStr longLongValue];
        if (g_fakeBootSec > 0) {
            int64_t up = (int64_t)time(NULL) - g_fakeBootSec;
            g_fakeUptime = up > 0 ? (double)up : 3600.0;
        }

        // 设备名 / 主机名必须同源：真机 gethostname == uname.nodename ==
        // NSProcessInfo.hostName == MG DeviceName，只多空格转连字符的差异。
        g_selfBundleID = [[NSBundle mainBundle] bundleIdentifier];
        NSString *dn0 = getPersistent(FKEY(@"dn"), ^{ return genDeviceName(); });
        NSString *host0 = [(dn0 ?: @"iPhone") stringByReplacingOccurrencesOfString:@" " withString:@"-"];
        strlcpy(g_fakeHost, [host0 UTF8String], sizeof(g_fakeHost));

        // 磁盘总容量：每克隆固定偏移，total 与 free 同步平移（已用量不变）
        NSString *diskStr = getPersistent(FKEY(@"disk"), ^{
            uint64_t GB = 1024ULL * 1024ULL * 1024ULL;
            uint64_t off = (8ULL + arc4random_uniform(25)) * GB;
            return [NSString stringWithFormat:@"%llu", off];
        });
        g_diskDelta = (long long)[diskStr longLongValue];

        // v82F 标记 + 画像落盘（装完看 bd_pay.log 首屏即可确认这版生效）
        CFPreferencesSetAppValue((__bridge CFStringRef)FKEY(@"v82"),
                                 (__bridge CFStringRef)@"1",
                                 kCFPreferencesCurrentApplication);
        pnLog(@"\n===== v82F PROFILE =====");
        pnLog(@"MACHINE=%s MODEL=%s ncpu=%u mem=%llu",
              g_fakeMachine, g_fakeHwModel, g_fakeNCpu,
              (unsigned long long)g_fakeMemSize);
        pnLog(@"OS=%s build=%s darwin=%s boot=%lld uptime=%.0f",
              g_fakeOSVersion, g_fakeBuild, g_fakeDarwinRel,
              (long long)g_fakeBootSec, g_fakeUptime);
        pnLog(@"HOST=%s diskDelta=%lld bundle=%s",
              g_fakeHost, g_diskDelta, g_selfBundleID.UTF8String ?: "-");

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

        // ---- 1z. v78F: App Group 容器隔离 ----
        @try {
            Class fmc = objc_getClass("NSFileManager");
            if (fmc) {
                SEL gs = @selector(containerURLForSecurityApplicationGroupIdentifier:);
                Method gm = class_getInstanceMethod(fmc, gs);
                if (gm) {
                    g_origGroupURL = method_getImplementation(gm);
                    class_replaceMethod(fmc, gs, (IMP)hook_groupContainerURL,
                                        method_getTypeEncoding(gm));
                }
            }
        } @catch (id e) {}

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
                        NSString *build = g_fakeBuild[0]
                            ? [NSString stringWithUTF8String:g_fakeBuild] : versionToBuild(sv);
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
                // v82F: boottime 既然伪了，uptime 必须跟着伪，否则
                //   now - boottime ≠ systemUptime，两值一减就露。
                Method suM = class_getInstanceMethod(pi, @selector(systemUptime));
                if (suM) {
                    IMP imp = imp_implementationWithBlock(^NSTimeInterval(id s) {
                        return g_fakeUptime > 0 ? g_fakeUptime : 3600.0;
                    });
                    class_replaceMethod(pi, @selector(systemUptime), imp, method_getTypeEncoding(suM));
                }
                Method hm = class_getInstanceMethod(pi, @selector(hostName));
                if (hm) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return g_fakeHost[0] ? [NSString stringWithUTF8String:g_fakeHost] : @"iPhone";
                    });
                    class_replaceMethod(pi, @selector(hostName), imp, method_getTypeEncoding(hm));
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

        // ---- 4b. v81F: 设备聚类通道（同机所有克隆完全一致、跨天稳定）----
        @try {
            // 4b-1. UIPasteboard —— 风控 SDK（TalosPro）会往剪贴板写设备标识，
            //   所有克隆共享同一块物理剪贴板 → 跨 App 串号。这里把 general 与
            //   命名剪贴板都私有化到本克隆命名空间。
            Class pbc = objc_getClass("UIPasteboard");
            if (pbc) {
                Class meta = object_getClass(pbc);
                SEL pnSel = NSSelectorFromString(@"pasteboardWithNamespace:");
                Method pnM = class_getInstanceMethod(meta, pnSel);
                if (pnM) {
                    g_origPBNamespace = method_getImplementation(pnM);
                    IMP impPN = imp_implementationWithBlock(^UIPasteboard *(id s, NSString *ns) {
                        if (!g_inPBCall && ns.length > 0 && ![ns hasPrefix:@"bdclone."]) {
                            g_inPBCall = YES;
                            @try {
                                return ((UIPasteboard *(*)(id, SEL, NSString *))g_origPBNamespace)(
                                    s, pnSel, [NSString stringWithFormat:@"bdclone.%@.%@", ns, fpx()]);
                            } @finally { g_inPBCall = NO; }
                        }
                        return ((UIPasteboard *(*)(id, SEL, NSString *))g_origPBNamespace)(s, pnSel, ns);
                    });
                    class_replaceMethod(meta, pnSel, impPN, method_getTypeEncoding(pnM));

                    SEL gpSel = @selector(generalPasteboard);
                    Method gpM = class_getInstanceMethod(meta, gpSel);
                    if (gpM) {
                        IMP impGP = imp_implementationWithBlock(^UIPasteboard *(id s) {
                            g_inPBCall = YES;
                            @try {
                                return ((UIPasteboard *(*)(id, SEL, NSString *))g_origPBNamespace)(
                                    s, pnSel, [NSString stringWithFormat:@"bdclone.general.%@", fpx()]);
                            } @finally { g_inPBCall = NO; }
                        });
                        class_replaceMethod(meta, gpSel, impGP, method_getTypeEncoding(gpM));
                    }

                    SEL pwnSel = NSSelectorFromString(@"pasteboardWithName:create:");
                    Method pwnM = class_getInstanceMethod(meta, pwnSel);
                    if (pwnM) {
                        g_origPBWithName = method_getImplementation(pwnM);
                        IMP impPWN = imp_implementationWithBlock(^UIPasteboard *(id s, NSString *name, BOOL create) {
                            if (name.length > 0 && ![name hasPrefix:@"bdclone."]) {
                                name = [NSString stringWithFormat:@"bdclone.%@.%@", name, fpx()];
                            }
                            return ((UIPasteboard *(*)(id, SEL, NSString *, BOOL))g_origPBWithName)(
                                s, pwnSel, name, create);
                        });
                        class_replaceMethod(meta, pwnSel, impPWN, method_getTypeEncoding(pwnM));
                    }
                }
            }
        } @catch (id e) {}
        @try {
            // 4b-2. DeviceCheck / App Attest —— Apple 服务器签名的设备证明，
            //   绑定物理设备，换 bundle id / 重装都无效。这是「同一台机器」
            //   最硬的证据，必须失败化（风控把它当可选信号，失败静默容忍）。
            Class dcd = objc_getClass("DCDevice");
            if (dcd) {
                SEL gtSel = NSSelectorFromString(@"generateTokenWithCompletionHandler:");
                Method gtM = class_getInstanceMethod(dcd, gtSel);
                if (gtM) {
                    IMP imp = imp_implementationWithBlock(^(id s, void (^h)(NSData *, NSError *)) {
                        if (h) h(nil, [NSError errorWithDomain:@"DCErrorDomain" code:1 userInfo:nil]);
                    });
                    class_replaceMethod(dcd, gtSel, imp, method_getTypeEncoding(gtM));
                }
            }
            Class dca = objc_getClass("DCAppAttestService");
            if (dca) {
                SEL gkSel = NSSelectorFromString(@"generateKeyWithCompletionHandler:");
                Method gkM = class_getInstanceMethod(dca, gkSel);
                if (gkM) {
                    IMP imp = imp_implementationWithBlock(^(id s, void (^h)(NSString *, NSError *)) {
                        if (h) h(nil, [NSError errorWithDomain:@"DCErrorDomain" code:1 userInfo:nil]);
                    });
                    class_replaceMethod(dca, gkSel, imp, method_getTypeEncoding(gkM));
                }
                SEL akSel = NSSelectorFromString(@"attestKey:clientDataHash:completionHandler:");
                Method akM = class_getInstanceMethod(dca, akSel);
                if (akM) {
                    IMP imp = imp_implementationWithBlock(^(id s, NSString *keyId, NSData *hash, void (^h)(NSError *)) {
                        if (h) h([NSError errorWithDomain:@"DCErrorDomain" code:1 userInfo:nil]);
                    });
                    class_replaceMethod(dca, akSel, imp, method_getTypeEncoding(akM));
                }
                SEL gaSel = NSSelectorFromString(@"generateAssertion:clientDataHash:completionHandler:");
                Method gaM = class_getInstanceMethod(dca, gaSel);
                if (gaM) {
                    IMP imp = imp_implementationWithBlock(^(id s, NSString *attestObj, NSData *hash, void (^h)(NSData *, NSError *)) {
                        if (h) h(nil, [NSError errorWithDomain:@"DCErrorDomain" code:1 userInfo:nil]);
                    });
                    class_replaceMethod(dca, gaSel, imp, method_getTypeEncoding(gaM));
                }
            }
        } @catch (id e) {}
        @try {
            // 4b-3. 磁盘总容量 —— 硬件属性，同机所有克隆一字不差
            Class fmc0 = objc_getClass("NSFileManager");
            SEL fsel = @selector(attributesOfFileSystemForPath:error:);
            Method fmm = class_getInstanceMethod(fmc0, fsel);
            if (fmm) {
                IMP of = method_getImplementation(fmm);
                IMP iff = imp_implementationWithBlock(^NSDictionary *(id s, NSString *path, NSError **err) {
                    NSDictionary *d = ((NSDictionary *(*)(id, SEL, NSString *, NSError **))of)(s, fsel, path, err);
                    if (!d || g_diskDelta <= 0) return d;
                    NSNumber *sz = d[@"NSFileSystemSize"];
                    if (![sz isKindOfClass:[NSNumber class]]) return d;
                    long long nv = [sz longLongValue] - g_diskDelta;
                    if (nv <= 0) return d;
                    NSMutableDictionary *md = [d mutableCopy];
                    md[@"NSFileSystemSize"] = @(nv);
                    NSNumber *fr = d[@"NSFileSystemFreeSize"];
                    if ([fr isKindOfClass:[NSNumber class]]) {
                        long long nf = [fr longLongValue] - g_diskDelta;
                        if (nf > 0 && nf <= nv) md[@"NSFileSystemFreeSize"] = @(nf);
                    }
                    return md;
                });
                class_replaceMethod(fmc0, fsel, iff, method_getTypeEncoding(fmm));
            }
        } @catch (id e) {}
        @try {
            // 4b-4. 已安装 App 枚举 —— 直接列出所有 BdF 克隆
            Class lsw = objc_getClass("LSApplicationWorkspace");
            if (!lsw) {
                dlopen("/System/Library/PrivateFrameworks/MobileCoreServices.framework/MobileCoreServices", RTLD_LAZY);
                lsw = objc_getClass("LSApplicationWorkspace");
            }
            if (lsw) {
                for (NSString *sn in @[@"allInstalledApplications",
                                       @"allApplications",
                                       @"installedApplications"]) {
                    SEL sl = NSSelectorFromString(sn);
                    Method m = class_getInstanceMethod(lsw, sl);
                    if (!m) continue;
                    IMP o = method_getImplementation(m);
                    IMP imp = imp_implementationWithBlock(^NSArray *(id s) {
                        NSArray *a = ((NSArray *(*)(id, SEL))o)(s, sl);
                        return filterCloneApps(a);
                    });
                    class_replaceMethod(lsw, sl, imp, method_getTypeEncoding(m));
                }
                SEL qs = NSSelectorFromString(@"applicationsForBundleIdentifier:");
                Method qm = class_getInstanceMethod(lsw, qs);
                if (qm) {
                    IMP oq = method_getImplementation(qm);
                    IMP impq = imp_implementationWithBlock(^NSArray *(id s, NSString *bid) {
                        if (isCloneBundleID(bid)) return @[];
                        return ((NSArray *(*)(id, SEL, NSString *))oq)(s, qs, bid);
                    });
                    class_replaceMethod(lsw, qs, impq, method_getTypeEncoding(qm));
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
            // v80F: 硬件兜底标识
            g_rebindings[10] = (struct rebinding){"gethostuuid",        (void *)hook_gethostuuid,         (void **)&orig_gethostuuid};
            // v81F: 补齐上一版漏掉的三条同机一致通道
            g_rebindings[11] = (struct rebinding){"gethostname",        (void *)hook_gethostname,         (void **)&orig_gethostname};
            g_rebindings[12] = (struct rebinding){"MGCopyAnswer",       (void *)hook_MGCopyAnswer,        (void **)&orig_MGCopyAnswer};
            g_rebindings[13] = (struct rebinding){"CNCopyCurrentNetworkInfo", (void *)hook_CNCopyCurrentNetworkInfo, (void **)&orig_CNCopyCurrentNetworkInfo};

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

        // ---- 10. v70F: 认领共享登录组里的既有票据 ----
        // 必须在 fishhook 装好之后（要用 orig_SecItemCopyMatching），
        // 也必须在 App 主程序发起任何 keychain 查询之前（constructor 满足）。
        // 做完这一步，本 clone 的白名单里就有了当前登录态所需的全部条目，
        // 打开 App 不会变成未登录。
        kcMigrate();
        CFPreferencesSetAppValue((__bridge CFStringRef)FKEY(@"kca"),
                                 (__bridge CFStringRef)@"1",
                                 kCFPreferencesCurrentApplication);
    }
}
