//
// PrivacyHook.m — v50: v49 (login preserved) + sysctlbyname fishhook (hardware fingerprint)
//
// THE MISSING COMBINATION:
//   v48b had sysctlbyname hook but cleared Keychain → couldn't login → couldn't test ordering
//   v49 preserved login but removed sysctlbyname → hw.machine returns REAL value → device detected
//   v50 = v49 login preservation + v48b sysctlbyname hook = UNTESTED BUT CRITICAL COMBINATION
//
// v50 NEW:
//   1. fishhook: sysctlbyname — hw.machine, hw.model, hw.memsize, hw.ncpu, kern.osversion
//      SAFE implementation: all fake values pre-computed as C strings at init time.
//      Hook function uses ONLY strcmp/memcpy/strlen — NO ObjC calls inside hook.
//      This was the crash cause in v48; v48b/v50 fix it by pre-computing.
//
//   2. Consistent device profiles — pick ONE real device, use ALL its specs:
//      hw.machine + hw.model + hw.memsize + kern.osversion + systemVersion
//      all match the same real device. Inconsistent values = server-side detection.
//
//   3. UIDevice.systemVersion hook — return version matching profile
//      (was missing in v49 — Baidu could read real OS version via UIDevice)
//
// v50 COOKIE CLEAR:
//   - Clear Cookie storage on first launch (BDUSS/STOKEN removed)
//   - Forces re-login = proves to Baidu this is a NEW device
//   - Keychain NOT cleared = login flow works correctly
//   - Bd50. prefix (force regenerate all fake IDs)
//   - All ObjC hooks (CUID, IDFV, IDFA, BIMBaiduUDID, etc.)
//   - Bundle ID 3-method hook (payment)
//   - Cookie read-only replacement
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#include "fishhook.h"
#include <sys/sysctl.h>
#include <string.h>
#include <errno.h>
#define NSLog(...)

static NSString *const kOrigBundleID = @"com.baidu.BaiduMobile";
static __thread BOOL g_inCookieHook = NO;
static BOOL g_inUDHook = NO;

// ============================================================
// Consistent device profiles
// ============================================================
typedef struct {
    const char *machine;     // hw.machine (e.g. "iPhone15,2")
    const char *model;       // hw.model (e.g. "D83AP")
    const char *osBuild;     // kern.osversion (e.g. "21F79")
    const char *sysVer;      // systemVersion (e.g. "17.5")
    uint64_t memSize;        // hw.memsize (bytes)
    uint32_t ncpu;           // hw.ncpu
} DeviceProfile;

static DeviceProfile g_profiles[] = {
    {"iPhone15,2", "D83AP", "21F79",   "17.5", 6ULL*1024*1024*1024, 6},  // iPhone 14 Pro
    {"iPhone15,4", "D16AP", "21G80",   "17.6", 6ULL*1024*1024*1024, 6},  // iPhone 15
    {"iPhone16,1", "D83AP", "22C152",  "18.2", 8ULL*1024*1024*1024, 6},  // iPhone 15 Pro
    {"iPhone14,7", "D15AP", "20G75",   "16.6", 6ULL*1024*1024*1024, 6},  // iPhone 14
    {"iPhone14,5", "D63AP", "20F66",   "16.5", 4ULL*1024*1024*1024, 6},  // iPhone 13
    {"iPhone15,3", "D84AP", "21F90",   "17.5", 6ULL*1024*1024*1024, 6},  // iPhone 14 Pro Max
    {"iPhone16,2", "D84AP", "22C152",  "18.2", 8ULL*1024*1024*1024, 6},  // iPhone 15 Pro Max
    {"iPhone14,8", "D16AP", "20G75",   "16.6", 6ULL*1024*1024*1024, 6},  // iPhone 14 Plus
};
#define NUM_PROFILES (sizeof(g_profiles) / sizeof(g_profiles[0]))

// Pre-computed C strings for sysctlbyname hook (NO ObjC in hook!)
static char g_fakeMachine[32] = "";
static char g_fakeModel[32]   = "";
static char g_fakeOSBuild[32] = "";
static uint64_t g_fakeMemSize = 0;
static uint32_t g_fakeNCPU    = 6;
static NSString *g_fakeSysVer = nil;

// ============================================================
// Persistent fake IDs
// ============================================================
// v50: New prefix "Bd50." forces ALL fake IDs to regenerate.
static NSString *getPersistent(NSString *key, NSString *(^gen)(void)) {
    NSString *realKey = [key hasPrefix:@"Bdhk."] ? [NSString stringWithFormat:@"Bd50.%@", [key substringFromIndex:5]] : key;
    CFStringRef cfKey = (__bridge CFStringRef)realKey;
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
    NSArray *sn = @[@"张",@"王",@"李",@"赵",@"刘",@"陈",@"杨",@"黄",@"周",@"吴",@"徐",@"孙",@"马",@"朱",@"胡",@"林",@"郭",@"何",@"高",@"罗"];
    NSArray *md = @[@"iPhone",@"iPhone 13",@"iPhone 14",@"iPhone 15",@"iPhone 12",@"iPhone 11",@"iPhone SE"];
    return [NSString stringWithFormat:@"%@的%@", sn[arc4random_uniform((uint32_t)sn.count)], md[arc4random_uniform((uint32_t)md.count)]];
}

static NSString *genRandStr(NSUInteger len, NSString *cs) {
    NSMutableString *s = [NSMutableString stringWithCapacity:len];
    for (NSUInteger i = 0; i < len; i++)
        [s appendFormat:@"%C", [cs characterAtIndex:arc4random_uniform((uint32_t)cs.length)]];
    return s;
}

static NSString *genCUID(void) {
    NSString *cs = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < 63; i++) {
        if (i > 0 && i % 10 == 3) [s appendString:@"-"];
        else [s appendFormat:@"%C", [cs characterAtIndex:arc4random_uniform((uint32_t)cs.length)]];
    }
    return s;
}

static NSString *genFakeCookie(NSString *name) {
    NSString *cuidCS = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    NSString *hexCS = @"0123456789abcdef";
    if ([name hasPrefix:@"BAIDUCUID"] || [name isEqualToString:@"MAWEBCUID"] || [name isEqualToString:@"cuid"])
        return genCUID();
    if ([name isEqualToString:@"DVIF"]) {
        NSString *num = [NSString stringWithFormat:@"%lu", (unsigned long)((uint64_t)arc4random() * arc4random() % 9000000000000000ULL + 1000000000000000ULL)];
        NSMutableData *d = [NSMutableData dataWithLength:300];
        arc4random_buf([d mutableBytes], 300);
        return [NSString stringWithFormat:@"%@_%@_%@", num, [d base64EncodedStringWithOptions:0], genRandStr(6, hexCS)];
    }
    if ([name isEqualToString:@"tcuid"]) return [genRandStr(40, hexCS).uppercaseString stringByAppendingString:genRandStr(4, @"ABCDEFGHIJ")];
    if ([name isEqualToString:@"__bid_n"]) return genRandStr(22, hexCS);
    if ([name isEqualToString:@"fuid"]) return genRandStr(32, hexCS);
    return genRandStr(32, cuidCS);
}

static NSString *getFakeID(NSString *name) {
    return getPersistent([NSString stringWithFormat:@"Bd50.ck.%@", name], ^{ return genFakeCookie(name); });
}

// ============================================================
// Device profile initialization (called BEFORE fishhook install)
// ============================================================
static void initDeviceProfile(void) {
    // Pick a random profile, persist it
    NSString *idxStr = getPersistent(@"Bd50.profile", ^{
        return [NSString stringWithFormat:@"%d", (int)arc4random_uniform((uint32_t)NUM_PROFILES)];
    });
    int idx = [idxStr intValue];
    if (idx < 0 || idx >= (int)NUM_PROFILES) idx = 0;

    DeviceProfile *p = &g_profiles[idx];

    // Pre-compute C strings — safe for sysctlbyname hook (no ObjC needed)
    strlcpy(g_fakeMachine, p->machine, sizeof(g_fakeMachine));
    strlcpy(g_fakeModel,   p->model,   sizeof(g_fakeModel));
    strlcpy(g_fakeOSBuild, p->osBuild, sizeof(g_fakeOSBuild));
    g_fakeMemSize = p->memSize;
    g_fakeNCPU    = p->ncpu;
    g_fakeSysVer  = [NSString stringWithUTF8String:p->sysVer];
}

// ObjC getters for hooks that need NSString
static NSString *getFakeMachine(void) {
    return [NSString stringWithUTF8String:g_fakeMachine];
}
static NSString *getFakeHWModel(void) {
    return [NSString stringWithUTF8String:g_fakeModel];
}
static NSString *getFakeSysVersion(void) {
    return g_fakeSysVer ?: @"17.5";
}

// ============================================================
// sysctlbyname fishhook (PURE C — no ObjC inside hook!)
// ============================================================
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;

static int hook_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name != NULL) {
        // --- String values: hw.machine, hw.model, kern.osversion ---
        const char *strVal = NULL;
        if (strcmp(name, "hw.machine") == 0)      strVal = g_fakeMachine;
        else if (strcmp(name, "hw.model") == 0)   strVal = g_fakeModel;
        else if (strcmp(name, "kern.osversion") == 0) strVal = g_fakeOSBuild;

        if (strVal != NULL && strVal[0] != '\0') {
            size_t need = strlen(strVal) + 1;
            if (oldp == NULL) {
                if (oldlenp) *oldlenp = need;
                return 0;
            }
            if (oldlenp) {
                if (*oldlenp >= need) {
                    memcpy(oldp, strVal, need);
                    *oldlenp = need;
                    return 0;
                }
                *oldlenp = need;
                return ENOMEM;
            }
            return 0;
        }

        // --- uint64_t value: hw.memsize ---
        if (strcmp(name, "hw.memsize") == 0 && g_fakeMemSize > 0) {
            size_t need = sizeof(uint64_t);
            if (oldp == NULL) {
                if (oldlenp) *oldlenp = need;
                return 0;
            }
            if (oldlenp) {
                if (*oldlenp >= need) {
                    memcpy(oldp, &g_fakeMemSize, need);
                    *oldlenp = need;
                    return 0;
                }
                *oldlenp = need;
                return ENOMEM;
            }
            return 0;
        }

        // --- uint32_t value: hw.ncpu, hw.logicalcpu, hw.physicalcpu, hw.activecpu ---
        if ((strcmp(name, "hw.ncpu") == 0 ||
             strcmp(name, "hw.logicalcpu") == 0 ||
             strcmp(name, "hw.physicalcpu") == 0 ||
             strcmp(name, "hw.activecpu") == 0) && g_fakeNCPU > 0) {
            size_t need = sizeof(uint32_t);
            if (oldp == NULL) {
                if (oldlenp) *oldlenp = need;
                return 0;
            }
            if (oldlenp) {
                if (*oldlenp >= need) {
                    memcpy(oldp, &g_fakeNCPU, need);
                    *oldlenp = need;
                    return 0;
                }
                *oldlenp = need;
                return ENOMEM;
            }
            return 0;
        }
    }
    // Call original for everything else
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

// ============================================================
// Cookie device ID detection
// ============================================================
static BOOL isDeviceCookie(NSString *cookieName) {
    if (!cookieName) return NO;
    NSString *lk = [cookieName lowercaseString];
    NSArray *names = @[@"baiducuid", @"baiducuid_bfess", @"mawebcuid",
                       @"dvif", @"tcuid", @"__bid_n", @"fuid", @"cuid"];
    for (NSString *n in names) {
        if ([lk isEqualToString:n]) return YES;
    }
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
    if ([key hasPrefix:@"Bd50"]) return NO;
    if ([key hasPrefix:@"Bd49"]) return NO;
    if ([key hasPrefix:@"Bdhk"]) return NO;
    NSArray *exactKeys = @[@"cuid", @"CUID", @"cuid_galaxy2", @"cuid_gid", @"cuid_loc",
                           @"BAIDUCUID", @"BAIDUCUID_BFESS", @"MAWEBCUID",
                           @"DVIF", @"tcuid", @"__bid_n", @"fuid",
                           @"bdudid", @"baiduid", @"bdid"];
    for (NSString *k in exactKeys) {
        if ([key isEqualToString:k]) return YES;
    }
    if ([key.lowercaseString hasPrefix:@"cuid"]) return YES;
    return NO;
}

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {

        // ---- 0. Initialize device profile (MUST be before fishhook) ----
        initDeviceProfile();

        // ---- 1. Install sysctlbyname fishhook ----
        // Pre-computed C strings are ready — hook uses only strcmp/memcpy
        @try {
            rebind_symbols((struct rebinding[1]){
                {"sysctlbyname", hook_sysctlbyname, (void **)&orig_sysctlbyname}
            }, 1);
        } @catch (id e) {}

        // ---- 1b. Clear Cookie storage (FIRST LAUNCH ONLY) ----
        // This forces re-login — proves to Baidu that this is a NEW device.
        // BDUSS/STOKEN are in cookies, clearing them = must re-login.
        // Keychain is NOT cleared — ensures login flow works correctly.
        @try {
            CFPropertyListRef cleared = CFPreferencesCopyAppValue(CFSTR("Bd50.cc"), kCFPreferencesCurrentApplication);
            if (!cleared) {
                NSHTTPCookieStorage *storage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
                NSArray *cookies = [storage cookies];
                for (NSHTTPCookie *cookie in cookies) { [storage deleteCookie:cookie]; }
                CFPreferencesSetAppValue(CFSTR("Bd50.cc"), kCFBooleanTrue, kCFPreferencesCurrentApplication);
                CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
            } else { CFRelease(cleared); }
        } @catch (id e) {}

        // ---- 2. Bundle ID hook (3 methods — payment critical) ----
        @try {
            Class bc = objc_getClass("NSBundle");
            if (bc) {
                Method m1 = class_getInstanceMethod(bc, @selector(bundleIdentifier));
                if (m1) {
                    IMP orig1 = method_getImplementation(m1);
                    IMP imp1 = imp_implementationWithBlock(^NSString *(id s) {
                        if ([s isEqual:[NSBundle mainBundle]]) return kOrigBundleID;
                        return ((NSString *(*)(id, SEL))orig1)(s, @selector(bundleIdentifier));
                    });
                    class_replaceMethod(bc, @selector(bundleIdentifier), imp1, method_getTypeEncoding(m1));
                }
                Method m2 = class_getInstanceMethod(bc, @selector(objectForInfoDictionaryKey:));
                if (m2) {
                    IMP orig2 = method_getImplementation(m2);
                    IMP imp2 = imp_implementationWithBlock(^id(id s, NSString *key) {
                        if ([s isEqual:[NSBundle mainBundle]] && key &&
                            [key isEqualToString:@"CFBundleIdentifier"]) return kOrigBundleID;
                        return ((id (*)(id, SEL, NSString *))orig2)(s, @selector(objectForInfoDictionaryKey:), key);
                    });
                    class_replaceMethod(bc, @selector(objectForInfoDictionaryKey:), imp2, method_getTypeEncoding(m2));
                }
                Method m3 = class_getInstanceMethod(bc, @selector(infoDictionary));
                if (m3) {
                    IMP orig3 = method_getImplementation(m3);
                    IMP imp3 = imp_implementationWithBlock(^NSDictionary *(id s) {
                        NSDictionary *dict = ((NSDictionary *(*)(id, SEL))orig3)(s, @selector(infoDictionary));
                        if ([s isEqual:[NSBundle mainBundle]] && dict) {
                            NSMutableDictionary *md = [NSMutableDictionary dictionaryWithDictionary:dict];
                            md[@"CFBundleIdentifier"] = kOrigBundleID;
                            return md;
                        }
                        return dict;
                    });
                    class_replaceMethod(bc, @selector(infoDictionary), imp3, method_getTypeEncoding(m3));
                }
            }
        } @catch (id e) {}

        // ---- 3. UIDevice hooks (including systemVersion — NEW in v50) ----
        @try {
            Class dc = objc_getClass("UIDevice");
            if (dc) {
                Method nameM = class_getInstanceMethod(dc, @selector(name));
                if (nameM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return getPersistent(@"Bdhk.dn", ^{ return genDeviceName(); });
                    });
                    class_replaceMethod(dc, @selector(name), imp, method_getTypeEncoding(nameM));
                }
                Method idfvM = class_getInstanceMethod(dc, @selector(identifierForVendor));
                if (idfvM) {
                    IMP imp = imp_implementationWithBlock(^NSUUID *(id s) {
                        return [[NSUUID alloc] initWithUUIDString:getPersistent(@"Bdhk.iv", ^{ return genUUIDStr(); })];
                    });
                    class_replaceMethod(dc, @selector(identifierForVendor), imp, method_getTypeEncoding(idfvM));
                }
                // NEW: systemVersion hook — return version matching device profile
                Method svM = class_getInstanceMethod(dc, @selector(systemVersion));
                if (svM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return getFakeSysVersion();
                    });
                    class_replaceMethod(dc, @selector(systemVersion), imp, method_getTypeEncoding(svM));
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
            }
        } @catch (id e) {}

        // ---- 4. IDFA hook ----
        @try {
            Class ac = objc_getClass("ASIdentifierManager");
            if (ac) {
                Method m = class_getInstanceMethod(ac, @selector(advertisingIdentifier));
                if (m) {
                    IMP imp = imp_implementationWithBlock(^NSUUID *(id s) {
                        return [[NSUUID alloc] initWithUUIDString:getPersistent(@"Bdhk.ai", ^{ return genUUIDStr(); })];
                    });
                    class_replaceMethod(ac, @selector(advertisingIdentifier), imp, method_getTypeEncoding(m));
                }
            }
        } @catch (id e) {}

        // ---- 5. NSUserDefaults hooks (exact key matching) ----
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

        // ---- 6. Cookie READ-ONLY hooks ----
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
        } @catch (id e) {}

        // ---- 7. NSMutableURLRequest Cookie header replacement ----
        @try {
            Class reqClass = objc_getClass("NSMutableURLRequest");
            if (reqClass) {
                Method svM = class_getInstanceMethod(reqClass, @selector(setValue:forHTTPHeaderField:));
                if (svM) {
                    IMP origSV = method_getImplementation(svM);
                    IMP newSV = imp_implementationWithBlock(^void(id s, NSString *value, NSString *field) {
                        if (value && field && [field caseInsensitiveCompare:@"Cookie"] == NSOrderedSame) {
                            NSArray *names = @[@"BAIDUCUID", @"BAIDUCUID_BFESS", @"MAWEBCUID",
                                               @"DVIF", @"tcuid", @"__bid_n", @"fuid"];
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
            }
        } @catch (id e) {}

        // ---- 8. ObjC: +[BIMBaiduUDID value] ----
        @try {
            Class udidCls = objc_getClass("BIMBaiduUDID");
            if (udidCls) {
                Class metaCls = object_getClass(udidCls);
                Method m = class_getInstanceMethod(metaCls, @selector(value));
                if (m) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return getPersistent(@"Bdhk.budid", ^{ return genUUIDStr(); });
                    });
                    class_replaceMethod(metaCls, @selector(value), imp, method_getTypeEncoding(m));
                }
            }
        } @catch (id e) {}

        // ---- 9. ObjC: -[BIMConfigurationManager cuid] ----
        @try {
            Class cfgCls = objc_getClass("BIMConfigurationManager");
            if (cfgCls) {
                Method m = class_getInstanceMethod(cfgCls, @selector(cuid));
                if (m) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return getFakeID(@"cuid");
                    });
                    class_replaceMethod(cfgCls, @selector(cuid), imp, method_getTypeEncoding(m));
                }
            }
        } @catch (id e) {}

        // ---- 10. ObjC: -[BARSDKProConfig CUID] ----
        @try {
            Class arCls = objc_getClass("BARSDKProConfig");
            if (arCls) {
                Method m = class_getInstanceMethod(arCls, @selector(CUID));
                if (m) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return getFakeID(@"cuid");
                    });
                    class_replaceMethod(arCls, @selector(CUID), imp, method_getTypeEncoding(m));
                }
            }
        } @catch (id e) {}

        // ---- 11. ObjC: -[UtilsHelper getDeviceID] ----
        @try {
            Class uhCls = objc_getClass("UtilsHelper");
            if (uhCls) {
                Method m1 = class_getInstanceMethod(uhCls, @selector(getDeviceID));
                if (m1) {
                    IMP imp1 = imp_implementationWithBlock(^NSString *(id s) {
                        return getPersistent(@"Bdhk.udid", ^{ return genUUIDStr(); });
                    });
                    class_replaceMethod(uhCls, @selector(getDeviceID), imp1, method_getTypeEncoding(m1));
                }
                Method m2 = class_getInstanceMethod(uhCls, @selector(getDeviceIDAndUpdate));
                if (m2) {
                    IMP imp2 = imp_implementationWithBlock(^NSString *(id s) {
                        return getPersistent(@"Bdhk.udid", ^{ return genUUIDStr(); });
                    });
                    class_replaceMethod(uhCls, @selector(getDeviceIDAndUpdate), imp2, method_getTypeEncoding(m2));
                }
            }
        } @catch (id e) {}

        // ---- 12. ObjC: +[DMDeviceInfoWrapper deviceModel/systemVersion/cellularProviderName] ----
        @try {
            Class dmCls = objc_getClass("DMDeviceInfoWrapper");
            if (dmCls) {
                Class metaCls = object_getClass(dmCls);

                Method m1 = class_getInstanceMethod(metaCls, @selector(deviceModel));
                if (m1) {
                    IMP imp1 = imp_implementationWithBlock(^NSString *(id s) {
                        return getFakeMachine();
                    });
                    class_replaceMethod(metaCls, @selector(deviceModel), imp1, method_getTypeEncoding(m1));
                }

                Method m2 = class_getInstanceMethod(metaCls, @selector(systemVersion));
                if (m2) {
                    IMP imp2 = imp_implementationWithBlock(^NSString *(id s) {
                        return getFakeSysVersion();
                    });
                    class_replaceMethod(metaCls, @selector(systemVersion), imp2, method_getTypeEncoding(m2));
                }

                Method m3 = class_getInstanceMethod(metaCls, @selector(cellularProviderName));
                if (m3) {
                    IMP imp3 = imp_implementationWithBlock(^NSString *(id s) {
                        return getPersistent(@"Bdhk.carrier", ^{
                            NSArray *carriers = @[@"中国移动", @"中国联通", @"中国电信"];
                            return carriers[arc4random_uniform((uint32_t)carriers.count)];
                        });
                    });
                    class_replaceMethod(metaCls, @selector(cellularProviderName), imp3, method_getTypeEncoding(m3));
                }
            }
        } @catch (id e) {}

        // ---- 13. ObjC: -[BIMDeviceInfoUtility deviceModelVersion] ----
        @try {
            Class diuCls = objc_getClass("BIMDeviceInfoUtility");
            if (diuCls) {
                Method m = class_getInstanceMethod(diuCls, @selector(deviceModelVersion));
                if (m) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return getFakeMachine();
                    });
                    class_replaceMethod(diuCls, @selector(deviceModelVersion), imp, method_getTypeEncoding(m));
                }
            }
        } @catch (id e) {}

        // ---- 14. ObjC: -[BBAMessageIMManagerUniform isForceCUIDLogin] ----
        @try {
            Class imCls = objc_getClass("BBAMessageIMManagerUniform");
            if (imCls) {
                Method m = class_getInstanceMethod(imCls, @selector(isForceCUIDLogin));
                if (m) {
                    IMP imp = imp_implementationWithBlock(^BOOL(id s) {
                        return NO;
                    });
                    class_replaceMethod(imCls, @selector(isForceCUIDLogin), imp, method_getTypeEncoding(m));
                }
            }
        } @catch (id e) {}
    }
}
