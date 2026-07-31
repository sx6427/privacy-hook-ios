//
// PrivacyHook.m — v27: sysctlbyname + uname hook for device model spoofing
//
// v26 problem: UIDevice hooks alone insufficient. Baidu reads hw.machine
//   via sysctlbyname("hw.machine") -> real "iPhone7,2" shown to server.
//   Also reads kern.osrelease -> wrong kernel version.
//
// v27 solution: use fishhook to intercept sysctlbyname + uname C functions.
//   - hw.machine / hw.product -> fake model (iPhone14,5 etc.)
//   - kern.osversion -> fake build number matching fake systemVersion
//   - kern.osrelease -> fake kernel version matching fake systemVersion
//   - uname() machine/release -> same fake values
//
// All fake values are persistent per-clone and consistent with each other.
// Payment safe: sysctl/uname hooks don't affect Alipay/WeChat SDK.
// vtool patches LC_BUILD_VERSION SDK to 17.0 (critical for payment)
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <string.h>
#import "fishhook.h"

#define NSLog(...)

static NSString *const kOrigBundleID = @"com.baidu.BaiduMobile";

// REAL bundle ID read BEFORE hooks — used as CFPreferences domain
// so each clone (A1/A2/...) has independent persistent fake IDs.
static NSString *g_realBundleID = nil;

// ============================================================
// Persistent fake IDs — keyed to REAL bundle ID
// ============================================================
static NSString *getPersistent(NSString *key, NSString *(^gen)(void)) {
    CFStringRef cfDomain = (__bridge CFStringRef)(g_realBundleID ?: kOrigBundleID);
    CFStringRef cfKey = (__bridge CFStringRef)key;
    CFPropertyListRef val = CFPreferencesCopyAppValue(cfKey, cfDomain);
    if (val) {
        NSString *s = [(__bridge id)val isKindOfClass:[NSString class]] ? (__bridge NSString *)val : nil;
        CFRelease(val);
        if (s) return s;
    }
    NSString *newVal = gen();
    CFPreferencesSetAppValue(cfKey, (__bridge CFStringRef)newVal, cfDomain);
    CFPreferencesAppSynchronize(cfDomain);
    return newVal;
}

static NSString *genUUIDStr(void) { return [[NSUUID UUID] UUIDString]; }

static NSString *genDeviceName(void) {
    NSArray *sn = @[@"张",@"王",@"李",@"赵",@"刘",@"陈",@"杨",@"黄",@"周",@"吴",@"徐",@"孙",@"马",@"朱",@"胡",@"林",@"郭",@"何",@"高",@"罗"];
    NSArray *md = @[@"iPhone",@"iPhone 13",@"iPhone 14",@"iPhone 15",@"iPhone 12",@"iPhone 11",@"iPhone SE"];
    return [NSString stringWithFormat:@"%@的%@", sn[arc4random_uniform((uint32_t)sn.count)], md[arc4random_uniform((uint32_t)md.count)]];
}

// Generate a fake iOS version string per clone
static NSString *genFakeSystemVersion(void) {
    NSArray *versions = @[@"15.7", @"16.0", @"16.1", @"16.2", @"16.3", @"16.4", @"16.5", @"16.6"];
    return versions[arc4random_uniform((uint32_t)versions.count)];
}

// Fake device hardware model (hw.machine)
static NSString *genFakeMachine(void) {
    NSArray *models = @[
        @"iPhone14,5",   // iPhone 13
        @"iPhone14,7",   // iPhone 14
        @"iPhone14,8",   // iPhone 14 Plus
        @"iPhone15,2",   // iPhone 14 Pro
        @"iPhone15,3",   // iPhone 14 Pro Max
        @"iPhone15,4",   // iPhone 15
        @"iPhone15,5",   // iPhone 15 Plus
        @"iPhone14,6",   // iPhone 13 mini
        @"iPhone14,4",   // iPhone 13 Pro
    ];
    return models[arc4random_uniform((uint32_t)models.count)];
}

// iOS version -> build number + kernel release mapping
// Ensures sysctlbyname("kern.osversion") and kern.osrelease are
// consistent with UIDevice.systemVersion
static NSDictionary *versionInfoMap(NSString *version) {
    NSDictionary *map = @{
        @"15.7": @{@"build": @"19H221",  @"release": @"21.6.0"},
        @"16.0": @{@"build": @"20A362",  @"release": @"22.0.0"},
        @"16.1": @{@"build": @"20B82",   @"release": @"22.1.0"},
        @"16.2": @{@"build": @"20C65",   @"release": @"22.2.0"},
        @"16.3": @{@"build": @"20D47",   @"release": @"22.3.0"},
        @"16.4": @{@"build": @"20E246",  @"release": @"22.4.0"},
        @"16.5": @{@"build": @"20F66",   @"release": @"22.5.0"},
        @"16.6": @{@"build": @"20G75",   @"release": @"22.6.0"},
    };
    return map[version] ?: @{@"build": @"20G75", @"release": @"22.6.0"};
}

// ============================================================
// fishhook: sysctlbyname hook
// Intercepts hw.machine, hw.product, kern.osversion, kern.osrelease
// ============================================================
static int (*orig_sysctlbyname)(const char *, void *, size_t *,
                                 const void *, size_t) = NULL;

static int hook_sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                              const void *newp, size_t newlen) {
    if (name) {
        NSString *fakeStr = nil;

        // hw.machine / hw.product -> fake device model
        if (strcmp(name, "hw.machine") == 0 || strcmp(name, "hw.product") == 0) {
            fakeStr = getPersistent(@"Bdhk.hm", ^{ return genFakeMachine(); });
        }
        // kern.osversion -> fake build number (e.g. "20G75")
        else if (strcmp(name, "kern.osversion") == 0) {
            NSString *fakeSV = getPersistent(@"Bdhk.sv", ^{ return genFakeSystemVersion(); });
            fakeStr = versionInfoMap(fakeSV)[@"build"];
        }
        // kern.osrelease -> fake kernel version (e.g. "22.6.0")
        else if (strcmp(name, "kern.osrelease") == 0) {
            NSString *fakeSV = getPersistent(@"Bdhk.sv", ^{ return genFakeSystemVersion(); });
            fakeStr = versionInfoMap(fakeSV)[@"release"];
        }

        if (fakeStr) {
            const char *cstr = [fakeStr UTF8String];
            size_t fakeLen = strlen(cstr) + 1;
            if (oldp && oldlenp) {
                if (*oldlenp >= fakeLen) {
                    memcpy(oldp, cstr, fakeLen);
                }
                *oldlenp = fakeLen;
                return 0;
            } else if (oldlenp) {
                *oldlenp = fakeLen;
                return 0;
            }
        }
    }
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

// ============================================================
// fishhook: uname hook
// Intercepts utsname.machine and utsname.release
// ============================================================
static int (*orig_uname)(struct utsname *) = NULL;

static int hook_uname(struct utsname *name) {
    int ret = orig_uname(name);
    if (ret == 0 && name) {
        // machine -> fake device model
        NSString *fakeMachine = getPersistent(@"Bdhk.hm", ^{ return genFakeMachine(); });
        const char *m = [fakeMachine UTF8String];
        memset(name->machine, 0, sizeof(name->machine));
        strncpy(name->machine, m, sizeof(name->machine) - 1);

        // release -> fake kernel version
        NSString *fakeSV = getPersistent(@"Bdhk.sv", ^{ return genFakeSystemVersion(); });
        NSString *release = versionInfoMap(fakeSV)[@"release"];
        const char *r = [release UTF8String];
        memset(name->release, 0, sizeof(name->release));
        strncpy(name->release, r, sizeof(name->release) - 1);
    }
    return ret;
}

// ============================================================
// Selective Keychain CUID deletion
// Deletes ONLY items whose service/account/label contains "cuid"
// Login tokens (BDUSS, STOKEN, passport, session, etc.) are PRESERVED
// ============================================================
static void wipeCUIDFromKeychain(void) {
    @try {
        NSDictionary *query = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecReturnAttributes: @YES,
            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
        };
        CFTypeRef result = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        if (status == errSecSuccess && result) {
            NSArray *items = (__bridge_transfer NSArray *)result;
            for (NSDictionary *item in items) {
                NSString *service = item[(__bridge id)kSecAttrService];
                NSString *account = item[(__bridge id)kSecAttrAccount];
                NSString *label   = item[(__bridge id)kSecAttrLabel];

                NSMutableString *searchStr = [NSMutableString string];
                if (service) [searchStr appendString:service];
                [searchStr appendString:@"\n"];
                if (account) [searchStr appendString:account];
                [searchStr appendString:@"\n"];
                if (label)   [searchStr appendString:label];

                NSString *lower = searchStr.lowercaseString;
                BOOL isDeviceID = ([lower containsString:@"cuid"] ||
                                   [lower containsString:@"deviceid"] ||
                                   [lower containsString:@"device_id"] ||
                                   [lower containsString:@"machineid"] ||
                                   [lower containsString:@"bdid"] ||
                                   [lower containsString:@"clientid"]);
                if (isDeviceID) {
                    NSMutableDictionary *delQuery = [NSMutableDictionary dictionary];
                    delQuery[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
                    if (service) delQuery[(__bridge id)kSecAttrService] = service;
                    if (account) delQuery[(__bridge id)kSecAttrAccount] = account;
                    SecItemDelete((__bridge CFDictionaryRef)delQuery);
                }
            }
        } else if (result) {
            CFRelease(result);
        }
    } @catch (id e) {}
}

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {

        // ---- 0. Read REAL bundle ID BEFORE any hooks ----
        @try {
            NSDictionary *d = [[NSBundle mainBundle] infoDictionary];
            g_realBundleID = [d[@"CFBundleIdentifier"] copy];
        } @catch (id e) {}

        // ---- 1. Delete CUID-related NSUserDefaults keys ----
        @try {
            NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
            NSDictionary *allDict = [ud dictionaryRepresentation];
            for (NSString *key in allDict.allKeys) {
                NSString *lk = key.lowercaseString;
                if ([lk containsString:@"cuid"] || [lk containsString:@"deviceid"] ||
                    [lk containsString:@"device_id"] || [lk containsString:@"machineid"]) {
                    [ud removeObjectForKey:key];
                }
            }
            [ud synchronize];
        } @catch (id e) {}

        // ---- 1b. Selectively delete CUID from Keychain ----
        wipeCUIDFromKeychain();

        // ---- 2. Bundle ID hook (3 methods) ----
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

        // ---- 3. UIDevice hooks ----
        @try {
            Class dc = objc_getClass("UIDevice");
            if (dc) {
                Method svM = class_getInstanceMethod(dc, @selector(systemVersion));
                if (svM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return getPersistent(@"Bdhk.sv", ^{ return genFakeSystemVersion(); });
                    });
                    class_replaceMethod(dc, @selector(systemVersion), imp, method_getTypeEncoding(svM));
                }
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

        // ---- 4. ASIdentifierManager IDFA hook ----
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

        // ---- 5. fishhook: sysctlbyname + uname ----
        // Hook C functions that bypass UIDevice and read kernel directly.
        // Baidu uses sysctlbyname("hw.machine") to get real device model.
        @try {
            struct rebinding rebindings[] = {
                {"sysctlbyname", (void *)hook_sysctlbyname, (void **)&orig_sysctlbyname},
                {"uname",        (void *)hook_uname,        (void **)&orig_uname},
            };
            rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
        } @catch (id e) {}

        // ---- 6. Pre-write fake CUID into NSUserDefaults ----
        @try {
            NSString *fakeCUID = getPersistent(@"Bdhk.cuid", ^{
                NSString *cs = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                NSMutableString *s = [NSMutableString string];
                for (int i = 0; i < 40; i++)
                    [s appendFormat:@"%c", [cs characterAtIndex:arc4random_uniform((uint32_t)cs.length)]];
                return s;
            });
            NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
            for (NSString *k in @[@"CUID", @"cuid", @"BD_CUID", @"baidu_cuid",
                                  @"BAIDU_CUID", @"kCUID", @"com.baidu.cuid"]) {
                [ud setObject:fakeCUID forKey:k];
            }
            [ud synchronize];
        } @catch (id e) {}
    }
}
