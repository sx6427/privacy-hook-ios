//
// PrivacyHook.m — v24: Per-clone CUID via systemVersion spoof (no keychain wipe)
//
// Problem with v23: clearing ALL keychain → deletes login tokens → re-login
//   every restart. And CUID regenerated from same hardware → same value.
//
// Solution: DON'T clear keychain. Instead:
//   1. Hook UIDevice.systemVersion → fake per-clone version
//   2. Delete only CUID-related NSUserDefaults keys → force regeneration
//   3. App regenerates CUID using fake systemVersion → different CUID
//   4. A1 (16.1) vs A2 (16.3) → different CUIDs
//   5. Login tokens in keychain preserved → no re-login
//
// No fishhook, no cookie hooks, no NSURLSession hooks → payment safe.
// vtool patches LC_BUILD_VERSION SDK to 17.0 (critical for payment)
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <objc/runtime.h>

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
        // Force app to regenerate CUID. Combined with systemVersion hook,
        // the regenerated CUID will be different per clone.
        // Login tokens in keychain are NOT touched → no re-login.
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
                // systemVersion → fake per-clone (changes CUID generation input)
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

        // ---- 5. Pre-write fake CUID into NSUserDefaults ----
        // After clearing CUID keys above, write our fake CUID so app uses it.
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
