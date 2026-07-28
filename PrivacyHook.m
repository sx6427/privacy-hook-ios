//
//  PrivacyHook.m — Step31
//
//  Goal: Each version = new device (verification code) + payment works.
//
//  Keychain: clear EVERY launch (payment SDK stays fresh → payment works)
//  UserDefaults: clear ALL Baidu keys, first launch only
//  Library/Caches: delete, first launch only
//  Library/Preferences: delete non-payment files, first launch only
//  (keep alipay/wechat/tencent files → payment SDK config preserved)
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <AppTrackingTransparency/AppTrackingTransparency.h>
#import <Security/Security.h>
#import <objc/runtime.h>

#define NSLog(...)

static NSUUID *_spoofedIDFA = nil;
static NSUUID *_spoofedIDFV = nil;
static NSString *_spoofedDeviceName = nil;

static NSString *kKey(NSString *suffix) {
    return [NSString stringWithFormat:@"BaiduBox.cfg.%@", suffix];
}

static NSUUID *getOrCreateSpoofedUUID(NSString *key) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *uuidString = [defaults stringForKey:key];
    if (uuidString) return [[NSUUID alloc] initWithUUIDString:uuidString];
    NSUUID *newUUID = [NSUUID UUID];
    [defaults setObject:[newUUID UUIDString] forKey:key];
    [defaults synchronize];
    return newUUID;
}

static NSString *getOrCreateSpoofedDeviceName(NSString *key) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *existing = [defaults stringForKey:key];
    if (existing) return existing;

    NSArray *prefixes = @[@"张", @"李", @"王", @"刘", @"陈", @"杨", @"赵", @"黄",
                          @"周", @"吴", @"徐", @"孙", @"马", @"朱", @"胡", @"林"];
    NSArray *suffixes = @[@"的 iPhone", @"的 iPhone", @"的 iPhone",
                          @"的iPhone", @"的 iPhone 14", @"的 iPhone 13"];
    NSString *prefix = prefixes[arc4random_uniform((uint32_t)prefixes.count)];
    NSString *suffix = suffixes[arc4random_uniform((uint32_t)suffixes.count)];
    NSString *name = [NSString stringWithFormat:@"%@%@", prefix, suffix];
    [defaults setObject:name forKey:key];
    [defaults synchronize];
    return name;
}

static void hookInstanceMethod(Class cls, SEL sel, IMP newImp, const char *types) {
    Method method = class_getInstanceMethod(cls, sel);
    if (method) {
        const char *existingTypes = types ?: method_getTypeEncoding(method);
        class_replaceMethod(cls, sel, newImp, existingTypes);
    }
}

static void hookClassMethod(Class cls, SEL sel, IMP newImp, const char *types) {
    Class metaClass = object_getClass(cls);
    Method method = class_getClassMethod(cls, sel);
    if (method) {
        const char *existingTypes = types ?: method_getTypeEncoding(method);
        class_replaceMethod(metaClass, sel, newImp, existingTypes);
    }
}

// ============================================================
// Keychain: clear EVERY launch
// Payment SDK writes bad data after first session → second launch fails.
// Clearing every launch keeps it fresh → payment always works.
// ============================================================
static void clearKeychainEveryLaunch(void) {
    NSArray *secItemClasses = @[
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword,
        (__bridge id)kSecClassKey,
        (__bridge id)kSecClassCertificate,
        (__bridge id)kSecClassIdentity
    ];
    for (id secItemClass in secItemClasses) {
        NSDictionary *query = @{(__bridge id)kSecClass: secItemClass};
        SecItemDelete((__bridge CFDictionaryRef)query);
    }
}

// Check if filename belongs to payment SDK (keep these)
static BOOL isPaymentSDKFile(NSString *filename) {
    NSString *lower = [filename lowercaseString];
    if ([lower containsString:@"alipay"]) return YES;
    if ([lower containsString:@"wechat"]) return YES;
    if ([lower containsString:@"tencent"]) return YES;
    if ([lower containsString:@"xauth"]) return YES;
    if ([lower containsString:@"wx"]) return YES;
    // System plist: <bundleid>.plist — keep this too (it's UserDefaults)
    if ([lower hasSuffix:@".plist"] && [lower containsString:@"baidumobile"]) return YES;
    return NO;
}

// ============================================================
// First-launch-only: clear Baidu data for new device identity
// ============================================================
static void clearBaiduDataFirstLaunch(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *flagKey = kKey(@"clean_v5");
    if ([defaults boolForKey:flagKey]) return;

    // 1. Clear ALL UserDefaults (save our config first)
    NSMutableDictionary *myConfig = [NSMutableDictionary dictionary];
    NSDictionary *allDict = [defaults dictionaryRepresentation];
    for (NSString *key in allDict) {
        if ([key hasPrefix:@"BaiduBox.cfg."]) {
            myConfig[key] = allDict[key];
        }
    }
    for (NSString *key in allDict) {
        if ([key hasPrefix:@"AKService"]) continue;
        if ([key hasPrefix:@"Apple"]) continue;
        if ([key hasPrefix:@"NS"]) continue;
        if ([key hasPrefix:@"com.apple"]) continue;
        if ([key hasPrefix:@"ITF"]) continue;
        if ([key hasPrefix:@"MSV"]) continue;
        if ([key hasPrefix:@"WebKit"]) continue;
        if ([key hasPrefix:@"CFUser"]) continue;
        if ([key hasPrefix:@"pkc"]) continue;
        [defaults removeObjectForKey:key];
    }
    for (NSString *key in myConfig) {
        [defaults setObject:myConfig[key] forKey:key];
    }

    // 2. Delete Library/Caches
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *home = NSHomeDirectory();
    NSString *cachesDir = [home stringByAppendingPathComponent:@"Library/Caches"];
    NSArray *cachesFiles = [fm contentsOfDirectoryAtPath:cachesDir error:nil];
    for (NSString *f in cachesFiles) {
        [fm removeItemAtPath:[cachesDir stringByAppendingPathComponent:f] error:nil];
    }

    // 3. Delete Library/Preferences — BUT keep payment SDK files
    NSString *prefsDir = [home stringByAppendingPathComponent:@"Library/Preferences"];
    NSArray *prefsFiles = [fm contentsOfDirectoryAtPath:prefsDir error:nil];
    for (NSString *f in prefsFiles) {
        if (!isPaymentSDKFile(f)) {
            [fm removeItemAtPath:[prefsDir stringByAppendingPathComponent:f] error:nil];
        }
    }

    // 4. Delete Documents
    NSString *docsDir = [home stringByAppendingPathComponent:@"Documents"];
    NSArray *docsFiles = [fm contentsOfDirectoryAtPath:docsDir error:nil];
    for (NSString *f in docsFiles) {
        [fm removeItemAtPath:[docsDir stringByAppendingPathComponent:f] error:nil];
    }

    // 5. Delete tmp
    NSString *tmpDir = [home stringByAppendingPathComponent:@"tmp"];
    NSArray *tmpFiles = [fm contentsOfDirectoryAtPath:tmpDir error:nil];
    for (NSString *f in tmpFiles) {
        [fm removeItemAtPath:[tmpDir stringByAppendingPathComponent:f] error:nil];
    }

    // Recreate dirs
    [fm createDirectoryAtPath:docsDir withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:cachesDir withIntermediateDirectories:YES attributes:nil error:nil];

    // Restore config + set flag
    for (NSString *key in myConfig) {
        [defaults setObject:myConfig[key] forKey:key];
    }
    [defaults setBool:YES forKey:flagKey];
    [defaults synchronize];
}

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {
        _spoofedIDFA = getOrCreateSpoofedUUID(kKey(@"id1"));
        _spoofedIDFV = getOrCreateSpoofedUUID(kKey(@"id2"));
        _spoofedDeviceName = getOrCreateSpoofedDeviceName(kKey(@"dn"));

        // Clear keychain EVERY launch (keeps payment fresh)
        clearKeychainEveryLaunch();

        // Clear Baidu data on first launch only
        clearBaiduDataFirstLaunch();

        // IDFA
        Class asmClass = objc_getClass("ASIdentifierManager");
        if (asmClass) {
            Method m = class_getInstanceMethod(asmClass, @selector(advertisingIdentifier));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSUUID *(id s) { return _spoofedIDFA; });
                hookInstanceMethod(asmClass, @selector(advertisingIdentifier), imp, method_getTypeEncoding(m));
            }
            m = class_getInstanceMethod(asmClass, @selector(isAdvertisingTrackingEnabled));
            if (m) {
                IMP imp = imp_implementationWithBlock(^BOOL(id s) { return YES; });
                hookInstanceMethod(asmClass, @selector(isAdvertisingTrackingEnabled), imp, method_getTypeEncoding(m));
            }
        }

        // ATTrackingManager
        Class attClass = objc_getClass("ATTrackingManager");
        if (attClass) {
            Method m = class_getClassMethod(attClass, @selector(trackingAuthorizationStatus));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSInteger(id s) { return 3; });
                hookClassMethod(attClass, @selector(trackingAuthorizationStatus), imp, method_getTypeEncoding(m));
            }
        }

        // IDFV + device name
        Class uiDeviceClass = objc_getClass("UIDevice");
        if (uiDeviceClass) {
            Method m = class_getInstanceMethod(uiDeviceClass, @selector(identifierForVendor));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSUUID *(id s) { return _spoofedIDFV; });
                hookInstanceMethod(uiDeviceClass, @selector(identifierForVendor), imp, method_getTypeEncoding(m));
            }
            m = class_getInstanceMethod(uiDeviceClass, @selector(name));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSString *(id s) { return _spoofedDeviceName; });
                hookInstanceMethod(uiDeviceClass, @selector(name), imp, method_getTypeEncoding(m));
            }
        }
    }
}
