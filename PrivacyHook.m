//
//  PrivacyHook.m
//  Device Fingerprint + Login State Isolation Dylib for iOS
//
//  v18: Clear persistent SDK risk flags on EVERY launch.
//
//  Problem: v14's aggressive hooks triggered SDK to write a persistent
//  "modified environment" flag to Keychain. Our v16 only cleared
//  Keychain on FIRST launch (using a UserDefaults flag), so the SDK's
//  flag survived across launches. Even after uninstall+reinstall,
//  Keychain items persist on iOS.
//
//  Fix: Clear Keychain EVERY launch (not just first). Also clear all
//  non-our NSUserDefaults keys to remove any SDK-written flags.
//
//  Reverted to v16 base: only bundleIdentifier method hook (no
//  infoDictionary / objectForInfoDictionaryKey — they break icons).
//
//  NO fishhook. NO C function hooks. ObjC swizzle ONLY.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <AppTrackingTransparency/AppTrackingTransparency.h>
#import <Security/Security.h>
#import <objc/runtime.h>

#define NSLog(...)

// ============================================================
// Persistent spoofed identifiers
// ============================================================
static NSUUID *_spoofedIDFA = nil;
static NSUUID *_spoofedIDFV = nil;
static NSString *_spoofedDeviceName = nil;

// ============================================================
// NSUserDefaults key prefix — looks like Baidu's own setting
// ============================================================
static NSString *kKey(NSString *suffix) {
    return [NSString stringWithFormat:@"BaiduBox.cfg.%@", suffix];
}

// ============================================================
// Spoofed value generators
// ============================================================
static NSUUID *getOrCreateSpoofedUUID(NSString *key) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *uuidString = [defaults stringForKey:key];
    if (uuidString) {
        return [[NSUUID alloc] initWithUUIDString:uuidString];
    }
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
                          @"周", @"吴", @"徐", @"孙", @"马", @"朱", @"胡", @"林",
                          @"何", @"郭", @"高", @"罗", @"郑", @"梁", @"谢", @"宋",
                          @"唐", @"许", @"韩", @"冯", @"邓", @"曹", @"彭", @"曾"];
    NSArray *suffixes = @[@"的 iPhone", @"的 iPhone", @"的 iPhone",
                          @"的iPhone", @"的 iPhone 14", @"的 iPhone 13",
                          @"的 iPhone 15", @"的 iPhone 12"];
    NSString *prefix = prefixes[arc4random_uniform((uint32_t)prefixes.count)];
    NSString *suffix = suffixes[arc4random_uniform((uint32_t)suffixes.count)];
    NSString *name = [NSString stringWithFormat:@"%@%@", prefix, suffix];

    [defaults setObject:name forKey:key];
    [defaults synchronize];
    return name;
}

// ============================================================
// Helper: replace an instance method's implementation
// ============================================================
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
// Keychain + Cookie + UserDefaults clearing
// ============================================================

// Clear ALL keychain items on EVERY launch
// (SDK may have written risk flags that persist across reinstalls)
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

// Clear all NSUserDefaults keys EXCEPT our own (BaiduBox.cfg.*)
// SDK may store risk flags in UserDefaults
static void clearNonOurUserDefaults(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSDictionary *allKeys = [defaults dictionaryRepresentation];
    NSString *ourPrefix = @"BaiduBox.cfg.";

    // Save our values first
    NSMutableDictionary *ourValues = [NSMutableDictionary dictionary];
    for (NSString *key in allKeys) {
        if ([key hasPrefix:ourPrefix]) {
            ourValues[key] = allKeys[key];
        }
    }

    // Remove the persistent domain (clears everything for this app)
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
    if (bundleID) {
        [[NSUserDefaults standardUserDefaults] removePersistentDomainForName:bundleID];
    }

    // Restore our values
    for (NSString *key in ourValues) {
        [defaults setObject:ourValues[key] forKey:key];
    }
    [defaults synchronize];
}

static void clearSharedCookies(void) {
    NSHTTPCookieStorage *storage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    NSArray *cookies = [[storage cookies] copy];
    for (NSHTTPCookie *cookie in cookies) {
        [storage deleteCookie:cookie];
    }
}

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {
        // --- Save our spoofed values BEFORE clearing UserDefaults ---
        // Read existing values if they exist, generate if not
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        NSString *ourPrefix = @"BaiduBox.cfg.";

        // Save our existing values
        NSMutableDictionary *savedValues = [NSMutableDictionary dictionary];
        NSDictionary *allKeys = [defaults dictionaryRepresentation];
        for (NSString *key in allKeys) {
            if ([key hasPrefix:ourPrefix]) {
                savedValues[key] = allKeys[key];
            }
        }

        // --- Clear ALL persistent SDK risk flags ---
        // Keychain: clear EVERY launch (iOS keychain persists across reinstalls!)
        clearKeychainEveryLaunch();

        // UserDefaults: clear everything except our keys
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
        if (bundleID) {
            [defaults removePersistentDomainForName:bundleID];
        }
        // Restore our values
        for (NSString *key in savedValues) {
            [defaults setObject:savedValues[key] forKey:key];
        }
        [defaults synchronize];

        // Cookies
        clearSharedCookies();

        // --- Initialize spoofed values (after clearing) ---
        _spoofedIDFA = getOrCreateSpoofedUUID(kKey(@"id1"));
        _spoofedIDFV = getOrCreateSpoofedUUID(kKey(@"id2"));
        _spoofedDeviceName = getOrCreateSpoofedDeviceName(kKey(@"dn"));

        // ============================================================
        // 1. IDFA
        // ============================================================
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

        // ============================================================
        // 2. ATTrackingManager
        // ============================================================
        Class attClass = objc_getClass("ATTrackingManager");
        if (attClass) {
            Method m = class_getClassMethod(attClass, @selector(trackingAuthorizationStatus));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSInteger(id s) { return 3; });
                hookClassMethod(attClass, @selector(trackingAuthorizationStatus), imp, method_getTypeEncoding(m));
            }
            m = class_getClassMethod(attClass, @selector(requestTrackingAuthorizationWithCompletionHandler:));
            if (m) {
                IMP imp = imp_implementationWithBlock(^(id s, void (^h)(NSInteger)) {
                    if (h) dispatch_async(dispatch_get_main_queue(), ^{ h(3); });
                });
                hookClassMethod(attClass, @selector(requestTrackingAuthorizationWithCompletionHandler:), imp, method_getTypeEncoding(m));
            }
        }

        // ============================================================
        // 3. IDFV + device name
        // ============================================================
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

        // ============================================================
        // 4. UIPasteboard — block ALL reads (login isolation)
        // ============================================================
        Class pbClass = objc_getClass("UIPasteboard");
        if (pbClass) {
            Method m = class_getInstanceMethod(pbClass, @selector(string));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @""; });
                hookInstanceMethod(pbClass, @selector(string), imp, method_getTypeEncoding(m));
            }
            m = class_getInstanceMethod(pbClass, @selector(strings));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSArray *(id s) { return @[]; });
                hookInstanceMethod(pbClass, @selector(strings), imp, method_getTypeEncoding(m));
            }
            m = class_getInstanceMethod(pbClass, @selector(dataForPasteboardType:));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSData *(id s, NSString *t) { return nil; });
                hookInstanceMethod(pbClass, @selector(dataForPasteboardType:), imp, method_getTypeEncoding(m));
            }
            m = class_getInstanceMethod(pbClass, @selector(valueForPasteboardType:));
            if (m) {
                IMP imp = imp_implementationWithBlock(^id(id s, NSString *t) { return nil; });
                hookInstanceMethod(pbClass, @selector(valueForPasteboardType:), imp, method_getTypeEncoding(m));
            }
            m = class_getInstanceMethod(pbClass, @selector(items));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSArray *(id s) { return @[]; });
                hookInstanceMethod(pbClass, @selector(items), imp, method_getTypeEncoding(m));
            }
            m = class_getInstanceMethod(pbClass, @selector(containsPasteboardTypes:));
            if (m) {
                IMP imp = imp_implementationWithBlock(^BOOL(id s, NSArray *t) { return NO; });
                hookInstanceMethod(pbClass, @selector(containsPasteboardTypes:), imp, method_getTypeEncoding(m));
            }
        }

        // ============================================================
        // 5. App Group container blocked
        // ============================================================
        Class fmClass = objc_getClass("NSFileManager");
        if (fmClass) {
            Method m = class_getInstanceMethod(fmClass,
                @selector(containerURLForSecurityApplicationGroupIdentifier:));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSURL *(id s, NSString *g) { return nil; });
                hookInstanceMethod(fmClass,
                    @selector(containerURLForSecurityApplicationGroupIdentifier:),
                    imp, method_getTypeEncoding(m));
            }
        }

        // ============================================================
        // 6. NSBundle bundleIdentifier — return ORIGINAL Bundle ID
        //    Payment SDKs check bundleIdentifier == "com.baidu.BaiduMobile"
        //    Only hook the METHOD, not infoDictionary (breaks icons).
        // ============================================================
        {
            static NSString *origBundleID = nil;
            static dispatch_once_t onceToken;
            dispatch_once(&onceToken, ^{
                const char parts[] = {99,111,109,46,98,97,105,100,117,46,
                                      66,97,105,100,117,77,111,98,105,108,101,0};
                origBundleID = [NSString stringWithUTF8String:parts];
            });

            Class bundleClass = objc_getClass("NSBundle");
            if (bundleClass) {
                Method m = class_getInstanceMethod(bundleClass, @selector(bundleIdentifier));
                if (m) {
                    static IMP orig_bundleID = NULL;
                    orig_bundleID = method_getImplementation(m);
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        if (s == [NSBundle mainBundle]) {
                            return origBundleID;
                        }
                        return ((NSString *(*)(id, SEL))orig_bundleID)(s, @selector(bundleIdentifier));
                    });
                    hookInstanceMethod(bundleClass, @selector(bundleIdentifier),
                                       imp, method_getTypeEncoding(m));
                }
            }
        }
    }
}
