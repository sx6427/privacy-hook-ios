//
//  PrivacyHook.m
//  Device Fingerprint + Login State Isolation Dylib for iOS
//
//  v19: Modify NSBundle's INTERNAL info dictionary ivar directly.
//
//  Previous problem: hooking infoDictionary METHOD broke icons.
//  New approach: don't hook the method at all. Instead, find the
//  internal NSDictionary ivar inside NSBundle and replace
//  CFBundleIdentifier in the actual data. This way:
//  - infoDictionary method returns the modified dict naturally
//  - objectForInfoDictionaryKey: reads from the same modified dict
//  - bundleIdentifier method is still hooked (belt & suspenders)
//  - No method hook on infoDictionary = no icon issues
//
//  Also: force ONE keychain clear (new flag kc19) to remove any
//  cached risk flags from v14. After that, first-launch-only.
//  User stays logged in on subsequent launches.
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
// NSUserDefaults key prefix
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
// Helper: replace method implementation
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
// Keychain clearing — force one-time clear with new flag
// ============================================================
static void clearKeychainOnce(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    // Use new flag to force one more clear even if old "kc" was set
    NSString *key = kKey(@"kc19");
    if ([defaults boolForKey:key]) return;

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
    [defaults setBool:YES forKey:key];
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
// Modify NSBundle's internal info dictionary ivar directly.
// This changes the ACTUAL data, not the method. All reads of
// infoDictionary and objectForInfoDictionaryKey: will see the
// modified CFBundleIdentifier without any method hooks.
// ============================================================
static void modifyBundleInfoDictionaryIvar(NSString *origBundleID) {
    NSBundle *mainBundle = [NSBundle mainBundle];

    // Force the info dictionary to load by accessing it once
    // (this populates the internal ivar)
    NSDictionary *loaded = [mainBundle infoDictionary];
    if (!loaded) return;

    // Enumerate all ivars of NSBundle to find the one holding the info dict
    unsigned int count = 0;
    Ivar *ivars = class_copyIvarList([NSBundle class], &count);

    for (unsigned int i = 0; i < count; i++) {
        Ivar ivar = ivars[i];
        const char *type = ivar_getTypeEncoding(ivar);
        if (!type || type[0] != '@') continue;

        id value = object_getIvar(mainBundle, ivar);
        if ([value isKindOfClass:[NSDictionary class]]) {
            // Check if this dict contains CFBundleIdentifier
            if ([value objectForKey:@"CFBundleIdentifier"]) {
                // Found the info dictionary ivar!
                // Replace with a mutable copy that has the original Bundle ID
                NSMutableDictionary *modified =
                    [NSMutableDictionary dictionaryWithDictionary:value];
                modified[@"CFBundleIdentifier"] = origBundleID;

                // Also replace CFBundleExecutable if it differs
                // (some SDKs check this too)
                // Keep original value — don't touch other keys

                // Set the modified dict back into the ivar
                object_setIvar(mainBundle, ivar, modified);
                break;
            }
        }
    }
    free(ivars);
}

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {
        // --- Original Bundle ID (runtime-constructed) ---
        static NSString *origBundleID = nil;
        const char parts[] = {99,111,109,46,98,97,105,100,117,46,
                              66,97,105,100,117,77,111,98,105,108,101,0};
        origBundleID = [NSString stringWithUTF8String:parts];

        // --- Initialize spoofed values ---
        _spoofedIDFA = getOrCreateSpoofedUUID(kKey(@"id1"));
        _spoofedIDFV = getOrCreateSpoofedUUID(kKey(@"id2"));
        _spoofedDeviceName = getOrCreateSpoofedDeviceName(kKey(@"dn"));

        // --- Clear keychain ONE TIME (force with new flag) ---
        clearKeychainOnce();

        // --- Clear cookies ---
        clearSharedCookies();

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
        // 6. Bundle ID — THREE layers of protection
        //
        //    Layer A: bundleIdentifier METHOD hook
        //    Layer B: objectForInfoDictionaryKey: hook (only CFBundleIdentifier)
        //    Layer C: ivar modification (changes the ACTUAL internal dict)
        //
        //    Layer C is the key innovation: instead of hooking the
        //    infoDictionary method (which broke icons in v9/v17),
        //    we modify the internal NSDictionary data directly.
        //    This means infoDictionary returns the modified dict
        //    naturally, without any method hook.
        // ============================================================

        // Layer C: Modify internal ivar FIRST (before any method hooks)
        // This ensures the data is correct even if called before hooks are set
        modifyBundleInfoDictionaryIvar(origBundleID);

        // Layer A + B: Method hooks for belt-and-suspenders
        Class bundleClass = objc_getClass("NSBundle");
        if (bundleClass) {
            // 6a. bundleIdentifier method
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

            // 6b. objectForInfoDictionaryKey: — intercept CFBundleIdentifier only
            //     (This was tested in v13.1 and did NOT break icons)
            m = class_getInstanceMethod(bundleClass, @selector(objectForInfoDictionaryKey:));
            if (m) {
                static IMP orig_infoKey = NULL;
                orig_infoKey = method_getImplementation(m);
                IMP imp = imp_implementationWithBlock(^id(id s, NSString *key) {
                    if (s == [NSBundle mainBundle] && key &&
                        [key isEqualToString:@"CFBundleIdentifier"]) {
                        return origBundleID;
                    }
                    return ((id(*)(id, SEL, NSString *))orig_infoKey)(
                        s, @selector(objectForInfoDictionaryKey:), key);
                });
                hookInstanceMethod(bundleClass, @selector(objectForInfoDictionaryKey:),
                                   imp, method_getTypeEncoding(m));
            }
        }
    }
}
