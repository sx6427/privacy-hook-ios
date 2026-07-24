//
//  PrivacyHook.m
//  Device Fingerprint + Login State Isolation Dylib for iOS
//
//  v2: Added UIPasteboard, Keychain, Cookie, App Group isolation
//
//  Hooks:
//    [Device Fingerprint]
//    - ASIdentifierManager advertisingIdentifier (IDFA)
//    - ASIdentifierManager isAdvertisingTrackingEnabled
//    - ATTrackingManager trackingAuthorizationStatus (iOS 14+)
//    - ATTrackingManager requestTrackingAuthorizationWithCompletionHandler:
//    - UIDevice identifierForVendor (IDFV)
//
//    [Login State Isolation - NEW in v2]
//    - UIPasteboard (blocks clipboard-based cross-app login sharing)
//    - Keychain clear on first launch (removes original app's credentials)
//    - NSHTTPCookieStorage (clears shared cookies on every launch)
//    - NSFileManager containerURLForSecurityApplicationGroupIdentifier: (blocks App Groups)
//
//  Build: make
//  Inject: Use modify_ipa.py to inject into IPA
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <AppTrackingTransparency/AppTrackingTransparency.h>
#import <Security/Security.h>
#import <objc/runtime.h>

// ============================================================
// Persistent spoofed identifiers
// ============================================================
static NSUUID *_spoofedIDFA = nil;
static NSUUID *_spoofedIDFV = nil;

// ============================================================
// Generate or load a persistent spoofed UUID from NSUserDefaults
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

// ============================================================
// Helper: replace a class method's implementation
// ============================================================
static void hookClassMethod(Class cls, SEL sel, IMP newImp, const char *types) {
    Class metaClass = object_getClass(cls);
    Method method = class_getClassMethod(cls, sel);
    if (method) {
        const char *existingTypes = types ?: method_getTypeEncoding(method);
        class_replaceMethod(metaClass, sel, newImp, existingTypes);
    }
}

// ============================================================
// Clear keychain on first launch only.
// On subsequent launches, the app can use keychain normally
// to persist its own login state.
// ============================================================
static void clearKeychainOnFirstLaunch(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    if ([defaults boolForKey:@"PrivacyHook.KeychainCleared"]) {
        NSLog(@"[PrivacyHook] Keychain already cleared on previous launch, skipping");
        return;
    }

    // Delete all keychain items of each class
    NSArray *secItemClasses = @[
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword,
        (__bridge id)kSecClassKey,
        (__bridge id)kSecClassCertificate,
        (__bridge id)kSecClassIdentity
    ];

    for (id secItemClass in secItemClasses) {
        NSDictionary *query = @{(__bridge id)kSecClass: secItemClass};
        OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
        NSLog(@"[PrivacyHook] Cleared keychain class %@ (status: %d)", secItemClass, status);
    }

    [defaults setBool:YES forKey:@"PrivacyHook.KeychainCleared"];
    [defaults synchronize];
    NSLog(@"[PrivacyHook] ✓ Keychain cleared on first launch");
}

// ============================================================
// Clear all shared cookies on every launch
// ============================================================
static void clearSharedCookies(void) {
    NSHTTPCookieStorage *storage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    NSArray *cookies = [[storage cookies] copy];
    for (NSHTTPCookie *cookie in cookies) {
        [storage deleteCookie:cookie];
    }
    NSLog(@"[PrivacyHook] ✓ Cleared %lu shared cookies", (unsigned long)cookies.count);
}

// ============================================================
// Constructor — runs automatically when the dylib is loaded
// (before the app's main() function)
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {
        NSLog(@"[PrivacyHook] v2 Initializing: fingerprint + login state isolation...");

        // Load or create persistent spoofed identifiers
        _spoofedIDFA = getOrCreateSpoofedUUID(@"PrivacyHook.SpoofedIDFA");
        _spoofedIDFV = getOrCreateSpoofedUUID(@"PrivacyHook.SpoofedIDFV");

        NSLog(@"[PrivacyHook] Spoofed IDFA: %@", _spoofedIDFA);
        NSLog(@"[PrivacyHook] Spoofed IDFV: %@", _spoofedIDFV);

        // ============================================================
        // 1. ASIdentifierManager - IDFA
        // ============================================================
        Class asmClass = objc_getClass("ASIdentifierManager");
        if (asmClass) {
            Method idfaMethod = class_getInstanceMethod(asmClass, @selector(advertisingIdentifier));
            if (idfaMethod) {
                IMP idfaImp = imp_implementationWithBlock(^NSUUID *(id _self) {
                    return _spoofedIDFA;
                });
                hookInstanceMethod(asmClass, @selector(advertisingIdentifier),
                                   idfaImp, method_getTypeEncoding(idfaMethod));
                NSLog(@"[PrivacyHook] ✓ Hooked IDFA");
            }

            Method trackingMethod = class_getInstanceMethod(asmClass, @selector(isAdvertisingTrackingEnabled));
            if (trackingMethod) {
                IMP trackingImp = imp_implementationWithBlock(^BOOL(id _self) {
                    return YES;
                });
                hookInstanceMethod(asmClass, @selector(isAdvertisingTrackingEnabled),
                                   trackingImp, method_getTypeEncoding(trackingMethod));
                NSLog(@"[PrivacyHook] ✓ Hooked isAdvertisingTrackingEnabled");
            }
        }

        // ============================================================
        // 2. ATTrackingManager (iOS 14+)
        // ============================================================
        Class attClass = objc_getClass("ATTrackingManager");
        if (attClass) {
            Method authMethod = class_getClassMethod(attClass, @selector(trackingAuthorizationStatus));
            if (authMethod) {
                IMP authImp = imp_implementationWithBlock(^NSInteger(id _self) {
                    return 3; // ATTrackingManagerAuthorizationStatusAuthorized
                });
                hookClassMethod(attClass, @selector(trackingAuthorizationStatus),
                                authImp, method_getTypeEncoding(authMethod));
                NSLog(@"[PrivacyHook] ✓ Hooked ATT trackingAuthorizationStatus");
            }

            Method reqMethod = class_getClassMethod(attClass,
                @selector(requestTrackingAuthorizationWithCompletionHandler:));
            if (reqMethod) {
                IMP reqImp = imp_implementationWithBlock(^(id _self, void (^handler)(NSInteger)) {
                    if (handler) {
                        dispatch_async(dispatch_get_main_queue(), ^{
                            handler(3);
                        });
                    }
                });
                hookClassMethod(attClass,
                                @selector(requestTrackingAuthorizationWithCompletionHandler:),
                                reqImp, method_getTypeEncoding(reqMethod));
                NSLog(@"[PrivacyHook] ✓ Hooked ATT requestTrackingAuthorization");
            }
        }

        // ============================================================
        // 3. UIDevice - identifierForVendor (IDFV)
        // ============================================================
        Class uiDeviceClass = objc_getClass("UIDevice");
        if (uiDeviceClass) {
            Method idfvMethod = class_getInstanceMethod(uiDeviceClass, @selector(identifierForVendor));
            if (idfvMethod) {
                IMP idfvImp = imp_implementationWithBlock(^NSUUID *(id _self) {
                    return _spoofedIDFV;
                });
                hookInstanceMethod(uiDeviceClass, @selector(identifierForVendor),
                                   idfvImp, method_getTypeEncoding(idfvMethod));
                NSLog(@"[PrivacyHook] ✓ Hooked IDFV");
            }
        }

        // ============================================================
        // 4. UIPasteboard — Block clipboard reads
        //    This is the #1 way Chinese apps share login state.
        //    Baidu writes a login token to the system pasteboard,
        //    and the clone reads it for auto-login.
        //    We return empty for ALL read operations.
        // ============================================================
        Class pbClass = objc_getClass("UIPasteboard");
        if (pbClass) {
            // string → return @""
            Method stringMethod = class_getInstanceMethod(pbClass, @selector(string));
            if (stringMethod) {
                IMP stringImp = imp_implementationWithBlock(^NSString *(id _self) {
                    return @"";
                });
                hookInstanceMethod(pbClass, @selector(string),
                                   stringImp, method_getTypeEncoding(stringMethod));
            }

            // strings → return @[]
            Method stringsMethod = class_getInstanceMethod(pbClass, @selector(strings));
            if (stringsMethod) {
                IMP stringsImp = imp_implementationWithBlock(^NSArray *(id _self) {
                    return @[];
                });
                hookInstanceMethod(pbClass, @selector(strings),
                                   stringsImp, method_getTypeEncoding(stringsMethod));
            }

            // dataForPasteboardType: → return nil
            Method dataMethod = class_getInstanceMethod(pbClass, @selector(dataForPasteboardType:));
            if (dataMethod) {
                IMP dataImp = imp_implementationWithBlock(^NSData *(id _self, NSString *type) {
                    return nil;
                });
                hookInstanceMethod(pbClass, @selector(dataForPasteboardType:),
                                   dataImp, method_getTypeEncoding(dataMethod));
            }

            // valueForPasteboardType: → return nil
            Method valueMethod = class_getInstanceMethod(pbClass, @selector(valueForPasteboardType:));
            if (valueMethod) {
                IMP valueImp = imp_implementationWithBlock(^id(id _self, NSString *type) {
                    return nil;
                });
                hookInstanceMethod(pbClass, @selector(valueForPasteboardType:),
                                   valueImp, method_getTypeEncoding(valueMethod));
            }

            // items → return @[]
            Method itemsMethod = class_getInstanceMethod(pbClass, @selector(items));
            if (itemsMethod) {
                IMP itemsImp = imp_implementationWithBlock(^NSArray *(id _self) {
                    return @[];
                });
                hookInstanceMethod(pbClass, @selector(items),
                                   itemsImp, method_getTypeEncoding(itemsMethod));
            }

            // containsPasteboardTypes: → return NO
            Method containsMethod = class_getInstanceMethod(pbClass, @selector(containsPasteboardTypes:));
            if (containsMethod) {
                IMP containsImp = imp_implementationWithBlock(^BOOL(id _self, NSArray *types) {
                    return NO;
                });
                hookInstanceMethod(pbClass, @selector(containsPasteboardTypes:),
                                   containsImp, method_getTypeEncoding(containsMethod));
            }

            NSLog(@"[PrivacyHook] ✓ Hooked UIPasteboard (clipboard isolation)");
        }

        // ============================================================
        // 5. Keychain — Clear on first launch
        //    Removes any credentials that might be shared via
        //    TrollStore's shared keychain access group.
        //    Only runs once; subsequent launches use keychain normally.
        // ============================================================
        clearKeychainOnFirstLaunch();

        // ============================================================
        // 6. NSHTTPCookieStorage — Clear shared cookies
        // ============================================================
        clearSharedCookies();

        // ============================================================
        // 7. NSFileManager — Block App Group container access
        //    Prevents reading shared files via App Groups
        // ============================================================
        Class fmClass = objc_getClass("NSFileManager");
        if (fmClass) {
            Method groupMethod = class_getInstanceMethod(fmClass,
                @selector(containerURLForSecurityApplicationGroupIdentifier:));
            if (groupMethod) {
                IMP groupImp = imp_implementationWithBlock(^NSURL *(id _self, NSString *groupIdentifier) {
                    NSLog(@"[PrivacyHook] Blocked App Group access: %@", groupIdentifier);
                    return nil;
                });
                hookInstanceMethod(fmClass,
                                   @selector(containerURLForSecurityApplicationGroupIdentifier:),
                                   groupImp, method_getTypeEncoding(groupMethod));
                NSLog(@"[PrivacyHook] ✓ Hooked App Group container access");
            }
        }

        NSLog(@"[PrivacyHook] v2 All hooks installed. Fingerprint + login state isolated.");
    }
}
