//
//  PrivacyHook.m
//  Device Fingerprint Isolation Dylib for iOS
//
//  Hooks device identifier APIs to return spoofed values,
//  preventing apps from detecting the same physical device.
//
//  Hooks:
//    - ASIdentifierManager advertisingIdentifier (IDFA)
//    - ASIdentifierManager isAdvertisingTrackingEnabled
//    - ATTrackingManager trackingAuthorizationStatus (iOS 14+)
//    - ATTrackingManager requestTrackingAuthorizationWithCompletionHandler:
//    - UIDevice identifierForVendor (IDFV)
//
//  Spoofed UUIDs are persisted in NSUserDefaults, so they remain
//  consistent across app launches. Since the Bundle ID is different,
//  NSUserDefaults is already isolated between the original and cloned app.
//
//  Build: make
//  Inject: Use modify_ipa.py to inject into IPA
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <AppTrackingTransparency/AppTrackingTransparency.h>
#import <objc/runtime.h>

// ============================================================
// Persistent spoofed identifiers
// ============================================================
static NSUUID *_spoofedIDFA = nil;
static NSUUID *_spoofedIDFV = nil;

// ============================================================
// Generate or load a persistent spoofed UUID from NSUserDefaults.
// The UUID is generated once and persisted, so it stays the same
// across app launches (more natural than changing every time).
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
// (operates on the metaclass)
// ============================================================
static void hookClassMethod(Class cls, SEL sel, IMP newImp, const char *types) {
    Class metaClass = object_getClass(cls); // metaclass
    Method method = class_getClassMethod(cls, sel);
    if (method) {
        const char *existingTypes = types ?: method_getTypeEncoding(method);
        class_replaceMethod(metaClass, sel, newImp, existingTypes);
    }
}

// ============================================================
// Constructor — runs automatically when the dylib is loaded
// (before the app's main() function)
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {
        NSLog(@"[PrivacyHook] Initializing device fingerprint isolation...");

        // Load or create persistent spoofed identifiers
        _spoofedIDFA = getOrCreateSpoofedUUID(@"PrivacyHook.SpoofedIDFA");
        _spoofedIDFV = getOrCreateSpoofedUUID(@"PrivacyHook.SpoofedIDFV");

        NSLog(@"[PrivacyHook] Spoofed IDFA: %@", _spoofedIDFA);
        NSLog(@"[PrivacyHook] Spoofed IDFV: %@", _spoofedIDFV);

        // ----------------------------------------------------
        // 1. Hook ASIdentifierManager - advertisingIdentifier
        //    This is the IDFA (Identifier for Advertising)
        // ----------------------------------------------------
        Class asmClass = objc_getClass("ASIdentifierManager");
        if (asmClass) {
            // advertisingIdentifier → return spoofed IDFA
            Method idfaMethod = class_getInstanceMethod(asmClass, @selector(advertisingIdentifier));
            if (idfaMethod) {
                IMP idfaImp = imp_implementationWithBlock(^NSUUID *(id _self) {
                    return _spoofedIDFA;
                });
                hookInstanceMethod(asmClass, @selector(advertisingIdentifier),
                                   idfaImp, method_getTypeEncoding(idfaMethod));
                NSLog(@"[PrivacyHook] ✓ Hooked ASIdentifierManager advertisingIdentifier");
            }

            // isAdvertisingTrackingEnabled → return YES
            Method trackingMethod = class_getInstanceMethod(asmClass, @selector(isAdvertisingTrackingEnabled));
            if (trackingMethod) {
                IMP trackingImp = imp_implementationWithBlock(^BOOL(id _self) {
                    return YES;
                });
                hookInstanceMethod(asmClass, @selector(isAdvertisingTrackingEnabled),
                                   trackingImp, method_getTypeEncoding(trackingMethod));
                NSLog(@"[PrivacyHook] ✓ Hooked ASIdentifierManager isAdvertisingTrackingEnabled");
            }
        }

        // ----------------------------------------------------
        // 2. Hook ATTrackingManager (iOS 14+)
        //    Make the app think tracking is always authorized
        // ----------------------------------------------------
        Class attClass = objc_getClass("ATTrackingManager");
        if (attClass) {
            // trackingAuthorizationStatus → return Authorized (3)
            // ATTrackingManagerAuthorizationStatusAuthorized = 3
            Method authMethod = class_getClassMethod(attClass, @selector(trackingAuthorizationStatus));
            if (authMethod) {
                IMP authImp = imp_implementationWithBlock(^NSInteger(id _self) {
                    return 3; // ATTrackingManagerAuthorizationStatusAuthorized
                });
                hookClassMethod(attClass, @selector(trackingAuthorizationStatus),
                                authImp, method_getTypeEncoding(authMethod));
                NSLog(@"[PrivacyHook] ✓ Hooked ATTrackingManager trackingAuthorizationStatus");
            }

            // requestTrackingAuthorizationWithCompletionHandler: → immediately call handler with Authorized
            Method reqMethod = class_getClassMethod(attClass,
                @selector(requestTrackingAuthorizationWithCompletionHandler:));
            if (reqMethod) {
                IMP reqImp = imp_implementationWithBlock(^(id _self, void (^handler)(NSInteger)) {
                    NSLog(@"[PrivacyHook] Intercepted ATT request, returning Authorized");
                    if (handler) {
                        dispatch_async(dispatch_get_main_queue(), ^{
                            handler(3); // ATTrackingManagerAuthorizationStatusAuthorized
                        });
                    }
                });
                hookClassMethod(attClass,
                                @selector(requestTrackingAuthorizationWithCompletionHandler:),
                                reqImp, method_getTypeEncoding(reqMethod));
                NSLog(@"[PrivacyHook] ✓ Hooked ATTrackingManager requestTrackingAuthorizationWithCompletionHandler:");
            }
        }

        // ----------------------------------------------------
        // 3. Hook UIDevice - identifierForVendor (IDFV)
        //    Note: Changing Bundle ID already gives a different IDFV,
        //    but we hook it as extra protection.
        // ----------------------------------------------------
        Class uiDeviceClass = objc_getClass("UIDevice");
        if (uiDeviceClass) {
            Method idfvMethod = class_getInstanceMethod(uiDeviceClass, @selector(identifierForVendor));
            if (idfvMethod) {
                IMP idfvImp = imp_implementationWithBlock(^NSUUID *(id _self) {
                    return _spoofedIDFV;
                });
                hookInstanceMethod(uiDeviceClass, @selector(identifierForVendor),
                                   idfvImp, method_getTypeEncoding(idfvMethod));
                NSLog(@"[PrivacyHook] ✓ Hooked UIDevice identifierForVendor");
            }
        }

        NSLog(@"[PrivacyHook] All hooks installed. Device fingerprint is now isolated.");
    }
}
