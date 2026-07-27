//
//  PrivacyHook.m — Step 4: Step3 + fishhook(sysctlbyname) + UIDevice model
//
//  Complete device fingerprint spoofing:
//    - IDFA, IDFV, device name (Step3)
//    - sysctlbyname hw.machine / hw.model (fishhook)
//    - UIDevice model / localizedModel / systemVersion
//    - Keychain clear, cookie clear, pasteboard, app group (Step3)
//    - NO Bundle ID spoof (causes icon disappearance)
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <AppTrackingTransparency/AppTrackingTransparency.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <sys/sysctl.h>
#import "fishhook.h"

#define NSLog(...)

// ============================================================
// Spoofed values
// ============================================================
static NSUUID *_spoofedIDFA = nil;
static NSUUID *_spoofedIDFV = nil;
static NSString *_spoofedDeviceName = nil;
static NSString *_spoofedModel = nil;       // hw.machine e.g. "iPhone15,2"
static NSString *_spoofedHWModel = nil;     // hw.model  e.g. "D83AP"
static NSString *_spoofedSysVersion = nil;  // e.g. "17.4.1"

// Common iPhone models + their hw.model board identifiers
// Each clone picks a different entry for realistic-looking device diversity
static NSDictionary *DEVICE_MODELS = nil;

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

// Pick a random device model and persist it per-clone
static void initSpoofedHWInfo(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];

    // Already assigned?
    NSString *saved = [defaults stringForKey:kKey(@"hw")];
    if (saved) {
        NSArray *parts = [saved componentsSeparatedByString:@"|"];
        if (parts.count >= 3) {
            _spoofedModel = parts[0];
            _spoofedHWModel = parts[1];
            _spoofedSysVersion = parts[2];
            return;
        }
    }

    // iPhone models: hw.machine -> hw.model mapping
    // Format: hw.machine (marketing) | hw.model (board) | typical iOS version
    NSArray *models = @[
        @"iPhone14,5|D27AP|17.4.1",   // iPhone 13
        @"iPhone14,2|D63AP|17.4.1",   // iPhone 13 Pro
        @"iPhone14,3|D64AP|17.3",     // iPhone 13 Pro Max
        @"iPhone14,7|D37AP|17.4.1",   // iPhone 14
        @"iPhone14,8|D38AP|17.4.1",   // iPhone 14 Plus
        @"iPhone15,2|D83AP|17.4.1",   // iPhone 14 Pro
        @"iPhone15,3|D84AP|17.4.1",   // iPhone 14 Pro Max
        @"iPhone15,4|D37AP|17.5.1",   // iPhone 15
        @"iPhone15,5|D38AP|17.5.1",   // iPhone 15 Plus
        @"iPhone16,1|D93AP|17.5.1",   // iPhone 15 Pro
        @"iPhone16,2|D94AP|17.5.1",   // iPhone 15 Pro Max
    ];

    NSString *chosen = models[arc4random_uniform((uint32_t)models.count)];
    NSArray *parts = [chosen componentsSeparatedByString:@"|"];
    _spoofedModel = parts[0];
    _spoofedHWModel = parts[1];
    _spoofedSysVersion = parts[2];

    NSString *combined = [NSString stringWithFormat:@"%@|%@|%@",
                          _spoofedModel, _spoofedHWModel, _spoofedSysVersion];
    [defaults setObject:combined forKey:kKey(@"hw")];
    [defaults synchronize];
}

// ============================================================
// Method hooking helpers
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
// Keychain + Cookie clearing
// ============================================================
static void clearKeychainOnce(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = kKey(@"kc23");
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
// fishhook: sysctlbyname
// ============================================================

// Function pointer to original sysctlbyname
static int (*orig_sysctlbyname)(const char *name, void *oldp,
                                 size_t *oldlenp, void *newp,
                                 size_t newlen) = NULL;

static int hooked_sysctlbyname(const char *name, void *oldp,
                                size_t *oldlenp, void *newp,
                                size_t newlen) {
    // Only intercept read-only queries (newp == NULL, newlen == 0)
    if (name && oldp && oldlenp && newp == NULL && newlen == 0) {

        // hw.machine -> e.g. "iPhone15,2"
        if (strcmp(name, "hw.machine") == 0) {
            const char *model = [_spoofedModel UTF8String];
            size_t modelLen = strlen(model) + 1;
            if (*oldlenp >= modelLen) {
                memcpy(oldp, model, modelLen);
                *oldlenp = modelLen;
                return 0;
            }
        }

        // hw.model -> e.g. "D83AP"
        if (strcmp(name, "hw.model") == 0) {
            const char *hwmodel = [_spoofedHWModel UTF8String];
            size_t hwLen = strlen(hwmodel) + 1;
            if (*oldlenp >= hwLen) {
                memcpy(oldp, hwmodel, hwLen);
                *oldlenp = hwLen;
                return 0;
            }
        }
    }

    // Pass through to original
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {
        // Initialize spoofed values
        _spoofedIDFA = getOrCreateSpoofedUUID(kKey(@"id1"));
        _spoofedIDFV = getOrCreateSpoofedUUID(kKey(@"id2"));
        _spoofedDeviceName = getOrCreateSpoofedDeviceName(kKey(@"dn"));
        initSpoofedHWInfo();

        // Clear keychain + cookies
        clearKeychainOnce();
        clearSharedCookies();

        // --- fishhook: sysctlbyname ---
        struct rebinding r = {
            "sysctlbyname",
            (void *)hooked_sysctlbyname,
            (void **)&orig_sysctlbyname
        };
        rebind_symbols(&r, 1);

        // --- 1. IDFA ---
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

        // --- 2. ATTrackingManager ---
        Class attClass = objc_getClass("ATTrackingManager");
        if (attClass) {
            Method m = class_getClassMethod(attClass, @selector(trackingAuthorizationStatus));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSInteger(id s) { return 3; });
                hookClassMethod(attClass, @selector(trackingAuthorizationStatus), imp, method_getTypeEncoding(m));
            }
        }

        // --- 3. UIDevice: IDFV + name + model + systemVersion ---
        Class uiDeviceClass = objc_getClass("UIDevice");
        if (uiDeviceClass) {
            // identifierForVendor
            Method m = class_getInstanceMethod(uiDeviceClass, @selector(identifierForVendor));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSUUID *(id s) { return _spoofedIDFV; });
                hookInstanceMethod(uiDeviceClass, @selector(identifierForVendor), imp, method_getTypeEncoding(m));
            }
            // name
            m = class_getInstanceMethod(uiDeviceClass, @selector(name));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSString *(id s) { return _spoofedDeviceName; });
                hookInstanceMethod(uiDeviceClass, @selector(name), imp, method_getTypeEncoding(m));
            }
            // model — returns "iPhone" for all iPhones, keep as-is
            // (changing this would be suspicious and could break things)
            // localizedModel — same

            // systemVersion — spoof to match our fake hw.machine
            m = class_getInstanceMethod(uiDeviceClass, @selector(systemVersion));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSString *(id s) { return _spoofedSysVersion; });
                hookInstanceMethod(uiDeviceClass, @selector(systemVersion), imp, method_getTypeEncoding(m));
            }
        }

        // --- 4. UIPasteboard — block ALL reads ---
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

        // --- 5. App Group container blocked ---
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
    }
}
