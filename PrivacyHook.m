//
//  PrivacyHook.m — Step 7: Step6 + IOKit hook (IOPlatformUUID)
//
//  Step6 doesn't crash but Baidu still recognizes the device.
//  Missing piece: IOPlatformUUID — hardware-level unique ID that
//  survives factory reset. Baidu reads it via IOKit.
//
//  Hook IORegistryEntryCreateCFProperty via DYLD_INTERPOSE.
//  Return fake UUID/serial when those keys are requested.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <AppTrackingTransparency/AppTrackingTransparency.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <sys/sysctl.h>
#import <string.h>
#import <CoreFoundation/CoreFoundation.h>
#import <IOKit/IOKitLib.h>

#define NSLog(...)

// ============================================================
// DYLD_INTERPOSE macro
// ============================================================
#define DYLD_INTERPOSE(_replacement, _replacee) \
   __attribute__((used)) static struct { \
       const void *replacement; \
       const void *replacee; \
   } _interpose_##_replacee \
   __attribute__((section("__DATA,__interpose"))) = { \
       (const void *)(unsigned long)&_replacement, \
       (const void *)(unsigned long)&_replacee \
   };

// ============================================================
// Spoofed values
// ============================================================
static NSUUID *_spoofedIDFA = nil;
static NSUUID *_spoofedIDFV = nil;
static NSString *_spoofedDeviceName = nil;
static NSString *_spoofedSysVersion = nil;

// C strings for sysctl hook (no ObjC!)
static char _c_machine[32] = {0};
static char _c_hwmodel[32] = {0};

// C strings for IOKit hook (no ObjC!)
static char _c_platformUUID[64] = {0};    // e.g. "A1B2C3D4-..."
static char _c_platformSerial[32] = {0};  // e.g. "F2LXY1234ABCDEFG"

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

static NSString *getOrCreateSpoofedSysVersion(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = kKey(@"sv");
    NSString *existing = [defaults stringForKey:key];
    if (existing) return existing;

    NSArray *versions = @[@"17.4.1", @"17.5.1", @"17.3", @"17.4",
                          @"16.6.1", @"17.2.1", @"17.5"];
    NSString *v = versions[arc4random_uniform((uint32_t)versions.count)];
    [defaults setObject:v forKey:key];
    [defaults synchronize];
    return v;
}

static void initSpoofedHWInfoC(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = kKey(@"hw");

    NSString *saved = [defaults stringForKey:key];
    if (!saved) {
        NSArray *models = @[
            @"iPhone14,5|D27AP",
            @"iPhone14,2|D63AP",
            @"iPhone14,3|D64AP",
            @"iPhone14,7|D37AP",
            @"iPhone14,8|D38AP",
            @"iPhone15,2|D83AP",
            @"iPhone15,3|D84AP",
            @"iPhone15,4|D37AP",
            @"iPhone15,5|D38AP",
            @"iPhone16,1|D93AP",
            @"iPhone16,2|D94AP",
        ];
        saved = models[arc4random_uniform((uint32_t)models.count)];
        [defaults setObject:saved forKey:key];
        [defaults synchronize];
    }

    NSArray *parts = [saved componentsSeparatedByString:@"|"];
    if (parts.count >= 2) {
        strlcpy(_c_machine, [parts[0] UTF8String], sizeof(_c_machine));
        strlcpy(_c_hwmodel, [parts[1] UTF8String], sizeof(_c_hwmodel));
    }
}

// Generate fake IOPlatformUUID + serial number
static void initSpoofedIOKitInfo(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];

    // UUID
    NSString *uuidKey = kKey(@"iouuid");
    NSString *savedUUID = [defaults stringForKey:uuidKey];
    if (!savedUUID) {
        // Generate a random UUID string
        savedUUID = [[NSUUID UUID] UUIDString];
        [defaults setObject:savedUUID forKey:uuidKey];
        [defaults synchronize];
    }
    strlcpy(_c_platformUUID, [savedUUID UTF8String], sizeof(_c_platformUUID));

    // Serial number — random 12-char alphanumeric
    NSString *serialKey = kKey(@"iosn");
    NSString *savedSerial = [defaults stringForKey:serialKey];
    if (!savedSerial) {
        const char *chars = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789";
        char serial[13] = {0};
        for (int i = 0; i < 12; i++) {
            serial[i] = chars[arc4random_uniform(33)];
        }
        savedSerial = [NSString stringWithUTF8String:serial];
        [defaults setObject:savedSerial forKey:serialKey];
        [defaults synchronize];
    }
    strlcpy(_c_platformSerial, [savedSerial UTF8String], sizeof(_c_platformSerial));
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
// Data clearing
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

static void clearURLCache(void) {
    [[NSURLCache sharedURLCache] removeAllCachedResponses];
}

static void clearWebViewData(void) {
    Class wkClass = objc_getClass("WKWebsiteDataStore");
    if (!wkClass) return;
    id defaultStore = [wkClass performSelector:@selector(defaultDataStore)];
    if (!defaultStore) return;

    NSSet *allTypes = [NSSet setWithArray:@[
        @"WKWebsiteDataTypeCookies",
        @"WKWebsiteDataTypeSessionStorage",
        @"WKWebsiteDataTypeLocalStorage",
        @"WKWebsiteDataTypeWebSQLDatabases",
        @"WKWebsiteDataTypeIndexedDBDatabases",
        @"WKWebsiteDataTypeDiskCache",
        @"WKWebsiteDataTypeMemoryCache",
        @"WKWebsiteDataTypeOfflineWebApplicationCache",
        @"WKWebsiteDataTypeFetchCache",
        @"WKWebsiteDataTypeServiceWorkerRegistrations",
    ]];

    SEL fetchSel = NSSelectorFromString(@"fetchDataRecordsOfTypes:completionHandler:");
    SEL removeSel = NSSelectorFromString(@"removeDataOfTypes:forDataRecords:completionHandler:");
    if (![defaultStore respondsToSelector:fetchSel]) return;

    ((void(*)(id, SEL, NSSet *, void(^)(NSArray *)))objc_msgSend)(
        defaultStore, fetchSel, allTypes, ^(NSArray *records) {
        if (![defaultStore respondsToSelector:removeSel]) return;
        ((void(*)(id, SEL, NSSet *, NSArray *, void(^)()))objc_msgSend)(
            defaultStore, removeSel, allTypes, records, ^{});
    });
}

// ============================================================
// DYLD_INTERPOSE: sysctlbyname — PURE C
// ============================================================
static int my_sysctlbyname(const char *name, void *oldp,
                            size_t *oldlenp, void *newp,
                            size_t newlen) {
    if (name && newp == NULL && newlen == 0) {

        if (strcmp(name, "hw.machine") == 0 && _c_machine[0] != 0) {
            size_t need = strlen(_c_machine) + 1;
            if (oldp == NULL) {
                if (oldlenp) *oldlenp = need;
                return 0;
            }
            if (oldlenp && *oldlenp >= need) {
                memcpy(oldp, _c_machine, need);
                *oldlenp = need;
                return 0;
            }
        }

        if (strcmp(name, "hw.model") == 0 && _c_hwmodel[0] != 0) {
            size_t need = strlen(_c_hwmodel) + 1;
            if (oldp == NULL) {
                if (oldlenp) *oldlenp = need;
                return 0;
            }
            if (oldlenp && *oldlenp >= need) {
                memcpy(oldp, _c_hwmodel, need);
                *oldlenp = need;
                return 0;
            }
        }

        // Also intercept hw.serialnumber and hw.memsize
        if (strcmp(name, "hw.serialnumber") == 0 && _c_platformSerial[0] != 0) {
            size_t need = strlen(_c_platformSerial) + 1;
            if (oldp == NULL) {
                if (oldlenp) *oldlenp = need;
                return 0;
            }
            if (oldlenp && *oldlenp >= need) {
                memcpy(oldp, _c_platformSerial, need);
                *oldlenp = need;
                return 0;
            }
        }
    }

    return sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

DYLD_INTERPOSE(my_sysctlbyname, sysctlbyname);

// ============================================================
// DYLD_INTERPOSE: IORegistryEntryCreateCFProperty
// ============================================================
// Hook IOKit to fake IOPlatformUUID and IOPlatformSerialNumber.
// These are the #1 hardware identifiers used by device fingerprinting.
// Uses CoreFoundation only (no ObjC) for safety.

static CFTypeRef my_IORegistryEntryCreateCFProperty(
    io_registry_entry_t entry,
    CFStringRef key,
    CFAllocatorRef allocator,
    IOOptionBits options) {

    if (key && _c_platformUUID[0] != 0) {
        // IOPlatformUUID
        if (CFStringCompare(key, CFSTR("IOPlatformUUID"), 0) == kCFCompareEqualTo) {
            return CFStringCreateWithCString(allocator, _c_platformUUID,
                                             kCFStringEncodingUTF8);
        }
        // IOPlatformSerialNumber
        if (CFStringCompare(key, CFSTR("IOPlatformSerialNumber"), 0) == kCFCompareEqualTo) {
            return CFStringCreateWithCString(allocator, _c_platformSerial,
                                             kCFStringEncodingUTF8);
        }
    }

    return IORegistryEntryCreateCFProperty(entry, key, allocator, options);
}

DYLD_INTERPOSE(my_IORegistryEntryCreateCFProperty, IORegistryEntryCreateCFProperty);

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {
        // --- Init ALL spoofed values FIRST ---
        _spoofedIDFA = getOrCreateSpoofedUUID(kKey(@"id1"));
        _spoofedIDFV = getOrCreateSpoofedUUID(kKey(@"id2"));
        _spoofedDeviceName = getOrCreateSpoofedDeviceName(kKey(@"dn"));
        _spoofedSysVersion = getOrCreateSpoofedSysVersion();
        initSpoofedHWInfoC();
        initSpoofedIOKitInfo();

        // --- Clear stored data ---
        clearKeychainOnce();
        clearSharedCookies();
        clearURLCache();
        clearWebViewData();

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

        // --- 3. UIDevice ---
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
            m = class_getInstanceMethod(uiDeviceClass, @selector(systemVersion));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSString *(id s) { return _spoofedSysVersion; });
                hookInstanceMethod(uiDeviceClass, @selector(systemVersion), imp, method_getTypeEncoding(m));
            }
        }

        // --- 4. UIPasteboard ---
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
