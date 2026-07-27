//
//  PrivacyHook.m — Step 15: Keychain spy + all interpose
//
//  Step14 result: ALL C functions 0 calls!
//  sysctlbyname=0, sysctl=0, IORegistry=0, getifaddrs=0
//
//  Baidu does NOT use C functions for device ID.
//  Most likely: Baidu stores its own device_id in Keychain.
//
//  Step15: Hook SecItemAdd/SecItemCopyMatching/SecItemUpdate
//  to see what Baidu reads/writes from keychain.
//  Also hook NSUserDefaults to see what device IDs are stored.
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
#import <ifaddrs.h>
#import <mach-o/dyld.h>

#define NSLog(...)

// ============================================================
// Diagnostic counters
// ============================================================
static volatile int diag_sbn_called = 0;
static volatile int diag_sc_called = 0;
static volatile int diag_iok_called = 0;
static volatile int diag_gifa_called = 0;
static volatile int diag_sec_add = 0;
static volatile int diag_sec_copy = 0;
static volatile int diag_sec_update = 0;
static volatile int diag_sec_delete = 0;

static NSMutableArray *diag_keychain_keys = nil;
static NSMutableArray *diag_defaults_keys = nil;

// ============================================================
// Spoofed values
// ============================================================
static NSUUID *_spoofedIDFA = nil;
static NSUUID *_spoofedIDFV = nil;
static NSString *_spoofedDeviceName = nil;
static NSString *_spoofedSysVersion = nil;
static NSString *_spoofedUserAgent = nil;
static NSString *_spoofedWebKitUA = nil;

static char _c_machine[32] = {0};
static char _c_hwmodel[32] = {0};
static char _c_platformUUID[64] = {0};
static char _c_platformSerial[32] = {0};

// ============================================================
// DYLD_INTERPOSE
// ============================================================
#define DYLD_INTERPOSE(_replacement, _replacee) \
  __attribute__((used)) static struct { \
      const void *replacement; \
      const void *replacee; \
  } _interpose_##_replacee \
  __attribute__ ((section ("__DATA,__interpose"))) = { \
      (const void *)(unsigned long)&_replacement, \
      (const void *)(unsigned long)&_replacee, \
  };

// ============================================================
// C function hooks (same as Step14, keep for completeness)
// ============================================================
static int my_sysctlbyname(const char *name, void *oldp,
                            size_t *oldlenp, void *newp, size_t newlen) {
    diag_sbn_called++;
    if (name && newp == NULL && newlen == 0) {
        if (strcmp(name, "hw.machine") == 0 && _c_machine[0] != 0) {
            size_t need = strlen(_c_machine) + 1;
            if (oldp == NULL) { if (oldlenp) *oldlenp = need; return 0; }
            if (oldlenp && *oldlenp >= need) { memcpy(oldp, _c_machine, need); *oldlenp = need; return 0; }
        }
        if (strcmp(name, "hw.model") == 0 && _c_hwmodel[0] != 0) {
            size_t need = strlen(_c_hwmodel) + 1;
            if (oldp == NULL) { if (oldlenp) *oldlenp = need; return 0; }
            if (oldlenp && *oldlenp >= need) { memcpy(oldp, _c_hwmodel, need); *oldlenp = need; return 0; }
        }
    }
    return sysctlbyname(name, oldp, oldlenp, newp, newlen);
}
DYLD_INTERPOSE(my_sysctlbyname, sysctlbyname);

static int my_sysctl(int *name, u_int namelen, void *oldp,
                     size_t *oldlenp, void *newp, size_t newlen) {
    diag_sc_called++;
    return sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}
DYLD_INTERPOSE(my_sysctl, sysctl);

static CFTypeRef my_IORegistryEntryCreateCFProperty(
    io_registry_entry_t entry, CFStringRef key,
    CFAllocatorRef allocator, IOOptionBits options) {
    diag_iok_called++;
    if (key && _c_platformUUID[0] != 0) {
        if (CFStringCompare(key, CFSTR("IOPlatformUUID"), 0) == kCFCompareEqualTo)
            return CFStringCreateWithCString(allocator, _c_platformUUID, kCFStringEncodingUTF8);
        if (CFStringCompare(key, CFSTR("IOPlatformSerialNumber"), 0) == kCFCompareEqualTo)
            return CFStringCreateWithCString(allocator, _c_platformSerial, kCFStringEncodingUTF8);
    }
    return IORegistryEntryCreateCFProperty(entry, key, allocator, options);
}
DYLD_INTERPOSE(my_IORegistryEntryCreateCFProperty, IORegistryEntryCreateCFProperty);

static int my_getifaddrs(struct ifaddrs **ifap) {
    diag_gifa_called++;
    *ifap = NULL;
    return 0;
}
DYLD_INTERPOSE(my_getifaddrs, getifaddrs);

// ============================================================
// Keychain spy hooks — see what Baidu reads/writes
// ============================================================
static OSStatus my_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    diag_sec_add++;
    if (attributes && diag_keychain_keys) {
        CFStringRef acct = CFDictionaryGetValue(attributes, kSecAttrAccount);
        CFStringRef svc = CFDictionaryGetValue(attributes, kSecAttrService);
        CFStringRef label = CFDictionaryGetValue(attributes, kSecAttrLabel);
        NSString *key = [NSString stringWithFormat:@"ADD: acct=%@ svc=%@ label=%@",
                         acct ? (__bridge NSString *)acct : @"(null)",
                         svc ? (__bridge NSString *)svc : @"(null)",
                         label ? (__bridge NSString *)label : @"(null)"];
        @synchronized(diag_keychain_keys) { [diag_keychain_keys addObject:key]; }
    }
    return SecItemAdd(attributes, result);
}
DYLD_INTERPOSE(my_SecItemAdd, SecItemAdd);

static OSStatus my_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    diag_sec_copy++;
    if (query && diag_keychain_keys) {
        CFStringRef acct = CFDictionaryGetValue(query, kSecAttrAccount);
        CFStringRef svc = CFDictionaryGetValue(query, kSecAttrService);
        CFStringRef label = CFDictionaryGetValue(query, kSecAttrLabel);
        NSString *key = [NSString stringWithFormat:@"READ: acct=%@ svc=%@",
                         acct ? (__bridge NSString *)acct : @"*",
                         svc ? (__bridge NSString *)svc : @"*"];
        @synchronized(diag_keychain_keys) { [diag_keychain_keys addObject:key]; }
    }
    return SecItemCopyMatching(query, result);
}
DYLD_INTERPOSE(my_SecItemCopyMatching, SecItemCopyMatching);

static OSStatus my_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    diag_sec_update++;
    if (query && diag_keychain_keys) {
        CFStringRef acct = CFDictionaryGetValue(query, kSecAttrAccount);
        CFStringRef svc = CFDictionaryGetValue(query, kSecAttrService);
        NSString *key = [NSString stringWithFormat:@"UPD: acct=%@ svc=%@",
                         acct ? (__bridge NSString *)acct : @"*",
                         svc ? (__bridge NSString *)svc : @"*"];
        @synchronized(diag_keychain_keys) { [diag_keychain_keys addObject:key]; }
    }
    return SecItemUpdate(query, attributesToUpdate);
}
DYLD_INTERPOSE(my_SecItemUpdate, SecItemUpdate);

static OSStatus my_SecItemDelete(CFDictionaryRef query) {
    diag_sec_delete++;
    return SecItemDelete(query);
}
DYLD_INTERPOSE(my_SecItemDelete, SecItemDelete);

// ============================================================
// Spoofed value initialization
// ============================================================
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
            @"iPhone14,5|D27AP", @"iPhone14,2|D63AP", @"iPhone14,3|D64AP",
            @"iPhone14,7|D37AP", @"iPhone14,8|D38AP", @"iPhone15,2|D83AP",
            @"iPhone15,3|D84AP", @"iPhone15,4|D37AP", @"iPhone15,5|D38AP",
            @"iPhone16,1|D93AP", @"iPhone16,2|D94AP",
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

static void initSpoofedIOKitInfo(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *uuidKey = kKey(@"iouuid");
    NSString *savedUUID = [defaults stringForKey:uuidKey];
    if (!savedUUID) {
        savedUUID = [[NSUUID UUID] UUIDString];
        [defaults setObject:savedUUID forKey:uuidKey];
        [defaults synchronize];
    }
    strlcpy(_c_platformUUID, [savedUUID UTF8String], sizeof(_c_platformUUID));
    NSString *serialKey = kKey(@"iosn");
    NSString *savedSerial = [defaults stringForKey:serialKey];
    if (!savedSerial) {
        const char *chars = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789";
        char serial[13] = {0};
        for (int i = 0; i < 12; i++) serial[i] = chars[arc4random_uniform(33)];
        savedSerial = [NSString stringWithUTF8String:serial];
        [defaults setObject:savedSerial forKey:serialKey];
        [defaults synchronize];
    }
    strlcpy(_c_platformSerial, [savedSerial UTF8String], sizeof(_c_platformSerial));
}

static void initSpoofedUserAgent(void) {
    NSString *uaVersion = [_spoofedSysVersion stringByReplacingOccurrencesOfString:@"." withString:@"_"];
    _spoofedWebKitUA = [NSString stringWithFormat:
        @"Mozilla/5.0 (iPhone; CPU iPhone OS %@ like Mac OS X) "
        @"AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", uaVersion];
    _spoofedUserAgent = [NSString stringWithFormat:
        @"Mozilla/5.0 (iPhone; CPU iPhone OS %@ like Mac OS X) "
        @"AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148", uaVersion];
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
// Data clearing — DON'T clear keychain this time!
// We want to see what's in it via the spy hooks.
// ============================================================
static void clearSharedCookies(void) {
    NSHTTPCookieStorage *storage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    NSArray *cookies = [[storage cookies] copy];
    for (NSHTTPCookie *cookie in cookies) [storage deleteCookie:cookie];
}

static void clearURLCache(void) { [[NSURLCache sharedURLCache] removeAllCachedResponses]; }

static void clearWebViewData(void) {
    Class wkClass = objc_getClass("WKWebsiteDataStore");
    if (!wkClass) return;
    id defaultStore = [wkClass performSelector:@selector(defaultDataStore)];
    if (!defaultStore) return;
    NSSet *allTypes = [NSSet setWithArray:@[
        @"WKWebsiteDataTypeCookies", @"WKWebsiteDataTypeSessionStorage", @"WKWebsiteDataTypeLocalStorage",
        @"WKWebsiteDataTypeWebSQLDatabases", @"WKWebsiteDataTypeIndexedDBDatabases", @"WKWebsiteDataTypeDiskCache",
        @"WKWebsiteDataTypeMemoryCache", @"WKWebsiteDataTypeOfflineWebApplicationCache",
        @"WKWebsiteDataTypeFetchCache", @"WKWebsiteDataTypeServiceWorkerRegistrations",
    ]];
    SEL fetchSel = NSSelectorFromString(@"fetchDataRecordsOfTypes:completionHandler:");
    SEL removeSel = NSSelectorFromString(@"removeDataOfTypes:forDataRecords:completionHandler:");
    if (![defaultStore respondsToSelector:fetchSel]) return;
    ((void(*)(id, SEL, NSSet *, void(^)(NSArray *)))objc_msgSend)(defaultStore, fetchSel, allTypes, ^(NSArray *records) {
        if (![defaultStore respondsToSelector:removeSel]) return;
        ((void(*)(id, SEL, NSSet *, NSArray *, void(^)()))objc_msgSend)(defaultStore, removeSel, allTypes, records, ^{});
    });
}

// ============================================================
// Diagnostic popup
// ============================================================
static void showDiagnosticPopup(void) {
    NSString *kcReport = @"(none)";
    if (diag_keychain_keys && diag_keychain_keys.count > 0) {
        @synchronized(diag_keychain_keys) {
            // Show up to 15 entries
            NSInteger max = MIN(diag_keychain_keys.count, 15);
            kcReport = [[diag_keychain_keys subarrayWithRange:NSMakeRange(0, max)] componentsJoinedByString:@"\n"];
            if (diag_keychain_keys.count > max) {
                kcReport = [kcReport stringByAppendingFormat:@"\n... +%d more", (int)(diag_keychain_keys.count - max)];
            }
        }
    }

    NSString *msg = [NSString stringWithFormat:
        @"=== Step15 Keychain Spy ===\n\n"
        @"C函数: sbn=%d sc=%d iok=%d gifa=%d\n\n"
        @"Keychain操作:\n"
        @"  Add: %d  Read: %d\n"
        @"  Update: %d  Delete: %d\n\n"
        @"Keychain记录:\n%@\n\n"
        @"ObjC: 已生效\n"
        @"设备名: %@\n系统版本: %@",
        diag_sbn_called, diag_sc_called, diag_iok_called, diag_gifa_called,
        diag_sec_add, diag_sec_copy, diag_sec_update, diag_sec_delete,
        kcReport,
        _spoofedDeviceName, _spoofedSysVersion];

    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:@"Step15"
                         message:msg
                  preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        UIWindowScene *scene = nil;
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if (s.activationState == UISceneActivationStateForegroundActive) {
                scene = (UIWindowScene *)s; break;
            }
        }
        UIWindow *window = scene ? scene.windows.firstObject : nil;
        if (window) [window.rootViewController presentViewController:alert animated:YES completion:nil];
    });
}

// ============================================================
// WKWebView + URLRequest hooks
// ============================================================
static IMP orig_wk_init_frame = NULL;
static IMP orig_wk_init_coder = NULL;

static id my_wk_init_frame(id self, SEL _cmd, CGRect frame, id config) {
    id instance = ((id(*)(id, SEL, CGRect, id))orig_wk_init_frame)(self, _cmd, frame, config);
    if (instance && _spoofedWebKitUA)
        ((void(*)(id, SEL, NSString *))objc_msgSend)(instance, @selector(setCustomUserAgent:), _spoofedWebKitUA);
    return instance;
}

static id my_wk_init_coder(id self, SEL _cmd, id coder) {
    id instance = ((id(*)(id, SEL, id))orig_wk_init_coder)(self, _cmd, coder);
    if (instance && _spoofedWebKitUA)
        ((void(*)(id, SEL, NSString *))objc_msgSend)(instance, @selector(setCustomUserAgent:), _spoofedWebKitUA);
    return instance;
}

static IMP orig_setValue = NULL;

static void my_setValue(id self, SEL _cmd, NSString *value, NSString *field) {
    if ([field caseInsensitiveCompare:@"User-Agent"] == NSOrderedSame && _spoofedUserAgent)
        value = _spoofedUserAgent;
    ((void(*)(id, SEL, NSString *, NSString *))orig_setValue)(self, _cmd, value, field);
}

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {
        diag_keychain_keys = [NSMutableArray new];

        _spoofedIDFA = getOrCreateSpoofedUUID(kKey(@"id1"));
        _spoofedIDFV = getOrCreateSpoofedUUID(kKey(@"id2"));
        _spoofedDeviceName = getOrCreateSpoofedDeviceName(kKey(@"dn"));
        _spoofedSysVersion = getOrCreateSpoofedSysVersion();
        initSpoofedHWInfoC();
        initSpoofedIOKitInfo();
        initSpoofedUserAgent();

        // DON'T clear keychain — we want to spy on it!
        // clearKeychainOnce();
        clearSharedCookies();
        clearURLCache();
        clearWebViewData();

        // ObjC hooks
        Class asmClass = objc_getClass("ASIdentifierManager");
        if (asmClass) {
            Method m = class_getInstanceMethod(asmClass, @selector(advertisingIdentifier));
            if (m) { IMP imp = imp_implementationWithBlock(^NSUUID *(id s) { return _spoofedIDFA; }); hookInstanceMethod(asmClass, @selector(advertisingIdentifier), imp, method_getTypeEncoding(m)); }
            m = class_getInstanceMethod(asmClass, @selector(isAdvertisingTrackingEnabled));
            if (m) { IMP imp = imp_implementationWithBlock(^BOOL(id s) { return YES; }); hookInstanceMethod(asmClass, @selector(isAdvertisingTrackingEnabled), imp, method_getTypeEncoding(m)); }
        }

        Class attClass = objc_getClass("ATTrackingManager");
        if (attClass) {
            Method m = class_getClassMethod(attClass, @selector(trackingAuthorizationStatus));
            if (m) { IMP imp = imp_implementationWithBlock(^NSInteger(id s) { return 3; }); hookClassMethod(attClass, @selector(trackingAuthorizationStatus), imp, method_getTypeEncoding(m)); }
        }

        Class uiDeviceClass = objc_getClass("UIDevice");
        if (uiDeviceClass) {
            Method m = class_getInstanceMethod(uiDeviceClass, @selector(identifierForVendor));
            if (m) { IMP imp = imp_implementationWithBlock(^NSUUID *(id s) { return _spoofedIDFV; }); hookInstanceMethod(uiDeviceClass, @selector(identifierForVendor), imp, method_getTypeEncoding(m)); }
            m = class_getInstanceMethod(uiDeviceClass, @selector(name));
            if (m) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return _spoofedDeviceName; }); hookInstanceMethod(uiDeviceClass, @selector(name), imp, method_getTypeEncoding(m)); }
            m = class_getInstanceMethod(uiDeviceClass, @selector(systemVersion));
            if (m) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return _spoofedSysVersion; }); hookInstanceMethod(uiDeviceClass, @selector(systemVersion), imp, method_getTypeEncoding(m)); }
        }

        Class pbClass = objc_getClass("UIPasteboard");
        if (pbClass) {
            Method m = class_getInstanceMethod(pbClass, @selector(string));
            if (m) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @""; }); hookInstanceMethod(pbClass, @selector(string), imp, method_getTypeEncoding(m)); }
            m = class_getInstanceMethod(pbClass, @selector(strings));
            if (m) { IMP imp = imp_implementationWithBlock(^NSArray *(id s) { return @[]; }); hookInstanceMethod(pbClass, @selector(strings), imp, method_getTypeEncoding(m)); }
            m = class_getInstanceMethod(pbClass, @selector(dataForPasteboardType:));
            if (m) { IMP imp = imp_implementationWithBlock(^NSData *(id s, NSString *t) { return nil; }); hookInstanceMethod(pbClass, @selector(dataForPasteboardType:), imp, method_getTypeEncoding(m)); }
            m = class_getInstanceMethod(pbClass, @selector(valueForPasteboardType:));
            if (m) { IMP imp = imp_implementationWithBlock(^id(id s, NSString *t) { return nil; }); hookInstanceMethod(pbClass, @selector(valueForPasteboardType:), imp, method_getTypeEncoding(m)); }
            m = class_getInstanceMethod(pbClass, @selector(items));
            if (m) { IMP imp = imp_implementationWithBlock(^NSArray *(id s) { return @[]; }); hookInstanceMethod(pbClass, @selector(items), imp, method_getTypeEncoding(m)); }
            m = class_getInstanceMethod(pbClass, @selector(containsPasteboardTypes:));
            if (m) { IMP imp = imp_implementationWithBlock(^BOOL(id s, NSArray *t) { return NO; }); hookInstanceMethod(pbClass, @selector(containsPasteboardTypes:), imp, method_getTypeEncoding(m)); }
        }

        Class fmClass = objc_getClass("NSFileManager");
        if (fmClass) {
            Method m = class_getInstanceMethod(fmClass, @selector(containerURLForSecurityApplicationGroupIdentifier:));
            if (m) { IMP imp = imp_implementationWithBlock(^NSURL *(id s, NSString *g) { return nil; }); hookInstanceMethod(fmClass, @selector(containerURLForSecurityApplicationGroupIdentifier:), imp, method_getTypeEncoding(m)); }
        }

        Class wkClass = objc_getClass("WKWebView");
        if (wkClass) {
            Method m = class_getInstanceMethod(wkClass, @selector(customUserAgent));
            if (m) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return _spoofedWebKitUA; }); hookInstanceMethod(wkClass, @selector(customUserAgent), imp, method_getTypeEncoding(m)); }
            m = class_getInstanceMethod(wkClass, @selector(initWithFrame:configuration:));
            if (m) { orig_wk_init_frame = method_getImplementation(m); class_replaceMethod(wkClass, @selector(initWithFrame:configuration:), (IMP)my_wk_init_frame, method_getTypeEncoding(m)); }
            m = class_getInstanceMethod(wkClass, @selector(initWithCoder:));
            if (m) { orig_wk_init_coder = method_getImplementation(m); class_replaceMethod(wkClass, @selector(initWithCoder:), (IMP)my_wk_init_coder, method_getTypeEncoding(m)); }
        }

        Class reqClass = objc_getClass("NSMutableURLRequest");
        if (reqClass) {
            Method m = class_getInstanceMethod(reqClass, @selector(setValue:forHTTPHeaderField:));
            if (m) { orig_setValue = method_getImplementation(m); class_replaceMethod(reqClass, @selector(setValue:forHTTPHeaderField:), (IMP)my_setValue, method_getTypeEncoding(m)); }
        }

        showDiagnosticPopup();
    }
}
