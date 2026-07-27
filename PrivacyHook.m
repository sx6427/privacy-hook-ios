//
//  PrivacyHook.m — Step 12: hook ALL app images + sysctl()
//
//  Step11 diagnosis revealed:
//    - sysctlbyname: rebind OK on main exec, but NOT CALLED
//    - IORegistryEntryCreateCFProperty: orig=NULL (not in main exec!)
//    - getifaddrs: rebind OK, but NOT CALLED
//
//  Root cause: Baidu's device info code is in ITS OWN dylibs,
//  not in the main executable. We were only hooking image 0.
//
//  Fix: Iterate ALL loaded images, hook only those inside the .app bundle.
//  Also add hook for sysctl() (numeric ID version) in case Baidu
//  uses that instead of sysctlbyname().
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
#import "fishhook.h"

#define NSLog(...)

// ============================================================
// Diagnostic counters
// ============================================================
static volatile int diag_sb_called = 0;
static volatile int diag_sysctl_called = 0;
static volatile int diag_iok_called = 0;
static volatile int diag_gifa_called = 0;
static volatile int diag_images_hooked = 0;
static volatile int diag_sb_orig_null = 0;
static volatile int diag_iok_orig_null = 0;
static volatile int diag_gifa_orig_null = 0;
static volatile int diag_sysctl_orig_null = 0;

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

// Original function pointers
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t) = NULL;
static CFTypeRef (*orig_IORegistryEntryCreateCFProperty)(io_registry_entry_t, CFStringRef, CFAllocatorRef, IOOptionBits) = NULL;
static int (*orig_getifaddrs)(struct ifaddrs **) = NULL;

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

static void clearKeychainOnce(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = kKey(@"kc23");
    if ([defaults boolForKey:key]) return;
    NSArray *secItemClasses = @[(__bridge id)kSecClassGenericPassword, (__bridge id)kSecClassInternetPassword,
        (__bridge id)kSecClassKey, (__bridge id)kSecClassCertificate, (__bridge id)kSecClassIdentity];
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
// fishhook hooks — PURE C, with diagnostic counters
// ============================================================

// Hook for sysctlbyname (string name version)
static int hooked_sysctlbyname(const char *name, void *oldp,
                                size_t *oldlenp, void *newp, size_t newlen) {
    diag_sb_called = 1;
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
        if (strcmp(name, "hw.serialnumber") == 0 && _c_platformSerial[0] != 0) {
            size_t need = strlen(_c_platformSerial) + 1;
            if (oldp == NULL) { if (oldlenp) *oldlenp = need; return 0; }
            if (oldlenp && *oldlenp >= need) { memcpy(oldp, _c_platformSerial, need); *oldlenp = need; return 0; }
        }
    }
    if (orig_sysctlbyname) return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    return -1;
}

// Hook for sysctl (numeric ID version) — NEW in Step12!
// Baidu may use sysctl({CTL_HW, HW_MACHINE}, ...) instead of sysctlbyname("hw.machine")
static int hooked_sysctl(int *name, u_int namelen, void *oldp,
                         size_t *oldlenp, void *newp, size_t newlen) {
    diag_sysctl_called = 1;
    if (orig_sysctl == NULL) { diag_sysctl_orig_null = 1; }

    if (name && namelen >= 2 && newp == NULL && newlen == 0) {
        // CTL_HW = 6
        if (name[0] == 6) {
            // HW_MACHINE = 1 → equivalent to "hw.machine"
            if (name[1] == 1 && _c_machine[0] != 0) {
                size_t need = strlen(_c_machine) + 1;
                if (oldp == NULL) { if (oldlenp) *oldlenp = need; return 0; }
                if (oldlenp && *oldlenp >= need) {
                    memcpy(oldp, _c_machine, need); *oldlenp = need; return 0;
                }
            }
            // HW_MODEL = 2 → equivalent to "hw.model"
            if (name[1] == 2 && _c_hwmodel[0] != 0) {
                size_t need = strlen(_c_hwmodel) + 1;
                if (oldp == NULL) { if (oldlenp) *oldlenp = need; return 0; }
                if (oldlenp && *oldlenp >= need) {
                    memcpy(oldp, _c_hwmodel, need); *oldlenp = need; return 0;
                }
            }
        }
        // CTL_KERN = 1
        if (name[0] == 1) {
            // KERN_OSVERSION = 2 → "kern.osversion"
            // KERN_HOSTNAME = 10 → "kern.hostname"
            // Don't need to spoof these, just let them pass through
        }
    }
    if (orig_sysctl) return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    return -1;
}

static CFTypeRef hooked_IORegistryEntryCreateCFProperty(
    io_registry_entry_t entry, CFStringRef key,
    CFAllocatorRef allocator, IOOptionBits options) {
    diag_iok_called = 1;
    if (orig_IORegistryEntryCreateCFProperty == NULL) { diag_iok_orig_null = 1; }
    if (key && _c_platformUUID[0] != 0) {
        if (CFStringCompare(key, CFSTR("IOPlatformUUID"), 0) == kCFCompareEqualTo)
            return CFStringCreateWithCString(allocator, _c_platformUUID, kCFStringEncodingUTF8);
        if (CFStringCompare(key, CFSTR("IOPlatformSerialNumber"), 0) == kCFCompareEqualTo)
            return CFStringCreateWithCString(allocator, _c_platformSerial, kCFStringEncodingUTF8);
    }
    if (orig_IORegistryEntryCreateCFProperty)
        return orig_IORegistryEntryCreateCFProperty(entry, key, allocator, options);
    return NULL;
}

static int hooked_getifaddrs(struct ifaddrs **ifap) {
    diag_gifa_called = 1;
    if (orig_getifaddrs == NULL) { diag_gifa_orig_null = 1; }
    *ifap = NULL;
    return 0;
}

// ============================================================
// Hook ALL images inside the .app bundle (not just main exec!)
// ============================================================
static void rebindAppImages(void) {
    uint32_t count = _dyld_image_count();

    struct rebinding rebindings[] = {
        {"sysctlbyname", (void *)hooked_sysctlbyname, (void **)&orig_sysctlbyname},
        {"sysctl", (void *)hooked_sysctl, (void **)&orig_sysctl},
        {"IORegistryEntryCreateCFProperty", (void *)hooked_IORegistryEntryCreateCFProperty, (void **)&orig_IORegistryEntryCreateCFProperty},
        {"getifaddrs", (void *)hooked_getifaddrs, (void **)&orig_getifaddrs},
    };
    int rebind_count = sizeof(rebindings)/sizeof(rebindings[0]);

    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;

        // Only hook images inside the app bundle
        // App bundle images have ".app/" in their path
        // System libraries have paths like /usr/lib/ or /System/Library/
        if (strstr(name, ".app/") != NULL) {
            const struct mach_header *header = _dyld_get_image_header(i);
            intptr_t slide = _dyld_get_image_vmaddr_slide(i);
            if (!header) continue;

            rebind_symbols_image((void *)header, slide, rebindings, rebind_count);
            diag_images_hooked++;
        }
    }
}

// ============================================================
// Diagnostic popup
// ============================================================
static void showDiagnosticPopup(void) {
    // Read REAL hw.machine to compare with spoofed
    char realMachine[32] = {0};
    size_t size = sizeof(realMachine);
    sysctlbyname("hw.machine", realMachine, &size, NULL, 0);

    NSString *msg = [NSString stringWithFormat:
        @"=== Step12 诊断 ===\n\n"
        @"已 hook image 数量: %d\n\n"
        @"sysctlbyname (字符串名):\n"
        @"  被调用: %@\n"
        @"  orig: %@\n"
        @"  伪造: %s | 真实: %s\n\n"
        @"sysctl (数字ID) — 新增:\n"
        @"  被调用: %@\n"
        @"  orig: %@\n\n"
        @"IORegistryEntry:\n"
        @"  被调用: %@\n"
        @"  orig: %@\n"
        @"  伪造UUID: %s\n\n"
        @"getifaddrs:\n"
        @"  被调用: %@\n"
        @"  orig: %@\n\n"
        @"ObjC: 已生效\n"
        @"设备名: %@\n"
        @"系统版本: %@",
        diag_images_hooked,
        diag_sb_called ? @"YES ✅" : @"NO ❌",
        orig_sysctlbyname ? @"OK" : @"NULL",
        _c_machine[0] ? _c_machine : "(空)",
        realMachine[0] ? realMachine : "(空)",
        diag_sysctl_called ? @"YES ✅" : @"NO ❌",
        orig_sysctl ? @"OK" : @"NULL",
        diag_iok_called ? @"YES ✅" : @"NO ❌",
        orig_IORegistryEntryCreateCFProperty ? @"OK" : @"NULL",
        _c_platformUUID[0] ? _c_platformUUID : "(空)",
        diag_gifa_called ? @"YES ✅" : @"NO ❌",
        orig_getifaddrs ? @"OK" : @"NULL",
        _spoofedDeviceName, _spoofedSysVersion];

    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:@"Step12 诊断"
                         message:msg
                  preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        UIWindowScene *scene = nil;
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if (s.activationState == UISceneActivationStateForegroundActive) {
                scene = (UIWindowScene *)s;
                break;
            }
        }
        UIWindow *window = scene ? scene.windows.firstObject : nil;
        if (window) {
            [window.rootViewController presentViewController:alert animated:YES completion:nil];
        }
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
        _spoofedIDFA = getOrCreateSpoofedUUID(kKey(@"id1"));
        _spoofedIDFV = getOrCreateSpoofedUUID(kKey(@"id2"));
        _spoofedDeviceName = getOrCreateSpoofedDeviceName(kKey(@"dn"));
        _spoofedSysVersion = getOrCreateSpoofedSysVersion();
        initSpoofedHWInfoC();
        initSpoofedIOKitInfo();
        initSpoofedUserAgent();

        clearKeychainOnce();
        clearSharedCookies();
        clearURLCache();
        clearWebViewData();

        // KEY CHANGE: Hook ALL app bundle images, not just main exec!
        rebindAppImages();

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
