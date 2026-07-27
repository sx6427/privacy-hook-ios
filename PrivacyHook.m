//
//  PrivacyHook.m — Step 19: Complete device fingerprint spoofing
//
//  Based on Step14 (proven safe, no crash)
//  Adds: UIScreen, NSProcessInfo, NSFileManager hooks
//
//  Problem: We spoofed device model (e.g. iPhone14,5) but screen resolution,
//  RAM, disk size still showed real device values (iPhone11,2).
//  Baidu sees mismatch → same device.
//
//  Fix: Spoof ALL ObjC-accessible device info to match the fake model.
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
#import <net/if.h>
#import <mach-o/dyld.h>

#define NSLog(...)

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

// Screen + hardware specs (must match spoofed device model)
static CGFloat _spoof_boundsW = 0, _spoof_boundsH = 0;
static CGFloat _spoof_nativeW = 0, _spoof_nativeH = 0;
static CGFloat _spoof_scale = 0, _spoof_nativeScale = 0;
static NSInteger _spoof_maxFps = 60;
static uint64_t _spoof_physicalMemory = 0;
static NSUInteger _spoof_processorCount = 0;
static uint64_t _spoof_diskTotal = 0;
static uint64_t _spoof_diskFree = 0;

// ============================================================
// DYLD_INTERPOSE macros (kept from Step14, works for our own calls)
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
// Hook: sysctlbyname
// ============================================================
static int my_sysctlbyname(const char *name, void *oldp,
                            size_t *oldlenp, void *newp, size_t newlen) {
    if (name && newp == NULL && newlen == 0) {
        if (strcmp(name, "hw.machine") == 0 && _c_machine[0] != 0) {
            size_t need = strlen(_c_machine) + 1;
            if (oldp == NULL) { if (oldlenp) *oldlenp = need; return 0; }
            if (oldlenp && *oldlenp >= need) {
                memcpy(oldp, _c_machine, need);
                *oldlenp = need;
                return 0;
            }
        }
        if (strcmp(name, "hw.model") == 0 && _c_hwmodel[0] != 0) {
            size_t need = strlen(_c_hwmodel) + 1;
            if (oldp == NULL) { if (oldlenp) *oldlenp = need; return 0; }
            if (oldlenp && *oldlenp >= need) {
                memcpy(oldp, _c_hwmodel, need);
                *oldlenp = need;
                return 0;
            }
        }
        if (strcmp(name, "hw.serialnumber") == 0 && _c_platformSerial[0] != 0) {
            size_t need = strlen(_c_platformSerial) + 1;
            if (oldp == NULL) { if (oldlenp) *oldlenp = need; return 0; }
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
// Hook: sysctl (numeric ID)
// ============================================================
static int my_sysctl(int *name, u_int namelen, void *oldp,
                     size_t *oldlenp, void *newp, size_t newlen) {
    if (name && namelen >= 2 && newp == NULL && newlen == 0) {
        if (name[0] == 6) {  // CTL_HW
            if (name[1] == 1 && _c_machine[0] != 0) {  // HW_MACHINE
                size_t need = strlen(_c_machine) + 1;
                if (oldp == NULL) { if (oldlenp) *oldlenp = need; return 0; }
                if (oldlenp && *oldlenp >= need) {
                    memcpy(oldp, _c_machine, need);
                    *oldlenp = need;
                    return 0;
                }
            }
            if (name[1] == 2 && _c_hwmodel[0] != 0) {  // HW_MODEL
                size_t need = strlen(_c_hwmodel) + 1;
                if (oldp == NULL) { if (oldlenp) *oldlenp = need; return 0; }
                if (oldlenp && *oldlenp >= need) {
                    memcpy(oldp, _c_hwmodel, need);
                    *oldlenp = need;
                    return 0;
                }
            }
        }
    }
    return sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}
DYLD_INTERPOSE(my_sysctl, sysctl);

// ============================================================
// Hook: IORegistryEntryCreateCFProperty
// ============================================================
static CFTypeRef my_IORegistryEntryCreateCFProperty(
    io_registry_entry_t entry, CFStringRef key,
    CFAllocatorRef allocator, IOOptionBits options) {
    if (key && _c_platformUUID[0] != 0) {
        if (CFStringCompare(key, CFSTR("IOPlatformUUID"), 0) == kCFCompareEqualTo) {
            return CFStringCreateWithCString(allocator, _c_platformUUID, kCFStringEncodingUTF8);
        }
        if (CFStringCompare(key, CFSTR("IOPlatformSerialNumber"), 0) == kCFCompareEqualTo) {
            return CFStringCreateWithCString(allocator, _c_platformSerial, kCFStringEncodingUTF8);
        }
    }
    return IORegistryEntryCreateCFProperty(entry, key, allocator, options);
}
DYLD_INTERPOSE(my_IORegistryEntryCreateCFProperty, IORegistryEntryCreateCFProperty);

// ============================================================
// Hook: getifaddrs
// ============================================================
static int my_getifaddrs(struct ifaddrs **ifap) {
    *ifap = NULL;
    return 0;
}
DYLD_INTERPOSE(my_getifaddrs, getifaddrs);

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

// Device specs table: machine|boundsW|boundsH|nativeW|nativeH|scale|nativeScale|maxFps|memGB|cpuCount
static void initSpoofedHWInfoC(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = kKey(@"hw");
    NSString *saved = [defaults stringForKey:key];
    if (!saved) {
        NSArray *models = @[
            @"iPhone14,5", @"iPhone14,2", @"iPhone14,3",
            @"iPhone14,7", @"iPhone14,8", @"iPhone15,2",
            @"iPhone15,3", @"iPhone15,4", @"iPhone15,5",
            @"iPhone16,1", @"iPhone16,2",
        ];
        saved = models[arc4random_uniform((uint32_t)models.count)];
        [defaults setObject:saved forKey:key];
        [defaults synchronize];
    }
    strlcpy(_c_machine, [saved UTF8String], sizeof(_c_machine));

    // Lookup screen + hardware specs for this device model
    typedef struct {
        const char *machine;
        CGFloat bw, bh, nw, nh, scale, nscale;
        NSInteger fps;
        uint64_t memGB;
        NSUInteger cpu;
    } DeviceSpec;

    DeviceSpec specs[] = {
        {"iPhone14,5", 390, 844, 1170, 2533, 3.0, 3.0, 60, 4, 6},   // iPhone 13
        {"iPhone14,2", 390, 844, 1170, 2533, 3.0, 3.0, 120, 6, 6},  // iPhone 13 Pro
        {"iPhone14,3", 428, 926, 1284, 2778, 3.0, 3.0, 120, 6, 6},  // iPhone 13 Pro Max
        {"iPhone14,7", 390, 844, 1170, 2533, 3.0, 3.0, 60, 4, 6},   // iPhone 14
        {"iPhone14,8", 428, 926, 1284, 2778, 3.0, 3.0, 60, 4, 6},   // iPhone 14 Plus
        {"iPhone15,2", 393, 852, 1179, 2556, 3.0, 3.0, 120, 6, 6},  // iPhone 14 Pro
        {"iPhone15,3", 430, 932, 1290, 2796, 3.0, 3.0, 120, 6, 6},  // iPhone 14 Pro Max
        {"iPhone15,4", 393, 852, 1179, 2556, 3.0, 3.0, 60, 6, 6},   // iPhone 15
        {"iPhone15,5", 430, 932, 1290, 2796, 3.0, 3.0, 60, 6, 6},   // iPhone 15 Plus
        {"iPhone16,1", 393, 852, 1179, 2556, 3.0, 3.0, 120, 8, 6},  // iPhone 15 Pro
        {"iPhone16,2", 430, 932, 1290, 2796, 3.0, 3.0, 120, 8, 6},  // iPhone 15 Pro Max
    };

    const char *machine = [saved UTF8String];
    BOOL found = NO;
    for (int i = 0; i < sizeof(specs)/sizeof(specs[0]); i++) {
        if (strcmp(machine, specs[i].machine) == 0) {
            _spoof_boundsW = specs[i].bw;
            _spoof_boundsH = specs[i].bh;
            _spoof_nativeW = specs[i].nw;
            _spoof_nativeH = specs[i].nh;
            _spoof_scale = specs[i].scale;
            _spoof_nativeScale = specs[i].nscale;
            _spoof_maxFps = specs[i].fps;
            _spoof_physicalMemory = specs[i].memGB * 1024ULL * 1024ULL * 1024ULL;
            _spoof_processorCount = specs[i].cpu;
            found = YES;
            break;
        }
    }
    if (!found) {
        _spoof_boundsW = 393; _spoof_boundsH = 852;
        _spoof_nativeW = 1179; _spoof_nativeH = 2556;
        _spoof_scale = 3.0; _spoof_nativeScale = 3.0;
        _spoof_maxFps = 120;
        _spoof_physicalMemory = 6ULL * 1024 * 1024 * 1024;
        _spoof_processorCount = 6;
    }

    // hw.model
    NSString *hwmodelKey = kKey(@"hwm");
    NSString *hwmodel = [defaults stringForKey:hwmodelKey];
    if (!hwmodel) {
        NSArray *models = @[@"D27AP", @"D63AP", @"D64AP", @"D37AP", @"D38AP",
                            @"D83AP", @"D84AP", @"D93AP", @"D94AP"];
        hwmodel = models[arc4random_uniform((uint32_t)models.count)];
        [defaults setObject:hwmodel forKey:hwmodelKey];
        [defaults synchronize];
    }
    strlcpy(_c_hwmodel, [hwmodel UTF8String], sizeof(_c_hwmodel));

    // Disk size: random 128/256/512 GB
    NSString *diskKey = kKey(@"disk");
    uint64_t savedDisk = [[defaults stringForKey:diskKey] longLongValue];
    if (savedDisk == 0) {
        uint64_t sizes[] = {128, 256, 512};
        savedDisk = sizes[arc4random_uniform(3)];
        [defaults setObject:[NSString stringWithFormat:@"%llu", savedDisk] forKey:diskKey];
        [defaults synchronize];
    }
    _spoof_diskTotal = savedDisk * 1024ULL * 1024 * 1024;
    // Random free space: 30%-80% of total
    NSString *diskFreeKey = kKey(@"diskf");
    uint64_t savedFree = [[defaults stringForKey:diskFreeKey] longLongValue];
    if (savedFree == 0) {
        savedFree = _spoof_diskTotal * (30 + arc4random_uniform(50)) / 100;
        [defaults setObject:[NSString stringWithFormat:@"%llu", savedFree] forKey:diskFreeKey];
        [defaults synchronize];
    }
    _spoof_diskFree = savedFree;
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
// UIScreen hooks — screen resolution spoofing
// ============================================================
static IMP orig_screen_bounds = NULL;
static CGRect my_screen_bounds(id self, SEL _cmd) {
    if (_spoof_boundsW > 0) return CGRectMake(0, 0, _spoof_boundsW, _spoof_boundsH);
    return ((CGRect(*)(id, SEL))orig_screen_bounds)(self, _cmd);
}

static IMP orig_screen_nativeBounds = NULL;
static CGRect my_screen_nativeBounds(id self, SEL _cmd) {
    if (_spoof_nativeW > 0) return CGRectMake(0, 0, _spoof_nativeW, _spoof_nativeH);
    return ((CGRect(*)(id, SEL))orig_screen_nativeBounds)(self, _cmd);
}

static IMP orig_screen_scale = NULL;
static CGFloat my_screen_scale(id self, SEL _cmd) {
    if (_spoof_scale > 0) return _spoof_scale;
    return ((CGFloat(*)(id, SEL))orig_screen_scale)(self, _cmd);
}

static IMP orig_screen_nativeScale = NULL;
static CGFloat my_screen_nativeScale(id self, SEL _cmd) {
    if (_spoof_nativeScale > 0) return _spoof_nativeScale;
    return ((CGFloat(*)(id, SEL))orig_screen_nativeScale)(self, _cmd);
}

static IMP orig_screen_maxFps = NULL;
static NSInteger my_screen_maxFps(id self, SEL _cmd) {
    if (_spoof_maxFps > 0) return _spoof_maxFps;
    return ((NSInteger(*)(id, SEL))orig_screen_maxFps)(self, _cmd);
}

// ============================================================
// NSProcessInfo hooks — RAM, CPU, OS version
// ============================================================
static IMP orig_pi_osVersion = NULL;
static NSOperatingSystemVersion my_pi_osVersion(id self, SEL _cmd) {
    if (_spoofedSysVersion) {
        NSArray *parts = [_spoofedSysVersion componentsSeparatedByString:@"."];
        NSOperatingSystemVersion v = {0};
        if (parts.count > 0) v.majorVersion = [parts[0] integerValue];
        if (parts.count > 1) v.minorVersion = [parts[1] integerValue];
        if (parts.count > 2) v.patchVersion = [parts[2] integerValue];
        return v;
    }
    return ((NSOperatingSystemVersion(*)(id, SEL))orig_pi_osVersion)(self, _cmd);
}

static IMP orig_pi_physMem = NULL;
static uint64_t my_pi_physMem(id self, SEL _cmd) {
    if (_spoof_physicalMemory > 0) return _spoof_physicalMemory;
    return ((uint64_t(*)(id, SEL))orig_pi_physMem)(self, _cmd);
}

static IMP orig_pi_procCount = NULL;
static NSUInteger my_pi_procCount(id self, SEL _cmd) {
    if (_spoof_processorCount > 0) return _spoof_processorCount;
    return ((NSUInteger(*)(id, SEL))orig_pi_procCount)(self, _cmd);
}

// ============================================================
// NSFileManager hooks — disk space spoofing
// ============================================================
static IMP orig_fm_attrs = NULL;
static NSDictionary *my_fm_attrs(id self, SEL _cmd, NSString *path, NSError **error) {
    NSDictionary *result = ((NSDictionary *(*)(id, SEL, NSString *, NSError **))orig_fm_attrs)(self, _cmd, path, error);
    if (result && _spoof_diskTotal > 0) {
        NSMutableDictionary *m = [result mutableCopy];
        [m setObject:[NSNumber numberWithUnsignedLongLong:_spoof_diskTotal] forKey:NSFileSystemSize];
        [m setObject:[NSNumber numberWithUnsignedLongLong:_spoof_diskFree] forKey:NSFileSystemFreeSize];
        return m;
    }
    return result;
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
// Diagnostic popup
// ============================================================
static void showDiagnosticPopup(void) {
    NSString *msg = [NSString stringWithFormat:
        @"=== Step19 全标识 ===\n\n"
        @"设备: %s\n"
        @"屏幕: %.0fx%.0f (native %.0fx%.0f)\n"
        @"缩放: %.1f/%.1f  FPS: %d\n"
        @"内存: %lluGB  CPU: %d核\n"
        @"磁盘: %lluGB/%lluGB\n"
        @"系统: %@\n"
        @"设备名: %@\n"
        @"IDFA: %@\n"
        @"IDFV: %@",
        _c_machine[0] ? _c_machine : "(空)",
        _spoof_boundsW, _spoof_boundsH, _spoof_nativeW, _spoof_nativeH,
        _spoof_scale, _spoof_nativeScale, (int)_spoof_maxFps,
        _spoof_physicalMemory / (1024*1024*1024), (int)_spoof_processorCount,
        _spoof_diskTotal / (1024*1024*1024), _spoof_diskFree / (1024*1024*1024),
        _spoofedSysVersion, _spoofedDeviceName,
        _spoofedIDFA, _spoofedIDFV];

    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:@"Step19"
                         message:msg
                  preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)),
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

        // === ObjC hooks ===

        // ASIdentifierManager (IDFA)
        Class asmClass = objc_getClass("ASIdentifierManager");
        if (asmClass) {
            Method m = class_getInstanceMethod(asmClass, @selector(advertisingIdentifier));
            if (m) { IMP imp = imp_implementationWithBlock(^NSUUID *(id s) { return _spoofedIDFA; }); hookInstanceMethod(asmClass, @selector(advertisingIdentifier), imp, method_getTypeEncoding(m)); }
            m = class_getInstanceMethod(asmClass, @selector(isAdvertisingTrackingEnabled));
            if (m) { IMP imp = imp_implementationWithBlock(^BOOL(id s) { return YES; }); hookInstanceMethod(asmClass, @selector(isAdvertisingTrackingEnabled), imp, method_getTypeEncoding(m)); }
        }

        // ATTrackingManager
        Class attClass = objc_getClass("ATTrackingManager");
        if (attClass) {
            Method m = class_getClassMethod(attClass, @selector(trackingAuthorizationStatus));
            if (m) { IMP imp = imp_implementationWithBlock(^NSInteger(id s) { return 3; }); hookClassMethod(attClass, @selector(trackingAuthorizationStatus), imp, method_getTypeEncoding(m)); }
        }

        // UIDevice
        Class uiDeviceClass = objc_getClass("UIDevice");
        if (uiDeviceClass) {
            Method m = class_getInstanceMethod(uiDeviceClass, @selector(identifierForVendor));
            if (m) { IMP imp = imp_implementationWithBlock(^NSUUID *(id s) { return _spoofedIDFV; }); hookInstanceMethod(uiDeviceClass, @selector(identifierForVendor), imp, method_getTypeEncoding(m)); }
            m = class_getInstanceMethod(uiDeviceClass, @selector(name));
            if (m) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return _spoofedDeviceName; }); hookInstanceMethod(uiDeviceClass, @selector(name), imp, method_getTypeEncoding(m)); }
            m = class_getInstanceMethod(uiDeviceClass, @selector(systemVersion));
            if (m) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return _spoofedSysVersion; }); hookInstanceMethod(uiDeviceClass, @selector(systemVersion), imp, method_getTypeEncoding(m)); }
            m = class_getInstanceMethod(uiDeviceClass, @selector(model));
            if (m) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @"iPhone"; }); hookInstanceMethod(uiDeviceClass, @selector(model), imp, method_getTypeEncoding(m)); }
            m = class_getInstanceMethod(uiDeviceClass, @selector(localizedModel));
            if (m) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @"iPhone"; }); hookInstanceMethod(uiDeviceClass, @selector(localizedModel), imp, method_getTypeEncoding(m)); }
        }

        // UIScreen — screen resolution
        Class screenClass = objc_getClass("UIScreen");
        if (screenClass) {
            Method m = class_getInstanceMethod(screenClass, @selector(bounds));
            if (m) { orig_screen_bounds = method_getImplementation(m); class_replaceMethod(screenClass, @selector(bounds), (IMP)my_screen_bounds, method_getTypeEncoding(m)); }
            m = class_getInstanceMethod(screenClass, @selector(nativeBounds));
            if (m) { orig_screen_nativeBounds = method_getImplementation(m); class_replaceMethod(screenClass, @selector(nativeBounds), (IMP)my_screen_nativeBounds, method_getTypeEncoding(m)); }
            m = class_getInstanceMethod(screenClass, @selector(scale));
            if (m) { orig_screen_scale = method_getImplementation(m); class_replaceMethod(screenClass, @selector(scale), (IMP)my_screen_scale, method_getTypeEncoding(m)); }
            m = class_getInstanceMethod(screenClass, @selector(nativeScale));
            if (m) { orig_screen_nativeScale = method_getImplementation(m); class_replaceMethod(screenClass, @selector(nativeScale), (IMP)my_screen_nativeScale, method_getTypeEncoding(m)); }
            m = class_getInstanceMethod(screenClass, @selector(maximumFramesPerSecond));
            if (m) { orig_screen_maxFps = method_getImplementation(m); class_replaceMethod(screenClass, @selector(maximumFramesPerSecond), (IMP)my_screen_maxFps, method_getTypeEncoding(m)); }
        }

        // NSProcessInfo — RAM, CPU, OS version
        Class piClass = objc_getClass("NSProcessInfo");
        if (piClass) {
            Method m = class_getInstanceMethod(piClass, @selector(operatingSystemVersion));
            if (m) { orig_pi_osVersion = method_getImplementation(m); class_replaceMethod(piClass, @selector(operatingSystemVersion), (IMP)my_pi_osVersion, method_getTypeEncoding(m)); }
            m = class_getInstanceMethod(piClass, @selector(physicalMemory));
            if (m) { orig_pi_physMem = method_getImplementation(m); class_replaceMethod(piClass, @selector(physicalMemory), (IMP)my_pi_physMem, method_getTypeEncoding(m)); }
            m = class_getInstanceMethod(piClass, @selector(processorCount));
            if (m) { orig_pi_procCount = method_getImplementation(m); class_replaceMethod(piClass, @selector(processorCount), (IMP)my_pi_procCount, method_getTypeEncoding(m)); }
        }

        // NSFileManager — disk space
        Class fmClass = objc_getClass("NSFileManager");
        if (fmClass) {
            Method m = class_getInstanceMethod(fmClass, @selector(attributesOfFileSystemForPath:error:));
            if (m) { orig_fm_attrs = method_getImplementation(m); class_replaceMethod(fmClass, @selector(attributesOfFileSystemForPath:error:), (IMP)my_fm_attrs, method_getTypeEncoding(m)); }
        }

        // UIPasteboard
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

        // NSFileManager containerURL
        if (fmClass) {
            Method m = class_getInstanceMethod(fmClass, @selector(containerURLForSecurityApplicationGroupIdentifier:));
            if (m) { IMP imp = imp_implementationWithBlock(^NSURL *(id s, NSString *g) { return nil; }); hookInstanceMethod(fmClass, @selector(containerURLForSecurityApplicationGroupIdentifier:), imp, method_getTypeEncoding(m)); }
        }

        // WKWebView
        Class wkClass = objc_getClass("WKWebView");
        if (wkClass) {
            Method m = class_getInstanceMethod(wkClass, @selector(customUserAgent));
            if (m) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return _spoofedWebKitUA; }); hookInstanceMethod(wkClass, @selector(customUserAgent), imp, method_getTypeEncoding(m)); }
            m = class_getInstanceMethod(wkClass, @selector(initWithFrame:configuration:));
            if (m) { orig_wk_init_frame = method_getImplementation(m); class_replaceMethod(wkClass, @selector(initWithFrame:configuration:), (IMP)my_wk_init_frame, method_getTypeEncoding(m)); }
            m = class_getInstanceMethod(wkClass, @selector(initWithCoder:));
            if (m) { orig_wk_init_coder = method_getImplementation(m); class_replaceMethod(wkClass, @selector(initWithCoder:), (IMP)my_wk_init_coder, method_getTypeEncoding(m)); }
        }

        // NSMutableURLRequest User-Agent
        Class reqClass = objc_getClass("NSMutableURLRequest");
        if (reqClass) {
            Method m = class_getInstanceMethod(reqClass, @selector(setValue:forHTTPHeaderField:));
            if (m) { orig_setValue = method_getImplementation(m); class_replaceMethod(reqClass, @selector(setValue:forHTTPHeaderField:), (IMP)my_setValue, method_getTypeEncoding(m)); }
        }

        showDiagnosticPopup();
    }
}
