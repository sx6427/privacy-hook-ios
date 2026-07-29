//
//  PrivacyHook.m — Step35b: Step33 + DYLD_INTERPOSE sysctlbyname
//
//  Step33: Bundle ID hook (支付成功) + Keychain清理 + IDFA/IDFV
//  Step35b: DYLD_INTERPOSE sysctlbyname (单条 interpose, Step13b 验证过安全)
//  每个副本不同设备型号 → 百度设备指纹不同 → 新设备
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <AppTrackingTransparency/AppTrackingTransparency.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <string.h>
#import <sys/sysctl.h>

#define NSLog(...)

// DYLD_INTERPOSE 宏 (单条使用, Step13b 验证过不会导致其他 hook 失效)
#define DYLD_INTERPOSE(_replacement, _replacee) \
  __attribute__((used)) static struct { \
      const void *replacement; \
      const void *replacee; \
  } _interpose_##_replacee \
  __attribute__ ((section ("__DATA,__interpose"))) = { \
      (const void *)(unsigned long)&_replacement, \
      (const void *)(unsigned long)&_replacee, \
  };

static NSUUID *_spoofedIDFA = nil;
static NSUUID *_spoofedIDFV = nil;
static NSString *_spoofedDeviceName = nil;
static NSString *_originalBundleID = @"com.baidu.BaiduMobile";
static IMP orig_bundleIdentifier = NULL;
static IMP orig_infoDictionary = NULL;

// 设备型号 (如 "iPhone14,5")
static char _spoofedMachine[32] = {0};

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

// 随机设备型号
static void initSpoofedMachine(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = kKey(@"machine");
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
    strlcpy(_spoofedMachine, [saved UTF8String], sizeof(_spoofedMachine));
}

// DYLD_INTERPOSE: sysctlbyname replacement
static int my_sysctlbyname(const char *name, void *oldp,
                           size_t *oldlenp, void *newp, size_t newlen) {
    if (name && newp == NULL && newlen == 0) {
        if (strcmp(name, "hw.machine") == 0 && _spoofedMachine[0] != 0) {
            size_t need = strlen(_spoofedMachine) + 1;
            if (oldp == NULL) {
                if (oldlenp) *oldlenp = need;
                return 0;
            }
            if (oldlenp && *oldlenp >= need) {
                memcpy(oldp, _spoofedMachine, need);
                *oldlenp = need;
                return 0;
            }
        }
    }
    return sysctlbyname(name, oldp, oldlenp, newp, newlen);
}
DYLD_INTERPOSE(my_sysctlbyname, sysctlbyname);

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

// Keychain: clear EVERY launch
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

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {
        _spoofedIDFA = getOrCreateSpoofedUUID(kKey(@"id1"));
        _spoofedIDFV = getOrCreateSpoofedUUID(kKey(@"id2"));
        _spoofedDeviceName = getOrCreateSpoofedDeviceName(kKey(@"dn"));

        // 初始化随机设备型号
        initSpoofedMachine();

        // Clear keychain every launch
        clearKeychainEveryLaunch();

        // *** Bundle ID hook ***
        Class bundleClass = objc_getClass("NSBundle");
        if (bundleClass) {
            Method m = class_getInstanceMethod(bundleClass, @selector(bundleIdentifier));
            if (m) {
                orig_bundleIdentifier = method_getImplementation(m);
                IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                    if ([s isEqual:[NSBundle mainBundle]]) return _originalBundleID;
                    return ((NSString *(*)(id, SEL))orig_bundleIdentifier)(s, @selector(bundleIdentifier));
                });
                class_replaceMethod(bundleClass, @selector(bundleIdentifier), imp, method_getTypeEncoding(m));
            }
            Method m2 = class_getInstanceMethod(bundleClass, @selector(infoDictionary));
            if (m2) {
                orig_infoDictionary = method_getImplementation(m2);
                IMP imp2 = imp_implementationWithBlock(^NSDictionary *(id s) {
                    NSDictionary *dict = ((NSDictionary *(*)(id, SEL))orig_infoDictionary)(s, @selector(infoDictionary));
                    if ([s isEqual:[NSBundle mainBundle]] && dict) {
                        NSMutableDictionary *md = [dict mutableCopy];
                        md[@"CFBundleIdentifier"] = _originalBundleID;
                        return md;
                    }
                    return dict;
                });
                class_replaceMethod(bundleClass, @selector(infoDictionary), imp2, method_getTypeEncoding(m2));
            }
            Method m3 = class_getInstanceMethod(bundleClass, @selector(objectForInfoDictionaryKey:));
            if (m3) {
                IMP orig3 = method_getImplementation(m3);
                IMP imp3 = imp_implementationWithBlock(^id(id s, SEL _cmd, NSString *key) {
                    id val = ((id(*)(id, SEL, NSString *))orig3)(s, _cmd, key);
                    if ([s isEqual:[NSBundle mainBundle]] && [key isEqualToString:@"CFBundleIdentifier"]) {
                        return _originalBundleID;
                    }
                    return val;
                });
                class_replaceMethod(bundleClass, @selector(objectForInfoDictionaryKey:), imp3, method_getTypeEncoding(m3));
            }
        }

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
