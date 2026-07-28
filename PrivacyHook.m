//
//  PrivacyHook.m — Step27b: Step3 + sandbox nuke (Caches only, keep Preferences)
//
//  Fix: Previous version deleted ALL of Library/ which broke payment SDK.
//  Now only deletes Library/Caches (Baidu device ID) and Documents.
//  Keeps Library/Preferences (payment SDK config) intact.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <AppTrackingTransparency/AppTrackingTransparency.h>
#import <objc/runtime.h>

#define NSLog(...)

static NSUUID *_spoofedIDFA = nil;
static NSUUID *_spoofedIDFV = nil;
static NSString *_spoofedDeviceName = nil;

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
// First-launch-only: clear Baidu UserDefaults
// ============================================================
static void clearBaiduUserDefaultsOnce(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *flagKey = kKey(@"ud_cleaned_v3");
    if ([defaults boolForKey:flagKey]) return;

    // Save our own config
    NSMutableDictionary *myConfig = [NSMutableDictionary dictionary];
    NSDictionary *allDict = [defaults dictionaryRepresentation];
    for (NSString *key in allDict) {
        if ([key hasPrefix:@"BaiduBox.cfg."]) {
            myConfig[key] = allDict[key];
        }
    }

    // Only delete Baidu-specific keys. Keep everything else
    // (payment SDK, login state, other app data).
    NSArray *baiduPatterns = @[@"cuid", @"device_id", @"deviceid",
                               @"bduss", @"STOKEN", @"BDID",
                               @"baidu", @"BIDU", @"bd_",
                               @"BaiduBox", @"BDSDK"];
    for (NSString *key in allDict) {
        // Skip system keys
        if ([key hasPrefix:@"AKService"]) continue;
        if ([key hasPrefix:@"Apple"]) continue;
        if ([key hasPrefix:@"NS"]) continue;
        if ([key hasPrefix:@"com.apple"]) continue;
        if ([key hasPrefix:@"ITF"]) continue;
        if ([key hasPrefix:@"MSV"]) continue;
        if ([key hasPrefix:@"WebKit"]) continue;
        if ([key hasPrefix:@"CFUser"]) continue;
        if ([key hasPrefix:@"pkc"]) continue;
        // Skip payment SDK keys
        NSString *lowerKey = [key lowercaseString];
        if ([lowerKey containsString:@"alipay"]) continue;
        if ([lowerKey containsString:@"wechat"]) continue;
        if ([lowerKey containsString:@"tencent"]) continue;
        if ([lowerKey containsString:@"xauth"]) continue;
        // Only delete if it matches a Baidu pattern
        BOOL isBaidu = NO;
        for (NSString *pattern in baiduPatterns) {
            if ([lowerKey containsString:[pattern lowercaseString]]) {
                isBaidu = YES;
                break;
            }
        }
        if (isBaidu) {
            [defaults removeObjectForKey:key];
        }
    }

    // Restore our config
    for (NSString *key in myConfig) {
        [defaults setObject:myConfig[key] forKey:key];
    }
    [defaults setBool:YES forKey:flagKey];
    [defaults synchronize];
}

// ============================================================
// First-launch-only: nuke sandbox — Caches only!
// DO NOT delete Library/Preferences (payment SDK config lives here)
// ============================================================
static void nukeSandboxOnce(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *flagKey = kKey(@"sandbox_nuked_v3");
    if ([defaults boolForKey:flagKey]) return;

    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *home = NSHomeDirectory();

    // Save our config
    NSMutableDictionary *savedConfig = [NSMutableDictionary dictionary];
    NSDictionary *allDict = [defaults dictionaryRepresentation];
    for (NSString *key in allDict) {
        if ([key hasPrefix:@"BaiduBox.cfg."]) {
            savedConfig[key] = allDict[key];
        }
    }

    // Delete Documents
    NSString *docsDir = [home stringByAppendingPathComponent:@"Documents"];
    NSArray *docsFiles = [fm contentsOfDirectoryAtPath:docsDir error:nil];
    for (NSString *f in docsFiles) {
        [fm removeItemAtPath:[docsDir stringByAppendingPathComponent:f] error:nil];
    }

    // Delete Library/Caches ONLY (not Library/Preferences!)
    // Payment SDK stores config in Library/Preferences — must keep it.
    NSString *cachesDir = [home stringByAppendingPathComponent:@"Library/Caches"];
    NSArray *cachesFiles = [fm contentsOfDirectoryAtPath:cachesDir error:nil];
    for (NSString *f in cachesFiles) {
        [fm removeItemAtPath:[cachesDir stringByAppendingPathComponent:f] error:nil];
    }

    // Delete tmp
    NSString *tmpDir = [home stringByAppendingPathComponent:@"tmp"];
    NSArray *tmpFiles = [fm contentsOfDirectoryAtPath:tmpDir error:nil];
    for (NSString *f in tmpFiles) {
        [fm removeItemAtPath:[tmpDir stringByAppendingPathComponent:f] error:nil];
    }

    // Recreate dirs
    [fm createDirectoryAtPath:docsDir withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:cachesDir withIntermediateDirectories:YES attributes:nil error:nil];

    // Restore config
    for (NSString *key in savedConfig) {
        [defaults setObject:savedConfig[key] forKey:key];
    }
    [defaults setBool:YES forKey:flagKey];
    [defaults synchronize];
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

        // First-launch-only cleanup (v3 flags)
        NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
        BOOL isFirstLaunch = ![ud boolForKey:kKey(@"first_launch_v3")];
        if (isFirstLaunch) {
            clearBaiduUserDefaultsOnce();
            nukeSandboxOnce();
            [ud setBool:YES forKey:kKey(@"first_launch_v3")];
            [ud synchronize];
        }

        // === Step3 hooks (proven to work with payment) ===

        // 1. IDFA
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

        // 2. ATTrackingManager
        Class attClass = objc_getClass("ATTrackingManager");
        if (attClass) {
            Method m = class_getClassMethod(attClass, @selector(trackingAuthorizationStatus));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSInteger(id s) { return 3; });
                hookClassMethod(attClass, @selector(trackingAuthorizationStatus), imp, method_getTypeEncoding(m));
            }
        }

        // 3. IDFV + device name
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

        // 4. UIPasteboard — block ALL reads
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

        // 5. App Group container blocked
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
