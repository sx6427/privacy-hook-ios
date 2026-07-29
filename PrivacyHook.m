//
//  PrivacyHook.m — Step36: Bundle ID + IDFA/IDFV + Cookie device fingerprint replacement
//
//  Hooks:
//  1. Bundle ID -> original (for payment SDK)
//  2. IDFA -> random per clone
//  3. IDFV -> random per clone
//  4. Device name -> random per clone
//  5. Keychain clear on launch
//  6. NSHTTPCookieStorage cookiesForURL: -> replace DVIF, tcuid, __bid_n, fuid, BAIDUCUID, cuid
//     (Each clone generates its own fake values, stored in NSUserDefaults)
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <AppTrackingTransparency/AppTrackingTransparency.h>
#import <Security/Security.h>
#import <objc/runtime.h>

#define NSLog(...)

static NSUUID *_spoofedIDFA = nil;
static NSUUID *_spoofedIDFV = nil;
static NSString *_spoofedDeviceName = nil;
static NSString *_originalBundleID = @"com.baidu.BaiduMobile";
static IMP orig_bundleIdentifier = NULL;
static IMP orig_infoDictionary = NULL;

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

// ---- Generate fake cookie values (per-clone, stored in NSUserDefaults) ----
static NSString *generateRandomString(NSUInteger length, NSString *charset) {
    NSMutableString *s = [NSMutableString stringWithCapacity:length];
    for (NSUInteger i = 0; i < length; i++) {
        NSUInteger idx = arc4random_uniform((uint32_t)charset.length);
        [s appendFormat:@"%C", [charset characterAtIndex:idx]];
    }
    return s;
}

static NSString *generateFakeCookieValue(NSString *cookieName) {
    NSString *cuidCharset = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    NSString *hexCharset = @"0123456789abcdef";

    if ([cookieName isEqualToString:@"BAIDUCUID"] ||
        [cookieName isEqualToString:@"BAIDUCUID_BFESS"] ||
        [cookieName isEqualToString:@"MAWEBCUID"] ||
        [cookieName isEqualToString:@"cuid"]) {
        return generateRandomString(arc4random_uniform(7) + 58, cuidCharset);
    }

    if ([cookieName isEqualToString:@"DVIF"]) {
        NSString *num = [NSString stringWithFormat:@"%lu", (unsigned long)(arc4random_uniform(9000000000000000ULL) + 1000000000000000ULL)];
        NSMutableData *rawData = [NSMutableData dataWithLength:300];
        arc4random_buf([rawData mutableBytes], 300);
        NSString *b64 = [rawData base64EncodedStringWithOptions:0];
        NSString *suffix = generateRandomString(6, hexCharset);
        return [NSString stringWithFormat:@"%@_%@_%@", num, b64, suffix];
    }

    if ([cookieName isEqualToString:@"tcuid"]) {
        NSString *hex = generateRandomString(40, hexCharset).uppercaseString;
        NSString *letters = generateRandomString(4, @"ABCDEFGHIJ");
        return [NSString stringWithFormat:@"%@%@", hex, letters];
    }

    if ([cookieName isEqualToString:@"__bid_n"]) {
        return generateRandomString(22, hexCharset);
    }

    if ([cookieName isEqualToString:@"fuid"]) {
        return generateRandomString(32, hexCharset);
    }

    return generateRandomString(32, cuidCharset);
}

static NSString *getOrCreateFakeCookieValue(NSString *cookieName) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = [NSString stringWithFormat:@"BaiduBox.cfg.ck.%@", cookieName];
    NSString *existing = [defaults stringForKey:key];
    if (existing) return existing;

    NSString *value = generateFakeCookieValue(cookieName);
    [defaults setObject:value forKey:key];
    [defaults synchronize];
    return value;
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

static NSSet *deviceCookieNames(void) {
    static dispatch_once_t once;
    static NSSet *names = nil;
    dispatch_once(&once, ^{
        names = [NSSet setWithObjects:
            @"BAIDUCUID", @"BAIDUCUID_BFESS", @"MAWEBCUID",
            @"DVIF", @"tcuid", @"__bid_n", @"fuid", @"cuid", nil];
    });
    return names;
}

__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {
        _spoofedIDFA = getOrCreateSpoofedUUID(kKey(@"id1"));
        _spoofedIDFV = getOrCreateSpoofedUUID(kKey(@"id2"));
        _spoofedDeviceName = getOrCreateSpoofedDeviceName(kKey(@"dn"));

        clearKeychainEveryLaunch();

        // === 1. Bundle ID hook (for payment SDK) ===
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

        // === 2. IDFA hook ===
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

        // === 3. ATT tracking authorization ===
        Class attClass = objc_getClass("ATTrackingManager");
        if (attClass) {
            Method m = class_getClassMethod(attClass, @selector(trackingAuthorizationStatus));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSInteger(id s) { return 3; });
                hookClassMethod(attClass, @selector(trackingAuthorizationStatus), imp, method_getTypeEncoding(m));
            }
        }

        // === 4. IDFV + device name hook ===
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

        // === 5. NSHTTPCookieStorage hook — replace device fingerprint cookies ===
        Class cookieStorageClass = objc_getClass("NSHTTPCookieStorage");
        if (cookieStorageClass) {
            Method cm = class_getInstanceMethod(cookieStorageClass, @selector(cookiesForURL:));
            if (cm) {
                IMP orig_cookiesForURL = method_getImplementation(cm);
                IMP cookieImp = imp_implementationWithBlock(^NSArray *(id self, NSURL *url) {
                    NSArray *cookies = ((NSArray *(*)(id, SEL, NSURL *))orig_cookiesForURL)(self, @selector(cookiesForURL:), url);

                    NSString *host = [url host];
                    if (!host || ![host containsString:@"baidu.com"]) {
                        return cookies;
                    }

                    NSSet *replaceNames = deviceCookieNames();
                    NSMutableArray *modified = [NSMutableArray arrayWithCapacity:cookies.count];
                    BOOL changed = NO;

                    for (NSHTTPCookie *cookie in cookies) {
                        if ([replaceNames containsObject:cookie.name]) {
                            NSString *fakeVal = getOrCreateFakeCookieValue(cookie.name);
                            if (fakeVal) {
                                NSMutableDictionary *props = [cookie.properties mutableCopy];
                                props[NSHTTPCookieValue] = fakeVal;
                                NSHTTPCookie *newCookie = [[NSHTTPCookie alloc] initWithProperties:props];
                                if (newCookie) {
                                    [modified addObject:newCookie];
                                    changed = YES;
                                    continue;
                                }
                            }
                        }
                        [modified addObject:cookie];
                    }

                    return changed ? [modified copy] : cookies;
                });
                class_replaceMethod(cookieStorageClass, @selector(cookiesForURL:), cookieImp, method_getTypeEncoding(cm));
            }

            // Also hook cookies (returns all cookies)
            Method cm2 = class_getInstanceMethod(cookieStorageClass, @selector(cookies));
            if (cm2) {
                IMP orig_cookies = method_getImplementation(cm2);
                IMP cookiesImp = imp_implementationWithBlock(^NSArray *(id self) {
                    NSArray *cookies = ((NSArray *(*)(id, SEL))orig_cookies)(self, @selector(cookies));

                    NSSet *replaceNames = deviceCookieNames();
                    NSMutableArray *modified = [NSMutableArray arrayWithCapacity:cookies.count];
                    BOOL changed = NO;

                    for (NSHTTPCookie *cookie in cookies) {
                        if ([replaceNames containsObject:cookie.name]) {
                            NSString *fakeVal = getOrCreateFakeCookieValue(cookie.name);
                            if (fakeVal) {
                                NSMutableDictionary *props = [cookie.properties mutableCopy];
                                props[NSHTTPCookieValue] = fakeVal;
                                NSHTTPCookie *newCookie = [[NSHTTPCookie alloc] initWithProperties:props];
                                if (newCookie) {
                                    [modified addObject:newCookie];
                                    changed = YES;
                                    continue;
                                }
                            }
                        }
                        [modified addObject:cookie];
                    }

                    return changed ? [modified copy] : cookies;
                });
                class_replaceMethod(cookieStorageClass, @selector(cookies), cookiesImp, method_getTypeEncoding(cm2));
            }
        }

        // === 6. Hook NSMutableURLRequest setValue:forHTTPHeaderField: ===
        Class mutableReqClass = objc_getClass("NSMutableURLRequest");
        if (mutableReqClass) {
            Method sm = class_getInstanceMethod(mutableReqClass, @selector(setValue:forHTTPHeaderField:));
            if (sm) {
                IMP orig_setValue = method_getImplementation(sm);
                IMP setValueImp = imp_implementationWithBlock(^void(id self, SEL _cmd, NSString *value, NSString *field) {
                    if ([field isEqualToString:@"Cookie"] && value && [value containsString:@"baidu"]) {
                        NSString *modified = value;
                        NSArray *names = @[@"BAIDUCUID", @"BAIDUCUID_BFESS", @"MAWEBCUID",
                                           @"DVIF", @"tcuid", @"__bid_n", @"fuid"];
                        for (NSString *name in names) {
                            NSString *fakeVal = getOrCreateFakeCookieValue(name);
                            NSString *pattern = [NSString stringWithFormat:@"%@=[^;]+", name];
                            NSRegularExpression *regex = [NSRegularExpression
                                regularExpressionWithPattern:pattern
                                options:NSRegularExpressionCaseInsensitive
                                error:nil];
                            modified = [regex stringByReplacingMatchesInString:modified
                                options:0 range:NSMakeRange(0, modified.length)
                                withTemplate:[NSString stringWithFormat:@"%@=%@", name, fakeVal]];
                        }
                        NSString *cuidFake = getOrCreateFakeCookieValue(@"cuid");
                        NSRegularExpression *cuidRegex = [NSRegularExpression
                            regularExpressionWithPattern:@"(?<![A-Za-z_])cuid=[^;]+"
                            options:0 error:nil];
                        modified = [cuidRegex stringByReplacingMatchesInString:modified
                            options:0 range:NSMakeRange(0, modified.length)
                            withTemplate:[NSString stringWithFormat:@"cuid=%@", cuidFake]];

                        ((void(*)(id, SEL, NSString *, NSString *))orig_setValue)(
                            self, @selector(setValue:forHTTPHeaderField:), modified, field);
                        return;
                    }
                    ((void(*)(id, SEL, NSString *, NSString *))orig_setValue)(
                        self, @selector(setValue:forHTTPHeaderField:), value, field);
                });
                class_replaceMethod(mutableReqClass, @selector(setValue:forHTTPHeaderField:),
                                    setValueImp, method_getTypeEncoding(sm));
            }

            Method am = class_getInstanceMethod(mutableReqClass, @selector(addValue:forHTTPHeaderField:));
            if (am) {
                IMP orig_addValue = method_getImplementation(am);
                IMP addValueImp = imp_implementationWithBlock(^void(id self, SEL _cmd, NSString *value, NSString *field) {
                    if ([field isEqualToString:@"Cookie"] && value) {
                        NSString *modified = value;
                        NSArray *names = @[@"BAIDUCUID", @"BAIDUCUID_BFESS", @"MAWEBCUID",
                                           @"DVIF", @"tcuid", @"__bid_n", @"fuid"];
                        for (NSString *name in names) {
                            NSString *fakeVal = getOrCreateFakeCookieValue(name);
                            NSString *pattern = [NSString stringWithFormat:@"%@=[^;]+", name];
                            NSRegularExpression *regex = [NSRegularExpression
                                regularExpressionWithPattern:pattern
                                options:NSRegularExpressionCaseInsensitive error:nil];
                            modified = [regex stringByReplacingMatchesInString:modified
                                options:0 range:NSMakeRange(0, modified.length)
                                withTemplate:[NSString stringWithFormat:@"%@=%@", name, fakeVal]];
                        }
                        ((void(*)(id, SEL, NSString *, NSString *))orig_addValue)(
                            self, @selector(addValue:forHTTPHeaderField:), modified, field);
                        return;
                    }
                    ((void(*)(id, SEL, NSString *, NSString *))orig_addValue)(
                        self, @selector(addValue:forHTTPHeaderField:), value, field);
                });
                class_replaceMethod(mutableReqClass, @selector(addValue:forHTTPHeaderField:),
                                    addValueImp, method_getTypeEncoding(am));
            }
        }
    }
}
