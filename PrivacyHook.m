//
// PrivacyHook.m — v48: v47 + sysctl + WiFi block + ObjC device ID hooks
//
// Based on reverse analysis of BaiduBoxApp binary (376MB):
//
// v47 base (retained):
//   - Cookie read-only replacement (CUID, BAIDUCUID, etc.)
//   - Bundle ID 3-method hook (payment compatibility)
//   - IDFV/IDFA hook
//   - Device name hook
//   - NSUserDefaults device key hook
//   - Cookie header replacement (NSMutableURLRequest)
//   - Keychain/Cookie clear on first launch
//
// v48 NEW (from reverse analysis findings):
//   1. fishhook: sysctlbyname — hw.machine, hw.model, hw.memsize, hw.ncpu, kern.osversion
//      Found: sysctl queries for hw.machine (1), hw.model (1), hw.memsize (1), hw.ncpu (1), kern.osversion (1)
//      These are hardware fingerprint components used by server-side risk control.
//
//   2. fishhook: CNCopySupportedInterfaces — return NULL
//      Found: WIFISSID | WIFIBSSID in device fingerprint signature string
//      String: IDFA | IDFAMD5 | OSVS | TERM | WIFI | WIFISSID | WIFIBSSID | SCWH | AKEY | ANAME | SDKVS | signString
//      WiFi SSID/BSSID is a strong network fingerprint that identifies the device.
//
//   3. ObjC: +[BIMBaiduUDID value] — return fake UDID
//      Found: +[BIMBaiduUDID value] in binary
//      Found: baiduudidkey with getter/setter API (http://10.103.227.13:8866/v2/getter)
//      This is Baidu's own device identifier, likely stored in Keychain and persisted.
//
//   4. ObjC: -[BIMConfigurationManager cuid] — return fake CUID
//      Found: -[BIMConfigurationManager cuid] in binary
//      IM SDK has its own CUID source that bypasses cookie storage.
//
//   5. ObjC: -[BARSDKProConfig CUID] — return fake CUID
//      Found: -[BARSDKProConfig CUID] in binary
//      AR SDK has its own CUID config.
//
//   6. ObjC: -[UtilsHelper getDeviceID] — return fake device ID
//      Found: -[UtilsHelper getDeviceID] and -[UtilsHelper getDeviceIDAndUpdate] in binary
//      This is a generic device ID getter that might bypass our hooks.
//
//   7. ObjC: -[DMDeviceInfoWrapper deviceModel/systemVersion/cellularProviderName] — return fake values
//      Found: +[DMDeviceInfoWrapper cellularProviderName], +[DMDeviceInfoWrapper deviceModel], +[DMDeviceInfoWrapper systemVersion]
//      Device info wrapper used for fingerprinting.
//
// Key insight: "下单人数过多" is NOT in the binary — it's a SERVER-SIDE response.
// The server identifies the device by combining: CUID + IDFV + IDFA + BaiduUDID +
// WiFi SSID/BSSID + hw.machine + screen resolution + IP address.
// Our v47 hooks cover CUID (cookie) + IDFV + IDFA, but NOT the others.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#define NSLog(...)

static NSString *const kOrigBundleID = @"com.baidu.BaiduMobile";
static __thread BOOL g_inCookieHook = NO;
static BOOL g_inUDHook = NO;

// ============================================================
// Persistent fake IDs
// ============================================================
static NSString *getPersistent(NSString *key, NSString *(^gen)(void)) {
    CFStringRef cfKey = (__bridge CFStringRef)key;
    CFPropertyListRef val = CFPreferencesCopyAppValue(cfKey, kCFPreferencesCurrentApplication);
    if (val) {
        NSString *s = [(__bridge id)val isKindOfClass:[NSString class]] ? (__bridge NSString *)val : nil;
        CFRelease(val);
        if (s) return s;
    }
    NSString *newVal = gen();
    CFPreferencesSetAppValue(cfKey, (__bridge CFStringRef)newVal, kCFPreferencesCurrentApplication);
    CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
    return newVal;
}

static NSString *genUUIDStr(void) { return [[NSUUID UUID] UUIDString]; }

static NSString *genDeviceName(void) {
    NSArray *sn = @[@"张",@"王",@"李",@"赵",@"刘",@"陈",@"杨",@"黄",@"周",@"吴",@"徐",@"孙",@"马",@"朱",@"胡",@"林",@"郭",@"何",@"高",@"罗"];
    NSArray *md = @[@"iPhone",@"iPhone 13",@"iPhone 14",@"iPhone 15",@"iPhone 12",@"iPhone 11",@"iPhone SE"];
    return [NSString stringWithFormat:@"%@的%@", sn[arc4random_uniform((uint32_t)sn.count)], md[arc4random_uniform((uint32_t)md.count)]];
}

static NSString *genRandStr(NSUInteger len, NSString *cs) {
    NSMutableString *s = [NSMutableString stringWithCapacity:len];
    for (NSUInteger i = 0; i < len; i++)
        [s appendFormat:@"%C", [cs characterAtIndex:arc4random_uniform((uint32_t)cs.length)]];
    return s;
}

static NSString *genCUID(void) {
    NSString *cs = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < 63; i++) {
        if (i > 0 && i % 10 == 3) [s appendString:@"-"];
        else [s appendFormat:@"%C", [cs characterAtIndex:arc4random_uniform((uint32_t)cs.length)]];
    }
    return s;
}

static NSString *genFakeCookie(NSString *name) {
    NSString *cuidCS = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    NSString *hexCS = @"0123456789abcdef";
    if ([name hasPrefix:@"BAIDUCUID"] || [name isEqualToString:@"MAWEBCUID"] || [name isEqualToString:@"cuid"])
        return genCUID();
    if ([name isEqualToString:@"DVIF"]) {
        NSString *num = [NSString stringWithFormat:@"%lu", (unsigned long)((uint64_t)arc4random() * arc4random() % 9000000000000000ULL + 1000000000000000ULL)];
        NSMutableData *d = [NSMutableData dataWithLength:300];
        arc4random_buf([d mutableBytes], 300);
        return [NSString stringWithFormat:@"%@_%@_%@", num, [d base64EncodedStringWithOptions:0], genRandStr(6, hexCS)];
    }
    if ([name isEqualToString:@"tcuid"]) return [genRandStr(40, hexCS).uppercaseString stringByAppendingString:genRandStr(4, @"ABCDEFGHIJ")];
    if ([name isEqualToString:@"__bid_n"]) return genRandStr(22, hexCS);
    if ([name isEqualToString:@"fuid"]) return genRandStr(32, hexCS);
    return genRandStr(32, cuidCS);
}

static NSString *getFakeID(NSString *name) {
    return getPersistent([NSString stringWithFormat:@"Bdhk.ck.%@", name], ^{ return genFakeCookie(name); });
}

// ============================================================
// Fake hardware info (for sysctlbyname hook)
// ============================================================
static NSString *getFakeMachine(void) {
    return getPersistent(@"Bdhk.hw.machine", ^{
        NSArray *models = @[@"iPhone14,2", @"iPhone14,3", @"iPhone14,4", @"iPhone14,5",
                            @"iPhone14,7", @"iPhone14,8", @"iPhone15,2", @"iPhone15,3",
                            @"iPhone15,4", @"iPhone15,5"];
        return models[arc4random_uniform((uint32_t)models.count)];
    });
}

static NSString *getFakeHWModel(void) {
    return getPersistent(@"Bdhk.hw.model", ^{
        NSArray *models = @[@"D63AP", @"D64AP", @"D61AP", @"D65AP",
                            @"D28AP", @"D29AP", @"D73AP", @"D74AP",
                            @"D79AP", @"D80AP"];
        return models[arc4random_uniform((uint32_t)models.count)];
    });
}

static NSString *getFakeOSVersion(void) {
    return getPersistent(@"Bdhk.kern.osversion", ^{
        NSArray *versions = @[@"21A329", @"21A350", @"21F90", @"21E240", @"21D60",
                              @"22A3354", @"22A3311", @"22B5061e"];
        return versions[arc4random_uniform((uint32_t)versions.count)];
    });
}

static uint64_t getFakeMemSize(void) {
    NSString *s = getPersistent(@"Bdhk.hw.memsize", ^{
        NSArray *sizes = @[@(4ULL * 1024 * 1024 * 1024), @(6ULL * 1024 * 1024 * 1024), @(8ULL * 1024 * 1024 * 1024)];
        NSNumber *n = sizes[arc4random_uniform((uint32_t)sizes.count)];
        return [NSString stringWithFormat:@"%llu", [n unsignedLongLongValue]];
    });
    return (uint64_t)[s longLongValue];
}

// ============================================================
// Cookie device ID detection
// ============================================================
static BOOL isDeviceCookie(NSString *cookieName) {
    if (!cookieName) return NO;
    NSString *lk = [cookieName lowercaseString];
    NSArray *names = @[@"baiducuid", @"baiducuid_bfess", @"mawebcuid",
                       @"dvif", @"tcuid", @"__bid_n", @"fuid", @"cuid"];
    for (NSString *n in names) {
        if ([lk isEqualToString:n]) return YES;
    }
    return NO;
}

static NSArray *modifiedCookies(NSArray *cookies) {
    if (!cookies || cookies.count == 0) return cookies;
    NSMutableArray *result = [NSMutableArray array];
    for (NSHTTPCookie *cookie in cookies) {
        if (isDeviceCookie(cookie.name)) {
            NSString *fakeValue = getFakeID(cookie.name);
            NSMutableDictionary *props = [NSMutableDictionary dictionary];
            props[NSHTTPCookieName] = cookie.name;
            props[NSHTTPCookieValue] = fakeValue;
            if (cookie.domain) props[NSHTTPCookieDomain] = cookie.domain;
            if (cookie.path) props[NSHTTPCookiePath] = cookie.path;
            if (cookie.expiresDate) props[NSHTTPCookieExpires] = cookie.expiresDate;
            props[NSHTTPCookieVersion] = @(cookie.version);
            if (cookie.secure) props[NSHTTPCookieSecure] = @YES;
            NSHTTPCookie *newCookie = [[NSHTTPCookie alloc] initWithProperties:props];
            if (newCookie) [result addObject:newCookie];
            else [result addObject:cookie];
        } else {
            [result addObject:cookie];
        }
    }
    return result;
}

// ============================================================
// Keychain + Cookie storage clear (FIRST LAUNCH ONLY)
// ============================================================
static void clearKeychain(void) {
    NSArray *classes = @[(__bridge id)kSecClassGenericPassword, (__bridge id)kSecClassInternetPassword,
                         (__bridge id)kSecClassCertificate, (__bridge id)kSecClassKey, (__bridge id)kSecClassIdentity];
    for (id cls in classes) { SecItemDelete((__bridge CFDictionaryRef)@{(__bridge id)kSecClass: cls}); }
}

static void clearCookieStorage(void) {
    NSHTTPCookieStorage *storage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    NSArray *cookies = [storage cookies];
    for (NSHTTPCookie *cookie in cookies) { [storage deleteCookie:cookie]; }
}

// ============================================================
// NSUserDefaults device key detection
// ============================================================
static BOOL isDeviceKey(NSString *key) {
    if (!key || g_inUDHook) return NO;
    if ([key hasPrefix:@"Bdhk"]) return NO;
    NSArray *exactKeys = @[@"cuid", @"CUID", @"cuid_galaxy2", @"cuid_gid", @"cuid_loc",
                           @"BAIDUCUID", @"BAIDUCUID_BFESS", @"MAWEBCUID",
                           @"DVIF", @"tcuid", @"__bid_n", @"fuid",
                           @"bdudid", @"baiduid", @"bdid"];
    for (NSString *k in exactKeys) {
        if ([key isEqualToString:k]) return YES;
    }
    if ([key.lowercaseString hasPrefix:@"cuid"]) return YES;
    return NO;
}

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {

        // ---- 1. Clear cookie storage (FIRST LAUNCH ONLY) ----
        @try {
            CFPropertyListRef cleared = CFPreferencesCopyAppValue(CFSTR("Bdhk.cc"), kCFPreferencesCurrentApplication);
            if (!cleared) {
                clearCookieStorage();
                CFPreferencesSetAppValue(CFSTR("Bdhk.cc"), kCFBooleanTrue, kCFPreferencesCurrentApplication);
                CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
            } else { CFRelease(cleared); }
        } @catch (id e) {}

        // ---- 2. Clear keychain (FIRST LAUNCH ONLY) ----
        @try {
            CFPropertyListRef cleared = CFPreferencesCopyAppValue(CFSTR("Bdhk.kc"), kCFPreferencesCurrentApplication);
            if (!cleared) {
                clearKeychain();
                CFPreferencesSetAppValue(CFSTR("Bdhk.kc"), kCFBooleanTrue, kCFPreferencesCurrentApplication);
                CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
            } else { CFRelease(cleared); }
        } @catch (id e) {}

        // ---- 3. Bundle ID hook (3 methods — payment critical) ----
        @try {
            Class bc = objc_getClass("NSBundle");
            if (bc) {
                Method m1 = class_getInstanceMethod(bc, @selector(bundleIdentifier));
                if (m1) {
                    IMP orig1 = method_getImplementation(m1);
                    IMP imp1 = imp_implementationWithBlock(^NSString *(id s) {
                        if ([s isEqual:[NSBundle mainBundle]]) return kOrigBundleID;
                        return ((NSString *(*)(id, SEL))orig1)(s, @selector(bundleIdentifier));
                    });
                    class_replaceMethod(bc, @selector(bundleIdentifier), imp1, method_getTypeEncoding(m1));
                }
                Method m2 = class_getInstanceMethod(bc, @selector(objectForInfoDictionaryKey:));
                if (m2) {
                    IMP orig2 = method_getImplementation(m2);
                    IMP imp2 = imp_implementationWithBlock(^id(id s, NSString *key) {
                        if ([s isEqual:[NSBundle mainBundle]] && key &&
                            [key isEqualToString:@"CFBundleIdentifier"]) return kOrigBundleID;
                        return ((id (*)(id, SEL, NSString *))orig2)(s, @selector(objectForInfoDictionaryKey:), key);
                    });
                    class_replaceMethod(bc, @selector(objectForInfoDictionaryKey:), imp2, method_getTypeEncoding(m2));
                }
                Method m3 = class_getInstanceMethod(bc, @selector(infoDictionary));
                if (m3) {
                    IMP orig3 = method_getImplementation(m3);
                    IMP imp3 = imp_implementationWithBlock(^NSDictionary *(id s) {
                        NSDictionary *dict = ((NSDictionary *(*)(id, SEL))orig3)(s, @selector(infoDictionary));
                        if ([s isEqual:[NSBundle mainBundle]] && dict) {
                            NSMutableDictionary *md = [NSMutableDictionary dictionaryWithDictionary:dict];
                            md[@"CFBundleIdentifier"] = kOrigBundleID;
                            return md;
                        }
                        return dict;
                    });
                    class_replaceMethod(bc, @selector(infoDictionary), imp3, method_getTypeEncoding(m3));
                }
            }
        } @catch (id e) {}

        // ---- 4. UIDevice hooks ----
        @try {
            Class dc = objc_getClass("UIDevice");
            if (dc) {
                Method nameM = class_getInstanceMethod(dc, @selector(name));
                if (nameM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return getPersistent(@"Bdhk.dn", ^{ return genDeviceName(); });
                    });
                    class_replaceMethod(dc, @selector(name), imp, method_getTypeEncoding(nameM));
                }
                Method idfvM = class_getInstanceMethod(dc, @selector(identifierForVendor));
                if (idfvM) {
                    IMP imp = imp_implementationWithBlock(^NSUUID *(id s) {
                        return [[NSUUID alloc] initWithUUIDString:getPersistent(@"Bdhk.iv", ^{ return genUUIDStr(); })];
                    });
                    class_replaceMethod(dc, @selector(identifierForVendor), imp, method_getTypeEncoding(idfvM));
                }
                Method lmM = class_getInstanceMethod(dc, @selector(localizedModel));
                if (lmM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @"iPhone"; });
                    class_replaceMethod(dc, @selector(localizedModel), imp, method_getTypeEncoding(lmM));
                }
                Method modelM = class_getInstanceMethod(dc, @selector(model));
                if (modelM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @"iPhone"; });
                    class_replaceMethod(dc, @selector(model), imp, method_getTypeEncoding(modelM));
                }
            }
        } @catch (id e) {}

        // ---- 5. IDFA hook ----
        @try {
            Class ac = objc_getClass("ASIdentifierManager");
            if (ac) {
                Method m = class_getInstanceMethod(ac, @selector(advertisingIdentifier));
                if (m) {
                    IMP imp = imp_implementationWithBlock(^NSUUID *(id s) {
                        return [[NSUUID alloc] initWithUUIDString:getPersistent(@"Bdhk.ai", ^{ return genUUIDStr(); })];
                    });
                    class_replaceMethod(ac, @selector(advertisingIdentifier), imp, method_getTypeEncoding(m));
                }
            }
        } @catch (id e) {}

        // ---- 6. NSUserDefaults hooks (exact key matching) ----
        @try {
            Class uc = objc_getClass("NSUserDefaults");
            if (uc) {
                Method ofkM = class_getInstanceMethod(uc, @selector(objectForKey:));
                if (ofkM) {
                    IMP orig = method_getImplementation(ofkM);
                    IMP imp = imp_implementationWithBlock(^id(id s, NSString *key) {
                        if (!g_inUDHook && isDeviceKey(key)) {
                            g_inUDHook = YES;
                            @try { NSString *f = getFakeID(@"cuid"); g_inUDHook = NO; return f; }
                            @catch (id e) { g_inUDHook = NO; }
                        }
                        return ((id (*)(id, SEL, NSString *))orig)(s, @selector(objectForKey:), key);
                    });
                    class_replaceMethod(uc, @selector(objectForKey:), imp, method_getTypeEncoding(ofkM));
                }
                Method sfkM = class_getInstanceMethod(uc, @selector(stringForKey:));
                if (sfkM) {
                    IMP orig = method_getImplementation(sfkM);
                    IMP imp = imp_implementationWithBlock(^NSString *(id s, NSString *key) {
                        if (!g_inUDHook && isDeviceKey(key)) {
                            g_inUDHook = YES;
                            @try { NSString *f = getFakeID(@"cuid"); g_inUDHook = NO; return f; }
                            @catch (id e) { g_inUDHook = NO; }
                        }
                        return ((NSString *(*)(id, SEL, NSString *))orig)(s, @selector(stringForKey:), key);
                    });
                    class_replaceMethod(uc, @selector(stringForKey:), imp, method_getTypeEncoding(sfkM));
                }
            }
        } @catch (id e) {}

        // ---- 7. Cookie READ-ONLY hooks (no setCookie/setCookies) ----
        @try {
            Class cs = objc_getClass("NSHTTPCookieStorage");

            Method cfuM = class_getInstanceMethod(cs, @selector(cookiesForURL:));
            if (cfuM) {
                IMP origCFU = method_getImplementation(cfuM);
                IMP newCFU = imp_implementationWithBlock(^NSArray *(id s, NSURL *url) {
                    NSArray *cookies = ((NSArray *(*)(id, SEL, NSURL *))origCFU)(s, @selector(cookiesForURL:), url);
                    if (g_inCookieHook) return cookies;
                    g_inCookieHook = YES;
                    @try { NSArray *m = modifiedCookies(cookies); g_inCookieHook = NO; return m; }
                    @catch (id e) { g_inCookieHook = NO; return cookies; }
                });
                class_replaceMethod(cs, @selector(cookiesForURL:), newCFU, method_getTypeEncoding(cfuM));
            }

            Method allM = class_getInstanceMethod(cs, @selector(cookies));
            if (allM) {
                IMP origAll = method_getImplementation(allM);
                IMP newAll = imp_implementationWithBlock(^NSArray *(id s) {
                    NSArray *cookies = ((NSArray *(*)(id, SEL))origAll)(s, @selector(cookies));
                    if (g_inCookieHook) return cookies;
                    g_inCookieHook = YES;
                    @try { NSArray *m = modifiedCookies(cookies); g_inCookieHook = NO; return m; }
                    @catch (id e) { g_inCookieHook = NO; return cookies; }
                });
                class_replaceMethod(cs, @selector(cookies), newAll, method_getTypeEncoding(allM));
            }
        } @catch (id e) {}

        // ---- 8. NSMutableURLRequest Cookie header replacement ----
        @try {
            Class reqClass = objc_getClass("NSMutableURLRequest");
            if (reqClass) {
                Method svM = class_getInstanceMethod(reqClass, @selector(setValue:forHTTPHeaderField:));
                if (svM) {
                    IMP origSV = method_getImplementation(svM);
                    IMP newSV = imp_implementationWithBlock(^void(id s, NSString *value, NSString *field) {
                        if (value && field && [field caseInsensitiveCompare:@"Cookie"] == NSOrderedSame) {
                            NSArray *names = @[@"BAIDUCUID", @"BAIDUCUID_BFESS", @"MAWEBCUID",
                                               @"DVIF", @"tcuid", @"__bid_n", @"fuid"];
                            NSString *modified = value;
                            for (NSString *name in names) {
                                NSString *fake = getFakeID(name);
                                NSRegularExpression *regex = [NSRegularExpression
                                    regularExpressionWithPattern:[NSString stringWithFormat:@"%@=[^;]+", name]
                                    options:NSRegularExpressionCaseInsensitive error:nil];
                                modified = [regex stringByReplacingMatchesInString:modified options:0
                                    range:NSMakeRange(0, modified.length)
                                    withTemplate:[NSString stringWithFormat:@"%@=%@", name, fake]];
                            }
                            NSRegularExpression *cuidRegex = [NSRegularExpression
                                regularExpressionWithPattern:@"(?<![A-Za-z_])cuid=[^;]+" options:0 error:nil];
                            modified = [cuidRegex stringByReplacingMatchesInString:modified options:0
                                range:NSMakeRange(0, modified.length)
                                withTemplate:[NSString stringWithFormat:@"cuid=%@", getFakeID(@"cuid")]];
                            ((void (*)(id, SEL, NSString *, NSString *))origSV)(s, @selector(setValue:forHTTPHeaderField:), modified, field);
                            return;
                        }
                        ((void (*)(id, SEL, NSString *, NSString *))origSV)(s, @selector(setValue:forHTTPHeaderField:), value, field);
                    });
                    class_replaceMethod(reqClass, @selector(setValue:forHTTPHeaderField:), newSV, method_getTypeEncoding(svM));
                }
            }
        } @catch (id e) {}

        // ---- 9. ObjC: +[BIMBaiduUDID value] — Baidu device UDID ----
        @try {
            Class udidCls = objc_getClass("BIMBaiduUDID");
            if (udidCls) {
                Class metaCls = object_getClass(udidCls);
                Method m = class_getInstanceMethod(metaCls, @selector(value));
                if (m) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return getPersistent(@"Bdhk.budid", ^{ return genUUIDStr(); });
                    });
                    class_replaceMethod(metaCls, @selector(value), imp, method_getTypeEncoding(m));
                }
            }
        } @catch (id e) {}

        // ---- 12. ObjC: -[BIMConfigurationManager cuid] — IM SDK CUID ----
        @try {
            Class cfgCls = objc_getClass("BIMConfigurationManager");
            if (cfgCls) {
                Method m = class_getInstanceMethod(cfgCls, @selector(cuid));
                if (m) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return getFakeID(@"cuid");
                    });
                    class_replaceMethod(cfgCls, @selector(cuid), imp, method_getTypeEncoding(m));
                }
            }
        } @catch (id e) {}

        // ---- 13. ObjC: -[BARSDKProConfig CUID] — AR SDK CUID ----
        @try {
            Class arCls = objc_getClass("BARSDKProConfig");
            if (arCls) {
                Method m = class_getInstanceMethod(arCls, @selector(CUID));
                if (m) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return getFakeID(@"cuid");
                    });
                    class_replaceMethod(arCls, @selector(CUID), imp, method_getTypeEncoding(m));
                }
            }
        } @catch (id e) {}

        // ---- 14. ObjC: -[UtilsHelper getDeviceID] / getDeviceIDAndUpdate ----
        @try {
            Class uhCls = objc_getClass("UtilsHelper");
            if (uhCls) {
                Method m1 = class_getInstanceMethod(uhCls, @selector(getDeviceID));
                if (m1) {
                    IMP imp1 = imp_implementationWithBlock(^NSString *(id s) {
                        return getPersistent(@"Bdhk.udid", ^{ return genUUIDStr(); });
                    });
                    class_replaceMethod(uhCls, @selector(getDeviceID), imp1, method_getTypeEncoding(m1));
                }
                Method m2 = class_getInstanceMethod(uhCls, @selector(getDeviceIDAndUpdate));
                if (m2) {
                    IMP imp2 = imp_implementationWithBlock(^NSString *(id s) {
                        return getPersistent(@"Bdhk.udid", ^{ return genUUIDStr(); });
                    });
                    class_replaceMethod(uhCls, @selector(getDeviceIDAndUpdate), imp2, method_getTypeEncoding(m2));
                }
            }
        } @catch (id e) {}

        // ---- 15. ObjC: -[DMDeviceInfoWrapper deviceModel/systemVersion/cellularProviderName] ----
        @try {
            Class dmCls = objc_getClass("DMDeviceInfoWrapper");
            if (dmCls) {
                // Class methods: +[DMDeviceInfoWrapper deviceModel], +[DMDeviceInfoWrapper systemVersion], +[DMDeviceInfoWrapper cellularProviderName]
                Class metaCls = object_getClass(dmCls);

                Method m1 = class_getInstanceMethod(metaCls, @selector(deviceModel));
                if (m1) {
                    IMP imp1 = imp_implementationWithBlock(^NSString *(id s) {
                        return getFakeMachine();
                    });
                    class_replaceMethod(metaCls, @selector(deviceModel), imp1, method_getTypeEncoding(m1));
                }

                Method m2 = class_getInstanceMethod(metaCls, @selector(systemVersion));
                if (m2) {
                    IMP imp2 = imp_implementationWithBlock(^NSString *(id s) {
                        return getPersistent(@"Bdhk.osvs", ^{
                            NSArray *versions = @[@"16.5", @"16.6", @"17.0", @"17.1", @"17.2", @"17.3", @"17.4", @"17.5", @"17.6", @"18.0", @"18.1", @"18.2", @"18.3", @"18.4"];
                            return versions[arc4random_uniform((uint32_t)versions.count)];
                        });
                    });
                    class_replaceMethod(metaCls, @selector(systemVersion), imp2, method_getTypeEncoding(m2));
                }

                Method m3 = class_getInstanceMethod(metaCls, @selector(cellularProviderName));
                if (m3) {
                    IMP imp3 = imp_implementationWithBlock(^NSString *(id s) {
                        return getPersistent(@"Bdhk.carrier", ^{
                            NSArray *carriers = @[@"中国移动", @"中国联通", @"中国电信"];
                            return carriers[arc4random_uniform((uint32_t)carriers.count)];
                        });
                    });
                    class_replaceMethod(metaCls, @selector(cellularProviderName), imp3, method_getTypeEncoding(m3));
                }
            }
        } @catch (id e) {}

        // ---- 16. ObjC: -[BIMDeviceInfoUtility deviceModelVersion] ----
        @try {
            Class diuCls = objc_getClass("BIMDeviceInfoUtility");
            if (diuCls) {
                Method m = class_getInstanceMethod(diuCls, @selector(deviceModelVersion));
                if (m) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return getFakeMachine();
                    });
                    class_replaceMethod(diuCls, @selector(deviceModelVersion), imp, method_getTypeEncoding(m));
                }
            }
        } @catch (id e) {}

        // ---- 17. ObjC: -[BBAMessageIMManagerUniform isForceCUIDLogin] ----
        // Prevent CUID-based forced login (which might trigger risk control)
        @try {
            Class imCls = objc_getClass("BBAMessageIMManagerUniform");
            if (imCls) {
                Method m = class_getInstanceMethod(imCls, @selector(isForceCUIDLogin));
                if (m) {
                    IMP imp = imp_implementationWithBlock(^BOOL(id s) {
                        return NO;
                    });
                    class_replaceMethod(imCls, @selector(isForceCUIDLogin), imp, method_getTypeEncoding(m));
                }
            }
        } @catch (id e) {}
    }
}
