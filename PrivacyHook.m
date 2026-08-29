
//
// PrivacyHook.m — NO fishhook, pure ObjC swizzle only
// UIDevice + NSProcessInfo + IDFA + NSUserDefaults + Cookie + NSBundle + WKWebView + skip update
//
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <Security/Security.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>

#define NSLog(...)

static __thread BOOL g_inCookieHook = NO;
static BOOL g_inUDHook = NO;

static NSString *getPersistent(NSString *key, NSString *(^gen)(void));
static NSString *getFakeSystemVersion(void);
static NSString *versionToBuild(NSString *version);
static NSString *versionToMachine(NSString *version);
static NSString *genUUIDStr(void);
static NSString *genDeviceName(void);
static NSString *buildFakeUserAgent(void);

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
    NSArray *s = @[@"张", @"王", @"李", @"赵", @"刘"];
    NSArray *g = @[@"伟", @"芳", @"杰", @"磊", @"敏"];
    return [NSString stringWithFormat:@"%@%@的 iPhone",
        s[arc4random_uniform((uint32_t)s.count)],
        g[arc4random_uniform((uint32_t)g.count)]];
}

static NSString *genRandStr(NSUInteger len, NSString *cs) {
    NSMutableString *s = [NSMutableString stringWithCapacity:len];
    for (NSUInteger i = 0; i < len; i++)
        [s appendFormat:@"%C", [cs characterAtIndex:arc4random_uniform((uint32_t)cs.length)]];
    return s;
}

static NSString *getFakeSystemVersion(void) {
    return getPersistent(@"JdD1.sv", ^{
        NSArray *v = @[@"16.5", @"16.6.1", @"16.7.2", @"17.0", @"17.1.2", @"17.2", @"17.3", @"17.4.1"];
        return v[arc4random_uniform((uint32_t)v.count)];
    });
}

static NSString *versionToBuild(NSString *v) {
    NSDictionary *m = @{@"16.5":@"20F66",@"16.6.1":@"20G81",@"16.7.2":@"20H115",
        @"17.0":@"21A329",@"17.1.2":@"21B101",@"17.2":@"21C62",@"17.3":@"21D50",@"17.4.1":@"21E237"};
    return m[v] ?: @"20F66";
}

static NSString *versionToMachine(NSString *v) {
    NSInteger major = [[v componentsSeparatedByString:@"."][0] integerValue];
    if (major == 16) { NSArray *m = @[@"iPhone14,7",@"iPhone14,8",@"iPhone15,2",@"iPhone15,3"]; return m[arc4random_uniform((uint32_t)m.count)]; }
    if (major == 17) { NSArray *m = @[@"iPhone15,4",@"iPhone15,5",@"iPhone16,1",@"iPhone16,2"]; return m[arc4random_uniform((uint32_t)m.count)]; }
    return @"iPhone14,7";
}

static NSOperatingSystemVersion parseVersion(NSString *v) {
    NSArray *p = [v componentsSeparatedByString:@"."];
    NSOperatingSystemVersion ov = {0,0,0};
    if (p.count > 0) ov.majorVersion = [p[0] integerValue];
    if (p.count > 1) ov.minorVersion = [p[1] integerValue];
    if (p.count > 2) ov.patchVersion = [p[2] integerValue];
    return ov;
}

static NSString *buildFakeUserAgent(void) {
    NSString *sv = getFakeSystemVersion();
    NSString *machine = getPersistent(@"JdD1.hw", ^{ return versionToMachine(sv); });
    return [NSString stringWithFormat:@"Mozilla/5.0 (iPhone; CPU iPhone OS %@ like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148", sv];
}

// JD device ID generation
static NSString *getFakeID(NSString *name) {
    return getPersistent([NSString stringWithFormat:@"JdD1.ck.%@", name], ^{
        NSString *hexCS = @"0123456789abcdef";
        return genRandStr(32, hexCS);
    });
}

static BOOL isDeviceCookie(NSString *n) {
    if (!n) return NO;
    NSArray *names = @[@"shshshfpb",@"shshshfpa",@"shshshfp",@"unionwsws",
        @"jcap_dvzw_fp",@"wlfso_s",@"TrackID",@"jdv",@"pt_key",@"pt_pin",@"thor",@"wskey"];
    for (NSString *k in names) { if (n caseInsensitiveCompare:k) return YES; }
    return NO;
}

static BOOL isDeviceKey(NSString *key) {
    if (!key || g_inUDHook) return NO;
    if ([key hasPrefix:@"JdD1"]) return NO;
    NSArray *keys = @[@"shshshfpb",@"shshshfpa",@"shshshfp",@"unionwsws",
        @"jcap_dvzw_fp",@"wlfso_s",@"TrackID",@"jdv",@"pt_key",@"pt_pin",@"thor",@"wskey",
        @"cuid",@"CUID",@"uuid",@"udid",@"deviceFingerprint"];
    for (NSString *k in keys) { if (key caseInsensitiveCompare:k) return YES; }
    return NO;
}

static NSArray *modifiedCookies(NSArray *cookies) {
    if (!cookies || cookies.count == 0) return cookies;
    NSMutableArray *r = [NSMutableArray array];
    for (NSHTTPCookie *c in cookies) {
        if (isDeviceCookie(c.name)) {
            NSMutableDictionary *p = [NSMutableDictionary dictionary];
            p[NSHTTPCookieName] = c.name; p[NSHTTPCookieValue] = getFakeID(c.name);
            if (c.domain) p[NSHTTPCookieDomain] = c.domain;
            if (c.path) p[NSHTTPCookiePath] = c.path;
            if (c.expiresDate) p[NSHTTPCookieExpires] = c.expiresDate;
            p[NSHTTPCookieVersion] = @(c.version);
            if (c.secure) p[NSHTTPCookieSecure] = @YES;
            NSHTTPCookie *nc = [[NSHTTPCookie alloc] initWithProperties:p];
            [r addObject:nc ?: c];
        } else { [r addObject:c]; }
    }
    return r;
}

__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {
        // ---- 1. 清理 Cookie + Keychain（首次） ----
        @try {
            CFPropertyListRef cleared = CFPreferencesCopyAppValue(CFSTR("JdD1.reset"), kCFPreferencesCurrentApplication);
            if (!cleared) {
                NSHTTPCookieStorage *storage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
                for (NSHTTPCookie *c in [storage cookies]) { [storage deleteCookie:c]; }
                NSArray *classes = @[(__bridge id)kSecClassGenericPassword, (__bridge id)kSecClassInternetPassword,
                     (__bridge id)kSecClassCertificate, (__bridge id)kSecClassKey, (__bridge id)kSecClassIdentity];
                for (id cls in classes) { SecItemDelete((__bridge CFDictionaryRef)@{(__bridge id)kSecClass: cls}); }
                CFPreferencesSetAppValue(CFSTR("JdD1.reset"), kCFBooleanTrue, kCFPreferencesCurrentApplication);
                CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
            } else { CFRelease(cleared); }
        } @catch (id e) {}

        // ---- 2. UIDevice hooks ----
        @try {
            Class dc = objc_getClass("UIDevice");
            if (dc) {
                Method nameM = class_getInstanceMethod(dc, @selector(name));
                if (nameM) { class_replaceMethod(dc, @selector(name),
                    imp_implementationWithBlock(^NSString *(id s) { return getPersistent(@"JdD1.dn", ^{ return genDeviceName(); }); }),
                    method_getTypeEncoding(nameM)); }
                Method idfvM = class_getInstanceMethod(dc, @selector(identifierForVendor));
                if (idfvM) { class_replaceMethod(dc, @selector(identifierForVendor),
                    imp_implementationWithBlock(^NSUUID *(id s) { return [[NSUUID alloc] initWithUUIDString:getPersistent(@"JdD1.iv", ^{ return genUUIDStr(); })]; }),
                    method_getTypeEncoding(idfvM)); }
                Method modelM = class_getInstanceMethod(dc, @selector(model));
                if (modelM) { class_replaceMethod(dc, @selector(model),
                    imp_implementationWithBlock(^NSString *(id s) { return @"iPhone"; }),
                    method_getTypeEncoding(modelM)); }
                Method svM = class_getInstanceMethod(dc, @selector(systemVersion));
                if (svM) { class_replaceMethod(dc, @selector(systemVersion),
                    imp_implementationWithBlock(^NSString *(id s) { return getFakeSystemVersion(); }),
                    method_getTypeEncoding(svM)); }
            }
        } @catch (id e) {}

        // ---- 3. NSProcessInfo hooks ----
        @try {
            Class pi = objc_getClass("NSProcessInfo");
            if (pi) {
                Method osvM = class_getInstanceMethod(pi, @selector(operatingSystemVersion));
                if (osvM) { class_replaceMethod(pi, @selector(operatingSystemVersion),
                    imp_implementationWithBlock(^NSOperatingSystemVersion(id s) { return parseVersion(getFakeSystemVersion()); }),
                    method_getTypeEncoding(osvM)); }
                Method osvsM = class_getInstanceMethod(pi, @selector(operatingSystemVersionString));
                if (osvsM) { class_replaceMethod(pi, @selector(operatingSystemVersionString),
                    imp_implementationWithBlock(^NSString *(id s) {
                        NSString *sv = getFakeSystemVersion();
                        return [NSString stringWithFormat:@"Version %@ (Build %@)", sv, versionToBuild(sv)];
                    }), method_getTypeEncoding(osvsM)); }
            }
        } @catch (id e) {}

        // ---- 4. IDFA hook ----
        @try {
            Class ac = objc_getClass("ASIdentifierManager");
            if (ac) {
                Method m = class_getInstanceMethod(ac, @selector(advertisingIdentifier));
                if (m) { class_replaceMethod(ac, @selector(advertisingIdentifier),
                    imp_implementationWithBlock(^NSUUID *(id s) { return [[NSUUID alloc] initWithUUIDString:getPersistent(@"JdD1.ai", ^{ return genUUIDStr(); })]; }),
                    method_getTypeEncoding(m)); }
            }
        } @catch (id e) {}

        // ---- 5. NSUserDefaults hooks ----
        @try {
            Class uc = objc_getClass("NSUserDefaults");
            if (uc) {
                Method ofkM = class_getInstanceMethod(uc, @selector(objectForKey:));
                if (ofkM) {
                    IMP orig = method_getImplementation(ofkM);
                    IMP imp = imp_implementationWithBlock(^id(id s, NSString *key) {
                        if (!g_inUDHook && isDeviceKey(key)) {
                            g_inUDHook = YES;
                            @try { NSString *f = getFakeID(@"shshshfpb"); g_inUDHook = NO; return f; }
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
                            @try { NSString *f = getFakeID(@"shshshfpb"); g_inUDHook = NO; return f; }
                            @catch (id e) { g_inUDHook = NO; }
                        }
                        return ((NSString *(*)(id, SEL, NSString *))orig)(s, @selector(stringForKey:), key);
                    });
                    class_replaceMethod(uc, @selector(stringForKey:), imp, method_getTypeEncoding(sfkM));
                }
                // boolForKey: — skip update detection
                Method bfkM = class_getInstanceMethod(uc, @selector(boolForKey:));
                if (bfkM) {
                    IMP orig = method_getImplementation(bfkM);
                    IMP imp = imp_implementationWithBlock(^BOOL(id s, NSString *key) {
                        if (key) {
                            NSString *lk = key.lowercaseString;
                            if ([lk containsString:@"needupdate"] || [lk containsString:@"forceupdate"] ||
                                [lk containsString:@"mustupdate"] || [lk containsString:@"hasupdate"] ||
                                [lk containsString:@"isforceupdate"] || [lk containsString:@"newversion"]) {
                                return NO;
                            }
                        }
                        return ((BOOL (*)(id, SEL, NSString *))orig)(s, @selector(boolForKey:), key);
                    });
                    class_replaceMethod(uc, @selector(boolForKey:), imp, method_getTypeEncoding(bfkM));
                }
            }
        } @catch (id e) {}

        // ---- 6. Cookie hooks ----
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

        // ---- 7. NSMutableURLRequest Cookie header ----
        @try {
            Class reqClass = objc_getClass("NSMutableURLRequest");
            if (reqClass) {
                Method svM = class_getInstanceMethod(reqClass, @selector(setValue:forHTTPHeaderField:));
                if (svM) {
                    IMP origSV = method_getImplementation(svM);
                    IMP newSV = imp_implementationWithBlock(^void(id s, NSString *value, NSString *field) {
                        if (value && field && [field caseInsensitiveCompare:@"Cookie"] == NSOrderedSame) {
                            NSArray *names = @[@"shshshfpb",@"shshshfpa",@"shshshfp",@"unionwsws",
                                @"jcap_dvzw_fp",@"wlfso_s",@"TrackID",@"jdv",
                                @"pt_key",@"pt_pin",@"thor",@"wskey"];
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
                            ((void (*)(id, SEL, NSString *, NSString *))origSV)(s, @selector(setValue:forHTTPHeaderField:), modified, field);
                            return;
                        }
                        ((void (*)(id, SEL, NSString *, NSString *))origSV)(s, @selector(setValue:forHTTPHeaderField:), value, field);
                    });
                    class_replaceMethod(reqClass, @selector(setValue:forHTTPHeaderField:), newSV, method_getTypeEncoding(svM));
                }
            }
        } @catch (id e) {}

        // ---- 8. NSBundle infoDictionary ----
        @try {
            Class bundle = objc_getClass("NSBundle");
            if (bundle) {
                Method infoM = class_getInstanceMethod(bundle, @selector(infoDictionary));
                if (infoM) {
                    IMP origInfo = method_getImplementation(infoM);
                    IMP newInfo = imp_implementationWithBlock(^NSDictionary *(id s) {
                        NSDictionary *dict = ((NSDictionary *(*)(id, SEL))origInfo)(s, @selector(infoDictionary));
                        if (dict) {
                            NSMutableDictionary *md = [dict mutableCopy];
                            NSString *fakeSV = getFakeSystemVersion();
                            NSString *fakeBuild = versionToBuild(fakeSV);
                            md[@"DTPlatformVersion"] = fakeSV;
                            md[@"DTSDKName"] = [NSString stringWithFormat:@"iphoneos%@", fakeSV];
                            md[@"MinimumOSVersion"] = fakeSV;
                            md[@"DTSDKBuild"] = fakeBuild;
                            md[@"DTPlatformBuild"] = fakeBuild;
                            return md;
                        }
                        return dict;
                    });
                    class_replaceMethod(bundle, @selector(infoDictionary), newInfo, method_getTypeEncoding(infoM));
                }
            }
        } @catch (id e) {}

        // ---- 9. WKWebView customUserAgent ----
        @try {
            Class wkClass = objc_getClass("WKWebView");
            if (wkClass) {
                Method initM = class_getInstanceMethod(wkClass, @selector(initWithFrame:configuration:));
                if (initM) {
                    IMP origInit = method_getImplementation(initM);
                    IMP newInit = imp_implementationWithBlock(^id(id s, CGRect frame, id config) {
                        id obj = ((id (*)(id, SEL, CGRect, id))origInit)(s, @selector(initWithFrame:configuration:), frame, config);
                        if (obj) {
                            @try {
                                NSString *cur = [obj valueForKey:@"customUserAgent"];
                                if (!cur || cur.length == 0) {
                                    [obj setValue:buildFakeUserAgent() forKey:@"customUserAgent"];
                                }
                            } @catch (id e) {}
                        }
                        return obj;
                    });
                    class_replaceMethod(wkClass, @selector(initWithFrame:configuration:), newInit, method_getTypeEncoding(initM));
                }
            }
        } @catch (id e) {}
    }
}
