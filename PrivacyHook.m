//
// NoFishHook.m — pure ObjC swizzle, NO fishhook at all
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
    NSArray *surnames = @[@"张", @"王", @"李", @"赵", @"刘"];
    NSArray *givenNames = @[@"伟", @"芳", @"杰", @"磊", @"敏"];
    return [NSString stringWithFormat:@"%@%@的 iPhone",
        surnames[arc4random_uniform((uint32_t)surnames.count)],
        givenNames[arc4random_uniform((uint32_t)givenNames.count)]];
}

static NSString *genRandStr(NSUInteger len, NSString *cs) {
    NSMutableString *s = [NSMutableString stringWithCapacity:len];
    for (NSUInteger i = 0; i < len; i++)
        [s appendFormat:@"%C", [cs characterAtIndex:arc4random_uniform((uint32_t)cs.length)]];
    return s;
}

static NSString *getFakeSystemVersion(void) {
    return getPersistent(@"JdD1.sv", ^{
        NSArray *versions = @[@"16.5", @"16.6.1", @"16.7.2", @"17.0", @"17.1.2", @"17.2", @"17.3", @"17.4.1"];
        return versions[arc4random_uniform((uint32_t)versions.count)];
    });
}

static NSString *versionToBuild(NSString *version) {
    NSDictionary *map = @{@"16.5":@"20F66",@"16.6.1":@"20G81",@"16.7.2":@"20H115",
        @"17.0":@"21A329",@"17.1.2":@"21B101",@"17.2":@"21C62",@"17.3":@"21D50",@"17.4.1":@"21E237"};
    return map[version] ?: @"20F66";
}

static NSString *versionToMachine(NSString *version) {
    NSInteger major = [[version componentsSeparatedByString:@"."][0] integerValue];
    if (major == 16) {
        NSArray *m = @[@"iPhone14,7",@"iPhone14,8",@"iPhone15,2",@"iPhone15,3"];
        return m[arc4random_uniform((uint32_t)m.count)];
    }
    if (major == 17) {
        NSArray *m = @[@"iPhone15,4",@"iPhone15,5",@"iPhone16,1",@"iPhone16,2"];
        return m[arc4random_uniform((uint32_t)m.count)];
    }
    return @"iPhone14,7";
}

static NSOperatingSystemVersion parseVersion(NSString *versionStr) {
    NSOperatingSystemVersion ov = {0,0,0};
    NSArray *parts = [versionStr componentsSeparatedByString:@"."];
    if (parts.count > 0) ov.majorVersion = [parts[0] integerValue];
    if (parts.count > 1) ov.minorVersion = [parts[1] integerValue];
    if (parts.count > 2) ov.patchVersion = [parts[2] integerValue];
    return ov;
}

static NSString *buildFakeUserAgent(void) {
    NSString *sv = getFakeSystemVersion();
    return [NSString stringWithFormat:@"Mozilla/5.0 (iPhone; CPU iPhone OS %@ like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148", sv];
}

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
    for (NSString *k in names) {
        if ([n caseInsensitiveCompare:k] == NSOrderedSame) return YES;
    }
    return NO;
}

static BOOL isDeviceKey(NSString *key) {
    if (!key || g_inUDHook) return NO;
    if ([key hasPrefix:@"JdD1"]) return NO;
    NSArray *keys = @[@"shshshfpb",@"shshshfpa",@"shshshfp",@"unionwsws",
        @"jcap_dvzw_fp",@"wlfso_s",@"TrackID",@"jdv",@"pt_key",@"pt_pin",@"thor",@"wskey",
        @"cuid",@"CUID",@"uuid",@"udid",@"deviceFingerprint"];
    for (NSString *k in keys) {
        if ([key caseInsensitiveCompare:k] == NSOrderedSame) return YES;
    }
    return NO;
}

static NSArray *modifiedCookies(NSArray *cookies) {
    if (!cookies || cookies.count == 0) return cookies;
    NSMutableArray *result = [NSMutableArray array];
    for (NSHTTPCookie *cookie in cookies) {
        if (isDeviceCookie(cookie.name)) {
            NSMutableDictionary *props = [NSMutableDictionary dictionary];
            props[NSHTTPCookieName] = cookie.name;
            props[NSHTTPCookieValue] = getFakeID(cookie.name);
            if (cookie.domain) props[NSHTTPCookieDomain] = cookie.domain;
            if (cookie.path) props[NSHTTPCookiePath] = cookie.path;
            if (cookie.expiresDate) props[NSHTTPCookieExpires] = cookie.expiresDate;
            props[NSHTTPCookieVersion] = @(cookie.version);
            if (cookie.secure) props[NSHTTPCookieSecure] = @YES;
            NSHTTPCookie *newCookie = [[NSHTTPCookie alloc] initWithProperties:props];
            [result addObject:newCookie ?: cookie];
        } else {
            [result addObject:cookie];
        }
    }
    return result;
}

__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {
        // 1. Clean Cookie + Keychain (first run)
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

        // 2. UIDevice hooks
        @try {
            Class dc = objc_getClass("UIDevice");
            if (dc) {
                Method nameM = class_getInstanceMethod(dc, @selector(name));
                if (nameM) {
                    class_replaceMethod(dc, @selector(name),
                        imp_implementationWithBlock(^NSString *(id s) {
                            return getPersistent(@"JdD1.dn", ^{ return genDeviceName(); });
                        }), method_getTypeEncoding(nameM));
                }
                Method idfvM = class_getInstanceMethod(dc, @selector(identifierForVendor));
                if (idfvM) {
                    class_replaceMethod(dc, @selector(identifierForVendor),
                        imp_implementationWithBlock(^NSUUID *(id s) {
                            return [[NSUUID alloc] initWithUUIDString:getPersistent(@"JdD1.iv", ^{ return genUUIDStr(); })];
                        }), method_getTypeEncoding(idfvM));
                }
                Method modelM = class_getInstanceMethod(dc, @selector(model));
                if (modelM) {
                    class_replaceMethod(dc, @selector(model),
                        imp_implementationWithBlock(^NSString *(id s) { return @"iPhone"; }),
                        method_getTypeEncoding(modelM));
                }
                Method svM = class_getInstanceMethod(dc, @selector(systemVersion));
                if (svM) {
                    class_replaceMethod(dc, @selector(systemVersion),
                        imp_implementationWithBlock(^NSString *(id s) { return getFakeSystemVersion(); }),
                        method_getTypeEncoding(svM));
                }
            }
        } @catch (id e) {}

        // 3. NSProcessInfo hooks
        @try {
            Class pi = objc_getClass("NSProcessInfo");
            if (pi) {
                Method osvM = class_getInstanceMethod(pi, @selector(operatingSystemVersion));
                if (osvM) {
                    class_replaceMethod(pi, @selector(operatingSystemVersion),
                        imp_implementationWithBlock(^NSOperatingSystemVersion(id s) {
                            return parseVersion(getFakeSystemVersion());
                        }), method_getTypeEncoding(osvM));
                }
                Method osvsM = class_getInstanceMethod(pi, @selector(operatingSystemVersionString));
                if (osvsM) {
                    class_replaceMethod(pi, @selector(operatingSystemVersionString),
                        imp_implementationWithBlock(^NSString *(id s) {
                            NSString *sv = getFakeSystemVersion();
                            return [NSString stringWithFormat:@"Version %@ (Build %@)", sv, versionToBuild(sv)];
                        }), method_getTypeEncoding(osvsM));
                }
            }
        } @catch (id e) {}

        // 4. IDFA hook
        @try {
            Class ac = objc_getClass("ASIdentifierManager");
            if (ac) {
                Method m = class_getInstanceMethod(ac, @selector(advertisingIdentifier));
                if (m) {
                    class_replaceMethod(ac, @selector(advertisingIdentifier),
                        imp_implementationWithBlock(^NSUUID *(id s) {
                            return [[NSUUID alloc] initWithUUIDString:getPersistent(@"JdD1.ai", ^{ return genUUIDStr(); })];
                        }), method_getTypeEncoding(m));
                }
            }
        } @catch (id e) {}

        // 5. NSUserDefaults hooks
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
                            if ([lk containsString:@"needupdate"] ||
                                [lk containsString:@"forceupdate"] ||
                                [lk containsString:@"mustupdate"] ||
                                [lk containsString:@"hasupdate"] ||
                                [lk containsString:@"isforceupdate"] ||
                                [lk containsString:@"newversion"]) {
                                return NO;
                            }
                        }
                        return ((BOOL (*)(id, SEL, NSString *))orig)(s, @selector(boolForKey:), key);
                    });
                    class_replaceMethod(uc, @selector(boolForKey:), imp, method_getTypeEncoding(bfkM));
                }
            }
        } @catch (id e) {}

        // 6. Cookie hooks
        @try {
            Class cs = objc_getClass("NSHTTPCookieStorage");
            Method cfuM = class_getInstanceMethod(cs, @selector(cookiesForURL:));
            if (cfuM) {
                IMP orig = method_getImplementation(cfuM);
                IMP imp = imp_implementationWithBlock(^NSArray *(id s, NSURL *url) {
                    NSArray *cookies = ((NSArray *(*)(id, SEL, NSURL *))orig)(s, @selector(cookiesForURL:), url);
                    if (g_inCookieHook) return cookies;
                    g_inCookieHook = YES;
                    @try { NSArray *m = modifiedCookies(cookies); g_inCookieHook = NO; return m; }
                    @catch (id e) { g_inCookieHook = NO; return cookies; }
                });
                class_replaceMethod(cs, @selector(cookiesForURL:), imp, method_getTypeEncoding(cfuM));
            }
            Method allM = class_getInstanceMethod(cs, @selector(cookies));
            if (allM) {
                IMP orig = method_getImplementation(allM);
                IMP imp = imp_implementationWithBlock(^NSArray *(id s) {
                    NSArray *cookies = ((NSArray *(*)(id, SEL))orig)(s, @selector(cookies));
                    if (g_inCookieHook) return cookies;
                    g_inCookieHook = YES;
                    @try { NSArray *m = modifiedCookies(cookies); g_inCookieHook = NO; return m; }
                    @catch (id e) { g_inCookieHook = NO; return cookies; }
                });
                class_replaceMethod(cs, @selector(cookies), imp, method_getTypeEncoding(allM));
            }
        } @catch (id e) {}

        // 7. NSMutableURLRequest Cookie header
        @try {
            Class reqClass = objc_getClass("NSMutableURLRequest");
            if (reqClass) {
                Method svM = class_getInstanceMethod(reqClass, @selector(setValue:forHTTPHeaderField:));
                if (svM) {
                    IMP orig = method_getImplementation(svM);
                    IMP imp = imp_implementationWithBlock(^void(id s, NSString *value, NSString *field) {
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
                            ((void (*)(id, SEL, NSString *, NSString *))orig)(s, @selector(setValue:forHTTPHeaderField:), modified, field);
                            return;
                        }
                        ((void (*)(id, SEL, NSString *, NSString *))orig)(s, @selector(setValue:forHTTPHeaderField:), value, field);
                    });
                    class_replaceMethod(reqClass, @selector(setValue:forHTTPHeaderField:), imp, method_getTypeEncoding(svM));
                }
            }
        } @catch (id e) {}

        // 8. NSBundle infoDictionary
        @try {
            Class bundle = objc_getClass("NSBundle");
            if (bundle) {
                Method infoM = class_getInstanceMethod(bundle, @selector(infoDictionary));
                if (infoM) {
                    IMP orig = method_getImplementation(infoM);
                    IMP imp = imp_implementationWithBlock(^NSDictionary *(id s) {
                        NSDictionary *dict = ((NSDictionary *(*)(id, SEL))orig)(s, @selector(infoDictionary));
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
                    class_replaceMethod(bundle, @selector(infoDictionary), imp, method_getTypeEncoding(infoM));
                }
            }
        } @catch (id e) {}

        // 9. WKWebView customUserAgent
        @try {
            Class wkClass = objc_getClass("WKWebView");
            if (wkClass) {
                Method initM = class_getInstanceMethod(wkClass, @selector(initWithFrame:configuration:));
                if (initM) {
                    IMP orig = method_getImplementation(initM);
                    IMP imp = imp_implementationWithBlock(^id(id s, CGRect frame, id config) {
                        id obj = ((id (*)(id, SEL, CGRect, id))orig)(s, @selector(initWithFrame:configuration:), frame, config);
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
                    class_replaceMethod(wkClass, @selector(initWithFrame:configuration:), imp, method_getTypeEncoding(initM));
                }
            }
        } @catch (id e) {}

        // 10. NSJSONSerialization — 拦截服务器返回的更新指令
        @try {
            Class jsonClass = objc_getClass("NSJSONSerialization");
            if (jsonClass) {
                Method jwomM = class_getClassMethod(jsonClass, @selector(JSONObjectWithData:options:error:));
                if (jwomM) {
                    IMP orig = method_getImplementation(jwomM);
                    IMP imp = imp_implementationWithBlock(^id(id cls, NSData *data, NSJSONReadingOptions opts, NSError **err) {
                        id result = ((id (*)(id, SEL, NSData *, NSJSONReadingOptions, NSError **))orig)(cls, @selector(JSONObjectWithData:options:error:), data, opts, err);
                        if (result && [result isKindOfClass:[NSDictionary class]]) {
                            @try {
                                NSMutableDictionary *md = [(NSDictionary *)result mutableCopy];
                                BOOL modified = NO;
                                // 清除更新标记
                                NSArray *updateKeys = @[@"needUpdate", @"forceUpdate", @"mustUpdate",
                                    @"need_update", @"force_update", @"hasUpdate",
                                    @"hasNewVersion", @"isForceUpdate", @"updateType",
                                    @"isNewVersion", @"shouldUpdate", @"requireUpdate",
                                    @"hasLatestVersion", @"upgradeType"];
                                for (NSString *key in updateKeys) {
                                    if (md[key]) {
                                        id val = md[key];
                                        if ([val isKindOfClass:[NSNumber class]] && [val boolValue]) {
                                            md[key] = @NO; modified = YES;
                                        } else if ([val isKindOfClass:[NSString class]] && ![val isEqualToString:@"0"] && ![val isEqualToString:@"false"] && ![val isEqualToString:@"no"]) {
                                            md[key] = @"false"; modified = YES;
                                        }
                                    }
                                }
                                // code/status == 特定值表示需要更新
                                for (NSString *key in @[@"code", @"status", @"resultCode"]) {
                                    id val = md[key];
                                    if (val) {
                                        if ([val isKindOfClass:[NSString class]]) {
                                            int code = [val intValue];
                                            if (code == 3 || code == 1001 || code == 1002 || code == 2001) {
                                                md[key] = @"0"; modified = YES;
                                            }
                                        } else if ([val isKindOfClass:[NSNumber class]]) {
                                            int code = [val intValue];
                                            if (code == 3 || code == 1001 || code == 1002 || code == 2001) {
                                                md[key] = @0; modified = YES;
                                            }
                                        }
                                    }
                                }
                                // 修改 URL 字段（下载链接）
                                if (md[@"downloadUrl"]) { md[@"downloadUrl"] = @""; modified = YES; }
                                if (md[@"updateUrl"]) { md[@"updateUrl"] = @""; modified = YES; }
                                if (md[@"newVersionUrl"]) { md[@"newVersionUrl"] = @""; modified = YES; }
                                // 修改版本号字段
                                if (md[@"latestVersion"]) { md[@"latestVersion"] = @"0.0.0"; modified = YES; }
                                if (md[@"newVersion"]) { md[@"newVersion"] = @"0.0.0"; modified = YES; }
                                if (md[@"serverVersion"]) { md[@"serverVersion"] = @"0.0.0"; modified = YES; }
                                if (md[@"minVersion"]) { md[@"minVersion"] = @"0.0.0"; modified = YES; }
                                if (md[@"version"]) {
                                    id val = md[@"version"];
                                    if ([val isKindOfClass:[NSString class]]) {
                                        NSString *vs = (NSString *)val;
                                        if ([vs length] > 0 && ![vs isEqualToString:@"0"] && ![vs hasPrefix:@"0."]) {
                                            md[@"version"] = @"0"; modified = YES;
                                        }
                                    }
                                }
                                if (modified) return md;
                            } @catch (id e) {}
                        }
                        return result;
                    });
                    class_replaceMethod(jsonClass, @selector(JSONObjectWithData:options:error:), imp, method_getTypeEncoding(jwomM));
                }
            }
        } @catch (id e) {}

        // 11. NSURLSession — 网络层拦截更新 API 响应
        @try {
            Class sessionClass = objc_getClass("NSURLSession");
            if (sessionClass) {
                Method dtwM = class_getInstanceMethod(sessionClass, @selector(dataTaskWithRequest:completionHandler:));
                if (dtwM) {
                    IMP orig = method_getImplementation(dtwM);
                    IMP imp = imp_implementationWithBlock(^id(id s, NSURLRequest *req, void (^completion)(NSData *, NSURLResponse *, NSError *)) {
                        // 包装 completion handler 来修改响应数据
                        void (^wrappedCompletion)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *response, NSError *error) {
                            if (data && response && !error) {
                                // 检查是否是更新相关的 API
                                NSURL *url = req.URL;
                                NSString *urlStr = url ? url.absoluteString : @"";
                                NSString *lowerUrl = urlStr.lowercaseString;
                                BOOL isUpdateAPI = ([lowerUrl containsString:@"upgrade"] ||
                                                    [lowerUrl containsString:@"update"] ||
                                                    [lowerUrl containsString:@"version"] ||
                                                    [lowerUrl containsString:@"bounce"] ||
                                                    [lowerUrl containsString:@"check"] ||
                                                    [lowerUrl containsString:@"config"] ||
                                                    [lowerUrl containsString:@"init"]);
                                if (isUpdateAPI) {
                                    // 尝试修改 JSON 响应
                                    @try {
                                        id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                                        if (json && [json isKindOfClass:[NSDictionary class]]) {
                                            NSMutableDictionary *md = [(NSDictionary *)json mutableCopy];
                                            NSArray *updateKeys = @[@"needUpdate", @"forceUpdate", @"mustUpdate",
                                                @"hasUpdate", @"hasNewVersion", @"isForceUpdate",
                                                @"shouldUpdate", @"requireUpdate", @"isNewVersion",
                                                @"upgrade", @"updateType", @"upgradeType"];
                                            for (NSString *key in updateKeys) {
                                                if (md[key]) md[key] = @NO;
                                            }
                                            for (NSString *key in @[@"code", @"status", @"resultCode"]) {
                                                id val = md[key];
                                                if (val) {
                                                    int code = [val isKindOfClass:[NSString class]] ? [(NSString *)val intValue] : [val intValue];
                                                    if (code != 0 && code != 200 && code != 1) {
                                                        md[key] = @0;
                                                    }
                                                }
                                            }
                                            if (md[@"downloadUrl"]) md[@"downloadUrl"] = @"";
                                            if (md[@"updateUrl"]) md[@"updateUrl"] = @"";
                                            if (md[@"newVersionUrl"]) md[@"newVersionUrl"] = @"";
                                            if (md[@"latestVersion"]) md[@"latestVersion"] = @"0.0.0";
                                            if (md[@"newVersion"]) md[@"newVersion"] = @"0.0.0";
                                            if (md[@"serverVersion"]) md[@"serverVersion"] = @"0.0.0";
                                            NSData *modifiedData = [NSJSONSerialization dataWithJSONObject:md options:0 error:nil];
                                            if (modifiedData) data = modifiedData;
                                        }
                                    } @catch (id e) {}
                                }
                            }
                            if (completion) completion(data, response, error);
                        };
                        return ((id (*)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *)))orig)(s, @selector(dataTaskWithRequest:completionHandler:), req, wrappedCompletion);
                    });
                    class_replaceMethod(sessionClass, @selector(dataTaskWithRequest:completionHandler:), imp, method_getTypeEncoding(dtwM));
                }
            }
        } @catch (id e) {}

        // 12. UIViewController — 拦截更新弹窗
        @try {
            Method vam = class_getInstanceMethod(objc_getClass("UIViewController"), @selector(viewDidAppear:));
            if (vam) {
                IMP orig = method_getImplementation(vam);
                IMP imp = imp_implementationWithBlock(^void(id s, BOOL animated) {
                    ((void (*)(id, SEL, BOOL))orig)(s, @selector(viewDidAppear:), animated);
                    // 检测并关闭更新弹窗
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                        @try {
                            // 检查 view 上的所有子视图，找更新弹窗
                            UIView *view = [s valueForKey:@"view"];
                            if (!view) return;
                            // 递归搜索按钮文字
                            void (^findButtons)(UIView *) = ^(UIView *v) {
                                if ([v isKindOfClass:[UIButton class]]) {
                                    UIButton *btn = (UIButton *)v;
                                    NSString *title = [btn titleForState:UIControlStateNormal];
                                    if (title) {
                                        NSString *lower = title.lowercaseString;
                                        // 找到"立即更新"按钮，点击"暂不"或关闭弹窗
                                        if ([lower containsString:@"更新"] || [lower containsString:@"升级"]) {
                                            // 寻找同级的"暂不"按钮
                                            UIView *parent = v.superview;
                                            if (parent) {
                                                for (UIView *sibling in parent.subviews) {
                                                    if ([sibling isKindOfClass:[UIButton class]]) {
                                                        UIButton *sibBtn = (UIButton *)sibling;
                                                        NSString *sibTitle = [sibBtn titleForState:UIControlStateNormal];
                                                        if (sibTitle) {
                                                            NSString *sl = sibTitle.lowercaseString;
                                                            if ([sl containsString:@"暂不"] || [sl containsString:@"以后"] ||
                                                                [sl containsString:@"取消"] || [sl containsString:@"关闭"] ||
                                                                [sl containsString:@"cancel"]) {
                                                                [sibBtn sendActionsForControlEvents:UIControlEventTouchUpInside];
                                                                return;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            // 没找到取消按钮，直接 dismiss
                                            [s dismissViewControllerAnimated:YES completion:nil];
                                        }
                                    }
                                }
                                for (UIView *sub in v.subviews) {
                                    findButtons(sub);
                                }
                            };
                            findButtons(view);
                        } @catch (id e) {}
                    });
                });
                class_replaceMethod(objc_getClass("UIViewController"), @selector(viewDidAppear:), imp, method_getTypeEncoding(vam));
            }
        } @catch (id e) {}
    }
}
