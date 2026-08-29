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

        // 10. JDUpgradeModule router handlers — 直接拦截更新检测逻辑
        // 遍历所有类，找到包含 routerHandle_JDUpgradeModule_ 前缀方法的类
        @try {
            unsigned int classCount = 0;
            Class *classes = objc_copyClassList(&classCount);
            if (classes) {
                // 需要拦截的方法 SEL 前缀列表
                NSArray *handlerNames = @[
                    @"routerHandle_JDUpgradeModule_requestUpgrade:callback:",
                    @"routerHandle_JDUpgradeModule_requestForceUpgrade:callback:",
                    @"routerHandle_JDUpgradeModule_requestTFUpgrade:callback:",
                    @"routerHandle_JDUpgradeModule_showCommon:callback:",
                    @"routerHandle_JDUpgradeModule_showForce:callback:",
                    @"routerHandle_JDUpgradeModule_showGray:callback:",
                    @"routerHandle_JDUpgradeModule_showTF:callback:",
                    @"routerHandle_JDUpgradeModule_showTFReward:callback:",
                    @"routerHandle_JDUpgradeModule_upgradeInfo:callback:",
                    @"routerHandle_JDUpgradeModule_updateLocalData:callback:",
                    @"routerHandle_JDUpgradeModule_getTFRequestParam:callback:",
                    @"routerHandle_JDUpgradeModule_myJdDisAppear:callback:",
                ];
                for (unsigned int i = 0; i < classCount; i++) {
                    Class cls = classes[i];
                    if (!cls) continue;
                    for (NSString *methodName in handlerNames) {
                        SEL sel = NSSelectorFromString(methodName);
                        Method m = class_getInstanceMethod(cls, sel);
                        if (m) {
                            // 找到了！替换为直接调用 callback(nil)
                            IMP imp = imp_implementationWithBlock(^void(id self, id params, void (^callback)(id)) {
                                if (callback) callback(nil);
                            });
                            class_replaceMethod(cls, sel, imp, method_getTypeEncoding(m));
                        }
                    }
                }
                free(classes);
            }
        } @catch (id e) {}

        // 11. JDUpgradeManager — 拦截单例方法，返回 nil
        @try {
            Class upgradeMgr = objc_getClass("JDUpgradeManager");
            if (upgradeMgr) {
                // 拦截 sharedJDUpgradeManager
                Method sharedM = class_getClassMethod(upgradeMgr, @selector(sharedJDUpgradeManager));
                if (sharedM) {
                    // 不拦截单例本身，但拦截 requestUpgrade:withFinishBlock:
                }
                // 拦截 requestUpgrade:withFinishBlock:
                Method reqM = class_getInstanceMethod(upgradeMgr, @selector(requestUpgrade:withFinishBlock:));
                if (reqM) {
                    IMP imp = imp_implementationWithBlock(^void(id self, id params, void (^finishBlock)(id)) {
                        if (finishBlock) finishBlock(nil);
                    });
                    class_replaceMethod(upgradeMgr, @selector(requestUpgrade:withFinishBlock:), imp, method_getTypeEncoding(reqM));
                }
                // 拦截 requestForceUpgrade
                Method forceM = class_getInstanceMethod(upgradeMgr, @selector(requestForceUpgrade:));
                if (forceM) {
                    IMP imp = imp_implementationWithBlock(^void(id self, id params) {});
                    class_replaceMethod(upgradeMgr, @selector(requestForceUpgrade:), imp, method_getTypeEncoding(forceM));
                }
                // 拦截 requestUpgradeWithParam:completion:
                Method reqParamM = class_getInstanceMethod(upgradeMgr, @selector(requestUpgradeWithParam:completion:));
                if (reqParamM) {
                    IMP imp = imp_implementationWithBlock(^void(id self, id params, void (^completion)(id)) {
                        if (completion) completion(nil);
                    });
                    class_replaceMethod(upgradeMgr, @selector(requestUpgradeWithParam:completion:), imp, method_getTypeEncoding(reqParamM));
                }
                // 拦截 showForceUpgrade:
                Method showForceM = class_getInstanceMethod(upgradeMgr, @selector(showForceUpgrade:));
                if (showForceM) {
                    IMP imp = imp_implementationWithBlock(^void(id self, id params) {});
                    class_replaceMethod(upgradeMgr, @selector(showForceUpgrade:), imp, method_getTypeEncoding(showForceM));
                }
            }
        } @catch (id e) {}

        // 12. JDUpgradeTool — 拦截所有方法
        @try {
            Class upgradeTool = objc_getClass("JDUpgradeTool");
            if (upgradeTool) {
                unsigned int methodCount = 0;
                Method *methods = class_copyMethodList(upgradeTool, &methodCount);
                if (methods) {
                    for (unsigned int i = 0; i < methodCount; i++) {
                        SEL sel = method_getName(methods[i]);
                        NSString *name = NSStringFromSelector(sel);
                        // 拦截所有以 request/show/check 开头的方法
                        if ([name hasPrefix:@"request"] || [name hasPrefix:@"show"] || [name hasPrefix:@"check"]) {
                            IMP imp = imp_implementationWithBlock(^void(id self, id param1, id param2) {});
                            class_replaceMethod(upgradeTool, sel, imp, method_getTypeEncoding(methods[i]));
                        }
                    }
                    free(methods);
                }
            }
        } @catch (id e) {}

    }
}
