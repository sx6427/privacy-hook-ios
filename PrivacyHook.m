//
// PrivacyHook.m — v54: 补上 BAIDUID + 去掉支付 hook，专注设备伪装
//
// v52b/v53c 遗漏：isDeviceCookie 没有 baiduid
//   BAIDUID 是百度最基础设备标识 Cookie（14次出现在二进制中）
//   Cookie 中 BAIDUID 没被替换 → 百度通过 BAIDUID 识别设备 → "还是检测到本机"
//
// v54 修复：
//   1. isDeviceCookie 加入 baiduid
//   2. Cookie 头替换加入 BAIDUID
//   3. 去掉越狱检测 hook（不搞支付 hook）
//   4. 去掉 URL/Body 替换（签名错误）
//   5. 新前缀 Bd54.
//
// 完整 Hook 清单：
//   - Cookie 读写 hook（v6 完整方案，读+写都替换，包含 BAIDUID）
//   - Cookie 头替换（包含 BAIDUID）
//   - 首次清 Cookie + Keychain
//   - IDFV / IDFA / UIDevice name/model/systemVersion hook
//   - NSUserDefaults 设备键 hook
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#define NSLog(...)

static __thread BOOL g_inCookieHook = NO;
static BOOL g_inUDHook = NO;

// ============================================================
// Persistent fake IDs (Bd54. prefix = new identity)
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

// BAIDUID 格式: 类似 "EFGRt5qV2F3x4RtN5uYH6rD7s8m-9n0o" 的字符串
static NSString *genBAIDUID(void) {
    NSString *cs = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    return genRandStr(32, cs);
}

static NSString *genFakeCookie(NSString *name) {
    NSString *cuidCS = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    NSString *hexCS = @"0123456789abcdef";
    if ([name hasPrefix:@"BAIDUCUID"] || [name isEqualToString:@"MAWEBCUID"] || [name isEqualToString:@"cuid"])
        return genCUID();
    if ([name isEqualToString:@"BAIDUID"])
        return genBAIDUID();
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
    return getPersistent([NSString stringWithFormat:@"Bd54.ck.%@", name], ^{ return genFakeCookie(name); });
}

// ============================================================
// Cookie device ID detection (v54: 加入 baiduid)
// ============================================================
static BOOL isDeviceCookie(NSString *cookieName) {
    if (!cookieName) return NO;
    NSString *lk = [cookieName lowercaseString];
    NSArray *names = @[@"baiducuid", @"baiducuid_bfess", @"mawebcuid",
                       @"dvif", @"tcuid", @"__bid_n", @"fuid", @"cuid",
                       @"baiduid"];  // v54: 加入 BAIDUID
    for (NSString *n in names) { if ([lk isEqualToString:n]) return YES; }
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
// NSUserDefaults device key detection
// ============================================================
static BOOL isDeviceKey(NSString *key) {
    if (!key || g_inUDHook) return NO;
    if ([key hasPrefix:@"Bd54"]) return NO;
    NSArray *exactKeys = @[@"cuid", @"CUID", @"cuid_galaxy2", @"cuid_gid", @"cuid_loc",
                           @"BAIDUCUID", @"BAIDUCUID_BFESS", @"MAWEBCUID",
                           @"DVIF", @"tcuid", @"__bid_n", @"fuid",
                           @"bdudid", @"baiduid", @"bdid"];
    for (NSString *k in exactKeys) { if ([key isEqualToString:k]) return YES; }
    if ([key.lowercaseString hasPrefix:@"cuid"]) return YES;
    return NO;
}

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {

        // ---- 1. Clear Cookie + Keychain (FIRST LAUNCH ONLY) ----
        @try {
            CFPropertyListRef cleared = CFPreferencesCopyAppValue(CFSTR("Bd54.reset"), kCFPreferencesCurrentApplication);
            if (!cleared) {
                // 1a. Clear Cookie storage
                NSHTTPCookieStorage *storage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
                NSArray *cookies = [storage cookies];
                for (NSHTTPCookie *cookie in cookies) { [storage deleteCookie:cookie]; }

                // 1b. Clear Keychain (all classes)
                NSArray *classes = @[(__bridge id)kSecClassGenericPassword, (__bridge id)kSecClassInternetPassword,
                                     (__bridge id)kSecClassCertificate, (__bridge id)kSecClassKey, (__bridge id)kSecClassIdentity];
                for (id cls in classes) {
                    SecItemDelete((__bridge CFDictionaryRef)@{(__bridge id)kSecClass: cls});
                }

                CFPreferencesSetAppValue(CFSTR("Bd54.reset"), kCFBooleanTrue, kCFPreferencesCurrentApplication);
                CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
            } else { CFRelease(cleared); }
        } @catch (id e) {}

        // ---- 2. UIDevice hooks (name + IDFV + model + localizedModel + systemVersion) ----
        @try {
            Class dc = objc_getClass("UIDevice");
            if (dc) {
                Method nameM = class_getInstanceMethod(dc, @selector(name));
                if (nameM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return getPersistent(@"Bd54.dn", ^{ return genDeviceName(); });
                    });
                    class_replaceMethod(dc, @selector(name), imp, method_getTypeEncoding(nameM));
                }
                Method idfvM = class_getInstanceMethod(dc, @selector(identifierForVendor));
                if (idfvM) {
                    IMP imp = imp_implementationWithBlock(^NSUUID *(id s) {
                        return [[NSUUID alloc] initWithUUIDString:getPersistent(@"Bd54.iv", ^{ return genUUIDStr(); })];
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
                Method svM = class_getInstanceMethod(dc, @selector(systemVersion));
                if (svM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return getPersistent(@"Bd54.sv", ^{
                            NSArray *versions = @[@"15.5", @"16.0", @"16.5", @"16.7", @"17.0",
                                                  @"17.2", @"17.4", @"17.5", @"17.6", @"18.0"];
                            return versions[arc4random_uniform((uint32_t)versions.count)];
                        });
                    });
                    class_replaceMethod(dc, @selector(systemVersion), imp, method_getTypeEncoding(svM));
                }
            }
        } @catch (id e) {}

        // ---- 3. IDFA hook ----
        @try {
            Class ac = objc_getClass("ASIdentifierManager");
            if (ac) {
                Method m = class_getInstanceMethod(ac, @selector(advertisingIdentifier));
                if (m) {
                    IMP imp = imp_implementationWithBlock(^NSUUID *(id s) {
                        return [[NSUUID alloc] initWithUUIDString:getPersistent(@"Bd54.ai", ^{ return genUUIDStr(); })];
                    });
                    class_replaceMethod(ac, @selector(advertisingIdentifier), imp, method_getTypeEncoding(m));
                }
            }
        } @catch (id e) {}

        // ---- 4. NSUserDefaults hooks (CUID 等设备键) ----
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

        // ---- 5. Cookie hooks (v6 完整方案：读+写都替换) ----
        @try {
            Class cs = objc_getClass("NSHTTPCookieStorage");

            // 5a. 读 hook: cookiesForURL:
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

            // 5b. 读 hook: cookies
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

            // 5c. 写 hook: setCookie:
            Method scM = class_getInstanceMethod(cs, @selector(setCookie:));
            if (scM) {
                IMP origSC = method_getImplementation(scM);
                IMP newSC = imp_implementationWithBlock(^void(id s, NSHTTPCookie *cookie) {
                    if (cookie && isDeviceCookie(cookie.name)) {
                        @try {
                            NSString *fakeValue = getFakeID(cookie.name);
                            NSMutableDictionary *props = [NSMutableDictionary dictionary];
                            props[NSHTTPCookieName] = cookie.name;
                            props[NSHTTPCookieValue] = fakeValue;
                            if (cookie.domain) props[NSHTTPCookieDomain] = cookie.domain;
                            if (cookie.path) props[NSHTTPCookiePath] = cookie.path;
                            if (cookie.expiresDate) props[NSHTTPCookieExpires] = cookie.expiresDate;
                            props[NSHTTPCookieVersion] = @(cookie.version);
                            if (cookie.secure) props[NSHTTPCookieSecure] = @YES;
                            NSHTTPCookie *fakeCookie = [[NSHTTPCookie alloc] initWithProperties:props];
                            if (fakeCookie) {
                                ((void (*)(id, SEL, NSHTTPCookie *))origSC)(s, @selector(setCookie:), fakeCookie);
                                return;
                            }
                        } @catch (id e) {}
                    }
                    ((void (*)(id, SEL, NSHTTPCookie *))origSC)(s, @selector(setCookie:), cookie);
                });
                class_replaceMethod(cs, @selector(setCookie:), newSC, method_getTypeEncoding(scM));
            }

            // 5d. 写 hook: setCookies:forURL:mainDocumentURL:
            Method scsM = class_getInstanceMethod(cs, @selector(setCookies:forURL:mainDocumentURL:));
            if (scsM) {
                IMP origSCS = method_getImplementation(scsM);
                IMP newSCS = imp_implementationWithBlock(^void(id s, NSArray *cookies, NSURL *URL, NSURL *mainDocumentURL) {
                    if (g_inCookieHook) {
                        ((void (*)(id, SEL, NSArray *, NSURL *, NSURL *))origSCS)(s, @selector(setCookies:forURL:mainDocumentURL:), cookies, URL, mainDocumentURL);
                        return;
                    }
                    g_inCookieHook = YES;
                    @try {
                        NSArray *m = modifiedCookies(cookies);
                        g_inCookieHook = NO;
                        ((void (*)(id, SEL, NSArray *, NSURL *, NSURL *))origSCS)(s, @selector(setCookies:forURL:mainDocumentURL:), m, URL, mainDocumentURL);
                        return;
                    } @catch (id e) { g_inCookieHook = NO; }
                    ((void (*)(id, SEL, NSArray *, NSURL *, NSURL *))origSCS)(s, @selector(setCookies:forURL:mainDocumentURL:), cookies, URL, mainDocumentURL);
                });
                class_replaceMethod(cs, @selector(setCookies:forURL:mainDocumentURL:), newSCS, method_getTypeEncoding(scsM));
            }
        } @catch (id e) {}

        // ---- 6. NSMutableURLRequest Cookie header replacement (v54: 加入 BAIDUID) ----
        @try {
            Class reqClass = objc_getClass("NSMutableURLRequest");
            if (reqClass) {
                Method svM = class_getInstanceMethod(reqClass, @selector(setValue:forHTTPHeaderField:));
                if (svM) {
                    IMP origSV = method_getImplementation(svM);
                    IMP newSV = imp_implementationWithBlock(^void(id s, NSString *value, NSString *field) {
                        if (value && field && [field caseInsensitiveCompare:@"Cookie"] == NSOrderedSame) {
                            // v54: 加入 BAIDUID
                            NSArray *names = @[@"BAIDUCUID", @"BAIDUCUID_BFESS", @"MAWEBCUID",
                                               @"DVIF", @"tcuid", @"__bid_n", @"fuid",
                                               @"BAIDUID"];
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
    }
}
