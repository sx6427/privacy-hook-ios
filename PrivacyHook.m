//
// PrivacyHook.m — v53b: 修复 containsDeviceID bug + 越狱检测 hook
//
// v53 致命 bug：containsDeviceID 检查首字符，但 URL 以 'h'(https://) 开头
//   → 首字符 'h' 不在检查列表 → 所有 URL 返回 NO → URL 参数替换完全没生效！
//   → CUID 仍通过 URL 参数以真实值发送 → 服务器检测到本机
//
// v53b 修复：
//   1. 修复 containsDeviceID — 去掉首字符检查，直接全文搜索
//   2. 加越狱检测 hook — dxmpay_isJailbreak → NO，isJailbroken → NO
//   3. 加 initWithURL: hook — 捕获通过 init 设置的 URL
//
// v53b 保留 v53 的：
//   - Cookie 读写 hook（完整方案）
//   - URL 参数 + POST Body 替换（现在真的生效了）
//   - systemVersion hook
//   - 首次清 Cookie + Keychain
//   - IDFV / IDFA / UIDevice name/model hook
//
// 前缀：Bd53b.（全新身份）
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#define NSLog(...)

static __thread BOOL g_inCookieHook = NO;
static __thread BOOL g_inURLHook = NO;
static __thread BOOL g_inBodyHook = NO;
static BOOL g_inUDHook = NO;
static BOOL g_jailbreakHooked = NO; // 标记越狱检测已 hook

// ============================================================
// Persistent fake IDs (Bd53. prefix = new identity)
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
    if ([name isEqualToString:@"bdudid"]) return genRandStr(40, hexCS);
    if ([name isEqualToString:@"device_id"]) return genRandStr(40, hexCS);
    return genRandStr(32, cuidCS);
}

static NSString *getFakeID(NSString *name) {
    return getPersistent([NSString stringWithFormat:@"Bd53b.ck.%@", name], ^{ return genFakeCookie(name); });
}

// ============================================================
// Cookie device ID detection
// ============================================================
static BOOL isDeviceCookie(NSString *cookieName) {
    if (!cookieName) return NO;
    NSString *lk = [cookieName lowercaseString];
    NSArray *names = @[@"baiducuid", @"baiducuid_bfess", @"mawebcuid",
                       @"dvif", @"tcuid", @"__bid_n", @"fuid", @"cuid"];
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
// URL / POST Body device ID replacement (v53 NEW)
// ============================================================

// 检查字符串是否包含设备标识关键词
// v53b 修复：去掉首字符检查（URL 以 https:// 开头，首字符 'h' 不在旧检查列表中）
static BOOL containsDeviceID(NSString *str) {
    if (!str || str.length < 4) return NO;
    return ([str containsString:@"cuid"] || [str containsString:@"CUID"] ||
            [str containsString:@"DVIF"] || [str containsString:@"tcuid"] ||
            [str containsString:@"__bid_n"] || [str containsString:@"fuid"] ||
            [str containsString:@"idfa"] || [str containsString:@"IDFA"] ||
            [str containsString:@"idfv"] || [str containsString:@"IDFV"] ||
            [str containsString:@"device_id"] || [str containsString:@"bdudid"] ||
            [str containsString:@"BAIDUID"]);
}

// 替换字符串中的设备标识
// 适用于 URL 查询参数（cuid=value&...）和 POST Body（JSON 或 form-encoded）
static NSString *replaceDeviceIDsInString(NSString *str) {
    if (!str || str.length == 0) return str;

    NSString *modified = str;

    // 设备标识列表：(正则模式, 假ID名)
    // 注意顺序：先替换长名称（BAIDUCUID_BFESS），再替换短名称（cuid）
    struct { NSString *pattern; NSString *fakeName; } patterns[] = {
        // BAIDUCUID_BFESS (最长，先替换)
        { @"BAIDUCUID_BFESS=[^&;#\"\\\\}\\s]+", @"BAIDUCUID_BFESS" },
        // BAIDUCUID
        { @"BAIDUCUID=[^&;#\"\\\\}\\s]+", @"BAIDUCUID" },
        // MAWEBCUID
        { @"MAWEBCUID=[^&;#\"\\\\}\\s]+", @"MAWEBCUID" },
        // cuid (不匹配 BAIDUCUID/MAWEBCUID 中的 cuid)
        { @"(?<![A-Za-z_])cuid=[^&;#\"\\\\}\\s]+", @"cuid" },
        // DVIF
        { @"(?<![A-Za-z_])DVIF=[^&;#\"\\\\}\\s]+", @"DVIF" },
        // tcuid
        { @"(?<![A-Za-z_])tcuid=[^&;#\"\\\\}\\s]+", @"tcuid" },
        // __bid_n
        { @"__bid_n=[^&;#\"\\\\}\\s]+", @"__bid_n" },
        // fuid
        { @"(?<![A-Za-z_])fuid=[^&;#\"\\\\}\\s]+", @"fuid" },
        // idfa
        { @"(?<![A-Za-z_])idfa=[^&;#\"\\\\}\\s]+", @"idfa" },
        // idfv
        { @"(?<![A-Za-z_])idfv=[^&;#\"\\\\}\\s]+", @"idfv" },
        // device_id
        { @"(?<![A-Za-z_])device_id=[^&;#\"\\\\}\\s]+", @"device_id" },
        // bdudid
        { @"(?<![A-Za-z_])bdudid=[^&;#\"\\\\}\\s]+", @"bdudid" },
    };

    for (int i = 0; i < sizeof(patterns)/sizeof(patterns[0]); i++) {
        NSRegularExpression *regex = [NSRegularExpression
            regularExpressionWithPattern:patterns[i].pattern
            options:NSRegularExpressionCaseInsensitive error:nil];
        NSString *fakeVal = getFakeID(patterns[i].fakeName);
        // 提取参数名（= 前面的部分）
        NSString *paramName = [patterns[i].pattern componentsSeparatedByString:@"="][0];
        // 清理正则特殊字符
        paramName = [paramName stringByReplacingOccurrencesOfString:@"(?<![A-Za-z_])" withString:@""];

        NSString *replacement = [NSString stringWithFormat:@"%@=%@", paramName, fakeVal];
        modified = [regex stringByReplacingMatchesInString:modified
            options:0 range:NSMakeRange(0, modified.length)
            withTemplate:replacement];
    }

    // JSON 格式: "cuid":"value" → "cuid":"fake"
    // 匹配 "key":"value" 模式
    NSArray *jsonKeys = @[@"cuid", @"CUID", @"BAIDUCUID", @"BAIDUCUID_BFESS",
                          @"MAWEBCUID", @"DVIF", @"tcuid", @"__bid_n",
                          @"fuid", @"idfa", @"idfv", @"device_id", @"bdudid"];
    for (NSString *key in jsonKeys) {
        NSString *pattern = [NSString stringWithFormat:@"\"%@\"\\s*:\\s*\"[^\"]*\"", key];
        NSRegularExpression *regex = [NSRegularExpression
            regularExpressionWithPattern:pattern options:0 error:nil];
        NSString *fakeVal = getFakeID(key);
        NSString *replacement = [NSString stringWithFormat:@"\"%@\":\"%@\"", key, fakeVal];
        modified = [regex stringByReplacingMatchesInString:modified
            options:0 range:NSMakeRange(0, modified.length)
            withTemplate:replacement];
    }

    return modified;
}

// 修改 NSURL 中的查询参数
static NSURL *modifiedURL(NSURL *url) {
    if (!url) return url;
    NSString *urlStr = [url absoluteString];
    if (!containsDeviceID(urlStr)) return url;

    NSString *modified = replaceDeviceIDsInString(urlStr);
    if ([modified isEqualToString:urlStr]) return url;

    NSURL *result = [NSURL URLWithString:modified];
    return result ?: url;
}

// 修改 HTTPBody 中的设备标识
static NSData *modifiedBody(NSData *body) {
    if (!body || body.length == 0) return body;
    // 尝试解析为 UTF-8 字符串
    NSString *bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    if (!bodyStr) return body; // 二进制数据，跳过
    if (!containsDeviceID(bodyStr)) return body;

    NSString *modified = replaceDeviceIDsInString(bodyStr);
    if ([modified isEqualToString:bodyStr]) return body;

    NSData *result = [modified dataUsingEncoding:NSUTF8StringEncoding];
    return result ?: body;
}

// ============================================================
// NSUserDefaults device key detection
// ============================================================
static BOOL isDeviceKey(NSString *key) {
    if (!key || g_inUDHook) return NO;
    if ([key hasPrefix:@"Bd53b"]) return NO;
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
            CFPropertyListRef cleared = CFPreferencesCopyAppValue(CFSTR("Bd53b.reset"), kCFPreferencesCurrentApplication);
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

                CFPreferencesSetAppValue(CFSTR("Bd53b.reset"), kCFBooleanTrue, kCFPreferencesCurrentApplication);
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
                        return getPersistent(@"Bd53b.dn", ^{ return genDeviceName(); });
                    });
                    class_replaceMethod(dc, @selector(name), imp, method_getTypeEncoding(nameM));
                }
                Method idfvM = class_getInstanceMethod(dc, @selector(identifierForVendor));
                if (idfvM) {
                    IMP imp = imp_implementationWithBlock(^NSUUID *(id s) {
                        return [[NSUUID alloc] initWithUUIDString:getPersistent(@"Bd53b.iv", ^{ return genUUIDStr(); })];
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
                // v53 NEW: systemVersion hook (OSVS 指纹)
                Method svM = class_getInstanceMethod(dc, @selector(systemVersion));
                if (svM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return getPersistent(@"Bd53b.sv", ^{
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
                        return [[NSUUID alloc] initWithUUIDString:getPersistent(@"Bd53b.ai", ^{ return genUUIDStr(); })];
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

        // ---- 6. NSMutableURLRequest Cookie header + URL + Body replacement ----
        @try {
            Class reqClass = objc_getClass("NSMutableURLRequest");
            if (reqClass) {
                // 6a. Cookie 头替换 (v52b 保留)
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

                // 6b. v53b: URL 查询参数替换 (setter)
                Method setURLM = class_getInstanceMethod(reqClass, @selector(setURL:));
                if (setURLM) {
                    IMP origSetURL = method_getImplementation(setURLM);
                    IMP newSetURL = imp_implementationWithBlock(^void(id s, NSURL *url) {
                        if (g_inURLHook || !url) {
                            ((void (*)(id, SEL, NSURL *))origSetURL)(s, @selector(setURL:), url);
                            return;
                        }
                        g_inURLHook = YES;
                        @try {
                            NSURL *modified = modifiedURL(url);
                            g_inURLHook = NO;
                            ((void (*)(id, SEL, NSURL *))origSetURL)(s, @selector(setURL:), modified);
                            return;
                        } @catch (id e) { g_inURLHook = NO; }
                        ((void (*)(id, SEL, NSURL *))origSetURL)(s, @selector(setURL:), url);
                    });
                    class_replaceMethod(reqClass, @selector(setURL:), newSetURL, method_getTypeEncoding(setURLM));
                }

                // 6b2. v53b NEW: initWithURL: hook — 捕获通过 init 设置的 URL
                SEL initWithURLSel = @selector(initWithURL:);
                Method initURLM = class_getInstanceMethod(reqClass, initWithURLSel);
                if (initURLM) {
                    IMP origInit = method_getImplementation(initURLM);
                    IMP newInit = imp_implementationWithBlock(^id(id s, NSURL *url) {
                        if (g_inURLHook || !url) {
                            return ((id (*)(id, SEL, NSURL *))origInit)(s, initWithURLSel, url);
                        }
                        g_inURLHook = YES;
                        @try {
                            NSURL *modified = modifiedURL(url);
                            g_inURLHook = NO;
                            return ((id (*)(id, SEL, NSURL *))origInit)(s, initWithURLSel, modified);
                        } @catch (id e) { g_inURLHook = NO; }
                        return ((id (*)(id, SEL, NSURL *))origInit)(s, initWithURLSel, url);
                    });
                    class_replaceMethod(reqClass, initWithURLSel, newInit, method_getTypeEncoding(initURLM));
                }

                // 6b3. v53b NEW: initWithURL:cachePolicy:timeoutInterval: hook
                SEL initFullSel = @selector(initWithURL:cachePolicy:timeoutInterval:);
                Method initFullM = class_getInstanceMethod(reqClass, initFullSel);
                if (initFullM) {
                    IMP origInitFull = method_getImplementation(initFullM);
                    IMP newInitFull = imp_implementationWithBlock(^id(id s, NSURL *url, NSURLRequestCachePolicy policy, NSTimeInterval timeout) {
                        if (g_inURLHook || !url) {
                            return ((id (*)(id, SEL, NSURL, NSURLRequestCachePolicy, NSTimeInterval))origInitFull)(s, initFullSel, url, policy, timeout);
                        }
                        g_inURLHook = YES;
                        @try {
                            NSURL *modified = modifiedURL(url);
                            g_inURLHook = NO;
                            return ((id (*)(id, SEL, NSURL, NSURLRequestCachePolicy, NSTimeInterval))origInitFull)(s, initFullSel, modified, policy, timeout);
                        } @catch (id e) { g_inURLHook = NO; }
                        return ((id (*)(id, SEL, NSURL, NSURLRequestCachePolicy, NSTimeInterval))origInitFull)(s, initFullSel, url, policy, timeout);
                    });
                    class_replaceMethod(reqClass, initFullSel, newInitFull, method_getTypeEncoding(initFullM));
                }

                // 6c. v53 NEW: URL getter 替换 (安全网：捕获 initWithURL: 设置的 URL)
                Method urlM = class_getInstanceMethod(reqClass, @selector(URL));
                if (urlM) {
                    IMP origURL = method_getImplementation(urlM);
                    IMP newURL = imp_implementationWithBlock(^NSURL *(id s) {
                        NSURL *url = ((NSURL *(*)(id, SEL))origURL)(s, @selector(URL));
                        if (g_inURLHook || !url) return url;
                        g_inURLHook = YES;
                        @try {
                            NSURL *modified = modifiedURL(url);
                            g_inURLHook = NO;
                            return modified;
                        } @catch (id e) { g_inURLHook = NO; return url; }
                    });
                    class_replaceMethod(reqClass, @selector(URL), newURL, method_getTypeEncoding(urlM));
                }

                // 6d. v53 NEW: POST Body 替换 (setter)
                Method setBodyM = class_getInstanceMethod(reqClass, @selector(setHTTPBody:));
                if (setBodyM) {
                    IMP origSetBody = method_getImplementation(setBodyM);
                    IMP newSetBody = imp_implementationWithBlock(^void(id s, NSData *body) {
                        if (g_inBodyHook || !body) {
                            ((void (*)(id, SEL, NSData *))origSetBody)(s, @selector(setHTTPBody:), body);
                            return;
                        }
                        g_inBodyHook = YES;
                        @try {
                            NSData *modified = modifiedBody(body);
                            g_inBodyHook = NO;
                            ((void (*)(id, SEL, NSData *))origSetBody)(s, @selector(setHTTPBody:), modified);
                            return;
                        } @catch (id e) { g_inBodyHook = NO; }
                        ((void (*)(id, SEL, NSData *))origSetBody)(s, @selector(setHTTPBody:), body);
                    });
                    class_replaceMethod(reqClass, @selector(setHTTPBody:), newSetBody, method_getTypeEncoding(setBodyM));
                }

                // 6e. v53 NEW: POST Body 替换 (getter，安全网)
                Method bodyM = class_getInstanceMethod(reqClass, @selector(HTTPBody));
                if (bodyM) {
                    IMP origBody = method_getImplementation(bodyM);
                    IMP newBody = imp_implementationWithBlock(^NSData *(id s) {
                        NSData *body = ((NSData *(*)(id, SEL))origBody)(s, @selector(HTTPBody));
                        if (g_inBodyHook || !body) return body;
                        g_inBodyHook = YES;
                        @try {
                            NSData *modified = modifiedBody(body);
                            g_inBodyHook = NO;
                            return modified;
                        } @catch (id e) { g_inBodyHook = NO; return body; }
                    });
                    class_replaceMethod(reqClass, @selector(HTTPBody), newBody, method_getTypeEncoding(bodyM));
                }
            }
        } @catch (id e) {}

        // ---- 7. v53b NEW: 越狱检测 hook ----
        // 逆向发现：dxmpay_isJailbreak (支付SDK) + isJailbroken/isJailbreak
        // 百度检测路径: /Applications/Cydia.app /usr/sbin/sshd /bin/bash /private/var/lib/apt/
        // 支付宝SDK检测: MobileSubstrate mobilesubstrate
        @try {
            // 7a. dxmpay_isJailbreak — NSString category 方法
            SEL jbSel = NSSelectorFromString(@"dxmpay_isJailbreak");
            Class nsStr = objc_getClass("NSString");
            if (nsStr) {
                Method jbM = class_getInstanceMethod(nsStr, jbSel);
                if (jbM) {
                    IMP imp = imp_implementationWithBlock(^BOOL(id s) { return NO; });
                    class_replaceMethod(nsStr, jbSel, imp, method_getTypeEncoding(jbM));
                    g_jailbreakHooked = YES;
                }
            }
            // 7b. 通用 isJailbroken / isJailbreak 方法（可能在多个类上）
            for (NSString *clsName in @[@"UIDevice", @"NSBundle", @"NSString"]) {
                Class cls = objc_getClass([clsName UTF8String]);
                if (!cls) continue;
                for (NSString *selName in @[@"isJailbroken", @"isJailbreak", @"isJailBroken"]) {
                    SEL sel = NSSelectorFromString(selName);
                    Method m = class_getInstanceMethod(cls, sel);
                    if (m) {
                        IMP imp = imp_implementationWithBlock(^BOOL(id s) { return NO; });
                        class_replaceMethod(cls, sel, imp, method_getTypeEncoding(m));
                    }
                }
            }
        } @catch (id e) {}
    }
}
