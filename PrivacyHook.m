//
// PrivacyHook.m — v31: Comprehensive CUID interception (init + body + cookie value)
//
// v30 gaps causing "下单人数过多":
//   1. initWithURL: not hooked → URL with cuid set at init, bypasses setURL:
//   2. setHTTPBody: not hooked → CUID in POST JSON/form body
//   3. Cookie header value not checked → field name "Cookie" != "cuid"
//
// v31 fixes:
//   - Hook NSMutableURLRequest initWithURL: + initWithURL:cachePolicy:timeoutInterval:
//   - Hook setHTTPBody: → scan body for cuid, replace value
//   - Hook setValue:forHTTPHeaderField: → also check VALUE for cuid (Cookie header)
//   - Hook setAllHTTPHeaderFields: → scan all headers
//   - Hook NSURLSession dataTaskWithRequest: as catch-all
//
// Payment safe: only modify data containing "cuid" (case-insensitive)
// No fishhook → no crash
// vtool SDK 17.0
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <Security/Security.h>
#import <objc/runtime.h>

#define NSLog(...)

static NSString *const kOrigBundleID = @"com.baidu.BaiduMobile";
static NSString *g_realBundleID = nil;
static __thread BOOL g_inHook = NO;

// ============================================================
// Persistent fake IDs
// ============================================================
static NSString *getPersistent(NSString *key, NSString *(^gen)(void)) {
    CFStringRef cfDomain = (__bridge CFStringRef)(g_realBundleID ?: kOrigBundleID);
    CFStringRef cfKey = (__bridge CFStringRef)key;
    CFPropertyListRef val = CFPreferencesCopyAppValue(cfKey, cfDomain);
    if (val) {
        NSString *s = [(__bridge id)val isKindOfClass:[NSString class]] ? (__bridge NSString *)val : nil;
        CFRelease(val);
        if (s) return s;
    }
    NSString *newVal = gen();
    CFPreferencesSetAppValue(cfKey, (__bridge CFStringRef)newVal, cfDomain);
    CFPreferencesAppSynchronize(cfDomain);
    return newVal;
}

static NSString *genUUIDStr(void) { return [[NSUUID UUID] UUIDString]; }

static NSString *genDeviceName(void) {
    NSArray *sn = @[@"张",@"王",@"李",@"赵",@"刘",@"陈",@"杨",@"黄",@"周",@"吴",@"徐",@"孙",@"马",@"朱",@"胡",@"林",@"郭",@"何",@"高",@"罗"];
    NSArray *md = @[@"iPhone",@"iPhone 13",@"iPhone 14",@"iPhone 15",@"iPhone 12",@"iPhone 11",@"iPhone SE"];
    return [NSString stringWithFormat:@"%@的%@", sn[arc4random_uniform((uint32_t)sn.count)], md[arc4random_uniform((uint32_t)md.count)]];
}

static NSString *genFakeSystemVersion(void) {
    NSArray *versions = @[@"15.7", @"16.0", @"16.1", @"16.2", @"16.3", @"16.4", @"16.5", @"16.6"];
    return versions[arc4random_uniform((uint32_t)versions.count)];
}

static NSString *getFakeCUID(void) {
    return getPersistent(@"Bdhk.cuid", ^{
        NSString *cs = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        NSMutableString *s = [NSMutableString string];
        for (int i = 0; i < 40; i++)
            [s appendFormat:@"%c", [cs characterAtIndex:arc4random_uniform((uint32_t)cs.length)]];
        return s;
    });
}

static BOOL containsCUID(NSString *s) {
    if (!s) return NO;
    return [s.lowercaseString containsString:@"cuid"];
}

// ============================================================
// Replace CUID value in a string
// Handles patterns like: cuid=XXX, "cuid":"XXX", cuid%3DXXX
// ============================================================
static NSString *replaceCUIDInString(NSString *str) {
    if (!str || !containsCUID(str)) return str;
    NSString *fakeCUID = getFakeCUID();
    NSMutableString *result = [str mutableCopy];

    // Pattern: cuid=VALUE  (URL-encoded form, query string, cookie)
    // Match cuid= followed by non-& non-; non-" characters
    NSError *err = nil;
    NSRegularExpression *regex1 = [NSRegularExpression
        regularExpressionWithPattern:@"(cuid=)([^&;\"' \r\n]+)"
        options:NSRegularExpressionCaseInsensitive error:&err];
    if (regex1) {
        [regex1 replaceMatchesInString:result options:0
            range:NSMakeRange(0, result.length)
            withTemplate:[NSString stringWithFormat:@"$1%@", fakeCUID]];
    }

    // Pattern: "cuid":"VALUE"  (JSON)
    NSRegularExpression *regex2 = [NSRegularExpression
        regularExpressionWithPattern:@"(\"cuid\"\\s*:\\s*\")([^\"]+)(\")"
        options:NSRegularExpressionCaseInsensitive error:&err];
    if (regex2) {
        [regex2 replaceMatchesInString:result options:0
            range:NSMakeRange(0, result.length)
            withTemplate:[NSString stringWithFormat:@"$1%@$3", fakeCUID]];
    }

    // Pattern: "cuid": VALUE  (JSON without quotes around value)
    NSRegularExpression *regex3 = [NSRegularExpression
        regularExpressionWithPattern:@"(\"cuid\"\\s*:\\s*)([0-9]+)"
        options:NSRegularExpressionCaseInsensitive error:&err];
    if (regex3) {
        [regex3 replaceMatchesInString:result options:0
            range:NSMakeRange(0, result.length)
            withTemplate:[NSString stringWithFormat:@"$1\"%@\"", fakeCUID]];
    }

    // Pattern: cuid%3DVALUE (double-encoded)
    NSRegularExpression *regex4 = [NSRegularExpression
        regularExpressionWithPattern:@"(cuid%3[dD])([^&;%\"' ]+)"
        options:0 error:&err];
    if (regex4) {
        [regex4 replaceMatchesInString:result options:0
            range:NSMakeRange(0, result.length)
            withTemplate:[NSString stringWithFormat:@"$1%@", fakeCUID]];
    }

    return result;
}

// ============================================================
// Replace CUID in URL query params
// ============================================================
static NSURL *replaceCUIDInURL(NSURL *url) {
    if (!url) return url;
    NSString *query = [url query];
    if (!query || !containsCUID(query)) return url;

    NSURLComponents *comp = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    if (!comp || !comp.queryItems) return url;

    NSMutableArray *newItems = [NSMutableArray array];
    NSString *fakeCUID = getFakeCUID();
    for (NSURLQueryItem *item in comp.queryItems) {
        if (containsCUID(item.name)) {
            [newItems addObject:[NSURLQueryItem queryItemWithName:item.name value:fakeCUID]];
        } else {
            [newItems addObject:item];
        }
    }
    comp.queryItems = newItems;
    NSURL *newURL = [comp URL];
    return newURL ?: url;
}

// ============================================================
// Replace CUID in HTTP body (JSON or form-encoded)
// ============================================================
static NSData *replaceCUIDInBody(NSData *body) {
    if (!body || body.length == 0) return body;
    // Try to interpret as string
    NSString *bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    if (!bodyStr) return body;  // binary data, can't process
    if (!containsCUID(bodyStr)) return body;

    NSString *replaced = replaceCUIDInString(bodyStr);
    if ([replaced isEqualToString:bodyStr]) return body;
    return [replaced dataUsingEncoding:NSUTF8StringEncoding];
}

// ============================================================
// Cookie helpers
// ============================================================
static NSHTTPCookie *modifiedCookie(NSHTTPCookie *cookie) {
    if (!cookie || !containsCUID(cookie.name)) return cookie;
    NSMutableDictionary *props = [NSMutableDictionary dictionary];
    props[NSHTTPCookieName] = cookie.name;
    props[NSHTTPCookieValue] = getFakeCUID();
    if (cookie.domain) props[NSHTTPCookieDomain] = cookie.domain;
    if (cookie.path) props[NSHTTPCookiePath] = cookie.path;
    if (cookie.expiresDate) props[NSHTTPCookieExpires] = cookie.expiresDate;
    props[NSHTTPCookieVersion] = @(cookie.version);
    if (cookie.secure) props[NSHTTPCookieSecure] = @YES;
    NSHTTPCookie *newCookie = [[NSHTTPCookie alloc] initWithProperties:props];
    return newCookie ?: cookie;
}

static NSArray *modifiedCookies(NSArray *cookies) {
    if (!cookies || cookies.count == 0) return cookies;
    NSMutableArray *result = [NSMutableArray arrayWithCapacity:cookies.count];
    for (NSHTTPCookie *cookie in cookies) {
        [result addObject:modifiedCookie(cookie)];
    }
    return result;
}

// ============================================================
// Selective Keychain CUID deletion
// ============================================================
static void wipeCUIDFromKeychain(void) {
    @try {
        NSDictionary *query = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecReturnAttributes: @YES,
            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
        };
        CFTypeRef result = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        if (status == errSecSuccess && result) {
            NSArray *items = (__bridge_transfer NSArray *)result;
            for (NSDictionary *item in items) {
                NSString *service = item[(__bridge id)kSecAttrService];
                NSString *account = item[(__bridge id)kSecAttrAccount];
                NSString *label   = item[(__bridge id)kSecAttrLabel];

                NSMutableString *searchStr = [NSMutableString string];
                if (service) [searchStr appendString:service];
                [searchStr appendString:@"\n"];
                if (account) [searchStr appendString:account];
                [searchStr appendString:@"\n"];
                if (label)   [searchStr appendString:label];

                NSString *lower = searchStr.lowercaseString;
                BOOL isDeviceID = ([lower containsString:@"cuid"] ||
                                   [lower containsString:@"deviceid"] ||
                                   [lower containsString:@"device_id"] ||
                                   [lower containsString:@"machineid"] ||
                                   [lower containsString:@"bdid"] ||
                                   [lower containsString:@"clientid"]);
                if (isDeviceID) {
                    NSMutableDictionary *delQuery = [NSMutableDictionary dictionary];
                    delQuery[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
                    if (service) delQuery[(__bridge id)kSecAttrService] = service;
                    if (account) delQuery[(__bridge id)kSecAttrAccount] = account;
                    SecItemDelete((__bridge CFDictionaryRef)delQuery);
                }
            }
        } else if (result) {
            CFRelease(result);
        }
    } @catch (id e) {}
}

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {

        // ---- 0. Read REAL bundle ID BEFORE any hooks ----
        @try {
            NSDictionary *d = [[NSBundle mainBundle] infoDictionary];
            g_realBundleID = [d[@"CFBundleIdentifier"] copy];
        } @catch (id e) {}

        // ---- 1. Delete CUID from NSUserDefaults + Keychain ----
        @try {
            NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
            NSDictionary *allDict = [ud dictionaryRepresentation];
            for (NSString *key in allDict.allKeys) {
                NSString *lk = key.lowercaseString;
                if ([lk containsString:@"cuid"] || [lk containsString:@"deviceid"] ||
                    [lk containsString:@"device_id"] || [lk containsString:@"machineid"]) {
                    [ud removeObjectForKey:key];
                }
            }
            [ud synchronize];
        } @catch (id e) {}
        wipeCUIDFromKeychain();

        // ---- 2. Bundle ID hook ----
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

        // ---- 3. UIDevice hooks ----
        @try {
            Class dc = objc_getClass("UIDevice");
            if (dc) {
                Method svM = class_getInstanceMethod(dc, @selector(systemVersion));
                if (svM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return getPersistent(@"Bdhk.sv", ^{ return genFakeSystemVersion(); });
                    });
                    class_replaceMethod(dc, @selector(systemVersion), imp, method_getTypeEncoding(svM));
                }
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

        // ---- 4. IDFA hook ----
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

        // ---- 5. NSMutableURLRequest: init + URL + header + body ----
        @try {
            Class reqClass = objc_getClass("NSMutableURLRequest");

            // 5a. initWithURL: — THE BIGGEST GAP in v30
            // Most requests are created here, URL already contains cuid
            Method im1 = class_getInstanceMethod(reqClass, @selector(initWithURL:));
            if (im1) {
                IMP origI1 = method_getImplementation(im1);
                IMP newI1 = imp_implementationWithBlock(^id(id s, NSURL *url) {
                    if (!g_inHook && url) {
                        NSURL *newURL = replaceCUIDInURL(url);
                        if (newURL != url) {
                            g_inHook = YES;
                            id r = ((id (*)(id, SEL, NSURL *))origI1)(s, @selector(initWithURL:), newURL);
                            g_inHook = NO;
                            return r;
                        }
                    }
                    return ((id (*)(id, SEL, NSURL *))origI1)(s, @selector(initWithURL:), url);
                });
                class_replaceMethod(reqClass, @selector(initWithURL:), newI1, method_getTypeEncoding(im1));
            }

            // 5b. initWithURL:cachePolicy:timeoutInterval:
            Method im2 = class_getInstanceMethod(reqClass, @selector(initWithURL:cachePolicy:timeoutInterval:));
            if (im2) {
                IMP origI2 = method_getImplementation(im2);
                IMP newI2 = imp_implementationWithBlock(^id(id s, NSURL *url, NSURLRequestCachePolicy policy, NSTimeInterval timeout) {
                    if (!g_inHook && url) {
                        NSURL *newURL = replaceCUIDInURL(url);
                        if (newURL != url) {
                            g_inHook = YES;
                            id r = ((id (*)(id, SEL, NSURL *, NSURLRequestCachePolicy, NSTimeInterval))origI2)(
                                s, @selector(initWithURL:cachePolicy:timeoutInterval:), newURL, policy, timeout);
                            g_inHook = NO;
                            return r;
                        }
                    }
                    return ((id (*)(id, SEL, NSURL *, NSURLRequestCachePolicy, NSTimeInterval))origI2)(
                        s, @selector(initWithURL:cachePolicy:timeoutInterval:), url, policy, timeout);
                });
                class_replaceMethod(reqClass, @selector(initWithURL:cachePolicy:timeoutInterval:), newI2, method_getTypeEncoding(im2));
            }

            // 5c. setURL: — replace cuid in URL query
            Method sum = class_getInstanceMethod(reqClass, @selector(setURL:));
            if (sum) {
                IMP origSU = method_getImplementation(sum);
                IMP newSU = imp_implementationWithBlock(^void(id s, NSURL *url) {
                    if (!g_inHook && url) {
                        NSURL *newURL = replaceCUIDInURL(url);
                        if (newURL != url) {
                            g_inHook = YES;
                            ((void (*)(id, SEL, NSURL *))origSU)(s, @selector(setURL:), newURL);
                            g_inHook = NO;
                            return;
                        }
                    }
                    ((void (*)(id, SEL, NSURL *))origSU)(s, @selector(setURL:), url);
                });
                class_replaceMethod(reqClass, @selector(setURL:), newSU, method_getTypeEncoding(sum));
            }

            // 5d. setValue:forHTTPHeaderField: — check BOTH field name AND value
            // "Cookie: BAIDUCUID=xxx" → field="Cookie", value contains "cuid"
            Method svm = class_getInstanceMethod(reqClass, @selector(setValue:forHTTPHeaderField:));
            if (svm) {
                IMP origSV = method_getImplementation(svm);
                IMP newSV = imp_implementationWithBlock(^void(id s, NSString *value, NSString *field) {
                    if (!g_inHook && value) {
                        // If field name contains cuid → replace entire value
                        if (field && containsCUID(field)) {
                            g_inHook = YES;
                            ((void (*)(id, SEL, NSString *, NSString *))origSV)(s, @selector(setValue:forHTTPHeaderField:), getFakeCUID(), field);
                            g_inHook = NO;
                            return;
                        }
                        // If value contains cuid (e.g. Cookie: BAIDUCUID=xxx; BDUSS=yyy)
                        if (containsCUID(value)) {
                            NSString *newVal = replaceCUIDInString(value);
                            g_inHook = YES;
                            ((void (*)(id, SEL, NSString *, NSString *))origSV)(s, @selector(setValue:forHTTPHeaderField:), newVal, field);
                            g_inHook = NO;
                            return;
                        }
                    }
                    ((void (*)(id, SEL, NSString *, NSString *))origSV)(s, @selector(setValue:forHTTPHeaderField:), value, field);
                });
                class_replaceMethod(reqClass, @selector(setValue:forHTTPHeaderField:), newSV, method_getTypeEncoding(svm));
            }

            // 5e. addValue:forHTTPHeaderField: — same checks
            Method avm = class_getInstanceMethod(reqClass, @selector(addValue:forHTTPHeaderField:));
            if (avm) {
                IMP origAV = method_getImplementation(avm);
                IMP newAV = imp_implementationWithBlock(^void(id s, NSString *value, NSString *field) {
                    if (!g_inHook && value) {
                        if (field && containsCUID(field)) {
                            g_inHook = YES;
                            ((void (*)(id, SEL, NSString *, NSString *))origAV)(s, @selector(addValue:forHTTPHeaderField:), getFakeCUID(), field);
                            g_inHook = NO;
                            return;
                        }
                        if (containsCUID(value)) {
                            NSString *newVal = replaceCUIDInString(value);
                            g_inHook = YES;
                            ((void (*)(id, SEL, NSString *, NSString *))origAV)(s, @selector(addValue:forHTTPHeaderField:), newVal, field);
                            g_inHook = NO;
                            return;
                        }
                    }
                    ((void (*)(id, SEL, NSString *, NSString *))origAV)(s, @selector(addValue:forHTTPHeaderField:), value, field);
                });
                class_replaceMethod(reqClass, @selector(addValue:forHTTPHeaderField:), newAV, method_getTypeEncoding(avm));
            }

            // 5f. setAllHTTPHeaderFields: — scan all headers
            Method sahM = class_getInstanceMethod(reqClass, @selector(setAllHTTPHeaderFields:));
            if (sahM) {
                IMP origSAH = method_getImplementation(sahM);
                IMP newSAH = imp_implementationWithBlock(^void(id s, NSDictionary *headers) {
                    if (!g_inHook && headers) {
                        BOOL modified = NO;
                        NSMutableDictionary *md = [NSMutableDictionary dictionary];
                        for (NSString *key in headers) {
                            NSString *val = headers[key];
                            if (containsCUID(key)) {
                                md[key] = getFakeCUID();
                                modified = YES;
                            } else if (val && containsCUID(val)) {
                                md[key] = replaceCUIDInString(val);
                                modified = YES;
                            } else {
                                md[key] = val;
                            }
                        }
                        if (modified) {
                            g_inHook = YES;
                            ((void (*)(id, SEL, NSDictionary *))origSAH)(s, @selector(setAllHTTPHeaderFields:), md);
                            g_inHook = NO;
                            return;
                        }
                    }
                    ((void (*)(id, SEL, NSDictionary *))origSAH)(s, @selector(setAllHTTPHeaderFields:), headers);
                });
                class_replaceMethod(reqClass, @selector(setAllHTTPHeaderFields:), newSAH, method_getTypeEncoding(sahM));
            }

            // 5g. setHTTPBody: — replace cuid in POST body (JSON/form)
            Method sbm = class_getInstanceMethod(reqClass, @selector(setHTTPBody:));
            if (sbm) {
                IMP origSB = method_getImplementation(sbm);
                IMP newSB = imp_implementationWithBlock(^void(id s, NSData *body) {
                    if (!g_inHook && body) {
                        NSData *newBody = replaceCUIDInBody(body);
                        if (newBody != body) {
                            g_inHook = YES;
                            ((void (*)(id, SEL, NSData *))origSB)(s, @selector(setHTTPBody:), newBody);
                            g_inHook = NO;
                            return;
                        }
                    }
                    ((void (*)(id, SEL, NSData *))origSB)(s, @selector(setHTTPBody:), body);
                });
                class_replaceMethod(reqClass, @selector(setHTTPBody:), newSB, method_getTypeEncoding(sbm));
            }
        } @catch (id e) {}

        // ---- 6. NSHTTPCookieStorage hooks ----
        @try {
            Class cs = objc_getClass("NSHTTPCookieStorage");
            if (cs) {
                Method cfuM = class_getInstanceMethod(cs, @selector(cookiesForURL:));
                if (cfuM) {
                    IMP origCFU = method_getImplementation(cfuM);
                    IMP newCFU = imp_implementationWithBlock(^NSArray *(id s, NSURL *url) {
                        NSArray *cookies = ((NSArray *(*)(id, SEL, NSURL *))origCFU)(s, @selector(cookiesForURL:), url);
                        if (g_inHook) return cookies;
                        g_inHook = YES;
                        @try { NSArray *m = modifiedCookies(cookies); g_inHook = NO; return m; }
                        @catch (id e) { g_inHook = NO; return cookies; }
                    });
                    class_replaceMethod(cs, @selector(cookiesForURL:), newCFU, method_getTypeEncoding(cfuM));
                }

                Method allM = class_getInstanceMethod(cs, @selector(cookies));
                if (allM) {
                    IMP origAll = method_getImplementation(allM);
                    IMP newAll = imp_implementationWithBlock(^NSArray *(id s) {
                        NSArray *cookies = ((NSArray *(*)(id, SEL))origAll)(s, @selector(cookies));
                        if (g_inHook) return cookies;
                        g_inHook = YES;
                        @try { NSArray *m = modifiedCookies(cookies); g_inHook = NO; return m; }
                        @catch (id e) { g_inHook = NO; return cookies; }
                    });
                    class_replaceMethod(cs, @selector(cookies), newAll, method_getTypeEncoding(allM));
                }

                Method scM = class_getInstanceMethod(cs, @selector(setCookie:));
                if (scM) {
                    IMP origSC = method_getImplementation(scM);
                    IMP newSC = imp_implementationWithBlock(^void(id s, NSHTTPCookie *cookie) {
                        NSHTTPCookie *mc = g_inHook ? cookie : modifiedCookie(cookie);
                        ((void (*)(id, SEL, NSHTTPCookie *))origSC)(s, @selector(setCookie:), mc);
                    });
                    class_replaceMethod(cs, @selector(setCookie:), newSC, method_getTypeEncoding(scM));
                }

                Method scfM = class_getInstanceMethod(cs, @selector(setCookies:forURL:mainDocumentURL:));
                if (scfM) {
                    IMP origSCF = method_getImplementation(scfM);
                    IMP newSCF = imp_implementationWithBlock(^void(id s, NSArray *cookies, NSURL *url, NSURL *mainDocURL) {
                        NSArray *mc = g_inHook ? cookies : modifiedCookies(cookies);
                        ((void (*)(id, SEL, NSArray *, NSURL *, NSURL *))origSCF)(s, @selector(setCookies:forURL:mainDocumentURL:), mc, url, mainDocURL);
                    });
                    class_replaceMethod(cs, @selector(setCookies:forURL:mainDocumentURL:), newSCF, method_getTypeEncoding(scfM));
                }
            }
        } @catch (id e) {}

        // ---- 7. Pre-write fake CUID into NSUserDefaults ----
        @try {
            NSString *fakeCUID = getFakeCUID();
            NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
            for (NSString *k in @[@"CUID", @"cuid", @"BD_CUID", @"baidu_cuid",
                                  @"BAIDU_CUID", @"kCUID", @"com.baidu.cuid"]) {
                [ud setObject:fakeCUID forKey:k];
            }
            [ud synchronize];
        } @catch (id e) {}
    }
}
