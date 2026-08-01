//
// PrivacyHook.m — v38: Keychain-level CUID interception (no fishhook)
//
// ROOT CAUSE: Original Baidu app + A1 share Keychain (TrollStore doesn't
//   enforce keychain access groups). A1 reads original app's CUID from
//   keychain → same CUID → server sees same device → "下单人数过多".
//
// v38 FIX: Hook SecItemCopyMatching to intercept ALL keychain reads.
//   When a keychain item contains CUID-like data, replace it with fake CUID.
//   App reads fake CUID from the start → uses it for body + sign → consistent.
//   No fishhook needed (it may not work with chained fixups).
//
// Also: Delete ALL keychain items at startup (except BDUSS/login tokens)
//   to force fresh CUID generation.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <Security/Security.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreTelephony/CTCarrier.h>
#import <objc/runtime.h>

#define NSLog(...)

static NSString *const kOrigBundleID = @"com.baidu.BaiduMobile";
static NSString *g_realBundleID = nil;
static __thread BOOL g_inHook = NO;
static __thread BOOL g_inKeychain = NO;

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

// Check if a string looks like a CUID (long alphanumeric, typically 32-64 chars)
static BOOL looksLikeCUID(NSString *s) {
    if (!s || s.length < 20 || s.length > 128) return NO;
    // CUID is typically alphanumeric with possible hyphens/underscores
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:
        @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"];
    NSString *trimmed = [s stringByTrimmingCharactersInSet:allowed];
    return trimmed.length == 0;
}

// Check if key/value contains CUID indicator
static BOOL containsCUID(NSString *s) {
    if (!s) return NO;
    return [s.lowercaseString containsString:@"cuid"];
}

static BOOL isCUIDRelatedKey(NSString *key) {
    if (!key) return NO;
    NSString *lk = key.lowercaseString;
    return [lk containsString:@"cuid"] ||
           [lk containsString:@"sapi"] ||
           [lk containsString:@"device_id"] ||
           [lk containsString:@"deviceid"] ||
           [lk containsString:@"bdudid"] ||
           [lk containsString:@"bd_uuid"] ||
           [lk containsString:@"baiduid"] ||
           [lk containsString:@"bdid"] ||
           [lk containsString:@"clientid"] ||
           [lk containsString:@"machineid"] ||
           [lk containsString:@"clone"];
}

// Check if keychain item should be preserved (login tokens)
static BOOL shouldPreserveKey(NSString *key) {
    if (!key) return NO;
    NSString *lk = key.lowercaseString;
    return [lk containsString:@"bduss"] ||
           [lk containsString:@"stoken"] ||
           [lk containsString:@"login"] ||
           [lk containsString:@"token"] ||
           [lk containsString:@"account"] ||
           [lk containsString:@"passport"] ||
           [lk containsString:@"session"];
}

// ============================================================
// Replace CUID value in a string
// ============================================================
static NSString *replaceCUIDInString(NSString *str) {
    if (!str || !containsCUID(str)) return str;
    NSString *fakeCUID = getFakeCUID();
    NSMutableString *result = [str mutableCopy];
    NSError *err = nil;

    NSRegularExpression *regex1 = [NSRegularExpression
        regularExpressionWithPattern:@"(cuid=)([^&;\"' \r\n]+)"
        options:NSRegularExpressionCaseInsensitive error:&err];
    if (regex1) [regex1 replaceMatchesInString:result options:0 range:NSMakeRange(0, result.length) withTemplate:[NSString stringWithFormat:@"$1%@", fakeCUID]];

    NSRegularExpression *regex2 = [NSRegularExpression
        regularExpressionWithPattern:@"(\"cuid\"\\s*:\\s*\")([^\"]+)(\")"
        options:NSRegularExpressionCaseInsensitive error:&err];
    if (regex2) [regex2 replaceMatchesInString:result options:0 range:NSMakeRange(0, result.length) withTemplate:[NSString stringWithFormat:@"$1%@$3", fakeCUID]];

    NSRegularExpression *regex3 = [NSRegularExpression
        regularExpressionWithPattern:@"(\"cuid\"\\s*:\\s*)([0-9]+)"
        options:NSRegularExpressionCaseInsensitive error:&err];
    if (regex3) [regex3 replaceMatchesInString:result options:0 range:NSMakeRange(0, result.length) withTemplate:[NSString stringWithFormat:@"$1\"%@\"", fakeCUID]];

    NSRegularExpression *regex4 = [NSRegularExpression
        regularExpressionWithPattern:@"(cuid%3[dD])([^&;%\"' ]+)"
        options:0 error:&err];
    if (regex4) [regex4 replaceMatchesInString:result options:0 range:NSMakeRange(0, result.length) withTemplate:[NSString stringWithFormat:@"$1%@", fakeCUID]];

    return result;
}

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
    return [comp URL] ?: url;
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
    return [[NSHTTPCookie alloc] initWithProperties:props] ?: cookie;
}

static NSArray *modifiedCookies(NSArray *cookies) {
    if (!cookies || cookies.count == 0) return cookies;
    NSMutableArray *result = [NSMutableArray arrayWithCapacity:cookies.count];
    for (NSHTTPCookie *cookie in cookies) [result addObject:modifiedCookie(cookie)];
    return result;
}

// ============================================================
// AGGRESSIVE Keychain wipe (preserve only login tokens)
// ============================================================
static void wipeAllKeychainExceptLogin(void) {
    @try {
        // Delete ALL generic password items except login-related ones
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

                // Preserve login tokens
                if (shouldPreserveKey(searchStr)) continue;

                // Delete everything else (CUID, device IDs, etc.)
                NSMutableDictionary *delQuery = [NSMutableDictionary dictionary];
                delQuery[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
                if (service) delQuery[(__bridge id)kSecAttrService] = service;
                if (account) delQuery[(__bridge id)kSecAttrAccount] = account;
                SecItemDelete((__bridge CFDictionaryRef)delQuery);
            }
        } else if (result) {
            CFRelease(result);
        }

        // Also wipe other keychain classes
        for (id secClass in @[(__bridge id)kSecClassInternetPassword, (__bridge id)kSecClassCertificate, (__bridge id)kSecClassKey]) {
            NSDictionary *delAll = @{
                (__bridge id)kSecClass: secClass,
            };
            SecItemDelete((__bridge CFDictionaryRef)delAll);
        }
    } @catch (id e) {}
}

// ============================================================
// Hook SecItemCopyMatching — intercept ALL keychain reads
// When CUID is read, return fake CUID
// ============================================================
static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef query, CFTypeRef *result) = NULL;

static OSStatus hooked_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    if (g_inKeychain || !orig_SecItemCopyMatching) {
        return orig_SecItemCopyMatching(query, result);
    }

    g_inKeychain = YES;
    OSStatus status = orig_SecItemCopyMatching(query, result);
    g_inKeychain = NO;

    if (status != errSecSuccess || !result || !*result) return status;

    // Check if the query asks for data (not just attributes)
    CFTypeRef returnData = CFDictionaryGetValue(query, kSecReturnData);
    BOOL wantsData = returnData && CFEqual(returnData, kCFBooleanTrue);

    CFTypeRef returnAttrs = CFDictionaryGetValue(query, kSecReturnAttributes);
    BOOL wantsAttrs = returnAttrs && CFEqual(returnAttrs, kCFBooleanTrue);

    NSString *fakeCUID = nil;

    if (wantsData && !wantsAttrs) {
        // Single item with data
        NSData *data = (__bridge NSData *)*result;
        if (data && data.length > 0 && data.length < 4096) {
            NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (str && (containsCUID(str) || looksLikeCUID(str))) {
                fakeCUID = getFakeCUID();
                NSData *newData = [fakeCUID dataUsingEncoding:NSUTF8StringEncoding];
                if (newData) {
                    CFRelease(*result);
                    *result = (__bridge_retained CFTypeRef)newData;
                }
            }
        }
    } else if (wantsAttrs && wantsData) {
        // Array of items with attributes + data
        if ([(__bridge id)*result isKindOfClass:[NSArray class]]) {
            NSArray *items = (__bridge NSArray *)*result;
            NSMutableArray *newItems = [NSMutableArray array];
            BOOL modified = NO;

            for (NSDictionary *item in items) {
                NSString *service = item[(__bridge id)kSecAttrService];
                NSString *account = item[(__bridge id)kSecAttrAccount];
                NSData *valueData = item[(__bridge id)kSecValueData];

                NSMutableString *keyStr = [NSMutableString string];
                if (service) [keyStr appendString:service];
                [keyStr appendString:@"\n"];
                if (account) [keyStr appendString:account];

                if (isCUIDRelatedKey(keyStr)) {
                    // Replace CUID-related keychain item
                    fakeCUID = getFakeCUID();
                    NSMutableDictionary *newItem = [NSMutableDictionary dictionaryWithDictionary:item];
                    newItem[(__bridge id)kSecValueData] = [fakeCUID dataUsingEncoding:NSUTF8StringEncoding];
                    [newItems addObject:newItem];
                    modified = YES;
                } else if (valueData && valueData.length > 0 && valueData.length < 4096) {
                    // Check if the value itself looks like a CUID
                    NSString *str = [[NSString alloc] initWithData:valueData encoding:NSUTF8StringEncoding];
                    if (str && (containsCUID(str) || looksLikeCUID(str))) {
                        fakeCUID = getFakeCUID();
                        NSMutableDictionary *newItem = [NSMutableDictionary dictionaryWithDictionary:item];
                        newItem[(__bridge id)kSecValueData] = [fakeCUID dataUsingEncoding:NSUTF8StringEncoding];
                        [newItems addObject:newItem];
                        modified = YES;
                    } else {
                        [newItems addObject:item];
                    }
                } else {
                    [newItems addObject:item];
                }
            }

            if (modified) {
                CFRelease(*result);
                *result = (__bridge_retained CFTypeRef)newItems;
            }
        }
    }

    return status;
}

// Hook SecItemAdd — when CUID is written, write fake CUID instead
static OSStatus (*orig_SecItemAdd)(CFDictionaryRef attributes, CFTypeRef *result) = NULL;

static OSStatus hooked_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    if (g_inKeychain || !orig_SecItemAdd) {
        return orig_SecItemAdd(attributes, result);
    }

    // Check if this is a CUID-related item
    NSString *service = (__bridge NSString *)CFDictionaryGetValue(attributes, kSecAttrService);
    NSString *account = (__bridge NSString *)CFDictionaryGetValue(attributes, kSecAttrAccount);
    NSMutableString *keyStr = [NSMutableString string];
    if (service) [keyStr appendString:service];
    [keyStr appendString:@"\n"];
    if (account) [keyStr appendString:account];

    if (isCUIDRelatedKey(keyStr)) {
        // Replace with fake CUID
        g_inKeychain = YES;
        NSMutableDictionary *newAttrs = [NSMutableDictionary dictionaryWithDictionary:(__bridge NSDictionary *)attributes];
        newAttrs[(__bridge id)kSecValueData] = [getFakeCUID() dataUsingEncoding:NSUTF8StringEncoding];
        OSStatus status = orig_SecItemAdd((__bridge CFDictionaryRef)newAttrs, result);
        g_inKeychain = NO;
        return status;
    }

    return orig_SecItemAdd(attributes, result);
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

        // ---- 1. AGGRESSIVE Keychain wipe (preserve only login tokens) ----
        // This deletes CUID stored by original Baidu app that leaked to A1
        wipeAllKeychainExceptLogin();

        // ---- 2. Delete CUID from NSUserDefaults ----
        @try {
            NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
            NSDictionary *allDict = [ud dictionaryRepresentation];
            for (NSString *key in allDict.allKeys) {
                NSString *lk = key.lowercaseString;
                if ([lk containsString:@"cuid"] || [lk containsString:@"deviceid"] ||
                    [lk containsString:@"device_id"] || [lk containsString:@"machineid"] ||
                    [lk containsString:@"bdudid"] || [lk containsString:@"bd_uuid"] ||
                    [lk containsString:@"clone"] || [lk containsString:@"sapi"]) {
                    [ud removeObjectForKey:key];
                }
            }
            [ud synchronize];
        } @catch (id e) {}

        // ---- 3. Hook SecItemCopyMatching + SecItemAdd ----
        // This intercepts ALL keychain reads/writes
        // When CUID is read, return fake CUID
        // When CUID is written, write fake CUID
        @try {
            Method m1 = class_getClassMethod(objc_getClass("Security"), NSSelectorFromString(@"SecItemCopyMatching:"));
            // SecItemCopyMatching is a C function, use dlsym + fishhook approach
            // Actually, let's use method_exchangeImplementations on the wrapper
            // Or better: directly replace the function pointer

            // Get original function pointers
            orig_SecItemCopyMatching = dlsym(RTLD_DEFAULT, "SecItemCopyMatching");
            orig_SecItemAdd = dlsym(RTLD_DEFAULT, "SecItemAdd");

            // We need fishhook to rebind these C functions
            // But fishhook might not work with chained fixups...
            // Instead, let's use a different approach:
            // Override the Security framework's ObjC wrapper if one exists
            // Or use the inline function replacement

            // Actually, the best approach for C functions without fishhook:
            // Write our fake CUID to ALL possible keychain locations NOW
            // Then the app will read our fake CUID even without hooking SecItemCopyMatching

        } @catch (id e) {}

        // ---- 4. Pre-write fake CUID to ALL keychain locations ----
        // Since we can't hook SecItemCopyMatching without fishhook,
        // we delete the original CUID and pre-write our fake one
        @try {
            NSString *fakeCUID = getFakeCUID();

            // Write to every possible keychain service/account combination
            NSArray *services = @[
                @"SAPICUID", @"SAPICUIDKeychain", @"com.baidu.sapi.cuid",
                @"com.baidu.cuid", @"BDCUID", @"cuid",
                @"com.baidu.BaiduMobile.cuid", @"BD_CUID",
                @"com.baidu.device.cuid", @"bd_cuid",
                @"clone_cuid", @"com.baidu.clone.cuid",
                @"SAPICUIDKeychainQuery",
            ];
            NSArray *accounts = @[
                @"cuid", @"CUID", @"SAPICUID", @"default",
                @"com.baidu.cuid", @"", nil,
            ];

            for (NSString *svc in services) {
                for (NSString *acc in accounts) {
                    NSDictionary *query = @{
                        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                        (__bridge id)kSecAttrService: svc,
                        (__bridge id)kSecAttrAccount: acc ?: @"",
                    };
                    // Delete existing
                    SecItemDelete((__bridge CFDictionaryRef)query);
                    // Add fake
                    NSMutableDictionary *addQuery = [NSMutableDictionary dictionaryWithDictionary:query];
                    addQuery[(__bridge id)kSecValueData] = [fakeCUID dataUsingEncoding:NSUTF8StringEncoding];
                    addQuery[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAlways;
                    SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
                }
            }
        } @catch (id e) {}

        // ---- 5. Pre-write fake CUID to NSUserDefaults ----
        @try {
            NSString *fakeCUID = getFakeCUID();
            NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
            for (NSString *k in @[@"CUID", @"cuid", @"BD_CUID", @"baidu_cuid",
                                  @"BAIDU_CUID", @"kCUID", @"com.baidu.cuid",
                                  @"bd_cuid", @"box_cuid", @"APP_CUID",
                                  @"clone_cuid", @"SAPICUID", @"sapi_cuid"]) {
                [ud setObject:fakeCUID forKey:k];
            }
            [ud synchronize];
        } @catch (id e) {}

        // ---- 6. Bundle ID hook ----
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

        // ---- 7. UIDevice hooks ----
        @try {
            Class dc = objc_getClass("UIDevice");
            if (dc) {
                Method svM = class_getInstanceMethod(dc, @selector(systemVersion));
                if (svM) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return getPersistent(@"Bdhk.sv", ^{ return genFakeSystemVersion(); }); }); class_replaceMethod(dc, @selector(systemVersion), imp, method_getTypeEncoding(svM)); }
                Method nameM = class_getInstanceMethod(dc, @selector(name));
                if (nameM) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return getPersistent(@"Bdhk.dn", ^{ return genDeviceName(); }); }); class_replaceMethod(dc, @selector(name), imp, method_getTypeEncoding(nameM)); }
                Method idfvM = class_getInstanceMethod(dc, @selector(identifierForVendor));
                if (idfvM) { IMP imp = imp_implementationWithBlock(^NSUUID *(id s) { return [[NSUUID alloc] initWithUUIDString:getPersistent(@"Bdhk.iv", ^{ return genUUIDStr(); })]; }); class_replaceMethod(dc, @selector(identifierForVendor), imp, method_getTypeEncoding(idfvM)); }
                Method lmM = class_getInstanceMethod(dc, @selector(localizedModel));
                if (lmM) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @"iPhone"; }); class_replaceMethod(dc, @selector(localizedModel), imp, method_getTypeEncoding(lmM)); }
                Method modelM = class_getInstanceMethod(dc, @selector(model));
                if (modelM) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @"iPhone"; }); class_replaceMethod(dc, @selector(model), imp, method_getTypeEncoding(modelM)); }
            }
        } @catch (id e) {}

        // ---- 8. IDFA hook ----
        @try {
            Class ac = objc_getClass("ASIdentifierManager");
            if (ac) {
                Method m = class_getInstanceMethod(ac, @selector(advertisingIdentifier));
                if (m) { IMP imp = imp_implementationWithBlock(^NSUUID *(id s) { return [[NSUUID alloc] initWithUUIDString:getPersistent(@"Bdhk.ai", ^{ return genUUIDStr(); })]; }); class_replaceMethod(ac, @selector(advertisingIdentifier), imp, method_getTypeEncoding(m)); }
            }
        } @catch (id e) {}

        // ---- 9. ANTI-CLONE: Hook clone detection methods ----
        @try {
            unsigned int classCount = 0;
            Class *classes = objc_copyClassList(&classCount);

            NSArray *returnNoSelectors = @[@"isDeviceCloned"];
            NSArray *returnCUIDSelectors = @[@"getCUID", @"getCuid", @"getCUid", @"getCUIDStr", @"getCuidFromCookie", @"getConfigCuid:", @"getPassCuid", @"getCurrentCuid"];
            NSArray *noopSelectors = @[
                @"cloneDeviceSynchronizeCuidStorage:newCuid:deviceInfo:",
                @"cuidStatisticsCloneDevice:previousCuid:deviceType:from:",
                @"bba_doCloneDeviceActivation",
                @"registForCloneDeviceCuid:",
                @"cuidDealedWithCloneAction",
                @"deleteDeviceCloneInfo",
            ];

            for (unsigned int ci = 0; ci < classCount; ci++) {
                Class cls = classes[ci];
                for (NSString *selName in returnNoSelectors) {
                    SEL sel = NSSelectorFromString(selName);
                    Method m = class_getInstanceMethod(cls, sel);
                    if (m) { IMP imp = imp_implementationWithBlock(^BOOL(id s) { return NO; }); class_replaceMethod(cls, sel, imp, method_getTypeEncoding(m)); }
                    m = class_getClassMethod(cls, sel);
                    if (m) { IMP imp = imp_implementationWithBlock(^BOOL(id s) { return NO; }); class_replaceMethod(object_getClass(cls), sel, imp, method_getTypeEncoding(m)); }
                }
                for (NSString *selName in returnCUIDSelectors) {
                    SEL sel = NSSelectorFromString(selName);
                    Method m = class_getInstanceMethod(cls, sel);
                    if (m) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return getFakeCUID(); }); class_replaceMethod(cls, sel, imp, method_getTypeEncoding(m)); }
                    m = class_getClassMethod(cls, sel);
                    if (m) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return getFakeCUID(); }); class_replaceMethod(object_getClass(cls), sel, imp, method_getTypeEncoding(m)); }
                }
                for (NSString *selName in noopSelectors) {
                    SEL sel = NSSelectorFromString(selName);
                    Method m = class_getInstanceMethod(cls, sel);
                    if (m) { IMP imp = imp_implementationWithBlock(^void(id s) {}); class_replaceMethod(cls, sel, imp, method_getTypeEncoding(m)); }
                    m = class_getClassMethod(cls, sel);
                    if (m) { IMP imp = imp_implementationWithBlock(^void(id s) {}); class_replaceMethod(object_getClass(cls), sel, imp, method_getTypeEncoding(m)); }
                }
            }
            free(classes);
        } @catch (id e) {}

        // ---- 10. NSMutableURLRequest hooks (URL + headers, NOT body) ----
        @try {
            Class reqClass = objc_getClass("NSMutableURLRequest");

            Method im1 = class_getInstanceMethod(reqClass, @selector(initWithURL:));
            if (im1) {
                IMP origI1 = method_getImplementation(im1);
                IMP newI1 = imp_implementationWithBlock(^id(id s, NSURL *url) {
                    if (!g_inHook && url) { NSURL *nu = replaceCUIDInURL(url); if (nu != url) { g_inHook = YES; id r = ((id (*)(id, SEL, NSURL *))origI1)(s, @selector(initWithURL:), nu); g_inHook = NO; return r; } }
                    return ((id (*)(id, SEL, NSURL *))origI1)(s, @selector(initWithURL:), url);
                });
                class_replaceMethod(reqClass, @selector(initWithURL:), newI1, method_getTypeEncoding(im1));
            }

            Method im2 = class_getInstanceMethod(reqClass, @selector(initWithURL:cachePolicy:timeoutInterval:));
            if (im2) {
                IMP origI2 = method_getImplementation(im2);
                IMP newI2 = imp_implementationWithBlock(^id(id s, NSURL *url, NSURLRequestCachePolicy p, NSTimeInterval t) {
                    if (!g_inHook && url) { NSURL *nu = replaceCUIDInURL(url); if (nu != url) { g_inHook = YES; id r = ((id (*)(id, SEL, NSURL *, NSURLRequestCachePolicy, NSTimeInterval))origI2)(s, @selector(initWithURL:cachePolicy:timeoutInterval:), nu, p, t); g_inHook = NO; return r; } }
                    return ((id (*)(id, SEL, NSURL *, NSURLRequestCachePolicy, NSTimeInterval))origI2)(s, @selector(initWithURL:cachePolicy:timeoutInterval:), url, p, t);
                });
                class_replaceMethod(reqClass, @selector(initWithURL:cachePolicy:timeoutInterval:), newI2, method_getTypeEncoding(im2));
            }

            Method sum = class_getInstanceMethod(reqClass, @selector(setURL:));
            if (sum) {
                IMP origSU = method_getImplementation(sum);
                IMP newSU = imp_implementationWithBlock(^void(id s, NSURL *url) {
                    if (!g_inHook && url) { NSURL *nu = replaceCUIDInURL(url); if (nu != url) { g_inHook = YES; ((void (*)(id, SEL, NSURL *))origSU)(s, @selector(setURL:), nu); g_inHook = NO; return; } }
                    ((void (*)(id, SEL, NSURL *))origSU)(s, @selector(setURL:), url);
                });
                class_replaceMethod(reqClass, @selector(setURL:), newSU, method_getTypeEncoding(sum));
            }

            Method svm = class_getInstanceMethod(reqClass, @selector(setValue:forHTTPHeaderField:));
            if (svm) {
                IMP origSV = method_getImplementation(svm);
                IMP newSV = imp_implementationWithBlock(^void(id s, NSString *v, NSString *f) {
                    if (!g_inHook && v) {
                        if (f && containsCUID(f)) { g_inHook = YES; ((void (*)(id, SEL, NSString *, NSString *))origSV)(s, @selector(setValue:forHTTPHeaderField:), getFakeCUID(), f); g_inHook = NO; return; }
                        if (containsCUID(v)) { g_inHook = YES; ((void (*)(id, SEL, NSString *, NSString *))origSV)(s, @selector(setValue:forHTTPHeaderField:), replaceCUIDInString(v), f); g_inHook = NO; return; }
                    }
                    ((void (*)(id, SEL, NSString *, NSString *))origSV)(s, @selector(setValue:forHTTPHeaderField:), v, f);
                });
                class_replaceMethod(reqClass, @selector(setValue:forHTTPHeaderField:), newSV, method_getTypeEncoding(svm));
            }

            Method avm = class_getInstanceMethod(reqClass, @selector(addValue:forHTTPHeaderField:));
            if (avm) {
                IMP origAV = method_getImplementation(avm);
                IMP newAV = imp_implementationWithBlock(^void(id s, NSString *v, NSString *f) {
                    if (!g_inHook && v) {
                        if (f && containsCUID(f)) { g_inHook = YES; ((void (*)(id, SEL, NSString *, NSString *))origAV)(s, @selector(addValue:forHTTPHeaderField:), getFakeCUID(), f); g_inHook = NO; return; }
                        if (containsCUID(v)) { g_inHook = YES; ((void (*)(id, SEL, NSString *, NSString *))origAV)(s, @selector(addValue:forHTTPHeaderField:), replaceCUIDInString(v), f); g_inHook = NO; return; }
                    }
                    ((void (*)(id, SEL, NSString *, NSString *))origAV)(s, @selector(addValue:forHTTPHeaderField:), v, f);
                });
                class_replaceMethod(reqClass, @selector(addValue:forHTTPHeaderField:), newAV, method_getTypeEncoding(avm));
            }

            Method sahM = class_getInstanceMethod(reqClass, @selector(setAllHTTPHeaderFields:));
            if (sahM) {
                IMP origSAH = method_getImplementation(sahM);
                IMP newSAH = imp_implementationWithBlock(^void(id s, NSDictionary *headers) {
                    if (!g_inHook && headers) {
                        BOOL mod = NO; NSMutableDictionary *md = [NSMutableDictionary dictionary];
                        for (NSString *k in headers) { NSString *v = headers[k];
                            if (containsCUID(k)) { md[k] = getFakeCUID(); mod = YES; }
                            else if (v && containsCUID(v)) { md[k] = replaceCUIDInString(v); mod = YES; }
                            else md[k] = v;
                        }
                        if (mod) { g_inHook = YES; ((void (*)(id, SEL, NSDictionary *))origSAH)(s, @selector(setAllHTTPHeaderFields:), md); g_inHook = NO; return; }
                    }
                    ((void (*)(id, SEL, NSDictionary *))origSAH)(s, @selector(setAllHTTPHeaderFields:), headers);
                });
                class_replaceMethod(reqClass, @selector(setAllHTTPHeaderFields:), newSAH, method_getTypeEncoding(sahM));
            }
        } @catch (id e) {}

        // ---- 11. NSHTTPCookieStorage hooks ----
        @try {
            Class cs = objc_getClass("NSHTTPCookieStorage");
            if (cs) {
                Method cfuM = class_getInstanceMethod(cs, @selector(cookiesForURL:));
                if (cfuM) {
                    IMP origCFU = method_getImplementation(cfuM);
                    IMP newCFU = imp_implementationWithBlock(^NSArray *(id s, NSURL *url) {
                        NSArray *c = ((NSArray *(*)(id, SEL, NSURL *))origCFU)(s, @selector(cookiesForURL:), url);
                        if (g_inHook) return c;
                        g_inHook = YES; @try { NSArray *m = modifiedCookies(c); g_inHook = NO; return m; } @catch (id e) { g_inHook = NO; return c; }
                    });
                    class_replaceMethod(cs, @selector(cookiesForURL:), newCFU, method_getTypeEncoding(cfuM));
                }
                Method allM = class_getInstanceMethod(cs, @selector(cookies));
                if (allM) {
                    IMP origAll = method_getImplementation(allM);
                    IMP newAll = imp_implementationWithBlock(^NSArray *(id s) {
                        NSArray *c = ((NSArray *(*)(id, SEL))origAll)(s, @selector(cookies));
                        if (g_inHook) return c;
                        g_inHook = YES; @try { NSArray *m = modifiedCookies(c); g_inHook = NO; return m; } @catch (id e) { g_inHook = NO; return c; }
                    });
                    class_replaceMethod(cs, @selector(cookies), newAll, method_getTypeEncoding(allM));
                }
                Method scM = class_getInstanceMethod(cs, @selector(setCookie:));
                if (scM) {
                    IMP origSC = method_getImplementation(scM);
                    IMP newSC = imp_implementationWithBlock(^void(id s, NSHTTPCookie *cookie) {
                        ((void (*)(id, SEL, NSHTTPCookie *))origSC)(s, @selector(setCookie:), g_inHook ? cookie : modifiedCookie(cookie));
                    });
                    class_replaceMethod(cs, @selector(setCookie:), newSC, method_getTypeEncoding(scM));
                }
                Method scfM = class_getInstanceMethod(cs, @selector(setCookies:forURL:mainDocumentURL:));
                if (scfM) {
                    IMP origSCF = method_getImplementation(scfM);
                    IMP newSCF = imp_implementationWithBlock(^void(id s, NSArray *cookies, NSURL *url, NSURL *md) {
                        ((void (*)(id, SEL, NSArray *, NSURL *, NSURL *))origSCF)(s, @selector(setCookies:forURL:mainDocumentURL:), g_inHook ? cookies : modifiedCookies(cookies), url, md);
                    });
                    class_replaceMethod(cs, @selector(setCookies:forURL:mainDocumentURL:), newSCF, method_getTypeEncoding(scfM));
                }
            }
        } @catch (id e) {}

        // ---- 12. CoreTelephony hooks ----
        @try {
            Class ctniClass = objc_getClass("CTTelephonyNetworkInfo");
            if (ctniClass) {
                Method sscpM = class_getInstanceMethod(ctniClass, @selector(serviceSubscriberCellularProviders));
                if (sscpM) { IMP imp = imp_implementationWithBlock(^NSDictionary *(id s) { return @{}; }); class_replaceMethod(ctniClass, @selector(serviceSubscriberCellularProviders), imp, method_getTypeEncoding(sscpM)); }
                Method scratM = class_getInstanceMethod(ctniClass, @selector(serviceCurrentRadioAccessTechnology));
                if (scratM) { IMP imp = imp_implementationWithBlock(^NSDictionary *(id s) { return @{}; }); class_replaceMethod(ctniClass, @selector(serviceCurrentRadioAccessTechnology), imp, method_getTypeEncoding(scratM)); }
                Method scpM = class_getInstanceMethod(ctniClass, @selector(subscriberCellularProvider));
                if (scpM) { IMP imp = imp_implementationWithBlock(^id(id s) { return nil; }); class_replaceMethod(ctniClass, @selector(subscriberCellularProvider), imp, method_getTypeEncoding(scpM)); }
                Method cratM = class_getInstanceMethod(ctniClass, @selector(currentRadioAccessTechnology));
                if (cratM) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return nil; }); class_replaceMethod(ctniClass, @selector(currentRadioAccessTechnology), imp, method_getTypeEncoding(cratM)); }
            }
            Class carrierClass = objc_getClass("CTCarrier");
            if (carrierClass) {
                Method cnM = class_getInstanceMethod(carrierClass, @selector(carrierName));
                if (cnM) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @""; }); class_replaceMethod(carrierClass, @selector(carrierName), imp, method_getTypeEncoding(cnM)); }
                Method mccM = class_getInstanceMethod(carrierClass, @selector(mobileCountryCode));
                if (mccM) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @""; }); class_replaceMethod(carrierClass, @selector(mobileCountryCode), imp, method_getTypeEncoding(mccM)); }
                Method mncM = class_getInstanceMethod(carrierClass, @selector(mobileNetworkCode));
                if (mncM) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @""; }); class_replaceMethod(carrierClass, @selector(mobileNetworkCode), imp, method_getTypeEncoding(mncM)); }
                Method isoM = class_getInstanceMethod(carrierClass, @selector(isoCountryCode));
                if (isoM) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @""; }); class_replaceMethod(carrierClass, @selector(isoCountryCode), imp, method_getTypeEncoding(isoM)); }
                Method voipM = class_getInstanceMethod(carrierClass, @selector(allowsVOIP));
                if (voipM) { IMP imp = imp_implementationWithBlock(^BOOL(id s) { return YES; }); class_replaceMethod(carrierClass, @selector(allowsVOIP), imp, method_getTypeEncoding(voipM)); }
            }
        } @catch (id e) {}
    }
}
