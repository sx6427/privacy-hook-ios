//
// PrivacyHook.m — Device fingerprint spoofing v2
// Key fix: hook NSURLSessionConfiguration.protocolClasses so ALL sessions
// use our NSURLProtocol (Baidu uses custom sessions, not default)
// + purge device IDs from NSUserDefaults on launch
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <Security/Security.h>
#import <objc/runtime.h>

#define NSLog(...)

static BOOL g_inHook = NO;

// ============================================================
// Persistent fake IDs — uses CFPreferences to avoid recursion
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
        NSString *num = [NSString stringWithFormat:@"%lu", (unsigned long)(arc4random_uniform(9000000000000000ULL) + 1000000000000000ULL)];
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
// Keychain clear
// ============================================================
static void clearKeychain(void) {
    NSArray *classes = @[(__bridge id)kSecClassGenericPassword, (__bridge id)kSecClassInternetPassword,
                         (__bridge id)kSecClassCertificate, (__bridge id)kSecClassKey, (__bridge id)kSecClassIdentity];
    for (id cls in classes) { SecItemDelete((__bridge CFDictionaryRef)@{(__bridge id)kSecClass: cls}); }
}

// ============================================================
// Purge ALL device IDs from NSUserDefaults on launch
// ============================================================
static void purgeDeviceIDs(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSDictionary *all = [ud dictionaryRepresentation];

    // Broad matching: any key containing these substrings
    NSArray *patterns = @[@"cuid", @"dvif", @"tcuid", @"bid_n", @"fuid",
                          @"device", @"udid", @"bdudid", @"baiduid", @"bdid",
                          @"idfa", @"idfv", @"imei", @"serial", @"mac",
                          @"android_id", @"uuid", @"guid"];

    for (NSString *key in [all allKeys]) {
        NSString *lk = [key lowercaseString];
        // Skip our own keys
        if ([lk hasPrefix:@"bdhk"]) continue;
        // Skip system keys
        if ([lk hasPrefix:@"apple"] || [lk hasPrefix:@"ak"] || [lk hasPrefix:@"ns"] || [lk hasPrefix:@"ui"]) continue;

        for (NSString *p in patterns) {
            if ([lk containsString:p]) {
                [ud removeObjectForKey:key];
                break;
            }
        }
    }
    [ud synchronize];
}

// ============================================================
// Network request modification
// ============================================================
static NSString *replaceDeviceCookiesInString(NSString *cookie) {
    NSArray *names = @[@"BAIDUCUID", @"BAIDUCUID_BFESS", @"MAWEBCUID", @"DVIF", @"tcuid", @"__bid_n", @"fuid"];
    NSString *modified = cookie;
    for (NSString *name in names) {
        NSString *fake = getFakeID(name);
        NSRegularExpression *regex = [NSRegularExpression
            regularExpressionWithPattern:[NSString stringWithFormat:@"%@=[^;]+", name]
            options:NSRegularExpressionCaseInsensitive error:nil];
        modified = [regex stringByReplacingMatchesInString:modified options:0
            range:NSMakeRange(0, modified.length)
            withTemplate:[NSString stringWithFormat:@"%@=%@", name, fake]];
    }
    // standalone cuid=
    NSRegularExpression *cuidRegex = [NSRegularExpression
        regularExpressionWithPattern:@"(?<![A-Za-z_])cuid=[^;]+" options:0 error:nil];
    modified = [cuidRegex stringByReplacingMatchesInString:modified options:0
        range:NSMakeRange(0, modified.length)
        withTemplate:[NSString stringWithFormat:@"cuid=%@", getFakeID(@"cuid")]];
    return modified;
}

static NSURL *replaceDeviceParamsInURL(NSURL *url) {
    if (!url) return url;
    NSURLComponents *comp = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    if (!comp) return url;
    NSArray *items = comp.queryItems;
    if (!items || items.count == 0) return url;

    BOOL modified = NO;
    NSMutableArray *newItems = [NSMutableArray array];
    for (NSURLQueryItem *item in items) {
        NSString *n = item.name.lowercaseString;
        if ([n isEqualToString:@"cuid"] || [n hasPrefix:@"cuid_"] ||
            [n isEqualToString:@"cfrom"] || [n isEqualToString:@"c3_aid"]) {
            [newItems addObject:[NSURLQueryItem queryItemWithName:item.name value:getFakeID(@"cuid")]];
            modified = YES;
        } else { [newItems addObject:item]; }
    }
    if (modified) { comp.queryItems = newItems; return comp.URL ?: url; }
    return url;
}

static NSData *replaceDeviceParamsInBody(NSData *body, NSString *contentType) {
    if (!body || body.length == 0) return body;

    if ([contentType containsString:@"json"]) {
        NSError *err = nil;
        NSMutableDictionary *json = [NSJSONSerialization JSONObjectWithData:body
            options:NSJSONReadingMutableContainers error:&err];
        if (err || !json || ![json isKindOfClass:[NSDictionary class]]) return body;

        BOOL modified = NO;
        for (NSString *key in [json allKeys]) {
            NSString *lk = key.lowercaseString;
            if ([lk isEqualToString:@"cuid"] || [lk hasPrefix:@"cuid"] ||
                [lk isEqualToString:@"cfrom"] || [lk isEqualToString:@"c3_aid"]) {
                json[key] = getFakeID(@"cuid"); modified = YES;
            }
        }
        if (modified) return [NSJSONSerialization dataWithJSONObject:json options:0 error:nil] ?: body;
    } else {
        NSString *bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
        if (!bodyStr) return body;
        NSArray *pairs = [bodyStr componentsSeparatedByString:@"&"];
        NSMutableArray *newPairs = [NSMutableArray array];
        BOOL modified = NO;
        for (NSString *pair in pairs) {
            NSRange eq = [pair rangeOfString:@"="];
            if (eq.location == NSNotFound) { [newPairs addObject:pair]; continue; }
            NSString *name = [pair substringToIndex:eq.location];
            NSString *lk = name.lowercaseString;
            if ([lk isEqualToString:@"cuid"] || [lk hasPrefix:@"cuid"] ||
                [lk isEqualToString:@"cfrom"] || [lk isEqualToString:@"c3_aid"]) {
                [newPairs addObject:[NSString stringWithFormat:@"%@=%@", name, getFakeID(@"cuid")]];
                modified = YES;
            } else { [newPairs addObject:pair]; }
        }
        if (modified) return [[newPairs componentsJoinedByString:@"&"] dataUsingEncoding:NSUTF8StringEncoding];
    }
    return body;
}

static NSMutableURLRequest *modifiedRequest(NSURLRequest *req) {
    NSMutableURLRequest *m = [req mutableCopy];
    NSString *cookie = [m valueForHTTPHeaderField:@"Cookie"];
    if (cookie.length > 0)
        [m setValue:replaceDeviceCookiesInString(cookie) forHTTPHeaderField:@"Cookie"];
    NSURL *newURL = replaceDeviceParamsInURL(m.URL);
    if (newURL && ![newURL isEqual:m.URL]) [m setURL:newURL];
    NSData *body = m.HTTPBody;
    if (body) {
        NSString *ct = [m valueForHTTPHeaderField:@"Content-Type"];
        NSData *newBody = replaceDeviceParamsInBody(body, ct);
        if (newBody && ![newBody isEqual:body]) [m setHTTPBody:newBody];
    }
    return m;
}

// ============================================================
// NSURLProtocol
// ============================================================
static NSString *const kMarker = @"X-Bdhk-Int";

@interface BdhkProtocol : NSURLProtocol @end

@implementation BdhkProtocol { NSURLSessionDataTask *_task; }

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    NSString *host = request.URL.host;
    if (!host) return NO;
    // Broader host matching
    if (![host containsString:@"baidu"] && ![host containsString:@"bdstatic"] &&
        ![host containsString:@"bdimg"] && ![host containsString:@"baidustatic"] &&
        ![host containsString:@"hao123"]) return NO;
    return ![[request valueForHTTPHeaderField:kMarker] isEqualToString:@"1"];
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }

- (void)startLoading {
    NSMutableURLRequest *req = modifiedRequest(self.request);
    [req setValue:@"1" forHTTPHeaderField:kMarker];
    NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
    config.protocolClasses = @[];
    __weak typeof(self) ws = self;
    _task = [[NSURLSession sessionWithConfiguration:config] dataTaskWithRequest:req
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            __strong typeof(ws) ss = ws;
            if (!ss) return;
            if (error) [ss.client URLProtocol:ss didFailWithError:error];
            else {
                [ss.client URLProtocol:ss didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
                [ss.client URLProtocol:ss didLoadData:data];
                [ss.client URLProtocolDidFinishLoading:ss];
            }
        }];
    [_task resume];
}

- (void)stopLoading { [_task cancel]; _task = nil; }
@end

// ============================================================
// NSUserDefaults device key matching (broad)
// ============================================================
static BOOL isDeviceKey(NSString *key) {
    if (!key || g_inHook) return NO;
    NSString *lk = [key lowercaseString];
    if ([lk hasPrefix:@"bdhk"]) return NO;  // skip our own keys
    if ([lk hasPrefix:@"apple"] || [lk hasPrefix:@"ak"] || [lk hasPrefix:@"ns"] || [lk hasPrefix:@"ui"]) return NO;

    NSArray *patterns = @[@"cuid", @"dvif", @"tcuid", @"bid_n", @"fuid",
                          @"device", @"udid", @"bdudid", @"baiduid", @"bdid",
                          @"idfa", @"idfv", @"imei", @"serial"];
    for (NSString *p in patterns) {
        if ([lk containsString:p]) return YES;
    }
    return NO;
}

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {

        // ---- 1. Purge device IDs from NSUserDefaults ----
        @try { purgeDeviceIDs(); } @catch (id e) {}

        // ---- 2. Keychain clear (first launch) ----
        @try {
            CFPropertyListRef cleared = CFPreferencesCopyAppValue(CFSTR("Bdhk.kc"), kCFPreferencesCurrentApplication);
            if (!cleared) {
                clearKeychain();
                CFPreferencesSetAppValue(CFSTR("Bdhk.kc"), kCFBooleanTrue, kCFPreferencesCurrentApplication);
                CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
            } else { CFRelease(cleared); }
        } @catch (id e) {}

        // ---- 3. Bundle ID hook ----
        @try {
            Class bc = objc_getClass("NSBundle");
            if (bc) {
                Method m = class_getInstanceMethod(bc, @selector(bundleIdentifier));
                if (m) {
                    IMP orig = method_getImplementation(m);
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        if ([s isEqual:[NSBundle mainBundle]]) return @"com.baidu.BaiduMobile";
                        return ((NSString *(*)(id, SEL))orig)(s, @selector(bundleIdentifier));
                    });
                    class_replaceMethod(bc, @selector(bundleIdentifier), imp, method_getTypeEncoding(m));
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

        // ---- 5. ASIdentifierManager IDFA hook ----
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

        // ---- 6. NSUserDefaults hooks (with recursion guard) ----
        @try {
            Class uc = objc_getClass("NSUserDefaults");
            if (uc) {
                Method ofkM = class_getInstanceMethod(uc, @selector(objectForKey:));
                if (ofkM) {
                    IMP orig = method_getImplementation(ofkM);
                    IMP imp = imp_implementationWithBlock(^id(id s, NSString *key) {
                        if (!g_inHook && isDeviceKey(key)) {
                            g_inHook = YES;
                            @try { NSString *f = getFakeID(@"cuid"); g_inHook = NO; return f; }
                            @catch (id e) { g_inHook = NO; }
                        }
                        return ((id (*)(id, SEL, NSString *))orig)(s, @selector(objectForKey:), key);
                    });
                    class_replaceMethod(uc, @selector(objectForKey:), imp, method_getTypeEncoding(ofkM));
                }
                Method sfkM = class_getInstanceMethod(uc, @selector(stringForKey:));
                if (sfkM) {
                    IMP orig = method_getImplementation(sfkM);
                    IMP imp = imp_implementationWithBlock(^NSString *(id s, NSString *key) {
                        if (!g_inHook && isDeviceKey(key)) {
                            g_inHook = YES;
                            @try { NSString *f = getFakeID(@"cuid"); g_inHook = NO; return f; }
                            @catch (id e) { g_inHook = NO; }
                        }
                        return ((NSString *(*)(id, SEL, NSString *))orig)(s, @selector(stringForKey:), key);
                    });
                    class_replaceMethod(uc, @selector(stringForKey:), imp, method_getTypeEncoding(sfkM));
                }
            }
        } @catch (id e) {}

        // ---- 7. CRITICAL: Hook NSURLSessionConfiguration.protocolClasses ----
        // This ensures ALL NSURLSessions (including Baidu's custom ones)
        // use our NSURLProtocol. registerClass: only works for default session.
        @try {
            Class sc = objc_getClass("NSURLSessionConfiguration");
            if (sc) {
                Method pcM = class_getInstanceMethod(sc, @selector(protocolClasses));
                if (pcM) {
                    IMP origPC = method_getImplementation(pcM);
                    IMP newPC = imp_implementationWithBlock(^NSArray *(id s) {
                        NSArray *orig = ((NSArray *(*)(id, SEL))origPC)(s, @selector(protocolClasses));
                        NSMutableArray *arr = [NSMutableArray arrayWithArray:orig ?: @[]];
                        if (![arr containsObject:[BdhkProtocol class]]) {
                            [arr insertObject:[BdhkProtocol class] atIndex:0];
                        }
                        return arr;
                    });
                    class_replaceMethod(sc, @selector(protocolClasses), newPC, method_getTypeEncoding(pcM));
                }
            }
        } @catch (id e) {}

        // ---- 8. Also register globally (backup for default session) ----
        @try { [NSURLProtocol registerClass:[BdhkProtocol class]]; } @catch (id e) {}
    }
}
