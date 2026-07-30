//
// PrivacyHook.m — Device fingerprint spoofing (crash-free)
// Safe hooks only: Bundle ID + UIDevice + IDFA + NSUserDefaults + NSURLProtocol
// No fishhook, no raw IMP swizzle
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <Security/Security.h>
#import <objc/runtime.h>

#define NSLog(...)

// ============================================================
// Recursion guard — prevent infinite loop in NSUserDefaults hook
// ============================================================
static BOOL g_inHook = NO;

// ============================================================
// Persistent fake IDs — uses raw CFPreferences to avoid recursion
// ============================================================
static NSString *getPersistent(NSString *key, NSString *(^gen)(void)) {
    // Use CFPreferencesCopyAppValue to bypass our NSUserDefaults hook
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

static NSString *genUUIDStr(void) {
    return [[NSUUID UUID] UUIDString];
}

static NSString *genDeviceName(void) {
    NSArray *surnames = @[@"张", @"王", @"李", @"赵", @"刘", @"陈", @"杨", @"黄", @"周", @"吴",
                          @"徐", @"孙", @"马", @"朱", @"胡", @"林", @"郭", @"何", @"高", @"罗"];
    NSArray *models   = @[@"iPhone", @"iPhone 13", @"iPhone 14", @"iPhone 15",
                          @"iPhone 12", @"iPhone 11", @"iPhone SE"];
    NSString *sn = surnames[arc4random_uniform((uint32_t)surnames.count)];
    NSString *md = models[arc4random_uniform((uint32_t)models.count)];
    return [NSString stringWithFormat:@"%@的%@", sn, md];
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
        NSString *num = [NSString stringWithFormat:@"%lu",
            (unsigned long)(arc4random_uniform(9000000000000000ULL) + 1000000000000000ULL)];
        NSMutableData *d = [NSMutableData dataWithLength:300];
        arc4random_buf([d mutableBytes], 300);
        return [NSString stringWithFormat:@"%@_%@_%@", num, [d base64EncodedStringWithOptions:0], genRandStr(6, hexCS)];
    }
    if ([name isEqualToString:@"tcuid"])
        return [genRandStr(40, hexCS).uppercaseString stringByAppendingString:genRandStr(4, @"ABCDEFGHIJ")];
    if ([name isEqualToString:@"__bid_n"]) return genRandStr(22, hexCS);
    if ([name isEqualToString:@"fuid"]) return genRandStr(32, hexCS);
    return genRandStr(32, cuidCS);
}

static NSString *getFakeID(NSString *name) {
    return getPersistent([NSString stringWithFormat:@"Bdhk.ck.%@", name], ^NSString *{
        return genFakeCookie(name);
    });
}

// ============================================================
// Keychain clear
// ============================================================
static void clearKeychain(void) {
    NSArray *classes = @[(__bridge id)kSecClassGenericPassword,
                         (__bridge id)kSecClassInternetPassword,
                         (__bridge id)kSecClassCertificate,
                         (__bridge id)kSecClassKey,
                         (__bridge id)kSecClassIdentity];
    for (id cls in classes) {
        NSDictionary *q = @{(__bridge id)kSecClass: cls};
        SecItemDelete((__bridge CFDictionaryRef)q);
    }
}

// ============================================================
// Network request modification
// ============================================================
static NSString *replaceDeviceCookiesInString(NSString *cookie) {
    NSArray *names = @[@"BAIDUCUID", @"BAIDUCUID_BFESS", @"MAWEBCUID",
                       @"DVIF", @"tcuid", @"__bid_n", @"fuid"];
    NSString *modified = cookie;
    for (NSString *name in names) {
        NSString *fake = getFakeID(name);
        NSString *pattern = [NSString stringWithFormat:@"%@=[^;]+", name];
        NSRegularExpression *regex = [NSRegularExpression
            regularExpressionWithPattern:pattern options:NSRegularExpressionCaseInsensitive error:nil];
        modified = [regex stringByReplacingMatchesInString:modified options:0
            range:NSMakeRange(0, modified.length)
            withTemplate:[NSString stringWithFormat:@"%@=%@", name, fake]];
    }
    NSString *cuidFake = getFakeID(@"cuid");
    NSRegularExpression *cuidRegex = [NSRegularExpression
        regularExpressionWithPattern:@"(?<![A-Za-z_])cuid=[^;]+" options:0 error:nil];
    modified = [cuidRegex stringByReplacingMatchesInString:modified options:0
        range:NSMakeRange(0, modified.length)
        withTemplate:[NSString stringWithFormat:@"cuid=%@", cuidFake]];
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
        } else {
            [newItems addObject:item];
        }
    }
    if (modified) {
        comp.queryItems = newItems;
        return comp.URL ?: url;
    }
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
                json[key] = getFakeID(@"cuid");
                modified = YES;
            }
        }
        if (modified)
            return [NSJSONSerialization dataWithJSONObject:json options:0 error:nil] ?: body;
    } else {
        NSString *bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
        if (!bodyStr) return body;

        NSArray *pairs = [bodyStr componentsSeparatedByString:@"&"];
        NSMutableArray *newPairs = [NSMutableArray array];
        BOOL modified = NO;
        for (NSString *pair in pairs) {
            NSRange eqRange = [pair rangeOfString:@"="];
            if (eqRange.location == NSNotFound) { [newPairs addObject:pair]; continue; }
            NSString *name = [pair substringToIndex:eqRange.location];
            NSString *lk = name.lowercaseString;
            if ([lk isEqualToString:@"cuid"] || [lk hasPrefix:@"cuid"] ||
                [lk isEqualToString:@"cfrom"] || [lk isEqualToString:@"c3_aid"]) {
                [newPairs addObject:[NSString stringWithFormat:@"%@=%@", name, getFakeID(@"cuid")]];
                modified = YES;
            } else {
                [newPairs addObject:pair];
            }
        }
        if (modified) {
            NSString *s = [newPairs componentsJoinedByString:@"&"];
            return [s dataUsingEncoding:NSUTF8StringEncoding];
        }
    }
    return body;
}

static NSMutableURLRequest *modifiedRequest(NSURLRequest *req) {
    NSMutableURLRequest *m = [req mutableCopy];

    NSString *cookie = [m valueForHTTPHeaderField:@"Cookie"];
    if (cookie.length > 0)
        [m setValue:replaceDeviceCookiesInString(cookie) forHTTPHeaderField:@"Cookie"];

    NSURL *newURL = replaceDeviceParamsInURL(m.URL);
    if (newURL && ![newURL isEqual:m.URL])
        [m setURL:newURL];

    NSData *body = m.HTTPBody;
    if (body) {
        NSString *ct = [m valueForHTTPHeaderField:@"Content-Type"];
        NSData *newBody = replaceDeviceParamsInBody(body, ct);
        if (newBody && ![newBody isEqual:body])
            [m setHTTPBody:newBody];
    }
    return m;
}

// ============================================================
// NSURLProtocol
// ============================================================
static NSString *const kMarker = @"X-BaiduIntercept";

@interface BaiduDeviceProtocol : NSURLProtocol
@end

@implementation BaiduDeviceProtocol {
    NSURLSessionDataTask *_task;
}

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    NSString *host = request.URL.host;
    if (!host || ![host containsString:@"baidu"]) return NO;
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
// NSUserDefaults key matching
// ============================================================
static BOOL isDeviceKey(NSString *key) {
    if (!key || g_inHook) return NO;
    NSString *lk = [key lowercaseString];
    // Only match exact baidu device keys, not substrings
    NSArray *exact = @[@"cuid", @"cuid_galaxy2", @"cuid_gid", @"cuid_loc",
                       @"dvif", @"tcuid", @"__bid_n", @"fuid",
                       @"bdudid", @"baiduid", @"device_id",
                       @"baidu_cuid", @"baidubox_cuid",
                       @"com.baidu.cuid"];
    for (NSString *k in exact) {
        if ([lk isEqualToString:k]) return YES;
    }
    // Also match keys that start with "cuid" but not "Bdhk" (our own storage prefix)
    if ([lk hasPrefix:@"cuid"] && ![lk hasPrefix:@"bdhk"]) return YES;
    return NO;
}

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {

        // ---- 1. Bundle ID hook ----
        @try {
            Class bundleClass = objc_getClass("NSBundle");
            if (bundleClass) {
                Method m = class_getInstanceMethod(bundleClass, @selector(bundleIdentifier));
                if (m) {
                    IMP orig = method_getImplementation(m);
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        if ([s isEqual:[NSBundle mainBundle]]) return @"com.baidu.BaiduMobile";
                        return ((NSString *(*)(id, SEL))orig)(s, @selector(bundleIdentifier));
                    });
                    class_replaceMethod(bundleClass, @selector(bundleIdentifier), imp, method_getTypeEncoding(m));
                }
            }
        } @catch (id e) {}

        // ---- 2. UIDevice hooks ----
        @try {
            Class deviceClass = objc_getClass("UIDevice");
            if (deviceClass) {
                Method nameM = class_getInstanceMethod(deviceClass, @selector(name));
                if (nameM) {
                    IMP nameImp = imp_implementationWithBlock(^NSString *(id s) {
                        return getPersistent(@"Bdhk.devname", ^{ return genDeviceName(); });
                    });
                    class_replaceMethod(deviceClass, @selector(name), nameImp, method_getTypeEncoding(nameM));
                }
                Method idfvM = class_getInstanceMethod(deviceClass, @selector(identifierForVendor));
                if (idfvM) {
                    IMP idfvImp = imp_implementationWithBlock(^NSUUID *(id s) {
                        NSString *uuidStr = getPersistent(@"Bdhk.udid", ^{ return genUUIDStr(); });
                        return [[NSUUID alloc] initWithUUIDString:uuidStr];
                    });
                    class_replaceMethod(deviceClass, @selector(identifierForVendor), idfvImp, method_getTypeEncoding(idfvM));
                }
            }
        } @catch (id e) {}

        // ---- 3. ASIdentifierManager IDFA hook ----
        @try {
            Class asidClass = objc_getClass("ASIdentifierManager");
            if (asidClass) {
                Method idfaM = class_getInstanceMethod(asidClass, @selector(advertisingIdentifier));
                if (idfaM) {
                    IMP idfaImp = imp_implementationWithBlock(^NSUUID *(id s) {
                        NSString *uuidStr = getPersistent(@"Bdhk.adid", ^{ return genUUIDStr(); });
                        return [[NSUUID alloc] initWithUUIDString:uuidStr];
                    });
                    class_replaceMethod(asidClass, @selector(advertisingIdentifier), idfaImp, method_getTypeEncoding(idfaM));
                }
            }
        } @catch (id e) {}

        // ---- 4. NSUserDefaults hooks (with recursion guard) ----
        @try {
            Class udClass = objc_getClass("NSUserDefaults");
            if (udClass) {
                // objectForKey:
                Method ofkM = class_getInstanceMethod(udClass, @selector(objectForKey:));
                if (ofkM) {
                    IMP origOfk = method_getImplementation(ofkM);
                    IMP ofkImp = imp_implementationWithBlock(^id(id s, NSString *key) {
                        if (!g_inHook && isDeviceKey(key)) {
                            g_inHook = YES;
                            @try {
                                NSString *fake = getFakeID(@"cuid");
                                g_inHook = NO;
                                return fake;
                            } @catch (id e) {
                                g_inHook = NO;
                            }
                        }
                        return ((id (*)(id, SEL, NSString *))origOfk)(s, @selector(objectForKey:), key);
                    });
                    class_replaceMethod(udClass, @selector(objectForKey:), ofkImp, method_getTypeEncoding(ofkM));
                }
                // stringForKey:
                Method sfkM = class_getInstanceMethod(udClass, @selector(stringForKey:));
                if (sfkM) {
                    IMP origSfk = method_getImplementation(sfkM);
                    IMP sfkImp = imp_implementationWithBlock(^NSString *(id s, NSString *key) {
                        if (!g_inHook && isDeviceKey(key)) {
                            g_inHook = YES;
                            @try {
                                NSString *fake = getFakeID(@"cuid");
                                g_inHook = NO;
                                return fake;
                            } @catch (id e) {
                                g_inHook = NO;
                            }
                        }
                        return ((NSString *(*)(id, SEL, NSString *))origSfk)(s, @selector(stringForKey:), key);
                    });
                    class_replaceMethod(udClass, @selector(stringForKey:), sfkImp, method_getTypeEncoding(sfkM));
                }
            }
        } @catch (id e) {}

        // ---- 5. Keychain clear (first launch only) ----
        @try {
            // Use CFPreferences to check our flag (bypasses NSUserDefaults hook)
            CFPropertyListRef cleared = CFPreferencesCopyAppValue(
                CFSTR("Bdhk.kc"), kCFPreferencesCurrentApplication);
            if (!cleared) {
                clearKeychain();
                CFPreferencesSetAppValue(CFSTR("Bdhk.kc"), kCFBooleanTrue, kCFPreferencesCurrentApplication);
                CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
            } else {
                CFRelease(cleared);
            }
        } @catch (id e) {}

        // ---- 6. NSURLProtocol ----
        @try {
            [NSURLProtocol registerClass:[BaiduDeviceProtocol class]];
        } @catch (id e) {}
    }
}
