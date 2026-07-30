//
// PrivacyHook.m — Device fingerprint spoofing + Bundle ID + NSURLProtocol
// Hooks: UIDevice (name, identifierForVendor), ASIdentifierManager (IDFA),
//        Keychain clear, NSURLProtocol (network-level cookie/param replacement)
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <Security/Security.h>
#import <objc/runtime.h>

#define NSLog(...)

// ============================================================
// Persistent fake IDs — one set per clone, stored in NSUserDefaults
// ============================================================
static NSString *getPersistent(NSString *key, NSString *(^gen)(void)) {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    NSString *v = [d stringForKey:key];
    if (v) return v;
    v = gen();
    [d setObject:v forKey:key];
    [d synchronize];
    return v;
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

static NSString *genFakeCookie(NSString *name) {
    NSString *cuidCS = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    NSString *hexCS = @"0123456789abcdef";
    if ([name hasPrefix:@"BAIDUCUID"] || [name isEqualToString:@"MAWEBCUID"] || [name isEqualToString:@"cuid"])
        return genRandStr(arc4random_uniform(7) + 58, cuidCS);
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
    return getPersistent([NSString stringWithFormat:@"BaiduBox.cfg.ck.%@", name], ^NSString *{
        return genFakeCookie(name);
    });
}

// ============================================================
// Keychain clear — remove cached device tokens
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
// Cookie header replacement
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

// ============================================================
// URL query param replacement
// ============================================================
static NSURL *replaceDeviceParamsInURL(NSURL *url) {
    if (!url) return url;
    NSURLComponents *comp = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    if (!comp) return url;
    NSArray *items = comp.queryItems;
    if (!items || items.count == 0) return url;

    BOOL modified = NO;
    NSMutableArray *newItems = [NSMutableArray array];
    for (NSURLQueryItem *item in items) {
        if ([item.name isEqualToString:@"cuid"] || [item.name hasPrefix:@"cuid_"] ||
            [item.name isEqualToString:@"cfrom"] || [item.name isEqualToString:@"c3_aid"] ||
            [item.name isEqualToString:@"idfa"] || [item.name isEqualToString:@"idfv"]) {
            NSString *fakeVal = [item.name isEqualToString:@"idfa"] ? getPersistent(@"fake.idfa", genUUIDStr)
                          : [item.name isEqualToString:@"idfv"] ? getPersistent(@"fake.idfv", genUUIDStr)
                          : getFakeID(@"cuid");
            [newItems addObject:[NSURLQueryItem queryItemWithName:item.name value:fakeVal]];
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

// ============================================================
// POST body replacement
// ============================================================
static NSData *replaceDeviceParamsInBody(NSData *body, NSString *contentType) {
    if (!body || body.length == 0) return body;

    if ([contentType containsString:@"json"]) {
        NSError *err = nil;
        NSMutableDictionary *json = [NSJSONSerialization JSONObjectWithData:body
            options:NSJSONReadingMutableContainers error:&err];
        if (err || !json || ![json isKindOfClass:[NSDictionary class]]) return body;

        BOOL modified = NO;
        NSArray *deviceKeys = @[@"cuid", @"cuid_galaxy2", @"cuid_gid", @"cfrom", @"c3_aid",
                                @"idfa", @"idfv", @"device_id", @"udid"];
        for (NSString *key in [json allKeys]) {
            if ([deviceKeys containsObject:key] || [key hasPrefix:@"cuid"]) {
                NSString *fakeVal = [key isEqualToString:@"idfa"] ? getPersistent(@"fake.idfa", genUUIDStr)
                              : [key isEqualToString:@"idfv"] ? getPersistent(@"fake.idfv", genUUIDStr)
                              : getFakeID(@"cuid");
                json[key] = fakeVal;
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
        NSArray *deviceKeys = @[@"cuid", @"cfrom", @"c3_aid", @"idfa", @"idfv"];
        for (NSString *pair in pairs) {
            NSRange eqRange = [pair rangeOfString:@"="];
            if (eqRange.location == NSNotFound) { [newPairs addObject:pair]; continue; }
            NSString *name = [pair substringToIndex:eqRange.location];
            if ([deviceKeys containsObject:name] || [name hasPrefix:@"cuid"]) {
                NSString *fakeVal = [name isEqualToString:@"idfa"] ? getPersistent(@"fake.idfa", genUUIDStr)
                              : [name isEqualToString:@"idfv"] ? getPersistent(@"fake.idfv", genUUIDStr)
                              : getFakeID(@"cuid");
                [newPairs addObject:[NSString stringWithFormat:@"%@=%@", name, fakeVal]];
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

// ============================================================
// NSURLProtocol — intercept baidu HTTP requests
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
    NSString *m = [request valueForHTTPHeaderField:kMarker];
    return ![m isEqualToString:@"1"];
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    NSMutableURLRequest *req = [self.request mutableCopy];
    [req setValue:@"1" forHTTPHeaderField:kMarker];

    // 1. Cookie header
    NSString *cookie = [req valueForHTTPHeaderField:@"Cookie"];
    if (cookie && cookie.length > 0)
        [req setValue:replaceDeviceCookiesInString(cookie) forHTTPHeaderField:@"Cookie"];

    // 2. URL query params
    NSURL *newURL = replaceDeviceParamsInURL(req.URL);
    if (newURL && ![newURL isEqual:req.URL])
        [req setURL:newURL];

    // 3. POST body
    NSString *ct = [req valueForHTTPHeaderField:@"Content-Type"];
    NSData *body = req.HTTPBody;
    if (body) {
        NSData *newBody = replaceDeviceParamsInBody(body, ct);
        if (newBody && ![newBody isEqual:body])
            [req setHTTPBody:newBody];
    }

    NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
    config.protocolClasses = @[];

    __weak typeof(self) ws = self;
    _task = [[NSURLSession sessionWithConfiguration:config] dataTaskWithRequest:req
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            __strong typeof(ws) ss = ws;
            if (!ss) return;
            if (error) {
                [ss.client URLProtocol:ss didFailWithError:error];
            } else {
                [ss.client URLProtocol:ss didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
                [ss.client URLProtocol:ss didLoadData:data];
                [ss.client URLProtocolDidFinishLoading:ss];
            }
        }];
    [_task resume];
}

- (void)stopLoading {
    [_task cancel];
    _task = nil;
}

@end

// ============================================================
// Constructor — install all hooks
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {

        // ---- 1. Bundle ID hook ----
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

        // ---- 2. UIDevice name hook ----
        Class deviceClass = objc_getClass("UIDevice");
        if (deviceClass) {
            // name → fake device name
            Method nameM = class_getInstanceMethod(deviceClass, @selector(name));
            if (nameM) {
                IMP nameImp = imp_implementationWithBlock(^NSString *(id s) {
                    return getPersistent(@"fake.devname", ^NSString *{ return genDeviceName(); });
                });
                class_replaceMethod(deviceClass, @selector(name), nameImp, method_getTypeEncoding(nameM));
            }

            // identifierForVendor → fake NSUUID
            Method idfvM = class_getInstanceMethod(deviceClass, @selector(identifierForVendor));
            if (idfvM) {
                IMP idfvOrig = method_getImplementation(idfvM);
                IMP idfvImp = imp_implementationWithBlock(^NSUUID *(id s) {
                    NSString *uuidStr = getPersistent(@"fake.idfv", ^NSString *{ return genUUIDStr(); });
                    return [[NSUUID alloc] initWithUUIDString:uuidStr];
                });
                class_replaceMethod(deviceClass, @selector(identifierForVendor), idfvImp, method_getTypeEncoding(idfvM));
            }
        }

        // ---- 3. ASIdentifierManager IDFA hook ----
        Class asidClass = objc_getClass("ASIdentifierManager");
        if (asidClass) {
            Method idfaM = class_getInstanceMethod(asidClass, @selector(advertisingIdentifier));
            if (idfaM) {
                IMP idfaImp = imp_implementationWithBlock(^NSUUID *(id s) {
                    NSString *uuidStr = getPersistent(@"fake.idfa", ^NSString *{ return genUUIDStr(); });
                    return [[NSUUID alloc] initWithUUIDString:uuidStr];
                });
                class_replaceMethod(asidClass, @selector(advertisingIdentifier), idfaImp, method_getTypeEncoding(idfaM));
            }
        }

        // ---- 4. Keychain clear (first launch only) ----
        NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
        if (![ud boolForKey:@"keychain.cleared"]) {
            clearKeychain();
            [ud setBool:YES forKey:@"keychain.cleared"];
            [ud synchronize];
        }

        // ---- 5. Register NSURLProtocol ----
        [NSURLProtocol registerClass:[BaiduDeviceProtocol class]];
    }
}
