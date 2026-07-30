//
// PrivacyHook.m — Bundle ID hook + NSURLProtocol device ID replacement
// Only links Foundation — no UIKit/AdSupport/Security/IOKit
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

#define NSLog(...)

static NSString *_originalBundleID = @"com.baidu.BaiduMobile";

// ============================================================
// Fake device ID generation + persistence
// ============================================================
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
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    NSString *key = [NSString stringWithFormat:@"BaiduBox.cfg.ck.%@", name];
    NSString *v = [d stringForKey:key];
    if (v) return v;
    v = genFakeCookie(name);
    [d setObject:v forKey:key];
    [d synchronize];
    return v;
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
            [item.name isEqualToString:@"cfrom"] || [item.name isEqualToString:@"c3_aid"]) {
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
        for (NSString *key in [json allKeys]) {
            if ([key isEqualToString:@"cuid"] || [key hasPrefix:@"cuid_"] ||
                [key isEqualToString:@"cfrom"] || [key isEqualToString:@"c3_aid"]) {
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
            if ([name isEqualToString:@"cuid"] || [name hasPrefix:@"cuid_"] ||
                [name isEqualToString:@"cfrom"] || [name isEqualToString:@"c3_aid"]) {
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
// Constructor
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {
        // Bundle ID hook (payment critical)
        Class bundleClass = objc_getClass("NSBundle");
        if (bundleClass) {
            Method m = class_getInstanceMethod(bundleClass, @selector(bundleIdentifier));
            if (m) {
                IMP orig = method_getImplementation(m);
                IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                    if ([s isEqual:[NSBundle mainBundle]]) return _originalBundleID;
                    return ((NSString *(*)(id, SEL))orig)(s, @selector(bundleIdentifier));
                });
                class_replaceMethod(bundleClass, @selector(bundleIdentifier), imp, method_getTypeEncoding(m));
            }
        }

        // Register NSURLProtocol for device ID replacement
        [NSURLProtocol registerClass:[BaiduDeviceProtocol class]];
    }
}
