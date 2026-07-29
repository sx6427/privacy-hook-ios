//
//  PrivacyHook.m — Step37: NSURLProtocol approach for cookie replacement
//
//  No method swizzling on NSHTTPCookieStorage (caused crashes).
//  Instead, use NSURLProtocol to intercept HTTP requests to baidu.com
//  and replace device fingerprint cookies.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <AppTrackingTransparency/AppTrackingTransparency.h>
#import <Security/Security.h>
#import <objc/runtime.h>

#define NSLog(...)

static NSUUID *_spoofedIDFA = nil;
static NSUUID *_spoofedIDFV = nil;
static NSString *_spoofedDeviceName = nil;
static NSString *_originalBundleID = @"com.baidu.BaiduMobile";
static IMP orig_bundleIdentifier = NULL;
static IMP orig_infoDictionary = NULL;

static NSString *kKey(NSString *suffix) {
    return [NSString stringWithFormat:@"BaiduBox.cfg.%@", suffix];
}

static NSUUID *getOrCreateSpoofedUUID(NSString *key) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *uuidString = [defaults stringForKey:key];
    if (uuidString) return [[NSUUID alloc] initWithUUIDString:uuidString];
    NSUUID *newUUID = [NSUUID UUID];
    [defaults setObject:[newUUID UUIDString] forKey:key];
    [defaults synchronize];
    return newUUID;
}

static NSString *getOrCreateSpoofedDeviceName(NSString *key) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *existing = [defaults stringForKey:key];
    if (existing) return existing;
    NSArray *prefixes = @[@"张", @"李", @"王", @"刘", @"陈", @"杨", @"赵", @"黄",
                          @"周", @"吴", @"徐", @"孙", @"马", @"朱", @"胡", @"林"];
    NSArray *suffixes = @[@"的 iPhone", @"的 iPhone", @"的 iPhone",
                          @"的iPhone", @"的 iPhone 14", @"的 iPhone 13"];
    NSString *prefix = prefixes[arc4random_uniform((uint32_t)prefixes.count)];
    NSString *suffix = suffixes[arc4random_uniform((uint32_t)suffixes.count)];
    NSString *name = [NSString stringWithFormat:@"%@%@", prefix, suffix];
    [defaults setObject:name forKey:key];
    [defaults synchronize];
    return name;
}

// ---- Fake cookie values ----
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

static NSString *getFakeCookie(NSString *name) {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    NSString *key = [NSString stringWithFormat:@"BaiduBox.cfg.ck.%@", name];
    NSString *v = [d stringForKey:key];
    if (v) return v;
    v = genFakeCookie(name);
    [d setObject:v forKey:key];
    [d synchronize];
    return v;
}

// Replace device cookies in a Cookie header string
static NSString *replaceDeviceCookiesInString(NSString *cookie) {
    NSArray *names = @[@"BAIDUCUID", @"BAIDUCUID_BFESS", @"MAWEBCUID",
                       @"DVIF", @"tcuid", @"__bid_n", @"fuid"];
    NSString *modified = cookie;
    for (NSString *name in names) {
        NSString *fake = getFakeCookie(name);
        NSString *pattern = [NSString stringWithFormat:@"%@=[^;]+", name];
        NSRegularExpression *regex = [NSRegularExpression
            regularExpressionWithPattern:pattern
            options:NSRegularExpressionCaseInsensitive error:nil];
        modified = [regex stringByReplacingMatchesInString:modified
            options:0 range:NSMakeRange(0, modified.length)
            withTemplate:[NSString stringWithFormat:@"%@=%@", name, fake]];
    }
    // cuid= (but not BAIDUCUID= or c3_aid=)
    NSString *cuidFake = getFakeCookie(@"cuid");
    NSRegularExpression *cuidRegex = [NSRegularExpression
        regularExpressionWithPattern:@"(?<![A-Za-z_])cuid=[^;]+" options:0 error:nil];
    modified = [cuidRegex stringByReplacingMatchesInString:modified
        options:0 range:NSMakeRange(0, modified.length)
        withTemplate:[NSString stringWithFormat:@"cuid=%@", cuidFake]];
    return modified;
}

static void hookInstanceMethod(Class cls, SEL sel, IMP newImp, const char *types) {
    Method method = class_getInstanceMethod(cls, sel);
    if (method) {
        const char *t = types ?: method_getTypeEncoding(method);
        class_replaceMethod(cls, sel, newImp, t);
    }
}

static void hookClassMethod(Class cls, SEL sel, IMP newImp, const char *types) {
    Class meta = object_getClass(cls);
    Method method = class_getClassMethod(cls, sel);
    if (method) {
        const char *t = types ?: method_getTypeEncoding(method);
        class_replaceMethod(meta, sel, newImp, t);
    }
}

static void clearKeychainEveryLaunch(void) {
    NSArray *cls = @[(__bridge id)kSecClassGenericPassword, (__bridge id)kSecClassInternetPassword,
                     (__bridge id)kSecClassKey, (__bridge id)kSecClassCertificate, (__bridge id)kSecClassIdentity];
    for (id c in cls) { NSDictionary *q = @{(__bridge id)kSecClass: c}; SecItemDelete((__bridge CFDictionaryRef)q); }
}

// ============================================================
// NSURLProtocol for intercepting baidu HTTP requests
// ============================================================
static NSString *const kMarker = @"X-BaiduIntercept";

@interface BaiduCookieProtocol : NSURLProtocol
@end

@implementation BaiduCookieProtocol {
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

    // Replace device cookies
    NSString *cookie = [req valueForHTTPHeaderField:@"Cookie"];
    if (cookie && [cookie length] > 0) {
        [req setValue:replaceDeviceCookiesInString(cookie) forHTTPHeaderField:@"Cookie"];
    }

    // Use a session with no protocol interception (prevent recursion)
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
                [ss.client URLProtocol:ss didReceiveResponse:response cacheRequest:nil];
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
        _spoofedIDFA = getOrCreateSpoofedUUID(kKey(@"id1"));
        _spoofedIDFV = getOrCreateSpoofedUUID(kKey(@"id2"));
        _spoofedDeviceName = getOrCreateSpoofedDeviceName(kKey(@"dn"));
        clearKeychainEveryLaunch();

        // === Bundle ID hook (payment) ===
        Class bundleClass = objc_getClass("NSBundle");
        if (bundleClass) {
            Method m = class_getInstanceMethod(bundleClass, @selector(bundleIdentifier));
            if (m) {
                orig_bundleIdentifier = method_getImplementation(m);
                IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                    if ([s isEqual:[NSBundle mainBundle]]) return _originalBundleID;
                    return ((NSString *(*)(id, SEL))orig_bundleIdentifier)(s, @selector(bundleIdentifier));
                });
                class_replaceMethod(bundleClass, @selector(bundleIdentifier), imp, method_getTypeEncoding(m));
            }
            Method m2 = class_getInstanceMethod(bundleClass, @selector(infoDictionary));
            if (m2) {
                orig_infoDictionary = method_getImplementation(m2);
                IMP imp2 = imp_implementationWithBlock(^NSDictionary *(id s) {
                    NSDictionary *dict = ((NSDictionary *(*)(id, SEL))orig_infoDictionary)(s, @selector(infoDictionary));
                    if ([s isEqual:[NSBundle mainBundle]] && dict) {
                        NSMutableDictionary *md = [dict mutableCopy];
                        md[@"CFBundleIdentifier"] = _originalBundleID;
                        return md;
                    }
                    return dict;
                });
                class_replaceMethod(bundleClass, @selector(infoDictionary), imp2, method_getTypeEncoding(m2));
            }
            Method m3 = class_getInstanceMethod(bundleClass, @selector(objectForInfoDictionaryKey:));
            if (m3) {
                IMP orig3 = method_getImplementation(m3);
                IMP imp3 = imp_implementationWithBlock(^id(id s, SEL _cmd, NSString *key) {
                    id val = ((id(*)(id, SEL, NSString *))orig3)(s, _cmd, key);
                    if ([s isEqual:[NSBundle mainBundle]] && [key isEqualToString:@"CFBundleIdentifier"])
                        return _originalBundleID;
                    return val;
                });
                class_replaceMethod(bundleClass, @selector(objectForInfoDictionaryKey:), imp3, method_getTypeEncoding(m3));
            }
        }

        // === IDFA ===
        Class asm = objc_getClass("ASIdentifierManager");
        if (asm) {
            Method m = class_getInstanceMethod(asm, @selector(advertisingIdentifier));
            if (m) hookInstanceMethod(asm, @selector(advertisingIdentifier),
                imp_implementationWithBlock(^NSUUID *(id s) { return _spoofedIDFA; }), method_getTypeEncoding(m));
            m = class_getInstanceMethod(asm, @selector(isAdvertisingTrackingEnabled));
            if (m) hookInstanceMethod(asm, @selector(isAdvertisingTrackingEnabled),
                imp_implementationWithBlock(^BOOL(id s) { return YES; }), method_getTypeEncoding(m));
        }

        // === ATT ===
        Class att = objc_getClass("ATTrackingManager");
        if (att) {
            Method m = class_getClassMethod(att, @selector(trackingAuthorizationStatus));
            if (m) hookClassMethod(att, @selector(trackingAuthorizationStatus),
                imp_implementationWithBlock(^NSInteger(id s) { return 3; }), method_getTypeEncoding(m));
        }

        // === IDFV + device name ===
        Class ud = objc_getClass("UIDevice");
        if (ud) {
            Method m = class_getInstanceMethod(ud, @selector(identifierForVendor));
            if (m) hookInstanceMethod(ud, @selector(identifierForVendor),
                imp_implementationWithBlock(^NSUUID *(id s) { return _spoofedIDFV; }), method_getTypeEncoding(m));
            m = class_getInstanceMethod(ud, @selector(name));
            if (m) hookInstanceMethod(ud, @selector(name),
                imp_implementationWithBlock(^NSString *(id s) { return _spoofedDeviceName; }), method_getTypeEncoding(m));
        }

        // === NSURLProtocol: intercept baidu requests, replace device cookies ===
        // NO method swizzling on system classes — just register a protocol
        [NSURLProtocol registerClass:[BaiduCookieProtocol class]];
    }
}
