//
// PrivacyHook.m — Comprehensive device fingerprint spoofing
// Layers: sysctl hook + NSUserDefaults hook + NSURLSession swizzle +
//         UIDevice/ASIdentifierManager hooks + Bundle ID + keychain clear
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <sys/sysctl.h>
#import <string.h>
#import "fishhook.h"

#define NSLog(...)

// ============================================================
// Persistent fake IDs
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

static NSString *genCUID(void) {
    NSString *cs = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < 63; i++) {
        if (i > 0 && i % 10 == 3) [s appendString:@"-"];
        else [s appendFormat:@"%C", [cs characterAtIndex:arc4random_uniform((uint32_t)cs.length)]];
    }
    return s;
}

static NSString *genIMEI(void) {
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < 15; i++)
        [s appendFormat:@"%d", arc4random_uniform(10)];
    return s;
}

static NSString *genSerial(void) {
    NSString *cs = @"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    return [NSString stringWithFormat:@"F2L%@", genRandStr(11, cs)];
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
    return getPersistent([NSString stringWithFormat:@"BaiduBox.cfg.ck.%@", name], ^NSString *{
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
// Network request modification functions
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
            [n isEqualToString:@"cfrom"] || [n isEqualToString:@"c3_aid"] ||
            [n isEqualToString:@"idfa"] || [n isEqualToString:@"idfv"] ||
            [n isEqualToString:@"imei"] || [n isEqualToString:@"device_id"] ||
            [n isEqualToString:@"deviceid"]) {
            NSString *fakeVal = [n isEqualToString:@"idfa"] ? getPersistent(@"fake.idfa", ^{ return genUUIDStr(); })
                          : [n isEqualToString:@"idfv"] ? getPersistent(@"fake.idfv", ^{ return genUUIDStr(); })
                          : [n isEqualToString:@"imei"] ? getPersistent(@"fake.imei", ^{ return genIMEI(); })
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

static NSData *replaceDeviceParamsInBody(NSData *body, NSString *contentType) {
    if (!body || body.length == 0) return body;

    if ([contentType containsString:@"json"]) {
        NSError *err = nil;
        NSMutableDictionary *json = [NSJSONSerialization JSONObjectWithData:body
            options:NSJSONReadingMutableContainers error:&err];
        if (err || !json || ![json isKindOfClass:[NSDictionary class]]) return body;

        BOOL modified = NO;
        NSArray *deviceKeys = @[@"cuid", @"cuid_galaxy2", @"cuid_gid", @"cfrom", @"c3_aid",
                                @"idfa", @"idfv", @"device_id", @"udid", @"imei"];
        for (NSString *key in [json allKeys]) {
            NSString *lk = key.lowercaseString;
            if ([deviceKeys containsObject:lk] || [lk hasPrefix:@"cuid"]) {
                NSString *fakeVal = [lk isEqualToString:@"idfa"] ? getPersistent(@"fake.idfa", ^{ return genUUIDStr(); })
                              : [lk isEqualToString:@"idfv"] ? getPersistent(@"fake.idfv", ^{ return genUUIDStr(); })
                              : [lk isEqualToString:@"imei"] ? getPersistent(@"fake.imei", ^{ return genIMEI(); })
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
        NSArray *deviceKeys = @[@"cuid", @"cfrom", @"c3_aid", @"idfa", @"idfv", @"imei"];
        for (NSString *pair in pairs) {
            NSRange eqRange = [pair rangeOfString:@"="];
            if (eqRange.location == NSNotFound) { [newPairs addObject:pair]; continue; }
            NSString *name = [pair substringToIndex:eqRange.location];
            NSString *lk = name.lowercaseString;
            if ([deviceKeys containsObject:lk] || [lk hasPrefix:@"cuid"]) {
                NSString *fakeVal = [lk isEqualToString:@"idfa"] ? getPersistent(@"fake.idfa", ^{ return genUUIDStr(); })
                              : [lk isEqualToString:@"idfv"] ? getPersistent(@"fake.idfv", ^{ return genUUIDStr(); })
                              : [lk isEqualToString:@"imei"] ? getPersistent(@"fake.imei", ^{ return genIMEI(); })
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

// Apply all modifications to a request, return new mutable request
static NSMutableURLRequest *modifiedRequest(NSURLRequest *req) {
    NSMutableURLRequest *m = [req mutableCopy];

    // Cookie
    NSString *cookie = [m valueForHTTPHeaderField:@"Cookie"];
    if (cookie.length > 0)
        [m setValue:replaceDeviceCookiesInString(cookie) forHTTPHeaderField:@"Cookie"];

    // URL
    NSURL *newURL = replaceDeviceParamsInURL(m.URL);
    if (newURL && ![newURL isEqual:m.URL])
        [m setURL:newURL];

    // Body
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
// Layer 1: fishhook sysctlbyname — fake hardware identifiers
// ============================================================
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);

static int hook_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name) {
        // Fake device model
        if (strcmp(name, "hw.machine") == 0) {
            NSArray *models = @[@"iPhone14,7", @"iPhone15,2", @"iPhone13,2", @"iPhone14,5",
                                @"iPhone12,1", @"iPhone15,3", @"iPhone13,3", @"iPhone14,3"];
            const char *fake = [[models objectAtIndex:arc4random_uniform((uint32_t)models.count)]
                                UTF8String];
            if (oldp && oldlenp) {
                size_t len = strlen(fake) + 1;
                if (*oldlenp >= len) memcpy(oldp, fake, len);
                *oldlenp = len;
            }
            return 0;
        }
        // Fake serial number
        if (strcmp(name, "hw.serialnumber") == 0 || strcmp(name, "hw.serial") == 0) {
            NSString *serial = getPersistent(@"fake.serial", ^{ return genSerial(); });
            const char *fake = [serial UTF8String];
            if (oldp && oldlenp) {
                size_t len = strlen(fake) + 1;
                if (*oldlenp >= len) memcpy(oldp, fake, len);
                *oldlenp = len;
            }
            return 0;
        }
    }
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

// ============================================================
// Layer 2: NSUserDefaults swizzle — intercept CUID reads
// ============================================================
static BOOL isDeviceKey(NSString *key) {
    if (!key) return NO;
    NSString *lk = key.lowercaseString;
    NSArray *patterns = @[@"cuid", @"dvif", @"tcuid", @"__bid_n", @"fuid",
                          @"device_id", @"deviceid", @"imei", @"serial",
                          @"idfa", @"idfv", @"udid", @"bdid"];
    for (NSString *p in patterns) {
        if ([lk containsString:p]) return YES;
    }
    return NO;
}

static NSString *fakeValueForKey(NSString *key) {
    NSString *lk = key.lowercaseString;
    if ([lk containsString:@"idfa"]) return getPersistent(@"fake.idfa", ^{ return genUUIDStr(); });
    if ([lk containsString:@"idfv"]) return getPersistent(@"fake.idfv", ^{ return genUUIDStr(); });
    if ([lk containsString:@"imei"]) return getPersistent(@"fake.imei", ^{ return genIMEI(); });
    if ([lk containsString:@"serial"]) return getPersistent(@"fake.serial", ^{ return genSerial(); });
    if ([lk containsString:@"dvif"]) return getFakeID(@"DVIF");
    if ([lk containsString:@"tcuid"]) return getFakeID(@"tcuid");
    if ([lk containsString:@"__bid_n"]) return getFakeID(@"__bid_n");
    if ([lk containsString:@"fuid"]) return getFakeID(@"fuid");
    // Default: treat as CUID
    return getFakeID(@"cuid");
}

// ============================================================
// Layer 3: NSURLSession swizzle — intercept ALL network requests
// ============================================================
static IMP orig_dataTaskWithRequest = NULL;
static IMP orig_dataTaskWithRequestCompletion = NULL;

static NSURLSessionDataTask *hook_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *request) {
    @try {
        NSString *host = request.URL.host;
        if (host && [host containsString:@"baidu"]) {
            NSMutableURLRequest *m = modifiedRequest(request);
            return ((NSURLSessionDataTask *(*)(id, SEL, NSURLRequest *))orig_dataTaskWithRequest)(self, _cmd, m);
        }
    } @catch (id e) {}
    return ((NSURLSessionDataTask *(*)(id, SEL, NSURLRequest *))orig_dataTaskWithRequest)(self, _cmd, request);
}

static NSURLSessionDataTask *hook_dataTaskWithRequestCompletion(id self, SEL _cmd,
        NSURLRequest *request, void (^completionHandler)(NSData *, NSURLResponse *, NSError *)) {
    @try {
        NSString *host = request.URL.host;
        if (host && [host containsString:@"baidu"]) {
            NSMutableURLRequest *m = modifiedRequest(request);
            return ((NSURLSessionDataTask *(*)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *)))
                    orig_dataTaskWithRequestCompletion)(self, _cmd, m, completionHandler);
        }
    } @catch (id e) {}
    return ((NSURLSessionDataTask *(*)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *)))
            orig_dataTaskWithRequestCompletion)(self, _cmd, request, completionHandler);
}

// ============================================================
// Layer 4: NSURLProtocol (backup)
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
// Constructor — install ALL hooks
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

        // ---- 2. UIDevice hooks ----
        Class deviceClass = objc_getClass("UIDevice");
        if (deviceClass) {
            Method nameM = class_getInstanceMethod(deviceClass, @selector(name));
            if (nameM) {
                IMP nameImp = imp_implementationWithBlock(^NSString *(id s) {
                    return getPersistent(@"fake.devname", ^{ return genDeviceName(); });
                });
                class_replaceMethod(deviceClass, @selector(name), nameImp, method_getTypeEncoding(nameM));
            }
            Method idfvM = class_getInstanceMethod(deviceClass, @selector(identifierForVendor));
            if (idfvM) {
                IMP idfvImp = imp_implementationWithBlock(^NSUUID *(id s) {
                    NSString *uuidStr = getPersistent(@"fake.idfv", ^{ return genUUIDStr(); });
                    return [[NSUUID alloc] initWithUUIDString:uuidStr];
                });
                class_replaceMethod(deviceClass, @selector(identifierForVendor), idfvImp, method_getTypeEncoding(idfvM));
            }
            // model → return fake model string
            Method modelM = class_getInstanceMethod(deviceClass, @selector(model));
            if (modelM) {
                IMP modelImp = imp_implementationWithBlock(^NSString *(id s) { return @"iPhone"; });
                class_replaceMethod(deviceClass, @selector(model), modelImp, method_getTypeEncoding(modelM));
            }
        }

        // ---- 3. ASIdentifierManager IDFA hook ----
        Class asidClass = objc_getClass("ASIdentifierManager");
        if (asidClass) {
            Method idfaM = class_getInstanceMethod(asidClass, @selector(advertisingIdentifier));
            if (idfaM) {
                IMP idfaImp = imp_implementationWithBlock(^NSUUID *(id s) {
                    NSString *uuidStr = getPersistent(@"fake.idfa", ^{ return genUUIDStr(); });
                    return [[NSUUID alloc] initWithUUIDString:uuidStr];
                });
                class_replaceMethod(asidClass, @selector(advertisingIdentifier), idfaImp, method_getTypeEncoding(idfaM));
            }
        }

        // ---- 4. NSUserDefaults hooks ----
        Class udClass = objc_getClass("NSUserDefaults");
        if (udClass) {
            // objectForKey:
            Method ofkM = class_getInstanceMethod(udClass, @selector(objectForKey:));
            if (ofkM) {
                IMP origOfk = method_getImplementation(ofkM);
                IMP ofkImp = imp_implementationWithBlock(^id(id s, SEL _c, NSString *key) {
                    if (isDeviceKey(key)) {
                        NSString *fake = fakeValueForKey(key);
                        if (fake) return fake;
                    }
                    return ((id (*)(id, SEL, NSString *))origOfk)(s, _c, key);
                });
                class_replaceMethod(udClass, @selector(objectForKey:), ofkImp, method_getTypeEncoding(ofkM));
            }
            // stringForKey:
            Method sfkM = class_getInstanceMethod(udClass, @selector(stringForKey:));
            if (sfkM) {
                IMP origSfk = method_getImplementation(sfkM);
                IMP sfkImp = imp_implementationWithBlock(^NSString *(id s, SEL _c, NSString *key) {
                    if (isDeviceKey(key)) {
                        NSString *fake = fakeValueForKey(key);
                        if (fake) return fake;
                    }
                    return ((NSString *(*)(id, SEL, NSString *))origSfk)(s, _c, key);
                });
                class_replaceMethod(udClass, @selector(stringForKey:), sfkImp, method_getTypeEncoding(sfkM));
            }
        }

        // ---- 5. NSURLSession swizzle ----
        Class sessionClass = objc_getClass("NSURLSession");
        if (sessionClass) {
            Method dtM = class_getInstanceMethod(sessionClass, @selector(dataTaskWithRequest:));
            if (dtM) {
                orig_dataTaskWithRequest = method_getImplementation(dtM);
                class_replaceMethod(sessionClass, @selector(dataTaskWithRequest:),
                    (IMP)hook_dataTaskWithRequest, method_getTypeEncoding(dtM));
            }
            Method dtcM = class_getInstanceMethod(sessionClass, @selector(dataTaskWithRequest:completionHandler:));
            if (dtcM) {
                orig_dataTaskWithRequestCompletion = method_getImplementation(dtcM);
                class_replaceMethod(sessionClass, @selector(dataTaskWithRequest:completionHandler:),
                    (IMP)hook_dataTaskWithRequestCompletion, method_getTypeEncoding(dtcM));
            }
        }

        // ---- 6. fishhook sysctlbyname ----
        struct rebinding r = {"sysctlbyname", (void *)hook_sysctlbyname, (void **)&orig_sysctlbyname};
        rebind_symbols(&r, 1);

        // ---- 7. Keychain clear (first launch only) ----
        NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
        if (![ud boolForKey:@"keychain.cleared"]) {
            clearKeychain();
            [ud setBool:YES forKey:@"keychain.cleared"];
            [ud synchronize];
        }

        // ---- 8. NSURLProtocol (backup) ----
        [NSURLProtocol registerClass:[BaiduDeviceProtocol class]];
    }
}
