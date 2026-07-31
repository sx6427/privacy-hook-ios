//
// PrivacyHook.m — v29: sysctlbyname hook (pre-loaded, no recursion) + CUID interception
//
// v28: CUID HTTP interception works but device model still "iPhone7.2"
// v27: fishhook crashed → getPersistent() inside hook calls CFPreferences
//      which internally calls sysctlbyname → infinite recursion → crash
//
// v29 fix: Pre-load ALL fake values into static variables BEFORE rebind_symbols.
//   Hook functions ONLY read static vars → zero function calls → no recursion.
//   Backup recursion guard (__thread flag) as safety net.
//
// Features:
//   1. fishhook: sysctlbyname (hw.machine, kern.osversion, kern.osrelease)
//   2. fishhook: uname (machine, release)
//   3. CUID interception: Cookie + URL params + HTTP Header
//   4. Selective Keychain CUID wipe (login tokens preserved)
//   5. UIDevice hooks (systemVersion, name, IDFV, model)
//   6. IDFA hook
//   7. Bundle ID hook (payment compatibility)
//   8. vtool SDK 17.0 (payment compatibility)
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <string.h>
#import "fishhook.h"

#define NSLog(...)

static NSString *const kOrigBundleID = @"com.baidu.BaiduMobile";
static NSString *g_realBundleID = nil;
static __thread BOOL g_inHook = NO;

// ============================================================
// Pre-loaded fake values (filled BEFORE fishhook installation)
// Hook functions ONLY read these — never call getPersistent
// ============================================================
static char g_fakeMachine[64]   = {0};  // e.g. "iPhone14,5"
static char g_fakeBuild[64]     = {0};  // e.g. "20G75"
static char g_fakeRelease[64]   = {0};  // e.g. "22.6.0"
static char g_fakeCUID[256]     = {0};  // per-clone fake CUID

// ============================================================
// Persistent fake IDs — keyed to REAL bundle ID
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

static NSString *genFakeMachine(void) {
    NSArray *models = @[
        @"iPhone14,5", @"iPhone14,7", @"iPhone14,8",
        @"iPhone15,2", @"iPhone15,3", @"iPhone15,4", @"iPhone15,5",
        @"iPhone14,6", @"iPhone14,4",
    ];
    return models[arc4random_uniform((uint32_t)models.count)];
}

static NSString *genFakeCUID(void) {
    NSString *cs = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < 40; i++)
        [s appendFormat:@"%c", [cs characterAtIndex:arc4random_uniform((uint32_t)cs.length)]];
    return s;
}

static NSDictionary *versionInfoMap(NSString *version) {
    NSDictionary *map = @{
        @"15.7": @{@"build": @"19H221",  @"release": @"21.6.0"},
        @"16.0": @{@"build": @"20A362",  @"release": @"22.0.0"},
        @"16.1": @{@"build": @"20B82",   @"release": @"22.1.0"},
        @"16.2": @{@"build": @"20C65",   @"release": @"22.2.0"},
        @"16.3": @{@"build": @"20D47",   @"release": @"22.3.0"},
        @"16.4": @{@"build": @"20E246",  @"release": @"22.4.0"},
        @"16.5": @{@"build": @"20F66",   @"release": @"22.5.0"},
        @"16.6": @{@"build": @"20G75",   @"release": @"22.6.0"},
    };
    return map[version] ?: @{@"build": @"20G75", @"release": @"22.6.0"};
}

// ============================================================
// fishhook: sysctlbyname (READ-ONLY static vars, no recursion)
// ============================================================
static int (*orig_sysctlbyname)(const char *, void *, size_t *,
                                 const void *, size_t) = NULL;

static int hook_sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                              const void *newp, size_t newlen) {
    // Recursion guard: if CFPreferences internally calls sysctlbyname,
    // pass through to original immediately
    if (g_inHook) {
        return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }

    if (name) {
        const char *fakeStr = NULL;

        if (strcmp(name, "hw.machine") == 0 || strcmp(name, "hw.product") == 0) {
            fakeStr = g_fakeMachine;
        } else if (strcmp(name, "kern.osversion") == 0) {
            fakeStr = g_fakeBuild;
        } else if (strcmp(name, "kern.osrelease") == 0) {
            fakeStr = g_fakeRelease;
        }

        if (fakeStr && fakeStr[0]) {
            size_t fakeLen = strlen(fakeStr) + 1;
            if (oldp && oldlenp) {
                if (*oldlenp >= fakeLen) {
                    memcpy(oldp, fakeStr, fakeLen);
                }
                *oldlenp = fakeLen;
                return 0;
            } else if (oldlenp) {
                *oldlenp = fakeLen;
                return 0;
            }
        }
    }
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

// ============================================================
// fishhook: uname (READ-ONLY static vars, no recursion)
// ============================================================
static int (*orig_uname)(struct utsname *) = NULL;

static int hook_uname(struct utsname *name) {
    int ret = orig_uname(name);
    if (ret == 0 && name) {
        if (g_fakeMachine[0]) {
            memset(name->machine, 0, sizeof(name->machine));
            strncpy(name->machine, g_fakeMachine, sizeof(name->machine) - 1);
        }
        if (g_fakeRelease[0]) {
            memset(name->release, 0, sizeof(name->release));
            strncpy(name->release, g_fakeRelease, sizeof(name->release) - 1);
        }
    }
    return ret;
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
// CUID helpers for HTTP interception
// ============================================================
static BOOL containsCUID(NSString *s) {
    if (!s) return NO;
    return [s.lowercaseString containsString:@"cuid"];
}

static NSString *getFakeCUIDStr(void) {
    return [NSString stringWithUTF8String:g_fakeCUID];
}

static NSURL *replaceCUIDInURL(NSURL *url) {
    if (!url) return url;
    NSString *query = [url query];
    if (!query || !containsCUID(query)) return url;

    NSURLComponents *comp = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    if (!comp || !comp.queryItems) return url;

    NSMutableArray *newItems = [NSMutableArray array];
    for (NSURLQueryItem *item in comp.queryItems) {
        if (containsCUID(item.name)) {
            [newItems addObject:[NSURLQueryItem queryItemWithName:item.name value:getFakeCUIDStr()]];
        } else {
            [newItems addObject:item];
        }
    }
    comp.queryItems = newItems;
    NSURL *newURL = [comp URL];
    return newURL ?: url;
}

static NSHTTPCookie *modifiedCookie(NSHTTPCookie *cookie) {
    if (!cookie || !containsCUID(cookie.name)) return cookie;
    NSMutableDictionary *props = [NSMutableDictionary dictionary];
    props[NSHTTPCookieName] = cookie.name;
    props[NSHTTPCookieValue] = getFakeCUIDStr();
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

        // ---- 1. Pre-load ALL fake values into static C strings ----
        // This MUST happen BEFORE rebind_symbols, so that hook functions
        // can read static vars without calling any ObjC/Foundation functions.
        // This prevents the recursion crash that v27 had.
        @try {
            NSString *fakeSV = getPersistent(@"Bdhk.sv", ^{ return genFakeSystemVersion(); });
            NSString *fakeHM = getPersistent(@"Bdhk.hm", ^{ return genFakeMachine(); });
            NSString *fakeCUID = getPersistent(@"Bdhk.cuid", ^{ return genFakeCUID(); });

            NSDictionary *vi = versionInfoMap(fakeSV);

            // Copy to static C strings (no ObjC needed in hooks after this)
            strncpy(g_fakeMachine, [fakeHM UTF8String], sizeof(g_fakeMachine) - 1);
            strncpy(g_fakeBuild,   [vi[@"build"] UTF8String], sizeof(g_fakeBuild) - 1);
            strncpy(g_fakeRelease, [vi[@"release"] UTF8String], sizeof(g_fakeRelease) - 1);
            strncpy(g_fakeCUID,    [fakeCUID UTF8String], sizeof(g_fakeCUID) - 1);
        } @catch (id e) {}

        // ---- 2. Delete CUID-related NSUserDefaults keys ----
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

        // ---- 2b. Selectively delete CUID from Keychain ----
        wipeCUIDFromKeychain();

        // ---- 3. fishhook: sysctlbyname + uname ----
        // NOW safe: hook functions only read pre-loaded static C strings.
        // No ObjC/Foundation calls inside hooks → no recursion.
        // Backup recursion guard (g_inHook) as extra safety.
        @try {
            struct rebinding rebindings[] = {
                {"sysctlbyname", (void *)hook_sysctlbyname, (void **)&orig_sysctlbyname},
                {"uname",        (void *)hook_uname,        (void **)&orig_uname},
            };
            rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
        } @catch (id e) {}

        // ---- 4. Bundle ID hook (3 methods) ----
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

        // ---- 5. UIDevice hooks ----
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

        // ---- 6. ASIdentifierManager IDFA hook ----
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

        // ---- 7. NSMutableURLRequest hooks (HTTP Header + URL params) ----
        @try {
            Class reqClass = objc_getClass("NSMutableURLRequest");
            if (reqClass) {
                Method svm = class_getInstanceMethod(reqClass, @selector(setValue:forHTTPHeaderField:));
                if (svm) {
                    IMP origSV = method_getImplementation(svm);
                    IMP newSV = imp_implementationWithBlock(^void(id s, NSString *value, NSString *field) {
                        if (!g_inHook && field && containsCUID(field)) {
                            g_inHook = YES;
                            ((void (*)(id, SEL, NSString *, NSString *))origSV)(s, @selector(setValue:forHTTPHeaderField:), getFakeCUIDStr(), field);
                            g_inHook = NO;
                            return;
                        }
                        ((void (*)(id, SEL, NSString *, NSString *))origSV)(s, @selector(setValue:forHTTPHeaderField:), value, field);
                    });
                    class_replaceMethod(reqClass, @selector(setValue:forHTTPHeaderField:), newSV, method_getTypeEncoding(svm));
                }

                Method avm = class_getInstanceMethod(reqClass, @selector(addValue:forHTTPHeaderField:));
                if (avm) {
                    IMP origAV = method_getImplementation(avm);
                    IMP newAV = imp_implementationWithBlock(^void(id s, NSString *value, NSString *field) {
                        if (!g_inHook && field && containsCUID(field)) {
                            g_inHook = YES;
                            ((void (*)(id, SEL, NSString *, NSString *))origAV)(s, @selector(addValue:forHTTPHeaderField:), getFakeCUIDStr(), field);
                            g_inHook = NO;
                            return;
                        }
                        ((void (*)(id, SEL, NSString *, NSString *))origAV)(s, @selector(addValue:forHTTPHeaderField:), value, field);
                    });
                    class_replaceMethod(reqClass, @selector(addValue:forHTTPHeaderField:), newAV, method_getTypeEncoding(avm));
                }

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
            }
        } @catch (id e) {}

        // ---- 8. NSHTTPCookieStorage hooks (Cookie CUID replacement) ----
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

        // ---- 9. Pre-write fake CUID into NSUserDefaults ----
        @try {
            NSString *fakeCUID = getFakeCUIDStr();
            NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
            for (NSString *k in @[@"CUID", @"cuid", @"BD_CUID", @"baidu_cuid",
                                  @"BAIDU_CUID", @"kCUID", @"com.baidu.cuid"]) {
                [ud setObject:fakeCUID forKey:k];
            }
            [ud synchronize];
        } @catch (id e) {}
    }
}
