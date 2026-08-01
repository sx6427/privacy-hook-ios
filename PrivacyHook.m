//
// PrivacyHook.m — v36: fishhook ALL non-system images
//
// v35 issue: rebind_symbols_image only hooked index 0 (main executable).
//   But Baidu's CUID generation code lives in its own frameworks/dylibs,
//   not in the main executable → sysctlbyname not intercepted → real CUID.
//
// v36 fix: Iterate ALL loaded images, skip /System/ and /usr/lib/,
//   hook every Baidu-owned image. System frameworks untouched → no crash.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <Security/Security.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreTelephony/CTCarrier.h>
#import <objc/runtime.h>
#import <sys/utsname.h>
#import <string.h>
#import <errno.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import "fishhook.h"

#define NSLog(...)

static NSString *const kOrigBundleID = @"com.baidu.BaiduMobile";
static NSString *g_realBundleID = nil;
static __thread BOOL g_inHook = NO;

// ============================================================
// Pre-cached fake device info (C strings, set BEFORE fishhook)
// ============================================================
static char g_fakeMachine[32]  = "";   // hw.machine   e.g. "iPhone14,5"
static char g_fakeModel[32]    = "";   // hw.model
static char g_fakeOSVersion[32] = "";  // kern.osversion e.g. "20A362"
static char g_fakeOSRelease[32] = "";  // kern.osrelease e.g. "22.0.0"
static char g_fakeOSType[32]    = "";  // kern.ostype   "Darwin"
static char g_fakeProductName[32] = ""; // hw.productName "iPhone"
static uint64_t g_fakeMemSize = 0;     // hw.memsize
static char g_fakeSysVersion[16] = ""; // for UIDevice, e.g. "16.0"

static __thread BOOL g_inSysctlHook = NO;

// Original function pointers (filled by fishhook)
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
static int (*orig_uname)(struct utsname *) = NULL;

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

// ============================================================
// Device profiles: (machine, iOS version, build, Darwin release, memsize)
// ============================================================
static NSString *getDeviceProfileComponent(NSInteger index) {
    // Each profile: [machine, iosVersion, build, darwinRelease, memSizeGB]
    NSArray *profiles = @[
        @[@"iPhone14,5", @"16.0", @"20A362",  @"22.0.0", @"4"],
        @[@"iPhone14,7", @"16.1", @"20B5045d", @"22.1.0", @"6"],
        @[@"iPhone14,8", @"16.2", @"20C65",   @"22.2.0", @"6"],
        @[@"iPhone15,2", @"16.3", @"20D47",   @"22.3.0", @"6"],
        @[@"iPhone15,3", @"16.4", @"20E246",  @"22.4.0", @"6"],
        @[@"iPhone15,4", @"16.5", @"20F66",   @"22.5.0", @"6"],
        @[@"iPhone15,5", @"16.6", @"20G75",   @"22.6.0", @"6"],
        @[@"iPhone16,1", @"17.0", @"21A329",  @"23.0.0", @"8"],
        @[@"iPhone16,2", @"17.1", @"21B74",   @"23.1.0", @"8"],
    ];
    NSString *profileKey = getPersistent(@"Bdhk.profile.idx", ^{
        return [NSString stringWithFormat:@"%lu", (unsigned long)arc4random_uniform((uint32_t)profiles.count)];
    });
    NSUInteger idx = [profileKey integerValue];
    if (idx >= profiles.count) idx = 0;
    return profiles[idx][index];
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
// ============================================================
static NSString *replaceCUIDInString(NSString *str) {
    if (!str || !containsCUID(str)) return str;
    NSString *fakeCUID = getFakeCUID();
    NSMutableString *result = [str mutableCopy];

    NSError *err = nil;
    NSRegularExpression *regex1 = [NSRegularExpression
        regularExpressionWithPattern:@"(cuid=)([^&;\"' \r\n]+)"
        options:NSRegularExpressionCaseInsensitive error:&err];
    if (regex1) {
        [regex1 replaceMatchesInString:result options:0
            range:NSMakeRange(0, result.length)
            withTemplate:[NSString stringWithFormat:@"$1%@", fakeCUID]];
    }

    NSRegularExpression *regex2 = [NSRegularExpression
        regularExpressionWithPattern:@"(\"cuid\"\\s*:\\s*\")([^\"]+)(\")"
        options:NSRegularExpressionCaseInsensitive error:&err];
    if (regex2) {
        [regex2 replaceMatchesInString:result options:0
            range:NSMakeRange(0, result.length)
            withTemplate:[NSString stringWithFormat:@"$1%@$3", fakeCUID]];
    }

    NSRegularExpression *regex3 = [NSRegularExpression
        regularExpressionWithPattern:@"(\"cuid\"\\s*:\\s*)([0-9]+)"
        options:NSRegularExpressionCaseInsensitive error:&err];
    if (regex3) {
        [regex3 replaceMatchesInString:result options:0
            range:NSMakeRange(0, result.length)
            withTemplate:[NSString stringWithFormat:@"$1\"%@\"", fakeCUID]];
    }

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
                                   [lower containsString:@"clientid"] ||
                                   [lower containsString:@"bdudid"] ||
                                   [lower containsString:@"bd_uuid"] ||
                                   [lower containsString:@"baiduid"]);
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
// fishhook: sysctlbyname hook (PURE C, zero ObjC)
// ============================================================
static int hooked_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    // NULL check — if fishhook didn't find the symbol, can't do anything
    if (!orig_sysctlbyname) {
        return -1;
    }
    // Recursion guard
    if (g_inSysctlHook || !name) {
        return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }

    const char *fakeVal = NULL;

    if (strcmp(name, "hw.machine") == 0) {
        fakeVal = g_fakeMachine;
    } else if (strcmp(name, "hw.model") == 0) {
        fakeVal = g_fakeModel;
    } else if (strcmp(name, "kern.osversion") == 0) {
        fakeVal = g_fakeOSVersion;
    } else if (strcmp(name, "kern.osrelease") == 0) {
        fakeVal = g_fakeOSRelease;
    } else if (strcmp(name, "kern.ostype") == 0) {
        fakeVal = g_fakeOSType;
    } else if (strcmp(name, "hw.productName") == 0) {
        fakeVal = g_fakeProductName;
    }

    if (fakeVal && fakeVal[0]) {
        size_t fakeLen = strlen(fakeVal) + 1;  // include null terminator
        if (oldlenp) {
            if (oldp) {
                if (*oldlenp >= fakeLen) {
                    memcpy(oldp, fakeVal, fakeLen);
                } else {
                    *oldlenp = fakeLen;
                    return ENOMEM;
                }
            }
            *oldlenp = fakeLen;
        }
        return 0;
    }

    // hw.memsize — return fake uint64_t
    if (strcmp(name, "hw.memsize") == 0 && g_fakeMemSize > 0) {
        if (oldlenp) {
            if (oldp) {
                if (*oldlenp >= sizeof(uint64_t)) {
                    memcpy(oldp, &g_fakeMemSize, sizeof(uint64_t));
                } else {
                    *oldlenp = sizeof(uint64_t);
                    return ENOMEM;
                }
            }
            *oldlenp = sizeof(uint64_t);
        }
        return 0;
    }

    // Not a name we care about — pass through to original
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

// ============================================================
// fishhook: uname hook (PURE C, zero ObjC)
// ============================================================
static int hooked_uname(struct utsname *name) {
    // NULL check
    if (!orig_uname) {
        return -1;
    }
    if (g_inSysctlHook || !name) {
        return orig_uname(name);
    }
    g_inSysctlHook = YES;
    int ret = orig_uname(name);
    g_inSysctlHook = NO;

    if (ret == 0 && name) {
        if (g_fakeMachine[0]) {
            strncpy(name->machine, g_fakeMachine, sizeof(name->machine) - 1);
            name->machine[sizeof(name->machine) - 1] = '\0';
        }
        if (g_fakeOSRelease[0]) {
            strncpy(name->release, g_fakeOSRelease, sizeof(name->release) - 1);
            name->release[sizeof(name->release) - 1] = '\0';
        }
        if (g_fakeOSVersion[0]) {
            strncpy(name->version, g_fakeOSVersion, sizeof(name->version) - 1);
            name->version[sizeof(name->version) - 1] = '\0';
        }
    }
    return ret;
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
                    [lk containsString:@"device_id"] || [lk containsString:@"machineid"] ||
                    [lk containsString:@"bdudid"] || [lk containsString:@"bd_uuid"]) {
                    [ud removeObjectForKey:key];
                }
            }
            [ud synchronize];
        } @catch (id e) {}
        wipeCUIDFromKeychain();

        // ---- 2. Pre-cache fake device info as C strings ----
        // MUST be done BEFORE installing fishhook to avoid recursion
        @try {
            NSString *machine = getDeviceProfileComponent(0);   // e.g. "iPhone14,5"
            NSString *iosVer = getDeviceProfileComponent(1);    // e.g. "16.0"
            NSString *build  = getDeviceProfileComponent(2);    // e.g. "20A362"
            NSString *darwin = getDeviceProfileComponent(3);    // e.g. "22.0.0"
            NSString *memGB  = getDeviceProfileComponent(4);    // e.g. "6"

            strncpy(g_fakeMachine,   [machine UTF8String], sizeof(g_fakeMachine) - 1);
            strncpy(g_fakeModel,     [machine UTF8String], sizeof(g_fakeModel) - 1);
            strncpy(g_fakeOSVersion, [build UTF8String],  sizeof(g_fakeOSVersion) - 1);
            strncpy(g_fakeOSRelease, [darwin UTF8String], sizeof(g_fakeOSRelease) - 1);
            strncpy(g_fakeOSType,    "Darwin",            sizeof(g_fakeOSType) - 1);
            strncpy(g_fakeProductName, "iPhone",           sizeof(g_fakeProductName) - 1);
            strncpy(g_fakeSysVersion, [iosVer UTF8String], sizeof(g_fakeSysVersion) - 1);

            uint64_t memBytes = (uint64_t)([memGB longLongValue]) * 1024ULL * 1024ULL * 1024ULL;
            g_fakeMemSize = memBytes;
        } @catch (id e) {}

        // ---- 3. Install fishhook for sysctlbyname + uname ----
        // v36: Hook ALL non-system images (main exe + Baidu frameworks)
        // v35 only hooked index 0 which missed CUID generation in frameworks
        // v34 hooked everything including system frameworks → crash
        // v36: skip /System/, /usr/lib/, /Developer/ → only hook App's own images
        orig_sysctlbyname = dlsym(RTLD_DEFAULT, "sysctlbyname");
        orig_uname = dlsym(RTLD_DEFAULT, "uname");

        uint32_t imgCount = _dyld_image_count();
        for (uint32_t i = 0; i < imgCount; i++) {
            const char *path = _dyld_get_image_name(i);
            if (!path) continue;
            // Skip system libraries and developer tools
            if (strncmp(path, "/System/", 8) == 0) continue;
            if (strncmp(path, "/usr/lib/", 9) == 0) continue;
            if (strncmp(path, "/Developer/", 11) == 0) continue;

            const struct mach_header *hdr = _dyld_get_image_header(i);
            intptr_t slide = _dyld_get_image_vmaddr_slide(i);
            if (!hdr) continue;

            struct rebinding rebindings[] = {
                {"sysctlbyname", hooked_sysctlbyname, (void **)&orig_sysctlbyname},
                {"uname",        hooked_uname,        (void **)&orig_uname}
            };
            rebind_symbols_image((void *)hdr, slide, rebindings, 2);
        }

        // ---- 4. Bundle ID hook ----
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
                        return [NSString stringWithUTF8String:g_fakeSysVersion];
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

        // ---- 6. IDFA hook ----
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

        // ---- 7. NSMutableURLRequest: init + URL + header ----
        @try {
            Class reqClass = objc_getClass("NSMutableURLRequest");

            // 7a. initWithURL:
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

            // 7b. initWithURL:cachePolicy:timeoutInterval:
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

            // 7c. setURL:
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

            // 7d. setValue:forHTTPHeaderField:
            Method svm = class_getInstanceMethod(reqClass, @selector(setValue:forHTTPHeaderField:));
            if (svm) {
                IMP origSV = method_getImplementation(svm);
                IMP newSV = imp_implementationWithBlock(^void(id s, NSString *value, NSString *field) {
                    if (!g_inHook && value) {
                        if (field && containsCUID(field)) {
                            g_inHook = YES;
                            ((void (*)(id, SEL, NSString *, NSString *))origSV)(s, @selector(setValue:forHTTPHeaderField:), getFakeCUID(), field);
                            g_inHook = NO;
                            return;
                        }
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

            // 7e. addValue:forHTTPHeaderField:
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

            // 7f. setAllHTTPHeaderFields:
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

            // 7g. setHTTPBody: — REMOVED (v33/v34)
            // Modifying body CUID breaks API signature (sign calculated with original CUID)
            // Instead, fishhook makes App generate fake CUID naturally → body has fake CUID → sign is valid
        } @catch (id e) {}

        // ---- 8. NSHTTPCookieStorage hooks ----
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

        // ---- 9. CoreTelephony hooks (SIM/carrier spoofing) ----
        @try {
            Class ctniClass = objc_getClass("CTTelephonyNetworkInfo");
            if (ctniClass) {
                Method sscpM = class_getInstanceMethod(ctniClass, @selector(serviceSubscriberCellularProviders));
                if (sscpM) {
                    IMP imp = imp_implementationWithBlock(^NSDictionary *(id s) { return @{}; });
                    class_replaceMethod(ctniClass, @selector(serviceSubscriberCellularProviders), imp, method_getTypeEncoding(sscpM));
                }
                Method scratM = class_getInstanceMethod(ctniClass, @selector(serviceCurrentRadioAccessTechnology));
                if (scratM) {
                    IMP imp = imp_implementationWithBlock(^NSDictionary *(id s) { return @{}; });
                    class_replaceMethod(ctniClass, @selector(serviceCurrentRadioAccessTechnology), imp, method_getTypeEncoding(scratM));
                }
                Method scpM = class_getInstanceMethod(ctniClass, @selector(subscriberCellularProvider));
                if (scpM) {
                    IMP imp = imp_implementationWithBlock(^id(id s) { return nil; });
                    class_replaceMethod(ctniClass, @selector(subscriberCellularProvider), imp, method_getTypeEncoding(scpM));
                }
                Method cratM = class_getInstanceMethod(ctniClass, @selector(currentRadioAccessTechnology));
                if (cratM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) { return nil; });
                    class_replaceMethod(ctniClass, @selector(currentRadioAccessTechnology), imp, method_getTypeEncoding(cratM));
                }
            }

            Class carrierClass = objc_getClass("CTCarrier");
            if (carrierClass) {
                Method cnM = class_getInstanceMethod(carrierClass, @selector(carrierName));
                if (cnM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @""; });
                    class_replaceMethod(carrierClass, @selector(carrierName), imp, method_getTypeEncoding(cnM));
                }
                Method mccM = class_getInstanceMethod(carrierClass, @selector(mobileCountryCode));
                if (mccM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @""; });
                    class_replaceMethod(carrierClass, @selector(mobileCountryCode), imp, method_getTypeEncoding(mccM));
                }
                Method mncM = class_getInstanceMethod(carrierClass, @selector(mobileNetworkCode));
                if (mncM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @""; });
                    class_replaceMethod(carrierClass, @selector(mobileNetworkCode), imp, method_getTypeEncoding(mncM));
                }
                Method isoM = class_getInstanceMethod(carrierClass, @selector(isoCountryCode));
                if (isoM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @""; });
                    class_replaceMethod(carrierClass, @selector(isoCountryCode), imp, method_getTypeEncoding(isoM));
                }
                Method voipM = class_getInstanceMethod(carrierClass, @selector(allowsVOIP));
                if (voipM) {
                    IMP imp = imp_implementationWithBlock(^BOOL(id s) { return YES; });
                    class_replaceMethod(carrierClass, @selector(allowsVOIP), imp, method_getTypeEncoding(voipM));
                }
            }
        } @catch (id e) {}

        // ---- 10. Pre-write fake CUID into NSUserDefaults ----
        @try {
            NSString *fakeCUID = getFakeCUID();
            NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
            for (NSString *k in @[@"CUID", @"cuid", @"BD_CUID", @"baidu_cuid",
                                  @"BAIDU_CUID", @"kCUID", @"com.baidu.cuid",
                                  @"bd_cuid", @"box_cuid", @"APP_CUID"]) {
                [ud setObject:fakeCUID forKey:k];
            }
            [ud synchronize];
        } @catch (id e) {}
    }
}
