//
// PrivacyHook.m — v41: atbc/natbc/wcp security tokens + receipt + jailbreak file hiding
//
// ROOT CAUSE: Baidu sends atbc/natbc/wcp security tokens in order requests.
//   These tokens are generated based on app integrity (code signature, binary hash).
//   TrollStore app has different signature → tokens are invalid → server rejects.
//   Also: appStoreReceiptURL check, jailbreak file path checks.
//
// v41 FIX:
//   1. Hook fetchAtbcForNetworking/fetchNatbcForNetworking/fetchWcpInfoForNetwork
//   2. Hook appStoreReceiptURL to return fake URL
//   3. Hook access()/stat()/lstat() via fishhook to hide jailbreak files
//   4. Hook bundlePath/executablePath to return fake App Store paths
//   5. Keep all v40 anti-injection + device fingerprint hooks
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <Security/Security.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreTelephony/CTCarrier.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <sys/stat.h>
#import <unistd.h>
#import "fishhook.h"

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

// BAIDUID: server-assigned cookie, typically like "A1B2C3D4E5F6G7H8:FG=1"
static NSString *getFakeBAIDUID(void) {
    return getPersistent(@"Bdhk.baiduid", ^{
        NSString *cs = @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        NSMutableString *s = [NSMutableString string];
        for (int i = 0; i < 32; i++)
            [s appendFormat:@"%c", [cs characterAtIndex:arc4random_uniform((uint32_t)cs.length)]];
        [s appendString:@":FG=1"];
        return s;
    });
}

static NSString *getFakeMAC(void) {
    return getPersistent(@"Bdhk.mac", ^{
        NSMutableString *s = [NSMutableString string];
        for (int i = 0; i < 6; i++) {
            if (i > 0) [s appendString:@":"];
            [s appendFormat:@"%02X%02X", arc4random_uniform(256), arc4random_uniform(256)];
        }
        return s;
    });
}

static NSString *getFakeMachineID(void) {
    return getPersistent(@"Bdhk.machineid", ^{ return genUUIDStr(); });
}

static NSString *getFakeUDID(void) {
    return getPersistent(@"Bdhk.udid", ^{
        NSMutableString *s = [NSMutableString string];
        NSString *cs = @"0123456789abcdef";
        for (int i = 0; i < 40; i++)
            [s appendFormat:@"%c", [cs characterAtIndex:arc4random_uniform((uint32_t)cs.length)]];
        return s;
    });
}

// ============================================================
// Check functions
// ============================================================
static BOOL containsCUID(NSString *s) {
    if (!s) return NO;
    return [s.lowercaseString containsString:@"cuid"];
}

static BOOL containsBAIDUID(NSString *s) {
    if (!s) return NO;
    return [s.lowercaseString containsString:@"baiduid"];
}

static BOOL containsDeviceID(NSString *s) {
    if (!s) return NO;
    return containsCUID(s) || containsBAIDUID(s);
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
           [lk containsString:@"baiduid"] ||
           [lk containsString:@"bdid"] ||
           [lk containsString:@"clientid"] ||
           [lk containsString:@"machineid"] ||
           [lk containsString:@"clone"];
}

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
// Replace device IDs in strings and URLs
// ============================================================
static NSString *replaceDeviceIDsInString(NSString *str) {
    if (!str) return str;
    BOOL hasCUID = containsCUID(str);
    BOOL hasBAIDUID = containsBAIDUID(str);
    if (!hasCUID && !hasBAIDUID) return str;

    NSMutableString *result = [str mutableCopy];
    NSError *err = nil;

    if (hasCUID) {
        NSString *fakeCUID = getFakeCUID();

        // cuid=xxx in URL query
        NSRegularExpression *regex1 = [NSRegularExpression
            regularExpressionWithPattern:@"(cuid=)([^&;\"' \r\n]+)"
            options:NSRegularExpressionCaseInsensitive error:&err];
        if (regex1) [regex1 replaceMatchesInString:result options:0 range:NSMakeRange(0, result.length) withTemplate:[NSString stringWithFormat:@"$1%@", fakeCUID]];

        // "cuid":"xxx" in JSON
        NSRegularExpression *regex2 = [NSRegularExpression
            regularExpressionWithPattern:@"(\"cuid\"\\s*:\\s*\")([^\"]+)(\")"
            options:NSRegularExpressionCaseInsensitive error:&err];
        if (regex2) [regex2 replaceMatchesInString:result options:0 range:NSMakeRange(0, result.length) withTemplate:[NSString stringWithFormat:@"$1%@$3", fakeCUID]];

        // "cuid":12345 (numeric) in JSON
        NSRegularExpression *regex3 = [NSRegularExpression
            regularExpressionWithPattern:@"(\"cuid\"\\s*:\\s*)([0-9]+)"
            options:NSRegularExpressionCaseInsensitive error:&err];
        if (regex3) [regex3 replaceMatchesInString:result options:0 range:NSMakeRange(0, result.length) withTemplate:[NSString stringWithFormat:@"$1\"%@\"", fakeCUID]];

        // cuid%3Dxxx (URL encoded)
        NSRegularExpression *regex4 = [NSRegularExpression
            regularExpressionWithPattern:@"(cuid%3[dD])([^&;%\"' ]+)"
            options:0 error:&err];
        if (regex4) [regex4 replaceMatchesInString:result options:0 range:NSMakeRange(0, result.length) withTemplate:[NSString stringWithFormat:@"$1%@", fakeCUID]];
    }

    if (hasBAIDUID) {
        NSString *fakeBAIDUID = getFakeBAIDUID();

        // BAIDUID=xxx in URL query
        NSRegularExpression *regex1 = [NSRegularExpression
            regularExpressionWithPattern:@"(BAIDUID=)([^&;\"' \r\n:]+)(:[^&;\"' \r\n]*)?"
            options:NSRegularExpressionCaseInsensitive error:&err];
        if (regex1) [regex1 replaceMatchesInString:result options:0 range:NSMakeRange(0, result.length) withTemplate:[NSString stringWithFormat:@"$1%@", fakeBAIDUID]];

        // "baiduid":"xxx" in JSON
        NSRegularExpression *regex2 = [NSRegularExpression
            regularExpressionWithPattern:@"(\"baiduid\"\\s*:\\s*\")([^\"]+)(\")"
            options:NSRegularExpressionCaseInsensitive error:&err];
        if (regex2) [regex2 replaceMatchesInString:result options:0 range:NSMakeRange(0, result.length) withTemplate:[NSString stringWithFormat:@"$1%@$3", fakeBAIDUID]];
    }

    return result;
}

static NSURL *replaceDeviceIDsInURL(NSURL *url) {
    if (!url) return url;
    NSString *query = [url query];
    if (!query || !containsDeviceID(query)) return url;
    NSURLComponents *comp = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    if (!comp || !comp.queryItems) return url;
    NSMutableArray *newItems = [NSMutableArray array];
    NSString *fakeCUID = getFakeCUID();
    NSString *fakeBAIDUID = getFakeBAIDUID();
    for (NSURLQueryItem *item in comp.queryItems) {
        if (containsCUID(item.name)) {
            [newItems addObject:[NSURLQueryItem queryItemWithName:item.name value:fakeCUID]];
        } else if (containsBAIDUID(item.name)) {
            [newItems addObject:[NSURLQueryItem queryItemWithName:item.name value:fakeBAIDUID]];
        } else if (item.value && containsDeviceID(item.value)) {
            [newItems addObject:[NSURLQueryItem queryItemWithName:item.name value:replaceDeviceIDsInString(item.value)]];
        } else {
            [newItems addObject:item];
        }
    }
    comp.queryItems = newItems;
    return [comp URL] ?: url;
}

// ============================================================
// Cookie helpers — now handles BAIDUID too!
// ============================================================
static NSHTTPCookie *modifiedCookie(NSHTTPCookie *cookie) {
    if (!cookie) return cookie;

    BOOL isCUIDCookie = containsCUID(cookie.name);
    BOOL isBAIDUIDCookie = containsBAIDUID(cookie.name);

    if (!isCUIDCookie && !isBAIDUIDCookie) return cookie;

    NSString *newValue = isCUIDCookie ? getFakeCUID() : getFakeBAIDUID();
    NSMutableDictionary *props = [NSMutableDictionary dictionary];
    props[NSHTTPCookieName] = cookie.name;
    props[NSHTTPCookieValue] = newValue;
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
// Delete ALL cookies except BDUSS/STOKEN
// ============================================================
static void wipeAllCookiesExceptLogin(void) {
    @try {
        NSHTTPCookieStorage *cs = [NSHTTPCookieStorage sharedHTTPCookieStorage];
        NSArray *allCookies = [cs cookies];
        if (!allCookies) return;

        for (NSHTTPCookie *cookie in allCookies) {
            NSString *ln = cookie.name.lowercaseString;
            // Preserve login-related cookies
            if ([ln containsString:@"bduss"] || [ln containsString:@"stoken"] ||
                [ln containsString:@"login"] || [ln containsString:@"token"] ||
                [ln containsString:@"account"] || [ln containsString:@"passport"]) {
                continue;
            }
            // Delete everything else — especially BAIDUID!
            [cs deleteCookie:cookie];
        }
    } @catch (id e) {}
}

// ============================================================
// AGGRESSIVE Keychain wipe (preserve only login tokens)
// ============================================================
static void wipeAllKeychainExceptLogin(void) {
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

                if (shouldPreserveKey(searchStr)) continue;

                NSMutableDictionary *delQuery = [NSMutableDictionary dictionary];
                delQuery[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
                if (service) delQuery[(__bridge id)kSecAttrService] = service;
                if (account) delQuery[(__bridge id)kSecAttrAccount] = account;
                SecItemDelete((__bridge CFDictionaryRef)delQuery);
            }
        } else if (result) {
            CFRelease(result);
        }

        for (id secClass in @[(__bridge id)kSecClassInternetPassword, (__bridge id)kSecClassCertificate, (__bridge id)kSecClassKey]) {
            NSDictionary *delAll = @{ (__bridge id)kSecClass: secClass };
            SecItemDelete((__bridge CFDictionaryRef)delAll);
        }
    } @catch (id e) {}
}

// ============================================================
// Anti-jailbreak: Hook access() to hide jailbreak files
// ============================================================
static int (*orig_access)(const char *, int) = NULL;
static int hooked_access(const char *path, int mode) {
    if (!orig_access) return -1;
    if (path) {
        // Hide jailbreak/TrollStore files
        if (strstr(path, "/Applications/Cydia.app") ||
            strstr(path, "/private/var/lib/apt") ||
            strstr(path, "/private/var/lib/cydia") ||
            strstr(path, "/private/var/tmp/cydia") ||
            strstr(path, "/private/var/stash") ||
            strstr(path, "/usr/lib/libcycript") ||
            strstr(path, "/usr/sbin/sshd") ||
            strstr(path, "/usr/bin/ssh") ||
            strstr(path, "/bin/bash") ||
            strstr(path, "/bin/sh") ||
            strstr(path, "/Applications/Sileo.app") ||
            strstr(path, "/var/jb/") ||
            strstr(path, "/var/checkra1n") ||
            strstr(path, "/usr/lib/TweakInject") ||
            strstr(path, "/usr/sbin/trollstore") ||
            strstr(path, "/TrollStore/") ||
            strstr(path, "trollstore")) {
            return -1;
        }
    }
    return orig_access(path, mode);
}

// Hook stat() to hide jailbreak files
static int (*orig_stat)(const char *, struct stat *) = NULL;
static int hooked_stat(const char *path, struct stat *buf) {
    if (!orig_stat) return -1;
    if (path) {
        if (strstr(path, "/Applications/Cydia.app") ||
            strstr(path, "/private/var/lib/apt") ||
            strstr(path, "/private/var/lib/cydia") ||
            strstr(path, "/private/var/stash") ||
            strstr(path, "/usr/lib/libcycript") ||
            strstr(path, "/var/jb/") ||
            strstr(path, "trollstore") ||
            strstr(path, "/TrollStore/")) {
            return -1;
        }
    }
    return orig_stat(path, buf);
}

// Hook lstat() to hide jailbreak files
static int (*orig_lstat)(const char *, struct stat *) = NULL;
static int hooked_lstat(const char *path, struct stat *buf) {
    if (!orig_lstat) return -1;
    if (path) {
        if (strstr(path, "/Applications/Cydia.app") ||
            strstr(path, "/private/var/lib/apt") ||
            strstr(path, "/private/var/lib/cydia") ||
            strstr(path, "/private/var/stash") ||
            strstr(path, "/var/jb/") ||
            strstr(path, "trollstore") ||
            strstr(path, "/TrollStore/")) {
            return -1;
        }
    }
    return orig_lstat(path, buf);
}

// ============================================================
// Anti-injection detection: Hide our dylib from scans
// ============================================================

// The dylib is renamed to BaiduBoxSys.dylib in the IPA
// We need to hide both "PrivacyHook" and "BaiduBoxSys" from detection
static BOOL shouldHideImageName(const char *name) {
    if (!name) return NO;
    // Check for our dylib names
    if (strstr(name, "PrivacyHook") || strstr(name, "BaiduBoxSys")) return YES;
    // Also check for any dylib in the app's Frameworks dir that shouldn't be there
    // (but be conservative - only hide our own)
    return NO;
}

static const char *getFakeImageName(void) {
    // Return a plausible system framework name
    return "/System/Library/Frameworks/Foundation.framework/Foundation";
}

// Hook _dyld_get_image_name
static const char *(*orig_dyld_get_image_name)(uint32_t) = NULL;
static const char *hooked_dyld_get_image_name(uint32_t image_index) {
    if (!orig_dyld_get_image_name) return NULL;
    const char *name = orig_dyld_get_image_name(image_index);
    if (shouldHideImageName(name)) {
        return getFakeImageName();
    }
    return name;
}

// Hook dladdr - hide info about our dylib
static int (*orig_dladdr)(const void *, Dl_info *) = NULL;
static int hooked_dladdr(const void *addr, Dl_info *info) {
    if (!orig_dladdr) return 0;
    int ret = orig_dladdr(addr, info);
    if (ret != 0 && info && info->dli_fname) {
        if (shouldHideImageName(info->dli_fname)) {
            // Replace with fake info
            info->dli_fname = getFakeImageName();
            info->dli_sname = NULL;
            info->dli_saddr = NULL;
        }
    }
    return ret;
}

// Hook getenv - hide DYLD_INSERT_LIBRARIES
static char *(*orig_getenv)(const char *) = NULL;
static char *hooked_getenv(const char *name) {
    if (!orig_getenv) return NULL;
    if (name && strcmp(name, "DYLD_INSERT_LIBRARIES") == 0) {
        return NULL;
    }
    return orig_getenv(name);
}

// Hook class_getImageName - hide our classes' image
static const char *(*orig_class_getImageName)(Class) = NULL;
static const char *hooked_class_getImageName(Class cls) {
    if (!orig_class_getImageName) return NULL;
    const char *name = orig_class_getImageName(cls);
    if (shouldHideImageName(name)) {
        return getFakeImageName();
    }
    return name;
}

// ============================================================
// Fishhook: sysctlbyname and uname
// ============================================================
static char g_fakeModel[32] = {0};
static char g_fakeMachine[32] = {0};
static char g_fakeVersion[32] = {0};
static char g_fakeRelease[32] = {0};

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;

static int hooked_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (!orig_sysctlbyname) return -1;

    // hw.machine → fake machine model
    if (name && strcmp(name, "hw.machine") == 0) {
        if (oldp && oldlenp && *oldlenp >= strlen(g_fakeMachine) + 1) {
            strcpy((char *)oldp, g_fakeMachine);
            *oldlenp = strlen(g_fakeMachine);
            return 0;
        }
        if (oldlenp) *oldlenp = strlen(g_fakeMachine);
        return 0;
    }
    // hw.model → fake model
    if (name && strcmp(name, "hw.model") == 0) {
        if (oldp && oldlenp && *oldlenp >= strlen(g_fakeModel) + 1) {
            strcpy((char *)oldp, g_fakeModel);
            *oldlenp = strlen(g_fakeModel);
            return 0;
        }
        if (oldlenp) *oldlenp = strlen(g_fakeModel);
        return 0;
    }

    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

static int (*orig_uname)(struct utsname *) = NULL;

static int hooked_uname(struct utsname *buf) {
    if (!orig_uname) return -1;
    int ret = orig_uname(buf);
    if (ret == 0 && buf) {
        strcpy(buf->machine, g_fakeMachine);
        strcpy(buf->release, g_fakeRelease);
        strcpy(buf->version, g_fakeVersion);
    }
    return ret;
}

// ============================================================
// Hook ALL device ID class methods
// ============================================================
static void hookDeviceIDMethods(void) {
    // +[BIMBaiduUDID value]
    @try {
        Class cls = objc_getClass("BIMBaiduUDID");
        if (cls) {
            Method m = class_getClassMethod(cls, @selector(value));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSString *(id s) { return getFakeUDID(); });
                class_replaceMethod(object_getClass(cls), @selector(value), imp, method_getTypeEncoding(m));
            }
        }
    } @catch (id e) {}

    // +[DXMSensorsAnalyticsSDK getUniqueHardwareId]
    @try {
        Class cls = objc_getClass("DXMSensorsAnalyticsSDK");
        if (cls) {
            Method m = class_getClassMethod(cls, @selector(getUniqueHardwareId));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSString *(id s) { return getFakeUDID(); });
                class_replaceMethod(object_getClass(cls), @selector(getUniqueHardwareId), imp, method_getTypeEncoding(m));
            }
            m = class_getClassMethod(cls, @selector(getIDFA));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                    return getPersistent(@"Bdhk.ai", ^{ return genUUIDStr(); });
                });
                class_replaceMethod(object_getClass(cls), @selector(getIDFA), imp, method_getTypeEncoding(m));
            }
        }
    } @catch (id e) {}

    // +[YYUtility(Device) macAddresss]
    @try {
        Class cls = objc_getClass("YYUtility");
        if (cls) {
            // Try class method
            Method m = class_getClassMethod(cls, @selector(macAddresss));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSString *(id s) { return getFakeMAC(); });
                class_replaceMethod(object_getClass(cls), @selector(macAddresss), imp, method_getTypeEncoding(m));
            }
            // Try instance method
            m = class_getInstanceMethod(cls, @selector(macAddresss));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSString *(id s) { return getFakeMAC(); });
                class_replaceMethod(cls, @selector(macAddresss), imp, method_getTypeEncoding(m));
            }
        }
    } @catch (id e) {}

    // +[UtilsHelper getMachineID:] / -[UtilsHelper getDeviceID] / +[UtilsHelper lists_YYUdid]
    @try {
        Class cls = objc_getClass("UtilsHelper");
        if (cls) {
            // +[UtilsHelper getMachineID:]
            Method m = class_getClassMethod(cls, @selector(getMachineID:));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSString *(id s, id arg) { return getFakeMachineID(); });
                class_replaceMethod(object_getClass(cls), @selector(getMachineID:), imp, method_getTypeEncoding(m));
            }
            // -[UtilsHelper getDeviceID]
            m = class_getInstanceMethod(cls, @selector(getDeviceID));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSString *(id s) { return getFakeMachineID(); });
                class_replaceMethod(cls, @selector(getDeviceID), imp, method_getTypeEncoding(m));
            }
            // +[UtilsHelper lists_YYUdid]
            m = class_getClassMethod(cls, @selector(lists_YYUdid));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSString *(id s) { return getFakeUDID(); });
                class_replaceMethod(object_getClass(cls), @selector(lists_YYUdid), imp, method_getTypeEncoding(m));
            }
        }
    } @catch (id e) {}

    // +[DMDeviceInfoWrapper deviceModel / systemVersion / cellularProviderName]
    @try {
        Class cls = objc_getClass("DMDeviceInfoWrapper");
        if (cls) {
            Method m = class_getClassMethod(cls, @selector(deviceModel));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                    return getPersistent(@"Bdhk.hwmodel", ^{
                        NSArray *models = @[@"iPhone14,5", @"iPhone14,7", @"iPhone15,2", @"iPhone15,3", @"iPhone13,2", @"iPhone12,1"];
                        return models[arc4random_uniform((uint32_t)models.count)];
                    });
                });
                class_replaceMethod(object_getClass(cls), @selector(deviceModel), imp, method_getTypeEncoding(m));
            }
            m = class_getClassMethod(cls, @selector(systemVersion));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                    return getPersistent(@"Bdhk.sv", ^{ return genFakeSystemVersion(); });
                });
                class_replaceMethod(object_getClass(cls), @selector(systemVersion), imp, method_getTypeEncoding(m));
            }
            m = class_getClassMethod(cls, @selector(cellularProviderName));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @""; });
                class_replaceMethod(object_getClass(cls), @selector(cellularProviderName), imp, method_getTypeEncoding(m));
            }
        }
    } @catch (id e) {}

    // -[BIMDeviceInfoUtility deviceModelVersion]
    @try {
        Class cls = objc_getClass("BIMDeviceInfoUtility");
        if (cls) {
            Method m = class_getInstanceMethod(cls, @selector(deviceModelVersion));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                    return getPersistent(@"Bdhk.hwmodel", ^{
                        NSArray *models = @[@"iPhone14,5", @"iPhone14,7", @"iPhone15,2", @"iPhone15,3", @"iPhone13,2", @"iPhone12,1"];
                        return models[arc4random_uniform((uint32_t)models.count)];
                    });
                });
                class_replaceMethod(cls, @selector(deviceModelVersion), imp, method_getTypeEncoding(m));
            }
        }
    } @catch (id e) {}

    // Hook getBaiduid / getBaiduID / readBaiduIDFromCookie / getBaiduIDInCookie
    @try {
        unsigned int classCount = 0;
        Class *classes = objc_copyClassList(&classCount);
        NSArray *baiduidSelectors = @[@"getBaiduid", @"getbaiduid", @"getBaiduID",
                                      @"getBaiduIDInCookie", @"readBaiduIDFromCookie",
                                      @"getBaiduidFromCookie"];
        for (unsigned int ci = 0; ci < classCount; ci++) {
            Class cls = classes[ci];
            for (NSString *selName in baiduidSelectors) {
                SEL sel = NSSelectorFromString(selName);
                Method m = class_getInstanceMethod(cls, sel);
                if (m) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) { return getFakeBAIDUID(); });
                    class_replaceMethod(cls, sel, imp, method_getTypeEncoding(m));
                }
                m = class_getClassMethod(cls, sel);
                if (m) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) { return getFakeBAIDUID(); });
                    class_replaceMethod(object_getClass(cls), sel, imp, method_getTypeEncoding(m));
                }
            }
        }
        free(classes);
    } @catch (id e) {}
}

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {

        // ---- 0. Read REAL bundle ID ----
        @try {
            NSDictionary *d = [[NSBundle mainBundle] infoDictionary];
            g_realBundleID = [d[@"CFBundleIdentifier"] copy];
        } @catch (id e) {}

        // ---- 1. Generate fake hardware identifiers for fishhook ----
        @try {
            NSString *fakeMachine = getPersistent(@"Bdhk.hwmodel", ^{
                NSArray *models = @[@"iPhone14,5", @"iPhone14,7", @"iPhone15,2", @"iPhone15,3", @"iPhone13,2", @"iPhone12,1"];
                return models[arc4random_uniform((uint32_t)models.count)];
            });
            NSString *fakeVersion = getPersistent(@"Bdhk.sv", ^{ return genFakeSystemVersion(); });

            strncpy(g_fakeMachine, [fakeMachine UTF8String], sizeof(g_fakeMachine) - 1);
            strncpy(g_fakeModel, [fakeMachine UTF8String], sizeof(g_fakeModel) - 1);
            strncpy(g_fakeRelease, [[NSString stringWithFormat:@"Darwin Kernel Version %@", fakeVersion] UTF8String], sizeof(g_fakeRelease) - 1);
            strncpy(g_fakeVersion, [fakeVersion UTF8String], sizeof(g_fakeVersion) - 1);
        } @catch (id e) {}

        // ---- 2. Fishhook: sysctlbyname + uname + anti-injection ----
        @try {
            struct rebinding rebindings[] = {
                {"sysctlbyname",          (void *)hooked_sysctlbyname,          (void **)&orig_sysctlbyname},
                {"uname",                 (void *)hooked_uname,                 (void **)&orig_uname},
                // Anti-injection: hide our dylib from dyld scans
                {"_dyld_get_image_name",  (void *)hooked_dyld_get_image_name,  (void **)&orig_dyld_get_image_name},
                {"dladdr",                (void *)hooked_dladdr,                (void **)&orig_dladdr},
                {"getenv",                (void *)hooked_getenv,                (void **)&orig_getenv},
                {"class_getImageName",    (void *)hooked_class_getImageName,    (void **)&orig_class_getImageName},
                // Anti-jailbreak: hide jailbreak files
                {"access",                (void *)hooked_access,                (void **)&orig_access},
                {"stat",                  (void *)hooked_stat,                  (void **)&orig_stat},
                {"lstat",                 (void *)hooked_lstat,                 (void **)&orig_lstat},
            };

            // Hook in ALL non-system images (like v36)
            unsigned int imageCount = 0;
            const char **imageNames = objc_copyImageNames(&imageCount);
            for (unsigned int i = 0; i < imageCount; i++) {
                const char *name = imageNames[i];
                if (!name) continue;
                NSString *ns = [NSString stringWithUTF8String:name];
                // Skip system frameworks
                if ([ns containsString:@"/System/"] || [ns containsString:@"/Library/"]) continue;
                // Hook all app/framework images
                void *header = dlopen(name, RTLD_NOLOAD);
                if (header) {
                    Dl_info info;
                    if (dladdr(header, &info)) {
                        rebind_symbols_image(info.dli_fbase, 0, rebindings, 9);
                    }
                }
            }
            free(imageNames);
        } @catch (id e) {}

        // ---- 3. Delete ALL cookies except BDUSS/STOKEN (KEY FIX for BAIDUID!) ----
        wipeAllCookiesExceptLogin();

        // ---- 4. Wipe keychain (preserve login tokens) ----
        wipeAllKeychainExceptLogin();

        // ---- 5. Delete CUID/BAIDUID from NSUserDefaults ----
        @try {
            NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
            NSDictionary *allDict = [ud dictionaryRepresentation];
            for (NSString *key in allDict.allKeys) {
                NSString *lk = key.lowercaseString;
                if ([lk containsString:@"cuid"] || [lk containsString:@"deviceid"] ||
                    [lk containsString:@"device_id"] || [lk containsString:@"machineid"] ||
                    [lk containsString:@"bdudid"] || [lk containsString:@"bd_uuid"] ||
                    [lk containsString:@"clone"] || [lk containsString:@"sapi"] ||
                    [lk containsString:@"baiduid"]) {
                    [ud removeObjectForKey:key];
                }
            }
            [ud synchronize];
        } @catch (id e) {}

        // ---- 6. Pre-write fake CUID to ALL keychain locations ----
        @try {
            NSString *fakeCUID = getFakeCUID();
            NSArray *services = @[
                @"SAPICUID", @"SAPICUIDKeychain", @"com.baidu.sapi.cuid",
                @"com.baidu.cuid", @"BDCUID", @"cuid",
                @"com.baidu.BaiduMobile.cuid", @"BD_CUID",
                @"com.baidu.device.cuid", @"bd_cuid",
                @"clone_cuid", @"com.baidu.clone.cuid",
                @"SAPICUIDKeychainQuery",
                @"B83JBVZ6M5.com.baidu.baidumobile.cuid",
            ];
            NSArray *accounts = @[
                @"cuid", @"CUID", @"SAPICUID", @"default",
                @"com.baidu.cuid", @"",
            ];
            for (NSString *svc in services) {
                for (NSString *acc in accounts) {
                    NSDictionary *query = @{
                        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                        (__bridge id)kSecAttrService: svc,
                        (__bridge id)kSecAttrAccount: acc ?: @"",
                    };
                    SecItemDelete((__bridge CFDictionaryRef)query);
                    NSMutableDictionary *addQuery = [NSMutableDictionary dictionaryWithDictionary:query];
                    addQuery[(__bridge id)kSecValueData] = [fakeCUID dataUsingEncoding:NSUTF8StringEncoding];
                    addQuery[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;
                    SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
                }
            }
        } @catch (id e) {}

        // ---- 7. Pre-write fake CUID + BAIDUID to NSUserDefaults ----
        @try {
            NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
            for (NSString *k in @[@"CUID", @"cuid", @"BD_CUID", @"baidu_cuid",
                                  @"BAIDU_CUID", @"kCUID", @"com.baidu.cuid",
                                  @"bd_cuid", @"box_cuid", @"APP_CUID",
                                  @"clone_cuid", @"SAPICUID", @"sapi_cuid",
                                  @"BAIDUID", @"baiduid", @"BaiduID", @"baiduID"]) {
                if ([k.lowercaseString containsString:@"baiduid"]) {
                    [ud setObject:getFakeBAIDUID() forKey:k];
                } else {
                    [ud setObject:getFakeCUID() forKey:k];
                }
            }
            [ud synchronize];
        } @catch (id e) {}

        // ---- 8. Hook ALL device ID methods ----
        hookDeviceIDMethods();

        // ---- 9. Bundle ID hook ----
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

        // ---- 10. UIDevice hooks ----
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

        // ---- 11. IDFA hook ----
        @try {
            Class ac = objc_getClass("ASIdentifierManager");
            if (ac) {
                Method m = class_getInstanceMethod(ac, @selector(advertisingIdentifier));
                if (m) { IMP imp = imp_implementationWithBlock(^NSUUID *(id s) { return [[NSUUID alloc] initWithUUIDString:getPersistent(@"Bdhk.ai", ^{ return genUUIDStr(); })]; }); class_replaceMethod(ac, @selector(advertisingIdentifier), imp, method_getTypeEncoding(m)); }
            }
        } @catch (id e) {}

        // ---- 12. ANTI-CLONE: Hook clone detection methods ----
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

        // ---- 12b. ANTI-INJECTION: Hook jailbreak/tamper detection methods ----
        @try {
            // +[HDANA_ComUtils getJailbrokenApp]
            Class hdanaCom = objc_getClass("HDANA_ComUtils");
            if (hdanaCom) {
                Method m = class_getClassMethod(hdanaCom, @selector(getJailbrokenApp));
                if (m) {
                    IMP imp = imp_implementationWithBlock(^id(id s) { return nil; });
                    class_replaceMethod(object_getClass(hdanaCom), @selector(getJailbrokenApp), imp, method_getTypeEncoding(m));
                }
            }

            // BDPanJailbreakDetectTool - neutralize all methods
            Class jbDetect = objc_getClass("BDPanJailbreakDetectTool");
            if (jbDetect) {
                unsigned int methodCount = 0;
                Method *methods = class_copyMethodList(jbDetect, &methodCount);
                for (unsigned int i = 0; i < methodCount; i++) {
                    SEL sel = method_getName(methods[i]);
                    const char *typeEnc = method_getTypeEncoding(methods[i]);
                    NSString *selName = NSStringFromSelector(sel);
                    // Return NO for bool methods, nil for object methods
                    if ([selName.lowercaseString containsString:@"jailbreak"] ||
                        [selName.lowercaseString containsString:@"detect"] ||
                        [selName.lowercaseString containsString:@"check"]) {
                        if (typeEnc[0] == 'B') {
                            IMP imp = imp_implementationWithBlock(^BOOL(id s) { return NO; });
                            class_replaceMethod(jbDetect, sel, imp, typeEnc);
                        } else {
                            IMP imp = imp_implementationWithBlock(^id(id s) { return nil; });
                            class_replaceMethod(jbDetect, sel, imp, typeEnc);
                        }
                    }
                }
                free(methods);

                // Also hook class methods
                Method *clsMethods = class_copyMethodList(object_getClass(jbDetect), &methodCount);
                for (unsigned int i = 0; i < methodCount; i++) {
                    SEL sel = method_getName(clsMethods[i]);
                    const char *typeEnc = method_getTypeEncoding(clsMethods[i]);
                    NSString *selName = NSStringFromSelector(sel);
                    if ([selName.lowercaseString containsString:@"jailbreak"] ||
                        [selName.lowercaseString containsString:@"detect"] ||
                        [selName.lowercaseString containsString:@"check"]) {
                        if (typeEnc[0] == 'B') {
                            IMP imp = imp_implementationWithBlock(^BOOL(id s) { return NO; });
                            class_replaceMethod(object_getClass(jbDetect), sel, imp, typeEnc);
                        }
                    }
                }
                free(clsMethods);
            }

            // Hook IsValidate_hookDetection everywhere
            // preventingTampering → return NO
            // use_jailbreak_detect_tool → return NO
            // jailbreakDetectToolType → return 0
            // enableBDPTraceSwizzlingMethod → return NO
            unsigned int classCount2 = 0;
            Class *classes2 = objc_copyClassList(&classCount2);
            NSArray *antiDetectSelectors = @[
                @"IsValidate_hookDetection",
                @"preventingTampering",
                @"use_jailbreak_detect_tool",
                @"jailbreakDetectToolType",
                @"enableBDPTraceSwizzlingMethod",
                @"isJailbroken",
                @"isJailBreak",
                @"jailbroken",
                @"hasJailbreak",
                @"detectJailbreak",
                @"checkJailbreak",
                @"isHooked",
                @"hookDetect",
                @"detectHook",
                @"checkHook",
                @"isTampered",
                @"tamperDetect",
                @"detectTamper",
                @"checkTamper",
                @"isInjected",
                @"injectDetect",
                @"detectInject",
                @"checkInject",
            ];
            for (unsigned int ci = 0; ci < classCount2; ci++) {
                Class cls = classes2[ci];
                for (NSString *selName in antiDetectSelectors) {
                    SEL sel = NSSelectorFromString(selName);
                    Method m = class_getInstanceMethod(cls, sel);
                    if (m) {
                        const char *typeEnc = method_getTypeEncoding(m);
                        if (typeEnc[0] == 'B') {
                            IMP imp = imp_implementationWithBlock(^BOOL(id s) { return NO; });
                            class_replaceMethod(cls, sel, imp, typeEnc);
                        } else if (typeEnc[0] == 'q' || typeEnc[0] == 'i') {
                            IMP imp = imp_implementationWithBlock(^long(id s) { return 0; });
                            class_replaceMethod(cls, sel, imp, typeEnc);
                        } else {
                            IMP imp = imp_implementationWithBlock(^id(id s) { return nil; });
                            class_replaceMethod(cls, sel, imp, typeEnc);
                        }
                    }
                    // Also class methods
                    m = class_getClassMethod(cls, sel);
                    if (m) {
                        const char *typeEnc = method_getTypeEncoding(m);
                        if (typeEnc[0] == 'B') {
                            IMP imp = imp_implementationWithBlock(^BOOL(id s) { return NO; });
                            class_replaceMethod(object_getClass(cls), sel, imp, typeEnc);
                        } else if (typeEnc[0] == 'q' || typeEnc[0] == 'i') {
                            IMP imp = imp_implementationWithBlock(^long(id s) { return 0; });
                            class_replaceMethod(object_getClass(cls), sel, imp, typeEnc);
                        } else {
                            IMP imp = imp_implementationWithBlock(^id(id s) { return nil; });
                            class_replaceMethod(object_getClass(cls), sel, imp, typeEnc);
                        }
                    }
                }

                // Also hook setters for preventingTampering
                SEL setTamper = NSSelectorFromString(@"setPreventingTampering:");
                Method setM = class_getInstanceMethod(cls, setTamper);
                if (setM) {
                    IMP imp = imp_implementationWithBlock(^void(id s, BOOL v) {});
                    class_replaceMethod(cls, setTamper, imp, method_getTypeEncoding(setM));
                }
            }
            free(classes2);
        } @catch (id e) {}

        // ---- 13. NSMutableURLRequest hooks (URL + headers, NOT body) ----
        @try {
            Class reqClass = objc_getClass("NSMutableURLRequest");

            Method im1 = class_getInstanceMethod(reqClass, @selector(initWithURL:));
            if (im1) {
                IMP origI1 = method_getImplementation(im1);
                IMP newI1 = imp_implementationWithBlock(^id(id s, NSURL *url) {
                    if (!g_inHook && url) { NSURL *nu = replaceDeviceIDsInURL(url); if (nu != url) { g_inHook = YES; id r = ((id (*)(id, SEL, NSURL *))origI1)(s, @selector(initWithURL:), nu); g_inHook = NO; return r; } }
                    return ((id (*)(id, SEL, NSURL *))origI1)(s, @selector(initWithURL:), url);
                });
                class_replaceMethod(reqClass, @selector(initWithURL:), newI1, method_getTypeEncoding(im1));
            }

            Method im2 = class_getInstanceMethod(reqClass, @selector(initWithURL:cachePolicy:timeoutInterval:));
            if (im2) {
                IMP origI2 = method_getImplementation(im2);
                IMP newI2 = imp_implementationWithBlock(^id(id s, NSURL *url, NSURLRequestCachePolicy p, NSTimeInterval t) {
                    if (!g_inHook && url) { NSURL *nu = replaceDeviceIDsInURL(url); if (nu != url) { g_inHook = YES; id r = ((id (*)(id, SEL, NSURL *, NSURLRequestCachePolicy, NSTimeInterval))origI2)(s, @selector(initWithURL:cachePolicy:timeoutInterval:), nu, p, t); g_inHook = NO; return r; } }
                    return ((id (*)(id, SEL, NSURL *, NSURLRequestCachePolicy, NSTimeInterval))origI2)(s, @selector(initWithURL:cachePolicy:timeoutInterval:), url, p, t);
                });
                class_replaceMethod(reqClass, @selector(initWithURL:cachePolicy:timeoutInterval:), newI2, method_getTypeEncoding(im2));
            }

            Method sum = class_getInstanceMethod(reqClass, @selector(setURL:));
            if (sum) {
                IMP origSU = method_getImplementation(sum);
                IMP newSU = imp_implementationWithBlock(^void(id s, NSURL *url) {
                    if (!g_inHook && url) { NSURL *nu = replaceDeviceIDsInURL(url); if (nu != url) { g_inHook = YES; ((void (*)(id, SEL, NSURL *))origSU)(s, @selector(setURL:), nu); g_inHook = NO; return; } }
                    ((void (*)(id, SEL, NSURL *))origSU)(s, @selector(setURL:), url);
                });
                class_replaceMethod(reqClass, @selector(setURL:), newSU, method_getTypeEncoding(sum));
            }

            Method svm = class_getInstanceMethod(reqClass, @selector(setValue:forHTTPHeaderField:));
            if (svm) {
                IMP origSV = method_getImplementation(svm);
                IMP newSV = imp_implementationWithBlock(^void(id s, NSString *v, NSString *f) {
                    if (!g_inHook && v) {
                        if (f && containsDeviceID(f)) { g_inHook = YES; ((void (*)(id, SEL, NSString *, NSString *))origSV)(s, @selector(setValue:forHTTPHeaderField:), containsCUID(f) ? getFakeCUID() : getFakeBAIDUID(), f); g_inHook = NO; return; }
                        if (containsDeviceID(v)) { g_inHook = YES; ((void (*)(id, SEL, NSString *, NSString *))origSV)(s, @selector(setValue:forHTTPHeaderField:), replaceDeviceIDsInString(v), f); g_inHook = NO; return; }
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
                        if (f && containsDeviceID(f)) { g_inHook = YES; ((void (*)(id, SEL, NSString *, NSString *))origAV)(s, @selector(addValue:forHTTPHeaderField:), containsCUID(f) ? getFakeCUID() : getFakeBAIDUID(), f); g_inHook = NO; return; }
                        if (containsDeviceID(v)) { g_inHook = YES; ((void (*)(id, SEL, NSString *, NSString *))origAV)(s, @selector(addValue:forHTTPHeaderField:), replaceDeviceIDsInString(v), f); g_inHook = NO; return; }
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
                            if (containsDeviceID(k)) { md[k] = containsCUID(k) ? getFakeCUID() : getFakeBAIDUID(); mod = YES; }
                            else if (v && containsDeviceID(v)) { md[k] = replaceDeviceIDsInString(v); mod = YES; }
                            else md[k] = v;
                        }
                        if (mod) { g_inHook = YES; ((void (*)(id, SEL, NSDictionary *))origSAH)(s, @selector(setAllHTTPHeaderFields:), md); g_inHook = NO; return; }
                    }
                    ((void (*)(id, SEL, NSDictionary *))origSAH)(s, @selector(setAllHTTPHeaderFields:), headers);
                });
                class_replaceMethod(reqClass, @selector(setAllHTTPHeaderFields:), newSAH, method_getTypeEncoding(sahM));
            }
        } @catch (id e) {}

        // ---- 14. NSHTTPCookieStorage hooks (now handles BAIDUID too!) ----
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

        // ---- 15. CoreTelephony hooks ----
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

        // ---- 16. Security tokens: atbc/natbc/wcp ----
        // These tokens prove app integrity. Hook them to return dummy values.
        @try {
            unsigned int classCount3 = 0;
            Class *classes3 = objc_copyClassList(&classCount3);

            // Methods that return security tokens - hook to return persistent dummy string
            NSArray *tokenSelectors = @[
                @"fetchAtbcForNetworking",
                @"fetchNatbcForNetworking",
                @"fetchWcpInfoForNetwork",
                @"fetchWcpInfoForDXMBankPay",
                @"wcpEncoded",
                @"fetchAtbc",
                @"fetchNatbc",
                @"fetchWcp",
            ];

            NSString *fakeToken = getPersistent(@"Bdhk.token", ^{
                NSString *cs = @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                NSMutableString *s = [NSMutableString string];
                for (int i = 0; i < 44; i++)
                    [s appendFormat:@"%c", [cs characterAtIndex:arc4random_uniform((uint32_t)cs.length)]];
                return s;
            });

            for (unsigned int ci = 0; ci < classCount3; ci++) {
                Class cls = classes3[ci];
                for (NSString *selName in tokenSelectors) {
                    SEL sel = NSSelectorFromString(selName);
                    // Instance method
                    Method m = class_getInstanceMethod(cls, sel);
                    if (m) {
                        const char *typeEnc = method_getTypeEncoding(m);
                        IMP imp = imp_implementationWithBlock(^NSString *(id s) { return fakeToken; });
                        class_replaceMethod(cls, sel, imp, typeEnc);
                    }
                    // Class method
                    m = class_getClassMethod(cls, sel);
                    if (m) {
                        const char *typeEnc = method_getTypeEncoding(m);
                        IMP imp = imp_implementationWithBlock(^NSString *(id s) { return fakeToken; });
                        class_replaceMethod(object_getClass(cls), sel, imp, typeEnc);
                    }
                }
            }
            free(classes3);
        } @catch (id e) {}

        // ---- 17. App Store receipt hook ----
        // TrollStore apps don't have a receipt. Return a fake URL.
        @try {
            Class bc2 = objc_getClass("NSBundle");
            if (bc2) {
                Method rm = class_getInstanceMethod(bc2, @selector(appStoreReceiptURL));
                if (rm) {
                    IMP origR = method_getImplementation(rm);
                    IMP newR = imp_implementationWithBlock(^NSURL *(id s) {
                        if ([s isEqual:[NSBundle mainBundle]]) {
                            // Return a fake receipt URL that looks like App Store
                            NSString *fakePath = [@"/var/containers/Bundle/Application/" stringByAppendingPathComponent:getPersistent(@"Bdhk.uuid", ^{ return genUUIDStr(); })];
                            fakePath = [fakePath stringByAppendingPathComponent:@"BaiduBoxApp.app/_MASReceipt/receipt"];
                            return [NSURL fileURLWithPath:fakePath];
                        }
                        return ((NSURL *(*)(id, SEL))origR)(s, @selector(appStoreReceiptURL));
                    });
                    class_replaceMethod(bc2, @selector(appStoreReceiptURL), newR, method_getTypeEncoding(rm));
                }
                // Also hook bundlePath to return App Store-like path
                Method bpm = class_getInstanceMethod(bc2, @selector(bundlePath));
                if (bpm) {
                    IMP origBP = method_getImplementation(bpm);
                    IMP newBP = imp_implementationWithBlock(^NSString *(id s) {
                        if ([s isEqual:[NSBundle mainBundle]]) {
                            NSString *fakePath = [@"/var/containers/Bundle/Application/" stringByAppendingPathComponent:getPersistent(@"Bdhk.uuid", ^{ return genUUIDStr(); })];
                            return [fakePath stringByAppendingPathComponent:@"BaiduBoxApp.app"];
                        }
                        return ((NSString *(*)(id, SEL))origBP)(s, @selector(bundlePath));
                    });
                    class_replaceMethod(bc2, @selector(bundlePath), newBP, method_getTypeEncoding(bpm));
                }
                // Hook executablePath
                Method epm = class_getInstanceMethod(bc2, @selector(executablePath));
                if (epm) {
                    IMP origEP = method_getImplementation(epm);
                    IMP newEP = imp_implementationWithBlock(^NSString *(id s) {
                        if ([s isEqual:[NSBundle mainBundle]]) {
                            NSString *fakePath = [@"/var/containers/Bundle/Application/" stringByAppendingPathComponent:getPersistent(@"Bdhk.uuid", ^{ return genUUIDStr(); })];
                            return [fakePath stringByAppendingPathComponent:@"BaiduBoxApp.app/BaiduBoxApp"];
                        }
                        return ((NSString *(*)(id, SEL))origEP)(s, @selector(executablePath));
                    });
                    class_replaceMethod(bc2, @selector(executablePath), newEP, method_getTypeEncoding(epm));
                }
            }
        } @catch (id e) {}
    }
}
