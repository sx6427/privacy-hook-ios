#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <AppTrackingTransparency/AppTrackingTransparency.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <sys/sysctl.h>
#import <net/if.h>
#import <net/if_dl.h>
#import <ifaddrs.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#include <string.h>

#define NSLog(...)

// ============================================================
// Runtime string construction
// ============================================================
static NSString *rtStr(const char *s) {
    return [NSString stringWithUTF8String:s];
}

static NSString *rtConcat(const char *a, const char *b) {
    return [NSString stringWithFormat:@"%s%s", a, b];
}

// ============================================================
// Persistent spoofed identifiers
// ============================================================
static NSUUID *_spoofedIDFA = nil;
static NSUUID *_spoofedIDFV = nil;
static NSString *_spoofedDeviceName = nil;
static NSString *_spoofedSerialNumber = nil;
static NSString *_spoofedUDID = nil;
static NSString *_spoofedMAC = nil;
static NSString *_spoofedLocalIP = nil;

static volatile BOOL g_initialized = NO;

// ============================================================
// NSUserDefaults key prefix — looks like Baidu's own
// ============================================================
static NSString *kPrefix(void) {
    return rtConcat("BaiduBox.cfg.", "");
}

static NSString *kKey(const char *suffix) {
    return [NSString stringWithFormat:@"%@%s", kPrefix(), suffix];
}

// ============================================================
// Spoofed value generators
// ============================================================
static NSUUID *getOrCreateSpoofedUUID(const char *suffix) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = kKey(suffix);
    NSString *uuidString = [defaults stringForKey:key];
    if (uuidString) {
        return [[NSUUID alloc] initWithUUIDString:uuidString];
    }
    NSUUID *newUUID = [NSUUID UUID];
    [defaults setObject:[newUUID UUIDString] forKey:key];
    [defaults synchronize];
    return newUUID;
}

static NSString *getOrCreateSpoofedString(const char *suffix, NSUInteger length) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = kKey(suffix);
    NSString *existing = [defaults stringForKey:key];
    if (existing) return existing;

    NSMutableString *str = [NSMutableString stringWithCapacity:length];
    NSString *chars = @"0123456789abcdef";
    for (NSUInteger i = 0; i < length; i++) {
        [str appendFormat:@"%C", (unichar)[chars characterAtIndex:arc4random_uniform((uint32_t)chars.length)]];
    }
    [defaults setObject:str forKey:key];
    [defaults synchronize];
    return str;
}

static NSString *getOrCreateSpoofedSerial(const char *suffix) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = kKey(suffix);
    NSString *existing = [defaults stringForKey:key];
    if (existing) return existing;

    NSString *chars = @"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    NSMutableString *str = [NSMutableString stringWithCapacity:12];
    for (int i = 0; i < 12; i++) {
        [str appendFormat:@"%C", (unichar)[chars characterAtIndex:arc4random_uniform((uint32_t)chars.length)]];
    }
    [defaults setObject:str forKey:key];
    [defaults synchronize];
    return str;
}

static NSString *getOrCreateSpoofedDeviceName(const char *suffix) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = kKey(suffix);
    NSString *existing = [defaults stringForKey:key];
    if (existing) return existing;

    NSArray *prefixes = @[@"张", @"李", @"王", @"刘", @"陈", @"杨", @"赵", @"黄",
                          @"周", @"吴", @"徐", @"孙", @"马", @"朱", @"胡", @"林",
                          @"何", @"郭", @"高", @"罗", @"郑", @"梁", @"谢", @"宋",
                          @"唐", @"许", @"韩", @"冯", @"邓", @"曹", @"彭", @"曾"];
    NSArray *suffixes = @[@"的 iPhone", @"的 iPhone", @"的 iPhone",
                          @"的iPhone", @"的 iPhone 14", @"的 iPhone 13",
                          @"的 iPhone 15", @"的 iPhone 12"];
    NSString *prefix = prefixes[arc4random_uniform((uint32_t)prefixes.count)];
    NSString *suffix2 = suffixes[arc4random_uniform((uint32_t)suffixes.count)];
    NSString *name = [NSString stringWithFormat:@"%@%@", prefix, suffix2];

    [defaults setObject:name forKey:key];
    [defaults synchronize];
    return name;
}

static NSString *getOrCreateSpoofedMAC(const char *suffix) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = kKey(suffix);
    NSString *existing = [defaults stringForKey:key];
    if (existing) return existing;

    uint8_t firstByte = 0x02 | (arc4random_uniform(64) << 2);
    NSMutableString *mac = [NSMutableString string];
    [mac appendFormat:@"%02x", firstByte];
    for (int i = 1; i < 6; i++) {
        [mac appendString:@":"];
        [mac appendFormat:@"%02x", arc4random_uniform(256)];
    }
    [defaults setObject:mac forKey:key];
    [defaults synchronize];
    return mac;
}

static NSString *getOrCreateSpoofedIP(const char *suffix) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = kKey(suffix);
    NSString *existing = [defaults stringForKey:key];
    if (existing) return existing;

    uint32_t r = arc4random_uniform(100);
    uint8_t subnet;
    if (r < 45) subnet = 1;
    else if (r < 80) subnet = 0;
    else if (r < 90) subnet = 31;
    else subnet = (uint8_t)arc4random_uniform(254) + 1;
    uint8_t host = (uint8_t)arc4random_uniform(253) + 2;

    NSString *ip = [NSString stringWithFormat:@"192.168.%d.%d", subnet, host];
    [defaults setObject:ip forKey:key];
    [defaults synchronize];
    return ip;
}

// ============================================================
// Method hooking helpers
// ============================================================
static void hookInstanceMethod(Class cls, SEL sel, IMP newImp, const char *types) {
    Method method = class_getInstanceMethod(cls, sel);
    if (method) {
        const char *existingTypes = types ?: method_getTypeEncoding(method);
        class_replaceMethod(cls, sel, newImp, existingTypes);
    }
}

static void hookClassMethod(Class cls, SEL sel, IMP newImp, const char *types) {
    Class metaClass = object_getClass(cls);
    Method method = class_getClassMethod(cls, sel);
    if (method) {
        const char *existingTypes = types ?: method_getTypeEncoding(method);
        class_replaceMethod(metaClass, sel, newImp, existingTypes);
    }
}

// ============================================================
// Keychain + Cookie clearing
// ============================================================
static void clearKeychainOnFirstLaunch(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = kKey("kc");
    if ([defaults boolForKey:key]) return;

    NSArray *secItemClasses = @[
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword,
        (__bridge id)kSecClassKey,
        (__bridge id)kSecClassCertificate,
        (__bridge id)kSecClassIdentity
    ];
    for (id secItemClass in secItemClasses) {
        NSDictionary *query = @{(__bridge id)kSecClass: secItemClass};
        SecItemDelete((__bridge CFDictionaryRef)query);
    }
    [defaults setBool:YES forKey:key];
    [defaults synchronize];
}

static void clearSharedCookies(void) {
    NSHTTPCookieStorage *storage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    NSArray *cookies = [[storage cookies] copy];
    for (NSHTTPCookie *cookie in cookies) {
        [storage deleteCookie:cookie];
    }
}

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {
        // --- Initialize spoofed values ---
        _spoofedIDFA = getOrCreateSpoofedUUID("id1");
        _spoofedIDFV = getOrCreateSpoofedUUID("id2");
        _spoofedDeviceName = getOrCreateSpoofedDeviceName("dn");
        _spoofedSerialNumber = getOrCreateSpoofedSerial("sr");
        _spoofedUDID = getOrCreateSpoofedString("ud", 40);
        _spoofedMAC = getOrCreateSpoofedMAC("mc");
        _spoofedLocalIP = getOrCreateSpoofedIP("ip");

        g_initialized = YES;

        // ============================================================
        // 1. IDFA
        // ============================================================
        Class asmClass = objc_getClass("ASIdentifierManager");
        if (asmClass) {
            Method m = class_getInstanceMethod(asmClass, @selector(advertisingIdentifier));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSUUID *(id s) { return _spoofedIDFA; });
                hookInstanceMethod(asmClass, @selector(advertisingIdentifier), imp, method_getTypeEncoding(m));
            }
            m = class_getInstanceMethod(asmClass, @selector(isAdvertisingTrackingEnabled));
            if (m) {
                IMP imp = imp_implementationWithBlock(^BOOL(id s) { return YES; });
                hookInstanceMethod(asmClass, @selector(isAdvertisingTrackingEnabled), imp, method_getTypeEncoding(m));
            }
        }

        // ============================================================
        // 2. ATTrackingManager
        // ============================================================
        Class attClass = objc_getClass("ATTrackingManager");
        if (attClass) {
            Method m = class_getClassMethod(attClass, @selector(trackingAuthorizationStatus));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSInteger(id s) { return 3; });
                hookClassMethod(attClass, @selector(trackingAuthorizationStatus), imp, method_getTypeEncoding(m));
            }
            m = class_getClassMethod(attClass, @selector(requestTrackingAuthorizationWithCompletionHandler:));
            if (m) {
                IMP imp = imp_implementationWithBlock(^(id s, void (^h)(NSInteger)) {
                    if (h) dispatch_async(dispatch_get_main_queue(), ^{ h(3); });
                });
                hookClassMethod(attClass, @selector(requestTrackingAuthorizationWithCompletionHandler:), imp, method_getTypeEncoding(m));
            }
        }

        // ============================================================
        // 3. IDFV + device name
        // ============================================================
        Class uiDeviceClass = objc_getClass("UIDevice");
        if (uiDeviceClass) {
            Method m = class_getInstanceMethod(uiDeviceClass, @selector(identifierForVendor));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSUUID *(id s) { return _spoofedIDFV; });
                hookInstanceMethod(uiDeviceClass, @selector(identifierForVendor), imp, method_getTypeEncoding(m));
            }
            m = class_getInstanceMethod(uiDeviceClass, @selector(name));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSString *(id s) { return _spoofedDeviceName; });
                hookInstanceMethod(uiDeviceClass, @selector(name), imp, method_getTypeEncoding(m));
            }
        }

        // ============================================================
        // 4. UIPasteboard — block ALL reads
        // ============================================================
        Class pbClass = objc_getClass("UIPasteboard");
        if (pbClass) {
            Method m = class_getInstanceMethod(pbClass, @selector(string));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @""; });
                hookInstanceMethod(pbClass, @selector(string), imp, method_getTypeEncoding(m));
            }
            m = class_getInstanceMethod(pbClass, @selector(strings));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSArray *(id s) { return @[]; });
                hookInstanceMethod(pbClass, @selector(strings), imp, method_getTypeEncoding(m));
            }
            m = class_getInstanceMethod(pbClass, @selector(dataForPasteboardType:));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSData *(id s, NSString *t) { return nil; });
                hookInstanceMethod(pbClass, @selector(dataForPasteboardType:), imp, method_getTypeEncoding(m));
            }
            m = class_getInstanceMethod(pbClass, @selector(valueForPasteboardType:));
            if (m) {
                IMP imp = imp_implementationWithBlock(^id(id s, NSString *t) { return nil; });
                hookInstanceMethod(pbClass, @selector(valueForPasteboardType:), imp, method_getTypeEncoding(m));
            }
            m = class_getInstanceMethod(pbClass, @selector(items));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSArray *(id s) { return @[]; });
                hookInstanceMethod(pbClass, @selector(items), imp, method_getTypeEncoding(m));
            }
            m = class_getInstanceMethod(pbClass, @selector(containsPasteboardTypes:));
            if (m) {
                IMP imp = imp_implementationWithBlock(^BOOL(id s, NSArray *t) { return NO; });
                hookInstanceMethod(pbClass, @selector(containsPasteboardTypes:), imp, method_getTypeEncoding(m));
            }
        }

        // ============================================================
        // 5. Keychain clear on first launch
        // ============================================================
        clearKeychainOnFirstLaunch();

        // ============================================================
        // 6. Clear shared cookies
        // ============================================================
        clearSharedCookies();

        // NOTE: bundleIdentifier, canOpenURL, and app group hooks REMOVED.
        // The bundleIdentifier hook created a mismatch between the runtime
        // bundleIdentifier (returning original com.baidu.BaiduMobile) and
        // infoDictionary[@"CFBundleIdentifier"] (returning the real modified
        // Bundle ID). Payment SDKs compare these two values and detect the
        // mismatch as "non-genuine app". Without the hook, both values are
        // consistent (com.baidu.BaiduMobile.BaiduBoxAppA1), which the payment
        // SDK accepts.
    }
}

// ============================================================
// DYLD Interposing for C functions
// ============================================================
typedef struct {
    const void *replacement;
    const void *original;
} interpose_t;

// Interposed sysctlbyname — with nil safety
static int interposed_sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                                    void *newp, size_t newlen) {
    if (name && g_initialized && oldp && oldlenp) {
        NSString *nsName = [NSString stringWithUTF8String:name];

        if ([nsName isEqualToString:@"hw.serialnumber"]) {
            const char *serial = [_spoofedSerialNumber UTF8String];
            if (serial) {
                size_t len = strlen(serial) + 1;
                if (*oldlenp >= len) {
                    memcpy(oldp, serial, len);
                    *oldlenp = len - 1;
                    return 0;
                }
            }
        }

        if ([nsName isEqualToString:@"hw.uuid"]) {
            const char *uuid = [_spoofedUDID UTF8String];
            if (uuid) {
                size_t len = strlen(uuid) + 1;
                if (*oldlenp >= len) {
                    memcpy(oldp, uuid, len);
                    *oldlenp = len - 1;
                    return 0;
                }
            }
        }
    }
    return sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

// Interposed getifaddrs — with nil safety
static int interposed_getifaddrs(struct ifaddrs **ifap) {
    int result = getifaddrs(ifap);
    if (result == 0 && ifap && *ifap && g_initialized) {
        struct ifaddrs *ifa = *ifap;
        while (ifa) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_LINK) {
                struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
                if (sdl->sdl_alen > 0 && _spoofedMAC) {
                    char *macBytes = (char *)(sdl->sdl_data + sdl->sdl_nlen);
                    const char *spoofedMAC = [_spoofedMAC UTF8String];
                    unsigned int mac[6];
                    if (sscanf(spoofedMAC, "%x:%x:%x:%x:%x:%x",
                               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
                        for (int i = 0; i < 6 && i < sdl->sdl_alen; i++) {
                            macBytes[i] = (char)mac[i];
                        }
                    }
                }
            }
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
                if (sin->sin_addr.s_addr != htonl(INADDR_LOOPBACK) && sin->sin_addr.s_addr != 0 && _spoofedLocalIP) {
                    const char *ipStr = [_spoofedLocalIP UTF8String];
                    struct in_addr addr;
                    if (inet_pton(AF_INET, ipStr, &addr) == 1) {
                        sin->sin_addr = addr;
                    }
                }
            }
            ifa = ifa->ifa_next;
        }
    }
    return result;
}

// ============================================================
// Interpose arrays
// ============================================================
__attribute__((used))
static const interpose_t _interpose_sysctlbyname
__attribute__((section("__DATA,__interpose"))) = {
    (const void *)interposed_sysctlbyname,
    (const void *)sysctlbyname
};

__attribute__((used))
static const interpose_t _interpose_getifaddrs
__attribute__((section("__DATA,__interpose"))) = {
    (const void *)interposed_getifaddrs,
    (const void *)getifaddrs
};
