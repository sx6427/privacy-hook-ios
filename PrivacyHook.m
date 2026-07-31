//
// PrivacyHook.m — v15: v13 + image-scoped fishhook (find main binary by name)
//
// Fishhook only rebinds stat/lstat/access in the MAIN BINARY (BaiduBoxApp)
// Found by iterating _dyld_image_count and matching name, NOT image[0]
// All other hooks are ObjC (safe)
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <sys/stat.h>
#import <unistd.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>

#include "fishhook.h"

#define NSLog(...)

static __thread BOOL g_inCookieHook = NO;
static NSString *const kOrigBundleID = @"com.baidu.BaiduMobile";

// ============================================================
// Persistent fake IDs
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
        NSString *num = [NSString stringWithFormat:@"%llu", (unsigned long long)(arc4random_uniform(900000000U) + 100000000U)];
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
// Cookie helpers
// ============================================================
static BOOL isDeviceCookie(NSString *cookieName) {
    if (!cookieName) return NO;
    NSString *lk = [cookieName lowercaseString];
    NSArray *names = @[@"baiducuid", @"baiducuid_bfess", @"mawebcuid",
                       @"dvif", @"tcuid", @"__bid_n", @"fuid", @"cuid"];
    for (NSString *n in names) { if ([lk isEqualToString:n]) return YES; }
    return NO;
}

static NSHTTPCookie *modifiedCookie(NSHTTPCookie *cookie) {
    if (!isDeviceCookie(cookie.name)) return cookie;
    NSString *fakeValue = getFakeID(cookie.name);
    NSMutableDictionary *props = [NSMutableDictionary dictionary];
    props[NSHTTPCookieName] = cookie.name;
    props[NSHTTPCookieValue] = fakeValue;
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
    for (NSHTTPCookie *cookie in cookies) { [result addObject:modifiedCookie(cookie)]; }
    return result;
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
// Jailbreak path check (C string version)
// ============================================================
static BOOL isJailbreakPathC(const char *path) {
    if (!path) return NO;
    static const char *jbPaths[] = {
        "/bin/bash", "/bin/sh", "/usr/sbin/sshd", "/etc/apt", "/etc/ssh/sshd_config",
        "/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/usr/libexec/sftp-server", "/usr/libexec/ssh-keysign",
        "/usr/libexec/cydia/", "/usr/sbin/frida-server", "/usr/bin/cycript",
        "/private/var/lib/cydia", "/private/var/lib/apt", "/private/var/tmp/cydia.log",
        "/private/etc/apt", "/private/etc/ssh/sshd_config",
        "/Applications/WinterBoard.app", "/Applications/SBSetttings.app",
        "/Applications/IntelliScreen.app", "/Applications/FakeCarrier.app",
        "/private/var/stash", "/var/lib/cydia", "/var/lib/apt", "/var/cache/apt",
        "/private/bdpan_jailbreak_test",
        "/var/jb", "/var/jb/",
        "/Applications/TrollStore.app",
        "/usr/lib/TweakInject", "/usr/lib/libhooker", "/usr/lib/substitute",
        NULL
    };
    for (int i = 0; jbPaths[i] != NULL; i++) {
        if (strcmp(path, jbPaths[i]) == 0) return YES;
    }
    if (strstr(path, "MobileSubstrate") != NULL) return YES;
    if (strstr(path, "TweakInject") != NULL) return YES;
    if (strstr(path, "/var/jb/") != NULL) return YES;
    if (strstr(path, "frida") != NULL) return YES;
    return NO;
}

// ObjC version
static BOOL isJailbreakPath(NSString *path) {
    if (!path) return NO;
    static NSArray *jbPaths = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        jbPaths = @[
            @"/bin/bash", @"/bin/sh", @"/usr/sbin/sshd", @"/etc/apt", @"/etc/ssh/sshd_config",
            @"/Applications/Cydia.app", @"/Applications/Sileo.app", @"/Applications/Zebra.app",
            @"/Library/MobileSubstrate/MobileSubstrate.dylib",
            @"/usr/libexec/sftp-server", @"/usr/libexec/ssh-keysign",
            @"/usr/libexec/cydia/", @"/usr/sbin/frida-server", @"/usr/bin/cycript",
            @"/private/var/lib/cydia", @"/private/var/lib/apt", @"/private/var/tmp/cydia.log",
            @"/private/etc/apt", @"/private/etc/ssh/sshd_config",
            @"/Applications/WinterBoard.app", @"/Applications/SBSetttings.app",
            @"/Applications/IntelliScreen.app", @"/Applications/FakeCarrier.app",
            @"/private/var/stash", @"/var/lib/cydia", @"/var/lib/apt", @"/var/cache/apt",
            @"/private/bdpan_jailbreak_test",
            @"/var/jb", @"/var/jb/",
            @"/Applications/TrollStore.app",
            @"/usr/lib/TweakInject", @"/usr/lib/libhooker", @"/usr/lib/substitute"
        ];
    });
    for (NSString *jb in jbPaths) {
        if ([path isEqualToString:jb]) return YES;
    }
    if ([path containsString:@"MobileSubstrate"]) return YES;
    if ([path containsString:@"TweakInject"]) return YES;
    if ([path containsString:@"/var/jb/"]) return YES;
    if ([path containsString:@"frida"]) return YES;
    return NO;
}

// ============================================================
// C function hooks via fishhook — with NULL guard
// ============================================================
static int (*orig_stat)(const char *, struct stat *) = NULL;
static int hook_stat(const char *path, struct stat *buf) {
    if (!path) { return orig_stat ? orig_stat("", buf) : -1; }
    if (isJailbreakPathC(path)) { errno = ENOENT; return -1; }
    if (!orig_stat) { errno = ENOENT; return -1; }
    return orig_stat(path, buf);
}

static int (*orig_lstat)(const char *, struct stat *) = NULL;
static int hook_lstat(const char *path, struct stat *buf) {
    if (!path) { return orig_lstat ? orig_lstat("", buf) : -1; }
    if (isJailbreakPathC(path)) { errno = ENOENT; return -1; }
    if (!orig_lstat) { errno = ENOENT; return -1; }
    return orig_lstat(path, buf);
}

static int (*orig_access)(const char *, int) = NULL;
static int hook_access(const char *path, int mode) {
    if (!path) { return orig_access ? orig_access("", mode) : -1; }
    if (isJailbreakPathC(path)) { errno = ENOENT; return -1; }
    if (!orig_access) { errno = ENOENT; return -1; }
    return orig_access(path, mode);
}

// ============================================================
// Find main binary image by name
// ============================================================
static void rebindMainBinaryOnly(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        // Match the main executable: .../BaiduBoxApp.app/BaiduBoxApp
        // NOT a framework, NOT a dylib
        if (strstr(name, "/BaiduBoxApp.app/BaiduBoxApp") != NULL) {
            const struct mach_header *header = _dyld_get_image_header(i);
            intptr_t slide = _dyld_get_image_vmaddr_slide(i);
            if (header) {
                rebind_symbols_image((void *)header, slide,
                    (struct rebinding[]){
                        {"stat", (void *)hook_stat, (void **)&orig_stat},
                        {"lstat", (void *)hook_lstat, (void **)&orig_lstat},
                        {"access", (void *)hook_access, (void **)&orig_access},
                    }, 3);
            }
            return;
        }
    }
}

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {

        // ---- 0. Fishhook: stat/lstat/access ONLY in main binary ----
        @try { rebindMainBinaryOnly(); } @catch (id e) {}

        // ---- 1. Clear keychain EVERY launch ----
        @try { clearKeychain(); } @catch (id e) {}

        // ---- 2. Bundle ID hook (3 methods) ----
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

        // ---- 3. UIDevice hooks ----
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

        // ---- 4. ASIdentifierManager IDFA hook ----
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

        // ---- 5. NSHTTPCookieStorage hooks ----
        @try {
            Class cs = objc_getClass("NSHTTPCookieStorage");
            if (cs) {
                Method cfuM = class_getInstanceMethod(cs, @selector(cookiesForURL:));
                if (cfuM) {
                    IMP origCFU = method_getImplementation(cfuM);
                    IMP newCFU = imp_implementationWithBlock(^NSArray *(id s, NSURL *url) {
                        NSArray *cookies = ((NSArray *(*)(id, SEL, NSURL *))origCFU)(s, @selector(cookiesForURL:), url);
                        if (g_inCookieHook) return cookies;
                        g_inCookieHook = YES;
                        @try { NSArray *m = modifiedCookies(cookies); g_inCookieHook = NO; return m; }
                        @catch (id e) { g_inCookieHook = NO; return cookies; }
                    });
                    class_replaceMethod(cs, @selector(cookiesForURL:), newCFU, method_getTypeEncoding(cfuM));
                }
                Method allM = class_getInstanceMethod(cs, @selector(cookies));
                if (allM) {
                    IMP origAll = method_getImplementation(allM);
                    IMP newAll = imp_implementationWithBlock(^NSArray *(id s) {
                        NSArray *cookies = ((NSArray *(*)(id, SEL))origAll)(s, @selector(cookies));
                        if (g_inCookieHook) return cookies;
                        g_inCookieHook = YES;
                        @try { NSArray *m = modifiedCookies(cookies); g_inCookieHook = NO; return m; }
                        @catch (id e) { g_inCookieHook = NO; return cookies; }
                    });
                    class_replaceMethod(cs, @selector(cookies), newAll, method_getTypeEncoding(allM));
                }
                Method scM = class_getInstanceMethod(cs, @selector(setCookie:));
                if (scM) {
                    IMP origSC = method_getImplementation(scM);
                    IMP newSC = imp_implementationWithBlock(^void(id s, NSHTTPCookie *cookie) {
                        NSHTTPCookie *mc = g_inCookieHook ? cookie : modifiedCookie(cookie);
                        ((void (*)(id, SEL, NSHTTPCookie *))origSC)(s, @selector(setCookie:), mc);
                    });
                    class_replaceMethod(cs, @selector(setCookie:), newSC, method_getTypeEncoding(scM));
                }
                Method scfM = class_getInstanceMethod(cs, @selector(setCookies:forURL:mainDocumentURL:));
                if (scfM) {
                    IMP origSCF = method_getImplementation(scfM);
                    IMP newSCF = imp_implementationWithBlock(^void(id s, NSArray *cookies, NSURL *url, NSURL *mainDocURL) {
                        NSArray *mc = g_inCookieHook ? cookies : modifiedCookies(cookies);
                        ((void (*)(id, SEL, NSArray *, NSURL *, NSURL *))origSCF)(s, @selector(setCookies:forURL:mainDocumentURL:), mc, url, mainDocURL);
                    });
                    class_replaceMethod(cs, @selector(setCookies:forURL:mainDocumentURL:), newSCF, method_getTypeEncoding(scfM));
                }
            }
        } @catch (id e) {}

        // ---- 6. NSFileManager hook for fileExistsAtPath ----
        @try {
            Class fm = objc_getClass("NSFileManager");
            if (fm) {
                Method feM = class_getInstanceMethod(fm, @selector(fileExistsAtPath:));
                if (feM) {
                    IMP origFE = method_getImplementation(feM);
                    IMP newFE = imp_implementationWithBlock(^BOOL(id s, NSString *path) {
                        if (isJailbreakPath(path)) return NO;
                        return ((BOOL (*)(id, SEL, NSString *))origFE)(s, @selector(fileExistsAtPath:), path);
                    });
                    class_replaceMethod(fm, @selector(fileExistsAtPath:), newFE, method_getTypeEncoding(feM));
                }
                Method feaM = class_getInstanceMethod(fm, @selector(fileExistsAtPath:isDirectory:));
                if (feaM) {
                    IMP origFEA = method_getImplementation(feaM);
                    IMP newFEA = imp_implementationWithBlock(^BOOL(id s, NSString *path, BOOL *isDir) {
                        if (isJailbreakPath(path)) return NO;
                        return ((BOOL (*)(id, SEL, NSString *, BOOL *))origFEA)(s, @selector(fileExistsAtPath:isDirectory:), path, isDir);
                    });
                    class_replaceMethod(fm, @selector(fileExistsAtPath:isDirectory:), newFEA, method_getTypeEncoding(feaM));
                }
                Method aM = class_getInstanceMethod(fm, @selector(attributesOfItemAtPath:error:));
                if (aM) {
                    IMP origA = method_getImplementation(aM);
                    IMP newA = imp_implementationWithBlock(^NSDictionary *(id s, NSString *path, NSError **error) {
                        if (isJailbreakPath(path)) {
                            if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
                            return nil;
                        }
                        return ((NSDictionary *(*)(id, SEL, NSString *, NSError **))origA)(s, @selector(attributesOfItemAtPath:error:), path, error);
                    });
                    class_replaceMethod(fm, @selector(attributesOfItemAtPath:error:), newA, method_getTypeEncoding(aM));
                }
            }
        } @catch (id e) {}

        // ---- 7. NSProcessInfo hook for environment ----
        @try {
            Class pi = objc_getClass("NSProcessInfo");
            if (pi) {
                Method envM = class_getInstanceMethod(pi, @selector(environment));
                if (envM) {
                    IMP origEnv = method_getImplementation(envM);
                    IMP newEnv = imp_implementationWithBlock(^NSDictionary *(id s) {
                        NSDictionary *env = ((NSDictionary *(*)(id, SEL))origEnv)(s, @selector(environment));
                        NSMutableDictionary *md = [NSMutableDictionary dictionaryWithDictionary:env];
                        [md removeObjectForKey:@"DYLD_INSERT_LIBRARIES"];
                        [md removeObjectForKey:@"DYLD_LIBRARY_PATH"];
                        [md removeObjectForKey:@"DYLD_FRAMEWORK_PATH"];
                        [md removeObjectForKey:@"_MSSafeMode"];
                        return md;
                    });
                    class_replaceMethod(pi, @selector(environment), newEnv, method_getTypeEncoding(envM));
                }
            }
        } @catch (id e) {}
    }
}
