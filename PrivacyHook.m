//
// PrivacyHook.m — v11: Step33 + Cookie spoof + jailbreak detection bypass
//
// Hook file existence checks for jailbreak paths
// Hook stat/access for jailbreak paths
// Hook _dyld_get_image_name to hide our dylib (with thread-local guard)
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <sys/stat.h>
#import <unistd.h>

#include "fishhook.h"

#define NSLog(...)

static __thread BOOL g_inCookieHook = NO;
static __thread int g_dyldDepth = 0;
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
// JAILBREAK DETECTION BYPASS
// ============================================================

// Paths that indicate jailbreak/TrollStore/injection
static BOOL isJailbreakPath(const char *path) {
    if (!path) return NO;
    // Exact path checks for known jailbreak files
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
        "/var/jb/", "/var/jb",
        "/Applications/TrollStore.app",
        "/usr/lib/TweakInject", "/usr/lib/libhooker", "/usr/lib/substitute",
        NULL
    };
    for (int i = 0; jbPaths[i] != NULL; i++) {
        if (strcmp(path, jbPaths[i]) == 0) return YES;
    }
    // Prefix checks
    if (strstr(path, "/Library/MobileSubstrate") != NULL) return YES;
    if (strstr(path, "MobileSubstrate") != NULL) return YES;
    if (strstr(path, "TweakInject") != NULL) return YES;
    if (strstr(path, "/var/jb/") != NULL) return YES;
    if (strstr(path, "frida") != NULL) return YES;
    return NO;
}

// Hook stat / lstat / access / fopen for jailbreak paths
static int (*orig_stat)(const char *, struct stat *) = NULL;
static int hook_stat(const char *path, struct stat *buf) {
    if (isJailbreakPath(path)) { errno = ENOENT; return -1; }
    return orig_stat(path, buf);
}

static int (*orig_lstat)(const char *, struct stat *) = NULL;
static int hook_lstat(const char *path, struct stat *buf) {
    if (isJailbreakPath(path)) { errno = ENOENT; return -1; }
    return orig_lstat(path, buf);
}

static int (*orig_access)(const char *, int) = NULL;
static int hook_access(const char *path, int mode) {
    if (isJailbreakPath(path)) { errno = ENOENT; return -1; }
    return orig_access(path, mode);
}

static FILE *(*orig_fopen)(const char *, const char *) = NULL;
static FILE *hook_fopen(const char *path, const char *mode) {
    if (isJailbreakPath(path)) { errno = ENOENT; return NULL; }
    return orig_fopen(path, mode);
}

// Hook getenv for DYLD_INSERT_LIBRARIES
static char *(*orig_getenv)(const char *) = NULL;
static char *hook_getenv(const char *name) {
    if (name) {
        if (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0) return NULL;
        if (strcmp(name, "DYLD_LIBRARY_PATH") == 0) return NULL;
        if (strcmp(name, "DYLD_FRAMEWORK_PATH") == 0) return NULL;
        if (strcmp(name, "_MSSafeMode") == 0) return NULL;
    }
    return orig_getenv(name);
}

// Hook _dyld_get_image_name to hide our dylib
// Use depth counter to prevent recursion (system code calls this too)
static const char *(*orig_dyld_get_image_name)(uint32_t) = NULL;
static const char *hook_dyld_get_image_name(uint32_t image_index) {
    g_dyldDepth++;
    const char *name = orig_dyld_get_image_name ? orig_dyld_get_image_name(image_index) : NULL;
    g_dyldDepth--;
    if (name && g_dyldDepth == 0) {
        // Only hide when called from app code (depth == 0 means top-level call)
        if (strstr(name, "BaiduBoxSys") != NULL || strstr(name, "PrivacyHook") != NULL) {
            // Return a benign system library name
            return "/usr/lib/libSystem.B.dylib";
        }
    }
    return name;
}

// Code signature bypass
static OSStatus (*orig_SecStaticCodeCheckValidity)(void *, uint32_t, CFDictionaryRef) = NULL;
static OSStatus hook_SecStaticCodeCheckValidity(void *code, uint32_t flags, CFDictionaryRef requirements) {
    return 0;
}

static OSStatus (*orig_SecCodeCheckValidity)(void *, uint32_t, CFDictionaryRef) = NULL;
static OSStatus hook_SecCodeCheckValidity(void *code, uint32_t flags, CFDictionaryRef requirements) {
    return 0;
}

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {

        // ---- 0. Fishhook: C function hooks ----
        @try {
            rebind_symbols((struct rebinding[]){
                {"stat", (void *)hook_stat, (void **)&orig_stat},
                {"lstat", (void *)hook_lstat, (void **)&orig_lstat},
                {"access", (void *)hook_access, (void **)&orig_access},
                {"fopen", (void *)hook_fopen, (void **)&orig_fopen},
                {"getenv", (void *)hook_getenv, (void **)&orig_getenv},
                {"_dyld_get_image_name", (void *)hook_dyld_get_image_name, (void **)&orig_dyld_get_image_name},
                {"SecStaticCodeCheckValidity", (void *)hook_SecStaticCodeCheckValidity, (void **)&orig_SecStaticCodeCheckValidity},
                {"SecCodeCheckValidity", (void *)hook_SecCodeCheckValidity, (void **)&orig_SecCodeCheckValidity},
            }, 8);
        } @catch (id e) {}

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

        // ---- 6. NSFileManager hook for fileExistsAtPath (jailbreak paths) ----
        @try {
            Class fm = objc_getClass("NSFileManager");
            if (fm) {
                Method feM = class_getInstanceMethod(fm, @selector(fileExistsAtPath:));
                if (feM) {
                    IMP origFE = method_getImplementation(feM);
                    IMP newFE = imp_implementationWithBlock(^BOOL(id s, NSString *path) {
                        if (path) {
                            const char *cpath = [path UTF8String];
                            if (isJailbreakPath(cpath)) return NO;
                        }
                        return ((BOOL (*)(id, SEL, NSString *))origFE)(s, @selector(fileExistsAtPath:), path);
                    });
                    class_replaceMethod(fm, @selector(fileExistsAtPath:), newFE, method_getTypeEncoding(feM));
                }
                Method feaM = class_getInstanceMethod(fm, @selector(fileExistsAtPath:isDirectory:));
                if (feaM) {
                    IMP origFEA = method_getImplementation(feaM);
                    IMP newFEA = imp_implementationWithBlock(^BOOL(id s, NSString *path, BOOL *isDir) {
                        if (path) {
                            const char *cpath = [path UTF8String];
                            if (isJailbreakPath(cpath)) return NO;
                        }
                        return ((BOOL (*)(id, SEL, NSString *, BOOL *))origFEA)(s, @selector(fileExistsAtPath:isDirectory:), path, isDir);
                    });
                    class_replaceMethod(fm, @selector(fileExistsAtPath:isDirectory:), newFEA, method_getTypeEncoding(feaM));
                }
            }
        } @catch (id e) {}
    }
}
