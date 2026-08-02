//
// PrivacyHook.m — v43: Multi-instance without CUID replacement
//
// ROOT CAUSE (CONFIRMED): Replacing CUID with random values while keeping
//   the same BDUSS (login token) caused Baidu to flag the account.
//   CUID and BDUSS are linked server-side. Changing CUID = account theft
//   signal → risk control → "下单人数过多".
//
// v43 FIX: DON'T touch CUID/BAIDUID at all!
//   1. Change device fingerprint (model, OS version, IDFV, IDFA) → app generates different CUID naturally
//   2. Keychain is isolated by bundle ID change → each instance has own CUID/BAIDUID
//   3. Each instance uses a DIFFERENT Baidu account
//   4. Keep anti-jailbreak + anti-injection detection hiding
//   5. NO Keychain wiping, NO Cookie wiping, NO CUID replacement
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
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
// Persistent fake IDs — keyed to REAL bundle ID (per instance)
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

static NSString *getFakeMachine(void) {
    return getPersistent(@"Bdhk.hwmodel", ^{
        NSArray *models = @[@"iPhone14,5", @"iPhone14,7", @"iPhone15,2", @"iPhone15,3", @"iPhone13,2", @"iPhone12,1"];
        return models[arc4random_uniform((uint32_t)models.count)];
    });
}

// ============================================================
// Anti-jailbreak: Hook access/stat/lstat to hide jailbreak files
// ============================================================
static int (*orig_access)(const char *, int) = NULL;
static int hooked_access(const char *path, int mode) {
    if (!orig_access) return -1;
    if (path) {
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
// Anti-injection: Hide our dylib from all detection methods
// ============================================================
static BOOL shouldHideImageName(const char *name) {
    if (!name) return NO;
    if (strstr(name, "PrivacyHook") || strstr(name, "BaiduBoxSys")) return YES;
    return NO;
}

static const char *getFakeImageName(void) {
    return "/System/Library/Frameworks/Foundation.framework/Foundation";
}

static const char *(*orig_dyld_get_image_name)(uint32_t) = NULL;
static const char *hooked_dyld_get_image_name(uint32_t image_index) {
    if (!orig_dyld_get_image_name) return NULL;
    const char *name = orig_dyld_get_image_name(image_index);
    if (shouldHideImageName(name)) return getFakeImageName();
    return name;
}

static int (*orig_dladdr)(const void *, Dl_info *) = NULL;
static int hooked_dladdr(const void *addr, Dl_info *info) {
    if (!orig_dladdr) return 0;
    int ret = orig_dladdr(addr, info);
    if (ret != 0 && info && info->dli_fname) {
        if (shouldHideImageName(info->dli_fname)) {
            info->dli_fname = getFakeImageName();
            info->dli_sname = NULL;
            info->dli_saddr = NULL;
        }
    }
    return ret;
}

static char *(*orig_getenv)(const char *) = NULL;
static char *hooked_getenv(const char *name) {
    if (!orig_getenv) return NULL;
    if (name && (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0 ||
                 strcmp(name, "_MSSafeMode") == 0 ||
                 strcmp(name, "MSDebugFilter") == 0)) {
        return NULL;
    }
    return orig_getenv(name);
}

static const char *(*orig_class_getImageName)(Class) = NULL;
static const char *hooked_class_getImageName(Class cls) {
    if (!orig_class_getImageName) return NULL;
    const char *name = orig_class_getImageName(cls);
    if (shouldHideImageName(name)) return getFakeImageName();
    return name;
}

// REMOVED v43.1: task_info/objc_copyImageNames/_dyld_image_count hooks
// caused crashes (modifying kernel memory in task_info) → no network.

// ============================================================
// Fishhook: sysctlbyname + uname (device fingerprint)
// ============================================================
static char g_fakeMachine[32] = {0};
static char g_fakeRelease[32] = {0};
static char g_fakeVersion[32] = {0};

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
static int hooked_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (!orig_sysctlbyname) return -1;
    if (name && strcmp(name, "hw.machine") == 0) {
        if (oldp && oldlenp && *oldlenp >= strlen(g_fakeMachine) + 1) {
            strcpy((char *)oldp, g_fakeMachine);
            *oldlenp = strlen(g_fakeMachine);
            return 0;
        }
        if (oldlenp) *oldlenp = strlen(g_fakeMachine);
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
// Constructor
// ============================================================
__attribute__((constructor)) static void PrivacyHookConstructor(void) {
    @autoreleasepool {
        // ---- 0. Read REAL bundle ID (for per-instance persistent storage) ----
        @try {
            NSDictionary *d = [[NSBundle mainBundle] infoDictionary];
            g_realBundleID = d[@"CFBundleIdentifier"];
            if (!g_realBundleID) g_realBundleID = kOrigBundleID;
        } @catch (id e) {}

        // ---- 1. Generate persistent fake device fingerprint ----
        @try {
            NSString *fakeMachine = getFakeMachine();
            NSString *fakeVersion = getPersistent(@"Bdhk.sv", ^{ return genFakeSystemVersion(); });

            strncpy(g_fakeMachine, [fakeMachine UTF8String], sizeof(g_fakeMachine) - 1);
            strncpy(g_fakeRelease, [[NSString stringWithFormat:@"Darwin Kernel Version %@", fakeVersion] UTF8String], sizeof(g_fakeRelease) - 1);
            strncpy(g_fakeVersion, [fakeVersion UTF8String], sizeof(g_fakeVersion) - 1);
        } @catch (id e) {}

        // ---- 2. Fishhook: device fingerprint + anti-injection + anti-jailbreak ----
        @try {
            struct rebinding rebindings[] = {
                {"sysctlbyname",          (void *)hooked_sysctlbyname,          (void **)&orig_sysctlbyname},
                {"uname",                 (void *)hooked_uname,                 (void **)&orig_uname},
                // Anti-injection: hide our dylib
                {"_dyld_get_image_name",  (void *)hooked_dyld_get_image_name,  (void **)&orig_dyld_get_image_name},
                {"dladdr",                (void *)hooked_dladdr,                (void **)&orig_dladdr},
                {"getenv",                (void *)hooked_getenv,                (void **)&orig_getenv},
                {"class_getImageName",    (void *)hooked_class_getImageName,    (void **)&orig_class_getImageName},
                // Anti-jailbreak: hide jailbreak files
                {"access",                (void *)hooked_access,                (void **)&orig_access},
                {"stat",                  (void *)hooked_stat,                  (void **)&orig_stat},
                {"lstat",                 (void *)hooked_lstat,                 (void **)&orig_lstat},
            };

            // Hook in ALL non-system images
            unsigned int imageCount = 0;
            const char **imageNames = objc_copyImageNames(&imageCount);
            for (unsigned int i = 0; i < imageCount; i++) {
                const char *name = imageNames[i];
                if (!name) continue;
                NSString *ns = [NSString stringWithUTF8String:name];
                if ([ns containsString:@"/System/"] || [ns containsString:@"/Library/"]) continue;
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

        // ---- 3. Bundle ID hook (payment compatibility) ----
        @try {
            Class bc = objc_getClass("NSBundle");
            if (bc) {
                Method bm = class_getInstanceMethod(bc, @selector(bundleIdentifier));
                if (bm) {
                    IMP origBI = method_getImplementation(bm);
                    IMP newBI = imp_implementationWithBlock(^NSString *(id s) {
                        if ([s isEqual:[NSBundle mainBundle]]) return kOrigBundleID;
                        return ((NSString *(*)(id, SEL))origBI)(s, @selector(bundleIdentifier));
                    });
                    class_replaceMethod(bc, @selector(bundleIdentifier), newBI, method_getTypeEncoding(bm));
                }
            }
        } @catch (id e) {}

        // ---- 4. UIDevice hooks (systemVersion, name, IDFV, model) ----
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

        // ---- 5. IDFA hook ----
        @try {
            Class ac = objc_getClass("ASIdentifierManager");
            if (ac) {
                Method m = class_getInstanceMethod(ac, @selector(advertisingIdentifier));
                if (m) { IMP imp = imp_implementationWithBlock(^NSUUID *(id s) { return [[NSUUID alloc] initWithUUIDString:getPersistent(@"Bdhk.ai", ^{ return genUUIDStr(); })]; }); class_replaceMethod(ac, @selector(advertisingIdentifier), imp, method_getTypeEncoding(m)); }
            }
        } @catch (id e) {}

        // ---- 6. Device model hooks ----
        @try {
            Class cls = objc_getClass("DMDeviceInfoWrapper");
            if (cls) {
                Method m = class_getClassMethod(cls, @selector(deviceModel));
                if (m) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return getFakeMachine(); }); class_replaceMethod(object_getClass(cls), @selector(deviceModel), imp, method_getTypeEncoding(m)); }
                m = class_getClassMethod(cls, @selector(systemVersion));
                if (m) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return getPersistent(@"Bdhk.sv", ^{ return genFakeSystemVersion(); }); }); class_replaceMethod(object_getClass(cls), @selector(systemVersion), imp, method_getTypeEncoding(m)); }
            }
            Class cls2 = objc_getClass("BIMDeviceInfoUtility");
            if (cls2) {
                Method m = class_getInstanceMethod(cls2, @selector(deviceModelVersion));
                if (m) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return getFakeMachine(); }); class_replaceMethod(cls2, @selector(deviceModelVersion), imp, method_getTypeEncoding(m)); }
            }
        } @catch (id e) {}

        // ---- 7. Anti-jailbreak/hook detection method hooks ----
        @try {
            // BDPanJailbreakDetectTool
            Class jbDetect = objc_getClass("BDPanJailbreakDetectTool");
            if (jbDetect) {
                unsigned int methodCount = 0;
                Method *methods = class_copyMethodList(jbDetect, &methodCount);
                for (unsigned int i = 0; i < methodCount; i++) {
                    SEL sel = method_getName(methods[i]);
                    const char *typeEnc = method_getTypeEncoding(methods[i]);
                    if (typeEnc[0] == 'B') {
                        IMP imp = imp_implementationWithBlock(^BOOL(id s) { return NO; });
                        class_replaceMethod(jbDetect, sel, imp, typeEnc);
                    } else {
                        IMP imp = imp_implementationWithBlock(^id(id s) { return nil; });
                        class_replaceMethod(jbDetect, sel, imp, typeEnc);
                    }
                }
                free(methods);
            }

            // Hook all jailbreak/tamper/hook detection selectors
            unsigned int classCount = 0;
            Class *classes = objc_copyClassList(&classCount);
            NSArray *antiDetectSelectors = @[
                @"IsValidate_hookDetection", @"preventingTampering",
                @"use_jailbreak_detect_tool", @"jailbreakDetectToolType",
                @"enableBDPTraceSwizzlingMethod",
                @"isJailbroken", @"isJailBreak", @"jailbroken", @"hasJailbreak",
                @"detectJailbreak", @"checkJailbreak",
                @"isHooked", @"hookDetect", @"detectHook", @"checkHook",
                @"isTampered", @"tamperDetect", @"detectTamper", @"checkTamper",
                @"isInjected", @"injectDetect", @"detectInject", @"checkInject",
                @"isDeviceCloned",
            ];
            for (unsigned int ci = 0; ci < classCount; ci++) {
                Class cls = classes[ci];
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
            }
            free(classes);
        } @catch (id e) {}

        // ---- 8. CoreTelephony hooks ----
        @try {
            Class ctniClass = objc_getClass("CTTelephonyNetworkInfo");
            if (ctniClass) {
                Method m = class_getInstanceMethod(ctniClass, @selector(serviceSubscriberCellularProviders));
                if (m) { IMP imp = imp_implementationWithBlock(^NSDictionary *(id s) { return @{}; }); class_replaceMethod(ctniClass, @selector(serviceSubscriberCellularProviders), imp, method_getTypeEncoding(m)); }
                m = class_getInstanceMethod(ctniClass, @selector(serviceCurrentRadioAccessTechnology));
                if (m) { IMP imp = imp_implementationWithBlock(^NSDictionary *(id s) { return @{}; }); class_replaceMethod(ctniClass, @selector(serviceCurrentRadioAccessTechnology), imp, method_getTypeEncoding(m)); }
                m = class_getInstanceMethod(ctniClass, @selector(subscriberCellularProvider));
                if (m) { IMP imp = imp_implementationWithBlock(^id(id s) { return nil; }); class_replaceMethod(ctniClass, @selector(subscriberCellularProvider), imp, method_getTypeEncoding(m)); }
            }
            Class carrierClass = objc_getClass("CTCarrier");
            if (carrierClass) {
                Method m = class_getInstanceMethod(carrierClass, @selector(carrierName));
                if (m) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @""; }); class_replaceMethod(carrierClass, @selector(carrierName), imp, method_getTypeEncoding(m)); }
                m = class_getInstanceMethod(carrierClass, @selector(mobileCountryCode));
                if (m) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @""; }); class_replaceMethod(carrierClass, @selector(mobileCountryCode), imp, method_getTypeEncoding(m)); }
                m = class_getInstanceMethod(carrierClass, @selector(mobileNetworkCode));
                if (m) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @""; }); class_replaceMethod(carrierClass, @selector(mobileNetworkCode), imp, method_getTypeEncoding(m)); }
                m = class_getInstanceMethod(carrierClass, @selector(isoCountryCode));
                if (m) { IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @""; }); class_replaceMethod(carrierClass, @selector(isoCountryCode), imp, method_getTypeEncoding(m)); }
            }
        } @catch (id e) {}

        // ---- 9. Anti-clone detection (return NO, don't replace CUID) ----
        @try {
            unsigned int classCount = 0;
            Class *classes = objc_copyClassList(&classCount);
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

        // ---- 10. HDANA jailbreak detection ----
        @try {
            Class hdanaCom = objc_getClass("HDANA_ComUtils");
            if (hdanaCom) {
                Method m = class_getClassMethod(hdanaCom, @selector(getJailbrokenApp));
                if (m) {
                    IMP imp = imp_implementationWithBlock(^id(id s) { return nil; });
                    class_replaceMethod(object_getClass(hdanaCom), @selector(getJailbrokenApp), imp, method_getTypeEncoding(m));
                }
            }
        } @catch (id e) {}
    }
}
