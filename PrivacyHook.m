
//
// MinimalHook.m — only UIDevice + sysctlbyname fishhook (bisect test)
//
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include "fishhook.h"

#define NSLog(...)

static char g_fakeMachine[32] = "";
static char g_fakeBuild[32] = "";
static char g_fakeOSVersion[32] = "";
static char g_fakeDarwinRel[32] = "";
static uint64_t g_fakeMemSize = 0;

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
static int (*orig_uname)(struct utsname *) = NULL;

static struct rebinding g_rebindings[2];

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
    NSArray *s = @[@"张", @"王", @"李", @"赵", @"刘"];
    NSArray *g = @[@"伟", @"芳", @"杰", @"磊", @"敏"];
    return [NSString stringWithFormat:@"%@%@的 iPhone",
        s[arc4random_uniform((uint32_t)s.count)],
        g[arc4random_uniform((uint32_t)g.count)]];
}

static NSString *getFakeSystemVersion(void) {
    return getPersistent(@"JdD1.sv", ^{
        NSArray *v = @[@"16.5", @"16.6.1", @"16.7.2", @"17.0", @"17.1.2", @"17.2", @"17.3", @"17.4.1"];
        return v[arc4random_uniform((uint32_t)v.count)];
    });
}

static NSString *versionToBuild(NSString *v) {
    NSDictionary *m = @{@"16.5":@"20F66",@"16.6.1":@"20G81",@"16.7.2":@"20H115",
        @"17.0":@"21A329",@"17.1.2":@"21B101",@"17.2":@"21C62",@"17.3":@"21D50",@"17.4.1":@"21E237"};
    return m[v] ?: @"20F66";
}

static NSString *versionToMachine(NSString *v) {
    NSInteger major = [[v componentsSeparatedByString:@"."][0] integerValue];
    if (major == 16) { NSArray *m = @[@"iPhone14,7",@"iPhone14,8",@"iPhone15,2",@"iPhone15,3"]; return m[arc4random_uniform((uint32_t)m.count)]; }
    if (major == 17) { NSArray *m = @[@"iPhone15,4",@"iPhone15,5",@"iPhone16,1",@"iPhone16,2"]; return m[arc4random_uniform((uint32_t)m.count)]; }
    return @"iPhone14,7";
}

static uint64_t machineToMemSize(NSString *m) {
    NSArray *eight = @[@"iPhone16,1",@"iPhone16,2"];
    NSArray *six = @[@"iPhone14,7",@"iPhone14,8",@"iPhone15,2",@"iPhone15,3"];
    if ([eight containsObject:m]) return 8589934592ULL;
    if ([six containsObject:m]) return 6442450944ULL;
    return 6442450944ULL;
}

static NSString *versionToDarwinRelease(NSString *v) {
    NSArray *p = [v componentsSeparatedByString:@"."];
    NSInteger minor = 0;
    if (p.count > 1) minor = [p[1] integerValue];
    return [NSString stringWithFormat:@"%ld.%ld.0", (long)([p[0] integerValue]+6), (long)minor];
}

static void hook_new_image(const struct mach_header *header, intptr_t slide) {
    if (!header) return;
    Dl_info info;
    if (dladdr(header, &info) && info.dli_fname) {
        const char *path = info.dli_fname;
        if (strncmp(path, "/usr/lib/", 9) == 0) return;
        if (strncmp(path, "/System/", 8) == 0) return;
        if (strncmp(path, "/Developer/", 11) == 0) return;
        rebind_symbols_image((void *)header, slide, g_rebindings, 2);
    }
}

static int hook_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (!name) goto fallback;
    const char *fakeStr = NULL;
    if (strcmp(name, "hw.machine") == 0 || strcmp(name, "hw.model") == 0 ||
        strcmp(name, "hw.product") == 0 || strcmp(name, "hw.target") == 0) {
        fakeStr = g_fakeMachine;
    } else if (strcmp(name, "kern.osversion") == 0) {
        fakeStr = g_fakeBuild;
    } else if (strcmp(name, "kern.osproductversion") == 0) {
        fakeStr = g_fakeOSVersion;
    } else if (strcmp(name, "kern.osrelease") == 0) {
        fakeStr = g_fakeDarwinRel;
    } else if (strcmp(name, "hw.serialnumber") == 0 || strcmp(name, "hw.uuid") == 0) {
        if (oldlenp) { if (oldp && *oldlenp >= 1) { ((char *)oldp)[0] = '\0'; *oldlenp = 1; } else { *oldlenp = 1; } }
        return 0;
    } else if (strcmp(name, "hw.memsize") == 0) {
        if (oldlenp) {
            if (oldp) {
                if (*oldlenp >= sizeof(uint64_t)) { *(uint64_t *)oldp = g_fakeMemSize; *oldlenp = sizeof(uint64_t); return 0; }
                *oldlenp = sizeof(uint64_t); return ENOMEM;
            }
            *oldlenp = sizeof(uint64_t); return 0;
        }
        return 0;
    }
    if (fakeStr) {
        size_t fakeLen = strlen(fakeStr) + 1;
        if (oldlenp) {
            if (oldp) {
                if (*oldlenp >= fakeLen) { memcpy(oldp, fakeStr, fakeLen); *oldlenp = fakeLen; return 0; }
                *oldlenp = fakeLen; return ENOMEM;
            }
            *oldlenp = fakeLen; return 0;
        }
        return 0;
    }
fallback:
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

static int hook_uname(struct utsname *name) {
    int ret = orig_uname(name);
    if (ret == 0 && name) {
        strncpy(name->machine, g_fakeMachine, sizeof(name->machine) - 1);
        name->machine[sizeof(name->machine) - 1] = '\0';
        strncpy(name->release, g_fakeDarwinRel, sizeof(name->release) - 1);
        name->release[sizeof(name->release) - 1] = '\0';
    }
    return ret;
}

__attribute__((constructor))
static void initMinimalHook(void) {
    @autoreleasepool {
        NSString *fakeSV = getFakeSystemVersion();
        NSString *fakeBuild = versionToBuild(fakeSV);
        NSString *fakeMachine = getPersistent(@"JdD1.hw", ^{ return versionToMachine(fakeSV); });
        NSString *fakeDarwin = versionToDarwinRelease(fakeSV);
        NSString *memStr = getPersistent(@"JdD1.mem", ^{ return [NSString stringWithFormat:@"%llu", machineToMemSize(fakeMachine)]; });

        strlcpy(g_fakeMachine, [fakeMachine UTF8String], sizeof(g_fakeMachine));
        strlcpy(g_fakeBuild, [fakeBuild UTF8String], sizeof(g_fakeBuild));
        strlcpy(g_fakeOSVersion, [fakeSV UTF8String], sizeof(g_fakeOSVersion));
        strlcpy(g_fakeDarwinRel, [fakeDarwin UTF8String], sizeof(g_fakeDarwinRel));
        g_fakeMemSize = [memStr longLongValue];

        // 1. UIDevice hooks only
        @try {
            Class dc = objc_getClass("UIDevice");
            if (dc) {
                Method nameM = class_getInstanceMethod(dc, @selector(name));
                if (nameM) { class_replaceMethod(dc, @selector(name),
                    imp_implementationWithBlock(^NSString *(id s) { return getPersistent(@"JdD1.dn", ^{ return genDeviceName(); }); }),
                    method_getTypeEncoding(nameM)); }
                Method idfvM = class_getInstanceMethod(dc, @selector(identifierForVendor));
                if (idfvM) { class_replaceMethod(dc, @selector(identifierForVendor),
                    imp_implementationWithBlock(^NSUUID *(id s) { return [[NSUUID alloc] initWithUUIDString:getPersistent(@"JdD1.iv", ^{ return genUUIDStr(); })]; }),
                    method_getTypeEncoding(idfvM)); }
                Method modelM = class_getInstanceMethod(dc, @selector(model));
                if (modelM) { class_replaceMethod(dc, @selector(model),
                    imp_implementationWithBlock(^NSString *(id s) { return @"iPhone"; }),
                    method_getTypeEncoding(modelM)); }
                Method svM = class_getInstanceMethod(dc, @selector(systemVersion));
                if (svM) { class_replaceMethod(dc, @selector(systemVersion),
                    imp_implementationWithBlock(^NSString *(id s) { return getFakeSystemVersion(); }),
                    method_getTypeEncoding(svM)); }
            }
        } @catch (id e) {}

        // 2. fishhook sysctlbyname + uname only
        @try {
            g_rebindings[0] = (struct rebinding){"sysctlbyname", (void *)hook_sysctlbyname, (void **)&orig_sysctlbyname};
            g_rebindings[1] = (struct rebinding){"uname", (void *)hook_uname, (void **)&orig_uname};

            uint32_t count = _dyld_image_count();
            for (uint32_t i = 0; i < count; i++) {
                const struct mach_header *header = _dyld_get_image_header(i);
                intptr_t slide = _dyld_get_image_vmaddr_slide(i);
                const char *path = _dyld_get_image_name(i);
                if (!header || !path) continue;
                if (strncmp(path, "/usr/lib/", 9) == 0) continue;
                if (strncmp(path, "/System/", 8) == 0) continue;
                if (strncmp(path, "/Developer/", 11) == 0) continue;
                rebind_symbols_image((void *)header, slide, g_rebindings, 2);
            }
            _dyld_register_func_for_add_image(hook_new_image);
        } @catch (id e) {}
    }
}
