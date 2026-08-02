//
// PrivacyHook.m — v44: Ultra-minimal multi-instance
//
// GOAL: Multi-instance with different accounts, nothing else.
//   1. Hook bundleIdentifier → return original (app functionality)
//   2. Hook IDFV → per-instance unique (differentiation)
//   3. That's it. No CUID, no device model, no anti-jailbreak, no anti-injection.
//   App behaves exactly like original TrollStore → user bypasses "非正版应用" themselves.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

#define NSLog(...)

static NSString *const kOrigBundleID = @"com.baidu.BaiduMobile";
static NSString *g_realBundleID = nil;

// ============================================================
// Per-instance persistent storage
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

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor)) static void PrivacyHookConstructor(void) {
    @autoreleasepool {
        // ---- 0. Read REAL bundle ID ----
        @try {
            NSDictionary *d = [[NSBundle mainBundle] infoDictionary];
            g_realBundleID = d[@"CFBundleIdentifier"];
            if (!g_realBundleID) g_realBundleID = kOrigBundleID;
        } @catch (id e) {}

        // ---- 1. Hook bundleIdentifier → return original ----
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

        // ---- 2. Hook IDFV → per-instance unique ----
        @try {
            Class dc = objc_getClass("UIDevice");
            if (dc) {
                Method idfvM = class_getInstanceMethod(dc, @selector(identifierForVendor));
                if (idfvM) {
                    IMP imp = imp_implementationWithBlock(^NSUUID *(id s) {
                        return [[NSUUID alloc] initWithUUIDString:getPersistent(@"Bdhk.iv", ^{
                            return [[NSUUID UUID] UUIDString];
                        })];
                    });
                    class_replaceMethod(dc, @selector(identifierForVendor), imp, method_getTypeEncoding(idfvM));
                }
            }
        } @catch (id e) {}
    }
}
