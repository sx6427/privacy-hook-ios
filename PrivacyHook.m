//
// PrivacyHook.m — MINIMAL: only Bundle ID hook, only Foundation
// Binary search: if this crashes, the problem is class_replaceMethod on NSBundle
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

static NSString *_originalBundleID = @"com.baidu.BaiduMobile";

__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {
        Class bundleClass = objc_getClass("NSBundle");
        if (!bundleClass) return;

        Method m = class_getInstanceMethod(bundleClass, @selector(bundleIdentifier));
        if (m) {
            IMP orig = method_getImplementation(m);
            IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                if ([s isEqual:[NSBundle mainBundle]]) return _originalBundleID;
                return ((NSString *(*)(id, SEL))orig)(s, @selector(bundleIdentifier));
            });
            class_replaceMethod(bundleClass, @selector(bundleIdentifier), imp, method_getTypeEncoding(m));
        }
    }
}
