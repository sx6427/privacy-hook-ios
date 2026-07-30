//
// PrivacyHook.m — v7b-pay: ONLY Bundle ID hook for payment testing
// No device spoofing at all — server sees old device, no verification code
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {
        Class bc = objc_getClass("NSBundle");
        if (bc) {
            Method m = class_getInstanceMethod(bc, @selector(bundleIdentifier));
            if (m) {
                IMP orig = method_getImplementation(m);
                IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                    if ([s isEqual:[NSBundle mainBundle]]) return @"com.baidu.BaiduMobile";
                    return ((NSString *(*)(id, SEL))orig)(s, @selector(bundleIdentifier));
                });
                class_replaceMethod(bc, @selector(bundleIdentifier), imp, method_getTypeEncoding(m));
            }
        }
    }
}
