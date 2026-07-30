//
// PrivacyHook.m — v7b-pay2: Full Bundle ID hook (3 methods) like Step33
// Hook bundleIdentifier + infoDictionary + objectForInfoDictionaryKey:
// No device spoofing — only payment compatibility
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

static NSString *const kOrigBundleID = @"com.baidu.BaiduMobile";

__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {
        Class bc = objc_getClass("NSBundle");
        if (!bc) return;

        // 1. bundleIdentifier
        @try {
            Method m = class_getInstanceMethod(bc, @selector(bundleIdentifier));
            if (m) {
                IMP orig = method_getImplementation(m);
                IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                    if ([s isEqual:[NSBundle mainBundle]]) return kOrigBundleID;
                    return ((NSString *(*)(id, SEL))orig)(s, @selector(bundleIdentifier));
                });
                class_replaceMethod(bc, @selector(bundleIdentifier), imp, method_getTypeEncoding(m));
            }
        } @catch (id e) {}

        // 2. objectForInfoDictionaryKey: — SDK reads CFBundleIdentifier this way
        @try {
            Method m = class_getInstanceMethod(bc, @selector(objectForInfoDictionaryKey:));
            if (m) {
                IMP orig = method_getImplementation(m);
                IMP imp = imp_implementationWithBlock(^id(id s, NSString *key) {
                    if ([s isEqual:[NSBundle mainBundle]] && key &&
                        [key isEqualToString:@"CFBundleIdentifier"]) {
                        return kOrigBundleID;
                    }
                    return ((id (*)(id, SEL, NSString *))orig)(s, @selector(objectForInfoDictionaryKey:), key);
                });
                class_replaceMethod(bc, @selector(objectForInfoDictionaryKey:), imp, method_getTypeEncoding(m));
            }
        } @catch (id e) {}

        // 3. infoDictionary — modify CFBundleIdentifier in the returned dict
        @try {
            Method m = class_getInstanceMethod(bc, @selector(infoDictionary));
            if (m) {
                IMP orig = method_getImplementation(m);
                IMP imp = imp_implementationWithBlock(^NSDictionary *(id s) {
                    NSDictionary *dict = ((NSDictionary *(*)(id, SEL))orig)(s, @selector(infoDictionary));
                    if ([s isEqual:[NSBundle mainBundle]] && dict) {
                        NSMutableDictionary *md = [NSMutableDictionary dictionaryWithDictionary:dict];
                        md[@"CFBundleIdentifier"] = kOrigBundleID;
                        return md;
                    }
                    return dict;
                });
                class_replaceMethod(bc, @selector(infoDictionary), imp, method_getTypeEncoding(m));
            }
        } @catch (id e) {}
    }
}
