
//
// MinimalHook2.m — ONLY UIDevice hooks, NO fishhook
//
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

#define NSLog(...)

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

__attribute__((constructor))
static void initMinimalHook2(void) {
    @autoreleasepool {
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
    }
}
