//
//  XyProbe.m — 闲鱼存活测试 v2：裸 dylib + ObjC swizzle 验证
//
//  目的：验证在 TrollFools 注入（加密 App）环境下，ObjC method swizzle
//        不会触发完整性校验/闪退 —— 为「指令执行器」开路。
//  同时保留：cookie/keychain dump（写 xy_probe.log）
//

#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>

static NSMutableString *gLog = nil;

static void W(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (!gLog) gLog = [NSMutableString new];
    [gLog appendFormat:@"%@\n", s];
    NSLog(@"[XYPROBE] %@", s);
}

static void flush(void) {
    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *p = [dir stringByAppendingPathComponent:@"xy_probe.log"];
    [gLog writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

static NSString *b64(NSData *d) { return [d base64EncodedStringWithOptions:0]; }

static void dumpKeychainClass(CFTypeRef cls, NSString *label) {
    NSDictionary *q = @{(__bridge id)kSecClass: (__bridge id)cls,
                        (__bridge id)kSecReturnAttributes: @YES,
                        (__bridge id)kSecReturnData: @YES,
                        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll};
    CFTypeRef res = NULL;
    OSStatus s = SecItemCopyMatching((__bridge CFDictionaryRef)q, &res);
    W(@"=== KEYCHAIN %@ (status=%d) ===", label, (int)s);
    if (s != errSecSuccess || !res) return;
    NSArray *arr = (__bridge_transfer NSArray *)res;
    if (![arr isKindOfClass:[NSArray class]]) { arr = @[arr]; }
    for (NSDictionary *item in arr) {
        NSString *svc = item[(__bridge id)kSecAttrService] ?: @"";
        NSString *acct = item[(__bridge id)kSecAttrAccount] ?: @"";
        NSString *grp = item[(__bridge id)kSecAttrAccessGroup] ?: @"";
        NSData *dat = item[(__bridge id)kSecValueData];
        NSString *txt = @"";
        if ([dat isKindOfClass:[NSData class]]) {
            txt = [[NSString alloc] initWithData:dat encoding:NSUTF8StringEncoding] ?: b64(dat);
        }
        W(@"KC\t%@\t%@\t%@\t%@", svc, acct, grp, txt);
    }
}

static void dumpCookies(void) {
    W(@"=== COOKIES ===");
    for (NSHTTPCookie *c in [[NSHTTPCookieStorage sharedHTTPCookieStorage] cookies]) {
        W(@"COOKIE\t%@\t%@=%@", c.domain, c.name, c.value);
    }
}

static void dumpClasses(void) {
    W(@"=== BRIDGE CLASSES ===");
    NSArray *names = @[@"WVIdleFishApi", @"MtopWVPlugin", @"WVPluginManager",
                       @"TMWindVaneBridge", @"MTOPRequest", @"TMNetworkClient",
                       @"TVMTOPRequest", @"WVBJContext", @"KunJSBridge"];
    for (NSString *n in names) {
        Class c = NSClassFromString(n);
        W(@"CLASS %@ = %@", n, c ? @"YES" : @"no");
        if (c) {
            W(@"  instancesRespond callMtop: %@", [c instancesRespondToSelector:@selector(callMtop:)] ? @"YES" : @"no");
        }
    }
}

// ---------- swizzle ----------
static NSInteger gEvalCount = 0;
static void (*orig_eval)(id, SEL, NSString *, void (^)(id, NSError *));

static void my_eval(id self, SEL _cmd, NSString *js, void (^cb)(id, NSError *)) {
    gEvalCount++;
    if (gEvalCount <= 30) {
        NSString *s = [js length] > 300 ? [js substringToIndex:300] : js;
        W(@"EVAL#%d %@", gEvalCount, [s length] ? s : @"(empty)");
        flush();
    }
    orig_eval(self, _cmd, js, cb);
}

static void doSwizzle(void) {
    Class cls = NSClassFromString(@"WKWebView");
    SEL sel = @selector(evaluateJavaScript:completionHandler:);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) { W(@"SWIZZLE target missing"); return; }
    Method orig = class_getInstanceMethod(cls, sel);
    orig_eval = (void (*)(id, SEL, NSString *, void (^)(id, NSError *)))method_getImplementation(orig);
    method_setImplementation(orig, (IMP)my_eval);
    W(@"SWIZZLE evaluateJavaScript OK");
}

static void dumpAll(void) {
    @autoreleasepool {
        W(@"---- probe v2 at %@ ----", [NSDate date]);
        W(@"bundle=%@ executable=%@", [[NSBundle mainBundle] bundleIdentifier], [[NSBundle mainBundle] executablePath]);
        dumpClasses();
        dumpCookies();
        flush();
        dumpKeychainClass(kSecClassGenericPassword, @"generic");
        flush();
    }
}

__attribute__((constructor))
static void xyprobe_init(void) {
    @autoreleasepool {
        gLog = [NSMutableString new];
        doSwizzle();          // ★ 关键验证点：swizzle 后是否存活
        dumpAll();
        W(@"---- swizzle done, alive ----");
        flush();
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(15 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            @autoreleasepool {
                W(@"---- alive-check 15s: evalCount=%ld ----", (long)gEvalCount);
                flush();
            }
        });
    }
}
