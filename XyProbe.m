//
//  XyProbe.m — 闲鱼桥侦察 v3：枚举桥类方法 + 全量捕获 WindVane 回调
//
//  v2 已验证：ObjC swizzle 在 TrollFools 注入下存活。
//  v3 目标：
//    1. 枚举 WVIdleFishApi / MtopWVPlugin 的全部实例方法（找真实 callMtop selector）
//    2. 全量捕获 evaluateJavaScript 里的 window.__windvane__.onSuccess 回调
//       （用户在鱼塘里点任务时，响应会带 API 结果流经这里）
//    输出：Documents/xy_bridge.log（独立大文件）+ xy_probe.log（摘要）
//

#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>

static NSMutableString *gLog = nil;   // 摘要 → xy_probe.log
static NSMutableString *gBridge = nil; // 全量 → xy_bridge.log

static void W(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (!gLog) gLog = [NSMutableString new];
    [gLog appendFormat:@"%@\n", s];
}

static void flushLog(void) {
    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    [gLog writeToFile:[dir stringByAppendingPathComponent:@"xy_probe.log"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
    [gBridge writeToFile:[dir stringByAppendingPathComponent:@"xy_bridge.log"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

static void B(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (!gBridge) gBridge = [NSMutableString new];
    [gBridge appendFormat:@"%@\n", s];
}

static NSString *b64(NSData *d) { return [d base64EncodedStringWithOptions:0]; }

// ---------- 桥类方法枚举 ----------
static void enumClass(NSString *name) {
    Class c = NSClassFromString(name);
    W(@"=== CLASS %@ = %@", name, c ? @"YES" : @"no");
    if (!c) return;
    unsigned int cnt = 0;
    Method *ms = class_copyMethodList(c, &cnt);
    W(@"  instance methods: %u", cnt);
    for (unsigned int i = 0; i < cnt; i++) {
        SEL s = method_getName(ms[i]);
        unsigned int argc = method_getNumberOfArguments(ms[i]);
        W(@"  M -[%@ %@] argc=%d", name, NSStringFromSelector(s), (int)argc - 2);
    }
    free(ms);
    unsigned int ccnt = 0;
    Method *cms = class_copyMethodList(object_getClass(c), &ccnt);
    for (unsigned int i = 0; i < ccnt; i++) {
        SEL s = method_getName(cms[i]);
        NSString *n = NSStringFromSelector(s);
        if ([n hasPrefix:@"_"] || [n hasPrefix:@"initialize"]) continue;
        W(@"  M +[%@ %@]", name, n);
    }
    free(cms);
}

// ---------- evaluateJavaScript swizzle ----------
static NSInteger gEvalCount = 0;
static void (*orig_eval)(id, SEL, NSString *, void (^)(id, NSError *));

static void my_eval(id self, SEL _cmd, NSString *js, void (^cb)(id, NSError *)) {
    @autoreleasepool {
        gEvalCount++;
        if ([js containsString:@"__windvane__"]) {
            // 完整记录 WindVane 回调（API 响应全在这）
            B(@"[EVAL %ld] %@", (long)gEvalCount, js);
            if (gBridge.length > 800000) { /* 防爆 */ }
            flushLog();
        } else if (gEvalCount <= 20) {
            NSString *s = [js length] > 120 ? [js substringToIndex:120] : js;
            B(@"[EVAL %ld|other] %@", (long)gEvalCount, s);
        }
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

// ---------- 旧版数据采集（沿用） ----------
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
        NSData *dat = item[(__bridge id)kSecValueData];
        NSString *txt = @"";
        if ([dat isKindOfClass:[NSData class]]) {
            txt = [[NSString alloc] initWithData:dat encoding:NSUTF8StringEncoding] ?: b64(dat);
        }
        W(@"KC\t%@\t%@\t%@\t%@",
          item[(__bridge id)kSecAttrService] ?: @"",
          item[(__bridge id)kSecAttrAccount] ?: @"",
          item[(__bridge id)kSecAttrAccessGroup] ?: @"", txt);
    }
}

static void dumpCookies(void) {
    W(@"=== COOKIES ===");
    for (NSHTTPCookie *c in [[NSHTTPCookieStorage sharedHTTPCookieStorage] cookies]) {
        W(@"COOKIE\t%@\t%@=%@", c.domain, c.name, c.value);
    }
}

__attribute__((constructor))
static void xyprobe_init(void) {
    @autoreleasepool {
        gLog = [NSMutableString new];
        gBridge = [NSMutableString new];
        doSwizzle();
        W(@"---- probe v3 at %@ ----", [NSDate date]);
        W(@"bundle=%@", [[NSBundle mainBundle] bundleIdentifier]);
        enumClass(@"WVIdleFishApi");
        enumClass(@"MtopWVPlugin");
        dumpCookies();
        flushLog();
        dumpKeychainClass(kSecClassGenericPassword, @"generic");
        flushLog();
        W(@"---- v3 ready, waiting bridge traffic ----");
        flushLog();
        // 周期落盘：让桥流量持续可见
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(20 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            W(@"---- alive 20s, evalCount=%ld ----", (long)gEvalCount);
            flushLog();
        });
    }
}
