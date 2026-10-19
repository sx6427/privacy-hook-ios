//
//  XyProbe.m — 闲鱼指令执行器 v4（不越狱自动化核心）
//
//  架构（= 高德 sg_drive 的原生版）：
//    PC --WebDAV(Filza)--> Documents/xy_cmd.json   （指令）
//    dylib 轮询指令 -> [MtopWVPlugin send:...] 原生桥（真机签名）-> 响应
//    响应(evaluateJavaScript onSuccess) swizzle 捕获 -> Documents/xy_result.log
//    PC 读结果。全程无需代理/越狱。
//
//  用户需打开一次鱼塘页面，让 WKWebView/桥处于活跃状态。
//

#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <objc/message.h>

static NSMutableString *gLog = nil;     // 摘要 → xy_probe.log
static NSMutableString *gBridge = nil;  // 全量桥流量 → xy_bridge.log
static WKWebView *gWebView = nil;       // 活跃 webview（send 需要）
static NSMutableDictionary *gPending;   // cbId -> tag
static long long gLastCmdAt = 0;
static long gCmdSeq = 0;

static void W(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (!gLog) gLog = [NSMutableString new];
    [gLog appendFormat:@"%@\n", s];
    if (gLog.length > 300000) gLog = [NSMutableString new];
}

static void B(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (!gBridge) gBridge = [NSMutableString new];
    [gBridge appendFormat:@"%@\n", s];
    if (gBridge.length > 2000000) gBridge = [NSMutableString new];
}

static NSString *docsDir(void) {
    return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
}

static void flushLogs(void) {
    [gLog writeToFile:[docsDir() stringByAppendingPathComponent:@"xy_probe.log"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
    [gBridge writeToFile:[docsDir() stringByAppendingPathComponent:@"xy_bridge.log"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

static void appendResult(NSString *line) {
    NSString *p = [docsDir() stringByAppendingPathComponent:@"xy_result.log"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:p];
    if (!fh) {
        [line writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
        return;
    }
    [fh seekToEndOfFile];
    [fh writeData:[[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
    [fh closeFile];
}

static void dumpCookiesTo(NSString *label) {
    NSMutableString *s = [NSMutableString new];
    for (NSHTTPCookie *c in [[NSHTTPCookieStorage sharedHTTPCookieStorage] cookies]) {
        [s appendFormat:@"COOKIE\t%@\t%@=%@\n", c.domain, c.name, c.value];
    }
    NSString *p = [docsDir() stringByAppendingPathComponent:@"xy_cookies.txt"];
    [s writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
    W(@"cookies dumped (%@)", label);
}

// ---------- evaluateJavaScript swizzle：捕获 WindVane 响应 ----------
static NSInteger gEvalCount = 0;
static void (*orig_eval)(id, SEL, NSString *, void (^)(id, NSError *));

static void my_eval(id self, SEL _cmd, NSString *js, void (^cb)(id, NSError *)) {
    @autoreleasepool {
        gEvalCount++;
        if (!gWebView) {
            if ([self isKindOfClass:NSClassFromString(@"WKWebView")]) {
                gWebView = self;
                W(@"webview captured");
            }
        }
        if ([js containsString:@"__windvane__"]) {
            B(@"[EVAL %ld] %@", (long)gEvalCount, js);
            // 解析 onSuccess('$cbId', payload)
            NSRange r = [js rangeOfString:@"onSuccess("];
            if (r.location != NSNotFound) {
                NSString *rest = [js substringFromIndex:r.location + 10];
                NSRange q1 = [rest rangeOfString:@"'"];
                if (q1.location != NSNotFound) {
                    NSString *after = [rest substringFromIndex:q1.location + 1];
                    NSRange q2 = [after rangeOfString:@"'"];
                    if (q2.location != NSNotFound) {
                        NSString *cbId = [after substringToIndex:q2.location];
                        NSRange comma = [after rangeOfString:@","];
                        if (comma.location != NSNotFound) {
                            NSString *payload = [after substringFromIndex:comma.location + 1];
                            // 去掉尾部 ",false)" 或 ")"
                            NSRange tail = [payload rangeOfString:@",false)" options:NSBackwardsSearch];
                            if (tail.location != NSNotFound) payload = [payload substringToIndex:tail.location];
                            NSRange tail2 = [payload rangeOfString:@")" options:NSBackwardsSearch];
                            if (tail2.location != NSNotFound && tail.location == NSNotFound) payload = [payload substringToIndex:tail2.location];
                            // 找到对应 tag（若有）
                            NSString *tag = gPending[cbId] ?: @"";
                            if (tag.length) [gPending removeObjectForKey:cbId];
                            NSString *line = [NSString stringWithFormat:@"{\"cb\":\"%@\",\"tag\":\"%@\",\"at\":%lld,\"payload\":%@}",
                                              cbId, tag, (long long)([[NSDate date] timeIntervalSince1970] * 1000), payload];
                            appendResult(line);
                            if (tag.length) W(@"cmd result captured: %@ -> %lu bytes", tag, (unsigned long)payload.length);
                        }
                    }
                }
            }
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

// ---------- 指令执行 ----------
static void execCall(NSDictionary *cmd) {
    NSString *api = cmd[@"api"];
    if (!api.length) return;
    NSString *v = cmd[@"v"] ?: @"1.0";
    NSString *tag = cmd[@"tag"] ?: @"";
    id data = cmd[@"data"] ?: @{};
    NSString *site = cmd[@"site"] ?: @"xianyu";

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            W(@"MS-CALL %@ v=%@ site=%@ tag=%@", api, v, site, tag);
            flushLogs();
            Class ms = NSClassFromString(@"MtopService");
            if (!ms) { W(@"no MtopService"); flushLogs(); return; }
            SEL gs = @selector(getInstanceWithAccountSite:);
            if (![ms respondsToSelector:gs]) { W(@"no getInstanceWithAccountSite"); flushLogs(); return; }
            id inst = ((id (*)(id, SEL, id))objc_msgSend)(ms, gs, site);
            if (!inst) { W(@"no MtopService instance"); flushLogs(); return; }
            SEL call = @selector(sync_call:apiVersion:bizParameters:);
            if (![inst respondsToSelector:call]) { W(@"no sync_call sel"); flushLogs(); return; }
            id resp = nil;
            @try {
                resp = ((id (*)(id, SEL, id, id, id))objc_msgSend)(inst, call, api, v, data);
                W(@"MS-RESP class=%@", NSStringFromClass([resp class]));
            } @catch (NSException *e) {
                W(@"MS-EXCEPTION %@: %@", e.name, e.reason);
                flushLogs();
                return;
            }
            // 序列化响应
            NSString *payload = nil;
            if ([resp isKindOfClass:[NSDictionary class]] || [resp isKindOfClass:[NSArray class]]) {
                NSData *jd = [NSJSONSerialization dataWithJSONObject:resp options:0 error:nil];
                payload = jd ? [[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding] : nil;
            }
            if (!payload) {
                payload = [NSString stringWithFormat:@"%@", resp ?: @"(nil)"];
            }
            if (payload.length > 200000) payload = [payload substringToIndex:200000];
            NSString *line = [NSString stringWithFormat:@"{\"tag\":\"%@\",\"api\":\"%@\",\"at\":%lld,\"payload\":%@}",
                              tag, api, (long long)([[NSDate date] timeIntervalSince1970] * 1000),
                              ([payload hasPrefix:@"{"] || [payload hasPrefix:@"["]) ? payload :
                              [NSString stringWithFormat:@"%@", [[payload stringByReplacingOccurrencesOfString:@"\\" withString:@"\\\\"] stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""]]];
            appendResult(line);
            W(@"MS-DONE tag=%@ respLen=%lu", tag, (unsigned long)payload.length);
            flushLogs();
        }
    });
}

// ---------- v4.2 运行时类扫描 ----------
static void appendScan(NSString *line) {
    NSString *p = [docsDir() stringByAppendingPathComponent:@"xy_scan.log"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:p];
    if (!fh) { [line writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil]; return; }
    [fh seekToEndOfFile];
    [fh writeData:[[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
    [fh closeFile];
}

static BOOL nameMatches(NSString *n) {
    NSString *l = n.lowercaseString;
    if ([l containsString:@"mtop"]) return YES;
    if ([l containsString:@"amnet"]) return YES;
    return NO;
}

static BOOL selInteresting(NSString *n) {
    NSString *l = n.lowercaseString;
    NSArray *kw = @[@"send", @"request", @"call", @"post", @"get", @"sign", @"wua", @"submit"];
    for (NSString *k in kw) if ([l containsString:k]) return YES;
    return NO;
}

static void scanClasses(void) {
    W(@"SCAN start");
    unsigned int count = 0;
    Class *classes = objc_copyClassList(&count);
    appendScan([NSString stringWithFormat:@"==== scan %@ total=%u ====", [NSDate date], count]);
    int matched = 0;
    for (unsigned int i = 0; i < count; i++) {
        Class c = classes[i];
        NSString *n = NSStringFromClass(c);
        if (!nameMatches(n)) continue;
        matched++;
        appendScan([NSString stringWithFormat:@"--- CLASS %@ ---", n]);
        unsigned int mc = 0;
        Method *ms = class_copyMethodList(c, &mc);
        BOOL printAll = (mc <= 40);
        for (unsigned int j = 0; j < mc; j++) {
            NSString *mn = NSStringFromSelector(method_getName(ms[j]));
            if (printAll || selInteresting(mn)) {
                appendScan([NSString stringWithFormat:@"  -[%@ %@] argc=%d", n, mn, (int)method_getNumberOfArguments(ms[j]) - 2]);
            }
        }
        free(ms);
    }
    free(classes);
    appendScan([NSString stringWithFormat:@"==== scan done matched=%d ====", matched]);
    W(@"SCAN done matched=%d", matched);
    flushLogs();
}

static void pollCmd(void) {
    @autoreleasepool {
        NSString *p = [docsDir() stringByAppendingPathComponent:@"xy_cmd.json"];
        NSData *d = [NSData dataWithContentsOfFile:p];
        if (!d) return;
        id obj = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
        if (![obj isKindOfClass:[NSDictionary class]]) return;
        long long at = [obj[@"at"] longLongValue];
        long long nowms = (long long)([[NSDate date] timeIntervalSince1970] * 1000);
        if (at <= gLastCmdAt) return;
        if (at > nowms + 60000) return; // 未来时间戳：忽略，不消费
        gLastCmdAt = at;
        NSString *mode = obj[@"mode"] ?: @"";
        W(@"CMD mode=%@ at=%lld", mode, at);
        if ([mode isEqualToString:@"call"]) {
            if (![obj[@"arm"] boolValue]) { W(@"call not armed, skip"); return; }
            execCall(obj);
        } else if ([mode isEqualToString:@"scan"]) {
            scanClasses();
        } else if ([mode isEqualToString:@"cookies"]) {
            dumpCookiesTo(@"cmd");
        } else if ([mode isEqualToString:@"ping"]) {
            W(@"ping ok");
        }
        flushLogs();
    }
}

__attribute__((constructor))
static void xyprobe_init(void) {
    @autoreleasepool {
        gLog = [NSMutableString new];
        gBridge = [NSMutableString new];
        gPending = [NSMutableDictionary new];
        doSwizzle();
        W(@"---- executor v4 at %@ ----", [NSDate date]);
        W(@"bundle=%@", [[NSBundle mainBundle] bundleIdentifier]);
        dumpCookiesTo(@"boot");
        flushLogs();
        // 主线程定时器：轮询指令 + 周期落盘
        dispatch_async(dispatch_get_main_queue(), ^{
            [NSTimer scheduledTimerWithTimeInterval:2.0 repeats:YES block:^(NSTimer *t) {
                pollCmd();
                if (gEvalCount % 1 == 0) flushLogs();
            }];
            W(@"poll timer started");
            flushLogs();
        });
    }
}
