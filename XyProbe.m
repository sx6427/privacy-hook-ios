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
static void sendViaPlugin(NSDictionary *req, NSString *cbId) {
    Class plugin = NSClassFromString(@"MtopWVPlugin");
    id inst = [plugin performSelector:@selector(instance)];
    WKWebView *wv = gWebView;
    if (!inst) { W(@"no plugin instance"); return; }
    SEL sel = @selector(send:withCallback:withWebView:withViewController:);
    if (![inst respondsToSelector:sel]) { W(@"plugin no send sel"); return; }
    @try {
        W(@"SEND-START api=%@ dataClass=%@", req[@"api"], NSStringFromClass([req[@"data"] class]));
        flushLogs();
        ((void (*)(id, SEL, id, id, id, id))objc_msgSend)(inst, sel, req, cbId, wv, nil);
        W(@"SEND-OK");
    } @catch (NSException *e) {
        W(@"SEND-EXCEPTION %@: %@", e.name, e.reason);
    }
    flushLogs();
}

static void execCall(NSDictionary *cmd) {
    NSString *api = cmd[@"api"];
    if (!api.length) return;
    NSString *v = cmd[@"v"] ?: @"1.0";
    NSString *tag = cmd[@"tag"] ?: @"";
    id rawData = cmd[@"data"] ?: @{};
    NSString *dataStr = nil;
    if ([rawData isKindOfClass:[NSString class]]) dataStr = rawData;
    else { NSData *jd = [NSJSONSerialization dataWithJSONObject:rawData options:0 error:nil]; dataStr = jd ? [[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding] : @"{}"; }

    NSString *cbId = [NSString stringWithFormat:@"$xy%ld", ++gCmdSeq];
    if (tag.length) gPending[cbId] = tag;

    // 尝试 1：data 为字典
    NSDictionary *req1 = @{@"api": api, @"v": v, @"data": rawData,
                           @"type": @"originaljson", @"dataType": @"json",
                           @"needLogin": @YES, @"ecode": @1, @"timeout": @20000};
    sendViaPlugin(req1, cbId);
    if (!gPending[cbId]) { W(@"call done (dict) tag=%@", tag); flushLogs(); return; }

    // 尝试 2：data 为 JSON 字符串
    NSDictionary *req2 = @{@"api": api, @"v": v, @"data": dataStr,
                           @"type": @"originaljson", @"dataType": @"json",
                           @"needLogin": @YES, @"ecode": @1, @"timeout": @20000};
    W(@"retry with data-as-string");
    sendViaPlugin(req2, cbId);
    if (!gPending[cbId]) { W(@"call done (string) tag=%@", tag); flushLogs(); return; }

    // 尝试 3：极简字段
    NSDictionary *req3 = @{@"api": api, @"v": v, @"data": dataStr};
    W(@"retry minimal");
    sendViaPlugin(req3, cbId);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(30 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (gPending[cbId]) { [gPending removeObjectForKey:cbId]; W(@"cmd timeout %@", tag); flushLogs(); }
    });
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
