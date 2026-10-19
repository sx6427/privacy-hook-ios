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
    if (!gLogLock) gLogLock = [NSLock new];
    [gLogLock lock];
    [gLog writeToFile:[docsDir() stringByAppendingPathComponent:@"xy_probe.log"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
    [gBridge writeToFile:[docsDir() stringByAppendingPathComponent:@"xy_bridge.log"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
    [gLogLock unlock];
}

static void writeResult(NSString *tag, NSString *api, NSString *text) {
    NSDictionary *rec = @{@"tag": tag ?: @"", @"api": api ?: @"", @"at": @((long long)([[NSDate date] timeIntervalSince1970] * 1000)), @"payload": text ?: @""};
    NSData *jd = [NSJSONSerialization dataWithJSONObject:rec options:NSJSONWritingWithoutEscapingSlashes error:nil];
    if (!jd) return;
    NSString *p = [docsDir() stringByAppendingPathComponent:[NSString stringWithFormat:@"xy_res_%@.json", tag ?: @"last"]];
    [jd writeToFile:p options:NSDataWritingAtomic error:nil];
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
                            if (tag.length) writeResult(tag, @"", [NSString stringWithFormat:@"%@", payload]);
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
            // 序列化响应：优先 data 属性
            NSString *payload = nil;
            id d = nil;
            @try { d = [resp valueForKey:@"data"]; } @catch (id e) { d = nil; }
            if ([d isKindOfClass:[NSDictionary class]] || [d isKindOfClass:[NSArray class]]) {
                NSData *jd = [NSJSONSerialization dataWithJSONObject:d options:0 error:nil];
                payload = jd ? [[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding] : nil;
            }
            if (!payload) {
                NSData *jd = nil;
                if ([resp isKindOfClass:[NSDictionary class]] || [resp isKindOfClass:[NSArray class]]) {
                    jd = [NSJSONSerialization dataWithJSONObject:resp options:0 error:nil];
                }
                payload = jd ? [[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding] : nil;
            }
            if (!payload) {
                payload = [NSString stringWithFormat:@"%@", resp ?: @"(nil)"];
            }
            if (payload.length > 300000) payload = [payload substringToIndex:300000];
            writeResult(tag, api, payload);
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


// ---------- v5: MtopService 全请求日志 + WKScriptMessage 全量捕获 ----------
static NSMutableString *gMtopLog = nil;
static NSMutableDictionary *gOrigImps = nil;
static long gMtopCount = 0;
static void (*orig_async_call_del)(id, SEL, id, id);
static void (*orig_async_call_del_sf)(id, SEL, id, id, id);
static void (*orig_sync_call)(id, SEL, id);
static void (*orig_sync_call_v)(id, SEL, id, id);
static void (*orig_sync_call_biz)(id, SEL, id, id, id);
static NSLock *gLogLock = nil;

static void MLOG(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (!gLogLock) gLogLock = [NSLock new];
    [gLogLock lock];
    @try {
        if (!gMtopLog) gMtopLog = [NSMutableString new];
        [gMtopLog appendFormat:@"%@\n", s];
        if (gMtopLog.length > 500000) gMtopLog = [NSMutableString new];
        [gMtopLog writeToFile:[docsDir() stringByAppendingPathComponent:@"xy_mtop.log"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } @catch (id e) {}
    [gLogLock unlock];
}

static void logMtopReq(id req) {
    @try {
        gMtopCount++;
        MLOG(@"---- REQ #%ld class=%@", gMtopCount, NSStringFromClass([req class]));
        NSString *desc = [req description];
        if (desc.length > 1200) desc = [desc substringToIndex:1200];
        MLOG(@"%@", desc);
    } @catch (id e) {}
}

static void my_async_call_del(id self, SEL _cmd, id req, id dlg) {
    logMtopReq(req);
    orig_async_call_del(self, _cmd, req, dlg);
}
static void my_async2(id self, SEL _cmd, id a, id b, id c) {
    logMtopReq(a);
    orig_async_call_del_sf(self, _cmd, a, b, c);
}
static void my_sync_call(id self, SEL _cmd, id req) {
    logMtopReq(req);
    orig_sync_call(self, _cmd, req);
}
static void my_sync_call_v(id self, SEL _cmd, id a, id b) {
    logMtopReq(a);
    orig_sync_call_v(self, _cmd, a, b);
}
static void my_sync_call_biz(id self, SEL _cmd, id a, id b, id c) {
    logMtopReq(a);
    orig_sync_call_biz(self, _cmd, a, b, c);
}

static void swizzleMtopService(void) {
    Class c = NSClassFromString(@"MtopService");
    if (!c) { W(@"v5: no MtopService"); return; }
    gOrigImps = [NSMutableDictionary new];
    struct { SEL sel; IMP *store; const char *types; } items[] = {
        {@selector(async_call:delegate:), &orig_async_call_del, "v@:@@"},
        {@selector(async_call:delegate:startFilter:), &orig_async_call_del_sf, "v@:@@@"},
        {@selector(sync_call:), &orig_sync_call, "v@:@"},
        {@selector(sync_call:apiVersion:), &orig_sync_call_v, "v@:@@"},
        {@selector(sync_call:apiVersion:bizParameters:), &orig_sync_call_biz, "v@:@@@"},
    };
    for (int i = 0; i < 5; i++) {
        Method m = class_getInstanceMethod(c, items[i].sel);
        if (!m) continue;
        IMP orig = method_getImplementation(m);
        if (items[i].store) *items[i].store = orig;
        NSString *key = NSStringFromSelector(items[i].sel);
        [gOrigImps setObject:[NSValue valueWithPointer:orig] forKey:key];
        IMP newImp = NULL;
        if (sel_isEqual(items[i].sel, @selector(async_call:delegate:))) newImp = (IMP)my_async_call_del;
        else if (sel_isEqual(items[i].sel, @selector(sync_call:))) newImp = (IMP)my_sync_call;
        else if (sel_isEqual(items[i].sel, @selector(sync_call:apiVersion:))) newImp = (IMP)my_sync_call_v;
        else if (sel_isEqual(items[i].sel, @selector(sync_call:apiVersion:bizParameters:))) newImp = (IMP)my_sync_call_biz;
        else if (sel_isEqual(items[i].sel, @selector(async_call:delegate:startFilter:))) newImp = (IMP)my_async2;
        if (newImp) { method_setImplementation(m, newImp); W(@"v5 swizzle %@", key); }
    }
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
        swizzleMtopService();
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
