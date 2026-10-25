//
//  XyProbe.m — 闲鱼指令执行器 v7.6（修闪退 + reqdump + mrequest 里的 api/data）
//
//  架构：
//    PC(cmd_server.py :8081)  <--HTTP-->  dylib（TrollFools 注入，常驻闲鱼进程）
//      dylib 每 2s GET /cmd 拉批量指令 -> MtopService.sync_call（真机签名）逐条执行
//      结果 POST /res 回传；Filza 文件通道保留为后备。
//
#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>
#import <AVFoundation/AVFoundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <objc/message.h>

static NSMutableString *gLog = nil;     // 摘要 → xy_probe.log
static NSMutableString *gBridge = nil;  // 全量桥流量 → xy_bridge.log
static WKWebView *gWebView = nil;       // 活跃 webview
static NSLock *gLogLock = nil;
static NSMutableDictionary *gPending;   // cbId -> tag
static long long gLastCmdAt = 0;
static long gCmdSeq = 0;

// v6 网络通道
static NSString *gSrv = @"http://192.168.6.72:8081";
static NSString *gDevid = nil;
static dispatch_queue_t gExecQueue = nil;
static long gNetCmdCount = 0;
static void swizzleMtopService(void);   // 前向声明（v5 段定义）

static BOOL gLogDirty = NO;
static BOOL gReqDump = NO;   // 只在排查时打开：把请求对象 description + ivar 全打出来
static double gLastFlush = 0;

// ★ v7.4：日志缓冲区加锁 —— 之前 W()/B() 在 MTOP 回调线程无锁 append，
//   主线程 flushLogs 同时读取/替换指针，导致 EXC_BAD_ACCESS（Runner 闪退）
static void wlogAppend(NSString *s, BOOL bridge) {
    if (!s) return;
    if (!gLogLock) gLogLock = [NSLock new];
    [gLogLock lock];
    NSMutableString *buf = bridge ? gBridge : gLog;
    if (!buf) {
        buf = [NSMutableString new];
        if (bridge) gBridge = buf; else gLog = buf;
    }
    [buf appendString:s];
    [buf appendString:@"\n"];
    NSUInteger cap = bridge ? 1000000 : 250000;
    NSUInteger keep = bridge ? 500000 : 120000;
    if (buf.length > cap) {
        // 原地删头，绝不换指针（换指针会让正在写盘的线程 use-after-free）
        [buf deleteCharactersInRange:NSMakeRange(0, keep)];
    }
    gLogDirty = YES;
    [gLogLock unlock];
}

static void W(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    wlogAppend(s, NO);
}

static void B(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    wlogAppend(s, YES);
}

static NSString *docsDir(void) {
    return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
}

static void flushLogs(void) {
    if (!gLogLock) gLogLock = [NSLock new];
    // 1.5s 内最多写一次盘，避免 0.5s 一次全量重写拖慢主线程
    double now = [[NSDate date] timeIntervalSince1970];
    if (now - gLastFlush < 1.5) return;
    NSString *a = nil, *b = nil;
    [gLogLock lock];
    if (!gLogDirty) { [gLogLock unlock]; return; }
    gLogDirty = NO;
    gLastFlush = now;
    a = gLog ? [gLog copy] : nil;      // 拷贝在锁内，写盘在锁外
    b = gBridge ? [gBridge copy] : nil;
    [gLogLock unlock];
    @try {
        if (a.length) {
            [a writeToFile:[docsDir() stringByAppendingPathComponent:@"xy_probe.log"]
                atomically:YES encoding:NSUTF8StringEncoding error:nil];
        }
        if (b.length) {
            [b writeToFile:[docsDir() stringByAppendingPathComponent:@"xy_bridge.log"]
                atomically:YES encoding:NSUTF8StringEncoding error:nil];
        }
    } @catch (NSException *e) {
        // 写盘失败不能把 App 带走
    }
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

// ---------- mtop 执行核心（文件通道与网络通道共用） ----------
// 返回 payload 文本（描述文本，内含 http body JSON）；失败返回错误说明
static NSString *runMtop(NSString *api, NSString *v, id data, NSString *site, NSString *tag) {
    if (!site.length) site = @"xianyu";
    W(@"MS-CALL %@ v=%@ site=%@ tag=%@", api, v, site, tag);
    flushLogs();
    Class ms = NSClassFromString(@"MtopService");
    if (!ms) { W(@"no MtopService"); flushLogs(); return @"{\"error\":\"no MtopService\"}"; }
    SEL gs = @selector(getInstanceWithAccountSite:);
    if (![ms respondsToSelector:gs]) { W(@"no getInstanceWithAccountSite"); flushLogs(); return @"{\"error\":\"no getInstanceWithAccountSite\"}"; }
    id inst = ((id (*)(id, SEL, id))objc_msgSend)(ms, gs, site);
    if (!inst) { W(@"no MtopService instance"); flushLogs(); return @"{\"error\":\"no MtopService instance\"}"; }
    SEL call = @selector(sync_call:apiVersion:bizParameters:);
    if (![inst respondsToSelector:call]) { W(@"no sync_call sel"); flushLogs(); return @"{\"error\":\"no sync_call sel\"}"; }
    id resp = nil;
    @try {
        resp = ((id (*)(id, SEL, id, id, id))objc_msgSend)(inst, call, api, v, data);
        W(@"MS-RESP class=%@", NSStringFromClass([resp class]));
    } @catch (NSException *e) {
        W(@"MS-EXCEPTION %@: %@", e.name, e.reason);
        flushLogs();
        return [NSString stringWithFormat:@"{\"error\":\"exception\",\"name\":\"%@\",\"reason\":\"%@\"}", e.name, e.reason];
    }
    // 序列化响应：优先 data 属性，其次整体 JSON，最后 description
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
    W(@"MS-DONE tag=%@ respLen=%lu", tag, (unsigned long)payload.length);
    flushLogs();
    return payload;
}

// ---------- v6 网络指令通道 ----------
static NSString *loginUid(void) {
    // 当前登录账号：优先 uid，其次 unb；值可能带引号
    for (NSHTTPCookie *c in [[NSHTTPCookieStorage sharedHTTPCookieStorage] cookies]) {
        if ([c.name isEqualToString:@"uid"] || [c.name isEqualToString:@"unb"]) {
            NSString *v = [c.value stringByReplacingOccurrencesOfString:@"\"" withString:@""];
            if (v.length >= 6) return v;
        }
    }
    return @"";
}

static void postResult(NSString *tag, NSString *api, NSString *payload) {
    @try {
        NSDictionary *rec = @{@"tag": tag ?: @"", @"api": api ?: @"",
                              @"payload": payload ?: @"", @"devid": gDevid ?: @"",
                              @"uid": loginUid() ?: @""};
        NSData *jd = [NSJSONSerialization dataWithJSONObject:rec options:0 error:nil];
        if (!jd) return;
        NSMutableURLRequest *rq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:[gSrv stringByAppendingString:@"/res"]]];
        rq.HTTPMethod = @"POST";
        rq.HTTPBody = jd;
        rq.timeoutInterval = 20;
        [NSURLConnection sendSynchronousRequest:rq returningResponse:NULL error:nil];
    } @catch (id e) {}
}

static void execNetCmd(NSDictionary *cmd) {
    @autoreleasepool {
        NSString *api = cmd[@"api"];
        if (!api.length) return;
        // 远程控制指令
        if ([api isEqualToString:@"__swizzle"]) {
            swizzleMtopService();
            postResult(cmd[@"tag"], @"__swizzle", @"{\"ok\":true}");
            return;
        }
        if ([api isEqualToString:@"__dump"]) {
            NSString *p = [docsDir() stringByAppendingPathComponent:@"xy_mtop.log"];
            NSString *log = [NSString stringWithContentsOfFile:p encoding:NSUTF8StringEncoding error:nil] ?: @"";
            if (log.length > 250000) log = [log substringFromIndex:log.length - 250000];
            postResult(cmd[@"tag"], @"__dump", log);
            return;
        }
        NSString *v = [cmd[@"v"] isKindOfClass:[NSString class]] ? cmd[@"v"] : [NSString stringWithFormat:@"%@", cmd[@"v"] ?: @"1.0"];
        NSString *tag = cmd[@"tag"] ?: @"";
        NSString *site = cmd[@"site"] ?: @"xianyu";
        id data = cmd[@"data"] ?: @{};
        gNetCmdCount++;
        NSString *payload = runMtop(api, v, data, site, tag);
        writeResult(tag, api, payload);   // 落盘备份
        postResult(tag, api, payload);    // 回传 PC
    }
}

static void pollNet(void) {
    NSString *uid = loginUid() ?: @"";
    NSString *url = [gSrv stringByAppendingString:[NSString stringWithFormat:@"/cmd?uid=%@", uid]];
    NSMutableURLRequest *rq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
    rq.timeoutInterval = 8;
    [[[NSURLSession sharedSession] dataTaskWithRequest:rq completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
        if (!d || e) return;
        id arr = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
        if (![arr isKindOfClass:[NSArray class]]) return;
        NSArray *cmds = (NSArray *)arr;
        if (cmds.count == 0) return;
        W(@"NET batch=%lu uid=%@", (unsigned long)cmds.count, uid);
        flushLogs();
        for (NSDictionary *cmd in cmds) {
            if (![cmd isKindOfClass:[NSDictionary class]]) continue;
            dispatch_async(gExecQueue, ^{ execNetCmd(cmd); });
        }
    }] resume];
}

// ---------- 文件通道（后备） ----------
static void execCall(NSDictionary *cmd) {
    NSString *api = cmd[@"api"];
    if (!api.length) return;
    NSString *v = cmd[@"v"] ?: @"1.0";
    NSString *tag = cmd[@"tag"] ?: @"";
    NSString *site = cmd[@"site"] ?: @"xianyu";
    id data = cmd[@"data"] ?: @{};
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            NSString *payload = runMtop(api, v, data, site, tag);
            writeResult(tag, api, payload);
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

// ---------- v5: MtopService 全请求日志 ----------
static NSMutableString *gMtopLog = nil;
static NSMutableDictionary *gOrigImps = nil;
static long gMtopCount = 0;
static void (*orig_async_call_del)(id, SEL, id, id);
static void (*orig_async_call_del_sf)(id, SEL, id, id, id);
static id (*orig_sync_call)(id, SEL, id);
static id (*orig_sync_call_v)(id, SEL, id, id);
static id (*orig_sync_call_biz)(id, SEL, id, id, id);

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
        Class c = [req class];
        unsigned int pc = 0;
        objc_property_t *props = class_copyPropertyList(c, &pc);
        for (unsigned int i = 0; i < pc; i++) {
            const char *pn = property_getName(props[i]);
            @try {
                id v = [req valueForKey:@(pn)];
                NSString *vs = nil;
                if ([v isKindOfClass:[NSString class]]) vs = v;
                else if (v) { NSData *jd = [NSJSONSerialization dataWithJSONObject:v options:0 error:nil]; vs = jd ? [[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding] : [v description]; }
                if (vs.length > 2000) vs = [vs substringToIndex:2000];
                MLOG(@"  %@ = %@", @(pn), vs ?: @"(nil)");
            } @catch (id e) {
                MLOG(@"  %@ = (KVC fail)", @(pn));
            }
        }
        if (pc) free(props);
        if (gReqDump) {
            MLOG(@"  DESC = %@", [req description]);
            unsigned int ic = 0;
            Ivar *ivs = class_copyIvarList(c, &ic);
            for (unsigned int i = 0; i < ic; i++) {
                const char *in = ivar_getName(ivs[i]);
                NSString *ns = @(in ?: "");
                if (![ns.lowercaseString containsString:@"api"] &&
                    ![ns.lowercaseString containsString:@"request"] &&
                    ![ns.lowercaseString containsString:@"data"]) continue;
                @try {
                    id v = object_getIvar(req, ivs[i]);
                    MLOG(@"  IVAR %@ = %@", ns, v ? [v description] : @"(nil)");
                } @catch (id e) { MLOG(@"  IVAR %@ = (fail)", ns); }
            }
            if (ic) free(ivs);
            // ★ v7.6：api/data 在 mrequest（TBSDKRequest）里，单独挖一层
            @try {
                Ivar miv = class_getInstanceVariable(c, "mrequest");
                id mr = miv ? object_getIvar(req, miv) : nil;
                if (mr) {
                    MLOG(@"  MREQ class=%@ desc=%@", NSStringFromClass([mr class]), [mr description]);
                    unsigned int pc2 = 0;
                    objc_property_t *p2 = class_copyPropertyList([mr class], &pc2);
                    for (unsigned int j = 0; j < pc2; j++) {
                        const char *pn = property_getName(p2[j]);
                        @try {
                            id v = [mr valueForKey:@(pn)];
                            NSString *vs = nil;
                            if ([v isKindOfClass:[NSString class]]) vs = v;
                            else if (v) {
                                NSData *jd = [NSJSONSerialization dataWithJSONObject:v options:0 error:nil];
                                vs = jd ? [[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding] : [v description];
                            }
                            if (vs.length > 1500) vs = [vs substringToIndex:1500];
                            MLOG(@"    %@ = %@", @(pn), vs ?: @"(nil)");
                        } @catch (id e2) { MLOG(@"    %@ = (KVC fail)", @(pn)); }
                    }
                    if (pc2) free(p2);
                }
            } @catch (id e3) {}
        }
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
static id my_sync_call(id self, SEL _cmd, id req) {
    logMtopReq(req);
    return orig_sync_call(self, _cmd, req);
}
static id my_sync_call_v(id self, SEL _cmd, id a, id b) {
    logMtopReq(a);
    return orig_sync_call_v(self, _cmd, a, b);
}
static id my_sync_call_biz(id self, SEL _cmd, id a, id b, id c) {
    logMtopReq(a);
    return orig_sync_call_biz(self, _cmd, a, b, c);
}

static void swizzleMtopService(void) {
    Class c = NSClassFromString(@"MtopService");
    if (!c) { W(@"v5: no MtopService"); return; }
    if (gOrigImps) { W(@"v5 already swizzled"); return; }  // 幂等保护
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


// ================= v7：后台常驻（静音音频） =================
static AVAudioPlayer *gKaPlayer = nil;
static AVAudioEngine *gKaEngine = nil;
static AVAudioPlayerNode *gKaNode = nil;
static BOOL gKaWanted = YES;
static long long gKaLastTry = 0;

static NSData *xySilentWav(void) {
    uint32_t sr = 8000, ch = 1, bits = 16;
    uint32_t dataSize = sr * ch * (bits / 8);
    NSMutableData *d = [NSMutableData data];
    void (^put)(const char *, uint32_t) = ^(const char *tag, uint32_t v) {
        [d appendBytes:tag length:4];
        uint32_t le = v;
        [d appendBytes:&le length:4];
    };
    put("RIFF", 36 + dataSize);
    [d appendBytes:"WAVE" length:4];
    put("fmt ", 16);
    uint16_t fmt = 1;
    uint32_t srv = sr;
    uint32_t byteRate = sr * ch * (bits / 8);
    uint32_t blockAlign = ch * (bits / 8);
    uint16_t bps = (uint16_t)bits;
    [d appendBytes:&fmt length:2];          // ★ 必须是 2 字节，之前误写 4 字节导致 WAV 头错位
    uint16_t ch16 = (uint16_t)ch;
    [d appendBytes:&ch16 length:2];
    [d appendBytes:&srv length:4];
    [d appendBytes:&byteRate length:4];
    uint16_t ba = (uint16_t)blockAlign;
    [d appendBytes:&ba length:2];
    [d appendBytes:&bps length:2];
    put("data", dataSize);
    // 不用全 0：填 ±1 LSB（约 -90dB，人耳听不到），避免被系统按“纯静音”判定
    NSMutableData *pcm = [NSMutableData dataWithLength:dataSize];
    int16_t *sp = (int16_t *)pcm.mutableBytes;
    for (uint32_t i = 0; i < dataSize / 2; i++) sp[i] = (i % 2) ? 1 : -1;
    [d appendData:pcm];
    return d;
}


// 兜底方案：AVAudioEngine 循环播放极低幅度 PCM（不依赖 WAV 解析）
static void xyStartEngineKeepAlive(NSString *why) {
    @try {
        if (gKaNode && gKaNode.isPlaying) return;
        AVAudioEngine *e = [AVAudioEngine new];
        AVAudioPlayerNode *n = [AVAudioPlayerNode new];
        AVAudioFormat *fmt = [[AVAudioFormat alloc] initStandardFormatWithSampleRate:44100 channels:1];
        [e attachNode:n];
        [e connect:n to:e.mainMixerNode format:fmt];
        NSError *err = nil;
        if (![e startAndReturnError:&err]) { W(@"v7 engine start err=%@", err.localizedDescription); return; }
        AVAudioPCMBuffer *buf = [[AVAudioPCMBuffer alloc] initWithPCMFormat:fmt frameCapacity:44100];
        buf.frameLength = 44100;
        float *ch0 = buf.floatChannelData[0];
        for (int i = 0; i < 44100; i++) ch0[i] = (i % 2) ? (1.0f / 32768.0f) : (-1.0f / 32768.0f);
        [n scheduleBuffer:buf atTime:nil options:AVAudioPlayerNodeBufferLoops completionHandler:nil];
        [n play];
        gKaEngine = e;
        gKaNode = n;
        W(@"v7 engine keepalive[%@] playing=%d", why, n.isPlaying);
    } @catch (id ex) {
        W(@"v7 engine EXC %@", ex);
    }
}

static void xyStartKeepAlive(NSString *why) {
    if (!gKaWanted) return;
    long long now = (long long)([[NSDate date] timeIntervalSince1970] * 1000);
    if (gKaPlayer && gKaPlayer.isPlaying) return;
    if (now - gKaLastTry < 3000) return;      // 3s 内不重复尝试
    gKaLastTry = now;
    @try {
        AVAudioSession *s = [AVAudioSession sharedInstance];
        NSError *e1 = nil, *e2 = nil;
        [s setCategory:AVAudioSessionCategoryPlayback
                  mode:AVAudioSessionModeDefault
               options:AVAudioSessionCategoryOptionMixWithOthers
                 error:&e1];
        [s setActive:YES error:&e2];
        NSError *perr = nil;
        gKaPlayer = [[AVAudioPlayer alloc] initWithData:xySilentWav() error:&perr];
        if (!gKaPlayer) {
            W(@"v7 player nil err=%@ wavLen=%lu", perr.localizedDescription, (unsigned long)xySilentWav().length);
            xyStartEngineKeepAlive(@"player-nil");
            return;
        }
        gKaPlayer.numberOfLoops = -1;
        gKaPlayer.volume = 0.05;
        [gKaPlayer prepareToPlay];
        BOOL ok = [gKaPlayer play];
        if (!ok) xyStartEngineKeepAlive(@"play-failed");
        W(@"v7 keepalive[%@] play=%d playing=%d cat_err=%@ act_err=%@",
          why, ok, gKaPlayer.isPlaying, e1.localizedDescription, e2.localizedDescription);
    } @catch (id e) {
        W(@"v7 keepalive EXC %@", e);
    }
}

static void xyStopKeepAlive(void) {
    gKaWanted = NO;
    @try {
        [gKaPlayer stop];
        gKaPlayer = nil;
        [gKaNode stop]; gKaNode = nil; [gKaEngine stop]; gKaEngine = nil;
        [[AVAudioSession sharedInstance] setActive:NO
                                      withOptions:AVAudioSessionSetActiveOptionNotifyOthersOnDeactivation
                                            error:nil];
    } @catch (id e) {}
    W(@"v7 keepalive stopped");
}

static void xyInstallKeepAliveHooks(void) {
    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    [nc addObserverForName:AVAudioSessionInterruptionNotification object:nil queue:[NSOperationQueue mainQueue]
                usingBlock:^(NSNotification *n) {
        NSInteger t = [n.userInfo[AVAudioSessionInterruptionTypeKey] integerValue];
        if (t == AVAudioSessionInterruptionTypeEnded) {
            gKaPlayer = nil;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ xyStartKeepAlive(@"interruption-end"); });
        } else {
            W(@"v7 audio interrupted");
        }
    }];
    [nc addObserverForName:UIApplicationDidEnterBackgroundNotification object:nil queue:[NSOperationQueue mainQueue]
                usingBlock:^(NSNotification *n) {
        W(@"v7 entered background -> keepalive");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ xyStartKeepAlive(@"bg"); });
    }];
    [nc addObserverForName:UIApplicationWillEnterForegroundNotification object:nil queue:[NSOperationQueue mainQueue]
                usingBlock:^(NSNotification *n) { W(@"v7 entered foreground"); }];
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
        if (at > nowms + 60000) return;
        gLastCmdAt = at;
        NSString *mode = obj[@"mode"] ?: @"";
        W(@"CMD mode=%@ at=%lld", mode, at);
        if ([mode isEqualToString:@"call"]) {
            if (![obj[@"arm"] boolValue]) { W(@"call not armed, skip"); return; }
            execCall(obj);
        } else if ([mode isEqualToString:@"swizzle"]) {
            swizzleMtopService();
        } else if ([mode isEqualToString:@"reqdump"]) {
            gReqDump = obj[@"on"] ? [obj[@"on"] boolValue] : YES;
            if (gReqDump) swizzleMtopService();
            W(@"reqdump=%d", gReqDump);
        } else if ([mode isEqualToString:@"scan"]) {
            scanClasses();
        } else if ([mode isEqualToString:@"cookies"]) {
            dumpCookiesTo(@"cmd");
        } else if ([mode isEqualToString:@"ka"]) {
            if (obj[@"on"] && ![obj[@"on"] boolValue]) { xyStopKeepAlive(); }
            else { gKaWanted = YES; gKaPlayer = nil; xyStartKeepAlive(@"cmd"); }
            W(@"ka wanted=%d playing=%d", gKaWanted, gKaPlayer.isPlaying);
        } else if ([mode isEqualToString:@"ping"]) {
            W(@"ping ok bg=%d ka=%d eng=%d", (int)([UIApplication sharedApplication].applicationState == UIApplicationStateBackground),
              (int)gKaPlayer.isPlaying, (int)(gKaNode && gKaNode.isPlaying));
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
        gDevid = [[NSUUID UUID] UUIDString];
        gExecQueue = dispatch_queue_create("xy.exec.v6", DISPATCH_QUEUE_SERIAL);
        doSwizzle();
        W(@"---- executor v6.1 (multi-account) at %@ ----", [NSDate date]);
        W(@"bundle=%@ srv=%@ devid=%@ uid=%@", [[NSBundle mainBundle] bundleIdentifier], gSrv, gDevid, loginUid());
        dumpCookiesTo(@"boot");
        flushLogs();
        dispatch_async(dispatch_get_main_queue(), ^{
            xyInstallKeepAliveHooks();
            xyStartKeepAlive(@"boot");
            // 文件通道：0.5s 一次，指令响应快
            [NSTimer scheduledTimerWithTimeInterval:0.5 repeats:YES block:^(NSTimer *t) {
                pollCmd();
                flushLogs();
            }];
            // 网络通道 + 保活看门狗：2s 一次（避免请求过密）
            __block long kaTick = 0;
            [NSTimer scheduledTimerWithTimeInterval:2.0 repeats:YES block:^(NSTimer *t) {
                pollNet();
                flushLogs();
                if (++kaTick % 15 == 0 && gKaWanted && !gKaPlayer.isPlaying && !(gKaNode && gKaNode.isPlaying)) {
                    xyStartKeepAlive(@"watchdog");
                }
            }];
            W(@"v7.6 timers started (file 0.5s + net 2s + keepalive + log-lock + reqdump + mrequest)");
            flushLogs();
        });
    }
}
