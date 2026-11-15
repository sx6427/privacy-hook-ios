//
//  DamaiSpy.m — 大麦（cn.damai.iphone）进程内探针 v0.1
//
//  注入方式：TrollFools 注入 DMPortal.app（重签，CoreTrust 签名）
//  核心思想：不走代理、不碰证书 —— 在 MTOP SDK 内部取明文、发请求，
//            签名/设备指纹全部由 App 自己算（真实通道）
//
//  能力：
//    1) Hook MtopService 的 async_call / sync_call 全家族 → 请求 api/data + 响应 JSON
//    2) Hook NSURLSession → 明文 URL / headers / body / 响应体（MTOP 之下的兜底）
//    3) 运行时类扫描（找 抢票/下单/实名 相关类与选择器）
//    4) 指令通道：Documents/dm_cmd.txt（Filza WebDAV 可直写）→ 执行 → dm_out.txt
//    5) 主动调用 MTOP：{"c":"call","api":"...","data":{...}} —— 用 App 自己的签名
//
//  急停：在 Documents 放一个 dm_off 文件，dylib 立刻变哑巴（不再 hook 任何东西）
//
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

static NSString *const kVer = @"v0.1";

// ---------------- 日志 ----------------
static NSLock *gLock;
static NSMutableString *gLog;      // dm_spy.log   启动/状态/扫描摘要
static NSMutableString *gMtopLog;  // dm_mtop.log  MTOP 请求响应（核心产物）
static NSMutableString *gNetLog;   // dm_net.log   NSURLSession 明文
static BOOL gLogDirty, gMtopDirty, gNetDirty;
static double gLastFlush;
static dispatch_queue_t gExecQ;
static long gNwSeq, gMtopSeq;
static BOOL gNetOn = NO;
static NSString *gSrv = @"http://192.168.6.72:8082";

static NSString *docs(void) {
    static NSString *d = nil;
    if (!d) d = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return d;
}
static NSString *dpath(NSString *n) { return [docs() stringByAppendingPathComponent:n]; }
static BOOL exists(NSString *n) { return [[NSFileManager defaultManager] fileExistsAtPath:dpath(n)]; }

static void appendLog(int kind, NSString *s, NSUInteger cap, NSUInteger keep) {
    if (!s.length) return;
    if (!gLock) gLock = [NSLock new];
    [gLock lock];
    NSMutableString *buf = (kind == 0) ? gLog : (kind == 1 ? gMtopLog : gNetLog);
    if (!buf) buf = [NSMutableString new];
    [buf appendString:s];
    [buf appendString:@"\n"];
    if (buf.length > cap) [buf deleteCharactersInRange:NSMakeRange(0, keep)];
    if (kind == 0) { gLog = buf; gLogDirty = YES; }
    else if (kind == 1) { gMtopLog = buf; gMtopDirty = YES; }
    else { gNetLog = buf; gNetDirty = YES; }
    [gLock unlock];
}

static void W(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    appendLog(0, s, 160000, 80000);
}
static void M(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    appendLog(1, s, 900000, 400000);
}
static void N(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    appendLog(2, s, 900000, 400000);
}

static void flushAll(void) {
    if (!gLock) gLock = [NSLock new];
    double now = [[NSDate date] timeIntervalSince1970];
    if (now - gLastFlush < 2.0) return;
    NSString *a = nil, *b = nil, *c = nil;
    BOOL da = NO, db = NO, dc = NO;
    [gLock lock];
    if (gLogDirty) { a = [gLog copy]; gLogDirty = NO; da = YES; }
    if (gMtopDirty) { b = [gMtopLog copy]; gMtopDirty = NO; db = YES; }
    if (gNetDirty) { c = [gNetLog copy]; gNetDirty = NO; dc = YES; }
    if (da || db || dc) gLastFlush = now;
    [gLock unlock];
    @try {
        if (a.length) [a writeToFile:dpath(@"dm_spy.log") atomically:YES encoding:NSUTF8StringEncoding error:nil];
        if (b.length) [b writeToFile:dpath(@"dm_mtop.log") atomically:YES encoding:NSUTF8StringEncoding error:nil];
        if (c.length) [c writeToFile:dpath(@"dm_net.log") atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } @catch (id e) {}
}

// ---------------- 对象/字节 预览 ----------------
static NSString *clip(NSString *s, NSUInteger n) {
    if (!s) return @"(nil)";
    return s.length > n ? [[s substringToIndex:n] stringByAppendingString:@"…"] : s;
}

static NSString *dumpObj(id o) {
    if (!o) return @"(nil)";
    NSMutableString *s = [NSMutableString string];
    @try {
        [s appendFormat:@"<%@> %@", NSStringFromClass([o class]), clip([NSString stringWithFormat:@"%@", o], 400)];
        unsigned int n = 0;
        Ivar *ivars = class_copyIvarList([o class], &n);
        for (unsigned int i = 0; i < n; i++) {
            const char *tn = ivar_getTypeEncoding(ivars[i]);
            NSString *nm = [NSString stringWithUTF8String:ivar_getName(ivars[i])];
            if (tn && tn[0] == '@' && tn[1] != '?') {
                id v = nil;
                @try { v = object_getIvar(o, ivars[i]); } @catch (id e) {}
                [s appendFormat:@" | %@=%@", nm, clip([NSString stringWithFormat:@"%@", v ?: @"nil"], 260)];
            } else if (tn) {
                [s appendFormat:@" | %@=(%s)", nm, tn];
            }
        }
        if (ivars) free(ivars);
    } @catch (id e) {
        [s appendFormat:@" <dump-exc %@>", e];
    }
    return s;
}

static NSString *bytesPreview(NSData *d, NSUInteger max) {
    if (!d) return @"(nil)";
    if (!d.length) return @"(empty)";
    NSString *s = [[NSString alloc] initWithData:[d subdataWithRange:NSMakeRange(0, MIN(d.length, max))] encoding:NSUTF8StringEncoding];
    if (!s) {
        const uint8_t *p = (const uint8_t *)d.bytes;
        NSMutableString *h = [NSMutableString stringWithFormat:@"(bin %luB head:", (unsigned long)d.length];
        for (NSUInteger i = 0; i < MIN(d.length, (NSUInteger)24); i++) [h appendFormat:@"%02x", p[i]];
        [h appendString:@")"];
        return h;
    }
    return d.length > max ? [s stringByAppendingString:@"…"] : s;
}

// ---------------- MTOP hook ----------------
typedef struct { Class cls; SEL sel; IMP orig; } HookRec;
static HookRec gHooks[32];
static int gHookCount = 0;

static IMP origFor(SEL cmd) {
    for (int i = 0; i < gHookCount; i++) if (sel_isEqual(gHooks[i].sel, cmd)) return gHooks[i].orig;
    return NULL;
}

static id dm_async2(id self, SEL _cmd, id req, id dlg) {
    gMtopSeq++;
    M(@"==== REQ #%ld -[%@ async_call:delegate:] ====", gMtopSeq, NSStringFromClass([self class]));
    M(@"%@", dumpObj(req));
    IMP o = origFor(_cmd);
    return o ? ((id (*)(id, SEL, id, id))o)(self, _cmd, req, dlg) : nil;
}
static id dm_async3(id self, SEL _cmd, id req, id dlg, id sf) {
    gMtopSeq++;
    M(@"==== REQ #%ld -[%@ async_call:delegate:startFilter:] sf=%@ ====", gMtopSeq, NSStringFromClass([self class]), sf);
    M(@"%@", dumpObj(req));
    IMP o = origFor(_cmd);
    return o ? ((id (*)(id, SEL, id, id, id))o)(self, _cmd, req, dlg, sf) : nil;
}
static id dm_sync1(id self, SEL _cmd, id req) {
    gMtopSeq++;
    M(@"==== REQ #%ld -[%@ sync_call:] ====", gMtopSeq, NSStringFromClass([self class]));
    M(@"%@", dumpObj(req));
    IMP o = origFor(_cmd);
    id r = o ? ((id (*)(id, SEL, id))o)(self, _cmd, req) : nil;
    M(@"---- RESP #%ld sync_call: %@", gMtopSeq, dumpObj(r));
    return r;
}
static id dm_sync2(id self, SEL _cmd, id req, id v) {
    gMtopSeq++;
    M(@"==== REQ #%ld -[%@ sync_call:apiVersion:] v=%@ ====", gMtopSeq, NSStringFromClass([self class]), v);
    M(@"%@", dumpObj(req));
    IMP o = origFor(_cmd);
    id r = o ? ((id (*)(id, SEL, id, id))o)(self, _cmd, req, v) : nil;
    M(@"---- RESP #%ld %@", gMtopSeq, dumpObj(r));
    return r;
}
static id dm_sync3(id self, SEL _cmd, id req, id v, id biz) {
    gMtopSeq++;
    M(@"==== REQ #%ld -[%@ sync_call:apiVersion:bizParameters:] v=%@ biz=%@ ====", gMtopSeq, NSStringFromClass([self class]), v, clip([NSString stringWithFormat:@"%@", biz], 400));
    M(@"%@", dumpObj(req));
    IMP o = origFor(_cmd);
    id r = o ? ((id (*)(id, SEL, id, id, id))o)(self, _cmd, req, v, biz) : nil;
    M(@"---- RESP #%ld %@", gMtopSeq, dumpObj(r));
    return r;
}

static void hookMtop(void) {
    SEL sels[5] = { @selector(async_call:delegate:),
                    @selector(async_call:delegate:startFilter:),
                    @selector(sync_call:),
                    @selector(sync_call:apiVersion:),
                    @selector(sync_call:apiVersion:bizParameters:) };
    IMP news[5] = { (IMP)dm_async2, (IMP)dm_async3, (IMP)dm_sync1, (IMP)dm_sync2, (IMP)dm_sync3 };

    unsigned int count = 0;
    Class *classes = objc_copyClassList(&count);
    if (!classes) return;
    int hooked = 0;
    for (unsigned int i = 0; i < count && gHookCount < 30; i++) {
        Class c = classes[i];
        if (!c) continue;
        NSString *cn = NSStringFromClass(c);
        if (!cn.length) continue;
        for (int k = 0; k < 5; k++) {
            @try {
                Method m = class_getInstanceMethod(c, sels[k]);
                if (!m) continue;
                // 只处理"自己实现"的，继承来的跳过，避免重复 hook
                Class sup = class_getSuperclass(c);
                if (sup) {
                    Method sm = class_getInstanceMethod(sup, sels[k]);
                    if (sm && method_getImplementation(sm) == method_getImplementation(m)) continue;
                }
                IMP orig = method_getImplementation(m);
                // 已经是我们自己的实现就跳过（幂等）
                if (orig == news[k]) continue;
                method_setImplementation(m, news[k]);
                gHooks[gHookCount].cls = c;
                gHooks[gHookCount].sel = sels[k];
                gHooks[gHookCount].orig = orig;
                gHookCount++; hooked++;
                M(@"HOOK -[%@ %@]", cn, NSStringFromSelector(sels[k]));
            } @catch (id e) {
                M(@"HOOK-EXC %@ %@: %@", cn, NSStringFromSelector(sels[k]), e);
            }
        }
    }
    free(classes);
    M(@"hook done: %d hooks on mtop selectors", hooked);
}

// ---------------- NSURLSession 明文 hook ----------------
static id (*o_dt_ch)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *));
static id (*o_up_ch)(id, SEL, NSURLRequest *, NSData *, void (^)(NSData *, NSURLResponse *, NSError *));
static id (*o_dt)(id, SEL, NSURLRequest *);

static void logReq(NSString *tag, NSURLRequest *rq) {
    N(@"==== %@ %@ %@ ====", tag, rq.HTTPMethod ?: @"GET", rq.URL.absoluteString);
    if (rq.allHTTPHeaderFields.count) N(@"HDR %@", clip([NSString stringWithFormat:@"%@", rq.allHTTPHeaderFields], 1500));
    if (rq.HTTPBody) N(@"BODY(%lu) %@", (unsigned long)rq.HTTPBody.length, clip(bytesPreview(rq.HTTPBody, 2200), 2200));
    else if (rq.HTTPBodyStream) N(@"BODY(stream)");
}
static void logResp(NSString *tag, NSString *url, NSURLResponse *r, NSData *d, NSError *e) {
    NSInteger code = [r isKindOfClass:[NSHTTPURLResponse class]] ? [(NSHTTPURLResponse *)r statusCode] : -1;
    N(@"---- %@ %ld %@ len=%lu err=%@ ct=%@", tag, (long)code, clip(url, 200), (unsigned long)d.length, e.localizedDescription ?: @"nil", r.MIMEType ?: @"-");
    if (d.length) N(@"RESP %@", clip(bytesPreview(d, 3000), 3000));
}

static id dm_dt_ch(id self, SEL _cmd, NSURLRequest *rq, void (^ch)(NSData *, NSURLResponse *, NSError *)) {
    NSString *tag = [NSString stringWithFormat:@"nw#%ld", ++gNwSeq];
    logReq(tag, rq);
    void (^wrapped)(NSData *, NSURLResponse *, NSError *) = ^(NSData *d, NSURLResponse *r, NSError *e) {
        logResp(tag, rq.URL.absoluteString, r, d, e);
        if (ch) ch(d, r, e);
    };
    return o_dt_ch ? o_dt_ch(self, _cmd, rq, wrapped) : nil;
}
static id dm_up_ch(id self, SEL _cmd, NSURLRequest *rq, NSData *body, void (^ch)(NSData *, NSURLResponse *, NSError *)) {
    NSString *tag = [NSString stringWithFormat:@"nw#%ld", ++gNwSeq];
    logReq(tag, rq);
    if (body) N(@"UPBODY(%lu) %@", (unsigned long)body.length, clip(bytesPreview(body, 2200), 2200));
    void (^wrapped)(NSData *, NSURLResponse *, NSError *) = ^(NSData *d, NSURLResponse *r, NSError *e) {
        logResp(tag, rq.URL.absoluteString, r, d, e);
        if (ch) ch(d, r, e);
    };
    return o_up_ch ? o_up_ch(self, _cmd, rq, body, wrapped) : nil;
}
static id dm_dt(id self, SEL _cmd, NSURLRequest *rq) {
    logReq([NSString stringWithFormat:@"nw#%ld(no-cb)", ++gNwSeq], rq);
    return o_dt ? o_dt(self, _cmd, rq) : nil;
}

static void hookNet(void) {
    Class c = [NSURLSession class];
    Method m1 = class_getInstanceMethod(c, @selector(dataTaskWithRequest:completionHandler:));
    if (m1) { o_dt_ch = (void *)method_getImplementation(m1); method_setImplementation(m1, (IMP)dm_dt_ch); W(@"hook dataTaskWithRequest:completionHandler:"); }
    Method m2 = class_getInstanceMethod(c, @selector(uploadTaskWithRequest:fromData:completionHandler:));
    if (m2) { o_up_ch = (void *)method_getImplementation(m2); method_setImplementation(m2, (IMP)dm_up_ch); W(@"hook uploadTaskWithRequest:fromData:completionHandler:"); }
    Method m3 = class_getInstanceMethod(c, @selector(dataTaskWithRequest:));
    if (m3) { o_dt = (void *)method_getImplementation(m3); method_setImplementation(m3, (IMP)dm_dt); W(@"hook dataTaskWithRequest:"); }
}

// ---------------- 类扫描 ----------------
static NSArray *kwList(NSString *s) {
    NSMutableArray *a = [NSMutableArray array];
    for (NSString *p in [s componentsSeparatedByString:@","]) {
        NSString *t = [p stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]].lowercaseString;
        if (t.length) [a addObject:t];
    }
    if (!a.count) [a addObjectsFromArray:@[@"mtop", @"trade", @"order", @"ticket", @"buy", @"seat", @"attendee"]];
    return a;
}

static NSString *scanClasses(NSString *kws) {
    NSArray *kw = kwList(kws);
    NSMutableString *out = [NSMutableString string];
    unsigned int count = 0;
    Class *classes = objc_copyClassList(&count);
    if (!classes) return @"scan failed";
    [out appendFormat:@"==== scan kw=%@ total=%u ====\n", [kw componentsJoinedByString:@"|"], count];
    int matched = 0;
    for (unsigned int i = 0; i < count; i++) {
        Class c = classes[i];
        NSString *n = NSStringFromClass(c);
        if (!n.length) continue;
        NSString *ln = n.lowercaseString;
        BOOL hit = NO;
        for (NSString *k in kw) if ([ln containsString:k]) { hit = YES; break; }
        if (!hit) continue;
        matched++;
        [out appendFormat:@"--- %@ (super=%@) ---\n", n, NSStringFromClass(class_getSuperclass(c))];
        unsigned int mc = 0;
        Method *ms = class_copyMethodList(c, &mc);
        for (unsigned int j = 0; j < mc && j < 120; j++) {
            [out appendFormat:@"  -%@\n", NSStringFromSelector(method_getName(ms[j]))];
        }
        if (ms) free(ms);
        if (matched > 220) { [out appendString:@"... (truncated)\n"]; break; }
    }
    free(classes);
    [out appendFormat:@"==== done matched=%d ====\n", matched];
    return out;
}

// ---------------- 主动调 MTOP ----------------
static Class mtopServiceClass(void) {
    Class c = NSClassFromString(@"MtopService");
    if (c) return c;
    for (int i = 0; i < gHookCount; i++) {
        if (sel_isEqual(gHooks[i].sel, @selector(sync_call:apiVersion:bizParameters:))) return gHooks[i].cls;
    }
    return Nil;
}

static NSString *runMtop(NSString *api, NSString *v, id data, NSString *site, NSString *tag) {
    Class c = mtopServiceClass();
    if (!c) return @"{\"err\":\"no mtop service class\"}";
    id inst = nil;
    if ([c respondsToSelector:@selector(getInstanceWithAccountSite:)]) {
        NSArray *sites = site.length ? @[site] : @[@"damai", @"DM", @"damai_app", @"mtop", @"taobao"];
        for (NSString *s in sites) {
            @try { inst = ((id (*)(id, SEL, id))objc_msgSend)(c, @selector(getInstanceWithAccountSite:), s); } @catch (id e) { inst = nil; }
            if (inst) { W(@"mtop inst via site=%@", s); break; }
        }
    }
    if (!inst && [c respondsToSelector:@selector(sharedInstance)]) inst = ((id (*)(id, SEL))objc_msgSend)(c, @selector(sharedInstance));
    if (!inst) return @"{\"err\":\"no mtop instance\"}";

    SEL call = @selector(sync_call:apiVersion:bizParameters:);
    if (![inst respondsToSelector:call]) return @"{\"err\":\"no sync_call:apiVersion:bizParameters:\"}";
    id resp = nil;
    @try {
        resp = ((id (*)(id, SEL, id, id, id))objc_msgSend)(inst, call, api, v ?: @"1.0", data ?: @{});
    } @catch (NSException *e) {
        return [NSString stringWithFormat:@"{\"err\":\"exception\",\"name\":\"%@\",\"reason\":\"%@\"}", e.name, clip(e.reason, 300)];
    }
    NSMutableString *payload = [NSMutableString string];
    id d = nil;
    @try { d = [resp valueForKey:@"data"]; } @catch (id e) {}
    if ([d isKindOfClass:[NSDictionary class]] || [d isKindOfClass:[NSArray class]]) {
        NSData *jd = [NSJSONSerialization dataWithJSONObject:d options:NSJSONWritingWithoutEscapingSlashes error:nil];
        if (jd) [payload appendString:[[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding]];
    }
    if (!payload.length) {
        NSData *jd = nil;
        if ([resp isKindOfClass:[NSDictionary class]] || [resp isKindOfClass:[NSArray class]])
            jd = [NSJSONSerialization dataWithJSONObject:resp options:NSJSONWritingWithoutEscapingSlashes error:nil];
        if (jd) [payload appendString:[[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding]];
    }
    if (!payload.length) [payload appendString:[NSString stringWithFormat:@"%@", resp ?: @"(nil)"]];
    if (payload.length > 260000) [payload deleteCharactersInRange:NSMakeRange(260000, payload.length - 260000)];
    M(@"CALL tag=%@ api=%@ len=%lu", tag ?: @"-", api, (unsigned long)payload.length);
    return payload;
}

// ---------------- 指令通道 ----------------
static NSString *gLastCmd = nil;

static void writeOut(NSString *s) {
    @try { [s writeToFile:dpath(@"dm_out.txt") atomically:YES encoding:NSUTF8StringEncoding error:nil]; } @catch (id e) {}
    W(@"OUT len=%lu", (unsigned long)s.length);
}

static void execCmd(NSDictionary *cmd) {
    NSString *c = cmd[@"c"] ?: cmd[@"cmd"];
    if (![c isKindOfClass:[NSString class]]) return;
    NSString *tag = cmd[@"tag"] ?: @"-";
    if ([c isEqualToString:@"ping"]) {
        writeOut([NSString stringWithFormat:@"pong %@ hooks=%d bundle=%@\n", kVer, gHookCount, [[NSBundle mainBundle] bundleIdentifier]]);
    } else if ([c isEqualToString:@"scan"]) {
        NSString *kw = [cmd[@"kw"] isKindOfClass:[NSString class]] ? cmd[@"kw"] : nil;
        writeOut(scanClasses(kw));
    } else if ([c isEqualToString:@"call"]) {
        NSString *api = cmd[@"api"];
        NSString *v = [cmd[@"v"] isKindOfClass:[NSString class]] ? cmd[@"v"] : @"1.0";
        NSString *site = [cmd[@"site"] isKindOfClass:[NSString class]] ? cmd[@"site"] : nil;
        id data = cmd[@"data"] ?: @{};
        NSString *payload = runMtop(api, v, data, site, tag);
        writeOut([NSString stringWithFormat:@"[call %@ %@]\n%@\n", api, tag, payload]);
        [payload writeToFile:dpath([NSString stringWithFormat:@"dm_res_%@.json", tag]) atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } else if ([c isEqualToString:@"dump"]) {
        NSString *f = [cmd[@"file"] isKindOfClass:[NSString class]] ? cmd[@"file"] : @"dm_mtop.log";
        NSString *s = [NSString stringWithContentsOfFile:dpath(f) encoding:NSUTF8StringEncoding error:nil] ?: @"(empty)";
        if (s.length > 260000) s = [s substringFromIndex:s.length - 260000];
        writeOut(s);
    } else if ([c isEqualToString:@"clear"]) {
        if ([cmd[@"what"] isEqualToString:@"mtop"]) { [gLock lock]; [gMtopLog setString:@""]; gMtopDirty = YES; [gLock unlock]; }
        writeOut(@"cleared");
    } else if ([c isEqualToString:@"mtopinfo"]) {
        NSMutableString *o = [NSMutableString string];
        Class c2 = mtopServiceClass();
        [o appendFormat:@"class=%@ hooks=%d\n", c2 ? NSStringFromClass(c2) : @"nil", gHookCount];
        for (int i = 0; i < gHookCount; i++)
            [o appendFormat:@"  -[%@ %@]\n", NSStringFromClass(gHooks[i].cls), NSStringFromSelector(gHooks[i].sel)];
        if (c2) {
            [o appendFormat:@"classMethods:\n"];
            unsigned int mc = 0;
            Method *ms = class_copyMethodList(object_getClass(c2), &mc);
            for (unsigned int j = 0; j < mc && j < 80; j++) [o appendFormat:@"  +%@\n", NSStringFromSelector(method_getName(ms[j]))];
            if (ms) free(ms);
        }
        writeOut(o);
    }
}

static void pollCmd(void) {
    NSString *p = dpath(@"dm_cmd.txt");
    NSString *s = [NSString stringWithContentsOfFile:p encoding:NSUTF8StringEncoding error:nil];
    if (!s.length || (gLastCmd && [s isEqualToString:gLastCmd])) return;
    gLastCmd = s;
    for (NSString *line in [s componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
        NSString *t = [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if (t.length < 2) continue;
        NSData *jd = [t dataUsingEncoding:NSUTF8StringEncoding];
        id obj = [NSJSONSerialization JSONObjectWithData:jd options:0 error:nil];
        if ([obj isKindOfClass:[NSDictionary class]])
            dispatch_async(gExecQ, ^{ @autoreleasepool { execCmd((NSDictionary *)obj); } });
        else W(@"cmd parse fail: %@", clip(t, 120));
    }
}

static void pollNet(void) {
    if (!gNetOn) return;
    NSMutableURLRequest *rq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:[gSrv stringByAppendingString:@"/cmd"]]];
    rq.timeoutInterval = 8;
    [[[NSURLSession sharedSession] dataTaskWithRequest:rq completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
        if (!d || e) return;
        id arr = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
        if (![arr isKindOfClass:[NSArray class]]) return;
        for (NSDictionary *cmd in (NSArray *)arr) {
            if (![cmd isKindOfClass:[NSDictionary class]]) continue;
            dispatch_async(gExecQ, ^{ @autoreleasepool { execCmd(cmd); } });
        }
    }] resume];
}

// ---------------- 启动 ----------------
__attribute__((constructor))
static void dspy_init(void) {
    @autoreleasepool {
        gLock = [NSLock new];
        gExecQ = dispatch_queue_create("dspy.exec", DISPATCH_QUEUE_SERIAL);
        BOOL off = exists(@"dm_off");
        W(@"==== DamaiSpy %@ loaded at %@ ====", kVer, [NSDate date]);
        W(@"bundle=%@ off=%d docs=%@", [[NSBundle mainBundle] bundleIdentifier], off, docs());
        if (off) { flushAll(); return; }
        gNetOn = exists(@"dm_net_on");

        @try { hookMtop(); } @catch (id e) { W(@"hookMtop EXC %@", e); }
        @try { hookNet(); } @catch (id e) { W(@"hookNet EXC %@", e); }

        // 启动即把 MTOP 类家族关系落一份，方便判断是不是 MtopService
        @try {
            Class ms = NSClassFromString(@"MtopService");
            M(@"boot: MtopService=%@", ms ? @"found" : @"nil");
            if (ms) {
                unsigned int mc = 0;
                Method *mm = class_copyMethodList(ms, &mc);
                NSMutableArray *names = [NSMutableArray array];
                for (unsigned int i = 0; i < mc; i++) [names addObject:NSStringFromSelector(method_getName(mm[i]))];
                if (mm) free(mm);
                M(@"MtopService instance methods(%u): %@", mc, clip([names componentsJoinedByString:@", "], 3000));
            }
        } @catch (id e) { M(@"boot mtopinfo EXC %@", e); }

        flushAll();
        dispatch_async(dispatch_get_main_queue(), ^{
            [NSTimer scheduledTimerWithTimeInterval:0.5 repeats:YES block:^(NSTimer *t) {
                pollCmd();
                flushAll();
            }];
            [NSTimer scheduledTimerWithTimeInterval:2.0 repeats:YES block:^(NSTimer *t) {
                pollNet();
                flushAll();
            }];
            W(@"timers started (cmd-file 0.5s, net %d)", gNetOn);
            flushAll();
        });
    }
}
