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
#import <zlib.h>
#import <dlfcn.h>
#import <mach/mach_time.h>
#import <execinfo.h>

static NSString *const kVer = @"v2.0";

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

// 递归父类的 ivar dump（MtopExtRequest 的真参数在 MtopRequest/TBSDKRequest 里）
static NSString *bytesPreview(NSData *d, NSUInteger max);
static NSString *decodeParamsField(id biz);
static NSString *dmBacktrace(int max);
static NSString *runCreateViaRequest(NSDictionary *biz, NSString *api, NSString *v, NSString *tag);

static void dumpIvarsOf(id o, Class c, NSMutableString *s, int *budget) {
    if (!c || c == [NSObject class] || *budget <= 0) return;
    dumpIvarsOf(o, class_getSuperclass(c), s, budget);
    unsigned int n = 0;
    Ivar *ivars = class_copyIvarList(c, &n);
    for (unsigned int i = 0; i < n && *budget > 0; i++) {
        const char *tn = ivar_getTypeEncoding(ivars[i]);
        NSString *nm = [NSString stringWithUTF8String:ivar_getName(ivars[i])];
        if (tn && tn[0] == '@' && tn[1] != '?') {
            id v = nil;
            @try { v = object_getIvar(o, ivars[i]); } @catch (id e) {}
            if (!v) continue;
            NSString *vs;
            if ([v isKindOfClass:[NSData class]]) {
                NSData *dd = (NSData *)v;
                vs = [NSString stringWithFormat:@"(NSData %luB) %@", (unsigned long)dd.length, bytesPreview(dd, 900)];
            } else {
                vs = [NSString stringWithFormat:@"%@", v];
            }
            [s appendFormat:@"\n  .%@ = %@", nm, clip(vs, 900)];
            *budget -= 1;
        } else if (tn && (tn[0] == 'i' || tn[0] == 'q' || tn[0] == 'Q' || tn[0] == 'd' || tn[0] == 'c' || tn[0] == 'B')) {
            // 数值型只留少数关键字段，避免刷屏
            if ([nm rangeOfString:@"api"].location != NSNotFound || [nm rangeOfString:@"version"].location != NSNotFound) {
                [s appendFormat:@"\n  .%@ = (%s)", nm, tn];
                *budget -= 1;
            }
        }
    }
    if (ivars) free(ivars);
}

static NSString *kvcProbe(id o, NSArray *keys) {
    if (!o) return @"";
    NSMutableString *s = [NSMutableString string];
    for (NSString *k in keys) {
        @try {
            id v = [o valueForKey:k];
            if (!v) continue;
            NSString *vs = [NSString stringWithFormat:@"%@", v];
            if (!vs.length || [vs isEqualToString:@"(null)"]) continue;
            [s appendFormat:@"\n  %@ = %@", k, clip(vs, 900)];
        } @catch (id e) {}
    }
    return s;
}

static NSArray *reqKeys(void) {
    return @[@"api", @"apiName", @"v", @"apiVersion", @"version", @"data", @"dataParams",
             @"params", @"bizParameters", @"appKey", @"ttid", @"mid", @"sid", @"t", @"sign",
             @"needLogin", @"needEcode", @"url", @"host", @"method", @"fullTraceID", @"pageName"];
}

static NSArray *respKeys(void) {
    return @[@"api", @"apiName", @"apiVersion", @"v", @"ret", @"code", @"msg", @"message",
             @"subCode", @"data", @"headers", @"fullTraceID", @"mappingCode", @"success"];
}

static NSString *dumpObj(id o) {
    if (!o) return @"(nil)";
    NSMutableString *s = [NSMutableString string];
    @try {
        [s appendFormat:@"<%@>", NSStringFromClass([o class])];
        [s appendString:kvcProbe(o, reqKeys())];
        [s appendString:kvcProbe(o, respKeys())];
        // ★ 对象自己的 ivar（响应体常藏在 _data / _response 里）
        int b0 = 18;
        [s appendString:@"\n  -- self ivars --"];
        dumpIvarsOf(o, [o class], s, &b0);
        // 嵌套的 mrequest（TBSDKRequest）才是真正拼包对象
        id mr = nil;
        @try { mr = [o valueForKey:@"mrequest"]; } @catch (id e) {}
        if (mr && mr != o) {
            [s appendFormat:@"\n [mrequest %@]", NSStringFromClass([mr class])];
            [s appendString:kvcProbe(mr, reqKeys())];
            int b1 = 12;
            [s appendString:@"\n  -- ivars --"];
            dumpIvarsOf(mr, [mr class], s, &b1);
        }
        id bizp = nil;
        @try { bizp = [o valueForKey:@"bizParameters"]; } @catch (id e) {}
        NSString *dec = decodeParamsField(bizp);
        if (dec.length) [s appendFormat:@"\n PARAMS_DECODED = %@", dec];

        id d = nil;
        @try { d = [o valueForKey:@"data"]; } @catch (id e) {}
        if ([d isKindOfClass:[NSDictionary class]] || [d isKindOfClass:[NSArray class]]) {
            NSData *jd = [NSJSONSerialization dataWithJSONObject:d options:NSJSONWritingWithoutEscapingSlashes error:nil];
            if (jd) [s appendFormat:@"\n DATA %@", clip([[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding], 2000)];
        }
        if (s.length > 4000) s = [[s substringToIndex:4000] mutableCopy];
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

// ---------------- gzip / base64 工具（params 字段是 gzip+base64 的表单体）----------------
static NSData *dmGunzip(NSData *in) {
    if (in.length < 18) return nil;
    z_stream s; memset(&s, 0, sizeof(s));
    if (inflateInit2(&s, 16 + MAX_WBITS) != Z_OK) return nil;
    NSMutableData *out = [NSMutableData dataWithLength:256 * 1024];
    s.next_in = (Bytef *)in.bytes;
    s.avail_in = (uInt)in.length;
    s.next_out = (Bytef *)out.mutableBytes;
    s.avail_out = (uInt)out.length;
    int ret = inflate(&s, Z_FINISH);
    NSData *res = nil;
    if (ret == Z_STREAM_END && s.total_out > 0)
        res = [out subdataWithRange:NSMakeRange(0, s.total_out)];
    inflateEnd(&s);
    return res;
}

static NSData *dmGzip(NSData *in) {
    if (!in.length) return nil;
    z_stream s; memset(&s, 0, sizeof(s));
    if (deflateInit2(&s, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY) != Z_OK) return nil;
    NSUInteger cap = in.length + 1024;
    NSMutableData *out = [NSMutableData dataWithLength:cap];
    s.next_in = (Bytef *)in.bytes;
    s.avail_in = (uInt)in.length;
    s.next_out = (Bytef *)out.mutableBytes;
    s.avail_out = (uInt)out.length;
    int ret = deflate(&s, Z_FINISH);
    NSData *res = nil;
    if (ret == Z_STREAM_END) res = [out subdataWithRange:NSMakeRange(0, s.total_out)];
    deflateEnd(&s);
    return res;
}

// 从 bizParameters 里把 params(gzip+base64) 解成明文
static NSString *decodeParamsField(id biz) {
    if (![biz isKindOfClass:[NSDictionary class]]) return nil;
    id v = [(NSDictionary *)biz objectForKey:@"params"];
    if (![v isKindOfClass:[NSString class]] || ![(NSString *)v hasPrefix:@"H4sI"]) return nil;
    NSData *raw = [[NSData alloc] initWithBase64EncodedString:(NSString *)v options:0];
    if (!raw) return nil;
    NSData *plain = dmGunzip(raw);
    if (!plain) return [NSString stringWithFormat:@"(params %luB, gunzip 失败)", (unsigned long)((NSString *)v).length];
    NSString *txt = [[NSString alloc] initWithData:plain encoding:NSUTF8StringEncoding];
    return txt.length ? clip(txt, 4000) : [NSString stringWithFormat:@"(params %luB 解出非文本)", (unsigned long)plain.length];
}

// ---------------- MTOP hook ----------------
static NSDictionary *gLastCreateBiz = nil;   // 最近一次 trade.order.create 的 bizParameters
static id gLastDelegate = nil;
static id gLastReqObj = nil;   // App 原生的 MtopExtRequest 对象本身
static NSString *gLastTtid = nil;
static NSString *gLastCreateAPI = nil;

static void rememberCreate(id req) {
    @try {
        NSString *api = [req valueForKey:@"apiName"];
        if (![api isKindOfClass:[NSString class]] || [api rangeOfString:@"trade.order"].location == NSNotFound) return;
        id biz = [req valueForKey:@"bizParameters"];
        @try { id dg = [req valueForKey:@"delegate"]; if (dg) gLastDelegate = dg; } @catch (id e) {}
        gLastReqObj = req;   // ★ 保留对象本体
        @try { id tt = [req valueForKey:@"ttid"]; if ([tt isKindOfClass:[NSString class]] && [(NSString *)tt length]) gLastTtid = tt; } @catch (id e) {}
        if ([biz isKindOfClass:[NSDictionary class]]) {
            gLastCreateBiz = [(NSDictionary *)biz copy];
            gLastCreateAPI = [api copy];
            NSMutableArray *ks = [NSMutableArray array];
            for (NSString *k in [(NSDictionary *)biz allKeys]) [ks addObject:[NSString stringWithFormat:@"%@(%lu)", k, (unsigned long)[[NSString stringWithFormat:@"%@", [(NSDictionary *)biz objectForKey:k]] length]]];
            W(@"saved last %@ biz: %@", api, [ks componentsJoinedByString:@", "]);
            if ([api rangeOfString:@"order.create"].location != NSNotFound) {
                @try {
                    NSDictionary *snap = @{@"api": api, @"v": @"1.0", @"biz": gLastCreateBiz};
                    NSData *jd = [NSJSONSerialization dataWithJSONObject:snap options:NSJSONWritingWithoutEscapingSlashes error:nil];
                    if (jd) [jd writeToFile:dpath(@"dm_biz.json") options:NSDataWritingAtomic error:nil];
                } @catch (id e) {}
            }
            if ([api rangeOfString:@"order.create"].location != NSNotFound)
                M(@"==== CREATE 调用栈 ====\n%@", dmBacktrace(22));
        }
    } @catch (id e) { W(@"rememberCreate EXC %@", e); }
}

typedef struct { Class cls; SEL sel; IMP orig; } HookRec;
static HookRec gHooks[32];
static int gHookCount = 0;

static id dm_succeed(id self, SEL _cmd, id req, id resp);
static id dm_failed(id self, SEL _cmd, id req, id resp);

static IMP origFor(SEL cmd) {
    for (int i = 0; i < gHookCount; i++) if (sel_isEqual(gHooks[i].sel, cmd)) return gHooks[i].orig;
    return NULL;
}

static id dm_async2(id self, SEL _cmd, id req, id dlg) {
    gMtopSeq++;
    rememberCreate(req);
    M(@"==== REQ #%ld -[%@ async_call:delegate:] ====", gMtopSeq, NSStringFromClass([self class]));
    M(@"%@", dumpObj(req));
    IMP o = origFor(_cmd);
    return o ? ((id (*)(id, SEL, id, id))o)(self, _cmd, req, dlg) : nil;
}
static id dm_async3(id self, SEL _cmd, id req, id dlg, id sf) {
    gMtopSeq++;
    rememberCreate(req);
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
    rememberCreate(req);
    M(@"==== REQ #%ld -[%@ sync_call:apiVersion:bizParameters:] v=%@ biz=%@ ====", gMtopSeq, NSStringFromClass([self class]), v, clip([NSString stringWithFormat:@"%@", biz], 400));
    M(@"%@", dumpObj(req));
    IMP o = origFor(_cmd);
    id r = o ? ((id (*)(id, SEL, id, id, id))o)(self, _cmd, req, v, biz) : nil;
    M(@"---- RESP #%ld %@", gMtopSeq, dumpObj(r));
    return r;
}

// 只 hook 指定类（省事且安全：不遍历全部类，避免启动期 realize 崩溃）
static int hookClassNamed(NSString *cn) {
    Class c = NSClassFromString(cn);
    if (!c) return 0;
    SEL sels[5] = { @selector(async_call:delegate:),
                    @selector(async_call:delegate:startFilter:),
                    @selector(sync_call:),
                    @selector(sync_call:apiVersion:),
                    @selector(sync_call:apiVersion:bizParameters:) };
    IMP news[5] = { (IMP)dm_async2, (IMP)dm_async3, (IMP)dm_sync1, (IMP)dm_sync2, (IMP)dm_sync3 };
    int hooked = 0;
    // 响应回调
    @try {
        Method ms = class_getInstanceMethod(c, @selector(succeed:response:));
        if (ms && method_getImplementation(ms) != (IMP)dm_succeed) {
            IMP orig = method_getImplementation(ms);
            method_setImplementation(ms, (IMP)dm_succeed);
            if (gHookCount < 30) { gHooks[gHookCount].cls = c; gHooks[gHookCount].sel = @selector(succeed:response:); gHooks[gHookCount].orig = orig; gHookCount++; }
            hooked++; M(@"HOOK -[%@ succeed:response:]", cn);
        }
        Method mf = class_getInstanceMethod(c, @selector(failed:response:));
        if (mf && method_getImplementation(mf) != (IMP)dm_failed) {
            IMP orig = method_getImplementation(mf);
            method_setImplementation(mf, (IMP)dm_failed);
            if (gHookCount < 30) { gHooks[gHookCount].cls = c; gHooks[gHookCount].sel = @selector(failed:response:); gHooks[gHookCount].orig = orig; gHookCount++; }
            hooked++; M(@"HOOK -[%@ failed:response:]", cn);
        }
    } @catch (id e) { M(@"resp-hook EXC %@", e); }

    for (int k = 0; k < 5; k++) {
        @try {
            Method m = class_getInstanceMethod(c, sels[k]);
            if (!m) continue;
            IMP orig = method_getImplementation(m);
            if (orig == news[k]) continue;
            method_setImplementation(m, news[k]);
            if (gHookCount < 30) {
                gHooks[gHookCount].cls = c;
                gHooks[gHookCount].sel = sels[k];
                gHooks[gHookCount].orig = orig;
                gHookCount++;
            }
            hooked++;
            M(@"HOOK -[%@ %@]", cn, NSStringFromSelector(sels[k]));
        } @catch (id e) { M(@"HOOK-EXC %@ %@: %@", cn, NSStringFromSelector(sels[k]), e); }
    }
    return hooked;
}

// 快速路径：只试已知类名
static id dm_succeed(id self, SEL _cmd, id req, id resp) {
    M(@"==== RESP(ok) %@ ====", NSStringFromClass([self class]));
    id apiv = nil;
    @try { apiv = [req valueForKey:@"api"]; } @catch (id e) {}
    M(@" req api=%@", clip([NSString stringWithFormat:@"%@", apiv ?: @"?"], 120));
    M(@"%@", dumpObj(resp));
    IMP o = origFor(_cmd);
    return o ? ((id (*)(id, SEL, id, id))o)(self, _cmd, req, resp) : nil;
}
static id dm_failed(id self, SEL _cmd, id req, id resp) {
    M(@"==== RESP(fail) %@ ====", NSStringFromClass([self class]));
    M(@"%@", dumpObj(resp));
    IMP o = origFor(_cmd);
    return o ? ((id (*)(id, SEL, id, id))o)(self, _cmd, req, resp) : nil;
}

static void hookMtop(void) {
    NSArray *cands = @[@"MtopService", @"MTOPService", @"MtopServer", @"MtopSDKService", @"MtopClient"];
    for (NSString *n in cands) {
        int h = hookClassNamed(n);
        if (h > 0) { M(@"hook done via fast path: %@ hooks=%d", n, h); return; }
    }
    M(@"hook: 已知类名都没命中，可下发 {\"c\":\"hookall\"} 全量扫描");
}

// 慢速路径：遍历所有类（只在指令触发时用，运行期已稳定）
static void hookAllClasses(void) {
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
                Class sup = class_getSuperclass(c);
                if (sup) {
                    Method sm = class_getInstanceMethod(sup, sels[k]);
                    if (sm && method_getImplementation(sm) == method_getImplementation(m)) continue;
                }
                IMP orig = method_getImplementation(m);
                if (orig == news[k]) continue;
                method_setImplementation(m, news[k]);
                gHooks[gHookCount].cls = c;
                gHooks[gHookCount].sel = sels[k];
                gHooks[gHookCount].orig = orig;
                gHookCount++; hooked++;
                M(@"HOOK(all) -[%@ %@]", cn, NSStringFromSelector(sels[k]));
            } @catch (id e) {}
        }
    }
    free(classes);
    M(@"hookall done: +%d hooks (total %d)", hooked, gHookCount);
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

// ---------------- UI 自动化（进程内驱动 App 自己的流程）----------------
static void dmRunOnMain(dispatch_block_t blk) {
    if ([NSThread isMainThread]) blk();
    else dispatch_sync(dispatch_get_main_queue(), blk);
}

static NSString *viewText(UIView *v) {
    NSString *t = nil;
    @try {
        if ([v isKindOfClass:[UILabel class]]) t = [(UILabel *)v text];
        else if ([v isKindOfClass:[UIButton class]]) t = [[(UIButton *)v titleLabel] text];
        else if ([v isKindOfClass:[UITextField class]]) t = [(UITextField *)v text] ?: [(UITextField *)v placeholder];
        if (!t.length && [v respondsToSelector:NSSelectorFromString(@"text")]) {
            id x = nil;
            @try { x = [v performSelector:NSSelectorFromString(@"text")]; } @catch (id e) {}
            if ([x isKindOfClass:[NSString class]]) t = x;
        }
    } @catch (id e) {}
    return t;
}

static void dmWalkViews(UIView *v, int depth, NSMutableString *out, int *budget, NSString *needle) {
    if (!v || *budget <= 0) return;
    NSString *txt = viewText(v);
    BOOL hit = needle.length ? (txt.length && [txt rangeOfString:needle].location != NSNotFound) : YES;
    BOOL interesting = txt.length > 0 || [v isKindOfClass:[UIControl class]];
    if (interesting && hit) {
        [out appendFormat:@"%*s%@ frame=(%.0f,%.0f,%.0f,%.0f) tappable=%d txt=%@\n",
         depth * 2, "", NSStringFromClass([v class]), v.frame.origin.x, v.frame.origin.y,
         v.frame.size.width, v.frame.size.height, (int)[v isKindOfClass:[UIControl class]],
         clip(txt, 60)];
        (*budget)--;
    }
    for (UIView *s in v.subviews) dmWalkViews(s, depth + 1, out, budget, needle);
}

static UIViewController *dmTopVC(void) {
    UIWindow *w = nil;
    for (UIWindow *x in [UIApplication sharedApplication].windows) if (x.isKeyWindow) { w = x; break; }
    if (!w) w = [UIApplication sharedApplication].keyWindow;
    UIViewController *vc = w.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

// 找到文字包含 needle 的控件并触发点击
static NSString *dmTapByText(NSString *needle) {
    __block NSString *report = nil;
    dmRunOnMain(^{
        UIViewController *vc = dmTopVC();
        NSMutableArray *cands = [NSMutableArray array];
        NSMutableArray *stack = [NSMutableArray arrayWithObject:vc.view];
        while (stack.count) {
            UIView *v = [stack lastObject];
            [stack removeLastObject];
            NSString *t = viewText(v);
            if (t.length && [t rangeOfString:needle].location != NSNotFound) [cands addObject:v];
            for (UIView *s in v.subviews) [stack addObject:s];
        }
        NSMutableString *r = [NSMutableString string];
        [r appendFormat:@"candidates=%lu\n", (unsigned long)cands.count];
        for (UIView *v in cands) {
            [r appendFormat:@"  %@ frame=%@ txt=%@\n", NSStringFromClass([v class]),
             NSStringFromCGRect(v.frame), clip(viewText(v), 40)];
        }
        // 优先挑 UIControl，且层级最深（最内层）的
        UIView *target = nil;
        for (UIView *v in cands) if ([v isKindOfClass:[UIControl class]]) target = v;
        if (!target && cands.count) target = [cands lastObject];
        if (target) {
            [r appendFormat:@"TAP -> %@\n", NSStringFromClass([target class])];
            if ([target isKindOfClass:[UIControl class]]) {
                [(UIControl *)target sendActionsForControlEvents:UIControlEventTouchUpInside];
                [r appendString:@"sent TouchUpInside\n"];
            } else {
                // 非控件：尝试触发其单指手势的 target-action
                BOOL fired = NO;
                for (UIGestureRecognizer *g in target.gestureRecognizers) {
                    if (![g isKindOfClass:[UITapGestureRecognizer class]]) continue;
                    NSArray *targets = [g valueForKey:@"_targets"];
                    for (id t in targets) {
                        id tgt = [t valueForKey:@"_target"];
                        NSString *act = [t valueForKey:@"_action"];
                        SEL sel = NSSelectorFromString(act);
                        if (tgt && sel && [tgt respondsToSelector:sel]) {
                            ((void (*)(id, SEL, id))objc_msgSend)(tgt, sel, g);
                            fired = YES;
                        }
                    }
                }
                [r appendFormat:@"gesture fired=%d\n", (int)fired];
            }
        } else {
            [r appendString:@"未找到可点击目标\n"];
        }
        report = [r copy];
    });
    return report ?: @"(nil)";
}


// ---------------- HID 级触摸注入（真实触摸事件，DinamicX 节点也能点）----------------
typedef void *(*DMCreateFingerEventFn)(CFAllocatorRef, uint64_t, uint32_t, uint32_t, uint32_t,
                                       double, double, double, double, double, Boolean, Boolean, uint32_t);

static NSString *dmHIDTap(CGPoint pt, NSString *why) {
    NSMutableString *r = [NSMutableString string];
    [r appendFormat:@"hidtap at (%.0f,%.0f) %@\n", pt.x, pt.y, why ?: @""];
    void *sym = dlsym(RTLD_DEFAULT, "IOHIDEventCreateDigitizerFingerEvent");
    [r appendFormat:@"symbol=%s\n", sym ? "ok" : "MISSING"];
    if (!sym) return r;
    DMCreateFingerEventFn mk = (DMCreateFingerEventFn)sym;
    UIApplication *app = [UIApplication sharedApplication];
    SEL enq = NSSelectorFromString(@"_enqueueHIDEvent:");
    [r appendFormat:@"enqueue=%d\n", (int)[app respondsToSelector:enq]];

    uint32_t mask = 0x3;   // Range|Touch
    for (int phase = 0; phase < 2; phase++) {
        Boolean touch = (phase == 0);
        uint64_t ts = mach_absolute_time();
        void *ev = mk(kCFAllocatorDefault, ts, 0, 0x1, mask,
                      pt.x, pt.y, 0.0, phase == 0 ? 1.0 : 0.0, 0.0, touch, touch, 0);
        if (!ev) { [r appendString:@"event=nil\n"]; continue; }
        @try {
            if ([app respondsToSelector:enq]) ((void (*)(id, SEL, void *))objc_msgSend)(app, enq, ev);
            else [app sendEvent:(__bridge UIEvent *)ev];
            [r appendFormat:@"sent phase=%d\n", phase];
        } @catch (id e) { [r appendFormat:@"send EXC %@\n", e]; }
        CFRelease(ev);
        usleep(60000);
    }
    return r;
}

// 找到文字匹配的视图，换算成窗口坐标后 HID 点击
static NSString *dmHIDTapByText(NSString *needle, BOOL doTap) {
    __block NSString *report = nil;
    dmRunOnMain(^{
        NSMutableString *r = [NSMutableString string];
        UIViewController *vc = dmTopVC();
        UIWindow *win = vc.view.window;
        NSMutableArray *cands = [NSMutableArray array];
        NSMutableArray *stack = [NSMutableArray arrayWithObject:vc.view];
        while (stack.count) {
            UIView *v = [stack lastObject];
            [stack removeLastObject];
            NSString *t = viewText(v);
            if (t.length && [t rangeOfString:needle].location != NSNotFound) [cands addObject:v];
            for (UIView *s in v.subviews) [stack addObject:s];
        }
        [r appendFormat:@"candidates=%lu\n", (unsigned long)cands.count];
        UIView *target = nil;
        for (UIView *v in cands) {
            CGPoint c = [v convertPoint:CGPointMake(CGRectGetMidX(v.bounds), CGRectGetMidY(v.bounds)) toView:win];
            [r appendFormat:@"  %@ bounds=%@ winCenter=(%.0f,%.0f) txt=%@\n",
             NSStringFromClass([v class]), NSStringFromCGRect(v.bounds), c.x, c.y, clip(viewText(v), 30)];
            if (!target) target = v;
        }
        if (!target) { [r appendString:@"未找到目标\n"]; report = [r copy]; return; }
        CGPoint p = [target convertPoint:CGPointMake(CGRectGetMidX(target.bounds), CGRectGetMidY(target.bounds)) toView:win];
        if (doTap) [r appendString:dmHIDTap(p, needle)];
        report = [r copy];
    });
    return report ?: @"(nil)";
}


// 无障碍激活（DinamicX 节点一般实现了 accessibilityActivate，能触发内部事件）
static NSString *dmAXActivate(NSString *needle) {
    __block NSString *report = nil;
    dmRunOnMain(^{
        NSMutableString *r = [NSMutableString string];
        UIViewController *vc = dmTopVC();
        NSMutableArray *stack = [NSMutableArray arrayWithObject:vc.view];
        NSMutableArray *cands = [NSMutableArray array];
        while (stack.count) {
            UIView *v = [stack lastObject]; [stack removeLastObject];
            NSString *t = viewText(v);
            if (t.length && [t rangeOfString:needle].location != NSNotFound) [cands addObject:v];
            for (UIView *s in v.subviews) [stack addObject:s];
        }
        [r appendFormat:@"candidates=%lu\n", (unsigned long)cands.count];
        for (UIView *v in cands) {
            BOOL act = [v respondsToSelector:@selector(accessibilityActivate)];
            BOOL hadAct = NO;
            if (act) {
                @try { hadAct = (BOOL)[v performSelector:@selector(accessibilityActivate)]; }
                @catch (id e) { [r appendFormat:@"  EXC %@\n", e]; }
            }
            [r appendFormat:@"  %@ activate=%d returned=%d label=%@\n", NSStringFromClass([v class]),
             (int)act, (int)hadAct, clip([v accessibilityLabel], 30)];
        }
        report = [r copy];
    });
    return report ?: @"(nil)";
}

// 打印匹配视图的 ivar，找内部 handler / event 对象
static NSString *dmViewIvars(NSString *needle) {
    __block NSString *report = nil;
    dmRunOnMain(^{
        NSMutableString *r = [NSMutableString string];
        UIViewController *vc = dmTopVC();
        NSMutableArray *stack = [NSMutableArray arrayWithObject:vc.view];
        UIView *target = nil;
        while (stack.count) {
            UIView *v = [stack lastObject]; [stack removeLastObject];
            NSString *t = viewText(v);
            if (!target && t.length && [t rangeOfString:needle].location != NSNotFound) target = v;
            for (UIView *s in v.subviews) [stack addObject:s];
        }
        if (!target) { report = @"未找到"; return; }
        [r appendFormat:@"target=%@\n", NSStringFromClass([target class])];
        int budget = 40;
        dumpIvarsOf(target, [target class], r, &budget);
        report = [r copy];
    });
    return report ?: @"(nil)";
}


// 沿祖先链找手势（DinamicX 的点击挂在容器上）
static UIView *dmFindByText(NSString *needle) {
    UIViewController *vc = dmTopVC();
    NSMutableArray *stack = [NSMutableArray arrayWithObject:vc.view];
    while (stack.count) {
        UIView *v = [stack lastObject]; [stack removeLastObject];
        NSString *t = viewText(v);
        if (t.length && [t rangeOfString:needle].location != NSNotFound) return v;
        for (UIView *s in v.subviews) [stack addObject:s];
    }
    return nil;
}

static NSString *dmChain(NSString *needle, BOOL fire) {
    __block NSString *report = nil;
    dmRunOnMain(^{
        NSMutableString *r = [NSMutableString string];
        UIView *v = dmFindByText(needle);
        if (!v) { report = @"未找到"; return; }
        int depth = 0;
        BOOL fired = NO;
        for (UIView *cur = v; cur && depth < 12; cur = cur.superview, depth++) {
            NSMutableArray *gs = [NSMutableArray array];
            for (UIGestureRecognizer *g in cur.gestureRecognizers) {
                NSString *tn = NSStringFromClass([g class]);
                NSArray *targets = nil;
                @try { targets = [g valueForKey:@"_targets"]; } @catch (id e) {}
                [gs addObject:[NSString stringWithFormat:@"%@(%lu)", tn, (unsigned long)targets.count]];
                if (fire && !fired && [g isKindOfClass:[UITapGestureRecognizer class]]) {
                    for (id t in targets) {
                        id tgt = nil; NSString *act = nil;
                        @try { tgt = [t valueForKey:@"_target"]; act = [t valueForKey:@"_action"]; } @catch (id e) {}
                        SEL sel = act ? NSSelectorFromString(act) : NULL;
                        if (tgt && sel && [tgt respondsToSelector:sel]) {
                            @try {
                                ((void (*)(id, SEL, id))objc_msgSend)(tgt, sel, g);
                                [r appendFormat:@"FIRE %@ -%@ (ancestor %d)\n", NSStringFromClass([tgt class]), act, depth];
                                fired = YES;
                            } @catch (id e) { [r appendFormat:@"FIRE EXC %@\n", e]; }
                        }
                    }
                }
            }
            [r appendFormat:@"%*s%@ frame=%@ gestures=[%@]\n", depth * 2, "", NSStringFromClass([cur class]),
             NSStringFromCGRect(cur.frame), [gs componentsJoinedByString:@","]];
        }
        [r appendFormat:@"fired=%d\n", (int)fired];
        report = [r copy];
    });
    return report ?: @"(nil)";
}


// 打印调用栈（用于定位"谁构造了 create 包"）
static NSString *dmBacktrace(int max) {
    void *buf[80];
    int n = backtrace(buf, 80);
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < n && i < max; i++) {
        Dl_info info;
        if (dladdr(buf[i], &info) && info.dli_sname) {
            const char *img = info.dli_fname ? strrchr(info.dli_fname, '/') : NULL;
            [s appendFormat:@"  #%-2d %s  [%s]\n", i, info.dli_sname, img ? img + 1 : "?"];
        } else {
            [s appendFormat:@"  #%-2d %p\n", i, buf[i]];
        }
    }
    return s;
}

// 安全签名类 hook（看它是不是交易签名的实施者）
static id (*o_sg_sign)(id, SEL, id, id);
static id dm_sg_sign(id self, SEL _cmd, id req, id code) {
    NSString *in = clip([NSString stringWithFormat:@"%@", req], 1200);
    M(@"==== SG signRequest in ====\n%@\n-- bt --\n%@", in, dmBacktrace(14));
    id out = o_sg_sign ? o_sg_sign(self, _cmd, req, code) : nil;
    M(@"---- SG signRequest out = %@", clip([NSString stringWithFormat:@"%@", out], 1200));
    return out;
}

static void hookSecurityGuard(void) {
    Class c = NSClassFromString(@"SecurityGuardOpenSecureSignature");
    if (!c) { W(@"no SecurityGuardOpenSecureSignature"); return; }
    Method m = class_getInstanceMethod(c, @selector(signRequest:authCode:));
    if (!m) { W(@"no signRequest:authCode:"); return; }
    o_sg_sign = (void *)method_getImplementation(m);
    method_setImplementation(m, (IMP)dm_sg_sign);
    W(@"hook SecurityGuardOpenSecureSignature signRequest:authCode:");
}


// DXRootView 点击事件追踪
static void (*o_dxpost)(id, SEL, id);
static void dm_dxpost(id self, SEL _cmd, id msg) {
    M(@"==== DXRootView postMessage ====");
    M(@"%@", dumpObj(msg));
    M(@"-- bt --\n%@", dmBacktrace(20));
    if (o_dxpost) o_dxpost(self, _cmd, msg);
}

static void hookDX(void) {
    Class c = NSClassFromString(@"DXRootView");
    if (!c) { W(@"no DXRootView"); return; }
    Method m = class_getInstanceMethod(c, @selector(postMessage:));
    if (!m) { W(@"DXRootView 无 postMessage:"); return; }
    o_dxpost = (void *)method_getImplementation(m);
    method_setImplementation(m, (IMP)dm_dxpost);
    W(@"hook DXRootView postMessage:");
}

static NSString *dmDXEv(NSString *needle) {
    __block NSString *report = nil;
    dmRunOnMain(^{
        NSMutableString *r = [NSMutableString string];
        UIView *tv = dmFindByText(needle);
        UIView *root = tv ? tv.superview : nil;
        Class dxc = NSClassFromString(@"DXRootView");
        while (root && dxc && ![root isKindOfClass:dxc]) root = root.superview;
        if (!root) { report = @"未找到 DXRootView"; return; }
        id disp = nil;
        @try { disp = [root performSelector:@selector(eventDispatcher)]; } @catch (id e) {}
        [r appendFormat:@"DXRootView ok, dispatcher=%@\n", disp ? NSStringFromClass([disp class]) : @"nil"];
        if (disp) {
            unsigned int mc = 0;
            Method *ms = class_copyMethodList([disp class], &mc);
            for (unsigned int i = 0; i < mc && i < 100; i++)
                [r appendFormat:@"  -%@\n", NSStringFromSelector(method_getName(ms[i]))];
            if (ms) free(ms);
            int b = 24;
            dumpIvarsOf(disp, [disp class], r, &b);
        }
        report = [r copy];
    });
    return report ?: @"(nil)";
}


// 发送前转换观察（MtopExtRequest -> TBSDKRequest 在哪里失败）
static id (*o_sending)(id, SEL, id, id, id);
static id dm_sending(id self, SEL _cmd, id req, id dlg, id sf) {
    NSString *api = nil;
    @try { api = [req valueForKey:@"apiName"]; } @catch (id e) {}
    if ([api rangeOfString:@"order.create"].location != NSNotFound) {
        if (dlg) gLastDelegate = dlg;   // ★ delegate 在这里才就位
        M(@"==== sendingRequest for create ====");
        M(@"%@", dumpObj(req));
        id out = o_sending ? o_sending(self, _cmd, req, dlg, sf) : nil;
        M(@"---- sendingRequest out ----\n%@", dumpObj(out));
        return out;
    }
    return o_sending ? o_sending(self, _cmd, req, dlg, sf) : nil;
}

static void hookSending(void) {
    Class c = NSClassFromString(@"MtopService");
    if (!c) return;
    Method m = class_getInstanceMethod(c, @selector(sendingRequest:delegate:startFilter:));
    if (!m) { W(@"no sendingRequest:"); return; }
    o_sending = (void *)method_getImplementation(m);
    method_setImplementation(m, (IMP)dm_sending);
    W(@"hook sendingRequest:delegate:startFilter:");
}


// HTTP 头捕获（定位 431：Request Header Fields Too Large）
static void (*o_setH)(id, SEL, NSString *, NSString *);
static void dm_setH(id self, SEL _cmd, NSString *v, NSString *f) {
    @try {
        NSString *fl = f.lowercaseString ?: @"";
        if ([fl containsString:@"sign"] || [fl containsString:@"wua"] || [fl containsString:@"sgext"]
            || [fl containsString:@"umt"] || [fl isEqualToString:@"cookie"] || [fl containsString:@"x-"]) {
            M(@"HDR[%p] %@ = %@", self, f ?: @"-", clip(v, 260));
        }
    } @catch (id e) {}
    if (o_setH) o_setH(self, _cmd, v, f);
}
static void (*o_setAllH)(id, SEL, NSDictionary *);
static void dm_setAllH(id self, SEL _cmd, NSDictionary *hs) {
    @try {
        for (NSString *k in hs) {
            NSString *kl = k.lowercaseString;
            if ([kl containsString:@"sign"] || [kl containsString:@"wua"] || [kl containsString:@"sgext"] || [kl isEqualToString:@"cookie"]) {
                M(@"HDRALL[%p] %@ = %@", self, k, clip([NSString stringWithFormat:@"%@", hs[k]], 260));
            }
        }
    } @catch (id e) {}
    if (o_setAllH) o_setAllH(self, _cmd, hs);
}
static void (*o_setBody)(id, SEL, NSData *);
static void dm_setBody(id self, SEL _cmd, NSData *b) {
    @try {
        NSString *s = bytesPreview(b, 200) ?: @"";
        if ([s containsString:@"order.create"] || [s containsString:@"H4sIA"]) {
            M(@"BODY[%p] len=%lu head=%@", self, (unsigned long)b.length, clip(s, 200));
        }
    } @catch (id e) {}
    if (o_setBody) o_setBody(self, _cmd, b);
}

static void hookHeaders(void) {
    Class c = [NSMutableURLRequest class];
    Method m1 = class_getInstanceMethod(c, @selector(setValue:forHTTPHeaderField:));
    if (m1) { o_setH = (void *)method_getImplementation(m1); method_setImplementation(m1, (IMP)dm_setH); W(@"hook setValue:forHTTPHeaderField:"); }
    Method m2 = class_getInstanceMethod(c, @selector(setAllHTTPHeaderFields:));
    if (m2) { o_setAllH = (void *)method_getImplementation(m2); method_setImplementation(m2, (IMP)dm_setAllH); W(@"hook setAllHTTPHeaderFields:"); }
    Method m3 = class_getInstanceMethod(c, @selector(setHTTPBody:));
    if (m3) { o_setBody = (void *)method_getImplementation(m3); method_setImplementation(m3, (IMP)dm_setBody); W(@"hook setHTTPBody:"); }
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

static id mtopInstance(NSString *site) {
    Class c = mtopServiceClass();
    if (!c) return nil;
    // 1) 标准单例 +getInstance
    if ([c respondsToSelector:@selector(getInstance)]) {
        @try {
            id i = ((id (*)(id, SEL))objc_msgSend)(c, @selector(getInstance));
            if (i) { W(@"mtop inst via +getInstance"); return i; }
        } @catch (id e) { W(@"getInstance EXC %@", e); }
    }
    // 2) 指定 site + 常见候选
    if ([c respondsToSelector:@selector(getInstanceWithAccountSite:)]) {
        NSMutableArray *sites = [NSMutableArray array];
        if (site.length) [sites addObject:site];
        [sites addObjectsFromArray:@[@"damai", @"damai_app", @"damai_iphone", @"DM", @"damaiApp", @"mtop", @"taobao"]];
        for (NSString *s in sites) {
            @try {
                id i = ((id (*)(id, SEL, id))objc_msgSend)(c, @selector(getInstanceWithAccountSite:), s);
                if (i) { W(@"mtop inst via site=%@", s); return i; }
            } @catch (id e) {}
        }
    }
    return nil;
}

static NSString *runMtop(NSString *api, NSString *v, id data, NSString *site, NSString *tag) {
    id inst = mtopInstance(site);
    if (!inst) {
        Class c = mtopServiceClass();
        return [NSString stringWithFormat:@"{\"err\":\"no mtop instance\",\"class\":\"%@\"}", c ? NSStringFromClass(c) : @"nil"];
    }
    SEL call = @selector(sync_call:apiVersion:bizParameters:);
    if (![inst respondsToSelector:call])
        call = @selector(sync_call:apiVersion:);
    if (![inst respondsToSelector:call])
        return @"{\"err\":\"no sync_call selector\"}";

    id resp = nil;
    @try {
        if (sel_isEqual(call, @selector(sync_call:apiVersion:bizParameters:)))
            resp = ((id (*)(id, SEL, id, id, id))objc_msgSend)(inst, call, api, v ?: @"1.0", data ?: @{});
        else
            resp = ((id (*)(id, SEL, id, id))objc_msgSend)(inst, call, api, v ?: @"1.0");
    } @catch (NSException *e) {
        return [NSString stringWithFormat:@"{\"err\":\"exception\",\"name\":\"%@\",\"reason\":\"%@\"}", e.name, clip(e.reason, 300)];
    }

    // 取响应：优先 data / 整体 JSON / description
    NSMutableString *payload = [NSMutableString string];
    NSArray *tryKeys = @[@"data", @"responseData", @"json"];
    for (NSString *k in tryKeys) {
        id d = nil;
        @try { d = [resp valueForKey:k]; } @catch (id e) {}
        if ([d isKindOfClass:[NSDictionary class]] || [d isKindOfClass:[NSArray class]]) {
            NSData *jd = [NSJSONSerialization dataWithJSONObject:d options:NSJSONWritingWithoutEscapingSlashes error:nil];
            if (jd) { [payload appendString:[[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding]]; break; }
        } else if ([d isKindOfClass:[NSData class]] && ((NSData *)d).length) {
            NSString *s = [[NSString alloc] initWithData:(NSData *)d encoding:NSUTF8StringEncoding];
            if (s.length) { [payload appendString:s]; break; }
        } else if ([d isKindOfClass:[NSString class]] && ((NSString *)d).length) {
            [payload appendString:(NSString *)d]; break;
        }
    }
    if (!payload.length) {
        NSData *jd = nil;
        if ([resp isKindOfClass:[NSDictionary class]] || [resp isKindOfClass:[NSArray class]])
            jd = [NSJSONSerialization dataWithJSONObject:resp options:NSJSONWritingWithoutEscapingSlashes error:nil];
        if (jd) [payload appendString:[[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding]];
    }
    if (!payload.length) [payload appendString:[NSString stringWithFormat:@"%@", resp ?: @"(nil)"]];
    if (payload.length > 260000) [payload deleteCharactersInRange:NSMakeRange(260000, payload.length - 260000)];
    M(@"CALL tag=%@ api=%@ v=%@ len=%lu", tag ?: @"-", api, v, (unsigned long)payload.length);
    return payload;
}


// 自建 MtopExtRequest 发 create（对齐 App 原生请求形态）
static NSMutableString *r_err = nil;

static NSString *runCreateViaRequest(NSDictionary *biz, NSString *api, NSString *v, NSString *tag) {
    r_err = [NSMutableString new];
    Class reqCls = NSClassFromString(@"MtopExtRequest");
    if (!reqCls) return @"{\"err\":\"no MtopExtRequest\"}";
    id inst = mtopInstance(nil);
    if (!inst) return @"{\"err\":\"no mtop instance\"}";

    id req = ((id (*)(id, SEL))objc_msgSend)(reqCls, @selector(alloc));
    @try { req = ((id (*)(id, SEL))objc_msgSend)(req, @selector(init)); } @catch (id e) {}

    // 外层：MtopExtRequest 自己的属性
    for (NSArray *kv in @[@[@"apiName", api ?: @"mtop.damai.trade.order.create"],
                          @[@"apiVersion", v ?: @"1.0"],
                          @[@"customHost", @"mtop.damai.cn"]]) {
        @try { [req setValue:kv[1] forKey:kv[0]]; W(@"outer set %@ ok", kv[0]); } @catch (id e) { W(@"outer set %@ EXC", kv[0]); }
    }
    for (NSString *k in @[@"needEcode", @"isNeedEcode"]) {
        @try { [req setValue:@YES forKey:k]; W(@"outer set %@ ok", k); break; } @catch (id e) {}
    }
    // 反降级：补 delegate / ttid，关 slim
    id dg = gLastDelegate;
    if (!dg) {
        Class ds = NSClassFromString(@"TBSDKMTOPServer");
        if (ds) {
            for (NSString *mk in @[@"getInstance", @"sharedInstance", @"getInstanceWithID:"]) {
                SEL s = NSSelectorFromString(mk);
                if ([ds respondsToSelector:s] || [ds instancesRespondToSelector:s]) {
                    @try {
                        if ([ds respondsToSelector:s]) dg = ((id (*)(id, SEL))objc_msgSend)(ds, s);
                        else if (inst && [(id)inst respondsToSelector:s]) dg = ((id (*)(id, SEL))objc_msgSend)(inst, s);
                    } @catch (id e) {}
                    if (dg) { W(@"delegate via %@ ok", mk); break; }
                }
            }
        }
    }
    if (dg) { @try { [req setValue:dg forKey:@"delegate"]; W(@"set delegate ok (%@)", NSStringFromClass([dg class])); } @catch (id e) { W(@"set delegate EXC"); } }
    else W(@"delegate 未取得");
    NSString *ttid = gLastTtid ?: @"cn.damai.iphone@damai_iphone_9.0.37";
    @try { [req setValue:ttid forKey:@"ttid"]; W(@"set ttid ok"); } @catch (id e) { W(@"set ttid EXC"); }
    for (NSString *k in @[@"isSlimConfRetry", @"_isSlimConfRetry"]) {
        @try { [req setValue:@NO forKey:k]; W(@"set %@ NO ok", k); break; } @catch (id e) {}
    }
    // 内层：bizParameters 挂在 TBSDKRequest(mrequest) 上
    Class tbCls = NSClassFromString(@"TBSDKRequest");
    if (tbCls) {
        id tbr = ((id (*)(id, SEL))objc_msgSend)(tbCls, @selector(alloc));
        @try { tbr = ((id (*)(id, SEL))objc_msgSend)(tbr, @selector(init)); } @catch (id e) {}
        if (tbr) {
            BOOL ok = NO;
            for (NSArray *kv in @[@[@"apiName", api ?: @"mtop.damai.trade.order.create"],
                                  @[@"apiVersion", v ?: @"1.0"],
                                  @[@"bizParameters", biz ?: @{}],
                                  @[@"customHost", @"mtop.damai.cn"]]) {
                @try { [tbr setValue:kv[1] forKey:kv[0]]; ok = YES; W(@"inner set %@ ok", kv[0]); } @catch (id e) { W(@"inner set %@ EXC", kv[0]); }
            }
            if (ok) {
                BOOL attached = NO;
                for (NSString *k in @[@"mrequest", @"request"]) {
                    @try { [req setValue:tbr forKey:k]; attached = YES; W(@"attach via %@ ok", k); break; } @catch (id e) {}
                }
                if (!attached) W(@"attach mrequest EXC（无 setter）");
            }
        } else [r_err appendString:@"TBSDKRequest init 失败;"];
    } else [r_err appendString:@"无 TBSDKRequest 类;"];

    W(@"REQ-OBJ api=%@ v=%@ biz=%lu", api, v, (unsigned long)biz.count);
    SEL call = @selector(sync_call:);
    id resp = nil;
    @try {
        resp = ((id (*)(id, SEL, id))objc_msgSend)(inst, call, req);
    } @catch (NSException *e) {
        return [NSString stringWithFormat:@"{\"err\":\"exception\",\"name\":\"%@\",\"reason\":\"%@\"}", e.name, clip(e.reason, 200)];
    }
    NSMutableString *payload = [NSMutableString string];
    id d = nil;
    @try { d = [resp valueForKey:@"data"]; } @catch (id e) {}
    if ([d isKindOfClass:[NSDictionary class]] || [d isKindOfClass:[NSArray class]]) {
        NSData *jd = [NSJSONSerialization dataWithJSONObject:d options:NSJSONWritingWithoutEscapingSlashes error:nil];
        if (jd) [payload appendString:[[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding]];
    }
    if (!payload.length) {
        NSString *errLine = nil;
        @try { errLine = [[resp valueForKey:@"error"] description]; } @catch (id e) {}
        [payload appendFormat:@"{\"raw\":\"%@\"}", clip(errLine ?: [NSString stringWithFormat:@"%@", resp ?: @"(nil)"], 600)];
    }
    M(@"CREATE-VIA-REQ tag=%@ len=%lu err=%@", tag ?: @"-", (unsigned long)payload.length, r_err);
    return payload;
}

// ---------------- 指令通道 ----------------
static void hookAllClasses(void);   // 前向声明

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
    } else if ([c isEqualToString:@"replay_create"] || [c isEqualToString:@"dumpparams"]) {
        if (!gLastCreateBiz) { writeOut(@"尚未捕获到 trade.order.* 请求（先在 App 里点一次提交）"); return; }
        if ([c isEqualToString:@"dumpparams"]) {
            NSMutableString *o = [NSMutableString string];
            [o appendFormat:@"api=%@\nbuyParam=%@\nexParams=%lu B\nfeature=%@\n",
             gLastCreateAPI, gLastCreateBiz[@"buyParam"],
             (unsigned long)[[NSString stringWithFormat:@"%@", gLastCreateBiz[@"exParams"]] length],
             gLastCreateBiz[@"feature"]];
            id pv = gLastCreateBiz[@"params"];
            [o appendFormat:@"paramsLen=%lu\n---- params(base64) ----\n%@\n---- decoded ----\n%@\n",
             (unsigned long)[pv length], pv, decodeParamsField(gLastCreateBiz)];
            writeOut(o);
            return;
        }
        if (!exists(@"dm_allow_create")) { writeOut(@"拒绝：没有 dm_allow_create"); return; }
        NSString *bp = cmd[@"buyParam"];
        NSString *payload = nil;
        if (gLastReqObj) {
            // ★ 对象复用：原样（或改 buyParam 后）重发 App 自己的请求对象
            if ([bp isKindOfClass:[NSString class]] && bp.length) {
                @try { [gLastReqObj setValue:bp forKey:@"buyParam"]; } @catch (id e) {}
                id mr = nil;
                @try { mr = [gLastReqObj valueForKey:@"mrequest"]; } @catch (id e) {}
                if (mr) {
                    NSMutableDictionary *nb = [gLastCreateBiz mutableCopy];
                    nb[@"buyParam"] = bp;
                    BOOL done = NO;
                    @try { [mr setValue:nb forKey:@"bizParameters"]; done = YES; } @catch (id e) {}
                    if (!done) {
                        Ivar iv = class_getInstanceVariable([mr class], "_bizParameters");
                        if (iv) { object_setIvar(mr, iv, nb); done = YES; }
                    }
                    W(@"mutate buyParam=%@ done=%d", bp, (int)done);
                }
            }
            id inst2 = mtopInstance(nil);
            id resp = nil;
            @try { resp = ((id (*)(id, SEL, id))objc_msgSend)(inst2, @selector(sync_call:), gLastReqObj); }
            @catch (NSException *e) { payload = [NSString stringWithFormat:@"{\"err\":\"%@\"}", e.name]; }
            NSMutableString *pl = [NSMutableString string];
            id d2 = nil;
            @try { d2 = [resp valueForKey:@"data"]; } @catch (id e) {}
            if ([d2 isKindOfClass:[NSDictionary class]] || [d2 isKindOfClass:[NSArray class]]) {
                NSData *jd = [NSJSONSerialization dataWithJSONObject:d2 options:NSJSONWritingWithoutEscapingSlashes error:nil];
                if (jd) [pl appendString:[[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding]];
            }
            if (!pl.length) {
                NSString *errLine = nil;
                @try { errLine = [[resp valueForKey:@"error"] description]; } @catch (id e) {}
                [pl appendFormat:@"{\"raw\":\"%@\"}", clip(errLine ?: @"(nil)", 600)];
            }
            payload = pl;
            W(@"REPLAY-OBJ buyParam=%@ len=%lu", bp ?: @"(原样)", (unsigned long)pl.length);
        } else {
            NSMutableDictionary *biz = [gLastCreateBiz mutableCopy];
            if ([bp isKindOfClass:[NSString class]] && bp.length) biz[@"buyParam"] = bp;
            payload = runCreateViaRequest(biz, gLastCreateAPI, @"1.0", tag);
        }
        writeOut([NSString stringWithFormat:@"[replay %@ buyParam=%@]\n%@\n", gLastCreateAPI, bp ?: @"(原样)", payload]);
        [payload writeToFile:dpath([NSString stringWithFormat:@"dm_res_%@.json", tag]) atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } else if ([c isEqualToString:@"create"]) {
        if (!exists(@"dm_allow_create")) { writeOut(@"拒绝执行：沙盒里没有 dm_allow_create"); return; }
        NSString *buyParam = cmd[@"buyParam"];
        NSString *signKey = cmd[@"signKey"] ?: @"";
        id params = cmd[@"params"] ?: @{};
        if (!buyParam.length || ![params isKindOfClass:[NSDictionary class]]) { writeOut(@"参数不足：需要 buyParam + params"); return; }
        NSData *pj = [NSJSONSerialization dataWithJSONObject:params options:0 error:nil];
        NSData *gz = dmGzip(pj);
        NSString *b64 = gz ? [gz base64EncodedStringWithOptions:0] : @"";
        NSDictionary *ex = @{@"signKey": signKey, @"novad": @"mtop.damai.cn", @"novacv": @"1.0",
                             @"novab": @"mtop.damai.trade.order.build", @"channel": @"damai_app",
                             @"novaav": @"1.0", @"novac": @"mtop.damai.trade.order.create", @"coupon": @"true",
                             @"umpChannel": @"10001", @"novaa": @"mtop.damai.trade.order.adjust", @"coVersion": @"2.0",
                             @"novabv": @"1.0", @"pioneer": @"1", @"atomSplit": @"1"};
        NSData *exj = [NSJSONSerialization dataWithJSONObject:ex options:0 error:nil];
        NSString *exs = exj ? [[NSString alloc] initWithData:exj encoding:NSUTF8StringEncoding] : @"{}";
        NSMutableDictionary *biz = [NSMutableDictionary dictionary];
        biz[@"buyNow"] = @YES;
        biz[@"buyParam"] = buyParam;
        biz[@"exParams"] = exs;
        biz[@"params"] = b64;
        biz[@"feature"] = @"{\"gzip\":\"true\"}";
        NSString *payload = runMtop(@"mtop.damai.trade.order.create", @"1.0", biz, nil, tag);
        writeOut([NSString stringWithFormat:@"[create %@ paramsRaw=%lu b64=%lu]\n%@\n", buyParam, (unsigned long)pj.length, (unsigned long)b64.length, payload]);
        [payload writeToFile:dpath([NSString stringWithFormat:@"dm_res_%@.json", tag]) atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } else if ([c isEqualToString:@"ui"]) {
        __block NSString *out = nil;
        dmRunOnMain(^{
            NSMutableString *o = [NSMutableString string];
            UIViewController *vc = dmTopVC();
            [o appendFormat:@"topVC=%@\n", vc ? NSStringFromClass([vc class]) : @"nil"];
            int budget = 300;
            dmWalkViews(vc.view, 0, o, &budget, cmd[@"kw"]);
            out = [o copy];
        });
        writeOut(out ?: @"(nil)");
    } else if ([c isEqualToString:@"uitap"]) {
        NSString *needle = cmd[@"txt"];
        if (!needle.length) { writeOut(@"需要 txt 参数"); return; }
        writeOut(dmTapByText(needle));
    } else if ([c isEqualToString:@"hidfind"] || [c isEqualToString:@"hidtap"]) {
        NSString *needle = cmd[@"txt"];
        if (!needle.length) { writeOut(@"需要 txt 参数"); return; }
        writeOut(dmHIDTapByText(needle, [c isEqualToString:@"hidtap"]));
    } else if ([c isEqualToString:@"chain"] || [c isEqualToString:@"gestap"]) {
        writeOut(dmChain(cmd[@"txt"] ?: @"立即提交", [c isEqualToString:@"gestap"]));
    } else if ([c isEqualToString:@"axact"]) {
        writeOut(dmAXActivate(cmd[@"txt"] ?: @""));
    } else if ([c isEqualToString:@"viewinfo"]) {
        writeOut(dmViewIvars(cmd[@"txt"] ?: @"立即提交"));
    } else if ([c isEqualToString:@"dxev"]) {
        writeOut(dmDXEv(cmd[@"txt"] ?: @"立即提交"));
    } else if ([c isEqualToString:@"instinfo"]) {
        NSMutableString *o = [NSMutableString string];
        id inst = mtopInstance(cmd[@"site"]);
        [o appendFormat:@"inst=%@\n", inst ? NSStringFromClass([inst class]) : @"nil"];
        if (inst) {
            int b = 40;
            dumpIvarsOf(inst, [inst class], o, &b);
        }
        writeOut(o);
    } else if ([c isEqualToString:@"classinfo"]) {
        NSString *cn = cmd[@"cls"] ?: @"";
        Class cc = NSClassFromString(cn);
        NSMutableString *o = [NSMutableString string];
        if (!cc) { [o appendFormat:@"no class %@\n", cn]; }
        else {
            for (Class k = cc; k && k != [NSObject class]; k = class_getSuperclass(k)) {
                [o appendFormat:@"=== %@ (super=%@) ===\n", NSStringFromClass(k), NSStringFromClass(class_getSuperclass(k))];
                unsigned int ic = 0; Ivar *iv = class_copyIvarList(k, &ic);
                for (unsigned int i = 0; i < ic; i++) [o appendFormat:@"  .%s (%s)\n", ivar_getName(iv[i]), ivar_getTypeEncoding(iv[i])];
                if (iv) free(iv);
                unsigned int mc = 0; Method *mm = class_copyMethodList(k, &mc);
                for (unsigned int i = 0; i < mc; i++) [o appendFormat:@"  -%@\n", NSStringFromSelector(method_getName(mm[i]))];
                if (mm) free(mm);
            }
        }
        writeOut(o);
    } else if ([c isEqualToString:@"hookall"]) {
        hookAllClasses();
        writeOut([NSString stringWithFormat:@"hookall done total=%d\n", gHookCount]);
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
// ★ v0.2 关键修正：绝不能在 dylib 构造函数里调 objc_copyClassList / class_getInstanceMethod。
//   那一刻 dyld 还在跑 initializer，libobjc 的 realizeAllClasses() 会 SIGSEGV（v0.1 就是这么崩的）。
//   正确做法：延后到主队列、且 App 已 finishLaunching 之后再做 hook。
static BOOL gSetup = NO;

static void bootMtopInfo(void) {
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
}

static void setupOnce(void) {
    if (gSetup) return;
    gSetup = YES;
    W(@"setupOnce begin (app state=%ld)", (long)[UIApplication sharedApplication].applicationState);
    // 从落盘文件恢复最近一次 create 参数（重启后不用再点提交）
    @try {
        NSData *jd = [NSData dataWithContentsOfFile:dpath(@"dm_biz.json")];
        if (jd) {
            NSDictionary *snap = [NSJSONSerialization JSONObjectWithData:jd options:0 error:nil];
            if ([snap isKindOfClass:[NSDictionary class]] && [snap[@"biz"] isKindOfClass:[NSDictionary class]]) {
                gLastCreateBiz = snap[@"biz"];
                gLastCreateAPI = snap[@"api"];
                W(@"restored biz from dm_biz.json (params len=%lu)", (unsigned long)[[NSString stringWithFormat:@"%@", gLastCreateBiz[@"params"]] length]);
            }
        }
    } @catch (id e) { W(@"restore biz EXC %@", e); }
    @try { hookNet(); } @catch (id e) { W(@"hookNet EXC %@", e); }
    @try { hookSecurityGuard(); } @catch (id e) { W(@"hookSG EXC %@", e); }
    @try { hookDX(); } @catch (id e) { W(@"hookDX EXC %@", e); }
    @try { hookSending(); } @catch (id e) { W(@"hookSending EXC %@", e); }
    @try { hookHeaders(); } @catch (id e) { W(@"hookHeaders EXC %@", e); }
    @try { hookMtop(); } @catch (id e) { W(@"hookMtop EXC %@", e); }
    @try { bootMtopInfo(); } @catch (id e) { M(@"bootMtopInfo EXC %@", e); }
    flushAll();
    W(@"setupOnce done hooks=%d", gHookCount);
    flushAll();
}

static void startTimers(void) {
    static BOOL started = NO;
    if (started) return;
    started = YES;
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
}

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
        // 只写日志，不碰 ObjC 运行时
        dispatch_async(dispatch_get_main_queue(), ^{
            @autoreleasepool {
                [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                                  object:nil queue:[NSOperationQueue mainQueue]
                                                              usingBlock:^(NSNotification *n) {
                    W(@"got didFinishLaunching");
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                        setupOnce();
                        startTimers();
                    });
                }];
                // 兜底：万一通知错过了（dylib 注入到已运行的进程），1.8s 后直接干
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.8 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    if (!gSetup) { W(@"fallback timer -> setupOnce"); setupOnce(); }
                    startTimers();
                });
            }
        });
        flushAll();
    }
}
