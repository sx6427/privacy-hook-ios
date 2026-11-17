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
#import <CommonCrypto/CommonDigest.h>
#import <WebKit/WebKit.h>
#import <JavaScriptCore/JavaScriptCore.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <poll.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <libkern/OSCacheControl.h>

static NSString *const kVer = @"v6.3";

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
static NSString *runMtop(NSString *api, NSString *v, id data, NSString *site, NSString *tag);
static id mtopInstance(NSString *site);
static void dmForceSign(id mr);
static NSString *dmH5Call(NSString *api, NSString *ver, NSString *dataJson);
static id dmFindNode(id node, NSString *needle);
static NSString *dmRunJS2(NSString *code);
static void dmWalkNodes(id node, int depth, NSMutableString *s, int *budget, NSString *needle, id *found);
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


// 强制 TBSDKRequest 走 HTTPS+POST+签名（关掉 unsign 降级）
static void dmForceSign(id mr) {
    if (!mr) return;
    for (NSArray *kv in @[@[@"isUseHttpPost", @YES],
                          @[@"allowSwithToPOST", @YES],
                          @[@"isUseHttps", @YES],
                          @[@"attemptUnsign", @NO],
                          @[@"isConfiguredUnSign", @NO],
                          @[@"degradedUnSignPositive", @NO]]) {
        @try { [mr setValue:kv[1] forKey:kv[0]]; W(@"force %@ ok", kv[0]); } @catch (id e) { W(@"force %@ EXC", kv[0]); }
    }
}


// ---------------- H5 购买链路（buy.damai.cn，cookie 鉴权，无加固签名）----------------
static NSData *dmSyncGet(NSURL *url, NSDictionary *headers) {
    NSMutableURLRequest *rq = [NSMutableURLRequest requestWithURL:url];
    rq.HTTPMethod = @"GET";
    rq.timeoutInterval = 15;
    for (NSString *k in headers) [rq setValue:headers[k] forHTTPHeaderField:k];
    __block NSData *out = nil;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    [[[NSURLSession sharedSession] dataTaskWithRequest:rq completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
        out = d; dispatch_semaphore_signal(sem);
    }] resume];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_SEC));
    return out;
}

static NSData *dmSyncPost(NSURL *url, NSDictionary *headers, NSData *body) {
    NSMutableURLRequest *rq = [NSMutableURLRequest requestWithURL:url];
    rq.HTTPMethod = @"POST";
    rq.HTTPBody = body;
    rq.timeoutInterval = 15;
    for (NSString *k in headers) [rq setValue:headers[k] forHTTPHeaderField:k];
    __block NSData *out = nil;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    [[[NSURLSession sharedSession] dataTaskWithRequest:rq completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
        out = d; dispatch_semaphore_signal(sem);
    }] resume];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_SEC));
    return out;
}

static NSString *dmEnc(NSString *s) {
    return [s stringByAddingPercentEncodingWithAllowedCharacters:[[NSCharacterSet alphanumericCharacterSet] invertedSet]];
}

// 完整 H5 下单：orderConfirm -> 改表单 -> createOrder
static NSString *dmH5Buy(NSString *buyParam, NSString *viewerName, BOOL doSubmit) {
    NSMutableString *log = [NSMutableString string];
    NSString *ex = @"{\"channel\":\"damai_app\",\"umpChannel\":\"10001\",\"coVersion\":\"2.0\",\"coupon\":\"true\",\"pioneer\":\"1\",\"atomSplit\":\"1\",\"damai\":\"1\"}";
    NSDictionary *gh = @{@"User-Agent": @"Mozilla/5.0 (iPhone; CPU iPhone OS 16_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                         @"Accept": @"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"};
    NSString *u1 = [NSString stringWithFormat:@"https://buy.damai.cn/orderConfirm?exParams=%@&buyParam=%@&buyNow=true&spm=a2oeg.project.projectinfo.dbuy",
                    dmEnc(ex), dmEnc(buyParam)];
    [log appendFormat:@"[1] GET orderConfirm\n"];
    NSData *d1 = dmSyncGet([NSURL URLWithString:u1], gh);
    NSString *html = [[NSString alloc] initWithData:d1 encoding:NSUTF8StringEncoding] ?: @"";
    [log appendFormat:@"    htmlLen=%lu\n", (unsigned long)html.length];
    // 抠 window.INIT_DATA
    NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:@"window\\.INIT_DATA[\\s\\S]*?};"
                                                                       options:0 error:nil];
    NSTextCheckingResult *hit = [re firstMatchInString:html options:0 range:NSMakeRange(0, html.length)];
    if (!hit) { [log appendFormat:@"    未找到 INIT_DATA（可能未登录/风控/页面结构变化）\n    head=%@\n", clip(html, 400)]; return log; }
    NSString *jsonStr = [[html substringWithRange:hit.range] stringByReplacingOccurrencesOfString:@"window.INIT_DATA = " withString:@""];
    jsonStr = [jsonStr substringToIndex:jsonStr.length - 1];   // 去掉结尾的 };
    NSDictionary *form = [NSJSONSerialization JSONObjectWithData:[jsonStr dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
    if (!form) { [log appendString:@"    INIT_DATA 解析失败\n"]; return log; }
    NSMutableDictionary *info = [form mutableCopy];
    @try {
        NSString *ostr = [NSString stringWithFormat:@"%@", form[@"output"] ?: @"{}"];
        NSData *od = [ostr dataUsingEncoding:NSUTF8StringEncoding];
        id oj = od ? [NSJSONSerialization JSONObjectWithData:od options:0 error:nil] : nil;
        if (oj) info[@"output"] = oj;
    } @catch (id e) {}
    [log appendFormat:@"[2] 表单解析成功 dataKeys=%@\n", [[info[@"data"] allKeys] componentsJoinedByString:@","]];
    // 标观演人
    NSString *viewerKey = nil;
    for (NSString *k in info[@"data"]) if ([k rangeOfString:@"dmViewer"].location != NSNotFound) viewerKey = k;
    if (viewerKey) {
        NSDictionary *vk = info[@"data"][viewerKey];
        NSMutableArray *ul = [((NSArray *)vk[@"fields"][@"dmViewerList"] ?: @[]) mutableCopy];
        BOOL matched = NO;
        for (NSMutableDictionary *u in ul) {
            NSString *nm = u[@"viewerName"] ?: @"";
            BOOL use = viewerName.length ? [nm rangeOfString:viewerName].location != NSNotFound : YES;
            u[@"isUsed"] = use ? @YES : @NO;
            if (use) matched = YES;
        }
        NSMutableDictionary *vk2 = [vk mutableCopy];
        NSMutableDictionary *f2 = [vk[@"fields"] mutableCopy];
        f2[@"dmViewerList"] = ul;
        vk2[@"fields"] = f2;
        NSMutableDictionary *data2 = [info[@"data"] mutableCopy];
        data2[viewerKey] = vk2;
        info[@"data"] = data2;
        [log appendFormat:@"    观演人匹配=%d (viewer=%@)\n", (int)matched, viewerName ?: @"(第一个)"];
        if (viewerName.length && !matched) [log appendString:@"    ★ 观演人没匹配上，仍会提交（isUsed 全 false）\n"];
    } else [log appendString:@"    该表单无 dmViewer 节点\n"];
    if (!doSubmit) { [log appendString:@"[3] 未提交（观察模式）\n    表单已保存到 dm_res_h5form.json\n"];
        NSData *jd = [NSJSONSerialization dataWithJSONObject:info options:NSJSONWritingWithoutEscapingSlashes error:nil];
        if (jd) [jd writeToFile:dpath(@"dm_res_h5form.json") options:NSDataWritingAtomic error:nil];
        return log;
    }
    // step3: createOrder
    [log appendString:@"[3] POST createOrder\n"];
    NSData *body = [NSJSONSerialization dataWithJSONObject:info options:NSJSONWritingWithoutEscapingSlashes error:nil];
    NSDictionary *ph = @{@"User-Agent": gh[@"User-Agent"],
                         @"Content-Type": @"application/json;charset=UTF-8",
                         @"X-Requested-With": @"XMLHttpRequest",
                         @"Origin": @"https://buy.damai.cn",
                         @"Referer": @"https://buy.damai.cn/orderConfirm?",
                         @"Accept": @"application/json, text/plain, */*"};
    NSString *u3 = @"https://buy.damai.cn/multi/trans/createOrder?feature=%7B%22returnUrl%22%3A%22https%3A%2F%2Forders.damai.cn%2ForderDetail%22%2C%22serviceVersion%22%3A%221.8.5%22%7D&submitref=undefined";
    NSData *d3 = dmSyncPost([NSURL URLWithString:u3], ph, body);
    NSString *resp = [[NSString alloc] initWithData:d3 encoding:NSUTF8StringEncoding] ?: @"";
    [log appendFormat:@"    resp=%@\n", clip(resp, 1200)];
    [resp writeToFile:dpath(@"dm_res_h5create.json") atomically:YES encoding:NSUTF8StringEncoding error:nil];
    return log;
}


// ---------------- H5 网关（公开 MD5 签名协议，绕开加固壳）----------------
static NSString *dmMd5(NSString *in) {
    unsigned char dg[CC_MD5_DIGEST_LENGTH];
    const char *c = in.UTF8String;
    CC_MD5(c, (CC_LONG)strlen(c), dg);
    NSMutableString *h = [NSMutableString string];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) [h appendFormat:@"%02x", dg[i]];
    return h;
}

static NSString *dmH5Token(void) {
    for (NSHTTPCookie *c in [NSHTTPCookieStorage sharedHTTPCookieStorage].cookies) {
        if ([c.name isEqualToString:@"_m_h5_tk"]) {
            NSArray *p = [c.value componentsSeparatedByString:@"_"];
            return p.firstObject ?: @"";
        }
    }
    return @"";
}

static NSString *dmEnc2(NSString *s) {
    return [s stringByAddingPercentEncodingWithAllowedCharacters:[[NSCharacterSet alphanumericCharacterSet] invertedSet]];
}

static NSData *dmH5Sync(NSURL *url, NSString *method, NSData *body) {
    NSMutableURLRequest *rq = [NSMutableURLRequest requestWithURL:url];
    rq.HTTPMethod = method;
    rq.timeoutInterval = 15;
    if (body) rq.HTTPBody = body;
    __block NSData *out = nil;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    [[[NSURLSession sharedSession] dataTaskWithRequest:rq completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
        out = d; dispatch_semaphore_signal(sem);
    }] resume];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_SEC));
    return out;
}

// 通用 H5 mtop 调用（自动处理 token 过期重试）
static NSString *dmH5Call(NSString *api, NSString *ver, NSString *dataJson) {
    NSMutableString *log = [NSMutableString string];
    for (int attempt = 0; attempt < 2; attempt++) {
        NSString *token = dmH5Token();
        long long t = (long long)([[NSDate date] timeIntervalSince1970] * 1000);
        NSString *sign = dmMd5([NSString stringWithFormat:@"%@&%lld&12574478&%@", token, t, dataJson]);
        NSString *u = [NSString stringWithFormat:
            @"https://mtop.damai.cn/h5/%@/%@/?appKey=12574478&t=%lld&sign=%@&api=%@&v=%@&type=originaljson&dataType=json&timeout=20000&data=%@",
            api, ver, t, sign, dmEnc2(api), dmEnc2(ver), dmEnc2(dataJson)];
        [log appendFormat:@"[attempt %d] token=%@... sign=%@...\n", attempt, clip(token, 8), clip(sign, 12)];
        NSData *d = dmH5Sync([NSURL URLWithString:u], @"GET", nil);
        NSString *body = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] ?: @"";
        [log appendFormat:@"    resp=%@\n", clip(body, 900)];
        NSData *jd = [body dataUsingEncoding:NSUTF8StringEncoding];
        id obj = jd ? [NSJSONSerialization JSONObjectWithData:jd options:0 error:nil] : nil;
        NSString *ret = @"";
        if ([obj isKindOfClass:[NSDictionary class]]) {
            id r = obj[@"ret"];
            if ([r isKindOfClass:[NSArray class]] && [r count]) ret = [r firstObject];
            else if ([r isKindOfClass:[NSString class]]) ret = r;
        }
        if ([ret rangeOfString:@"SUCCESS"].location != NSNotFound ||
            [ret rangeOfString:@"TOKEN"].location == NSNotFound) {
            return [log stringByAppendingFormat:@"\nRESULT %@", body];
        }
        [log appendString:@"    token 失效，刷新重试\n"];
    }
    return log;
}


// 挖 DXRootView 手势的 target/block 并尝试直接触发
static NSString *dmDXGest(NSString *needle, BOOL fire) {
    __block NSString *report = nil;
    dmRunOnMain(^{
        NSMutableString *r = [NSMutableString string];
        UIView *tv = dmFindByText(needle);
        UIView *root = tv ? tv.superview : nil;
        Class dxc = NSClassFromString(@"DXRootView");
        while (root && dxc && ![root isKindOfClass:dxc]) root = root.superview;
        if (!root) { report = @"未找到 DXRootView（当前页面不是确认页）"; return; }
        [r appendFormat:@"DXRootView=%@\n", root];
        for (UIGestureRecognizer *g in root.gestureRecognizers) {
            [r appendFormat:@"gesture=%@\n", NSStringFromClass([g class])];
            NSArray *targets = nil;
            @try { targets = [g valueForKey:@"_targets"]; } @catch (id e) { [r appendFormat:@"  _targets KVC EXC\n"]; }
            if (!targets) { [r appendString:@"  _targets=nil\n"]; continue; }
            [r appendFormat:@"  targets=%lu\n", (unsigned long)targets.count];
            for (id t in targets) {
                id tgt = nil, act = nil;
                @try { tgt = [t valueForKey:@"_target"]; } @catch (id e) {}
                @try { act = [t valueForKey:@"_action"]; } @catch (id e) {}
                [r appendFormat:@"  entry: target=%@(%@) action=%@(%@)\n",
                 tgt ? NSStringFromClass([tgt class]) : @"nil", tgt ? [NSString stringWithFormat:@"%p", tgt] : @"-",
                 act ? NSStringFromClass([act class]) : @"nil", act ? @"value" : @"-"];
                BOOL isBlock = act && [NSStringFromClass([act class]) containsString:@"Block"];
                if (fire && isBlock) {
                    [r appendString:@"  ★ action 是 block，尝试直接调用…\n"];
                    @try {
                        void (^blk)(id) = act;
                        blk(g);
                        [r appendString:@"  ★ block 调用完成（观察大麦是否弹出收银台）\n"];
                    } @catch (id e) { [r appendFormat:@"  block EXC %@\n", e]; }
                } else if (fire && tgt && act && [act isKindOfClass:[NSString class]]) {
                    SEL sel = NSSelectorFromString(act);
                    if ([tgt respondsToSelector:sel]) {
                        @try { ((void (*)(id, SEL, id))objc_msgSend)(tgt, sel, g); [r appendString:@"  ★ target-action 调用完成\n"]; }
                        @catch (id e) { [r appendFormat:@"  EXC %@\n", e]; }
                    } else [r appendFormat:@"  target 不响应 %@\n", act];
                }
            }
        }
        report = [r copy];
    });
    return report ?: @"(nil)";
}


// 劫持 locationInView: 以便 onTap: 落在指定坐标
static CGPoint gFakeLoc;
static BOOL gFakeLocOn = NO;
static CGPoint (*o_locInView)(id, SEL, UIView *);
static CGPoint dm_locInView(id self, SEL _cmd, UIView *v) {
    if (gFakeLocOn) return gFakeLoc;
    return o_locInView ? o_locInView(self, _cmd, v) : CGPointZero;
}
static void dmSwizzleLoc(BOOL on) {
    static BOOL installed = NO;
    if (!installed) {
        Method m = class_getInstanceMethod([UIGestureRecognizer class], @selector(locationInView:));
        if (m) {
            o_locInView = (void *)method_getImplementation(m);
            method_setImplementation(m, (IMP)dm_locInView);
            installed = YES;
            W(@"swizzle locationInView: 已安装");
        }
    }
    gFakeLocOn = on;
}

// 程序化点击 DinamicX 节点：调 DXEventDispatcher onTap:
static NSString *dmDXFire(NSString *needle) {
    __block NSString *report = nil;
    dmRunOnMain(^{
        NSMutableString *r = [NSMutableString string];
        UIView *tv = dmFindByText(needle);
        if (!tv) { report = @"未找到目标文本节点"; return; }
        UIView *root = tv.superview;
        Class dxc = NSClassFromString(@"DXRootView");
        while (root && dxc && ![root isKindOfClass:dxc]) root = root.superview;
        if (!root) { report = @"未找到 DXRootView"; return; }
        id disp = nil;
        @try { disp = [root performSelector:@selector(eventDispatcher)]; } @catch (id e) {}
        if (!disp) { report = @"eventDispatcher 为空"; return; }
        // 目标坐标（转换成 rootView 坐标系）
        gFakeLoc = [tv convertPoint:CGPointMake(CGRectGetMidX(tv.bounds), CGRectGetMidY(tv.bounds)) toView:root];
        [r appendFormat:@"目标点(rootView坐标)=(%.0f,%.0f) dispatcher=%@\n", gFakeLoc.x, gFakeLoc.y, NSStringFromClass([disp class])];
        // 找 tap 手势
        UIGestureRecognizer *tap = nil;
        for (UIGestureRecognizer *g in root.gestureRecognizers)
            if ([g isKindOfClass:[UITapGestureRecognizer class]]) { tap = g; break; }
        [r appendFormat:@"tapGesture=%@\n", tap ? NSStringFromClass([tap class]) : @"nil"];
        dmSwizzleLoc(YES);
        // ★ 关键：把手势状态伪造成 ended(3)，否则 DinamicX handler 会提前返回
        Ivar sIV = class_getInstanceVariable([UIGestureRecognizer class], "_state");
        if (sIV) { object_setIvar(tap, sIV, @(3)); [r appendString:@"gesture._state → ended(3)\n"]; }
        Ivar vIV = class_getInstanceVariable([UIGestureRecognizer class], "_view");
        if (vIV && root) { @try { object_setIvar(tap, vIV, root); } @catch (id e) {} }
        @try {
            if ([disp respondsToSelector:@selector(onTap:)]) {
                ((void (*)(id, SEL, id))objc_msgSend)(disp, @selector(onTap:), tap);
                [r appendString:@"★ onTap: 调用完成\n"];
            } else [r appendString:@"dispatcher 不响应 onTap:/n"];
        } @catch (id e) { [r appendFormat:@"onTap EXC %@\n", e]; }
        usleep(200000);
        dmSwizzleLoc(NO);
        report = [r copy];
    });
    return report ?: @"(nil)";
}


// ---------------- JavaScriptCore 引擎 + ObjC 桥（改逻辑不用重注入）----------------
@protocol DMBridgeExport <JSExport>
- (NSString *)mtop:(NSString *)api v:(NSString *)v dataJson:(NSString *)dataJson;
- (NSString *)h5:(NSString *)api v:(NSString *)v dataJson:(NSString *)dataJson;
- (NSString *)uiTree:(NSString *)kw;
- (NSString *)dxTap:(NSString *)text state:(int)state offx:(double)ox offy:(double)oy;
- (NSString *)tapText:(NSString *)text;
- (NSString *)replay:(NSString *)buyParam;
- (NSString *)eventMap:(NSString *)text;
- (NSString *)triggerEvent:(NSString *)text name:(NSString *)name;
- (NSString *)gaiaTap:(NSString *)text;
- (NSString *)nodeTree:(NSString *)text;
- (NSString *)fireNode:(NSString *)text;
- (void)logjs:(NSString *)s;
- (void)sleepms:(double)ms;
@end

@interface DMBridge : NSObject <DMBridgeExport>
@property (nonatomic, strong) NSMutableString *out;
@end

@implementation DMBridge
- (instancetype)init { if ((self = [super init])) { _out = [NSMutableString new]; } return self; }
- (void)logjs:(NSString *)s { [_out appendFormat:@"[js] %@\n", s ?: @""]; }
- (void)sleepms:(double)ms { usleep((useconds_t)(ms * 1000)); }
- (NSString *)mtop:(NSString *)api v:(NSString *)v dataJson:(NSString *)dataJson {
    id data = nil;
    if (dataJson.length) data = [NSJSONSerialization JSONObjectWithData:[dataJson dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
    NSString *r = runMtop(api, v ?: @"1.0", data ?: @{}, nil, @"js");
    [_out appendFormat:@"[mtop %@] %@\n", api, clip(r, 2000)];
    return r;
}
- (NSString *)h5:(NSString *)api v:(NSString *)v dataJson:(NSString *)dataJson {
    NSString *r = dmH5Call(api, v ?: @"1.0", dataJson ?: @"{}");
    [_out appendFormat:@"[h5 %@] %@\n", api, clip(r, 2000)];
    return r;
}
- (NSString *)uiTree:(NSString *)kw {
    __block NSString *o = nil;
    dmRunOnMain(^{
        NSMutableString *s = [NSMutableString string];
        UIViewController *vc = dmTopVC();
        [s appendFormat:@"topVC=%@\n", vc ? NSStringFromClass([vc class]) : @"nil"];
        int budget = 300;
        dmWalkViews(vc.view, 0, s, &budget, kw);
        o = [s copy];
    });
    [_out appendString:clip(o, 4000)];
    return o ?: @"";
}
- (NSString *)dxTap:(NSString *)text state:(int)state offx:(double)ox offy:(double)oy {
    __block NSString *rep = nil;
    dmRunOnMain(^{
        NSMutableString *r = [NSMutableString string];
        UIView *tv = dmFindByText(text);
        if (!tv) { rep = @"未找到文本节点"; return; }
        UIView *root = tv.superview;
        Class dxc = NSClassFromString(@"DXRootView");
        while (root && dxc && ![root isKindOfClass:dxc]) root = root.superview;
        if (!root) { rep = @"未找到 DXRootView"; return; }
        id disp = nil;
        @try { disp = [root performSelector:@selector(eventDispatcher)]; } @catch (id e) {}
        UIGestureRecognizer *tap = nil;
        for (UIGestureRecognizer *g in root.gestureRecognizers)
            if ([g isKindOfClass:[UITapGestureRecognizer class]]) { tap = g; break; }
        if (!tap || !disp) { rep = @"gesture/dispatcher 缺失"; return; }
        CGPoint c = [tv convertPoint:CGPointMake(CGRectGetMidX(tv.bounds), CGRectGetMidY(tv.bounds)) toView:root];
        gFakeLoc = CGPointMake(c.x + ox, c.y + oy);
        dmSwizzleLoc(YES);
        Ivar sIV = class_getInstanceVariable([UIGestureRecognizer class], "_state");
        if (sIV) object_setIvar(tap, sIV, @(state));
        Ivar vIV = class_getInstanceVariable([UIGestureRecognizer class], "_view");
        if (vIV) @try { object_setIvar(tap, vIV, root); } @catch (id e) {}
        @try {
            ((void (*)(id, SEL, id))objc_msgSend)(disp, @selector(onTap:), tap);
            [r appendFormat:@"onTap 调用完成 state=%d pt=(%.0f,%.0f)\n", state, gFakeLoc.x, gFakeLoc.y];
        } @catch (id e) { [r appendFormat:@"EXC %@\n", e]; }
        usleep(300000);
        dmSwizzleLoc(NO);
        rep = [r copy];
    });
    [_out appendString:rep ?: @""];
    return rep ?: @"";
}


- (NSString *)nodeTree:(NSString *)text {
    __block NSString *rep = nil;
    dmRunOnMain(^{
        NSMutableString *s = [NSMutableString string];
        UIView *v = dmFindByText(text.length ? text : @"立即提交");
        UIView *root = v;
        Class rvc = NSClassFromString(@"DXRootView");
        while (root && rvc && ![root isKindOfClass:rvc]) root = root.superview;
        id wn = nil;
        @try { wn = ((id (*)(id, SEL))objc_msgSend)(root, NSSelectorFromString(@"dx_getWidgetNode")); } @catch (id e) {}
        [s appendFormat:@"rootNode=%@\n", wn ? NSStringFromClass([wn class]) : @"nil"];
        if (wn) { int b = 200; dmWalkNodes(wn, 0, s, &b, text, NULL); }
        rep = [s copy];
    });
    [_out appendString:clip(rep, 6000)];
    return rep ?: @"";
}

- (NSString *)fireNode:(NSString *)text {
    __block NSString *rep = nil;
    dmRunOnMain(^{
        NSMutableString *s = [NSMutableString string];
        UIView *v = dmFindByText(text);
        UIView *root = v;
        Class rvc = NSClassFromString(@"DXRootView");
        while (root && rvc && ![root isKindOfClass:rvc]) root = root.superview;
        id wn = nil;
        @try { wn = ((id (*)(id, SEL))objc_msgSend)(root, NSSelectorFromString(@"dx_getWidgetNode")); } @catch (id e) {}
        if (!wn) { rep = @"无根节点"; return; }
        id node = dmFindNode(wn, text);
        if (!node) { rep = [NSString stringWithFormat:@"控件树里没找到 %@", text]; return; }
        NSArray *ev = nil;
        @try { ev = [node valueForKey:@"eventList"]; } @catch (id e) {}
        [s appendFormat:@"node=%@ ev=%lu\n", NSStringFromClass([node class]), (unsigned long)ev.count];
        if (ev.count) [s appendFormat:@"  ev[0]=%@\n", clip([NSString stringWithFormat:@"%@", ev.firstObject], 400)];
        id event = ev.count ? ev.firstObject : nil;
        NSArray *sels = @[@"dispatchEvent:withArgs:", @"dispatchEvent:", @"handleEvent:withArgs:", @"triggerEvent:withArgs:"];
        BOOL done = NO;
        for (NSString *sn in sels) {
            SEL sel = NSSelectorFromString(sn);
            if (![node respondsToSelector:sel]) continue;
            @try {
                if ([sn hasSuffix:@"withArgs:"]) ((void (*)(id, SEL, id, id))objc_msgSend)(node, sel, event, @{});
                else ((void (*)(id, SEL, id))objc_msgSend)(node, sel, event);
                [s appendFormat:@"★ %@ 调用完成\n", sn];
                done = YES;
                break;
            } @catch (id e) { [s appendFormat:@"%@ EXC %@\n", sn, e]; }
        }
        if (!done) {
            // 兜底：把节点当作可响应点击的控件，尝试 respondToTapEvent 系列
            for (NSString *sn in @[@"respondToTapEvent", @"onClick", @"performClick"]) {
                SEL sel = NSSelectorFromString(sn);
                if ([node respondsToSelector:sel]) {
                    @try { ((void (*)(id, SEL))objc_msgSend)(node, sel); [s appendFormat:@"★ %@ 调用完成\n", sn]; done = YES; break; }
                    @catch (id e) {}
                }
            }
        }
        if (!done) [s appendString:@"节点上没有可调用的事件方法\n"];
        rep = [s copy];
    });
    [_out appendString:rep ?: @""];
    return rep ?: @"";
}

- (NSString *)eventMap:(NSString *)text {
    __block NSString *rep = nil;
    dmRunOnMain(^{
        NSMutableString *s = [NSMutableString string];
        UIView *v = dmFindByText(text);
        if (!v) { rep = @"未找到"; return; }
        Class rvc = NSClassFromString(@"DXRootView");
        int depth = 0;
        for (UIView *cur = v; cur && depth < 8; cur = cur.superview, depth++) {
            [s appendFormat:@"[%d] %@\n", depth, NSStringFromClass([cur class])];
            @try {
                if ([cur respondsToSelector:NSSelectorFromString(@"dx_getWidgetNode")]) {
                    id node = ((id (*)(id, SEL))objc_msgSend)(cur, NSSelectorFromString(@"dx_getWidgetNode"));
                    if (node) [s appendFormat:@"    widgetNode=%@ <%p>\n", NSStringFromClass([node class]), node];
                }
            } @catch (id e) {}
            @try {
                if ([cur respondsToSelector:NSSelectorFromString(@"tbd_getEventMap")]) {
                    id map = ((id (*)(id, SEL))objc_msgSend)(cur, NSSelectorFromString(@"tbd_getEventMap"));
                    if (map) [s appendFormat:@"    eventMap=%@\n", clip([NSString stringWithFormat:@"%@", map], 800)];
                }
            } @catch (id e) {}
            @try {
                if ([cur respondsToSelector:NSSelectorFromString(@"gaiaEvent")]) {
                    id ge = ((id (*)(id, SEL))objc_msgSend)(cur, NSSelectorFromString(@"gaiaEvent"));
                    if (ge) [s appendFormat:@"    gaiaEvent=%@\n", clip([NSString stringWithFormat:@"%@", ge], 300)];
                }
            } @catch (id e) {}
            if (rvc && [cur isKindOfClass:rvc]) break;
        }
        rep = [s copy];
    });
    [_out appendString:rep ?: @""];
    return rep ?: @"";
}

- (NSString *)triggerEvent:(NSString *)text name:(NSString *)name {
    __block NSString *rep = nil;
    dmRunOnMain(^{
        NSMutableString *s = [NSMutableString string];
        UIView *v = dmFindByText(text);
        if (!v) { rep = @"未找到"; return; }
        Class rvc = NSClassFromString(@"DXRootView");
        int depth = 0;
        for (UIView *cur = v; cur && depth < 8; cur = cur.superview, depth++) {
            SEL sel = NSSelectorFromString(@"tbd_triggerEvent:args:");
            if ([cur respondsToSelector:sel]) {
                @try {
                    ((void (*)(id, SEL, id, id))objc_msgSend)(cur, sel, name, @{});
                    [s appendFormat:@"[%d] %@ tbd_triggerEvent:%@ 已调用\n", depth, NSStringFromClass([cur class]), name];
                } @catch (id e) { [s appendFormat:@"[%d] EXC %@\n", depth, e]; }
            }
            if (rvc && [cur isKindOfClass:rvc]) break;
        }
        if (!s.length) [s appendString:@"没有任何层响应 tbd_triggerEvent:args:/n"];
        rep = [s copy];
    });
    [_out appendString:rep ?: @""];
    return rep ?: @"";
}

- (NSString *)gaiaTap:(NSString *)text {
    __block NSString *rep = nil;
    dmRunOnMain(^{
        NSMutableString *s = [NSMutableString string];
        UIView *v = dmFindByText(text);
        if (!v) { rep = @"未找到"; return; }
        SEL gsel = NSSelectorFromString(@"gaiaEvent");
        SEL esel = NSSelectorFromString(@"emit:event:");
        for (UIView *cur = v; cur && [cur isKindOfClass:[UIView class]]; cur = cur.superview) {
            if ([cur respondsToSelector:gsel]) {
                id ge = nil;
                @try { ge = ((id (*)(id, SEL))objc_msgSend)(cur, gsel); } @catch (id e) {}
                if (ge) {
                    [s appendFormat:@"%@ gaiaEvent=%@\n", NSStringFromClass([cur class]), clip([NSString stringWithFormat:@"%@", ge], 200)];
                    // 尝试用 emit:event: 触发
                    SEL peer = NSSelectorFromString(@"emit:event:");
                    if ([cur respondsToSelector:peer]) {
                        @try { ((void (*)(id, SEL, id, id))objc_msgSend)(cur, peer, @"tap", ge); [s appendString:@"emit 调用完成\n"]; }
                        @catch (id e) { [s appendFormat:@"emit EXC %@\n", e]; }
                    }
                    break;
                }
            }
        }
        (void)esel;
        if (!s.length) [s appendString:@"未发现 gaiaEvent\n"];
        rep = [s copy];
    });
    [_out appendString:rep ?: @""];
    return rep ?: @"";
}

- (NSString *)tapText:(NSString *)text { return dmTapByText(text); }
- (NSString *)replay:(NSString *)buyParam {
    // 复用最近一次 create 对象
    if (!gLastReqObj) return @"无对象";
    if (buyParam.length) {
        @try { [gLastReqObj setValue:buyParam forKey:@"buyParam"]; } @catch (id e) {}
    }
    id mr = nil; @try { mr = [gLastReqObj valueForKey:@"mrequest"]; } @catch (id e) {}
    dmForceSign(mr);
    id inst = mtopInstance(nil);
    id resp = nil;
    @try { resp = ((id (*)(id, SEL, id))objc_msgSend)(inst, @selector(sync_call:), gLastReqObj); } @catch (id e) { return @"EXC"; }
    NSString *s = [NSString stringWithFormat:@"%@", resp];
    [_out appendFormat:@"[replay] %@\n", clip(s, 1500)];
    return s;
}
@end

static NSString *dmRunJS(NSString *code) {
    JSContext *ctx = [[JSContext alloc] init];
    DMBridge *br = [DMBridge new];
    ctx[@"dm"] = br;
    ctx[@"console"] = @{@"log": ^(NSString *s) { [br logjs:s]; }};
    ctx.exceptionHandler = ^(JSContext *c, JSValue *e) {
        [br.out appendFormat:@"[JS-EXC] %@\n", e];
    };
    JSValue *v = [ctx evaluateScript:code];
    NSString *res = v ? [v toString] : @"(nil)";
    return [NSString stringWithFormat:@"%@\n[return] %@\n", br.out ?: @"", clip(res, 500)];
}


// 遍历 DinamicX 控件树
static void dmWalkNodes(id node, int depth, NSMutableString *s, int *budget, NSString *needle, id *found) {
    if (!node || *budget <= 0 || depth > 40) return;
    if (![node isKindOfClass:[NSObject class]]) return;
    @try {
        NSString *cls = NSStringFromClass([node class]);
        CGRect f = CGRectZero;
        @try { id fv = [node valueForKey:@"frame"]; if ([fv isKindOfClass:[NSValue class]]) f = [fv CGRectValue]; } @catch (id e) {}
        NSArray *ev = nil;
        @try { id e2 = [node valueForKey:@"eventList"]; if ([e2 isKindOfClass:[NSArray class]]) ev = e2; } @catch (id e) {}
        NSString *txt = nil;
        @try { id t = [node valueForKey:@"text"]; if ([t isKindOfClass:[NSString class]]) txt = t; } @catch (id e) {}
        if (txt.length && needle.length && [txt rangeOfString:needle].location != NSNotFound && found && !*found) *found = node;
        if (ev.count || txt.length) {
            [s appendFormat:@"%*s%@ (%.0f,%.0f) ev=%lu txt=%@\n", depth * 2, "", cls, f.origin.x, f.origin.y,
             (unsigned long)ev.count, clip(txt, 24)];
            (*budget)--;
        }
        NSArray *kids = nil;
        @try { id k = [node valueForKey:@"subWidgets"]; if ([k isKindOfClass:[NSArray class]]) kids = k; } @catch (id e) {}
        if (!kids) @try { id k = [node valueForKey:@"children"]; if ([k isKindOfClass:[NSArray class]]) kids = k; } @catch (id e) {}
        for (id k in kids) {
            if ([k isKindOfClass:[NSObject class]]) dmWalkNodes(k, depth + 1, s, budget, needle, found);
        }
    } @catch (id e) {
        [s appendFormat:@"<walk EXC %@ at depth %d>\n", e, depth];
    }
}

static id dmFindNode(id node, NSString *needle) {
    id found = nil;
    NSMutableString *tmp = [NSMutableString string];
    int b = 4000;
    dmWalkNodes(node, 0, tmp, &b, needle, &found);
    return found;
}


// ---------------- 通用 ObjC 运行时桥（句柄 + 任意调用），JS 可做一切 ----------------
static NSMutableDictionary *gHandles = nil;
static int gHandleSeq = 0;
static NSString *dmReg(id o) {
    if (!o) return @"";
    if (!gHandles) gHandles = [NSMutableDictionary new];
    NSString *k = [NSString stringWithFormat:@"h%d", ++gHandleSeq];
    gHandles[k] = o;
    return k;
}
static id dmGetHandle(NSString *k) {
    if (![k isKindOfClass:[NSString class]] || !k.length) return nil;
    return gHandles[k];
}

@protocol DMRuntimeExport <JSExport>
- (NSString *)findText:(NSString *)text;
- (NSString *)sup:(NSString *)h;
- (NSString *)desc:(NSString *)h;
- (NSString *)kvc:(NSString *)h key:(NSString *)key;
- (NSString *)clsName:(NSString *)h;
- (NSString *)call:(NSString *)h sel:(NSString *)selName args:(NSString *)argsJson;
- (NSString *)walk:(NSString *)h needle:(NSString *)needle;
- (NSString *)clsInfo:(NSString *)name;
- (NSString *)newObj:(NSString *)clsName;
@end

@interface DMRuntime : NSObject <DMRuntimeExport>
@property (nonatomic, strong) NSMutableString *out;
- (NSString *)reg:(JSValue *)v;
- (NSString *)findText:(NSString *)text;
- (NSString *)sup:(NSString *)h;
- (NSString *)desc:(NSString *)h;
- (NSString *)kvc:(NSString *)h key:(NSString *)key;
- (NSString *)clsName:(NSString *)h;
- (NSString *)call:(NSString *)h sel:(NSString *)selName args:(NSString *)argsJson;
- (NSString *)walk:(NSString *)h needle:(NSString *)needle;
- (NSString *)clsInfo:(NSString *)name;
- (NSString *)newObj:(NSString *)clsName;
@end

@implementation DMRuntime
- (instancetype)init { if ((self = [super init])) { _out = [NSMutableString new]; } return self; }
- (NSString *)reg:(JSValue *)v { id o = [v toObject]; return dmReg(o); }
- (NSString *)findText:(NSString *)text {
    __block NSString *h = @"";
    dmRunOnMain(^{ UIView *v = dmFindByText(text); if (v) h = dmReg(v); });
    return h;
}
- (NSString *)sup:(NSString *)h { UIView *v = dmGetHandle(h); return v.superview ? dmReg(v.superview) : @""; }
- (NSString *)desc:(NSString *)h { id o = dmGetHandle(h); return o ? [NSString stringWithFormat:@"%@", o] : @"(nil)"; }
- (NSString *)clsName:(NSString *)h { id o = dmGetHandle(h); return o ? NSStringFromClass([o class]) : @"(nil)"; }
- (NSString *)kvc:(NSString *)h key:(NSString *)key {
    id o = dmGetHandle(h);
    if (!o) return @"(nil-handle)";
    @try { id v = [o valueForKey:key]; return v ? [NSString stringWithFormat:@"%@", v] : @"(nil)"; }
    @catch (id e) { return @"(KVC-EXC)"; }
}
- (NSString *)call:(NSString *)h sel:(NSString *)selName args:(NSString *)argsJson {
    id o = dmGetHandle(h);
    if (!o) return @"(nil-handle)";
    SEL sel = NSSelectorFromString(selName);
    if (!sel || ![o respondsToSelector:sel]) return [NSString stringWithFormat:@"(no-sel %@)", selName];
    NSArray *raw = @[];
    if (argsJson.length) {
        id j = [NSJSONSerialization JSONObjectWithData:[argsJson dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
        if ([j isKindOfClass:[NSArray class]]) raw = j;
    }
    NSMethodSignature *sig = [o methodSignatureForSelector:sel];
    NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
    inv.target = o; inv.selector = sel;
    NSUInteger want = sig.numberOfArguments - 2;
    for (NSUInteger i = 0; i < want && i < raw.count; i++) {
        id a = raw[i];
        if ([a isKindOfClass:[NSDictionary class]] && a[@"h"]) a = dmGetHandle(a[@"h"]) ?: [NSNull null];
        if ([a isKindOfClass:[NSNull class]]) a = nil;
        void *ptr = (__bridge void *)a;
        [inv setArgument:&ptr atIndex:i + 2];
    }
    NSString *ret = @"(void)";
    @try {
        [inv invoke];
        const char *rt = sig.methodReturnType;
        if (rt[0] == '@') {
            __unsafe_unretained id rv = nil;
            [inv getReturnValue:&rv];
            ret = rv ? [NSString stringWithFormat:@"%@", rv] : @"(nil)";
            if ([rv isKindOfClass:[NSObject class]]) { NSString *hh = dmReg(rv); ret = [NSString stringWithFormat:@"%@ |handle=%@", ret, hh]; }
        } else if (rt[0] == 'v') ret = @"(void)";
        else if (rt[0] == 'B') { BOOL b = NO; [inv getReturnValue:&b]; ret = b ? @"YES" : @"NO"; }
        else if (rt[0] == 'q' || rt[0] == 'i' || rt[0] == 'Q') { long long n = 0; [inv getReturnValue:&n]; ret = [NSString stringWithFormat:@"%lld", n]; }
    } @catch (id e) { ret = [NSString stringWithFormat:@"(EXC %@)", e]; }
    [_out appendFormat:@"[call %@ %@] %@\n", [o class], selName, clip(ret, 400)];
    return ret;
}
- (NSString *)walk:(NSString *)h needle:(NSString *)needle {
    __block NSString *rep = nil;
    dmRunOnMain(^{
        id o = dmGetHandle(h);
        NSMutableString *s = [NSMutableString string];
        int b = 300;
        if ([o isKindOfClass:[UIView class]]) dmWalkViews((UIView *)o, 0, s, &b, needle);
        else dmWalkNodes(o, 0, s, &b, needle, NULL);
        int b2 = 300;
        (void)b2;
        rep = [s copy];
    });
    return rep ?: @"";
}
- (NSString *)clsInfo:(NSString *)name {
    Class c = NSClassFromString(name);
    if (!c) return @"(no-class)";
    NSMutableString *s = [NSMutableString string];
    for (Class k = c; k && k != [NSObject class]; k = class_getSuperclass(k)) {
        unsigned int mc = 0; Method *mm = class_copyMethodList(k, &mc);
        for (unsigned int i = 0; i < mc && i < 200; i++)
            [s appendFormat:@"%@ %@\n", NSStringFromClass(k), NSStringFromSelector(method_getName(mm[i]))];
        if (mm) free(mm);
    }
    return s;
}
- (NSString *)newObj:(NSString *)clsName {
    Class c = NSClassFromString(clsName);
    if (!c) return @"";
    id o = ((id (*)(id, SEL))objc_msgSend)(c, @selector(alloc));
    @try { o = ((id (*)(id, SEL))objc_msgSend)(o, @selector(init)); } @catch (id e) {}
    return dmReg(o);
}
@end

static NSString *dmRunJS2(NSString *code) {
    JSContext *ctx = [[JSContext alloc] init];
    DMBridge *br = [DMBridge new];
    DMRuntime *rt = [DMRuntime new];
    ctx[@"dm"] = br;
    ctx[@"rt"] = rt;
    ctx[@"console"] = @{@"log": ^(NSString *s) { [br logjs:s]; }};
    __block NSString *exc = nil;
    ctx.exceptionHandler = ^(JSContext *c, JSValue *e) { exc = [e toString]; };
    JSValue *v = [ctx evaluateScript:code];
    NSString *res = v ? [v toString] : @"(nil)";
    return [NSString stringWithFormat:@"%@%@%@\n[return] %@\n", br.out ?: @"", rt.out ?: @"", exc ? [@"[JS-EXC] " stringByAppendingString:exc] : @"", clip(res, 400)];
}


// ---------------- 签名方法全量 hook（找交易 linkage 的 md5）----------------
typedef struct { Class cls; SEL sel; IMP orig; } SignHook;
static SignHook gSignHooks[64];
static int gSignHookCount = 0;

static void dmLogSignCall(SignHook *h, id a1, id a2, id ret) {
    M(@"==== SIGN %@ -%@ ====", NSStringFromClass(h->cls), NSStringFromSelector(h->sel));
    M(@"  a1=%@", clip([NSString stringWithFormat:@"%@", a1], 1200));
    if (a2) M(@"  a2=%@", clip([NSString stringWithFormat:@"%@", a2], 300));
    if (ret) M(@"  ret=%@", clip([NSString stringWithFormat:@"%@", ret], 400));
}

// 两参版本（id,id -> id）
static id dmSign2_0(id self, SEL _cmd, id a1, id a2);
static id dmSign2(id self, SEL _cmd, id a1, id a2) {
    Class cls = object_getClass(self);
    IMP orig = NULL;
    for (int i = 0; i < gSignHookCount; i++) {
        if (gSignHooks[i].cls == cls && sel_isEqual(gSignHooks[i].sel, _cmd)) { orig = gSignHooks[i].orig; break; }
    }
    id ret = orig ? ((id (*)(id, SEL, id, id))orig)(self, _cmd, a1, a2) : nil;
    SignHook h = { cls, _cmd, orig };
    dmLogSignCall(&h, a1, a2, ret);
    return ret;
}

// 一参版本（id -> id）
static id dmSign1(id self, SEL _cmd, id a1) {
    Class cls = object_getClass(self);
    IMP orig = NULL;
    for (int i = 0; i < gSignHookCount; i++) {
        if (gSignHooks[i].cls == cls && sel_isEqual(gSignHooks[i].sel, _cmd)) { orig = gSignHooks[i].orig; break; }
    }
    id ret = orig ? ((id (*)(id, SEL, id))orig)(self, _cmd, a1) : nil;
    SignHook h = { cls, _cmd, orig };
    dmLogSignCall(&h, a1, nil, ret);
    return ret;
}

static void hookSignMethods(void) {
    NSArray *targets = @[@"generateMD5Sign:withSecret:", @"generateSignWithKey:content:",
                         @"generateMD5ByString:", @"generateMd5String:", @"generateSignStringWithParameters:",
                         @"generateSignWithKey:timestamp:havanaId:needSdkVersion:"];
    int n = objc_getClassList(NULL, 0);
    if (n <= 0) return;
    Class *classes = (__unsafe_unretained Class *)malloc(sizeof(Class) * n);
    n = objc_getClassList(classes, n);
    int hooked = 0;
    for (int i = 0; i < n; i++) {
        Class c = classes[i];
        unsigned int mc = 0;
        Method *ms = class_copyMethodList(c, &mc);
        for (unsigned j = 0; j < mc; j++) {
            NSString *sn = NSStringFromSelector(method_getName(ms[j]));
            if (![targets containsObject:sn]) continue;
            unsigned want = (unsigned)[[sn componentsSeparatedByString:@":"] count] - 1;
            if (want > 2) continue;
            if (gSignHookCount >= 60) break;
            IMP old = method_getImplementation(ms[j]);
            gSignHooks[gSignHookCount++] = (SignHook){ c, method_getName(ms[j]), old };
            method_setImplementation(ms[j], (IMP)(want == 1 ? dmSign1 : dmSign2));
            W(@"hook SIGN %@ -%@", NSStringFromClass(c), sn);
            hooked++;
        }
        if (ms) free(ms);
    }
    free(classes);
    W(@"签名方法 hook 数=%d", hooked);
}



// ---------------- 自带 MD5 实现（避免 interpose 递归）----------------
typedef struct { uint32_t state[4]; uint32_t count[2]; unsigned char buffer[64]; } dm_md5_ctx;

static const uint32_t dm_md5_k[64] = {
0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};
static const int dm_md5_s[64] = {
7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};

static void dm_md5_init(dm_md5_ctx *c) {
    c->state[0]=0x67452301; c->state[1]=0xefcdab89; c->state[2]=0x98badcfe; c->state[3]=0x10325476;
    c->count[0]=c->count[1]=0;
}
static void dm_md5_transform(uint32_t st[4], const unsigned char block[64]) {
    uint32_t a=st[0], b=st[1], c=st[2], d=st[3], m[16], x, t;
    for (int i=0;i<16;i++) m[i]= (uint32_t)block[i*4] | ((uint32_t)block[i*4+1]<<8) | ((uint32_t)block[i*4+2]<<16) | ((uint32_t)block[i*4+3]<<24);
    for (int i=0;i<64;i++) {
        int r;
        if (i<16) { x = (b & c) | (~b & d); r = i; }
        else if (i<32) { x = (d & b) | (~d & c); r = (5*i+1) % 16; }
        else if (i<48) { x = b ^ c ^ d; r = (3*i+5) % 16; }
        else { x = c ^ (b | ~d); r = (7*i) % 16; }
        t = d; d = c; c = b;
        uint32_t v = a + x + dm_md5_k[i] + m[r];
        b = b + ((v << dm_md5_s[i]) | (v >> (32 - dm_md5_s[i])));
        a = t;
    }
    st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d;
}
static void dm_md5_update(dm_md5_ctx *c, const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    size_t idx = (c->count[0] >> 3) & 0x3F;
    if ((c->count[0] += (uint32_t)(len << 3)) < (len << 3)) c->count[1]++;
    c->count[1] += (uint32_t)(len >> 29);
    size_t part = 64 - idx;
    size_t i = 0;
    if (len >= part) {
        memcpy(&c->buffer[idx], p, part);
        dm_md5_transform(c->state, c->buffer);
        for (i = part; i + 63 < len; i += 64) dm_md5_transform(c->state, &p[i]);
        idx = 0;
    }
    memcpy(&c->buffer[idx], &p[i], len - i);
}
static void dm_md5_final(unsigned char digest[16], dm_md5_ctx *c) {
    unsigned char bits[8];
    for (int i=0;i<4;i++) { bits[i]=(unsigned char)(c->count[0]>>(8*i)); bits[i+4]=(unsigned char)(c->count[1]>>(8*i)); }
    size_t idx = (c->count[0] >> 3) & 0x3F;
    unsigned char pad[64] = {0x80};
    size_t padlen = (idx < 56) ? (56 - idx) : (120 - idx);
    dm_md5_update(c, pad, padlen);
    dm_md5_update(c, bits, 8);
    for (int i=0;i<4;i++) { digest[i*4]=(unsigned char)(c->state[i]); digest[i*4+1]=(unsigned char)(c->state[i]>>8);
                            digest[i*4+2]=(unsigned char)(c->state[i]>>16); digest[i*4+3]=(unsigned char)(c->state[i]>>24); }
}

// ---------------- CC_MD5 hook（自带实现，不调原函数）----------------
static NSString *dmHexStr(const unsigned char *b, int n) {
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < n; i++) [s appendFormat:@"%02x", b[i]];
    return s;
}
static NSString *dmPreview(const void *d, CC_LONG n) {
    if (!d || !n) return @"";
    NSData *dt = [NSData dataWithBytes:d length:MIN(n, 400)];
    return clip(bytesPreview(dt, 400), 400);
}

// 结果字典：改完签名后，把最近的 md5 调用存下来便于比对
static NSMutableArray *gMd5Log = nil;   // 元素: @{in, out, len}
static volatile int gCryptoReady = 0;
static NSLock *gMd5Lock = nil;

static void dmRecordMd5(const void *data, CC_LONG len, const unsigned char *digest, NSString *tag) {
    if (!gMd5Lock) { gMd5Lock = [NSLock new]; gMd5Log = [NSMutableArray new]; }
    [gMd5Lock lock];
    @try {
        M(@"MD5[%@] len=%u in=%@", tag ?: @"-", len, dmPreview(data, len));
        M(@"     out=%@", dmHexStr(digest, 16));
        if (gMd5Log.count > 200) [gMd5Log removeObjectAtIndex:0];
        [gMd5Log addObject:@{@"len": @(len), @"out": dmHexStr(digest, 16),
                             @"in": dmPreview(data, len)}];
    } @catch (id e) {}
    [gMd5Lock unlock];
}

// 流式上下文 → 累积数据
static NSMutableDictionary *gCtxMap = nil;

static unsigned char *dm_CC_MD5(const void *data, CC_LONG len, unsigned char *md) {
    if (!md) return md;
    dm_md5_ctx c; dm_md5_init(&c);
    if (data && len) dm_md5_update(&c, data, (size_t)len);
    dm_md5_final(md, &c);
    if (len >= 24 && gCryptoReady) { @try { dmRecordMd5(data, len, md, @"oneshot"); } @catch (id e) {} }
    return md;
}
static int dm_CC_MD5_Init(CC_MD5_CTX *c) {
    if (!c) return 0;
    dm_md5_ctx *x = (dm_md5_ctx *)c;
    dm_md5_init(x);
    if (gCryptoReady) { @try { if (!gCtxMap) gCtxMap = [NSMutableDictionary new]; gCtxMap[@((uintptr_t)c)] = [NSMutableData new]; } @catch (id e) {} }
    return 1;
}
static int dm_CC_MD5_Update(CC_MD5_CTX *c, const void *data, CC_LONG len) {
    if (!c) return 0;
    dm_md5_ctx *x = (dm_md5_ctx *)c;
    if (data && len) dm_md5_update(x, data, (size_t)len);
    if (gCryptoReady && data && len) {
        @try { NSMutableData *acc = gCtxMap[@((uintptr_t)c)];
               if (acc) [acc appendBytes:data length:len]; } @catch (id e) {}
    }
    return 1;
}
static int dm_CC_MD5_Final(unsigned char *md, CC_MD5_CTX *c) {
    if (!md || !c) return 0;
    dm_md5_ctx *x = (dm_md5_ctx *)c;
    dm_md5_final(md, x);
    if (gCryptoReady) {
        @try { NSData *acc = gCtxMap[@((uintptr_t)c)];
               if (acc.length >= 24) dmRecordMd5(acc.bytes, (CC_LONG)acc.length, md, @"stream");
               if (acc) [gCtxMap removeObjectForKey:@((uintptr_t)c)]; } @catch (id e) {}
    }
    return 1;
}

// 装载 interpose 表
__attribute__((used)) static struct { const void *replacement; const void *replacee; }
g_interposers[] __attribute__((section("__DATA, __interpose"))) = {
    { (const void *)dm_CC_MD5,        (const void *)CC_MD5 },
    { (const void *)dm_CC_MD5_Init,   (const void *)CC_MD5_Init },
    { (const void *)dm_CC_MD5_Update, (const void *)CC_MD5_Update },
    { (const void *)dm_CC_MD5_Final,  (const void *)CC_MD5_Final },
};

static void dmInitCryptoHooks(void) { W(@"MD5 自带实现，无需 dlsym"); }


// ---------------- TCP 中继：0.0.0.0:27043 -> 127.0.0.1:27042（Frida gadget）----------------
static void dmRelayConn(int cs) {
    int us = socket(AF_INET, SOCK_STREAM, 0);
    if (us < 0) { close(cs); return; }
    struct sockaddr_in u; memset(&u, 0, sizeof(u));
    u.sin_family = AF_INET; u.sin_port = htons(27042); u.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (connect(us, (struct sockaddr *)&u, sizeof(u)) < 0) { close(cs); close(us); return; }
    char buf[8192];
    struct pollfd fds[2];
    fds[0].fd = cs; fds[0].events = POLLIN; fds[0].revents = 0;
    fds[1].fd = us; fds[1].events = POLLIN; fds[1].revents = 0;
    for (;;) {
        int r = poll(fds, 2, 60000);
        if (r <= 0) break;
        int dead = 0;
        for (int i = 0; i < 2; i++) {
            if (fds[i].revents & (POLLIN | POLLHUP | POLLERR)) {
                ssize_t n = read(fds[i].fd, buf, sizeof(buf));
                if (n <= 0) { dead = 1; break; }
                ssize_t off = 0;
                while (off < n) {
                    ssize_t w = write(fds[1 - i].fd, buf + off, n - off);
                    if (w <= 0) { dead = 1; break; }
                    off += w;
                }
                if (dead) break;
            }
        }
        if (dead) break;
    }
    close(cs); close(us);
}

static void dmStartRelay(void) {
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        int ls = socket(AF_INET, SOCK_STREAM, 0);
        if (ls < 0) return;
        int yes = 1;
        setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        struct sockaddr_in a; memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET; a.sin_port = htons(27043); a.sin_addr.s_addr = INADDR_ANY;
        if (bind(ls, (struct sockaddr *)&a, sizeof(a)) < 0) { W(@"relay bind 27043 失败 errno=%d", errno); close(ls); return; }
        listen(ls, 8);
        W(@"relay 就绪: 0.0.0.0:27043 → 127.0.0.1:27042");
        for (;;) {
            int cs = accept(ls, NULL, NULL);
            if (cs < 0) { usleep(100000); continue; }
            dispatch_async(dispatch_get_global_queue(0, 0), ^{ dmRelayConn(cs); });
        }
    });
}


// ---------------- 替换壳内 MD5 transform（0x104d05b64）----------------
static void dm_md5_transform(uint32_t st[4], const unsigned char block[64]);
static void dm_md5_transform_hook(void *state, const void *data, size_t blocks);

static NSString *gPatchReport = nil;

static void dmPatchShellMd5(void) {
    const struct mach_header *hdr = _dyld_get_image_header(0);
    intptr_t slide = _dyld_get_image_vmaddr_slide(0);
    uintptr_t target = (uintptr_t)hdr + 0x4d05b64;   // vmaddr 0x104d05b64 - image base 0x100000000
    (void)slide;
    size_t ps = 16384;
    uintptr_t page = target & ~(ps - 1);
    kern_return_t kr = vm_protect(mach_task_self(), page, ps, false,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        gPatchReport = [NSString stringWithFormat:@"vm_protect 失败 kr=%d", kr];
        W(@"patch shell md5: %@", gPatchReport);
        return;
    }
    uint32_t *p32 = (uint32_t *)target;
    uint32_t old0 = p32[0], old1 = p32[1];
    uint32_t ldr = 0x58000049;   // ldr x9, #8
    uint32_t br  = 0xD61F0120;   // br x9
    uint64_t fn  = (uint64_t)(uintptr_t)dm_md5_transform_hook;
    memcpy((void *)target, &ldr, 4);
    memcpy((void *)(target + 4), &br, 4);
    memcpy((void *)(target + 8), &fn, 8);
    sys_icache_invalidate((void *)target, 16);
    vm_protect(mach_task_self(), page, ps, false, VM_PROT_READ | VM_PROT_EXECUTE);
    gPatchReport = [NSString stringWithFormat:@"ok (原指令 %08x %08x → %p)", old0, old1, (void *)target];
    W(@"patch shell md5: %@", gPatchReport);
}

static void dm_md5_transform_hook(void *state, const void *data, size_t blocks) {
    @try {
        if (data && blocks > 0 && blocks <= 8192) {
            size_t len = blocks * 64;
            const unsigned char *b = (const unsigned char *)data;
            // 标记检测
            BOOL hit = NO;
            size_t scan = len < 8192 ? len : 8192;
            for (size_t i = 0; i + 8 < scan; i++) {
                if (b[i] == 'a' && !memcmp(b + i, "ali.china", 9)) { hit = YES; break; }
                if (b[i] == 'H' && !memcmp(b + i, "HALO", 4)) { hit = YES; break; }
                if (b[i] == 'o' && !memcmp(b + i, "orderLine", 9)) { hit = YES; break; }
                if (b[i] == 's' && !memcmp(b + i, "submitParam", 11)) { hit = YES; break; }
            }
            if (hit) {
                M(@"==== MD5-TRANSFORM blocks=%lu len=%lu ====", (unsigned long)blocks, (unsigned long)len);
                M(@"  head=%@", clip(bytesPreview([NSData dataWithBytes:b length:MIN(len, 300)], 300), 300));
                // 完整落盘（追加）
                NSMutableData *out = [NSMutableData data];
                uint32_t l = (uint32_t)len;
                [out appendBytes:&l length:4];
                [out appendBytes:b length:len];
                NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:dpath(@"dm_cap.bin")];
                if (!fh) { [[NSData data] writeToFile:dpath(@"dm_cap.bin") atomically:NO]; fh = [NSFileHandle fileHandleForWritingAtPath:dpath(@"dm_cap.bin")]; }
                [fh seekToEndOfFile]; [fh writeData:out]; [fh closeFile];
            }
        }
    } @catch (id e) {}
    if (!state || !data) return;
    uint32_t *st = (uint32_t *)state;
    const unsigned char *p = (const unsigned char *)data;
    for (size_t i = 0; i < blocks; i++) dm_md5_transform(st, p + i * 64);
}



static uintptr_t dmMainImageBase(void);

static NSString *dmImageDiag(void) {
    NSMutableString *s = [NSMutableString string];
    uint32_t count = _dyld_image_count();
    [s appendFormat:@"images=%u\n", count];
    for (uint32_t i = 0; i < count; i++) {
        const char *nm = _dyld_get_image_name(i);
        const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
        NSString *n = nm ? [NSString stringWithUTF8String:nm] : @"?";
        if ([n containsString:@"DMPortal"] || [n containsString:@"DamaiSpy"] || [n containsString:@"Privacy"] || i == 0) {
            [s appendFormat:@"  [%u] %@ base=%p type=%d slide=%ld\n", i, [n lastPathComponent], h, h ? h->filetype : -1,
             (long)_dyld_get_image_vmaddr_slide(i)];
        }
    }
    uintptr_t base = dmMainImageBase();
    uintptr_t target = base + 0x4d05b64;
    [s appendFormat:@"base=%p target=%p\n", (void *)base, (void *)target];
    // 查目标页权限
    vm_address_t addr = (vm_address_t)(target & ~0x3FFF);
    vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    kern_return_t kr = vm_region_64(mach_task_self(), &addr, &size, VM_REGION_BASIC_INFO_64,
                                    (vm_region_info_t)&info, &cnt, &obj);
    if (kr == KERN_SUCCESS) {
        [s appendFormat:@"region=0x%llx size=0x%llx prot=%d(max=%d) shared=%d\n",
         (unsigned long long)addr, (unsigned long long)size, info.protection, info.max_protection, info.shared];
    } else {
        [s appendFormat:@"vm_region kr=%d\n", kr];
    }
    // 尝试读目标首 4 字节
    if (target) {
        @try {
            uint32_t w = *(volatile uint32_t *)target;
            [s appendFormat:@"first_insn=%08x\n", w];
        } @catch (id e) { [s appendString:@"读指令 EXC\n"]; }
    }
    return s;
}

// ---------------- 壳内 MD5 预言机（调用而非改写）----------------
static uintptr_t dmMainImageBase(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "DMPortal")) {
            return (uintptr_t)_dyld_get_image_header(i);
        }
    }
    return 0;
}

static void dmShellMd5(const void *data, size_t len, unsigned char out[16]) {
    typedef void (*TFn)(uint32_t *, const void *, size_t);
    uintptr_t base = dmMainImageBase();
    uintptr_t addr = base + 0x4d05b64;
    TFn tf = (TFn)addr;
    uint32_t st[4] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u};
    size_t total = ((len + 8) / 64 + 1) * 64;
    unsigned char *buf = (unsigned char *)calloc(1, total);
    if (!buf) return;
    memcpy(buf, data, len);
    buf[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    memcpy(buf + total - 8, &bits, 8);
    tf(st, buf, total / 64);
    free(buf);
    for (int i = 0; i < 4; i++) {
        out[i*4+0]=(unsigned char)(st[i]); out[i*4+1]=(unsigned char)(st[i]>>8);
        out[i*4+2]=(unsigned char)(st[i]>>16); out[i*4+3]=(unsigned char)(st[i]>>24);
    }
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
                if (attached) dmForceSign(tbr); else W(@"attach mrequest EXC（无 setter）");
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
                    dmForceSign(mr);
                    W(@"mutate buyParam=%@ done=%d", bp, (int)done);
                }
            }
            id mr0 = nil;
            @try { mr0 = [gLastReqObj valueForKey:@"mrequest"]; } @catch (id e) {}
            dmForceSign(mr0);
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
    } else if ([c isEqualToString:@"js"]) {
        NSString *code = cmd[@"code"];
        if (![code isKindOfClass:[NSString class]] || !code.length) {
            code = [NSString stringWithContentsOfFile:dpath(@"dm_script.js") encoding:NSUTF8StringEncoding error:nil];
        }
        if (!code.length) { writeOut(@"没有 js 代码（写 Documents/dm_script.js 或传 code 参数）"); return; }
        writeOut(dmRunJS2(code));
    } else if ([c isEqualToString:@"dxfire"]) {
        writeOut(dmDXFire(cmd[@"txt"] ?: @"立即提交"));
    } else if ([c isEqualToString:@"imgdiag"]) {
        writeOut(dmImageDiag());
    } else if ([c isEqualToString:@"md5oracle"]) {
        NSString *txt = cmd[@"text"] ?: @"abc";
        NSData *in = [txt dataUsingEncoding:NSUTF8StringEncoding];
        unsigned char shell[16] = {0}, mine[16] = {0};
        dmShellMd5(in.bytes, in.length, shell);
        dm_md5_ctx mc; dm_md5_init(&mc);
        dm_md5_update(&mc, in.bytes, in.length);
        dm_md5_final(mine, &mc);
        NSMutableString *imgs = [NSMutableString string];
        for (uint32_t i = 0; i < _dyld_image_count(); i++) {
            const char *nm = _dyld_get_image_name(i);
            if (nm && (strstr(nm, "DMPortal") || strstr(nm, "DamaiSpy") || strstr(nm, "Privacy")))
                [imgs appendFormat:@"  img%d %s base=%p\n", i, nm, _dyld_get_image_header(i)];
        }
        uintptr_t mb = dmMainImageBase();
        writeOut([NSString stringWithFormat:@"%@base=%p target=%p\ninput=%@ len=%lu\nshell=%@\nstd =%@\n一致=%@",
                  imgs, (void *)mb, (void *)(mb + 0x4d05b64),
                  clip(txt, 60), (unsigned long)in.length, dmHexStr(shell, 16), dmHexStr(mine, 16),
                  [dmHexStr(shell,16) isEqualToString:dmHexStr(mine,16)] ? @"YES" : @"NO"]);
    } else if ([c isEqualToString:@"dxgest"]) {
        writeOut(dmDXGest(cmd[@"txt"] ?: @"立即提交", [cmd[@"fire"] boolValue]));
    } else if ([c isEqualToString:@"h5confirm"] || [c isEqualToString:@"h5buy"]) {
        NSString *bp = cmd[@"buyParam"] ?: @"1091503581127_1_6311209779027";
        NSString *viewer = [cmd[@"viewer"] isKindOfClass:[NSString class]] ? cmd[@"viewer"] : @"";
        BOOL submit = [c isEqualToString:@"h5buy"] && exists(@"dm_allow_create");
        if ([c isEqualToString:@"h5buy"] && !exists(@"dm_allow_create")) { writeOut(@"拒绝：没有 dm_allow_create"); return; }
        writeOut(dmH5Buy(bp, viewer, submit));
    } else if ([c isEqualToString:@"h5call"]) {
        NSString *api = cmd[@"api"] ?: @"mtop.damai.item.detail.getdetail";
        NSString *ver = [cmd[@"v"] isKindOfClass:[NSString class]] ? cmd[@"v"] : @"1.0";
        NSString *dataJson = nil;
        if ([cmd[@"data"] isKindOfClass:[NSDictionary class]]) {
            NSData *jd = [NSJSONSerialization dataWithJSONObject:cmd[@"data"] options:NSJSONWritingWithoutEscapingSlashes error:nil];
            dataJson = jd ? [[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding] : @"{}";
        } else dataJson = cmd[@"data"] ?: @"{}";
        writeOut(dmH5Call(api, ver, dataJson));
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
    @try { hookSignMethods(); } @catch (id e) { W(@"hookSign EXC %@", e); }
    @try { hookMtop(); } @catch (id e) { W(@"hookMtop EXC %@", e); }
    @try { bootMtopInfo(); } @catch (id e) { M(@"bootMtopInfo EXC %@", e); }
    flushAll();
    W(@"setupOnce done hooks=%d", gHookCount);
    gCryptoReady = 1;
    {
        unsigned char t[16]; dm_md5_ctx c; dm_md5_init(&c);
        dm_md5_update(&c, "abc", 3); dm_md5_final(t, &c);
        @try { dmPatchShellMd5(); } @catch (id e) { W(@"patch EXC %@", e); }
    W(@"crypto ready selftest md5(abc)=%@ (应为 900150983cd24fb0d6963f7d28e17f72)", dmHexStr(t, 16));
    }
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
