//
//  PikeSpy.m — 只读旁听 MSI Pike 桥消息（抓金猪敲门报文）
//
//  用途：美团币「敲金猪」走 MRN bundle 调 MSI Pike JSAPI。PC 端 HTTP 复刻
//        只进气泡池，真实入账通道是 Pike 加密长连接。本 dylib 在 App 进程内
//        旁听桥上消息，把 bizId / alias / content 原样落盘，供 PC 复刻。
//
//  形态约束（重要）：只做 ObjC method swizzle（改 runtime 方法表——可写内存，
//        不碰代码页），不装信号处理器、不做 inline hook —— 遵守轻量裸库约束。
//        只读不改：所有 hook 落盘后调用原实现，App 功能完全不变。
//
//  用法：
//    1) 注入到美团（TrollStore 解密版）
//    2) 启动 App → 进美团币页 → 手点一次「敲金猪」
//    3) Filza 拉数据容器 Documents/pikespy.log
//
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dispatch/dispatch.h>

#define SPY_TAG @"PIKESPY"

static NSMutableString *gBootLog = nil;
static NSFileHandle *gLogFile = nil;

// ---------- 落盘 ----------

static NSString *spyLogPath(void) {
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *dir = dirs.count ? dirs[0] : NSTemporaryDirectory();
    return [dir stringByAppendingPathComponent:@"pikespy.log"];
}

static void spyAppend(NSString *line) {
    @try {
        @synchronized (gLogFile) {
            if (!gLogFile) {
                NSString *p = spyLogPath();
                if (![[NSFileManager defaultManager] fileExistsAtPath:p]) {
                    [[NSFileManager defaultManager] createFileAtPath:p contents:nil attributes:nil];
                }
                gLogFile = [NSFileHandle fileHandleForWritingAtPath:p];
                if (gLogFile) [gLogFile seekToEndOfFile];
            }
            if (gLogFile) {
                NSData *d = [[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
                [gLogFile writeData:d];
            }
        }
    } @catch (NSException *e) {
        NSLog(@"%@ write fail: %@", SPY_TAG, e);
    }
}

static void bootLog(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void bootLog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (!gBootLog) gBootLog = [NSMutableString new];
    [gBootLog appendFormat:@"%@\n", s];
    NSLog(@"%@ %@", SPY_TAG, s);
    spyAppend([NSString stringWithFormat:@"[boot] %@", s]);
}

// ---------- 参数序列化（任何 id 都安全打印）----------

static NSString *safeJson(id obj) {
    if (!obj) return @"(nil)";
    @try {
        if ([obj isKindOfClass:[NSString class]]) return (NSString *)obj;
        if ([obj isKindOfClass:[NSData class]]) {
            NSString *s = [[NSString alloc] initWithData:(NSData *)obj encoding:NSUTF8StringEncoding];
            return s ?: [obj base64EncodedStringWithOptions:0];
        }
        if ([obj isKindOfClass:[NSNumber class]] || [obj isKindOfClass:[NSNull class]]) return [obj description];
        if ([obj isKindOfClass:[NSArray class]] || [obj isKindOfClass:[NSDictionary class]]) {
            NSData *d = [NSJSONSerialization dataWithJSONObject:obj options:NSJSONWritingWithoutEscapingSlashes error:NULL];
            if (d) return [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
            return [obj description];
        }
        return [obj description];
    } @catch (NSException *e) {
        return [NSString stringWithFormat:@"(desc-fail: %@)", e.name];
    }
}

static NSString *ts(void) {
    return [NSDateFormatter new] ? [[NSDate date] description] : @"";
}

static void logBridgeMsg(NSString *api, id bizId, id alias, id content, id extra1, id extra2) {
    NSString *line = [NSString stringWithFormat:
        @"[%@] %@\n  bizId=%@\n  alias=%@\n  content=%@\n  extra1=%@\n  extra2=%@",
        ts(), api, safeJson(bizId), safeJson(alias), safeJson(content),
        extra1 ? safeJson(extra1) : @"-",
        extra2 ? safeJson(extra2) : @"-"];
    NSLog(@"%@", line);
    spyAppend(line);
}

// ---------- hook 实现 ----------

// - __msi__v2__api__Pike_sendMessage:(id)p1 bizId:(id)b alias:(id)a content:(id)c customHeader:(id)h protocolVersion:(id)v
static void (*orig_pike_send)(id, SEL, id, id, id, id, id, id);
static void hook_pike_send(id self, SEL _cmd, id p1, id bizId, id alias, id content, id hdr, id ver) {
    logBridgeMsg(@"Pike_sendMessage", bizId, alias, content, hdr, ver);
    orig_pike_send(self, _cmd, p1, bizId, alias, content, hdr, ver);
}

// - __msi__v2__api__Pike_initClient:(id)p1 bizId:(id)b alias:(id)a extra:(id)e
static void (*orig_pike_init)(id, SEL, id, id, id, id);
static void hook_pike_init(id self, SEL _cmd, id p1, id bizId, id alias, id extra) {
    logBridgeMsg(@"Pike_initClient", bizId, alias, extra, nil, nil);
    orig_pike_init(self, _cmd, p1, bizId, alias, extra);
}

// - __msi__v2__api__AggPike_sendMessage:(id)p1 bizId:(id)b alias:(id)a content:(id)c priority:(id)p
static void (*orig_agg_send)(id, SEL, id, id, id, id, id);
static void hook_agg_send(id self, SEL _cmd, id p1, id bizId, id alias, id content, id pri) {
    logBridgeMsg(@"AggPike_sendMessage", bizId, alias, content, pri, nil);
    orig_agg_send(self, _cmd, p1, bizId, alias, content, pri);
}

// - __msi__v2__api__AggPike_initClient:(id)p1 bizId:(id)b alias:(id)a extra:(id)e
static void (*orig_agg_init)(id, SEL, id, id, id, id);
static void hook_agg_init(id self, SEL _cmd, id p1, id bizId, id alias, id extra) {
    logBridgeMsg(@"AggPike_initClient", bizId, alias, extra, nil, nil);
    orig_agg_init(self, _cmd, p1, bizId, alias, extra);
}

// ---------- 安装 ----------

// 找得到实例方法就 swizzle 实例方法；否则试类方法；都没有返回 NO
static BOOL swizzleOne(Class cls, NSString *selName, IMP newImp, IMP *origOut) {
    if (!cls) return NO;
    SEL sel = sel_registerName(selName.UTF8String);
    Method m = class_getInstanceMethod(cls, sel);
    BOOL isClassMethod = NO;
    if (!m) {
        m = class_getClassMethod(cls, sel);
        isClassMethod = YES;
    }
    if (!m) return NO;
    IMP old = method_setImplementation(m, newImp);
    *origOut = old;
    bootLog(@"swizzled %@ [%@] %@ (%@)", isClassMethod ? @"+" : @"-",
            NSStringFromClass(cls), selName, old ? @"ok" : @"old-imp-nil");
    return YES;
}

// 侦察：dump 类名/方法名含 Pike 的 OC 类清单（hook 落空时的兜底情报）
static void dumpPikeClasses(void) {
    unsigned int n = 0;
    Class *classes = objc_copyClassList(&n);
    int dumped = 0;
    for (unsigned int i = 0; i < n && dumped < 40; i++) {
        NSString *name = NSStringFromClass(classes[i]);
        if (![name containsString:@"Pike"]) continue;
        dumped++;
        unsigned int mc = 0;
        Method *ms = class_copyMethodList(classes[i], &mc);
        NSMutableString *sels = [NSMutableString string];
        for (unsigned int j = 0; j < mc; j++) {
            [sels appendFormat:@"%@ ", NSStringFromSelector(method_getName(ms[j]))];
        }
        free(ms);
        bootLog(@"class %@ (%u): %@", name, mc, sels);
    }
    free(classes);
    bootLog(@"class-dump done: %d classes", dumped);
}

static void installHooks(void) {
    @try {
        bootLog(@"PikeSpy start, pid=%d", getpid());

        Class ctx   = objc_getClass("MSIPikeAPIContext");
        Class agg   = objc_getClass("MSIAggPikeAPIContext");
        bootLog(@"classes: MSIPikeAPIContext=%@ MSIAggPikeAPIContext=%@",
                ctx ? @"found" : @"MISS", agg ? @"found" : @"MISS");

        int ok = 0;
        ok += swizzleOne(ctx, @"__msi__v2__api__Pike_sendMessage:bizId:alias:content:customHeader:protocolVersion:",
                         (IMP)hook_pike_send, (IMP *)&orig_pike_send);
        ok += swizzleOne(ctx, @"__msi__v2__api__Pike_initClient:bizId:alias:extra:",
                         (IMP)hook_pike_init, (IMP *)&orig_pike_init);
        ok += swizzleOne(agg, @"__msi__v2__api__AggPike_sendMessage:bizId:alias:content:priority:",
                         (IMP)hook_agg_send, (IMP *)&orig_agg_send);
        ok += swizzleOne(agg, @"__msi__v2__api__AggPike_initClient:bizId:alias:extra:",
                         (IMP)hook_agg_init, (IMP *)&orig_agg_init);

        bootLog(@"hooks installed: %d/4", ok);
        if (ok == 0) dumpPikeClasses();
        bootLog(@"PikeSpy ready — 去美团币页手点一次敲金猪，然后拉 Documents/pikespy.log");
    } @catch (NSException *e) {
        bootLog(@"install EXCEPTION: %@ %@", e.name, e.reason);
    }
}

__attribute__((constructor)) static void pikespy_ctor(void) {
    // 延迟到主 runloop 起来之后执行，避开 dyld 关键期
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        [NSThread sleepForTimeInterval:3.0];   // 等 OC 类全部注册、App 过启动保护
        installHooks();
    });
}
