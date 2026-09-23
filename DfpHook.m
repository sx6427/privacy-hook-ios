//
//  DfpHook.m — 换设备指纹（SAKGuard dfpid/seed + IDFA + IDFV）
//
//  背景：一号机身份已整体换新（keychain/AppGroup/uuid/IDFV/badge 全新），
//        但登录 a0 仍报「网络异常或设备异常」。剩余设备级向量：
//        ① sakguard_storage_dfpid（硬件指纹派生值，同机必然同值）
//        ② IDFA（全设备级、跨重装串联，从未重置）
//        本 dylib 把上述向量在 App 进程内替换成按「装机盐值」确定性派生的新值：
//        同一次安装内稳定不变（避免值抖动触发风控），删 App 重装后盐值随容器消失、
//        重新生成 → 得到全新指纹。
//
//  形态约束（同 KcWiper/PikeSpy）：只做 ObjC method swizzle（改 runtime 方法表），
//        不做 inline hook、不装信号处理器。不影响 App 其它功能：非命中键一律透传原实现。
//
//  观测：Documents/dfphook.log 记录每次命中（原值前缀 -> 新值前缀）；
//        另记录 SDK 对指纹键的「写入」——若启动后 dfpid 被回写重算，说明指纹是
//        硬件信号重推导的，下轮需要换更底层的信号 hook。
//
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dispatch/dispatch.h>
#import <stdint.h>
#import <stdio.h>

#define TAG @"DFPHOOK"

// ---------- 最小声明（不 import UIKit/AdSupport，避免链接面） ----------
@interface UIDevice : NSObject
+ (id)currentDevice;
- (id)identifierForVendor;
@end
@interface ASIdentifierManager : NSObject
+ (id)sharedManager;
- (id)advertisingIdentifier;
@end

// ---------- 日志 ----------
static NSFileHandle *gLog = nil;
static NSMutableDictionary *gLoggedOnce = nil;

static NSString *dfpLogPath(void) {
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    return [(dirs.count ? dirs[0] : NSTemporaryDirectory())
            stringByAppendingPathComponent:@"dfphook.log"];
}

static void dfpAppend(NSString *line) {
    @try {
        @synchronized (gLog) {
            if (!gLog) {
                NSString *p = dfpLogPath();
                NSFileManager *fm = [NSFileManager defaultManager];
                NSDictionary *at = [fm attributesOfItemAtPath:p error:NULL];
                unsigned long long sz = at ? [at fileSize] : 0;
                if (sz > 262144) [fm removeItemAtPath:p error:NULL];   // 超 256KB 重来
                if (![fm fileExistsAtPath:p]) [fm createFileAtPath:p contents:nil attributes:nil];
                gLog = [NSFileHandle fileHandleForWritingAtPath:p];
                if (gLog) [gLog seekToEndOfFile];
            }
            if (gLog) {
                NSData *d = [[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
                if (d) [gLog writeData:d];
            }
        }
    } @catch (NSException *e) {
        NSLog(@"%@ log fail: %@", TAG, e);
    }
}

static NSString *nowStr(void) {
    return [[NSDate date] description];
}

// 每个 (方向,键,原值前缀) 只记一次，防止刷爆
static void logHit(NSString *dir, NSString *key, NSString *orig, NSString *fake) {
    @try {
        NSString *op = [NSString stringWithFormat:@"%@|%@|%@", dir, key, orig ?: @"(nil)"];
        if (orig.length > 20) op = [NSString stringWithFormat:@"%@|%@|%@…", dir, key, [orig substringToIndex:20]];
        @synchronized (gLoggedOnce) {
            if ([gLoggedOnce objectForKey:op]) return;
            [gLoggedOnce setObject:@YES forKey:op];
        }
        NSString *line = [NSString stringWithFormat:@"[%@] %@ %@\n    orig=%@\n    fake=%@",
                          nowStr(), dir, key, orig ?: @"(nil)", fake ?: @"-"];
        NSLog(@"%@ %@", TAG, line);
        dfpAppend(line);
    } @catch (NSException *e) {
        NSLog(@"%@ hitlog fail: %@", TAG, e);
    }
}

// ---------- 盐值（每次安装一份，删 App 即消失） ----------
static NSString *gSalt = nil;
static NSString *gFakeDfp = nil;   // 52 hex（与实测 dfpid 同长）
static NSString *gFakeXid = nil;   // 56 hex（与实测 localid 同长）

static NSString *hexFromSalt(NSString *name, int bytes) {
    uint64_t h = seedFor(name);
    NSMutableString *s = [NSMutableString stringWithCapacity:bytes * 2];
    for (int i = 0; i < bytes; i++) {
        h = h * 0x100000001b3ULL + (uint64_t)(i + 1) + 0x97ULL;
        h ^= h >> 23;
        [s appendFormat:@"%02x", (unsigned char)(h & 0xff)];
    }
    return s;
}

static NSString *loadSalt(void) {
    if (gSalt) return gSalt;
    @try {
        NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *p = [(dirs.count ? dirs[0] : NSTemporaryDirectory())
                       stringByAppendingPathComponent:@".dfphook_salt"];
        NSFileManager *fm = [NSFileManager defaultManager];
        NSData *d = [fm contentsAtPath:p];
        if (d.length >= 32) {
            gSalt = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        }
        if (!gSalt) {
            // /dev/urandom 取 16 字节 -> 32 hex
            FILE *f = fopen("/dev/urandom", "rb");
            unsigned char buf[16] = {0};
            if (f) { fread(buf, 1, sizeof(buf), f); fclose(f); }
            NSMutableString *s = [NSMutableString stringWithCapacity:32];
            for (int i = 0; i < 16; i++) [s appendFormat:@"%02x", buf[i]];
            gSalt = s;
            [gSalt writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:NULL];
        }
    } @catch (NSException *e) {
        gSalt = @"fallback-salt-dfphook";
        NSLog(@"%@ salt fail: %@", TAG, e);
    }
    dfpAppend([NSString stringWithFormat:@"[%@] [boot] salt=%@ pid=%d", nowStr(), gSalt, getpid()]);
    gFakeDfp = hexFromSalt(@"dfp", 26);   // 52 chars
    gFakeXid = hexFromSalt(@"xid", 28);   // 56 chars
    return gSalt;
}

// ---------- 确定性伪值生成 ----------
static uint64_t fnv1a(const char *s, size_t n, uint64_t h) {
    for (size_t i = 0; i < n; i++) { h ^= (uint64_t)(unsigned char)s[i]; h *= 0x100000001b3ULL; }
    return h;
}

// 从 (盐,键) 派生 64 位种子
static uint64_t seedFor(NSString *key) {
    NSString *cat = [gSalt stringByAppendingString:key ?: @"?"];
    const char *c = cat.UTF8String;
    return fnv1a(c, strlen(c), 0xcbf29ce484222325ULL);
}

// 与原值同长度、同字符集的伪串；字符集不认识返回 nil（不替换）
static NSString *fakeLike(NSString *orig, NSString *key) {
    if (orig.length == 0 || orig.length > 4096) return nil;
    static NSString *AL_HEX_L, *AL_HEX_U, *AL_B64, *AL_ALNUM;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        AL_HEX_L = @"0123456789abcdef"; AL_HEX_U = @"0123456789ABCDEF";
        AL_B64   = @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        AL_ALNUM = @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    });
    NSCharacterSet *cs;
    NSString *alpha;
    uint64_t h0 = seedFor(key);
    // 依序探测字符集
    NSCharacterSet *hexL = [NSCharacterSet characterSetWithCharactersInString:AL_HEX_L];
    NSCharacterSet *hexU = [NSCharacterSet characterSetWithCharactersInString:AL_HEX_U];
    NSCharacterSet *b64c = [NSCharacterSet characterSetWithCharactersInString:AL_B64];
    NSCharacterSet *aln  = [NSCharacterSet characterSetWithCharactersInString:AL_ALNUM];
    if ([orig rangeOfCharacterFromSet:[hexL invertedSet]].location == NSNotFound) { cs = hexL; alpha = AL_HEX_L; }
    else if ([orig rangeOfCharacterFromSet:[hexU invertedSet]].location == NSNotFound) { cs = hexU; alpha = AL_HEX_U; }
    else if ([orig rangeOfCharacterFromSet:[b64c invertedSet]].location == NSNotFound) { cs = b64c; alpha = AL_B64; }
    else if ([orig rangeOfCharacterFromSet:[aln  invertedSet]].location == NSNotFound) { cs = aln;  alpha = AL_ALNUM; }
    else return nil;
    (void)cs;
    NSMutableString *out = [NSMutableString stringWithCapacity:orig.length];
    uint64_t h = h0;
    for (NSUInteger i = 0; i < orig.length; i++) {
        h = h * 0x100000001b3ULL + (uint64_t)i + 0x97ULL;
        [out appendFormat:@"%c", [alpha characterAtIndex:(NSUInteger)(h % (uint64_t)alpha.length)]];
    }
    return out;
}

// 从 (盐,名字) 派生规范 UUID
static NSUUID *fakeUUID(NSString *name) {
    uint64_t h = seedFor(name);
    unsigned char b[16];
    for (int i = 0; i < 16; i++) {
        h = h * 0x100000001b3ULL + (uint64_t)(i + 1) + 0x97ULL;
        h ^= h >> 29;
        b[i] = (unsigned char)(h & 0xff);
    }
    NSMutableString *s = [NSMutableString stringWithCapacity:36];
    for (int i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10) [s appendString:@"-"];
        [s appendFormat:@"%02x", b[i]];
    }
    return [[NSUUID alloc] initWithUUIDString:s];
}

// ---------- 指纹键判定 ----------
static BOOL isFpKey(NSString *k) {
    if (![k isKindOfClass:[NSString class]] || k.length == 0 || k.length > 256) return NO;
    return [k containsString:@"sakguard"] || [k hasPrefix:@"sakg_"] ||
           [k containsString:@"dfpid"]    || [k containsString:@"localid"] ||
           [k containsString:@"fama"]     || [k containsString:@"dfp_"];
}

// ---------- hook 实现 ----------
static id (*orig_objForKey)(id, SEL, id);
static id hook_objForKey(id self, SEL _cmd, id key) {
    id orig = orig_objForKey(self, _cmd, key);
    @try {
        if (isFpKey(key) && [orig isKindOfClass:[NSString class]]) {
            NSString *fake = fakeLike(orig, key);
            if (fake) { logHit(@"read", key, orig, fake); return fake; }
            logHit(@"read-pass", key, orig, nil);   // 字符集不认识，透传
        }
    } @catch (NSException *e) { NSLog(@"%@ hk1: %@", TAG, e); }
    return orig;
}

static id (*orig_objForKeyedSub)(id, SEL, id);
static id hook_objForKeyedSub(id self, SEL _cmd, id key) {
    id orig = orig_objForKeyedSub(self, _cmd, key);
    @try {
        if (isFpKey(key) && [orig isKindOfClass:[NSString class]]) {
            NSString *fake = fakeLike(orig, key);
            if (fake) { logHit(@"read-sub", key, orig, fake); return fake; }
        }
    } @catch (NSException *e) { NSLog(@"%@ hk2: %@", TAG, e); }
    return orig;
}

static void (*orig_setObj)(id, SEL, id, id);
static void hook_setObj(id self, SEL _cmd, id val, id key) {
    @try {
        if (isFpKey(key) && [val isKindOfClass:[NSString class]]) {
            logHit(@"write", key, val, nil);   // 观测：SDK 是否回写重算值（只记不改）
        }
    } @catch (NSException *e) { NSLog(@"%@ hk3: %@", TAG, e); }
    orig_setObj(self, _cmd, val, key);
}

static NSUUID *(*orig_idfa)(id, SEL);
static NSUUID *hook_idfa(id self, SEL _cmd) {
    NSUUID *orig = orig_idfa(self, _cmd);
    @try {
        NSUUID *f = fakeUUID(@"IDFA");
        if (f) { logHit(@"idfa", @"advertisingIdentifier", [orig UUIDString], [f UUIDString]); return f; }
    } @catch (NSException *e) { NSLog(@"%@ hk4: %@", TAG, e); }
    return orig;
}

static NSUUID *(*orig_idfv)(id, SEL);
static NSUUID *hook_idfv(id self, SEL _cmd) {
    NSUUID *orig = orig_idfv(self, _cmd);
    @try {
        NSUUID *f = fakeUUID(@"IDFV");
        if (f) { logHit(@"idfv", @"identifierForVendor", [orig UUIDString], [f UUIDString]); return f; }
    } @catch (NSException *e) { NSLog(@"%@ hk5: %@", TAG, e); }
    return orig;
}

// ================= v2：SAKGuard 指纹生成/持有点 hook =================
// v1 教训：dfpid 由 SAKGuard 每次启动从信号现算并回写（[write] d87187750b…），
// 只拦存储层读取没用 —— 服务端收到的是内存里的真指纹。
// v2 直接 hook 生成/持有类（类清单来自 v1 的 class-dump）：
//   SAKGuardDeviceFingerprint: getDeviceFingerprintString / static_dfpID / fingerprintStr /
//                              static_dfpXID / generateLocalXID / dpID
//   SAKFingerprintGenerator:   dfp / dpID / setDfp:
//   SAKWindFingerprintGenerator: dpID
//   观测（只记不改）：MSIRiskControlFingerprintContext getRiskControlFingerprint:（风控指纹载荷）
//                     SAKGuardCommon encrypt:/decrypt:（SAKGuard 私有存储，明文情报）

static NSMutableDictionary *gOrigV2 = nil;   // "类名+sel" -> NSValue(IMP)

static NSString *v2Key(id self, SEL _cmd) {
    return [NSStringFromClass(object_getClass(self)) stringByAppendingString:NSStringFromSelector(_cmd)];
}

// 通用 getter：NSString 原值 -> 同长度同字符集伪值；nil -> 固定伪 dfp/xid
static id hook_v2_getter(id self, SEL _cmd) {
    IMP orig = (IMP)[[gOrigV2 objectForKey:v2Key(self, _cmd)] pointerValue];
    if (!orig) return nil;
    NSString *origv = ((id(*)(id, SEL))orig)(self, _cmd);
    NSString *key = NSStringFromSelector(_cmd);
    @try {
        if ([origv isKindOfClass:[NSString class]] && origv.length > 0 && origv.length <= 4096) {
            NSString *fake = fakeLike(origv, key);
            if (fake) { logHit(@"v2-prop", key, origv, fake); return fake; }
        }
        if (!origv) {
            NSString *fake = ([key rangeOfString:@"XID"].location != NSNotFound ||
                              [key rangeOfString:@"xid"].location != NSNotFound ||
                              [key isEqualToString:@"generateLocalXID"]) ? gFakeXid : gFakeDfp;
            logHit(@"v2-nil", key, nil, fake);
            return fake;
        }
    } @catch (NSException *e) { NSLog(@"%@ v2g: %@", TAG, e); }
    return origv;
}

// setDfp: —— 真值写入前替换成伪值（内存里从此只有伪指纹）
static void hook_v2_setDfp(id self, SEL _cmd, id v) {
    IMP orig = (IMP)[[gOrigV2 objectForKey:v2Key(self, _cmd)] pointerValue];
    if (!orig) return;
    @try {
        if ([v isKindOfClass:[NSString class]] && v.length > 0) {
            NSString *fake = fakeLike(v, @"setDfp");
            logHit(@"v2-set", NSStringFromSelector(_cmd), v, fake);
            ((void(*)(id, SEL, id))orig)(self, _cmd, fake ?: v);
            return;
        }
    } @catch (NSException *e) { NSLog(@"%@ v2s: %@", TAG, e); }
    ((void(*)(id, SEL, id))orig)(self, _cmd, v);
}

// getRiskControlFingerprint: —— 只记（风控指纹载荷，v3 情报）
static id hook_v2_risk(id self, SEL _cmd, id arg) {
    IMP orig = (IMP)[[gOrigV2 objectForKey:v2Key(self, _cmd)] pointerValue];
    if (!orig) return nil;
    id out = ((id(*)(id, SEL, id))orig)(self, _cmd, arg);
    @try {
        NSString *s = [out description];
        if (s.length > 1200) s = [[s substringToIndex:1200] stringByAppendingString:@"…"];
        logHit(@"v2-risk", NSStringFromSelector(_cmd), s, nil);
    } @catch (NSException *e) { NSLog(@"%@ v2r: %@", TAG, e); }
    return out;
}

// encrypt:/decrypt: —— 只记（SAKGuard 私有存储明文，v3 情报）
static id hook_v2_codec(id self, SEL _cmd, id arg) {
    IMP orig = (IMP)[[gOrigV2 objectForKey:v2Key(self, _cmd)] pointerValue];
    if (!orig) return nil;
    id out = ((id(*)(id, SEL, id))orig)(self, _cmd, arg);
    @try {
        NSString *s = [out isKindOfClass:[NSString class]] ? (NSString *)out : [out description];
        if (s.length > 600) s = [[s substringToIndex:600] stringByAppendingString:@"…"];
        NSString *a = [arg isKindOfClass:[NSString class]] ? (NSString *)arg : [arg description];
        if (a.length > 200) a = [[a substringToIndex:200] stringByAppendingString:@"…"];
        logHit([NSString stringWithFormat:@"v2-%@", NSStringFromSelector(_cmd)],
               [NSString stringWithFormat:@"%@(%@)", NSStringFromClass(object_getClass(self)), a ?: @"-"], s, nil);
    } @catch (NSException *e) { NSLog(@"%@ v2c: %@", TAG, e); }
    return out;
}

// 装 v2 hook（类 + 方法列表；找不到类/方法跳过并记日志）
static void installV2(void) {
    @try {
        @synchronized (gOrigV2) {
            struct { const char *cls; const char *sel; IMP imp; } plan[] = {
                {"SAKGuardDeviceFingerprint", "getDeviceFingerprintString", (IMP)hook_v2_getter},
                {"SAKGuardDeviceFingerprint", "static_dfpID",               (IMP)hook_v2_getter},
                {"SAKGuardDeviceFingerprint", "fingerprintStr",             (IMP)hook_v2_getter},
                {"SAKGuardDeviceFingerprint", "static_dfpXID",              (IMP)hook_v2_getter},
                {"SAKGuardDeviceFingerprint", "generateLocalXID",           (IMP)hook_v2_getter},
                {"SAKGuardDeviceFingerprint", "dpID",                       (IMP)hook_v2_getter},
                {"SAKFingerprintGenerator",   "dfp",                        (IMP)hook_v2_getter},
                {"SAKFingerprintGenerator",   "dpID",                       (IMP)hook_v2_getter},
                {"SAKFingerprintGenerator",   "setDfp:",                    (IMP)hook_v2_setDfp},
                {"SAKWindFingerprintGenerator","dpID",                      (IMP)hook_v2_getter},
                {"MSIRiskControlFingerprintContext","getRiskControlFingerprint:", (IMP)hook_v2_risk},
                {"SAKGuardCommon",            "encrypt:",                   (IMP)hook_v2_codec},
                {"SAKGuardCommon",            "decrypt:",                   (IMP)hook_v2_codec},
            };
            int ok = 0;
            for (unsigned long i = 0; i < sizeof(plan)/sizeof(plan[0]); i++) {
                Class cls = objc_getClass(plan[i].cls);
                if (!cls) { dfpAppend([NSString stringWithFormat:@"[%@] [v2-miss-class] %@", nowStr(), [NSString stringWithUTF8String:plan[i].cls]]); continue; }
                SEL sel = sel_registerName(plan[i].sel);
                Method m = class_getInstanceMethod(cls, sel);
                if (!m) { dfpAppend([NSString stringWithFormat:@"[%@] [v2-miss-sel] %@ %@", nowStr(), [NSString stringWithUTF8String:plan[i].cls], [NSString stringWithUTF8String:plan[i].sel]]); continue; }
                NSString *k = [[NSString stringWithUTF8String:plan[i].cls] stringByAppendingString:[NSString stringWithUTF8String:plan[i].sel]];
                IMP old = method_setImplementation(m, plan[i].imp);
                [gOrigV2 setObject:[NSValue valueWithPointer:old] forKey:k];
                ok++;
                dfpAppend([NSString stringWithFormat:@"[%@] [v2-swizzle] %@ %@ (%@)", nowStr(),
                          [NSString stringWithUTF8String:plan[i].cls],
                          [NSString stringWithUTF8String:plan[i].sel], old ? @"ok" : @"old-nil"]);
            }
            dfpAppend([NSString stringWithFormat:@"[%@] [v2] installed %d hooks", nowStr(), ok]);
            NSLog(@"%@ v2 installed %d", TAG, ok);
        }
    } @catch (NSException *e) {
        NSLog(@"%@ installV2: %@", TAG, e);
    }
}

// ---------- swizzle 工具 ----------
static BOOL swizzleOne(Class cls, NSString *selName, IMP newImp, IMP *origOut) {
    if (!cls) return NO;
    SEL sel = sel_registerName(selName.UTF8String);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) m = class_getClassMethod(cls, sel);
    if (!m) return NO;
    IMP old = method_setImplementation(m, newImp);
    *origOut = old;
    dfpAppend([NSString stringWithFormat:@"[%@] [swizzle] %@ %@ (%@)", nowStr(),
              NSStringFromClass(cls), selName, old ? @"ok" : @"old-nil"]);
    return YES;
}

// ---------- 侦察：SAKGuard/指纹相关类清单（hook 落空时的情报） ----------
static void dumpFpClasses(void) {
    @try {
        unsigned int n = 0;
        Class *classes = objc_copyClassList(&n);
        int dumped = 0;
        NSArray *pats = @[@"SakGuard", @"SAKGuard", @"Sakguard", @"sakguard",
                          @"Fingerprint", @"fingerprint", @"DeviceFp", @"DeviceId"];
        for (unsigned int i = 0; i < n && dumped < 30; i++) {
            NSString *name = NSStringFromClass(classes[i]);
            BOOL hit = NO;
            for (NSString *p in pats) if ([name containsString:p]) { hit = YES; break; }
            if (!hit) continue;
            dumped++;
            unsigned int mc = 0;
            Method *ms = class_copyMethodList(classes[i], &mc);
            NSMutableString *sels = [NSMutableString string];
            for (unsigned int j = 0; j < mc && j < 40; j++)
                [sels appendFormat:@"%@ ", NSStringFromSelector(method_getName(ms[j]))];
            free(ms);
            dfpAppend([NSString stringWithFormat:@"[%@] [class] %@ (%u): %@",
                      nowStr(), name, mc, sels]);
        }
        free(classes);
        dfpAppend([NSString stringWithFormat:@"[%@] [class-dump done] %d classes", nowStr(), dumped]);
    } @catch (NSException *e) {
        NSLog(@"%@ dump fail: %@", TAG, e);
    }
}

// 延迟补装：ASIdentifierManager 若首装时类未加载，这里再试一次；并安装 v2 类 hook
static void lateInstall(void) {
    @try {
        Class as = objc_getClass("ASIdentifierManager");
        if (as && !orig_idfa) {
            swizzleOne(as, @"advertisingIdentifier", (IMP)hook_idfa, (IMP *)&orig_idfa);
        }
        installV2();          // ← v2：SAKGuard 指纹生成/持有点（App 类此时已注册）
        dumpFpClasses();
        dfpAppend([NSString stringWithFormat:@"[%@] [late] done", nowStr()]);
    } @catch (NSException *e) {
        NSLog(@"%@ late: %@", TAG, e);
    }
}

// ---------- 安装 ----------
__attribute__((constructor)) static void dfphook_ctor(void) {
    @try {
        gLoggedOnce = [NSMutableDictionary new];
        gOrigV2 = [NSMutableDictionary new];
        loadSalt();

        Class nud = objc_getClass("NSUserDefaults");
        Class uid = objc_getClass("UIDevice");
        Class as  = objc_getClass("ASIdentifierManager");

        int ok = 0;
        ok += swizzleOne(nud, @"objectForKey:",           (IMP)hook_objForKey,      (IMP *)&orig_objForKey);
        ok += swizzleOne(nud, @"objectForKeyedSubscript:",(IMP)hook_objForKeyedSub, (IMP *)&orig_objForKeyedSub);
        ok += swizzleOne(nud, @"setObject:forKey:",       (IMP)hook_setObj,         (IMP *)&orig_setObj);
        ok += swizzleOne(uid, @"identifierForVendor",     (IMP)hook_idfv,           (IMP *)&orig_idfv);
        if (as) ok += swizzleOne(as, @"advertisingIdentifier", (IMP)hook_idfa, (IMP *)&orig_idfa);

        dfpAppend([NSString stringWithFormat:@"[%@] [boot] DfpHook ready, hooks=%d/5", nowStr(), ok]);
        NSLog(@"%@ ready hooks=%d/5", TAG, ok);

        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            [NSThread sleepForTimeInterval:6.0];
            lateInstall();
        });
    } @catch (NSException *e) {
        NSLog(@"%@ ctor EXCEPTION: %@ %@", TAG, e.name, e.reason);
    }
}
