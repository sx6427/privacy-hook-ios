//
//  DfpHook.m v3 — C 层原始信号伪造（fishhook）+ 身份键白名单修正
//
//  v2 实测结论（2026-09-23 日志）：
//   ① v2 的 12 个 ObjC hook 全部生效（static_dfpID 等 getter 均返回伪值），
//     但 App 启动时把「重算后的 dfpid」原样写回 sakguard_storage_dfpid（d8718775…，
//     与历史值完全一致）⇒ dfpid 由底层硬件信号确定性重算，拦 ObjC getter 无效。
//   ② v2 的 fakeLike 把加密配置键（sakguard_func_instruction_key 等）也污染了，
//     产出非法 base64，可能反而让 SAKGuard 判定异常。
//
//  v3 方案：
//   A. fishhook rebind C 层符号：sysctl / sysctlbyname / dlsym / MGCopyAnswer
//      - sysctlbyname：伪造 hw.uuid / hw.serialno / hw.ufid / kern.serialno /
//        kern.uuid / kern.bootuuid / kern.bootsessionuuid（同长度同字符集）
//      - sysctl：观测全部 (mib0,mib1) 组合；伪造 CTL_HW/HW_UUID
//      - dlsym：拦截 SAKGuard dlopen(libMobileGestalt)+dlsym("MGCopyAnswer") 路径
//      - MGCopyAnswer：伪造 UniqueDeviceID(UDID 40hex)/SerialNumber(12位)/
//        UniqueChipID(CFNumber)/IMEI(15位)/MEID(14hex)
//      ⇒ dfpid 的原料（硬件身份）在源头被替换，重算自然得到全新 dfpid。
//   B. NSUserDefaults 读取伪造收缩为「身份键白名单」（dfpid/localid/xid/fama），
//      加密配置键一律透传，修掉 v2 的污染 bug。
//   C. v2 的 ObjC getter/setter hook 降级为「只观测不伪造」——v3 起所有指纹值
//      统一由伪原料推导，避免「伪上加伪」造成存储值与上报值不一致。
//
//  形态约束：ObjC method swizzle + fishhook GOT 重绑定（无 inline hook）。
//  观测：Documents/dfphook.log。
//
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dispatch/dispatch.h>
#import <stdint.h>
#import <stdio.h>
#import <string.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#include "fishhook.h"

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

static uint64_t seedFor(NSString *key);   // 前置声明（hexFromSalt 在其定义之前使用）

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

// v3：按 (盐,名字) 派生指定字符集、指定长度的伪串（MG 伪造用）
static NSString *fakeAlpha(NSString *name, NSUInteger len, NSString *alpha) {
    uint64_t h = seedFor(name);
    const char *a = alpha.UTF8String;
    NSUInteger al = strlen(a);
    NSMutableString *s = [NSMutableString stringWithCapacity:len];
    for (NSUInteger i = 0; i < len; i++) {
        h = h * 0x100000001b3ULL + (uint64_t)(i + 1) + 0x97ULL;
        h ^= h >> 23;
        [s appendFormat:@"%c", a[h % (uint64_t)al]];
    }
    return s;
}

// v4：统一假身份（所有层共用同一套，保证 UDID/序列号/UUID 跨通道一致）
static NSString *fakeSerial(void) {
    static NSString *s;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = fakeAlpha(@"MG-Serial", 12, @"0123456789ABCDEFGHJKLMNPQRSTUVWXYZ"); });
    return s;
}
static NSString *fakeUDID(void) {
    static NSString *s;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = fakeAlpha(@"MG-UDID", 40, @"0123456789ABCDEF"); });
    return s;
}
static NSString *fakeUUIDStr(NSString *name) {
    static NSMutableDictionary *cache;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ cache = [NSMutableDictionary new]; });
    @synchronized (cache) {
        NSString *c = [cache objectForKey:name];
        if (!c) {
            NSString *hex = hexFromSalt(name, 16);   // 32 hex
            NSMutableString *s = [NSMutableString stringWithCapacity:36];
            [s appendString:@"-"];
            for (NSUInteger i = 0; i < 32; i++) {
                if (i == 8 || i == 12 || i == 16 || i == 20) [s appendString:@"-"];
                [s appendString:[hex substringWithRange:NSMakeRange(i, 1)]];
            }
            [s deleteCharactersInRange:NSMakeRange(0, 1)];
            c = s;
            [cache setObject:c forKey:name];
        }
        return c;
    }
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

// ---------- 指纹键判定（v3 收缩白名单） ----------
// 配置键：SAKGuard 从服务端下发的加密配置，值必须原样 —— v2 污染它们的教训
static BOOL isConfigKey(NSString *k) {
    return [k containsString:@"config"] || [k containsString:@"instruction"] ||
           [k containsString:@"index"]  || [k containsString:@"collect"] ||
           [k containsString:@"raptor"] || [k containsString:@"blacklist"] ||
           [k containsString:@"method"] || [k containsString:@"enc_str"] ||
           [k containsString:@"_bio"]   || [k containsString:@"stat_"] ||
           [k containsString:@"record"] || [k containsString:@"reported"];
}

// 身份键：可以安全替换的设备身份派生值
static BOOL isIdentityKey(NSString *k) {
    if (![k isKindOfClass:[NSString class]] || k.length == 0 || k.length > 256) return NO;
    if (isConfigKey(k)) return NO;
    return [k containsString:@"dfpid"] || [k containsString:@"localid"] ||
           [k containsString:@"fama"]  || [k hasSuffix:@"_xid"];
}

// 观测键（只记日志不改值）：所有 sakguard 系
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
        if (isIdentityKey(key) && [orig isKindOfClass:[NSString class]]) {
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
        if (isIdentityKey(key) && [orig isKindOfClass:[NSString class]]) {
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

// 通用 getter —— v3 起只观测不伪造：原料已在 C 层替换，
// 这里再伪造会造成「存储值 ≠ 上报值」的伪上加伪
static id hook_v2_getter(id self, SEL _cmd) {
    IMP orig = (IMP)[[gOrigV2 objectForKey:v2Key(self, _cmd)] pointerValue];
    if (!orig) return nil;
    id out = ((id(*)(id, SEL))orig)(self, _cmd);
    @try {
        NSString *key = NSStringFromSelector(_cmd);
        if ([out isKindOfClass:[NSString class]]) {
            logHit(@"v3-obs", key, (NSString *)out, nil);
        } else if (!out) {
            logHit(@"v3-obs-nil", key, nil, nil);
        }
    } @catch (NSException *e) { NSLog(@"%@ v2g: %@", TAG, e); }
    return out;
}

// setDfp: —— v3 起只观测
static void hook_v2_setDfp(id self, SEL _cmd, id v) {
    IMP orig = (IMP)[[gOrigV2 objectForKey:v2Key(self, _cmd)] pointerValue];
    if (!orig) return;
    @try {
        if ([v isKindOfClass:[NSString class]]) {
            logHit(@"v3-obs-set", NSStringFromSelector(_cmd), (NSString *)v, nil);
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

// ================= v3：C 层原始信号伪造 =================
// 依据：v2 日志证实 dfpid 是从底层信号确定性重算的（写回值与历史完全一致）。
// 在原料层（sysctl / MobileGestalt）替换硬件身份，重算自然产出全新 dfpid。

// 同长度同字符集地把缓冲区改成伪值；认不出的字符集返回 NO（不动）
static BOOL fakeCBuffer(const char *key, unsigned char *buf, size_t len) {
    if (!buf || len == 0 || len > 128) return NO;
    size_t n = len;
    if (buf[n - 1] == 0) n--;          // 去掉结尾 NUL，不伪造它
    if (n < 4) return NO;
    BOOL hexL = YES, hexU = YES, digits = YES, alnum = YES, uuid = YES, uuidUpper = NO;
    for (size_t i = 0; i < n; i++) {
        char c = (char)buf[i];
        BOOL isDig = (c >= '0' && c <= '9');
        BOOL isL   = (c >= 'a' && c <= 'f');
        BOOL isU   = (c >= 'A' && c <= 'F');
        BOOL isAln = isDig || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        if (!(isDig || isL)) hexL = NO;
        if (!(isDig || isU)) hexU = NO;
        if (!isDig) digits = NO;
        if (!isAln && c != '-') { alnum = NO; uuid = NO; }
        else if (c == '-') { if (n != 36 || (i != 8 && i != 13 && i != 18 && i != 23)) uuid = NO; }
        else if (!(isDig || isL || isU)) uuid = NO;
        if (isU) uuidUpper = YES;
    }
    NSString *alpha = nil;
    BOOL isUuid = NO;
    if (uuid && n == 36) { isUuid = YES; alpha = uuidUpper ? @"0123456789ABCDEF" : @"0123456789abcdef"; }
    else if (digits)      alpha = @"0123456789";
    else if (hexL)        alpha = @"0123456789abcdef";
    else if (hexU)        alpha = @"0123456789ABCDEF";
    else if (alnum)       alpha = @"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    else return NO;
    if (!gSalt) loadSalt();
    uint64_t h = seedFor([NSString stringWithUTF8String:key]);
    const char *a = alpha.UTF8String;
    NSUInteger al = alpha.length;
    for (size_t i = 0; i < n; i++) {
        if (isUuid && (i == 8 || i == 13 || i == 18 || i == 23)) { buf[i] = '-'; continue; }
        h = h * 0x100000001b3ULL + (uint64_t)(i + 1) + 0x97ULL;
        h ^= h >> 23;
        buf[i] = (unsigned char)a[h % (uint64_t)al];
    }
    return YES;
}

static void logBuf(NSString *dir, NSString *key, const unsigned char *o, const unsigned char *f, size_t len) {
    NSMutableString *os = [NSMutableString string], *fs = [NSMutableString string];
    for (size_t j = 0; j < len && j < 128; j++) {
        [os appendFormat:@"%02x", o[j]];
        [fs appendFormat:@"%02x", f[j]];
    }
    logHit(dir, key, os, fs);
}

// ---- sysctlbyname ----
static const char *kFakeSysctlNames[] = {
    "hw.uuid", "hw.serialno", "hw.ufid", "hw.serial",
    "kern.serialno", "kern.uuid", "kern.bootuuid", "kern.bootsessionuuid",
};

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static int hook_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int r = orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    if (r != 0 || !oldp || !oldlenp || !name) return r;
    size_t len = *oldlenp;
    if (len == 0 || len > 128) return r;
    for (unsigned long i = 0; i < sizeof(kFakeSysctlNames) / sizeof(kFakeSysctlNames[0]); i++) {
        if (strcmp(name, kFakeSysctlNames[i]) != 0) continue;
        unsigned char origCopy[128];
        memcpy(origCopy, oldp, len);
        BOOL faked = NO;
        NSString *un = [NSString stringWithUTF8String:name];
        // uuid 类键：统一假 UUID（与 IOKit/MG 一致）
        if ([un isEqualToString:@"hw.uuid"] || [un isEqualToString:@"kern.uuid"] ||
            [un isEqualToString:@"kern.bootuuid"] || [un isEqualToString:@"kern.bootsessionuuid"]) {
            NSString *fu = fakeUUIDStr(@"MG-UUID");
            const char *fc = fu.UTF8String;
            size_t fl = strlen(fc);
            if (len >= fl) { memcpy(oldp, fc, fl); faked = YES; }
        } else if ([un isEqualToString:@"hw.serialno"] || [un isEqualToString:@"kern.serialno"] ||
                   [un isEqualToString:@"hw.serial"]) {
            NSString *fs = fakeSerial();
            const char *fc = fs.UTF8String;
            size_t fl = strlen(fc);
            if (len >= fl) { memcpy(oldp, fc, fl); faked = YES; }
        } else {
            faked = fakeCBuffer(name, (unsigned char *)oldp, len);
        }
        if (faked) {
            logBuf(@"v4-sysctl", un, origCopy, (const unsigned char *)oldp, len);
        }
        break;
    }
    return r;
}

// ---- sysctl（MIB 形式）----
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int hook_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int r = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    if (r != 0 || !name || namelen < 2) return r;
    if (!gSalt) loadSalt();
    // 观测：每组 (mib0,mib1) 记录一次（情报：SAKGuard 在查哪些信号）
    @try {
        NSString *mk = [NSString stringWithFormat:@"v3-mib|%d|%d", name[0], name[1]];
        BOOL isNew = NO;
        @synchronized (gLoggedOnce) {
            if (![gLoggedOnce objectForKey:mk]) { [gLoggedOnce setObject:@YES forKey:mk]; isNew = YES; }
        }
        if (isNew) dfpAppend([NSString stringWithFormat:@"[%@] [v3-mib] %d / %d", nowStr(), name[0], name[1]]);
        // 伪造 CTL_HW(6) / HW_UUID(202)
        if (name[0] == 6 && name[1] == 202 && oldp && oldlenp) {
            size_t len = *oldlenp;
            if (len > 0 && len <= 128) {
                unsigned char origCopy[128];
                memcpy(origCopy, oldp, len);
                if (fakeCBuffer("hw.uuid", (unsigned char *)oldp, len)) {
                    logBuf(@"v3-sysctl-mib", @"CTL_HW/HW_UUID", origCopy, (const unsigned char *)oldp, len);
                }
            }
        }
    } @catch (NSException *e) { NSLog(@"%@ v3sys: %@", TAG, e); }
    return r;
}

// ---- dlsym（拦截 dlopen+dlsym 路径：MobileGestalt / IOKit）----
static void *(*orig_dlsym)(void *, const char *);
static CFTypeRef (*gRealMG)(CFStringRef) = NULL;   // MGCopyAnswer 真身
static CFTypeRef hook_MGCopyAnswer(CFStringRef question);
static CFTypeRef hook_IORegCreateCFProp(uint32_t entry, CFStringRef key, CFAllocatorRef alloc, uint32_t opts);
static CFTypeRef hook_IORegSearchCFProp(uint32_t entry, const char *plane, CFStringRef key, CFAllocatorRef alloc, uint32_t opts);
static int hook_IORegGetProperty(uint32_t entry, const char *prop, void *buf, uint32_t *size);

static const char *kDlsymHookNames[] = {
    "MGCopyAnswer",
    "IORegistryEntryCreateCFProperty",
    "IORegistryEntrySearchCFProperty",
    "IORegistryEntryGetProperty",
};

static void *hook_dlsym(void *handle, const char *name) {
    if (name) {
        if (strcmp(name, "MGCopyAnswer") == 0) {
            if (!gRealMG) {
                gRealMG = (CFTypeRef (*)(CFStringRef))orig_dlsym(RTLD_DEFAULT, "MGCopyAnswer");
            }
            dfpAppend([NSString stringWithFormat:@"[%@] [v4-dlsym] MGCopyAnswer hooked", nowStr()]);
            return (void *)hook_MGCopyAnswer;
        }
        if (strcmp(name, "IORegistryEntryCreateCFProperty") == 0) return (void *)hook_IORegCreateCFProp;
        if (strcmp(name, "IORegistryEntrySearchCFProperty") == 0) return (void *)hook_IORegSearchCFProp;
        if (strcmp(name, "IORegistryEntryGetProperty") == 0)      return (void *)hook_IORegGetProperty;
    }
    return orig_dlsym(handle, name);
}

static CFTypeRef hook_MGCopyAnswer(CFStringRef question) {
    if (!gRealMG) gRealMG = (CFTypeRef (*)(CFStringRef))orig_dlsym(RTLD_DEFAULT, "MGCopyAnswer");
    if (!gRealMG) return NULL;
    CFTypeRef orig = gRealMG(question);
    @try {
        if (!question) return orig;
        NSString *k = (__bridge NSString *)question;
        NSString *fake = nil;
        CFNumberRef fakeNum = NULL;
        if ([k isEqualToString:@"UniqueDeviceID"]) {
            fake = fakeUDID();
        } else if ([k isEqualToString:@"SerialNumber"]) {
            fake = fakeSerial();
        } else if ([k isEqualToString:@"UniqueChipID"]) {
            uint64_t v = seedFor(@"MG-ChipID") % 100000000000ULL;
            fakeNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &v);
        } else if ([k isEqualToString:@"InternationalMobileEquipmentIdentity"]) {
            fake = fakeAlpha(@"MG-IMEI", 15, @"0123456789");
        } else if ([k isEqualToString:@"MobileEquipmentIdentifier"]) {
            fake = fakeAlpha(@"MG-MEID", 14, @"0123456789ABCDEF");
        } else if ([k isEqualToString:@"DeviceSupportsSilentRingSwitch"] ||
                   [k isEqualToString:@"mainScreenMagnificationEnabled"]) {
            return orig;   // 布尔/无身份语义的键不记日志
        }
        if (fakeNum) {
            logHit(@"v3-mg", k, [(__bridge NSNumber *)orig description], nil);
            return fakeNum;
        }
        if (fake) {
            NSString *origS = @"?";
            if ([(__bridge id)orig isKindOfClass:[NSString class]]) origS = (__bridge NSString *)orig;
            else if (orig) origS = [(__bridge id)orig description];
            logHit(@"v3-mg", k, origS, fake);
            return (CFTypeRef)CFBridgingRetain(fake);
        }
        // 其它键：只记录一次（情报）
        NSString *d = orig ? [(__bridge id)orig description] : @"(nil)";
        logHit(@"v3-mg-pass", k, d, nil);
        return orig;
    } @catch (NSException *e) { NSLog(@"%@ v3mg: %@", TAG, e); }
    return orig;
}

// ================= v4：IOKit 硬件注册表伪造 =================
// v3 实测：SAKGuard 不走 sysctl-hw 也不走 MobileGestalt（[v3-mg]/[v3-dlsym] 零命中，
// dfpid 写回仍 d8718775…）；fama_seed 第 1/3 段、localid 前缀跨重装稳定
// ⇒ 硬件身份来自 IOKit 平台注册表（IOPlatformSerialNumber/IOPlatformUUID）的嫌疑最大。

static CFTypeRef (*real_IORegCreateCFProp)(uint32_t, CFStringRef, CFAllocatorRef, uint32_t);
static CFTypeRef (*real_IORegSearchCFProp)(uint32_t, const char *, CFStringRef, CFAllocatorRef, uint32_t);
static int (*real_IORegGetProperty)(uint32_t, const char *, void *, uint32_t *);
static uint32_t (*real_IOServiceGetMatchingService)(uint32_t, CFDictionaryRef);

static void *ioReal(const char *name, void *cached) {
    if (cached) return cached;
    void *p = orig_dlsym(RTLD_DEFAULT, name);
    dfpAppend([NSString stringWithFormat:@"[%@] [v4-io] resolve %@ -> %@", nowStr(),
              [NSString stringWithUTF8String:name], p ? @"ok" : @"nil"]);
    return p;
}

// CFStringRef 键 -> 是否命中伪造；命中返回 CFString/CFData 伪值（调用方交出所有权）
static CFTypeRef fakeIOValue(CFStringRef key, CFTypeRef orig, NSString *dir) {
    if (!key) return NULL;
    NSString *k = (__bridge NSString *)key;
    NSString *fake = nil;
    if ([k isEqualToString:@"IOPlatformSerialNumber"] ||
        [k isEqualToString:@"IOPlatformHWSerialNumber"]) {
        fake = fakeSerial();
    } else if ([k isEqualToString:@"IOPlatformUUID"]) {
        fake = fakeUUIDStr(@"MG-UUID");
    } else if ([k isEqualToString:@"UniqueDeviceID"]) {
        fake = fakeUDID();
    } else {
        // 其余键只记一次（情报：SAKGuard 在读什么）
        NSString *d = orig ? [(__bridge id)orig description] : @"(nil)";
        if (d.length > 120) d = [[d substringToIndex:120] stringByAppendingString:@"…"];
        logHit(dir, k, d, nil);
        return NULL;
    }
    NSString *od = orig ? [(__bridge id)orig description] : @"(nil)";
    logHit(dir, k, od, fake);
    return (CFTypeRef)CFBridgingRetain(fake);
}

static CFTypeRef hook_IORegCreateCFProp(uint32_t entry, CFStringRef key, CFAllocatorRef alloc, uint32_t opts) {
    if (!real_IORegCreateCFProp) {
        real_IORegCreateCFProp = (CFTypeRef (*)(uint32_t, CFStringRef, CFAllocatorRef, uint32_t))ioReal("IORegistryEntryCreateCFProperty", real_IORegCreateCFProp);
    }
    if (!real_IORegCreateCFProp) return NULL;
    CFTypeRef orig = real_IORegCreateCFProp(entry, key, alloc, opts);
    @try {
        CFTypeRef fake = fakeIOValue(key, orig, @"v4-io");
        if (fake) return fake;
    } @catch (NSException *e) { NSLog(@"%@ v4io1: %@", TAG, e); }
    return orig;
}

static CFTypeRef hook_IORegSearchCFProp(uint32_t entry, const char *plane, CFStringRef key, CFAllocatorRef alloc, uint32_t opts) {
    if (!real_IORegSearchCFProp) {
        real_IORegSearchCFProp = (CFTypeRef (*)(uint32_t, const char *, CFStringRef, CFAllocatorRef, uint32_t))ioReal("IORegistryEntrySearchCFProperty", real_IORegSearchCFProp);
    }
    if (!real_IORegSearchCFProp) return NULL;
    CFTypeRef orig = real_IORegSearchCFProp(entry, plane, key, alloc, opts);
    @try {
        CFTypeRef fake = fakeIOValue(key, orig, @"v4-io-s");
        if (fake) return fake;
    } @catch (NSException *e) { NSLog(@"%@ v4io2: %@", TAG, e); }
    return orig;
}

static int hook_IORegGetProperty(uint32_t entry, const char *prop, void *buf, uint32_t *size) {
    if (!real_IORegGetProperty) {
        real_IORegGetProperty = (int (*)(uint32_t, const char *, void *, uint32_t *))ioReal("IORegistryEntryGetProperty", real_IORegGetProperty);
    }
    if (!real_IORegGetProperty) return -536870206;   // kIOReturnUnsupported
    int r = real_IORegGetProperty(entry, prop, buf, size);
    @try {
        if (r == 0 && buf && size && prop) {
            NSString *k = [NSString stringWithUTF8String:prop];
            NSString *fake = nil;
            if ([k isEqualToString:@"IOPlatformSerialNumber"] || [k isEqualToString:@"serial-number"]) {
                fake = fakeSerial();
            } else if ([k isEqualToString:@"IOPlatformUUID"]) {
                fake = fakeUUIDStr(@"MG-UUID");
            }
            if (fake) {
                const char *fc = fake.UTF8String;
                uint32_t fl = (uint32_t)strlen(fc);
                if (*size >= fl) {
                    unsigned char origCopy[128];
                    uint32_t origSz = *size;
                    if (origSz > 128) origSz = 128;
                    memcpy(origCopy, buf, origSz);
                    memcpy(buf, fc, fl);
                    logBuf(@"v4-io-g", k, origCopy, (const unsigned char *)buf, origSz);
                    *size = fl;
                }
            }
        }
    } @catch (NSException *e) { NSLog(@"%@ v4io3: %@", TAG, e); }
    return r;
}

// 观测：SAKGuard 在匹配哪个 IOService（不伪造服务本身，只伪造属性读数）
static uint32_t hook_IOServiceGetMatchingService(uint32_t masterPort, CFDictionaryRef matching) {
    if (!real_IOServiceGetMatchingService) {
        real_IOServiceGetMatchingService = (uint32_t (*)(uint32_t, CFDictionaryRef))ioReal("IOServiceGetMatchingService", real_IOServiceGetMatchingService);
    }
    if (!real_IOServiceGetMatchingService) return 0;
    uint32_t svc = real_IOServiceGetMatchingService(masterPort, matching);
    @try {
        if (matching) {
            NSDictionary *d = (__bridge NSDictionary *)matching;
            NSString *desc = [d description];
            if (desc.length > 120) desc = [[desc substringToIndex:120] stringByAppendingString:@"…"];
            logHit(@"v4-iosvc", @"IOServiceGetMatchingService", desc, svc ? @"svc" : @"nil");
        }
    } @catch (NSException *e) { NSLog(@"%@ v4io4: %@", TAG, e); }
    return svc;
}

// 装载 C 层 rebind（只在 ctor 调一次！重复调用会让 replaced 指到 hook 自己，死循环）
static void installV3Fishhook(void) {
    @try {
        struct rebinding rb[] = {
            {"sysctl",       (void *)hook_sysctl,       (void **)&orig_sysctl},
            {"sysctlbyname", (void *)hook_sysctlbyname, (void **)&orig_sysctlbyname},
            {"dlsym",        (void *)hook_dlsym,        (void **)&orig_dlsym},
            {"MGCopyAnswer", (void *)hook_MGCopyAnswer, (void **)&gRealMG},
            {"IORegistryEntryCreateCFProperty", (void *)hook_IORegCreateCFProp, (void **)&real_IORegCreateCFProp},
            {"IORegistryEntrySearchCFProperty",(void *)hook_IORegSearchCFProp, (void **)&real_IORegSearchCFProp},
            {"IORegistryEntryGetProperty",      (void *)hook_IORegGetProperty,  (void **)&real_IORegGetProperty},
            {"IOServiceGetMatchingService",     (void *)hook_IOServiceGetMatchingService, (void **)&real_IOServiceGetMatchingService},
        };
        int n = rebind_symbols(rb, sizeof(rb) / sizeof(rb[0]));
        dfpAppend([NSString stringWithFormat:@"[%@] [v4] rebind_symbols -> %d (8 rebinds: sysctl x2 + dlsym + MG + IOKit x4)", nowStr(), n]);
        NSLog(@"%@ v4 rebind=%d", TAG, n);
    } @catch (NSException *e) {
        NSLog(@"%@ installV3: %@", TAG, e);
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

// ================= v5b：网络层观测（无块包装，零内存写入） =================
// v5 闪退教训：_Block_copy 对全局块返回原指针，改其 invoke = 写只读内存 → 崩溃。
// v5b 一律不动 completion 块；响应侧改走 NSJSONSerialization 烟测
// （系统解析 JSON 必经，raw bytes 里扫 dfpid / 已知 dfpid 值）。
// v5 实测（88KB 日志）：风控请求实为 tte.meituan.com/api/v1/tte/fips/verify、
// appsec-mobile.meituan.com/api/{latte,ristretto}、api-unionid.meituan.com/mc/{config,register}、
// uuid/v2/collect、p*.d.meituan.net POST —— 关键词表已按此扩充；POST 一律记 body。

static BOOL isInterestingURL(NSString *u) {
    if (u.length == 0) return NO;
    NSArray *kw = @[@"dfp", @"risk", @"sakguard", @"cips", @"fingerprint",
                    @"deviceid", @"guard", @"antispider", @"verifyid", @"shumei",
                    @"tte.meituan", @"/fips", @"ristretto", @"/latte",
                    @"unionid", @"uuid/v2", @"appsec", @"bdgcf",
                    @"d.meituan.net", @"dreport", @"catdot", @"lx0.meituan"];
    for (NSString *k in kw)
        if ([u rangeOfString:k options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
    return NO;
}

static NSString *dataPreview(NSData *d, NSUInteger max) {
    if (!d || d.length == 0) return nil;
    NSUInteger take = MIN(d.length, max);
    NSString *s = [[NSString alloc] initWithData:[d subdataWithRange:NSMakeRange(0, take)]
                                         encoding:NSUTF8StringEncoding];
    if (!s) return [NSString stringWithFormat:@"<binary %lu bytes>", (unsigned long)d.length];
    if (d.length > max) s = [s stringByAppendingString:@"…"];
    return s;
}

static void logV5Request(id request) {
    @try {
        if (![request isKindOfClass:[NSURLRequest class]]) return;
        NSString *url = [(NSURLRequest *)request URL].absoluteString;
        if (url.length == 0) return;
        NSString *method = [(NSURLRequest *)request HTTPMethod] ?: @"GET";
        BOOL interesting = isInterestingURL(url);
        BOOL isPost = [method isEqualToString:@"POST"];
        if (!interesting && !isPost) return;
        // 去重键：URL + body 前 60 字符（同 URL 不同 body 的上报也要记）
        NSData *body = [(NSURLRequest *)request HTTPBody];
        NSString *bpre = dataPreview(body, 60) ?: @"";
        NSString *dk = [NSString stringWithFormat:@"v5-req|%@|%@", url, bpre];
        BOOL isNew = NO;
        @synchronized (gLoggedOnce) {
            if (![gLoggedOnce objectForKey:dk]) { [gLoggedOnce setObject:@YES forKey:dk]; isNew = YES; }
        }
        if (!isNew) return;
        dfpAppend([NSString stringWithFormat:@"[%@] [v5-req] %@ %@", nowStr(), method, url]);
        if (interesting || isPost) {
            NSString *bp = dataPreview(body, 2200);
            if (!bp && [(NSURLRequest *)request HTTPBodyStream]) bp = @"<body is stream>";
            dfpAppend([NSString stringWithFormat:@"    body: %@", bp ?: @"(empty)"]);
        }
    } @catch (NSException *e) { NSLog(@"%@ v5req: %@", TAG, e); }
}

static void logV5Response(id resp, id data, id err) {
    @try {
        NSString *url = nil;
        long status = -1;
        if ([resp isKindOfClass:[NSHTTPURLResponse class]]) {
            url = [(NSHTTPURLResponse *)resp URL].absoluteString;
            status = [(NSHTTPURLResponse *)resp statusCode];
        } else if ([resp isKindOfClass:[NSURLResponse class]]) {
            url = [(NSURLResponse *)resp URL].absoluteString;
        }
        if (url.length == 0) return;
        NSString *body = [data isKindOfClass:[NSData class]] ? dataPreview(data, 65536) : nil;
        // 烟测：任何响应里出现 dfpid 关键字或已知 dfpid 值都高亮
        if (body && ([body containsString:@"dfpid"] || [body containsString:@"d8718775"])) {
            NSString *full = [data isKindOfClass:[NSData class]] ? dataPreview(data, 4000) : nil;
            dfpAppend([NSString stringWithFormat:@"[%@] [v5-DFPID-HIT] %ld %@\n    %@",
                      nowStr(), status, url, full ?: @"(binary)"]);
        }
        if (!isInterestingURL(url)) return;
        NSString *pv = [data isKindOfClass:[NSData class]] ? dataPreview(data, 3000) : nil;
        dfpAppend([NSString stringWithFormat:@"[%@] [v5-resp] %ld %@\n    %@", nowStr(), status, url, pv ?: @"(empty)"]);
        if (err) dfpAppend([NSString stringWithFormat:@"    err: %@", [err description]]);
    } @catch (NSException *e) { NSLog(@"%@ v5resp: %@", TAG, e); }
}

static id (*orig_dtWRCH)(id, SEL, id, id);
static id hook_dtWRCH(id self, SEL _cmd, id request, id handler) {
    @try { logV5Request(request); } @catch (NSException *e) { NSLog(@"%@ v5a: %@", TAG, e); }
    return orig_dtWRCH(self, _cmd, request, handler);   // 块原样透传，不包装
}

static id (*orig_dtWR)(id, SEL, id);
static id hook_dtWR(id self, SEL _cmd, id request) {
    @try { logV5Request(request); } @catch (NSException *e) { NSLog(@"%@ v5b: %@", TAG, e); }
    return orig_dtWR(self, _cmd, request);
}

static id (*orig_utWRFDCH)(id, SEL, id, id, id);
static id hook_utWRFDCH(id self, SEL _cmd, id request, id body, id handler) {
    @try { logV5Request(request); } @catch (NSException *e) { NSLog(@"%@ v5c: %@", TAG, e); }
    return orig_utWRFDCH(self, _cmd, request, body, handler);
}

static NSData *(*orig_ssr)(id, SEL, id, id *, id *);
static NSData *hook_ssr(id self, SEL _cmd, id request, id *respOut, id *errOut) {
    NSData *d = orig_ssr(self, _cmd, request, respOut, errOut);
    @try {
        logV5Request(request);
        if (respOut && *respOut) logV5Response(*respOut, d, errOut ? *errOut : nil);
    } @catch (NSException *e) { NSLog(@"%@ v5d: %@", TAG, e); }
    return d;
}

static void (*orig_sar)(id, SEL, id, id, id);
static void hook_sar(id self, SEL _cmd, id request, id queue, id handler) {
    @try { logV5Request(request); } @catch (NSException *e) { NSLog(@"%@ v5e: %@", TAG, e); }
    orig_sar(self, _cmd, request, queue, handler);   // 块原样透传
}

// NSJSONSerialization 烟测：所有 JSON 解析的必经之路；raw bytes 扫 dfpid 特征。
// 这是响应侧唯一的观测点（配合 sendSynchronousRequest 的响应记录），全程零内存写入。
static id (*orig_jsonObj)(id, SEL, id, NSUInteger, id *);
static id hook_jsonObj(id self, SEL _cmd, id data, NSUInteger opt, id *err) {
    id out = orig_jsonObj(self, _cmd, data, opt, err);
    @try {
        if ([data isKindOfClass:[NSData class]] && [(NSData *)data length] > 0) {
            NSUInteger len = [(NSData *)data length];
            if (len <= 4194304) {
                const void *base = [(NSData *)data bytes];
                if (base && (memmem(base, len, "dfpid", 5) || memmem(base, len, "d8718775", 8))) {
                    NSString *pv = dataPreview(data, 4000);
                    NSString *dk = [@"v5-json|" stringByAppendingString:
                                    (pv.length > 100 ? [pv substringToIndex:100] : (pv ?: @""))];
                    BOOL isNew = NO;
                    @synchronized (gLoggedOnce) {
                        if (![gLoggedOnce objectForKey:dk]) { [gLoggedOnce setObject:@YES forKey:dk]; isNew = YES; }
                    }
                    if (isNew)
                        dfpAppend([NSString stringWithFormat:@"[%@] [v5-JSON-HIT] len=%lu\n    %@",
                                  nowStr(), (unsigned long)len, pv ?: @"(binary)"]);
                }
            }
        }
    } @catch (NSException *e) { NSLog(@"%@ v5j: %@", TAG, e); }
    return out;
}

static void installV5(void) {
    @try {
        Class sess = objc_getClass("NSURLSession");
        Class conn = objc_getClass("NSURLConnection");
        Class json = objc_getClass("NSJSONSerialization");
        int ok = 0;
        ok += swizzleOne(sess, @"dataTaskWithRequest:completionHandler:", (IMP)hook_dtWRCH, (IMP *)&orig_dtWRCH);
        ok += swizzleOne(sess, @"dataTaskWithRequest:",                   (IMP)hook_dtWR,   (IMP *)&orig_dtWR);
        ok += swizzleOne(sess, @"uploadTaskWithRequest:fromData:completionHandler:", (IMP)hook_utWRFDCH, (IMP *)&orig_utWRFDCH);
        ok += swizzleOne(conn, @"sendSynchronousRequest:returningResponse:error:",   (IMP)hook_ssr, (IMP *)&orig_ssr);
        ok += swizzleOne(conn, @"sendAsynchronousRequest:queue:completionHandler:",  (IMP)hook_sar, (IMP *)&orig_sar);
        ok += swizzleOne(json, @"JSONObjectWithData:options:error:",      (IMP)hook_jsonObj,(IMP *)&orig_jsonObj);
        dfpAppend([NSString stringWithFormat:@"[%@] [v5] installed %d network hooks (no block wrapping)", nowStr(), ok]);
        NSLog(@"%@ v5 installed %d", TAG, ok);
    } @catch (NSException *e) {
        NSLog(@"%@ installV5: %@", TAG, e);
    }
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

        // v3：C 层 rebind 必须最先装（SAKGuard 初始化前生效）
        installV3Fishhook();

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

        installV5();          // v5：网络层观测（启动期请求即生效，必须早装）

        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            [NSThread sleepForTimeInterval:6.0];
            lateInstall();
        });
    } @catch (NSException *e) {
        NSLog(@"%@ ctor EXCEPTION: %@ %@", TAG, e.name, e.reason);
    }
}
