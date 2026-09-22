//
//  KcWiper.m — 一次性清除美团系 keychain 设备身份条目（裸动态库）
//
//  用途：给「设备指纹被风控拉黑」的机器洗白。
//  原理：美团的设备身份（uuid / localID / dpid / unionID / ONIID）全部存放在
//        keychain 访问组 FSS9ANCQ68.com.meituan.access 里。卸载 App 时系统
//        只会清「App 默认组」，共享组条目会留下来，所以重装后读到的还是旧身份。
//        本 dylib 用官方 SecItemDelete API 把共享组条目删干净，App 下次启动
//        就会重新生成一套全新身份。
//
//  形态约束（重要）：只做「一次函数调用」，不 swizzle、不 hook、不装信号处理器、
//        不改自身代码页 —— 因此符合 TrollFools 对「加密的 App Store 应用只支持
//        裸动态库」的限制。不要往这个文件里加 frida / fishhook / inline hook。
//
//  用法：
//    1) TrollFools 注入到 com.meituan.imeituan
//    2) 启动 App 一次（constructor 在 dyld 阶段执行）
//    3) 读 App 容器 Documents/kcwiper.log 确认执行结果
//    4) 卸载 App → 重启 → 关 WiFi 走 4G → 从 App Store 重装
//
//  注意：删除不可逆。这是给「已经被拉黑的设备」做身份重置用的。
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <unistd.h>

static NSMutableString *gLog = nil;

static void W(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (!gLog) gLog = [NSMutableString new];
    [gLog appendFormat:@"%@\n", s];
    NSLog(@"[KCWIPER] %@", s);
}

static void flushLog(void) {
    @try {
        NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                            NSUserDomainMask, YES);
        NSString *dir = dirs.count ? dirs[0] : NSTemporaryDirectory();
        NSString *p = [dir stringByAppendingPathComponent:@"kcwiper.log"];
        [gLog writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    } @catch (NSException *e) {
        NSLog(@"[KCWIPER] flushLog failed: %@", e);
    }
}

static NSString *describe(OSStatus st) {
    if (st == errSecSuccess) return @"已删除";
    if (st == errSecItemNotFound) return @"无条目";
    if (st == -34018) return @"缺entitlement(非本App的组)";
    if (st == -25308) return @"交互不允许";
    return @"其他";
}

// 用指定的同步语义删一次
static OSStatus wipeOnce(CFStringRef cls, NSString *agrp, BOOL withSyncKey, id syncVal) {
    NSMutableDictionary *q = [NSMutableDictionary dictionary];
    q[(__bridge id)kSecClass] = (__bridge id)cls;
    q[(__bridge id)kSecAttrAccessGroup] = agrp;
    if (withSyncKey && syncVal) {
        q[(__bridge id)kSecAttrSynchronizable] = syncVal;
    }
    return SecItemDelete((__bridge CFDictionaryRef)q);
}

static int wipeGroupClass(NSString *agrp, CFStringRef cls, NSString *clsName) {
    int hits = 0;
    // 1) 同步 + 非同步一把删
    OSStatus st = wipeOnce(cls, agrp, YES, (__bridge id)kSecAttrSynchronizableAny);
    W(@"  [%@] %-22s -> %d (%@)",
      agrp, [clsName UTF8String], (int)st, describe(st));
    if (st == errSecSuccess) hits++;

    // 2) 兜底：不带同步键再删一次（覆盖 Any 不被接受的旧系统行为）
    OSStatus st2 = wipeOnce(cls, agrp, NO, nil);
    if (st2 == errSecSuccess) {
        W(@"  [%@] %-22s -> 兜底又删到", agrp, [clsName UTF8String]);
        hits++;
    }
    return hits;
}

__attribute__((constructor))
static void kcwiper_init(void) {
    @autoreleasepool {
        NSArray<NSString *> *groups = @[
            @"FSS9ANCQ68.com.meituan.access",           // 全家桶共享身份池（核心）
            @"FSS9ANCQ68.com.meituan.imeituan",         // 美团主 App 默认组
            @"FSS9ANCQ68.com.meituan.qcs.c",
            @"FSS9ANCQ68.com.meituan.ONIID",
            @"5DYWBWGPJ5.com.dianping.dpscope",         // 点评（在 imeituan 进程里会缺权限，正常）
            @"L5275TG2BV.com.meituan.banma.crowdsource",
        ];

        // kSecClassKey / kSecClassCertificate 在部分系统上删除需要额外属性，一并尝试
        NSArray *classes = @[
            (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecClassInternetPassword,
            (__bridge id)kSecClassKey,
            (__bridge id)kSecClassCertificate,
        ];
        NSArray<NSString *> *classNames = @[
            @"GenericPassword", @"InternetPassword", @"Key", @"Certificate",
        ];

        NSString *dir = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                            NSUserDomainMask, YES).firstObject;
        NSString *flag = [dir stringByAppendingPathComponent:@"kcwiper.done"];

        W(@"=== KcWiper start  %@ ===", [NSDate date]);
        W(@"bundle = %@", [[NSBundle mainBundle] bundleIdentifier]);
        W(@"docs   = %@", dir);

        // 只执行一次：跑过就跳过（避免用户想留着 App 正常用时反复闪退）
        if ([[NSFileManager defaultManager] fileExistsAtPath:flag]) {
            W(@"=== 已执行过，跳过 ===");
            flushLog();
            return;
        }

        int totalHits = 0;
        for (NSString *g in groups) {
            for (NSUInteger i = 0; i < classes.count; i++) {
                totalHits += wipeGroupClass(g, (__bridge CFStringRef)classes[i], classNames[i]);
            }
        }
        W(@"=== 完成：实际删到条目 %d 次 ===", totalHits);
        W(@"=== 若 access 组命中 0，说明该进程没有该组的 entitlement ===");

        [@"done" writeToFile:flag atomically:YES encoding:NSUTF8StringEncoding error:NULL];
        flushLog();

        if (totalHits > 0) {
            // 身份已清空 → 立即退出：不让 App 走到 main 重新生成并上报新的设备身份。
            // 这样卸载重装后，服务端看到的是「全新 IDFV + 无历史条目」的干净状态。
            _exit(0);
        }
    }
}
