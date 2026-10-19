//
//  XyProbe.m — 闲鱼会话探针（裸 dylib，仅读取，不 hook）
//
//  用途：TrollFools 注入 com.taobao.fleamarket 后，把进程内可见的
//        cookie / keychain / NSUserDefaults 里的登录态写到 App 容器
//        Documents/xy_probe.log，供 Filza 读出。
//
//  形态约束：不 swizzle、不 hook、不改代码页 —— 符合 TrollFools 对
//  加密 App Store 应用「只支持裸动态库」的限制。
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>

static NSMutableString *gLog = nil;

static void W(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (!gLog) gLog = [NSMutableString new];
    [gLog appendFormat:@"%@\n", s];
    NSLog(@"[XYPROBE] %@", s);
}

static void flush(void) {
    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *p = [dir stringByAppendingPathComponent:@"xy_probe.log"];
    [gLog writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

static NSString *b64(NSData *d) {
    return [d base64EncodedStringWithOptions:0];
}

static void dumpCookies(void) {
    W(@"=== COOKIES ===");
    NSHTTPCookieStorage *st = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    for (NSHTTPCookie *c in [st cookies]) {
        W(@"COOKIE\t%@\t%@=%@", c.domain, c.name, c.value);
    }
}

static void dumpKeychainClass(CFTypeRef cls, NSString *label) {
    NSDictionary *q = @{(__bridge id)kSecClass: (__bridge id)cls,
                        (__bridge id)kSecReturnAttributes: @YES,
                        (__bridge id)kSecReturnData: @YES,
                        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll};
    CFTypeRef res = NULL;
    OSStatus s = SecItemCopyMatching((__bridge CFDictionaryRef)q, &res);
    W(@"=== KEYCHAIN %@ (status=%d) ===", label, (int)s);
    if (s != errSecSuccess || !res) return;
    NSArray *arr = (__bridge_transfer NSArray *)res;
    if (![arr isKindOfClass:[NSArray class]]) { arr = @[arr]; }
    for (NSDictionary *item in arr) {
        NSString *svc = item[(__bridge id)kSecAttrService] ?: @"";
        NSString *acct = item[(__bridge id)kSecAttrAccount] ?: @"";
        NSString *grp = item[(__bridge id)kSecAttrAccessGroup] ?: @"";
        NSData *dat = item[(__bridge id)kSecValueData];
        NSString *txt = @"";
        if ([dat isKindOfClass:[NSData class]]) {
            txt = [[NSString alloc] initWithData:dat encoding:NSUTF8StringEncoding] ?: b64(dat);
        }
        W(@"KC\t%@\t%@\t%@\t%@", svc, acct, grp, txt);
    }
}

static void dumpDefaults(void) {
    W(@"=== DEFAULTS ===");
    NSArray *keys = [[[NSUserDefaults standardUserDefaults] dictionaryRepresentation] allKeys];
    NSArray *kws = @[@"login", @"sid", @"token", @"cookie", @"user", @"account", @"session", @"unb", @"utdid"];
    for (NSString *k in keys) {
        NSString *lk = k.lowercaseString;
        for (NSString *kw in kws) {
            if ([lk containsString:kw]) {
                id v = [[NSUserDefaults standardUserDefaults] objectForKey:k];
                W(@"DEF\t%@\t%@", k, [v description]);
                break;
            }
        }
    }
}

static void dumpAll(void) {
    @autoreleasepool {
        W(@"---- probe at %@ ----", [NSDate date]);
        W(@"bundle=%@  executable=%@", [[NSBundle mainBundle] bundleIdentifier], [[NSBundle mainBundle] executablePath]);
        dumpCookies();
        flush();
        dumpKeychainClass(kSecClassGenericPassword, @"generic");
        dumpKeychainClass(kSecClassInternetPassword, @"internet");
        dumpDefaults();
        flush();
        W(@"---- done, bytes=%lu ----", (unsigned long)gLog.length);
        flush();
    }
}

__attribute__((constructor))
static void xyprobe_init(void) {
    @autoreleasepool {
        dumpAll();
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ dumpAll(); });
    }
}
