//
// PrivacyHook.m — v66: keychain 隔离恢复 + 非身份项读回退
//
// ============ 版本主线 ============
//   v57N  伪造全套硬件人格（后被 v58 推翻）
//   v57Q  WKWebView UA 三路补堵（H5 读不到 baiduboxapp 段 → 农场进不去）
//   v57V  按 keychain 服务名精准拦截 cuid（修「下单人数多」）
//   v58   硬件人格一律回真机（假报大屏 → 小屏机页面错乱）
//   v59   keychain 全量命名空间隔离（克隆互不串味）
//   v60   隐藏注入痕迹：dyld 镜像枚举过滤 + 包标识伪装（v63 停用）
//   v61   回退 App Group 容器重定向 + UA 补缺（修「选不了榴莲」）
//   v62   group 域整域隔离（swizzle initWithSuiteName: + CFPreferences 换 appID）
//   v63   停用 v60 两段（修 v62 启动闪退）+ cloneTag 重入保护
//   v64   隔离粒度收窄到「身份键」——整域隔离会让共享域 72 键全读不到，
//         果园这类 H5 活动页拿不到渠道/活动参数 →「能进但选不了水果」。
//         改为 init 不改域名 + 按 key 分流：身份键走私有域，其余走共享域。
//   v65   对照实验：整体关闭 keychain 隔离。用户实测 → 原版 App 被
//         连坐拉黑 → keychain 隔离是保命机制，不能关。
//   v66   keychain 恢复隔离 + 非身份项读回退（T4 教训：共身份→连坐拉黑）
//   v67   cuid 双格式修复：平台层 cuid 用真机 40大写HEX+尾格式（PLATCUID），
//         cookie 层保持 b64url —— 两套 ID 本来就不同
//   v68   诊断日志（T7）：果园相关请求/响应写 bd_diag.log
//   v69   诊断增强（T7b）：delegate 型请求 + 响应体 + JSBridge 名单
//   v70   硬件人格回归（iPhone13,2）：下单通过但农场识破——真机是 13 Pro Max
//         （屏幕 1284×2778 透传），与 iPhone12 机型串矛盾
//   v71   人格改 iPhone13,4（12 Pro Max）：与真机同屏同内存，透传值全部自洽
//   v72   ★ 泄漏点修复（2026-09-21 审计）★
//         P0: UIPasteboard 克隆私有化（TalosPro 风控 SDK 在用，跨 App 串号）
//         P0: keychain 身份关键字补 mtj/cdid/umid/oaid/vaid/aaid（统计 SDK 串号）
//         P0: DCDevice/AppAttest 失败化（Apple 签名设备证明，绑定物理机）
//         P1: CNCopyCurrentNetworkInfo 返空（家庭 WiFi BSSID 网络锚点）
//   v67   ★ cuid 双格式修复 ★ 真机取证发现平台层 cuid（plist/keychain）
//         = 40位大写HEX+11位尾巴（51字符），与 cookie BAIDUCUID（b64url
//         ~70字符）是**两个不同的 ID**。旧实现把 cookie 格式顶给了平台层
//         → 服务端识别非法 cuid → 果园不下发浏览任务。新增 genPlatform
//         CUID()，NSUserDefaults/keychain 层改用平台格式，cookie 层不变。
//
// ============ v60 设计（当前） ============
//
// 堵两条已知暴露面：
//   1) dyld 枚举 —— 主可执行里有 _dyld_image_count /
//      _dyld_get_image_name / _dyld_get_image_header /
//      _dyld_get_image_vmaddr_slide。任何一次完整枚举都能看到
//      注入的 BaiduBoxSys.dylib（镜像数 +1、多一条陌生路径）。
//      → 对外 count 减 1，并做「对外索引 → 真实索引」重映射，
//        跳过隐藏项，遍历结果依旧连续完整。
//   2) 包标识 —— 多开必须改 bundle id，克隆是
//      com.baidu.BaiduMobile.BdD1，与官方不同，属重打包特征。
//      → 读取侧（bundleIdentifier / infoDictionary /
//        objectForInfoDictionaryKey / CFBundleGetIdentifier）
//        一律返回官方值；克隆后缀改走 realBundleIdentifier()。
//
// 身份伪造（cuid/UDID/IDFV/ECID/设备名）与 v59 隔离机制维持不变。
//
// 保留教训（不重蹈覆辙）：
//   不 hook sysctl() 旧 API（闪退）；不 hook setURL:/setHTTPBody:（签名错误）；
//   fishhook 覆盖所有非系统镜像 + dyld 回调；dyld 回调用全局 C 函数；
//   持久化用 CFPreferences 不用 NSUserDefaults；-Xlinker -no_fixup_chains。
//   返回结构体的方法严禁用 imp_implementationWithBlock（走 sret，ABI 无保证）。
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <Security/Security.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <string.h>
#include "fishhook.h"

// ============================================================
// MT_CLONE — 美团多开构建开关（2026-09-21）
//   1 = 美团多开（禁用百度专属 hook：WKWebView UA / NSMutableURLRequest UA 补段等）
//   0 = 百度多开（D/E/T/P 系列）
// ★ 由 Makefile 决定：默认 0；美团构建目标 $(DYLIB_MT) 传 -DMT_CLONE=1。
//   不要在这里硬编码——否则另一系重建时静默翻车。
// dylib 产物下载后本地留档（百度 = dylib_v72/，美团 = dylib_mt/），互不覆盖。
// ============================================================
#ifndef MT_CLONE
#define MT_CLONE 0
#endif

#define NSLog(...)

static __thread BOOL g_inCookieHook = NO;
static BOOL g_inUDHook = NO;

// ============================================================
// ★ v66: keychain 隔离恢复 + 非身份项读回退 ★
//
// v65 对照实验结论（用户实测）：关掉 keychain 隔离后，克隆与原版
// 共用同一批 keychain 项（cuid/SToken/登录票据），**原版 App 被连坐
// 拉黑** → keychain 隔离是保命机制，绝不能关。
//
// 但 v59 的全量隔离把 keychain 里所有项都切到私有域，若某些
// 非身份配置项是原版写入的（克隆从未写过），克隆就读不到 → 功能
// 降级嫌疑（果园不对劲从 v59 开始）。
//
// v66 策略：
//   写（Add/Update）/ 删（Delete）：始终落在本克隆后缀域 ——
//     克隆永远不写共享域，原版绝不被污染。
//   读（CopyMatching）：
//     身份/登录类项（isIdentityKeychainDict）→ 只读后缀域，绝不
//       回读共享域（防串号、防连坐 —— T4 的教训）。
//     非身份类项 → 先读后缀域；读不到（errSecItemNotFound）再
//       回读共享域原样项。读到的数据仍走 rewriteIdentityData
//       出口消毒，身份字符串照样替换。
// ============================================================
#define BD_KCHAIN_NS_ISOLATION 1
#define BD_KCHAIN_READTHROUGH 1

// ============================================================
// ★ 硬件人格策略（v58 起变更）
// v57N-v57V: 全套伪造 iPhone15,3 / iOS 17.6.1 / 6GB / 430x932
//   → XS 实测「页面变大」（UIScreen 假尺寸是根因）。
// v58: 硬件全部跟真机（机型/系统/内存/屏幕透传真值，全通道自洽），
//   只伪造身份（cuid/UDID/IDFV/ECID/设备名/序列号置空）。
//   实测已证明百度风控认 cuid 不认硬件指纹（D1 与原版同机均可下单）。
// 下方 FAKE_* 常量仅被未启用的 uname/sysctl hook 引用，保留备查。
// ============================================================
static const char *FAKE_MACHINE   = "iPhone13,4";        // v71: 12 Pro Max —— 与真机 13 Pro Max 同屏 428×926/1284×2778、同 6GB 内存，透传值零矛盾
static const char *FAKE_OSVER     = "17.6.1";            // 系统版本
static const char *FAKE_DARWIN    = "23.6.0";            // 对应 Darwin 内核版本
static const char *FAKE_PRODUCT   = "iPhone15,3";
static const char *FAKE_MODELNUM  = "MQ9G3CH/A";         // 14 Pro Max 国行型号
static const char *FAKE_UA_SUFFIX = "iPhone OS 17_6_1";  // UA 中的系统版本
static const uint64_t FAKE_MEMSIZE = 6ULL * 1024 * 1024 * 1024; // 6GB

// ============================================================
// fishhook 原函数指针
// ============================================================
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
static CFPropertyListRef (*orig_MGCopyAnswer)(CFStringRef key, CFDictionaryRef options) = NULL;
static __thread BOOL g_inMGHook = NO;

typedef unsigned int io_registry_entry_t;
static CFTypeRef (*orig_IORegistryEntryCreateCFProperty)(io_registry_entry_t, CFStringRef, CFAllocatorRef, uint32_t) = NULL;

// v72: WiFi 信息返空 —— SSID/BSSID 是家庭路由器锚点，所有克隆与原版一致，
// 服务端 IP+BSSID 聚类就能把新 bundle id 和被拉黑的原版连起来。
// iOS14+ 无定位权限本来也拿不到，返 NULL 不异常。
static CFArrayRef (*orig_CNCopyCurrentNetworkInfo)(CFStringRef) = NULL;
static CFArrayRef hook_CNCopyCurrentNetworkInfo(CFStringRef ifName) {
    (void)ifName;
    return NULL;
}

// ============ CFNetwork C 层 Cookie API ============
// iOS SDK 未公开 CFHTTPCookie 头文件（仅 macOS 公开），手动声明类型，
// 工具函数用 dlsym 运行时解析，hook 函数的 orig 指针由 fishhook 填充
typedef struct OpaqueCFHTTPCookie *CFHTTPCookieRef;
typedef struct OpaqueCFHTTPCookieStorage *CFHTTPCookieStorageRef;

// hook 的原函数（fishhook rebind 后由 fishhook 填充真实地址）
static void (*orig_CFHTTPCookieStorageSetCookie)(CFHTTPCookieStorageRef, CFHTTPCookieRef) = NULL;
static void (*orig_CFHTTPCookieStorageSetCookies)(CFHTTPCookieStorageRef, CFArrayRef, CFURLRef) = NULL;
static CFArrayRef (*orig_CFHTTPCookieStorageCopyCookiesForURL)(CFHTTPCookieStorageRef, CFURLRef, CFURLRef) = NULL;
static CFArrayRef (*orig_CFHTTPCookieStorageCopyAllCookies)(CFHTTPCookieStorageRef) = NULL;

// 工具函数（dlsym 运行时解析，避免链接依赖）
static CFStringRef (*p_CFHTTPCookieCopyName)(CFHTTPCookieRef) = NULL;
static CFStringRef (*p_CFHTTPCookieCopyValue)(CFHTTPCookieRef) = NULL;
static CFDictionaryRef (*p_CFHTTPCookieCopyProperties)(CFHTTPCookieRef) = NULL;
static CFHTTPCookieRef (*p_CFHTTPCookieCreateWithProperties)(CFAllocatorRef, CFDictionaryRef) = NULL;

static void init_cf_cookie_syms(void) {
    if (p_CFHTTPCookieCopyName) return;
    void *h = dlopen("/System/Library/Frameworks/CFNetwork.framework/CFNetwork", RTLD_LAZY);
    if (!h) h = dlopen(NULL, RTLD_LAZY); // 兜底：在已加载镜像中查找
    if (!h) return;
    p_CFHTTPCookieCopyName = dlsym(h, "CFHTTPCookieCopyName");
    p_CFHTTPCookieCopyValue = dlsym(h, "CFHTTPCookieCopyValue");
    p_CFHTTPCookieCopyProperties = dlsym(h, "CFHTTPCookieCopyProperties");
    p_CFHTTPCookieCreateWithProperties = dlsym(h, "CFHTTPCookieCreateWithProperties");
}

// CFPreferences suite 域隔离（防 App Group 共享容器泄露设备指纹）
static CFPropertyListRef (*orig_CFPreferencesCopyAppValue)(CFStringRef, CFStringRef) = NULL;
static CFPropertyListRef (*orig_CFPreferencesCopyValue)(CFStringRef, CFStringRef, CFStringRef, CFStringRef) = NULL;
static Boolean (*orig_CFPreferencesSetValue)(CFStringRef, CFPropertyListRef, CFStringRef, CFStringRef, CFStringRef) = NULL;
static void (*orig_CFPreferencesSetAppValue)(CFStringRef, CFPropertyListRef, CFStringRef) = NULL;

// 前向声明
static NSString *getPersistent(NSString *key, NSString *(^gen)(void));
static NSString *genUUIDStr(void);
static NSString *genDeviceName(void);
static NSString *getFakeID(NSString *name);
static BOOL isDeviceCookie(NSString *cookieName);
static NSString *canonicalCookieKey(NSString *name);
static BOOL isSessionCookie(NSString *cookieName);
static void captureRealIdentity(NSString *name, NSString *value);
static NSString *rewriteIdentityString(NSString *s);
static NSData *rewriteIdentityData(NSData *d);
static NSString *fakeCUIDValue(void);
static NSString *cloneTag(void);
static NSString *mapGroupSuite(NSString *suite);
static CFStringRef mapGroupAppID(CFStringRef appID);
static BOOL isCuidServiceDict(CFDictionaryRef dict);
static NSData *fakeCUIDDataFrom(NSData *realData);
static void forceCuidInResultDict(CFMutableDictionaryRef md);

// ============================================================
// v60-A: 隐藏注入痕迹 —— dyld 镜像枚举过滤
//
// 背景：主可执行里实测存在 _dyld_image_count / _dyld_get_image_name /
// _dyld_get_image_header / _dyld_get_image_vmaddr_slide（各 2~3 处）。
// 任何一次完整枚举都会看到注入的 BaiduBoxSys.dylib —— 镜像总数 +1，
// 且多出一条陌生路径，是最直白的「被注入」证据。
//
// 做法：对外把 count 减 1，并把「对外索引」重映射到「真实索引」
// （跳过隐藏项）。App 遍历 0..count-1 拿到的仍是连续完整的列表。
//
// ⚠️ 隐藏判定只能调用 orig_*，否则自我递归 / 索引错位。
// ⚠️ 这几个 API 自身的 GOT 也会被替换，所以安装 rebind 时必须先用
//    局部数组把 (header, slide) 收全，再统一替换（见构造函数 7d）。
// ============================================================
static uint32_t (*orig_dyld_image_count)(void) = NULL;
static const char *(*orig_dyld_get_image_name)(uint32_t) = NULL;
static const struct mach_header *(*orig_dyld_get_image_header)(uint32_t) = NULL;
static intptr_t (*orig_dyld_get_image_vmaddr_slide)(uint32_t) = NULL;

#define HIDDEN_IMAGE_COUNT 1
#if MT_CLONE
static const char *g_hiddenImageKeys[HIDDEN_IMAGE_COUNT] = { "MtKit.dylib" };       // 美团克隆内嵌名
#else
static const char *g_hiddenImageKeys[HIDDEN_IMAGE_COUNT] = { "BaiduBoxSys.dylib" }; // 百度克隆内嵌名
#endif

static int isHiddenImageIndex(uint32_t idx) {
    if (!orig_dyld_get_image_name) return 0;
    const char *n = orig_dyld_get_image_name(idx);
    if (!n) return 0;
    for (int i = 0; i < HIDDEN_IMAGE_COUNT; i++) {
        if (strstr(n, g_hiddenImageKeys[i])) return 1;
    }
    return 0;
}

static uint32_t hook_dyld_image_count(void) {
    if (!orig_dyld_image_count) return 0;
    uint32_t total = orig_dyld_image_count();
    uint32_t hidden = 0;
    for (uint32_t i = 0; i < total; i++) {
        if (isHiddenImageIndex(i)) hidden++;
    }
    return total - hidden;
}

static uint32_t mapImageIndex(uint32_t outIdx) {
    if (!orig_dyld_image_count) return outIdx;
    uint32_t total = orig_dyld_image_count();
    uint32_t seen = 0;
    for (uint32_t i = 0; i < total; i++) {
        if (isHiddenImageIndex(i)) continue;
        if (seen == outIdx) return i;
        seen++;
    }
    return outIdx;   // 越界：透传，交给系统自己报错
}

static const char *hook_dyld_get_image_name(uint32_t idx) {
    if (!orig_dyld_get_image_name) return NULL;
    return orig_dyld_get_image_name(mapImageIndex(idx));
}

static const struct mach_header *hook_dyld_get_image_header(uint32_t idx) {
    if (!orig_dyld_get_image_header) return NULL;
    return orig_dyld_get_image_header(mapImageIndex(idx));
}

static intptr_t hook_dyld_get_image_vmaddr_slide(uint32_t idx) {
    if (!orig_dyld_get_image_vmaddr_slide) return 0;
    return orig_dyld_get_image_vmaddr_slide(mapImageIndex(idx));
}

#define HIDE_REBIND_COUNT 4
#define HIDE_MAX_IMG      512
static struct rebinding g_hide_rebindings[HIDE_REBIND_COUNT];

// ============================================================
// v60-B: 包标识伪装 —— 对外一律报告官方 bundle id
//
// 背景：多开必须改 bundle id（同 id 无法共存），克隆是
// "com.baidu.BaiduMobile.BdD1"，官方是 "com.baidu.BaiduMobile"。
// 主可执行里 bundleIdentifier 选择器 5 处、CFBundleIdentifier 4 处、
// objectForInfoDictionaryKey 1 处。改包名本就是重打包检测的经典特征。
//
// 做法：读取侧全部返回官方值。
// ⚠️ 克隆后缀（keychain 命名空间）必须改走 realBundleIdentifier()，
//    绝不能再取被 hook 后的值 —— 否则每个克隆算出的后缀都会变成
//    "BaiduMobile"，v59 的隔离当场失效（所有克隆挤进同一命名空间）。
// ============================================================
#define OFFICIAL_BUNDLE_ID "com.baidu.BaiduMobile"

static NSString *(*orig_bundleIdentifier)(id, SEL) = NULL;
static NSDictionary *(*orig_infoDictionary)(id, SEL) = NULL;
static id (*orig_objectForInfoDictionaryKey)(id, SEL, NSString *) = NULL;
static CFStringRef (*orig_CFBundleGetIdentifier)(CFBundleRef) = NULL;

// 取真实 bundle id（绕过 hook）—— 只给 cloneTag 用
static NSString *realBundleIdentifier(void) {
    if (orig_bundleIdentifier) {
        return orig_bundleIdentifier([NSBundle mainBundle], @selector(bundleIdentifier));
    }
    return [[NSBundle mainBundle] bundleIdentifier];
}

static BOOL isMainBundleObject(id bundle) {
    return (bundle != nil) && (bundle == [NSBundle mainBundle]);
}

static NSString *hook_bundleIdentifier(id self, SEL _cmd) {
    if (isMainBundleObject(self)) return @(OFFICIAL_BUNDLE_ID);
    if (orig_bundleIdentifier) return orig_bundleIdentifier(self, _cmd);
    return nil;
}

static NSDictionary *hook_infoDictionary(id self, SEL _cmd) {
    NSDictionary *d = orig_infoDictionary ? orig_infoDictionary(self, _cmd) : nil;
    if (!d || !isMainBundleObject(self)) return d;
    static NSDictionary *cached = nil;          // infoDictionary 被高频调用，缓存一份
    if (!cached) {
        NSMutableDictionary *md = [d mutableCopy];
        if (md) {
            md[@"CFBundleIdentifier"] = @(OFFICIAL_BUNDLE_ID);
            cached = md;
        }
    }
    return cached ? cached : d;
}

static id hook_objectForInfoDictionaryKey(id self, SEL _cmd, NSString *key) {
    if (isMainBundleObject(self) && key && [key isEqualToString:@"CFBundleIdentifier"]) {
        return @(OFFICIAL_BUNDLE_ID);
    }
    if (orig_objectForInfoDictionaryKey) return orig_objectForInfoDictionaryKey(self, _cmd, key);
    return nil;
}

static CFStringRef hook_CFBundleGetIdentifier(CFBundleRef b) {
    if (b && b == CFBundleGetMainBundle()) return CFSTR(OFFICIAL_BUNDLE_ID);
    if (orig_CFBundleGetIdentifier) return orig_CFBundleGetIdentifier(b);
    return NULL;
}

// 给实例方法装 IMP，并把原实现存进 outOrig（传 &orig_xxx）
// class_addMethod 成功 = 本类原本没有该方法（继承自父类），新 IMP 直接生效；
// 返回 NO = 本类已有实现，走 method_setImplementation 覆盖。
// 这样绝不会误改父类的实现（NSBundle 的方法若来自父类，直接
// method_setImplementation 会污染所有子类）。
static void installInstanceMethod(Class cls, SEL sel, IMP newImp, void *outOrig) {
    if (!cls) return;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    IMP orig = method_getImplementation(m);
    if (outOrig) *(void **)outOrig = (void *)orig;
    if (!class_addMethod(cls, sel, newImp, method_getTypeEncoding(m))) {
        method_setImplementation(m, newImp);
    }
}

static void installBundleIdentifierHooks(void) {
    Class nb = objc_getClass("NSBundle");
    if (!nb) return;
    installInstanceMethod(nb, @selector(bundleIdentifier),
                          (IMP)hook_bundleIdentifier, &orig_bundleIdentifier);
    installInstanceMethod(nb, @selector(infoDictionary),
                          (IMP)hook_infoDictionary, &orig_infoDictionary);
    installInstanceMethod(nb, @selector(objectForInfoDictionaryKey:),
                          (IMP)hook_objectForInfoDictionaryKey, &orig_objectForInfoDictionaryKey);
}

// ============================================================
// 全局 rebindings — dyld 回调中需要访问（不能用 block 捕获）
// ============================================================
// v57T: 回退到 9 条 —— uname/sysctl/gethostname 三条 rebind 与
// v57R/v57S 启动闪退强相关（二分定位：Q.1 可启动，R/S 均闪退，
// 剩余可疑增量只有这 3 条 rebind + dlopen）。先保证能启动，
// 后续逐条加回以精确定位。
// hook 函数本体保留（未注册不影响体积），随时可恢复。
// v60: 13 → 14，新增 CFBundleGetIdentifier（包标识的 C 层读取入口）
// v63: 15 → 14 —— 移除 CFBundleGetIdentifier（v60 包标识伪装同批停用）
// v72: 16 → 17 —— 新增 CNCopyCurrentNetworkInfo（WiFi 锚点返空）
#define REBIND_COUNT 17
static struct rebinding g_rebindings[REBIND_COUNT];

// dyld 回调 — 动态加载的非系统镜像也 hook（必须用 C 函数，不能用 block）
static void hook_new_image(const struct mach_header *header, intptr_t slide) {
    if (!header) return;
    Dl_info info;
    if (dladdr(header, &info) && info.dli_fname) {
        const char *path = info.dli_fname;
        if (strncmp(path, "/usr/lib/", 9) == 0) return;
        if (strncmp(path, "/System/", 8) == 0) return;
        if (strncmp(path, "/Developer/", 11) == 0) return;
        rebind_symbols_image((void *)header, slide, g_rebindings, REBIND_COUNT);
        // v63: 不再装「隐藏」rebind —— 见构造函数 7d 的说明。
        // 动态加载的镜像若装了 dyld 枚举 hook，任何在新镜像里发起的
        // _dyld_image_count 调用都会走 O(n) 重映射，且与系统自身使用
        // 这些 API 的时序冲突，是启动崩溃的高危来源。
    }
}

// ============================================================
// sysctlbyname hook — v58 只消毒，不再伪造硬件人格
// 机型/内存/系统版本全部返回真值（跟真机，与 UIScreen/NSProcessInfo 自洽）
// 仅保留：序列号/UUID 置空（应用本来无权限，返回空不算异常）
// ============================================================
// 辅助：把 C 字符串写入 sysctl 输出缓冲（ZERO ObjC 调用）
static int hook_return_cstr(const char *val, void *oldp, size_t *oldlenp) {
    size_t need = strlen(val) + 1;
    if (oldlenp) {
        if (oldp && *oldlenp >= need) {
            memcpy(oldp, val, need);
        }
        *oldlenp = need;
    }
    return 0;
}

static int hook_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name) {
        // 序列号/UUID 清空（应用本来无权限，返回空不算异常）
        if (strcmp(name, "hw.serialnumber") == 0 || strcmp(name, "hw.uuid") == 0) {
            return hook_return_cstr("", oldp, oldlenp);
        }
        // v70/v71: hw.machine/hw.model 回伪人格。v71 改 iPhone13,4（12 Pro Max，
        //      与真机 13 Pro Max 同屏 1284×2778 同 6GB）—— v70 用 iPhone13,2
        //      被农场识破：请求里 cua@1284_2778/statusbar-height 等真屏幕参数
        //      与 iPhone12 的 1170×2532 矛盾，物理不存在的组合。
        if (strcmp(name, "hw.machine") == 0 || strcmp(name, "hw.model") == 0) {
            return hook_return_cstr(FAKE_MACHINE, oldp, oldlenp);
        }
        // kern.osproductversion / kern.osversion / kern.osrelease /
        // hw.memsize 全部透传真值 —— 与 12 Pro Max 人格自洽（6GB/同系统区间）
    }
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

// ============================================================
// ★★ v57R 关键补漏：uname / sysctl / gethostname ★★
//
// 二进制扫描确认：App 引用 uname 32 次、sysctl 9 次、gethostname 2 次。
// 此前只 hook 了 sysctlbyname —— 而 iOS 的 uname().machine 返回的是
// 真实机型（如 iPhone14,3），sysctl(CTL_HW, HW_MACHINE) 同理。
// 于是出现：sysctlbyname 说 iPhone15,3，uname 说 iPhone14,3 ——
// 同一设备两条通道两个答案，是最典型的篡改特征。
// 伪造人格再自洽，漏了这条通道就等于全盘暴露。
//
// 教训（务必遵守）：
//   1. 三个 hook 全部纯 C、零 ObjC 调用（可能在极早期被调用）
//   2. sysctl 只拦截明确的 MIB，其余全部透传（此前盲目 hook 闪退）
//   3. newp != NULL 是写操作，永远透传
// ============================================================
static int (*orig_uname)(struct utsname *) = NULL;
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t) = NULL;
static int (*orig_gethostname)(char *, size_t) = NULL;

static int hook_uname(struct utsname *u) {
    if (!orig_uname) return -1;                 // 防护：未绑定绝不能解引用
    if (!u) return orig_uname(u);
    int r = orig_uname(u);          // 先调真实版保证缓冲区有效，再覆盖
    if (r != 0) return r;
    // v70: 只覆盖 nodename（防真实设备名泄漏）和 machine（机型人格）。
    // sysname/release/version 保留真实值 —— 与 sysctlbyname 的
    // kern.osrelease（透传真值）保持自洽，不能再用写死的 FAKE_DARWIN。
    strlcpy(u->nodename, "iPhone",      sizeof(u->nodename));
    strlcpy(u->machine,  FAKE_MACHINE,  sizeof(u->machine));
    return 0;
}

// sysctl() 旧 API —— 只拦这几项，其余透传
// MIB 常量（Darwin 稳定值，直接用数字避免头文件差异）：
//   CTL_KERN=1  CTL_HW=6
//   KERN_OSTYPE=1  KERN_OSRELEASE=2  KERN_HOSTNAME=10
//   HW_MACHINE=1   HW_MODEL=2
static int hook_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
                       void *newp, size_t newlen) {
    if (!orig_sysctl) return -1;                // 防护：未绑定绝不能解引用
    if (!name || namelen != 2 || newp != NULL) {
        return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    }
    // 防护：oldp 与 oldlenp 必须成对出现，缺一透传（调用方布局未知，不能猜）
    if (!oldlenp && oldp) {
        return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    }
    const int a = name[0], b = name[1];
    if (a == 6 && (b == 1 || b == 2)) {          // HW_MACHINE / HW_MODEL
        return hook_return_cstr(FAKE_MACHINE, oldp, oldlenp);
    }
    if (a == 1) {                                 // CTL_KERN
        if (b == 1)  return hook_return_cstr("Darwin",      oldp, oldlenp);
        if (b == 2)  return hook_return_cstr(FAKE_DARWIN,   oldp, oldlenp);
        if (b == 10) return hook_return_cstr("iPhone",      oldp, oldlenp);
    }
    return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}

static int hook_gethostname(char *name, size_t namelen) {
    if (!orig_gethostname) return -1;           // 防护：未绑定绝不能解引用
    if (!name || namelen == 0) return orig_gethostname(name, namelen);
    const char *fake = "iPhone";   // 出厂默认主机名，与 uname.nodename 一致
    // v57S: 任何分支都保证 '\0' 结尾 —— 截断后不留 '\0' 会让调用方
    // strlen() 越界读（EXC_BAD_ACCESS，且 @try 拦不住内存故障）
    size_t copy = strlen(fake);
    if (copy > namelen - 1) copy = namelen - 1;
    memcpy(name, fake, copy);
    name[copy] = '\0';
    return 0;
}

// ============================================================
// MGCopyAnswer hook — MobileGestalt 私有 API
// v57L: 只伪装唯一标识（UDID/序列号/ECID/设备名），其余全放行真实值
// （真实机型/系统与屏幕、UA 天然一致，不存在交叉矛盾）
// ============================================================
static CFPropertyListRef hook_MGCopyAnswer(CFStringRef key, CFDictionaryRef options) {
    if (!key || g_inMGHook) return orig_MGCopyAnswer(key, options);
    g_inMGHook = YES;
    @try {
        // UniqueDeviceID (UDID) — 核心唯一标识
        if (CFStringCompare(key, CFSTR("J1WLa1FfC0Dowb1A"), 0) == 0 ||
            CFStringCompare(key, CFSTR("UniqueDeviceID"), 0) == 0) {
            NSString *u = getPersistent(@"BdD1.udid", ^{ return genUUIDStr(); });
            g_inMGHook = NO;
            return (__bridge_retained CFPropertyListRef)u;
        }
        // SerialNumber — 空值（应用层本来无权限，返回空不算异常）
        if (CFStringCompare(key, CFSTR("h9jDsbgj7xIugkIB2RVp1cKoVBOyBj8r"), 0) == 0 ||
            CFStringCompare(key, CFSTR("SerialNumber"), 0) == 0) {
            g_inMGHook = NO;
            return CFRetain(CFSTR(""));
        }
        // UniqueChipID (ECID) — 64位芯片唯一码，v57k 漏掉的硬伤
        if (CFStringCompare(key, CFSTR("UniqueChipID"), 0) == 0) {
            uint64_t ecid = 0;
            NSString *s = getPersistent(@"BdD1.ecid", ^{
                uint64_t hi = ((uint64_t)arc4random() << 32) | (uint64_t)arc4random();
                return [NSString stringWithFormat:@"%llu", (unsigned long long)(hi & 0x00FFFFFFFFFFFFFFULL)];
            });
            ecid = [s longLongValue];
            g_inMGHook = NO;
            return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &ecid);
        }
        // DeviceName — 每克隆独立设备名
        if (CFStringCompare(key, CFSTR("wfiZJ9aJbL5A3hMOznwq7A"), 0) == 0 ||
            CFStringCompare(key, CFSTR("DeviceName"), 0) == 0) {
            NSString *n = getPersistent(@"BdD1.dn", ^{ return genDeviceName(); });
            g_inMGHook = NO;
            return (__bridge_retained CFPropertyListRef)n;
        }
        // v70/v71: ProductType —— 机型人格（v71 起 iPhone13,4），与 hw.machine/uname 保持一致
        if (CFStringCompare(key, CFSTR("ProductType"), 0) == 0) {
            g_inMGHook = NO;
            return (__bridge_retained CFPropertyListRef)[NSString stringWithUTF8String:FAKE_MACHINE];
        }
        // v70: PhysicalMachineModel（硬件板型号）同样归人格，防止与 machine 矛盾
        if (CFStringCompare(key, CFSTR("PhysicalMachineModel"), 0) == 0 ||
            CFStringCompare(key, CFSTR("HardwareModel"), 0) == 0) {
            g_inMGHook = NO;
            return (__bridge_retained CFPropertyListRef)[NSString stringWithUTF8String:FAKE_MACHINE];
        }
        // ---- v58: ProductType / ModelNumber / ProductVersion / BuildVersion
        //      不再伪造 —— 硬件人格跟真机，避免「XS 假报 Pro Max」的矛盾。
        //      身份类（UDID/Serial/ECID/DeviceName）仍伪造。
        // 地区码保持 CN（真机国行）
        g_inMGHook = NO;
    } @catch (id e) {
        g_inMGHook = NO;
    }
    return orig_MGCopyAnswer(key, options);
}

// ============================================================
// IOKit hook — 只伪装 IOPlatformUUID / IOPlatformSerialNumber
// ============================================================
static CFTypeRef hook_IORegistryEntryCreateCFProperty(io_registry_entry_t entry, CFStringRef key, CFAllocatorRef allocator, uint32_t options) {
    if (key) {
        if (CFStringCompare(key, CFSTR("IOPlatformUUID"), 0) == 0) {
            NSString *u = getPersistent(@"BdD1.iouuid", ^{ return genUUIDStr(); });
            return (__bridge_retained CFTypeRef)u;
        }
        if (CFStringCompare(key, CFSTR("IOPlatformSerialNumber"), 0) == 0) {
            return CFRetain(CFSTR(""));
        }
    }
    if (!orig_IORegistryEntryCreateCFProperty) return NULL;
    return orig_IORegistryEntryCreateCFProperty(entry, key, allocator, options);
}

// ============================================================
// C 层 Cookie 清洗 — 百度 SDK 绕过 ObjC 直调 CFNetwork 时兜底
// v57U: capture=YES 时先捕获 SDK 生成的原始值（真实身份）再替换。
// 只在写入路径（SetCookie/SetCookies）传 YES；读路径（Copy*）存的是
// 已替换的伪造值，捕获会污染真实值缓存。
// ============================================================
static CFHTTPCookieRef sanitizeCFCookie(CFHTTPCookieRef ck, BOOL capture) {
    if (!ck) return ck;
    init_cf_cookie_syms();
    if (!p_CFHTTPCookieCopyName || !p_CFHTTPCookieCopyProperties || !p_CFHTTPCookieCreateWithProperties) return ck;
    CFStringRef nm = p_CFHTTPCookieCopyName(ck);
    if (!nm) return ck;
    NSString *name = (__bridge_transfer NSString *)nm; // +1 transferred
    if (!isDeviceCookie(name)) return ck;              // 返回原引用（调用方判断相同则不 release）
    if (capture && p_CFHTTPCookieCopyValue) {
        CFStringRef vv = p_CFHTTPCookieCopyValue(ck);
        if (vv) {
            NSString *val = (__bridge_transfer NSString *)vv; // +1 transferred
            captureRealIdentity(name, val);
        }
    }
    CFDictionaryRef props = p_CFHTTPCookieCopyProperties(ck);
    if (!props) return ck;
    NSMutableDictionary *md = [(__bridge_transfer NSDictionary *)props mutableCopy]; // +1 transferred
    md[@"kCFHTTPCookieValue"] = getFakeID(name);  // kCFHTTPCookieValue 运行时值即该字符串
    CFHTTPCookieRef nc = p_CFHTTPCookieCreateWithProperties(kCFAllocatorDefault, (__bridge CFDictionaryRef)md);
    return nc; // +1，调用方负责 release（若与原引用不同）
}

static void hook_CFHTTPCookieStorageSetCookie(CFHTTPCookieStorageRef storage, CFHTTPCookieRef ck) {
    if (ck) {
        CFHTTPCookieRef nc = sanitizeCFCookie(ck, YES);
        orig_CFHTTPCookieStorageSetCookie(storage, nc ? nc : ck);
        if (nc && nc != ck) CFRelease(nc);
        return;
    }
    orig_CFHTTPCookieStorageSetCookie(storage, ck);
}

static void hook_CFHTTPCookieStorageSetCookies(CFHTTPCookieStorageRef storage, CFArrayRef cookies, CFURLRef mainDoc) {
    if (cookies && CFArrayGetCount(cookies) > 0) {
        CFMutableArrayRef out = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        for (CFIndex i = 0; i < CFArrayGetCount(cookies); i++) {
            CFHTTPCookieRef ck = (CFHTTPCookieRef)CFArrayGetValueAtIndex(cookies, i);
            CFHTTPCookieRef nc = sanitizeCFCookie(ck, YES);
            if (nc) {
                CFArrayAppendValue(out, nc);
                if (nc != ck) CFRelease(nc);
            }
        }
        orig_CFHTTPCookieStorageSetCookies(storage, out, mainDoc);
        CFRelease(out);
        return;
    }
    orig_CFHTTPCookieStorageSetCookies(storage, cookies, mainDoc);
}

static CFArrayRef hook_CFHTTPCookieStorageCopyCookiesForURL(CFHTTPCookieStorageRef storage, CFURLRef url, CFURLRef mainDoc) {
    CFArrayRef arr = orig_CFHTTPCookieStorageCopyCookiesForURL(storage, url, mainDoc);
    if (!arr || CFArrayGetCount(arr) == 0) return arr;
    CFMutableArrayRef out = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    for (CFIndex i = 0; i < CFArrayGetCount(arr); i++) {
        CFHTTPCookieRef ck = (CFHTTPCookieRef)CFArrayGetValueAtIndex(arr, i);
        CFHTTPCookieRef nc = sanitizeCFCookie(ck, NO);
        if (nc) {
            CFArrayAppendValue(out, nc);
            if (nc != ck) CFRelease(nc);
        }
    }
    CFRelease(arr);
    return out;
}

static CFArrayRef hook_CFHTTPCookieStorageCopyAllCookies(CFHTTPCookieStorageRef storage) {
    CFArrayRef arr = orig_CFHTTPCookieStorageCopyAllCookies(storage);
    if (!arr || CFArrayGetCount(arr) == 0) return arr;
    CFMutableArrayRef out = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    for (CFIndex i = 0; i < CFArrayGetCount(arr); i++) {
        CFHTTPCookieRef ck = (CFHTTPCookieRef)CFArrayGetValueAtIndex(arr, i);
        CFHTTPCookieRef nc = sanitizeCFCookie(ck, NO);
        if (nc) {
            CFArrayAppendValue(out, nc);
            if (nc != ck) CFRelease(nc);
        }
    }
    CFRelease(arr);
    return out;
}

// ============================================================
// CFPreferences suite 域隔离 — App Group 共享容器防泄露
// 若克隆间共享 App Group（entitlement 泄露），SDK 可通过 group.* 域
// 读写共享设备指纹 → 全部重定向到本克隆私有域，物理隔离
//
// ★★ v62 重写（实测驱动）★★
// v57U~v61 的方案是「key 加前缀 + 塞进 kCFPreferencesCurrentApplication」，
// 真机验证结果：**完全没生效**。取证（Filza 直读设备文件）：
//   共享容器 .../Shared/AppGroup/E2DB4240.../Library/Preferences/
//        group.com.baidu.BaiduMobile.plist          → 72 键，含
//        cuid / devuid / idfv / user_id / is_login / SAPI_LOCAL_STTOKEN
//   克隆沙盒 .../Data/Application/<uuid>/Library/Preferences/
//        group.com.baidu.BaiduMobile.BdE1.plist     → 6 键，无任何身份键
// 根因：百度用 NSUserDefaults(suiteName:)，底层走 Foundation 内部的
//   私有函数 _CFPreferences*WithContainer —— 系统库内部调用，
//   fishhook 重绑定公开符号根本够不到。
//
// v62 改为在 **suiteName 层面** 隔离：把 group 域名字加后缀，
//   group.com.baidu.BaiduMobile → group.com.baidu.BaiduMobile.BdE1
// iOS 对「未在 entitlement 声明的 group 名」会当作普通域处理，
// 文件落在 App 自己的沙盒 Library/Preferences/ 下 —— 天然按克隆隔离，
// 且目录/机制由系统保证，无 v59「只拼路径不建目录」之虞。
// 真机已存在 group.com.baidu.BaiduMobile.BdD6.plist 这类文件，
// 证明该形态 iOS 接受。
// ============================================================
static BOOL isGroupDomain(CFStringRef appID) {
    if (!appID) return NO;
    NSString *dom = (__bridge NSString *)appID;
    return [dom hasPrefix:@"group."] || [dom hasPrefix:@"group:"];
}

// 后缀：cloneTag() 是 "#BdE1"，文件名里去掉 '#'（真机验证过的形态用 '.'）
static NSString *groupSuffix(void) {
    NSString *tag = cloneTag();
    if ([tag hasPrefix:@"#"]) return [tag substringFromIndex:1];
    return tag;
}

// 把 group 域映射为「本克隆私有域」；非 group 域返回 nil（表示不改写）
static NSString *mapGroupSuite(NSString *suite) {
    if (!suite || suite.length == 0) return nil;
    if (!isGroupDomain((__bridge CFStringRef)suite)) return nil;
    NSString *suf = groupSuffix();
    if (suf.length == 0) return nil;
    if ([suite hasSuffix:suf]) return nil;          // 已映射，幂等
    return [suite stringByAppendingFormat:@".%@", suf];
}

// CFStringRef 版本：需要改写时返回 +1 的映射值，调用方负责 release
static CFStringRef mapGroupAppID(CFStringRef appID) {
    if (!appID) return NULL;
    NSString *mapped = mapGroupSuite((__bridge NSString *)appID);
    if (!mapped) return NULL;
    return (__bridge_retained CFStringRef)mapped;
}

// ============================================================
// ★ v64: 按键精准隔离（取代 v62 的 group 域整域隔离）
//
// v62 把 group 域整体指到本克隆私有域。真机取证（Filza WebDAV 直读）：
//   共享域 group.com.baidu.BaiduMobile.plist        72 键
//   克隆私有域 group.com.baidu.BaiduMobile.BdD6.plist  5~6 键（只有 SAPI 登录态）
// → channel_prefix / BDPOpenWidgetCommonParams / 成长权益 / 位置历史 /
//   Widget 数据 等 60 多个 **非身份** 键全部读不到。
// 果园是跑在 WKWebView 里的 H5 活动页，初始化要读渠道与活动参数，
// 症状就是「能进果园，但选不了水果」。
//
// v64 只把「设备/账号标识」这一类键重定向到私有域，其余键一律继续
// 读写共享域（等价 v61 的可用行为）：
//   身份各克隆独立（防关联）+ 功能数据完整（果园可用）。
// ============================================================
static BOOL isStrictIdentityKeyStr(NSString *k) {
    if (k.length == 0) return NO;
    static NSSet *exact = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        exact = [NSSet setWithArray:@[
            @"cuid", @"devuid", @"idfv", @"user_id", @"is_login", @"bdpanCookie",
            @"BNPush_cuid", @"BNPush_cacheCuid", @"BNPush_token", @"BNPush_channelid",
        ]];
    });
    if ([exact containsObject:k]) return YES;
    if ([k rangeOfString:@"cuid" options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
    return NO;
}

static BOOL isStrictIdentityKey(CFStringRef key) {
    if (!key) return NO;
    return isStrictIdentityKeyStr((__bridge NSString *)key);
}

// ---- v64: NSUserDefaults 私有域镜像（按键重定向用）----
static IMP g_origISS = NULL;              // 原始 -[NSUserDefaults initWithSuiteName:]
static char kUDGroupSuiteKey;             // 关联对象 key：记录实例的 group 域名
static BOOL g_inPrivPeer = NO;            // 私有域实例构造重入哨兵

// 用原始 IMP 构造实例，绕过 swizzle（不打标记、不递归）
static NSUserDefaults *udRaw(NSString *suite) {
    if (!g_origISS || suite.length == 0) return nil;
    Class uc = objc_getClass("NSUserDefaults");
    if (!uc) return nil;
    id o = [uc alloc];
    return ((id (*)(id, SEL, NSString *))g_origISS)(o, @selector(initWithSuiteName:), suite);
}

// 取该 group 域实例对应的「本克隆私有域」实例（惰性建、缓存）
static NSUserDefaults *privPeerFor(id s) {
    // 重入保护：udRaw 构造实例时可能再次走到本函数（swizzle 是类级别的），
    // 不设哨兵会无限递归 → 栈溢出闪退（v62 的 NSBundle 递归是同类教训）。
    if (!s || g_inPrivPeer) return nil;
    NSString *suite = objc_getAssociatedObject(s, &kUDGroupSuiteKey);
    if (suite.length == 0) return nil;
    NSString *mapped = mapGroupSuite(suite);
    if (mapped.length == 0) return nil;
    static NSMutableDictionary *cache = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ cache = [NSMutableDictionary new]; });
    @synchronized (cache) {
        NSUserDefaults *d = cache[mapped];
        if (d) return d;
        g_inPrivPeer = YES;
        @try {
            d = udRaw(mapped);
            if (d) cache[mapped] = d;
        } @catch (id e) {}
        g_inPrivPeer = NO;
        return d;
    }
}

// v57U: 出口消毒 —— 返回的字符串若含本机真实身份值则替换
// （SDK 把真实 cuid 缓存在 NSUserDefaults/CFPreferences 里，读出来
//   就拼进请求参数。按值替换，不做 key 名猜测。）
// 注意：我们自己的键（BdD1.*，含真实值缓存）必须排除，否则 rewrite
// 拿到的"真实值"会被自己换成伪造值，逻辑失效。
static CFPropertyListRef sanitizeIdentityPList(CFPropertyListRef v) {
    if (!v) return v;
    if (CFGetTypeID(v) != CFStringGetTypeID()) return v;
    NSString *s = (__bridge NSString *)v;
    NSString *r = rewriteIdentityString(s);
    if (r == s) return v;
    return (__bridge_retained CFPropertyListRef)r;   // 调用方持有 +1
}

static BOOL isOwnPrefKey(CFStringRef key) {
    if (!key) return NO;
    return [( __bridge NSString *)key hasPrefix:@"BdD1."];
}

// v57V: 按键名拦截 —— key 含 "cuid" 且值为短字符串 → 强制返回伪造 cuid
// （SAPICUIDKit 等也走 CFPreferences/NSUserDefaults 持久化 cuid）
static CFPropertyListRef sanitizePrefValueForKey(CFStringRef key, CFPropertyListRef v) {
    if (!v || !key) return v;
    if (isOwnPrefKey(key)) return v;
    if (CFGetTypeID(v) != CFStringGetTypeID()) return v;
    NSString *k = (__bridge NSString *)key;
    if ([k rangeOfString:@"cuid" options:NSCaseInsensitiveSearch].location == NSNotFound) return v;
    NSString *s = (__bridge NSString *)v;
    if (s.length < 16 || s.length > 128) return v;      // cuid 合理长度
    NSString *fake = fakeCUIDValue();
    if ([s isEqualToString:fake]) return v;             // 已是伪造值
    captureRealIdentity(@"BAIDUCUID", s);               // 顺带捕获真实值兜底
    return (__bridge_retained CFPropertyListRef)fake;   // 调用方持有 +1
}

static CFPropertyListRef hook_CFPreferencesCopyAppValue(CFStringRef key, CFStringRef appID) {
    // v64: 只有身份键才改 appID（读本克隆私有域）；功能键保持原域，功能不受影响。
    CFStringRef mapped = isStrictIdentityKey(key) ? mapGroupAppID(appID) : NULL;
    CFPropertyListRef v = orig_CFPreferencesCopyAppValue(key, mapped ? mapped : appID);
    if (mapped) CFRelease(mapped);
    if (isOwnPrefKey(key)) return v;
    v = sanitizePrefValueForKey(key, v);
    return sanitizeIdentityPList(v);
}

static CFPropertyListRef hook_CFPreferencesCopyValue(CFStringRef key, CFStringRef appID, CFStringRef user, CFStringRef host) {
    CFStringRef mapped = isStrictIdentityKey(key) ? mapGroupAppID(appID) : NULL;
    CFPropertyListRef v = orig_CFPreferencesCopyValue(key, mapped ? mapped : appID, user, host);
    if (mapped) CFRelease(mapped);
    if (isOwnPrefKey(key)) return v;
    v = sanitizePrefValueForKey(key, v);
    return sanitizeIdentityPList(v);
}

// ============================================================
// v57U: keychain 出口消毒 — SecItemCopyMatching
// 同团队签名的 App 共享 keychain 访问组（百度系 App 全家桶），
// 克隆版能直接读到原版 App 存的本机真实设备 ID。
// 不做查询过滤（避免破坏登录凭证），只按「值」消毒：
// 返回的数据/字典里若含真实 CUID/BAIDUID → 替换为伪造值。
// ============================================================
static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef query, CFTypeRef *result) = NULL;
static OSStatus (*orig_SecItemAdd)(CFDictionaryRef attributes, CFTypeRef *result) = NULL;
static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) = NULL;
static OSStatus (*orig_SecItemDelete)(CFDictionaryRef query) = NULL;

// ---- v57V: keychain 服务名精准拦截 ----
// 二进制取证发现：
//   - keychain 共享组/服务名 "B83JBVZ6M5.com.baidu.baidumobile.cuid"
//   - SAPICUIDKit（百度原生 cuid 生成器）首启从真实硬件算 cuid 存 keychain
//   - 收银台反欺诈 BDNCashierSDKAntiFraudProcotol（下单环节）
// v57U 的按值替换依赖捕获，但原生 cuid 走 keychain 不经过 cookie 写路径，
// 捕获从未发生 → 替换从未生效。
// v57V 改为按「服务名」拦截：凡 kSecAttrService 含 "cuid" 的 keychain
// 读写，值一律替换为伪造 cuid（与 cookie 伪造值同源，单一身份）。
// 不再依赖捕获；同时顺带捕获真实值（若真出现）供按值替换兜底。

// 伪造 cuid（v67: keychain 里存的 cuid = 平台层格式 40大写HEX+尾，
// 与 plist cuid 一致；不再用 cookie 层的 b64url 格式）
static NSString *fakeCUIDValue(void) {
    return getFakeID(@"PLATCUID");
}

// 判断 keychain 查询/属性字典是否为 cuid 存储（服务名/账号名含 cuid）
static BOOL isCuidServiceDict(CFDictionaryRef dict) {
    if (!dict) return NO;
    const void *keys[] = { kSecAttrService, kSecAttrAccount, kSecAttrGeneric };
    for (size_t i = 0; i < 3; i++) {
        CFTypeRef v = CFDictionaryGetValue(dict, keys[i]);
        if (v && CFGetTypeID(v) == CFStringGetTypeID()) {
            NSString *s = (__bridge NSString *)v;
            if ([s rangeOfString:@"cuid" options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
        }
    }
    return NO;
}

// v66: 判断 keychain 项是否「身份/登录」类 —— 这类项绝不回读共享域。
// T4 实测教训：克隆读到原版的 cuid/SToken/登录票据 = 与原版共身份，
// 原版 App 直接被连坐拉黑。
// 关键字列表偏宽（宁可少回退、不冒串号风险）。
static BOOL isIdentityKeychainDict(CFDictionaryRef dict) {
    if (!dict) return NO;
    static NSArray *kw = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // v72: 补 mtj/cdid/umid/oaid/vaid/aaid —— 百度统计(MTJ)设备 ID 族，
        //       主二进制引用 40+ 处。缺了它们，克隆会按「非身份项」把原版
        //       存的统计设备 ID 读回退读进来 → 统计图谱直接关联
        kw = @[@"cuid", @"devuid", @"deviceid", @"device_id", @"idfv", @"idfa",
               @"udid", @"stoken", @"token", @"bduss", @"login", @"account",
               @"passport", @"sapi", @"user", @"ptoken", @"session",
               @"mtj", @"cdid", @"umid", @"oaid", @"vaid", @"aaid"];
    });
    const void *keys[] = { kSecAttrService, kSecAttrAccount, kSecAttrGeneric };
    for (size_t i = 0; i < 3; i++) {
        CFTypeRef v = CFDictionaryGetValue(dict, keys[i]);
        if (v && CFGetTypeID(v) == CFStringGetTypeID()) {
            NSString *s = (__bridge NSString *)v;
            for (NSString *k in kw) {
                if ([s rangeOfString:k options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
            }
        }
    }
    return NO;
}

// 捕获真实值（仅当不是我们自己的伪造值，防自毒）并返回伪造 data
static NSData *fakeCUIDDataFrom(NSData *realData) {
    @try {
        NSString *s = [[NSString alloc] initWithData:realData encoding:NSUTF8StringEncoding];
        if (s.length >= 16 && ![s isEqualToString:fakeCUIDValue()]) {
            captureRealIdentity(@"BAIDUCUID", s);
        }
    } @catch (id e) {}
    NSString *fake = fakeCUIDValue();
    return [fake dataUsingEncoding:NSUTF8StringEncoding] ?: realData;
}

// 从字典结果里强制替换 cuid 值（kSecValueData / kSecAttrGeneric）
static void forceCuidInResultDict(CFMutableDictionaryRef md) {
    const void *valKeys[] = { kSecValueData, kSecAttrGeneric };
    for (size_t i = 0; i < 2; i++) {
        CFDataRef vd = (CFDataRef)CFDictionaryGetValue(md, valKeys[i]);
        if (vd && CFGetTypeID(vd) == CFDataGetTypeID()) {
            NSData *nd = fakeCUIDDataFrom((__bridge NSData *)vd);
            CFDictionarySetValue(md, valKeys[i], (__bridge CFDataRef)nd);
        }
    }
}

// ============================================================
// ★ v59: keychain / App Group 全量命名空间隔离
//
// 原始 IPA entitlements（DER 实测）：
//   com.apple.security.application-groups = group.com.baidu.BaiduMobile
//   keychain-access-groups = B83JBVZ6M5.com.baidu.{shareLoginAccount,
//                            baidumobile.cuid, netdisk, lbsmap, mtjgroup}
// TrollStore 重签后这些字符串不变 → 所有克隆共享同一批 keychain 项
// 和同一个 App Group 容器目录。
// v57V 只拦 service 含 "cuid" 的项，其余（尤其 shareLoginAccount 里的
// 登录票据、mtjgroup 里的统计标识）克隆间互通 → 服务端可据此关联
// （实测：装/开 D2 后 D1 被判风险）。
//
// v59 方案：给所有 keychain 项的 service/account/generic 追加本克隆后缀，
// 读写两侧一致改写 → 各克隆物理互不可见，App 自身逻辑不受影响。
// App Group 容器同理：容器 URL 追加克隆专属子目录。
// ============================================================
static NSString *cloneTag(void) {
    static NSString *tag = nil;
    if (tag) return tag;
    // v63: 重入保护。
    // 本函数现在会在 initWithSuiteName: / CFPreferences / keychain hook
    // 内部被调用，可能落在非常早、非常深的调用栈上（例如 Foundation
    // 初始化 NSUserDefaults 的过程中）。原实现「算完才赋值」，一旦
    // 计算路径重新回到本函数（tag 仍为 nil）就是无限递归 → 爆栈闪退。
    // 计算前先立哨兵，重入时直接返回哨兵值而不是再算一遍。
    static BOOL computing = NO;
    if (computing) return @"#BdInit";
    computing = YES;
    NSString *bid = realBundleIdentifier() ?: @"unknown";
    NSArray *parts = [bid componentsSeparatedByString:@"."];
    NSString *last = parts.count ? parts.lastObject : @"unknown";
    tag = [NSString stringWithFormat:@"#%@", last];
    computing = NO;
    return tag;
}

// 改写 keychain 字典的标识字段（返回 +1；无需改写时返回原字典的 retain）
static CFDictionaryRef mangleKeychainDict(CFDictionaryRef dict) {
    if (!dict) return NULL;
#if !BD_KCHAIN_NS_ISOLATION
    // v65 对照实验曾整体关闭 keychain 隔离（本分支未编译保留备查）。
    // 用户实测结论：关闭后克隆与原版共身份 → 原版被连坐拉黑。
    // v66 恢复隔离（=1），读侧改用「非身份项读回退」保功能兼容。
    return CFRetain(dict);
#else
    const void *idKeys[] = { kSecAttrService, kSecAttrAccount, kSecAttrGeneric };
    NSString *tag = cloneTag();
    BOOL need = NO;
    for (size_t i = 0; i < 3; i++) {
        CFTypeRef v = CFDictionaryGetValue(dict, idKeys[i]);
        if (v && CFGetTypeID(v) == CFStringGetTypeID()) {
            if (![(__bridge NSString *)v hasSuffix:tag]) { need = YES; break; }
        }
    }
    if (!need) return CFRetain(dict);
    CFMutableDictionaryRef md = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, dict);
    for (size_t i = 0; i < 3; i++) {
        CFTypeRef v = CFDictionaryGetValue(dict, idKeys[i]);
        if (v && CFGetTypeID(v) == CFStringGetTypeID()) {
            NSString *s = (__bridge NSString *)v;
            if (![s hasSuffix:tag]) {
                CFDictionarySetValue(md, idKeys[i],
                    (__bridge CFStringRef)[s stringByAppendingString:tag]);
            }
        }
    }
    return md;
#endif
}

// 结果字典里隐藏克隆后缀（App 若自检 service 不会看出异常）
static void stripTagInResultDict(CFMutableDictionaryRef md) {
    if (!md) return;
    NSString *tag = cloneTag();
    const void *idKeys[] = { kSecAttrService, kSecAttrAccount, kSecAttrGeneric };
    for (size_t i = 0; i < 3; i++) {
        CFTypeRef v = CFDictionaryGetValue(md, idKeys[i]);
        if (v && CFGetTypeID(v) == CFStringGetTypeID()) {
            NSString *s = (__bridge NSString *)v;
            if ([s hasSuffix:tag] && s.length > tag.length) {
                NSString *ns = [s substringToIndex:s.length - tag.length];
                CFDictionarySetValue(md, idKeys[i], (__bridge CFStringRef)ns);
            }
        }
    }
}

static OSStatus hook_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    BOOL targeted = isCuidServiceDict(query);   // v57V: 按服务名精准拦截
    BOOL identity = targeted || isIdentityKeychainDict(query);   // v66
    CFDictionaryRef mq = mangleKeychainDict(query);   // v59: 命名空间隔离
    OSStatus st = orig_SecItemCopyMatching(mq ? mq : query, result);
    if (mq) CFRelease(mq);
#if BD_KCHAIN_READTHROUGH
    // v66: 非身份项读回退 —— 本克隆后缀域没有该条目时，回读共享域原样项。
    // 身份/登录类绝不回退（T4 教训：读到原版身份 = 连坐拉黑）。
    // 回退命中的结果照走下方出口消毒（rewriteIdentityData / stripTag）。
    if (!identity && query && st == -25300 /* errSecItemNotFound */) {
        st = orig_SecItemCopyMatching(query, result);
    }
#endif
    if (st != 0 || !result || !*result) return st;   // 0 = errSecSuccess
    @try {
        CFTypeRef v = *result;
        CFTypeID tid = CFGetTypeID(v);
        if (tid == CFDataGetTypeID()) {
            NSData *d = (__bridge NSData *)v;
            NSData *nd = targeted ? fakeCUIDDataFrom(d) : rewriteIdentityData(d);
            if (nd != d) {
                CFRelease(v);                                   // 释放 orig 给的 +1
                *result = (__bridge_retained CFTypeRef)nd;      // 交给调用方 +1
            }
        } else if (tid == CFDictionaryGetTypeID()) {
            CFMutableDictionaryRef md = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, (CFDictionaryRef)v);
            stripTagInResultDict(md);                  // v59: 对外隐藏克隆后缀
            if (targeted) {
                forceCuidInResultDict(md);
            } else {
                CFDataRef vd = (CFDataRef)CFDictionaryGetValue(md, kSecValueData);
                if (vd && CFGetTypeID(vd) == CFDataGetTypeID()) {
                    NSData *d = (__bridge NSData *)vd;
                    NSData *nd = rewriteIdentityData(d);
                    if (nd != d) {
                        CFDictionarySetValue(md, kSecValueData, (__bridge CFDataRef)nd);
                    }
                }
            }
            CFRelease(v);
            *result = (CFTypeRef)md;   // +1 交给调用方（CF→CF 普通 C 转型）
        }
    } @catch (id e) {}
    return st;
}

// v57V: 写入侧 —— cuid 服务名的 keychain 写入直接落伪造值，
// 让后续所有读取（含未 hook 的通道）天然拿到伪造值
// v59: 所有写入统一加克隆后缀（物理隔离）
static OSStatus hook_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    @try {
        CFDictionaryRef base = attributes;
        CFMutableDictionaryRef mut = NULL;
        if (isCuidServiceDict(attributes)) {
            mut = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, attributes);
            forceCuidInResultDict(mut);
            base = mut;
        }
        CFDictionaryRef mangled = mangleKeychainDict(base);
        CFDictionaryRef outDict = mangled ? mangled : base;
        OSStatus st = orig_SecItemAdd(outDict, result);
        if (mangled) CFRelease(mangled);
        if (mut) CFRelease(mut);
        return st;
    } @catch (id e) {}
    return orig_SecItemAdd(attributes, result);
}

static OSStatus hook_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    @try {
        CFDictionaryRef base = attributesToUpdate;
        CFMutableDictionaryRef mut = NULL;
        if (isCuidServiceDict(query) || isCuidServiceDict(attributesToUpdate)) {
            if (attributesToUpdate && CFDictionaryGetCount(attributesToUpdate) > 0) {
                mut = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, attributesToUpdate);
                forceCuidInResultDict(mut);
                base = mut;
            }
        }
        CFDictionaryRef mq = mangleKeychainDict(query);
        CFDictionaryRef ma = mangleKeychainDict(base);
        OSStatus st = orig_SecItemUpdate(mq ? mq : query, ma ? ma : base);
        if (mq) CFRelease(mq);
        if (ma) CFRelease(ma);
        if (mut) CFRelease(mut);
        return st;
    } @catch (id e) {}
    return orig_SecItemUpdate(query, attributesToUpdate);
}

// v59: 删除也要加后缀 —— 否则某克隆的「清空重来」会把共享组里
// 其他克隆/原版 App 的登录票据一起删掉（正是 D2 一开 D1 即异常的嫌疑路径）
static OSStatus hook_SecItemDelete(CFDictionaryRef query) {
    @try {
        CFDictionaryRef mq = mangleKeychainDict(query);
        OSStatus st = orig_SecItemDelete(mq ? mq : query);
        if (mq) CFRelease(mq);
        return st;
    } @catch (id e) {}
    return orig_SecItemDelete(query);
}

static Boolean hook_CFPreferencesSetValue(CFStringRef key, CFPropertyListRef value, CFStringRef appID, CFStringRef user, CFStringRef host) {
    // v64: 身份键写私有域；功能键写回原域（否则会把共享配置整体搬进私有域）
    CFStringRef mapped = isStrictIdentityKey(key) ? mapGroupAppID(appID) : NULL;
    Boolean ok = orig_CFPreferencesSetValue(key, value, mapped ? mapped : appID, user, host);
    if (mapped) CFRelease(mapped);
    return ok;
}

// v62: CFPreferencesSetAppValue 是公开 API，v61 之前完全漏了 ——
// 任何直接调用它的 SDK 都能把设备指纹原样写进共享域。
static void hook_CFPreferencesSetAppValue(CFStringRef key, CFPropertyListRef value, CFStringRef appID) {
    if (!orig_CFPreferencesSetAppValue) return;
    CFStringRef mapped = isStrictIdentityKey(key) ? mapGroupAppID(appID) : NULL;
    orig_CFPreferencesSetAppValue(key, value, mapped ? mapped : appID);
    if (mapped) CFRelease(mapped);
}

// ============================================================
// Persistent fake IDs (BdD1. prefix — 构建脚本替换为 Bd63/BdC1 等)
// ============================================================
static NSString *getPersistent(NSString *key, NSString *(^gen)(void)) {
    CFStringRef cfKey = (__bridge CFStringRef)key;
    CFPropertyListRef val = CFPreferencesCopyAppValue(cfKey, kCFPreferencesCurrentApplication);
    if (val) {
        NSString *s = [(__bridge id)val isKindOfClass:[NSString class]] ? (__bridge NSString *)val : nil;
        CFRelease(val);
        if (s) return s;
    }
    NSString *newVal = gen();
    CFPreferencesSetAppValue(cfKey, (__bridge CFStringRef)newVal, kCFPreferencesCurrentApplication);
    CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
    return newVal;
}

// v57U: 持久写入（捕获本机真实身份值用）
static void setPersistent(NSString *key, NSString *val) {
    if (!key || !val || val.length == 0) return;
    CFPreferencesSetAppValue((__bridge CFStringRef)key, (__bridge CFStringRef)val,
                             kCFPreferencesCurrentApplication);
    CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
}

// ============================================================
// ★★ v57U: 单一身份原则（Identity Coherence）★★
//
// 问题：cookie 里的 CUID 我们伪造了，但百度原生 SDK 还会把
// 「SDK 自己算出来的 cuid」塞进 URL 参数 / POST body
// （二进制取证：cuid=%@ / &cuid=%@ 拼接大量存在），
// 以及从 keychain 共享组读原版 App 存的本机真实设备 ID
// （同团队 App 共享 keychain —— 这正是"更换设备之后就正常了"的原因）。
// 于是服务端看到：cookie=假，参数=真 → 矛盾 → 按真设备下单名额判限。
//
// 解法：捕获真实值，在**所有出口**统一替换为伪造值：
//   1) 捕获：SDK 写设备 cookie 时，原始值经过我们手上先存下来
//      （BdD1.real.CUID_FAMILY / BdD1.real.BAIDUID_FAMILY，持久化）
//   2) keychain 出口：SecItemCopyMatching 返回数据含真实值 → 替换
//   3) CFPreferences 出口：返回字符串含真实值 → 替换
//   4) 请求出口：NSMutableURLRequest 的 URL/body、WKWebView loadRequest
//      中的真实值 → 替换
// 只按「值」替换（真实值是稳定长字符串，碰撞概率为零），不做 key 名猜测。
// ============================================================

// 捕获真实身份值（仅 CUID/BAIDUID 两个家族；只在写入路径调用）
static void captureRealIdentity(NSString *name, NSString *value) {
    if (!name || !value || value.length < 16) return;
    @try {
        NSString *ck = canonicalCookieKey(name);
        BOOL isCUID = [ck isEqualToString:@"CUID_FAMILY"];
        BOOL isBID  = [ck isEqualToString:@"BAIDUID_FAMILY"];
        if (!isCUID && !isBID) return;
        NSString *k = [NSString stringWithFormat:@"BdD1.real.%@", ck];
        NSString *old = getPersistent(k, ^{ return @""; });
        if (old.length == 0) {
            setPersistent(k, value);   // 首次捕获，落盘
        }
        // 之后即使 SDK 换了值也不更新 —— 保持单一稳定真实值，避免
        // 读路径误捕获伪造值（读路径不捕获，这里只兜底首次）
    } @catch (id e) {}
}

// 把字符串里出现的「本机真实身份值」替换为「伪造值」（所有出口共用）
static NSString *rewriteIdentityString(NSString *s) {
    if (!s || s.length < 20) return s;
    @try {
        NSString *rc = getPersistent(@"BdD1.real.CUID_FAMILY", ^{ return @""; });
        if (rc.length >= 16 && [s rangeOfString:rc].location != NSNotFound) {
            s = [s stringByReplacingOccurrencesOfString:rc withString:getFakeID(@"BAIDUCUID")];
        }
        NSString *rb = getPersistent(@"BdD1.real.BAIDUID_FAMILY", ^{ return @""; });
        if (rb.length >= 16 && [s rangeOfString:rb].location != NSNotFound) {
            s = [s stringByReplacingOccurrencesOfString:rb withString:getFakeID(@"BAIDUID")];
        }
    } @catch (id e) {}
    return s;
}

static NSData *rewriteIdentityData(NSData *d) {
    if (!d || d.length < 16) return d;
    @try {
        NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        if (!s) return d;
        NSString *r = rewriteIdentityString(s);
        if (r == s) return d;
        NSData *nd = [r dataUsingEncoding:NSUTF8StringEncoding];
        return nd ?: d;
    } @catch (id e) { return d; }
}

static NSString *genUUIDStr(void) { return [[NSUUID UUID] UUIDString]; }

static NSString *genDeviceName(void) {
    NSArray *surnames = @[@"张", @"王", @"李", @"赵", @"刘", @"陈", @"杨", @"黄", @"周", @"吴",
                          @"徐", @"孙", @"马", @"朱", @"胡", @"林", @"郭", @"何", @"高", @"罗",
                          @"郑", @"梁", @"谢", @"宋", @"唐", @"许", @"韩", @"冯", @"邓", @"曹"];
    NSArray *givenNames = @[@"伟", @"芳", @"娜", @"洋", @"杰", @"磊", @"敏", @"强", @"婷", @"明",
                            @"超", @"丽", @"军", @"静", @"峰", @"威", @"鹏", @"勇", @"华", @"宇",
                            @"辉", @"平", @"刚", @"桂英", @"秀兰", @"建国", @"志强", @"俊杰",
                            @"雨涵", @"子轩", @"浩然", @"嘉怡"];
    NSString *surname = surnames[arc4random_uniform((uint32_t)surnames.count)];
    NSString *given = givenNames[arc4random_uniform((uint32_t)givenNames.count)];
    NSArray *formats = @[
        [NSString stringWithFormat:@"%@%@的 iPhone", surname, given],
        [NSString stringWithFormat:@"%@%@的iPhone", surname, given],
        @"iPhone"
    ];
    return formats[arc4random_uniform((uint32_t)formats.count)];
}

static NSString *genRandStr(NSUInteger len, NSString *cs) {
    NSMutableString *s = [NSMutableString stringWithCapacity:len];
    for (NSUInteger i = 0; i < len; i++)
        [s appendFormat:@"%C", [cs characterAtIndex:arc4random_uniform((uint32_t)cs.length)]];
    return s;
}

#if !MT_CLONE
// ============================================================
// ============================================================
// UA 伪装 — v57N 必须替换（否则 UA 泄露真系统版本，与假机型矛盾）
// 真机样本 UA: Mozilla/5.0 (iPhone; CPU iPhone OS 16_1 like Mac OS X)
//              AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148
//              SP-engine/3.61.0 light/1.0(WKWebView) them...
// v57N 目标: iPhone OS 17_6_1（与伪造系统版本一致）
// ============================================================
// ★★ v57Q 关键修正：UA 必须保留 baiduboxapp/<版本> 段 ★★
//
// 血泪教训：此前 UA 被改成
//   Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15
//   (KHTML, like Gecko) Mobile/15E148 SP-engine/3.61.0 light/1.0(WKWebView) themecolor/1.0
// 里面**没有 baiduboxapp/ 段** —— 这个 UA 看起来是「WKWebView 网页」而非
// 「百度 App 内请求」。百度活动类接口（含农场 se-act.baidu.com）依赖 UA 中的
// baiduboxapp/ 识别 App 环境；缺失时服务端判定非 App 环境，返回
// 「活动太火爆，请稍后再试」这类兜底提示。
//
// 真机（农场自动化工具实测）UA 形态：
//   ... Mobile/15E148 SP-engine/3.58.0 main/1.0 baiduboxapp/15.63.0.10
// 本 App 版本为 15.69.0.10，故 UA 中 baiduboxapp 版本必须与之一致。
//
// ★ 关于 WKWebView 的三种 UA 设置方式与优先级（务必记牢）：
//
//   customUserAgent  >  NSUserDefaults["UserAgent"]  >  applicationNameForUserAgent
//
//   优先级高的生效时，低的**被完全忽略**（不是拼接）。
//   其中只有 applicationNameForUserAgent 是「追加到默认 UA 后面」，
//   另两种是「整体替换」。
//
//   因此本 hook 的设计：
//     - 三条路全部覆盖，且**全部设成同一个完整 UA**（含 baiduboxapp 段）
//     - 这样无论 App 走哪条路、无论哪个生效，最终 UA 都正确
//     - 因为生效的只有一条，不存在「两段 baiduboxapp 重复」的问题
//
//   注意 applicationNameForUserAgent 是「追加」语义：若只靠它，
//   它追加到的默认 UA 里没有 baiduboxapp，结果仍缺该段 —— 所以
//   必须再配合 customUserAgent（优先级更高，整体替换）双保险。
// ★★★ v61 UA 策略修正：从「整体覆盖」改为「只补缺段」 ★★★
//
// 血泪复盘：v57Q 起把 UA 硬编码成下面这条，三条通道全部强制覆盖。
// 当时硬件人格也伪造 17.6.1，看着自洽；但 v58 把硬件改回真机后，
// UIDevice / sysctl 报出的是**真机系统版本**，而 UA 仍写死 17_6_1
// —— UA 与设备自身环境对不上。
// 实测表现：原版 App 农场正常，克隆进去「原本能选榴莲，现在不给选」。
//
// 正确做法：不要覆盖 App 自己设好的 UA。百度 App 自己就会给 WKWebView
// 配置带 baiduboxapp 段的 UA（这正是原版一切正常的原因）。我们只在
// 某条通道的值**确实缺** baiduboxapp 段时才补上，其余原样透传。
#define BAIDUBOXAPP_SEGMENT @" baiduboxapp/15.69.0.10"

// 仅作参考，不再用于覆盖
#define FAKE_APP_UA_FULL  @"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) " \
                          "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 " \
                          "SP-engine/3.61.0 main/1.0 baiduboxapp/15.69.0.10"

// 只在缺 baiduboxapp 段时补一段；已含则原样返回（未做任何修改）
static NSString *ensureBaiduboxAppUA(NSString *ua) {
    if (ua.length > 0 && [ua rangeOfString:@"baiduboxapp"].location != NSNotFound) {
        return ua;                                    // 已带该段 —— 一个字都不改
    }
    if (ua.length == 0) return @"baiduboxapp/15.69.0.10";
    return [ua stringByAppendingString:BAIDUBOXAPP_SEGMENT];
}

// 兼容旧调用点：返回完整 App UA（仅在完全拿不到原值时兜底）
static NSString *buildFakeUserAgent(void) {
    return FAKE_APP_UA_FULL;
}

// 判定是否为「百度系 UA」——凡是百度 App/WebView 发出的 UA 都要整体替换为
// 自洽的 App UA，避免只替换一部分造成同会话内 UA 不一致。
static BOOL isUALike(NSString *s) {
    if (!s || s.length < 20) return NO;
    return [s rangeOfString:@"iPhone OS"].location != NSNotFound ||
           [s rangeOfString:@"AppleWebKit"].location != NSNotFound ||
           [s rangeOfString:@"baiduboxapp"].location != NSNotFound ||
           [s rangeOfString:@"baidu"].location != NSNotFound;
}
#endif // !MT_CLONE

// Cookie/设备标识生成（保持与真实格式一致）
//
// ★ v57M 关键修复：CUID 必须是真 base64url(随机50字节) + "mA"
//   真机样本: giHau0iA-uj6iHilluvqi_uuSigpu2i0giSLi_ucSf_4i2uhji2Pf085HOpukHMuh18mA
//   = base64url(50字节) 67字符 + "mA" 2字符 = 69字符
//   v57L 用逐字符随机 → 虽字面像 base64 但解码非法 → 百度校验即识破
// ============================================================
static NSString *b64urlEncode(NSData *data) {
    NSString *s = [data base64EncodedStringWithOptions:0];
    s = [s stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
    s = [s stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    // 去掉 padding（真机样本无 '='）
    while ([s hasSuffix:@"="]) s = [s substringToIndex:s.length - 1];
    return s;
}

static NSString *genCUID(void) {
    // cookie 层真机结构: base64url(50字节随机) + "mA"
    // （v57M 抓的 cookie BAIDUCUID 样本，仅适用于 cookie 层；
    //   NSUserDefaults/keychain 层的 cuid 是另一种格式，见 genPlatformCUID）
    NSMutableData *raw = [NSMutableData dataWithLength:50];
    arc4random_buf([raw mutableBytes], 50);
    return [NSString stringWithFormat:@"%@mA", b64urlEncode(raw)];
}

// ★ v67: 平台层 cuid（NSUserDefaults "cuid" 键 / keychain baidumobile.cuid 项）
//
// WebDAV 真机取证（bm_prefs.plist，原版 App 共享域）实锤：
//   cuid         = 3ECBAB9D9AA6A11172C115567CA774A95F5B9E38CFBHRSARBQS
//   BNPush_cuid  = D1311D9D3FA6AD38816050093190DA2CA145C5073OIAJMHMNOI
// 格式 = 40位大写HEX + 11位[0-9A-Z]尾巴，共 51 字符。
// 而旧实现（v57M 起）把 cookie 的 b64url 格式（~70字符，含小写/-/_）也顶给
// 了平台层 cuid —— 服务端一眼识别非法格式 → 果园只给基础功能、
// 不下发浏览任务（用户实测：原版正常、克隆「看不到浏览任务」）。
static NSString *genPlatformCUID(void) {
    NSString *hexCS = @"0123456789ABCDEF";
    NSString *tailCS = @"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    return [NSString stringWithFormat:@"%@%@",
            genRandStr(40, hexCS), genRandStr(11, tailCS)];
}

static NSString *genBAIDUID(void) {
    // 真机: 32位大写HEX + ":FG=1"  (例: 5A258432900A32B53931CFE922A7AF51:FG=1)
    NSString *hexCS = @"0123456789ABCDEF";
    return [genRandStr(32, hexCS) stringByAppendingString:@":FG=1"];
}

static NSString *genTcuid(void) {
    // tcuid: 48位大写HEX（保持十六进制）
    NSString *hexCS = @"0123456789ABCDEF";
    return genRandStr(48, hexCS);
}

static NSString *genFakeCookie(NSString *name) {
    NSString *cuidCS = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    NSString *hexCS = @"0123456789abcdef";
    NSString *upperHexCS = @"0123456789ABCDEF";

    // ★ v57P：先按「身份族」归一化，保证同族 cookie 拿到同一个值
    NSString *fam = canonicalCookieKey(name);

    // —— CUID 族：BAIDUCUID / BAIDUCUID_BFESS / MAWEBCUID / cuid 全部同值 ——
    if ([fam isEqualToString:@"CUID_FAMILY"])
        return genCUID();

    // —— BAIDUID 族 ——
    if ([fam isEqualToString:@"BAIDUID_FAMILY"])
        return genBAIDUID();

    // —— fuid 族 ——
    if ([fam isEqualToString:@"FUID_FAMILY"])
        return genRandStr(32, hexCS);

    // —— ab_jid 族 ——
    if ([fam isEqualToString:@"AB_JID_FAMILY"])
        return genRandStr(40, hexCS);

    // —— ab_bid 族 ——
    if ([fam isEqualToString:@"AB_BID_FAMILY"])
        return genRandStr(40, hexCS);

    // —— 以下为各自独立的标识，不共享 ——
    // ★ v67: 平台层 cuid —— 与 cookie CUID_FAMILY **不同值、不同格式**！
    // 真机里 cookie BAIDUCUID（b64url）与 plist/keychain cuid（40大写HEX+尾）
    // 本来就是两个 ID。旧实现把它们归一成一个 b64url 值是错误根源。
    if ([name isEqualToString:@"PLATCUID"]) return genPlatformCUID();
    if ([name isEqualToString:@"DVIF"]) {
        NSString *num = [NSString stringWithFormat:@"%lu", (unsigned long)((uint64_t)arc4random() * arc4random() % 9000000000000000ULL + 1000000000000000ULL)];
        NSMutableData *d = [NSMutableData dataWithLength:300];
        arc4random_buf([d mutableBytes], 300);
        return [NSString stringWithFormat:@"%@_%@_%@", num, [d base64EncodedStringWithOptions:0], genRandStr(6, hexCS)];
    }
    if ([name isEqualToString:@"tcuid"]) return genTcuid();
    if ([name isEqualToString:@"__bid_n"]) return genRandStr(22, hexCS);

    // ---- v57M 新增：真机样本中实际存在的设备/环境标识 ----
    // BDB2BVID: 32位hex 设备ID
    if ([name isEqualToString:@"BDB2BVID"]) return genRandStr(32, hexCS);
    // BA_HECTOR: 真机 848120240la12g8h810g04242ha1a41l73rr429 (35字符，数字+字母混合)
    if ([name isEqualToString:@"BA_HECTOR"]) return genRandStr(35, @"abcdefghijklmnopqrstuvwxyz0123456789");
    // BAIDU_WISE_UID: wapp_<13位时间戳>_<3位随机>
    if ([name isEqualToString:@"BAIDU_WISE_UID"]) {
        NSTimeInterval ts = [[NSDate date] timeIntervalSince1970] * 1000;
        return [NSString stringWithFormat:@"wapp_%.0f_%u", ts, arc4random_uniform(1000)];
    }
    // ZFY: 真机 carCl1WCG0JXAY:Bb7F4:AobXjhVWSBtT7AemD91AW0z0:C (段用冒号分隔)
    if ([name isEqualToString:@"ZFY"]) {
        NSString *cs2 = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        return [NSString stringWithFormat:@"%@:%@:%@:C",
                genRandStr(14, cs2), genRandStr(5, cs2), genRandStr(28, cs2)];
    }
    // RT: "z=1&dm=baidu.com&si=<uuid>&ss=<8位>&sl=1&tt=um&bcn=..."
    if ([name isEqualToString:@"RT"]) {
        NSString *uuid = [[NSUUID UUID] UUIDString];
        return [NSString stringWithFormat:@"\"z=1&dm=baidu.com&si=%@&ss=%@&sl=1&tt=um\"",
                [uuid lowercaseString], genRandStr(8, @"abcdefghijklmnopqrstuvwxyz0123456789")];
    }
    // H_WISE_SIDS: 数字下划线串（版本特征，非唯一标识，用固定值即可）
    //
    // ★★ v57Q 修正：AFD_IP / BAIDULOCNEW 必须「原样放行」，不碰 ★★
    //
    // 依据 38 个真机账号 cookie 实测统计：
    //   AFD_IP      出现 34/38，全部为真实公网 IP
    //   BAIDULOCNEW 出现 34/38，格式统一 __100000_317_<13位毫秒时间戳>_1
    //   其中 112.81.241.* 一个网段就有 28 个账号共用，且全部能正常进农场
    //
    // 由此确认两件事：
    //   1) 百度不校验 AFD_IP 与真实出口 IP 是否一致
    //   2) 百度不在乎多账号共用同一 IP（同 IP 是常态）
    //
    // 因此此前"清空 AFD_IP 防聚类"是无根据的，清除后反而让字段变为空值，
    // 而正常 App 从不写入空值 —— "存在但为空"本身就是篡改特征。
    // 生成假 IP 同样错误（会与真实出口 IP 矛盾，凭空制造不一致）。
    //
    // 正确处理：这两个字段不进入 isDeviceCookie 名单，本函数不会被调用，
    // 由 App 自行写入真实值。此处保留分支仅为显式文档化该决策。
    if ([name isEqualToString:@"AFD_IP"] || [name isEqualToString:@"BAIDULOCNEW"]) {
        // 不应到达此处（不在 isDeviceCookie 名单内）。若到达则原值无法获取，
        // 返回空串并依赖上层跳过改写。
        return @"";
    }
    return genRandStr(32, cuidCS);
}

static NSString *getFakeID(NSString *name) {
    return getPersistent([NSString stringWithFormat:@"BdD1.ck.%@", canonicalCookieKey(name)],
                         ^{ return genFakeCookie(name); });
}

// ============================================================
// ★ v57P 修复：Cookie 身份族归一化
//
// 问题：genFakeCookie 按 cookie 原始名生成并缓存，导致同一个「设备身份」
//       在不同 cookie 名下分裂成多个互不相干的值：
//         BAIDUCUID        -> BdD1.ck.BAIDUCUID        (值 A)
//         BAIDUCUID_BFESS  -> BdD1.ck.BAIDUCUID_BFESS  (值 B)  ✗ 应等于 A
//         MAWEBCUID        -> BdD1.ck.MAWEBCUID        (值 C)  ✗ 应等于 A
//         cuid             -> BdD1.ck.cuid             (值 D)  ✗ 应等于 A
//         CUID             -> BdD1.ck.CUID             (值 E)  ✗ 应等于 A
//       百度农场激活的硬性前置就是 BAIDUCUID，App 后续请求携带的 MAWEBCUID/
//       cuid 却是另一个值 → 服务端判定「设备身份不一致」→ 拒绝激活。
//       原版 App 能进农场，正因为它所有 CUID 名都是同一个真值。
//
// 方案：把语义等价的 cookie 名映射到同一个规范键，保证同族同值。
// ============================================================
static NSString *canonicalCookieKey(NSString *name) {
    if (!name) return @"";
    NSString *u = [name uppercaseString];

    // —— CUID 族：全部共用同一个 CUID（农场激活依赖此一致性）——
    // BAIDUCUID / BAIDUCUID_BFESS / MAWEBCUID / cuid / CUID / cuid_galaxy2
    if ([u hasPrefix:@"BAIDUCUID"]) return @"CUID_FAMILY";
    if ([u isEqualToString:@"MAWEBCUID"]) return @"CUID_FAMILY";
    if ([u hasPrefix:@"CUID"]) return @"CUID_FAMILY";

    // —— BAIDUID 族（浏览器/账号侧 ID，非设备指纹）——
    if ([u hasPrefix:@"BAIDUID"]) return @"BAIDUID_FAMILY";

    // —— fuid 族 ——
    if ([u isEqualToString:@"FUID"]) return @"FUID_FAMILY";

    // —— ab_jid 族 ——
    if ([u hasPrefix:@"AB_JID"]) return @"AB_JID_FAMILY";

    // —— ab_bid 族 ——
    if ([u hasPrefix:@"AB_BID"]) return @"AB_BID_FAMILY";

    return name;
}

// 会话凭证类：绝不伪造（伪造会直接破坏登录态与 CSRF 校验）
static BOOL isSessionCookie(NSString *cookieName) {
    if (!cookieName) return NO;
    NSString *u = [cookieName uppercaseString];
    // BDUSS / BDUSS_BFESS 是登录会话 + CSRF 镜像，篡改会导致会话失效
    if ([u hasPrefix:@"BDUSS"]) return YES;
    if ([u hasPrefix:@"STOKEN"]) return YES;
    if ([u hasPrefix:@"PTOKEN"]) return YES;
    return NO;
}

// ============================================================
// Cookie device ID detection
// ============================================================
static BOOL isDeviceCookie(NSString *cookieName) {
    if (!cookieName) return NO;
    // ★ v57P：会话凭证绝不伪造（BDUSS/BDUSS_BFESS/STOKEN/PTOKEN）
    //   篡改 BDUSS_BFESS 会破坏 CSRF 镜像 → 会话失效 → 农场/支付认证失败
    if (isSessionCookie(cookieName)) return NO;
    NSString *lk = [cookieName lowercaseString];
    NSArray *names = @[@"baiducuid", @"baiducuid_bfess", @"mawebcuid",
                       @"dvif", @"tcuid", @"__bid_n", @"fuid", @"cuid",
                       @"baiduid", @"baiduid_bfess",
                       // v57M 新增（真机样本确认存在）
                       @"bdb2bvid", @"ab_bid", @"ab_jid", @"ab_jid_bfess",
                       @"ba_hector", @"zfy", @"rt"];
    for (NSString *n in names) { if ([lk isEqualToString:n]) return YES; }
    return NO;
}

static NSArray *modifiedCookies(NSArray *cookies) {
    if (!cookies || cookies.count == 0) return cookies;
    NSMutableArray *result = [NSMutableArray array];
    for (NSHTTPCookie *cookie in cookies) {
        if (isDeviceCookie(cookie.name)) {
            NSString *fakeValue = getFakeID(cookie.name);
            NSMutableDictionary *props = [NSMutableDictionary dictionary];
            props[NSHTTPCookieName] = cookie.name;
            props[NSHTTPCookieValue] = fakeValue;
            if (cookie.domain) props[NSHTTPCookieDomain] = cookie.domain;
            if (cookie.path) props[NSHTTPCookiePath] = cookie.path;
            if (cookie.expiresDate) props[NSHTTPCookieExpires] = cookie.expiresDate;
            props[NSHTTPCookieVersion] = @(cookie.version);
            if (cookie.secure) props[NSHTTPCookieSecure] = @YES;
            NSHTTPCookie *newCookie = [[NSHTTPCookie alloc] initWithProperties:props];
            if (newCookie) [result addObject:newCookie];
            else [result addObject:cookie];
        } else {
            [result addObject:cookie];
        }
    }
    return result;
}

// ============================================================
// NSUserDefaults device key detection
// ============================================================
static BOOL isDeviceKey(NSString *key) {
    if (!key || g_inUDHook) return NO;
    if ([key hasPrefix:@"BdD1"]) return NO;
    NSArray *exactKeys = @[@"cuid", @"CUID", @"cuid_galaxy2", @"cuid_gid", @"cuid_loc",
                           @"BAIDUCUID", @"BAIDUCUID_BFESS", @"MAWEBCUID",
                           @"DVIF", @"tcuid", @"__bid_n", @"fuid",
                           @"bdudid", @"baiduid", @"baiduid_bfess", @"bdid"];
    for (NSString *k in exactKeys) { if ([key isEqualToString:k]) return YES; }
    if ([key.lowercaseString hasPrefix:@"cuid"]) return YES;
    return NO;
}

// ============================================================
// v58: NSProcessInfo / UIScreen 硬件伪造已整体移除 —— 硬件人格跟真机，
// 只保留身份伪造（cuid/UDID/IDFV/ECID/设备名）。历史教训见 git v57S/v57T。

// v59: NSFileManager App Group 容器方法原始实现（容器 URL 隔离用）
static NSURL *(*orig_containerURL)(id, SEL, NSString *) = NULL;

// ============================================================
// ★ v68: 诊断日志（T7 专用）★
//
// 目的：抓果园相关网络请求的 URL / 请求头 / 请求体 / 响应体，
// 对比克隆与原版的参数差异，定位「浏览任务不下发」的服务端判定依据。
// 日志写 /var/mobile/Documents/bd_diag.log（Filza/WebDAV 可直读），
// 无权限时退回 App 沙盒 Documents/bd_diag.log。
// 上限 3MB，超过即停写（防止无限膨胀）。
// ============================================================
static NSFileHandle *diagFH(void) {
    static NSFileHandle *fh = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        @try {
            NSString *doc = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
            NSArray *cands = @[
                @"/var/mobile/Documents/bd_diag.log",
                [doc stringByAppendingPathComponent:@"bd_diag.log"],
            ];
            NSFileManager *fm = [NSFileManager defaultManager];
            NSString *path = nil;
            for (NSString *p in cands) {
                if (![fm isWritableFileAtPath:[p stringByDeletingLastPathComponent]]) continue;
                if (![fm fileExistsAtPath:p]) {
                    [@"" writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
                }
                if ([fm fileExistsAtPath:p]) { path = p; break; }
            }
            if (!path) return;
            fh = [NSFileHandle fileHandleForUpdatingAtPath:path];
            [fh seekToEndOfFile];
            NSString *hdr = [NSString stringWithFormat:
                @"==== BD DIAG v68 start %@\n==== sandbox=%@\n==== fakeCookieCUID=%@\n==== fakePlatformCUID=%@\n",
                [NSDate date], NSHomeDirectory(), getFakeID(@"BAIDUCUID"), getFakeID(@"PLATCUID")];
            [fh writeData:[hdr dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data]];
        } @catch (id e) { fh = nil; }
    });
    return fh;
}

static long long g_diagSize = 0;

static void diagAppend(NSString *s) {
    NSFileHandle *fh = diagFH();
    if (!fh || !s) return;
    @try {
        @synchronized (fh) {
            if (g_diagSize > 3LL * 1024 * 1024) return;
            NSData *d = [s dataUsingEncoding:NSUTF8StringEncoding];
            if (!d) return;
            [fh seekToEndOfFile];
            [fh writeData:d];
            g_diagSize += d.length;
        }
    } @catch (id e) {}
}

// ★ v69: 排除法过滤 —— 果园接口 URL 关键词猜不准，改为只排除静态资源/CDN，
// 其余全部记录（3MB 上限兜底）。宁可多记，遗漏才是最大成本。
static BOOL diagInteresting(NSURL *u) {
    if (!u) return NO;
    NSString *s = u.absoluteString;
    if (s.length == 0) return NO;
    NSString *l = [[s lowercaseString] stringByRemovingPercentEncoding] ?: [s lowercaseString];
    if ([l rangeOfString:@"bd_diag"].location != NSNotFound) return NO;
    // 静态资源扩展名
    NSArray *ext = @[@".png", @".jpg", @".jpeg", @".gif", @".webp", @".css", @".js",
                     @".ico", @".woff", @".woff2", @".ttf", @".mp4", @".m3u8", @".svg"];
    for (NSString *e in ext) {
        if ([l hasSuffix:e]) return NO;
    }
    // 静态 CDN / 推送等无关通道
    NSArray *cdn = @[@"bdstatic.com", @"bdimg.com", @"bcebos.com", @"baidubce.com",
                     @"bdurl.net", @"mipcdn.com", @"push", @"mtj", @"apoll"];
    for (NSString *c in cdn) {
        if ([l rangeOfString:c].location != NSNotFound) return NO;
    }
    return YES;
}

static void diagDumpRequest(NSURLRequest *req, NSString *tag) {
    if (!req || !diagInteresting(req.URL)) return;
    NSMutableString *m = [NSMutableString stringWithFormat:@"\n[%@] %@ %@\n",
                          [NSDate date], tag, req.HTTPMethod ?: @"GET"];
    [m appendFormat:@"  URL: %@\n", req.URL.absoluteString];
    NSDictionary *h = req.allHTTPHeaderFields;
    for (NSString *k in h) {
        NSString *v = h[k];
        if (v.length > 300) v = [[v substringToIndex:300] stringByAppendingString:@"..."];
        [m appendFormat:@"  H %@: %@\n", k, v];
    }
    NSData *b = req.HTTPBody;
    if (b) {
        NSString *bs = [[NSString alloc] initWithData:b encoding:NSUTF8StringEncoding];
        if (!bs) bs = [NSString stringWithFormat:@"<%lu bytes binary>", (unsigned long)b.length];
        if (bs.length > 2500) bs = [[bs substringToIndex:2500] stringByAppendingString:@"...<trunc>"];
        [m appendFormat:@"  BODY: %@\n", bs];
    } else if (req.HTTPBodyStream) {
        [m appendString:@"  BODY: <stream>\n"];
    }
    diagAppend(m);
}

static void diagDumpResponse(NSURLRequest *req, NSHTTPURLResponse *resp, NSData *data) {
    NSURL *u = resp.URL ?: req.URL;
    if (!resp || !diagInteresting(u)) return;
    NSMutableString *m = [NSMutableString stringWithFormat:@"\n[%@] RESP %ld %@\n",
                          [NSDate date], (long)resp.statusCode, u.absoluteString];
    NSData *d = data;
    if (d.length > 4000) d = [d subdataWithRange:NSMakeRange(0, 4000)];
    NSString *bs = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    if (!bs) bs = [NSString stringWithFormat:@"<%lu bytes binary>", (unsigned long)(data ? data.length : 0)];
    [m appendFormat:@"  BODY: %@\n", bs];
    diagAppend(m);
}

// 构造函数里安装：
//   - NSURLSession dataTaskWithRequest:completionHandler:（原生接口层，含响应）
//   - NSURLSession dataTaskWithRequest:（v69: delegate 型，请求侧）
//   - uploadTaskWithRequest:fromData:completionHandler:（v69）
//   - sessionWithConfiguration:delegate:delegateQueue:（v69: 抓 delegate 并 swizzle
//     URLSession:dataTask:didReceiveData: / URLSession:task:didCompleteWithError:）
//   - WKWebView loadRequest:（H5 页面导航 URL）
//   - addScriptMessageHandler:name:（v69: 记录 H5↔原生 JSBridge 名单）
// 注：WKWebView 内部 XHR 在 WebKit 网络进程，App 内 hook 看不到；
//     JSBridge 消息是 H5 数据的主要通道之一，先记录名单。

// ---- v69: delegate 型响应体收集（per-task 缓存）----
static NSMutableDictionary *diagTaskData(void) {
    static NSMutableDictionary *d = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ d = [NSMutableDictionary new]; });
    return d;
}

// 对 delegate 类做一次性 swizzle（记录响应体）
static void diagSwizzleNetDelegate(id d) {
    if (!d) return;
    @try {
        Class c = object_getClass(d);
        static NSMutableSet *done = nil;
        static dispatch_once_t once;
        dispatch_once(&once, ^{ done = [NSMutableSet new]; });
        NSString *ck = NSStringFromClass(c);
        @synchronized (done) {
            if ([done containsObject:ck]) return;
            [done addObject:ck];
        }
        SEL s1 = @selector(URLSession:dataTask:didReceiveData:);
        SEL s2 = @selector(URLSession:task:didCompleteWithError:);
        Method m1 = class_getInstanceMethod(c, s1);
        Method m2 = class_getInstanceMethod(c, s2);
        if (m1) {
            IMP orig = method_getImplementation(m1);
            IMP imp = imp_implementationWithBlock(
                ^(id selfdg, NSURLSession *session, NSURLSessionDataTask *task, NSData *data) {
                    @try {
                        if (task && data) {
                            NSString *tid = [NSString stringWithFormat:@"%lu", (unsigned long)task.taskIdentifier];
                            [[diagTaskData() objectForKey:tid] appendData:data];
                        }
                    } @catch (id e) {}
                    ((void (*)(id, SEL, NSURLSession *, NSURLSessionDataTask *, NSData *))orig)(
                        selfdg, s1, session, task, data);
                });
            method_setImplementation(m1, imp);
        }
        if (m2) {
            IMP orig = method_getImplementation(m2);
            IMP imp = imp_implementationWithBlock(
                ^(id selfdg, NSURLSession *session, NSURLSessionTask *task, NSError *error) {
                    @try {
                        if (task) {
                            NSURLRequest *req = task.originalRequest ?: task.currentRequest;
                            NSHTTPURLResponse *resp = (NSHTTPURLResponse *)task.response;
                            NSString *tid = [NSString stringWithFormat:@"%lu", (unsigned long)task.taskIdentifier];
                            NSData *acc = [diagTaskData() objectForKey:tid];
                            [diagTaskData() removeObjectForKey:tid];
                            if (req) diagDumpRequest(req, @"DELEG-REQ");
                            if (resp && [resp isKindOfClass:objc_getClass("NSHTTPURLResponse")]) {
                                NSMutableString *m = [NSMutableString stringWithFormat:@"\n[%@] DELEG-RESP %ld %@\n",
                                                      [NSDate date], (long)resp.statusCode, resp.URL.absoluteString];
                                if (acc) {
                                    NSData *d2 = acc.length > 4000 ? [acc subdataWithRange:NSMakeRange(0, 4000)] : acc;
                                    NSString *bs = [[NSString alloc] initWithData:d2 encoding:NSUTF8StringEncoding];
                                    if (!bs) bs = [NSString stringWithFormat:@"<%lu bytes binary>", (unsigned long)acc.length];
                                    [m appendFormat:@"  BODY: %@\n", bs];
                                }
                                diagAppend(m);
                            }
                        }
                    } @catch (id e) {}
                    ((void (*)(id, SEL, NSURLSession *, NSURLSessionTask *, NSError *))orig)(
                        selfdg, s2, session, task, error);
                });
            method_setImplementation(m2, imp);
        }
    } @catch (id e) {}
}

// ============================================================
// Constructor — v58
// ============================================================
// v72: UIPasteboard 私有化 —— 保存 pasteboardWithNamespace: 原始 IMP + 防自递归标记
static IMP g_origPBNamespace = NULL;
static IMP g_origPWName = NULL;
static BOOL g_inPBCall = NO;

__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {

        // ---- 0. v63: 先把克隆标签算好，再装任何 hook ----
        // cloneTag() 会被 initWithSuiteName / CFPreferences / keychain 各处
        // 在很深的调用栈上（甚至初始化过程中）触发。此刻尚未安装任何
        // hook，NSBundle 读取路径最干净，提前固定下来可彻底避免
        // 「惰性计算 → 重入 → 递归爆栈」这一类风险。
        (void)cloneTag();

        // ---- 1. v59: 首启只清 Cookie ----
        // ★ 教训：此前这里 SecItemDelete 删「所有类别」的 keychain 项，
        //   而 keychain 访问组是所有克隆共享的 → 装/开一个克隆会把
        //   原版 App 和其他克隆的登录票据一起删掉（D2 一开 D1 就异常）。
        //   v59 起所有 keychain 项都带克隆后缀，历史无后缀项对本克隆
        //   天然不可见，已无需全量清理。
        @try {
            CFPropertyListRef cleared = CFPreferencesCopyAppValue(CFSTR("BdD1.reset"), kCFPreferencesCurrentApplication);
            if (!cleared) {
                NSHTTPCookieStorage *storage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
                for (NSHTTPCookie *cookie in [storage cookies]) {
                    [storage deleteCookie:cookie];
                }
                CFPreferencesSetAppValue(CFSTR("BdD1.reset"), kCFBooleanTrue, kCFPreferencesCurrentApplication);
                CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
            } else { CFRelease(cleared); }
        } @catch (id e) {
            CFPreferencesSetAppValue(CFSTR("BdD1.reset"), kCFBooleanTrue, kCFPreferencesCurrentApplication);
            CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
        }

        // ---- 2. UIDevice hooks — v57N 全套人格对齐（Pro Max 自洽） ----
        @try {
            Class dc = objc_getClass("UIDevice");
            if (dc) {
                Method nameM = class_getInstanceMethod(dc, @selector(name));
                if (nameM) {
                    IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                        return getPersistent(@"BdD1.dn", ^{ return genDeviceName(); });
                    });
                    class_replaceMethod(dc, @selector(name), imp, method_getTypeEncoding(nameM));
                }
                Method idfvM = class_getInstanceMethod(dc, @selector(identifierForVendor));
                if (idfvM) {
                    IMP imp = imp_implementationWithBlock(^NSUUID *(id s) {
                        return [[NSUUID alloc] initWithUUIDString:getPersistent(@"BdD1.iv", ^{ return genUUIDStr(); })];
                    });
                    class_replaceMethod(dc, @selector(identifierForVendor), imp, method_getTypeEncoding(idfvM));
                }
                // 型号字串 — 必须与 sysctl hw.machine 一致
                for (NSString *sel in @[@"model", @"localizedModel"]) {
                    SEL sl = NSSelectorFromString(sel);
                    Method m = class_getInstanceMethod(dc, sl);
                    if (m) {
                        IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                            return @"iPhone";
                        });
                        class_replaceMethod(dc, sl, imp, method_getTypeEncoding(m));
                    }
                }
                // v58: systemVersion 不再伪造 —— 真机系统版本全通道自洽
                // （教训：XS 上假报 17.6.1 + 假大屏尺寸导致页面渲染异常）
            }
        } @catch (id e) {}

        // ---- 2b. v58: UIScreen hooks 全部移除 ----
        // ★ 这是 XS 上「页面变大」的根因：强制所有设备返回 430x932/1284x2778，
        //   XS 真实 375x812，布局按大屏算 → 内容溢出/过大。
        //   硬件人格策略改为「跟真机」，屏幕永远真实。

        // ---- 2c. v58: NSProcessInfo hooks 全部移除 ----
        // 系统版本/内存返回真值，与 sysctl/UIDevice 全通道自洽。
        // （v57S 的纯 C IMP 方案保留在历史版本，若需恢复见 git）

        // ---- 2d. v59: App Group 容器隔离 ----
        // entitlement: com.apple.security.application-groups = group.com.baidu.BaiduMobile
        // → 所有克隆拿到同一个容器目录，文件级数据互相可见。
        // 给返回 URL 追加克隆专属子目录，读写路径一致改写即实现物理隔离。
        // ---- 2d. v61: App Group 容器隔离 —— 【已回退，重要】 ----
        // v59 曾把 containerURLForSecurityApplicationGroupIdentifier 的返回值
        // 追加克隆子目录，想隔离文件级共享数据。两个硬伤：
        //   1) URLByAppendingPathComponent 只拼路径、**不建目录** —— App 拿到
        //      之后直接写入会静默失败，共享数据全写不进去；
        //   2) 就算把目录建出来，App 原本写在共享容器里的历史数据也全部不可见，
        //      App 会当成全新环境重新初始化。
        // 实测症状：原版 App 农场正常，克隆进去「原本能选榴莲，现在不给选」。
        // 结论：App Group 容器是 App 自身读写依赖的目录，**不能整体重定向**；
        // 设备身份与登录态的隔离交给 keychain 层（service 后缀）就够了。
        // 原实现保留在 git 历史（v59/v60），需要时再取回。
#if 0
        @try {
            Class fmc = objc_getClass("NSFileManager");
            if (fmc) {
                SEL gsel = NSSelectorFromString(@"containerURLForSecurityApplicationGroupIdentifier:");
                Method gm = class_getInstanceMethod(fmc, gsel);
                if (gm) {
                    orig_containerURL = (void *)method_getImplementation(gm);
                    IMP imp = imp_implementationWithBlock(^NSURL *(id s, NSString *gid) {
                        NSURL *u = orig_containerURL ? orig_containerURL(s, gsel, gid) : nil;
                        if (!u) return nil;
                        NSURL *sub = [u URLByAppendingPathComponent:cloneTag() isDirectory:YES];
                        [[NSFileManager defaultManager] createDirectoryAtURL:sub
                                                  withIntermediateDirectories:YES
                                                                   attributes:nil error:nil];
                        return sub;
                    });
                    class_replaceMethod(fmc, gsel, imp, method_getTypeEncoding(gm));
                }
            }
        } @catch (id e) {}
#endif

        // ---- 3. IDFA hook — 每克隆独立 ----
        @try {
            Class ac = objc_getClass("ASIdentifierManager");
            if (ac) {
                Method m = class_getInstanceMethod(ac, @selector(advertisingIdentifier));
                if (m) {
                    IMP imp = imp_implementationWithBlock(^NSUUID *(id s) {
                        return [[NSUUID alloc] initWithUUIDString:getPersistent(@"BdD1.ai", ^{ return genUUIDStr(); })];
                    });
                    class_replaceMethod(ac, @selector(advertisingIdentifier), imp, method_getTypeEncoding(m));
                }
            }
        } @catch (id e) {}

        // ---- 3b. v72: UIPasteboard 克隆私有化 ★P0★ ----
        // 审计：主二进制 UIPasteboard ×22，风控 SDK TalosPro 就在调。所有克隆
        // 与原版共享同一物理剪贴板 → 风控写入的设备标识跨 App 串回真机。
        // 做法：generalPasteboard 重定向到克隆专属 namespace（bdclone.general.<tag>）；
        //       App 发起的 pasteboardWithNamespace: / pasteboardWithName:create:
        //       名字追加克隆后缀（同克隆重启后名字稳定，App 内持久性不受影响；
        //       与原版/其他克隆物理隔离）。
        @try {
            Class pbc = objc_getClass("UIPasteboard");
            if (pbc) {
                Class meta = object_getClass(pbc);
                SEL pnSel = NSSelectorFromString(@"pasteboardWithNamespace:");
                Method pnM = class_getInstanceMethod(meta, pnSel);
                if (pnM) {
                    g_origPBNamespace = method_getImplementation(pnM);
                    IMP impPN = imp_implementationWithBlock(^UIPasteboard *(id s, NSString *ns) {
                        if (!g_inPBCall && ns.length > 0 && ![ns hasPrefix:@"bdclone."]) {
                            g_inPBCall = YES;
                            @try {
                                return ((UIPasteboard *(*)(id, SEL, NSString *))g_origPBNamespace)(
                                    s, pnSel, [[@"bdclone." stringByAppendingString:ns]
                                               stringByAppendingString:[@"." stringByAppendingString:cloneTag()]]);
                            } @finally { g_inPBCall = NO; }
                        }
                        return ((UIPasteboard *(*)(id, SEL, NSString *))g_origPBNamespace)(s, pnSel, ns);
                    });
                    class_replaceMethod(meta, pnSel, impPN, method_getTypeEncoding(pnM));

                    SEL gpSel = @selector(generalPasteboard);
                    Method gpM = class_getInstanceMethod(meta, gpSel);
                    if (gpM) {
                    IMP impGP = imp_implementationWithBlock(^UIPasteboard *(id s) {
                        g_inPBCall = YES;
                        @try {
                            return ((UIPasteboard *(*)(id, SEL, NSString *))g_origPBNamespace)(
                                s, pnSel, [@"bdclone.general." stringByAppendingString:cloneTag()]);
                        } @finally { g_inPBCall = NO; }
                    });
                        class_replaceMethod(meta, gpSel, impGP, method_getTypeEncoding(gpM));
                    }

                    SEL pwnSel = NSSelectorFromString(@"pasteboardWithName:create:");
                    Method pwnM = class_getInstanceMethod(meta, pwnSel);
                    if (pwnM) {
                        g_origPWName = method_getImplementation(pwnM);
                        IMP impPWN = imp_implementationWithBlock(^UIPasteboard *(id s, NSString *name, BOOL create) {
                            if (name.length > 0 && ![name hasPrefix:@"bdclone."]) {
                                name = [[@"bdclone." stringByAppendingString:name]
                                        stringByAppendingString:[@"." stringByAppendingString:cloneTag()]];
                            }
                            return ((UIPasteboard *(*)(id, SEL, NSString *, BOOL))g_origPWName)(
                                s, pwnSel, name, create);
                        });
                        class_replaceMethod(meta, pwnSel, impPWN, method_getTypeEncoding(pwnM));
                    }
                }
            }
        } @catch (id e) {}

        // ---- 3c. v72: DeviceCheck / App Attest 失败化 ★P0★ ----
        // 审计：主二进制 DCDevice/DCAppAttestService/generateToken/attestKey 都有引用。
        // DeviceCheck 是 Apple 服务器签名的设备证明，绑定物理设备 —— 卸载重装、
        // 换 bundle id 全部无效，是「刚装能下单、几天后被拉黑」的最强解释。
        // 做法：所有 token/assert 生成回调直接报错。风控 SDK 对可选信号失败一般静默容忍。
        @try {
            Class dcd = objc_getClass("DCDevice");
            if (dcd) {
                SEL gtSel = NSSelectorFromString(@"generateTokenWithCompletionHandler:");
                Method gtM = class_getInstanceMethod(dcd, gtSel);
                if (gtM) {
                    IMP imp = imp_implementationWithBlock(^(id s, void (^h)(NSData *, NSError *)) {
                        if (h) h(nil, [NSError errorWithDomain:@"BdCloneV72" code:-1 userInfo:nil]);
                    });
                    class_replaceMethod(dcd, gtSel, imp, method_getTypeEncoding(gtM));
                }
            }
            Class dca = objc_getClass("DCAppAttestService");
            if (dca) {
                SEL gkSel = NSSelectorFromString(@"generateKeyWithCompletionHandler:");
                Method gkM = class_getInstanceMethod(dca, gkSel);
                if (gkM) {
                    IMP imp = imp_implementationWithBlock(^(id s, void (^h)(NSString *, NSError *)) {
                        if (h) h(nil, [NSError errorWithDomain:@"BdCloneV72" code:-2 userInfo:nil]);
                    });
                    class_replaceMethod(dca, gkSel, imp, method_getTypeEncoding(gkM));
                }
                SEL akSel = NSSelectorFromString(@"attestKey:clientDataHash:completionHandler:");
                Method akM = class_getInstanceMethod(dca, akSel);
                if (akM) {
                    IMP imp = imp_implementationWithBlock(^(id s, NSString *keyId, NSData *hash, void (^h)(NSError *)) {
                        if (h) h([NSError errorWithDomain:@"BdCloneV72" code:-3 userInfo:nil]);
                    });
                    class_replaceMethod(dca, akSel, imp, method_getTypeEncoding(akM));
                }
                SEL gaSel = NSSelectorFromString(@"generateAssertion:clientDataHash:completionHandler:");
                Method gaM = class_getInstanceMethod(dca, gaSel);
                if (gaM) {
                    IMP imp = imp_implementationWithBlock(^(id s, NSString *attestObj, NSData *hash, void (^h)(NSData *, NSError *)) {
                        if (h) h(nil, [NSError errorWithDomain:@"BdCloneV72" code:-4 userInfo:nil]);
                    });
                    class_replaceMethod(dca, gaSel, imp, method_getTypeEncoding(gaM));
                }
            }
        } @catch (id e) {}

        // ---- 4. NSUserDefaults hooks — 设备 ID 伪造 + v64 按键精准隔离 ----
        @try {
            Class uc = objc_getClass("NSUserDefaults");
            if (uc) {
                // ★ v64: 隔离粒度从「整个 group 域」收窄到「身份键」 ★
                //
                // v62 曾把 suite 名整体加后缀（group.com.baidu.BaiduMobile →
                // group.com.baidu.BaiduMobile.BdE1）。key 名虽不变，但整份
                // 共享数据（真机实测 72 键）都看不见了 —— 果园这类跑在
                // WKWebView 里的 H5 活动页拿不到渠道/活动参数，症状就是
                // 「能进果园，但选不了水果」。
                //
                // v64 做法：initWithSuiteName: **不再改域名**（实例仍指向共享
                // 域），只给 group 域实例打个标记；随后在 objectForKey: /
                // stringForKey: / setObject:forKey: 里按 key 分流 ——
                // 身份键走本克隆私有域，其余键留在共享域。
                // 于是：身份各克隆独立（防关联），功能数据完整（果园可用）。
                Method issM = class_getInstanceMethod(uc, @selector(initWithSuiteName:));
                if (issM) {
                    g_origISS = method_getImplementation(issM);
                    IMP impISS = imp_implementationWithBlock(^id(id s, NSString *suite) {
                        id obj = ((id (*)(id, SEL, NSString *))g_origISS)(
                            s, @selector(initWithSuiteName:), suite);
                        if (obj && suite.length &&
                            isGroupDomain((__bridge CFStringRef)suite)) {
                            objc_setAssociatedObject(obj, &kUDGroupSuiteKey, suite,
                                                     OBJC_ASSOCIATION_RETAIN);
                        }
                        return obj;
                    });
                    class_replaceMethod(uc, @selector(initWithSuiteName:), impISS, method_getTypeEncoding(issM));
                }
                Method ofkM = class_getInstanceMethod(uc, @selector(objectForKey:));
                if (ofkM) {
                    IMP orig = method_getImplementation(ofkM);
                    IMP imp = imp_implementationWithBlock(^id(id s, NSString *key) {
                        // v64: group 域 + 身份键 → 重定向到本克隆私有域
                        if (isStrictIdentityKeyStr(key)) {
                            NSUserDefaults *p = privPeerFor(s);
                            if (p && p != s) {
                                return ((id (*)(id, SEL, NSString *))orig)(
                                    p, @selector(objectForKey:), key);
                            }
                        }
                        if (!g_inUDHook && isDeviceKey(key)) {
                            g_inUDHook = YES;
                            @try { NSString *f = getFakeID(@"PLATCUID"); g_inUDHook = NO; return f; }   // v67: NSUserDefaults 的 cuid 键 = 平台层格式
                            @catch (id e) { g_inUDHook = NO; }
                        }
                        return ((id (*)(id, SEL, NSString *))orig)(s, @selector(objectForKey:), key);
                    });
                    class_replaceMethod(uc, @selector(objectForKey:), imp, method_getTypeEncoding(ofkM));
                }
                Method sfkM = class_getInstanceMethod(uc, @selector(stringForKey:));
                if (sfkM) {
                    IMP orig = method_getImplementation(sfkM);
                    IMP imp = imp_implementationWithBlock(^NSString *(id s, NSString *key) {
                        if (isStrictIdentityKeyStr(key)) {
                            NSUserDefaults *p = privPeerFor(s);
                            if (p && p != s) {
                                return ((NSString *(*)(id, SEL, NSString *))orig)(
                                    p, @selector(stringForKey:), key);
                            }
                        }
                        if (!g_inUDHook && isDeviceKey(key)) {
                            g_inUDHook = YES;
                            @try { NSString *f = getFakeID(@"PLATCUID"); g_inUDHook = NO; return f; }   // v67: NSUserDefaults 的 cuid 键 = 平台层格式
                            @catch (id e) { g_inUDHook = NO; }
                        }
                        return ((NSString *(*)(id, SEL, NSString *))orig)(s, @selector(stringForKey:), key);
                    });
                    class_replaceMethod(uc, @selector(stringForKey:), imp, method_getTypeEncoding(sfkM));
                }
                // v64: 写入侧对称分流 —— 身份键写私有域，其余键写共享域
                // （不这么做的话，因为 v64 已不改域名，身份键会被写进共享域 → 污染）
                Method soM = class_getInstanceMethod(uc, @selector(setObject:forKey:));
                if (soM) {
                    IMP orig = method_getImplementation(soM);
                    IMP imp = imp_implementationWithBlock(^(id s, id value, NSString *key) {
                        if (isStrictIdentityKeyStr(key)) {
                            NSUserDefaults *p = privPeerFor(s);
                            if (p && p != s) {
                                ((void (*)(id, SEL, id, NSString *))orig)(
                                    p, @selector(setObject:forKey:), value, key);
                                return;
                            }
                        }
                        ((void (*)(id, SEL, id, NSString *))orig)(
                            s, @selector(setObject:forKey:), value, key);
                    });
                    class_replaceMethod(uc, @selector(setObject:forKey:), imp, method_getTypeEncoding(soM));
                }
                Method rokM = class_getInstanceMethod(uc, @selector(removeObjectForKey:));
                if (rokM) {
                    IMP orig = method_getImplementation(rokM);
                    IMP imp = imp_implementationWithBlock(^(id s, NSString *key) {
                        if (isStrictIdentityKeyStr(key)) {
                            NSUserDefaults *p = privPeerFor(s);
                            if (p && p != s) {
                                ((void (*)(id, SEL, NSString *))orig)(
                                    p, @selector(removeObjectForKey:), key);
                                return;
                            }
                        }
                        ((void (*)(id, SEL, NSString *))orig)(
                            s, @selector(removeObjectForKey:), key);
                    });
                    class_replaceMethod(uc, @selector(removeObjectForKey:), imp, method_getTypeEncoding(rokM));
                }
            }
        } @catch (id e) {}

        // ---- 5. Cookie hooks (ObjC 层) ----
        @try {
            Class cs = objc_getClass("NSHTTPCookieStorage");

            Method cfuM = class_getInstanceMethod(cs, @selector(cookiesForURL:));
            if (cfuM) {
                IMP origCFU = method_getImplementation(cfuM);
                IMP newCFU = imp_implementationWithBlock(^NSArray *(id s, NSURL *url) {
                    NSArray *cookies = ((NSArray *(*)(id, SEL, NSURL *))origCFU)(s, @selector(cookiesForURL:), url);
                    if (g_inCookieHook) return cookies;
                    g_inCookieHook = YES;
                    @try { NSArray *m = modifiedCookies(cookies); g_inCookieHook = NO; return m; }
                    @catch (id e) { g_inCookieHook = NO; return cookies; }
                });
                class_replaceMethod(cs, @selector(cookiesForURL:), newCFU, method_getTypeEncoding(cfuM));
            }

            Method allM = class_getInstanceMethod(cs, @selector(cookies));
            if (allM) {
                IMP origAll = method_getImplementation(allM);
                IMP newAll = imp_implementationWithBlock(^NSArray *(id s) {
                    NSArray *cookies = ((NSArray *(*)(id, SEL))origAll)(s, @selector(cookies));
                    if (g_inCookieHook) return cookies;
                    g_inCookieHook = YES;
                    @try { NSArray *m = modifiedCookies(cookies); g_inCookieHook = NO; return m; }
                    @catch (id e) { g_inCookieHook = NO; return cookies; }
                });
                class_replaceMethod(cs, @selector(cookies), newAll, method_getTypeEncoding(allM));
            }

            Method scM = class_getInstanceMethod(cs, @selector(setCookie:));
            if (scM) {
                IMP origSC = method_getImplementation(scM);
                IMP newSC = imp_implementationWithBlock(^void(id s, NSHTTPCookie *cookie) {
                    if (cookie && isDeviceCookie(cookie.name)) {
                        @try {
                            captureRealIdentity(cookie.name, cookie.value);   // v57U: 捕获真实值
                            NSString *fakeValue = getFakeID(cookie.name);
                            NSMutableDictionary *props = [NSMutableDictionary dictionary];
                            props[NSHTTPCookieName] = cookie.name;
                            props[NSHTTPCookieValue] = fakeValue;
                            if (cookie.domain) props[NSHTTPCookieDomain] = cookie.domain;
                            if (cookie.path) props[NSHTTPCookiePath] = cookie.path;
                            if (cookie.expiresDate) props[NSHTTPCookieExpires] = cookie.expiresDate;
                            props[NSHTTPCookieVersion] = @(cookie.version);
                            if (cookie.secure) props[NSHTTPCookieSecure] = @YES;
                            NSHTTPCookie *fakeCookie = [[NSHTTPCookie alloc] initWithProperties:props];
                            if (fakeCookie) {
                                ((void (*)(id, SEL, NSHTTPCookie *))origSC)(s, @selector(setCookie:), fakeCookie);
                                return;
                            }
                        } @catch (id e) {}
                    }
                    ((void (*)(id, SEL, NSHTTPCookie *))origSC)(s, @selector(setCookie:), cookie);
                });
                class_replaceMethod(cs, @selector(setCookie:), newSC, method_getTypeEncoding(scM));
            }

            Method scsM = class_getInstanceMethod(cs, @selector(setCookies:forURL:mainDocumentURL:));
            if (scsM) {
                IMP origSCS = method_getImplementation(scsM);
                IMP newSCS = imp_implementationWithBlock(^void(id s, NSArray *cookies, NSURL *URL, NSURL *mainDocumentURL) {
                    if (g_inCookieHook) {
                        ((void (*)(id, SEL, NSArray *, NSURL *, NSURL *))origSCS)(s, @selector(setCookies:forURL:mainDocumentURL:), cookies, URL, mainDocumentURL);
                        return;
                    }
                    g_inCookieHook = YES;
                    @try {
                        NSArray *m = modifiedCookies(cookies);
                        g_inCookieHook = NO;
                        ((void (*)(id, SEL, NSArray *, NSURL *, NSURL *))origSCS)(s, @selector(setCookies:forURL:mainDocumentURL:), m, URL, mainDocumentURL);
                        return;
                    } @catch (id e) { g_inCookieHook = NO; }
                    ((void (*)(id, SEL, NSArray *, NSURL *, NSURL *))origSCS)(s, @selector(setCookies:forURL:mainDocumentURL:), cookies, URL, mainDocumentURL);
                });
                class_replaceMethod(cs, @selector(setCookies:forURL:mainDocumentURL:), newSCS, method_getTypeEncoding(scsM));
            }
        } @catch (id e) {}

        // ---- 6. NSMutableURLRequest hooks — Cookie + UA 替换 ----
        // v57N: UA 必须替换（否则泄露真系统版本，与伪造机型矛盾）
        @try {
            Class reqClass = objc_getClass("NSMutableURLRequest");
            if (reqClass) {
#if !MT_CLONE
                Method svM = class_getInstanceMethod(reqClass, @selector(setValue:forHTTPHeaderField:));
                if (svM) {
                    IMP origSV = method_getImplementation(svM);
                    IMP newSV = imp_implementationWithBlock(^void(id s, NSString *value, NSString *field) {
                        // UA 替换
                        if (value && field && [field caseInsensitiveCompare:@"User-Agent"] == NSOrderedSame
                            && isUALike(value)) {
                            ((void (*)(id, SEL, NSString *, NSString *))origSV)(s, @selector(setValue:forHTTPHeaderField:), ensureBaiduboxAppUA(value), field);
                            return;
                        }
                        if (value && field && [field caseInsensitiveCompare:@"Cookie"] == NSOrderedSame) {
                            NSArray *names = @[@"BAIDUCUID", @"BAIDUCUID_BFESS", @"MAWEBCUID",
                                               @"DVIF", @"tcuid", @"__bid_n", @"fuid",
                                               @"BAIDUID", @"BAIDUID_BFESS"];
                            NSString *modified = value;
                            for (NSString *name in names) {
                                NSString *fake = getFakeID(name);
                                NSRegularExpression *regex = [NSRegularExpression
                                    regularExpressionWithPattern:[NSString stringWithFormat:@"%@=[^;]+", name]
                                    options:NSRegularExpressionCaseInsensitive error:nil];
                                modified = [regex stringByReplacingMatchesInString:modified options:0
                                    range:NSMakeRange(0, modified.length)
                                    withTemplate:[NSString stringWithFormat:@"%@=%@", name, fake]];
                            }
                            NSRegularExpression *cuidRegex = [NSRegularExpression
                                regularExpressionWithPattern:@"(?<![A-Za-z_])cuid=[^;]+" options:0 error:nil];
                            modified = [cuidRegex stringByReplacingMatchesInString:modified options:0
                                range:NSMakeRange(0, modified.length)
                                withTemplate:[NSString stringWithFormat:@"cuid=%@", getFakeID(@"cuid")]];
                            ((void (*)(id, SEL, NSString *, NSString *))origSV)(s, @selector(setValue:forHTTPHeaderField:), modified, field);
                            return;
                        }
                        ((void (*)(id, SEL, NSString *, NSString *))origSV)(s, @selector(setValue:forHTTPHeaderField:), value, field);
                    });
                    class_replaceMethod(reqClass, @selector(setValue:forHTTPHeaderField:), newSV, method_getTypeEncoding(svM));
                }

                Method addValM = class_getInstanceMethod(reqClass, @selector(addValue:forHTTPHeaderField:));
                if (addValM) {
                    IMP origAddVal = method_getImplementation(addValM);
                    IMP newAddVal = imp_implementationWithBlock(^void(id s, NSString *value, NSString *field) {
                        if (value && field && [field caseInsensitiveCompare:@"User-Agent"] == NSOrderedSame
                            && isUALike(value)) {
                            ((void (*)(id, SEL, NSString *, NSString *))origAddVal)(s, @selector(addValue:forHTTPHeaderField:), ensureBaiduboxAppUA(value), field);
                            return;
                        }
                        if (value && field && [field caseInsensitiveCompare:@"Cookie"] == NSOrderedSame) {
                            NSArray *names = @[@"BAIDUCUID", @"BAIDUCUID_BFESS", @"MAWEBCUID",
                                               @"DVIF", @"tcuid", @"__bid_n", @"fuid",
                                               @"BAIDUID", @"BAIDUID_BFESS"];
                            NSString *modified = value;
                            for (NSString *name in names) {
                                NSString *fake = getFakeID(name);
                                NSRegularExpression *regex = [NSRegularExpression
                                    regularExpressionWithPattern:[NSString stringWithFormat:@"%@=[^;]+", name]
                                    options:NSRegularExpressionCaseInsensitive error:nil];
                                modified = [regex stringByReplacingMatchesInString:modified options:0
                                    range:NSMakeRange(0, modified.length)
                                    withTemplate:[NSString stringWithFormat:@"%@=%@", name, fake]];
                            }
                            NSRegularExpression *cuidRegex = [NSRegularExpression
                                regularExpressionWithPattern:@"(?<![A-Za-z_])cuid=[^;]+" options:0 error:nil];
                            modified = [cuidRegex stringByReplacingMatchesInString:modified options:0
                                range:NSMakeRange(0, modified.length)
                                withTemplate:[NSString stringWithFormat:@"cuid=%@", getFakeID(@"cuid")]];
                            ((void (*)(id, SEL, NSString *, NSString *))origAddVal)(s, @selector(addValue:forHTTPHeaderField:), modified, field);
                            return;
                        }
                        ((void (*)(id, SEL, NSString *, NSString *))origAddVal)(s, @selector(addValue:forHTTPHeaderField:), value, field);
                    });
                    class_replaceMethod(reqClass, @selector(addValue:forHTTPHeaderField:), newAddVal, method_getTypeEncoding(addValM));
                }
#endif // !MT_CLONE

                // v57U: 请求出口消毒 —— URL 参数 / POST body 里的真实 cuid
                // 原生 SDK 拼请求时 cuid=%@ 直接进 query/body（不走 cookie），
                // 按值替换为本克隆伪造值，与 cookie 保持单一身份
                Method suM = class_getInstanceMethod(reqClass, @selector(setURL:));
                if (suM) {
                    IMP origSetURL = method_getImplementation(suM);
                    IMP newSetURL = imp_implementationWithBlock(^void(id s, NSURL *u) {
                        NSURL *nu = u;
                        @try {
                            if (u.absoluteString.length > 20) {
                                NSString *r = rewriteIdentityString(u.absoluteString);
                                if (r != u.absoluteString) nu = [NSURL URLWithString:r] ?: u;
                            }
                        } @catch (id e) {}
                        ((void (*)(id, SEL, NSURL *))origSetURL)(s, @selector(setURL:), nu);
                    });
                    class_replaceMethod(reqClass, @selector(setURL:), newSetURL, method_getTypeEncoding(suM));
                }
                Method sbM = class_getInstanceMethod(reqClass, @selector(setHTTPBody:));
                if (sbM) {
                    IMP origSetBody = method_getImplementation(sbM);
                    IMP newSetBody = imp_implementationWithBlock(^void(id s, NSData *body) {
                        NSData *nb = body;
                        @try { if (body) nb = rewriteIdentityData(body); } @catch (id e) {}
                        ((void (*)(id, SEL, NSData *))origSetBody)(s, @selector(setHTTPBody:), nb);
                    });
                    class_replaceMethod(reqClass, @selector(setHTTPBody:), newSetBody, method_getTypeEncoding(sbM));
                }
                Method iwM = class_getInstanceMethod(reqClass, @selector(initWithURL:));
                if (iwM) {
                    IMP origInitURL = method_getImplementation(iwM);
                    IMP newInitURL = imp_implementationWithBlock(^id(id s, NSURL *u) {
                        NSURL *nu = u;
                        @try {
                            if (u.absoluteString.length > 20) {
                                NSString *r = rewriteIdentityString(u.absoluteString);
                                if (r != u.absoluteString) nu = [NSURL URLWithString:r] ?: u;
                            }
                        } @catch (id e) {}
                        return ((id (*)(id, SEL, NSURL *))origInitURL)(s, @selector(initWithURL:), nu);
                    });
                    class_replaceMethod(reqClass, @selector(initWithURL:), newInitURL, method_getTypeEncoding(iwM));
                }
            }
        } @catch (id e) {}

#if !MT_CLONE
        // ---- 6b. WKWebView hooks — UA 注入（v57Q 新增，农场关键） ----
        //
        // ★★ 这是「活动太火爆，请稍后再试」的真正根因 ★★
        //
        // 百度农场（se-act.baidu.com）是**跑在 WKWebView 里的 H5 页面**，
        // 不是原生 API 调用。WKWebView 发出的网络请求**完全绕过**
        // NSMutableURLRequest.setValue:forHTTPHeaderField: —— 也就是说
        // 上面第 6 节写的 UA hook 对农场页面**一次都不会触发**。
        //
        // 结果：农场页面带着 WKWebView 默认 UA 访问服务端，该 UA 里没有
        // baiduboxapp/ 段 → 服务端判定"非百度 App 环境" → 返回兜底文案
        // 「活动太火爆，请稍后再试」。
        //
        // 这正是此前 UA 里出现 light/1.0(WKWebView) 的来源：我们看到的
        // 就是 WKWebView 的原生 UA，我们的替换根本没生效。
        //
        // 正确做法：三条路**全部**设成同一个完整 UA（含 baiduboxapp 段）。
        //
        //   优先级：customUserAgent > NSUserDefaults > applicationNameForUserAgent
        //   生效的只有一条，其余被忽略 —— 所以三条都填同一个完整 UA 是安全的，
        //   不会产生重复段，同时保证「无论 App 走哪条路」结果都正确。
        //
        //   为什么必须带 customUserAgent：applicationNameForUserAgent 是
        //   「追加到默认 UA」语义，而默认 UA 里没有 baiduboxapp；只设它不够。
        //   customUserAgent 是「整体替换」语义，优先级最高，才是主力手段。
        //
        //   v57T: 移除 dlopen(WebKit) —— 已确认 App 主二进制自带
        //   LC_LOAD_DYLIB WebKit，dyld 在构造函数运行前必然已加载它，
        //   objc_getClass 不会返回 nil；dlopen 反而是 v57R/v57S 闪退的
        //   剩余可疑增量之一（二分期间先去掉）。
        @try {
            Class wkCfg = objc_getClass("WKWebViewConfiguration");
            if (wkCfg) {
                Method setAppNameM = class_getInstanceMethod(wkCfg, @selector(setApplicationNameForUserAgent:));
                if (setAppNameM) {
                    IMP origSAN = method_getImplementation(setAppNameM);
                    IMP newSAN = imp_implementationWithBlock(^void(id s, NSString *name) {
                        // v61: 只补缺段，绝不覆盖 App 自己设的值
                        ((void (*)(id, SEL, NSString *))origSAN)(s, @selector(setApplicationNameForUserAgent:), ensureBaiduboxAppUA(name));
                    });
                    class_replaceMethod(wkCfg, @selector(setApplicationNameForUserAgent:), newSAN, method_getTypeEncoding(setAppNameM));
                }
            }
        } @catch (id e) {}

        @try {
            Class wkView = objc_getClass("WKWebView");
            if (wkView) {
                // c1) 读取侧：getter 永远返回完整 App UA
                Method getUAM = class_getInstanceMethod(wkView, @selector(customUserAgent));
                if (getUAM) {
                    IMP origGUA = method_getImplementation(getUAM);
                    IMP newGUA = imp_implementationWithBlock(^NSString *(id s) {
                        // v61: 读原始值，缺段才补 —— 不再无条件返回硬编码 UA
                        NSString *cur = ((NSString *(*)(id, SEL))origGUA)(s, @selector(customUserAgent));
                        return ensureBaiduboxAppUA(cur);
                    });
                    class_replaceMethod(wkView, @selector(customUserAgent), newGUA, method_getTypeEncoding(getUAM));
                }
                // c2) 写入侧：透传 App 设的值（缺 baiduboxapp 段才补）
                Method setUAM = class_getInstanceMethod(wkView, @selector(setCustomUserAgent:));
                if (setUAM) {
                    IMP origSUA = method_getImplementation(setUAM);
                    IMP newSUA = imp_implementationWithBlock(^void(id s, NSString *ua) {
                        ((void (*)(id, SEL, NSString *))origSUA)(s, @selector(setCustomUserAgent:), ensureBaiduboxAppUA(ua));
                    });
                    class_replaceMethod(wkView, @selector(setCustomUserAgent:), newSUA, method_getTypeEncoding(setUAM));
                }
                // c3) 构造侧：v61 起不再主动写 UA。只在 config 的
                //     applicationNameForUserAgent 为空或确实缺 baiduboxapp 段时补一段，
                //     防止个别页面因没设 UA 退化成「非 App 环境」。
                Method initM = class_getInstanceMethod(wkView, @selector(initWithFrame:configuration:));
                if (initM) {
                    IMP origInit = method_getImplementation(initM);
                    IMP newInit = imp_implementationWithBlock(^id(id s, CGRect frame, id config) {
                        @try {
                            if (config &&
                                [config respondsToSelector:@selector(applicationNameForUserAgent)] &&
                                [config respondsToSelector:@selector(setApplicationNameForUserAgent:)]) {
                                NSString *cur = [config applicationNameForUserAgent];
                                if (cur.length == 0 || [cur rangeOfString:@"baiduboxapp"].location == NSNotFound) {
                                    [config setApplicationNameForUserAgent:ensureBaiduboxAppUA(cur)];
                                }
                            }
                        } @catch (id e) {}
                        return ((id (*)(id, SEL, CGRect, id))origInit)(s, @selector(initWithFrame:configuration:), frame, config);
                    });
                    class_replaceMethod(wkView, @selector(initWithFrame:configuration:), newInit, method_getTypeEncoding(initM));
                }

                // v57U: loadRequest: 出口消毒 —— App 打开 H5 活动页（含农场）
                // 时会把 SDK 计算的 cuid 等身份参数拼进 URL query，
                // 同样按值替换为本克隆伪造值
                Method lrM = class_getInstanceMethod(wkView, @selector(loadRequest:));
                if (lrM) {
                    IMP origLR = method_getImplementation(lrM);
                    IMP newLR = imp_implementationWithBlock(^void(id s, NSURLRequest *req) {
                        NSURLRequest *nr = req;
                        @try {
                            if (req.URL.absoluteString.length > 20) {
                                NSString *r = rewriteIdentityString(req.URL.absoluteString);
                                if (r != req.URL.absoluteString) {
                                    NSURL *nu = [NSURL URLWithString:r];
                                    if (nu) {
                                        nr = [NSURLRequest requestWithURL:nu];
                                    }
                                }
                            }
                        } @catch (id e) {}
                        ((void (*)(id, SEL, NSURLRequest *))origLR)(s, @selector(loadRequest:), nr);
                    });
                    class_replaceMethod(wkView, @selector(loadRequest:), newLR, method_getTypeEncoding(lrM));
                }

                // 补充：NSUserDefaults["UserAgent"] 是另一种较低优先级的设置方式，
                // 优先级低于 customUserAgent。由于我们已将 customUserAgent 全路径
                // 强制为完整 App UA，该方法即使被调用也不会生效，无需额外 hook。
            }
        } @catch (id e) {}
#endif // !MT_CLONE
        // （MT_CLONE=1 时跳过 6b：百度 UA 注入对美团是风控现行，美团 H5 用系统默认 UA）

        // ---- 7. fishhook — hook 所有非系统镜像 + dyld 回调 ----
        // v57L rebind 清单：sysctlbyname + MGCopyAnswer + IOKit
        //                  + 4个 C 层 Cookie API + 3个 CFPreferences API
        @try {
            g_rebindings[0] = (struct rebinding){"sysctlbyname",                          (void *)hook_sysctlbyname,                          (void **)&orig_sysctlbyname};
            g_rebindings[1] = (struct rebinding){"MGCopyAnswer",                          (void *)hook_MGCopyAnswer,                          (void **)&orig_MGCopyAnswer};
            g_rebindings[2] = (struct rebinding){"IORegistryEntryCreateCFProperty",       (void *)hook_IORegistryEntryCreateCFProperty,       (void **)&orig_IORegistryEntryCreateCFProperty};
            g_rebindings[3] = (struct rebinding){"CFHTTPCookieStorageSetCookie",          (void *)hook_CFHTTPCookieStorageSetCookie,          (void **)&orig_CFHTTPCookieStorageSetCookie};
            g_rebindings[4] = (struct rebinding){"CFHTTPCookieStorageSetCookies",         (void *)hook_CFHTTPCookieStorageSetCookies,         (void **)&orig_CFHTTPCookieStorageSetCookies};
            g_rebindings[5] = (struct rebinding){"CFHTTPCookieStorageCopyCookiesForURL",  (void *)hook_CFHTTPCookieStorageCopyCookiesForURL,  (void **)&orig_CFHTTPCookieStorageCopyCookiesForURL};
            g_rebindings[6] = (struct rebinding){"CFHTTPCookieStorageCopyAllCookies",     (void *)hook_CFHTTPCookieStorageCopyAllCookies,     (void **)&orig_CFHTTPCookieStorageCopyAllCookies};
            g_rebindings[7] = (struct rebinding){"CFPreferencesCopyAppValue",             (void *)hook_CFPreferencesCopyAppValue,             (void **)&orig_CFPreferencesCopyAppValue};
            g_rebindings[8] = (struct rebinding){"CFPreferencesCopyValue",                (void *)hook_CFPreferencesCopyValue,                (void **)&orig_CFPreferencesCopyValue};
            // v57U: keychain 出口消毒（只按值替换返回内容，查询不过滤）
            g_rebindings[9]  = (struct rebinding){"SecItemCopyMatching",                  (void *)hook_SecItemCopyMatching,                   (void **)&orig_SecItemCopyMatching};
            // v57V: 写入侧也拦截，让 keychain 天然存伪造 cuid
            g_rebindings[10] = (struct rebinding){"SecItemAdd",                           (void *)hook_SecItemAdd,                            (void **)&orig_SecItemAdd};
            g_rebindings[11] = (struct rebinding){"SecItemUpdate",                        (void *)hook_SecItemUpdate,                         (void **)&orig_SecItemUpdate};
            // v59: 删除也要隔离（否则清 keychain 会连带删掉共享组里其他克隆的票据）
            g_rebindings[12] = (struct rebinding){"SecItemDelete",                        (void *)hook_SecItemDelete,                         (void **)&orig_SecItemDelete};
            // v63: CFBundleGetIdentifier 的 rebind 已移除 —— 它属于 v60 的
            // 「包标识伪装」，与 NSBundle 那组 hook 同批停用。保留它会造成
            // 「C 层报官方值、ObjC 层报真实值」的自相矛盾，反而更容易被察觉。
            g_rebindings[13] = (struct rebinding){"CFPreferencesSetAppValue",             (void *)hook_CFPreferencesSetAppValue,              (void **)&orig_CFPreferencesSetAppValue};

            // v60: 隐藏注入痕迹。这里只「填表」，真正的 rebind 放在 7d ——
            // 这几个 API 自身的 GOT 会被替换，安装前必须先把镜像列表收全。
            // 提前填表是为了让 7b 注册的 dyld 回调里也能安全使用。
            g_hide_rebindings[0] = (struct rebinding){"_dyld_image_count",            (void *)hook_dyld_image_count,           (void **)&orig_dyld_image_count};
            g_hide_rebindings[1] = (struct rebinding){"_dyld_get_image_name",         (void *)hook_dyld_get_image_name,        (void **)&orig_dyld_get_image_name};
            g_hide_rebindings[2] = (struct rebinding){"_dyld_get_image_header",       (void *)hook_dyld_get_image_header,      (void **)&orig_dyld_get_image_header};
            g_hide_rebindings[3] = (struct rebinding){"_dyld_get_image_vmaddr_slide", (void *)hook_dyld_get_image_vmaddr_slide,(void **)&orig_dyld_get_image_vmaddr_slide};
            // v57T: uname/sysctl/gethostname 三条 rebind 暂时移除（闪退二分定位）
            // v70: uname/gethostname 绑回（真凶另有其人，见 REBIND_COUNT 注释）；
            //      老 sysctl() 继续不绑。
            g_rebindings[14] = (struct rebinding){"uname",                              (void *)hook_uname,                                 (void **)&orig_uname};
            g_rebindings[15] = (struct rebinding){"gethostname",                        (void *)hook_gethostname,                           (void **)&orig_gethostname};
            g_rebindings[16] = (struct rebinding){"CNCopyCurrentNetworkInfo",            (void *)hook_CNCopyCurrentNetworkInfo,               (void **)&orig_CNCopyCurrentNetworkInfo};
            // g_rebindings[9]  = (struct rebinding){"uname",                              (void *)hook_uname,                                 (void **)&orig_uname};
            // g_rebindings[10] = (struct rebinding){"sysctl",                             (void *)hook_sysctl,                                (void **)&orig_sysctl};
            // g_rebindings[11] = (struct rebinding){"gethostname",                        (void *)hook_gethostname,                           (void **)&orig_gethostname};

            // 7a. hook 所有已加载的非系统镜像
            uint32_t count = _dyld_image_count();
            for (uint32_t i = 0; i < count; i++) {
                const struct mach_header *header = _dyld_get_image_header(i);
                intptr_t slide = _dyld_get_image_vmaddr_slide(i);
                const char *path = _dyld_get_image_name(i);
                if (!header || !path) continue;
                if (strncmp(path, "/usr/lib/", 9) == 0) continue;
                if (strncmp(path, "/System/", 8) == 0) continue;
                if (strncmp(path, "/Developer/", 11) == 0) continue;
                rebind_symbols_image((void *)header, slide, g_rebindings, REBIND_COUNT);
            }

            // 7b. 注册 dyld 回调（动态加载的框架也覆盖，用全局 C 函数）
            _dyld_register_func_for_add_image(hook_new_image);

            // ---- 7c/7d. v63: v60 的「包标识伪装 + dyld 枚举隐藏」整体停用 ----
            //
            // ★ 启动闪退根因（v59 好用、v62 崩，中间只有这两段是新增）★
            //
            // 7c（installBundleIdentifierHooks）把 NSBundle 的
            //   -bundleIdentifier / -infoDictionary / -objectForInfoDictionaryKey
            // 全局替换，而这几个 hook 里判断「是不是主 bundle」用的是
            //   bundle == [NSBundle mainBundle]
            // 首次调用 [NSBundle mainBundle] 需要读自己的 Info.plist →
            // 触发 -infoDictionary → 进 hook → 再调 [NSBundle mainBundle]
            // （此刻尚未缓存）→ 无限递归 → 栈溢出 → 启动即崩。
            // 且它在启动早期被 Foundation 高频调用，必崩。
            //
            // 7d（dyld 枚举隐藏）hook 的是 _dyld_image_count /
            //   _dyld_get_image_name 等 dyld 自身的 API，系统组件、
            //   ObjC 运行时、崩溃上报 SDK 在启动早期都会调它们，
            //   每次调用都要 O(n) 遍历重映射，且与系统用这些 API 的
            //   时序互相干扰 —— 同为启动期高危。
            //
            // 结论：这两项收益本来就低（包名检测百度实际没做；dyld 枚举
            // 是崩溃 SDK 的常规用法），风险却最高。先用最稳的组合：
            //   v59 的 keychain 隔离 + v61 的功能回退 + v62 的 suite 域隔离。
            // 两段实现全部保留在文件里（未删除），后续要恢复需先修掉
            // isMainBundleObject 的递归（改成缓存 mainBundle 指针一次性比较）。
#if 0
            installBundleIdentifierHooks();

            @try {
                static void *hideHdrs[HIDE_MAX_IMG];
                static intptr_t hideSlides[HIDE_MAX_IMG];
                int hideN = 0;
                uint32_t cnt2 = _dyld_image_count();      // 此刻尚未被替换
                for (uint32_t i = 0; i < cnt2 && hideN < HIDE_MAX_IMG; i++) {
                    const struct mach_header *h = _dyld_get_image_header(i);
                    const char *p = _dyld_get_image_name(i);
                    if (!h || !p) continue;
                    if (strncmp(p, "/usr/lib/", 9) == 0) continue;
                    if (strncmp(p, "/System/", 8) == 0) continue;
                    if (strncmp(p, "/Developer/", 11) == 0) continue;
                    hideHdrs[hideN] = (void *)h;
                    hideSlides[hideN] = _dyld_get_image_vmaddr_slide(i);
                    hideN++;
                }
                for (int k = 0; k < hideN; k++) {
                    rebind_symbols_image(hideHdrs[k], hideSlides[k],
                                         g_hide_rebindings, HIDE_REBIND_COUNT);
                }
            } @catch (id e) {}
#endif

            // ---- 8. v68/v69: 诊断日志（T7）----
            @try {
                Class sc = objc_getClass("NSURLSession");
                if (sc) {
                    // 8a. block 型 data task（v68，含响应）
                    SEL sel = @selector(dataTaskWithRequest:completionHandler:);
                    Method m = class_getInstanceMethod(sc, sel);
                    if (m) {
                        IMP orig = method_getImplementation(m);
                        IMP imp = imp_implementationWithBlock(
                            ^NSURLSessionDataTask *(id s, NSURLRequest *req,
                                                     void (^ch)(NSData *, NSURLResponse *, NSError *)) {
                                diagDumpRequest(req, @"REQ");
                                if (!ch) {
                                    return ((NSURLSessionDataTask *(*)(id, SEL, NSURLRequest *, id))orig)(
                                        s, @selector(dataTaskWithRequest:completionHandler:), req, nil);
                                }
                                void (^wrapped)(NSData *, NSURLResponse *, NSError *) =
                                    ^(NSData *d, NSURLResponse *r, NSError *e) {
                                        @try {
                                            if ([r isKindOfClass:objc_getClass("NSHTTPURLResponse")]) {
                                                diagDumpResponse(req, (NSHTTPURLResponse *)r, d);
                                            }
                                        } @catch (id ex) {}
                                        ch(d, r, e);
                                    };
                                return ((NSURLSessionDataTask *(*)(id, SEL, NSURLRequest *, id))orig)(
                                    s, @selector(dataTaskWithRequest:completionHandler:), req, wrapped);
                            });
                        class_replaceMethod(sc, sel, imp, method_getTypeEncoding(m));
                    }
                    // 8b. v69: delegate 型 data task（请求侧）
                    SEL sel2 = @selector(dataTaskWithRequest:);
                    Method m2 = class_getInstanceMethod(sc, sel2);
                    if (m2) {
                        IMP orig = method_getImplementation(m2);
                        IMP imp = imp_implementationWithBlock(
                            ^NSURLSessionDataTask *(id s, NSURLRequest *req) {
                                diagDumpRequest(req, @"DELEG-REQ");
                                return ((NSURLSessionDataTask *(*)(id, SEL, NSURLRequest *))orig)(
                                    s, @selector(dataTaskWithRequest:), req);
                            });
                        class_replaceMethod(sc, sel2, imp, method_getTypeEncoding(m2));
                    }
                    // 8c. v69: block 型 upload task
                    SEL sel3 = @selector(uploadTaskWithRequest:fromData:completionHandler:);
                    Method m3 = class_getInstanceMethod(sc, sel3);
                    if (m3) {
                        IMP orig = method_getImplementation(m3);
                        IMP imp = imp_implementationWithBlock(
                            ^NSURLSessionUploadTask *(id s, NSURLRequest *req, NSData *body,
                                                      void (^ch)(NSData *, NSURLResponse *, NSError *)) {
                                diagDumpRequest(req, @"UPL-REQ");
                                if (body) diagAppend([NSString stringWithFormat:
                                    @"  UPBODY: %@\n", [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding] ?: @"<binary>"]);
                                if (!ch) {
                                    return ((NSURLSessionUploadTask *(*)(id, SEL, NSURLRequest *, NSData *, id))orig)(
                                        s, @selector(uploadTaskWithRequest:fromData:completionHandler:), req, body, nil);
                                }
                                void (^wrapped)(NSData *, NSURLResponse *, NSError *) =
                                    ^(NSData *d, NSURLResponse *r, NSError *e) {
                                        @try {
                                            if ([r isKindOfClass:objc_getClass("NSHTTPURLResponse")]) {
                                                diagDumpResponse(req, (NSHTTPURLResponse *)r, d);
                                            }
                                        } @catch (id ex) {}
                                        ch(d, r, e);
                                    };
                                return ((NSURLSessionUploadTask *(*)(id, SEL, NSURLRequest *, NSData *, id))orig)(
                                    s, @selector(uploadTaskWithRequest:fromData:completionHandler:), req, body, wrapped);
                            });
                        class_replaceMethod(sc, sel3, imp, method_getTypeEncoding(m3));
                    }
                }
                // 8d. v69: session 创建时抓 delegate → swizzle 其 didReceiveData/didComplete
                @try {
                    SEL csel = @selector(sessionWithConfiguration:delegate:delegateQueue:);
                    Method cm = class_getClassMethod(objc_getClass("NSURLSession"), csel);
                    if (cm) {
                        IMP orig = method_getImplementation(cm);
                        IMP imp = imp_implementationWithBlock(
                            ^NSURLSession *(id s, NSURLSessionConfiguration *cfg, id dg, NSOperationQueue *q) {
                                diagSwizzleNetDelegate(dg);
                                return ((NSURLSession *(*)(id, SEL, NSURLSessionConfiguration *, id, NSOperationQueue *))orig)(
                                    s, csel, cfg, dg, q);
                            });
                        method_setImplementation(cm, imp);
                    }
                    SEL isel = @selector(initWithConfiguration:delegate:delegateQueue:);
                    Method im = class_getInstanceMethod(objc_getClass("NSURLSession"), isel);
                    if (im) {
                        IMP orig = method_getImplementation(im);
                        IMP imp = imp_implementationWithBlock(
                            ^id (id s, NSURLSessionConfiguration *cfg, id dg, NSOperationQueue *q) {
                                diagSwizzleNetDelegate(dg);
                                return ((id (*)(id, SEL, NSURLSessionConfiguration *, id, NSOperationQueue *))orig)(
                                    s, isel, cfg, dg, q);
                            });
                        class_replaceMethod(objc_getClass("NSURLSession"), isel, imp, method_getTypeEncoding(im));
                    }
                } @catch (id e) {}
                Class wc = objc_getClass("WKWebView");
                if (wc) {
                    SEL lsel = @selector(loadRequest:);
                    Method lm = class_getInstanceMethod(wc, lsel);
                    if (lm) {
                        IMP orig = method_getImplementation(lm);
                        IMP imp = imp_implementationWithBlock(^id (id s, NSURLRequest *req) {
                            diagDumpRequest(req, @"WEBVIEW");
                            return ((id (*)(id, SEL, NSURLRequest *))orig)(
                                s, @selector(loadRequest:), req);
                        });
                        class_replaceMethod(wc, lsel, imp, method_getTypeEncoding(lm));
                    }
                }
                // 8e. v69: 记录 H5↔原生 JSBridge 名单
                @try {
                    Class ucc = objc_getClass("WKUserContentController");
                    if (ucc) {
                        SEL asel = @selector(addScriptMessageHandler:name:);
                        Method am = class_getInstanceMethod(ucc, asel);
                        if (am) {
                            IMP orig = method_getImplementation(am);
                            IMP imp = imp_implementationWithBlock(
                                ^void (id s, id handler, NSString *name) {
                                    diagAppend([NSString stringWithFormat:@"\n[%@] JSBRIDGE register: %@\n", [NSDate date], name]);
                                    ((void (*)(id, SEL, id, NSString *))orig)(s, asel, handler, name);
                                });
                            class_replaceMethod(ucc, asel, imp, method_getTypeEncoding(am));
                        }
                    }
                } @catch (id e) {}
                diagAppend(@"==== diag hooks v69 installed ====\n");
            } @catch (id e) {}
        } @catch (id e) {}
    }
}
