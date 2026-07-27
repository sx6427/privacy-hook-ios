//
//  PrivacyHook.m
//  Device Fingerprint + Login State Isolation Dylib for iOS
//
//  v21: Runtime keychain isolation via SecItem* hooks.
//       v20's blanket clearKeychainOnce() was destructive — clone B's
//       first launch deleted ALL keychain items (including clone A's),
//       then payment SDK wrote fresh risk flags visible to both clones.
//
//       v21 replaces blanket clear with per-clone namespace prefix.
//       Each clone gets a unique UUID. All kSecAttrService values are
//       transparently prefixed (e.g. "uuid|com.baidu.pay"), so each
//       clone only sees its own keychain items. No cross-contamination.
//
//  v20: Hook CFBundleGetIdentifier + CFBundleGetValueForInfoDictionaryKey
//       via fishhook. These are CoreFoundation C functions that payment
//       SDKs use to read Bundle ID, bypassing ALL ObjC method hooks.
//
//  ROOT CAUSE ANALYSIS:
//  Payment SDK reads CFBundleIdentifier via 5 paths:
//  1. [NSBundle mainBundle].bundleIdentifier           → ObjC hook ✅ (v13+)
//  2. [NSBundle mainBundle] objectForInfoDictionaryKey: → ObjC hook ✅ (v19)
//  3. [NSBundle mainBundle].infoDictionary[@"CFBundle..."] → ivar mod ✅ (v19)
//  4. CFBundleGetIdentifier(CFBundleGetMainBundle())  → C function ❌ NOT HOOKED
//  5. CFBundleGetValueForInfoDictionaryKey(...)        → C function ❌ NOT HOOKED
//
//  v13 "sometimes worked" = SDK sometimes used ObjC (hooked), sometimes C (not).
//  After v14's aggressive hooks, SDK switched to always using C API → always fail.
//
//  v20 uses fishhook ONLY for these 2 C functions. No sysctl, no getifaddrs,
//  no dyld, no dladdr — those were what caused v14's account bans.
//  fishhook for 2 CFBundle functions is minimal and safe.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <AppTrackingTransparency/AppTrackingTransparency.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach/mach.h>
#import <string.h>
#import <dlfcn.h>

#define NSLog(...)

// ============================================================
// fishhook — minimal rebind_symbols (fixed: skip leading underscore)
// ============================================================
struct rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

static void fishhook_rebind(const struct rebinding rebindings[], size_t rebindings_nel) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *header = _dyld_get_image_header(i);
        if (!header) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);

        BOOL is64 = (header->magic == 0xFEEDFACF);
        if (!is64 && header->magic != 0xFEEDFACE) continue;

        const uint8_t *ptr = (const uint8_t *)header;
        uint32_t ncmds;
        if (is64) {
            ncmds = ((struct mach_header_64 *)header)->ncmds;
            ptr += sizeof(struct mach_header_64);
        } else {
            ncmds = ((struct mach_header *)header)->ncmds;
            ptr += sizeof(struct mach_header);
        }

        uint64_t linkedit_fileoff = 0, linkedit_vmaddr = 0;
        struct symtab_command symtab = {0};
        struct dysymtab_command dysymtab = {0};

        typedef struct { uint64_t addr; uint64_t size; } ptr_section_t;
        ptr_section_t ptr_sections[8];
        int ptr_section_count = 0;

        for (uint32_t c = 0; c < ncmds; c++) {
            const struct load_command *lc = (const struct load_command *)ptr;
            if (lc->cmd == 0 || lc->cmdsize == 0) break;

            if (is64 && lc->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *seg = (struct segment_command_64 *)ptr;
                if (strcmp(seg->segname, SEG_DATA) == 0) {
                    const struct section_64 *sects = (const struct section_64 *)
                        (ptr + sizeof(struct segment_command_64));
                    for (uint32_t s = 0; s < seg->nsects; s++) {
                        if ((strcmp(sects[s].sectname, "__la_symbol_ptr") == 0 ||
                             strcmp(sects[s].sectname, "__got") == 0) &&
                            ptr_section_count < 8) {
                            ptr_sections[ptr_section_count].addr = sects[s].addr;
                            ptr_sections[ptr_section_count].size = sects[s].size;
                            ptr_section_count++;
                        }
                    }
                }
                if (strcmp(seg->segname, "__LINKEDIT") == 0) {
                    linkedit_fileoff = seg->fileoff;
                    linkedit_vmaddr = seg->vmaddr;
                }
            }

            if (lc->cmd == LC_SYMTAB)
                memcpy(&symtab, ptr, sizeof(struct symtab_command));
            if (lc->cmd == LC_DYSYMTAB)
                memcpy(&dysymtab, ptr, sizeof(struct dysymtab_command));

            ptr += lc->cmdsize;
        }

        if (ptr_section_count == 0 || !symtab.symoff || !dysymtab.indirectsymoff) continue;

        uintptr_t linkedit_base = (uintptr_t)slide + linkedit_vmaddr - linkedit_fileoff;
        struct nlist_64 *symbols = (struct nlist_64 *)(linkedit_base + symtab.symoff);
        const char *strtab = (const char *)(linkedit_base + symtab.stroff);
        const uint32_t *indirect_sym = (const uint32_t *)(linkedit_base + dysymtab.indirectsymoff);

        for (int si = 0; si < ptr_section_count; si++) {
            uint64_t *ptr_table = (uint64_t *)(slide + ptr_sections[si].addr);
            uint32_t ptr_count = (uint32_t)(ptr_sections[si].size / sizeof(void *));

            for (uint32_t j = 0; j < ptr_count; j++) {
                uint32_t symtab_index = indirect_sym[j];
                if (symtab_index == 0 ||
                    symtab_index == INDIRECT_SYMBOL_ABS ||
                    symtab_index == INDIRECT_SYMBOL_LOCAL) continue;

                struct nlist_64 *sym = &symbols[symtab_index];
                const char *sym_name = strtab + sym->n_un.n_strx;
                if (!sym_name || sym_name[0] == '\0') continue;

                // CRITICAL: skip leading underscore in Mach-O symbol names
                const char *cmp_name = (sym_name[0] == '_') ? sym_name + 1 : sym_name;

                for (size_t r = 0; r < rebindings_nel; r++) {
                    if (strcmp(cmp_name, rebindings[r].name) == 0) {
                        if (rebindings[r].replaced)
                            *rebindings[r].replaced = (void *)ptr_table[j];
                        size_t page_size = sysconf(_SC_PAGESIZE);
                        uintptr_t page_start = (uintptr_t)(&ptr_table[j]) & ~(page_size - 1);
                        vm_protect(mach_task_self(), (vm_address_t)page_start,
                                   page_size, FALSE,
                                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
                        ptr_table[j] = (uint64_t)rebindings[r].replacement;
                        break;
                    }
                }
            }
        }
    }
}

// ============================================================
// Original Bundle ID (file scope so C hooks can access it)
// "com.baidu.BaiduMobile" built at runtime to avoid plaintext
// ============================================================
static CFStringRef g_origBundleID_CF = NULL;
static NSString *g_origBundleID_NS = nil;

// ============================================================
// Persistent spoofed identifiers
// ============================================================
static NSUUID *_spoofedIDFA = nil;
static NSUUID *_spoofedIDFV = nil;
static NSString *_spoofedDeviceName = nil;

// ============================================================
// NSUserDefaults key prefix
// ============================================================
static NSString *kKey(NSString *suffix) {
    return [NSString stringWithFormat:@"BaiduBox.cfg.%@", suffix];
}

// ============================================================
// Spoofed value generators
// ============================================================
static NSUUID *getOrCreateSpoofedUUID(NSString *key) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *uuidString = [defaults stringForKey:key];
    if (uuidString) return [[NSUUID alloc] initWithUUIDString:uuidString];
    NSUUID *newUUID = [NSUUID UUID];
    [defaults setObject:[newUUID UUIDString] forKey:key];
    [defaults synchronize];
    return newUUID;
}

static NSString *getOrCreateSpoofedDeviceName(NSString *key) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *existing = [defaults stringForKey:key];
    if (existing) return existing;

    NSArray *prefixes = @[@"张", @"李", @"王", @"刘", @"陈", @"杨", @"赵", @"黄",
                          @"周", @"吴", @"徐", @"孙", @"马", @"朱", @"胡", @"林",
                          @"何", @"郭", @"高", @"罗", @"郑", @"梁", @"谢", @"宋",
                          @"唐", @"许", @"韩", @"冯", @"邓", @"曹", @"彭", @"曾"];
    NSArray *suffixes = @[@"的 iPhone", @"的 iPhone", @"的 iPhone",
                          @"的iPhone", @"的 iPhone 14", @"的 iPhone 13",
                          @"的 iPhone 15", @"的 iPhone 12"];
    NSString *prefix = prefixes[arc4random_uniform((uint32_t)prefixes.count)];
    NSString *suffix = suffixes[arc4random_uniform((uint32_t)suffixes.count)];
    NSString *name = [NSString stringWithFormat:@"%@%@", prefix, suffix];
    [defaults setObject:name forKey:key];
    [defaults synchronize];
    return name;
}

// ============================================================
// Helper: replace method implementation
// ============================================================
static void hookInstanceMethod(Class cls, SEL sel, IMP newImp, const char *types) {
    Method method = class_getInstanceMethod(cls, sel);
    if (method) {
        const char *existingTypes = types ?: method_getTypeEncoding(method);
        class_replaceMethod(cls, sel, newImp, existingTypes);
    }
}

static void hookClassMethod(Class cls, SEL sel, IMP newImp, const char *types) {
    Class metaClass = object_getClass(cls);
    Method method = class_getClassMethod(cls, sel);
    if (method) {
        const char *existingTypes = types ?: method_getTypeEncoding(method);
        class_replaceMethod(metaClass, sel, newImp, existingTypes);
    }
}

// ============================================================
// Keychain isolation — per-clone namespace prefix
//
// ROOT CAUSE: Multiple clones share the same keychain-access-groups
// (e.g. com.baidu.shareLoginAccount). Payment SDKs write risk flags
// to these shared groups. Clone B's flags poison Clone A.
//
// FIX: Hook SecItemAdd/CopyMatching/Update/Delete via fishhook.
// Each clone gets a unique UUID prefix. All kSecAttrService values
// are transparently prefixed, so each clone only sees its own items.
// No blanket clear needed — items are invisible across clones.
// ============================================================
static NSString *g_kcPrefix = nil;

static void initKeychainPrefix(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = kKey(@"kcp");
    g_kcPrefix = [defaults stringForKey:key];
    if (!g_kcPrefix) {
        g_kcPrefix = [[NSUUID UUID] UUIDString];
        [defaults setObject:g_kcPrefix forKey:key];
        [defaults synchronize];
    }
}

// Namespace a keychain query: prefix kSecAttrService and kSecAttrServer
// so each clone only sees its own items.
static void namespaceKeychainQuery(NSMutableDictionary *q) {
    if (!g_kcPrefix) return;

    // kSecAttrService — used by kSecClassGenericPassword (most common for SDKs)
    id service = q[(__bridge id)kSecAttrService];
    if (service && [service isKindOfClass:[NSString class]]) {
        q[(__bridge id)kSecAttrService] =
            [NSString stringWithFormat:@"%@|%@", g_kcPrefix, service];
    } else {
        // No service specified — if it's a generic password, add one
        // so broad queries don't leak across clones
        id secClass = q[(__bridge id)kSecClass];
        if (secClass == (__bridge id)kSecClassGenericPassword) {
            q[(__bridge id)kSecAttrService] =
                [NSString stringWithFormat:@"%@|ns", g_kcPrefix];
        }
    }

    // kSecAttrServer — used by kSecClassInternetPassword
    id server = q[(__bridge id)kSecAttrServer];
    if (server && [server isKindOfClass:[NSString class]]) {
        q[(__bridge id)kSecAttrServer] =
            [NSString stringWithFormat:@"%@|%@", g_kcPrefix, server];
    }
}

// --- SecItem function pointers ---
static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef, CFDictionaryRef);
static OSStatus (*orig_SecItemDelete)(CFDictionaryRef);

static OSStatus hook_SecItemAdd(CFDictionaryRef query, CFTypeRef *result) {
    NSMutableDictionary *q =
        [NSMutableDictionary dictionaryWithDictionary:(__bridge NSDictionary *)query];
    namespaceKeychainQuery(q);
    return orig_SecItemAdd((__bridge CFDictionaryRef)q, result);
}

static OSStatus hook_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    NSMutableDictionary *q =
        [NSMutableDictionary dictionaryWithDictionary:(__bridge NSDictionary *)query];
    namespaceKeychainQuery(q);
    return orig_SecItemCopyMatching((__bridge CFDictionaryRef)q, result);
}

static OSStatus hook_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attrsToUpdate) {
    NSMutableDictionary *q =
        [NSMutableDictionary dictionaryWithDictionary:(__bridge NSDictionary *)query];
    namespaceKeychainQuery(q);
    NSMutableDictionary *a =
        [NSMutableDictionary dictionaryWithDictionary:(__bridge NSDictionary *)attrsToUpdate];
    namespaceKeychainQuery(a);
    return orig_SecItemUpdate((__bridge CFDictionaryRef)q, (__bridge CFDictionaryRef)a);
}

static OSStatus hook_SecItemDelete(CFDictionaryRef query) {
    NSMutableDictionary *q =
        [NSMutableDictionary dictionaryWithDictionary:(__bridge NSDictionary *)query];
    namespaceKeychainQuery(q);
    return orig_SecItemDelete((__bridge CFDictionaryRef)q);
}

static void clearSharedCookies(void) {
    NSHTTPCookieStorage *storage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    NSArray *cookies = [[storage cookies] copy];
    for (NSHTTPCookie *cookie in cookies) {
        [storage deleteCookie:cookie];
    }
}

// ============================================================
// fishhook'd C functions — CFBundle Bundle ID reads
// These are the CoreFoundation C API paths that bypass ObjC hooks
// ============================================================

// CFBundleGetIdentifier — returns the bundle's identifier
static CFStringRef (*orig_CFBundleGetIdentifier)(CFBundleRef);

static CFStringRef hook_CFBundleGetIdentifier(CFBundleRef bundle) {
    if (g_origBundleID_CF && bundle == CFBundleGetMainBundle()) {
        return g_origBundleID_CF;
    }
    return orig_CFBundleGetIdentifier(bundle);
}

// CFBundleGetValueForInfoDictionaryKey — reads a key from info dict
static CFTypeRef (*orig_CFBundleGetValueForInfoDictionaryKey)(CFBundleRef, CFStringRef);

static CFTypeRef hook_CFBundleGetValueForInfoDictionaryKey(CFBundleRef bundle, CFStringRef key) {
    if (g_origBundleID_CF && bundle == CFBundleGetMainBundle() && key) {
        // kCFBundleIdentifierKey == "CFBundleIdentifier"
        if (CFStringCompare(key, CFSTR("CFBundleIdentifier"), 0) == kCFCompareEqualTo) {
            return g_origBundleID_CF;
        }
    }
    return orig_CFBundleGetValueForInfoDictionaryKey(bundle, key);
}

// ============================================================
// Modify NSBundle's internal info dictionary ivar directly
// Covers: [bundle infoDictionary][@"CFBundleIdentifier"]
// ============================================================
static void modifyBundleInfoDictionaryIvar(void) {
    NSBundle *mainBundle = [NSBundle mainBundle];
    NSDictionary *loaded = [mainBundle infoDictionary];
    if (!loaded) return;

    unsigned int count = 0;
    Ivar *ivars = class_copyIvarList([NSBundle class], &count);

    for (unsigned int i = 0; i < count; i++) {
        Ivar ivar = ivars[i];
        const char *type = ivar_getTypeEncoding(ivar);
        if (!type || type[0] != '@') continue;

        id value = object_getIvar(mainBundle, ivar);
        if ([value isKindOfClass:[NSDictionary class]] &&
            [value objectForKey:@"CFBundleIdentifier"]) {
            NSMutableDictionary *modified =
                [NSMutableDictionary dictionaryWithDictionary:value];
            modified[@"CFBundleIdentifier"] = g_origBundleID_NS;
            object_setIvar(mainBundle, ivar, modified);
            break;
        }
    }
    free(ivars);
}

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {
        // --- Build original Bundle ID at runtime ---
        const char parts[] = {99,111,109,46,98,97,105,100,117,46,
                              66,97,105,100,117,77,111,98,105,108,101,0};
        g_origBundleID_NS = [NSString stringWithUTF8String:parts];
        g_origBundleID_CF = (__bridge_retained CFStringRef)g_origBundleID_NS;

        // --- Initialize spoofed values ---
        _spoofedIDFA = getOrCreateSpoofedUUID(kKey(@"id1"));
        _spoofedIDFV = getOrCreateSpoofedUUID(kKey(@"id2"));
        _spoofedDeviceName = getOrCreateSpoofedDeviceName(kKey(@"dn"));

        // --- Keychain isolation: per-clone namespace prefix ---
        // No blanket clear — SecItem* hooks make each clone only see
        // its own items via a unique UUID prefix on kSecAttrService.
        initKeychainPrefix();

        // --- Clear cookies ---
        clearSharedCookies();

        // ============================================================
        // 1. IDFA
        // ============================================================
        Class asmClass = objc_getClass("ASIdentifierManager");
        if (asmClass) {
            Method m = class_getInstanceMethod(asmClass, @selector(advertisingIdentifier));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSUUID *(id s) { return _spoofedIDFA; });
                hookInstanceMethod(asmClass, @selector(advertisingIdentifier), imp, method_getTypeEncoding(m));
            }
            m = class_getInstanceMethod(asmClass, @selector(isAdvertisingTrackingEnabled));
            if (m) {
                IMP imp = imp_implementationWithBlock(^BOOL(id s) { return YES; });
                hookInstanceMethod(asmClass, @selector(isAdvertisingTrackingEnabled), imp, method_getTypeEncoding(m));
            }
        }

        // ============================================================
        // 2. ATTrackingManager
        // ============================================================
        Class attClass = objc_getClass("ATTrackingManager");
        if (attClass) {
            Method m = class_getClassMethod(attClass, @selector(trackingAuthorizationStatus));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSInteger(id s) { return 3; });
                hookClassMethod(attClass, @selector(trackingAuthorizationStatus), imp, method_getTypeEncoding(m));
            }
            m = class_getClassMethod(attClass, @selector(requestTrackingAuthorizationWithCompletionHandler:));
            if (m) {
                IMP imp = imp_implementationWithBlock(^(id s, void (^h)(NSInteger)) {
                    if (h) dispatch_async(dispatch_get_main_queue(), ^{ h(3); });
                });
                hookClassMethod(attClass, @selector(requestTrackingAuthorizationWithCompletionHandler:), imp, method_getTypeEncoding(m));
            }
        }

        // ============================================================
        // 3. IDFV + device name
        // ============================================================
        Class uiDeviceClass = objc_getClass("UIDevice");
        if (uiDeviceClass) {
            Method m = class_getInstanceMethod(uiDeviceClass, @selector(identifierForVendor));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSUUID *(id s) { return _spoofedIDFV; });
                hookInstanceMethod(uiDeviceClass, @selector(identifierForVendor), imp, method_getTypeEncoding(m));
            }
            m = class_getInstanceMethod(uiDeviceClass, @selector(name));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSString *(id s) { return _spoofedDeviceName; });
                hookInstanceMethod(uiDeviceClass, @selector(name), imp, method_getTypeEncoding(m));
            }
        }

        // ============================================================
        // 4. UIPasteboard — block ALL reads (login isolation)
        // ============================================================
        Class pbClass = objc_getClass("UIPasteboard");
        if (pbClass) {
            Method m = class_getInstanceMethod(pbClass, @selector(string));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSString *(id s) { return @""; });
                hookInstanceMethod(pbClass, @selector(string), imp, method_getTypeEncoding(m));
            }
            m = class_getInstanceMethod(pbClass, @selector(strings));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSArray *(id s) { return @[]; });
                hookInstanceMethod(pbClass, @selector(strings), imp, method_getTypeEncoding(m));
            }
            m = class_getInstanceMethod(pbClass, @selector(dataForPasteboardType:));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSData *(id s, NSString *t) { return nil; });
                hookInstanceMethod(pbClass, @selector(dataForPasteboardType:), imp, method_getTypeEncoding(m));
            }
            m = class_getInstanceMethod(pbClass, @selector(valueForPasteboardType:));
            if (m) {
                IMP imp = imp_implementationWithBlock(^id(id s, NSString *t) { return nil; });
                hookInstanceMethod(pbClass, @selector(valueForPasteboardType:), imp, method_getTypeEncoding(m));
            }
            m = class_getInstanceMethod(pbClass, @selector(items));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSArray *(id s) { return @[]; });
                hookInstanceMethod(pbClass, @selector(items), imp, method_getTypeEncoding(m));
            }
            m = class_getInstanceMethod(pbClass, @selector(containsPasteboardTypes:));
            if (m) {
                IMP imp = imp_implementationWithBlock(^BOOL(id s, NSArray *t) { return NO; });
                hookInstanceMethod(pbClass, @selector(containsPasteboardTypes:), imp, method_getTypeEncoding(m));
            }
        }

        // ============================================================
        // 5. App Group container blocked
        // ============================================================
        Class fmClass = objc_getClass("NSFileManager");
        if (fmClass) {
            Method m = class_getInstanceMethod(fmClass,
                @selector(containerURLForSecurityApplicationGroupIdentifier:));
            if (m) {
                IMP imp = imp_implementationWithBlock(^NSURL *(id s, NSString *g) { return nil; });
                hookInstanceMethod(fmClass,
                    @selector(containerURLForSecurityApplicationGroupIdentifier:),
                    imp, method_getTypeEncoding(m));
            }
        }

        // ============================================================
        // 6. Bundle ID — 5 LAYERS of protection
        //
        //    Layer A: bundleIdentifier METHOD hook (ObjC)
        //    Layer B: objectForInfoDictionaryKey: hook (ObjC)
        //    Layer C: internal ivar modification (data-level)
        //    Layer D: CFBundleGetIdentifier hook (fishhook C)
        //    Layer E: CFBundleGetValueForInfoDictionaryKey hook (fishhook C)
        //
        //    Layers D & E are the NEW additions in v20.
        //    They cover CoreFoundation C API that bypasses ObjC.
        // ============================================================

        // Layer C: Modify internal ivar FIRST
        modifyBundleInfoDictionaryIvar();

        // Layer A + B: ObjC method hooks
        Class bundleClass = objc_getClass("NSBundle");
        if (bundleClass) {
            Method m = class_getInstanceMethod(bundleClass, @selector(bundleIdentifier));
            if (m) {
                static IMP orig_bundleID = NULL;
                orig_bundleID = method_getImplementation(m);
                IMP imp = imp_implementationWithBlock(^NSString *(id s) {
                    if (s == [NSBundle mainBundle]) return g_origBundleID_NS;
                    return ((NSString *(*)(id, SEL))orig_bundleID)(s, @selector(bundleIdentifier));
                });
                hookInstanceMethod(bundleClass, @selector(bundleIdentifier),
                                   imp, method_getTypeEncoding(m));
            }

            m = class_getInstanceMethod(bundleClass, @selector(objectForInfoDictionaryKey:));
            if (m) {
                static IMP orig_infoKey = NULL;
                orig_infoKey = method_getImplementation(m);
                IMP imp = imp_implementationWithBlock(^id(id s, NSString *key) {
                    if (s == [NSBundle mainBundle] && key &&
                        [key isEqualToString:@"CFBundleIdentifier"]) {
                        return g_origBundleID_NS;
                    }
                    return ((id(*)(id, SEL, NSString *))orig_infoKey)(
                        s, @selector(objectForInfoDictionaryKey:), key);
                });
                hookInstanceMethod(bundleClass, @selector(objectForInfoDictionaryKey:),
                                   imp, method_getTypeEncoding(m));
            }
        }

        // Layer D + E: fishhook for CoreFoundation C functions
        struct rebinding rebindings[] = {
            { "CFBundleGetIdentifier",
              (void *)hook_CFBundleGetIdentifier,
              (void **)&orig_CFBundleGetIdentifier },
            { "CFBundleGetValueForInfoDictionaryKey",
              (void *)hook_CFBundleGetValueForInfoDictionaryKey,
              (void **)&orig_CFBundleGetValueForInfoDictionaryKey },
        };
        fishhook_rebind(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));

        // ============================================================
        // 7. Keychain isolation — SecItem* hooks via fishhook
        //
        //    Each clone gets a unique UUID prefix. All SecItemAdd/Copy/
        //    Update/Delete calls are transparently namespaced via
        //    kSecAttrService, so clones cannot see each other's items.
        //    This replaces the old blanket keychain clear (which was
        //    destructive to other clones).
        // ============================================================
        struct rebinding kc_rebindings[] = {
            { "SecItemAdd",
              (void *)hook_SecItemAdd,
              (void **)&orig_SecItemAdd },
            { "SecItemCopyMatching",
              (void *)hook_SecItemCopyMatching,
              (void **)&orig_SecItemCopyMatching },
            { "SecItemUpdate",
              (void *)hook_SecItemUpdate,
              (void **)&orig_SecItemUpdate },
            { "SecItemDelete",
              (void *)hook_SecItemDelete,
              (void **)&orig_SecItemDelete },
        };
        fishhook_rebind(kc_rebindings, sizeof(kc_rebindings) / sizeof(kc_rebindings[0]));
    }
}
