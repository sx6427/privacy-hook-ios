//
//  PrivacyHook.m
//  Device Fingerprint + Login State Isolation Dylib for iOS
//
//  v12: v11 + fishhook for sysctlbyname/getifaddrs (serial/MAC/IP spoofing)
//       fishhook rebinds via __la_symbol_ptr — no __interpose section,
//       invisible to payment SDK integrity checks.
//
//  Hooks:
//    [Device Fingerprint — ObjC swizzle]
//    - ASIdentifierManager advertisingIdentifier (IDFA)
//    - ASIdentifierManager isAdvertisingTrackingEnabled
//    - ATTrackingManager trackingAuthorizationStatus
//    - ATTrackingManager requestTrackingAuthorizationWithCompletionHandler:
//    - UIDevice identifierForVendor (IDFV)
//    - UIDevice name (device name)
//
//    [Device Fingerprint — fishhook rebind]
//    - sysctlbyname (hw.serialnumber, hw.uuid)
//    - getifaddrs (MAC address, local IP)
//
//    [Login State Isolation]
//    - UIPasteboard (blocks clipboard-based cross-app login sharing)
//    - Keychain clear on first launch
//    - NSHTTPCookieStorage (clears shared cookies)
//    - NSFileManager containerURLForSecurityApplicationGroupIdentifier:
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <AppTrackingTransparency/AppTrackingTransparency.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <sys/sysctl.h>
#import <net/if.h>
#import <net/if_dl.h>
#import <ifaddrs.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <string.h>

#define NSLog(...)

// ============================================================
// fishhook — minimal rebind_symbols implementation
// Based on Facebook's fishhook (simplified, single-file embed)
// Rebinds C function pointers in __DATA,__la_symbol_ptr
// without leaving __DATA,__interpose section traces
// ============================================================

#include <stdint.h>
#include <stddef.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>

struct rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

static void fishhook_rebind(const struct rebinding rebindings[], size_t rebindings_nel) {
    // Iterate all loaded images
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *header = _dyld_get_image_header(i);
        if (!header) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);

        // Determine if 64-bit
        BOOL is64 = (header->magic == 0xFEEDFACF);
        if (!is64 && header->magic != 0xFEEDFACE) continue;

        const uint8_t *ptr = (const uint8_t *)header;
        uint32_t ncmds;
        if (is64) {
            ncmds = ((mach_header_64 *)header)->ncmds;
            ptr += sizeof(mach_header_64);
        } else {
            ncmds = ((mach_header *)header)->ncmds;
            ptr += sizeof(mach_header);
        }

        // Find __LINKEDIT, symtab, dysymtab, and __la_symbol_ptr sections
        uint64_t linkedit_fileoff = 0, linkedit_vmaddr = 0;
        struct symtab_command symtab = {0};
        struct dysymtab_command dysymtab = {0};
        uint64_t la_symbol_ptr_addr = 0, la_symbol_ptr_size = 0;
        BOOL found_la = NO;

        for (uint32_t c = 0; c < ncmds; c++) {
            const struct load_command *lc = (const struct load_command *)ptr;
            if (lc->cmd == 0 || lc->cmdsize == 0) break;

            if (is64 && lc->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *seg = (struct segment_command_64 *)ptr;
                if (strcmp(seg->segname, SEG_DATA) == 0) {
                    const struct section_64 *sects = (const struct section_64 *)(ptr + sizeof(struct segment_command_64));
                    for (uint32_t s = 0; s < seg->nsects; s++) {
                        if (strcmp(sects[s].sectname, "__la_symbol_ptr") == 0) {
                            la_symbol_ptr_addr = sects[s].addr;
                            la_symbol_ptr_size = sects[s].size;
                            found_la = YES;
                        }
                    }
                }
                if (strcmp(seg->segname, "__LINKEDIT") == 0) {
                    linkedit_fileoff = seg->fileoff;
                    linkedit_vmaddr = seg->vmaddr;
                }
            }

            if (lc->cmd == LC_SYMTAB) {
                memcpy(&symtab, ptr, sizeof(struct symtab_command));
            }
            if (lc->cmd == LC_DYSYMTAB) {
                memcpy(&dysymtab, ptr, sizeof(struct dysymtab_command));
            }

            ptr += lc->cmdsize;
        }

        if (!found_la || !symtab.symoff || !dysymtab.indirectsymoff) continue;

        // Calculate base address for __LINKEDIT
        uintptr_t linkedit_base = (uintptr_t)slide + linkedit_vmaddr - linkedit_fileoff;

        // Symbol table
        struct nlist_64 *symbols = (struct nlist_64 *)(linkedit_base + symtab.symoff);
        // String table
        const char *strtab = (const char *)(linkedit_base + symtab.stroff);
        // Indirect symbol table
        const uint32_t *indirect_sym = (const uint32_t *)(linkedit_base + dysymtab.indirectsymoff);

        // __la_symbol_ptr section (64-bit: 8 bytes per pointer)
        uint64_t *ptr_table_64 = (uint64_t *)(slide + la_symbol_ptr_addr);
        uint32_t ptr_count = (uint32_t)(la_symbol_ptr_size / sizeof(void *));

        for (uint32_t j = 0; j < ptr_count; j++) {
            uint32_t symtab_index = indirect_sym[j];
            if (symtab_index == 0 || symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL) continue;

            struct nlist_64 *sym = &symbols[symtab_index];
            const char *sym_name = strtab + sym->n_strx;
            if (!sym_name || sym_name[0] == '\0') continue;

            // Check if this symbol matches any of our rebindings
            for (size_t r = 0; r < rebindings_nel; r++) {
                if (strcmp(sym_name, rebindings[r].name) == 0) {
                    if (rebindings[r].replaced) {
                        *rebindings[r].replaced = (void *)ptr_table_64[j];
                    }
                    // mprotect to make it writable
                    size_t page_size = sysconf(_SC_PAGESIZE);
                    uintptr_t page_start = (uintptr_t)(&ptr_table_64[j]) & ~(page_size - 1);
                    vm_protect(mach_task_self(), (vm_address_t)page_start,
                               page_size, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
                    ptr_table_64[j] = (uint64_t)rebindings[r].replacement;
                    break;
                }
            }
        }
    }
}

// ============================================================
// Persistent spoofed identifiers
// ============================================================
static NSUUID *_spoofedIDFA = nil;
static NSUUID *_spoofedIDFV = nil;
static NSString *_spoofedDeviceName = nil;
static NSString *_spoofedSerialNumber = nil;
static NSString *_spoofedUDID = nil;
static NSString *_spoofedMAC = nil;
static NSString *_spoofedLocalIP = nil;

static volatile BOOL g_initialized = NO;

// ============================================================
// NSUserDefaults key prefix — looks like Baidu's own setting
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
    if (uuidString) {
        return [[NSUUID alloc] initWithUUIDString:uuidString];
    }
    NSUUID *newUUID = [NSUUID UUID];
    [defaults setObject:[newUUID UUIDString] forKey:key];
    [defaults synchronize];
    return newUUID;
}

static NSString *getOrCreateSpoofedString(NSString *key, NSUInteger length) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *existing = [defaults stringForKey:key];
    if (existing) return existing;

    NSMutableString *str = [NSMutableString stringWithCapacity:length];
    NSString *chars = @"0123456789abcdef";
    for (NSUInteger i = 0; i < length; i++) {
        [str appendFormat:@"%C", (unichar)[chars characterAtIndex:arc4random_uniform((uint32_t)chars.length)]];
    }
    [defaults setObject:str forKey:key];
    [defaults synchronize];
    return str;
}

static NSString *getOrCreateSpoofedSerial(NSString *key) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *existing = [defaults stringForKey:key];
    if (existing) return existing;

    NSString *chars = @"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    NSMutableString *str = [NSMutableString stringWithCapacity:12];
    for (int i = 0; i < 12; i++) {
        [str appendFormat:@"%C", (unichar)[chars characterAtIndex:arc4random_uniform((uint32_t)chars.length)]];
    }
    [defaults setObject:str forKey:key];
    [defaults synchronize];
    return str;
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

static NSString *getOrCreateSpoofedMAC(NSString *key) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *existing = [defaults stringForKey:key];
    if (existing) return existing;

    uint8_t firstByte = 0x02 | (arc4random_uniform(64) << 2);
    NSMutableString *mac = [NSMutableString string];
    [mac appendFormat:@"%02x", firstByte];
    for (int i = 1; i < 6; i++) {
        [mac appendString:@":"];
        [mac appendFormat:@"%02x", arc4random_uniform(256)];
    }
    [defaults setObject:mac forKey:key];
    [defaults synchronize];
    return mac;
}

static NSString *getOrCreateSpoofedIP(NSString *key) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *existing = [defaults stringForKey:key];
    if (existing) return existing;

    uint32_t r = arc4random_uniform(100);
    uint8_t subnet;
    if (r < 45) subnet = 1;
    else if (r < 80) subnet = 0;
    else if (r < 90) subnet = 31;
    else subnet = (uint8_t)arc4random_uniform(254) + 1;
    uint8_t host = (uint8_t)arc4random_uniform(253) + 2;

    NSString *ip = [NSString stringWithFormat:@"192.168.%d.%d", subnet, host];
    [defaults setObject:ip forKey:key];
    [defaults synchronize];
    return ip;
}

// ============================================================
// Helper: replace an instance method's implementation
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
// Keychain + Cookie clearing
// ============================================================
static void clearKeychainOnFirstLaunch(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = kKey(@"kc");
    if ([defaults boolForKey:key]) return;

    NSArray *secItemClasses = @[
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword,
        (__bridge id)kSecClassKey,
        (__bridge id)kSecClassCertificate,
        (__bridge id)kSecClassIdentity
    ];
    for (id secItemClass in secItemClasses) {
        NSDictionary *query = @{(__bridge id)kSecClass: secItemClass};
        SecItemDelete((__bridge CFDictionaryRef)query);
    }
    [defaults setBool:YES forKey:key];
    [defaults synchronize];
}

static void clearSharedCookies(void) {
    NSHTTPCookieStorage *storage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    NSArray *cookies = [[storage cookies] copy];
    for (NSHTTPCookie *cookie in cookies) {
        [storage deleteCookie:cookie];
    }
}

// ============================================================
// fishhook'd C functions — sysctlbyname + getifaddrs
// These replace DYLD interpose (which left __interpose section
// traces detectable by payment SDKs). fishhook modifies
// __la_symbol_ptr which is much harder to detect.
// ============================================================
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);

static int hook_sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                              void *newp, size_t newlen) {
    if (name && g_initialized && oldp && oldlenp) {
        NSString *nsName = [NSString stringWithUTF8String:name];

        if ([nsName isEqualToString:@"hw.serialnumber"]) {
            const char *serial = [_spoofedSerialNumber UTF8String];
            if (serial) {
                size_t len = strlen(serial) + 1;
                if (*oldlenp >= len) {
                    memcpy(oldp, serial, len);
                    *oldlenp = len - 1;
                    return 0;
                }
            }
        }

        if ([nsName isEqualToString:@"hw.uuid"]) {
            const char *uuid = [_spoofedUDID UTF8String];
            if (uuid) {
                size_t len = strlen(uuid) + 1;
                if (*oldlenp >= len) {
                    memcpy(oldp, uuid, len);
                    *oldlenp = len - 1;
                    return 0;
                }
            }
        }
    }
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

static int (*orig_getifaddrs)(struct ifaddrs **);

static int hook_getifaddrs(struct ifaddrs **ifap) {
    int result = orig_getifaddrs(ifap);
    if (result == 0 && ifap && *ifap && g_initialized) {
        struct ifaddrs *ifa = *ifap;
        while (ifa) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_LINK) {
                struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
                if (sdl->sdl_alen > 0 && _spoofedMAC) {
                    char *macBytes = (char *)(sdl->sdl_data + sdl->sdl_nlen);
                    const char *spoofedMAC = [_spoofedMAC UTF8String];
                    unsigned int mac[6];
                    if (sscanf(spoofedMAC, "%x:%x:%x:%x:%x:%x",
                               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
                        for (int i = 0; i < 6 && i < sdl->sdl_alen; i++) {
                            macBytes[i] = (char)mac[i];
                        }
                    }
                }
            }
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
                if (sin->sin_addr.s_addr != htonl(INADDR_LOOPBACK) && sin->sin_addr.s_addr != 0 && _spoofedLocalIP) {
                    const char *ipStr = [_spoofedLocalIP UTF8String];
                    struct in_addr addr;
                    if (inet_pton(AF_INET, ipStr, &addr) == 1) {
                        sin->sin_addr = addr;
                    }
                }
            }
            ifa = ifa->ifa_next;
        }
    }
    return result;
}

// ============================================================
// Constructor
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {
        // --- Initialize ALL spoofed values ---
        _spoofedIDFA = getOrCreateSpoofedUUID(kKey(@"id1"));
        _spoofedIDFV = getOrCreateSpoofedUUID(kKey(@"id2"));
        _spoofedDeviceName = getOrCreateSpoofedDeviceName(kKey(@"dn"));
        _spoofedSerialNumber = getOrCreateSpoofedSerial(kKey(@"sr"));
        _spoofedUDID = getOrCreateSpoofedString(kKey(@"ud"), 40);
        _spoofedMAC = getOrCreateSpoofedMAC(kKey(@"mc"));
        _spoofedLocalIP = getOrCreateSpoofedIP(kKey(@"ip"));

        g_initialized = YES;

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
        // 5. Keychain clear on first launch
        // ============================================================
        clearKeychainOnFirstLaunch();

        // ============================================================
        // 6. Clear shared cookies
        // ============================================================
        clearSharedCookies();

        // ============================================================
        // 7. App Group container blocked
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
        // 8. fishhook — rebind sysctlbyname + getifaddrs
        //    No __DATA,__interpose section — invisible to payment SDKs
        // ============================================================
        struct rebinding rebindings[] = {
            { "sysctlbyname", (void *)hook_sysctlbyname, (void **)&orig_sysctlbyname },
            { "getifaddrs",   (void *)hook_getifaddrs,   (void **)&orig_getifaddrs   },
        };
        fishhook_rebind(rebindings, 2);
    }
}
