//
//  PrivacyHook.m — Step28: MINIMAL
//
//  NO hooks at all. Only sandbox nuke on first launch.
//  Payment SDK is completely untouched.
//  Device ID is wiped by deleting ALL of Library/.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#define NSLog(...)

static NSString *kKey(NSString *suffix) {
    return [NSString stringWithFormat:@"BaiduBox.cfg.%@", suffix];
}

// ============================================================
// First-launch-only: nuke ENTIRE sandbox
// Deletes Documents, Library (ALL), tmp
// This is what made Step26 require verification code.
// ============================================================
static void nukeSandboxOnce(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *flagKey = kKey(@"sandbox_nuked_v4");
    if ([defaults boolForKey:flagKey]) return;

    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *home = NSHomeDirectory();

    // Save our config
    NSMutableDictionary *savedConfig = [NSMutableDictionary dictionary];
    NSDictionary *allDict = [defaults dictionaryRepresentation];
    for (NSString *key in allDict) {
        if ([key hasPrefix:@"BaiduBox.cfg."]) {
            savedConfig[key] = allDict[key];
        }
    }

    // Delete Documents
    NSString *docsDir = [home stringByAppendingPathComponent:@"Documents"];
    NSArray *docsFiles = [fm contentsOfDirectoryAtPath:docsDir error:nil];
    for (NSString *f in docsFiles) {
        [fm removeItemAtPath:[docsDir stringByAppendingPathComponent:f] error:nil];
    }

    // Delete ALL of Library (Caches + Preferences + everything)
    NSString *libDir = [home stringByAppendingPathComponent:@"Library"];
    NSArray *libFiles = [fm contentsOfDirectoryAtPath:libDir error:nil];
    for (NSString *f in libFiles) {
        [fm removeItemAtPath:[libDir stringByAppendingPathComponent:f] error:nil];
    }

    // Delete tmp
    NSString *tmpDir = [home stringByAppendingPathComponent:@"tmp"];
    NSArray *tmpFiles = [fm contentsOfDirectoryAtPath:tmpDir error:nil];
    for (NSString *f in tmpFiles) {
        [fm removeItemAtPath:[tmpDir stringByAppendingPathComponent:f] error:nil];
    }

    // Recreate dirs
    [fm createDirectoryAtPath:docsDir withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:libDir withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:[libDir stringByAppendingPathComponent:@"Caches"] withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:[libDir stringByAppendingPathComponent:@"Preferences"] withIntermediateDirectories:YES attributes:nil error:nil];

    // Restore config
    for (NSString *key in savedConfig) {
        [defaults setObject:savedConfig[key] forKey:key];
    }
    [defaults setBool:YES forKey:flagKey];
    [defaults synchronize];
}

// ============================================================
// Constructor — NO hooks, just sandbox nuke
// ============================================================
__attribute__((constructor))
static void initPrivacyHook(void) {
    @autoreleasepool {
        nukeSandboxOnce();
    }
}
