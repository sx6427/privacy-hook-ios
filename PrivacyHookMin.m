//
// PrivacyHookMin.m — EMPTY dylib for crash isolation
// Does literally nothing. If this crashes, it's a binary format issue.
// If this doesn't crash, the problem is in the hook code.
//

#import <Foundation/Foundation.h>

__attribute__((constructor))
static void initMinimal(void) {
    // Do nothing. Just test if the dylib loads.
}
