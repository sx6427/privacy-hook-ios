//
// PrivacyHookTest.m — EMPTY dylib, zero hooks
// Purpose: test if dylib injection itself triggers "下单人数过多"
// If this works → the issue is one of our hooks
// If this fails → the issue is TrollStore/injection detection
//

#import <Foundation/Foundation.h>

__attribute__((constructor))
static void initTest(void) {
    // Do absolutely nothing
}
