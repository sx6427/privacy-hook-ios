//
//  PrivacyHook.m
//  最小化测试版本 — 什么都不做，只验证 dylib 注入是否正常
//

#import <Foundation/Foundation.h>

__attribute__((constructor))
static void initPrivacyHook(void) {
    // 什么都不做
}
