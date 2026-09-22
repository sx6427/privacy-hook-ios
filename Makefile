#
# Makefile — v58: rebind_symbols (ALL images) + sysctl() + UIScreen
#
# ★★ 2026-09-21 重要变更（临时方案）★★
# GitHub token 没有 workflow scope（改 .github/workflows 被 404），
# 且 OAuth 授权端点网络不通，无法加第二个 artifact 上传。
# 因此对调产物语义：
#   PrivacyHook.dylib      = 美团版（-DMT_CLONE=1）→ CI 产物 PrivacyHook-dylib 上传的就是它
#   PrivacyHookBaidu.dylib = 百度版（默认）        → 本地留档用，CI 不上传
# ⚠️ 百度 D 系列重建时：用 PrivacyHookBaidu.dylib，别拿 CI 产物！
#    （百度 v72 dylib 已本地存档 dylib_v72/）
# 等 token 有 workflow scope 后恢复双 artifact（build.yml 已在本地改好）。
#

DYLIB       = PrivacyHook.dylib       # 美团版（CI 产物）
DYLIB_BAIDU = PrivacyHookBaidu.dylib  # 百度版
# [TEMP-KCWIPER] 本次构建产物用于设备身份洗白；构建后由 _restore_makefile.py 还原
SRC   = KcWiper.m

SDKROOT ?= $(shell xcrun --sdk iphoneos --show-sdk-path)

CFLAGS  = -arch arm64 -isysroot $(SDKROOT) -miphoneos-version-min=14.0 -fobjc-arc -Wall

LDFLAGS = -arch arm64 -isysroot $(SDKROOT) -miphoneos-version-min=14.0 \
          -dynamiclib -framework Foundation -framework UIKit \
          -framework AdSupport -framework Security -framework WebKit \
          -install_name @executable_path/PrivacyHook.dylib \
          -Xlinker -no_fixup_chains

.PHONY: all clean

all: $(DYLIB) $(DYLIB_BAIDU)

# 美团多开：MT_CLONE=1 禁用百度专属 hook（WKWebView UA / NSMutableURLRequest UA 补段等）
# 内嵌名约定为 MtKit.dylib（镜像隐藏表按 MT_CLONE 同步切换）
$(DYLIB): $(SRC)
	clang $(CFLAGS) -DMT_CLONE=1 $(LDFLAGS) -o $@ $^
	@echo "=== [MT] Patching LC_BUILD_VERSION ==="
	vtool -set-build-version ios 14.0 17.0 -output $@.tmp $@ && mv $@.tmp $@
	@echo "=== [MT] Verifying ==="
	@otool -l $@ | grep -A4 "LC_BUILD_VERSION"
	@file $@

# 百度多开（D/E/T/P 系列）：默认 MT_CLONE=0
$(DYLIB_BAIDU): $(SRC)
	clang $(CFLAGS) $(LDFLAGS) -o $@ $^
	@echo "=== [BAIDU] Patching LC_BUILD_VERSION ==="
	vtool -set-build-version ios 14.0 17.0 -output $@.tmp $@ && mv $@.tmp $@
	@echo "=== [BAIDU] Verifying ==="
	@otool -l $@ | grep -A4 "LC_BUILD_VERSION"
	@otool -l $@ | grep "LC_DYLD_CHAINNED" && echo "FAIL!" || echo "OK"
	@file $@

clean:
	rm -f $(DYLIB) $(DYLIB_BAIDU)
