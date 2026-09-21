#
# Makefile — v58: rebind_symbols (ALL images) + sysctl() + UIScreen
#

DYLIB = PrivacyHook.dylib
DYLIB_MT = PrivacyHookMT.dylib
SRC   = PrivacyHook.m fishhook.c

SDKROOT ?= $(shell xcrun --sdk iphoneos --show-sdk-path)

CFLAGS  = -arch arm64 -isysroot $(SDKROOT) -miphoneos-version-min=14.0 -fobjc-arc -Wall

LDFLAGS = -arch arm64 -isysroot $(SDKROOT) -miphoneos-version-min=14.0 \
          -dynamiclib -framework Foundation -framework UIKit \
          -framework AdSupport -framework Security -framework WebKit \
          -install_name @executable_path/PrivacyHook.dylib \
          -Xlinker -no_fixup_chains

.PHONY: all clean

all: $(DYLIB) $(DYLIB_MT)

$(DYLIB): $(SRC)
	clang $(CFLAGS) $(LDFLAGS) -o $@ $^
	@echo "=== Patching LC_BUILD_VERSION SDK 26.5 → 17.0 ==="
	vtool -set-build-version ios 14.0 17.0 -output $@.tmp $@ && mv $@.tmp $@
	@echo "=== Verifying ==="
	@otool -l $@ | grep -A4 "LC_BUILD_VERSION"
	@otool -l $@ | grep "LC_DYLD_CHAINNED" && echo "FAIL!" || echo "OK"
	@file $@

# 美团多开构建：MT_CLONE=1 禁用百度专属 hook（WKWebView UA / NSMutableURLRequest UA 补段）
# 内嵌名约定为 MtKit.dylib（镜像隐藏表按 MT_CLONE 同步切换）
$(DYLIB_MT): $(SRC)
	clang $(CFLAGS) -DMT_CLONE=1 $(LDFLAGS) -o $@ $^
	@echo "=== [MT] Patching LC_BUILD_VERSION ==="
	vtool -set-build-version ios 14.0 17.0 -output $@.tmp $@ && mv $@.tmp $@
	@echo "=== [MT] Verifying ==="
	@otool -l $@ | grep -A4 "LC_BUILD_VERSION"
	@file $@

clean:
	rm -f $(DYLIB) $(DYLIB_MT)
