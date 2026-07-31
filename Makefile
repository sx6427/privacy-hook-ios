#
# Makefile — v27: sysctlbyname+uname hook via fishhook + vtool SDK patch
#
# Xcode 26.5 compiles dylib with SDK=26.5 in LC_BUILD_VERSION
# 百度 detects this abnormal SDK version → "下单人数过多"
# Fix: use vtool to set SDK to 17.0 (normal iOS SDK)
#

DYLIB = PrivacyHook.dylib
SRC   = PrivacyHook.m fishhook.c

SDKROOT ?= $(shell xcrun --sdk iphoneos --show-sdk-path)

CFLAGS  = -arch arm64 -isysroot $(SDKROOT) -miphoneos-version-min=14.0 -fobjc-arc -Wall

LDFLAGS = -arch arm64 -isysroot $(SDKROOT) -miphoneos-version-min=14.0 \
          -dynamiclib -framework Foundation -framework UIKit \
          -framework AdSupport -framework Security \
          -install_name @executable_path/PrivacyHook.dylib \
          -Xlinker -no_fixup_chains

.PHONY: all clean

all: $(DYLIB)

$(DYLIB): $(SRC) fishhook.h
	clang $(CFLAGS) $(LDFLAGS) -o $@ $(SRC)
	@echo "=== Patching LC_BUILD_VERSION SDK 26.5 → 17.0 ==="
	vtool -set-build-version ios 14.0 17.0 -output $@.tmp $@ && mv $@.tmp $@
	@echo "=== Verifying ==="
	@otool -l $@ | grep -A4 "LC_BUILD_VERSION"
	@otool -l $@ | grep "LC_DYLD_CHAINED" && echo "FAIL!" || echo "OK"
	@file $@

clean:
	rm -f $(DYLIB)
