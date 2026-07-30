#
# Makefile for PrivacyHook.dylib
# Force ld_classic via -fuse-ld to generate iOS 16-compatible Mach-O
#

DYLIB = PrivacyHook.dylib
SRC   = PrivacyHook.m

MIN_DYLIB = PrivacyHookMin.dylib
MIN_SRC   = PrivacyHookMin.m

SDKROOT ?= $(shell xcrun --sdk iphoneos --show-sdk-path)

CFLAGS  = -arch arm64 \
          -isysroot $(SDKROOT) \
          -miphoneos-version-min=14.0 \
          -fobjc-arc \
          -fobjc-weak \
          -Wall \
          -Wno-deprecated-declarations

# Force classic linker — ld_prime generates LC_DYLD_CHAINED_FIXUPS (iOS 16 incompatible)
# ld_classic generates LC_DYLD_INFO_ONLY (iOS 16 compatible)
LDFLAGS = -arch arm64 \
          -isysroot $(SDKROOT) \
          -miphoneos-version-min=14.0 \
          -dynamiclib \
          -framework Foundation \
          -framework UIKit \
          -framework AdSupport \
          -framework Security \
          -framework IOKit \
          -install_name @executable_path/PrivacyHook.dylib \
          -fuse-ld=ld_classic \
          -Wl,-weak_framework,AppTrackingTransparency

MIN_LDFLAGS = -arch arm64 \
          -isysroot $(SDKROOT) \
          -miphoneos-version-min=14.0 \
          -dynamiclib \
          -framework Foundation \
          -install_name @executable_path/PrivacyHookMin.dylib \
          -fuse-ld=ld_classic

.PHONY: all clean

all: $(DYLIB) $(MIN_DYLIB)

$(DYLIB): $(SRC)
	@echo "=== Build Info ==="
	@xcodebuild -version 2>/dev/null || true
	@echo "=================="
	@echo "Building PrivacyHook.dylib (fuse-ld=ld_classic)..."
	clang $(CFLAGS) $(LDFLAGS) -o $@ $^
	@echo "Done: $(DYLIB)"
	@echo "=== Verify: no chained fixups ==="
	@otool -l $@ | grep "LC_DYLD_CHAINED" && echo "FAIL: chained fixups present!" || echo "OK: no chained fixups"
	@echo "=== Verify: has dyld info ==="
	@otool -l $@ | grep "LC_DYLD_INFO" && echo "OK: has LC_DYLD_INFO" || echo "FAIL: no LC_DYLD_INFO"
	@echo "=== All load commands ==="
	@otool -l $@ | grep -E "cmd " | head -30
	@file $@

$(MIN_DYLIB): $(MIN_SRC)
	@echo "Building PrivacyHookMin.dylib..."
	clang $(CFLAGS) $(MIN_LDFLAGS) -o $@ $<
	@echo "Done: $(MIN_DYLIB)"

clean:
	rm -f $(DYLIB) $(MIN_DYLIB)
