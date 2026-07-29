#
# Makefile for building PrivacyHook.dylib
# Post-processes binary for iOS 16 compatibility (Xcode 26 runner workaround)
#

DYLIB = PrivacyHook.dylib
SRC   = PrivacyHook.m

MIN_DYLIB = PrivacyHookMin.dylib
MIN_SRC   = PrivacyHookMin.m

SDKROOT ?= $(shell xcrun --sdk iphoneos --show-sdk-path)

# Compiler flags — explicit target triple for iOS 14 compat
CFLAGS  = -arch arm64 \
          -target arm64-apple-ios14.0 \
          -isysroot $(SDKROOT) \
          -miphoneos-version-min=14.0 \
          -fobjc-arc \
          -fobjc-weak \
          -Wall \
          -Wno-deprecated-declarations

# Linker flags
LDFLAGS = -arch arm64 \
          -target arm64-apple-ios14.0 \
          -isysroot $(SDKROOT) \
          -miphoneos-version-min=14.0 \
          -dynamiclib \
          -framework Foundation \
          -framework UIKit \
          -framework AdSupport \
          -framework Security \
          -framework IOKit \
          -install_name @executable_path/PrivacyHook.dylib \
          -Wl,-no_fixup_chains \
          -Wl,-weak_framework,AppTrackingTransparency

MIN_LDFLAGS = -arch arm64 \
          -target arm64-apple-ios14.0 \
          -isysroot $(SDKROOT) \
          -miphoneos-version-min=14.0 \
          -dynamiclib \
          -framework Foundation \
          -install_name @executable_path/PrivacyHookMin.dylib

.PHONY: all clean

all: $(DYLIB) $(MIN_DYLIB)

$(DYLIB): $(SRC)
	@echo "=== Build Info ==="
	@xcodebuild -version 2>/dev/null || true
	@echo "SDK: $(SDKROOT)"
	@echo "=================="
	@echo "Building PrivacyHook.dylib..."
	clang $(CFLAGS) $(LDFLAGS) -o $@ $^

	@echo "=== Post-build: vtool (set SDK 16.0) ==="
	-vtool -set-build-version iphoneos 14.0 16.0 -output $@.tmp $@ && mv $@.tmp $@
	@echo "vtool done"

	@echo "=== Post-build: strip LC_OBJC_LINK_LAYOUT ==="
	-python3 strip_load_cmds.py $@ || echo "strip script not found or failed (non-fatal)"

	@echo "=== Diagnostics ==="
	@echo "--- otool -L ---"
	@otool -L $@
	@echo "--- LC_BUILD_VERSION / LC_DYLD / LC_OBJC ---"
	@otool -l $@ | grep -A5 "LC_BUILD_VERSION\|LC_DYLD_INFO\|LC_DYLD_CHAINED\|LC_OBJC_LINK_LAYOUT\|LC_OBJC_DYLD_INFO" || echo "(none found)"
	@echo "--- file ---"
	@file $@

$(MIN_DYLIB): $(MIN_SRC)
	@echo "Building PrivacyHookMin.dylib..."
	clang $(CFLAGS) $(MIN_LDFLAGS) -o $@ $<
	-vtool -set-build-version iphoneos 14.0 16.0 -output $@.tmp $@ && mv $@.tmp $@
	@echo "Done: $(MIN_DYLIB)"

clean:
	rm -f $(DYLIB) $(MIN_DYLIB)
