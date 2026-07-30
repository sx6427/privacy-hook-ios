#
# Makefile — ld_prime + -no_fixup_chains + vtool, NO strip
#

DYLIB = PrivacyHook.dylib
SRC   = PrivacyHook.m

MIN_DYLIB = PrivacyHookMin.dylib
MIN_SRC   = PrivacyHookMin.m

SDKROOT ?= $(shell xcrun --sdk iphoneos --show-sdk-path)

CFLAGS  = -arch arm64 \
          -target arm64-apple-ios14.0 \
          -isysroot $(SDKROOT) \
          -miphoneos-version-min=14.0 \
          -fobjc-arc \
          -fobjc-weak \
          -Wall \
          -Wno-deprecated-declarations

# -no_fixup_chains: force LC_DYLD_INFO_ONLY (traditional) instead of LC_DYLD_CHAINED_FIXUPS
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
          -install_name @executable_path/PrivacyHookMin.dylib \
          -Wl,-no_fixup_chains

.PHONY: all clean

all: $(DYLIB) $(MIN_DYLIB)

$(DYLIB): $(SRC)
	@echo "=== Build Info ==="
	@xcodebuild -version 2>/dev/null || true
	@echo "SDK: $(SDKROOT)"
	@echo "=================="
	@echo "Building PrivacyHook.dylib (no_fixup_chains + vtool, NO strip)..."
	clang $(CFLAGS) $(LDFLAGS) -o $@ $^

	@echo "=== Post-build: vtool (set SDK 16.0) ==="
	-vtool -set-build-version ios 14.0 16.0 -output $@.tmp $@ && mv $@.tmp $@
	@echo "vtool done"

	@echo "=== Diagnostics ==="
	@otool -L $@
	@echo "--- Load commands ---"
	@otool -l $@ | grep -E "cmd |cmdsize" | head -50
	@file $@

$(MIN_DYLIB): $(MIN_SRC)
	@echo "Building PrivacyHookMin.dylib..."
	clang $(CFLAGS) $(MIN_LDFLAGS) -o $@ $<
	-vtool -set-build-version ios 14.0 16.0 -output $@.tmp $@ && mv $@.tmp $@
	@echo "Done: $(MIN_DYLIB)"

clean:
	rm -f $(DYLIB) $(MIN_DYLIB)
