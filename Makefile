#
# Makefile — minimal, no post-processing, pure ld_classic
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
          -Wl,-ld_classic \
          -Wl,-weak_framework,AppTrackingTransparency

MIN_LDFLAGS = -arch arm64 \
          -target arm64-apple-ios14.0 \
          -isysroot $(SDKROOT) \
          -miphoneos-version-min=14.0 \
          -dynamiclib \
          -framework Foundation \
          -install_name @executable_path/PrivacyHookMin.dylib \
          -Wl,-ld_classic

.PHONY: all clean

all: $(DYLIB) $(MIN_DYLIB)

$(DYLIB): $(SRC)
	@echo "=== Build Info ==="
	@xcodebuild -version 2>/dev/null || true
	@echo "SDK: $(SDKROOT)"
	@echo "=================="
	@echo "Building PrivacyHook.dylib (no post-processing)..."
	clang $(CFLAGS) $(LDFLAGS) -o $@ $^
	@echo "=== Diagnostics ==="
	@echo "--- otool -L ---"
	@otool -L $@
	@echo "--- file ---"
	@file $@
	@echo "--- otool -l (load commands) ---"
	@otool -l $@ | grep -E "cmd |cmdsize|LC_" | head -40

$(MIN_DYLIB): $(MIN_SRC)
	@echo "Building PrivacyHookMin.dylib..."
	clang $(CFLAGS) $(MIN_LDFLAGS) -o $@ $<
	@echo "Done: $(MIN_DYLIB)"

clean:
	rm -f $(DYLIB) $(MIN_DYLIB)
