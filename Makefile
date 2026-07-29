#
# Makefile for building PrivacyHook.dylib
# Self-selects oldest Xcode for iOS 16 compatibility.
#

DYLIB = PrivacyHook.dylib
SRC   = PrivacyHook.m

# Also build a minimal test dylib
MIN_DYLIB = PrivacyHookMin.dylib
MIN_SRC   = PrivacyHookMin.m

# Auto-select oldest available Xcode (for iOS 16 compat)
# This runs before SDK detection
SELECT_XCODE := $(shell \
	xc=$(shell ls -d /Applications/Xcode_*.app 2>/dev/null | sort -V | head -1); \
	if [ -n "$$xc" ]; then sudo xcode-select -s "$$xc" 2>/dev/null; echo "$$xc"; \
	else echo "default"; fi)

SDKROOT ?= $(shell xcrun --sdk iphoneos --show-sdk-path)

# Compiler flags
CFLAGS  = -arch arm64 \
          -isysroot $(SDKROOT) \
          -miphoneos-version-min=14.0 \
          -fobjc-arc \
          -fobjc-weak \
          -Wall \
          -Wno-deprecated-declarations

# Linker flags — -no_fixup_chains critical for iOS 16 compat
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
          -Wl,-no_fixup_chains \
          -Wl,-weak_framework,AppTrackingTransparency

# Minimal dylib: only links Foundation
MIN_LDFLAGS = -arch arm64 \
          -isysroot $(SDKROOT) \
          -miphoneos-version-min=14.0 \
          -dynamiclib \
          -framework Foundation \
          -install_name @executable_path/PrivacyHookMin.dylib

.PHONY: all clean

all: $(DYLIB) $(MIN_DYLIB)

$(DYLIB): $(SRC)
	@echo "=== Build Info ==="
	@echo "Xcode: $(SELECT_XCODE)"
	@xcodebuild -version 2>/dev/null || true
	@echo "SDK: $(SDKROOT)"
	@echo "=================="
	@echo "Building PrivacyHook.dylib..."
	clang $(CFLAGS) $(LDFLAGS) -o $@ $^
	@echo "Done: $(DYLIB)"
	@lipo -info $@ || true
	@otool -L $@ || true

$(MIN_DYLIB): $(MIN_SRC)
	@echo "Building PrivacyHookMin.dylib..."
	clang $(CFLAGS) $(MIN_LDFLAGS) -o $@ $<
	@echo "Done: $(MIN_DYLIB)"
	@lipo -info $@ || true
	@otool -L $@ || true

clean:
	rm -f $(DYLIB) $(MIN_DYLIB)
