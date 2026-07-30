#
# Makefile for PrivacyHook.dylib
# Uses ld_classic to generate iOS 16-compatible Mach-O
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

# Use classic linker — ld_prime generates LC_DYLD_CHAINED_FIXUPS which iOS 16 dyld doesn't support
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
          -Wl,-ld_classic \
          -Wl,-weak_framework,AppTrackingTransparency

MIN_LDFLAGS = -arch arm64 \
          -isysroot $(SDKROOT) \
          -miphoneos-version-min=14.0 \
          -dynamiclib \
          -framework Foundation \
          -install_name @executable_path/PrivacyHookMin.dylib \
          -Wl,-ld_classic

.PHONY: all clean

all: $(DYLIB) $(MIN_DYLIB)

$(DYLIB): $(SRC)
	@echo "Building PrivacyHook.dylib (ld_classic)..."
	clang $(CFLAGS) $(LDFLAGS) -o $@ $^
	@echo "Done: $(DYLIB)"
	@echo "=== Verify: load commands ==="
	@otool -l $@ | grep -E "cmd |cmdsize" | head -50
	@echo "=== Verify: no chained fixups ==="
	@otool -l $@ | grep "LC_DYLD_CHAINED" && echo "WARNING: chained fixups present!" || echo "OK: no chained fixups"
	@echo "=== Verify: dyld info ==="
	@otool -l $@ | grep "LC_DYLD_INFO" && echo "OK: has LC_DYLD_INFO" || echo "WARNING: no LC_DYLD_INFO"
	@file $@

$(MIN_DYLIB): $(MIN_SRC)
	@echo "Building PrivacyHookMin.dylib..."
	clang $(CFLAGS) $(MIN_LDFLAGS) -o $@ $<
	@echo "Done: $(MIN_DYLIB)"

clean:
	rm -f $(DYLIB) $(MIN_DYLIB)
