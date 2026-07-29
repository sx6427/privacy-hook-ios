#
# Makefile for building PrivacyHook.dylib
# With iOS 16 compatibility: -no_fixup_chains + vtool SDK version fix
#

SDKROOT ?= $(shell xcrun --sdk iphoneos --show-sdk-path)

DYLIB = PrivacyHook.dylib
SRC   = PrivacyHook.m

# Compiler flags
CFLAGS  = -arch arm64 \
          -isysroot $(SDKROOT) \
          -miphoneos-version-min=14.0 \
          -target arm64-apple-ios14.0 \
          -fobjc-arc \
          -fobjc-weak \
          -Wall \
          -Wno-deprecated-declarations

# Linker flags with iOS 16 compatibility
LDFLAGS = -arch arm64 \
          -isysroot $(SDKROOT) \
          -miphoneos-version-min=14.0 \
          -target arm64-apple-ios14.0 \
          -dynamiclib \
          -framework Foundation \
          -framework UIKit \
          -framework AdSupport \
          -framework Security \
          -framework IOKit \
          -install_name @executable_path/PrivacyHook.dylib \
          -Wl,-weak_framework,AppTrackingTransparency \
          -Wl,-no_fixup_chains

.PHONY: all clean

all: $(DYLIB)
	@echo "=== Build Complete ==="

$(DYLIB): $(SRC)
	@echo "Building PrivacyHook.dylib..."
	clang $(CFLAGS) $(LDFLAGS) -o $@ $^
	@echo "Fixing SDK version with vtool..."
	@xcrun vtool -set-build-version ios 14.0 14.0 -output PrivacyHook_fixed.dylib $@ && mv PrivacyHook_fixed.dylib $@
	@echo "Done: $(DYLIB)"
	@echo "=== Architecture ==="
	@lipo -info $@ || true
	@echo "=== Linked Libraries ==="
	@otool -L $@ || true
	@echo "=== Version Info ==="
	@xcrun vtool -show-build $@ || true
	@echo "=== Check for chained fixups ==="
	@otool -l $@ | grep -A2 "DYLD_CHAINED_FIXUPS\|LC_DYLD_CHAINED_FIXUPS" || echo "No chained fixups (good!)"

clean:
	rm -f $(DYLIB)
