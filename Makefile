#
# Makefile for building PrivacyHook.dylib
# With iOS 16 compatibility flags
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
# -no_fixup_chains: disable chained fixups (newer format may crash on iOS 16)
# -no_objc_relative_method_lists: use old ObjC method list format
# -no_pie: disable PIE for better compatibility (optional)
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
	@echo "SDK: $(shell xcrun --sdk iphoneos --show-sdk-version)"
	@echo ""

$(DYLIB): $(SRC)
	@echo "Building PrivacyHook.dylib..."
	clang $(CFLAGS) $(LDFLAGS) -o $@ $^
	@echo "Done: $(DYLIB)"
	@echo "=== Architecture ==="
	@lipo -info $@ || true
	@echo "=== Linked Libraries ==="
	@otool -L $@ || true
	@echo "=== Load Commands (version info) ==="
	@otool -l $@ | grep -A5 "LC_BUILD_VERSION\|LC_VERSION_MIN" || true
	@echo "=== vtool ==="
	@xcrun vtool -show-build $@ 2>/dev/null || true
	@echo "=== Check for chained fixups ==="
	@otool -l $@ | grep -A2 "DYLD_CHAINED_FIXUPS\|LC_DYLD_CHAINED_FIXUPS" || echo "No chained fixups (good!)"

clean:
	rm -f $(DYLIB)
