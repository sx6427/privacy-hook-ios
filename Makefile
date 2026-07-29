#
# Makefile for building PrivacyHook.dylib
# Auto-selects older Xcode for iOS 16 compatibility
# (Xcode 26.x produces dylibs that crash on iOS 16)
#

# Auto-select oldest available Xcode (not the default Xcode 26.x)
# Try Xcode 14.x, 15.x, 16.x in order of preference (oldest first)
SELECT_XCODE := bash -c '\
    echo "=== Available Xcode versions ===" >&2; \
    ls -d /Applications/Xcode*.app 2>/dev/null >&2; \
    echo "" >&2; \
    unset DEVELOPER_DIR; \
    for xcode in $$(ls -d /Applications/Xcode_14*.app /Applications/Xcode_15*.app /Applications/Xcode_16*.app 2>/dev/null | sort -V); do \
        echo "Trying: $$xcode" >&2; \
        sudo xcode-select -s "$$xcode" 2>/dev/null; \
        export DEVELOPER_DIR="$$xcode/Contents/Developer"; \
        echo "Selected Xcode: $$xcode" >&2; \
        break; \
    done; \
    xcrun --sdk iphoneos --show-sdk-path'

SDKROOT := $(shell $(SELECT_XCODE))
SDK_VER := $(shell xcrun --sdk iphoneos --show-sdk-version)

DYLIB = PrivacyHook.dylib
SRC   = PrivacyHook.m

# Compiler flags
CFLAGS  = -arch arm64 \
          -isysroot $(SDKROOT) \
          -miphoneos-version-min=14.0 \
          -fobjc-arc \
          -fobjc-weak \
          -Wall \
          -Wno-deprecated-declarations

# Linker flags
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
          -Wl,-weak_framework,AppTrackingTransparency

.PHONY: all clean

all: $(DYLIB)
	@echo "=== Build Complete ==="
	@echo "SDK version: $(SDK_VER)"
	@echo "SDK path: $(SDKROOT)"
	@echo ""

$(DYLIB): $(SRC)
	@echo "Building PrivacyHook.dylib with SDK $(SDK_VER)..."
	clang $(CFLAGS) $(LDFLAGS) -o $@ $^
	@echo "Done: $(DYLIB)"
	@lipo -info $@ || true
	@otool -L $@ || true

clean:
	rm -f $(DYLIB)
