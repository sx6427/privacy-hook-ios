#
# Makefile for building PrivacyHook.dylib
#
# Usage (on macOS with Xcode):
#   make          # Build the dylib
#   make clean    # Remove build artifacts
#
# The dylib is compiled for arm64 (iOS device), targeting iOS 14.0+.
# It does NOT require Theos — just clang (included with Xcode).
#

SDKROOT ?= $(shell xcrun --sdk iphoneos --show-sdk-path)

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
          -framework AppTrackingTransparency \
          -install_name @executable_path/PrivacyHook.dylib \
          -Wl,-weak_framework,AppTrackingTransparency

.PHONY: all clean

all: $(DYLIB)

$(DYLIB): $(SRC)
	@echo "Building PrivacyHook.dylib..."
	clang $(CFLAGS) $(LDFLAGS) -o $@ $<
	@echo "Done: $(DYLIB)"
	@echo ""
	@echo "Verify architecture:"
	@lipo -info $@ || true
	@echo ""
	@echo "Verify load commands:"
	@otool -L $@ || true

clean:
	rm -f $(DYLIB)
