#
# Makefile — EXACT original Step33 (proven working, no modifications)
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

MIN_LDFLAGS = -arch arm64 \
          -isysroot $(SDKROOT) \
          -miphoneos-version-min=14.0 \
          -dynamiclib \
          -framework Foundation \
          -install_name @executable_path/PrivacyHookMin.dylib

.PHONY: all clean

all: $(DYLIB) $(MIN_DYLIB)

$(DYLIB): $(SRC)
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
