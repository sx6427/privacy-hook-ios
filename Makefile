#
# Makefile — v30: Pure ObjC CUID interception + vtool SDK patch
#

DYLIB = PrivacyHook.dylib
SRC   = PrivacyHook.m

SDKROOT ?= $(shell xcrun --sdk iphoneos --show-sdk-path)

CFLAGS  = -arch arm64 -isysroot $(SDKROOT) -miphoneos-version-min=14.0 -fobjc-arc -Wall

LDFLAGS = -arch arm64 -isysroot $(SDKROOT) -miphoneos-version-min=14.0 \
          -dynamiclib -framework Foundation -framework UIKit \
          -framework AdSupport -framework Security -framework CoreTelephony \
          -install_name @executable_path/PrivacyHook.dylib \
          -Xlinker -no_fixup_chains

.PHONY: all clean

all: $(DYLIB)

$(DYLIB): $(SRC)
	clang $(CFLAGS) $(LDFLAGS) -o $@ $^
	@echo "=== Patching LC_BUILD_VERSION SDK 26.5 → 17.0 ==="
	vtool -set-build-version ios 14.0 17.0 -output $@.tmp $@ && mv $@.tmp $@
	@echo "=== Verifying ==="
	@otool -l $@ | grep -A4 "LC_BUILD_VERSION"
	@otool -l $@ | grep "LC_DYLD_CHAINED" && echo "FAIL!" || echo "OK"
	@file $@

clean:
	rm -f $(DYLIB)
