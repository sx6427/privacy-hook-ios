#
# Makefile — Step34 with -Xlinker -no_fixup_chains
#

DYLIB = PrivacyHook.dylib
SRC   = PrivacyHook.m

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
          -Xlinker -no_fixup_chains \
          -Wl,-weak_framework,AppTrackingTransparency

.PHONY: all clean

all: $(DYLIB)

$(DYLIB): $(SRC)
	@echo "Building PrivacyHook.dylib..."
	clang $(CFLAGS) $(LDFLAGS) -o $@ $^
	@echo "Done: $(DYLIB)"
	@otool -l $@ | grep "LC_DYLD_CHAINED" && echo "FAIL: chained fixups!" || echo "OK: no chained fixups"
	@otool -l $@ | grep "LC_DYLD_INFO" && echo "OK: has dyld info" || echo "FAIL: no dyld info"
	@file $@

clean:
	rm -f $(DYLIB)
