#
# Makefile — v8: device spoof + payment compatible
#

DYLIB = PrivacyHook.dylib
SRC   = PrivacyHook.m

SDKROOT ?= $(shell xcrun --sdk iphoneos --show-sdk-path)

CFLAGS  = -arch arm64 -isysroot $(SDKROOT) -miphoneos-version-min=14.0 -fobjc-arc -Wall

LDFLAGS = -arch arm64 -isysroot $(SDKROOT) -miphoneos-version-min=14.0 \
          -dynamiclib -framework Foundation -framework UIKit \
          -framework AdSupport -framework Security \
          -install_name @executable_path/PrivacyHook.dylib \
          -Xlinker -no_fixup_chains

.PHONY: all clean

all: $(DYLIB)

$(DYLIB): $(SRC)
	clang $(CFLAGS) $(LDFLAGS) -o $@ $^
	@otool -l $@ | grep "LC_DYLD_CHAINED" && echo "FAIL!" || echo "OK"
	@file $@

clean:
	rm -f $(DYLIB)
