#
# Makefile — Device fingerprint spoofing + Bundle ID + NSURLProtocol
#

DYLIB = PrivacyHook.dylib
SRC   = PrivacyHook.m

SDKROOT ?= $(shell xcrun --sdk iphoneos --show-sdk-path)

CFLAGS  = -arch arm64 \
          -isysroot $(SDKROOT) \
          -miphoneos-version-min=14.0 \
          -fobjc-arc \
          -Wall

LDFLAGS = -arch arm64 \
          -isysroot $(SDKROOT) \
          -miphoneos-version-min=14.0 \
          -dynamiclib \
          -framework Foundation \
          -framework UIKit \
          -framework AdSupport \
          -framework Security \
          -install_name @executable_path/PrivacyHook.dylib \
          -Xlinker -no_fixup_chains

.PHONY: all clean

all: $(DYLIB)

$(DYLIB): $(SRC)
	@echo "Building PrivacyHook.dylib (device spoof + NSURLProtocol)..."
	clang $(CFLAGS) $(LDFLAGS) -o $@ $^
	@echo "Done: $(DYLIB)"
	@otool -l $@ | grep "LC_DYLD_CHAINED" && echo "FAIL!" || echo "OK: no chained fixups"
	@otool -L $@
	@file $@

clean:
	rm -f $(DYLIB)
