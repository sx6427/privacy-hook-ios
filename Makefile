#
# Makefile — Comprehensive device fingerprint spoofing
# Hooks: sysctl + NSUserDefaults + NSURLSession + UIDevice + IDFA + Bundle ID
#

DYLIB = PrivacyHook.dylib
SRC   = PrivacyHook.m fishhook.c

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

$(DYLIB): $(SRC) fishhook.h
	@echo "Building PrivacyHook.dylib (full device spoof)..."
	clang $(CFLAGS) $(LDFLAGS) -o $@ $(SRC)
	@echo "Done: $(DYLIB)"
	@otool -l $@ | grep "LC_DYLD_CHAINED" && echo "FAIL!" || echo "OK: no chained fixups"
	@otool -L $@
	@file $@

clean:
	rm -f $(DYLIB)
