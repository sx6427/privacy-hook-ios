#
# Makefile — MINIMAL empty dylib for crash isolation
#

DYLIB = PrivacyHook.dylib
SRC   = PrivacyHookMin.m

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
          -install_name @executable_path/PrivacyHook.dylib \
          -Xlinker -no_fixup_chains

.PHONY: all clean

all: $(DYLIB)

$(DYLIB): $(SRC)
	@echo "Building MINIMAL empty dylib..."
	clang $(CFLAGS) $(LDFLAGS) -o $@ $^
	@echo "Done: $(DYLIB)"
	@otool -l $@ | grep "LC_DYLD_CHAINED" && echo "FAIL: chained fixups!" || echo "OK: no chained fixups"
	@otool -l $@ | grep "LC_DYLD_INFO" && echo "OK: has dyld info" || echo "FAIL: no dyld info"
	@file $@

clean:
	rm -f $(DYLIB)
