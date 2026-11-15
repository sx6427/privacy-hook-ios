# DamaiSpy.dylib —— 大麦进程内探针
SDKROOT ?= $(shell xcrun --sdk iphoneos --show-sdk-path)

ARCH    = -arch arm64
CFLAGS  = $(ARCH) -isysroot $(SDKROOT) -miphoneos-version-min=15.0 -fobjc-arc -Wall -O2
LDFLAGS = $(ARCH) -isysroot $(SDKROOT) -miphoneos-version-min=15.0 \
          -dynamiclib -framework Foundation -framework UIKit -framework CoreFoundation \
          -install_name @executable_path/DamaiSpy.dylib \
          -Xlinker -no_fixup_chains -lz

# 产物名沿用 PrivacyHook.dylib 以匹配 workflow 的 upload path
DYLIB = PrivacyHook.dylib
SRC   = DamaiSpy.m

.PHONY: all clean
all: $(DYLIB)

$(DYLIB): $(SRC)
	clang $(CFLAGS) $(LDFLAGS) -o $@ $^
	@file $@
	@lipo -info $@

clean:
	rm -f $(DYLIB)
