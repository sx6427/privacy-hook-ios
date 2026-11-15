# 大麦探针构建（damai 分支专用）：源 DamaiSpy.m，产物沿用 PrivacyHook.dylib 以匹配 workflow
SDKROOT ?= $(shell xcrun --sdk iphoneos --show-sdk-path)
ARCH    = -arch arm64
CFLAGS  = $(ARCH) -isysroot $(SDKROOT) -miphoneos-version-min=15.0 -fobjc-arc -Wall -O2
LDFLAGS = $(ARCH) -isysroot $(SDKROOT) -miphoneos-version-min=15.0 \
          -dynamiclib -framework Foundation -framework UIKit \
          -install_name @executable_path/DamaiSpy.dylib \
          -Xlinker -no_fixup_chains
DYLIB = PrivacyHook.dylib
SRC   = DamaiSpy.m
.PHONY: all clean
all: $(DYLIB)
$(DYLIB): $(SRC)
	clang $(CFLAGS) $(LDFLAGS) -o $@ $^
	@file $@
clean:/n	rm -f $(DYLIB)
