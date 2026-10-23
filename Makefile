# 一次性构建：XyProbe.dylib（输出名固定为 PrivacyHook.dylib 以匹配 workflow 产物）
SDKROOT ?= $(shell xcrun --sdk iphoneos --show-sdk-path)

CFLAGS  = -arch arm64 -isysroot $(SDKROOT) -miphoneos-version-min=14.0 -fobjc-arc -Wall

LDFLAGS = -arch arm64 -isysroot $(SDKROOT) -miphoneos-version-min=14.0 \
          -dynamiclib -framework Foundation -framework Security \
          -framework AVFoundation -framework UIKit \
          -install_name @executable_path/XyProbe.dylib \
          -Xlinker -no_fixup_chains

DYLIB = PrivacyHook.dylib
SRC   = XyProbe.m

.PHONY: all clean
all: $(DYLIB)

$(DYLIB): $(SRC)
	clang $(CFLAGS) $(LDFLAGS) -o $@ $^
	@file $@
	@lipo -info $@

clean:
	rm -f $(DYLIB)
