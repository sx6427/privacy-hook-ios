# iOS 12 构建：XyProbe.dylib（输出名 PrivacyHook.dylib 匹配 workflow 产物）
SDKROOT ?= $(shell xcrun --sdk iphoneos --show-sdk-path)

CFLAGS  = -arch arm64 -isysroot $(SDKROOT) -miphoneos-version-min=12.0 -fobjc-arc -Wall

LDFLAGS = -arch arm64 -isysroot $(SDKROOT) -miphoneos-version-min=12.0 \
          -dynamiclib -framework Foundation -framework Security -framework UIKit \
          -framework WebKit -framework AVFoundation \
          -install_name @executable_path/XyProbe.dylib \
          -Xlinker -no_fixup_chains

DYLIB = PrivacyHook.dylib
SRC   = XyProbe.m

.PHONY: all clean
all: $(DYLIB)

$(DYLIB): $(SRC)
	clang $(CFLAGS) $(LDFLAGS) -o $@ $^
	@file $@
	@otool -l $@ | grep -A4 LC_BUILD_VERSION || true
	@otool -l $@ | grep minos || true

clean:
	rm -f $(DYLIB)
