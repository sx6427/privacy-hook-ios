# DamaiSpy.dylib —— 大麦进程内探针
SDKROOT ?= $(shell xcrun --sdk iphoneos --show-sdk-path)

ARCH    = -arch arm64
CFLAGS  = $(ARCH) -isysroot $(SDKROOT) -miphoneos-version-min=15.0 -fobjc-arc -Wall -O2
LDFLAGS = $(ARCH) -isysroot $(SDKROOT) -miphoneos-version-min=15.0 \
          -dynamiclib -framework Foundation -framework UIKit -framework CoreFoundation -framework CoreGraphics -framework JavaScriptCore \
          -install_name @executable_path/DamaiSpy.dylib \
          -Xlinker -no_fixup_chains -lz

# 产物名沿用 PrivacyHook.dylib 以匹配 workflow 的 upload path
DYLIB = PrivacyHook.dylib
SRC   = DamaiSpy.m

.PHONY: all clean
all: $(DYLIB)

$(DYLIB): $(SRC)
	clang $(CFLAGS) $(LDFLAGS) -o $@ $^
	@echo "=== fetch extras ==="
	@curl -sSL --retry 3 -o gadget.dylib.xz https://github.com/frida/frida/releases/download/17.26.3/frida-gadget-17.26.3-ios-universal.dylib.xz || echo "gadget dl failed"
	@mkdir -p wheels && python3 -m pip download frida --no-deps --only-binary=:all: --platform win_amd64 --python-version 3.13 --implementation cp --abi abi3 -d wheels || echo "frida whl failed"
	@python3 append_extras.py || echo "append failed"
	@file $@
	@lipo -info $@
	@ls -la $@

clean:
	rm -f $(DYLIB)
