#!/usr/bin/env python3
"""Inject dylib into A2 IPA — completely independent device fingerprint from A1."""
import subprocess, os, sys, shutil

DYLIB_SRC = 'C:/Users/Administrator/Desktop/PrivacyHook/artifact/PrivacyHook.dylib'
IPA_INPUT = 'D:/xiazai/baidu_A2_source.ipa'
IPA_OUTPUT = 'D:/xiazai/baidu_A2_fixed.ipa'

# Copy original IPA to ASCII-safe name if needed
original_ipa = 'D:/xiazai/百度A2.ipa'
if not os.path.exists(IPA_INPUT):
    if os.path.exists(original_ipa):
        print(f"Copying {original_ipa} -> {IPA_INPUT}")
        shutil.copy2(original_ipa, IPA_INPUT)
    else:
        print("Looking for IPAs in D:/xiazai/")
        for f in os.listdir('D:/xiazai'):
            if f.endswith('.ipa'):
                print(f"  Found: {f}")

if not os.path.exists(IPA_INPUT):
    print(f"Error: Source IPA not found at {IPA_INPUT}")
    sys.exit(1)

if not os.path.exists(DYLIB_SRC):
    print(f"Error: Dylib not found at {DYLIB_SRC}")
    sys.exit(1)

print(f"Dylib size: {os.path.getsize(DYLIB_SRC)} bytes")
print(f"IPA size: {os.path.getsize(IPA_INPUT)} bytes")
print()

cmd = [
    'python',
    'modify_ipa.py',
    IPA_INPUT,
    DYLIB_SRC,
    '--bundle-id', 'com.baidu.BaiduMobileA2',
    '--name', 'BaiduA2',
    '--output', IPA_OUTPUT
]

print(f"Running: {' '.join(cmd)}")
print()

result = subprocess.run(cmd,
    cwd='C:/Users/Administrator/Desktop/PrivacyHook',
    capture_output=True, text=True, encoding='utf-8', errors='replace')
print(result.stdout)
if result.stderr:
    print(f"STDERR: {result.stderr[:500]}")

if os.path.exists(IPA_OUTPUT):
    print(f"\nOutput IPA: {IPA_OUTPUT}")
    print(f"Size: {os.path.getsize(IPA_OUTPUT)} bytes")
    final_path = 'D:/xiazai/百度A2fix.ipa'
    shutil.copy2(IPA_OUTPUT, final_path)
    print(f"Copied to: {final_path}")
else:
    print(f"Error: Output IPA not created at {IPA_OUTPUT}")
