#!/usr/bin/env python3
"""
Batch IPA Cloner — Generate multiple independent Baidu clones.

Each clone gets:
  - Unique Bundle ID → independent sandbox, keychain, UserDefaults
  - PrivacyHook.dylib → independent random device fingerprint
  - Original Bundle ID spoofed at runtime → payment compatibility
  - Login state isolation (clipboard, keychain, cookie)

Usage:
    python batch_clone.py <input.ipa> <PrivacyHook.dylib> [count]

Examples:
    python batch_clone.py "百度_15.69.0_decrypted.ipa" PrivacyHook.dylib 3
    python batch_clone.py "百度_15.69.0_decrypted.ipa" PrivacyHook.dylib 5
"""

import os
import sys
import subprocess

# ============================================================
# Clone configurations
# Each clone has a unique Bundle ID suffix and display name.
# Add more entries here if you need more than 10 clones.
# ============================================================
CLONE_CONFIGS = [
    {"suffix": "BaiduBoxAppA1", "name": "百度A1"},
    {"suffix": "BaiduBoxAppA2", "name": "百度A2"},
    {"suffix": "BaiduBoxAppA3", "name": "百度A3"},
    {"suffix": "BaiduBoxAppA4", "name": "百度A4"},
    {"suffix": "BaiduBoxAppA5", "name": "百度A5"},
    {"suffix": "BaiduBoxAppA6", "name": "百度A6"},
    {"suffix": "BaiduBoxAppA7", "name": "百度A7"},
    {"suffix": "BaiduBoxAppA8", "name": "百度A8"},
    {"suffix": "BaiduBoxAppA9", "name": "百度A9"},
    {"suffix": "BaiduBoxAppB1", "name": "百度B1"},
    {"suffix": "BaiduBoxAppB2", "name": "百度B2"},
    {"suffix": "BaiduBoxAppB3", "name": "百度B3"},
    {"suffix": "BaiduBoxAppB4", "name": "百度B4"},
    {"suffix": "BaiduBoxAppB5", "name": "百度B5"},
    {"suffix": "BaiduBoxAppB6", "name": "百度B6"},
    {"suffix": "BaiduBoxAppB7", "name": "百度B7"},
    {"suffix": "BaiduBoxAppB8", "name": "百度B8"},
    {"suffix": "BaiduBoxAppB9", "name": "百度B9"},
    {"suffix": "BaiduBoxAppB10", "name": "百度B10"},
    {"suffix": "BaiduBoxAppB11", "name": "百度B11"},
    {"suffix": "BaiduBoxAppB12", "name": "百度B12"},
    {"suffix": "BaiduBoxAppB13", "name": "百度B13"},
    {"suffix": "BaiduBoxAppB14", "name": "百度B14"},
    {"suffix": "BaiduBoxAppB15", "name": "百度B15"},
    {"suffix": "BaiduBoxAppB16", "name": "百度B16"},
    {"suffix": "BaiduBoxAppB17", "name": "百度B17"},
    {"suffix": "BaiduBoxAppB18", "name": "百度B18"},
    {"suffix": "BaiduBoxAppB19", "name": "百度B19"},
    {"suffix": "BaiduBoxAppB20", "name": "百度B20"},
]

ORIGINAL_BUNDLE_ID = "com.baidu.BaiduMobile"

def main():
    if len(sys.argv) < 3:
        print("Usage: python batch_clone.py <input.ipa> <PrivacyHook.dylib> [count]")
        print("Example: python batch_clone.py \"百度_15.69.0_decrypted.ipa\" PrivacyHook.dylib 5")
        sys.exit(1)

    ipa_path = sys.argv[1]
    dylib_path = sys.argv[2]
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 3

    if count > len(CLONE_CONFIGS):
        print(f"Error: Max {len(CLONE_CONFIGS)} clones supported")
        sys.exit(1)

    if not os.path.isfile(ipa_path):
        print(f"Error: IPA not found: {ipa_path}")
        sys.exit(1)
    if not os.path.isfile(dylib_path):
        print(f"Error: Dylib not found: {dylib_path}")
        sys.exit(1)

    # Output directory
    output_dir = os.path.dirname(os.path.abspath(ipa_path))
    script_dir = os.path.dirname(os.path.abspath(__file__))
    modify_script = os.path.join(script_dir, "modify_ipa.py")

    print("=" * 60)
    print(f"  Batch IPA Cloner — {count} clones")
    print("=" * 60)
    print(f"  Input IPA : {ipa_path}")
    print(f"  Dylib     : {dylib_path}")
    print()

    success = 0
    failed = 0

    for i in range(count):
        config = CLONE_CONFIGS[i]
        bundle_id = f"{ORIGINAL_BUNDLE_ID}.{config['suffix']}"
        display_name = config["name"]
        output_name = f"{display_name}.ipa"
        output_path = os.path.join(output_dir, output_name)

        print(f"[{i+1}/{count}] Building {display_name} ({bundle_id})...")

        result = subprocess.run([
            sys.executable, modify_script,
            ipa_path, dylib_path,
            "--bundle-id", bundle_id,
            "--name", display_name,
            "--output", output_path
        ], capture_output=True, text=True)

        if result.returncode == 0:
            size_mb = os.path.getsize(output_path) / 1024 / 1024
            print(f"  OK -> {output_name} ({size_mb:.0f} MB)")
            success += 1
        else:
            print(f"  FAIL: {result.stderr[:200]}")
            failed += 1
        print()

    print("=" * 60)
    print(f"  Done! {success} succeeded, {failed} failed")
    print("=" * 60)
    print()
    print("Output files:")
    for i in range(count):
        config = CLONE_CONFIGS[i]
        output_name = f"{config['name']}.ipa"
        output_path = os.path.join(output_dir, output_name)
        if os.path.isfile(output_path):
            size_mb = os.path.getsize(output_path) / 1024 / 1024
            print(f"  {output_name} ({size_mb:.0f} MB) — Bundle ID: {ORIGINAL_BUNDLE_ID}.{config['suffix']}")
    print()
    print("Each clone has:")
    print("  - Independent Bundle ID (sandbox, keychain, data)")
    print("  - Independent random device fingerprint")
    print("  - Payment compatibility (original Bundle ID at runtime)")
    print("  - Login state isolation (clipboard, keychain, cookie)")

if __name__ == "__main__":
    main()
