import zipfile, plistlib

z = zipfile.ZipFile(r'D:\xiazai\百度_15.67.0_decrypted.ipa', 'r')

# Check for embedded.mobileprovision
names = z.namelist()
for n in names:
    if 'embedded.mobileprovision' in n:
        print(f"Found: {n}")

# Check for any .entitlements files
for n in names:
    if n.endswith('.entitlements') or n.endswith('Entitlements.plist'):
        print(f"Found: {n}")

# Read PrivacyInfo.xcprivacy
try:
    data = z.read('Payload/BaiduBoxApp.app/PrivacyInfo.xcprivacy')
    pl = plistlib.loads(data)
    print("\n=== PrivacyInfo.xcprivacy ===")
    print(pl)
except Exception as e:
    print(f"PrivacyInfo error: {e}")

# Read the Watch app's entitlements (might give clues about app groups)
try:
    data = z.read('Payload/BaiduBoxApp.app/com.apple.WatchPlaceholder/WatchApp.app/PlaceholderEntitlements.plist')
    pl = plistlib.loads(data)
    print("\n=== Watch PlaceholderEntitlements ===")
    import json
    print(json.dumps(pl, indent=2, default=str))
except Exception as e:
    print(f"Watch entitlements error: {e}")

# Check Info.plist for app group related keys
try:
    data = z.read('Payload/BaiduBoxApp.app/Info.plist')
    pl = plistlib.loads(data)
    # Look for app group related keys
    for key in pl:
        kl = key.lower()
        if 'group' in kl or 'entitle' in kl or 'keychain' in kl or 'pasteboard' in kl or 'cookie' in kl or 'shared' in kl:
            print(f"\nInfo.plist key: {key} = {pl[key]}")
except Exception as e:
    print(f"Info.plist error: {e}")
