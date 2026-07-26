import zipfile
z = zipfile.ZipFile(r'D:\xiazai\百度_15.67.0_decrypted.ipa', 'r')
for n in z.namelist():
    if 'BaiduBoxApp.app/' in n:
        parts = n.split('BaiduBoxApp.app/')
        if parts[1] and '/' not in parts[1]:
            print(parts[1])
