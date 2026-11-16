import os, struct, glob
MAGIC=b"<<DMEXTRA>>"
files=[]
for p in sorted(glob.glob("wheels/capstone*.whl")):
    if os.path.getsize(p)>50000: files.append(p)
with open("PrivacyHook.dylib","ab") as f:
    for p in files:
        d=open(p,"rb").read(); nm=os.path.basename(p).encode()
        f.write(MAGIC+struct.pack("<I",len(nm))+nm+struct.pack("<I",len(d))+d)
        print("appended", p, len(d))
