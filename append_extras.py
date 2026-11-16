import os, struct, glob
MAGIC=b"<<DMEXTRA>>"
files=[]
for p in ["gadget.dylib.xz"]+sorted(glob.glob("wheels/*.whl")):
    if os.path.exists(p) and os.path.getsize(p)>50000:
        files.append(p)
with open("PrivacyHook.dylib","ab") as f:
    for p in files:
        d=open(p,"rb").read()
        nm=os.path.basename(p).encode()
        f.write(MAGIC+struct.pack("<I",len(nm))+nm+struct.pack("<I",len(d))+d)
        print("appended", p, len(d))
