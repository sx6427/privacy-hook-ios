"""Check Mach-O header info for the BaiduBoxApp executable."""
import zipfile, struct, tempfile, os

ipa_path = r'D:\xiazai\百度_15.67.0_decrypted.ipa'

with zipfile.ZipFile(ipa_path, 'r') as z:
    # Read the main executable
    exec_data = z.read('Payload/BaiduBoxApp.app/BaiduBoxApp')

print(f"Executable size: {len(exec_data)} bytes ({len(exec_data)/1024/1024:.1f} MB)")

magic = struct.unpack_from('<I', exec_data, 0)[0]
print(f"Magic: {hex(magic)}")

if magic == 0xFEEDFACF:  # MH_MAGIC_64
    print("Type: 64-bit Mach-O")
    ncmds = struct.unpack_from('<I', exec_data, 16)[0]
    sizeofcmds = struct.unpack_from('<I', exec_data, 20)[0]
    header_size = 32
    print(f"Number of load commands: {ncmds}")
    print(f"Size of load commands: {sizeofcmds} bytes")
    print(f"Header + cmds end at: {header_size + sizeofcmds}")

    # Walk through load commands to find data start
    pos = header_size
    min_data_offset = float('inf')
    dylib_count = 0
    
    for i in range(ncmds):
        if pos + 8 > len(exec_data):
            break
        cmd_id = struct.unpack_from('<I', exec_data, pos)[0]
        cmdsize = struct.unpack_from('<I', exec_data, pos + 4)[0]
        if cmdsize == 0:
            break
        
        if cmd_id == 0x0C:  # LC_LOAD_DYLIB
            dylib_count += 1
            # Read dylib name
            name_offset = struct.unpack_from('<I', exec_data, pos + 8)[0]
            name_end = exec_data.index(b'\x00', pos + name_offset)
            name = exec_data[pos + name_offset:name_end].decode('utf-8', errors='replace')
            if 'baidu' in name.lower() or 'BaiduBoxApp' in name:
                print(f"  LC[{i}]: LOAD_DYLIB {name}")
        
        if cmd_id == 0x19:  # LC_SEGMENT_64
            seg_name = exec_data[pos+8:pos+24].split(b'\x00')[0].decode('utf-8', errors='replace')
            fileoff = struct.unpack_from('<Q', exec_data, pos + 40)[0]
            filesize = struct.unpack_from('<Q', exec_data, pos + 48)[0]
            nsects = struct.unpack_from('<I', exec_data, pos + 64)[0]
            print(f"  LC[{i}]: SEGMENT_64 {seg_name} fileoff={fileoff} filesize={filesize} nsects={nsects}")
            
            # Check sections
            sect_pos = pos + 72
            for j in range(nsects):
                if sect_pos + 80 > len(exec_data):
                    break
                sect_name = exec_data[sect_pos:sect_pos+16].split(b'\x00')[0].decode('utf-8', errors='replace')
                sect_off = struct.unpack_from('<I', exec_data, sect_pos + 48)[0]
                if sect_off > 0 and sect_off < min_data_offset:
                    min_data_offset = sect_off
                sect_pos += 80
        
        elif cmd_id == 0x01:  # LC_SEGMENT
            seg_name = exec_data[pos+8:pos+24].split(b'\x00')[0].decode('utf-8', errors='replace')
            fileoff = struct.unpack_from('<I', exec_data, pos + 28)[0]
            filesize = struct.unpack_from('<I', exec_data, pos + 32)[0]
            print(f"  LC[{i}]: SEGMENT {seg_name} fileoff={fileoff} filesize={filesize}")
            if fileoff > 0 and fileoff < min_data_offset:
                min_data_offset = fileoff
        
        pos += cmdsize
    
    print(f"\nTotal LC_LOAD_DYLIB count: {dylib_count}")
    print(f"Min data offset: {min_data_offset}")
    print(f"Available padding: {min_data_offset - header_size - sizeofcmds} bytes")
    print(f"Needed for new LC_LOAD_DYLIB: ~64 bytes")
    
    if min_data_offset - header_size - sizeofcmds < 64:
        print("\n*** NOT ENOUGH PADDING for injection! ***")
        print("*** This is why TrollStore gives error 175 ***")
        print("*** Need to expand the header padding ***")
    else:
        print("\n*** Padding seems sufficient ***")
        print("*** Error 175 might be caused by something else ***")

elif magic == 0xCAFEBABE:  # FAT
    print("Type: Fat binary")
    nfat = struct.unpack_from('>I', exec_data, 4)[0]
    print(f"Number of architectures: {nfat}")
else:
    print(f"Unknown format: {hex(magic)}")
