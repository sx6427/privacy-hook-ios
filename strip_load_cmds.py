#!/usr/bin/env python3
"""
Strip problematic Mach-O load commands for iOS 16 compatibility.

Xcode 26 adds load commands like LC_OBJC_LINK_LAYOUT that older dyld
(iOS 16 and below) doesn't understand, causing immediate crash on dylib load.

This script:
1. Parses the Mach-O header
2. Lists all load commands (diagnostic)
3. Removes any load command NOT in the safe whitelist
4. Fixes up header (ncmds, sizeofcmds)
5. Pads the freed space with NOPs (LC_LOAD_DYLIB is used as NOP in practice,
   but we just zero-fill since dyld ignores gaps)
"""

import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF

# Mach-O header_64 layout:
# uint32_t magic       (4)
# int32_t  cputype     (4)
# int32_t  cpusubtype  (4)
# uint32_t filetype    (4)
# uint32_t ncmds       (4)
# uint32_t sizeofcmds  (4)
# uint32_t flags       (4)
# uint32_t reserved    (4)
# Total: 32 bytes

HEADER_SIZE_64 = 32
LC_HEADER_SIZE = 8  # cmd (4) + cmdsize (4)

# Load command type names (for diagnostics)
LC_NAMES = {
    0x01: "LC_SEGMENT",
    0x02: "LC_SYMTAB",
    0x0B: "LC_DYSYMTAB",
    0x0C: "LC_LOAD_DYLIB",
    0x0D: "LC_ID_DYLIB",
    0x11: "LC_DYLD_INFO",
    0x15: "LC_ROUTINES",
    0x16: "LC_SUB_CLIENT",
    0x17: "LC_SUB_UMBRELLA",
    0x18: "LC_SUB_LIBRARY",
    0x19: "LC_SEGMENT_64",
    0x1A: "LC_ROUTINES_64",
    0x1B: "LC_UUID",
    0x1D: "LC_CODE_SIGNATURE",
    0x1E: "LC_SEGMENT_SPLIT_INFO",
    0x22: "LC_DYLD_INFO",
    0x24: "LC_VERSION_MIN_MACOSX",
    0x25: "LC_VERSION_MIN_IPHONEOS",
    0x26: "LC_FUNCTION_STARTS",
    0x27: "LC_DYLD_ENVIRONMENT",
    0x29: "LC_DATA_IN_CODE",
    0x2A: "LC_SOURCE_VERSION",
    0x2B: "LC_DYLIB_CODE_SIGN_DRS",
    0x2C: "LC_ENCRYPTION_INFO_64",
    0x32: "LC_BUILD_VERSION",
    0x33: "LC_DYLD_EXPORTS_TRIE",
    0x34: "LC_DYLD_CHAINED_FIXUPS",
    0x35: "LC_ATOM_INFO",
    0x36: "LC_OBJC_OPTIMIZATION",
    0x37: "LC_OBJC_LINK_LAYOUT",
    # With LC_REQ_DYLD bit
    0x80000018: "LC_LOAD_WEAK_DYLIB",
    0x8000001C: "LC_RPATH",
    0x8000001F: "LC_REEXPORT_DYLIB",
    0x80000022: "LC_DYLD_INFO_ONLY",
    0x80000023: "LC_LOAD_UPWARD_DYLIB",
    0x80000026: "LC_FUNCTION_STARTS",
    0x80000027: "LC_DYLD_ENVIRONMENT",
    0x80000028: "LC_MAIN",
    0x80000029: "LC_DATA_IN_CODE",
    0x8000002A: "LC_DATA_IN_CODE",
    0x8000002B: "LC_SOURCE_VERSION",
    0x80000033: "LC_DYLD_EXPORTS_TRIE",
    0x80000034: "LC_DYLD_CHAINED_FIXUPS",
    0x80000035: "LC_ATOM_INFO",
    0x80000036: "LC_OBJC_OPTIMIZATION",
    0x80000037: "LC_OBJC_LINK_LAYOUT",
}

# Whitelist: load commands that iOS 16 dyld understands
# Values from <loader.h> — note: modern Xcode emits WITHOUT LC_REQ_DYLD bit
SAFE_LC_TYPES = {
    0x01,               # LC_SEGMENT
    0x02,               # LC_SYMTAB
    0x0B,               # LC_DYSYMTAB
    0x0C,               # LC_LOAD_DYLIB
    0x0D,               # LC_ID_DYLIB
    0x16,               # LC_SUB_CLIENT
    0x19,               # LC_SEGMENT_64
    0x1B,               # LC_UUID
    0x1D,               # LC_CODE_SIGNATURE
    0x1E,               # LC_SEGMENT_SPLIT_INFO
    0x22,               # LC_DYLD_INFO
    0x25,               # LC_VERSION_MIN_IPHONEOS
    0x26,               # LC_FUNCTION_STARTS (modern: no REQ_DYLD)
    0x29,               # LC_DATA_IN_CODE (modern: no REQ_DYLD)
    0x2A,               # LC_SOURCE_VERSION (modern: no REQ_DYLD)
    0x32,               # LC_BUILD_VERSION
    0x80000018,         # LC_LOAD_WEAK_DYLIB
    0x8000001C,         # LC_RPATH
    0x8000001F,         # LC_REEXPORT_DYLIB
    0x80000022,         # LC_DYLD_INFO_ONLY  (traditional fixups - needed!)
    0x80000028,         # LC_MAIN
}


def get_lc_name(cmd_type):
    return LC_NAMES.get(cmd_type, f"UNKNOWN(0x{cmd_type:08X})")


def process_macho(filepath):
    with open(filepath, 'rb') as f:
        data = bytearray(f.read())

    # Check magic
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic != MH_MAGIC_64:
        print(f"Not a 64-bit Mach-O (magic=0x{magic:08X})")
        return False

    # Parse header
    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = \
        struct.unpack_from('<IIiiIIII', data, 0)

    print(f"=== Mach-O Header ===")
    print(f"  Magic: 0x{magic:08X}")
    print(f"  CPU: {cputype} (arm64=0x100000C)")
    print(f"  Filetype: {filetype} (6=MH_DYLIB)")
    print(f"  ncmds: {ncmds}")
    print(f"  sizeofcmds: {sizeofcmds}")
    print()

    # Parse load commands
    offset = HEADER_SIZE_64
    load_cmds = []
    print(f"=== Load Commands ===")
    for i in range(ncmds):
        if offset + LC_HEADER_SIZE > len(data):
            print(f"  [{i}] ERROR: truncated load command at offset {offset}")
            break

        cmd, cmdsize = struct.unpack_from('<II', data, offset)
        name = get_lc_name(cmd)
        safe = cmd in SAFE_LC_TYPES
        status = "KEEP" if safe else "STRIP"
        print(f"  [{i:2d}] {name:40s} size={cmdsize:4d}  -> {status}")

        load_cmds.append({
            'offset': offset,
            'cmd': cmd,
            'cmdsize': cmdsize,
            'name': name,
            'safe': safe,
        })
        offset += cmdsize

    # Check if anything needs stripping
    to_strip = [lc for lc in load_cmds if not lc['safe']]
    if not to_strip:
        print("\nAll load commands are safe. No changes needed.")
        return True

    print(f"\n=== Stripping {len(to_strip)} load command(s) ===")

    # Build new load commands region
    new_cmds = bytearray()
    for lc in load_cmds:
        if lc['safe']:
            new_cmds.extend(data[lc['offset']:lc['offset'] + lc['cmdsize']])

    # Calculate padding (old size - new size)
    old_cmds_end = HEADER_SIZE_64 + sizeofcmds
    new_sizeofcmds = len(new_cmds)
    new_ncmds = len([lc for lc in load_cmds if lc['safe']])
    padding_size = sizeofcmds - new_sizeofcmds

    print(f"  Old: ncmds={ncmds}, sizeofcmds={sizeofcmds}")
    print(f"  New: ncmds={new_ncmds}, sizeofcmds={new_sizeofcmds}")
    print(f"  Padding: {padding_size} bytes (zeroed)")

    # Write new load commands + zero padding
    data[HEADER_SIZE_64:old_cmds_end] = new_cmds + (b'\x00' * padding_size)

    # Update header
    struct.pack_into('<II', data, 16, new_ncmds, new_sizeofcmds)  # ncmds, sizeofcmds

    # Write output
    with open(filepath, 'wb') as f:
        f.write(data)

    print(f"\nDone! Stripped: {', '.join(lc['name'] for lc in to_strip)}")
    return True


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <macho_file>")
        sys.exit(1)

    filepath = sys.argv[1]
    print(f"Processing: {filepath}\n")
    success = process_macho(filepath)
    sys.exit(0 if success else 1)
