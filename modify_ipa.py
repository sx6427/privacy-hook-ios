#!/usr/bin/env python3
"""
IPA Modifier — Bundle ID Change + Dylib Injection (for TrollStore)

Modifies an iOS IPA to:
  1. Change the Bundle ID (creates an independent app clone)
  2. Change the display name
  3. Update keychain access groups (prevent data sharing)
  4. Inject a privacy dylib into the main executable

No external dependencies required — uses pure Python standard library.
Works on Windows, macOS, and Linux.

Usage:
    python modify_ipa.py <input.ipa> <PrivacyHook.dylib> [options]

Examples:
    python modify_ipa.py baidu.ipa PrivacyHook.dylib
    python modify_ipa.py baidu.ipa PrivacyHook.dylib --bundle-id com.baidu.BaiduMobile2 --name "Baidu2"
    python modify_ipa.py baidu.ipa PrivacyHook.dylib --output baidu_clone.ipa
"""

import argparse
import os
import plistlib
import shutil
import struct
import sys
import tempfile
import zipfile


# ============================================================
# Mach-O Constants
# ============================================================
MH_MAGIC       = 0xFEEDFACE   # 32-bit, native byte order
MH_MAGIC_64    = 0xFEEDFACF   # 64-bit, native byte order
MH_CIGAM       = 0xCEFAEDFE   # 32-bit, swapped
MH_CIGAM_64    = 0xCFFAEDFE   # 64-bit, swapped
FAT_MAGIC      = 0xCAFEBABE   # Fat binary (big-endian)
FAT_CIGAM      = 0xBEBAFECA   # Fat binary (swapped)
FAT_MAGIC_64   = 0xCAFEBABF   # Fat binary 64-bit
FAT_CIGAM_64   = 0xBFBAFECA   # Fat binary 64-bit (swapped)

LC_SEGMENT         = 0x01     # 32-bit segment
LC_SEGMENT_64      = 0x19     # 64-bit segment
LC_LOAD_DYLIB      = 0x0C     # Load a dynamic library
LC_CODE_SIGNATURE  = 0x1D     # Code signature


# ============================================================
# IPA Extraction / Repackaging
# ============================================================

def extract_ipa(ipa_path: str, extract_dir: str) -> None:
    """Extract an IPA (zip file) to the given directory."""
    with zipfile.ZipFile(ipa_path, "r") as zf:
        zf.extractall(extract_dir)


def repackage_ipa(extract_dir: str, output_path: str) -> None:
    """Repackage a directory into an IPA (zip file)."""
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(extract_dir):
            for file_name in sorted(files):
                file_path = os.path.join(root, file_name)
                arcname = os.path.relpath(file_path, extract_dir)
                zf.write(file_path, arcname)


def find_app_bundle(extract_dir: str) -> str:
    """Find the .app folder inside Payload/."""
    payload_dir = os.path.join(extract_dir, "Payload")
    if not os.path.isdir(payload_dir):
        raise FileNotFoundError("Payload/ directory not found in IPA")

    app_bundles = [d for d in os.listdir(payload_dir) if d.endswith(".app")]
    if not app_bundles:
        raise FileNotFoundError(".app bundle not found in Payload/")

    return os.path.join(payload_dir, app_bundles[0])


# ============================================================
# Info.plist Modification
# ============================================================

def modify_info_plist(app_path: str, new_bundle_id: str, new_display_name: str) -> str:
    """
    Modify Info.plist:
      - CFBundleIdentifier   → new_bundle_id
      - CFBundleDisplayName  → new_display_name
      - CFBundleName         → new_display_name
      - keychain-access-groups → replace old bundle ID with new
      - CFBundleURLTypes     → replace old bundle ID in URL schemes

    Returns the original bundle ID.
    """
    info_plist_path = os.path.join(app_path, "Info.plist")

    with open(info_plist_path, "rb") as f:
        info = plistlib.load(f)

    original_bundle_id = info.get("CFBundleIdentifier", "unknown")
    print(f"  Original Bundle ID:  {original_bundle_id}")
    print(f"  New Bundle ID:       {new_bundle_id}")

    # --- Bundle ID ---
    info["CFBundleIdentifier"] = new_bundle_id

    # --- Display name ---
    if new_display_name:
        info["CFBundleDisplayName"] = new_display_name
        info["CFBundleName"] = new_display_name
        print(f"  New Display Name:    {new_display_name}")

    # --- Keychain access groups ---
    if "keychain-access-groups" in info:
        old_groups = info["keychain-access-groups"]
        new_groups = []
        for group in old_groups:
            if isinstance(group, str) and original_bundle_id in group:
                new_group = group.replace(original_bundle_id, new_bundle_id)
                new_groups.append(new_group)
                print(f"  Keychain: {group} -> {new_group}")
            else:
                new_groups.append(group)
        info["keychain-access-groups"] = new_groups

    # --- URL schemes ---
    if "CFBundleURLTypes" in info:
        for url_type in info["CFBundleURLTypes"]:
            if "CFBundleURLSchemes" in url_type:
                new_schemes = []
                for scheme in url_type["CFBundleURLSchemes"]:
                    if isinstance(scheme, str) and original_bundle_id in scheme:
                        new_scheme = scheme.replace(original_bundle_id, new_bundle_id)
                        new_schemes.append(new_scheme)
                        print(f"  URL scheme: {scheme} -> {new_scheme}")
                    else:
                        new_schemes.append(scheme)
                url_type["CFBundleURLSchemes"] = new_schemes

    # --- Write back ---
    with open(info_plist_path, "wb") as f:
        plistlib.dump(info, f)

    return original_bundle_id


# ============================================================
# Raw Mach-O Load Command Injection
# ============================================================

def _build_load_dylib_command(dylib_name: str) -> bytes:
    """
    Build an LC_LOAD_DYLIB load command as raw bytes.

    Layout (little-endian):
      cmd                 (4)  = 0x0C (LC_LOAD_DYLIB)
      cmdsize             (4)  = total command size
      name.offset         (4)  = offset of name string from cmd start
      timestamp           (4)  = 2
      current_version     (4)  = 0
      compatibility_ver   (4)  = 0
      name                (N)  = "@executable_path/<dylib>\0", padded to 8
    """
    load_path = f"@executable_path/{dylib_name}"
    name_bytes = load_path.encode("utf-8") + b"\x00"
    # Pad name to 8-byte boundary
    name_padded_len = (len(name_bytes) + 7) & ~7

    fixed_size = 24  # 6 x uint32_t
    cmdsize = fixed_size + name_padded_len

    cmd = struct.pack(
        "<IIIIII",
        LC_LOAD_DYLIB,   # cmd
        cmdsize,          # cmdsize
        fixed_size,       # name.offset (offset from cmd start to name string)
        2,                # timestamp
        0,                # current_version
        0,                # compatibility_version
    )
    cmd += name_bytes.ljust(name_padded_len, b"\x00")
    return cmd


def _find_min_data_offset(data: bytearray, macho_off: int, is_64: bool,
                           header_size: int, sizeofcmds: int) -> int:
    """
    Find the minimum file offset (relative to the Mach-O slice start) where
    actual segment/section data begins. This tells us how much padding space
    is available after the load commands for inserting a new one.
    """
    min_offset = float("inf")
    pos = macho_off + header_size
    end = pos + sizeofcmds

    while pos < end:
        if pos + 8 > len(data):
            break
        cmd_id = struct.unpack_from("<I", data, pos)[0]
        cmdsize = struct.unpack_from("<I", data, pos + 4)[0]
        if cmdsize == 0:
            break

        if cmd_id == LC_SEGMENT_64:
            # segment_command_64 is 72 bytes
            if pos + 72 > len(data):
                break
            nsects = struct.unpack_from("<I", data, pos + 64)[0]
            # Sections start right after segment_command_64 (offset 72)
            sect_pos = pos + 72
            for _ in range(nsects):
                if sect_pos + 80 > len(data):
                    break
                # section_64: offset field is at +48 (uint32)
                sect_off = struct.unpack_from("<I", data, sect_pos + 48)[0]
                if 0 < sect_off < min_offset:
                    min_offset = sect_off
                sect_pos += 80  # sizeof(section_64)

        elif cmd_id == LC_SEGMENT:
            # segment_command is 56 bytes
            if pos + 56 > len(data):
                break
            nsects = struct.unpack_from("<I", data, pos + 48)[0]
            sect_pos = pos + 56
            for _ in range(nsects):
                if sect_pos + 68 > len(data):
                    break
                sect_off = struct.unpack_from("<I", data, sect_pos + 40)[0]
                if 0 < sect_off < min_offset:
                    min_offset = sect_off
                sect_pos += 68  # sizeof(section)

        pos += cmdsize

    if min_offset == float("inf"):
        # Fallback: assume next page boundary (16KB)
        min_offset = (header_size + sizeofcmds + 0x3FFF) & ~0x3FFF

    return min_offset


def _remove_code_signature(data: bytearray, macho_off: int, is_64: bool,
                            header_size: int, ncmds: int, sizeofcmds: int) -> tuple:
    """
    Find and remove the LC_CODE_SIGNATURE load command.
    Also:
      - Update __LINKEDIT segment filesize to exclude signature data
      - Truncate the file to remove the dead signature bytes
      - Zero out the freed load command space

    Returns (new_ncmds, new_sizeofcmds).
    """
    pos = macho_off + header_size
    end = pos + sizeofcmds
    cs_cmd_off = -1
    cs_cmd_size = 0
    cs_data_off = 0
    cs_data_size = 0
    linkedit_cmd_off = -1
    linkedit_fileoff = 0
    linkedit_filesize = 0

    # Walk load commands to find LC_CODE_SIGNATURE and __LINKEDIT
    while pos < end:
        if pos + 8 > len(data):
            break
        cmd_id = struct.unpack_from("<I", data, pos)[0]
        cmdsize = struct.unpack_from("<I", data, pos + 4)[0]
        if cmdsize == 0:
            break

        if cmd_id == LC_CODE_SIGNATURE:
            cs_cmd_off = pos
            cs_cmd_size = cmdsize
            cs_data_off = struct.unpack_from("<I", data, pos + 8)[0]
            cs_data_size = struct.unpack_from("<I", data, pos + 12)[0]
            print(f"  Found LC_CODE_SIGNATURE: cmdsize={cmdsize}, "
                  f"data_off={cs_data_off}, data_size={cs_data_size}")

        elif cmd_id == LC_SEGMENT_64:
            # segment_command_64: segname at +8, fileoff at +40, filesize at +48
            segname = data[pos + 8 : pos + 24].split(b'\x00')[0].decode('utf-8', errors='replace')
            if segname == '__LINKEDIT':
                linkedit_cmd_off = pos
                linkedit_fileoff = struct.unpack_from('<Q', data, pos + 40)[0]
                linkedit_filesize = struct.unpack_from('<Q', data, pos + 48)[0]
                print(f"  Found __LINKEDIT: fileoff={linkedit_fileoff}, filesize={linkedit_filesize}")

        elif cmd_id == LC_SEGMENT:
            # segment_command: segname at +8, fileoff at +28, filesize at +32
            segname = data[pos + 8 : pos + 24].split(b'\x00')[0].decode('utf-8', errors='replace')
            if segname == '__LINKEDIT':
                linkedit_cmd_off = pos
                linkedit_fileoff = struct.unpack_from('<I', data, pos + 28)[0]
                linkedit_filesize = struct.unpack_from('<I', data, pos + 32)[0]
                print(f"  Found __LINKEDIT: fileoff={linkedit_fileoff}, filesize={linkedit_filesize}")

        pos += cmdsize

    if cs_cmd_off < 0:
        # No code signature found
        return ncmds, sizeofcmds

    # --- Update __LINKEDIT filesize to exclude signature data ---
    # The code signature sits at the very end of __LINKEDIT.
    # New filesize = old_filesize - cs_data_size
    if linkedit_cmd_off >= 0 and cs_data_off >= linkedit_fileoff:
        new_linkedit_filesize = cs_data_off - linkedit_fileoff
        if is_64:
            struct.pack_into('<Q', data, linkedit_cmd_off + 48, new_linkedit_filesize)
        else:
            struct.pack_into('<I', data, linkedit_cmd_off + 32, new_linkedit_filesize)
        print(f"  Updated __LINKEDIT filesize: {linkedit_filesize} -> {new_linkedit_filesize}")

    # --- Remove the LC_CODE_SIGNATURE load command ---
    # Shift subsequent commands back
    shift_src = cs_cmd_off + cs_cmd_size
    shift_dst = cs_cmd_off
    shift_len = (macho_off + header_size + sizeofcmds) - shift_src

    if shift_len > 0:
        data[shift_dst : shift_dst + shift_len] = data[shift_src : shift_src + shift_len]

    # Zero out the freed space at the end of load commands
    freed_start = macho_off + header_size + sizeofcmds - cs_cmd_size
    for i in range(freed_start, freed_start + cs_cmd_size):
        data[i] = 0

    # --- Truncate the file to remove dead signature data ---
    # Only for single-arch (macho_off == 0); truncating a fat binary's
    # slice in the middle of the file would corrupt other slices.
    if macho_off == 0 and cs_data_off > 0 and cs_data_off < len(data):
        original_len = len(data)
        del data[cs_data_off:]
        print(f"  Truncated file: {original_len} -> {len(data)} bytes "
              f"(removed {original_len - len(data)} bytes)")

    new_ncmds = ncmds - 1
    new_sizeofcmds = sizeofcmds - cs_cmd_size

    print(f"  Removed LC_CODE_SIGNATURE ({cs_cmd_size}B freed)")
    return new_ncmds, new_sizeofcmds


def _inject_into_slice(data: bytearray, macho_off: int, dylib_name: str) -> bool:
    """
    Inject LC_LOAD_DYLIB into a single Mach-O slice within `data`.
    First removes any existing LC_CODE_SIGNATURE to ensure ldid can re-sign cleanly.
    `macho_off` is the absolute offset of this slice in the file.
    Returns True on success.
    """
    magic = struct.unpack_from("<I", data, macho_off)[0]

    if magic == MH_MAGIC_64:
        is_64 = True
    elif magic == MH_MAGIC:
        is_64 = False
    elif magic in (MH_CIGAM_64, MH_CIGAM):
        print(f"  [offset {macho_off}] Warning: Swapped byte order, skipping")
        return False
    else:
        print(f"  [offset {macho_off}] Not a Mach-O (magic={hex(magic)})")
        return False

    header_size = 32 if is_64 else 28

    # Read header fields
    ncmds = struct.unpack_from("<I", data, macho_off + 16)[0]
    sizeofcmds = struct.unpack_from("<I", data, macho_off + 20)[0]

    # --- Step 1: Remove existing code signature ---
    ncmds, sizeofcmds = _remove_code_signature(
        data, macho_off, is_64, header_size, ncmds, sizeofcmds
    )

    # Update header with new ncmds/sizeofcmds after removing code sig
    struct.pack_into("<I", data, macho_off + 16, ncmds)
    struct.pack_into("<I", data, macho_off + 20, sizeofcmds)

    end_of_cmds = macho_off + header_size + sizeofcmds

    # --- Step 2: Add LC_LOAD_DYLIB ---
    cmd_bytes = _build_load_dylib_command(dylib_name)
    cmdsize = len(cmd_bytes)

    # Check available padding
    min_data_off = _find_min_data_offset(data, macho_off, is_64, header_size, sizeofcmds)
    available = min_data_off - (header_size + sizeofcmds)

    if available < cmdsize:
        print(f"  [offset {macho_off}] Not enough padding: {available}B available, {cmdsize}B needed")
        return False

    # Write the new load command into the padding area
    data[end_of_cmds : end_of_cmds + cmdsize] = cmd_bytes

    # Update header: ncmds += 1, sizeofcmds += cmdsize
    struct.pack_into("<I", data, macho_off + 16, ncmds + 1)
    struct.pack_into("<I", data, macho_off + 20, sizeofcmds + cmdsize)

    print(f"  [offset {macho_off}] Injected LC_LOAD_DYLIB ({cmdsize}B) -> "
          f"@executable_path/{dylib_name}")
    return True


def inject_dylib_into_executable(executable_path: str, dylib_name: str) -> None:
    """
    Add an LC_LOAD_DYLIB load command to a Mach-O executable.
    Handles both single-arch and fat (universal) binaries.
    No external dependencies required.
    """
    with open(executable_path, "rb") as f:
        data = bytearray(f.read())

    magic_be = struct.unpack_from(">I", data, 0)[0]

    if magic_be in (FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64):
        # --- Fat binary ---
        is_fat64 = magic_be in (FAT_MAGIC_64, FAT_CIGAM_64)
        nfat = struct.unpack_from(">I", data, 4)[0]
        print(f"  Fat binary: {nfat} architecture(s)")

        arch_pos = 8  # after fat_header (8 bytes)
        for i in range(nfat):
            if is_fat64:
                # fat_arch_64: cputype(4) cpusubtype(4) offset(8) size(8) align(4) reserved(4)
                cputype = struct.unpack_from(">I", data, arch_pos)[0]
                slice_off = struct.unpack_from(">Q", data, arch_pos + 8)[0]
                arch_pos += 32
            else:
                # fat_arch: cputype(4) cpusubtype(4) offset(4) size(4) align(4)
                cputype = struct.unpack_from(">I", data, arch_pos)[0]
                slice_off = struct.unpack_from(">I", data, arch_pos + 8)[0]
                arch_pos += 20

            print(f"  Arch {i + 1}: cputype={hex(cputype)}, offset={slice_off}")
            _inject_into_slice(data, slice_off, dylib_name)

    else:
        # --- Single-arch Mach-O ---
        magic_le = struct.unpack_from("<I", data, 0)[0]
        if magic_le in (MH_MAGIC, MH_MAGIC_64, MH_CIGAM, MH_CIGAM_64):
            print("  Single-arch Mach-O detected")
            _inject_into_slice(data, 0, dylib_name)
        else:
            raise ValueError(
                f"Unknown file format (big-endian={hex(magic_be)}, "
                f"little-endian={hex(magic_le)})"
            )

    with open(executable_path, "wb") as f:
        f.write(data)


# ============================================================
# Main Workflow
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Modify IPA: change Bundle ID + inject privacy dylib (for TrollStore)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python modify_ipa.py baidu.ipa PrivacyHook.dylib
  python modify_ipa.py baidu.ipa PrivacyHook.dylib --bundle-id com.baidu.BaiduMobile2
  python modify_ipa.py baidu.ipa PrivacyHook.dylib --name "Baidu2" --output baidu2.ipa
        """,
    )
    parser.add_argument("ipa", help="Path to the original IPA file")
    parser.add_argument("dylib", help="Path to PrivacyHook.dylib")
    parser.add_argument(
        "--bundle-id", default=None,
        help="New Bundle ID (default: original + '2')",
    )
    parser.add_argument(
        "--name", default=None,
        help='New display name (default: original + " 2")',
    )
    parser.add_argument(
        "--dylib-name", default=None,
        help="Rename the dylib inside the .app bundle (anti-detection)",
    )
    parser.add_argument(
        "--output", default=None,
        help="Output IPA path (default: <input>_modified.ipa)",
    )

    args = parser.parse_args()

    # --- Validate inputs ---
    if not os.path.isfile(args.ipa):
        print(f"Error: IPA file not found: {args.ipa}")
        sys.exit(1)
    if not os.path.isfile(args.dylib):
        print(f"Error: Dylib file not found: {args.dylib}")
        sys.exit(1)

    # --- Set defaults ---
    if args.output is None:
        base, ext = os.path.splitext(args.ipa)
        args.output = f"{base}_modified{ext}"

    dylib_name = args.dylib_name or os.path.basename(args.dylib)

    print("=" * 60)
    print("  IPA Modifier - Bundle ID + Dylib Injection")
    print("  For TrollStore on iOS")
    print("=" * 60)
    print(f"  Input IPA : {args.ipa}")
    print(f"  Dylib     : {args.dylib}")
    if args.dylib_name:
        print(f"  Renamed   : {args.dylib_name} (anti-detection)")
    print(f"  Output    : {args.output}")
    print()

    with tempfile.TemporaryDirectory() as tmp:
        # --- Step 1: Extract ---
        print("[1/5] Extracting IPA...")
        extract_ipa(args.ipa, tmp)
        print("  Done.")

        # --- Step 2: Locate .app ---
        print("[2/5] Locating app bundle...")
        app_path = find_app_bundle(tmp)
        app_name = os.path.basename(app_path)
        print(f"  Found: {app_name}")

        # --- Step 3: Modify Info.plist ---
        print("[3/5] Modifying Info.plist...")
        # Read original values for defaults
        with open(os.path.join(app_path, "Info.plist"), "rb") as f:
            info = plistlib.load(f)

        orig_bid = info.get("CFBundleIdentifier", "com.app")
        orig_name = info.get("CFBundleDisplayName",
                             info.get("CFBundleName", "App"))

        new_bid = args.bundle_id or f"{orig_bid}2"
        new_name = args.name or f"{orig_name} 2"

        modify_info_plist(app_path, new_bid, new_name)

        # Remove old code signature (TrollStore will re-sign)
        cs_dir = os.path.join(app_path, "_CodeSignature")
        if os.path.isdir(cs_dir):
            shutil.rmtree(cs_dir)
            print("  Removed _CodeSignature (TrollStore will re-sign)")
        print("  Done.")

        # --- Step 4: Inject dylib ---
        print("[4/5] Injecting dylib...")

        # Copy dylib into .app bundle (optionally renamed)
        dest_dylib = os.path.join(app_path, dylib_name)
        shutil.copy2(args.dylib, dest_dylib)
        print(f"  Copied {os.path.basename(args.dylib)} -> {app_name}/{dylib_name}")

        # Find main executable
        # Re-read Info.plist (we modified it)
        with open(os.path.join(app_path, "Info.plist"), "rb") as f:
            info = plistlib.load(f)
        exec_name = info.get("CFBundleExecutable", "")
        if not exec_name:
            raise ValueError("CFBundleExecutable not found in Info.plist")

        exec_path = os.path.join(app_path, exec_name)
        print(f"  Main executable: {exec_name}")

        # Add LC_LOAD_DYLIB to the executable
        inject_dylib_into_executable(exec_path, dylib_name)
        print("  Done.")

        # --- Step 5: Repackage ---
        print("[5/5] Repackaging IPA...")
        repackage_ipa(tmp, args.output)
        print(f"  Saved: {args.output}")

    print()
    print("=" * 60)
    print("  SUCCESS! Modified IPA created.")
    print("=" * 60)
    print()
    print("Next steps:")
    print(f"  1. Transfer '{os.path.basename(args.output)}' to your iPhone")
    print(f"  2. Open with TrollStore to install")
    print(f"  3. The cloned app will have an isolated device fingerprint")
    print()


if __name__ == "__main__":
    main()
