#!/usr/bin/env python3
"""Normalize LC_BUILD_VERSION in a thin 64-bit Mach-O kext.

clang -mkernel -nostdlib emits LC_BUILD_VERSION with platform=0, minos=0,
sdk=0. platform 0 is not a valid macOS platform value, so we rewrite the
three fields in place (same size, no offset shuffling):

    platform = 1        (PLATFORM_MACOS)
    minos    = 0x000C0000  (12.0.0)
    sdk      = 0x000C0000  (12.0.0)

This keeps the file layout byte-identical apart from those 12 bytes, which
avoids having to relocate __LINKEDIT or fix up LC_SYMTAB/LC_DYSYMTAB offsets.
"""
import struct
import sys

LC_BUILD_VERSION = 0x2A
MH_MAGIC_64 = 0xFEEDFACF
PLATFORM_MACOS = 1
VERSION_12_0 = 0x000C0000


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def main():
    src, dst = sys.argv[1], sys.argv[2]
    b = bytearray(open(src, "rb").read())

    if u32(b, 0) != MH_MAGIC_64:
        print("not a thin 64-bit mach-o; copying through")
        open(dst, "wb").write(b)
        return 0

    ncmds = u32(b, 16)
    off = 32
    patched = False
    for _ in range(ncmds):
        cmd = u32(b, off)
        sz = u32(b, off + 4)
        if sz < 8:
            print("malformed command at 0x%X" % off)
            return 1
        if cmd == LC_BUILD_VERSION and sz >= 24:
            before = (u32(b, off + 8), u32(b, off + 12), u32(b, off + 16))
            struct.pack_into("<I", b, off + 8, PLATFORM_MACOS)
            struct.pack_into("<I", b, off + 12, VERSION_12_0)
            struct.pack_into("<I", b, off + 16, VERSION_12_0)
            print("LC_BUILD_VERSION platform=%d minos=0x%X sdk=0x%X -> platform=1 minos=0x%X"
                  % (before[0], before[1], before[2], VERSION_12_0))
            patched = True
        off += sz

    if not patched:
        print("no LC_BUILD_VERSION found; copying through")

    open(dst, "wb").write(b)
    print("wrote %s (%d bytes)" % (dst, len(b)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
