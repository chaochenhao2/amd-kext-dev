#!/usr/bin/env python3
"""Normalize a hand-linked 64-bit Mach-O kext so OpenCore can inject it.

Two defects are repaired, both of which cause
"OC: Prelinked Injection <kext> () - Invalid Parameter":

1. LC_BUILD_VERSION carries platform=0/minos=0/sdk=0.
   clang -mkernel -nostdlib supplies no platform triple. Rewrite in place:
       platform = 1          (PLATFORM_MACOS)
       minos    = 0x000C0000 (12.0.0)
       sdk      = 0x000C0000 (12.0.0)

2. __LINKEDIT declares vmsize > filesize (e.g. 0x6000 vs 0x5308).
   Mach-O requires them equal for __LINKEDIT (pure data, no zero-fill).
   MachoExpandImage copies vmsize bytes, so the tail is read past EOF and
   garbage lands in the image; KextFindKmodAddress then rejects it.
   Fix: pad the file to fileoff + vmsize and set filesize = vmsize.

Nothing is relocated, so LC_SYMTAB / LC_DYSYMTAB offsets stay valid.
"""
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_BUILD_VERSION = 0x2A
PLATFORM_MACOS = 1
VERSION_12_0 = 0x000C0000


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def p32(b, o, v):
    struct.pack_into("<I", b, o, v & 0xFFFFFFFF)


def p64(b, o, v):
    struct.pack_into("<Q", b, o, v & 0xFFFFFFFFFFFFFFFF)


def segname(b, off):
    return bytes(b[off + 8:off + 24]).split(b"\x00")[0].decode("ascii", "replace")


def main():
    src, dst = sys.argv[1], sys.argv[2]
    data = bytearray(open(src, "rb").read())

    if u32(data, 0) != MH_MAGIC_64:
        print("not a thin 64-bit mach-o; copying through")
        open(dst, "wb").write(data)
        return 0

    ncmds = u32(data, 16)

    # --- pass 1: locate segments and LC_BUILD_VERSION -----------------------
    off = 32
    seg_offsets = {}
    bv_off = -1
    for _ in range(ncmds):
        cmd = u32(data, off)
        sz = u32(data, off + 4)
        if sz < 8:
            print("malformed load command at 0x%X" % off)
            return 1
        if cmd == LC_SEGMENT_64:
            seg_offsets[segname(data, off)] = off
        elif cmd == LC_BUILD_VERSION:
            # NOTE: clang -mkernel emits a 16-byte LC_BUILD_VERSION holding only
            # cmd + cmdsize + platform + minos (no sdk, no ntools), which is
            # already shorter than the 24-byte minimum the struct allows. Only
            # touch fields that physically fit inside cmdsize.
            bv_off = off
            bv_size = sz
        off += sz

    # --- fix LC_BUILD_VERSION ----------------------------------------------
    if bv_off >= 0:
        old_plat = u32(data, bv_off + 8) if bv_size >= 12 else -1
        old_minos = u32(data, bv_off + 12) if bv_size >= 16 else -1
        if bv_size >= 12:
            p32(data, bv_off + 8, PLATFORM_MACOS)
        if bv_size >= 16:
            p32(data, bv_off + 12, VERSION_12_0)
        if bv_size >= 20:
            p32(data, bv_off + 16, VERSION_12_0)
        print("LC_BUILD_VERSION size=%d platform=%d minos=0x%X -> platform=1 minos=0x%X"
              % (bv_size, old_plat, old_minos, VERSION_12_0))
    else:
        print("no LC_BUILD_VERSION (ok)")

    # --- fix __LINKEDIT vmsize vs filesize ---------------------------------
    legend = seg_offsets.get("__LINKEDIT")
    if legend is None:
        print("no __LINKEDIT segment; copying through")
        open(dst, "wb").write(data)
        return 0

    fileoff = u64(data, legend + 40)
    filesize = u64(data, legend + 48)
    vmsize = u64(data, legend + 32)

    print("__LINKEDIT fileoff=0x%X filesize=0x%X vmsize=0x%X" % (fileoff, filesize, vmsize))

    if filesize == vmsize:
        print("__LINKEDIT already consistent")
        open(dst, "wb").write(data)
        return 0

    if vmsize < filesize:
        # Shrinking is unsafe; just report.
        print("WARNING: vmsize < filesize, leaving untouched")
        open(dst, "wb").write(data)
        return 0

    need = fileoff + vmsize
    if len(data) < need:
        data.extend(b"\x00" * (need - len(data)))
        print("padded file to 0x%X (%d bytes)" % (need, len(data)))
    else:
        print("file already long enough (%d bytes); only filesize will change" % len(data))

    p64(data, legend + 48, vmsize)
    print("__LINKEDIT filesize set to 0x%X (== vmsize)" % vmsize)

    open(dst, "wb").write(data)
    print("wrote %s (%d bytes)" % (dst, len(data)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
