"""Verify ARM64 ELF and uncompressed APK entries before distributing the APK."""
import struct
import sys
import zipfile


def check(path):
    checked = 0
    with open(path, "rb") as raw, zipfile.ZipFile(path) as archive:
        for item in archive.infolist():
            if not item.filename.startswith("lib/") or not item.filename.endswith(".so"):
                continue
            elf = archive.read(item)
            if elf[:4] != b"\x7fELF" or elf[5] != 1:
                raise ValueError("invalid little-endian ELF: " + item.filename)
            if elf[4] != 2:
                continue  # 16 KiB Android page sizes concern the 64-bit ABIs.
            phoff = struct.unpack_from("<Q", elf, 32)[0]
            stride, count = struct.unpack_from("<HH", elf, 54)
            loads = 0
            for index in range(count):
                offset = phoff + index * stride
                if struct.unpack_from("<I", elf, offset)[0] != 1:
                    continue
                file_offset, virtual_address = struct.unpack_from("<QQ", elf, offset + 8)
                alignment = struct.unpack_from("<Q", elf, offset + 48)[0]
                if alignment < 16384 or (file_offset - virtual_address) % 16384:
                    raise ValueError("ELF segment lacks 16 KiB alignment: " + item.filename)
                loads += 1
            if not loads:
                raise ValueError("ELF has no loadable segments: " + item.filename)
            if item.compress_type == zipfile.ZIP_STORED:
                raw.seek(item.header_offset + 26)
                name_size, extra_size = struct.unpack("<HH", raw.read(4))
                data_offset = item.header_offset + 30 + name_size + extra_size
                if data_offset % 16384:
                    raise ValueError("uncompressed APK entry lacks 16 KiB alignment: " + item.filename)
            checked += 1
            print(item.filename + ": 16 KiB ELF and packaging checks passed")
    if not checked:
        raise ValueError("no 64-bit native library found")


if __name__ == "__main__":
    check(sys.argv[1])
