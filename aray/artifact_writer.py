"""Raw binary artifact writers for the scan-only path (no compiler required)."""

import os
import struct

# Magic-byte → extension lookup (checked in order; first match wins).
_MAGIC_TO_EXT: list[tuple[bytes, str]] = [
    (b"\x89PNG",          ".png"),
    (b"\xFF\xD8\xFF",     ".jpg"),
    (b"\xD0\xCF\x11\xE0", ".doc"),
    (b"GIF8",             ".gif"),
    (b"PK",               ".zip"),
    (b"<?php",            ".php"),
    (b"<%",               ".asp"),
]

# Minimal ELF64 header (64 bytes): ET_EXEC, EM_X86_64, no program/section headers.
_ELF64_IDENT = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # 16 bytes
_ELF64_HEADER: bytes = _ELF64_IDENT + struct.pack(
    "<HHIQQQIHHHHHH",
    2,   # e_type:      ET_EXEC
    62,  # e_machine:   EM_X86_64
    1,   # e_version:   EV_CURRENT
    0,   # e_entry
    0,   # e_phoff
    0,   # e_shoff
    0,   # e_flags
    64,  # e_ehsize
    56,  # e_phentsize
    0,   # e_phnum
    64,  # e_shentsize
    0,   # e_shnum
    0,   # e_shstrndx
)  # 64 bytes total


def _compute_padding(current_size: int, min_bytes: int | None, max_bytes: int | None) -> int:
    """Compute how many padding bytes to append to satisfy a filesize constraint.

    Returns 0 when the constraint is already satisfied or when the binary exceeds
    the maximum (can't shrink).  The caller is responsible for printing a warning
    in the latter case.
    """
    if max_bytes is not None and current_size >= max_bytes:
        return 0
    if min_bytes is None or current_size >= min_bytes:
        return 0

    # current_size < min_bytes — need to pad
    effective_min = min_bytes
    if max_bytes is not None:
        target = (effective_min + max_bytes) // 2
        target = min(target, max_bytes - 1)
    else:
        target = effective_min + 1024
    return max(0, target - current_size)


def write_linux_artifact(
    sections: list[tuple[int, bytes]],
    constants: list,
    filesize_constraint: tuple[int | None, int | None] | None = None,
    debug: bool = False,
) -> bytes:
    """Allocate a zeroed buffer, place each section at its file offset, patch constants.

    A minimal ELF64 header is written at offset 0 unless a section already claims it.
    Non-nested constants are patched directly; nested constants are skipped (they
    only arise for PE rules, which are routed to write_pe_artifact instead).
    """
    # Determine required buffer size from sections and constants.
    required = 0
    for offset, data in sections:
        if data:
            required = max(required, offset + len(data))
    for entry in constants:
        if isinstance(entry, dict):
            off = entry.get("offset")
            sz = entry.get("size", 4)
        else:
            off = entry.offset
            sz = entry.size
        if off is not None:
            required = max(required, off + sz)

    required = max(required, 0x200)
    buf = bytearray(required)

    # Prepend ELF64 header if offset 0 is unclaimed.
    claimed_offsets = {off for off, data in sections if data}
    if 0 not in claimed_offsets:
        buf[0:64] = _ELF64_HEADER

    # Write section data.
    for offset, data in sections:
        if data:
            buf[offset : offset + len(data)] = data

    # Patch non-nested constants.
    for entry in constants:
        if isinstance(entry, dict):
            offset = entry.get("offset")
            value = entry.get("value")
            size = entry.get("size", 4)
            is_nested = entry.get("is_nested", False)
        else:
            offset = entry.offset
            value = entry.value
            size = entry.size
            is_nested = entry.is_nested

        if offset is None or is_nested:
            continue

        if isinstance(value, str):
            value = int(value, 16) if value.startswith(("0x", "0X")) else int(value)

        buf[offset : offset + size] = value.to_bytes(size, byteorder="little")

    buf = bytes(buf)
    if filesize_constraint:
        min_b, max_b = filesize_constraint
        if max_b is not None and len(buf) >= max_b:
            print(
                f"Warning: artifact size ({len(buf)} bytes) already meets or exceeds "
                f"the filesize < {max_b} constraint. Consider --scan-only for a smaller binary."
            )
        else:
            n = _compute_padding(len(buf), min_b, max_b)
            if debug:
                if n > 0:
                    print(f"[debug] filesize padding: {len(buf)} + {n} → {len(buf) + n} bytes")
                else:
                    print(f"[debug] filesize padding: {len(buf)} bytes already satisfies constraint")
            if n > 0:
                buf += os.urandom(n)
    return buf


def write_pe_artifact(
    sections: list[tuple[int, bytes]],
    constants: list,
    filesize_constraint: tuple[int | None, int | None] | None = None,
    debug: bool = False,
) -> bytes:
    """Build a minimal PE64 binary with strings at their exact file offsets.

    Layout:
      0x00  DOS header (64 bytes): MZ magic + e_lfanew=0x40
      0x40  PE signature (4 bytes): PE\\x00\\x00
      0x44  COFF header (20 bytes, NumberOfSections=0)
      0x58  Optional header PE64 (240 bytes, mostly zero)
      0x148 String and constant data at their exact file offsets

    Satisfies uint16(0)==0x5A4D and uint32(uint32(0x3C))==0x00004550 automatically.
    Strings with 'at' constraints are placed at their specified file offsets;
    strings without constraints land at their default-assigned offsets
    (DEFAULT_OFFSET_BASE=0x3000, incrementing by DEFAULT_OFFSET_STEP).
    Non-nested constants are patched at their file offsets after the header.
    """
    _PE_SIG_OFFSET = 0x40
    _COFF_OFFSET = _PE_SIG_OFFSET + 4   # 0x44
    _OPT_OFFSET = _COFF_OFFSET + 20     # 0x58
    _OPT_SIZE = 0xF0                     # PE64 optional header: 240 bytes
    _HDR_END = _OPT_OFFSET + _OPT_SIZE  # 0x148

    # Determine required buffer size from sections and constants.
    required = _HDR_END
    for offset, data in sections:
        if data:
            required = max(required, offset + len(data))
    for entry in constants:
        if isinstance(entry, dict):
            off = entry.get("offset")
            sz = entry.get("size", 4)
        else:
            off = entry.offset
            sz = entry.size
        if off is not None:
            required = max(required, off + sz)
    required = max(required, 0x200)
    buf = bytearray(required)

    # DOS header.
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, _PE_SIG_OFFSET)

    # PE signature.
    buf[_PE_SIG_OFFSET : _PE_SIG_OFFSET + 4] = b"PE\x00\x00"

    # COFF header (IMAGE_FILE_HEADER), no sections needed for YARA scanning.
    struct.pack_into(
        "<HHIIIHH", buf, _COFF_OFFSET,
        0x8664,    # Machine: IMAGE_FILE_MACHINE_AMD64
        0,         # NumberOfSections
        0,         # TimeDateStamp
        0,         # PointerToSymbolTable
        0,         # NumberOfSymbols
        _OPT_SIZE, # SizeOfOptionalHeader
        0x0002,    # Characteristics: IMAGE_FILE_EXECUTABLE_IMAGE
    )

    # Optional header magic (PE64).
    struct.pack_into("<H", buf, _OPT_OFFSET, 0x020B)

    # Write string data at their exact file offsets.
    for offset, data in sections:
        if data:
            buf[offset : offset + len(data)] = data

    # Patch non-nested constants.
    for entry in constants:
        if isinstance(entry, dict):
            offset = entry.get("offset")
            value = entry.get("value")
            size = entry.get("size", 4)
            is_nested = entry.get("is_nested", False)
        else:
            offset = entry.offset
            value = entry.value
            size = entry.size
            is_nested = entry.is_nested

        if offset is None or is_nested:
            continue

        if isinstance(value, str):
            value = int(value, 16) if value.startswith(("0x", "0X")) else int(value)

        buf[offset : offset + size] = value.to_bytes(size, byteorder="little")

    result = bytes(buf)
    if filesize_constraint:
        min_b, max_b = filesize_constraint
        if max_b is not None and len(result) >= max_b:
            print(
                f"Warning: artifact size ({len(result)} bytes) already meets or exceeds "
                f"the filesize < {max_b} constraint. Consider --scan-only for a smaller binary."
            )
        else:
            n = _compute_padding(len(result), min_b, max_b)
            if debug:
                if n > 0:
                    print(f"[debug] filesize padding: {len(result)} + {n} → {len(result) + n} bytes")
                else:
                    print(f"[debug] filesize padding: {len(result)} bytes already satisfies constraint")
            if n > 0:
                result += os.urandom(n)
    return result


def write_generic_artifact(
    sections: list[tuple[int, bytes]],
    constants: list,
    filesize_constraint: tuple[int | None, int | None] | None = None,
    debug: bool = False,
) -> tuple[bytes, str]:
    """Allocate a zeroed buffer, place sections at exact file offsets, patch constants.

    No ELF/PE header is written — offset 0 belongs entirely to the rule's own
    magic bytes.  Non-nested integer constants are patched via little-endian
    write (same as the Linux path).

    Returns ``(artifact_bytes, file_extension)`` where the extension is
    auto-detected from the first bytes at offset 0 using a magic-byte lookup
    table (e.g. ``b'\\x89PNG'`` → ``".png"``).  Falls back to ``""`` when no
    known magic is matched.
    """
    # Determine required buffer size from sections and constants.
    required = 0
    for offset, data in sections:
        if data:
            required = max(required, offset + len(data))
    for entry in constants:
        if isinstance(entry, dict):
            off = entry.get("offset")
            sz = entry.get("size", 4)
        else:
            off = entry.offset
            sz = entry.size
        if off is not None:
            required = max(required, off + sz)

    required = max(required, 0x200)
    buf = bytearray(required)

    # Write section data.
    for offset, data in sections:
        if data:
            buf[offset : offset + len(data)] = data

    # Patch non-nested constants.
    for entry in constants:
        if isinstance(entry, dict):
            offset = entry.get("offset")
            value = entry.get("value")
            size = entry.get("size", 4)
            is_nested = entry.get("is_nested", False)
        else:
            offset = entry.offset
            value = entry.value
            size = entry.size
            is_nested = entry.is_nested

        if offset is None or is_nested:
            continue

        if isinstance(value, str):
            value = int(value, 16) if value.startswith(("0x", "0X")) else int(value)

        buf[offset : offset + size] = value.to_bytes(size, byteorder="little")

    buf = bytes(buf)
    if filesize_constraint:
        min_b, max_b = filesize_constraint
        if max_b is not None and len(buf) >= max_b:
            print(
                f"Warning: artifact size ({len(buf)} bytes) already meets or exceeds "
                f"the filesize < {max_b} constraint."
            )
        else:
            n = _compute_padding(len(buf), min_b, max_b)
            if debug:
                if n > 0:
                    print(f"[debug] filesize padding: {len(buf)} + {n} → {len(buf) + n} bytes")
                else:
                    print(f"[debug] filesize padding: {len(buf)} bytes already satisfies constraint")
            if n > 0:
                buf += os.urandom(n)

    # Detect file extension from magic bytes at offset 0.
    ext = ""
    for magic, candidate_ext in _MAGIC_TO_EXT:
        if buf[: len(magic)] == magic:
            ext = candidate_ext
            break

    return buf, ext
