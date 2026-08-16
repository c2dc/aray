"""Assembler source and linker script generation for the aray pipeline."""

import re

from aray.constants import (
    BANNER,
    DEFAULT_OFFSET_BASE,
    DEFAULT_OFFSET_STEP,
    ELF_BASE,
    PE_OFFSET_SECTION,
)
from aray.models import YaraStringEntry


def _resolve_yara_hex(value: str) -> str:
    """Resolve YARA hex pattern syntax to plain hex bytes.

    Handles:
    - ``??`` wildcards → ``00``
    - ``[N]`` exact jumps → N repetitions of ``00``
    - ``[N-M]`` ranged jumps → N (minimum) repetitions of ``00``
    """

    def _expand_jump(m: re.Match) -> str:
        lo = int(m.group(1))
        return " ".join(["00"] * lo) if lo > 0 else ""

    value = re.sub(r"\?\?", "00", value)
    value = re.sub(r"\[(\d+)(?:-\d+)?\]", _expand_jump, value)
    return " ".join(value.split())


def _format_hex_initializer(value: str) -> str:
    """Convert a hex string to a C byte array initializer.

    Accepts both space-separated ('DE AD BE EF') and concatenated ('DEADBEEF') formats.
    Also resolves YARA wildcard/jump syntax (``??``, ``[N-M]``) before conversion.
    Used by the PE/MinGW C-source path.
    """
    value = _resolve_yara_hex(value)
    if " " in value:
        bytes_list = value.split(" ")
    else:
        bytes_list = [value[i:i+2] for i in range(0, len(value), 2)]
    return "{" + ", ".join(f"0x{b}" for b in bytes_list) + "}"


def _escape_c_string(value: str) -> str:
    """Escape a string for use inside a C double-quoted string literal."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _format_ascii_initializer(value: str) -> str:
    """Wrap an ASCII string as a C string-literal array initializer.

    Used by the PE/MinGW C-source path.
    """
    return f'{{"{_escape_c_string(value)}"}}'


def _hex_str_to_bytes(value: str) -> bytes:
    """Convert a hex string to raw bytes.

    Accepts both space-separated ('DE AD BE EF') and concatenated ('DEADBEEF') formats.
    Also resolves YARA wildcard/jump syntax (``??``, ``[N-M]``) before conversion.
    """
    value = _resolve_yara_hex(value)
    if " " in value:
        return bytes(int(b, 16) for b in value.split())
    return bytes(int(value[i:i+2], 16) for i in range(0, len(value), 2))


def _ascii_str_to_bytes(value: str) -> bytes:
    """Encode a YARA text string to its source UTF-8 bytes."""
    return value.encode("utf-8")


def _wide_str_to_bytes(value: str) -> bytes:
    """Encode a string as UTF-16-LE (YARA wide modifier)."""
    return value.encode("utf-16-le")


def _int_to_le_bytes(value: int, size: int) -> bytes:
    """Convert an integer to little-endian bytes.

    Examples:
        _int_to_le_bytes(0x5A4D, 2)     -> b'\\x4D\\x5A'
        _int_to_le_bytes(0x00004550, 4) -> b'\\x50\\x45\\x00\\x00'
    """
    return value.to_bytes(size, byteorder="little")


def _constant_bytes(value: int, size: int, byte_order: str = "little") -> bytes:
    return value.to_bytes(size, byteorder=byte_order)


def _assign_offsets(
    strings: list[YaraStringEntry],
    default_base: int = DEFAULT_OFFSET_BASE,
    step: int = DEFAULT_OFFSET_STEP,
    pack: bool = False,
    reserved_sections: list[tuple[int, bytes]] | None = None,
) -> list[tuple[int, bytes]]:
    """Return (offset, raw-bytes) pairs for every string.

    Strings with an explicit ``at`` offset keep it.  Strings without one
    are assigned incrementing offsets starting at *default_base*.

    When *pack* is True, unconstrained strings are packed consecutively
    (each one starts immediately after the previous one, with a 1-byte gap)
    rather than at fixed *step* intervals.  Use this for generic artifacts
    where tight filesize constraints must be satisfied.
    """
    requests: list[
        tuple[int, int, bytes, int | None, int | None, int | None, int]
    ] = []
    order = 0
    for entry in strings:
        if entry.format == "hex":
            data = _hex_str_to_bytes(entry.value)
        elif entry.format == "widechar":
            data = _wide_str_to_bytes(entry.value)
        else:
            data = _ascii_str_to_bytes(entry.value)
        boundary = (2 if entry.format == "widechar" else 1) if entry.fullword else 0
        for occurrence in range(entry.match_count):
            exact = entry.offset if occurrence == 0 else None
            priority = 0 if exact is not None else (1 if entry.range_start is not None else 2)
            requests.append(
                (
                    priority,
                    order,
                    data,
                    exact,
                    entry.range_start,
                    entry.range_end,
                    boundary,
                )
            )
            order += 1

    sections: list[tuple[int, bytes]] = list(reserved_sections or [])
    ordered_sections: list[tuple[int, int, bytes]] = []
    next_default = default_base

    def available(offset: int, data: bytes, boundary: int) -> bool:
        start = max(0, offset - boundary)
        end = offset + len(data) + boundary
        return all(end <= placed or start >= placed + len(blob) for placed, blob in sections)

    for (
        _priority,
        request_order,
        data,
        exact,
        range_start,
        range_end,
        boundary,
    ) in sorted(requests):
        if exact is not None:
            if not available(exact, data, boundary):
                raise ValueError(f"string placement at offset 0x{exact:x} overlaps another string")
            offset = exact
        elif range_start is not None:
            offset = range_start
            while offset <= range_end and not available(offset, data, boundary):
                offset += 1
            if offset > range_end:
                raise ValueError(
                    f"no non-overlapping placement available in range "
                    f"0x{range_start:x}..0x{range_end:x}"
                )
        else:
            offset = next_default
            payload_size = len(data) + boundary
            increment = (payload_size + 1) if pack else step
            while not available(offset, data, boundary):
                offset += increment
            next_default = offset + increment
        payload = data + (b"\x00" * boundary)
        sections.append((offset, payload))
        ordered_sections.append((request_order, offset, payload))

    return [(offset, data) for _order, offset, data in sorted(ordered_sections)]


def _constants_to_sections(
    constants: list,
    intermediate_base: int = 0x100,
) -> list[tuple[int, bytes]]:
    """Convert constant entries to (offset, raw-bytes) pairs.

    Non-nested (e.g. uint16(0) == 0x5A4D): place LE bytes of value at offset.
    Nested (e.g. uint32(uint32(0x3C)) == 0x00004550):
      - Place 4-byte LE pointer to intermediate_base at offset.
      - Place LE value at intermediate_base.
      - Increment intermediate_base by 0x10 for the next nested entry.
    Entries with offset=None are skipped.
    """
    sections: list[tuple[int, bytes]] = []
    current_intermediate = intermediate_base

    for entry in constants:
        if isinstance(entry, dict):
            offset = entry.get("offset")
            value = entry.get("value")
            size = entry.get("size", 4)
            is_nested = entry.get("is_nested", False)
            byte_order = entry.get("byte_order", "little")
            relative_offset = entry.get("relative_offset", 0)
        else:
            offset = entry.offset
            value = entry.value
            size = entry.size
            is_nested = entry.is_nested
            byte_order = entry.byte_order
            relative_offset = entry.relative_offset

        if offset is None:
            continue

        if isinstance(value, str):
            value = int(value, 16) if value.startswith(("0x", "0X")) else int(value)

        if is_nested:
            sections.append((offset, _int_to_le_bytes(current_intermediate, 4)))
            sections.append(
                (
                    current_intermediate + relative_offset,
                    _constant_bytes(value, size, byte_order),
                )
            )
            current_intermediate += max(0x10, relative_offset + size + 1)
        else:
            sections.append((offset, _constant_bytes(value, size, byte_order)))

    return sections


def _generate_asm_source(sections: list[tuple[int, bytes]]) -> str:
    """Emit a GNU assembler (.S) file for the Linux ELF path.

    For each (offset, data) pair emits a named progbits section with .byte
    directives.  Then emits a _start routine that uses raw x86-64 Linux
    syscalls (write + exit) so the binary can be assembled with -nostdlib.
    """
    lines: list[str] = []

    for offset, data in sections:
        if not data:  # .byte with no args is a gas error
            continue
        tag = hex(offset)
        byte_list = ", ".join(f"0x{b:02X}" for b in data)
        lines.append(f'.section .sec_{tag},"aw",@progbits')
        lines.append(f'.byte {byte_list}')
        lines.append("")

    banner_bytes = (BANNER + "\n").encode("ascii")
    msg_len = len(banner_bytes)
    banner_hex = ", ".join(f"0x{b:02X}" for b in banner_bytes)

    lines.extend([
        '.section .text,"ax",@progbits',
        ".globl _start",
        "_start:",
        "    leaq msg(%rip), %rsi",
        f"    movq ${msg_len}, %rdx",
        "    movq $1, %rdi",
        "    movq $1, %rax",
        "    syscall",
        "    xorq %rdi, %rdi",
        "    movq $60, %rax",
        "    syscall",
        "msg:",
        f"    .byte {banner_hex}",
        "",
    ])
    return "\n".join(lines)


def _generate_linker_script(offsets: list[int]) -> str:
    """Build a linker script that places each section at its file offset.

    Sections are assigned VMA = ELF_BASE + file_offset.  A single PT_LOAD
    segment is declared with FILEHDR PHDRS so the ELF header itself is mapped
    at p_vaddr=ELF_BASE, p_offset=0.  This ensures the relationship

        file_offset = VMA - ELF_BASE

    holds for every section, regardless of toolchain version.  Without PHDRS,
    modern GNU ld may choose p_offset=0x1000 (one page), shifting all file
    offsets by 0x1000 and breaking YARA ``at`` offset constraints.

    All VMAs are >= ELF_BASE = 0x400000, well above vm.mmap_min_addr (0x10000),
    so execve succeeds.
    """
    max_offset = max(offsets, default=0)
    # Place .text one page above the highest data section
    text_vma = (ELF_BASE + max_offset + 0x2000) & ~0xFFF

    lines = [
        'PHDRS { load PT_LOAD FILEHDR PHDRS ; }',
        'SECTIONS',
        '{',
        f'    . = {hex(ELF_BASE)} + SIZEOF_HEADERS;',
    ]

    for offset in sorted(offsets):
        vma = ELF_BASE + offset
        tag = hex(offset)
        lines.append(f'    . = {hex(vma)};')
        lines.append(f'    .sec_{tag} : {{ *(.sec_{tag}) }} :load')

    lines.extend([
        f'    . = {hex(text_vma)};',
        '    .text : { *(.text*) } :load',
        '    .data : { *(.data*) } :load',
        '    .bss  : { *(.bss*) } :load',
        '}',
        '',
    ])
    return '\n'.join(lines)


# --- Windows PE "string at offset" (runnable) codegen -----------------------


def _entry_field(entry, key, default=None):
    """Read a field from a pydantic model or a plain dict entry."""
    if isinstance(entry, dict):
        return entry.get(key, default)
    return getattr(entry, key, default)


def _string_entry_bytes(entry) -> bytes:
    """Encode a YARA string entry to its raw bytes according to its format."""
    value = _entry_field(entry, "value", "")
    fmt = _entry_field(entry, "format", "ascii")
    if fmt == "hex":
        return _hex_str_to_bytes(value)
    if fmt == "widechar":
        return _wide_str_to_bytes(value)
    return _ascii_str_to_bytes(value)


def _c_byte_array(data: bytes) -> str:
    """Render raw bytes as a C array initializer, e.g. ``{0x41, 0x42}``."""
    return "{" + ", ".join(f"0x{b:02X}" for b in data) + "}"


def build_pe_offset_blob(
    offset_sections: list[tuple[int, bytes]], data_start: int
) -> bytes:
    """Build the contiguous ``.oray`` blob that places each string at its offset.

    In a low-alignment PE the section data is mapped flat, so a byte at file
    offset ``F`` sits at blob index ``F - data_start`` (where *data_start* is the
    file offset at which the blob's first byte lands, discovered by the probe
    pass).  Gaps are zero-filled.

    Raises ValueError when a requested offset falls below *data_start* (inside the
    PE headers / code, unreachable in a runnable PE) or when two strings overlap.
    """
    placements = sorted(offset_sections, key=lambda pair: pair[0])
    blob = bytearray()
    for offset, data in placements:
        if not data:
            continue
        if offset < data_start:
            raise ValueError(
                f"offset 0x{offset:x} is below the PE section floor "
                f"(0x{data_start:x}); not placeable in a runnable PE — use --scan-only"
            )
        pos = offset - data_start
        if pos < len(blob):
            raise ValueError(
                f"string at offset 0x{offset:x} overlaps a previously placed string"
            )
        blob.extend(b"\x00" * (pos - len(blob)))
        blob.extend(data)
    return bytes(blob)


_PE_KERNEL32_DECLS = (
    "__declspec(dllimport) void* __stdcall GetStdHandle(unsigned n);\n"
    "__declspec(dllimport) int   __stdcall WriteFile(void* h, const void* b, "
    "unsigned n, unsigned* w, void* o);\n"
    "__declspec(dllimport) void  __stdcall ExitProcess(unsigned c);\n"
)


def _generate_pe_free_globals(free_strings: list) -> list[str]:
    """Emit free (non-offset) strings as ordinary global arrays.

    YARA scans the whole file, so their exact placement is irrelevant.
    """
    lines: list[str] = []
    for i, entry in enumerate(free_strings):
        data = _string_entry_bytes(entry)
        terminator = b"\x00\x00" if _entry_field(entry, "format", "ascii") == "widechar" else b"\x00"
        lines.append(
            f"__attribute__((used)) unsigned char fstr_{i}[] = "
            f"{_c_byte_array(terminator + data + terminator)};"
        )
    return lines


def generate_pe_offset_c_source(oray_blob: bytes, free_strings: list) -> str:
    """Emit the C source for the runnable, offset-aware PE.

    The ``.oray`` section holds *oray_blob* verbatim; free strings become plain
    globals; ``_start`` prints the banner via kernel32 (the Windows equivalent of
    the ELF path's raw syscalls) and exits cleanly.  Built with
    ``-nostdlib -lkernel32 -e _start``.
    """
    banner = (BANNER + "\n").encode("ascii")
    lines: list[str] = [_PE_KERNEL32_DECLS, ""]
    lines.append(
        f'__attribute__((section("{PE_OFFSET_SECTION}"), used))\n'
        f"unsigned char _oray[] = {_c_byte_array(oray_blob)};"
    )
    lines.append("")
    lines.extend(_generate_pe_free_globals(free_strings))
    lines.append("")
    lines.append(f"static const unsigned char _banner[] = {_c_byte_array(banner)};")
    lines.extend(
        [
            "",
            "void _start(void) {",
            "    unsigned w;",
            "    WriteFile(GetStdHandle((unsigned)-11), _banner, sizeof(_banner), &w, 0);",
            "    ExitProcess(0);",
            "}",
            "",
        ]
    )
    return "\n".join(lines)
