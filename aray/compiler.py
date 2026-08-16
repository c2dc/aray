"""Binary compilation for the aray pipeline (Linux ELF and Windows PE)."""

import os
import re
import subprocess
from pathlib import Path

from aray.codegen import (
    _assign_offsets,
    _entry_field,
    _escape_c_string,
    _format_ascii_initializer,
    _format_hex_initializer,
    _generate_asm_source,
    _generate_linker_script,
    _string_entry_bytes,
    build_pe_offset_blob,
    generate_pe_offset_c_source,
)
from aray.constants import (
    BANNER,
    BUILD_DIR,
    BUILD_DIR_WIN,
    MINGW_GCC,
    MINGW_GCC_32,
    PE_ALIGN,
    PE_IMAGE_BASE,
    PE_IMAGE_BASE_32,
    PE_SENTINEL,
)
from aray.state import ArayGraphState


def _parse_filesize_constraint(rule_text: str) -> tuple[int | None, int | None]:
    """Parse filesize conditions from a YARA rule and return (min_bytes, max_bytes).

    Handles all YARA comparison operators and KB/MB/GB unit suffixes.
    Multiple constraints are composed with AND logic.
    Returns ``(None, None)`` when no filesize condition is present.
    """
    unit_map = {"KB": 1024, "MB": 1024 * 1024, "GB": 1024 * 1024 * 1024}
    min_bytes: int | None = None
    max_bytes: int | None = None

    for op, val_str, unit in re.findall(
        r"filesize\s*([<>]=?|==)\s*(\d+)\s*(KB|MB|GB)?", rule_text
    ):
        val = int(val_str)
        if unit:
            val *= unit_map[unit]

        if op == ">":
            new = val + 1
            min_bytes = max(min_bytes, new) if min_bytes is not None else new
        elif op == ">=":
            new = val
            min_bytes = max(min_bytes, new) if min_bytes is not None else new
        elif op == "<":
            new = val
            max_bytes = min(max_bytes, new) if max_bytes is not None else new
        elif op == "<=":
            new = val + 1
            max_bytes = min(max_bytes, new) if max_bytes is not None else new
        elif op == "==":
            new_min, new_max = val, val + 1
            min_bytes = max(min_bytes, new_min) if min_bytes is not None else new_min
            max_bytes = min(max_bytes, new_max) if max_bytes is not None else new_max

    return min_bytes, max_bytes


def _print_debug_sections(sections: list) -> None:
    """Print a summary of section placements to stdout."""
    non_empty = [(off, data) for off, data in sections if data]
    print(f"[debug] sections ({len(non_empty)}):")
    for offset, data in non_empty:
        preview = " ".join(f"{b:02x}" for b in data[:16])
        suffix = "..." if len(data) > 16 else ""
        print(f"  .sec_0x{offset:04x}  {len(data):5d} bytes  ({preview}{suffix})")
    if not non_empty:
        print("  (none)")


def _apply_filesize_padding(
    path: Path,
    min_bytes: int | None,
    max_bytes: int | None,
    debug: bool = False,
) -> None:
    """Append random bytes to *path* to satisfy the filesize constraint.

    Prints a warning and leaves the file unchanged when the binary is already
    larger than the maximum (can't shrink).
    """
    from aray.artifact_writer import _compute_padding

    current_size = path.stat().st_size
    if max_bytes is not None and current_size >= max_bytes:
        print(
            f"Warning: binary size ({current_size} bytes) already meets or exceeds "
            f"the filesize < {max_bytes} constraint. Consider --scan-only for a smaller binary."
        )
        return

    n = _compute_padding(current_size, min_bytes, max_bytes)
    if debug:
        if n > 0:
            print(
                f"[debug] filesize padding: {current_size} + {n} → {current_size + n} bytes"
            )
        else:
            print(f"[debug] filesize padding: {current_size} bytes already satisfies constraint")
    if n > 0:
        with open(path, "ab") as f:
            f.write(os.urandom(n))


def _is_pe_rule(constants: list, strings: list) -> bool:
    """Return True if any constant requires a Windows PE binary.

    A rule is a PE rule when it contains a doubly-nested uint32 check such as
    ``uint32(uint32(0x3C)) == 0x00004550`` (PE signature) or uint16(0) == 0x5A4D (MZ header).
    MinGW produces a real PE/EXE that naturally satisfies both the MZ header and PE signature
    conditions, so no post-compilation patching is needed.
    """
    for entry in constants:
        value = entry.get("value") if isinstance(entry, dict) else entry.value
        offset = entry.get("offset") if isinstance(entry, dict) else entry.offset
        size = entry.get("size", 4) if isinstance(entry, dict) else entry.size
        byte_order = (
            entry.get("byte_order", "little")
            if isinstance(entry, dict)
            else entry.byte_order
        )
        numeric = int(value, 16) if isinstance(value, str) else value
        expected = numeric.to_bytes(size, byteorder=byte_order)
        if expected == b"MZ" and offset == 0:
            return True
        if expected == b"PE\x00\x00" and offset == 0x3C:
            return True

    # if it has a wide string, it is a PE rule
    if any("wide" in (s.get("format", "ascii") if isinstance(s, dict) else s.format) for s in strings):
        return True
    return False


def _patch_constants(binary_path: Path, constants: list) -> None:
    """Patch constant bytes into a compiled binary at specific file offsets.

    Non-nested (e.g. uint16(0) == 0x5A4D): writes LE bytes of value directly
    at the given file offset, overwriting whatever is there.

    Nested (e.g. uint32(uint32(0x3C)) == 0x00004550): appends the LE value
    bytes at the end of the file (safe — avoids touching existing ELF
    structures), then writes the file offset of those appended bytes as a
    4-byte LE pointer at the given offset.

    Entries with offset=None are skipped.
    """
    if not constants:
        return

    with open(binary_path, "r+b") as f:
        f.seek(0, 2)
        file_end = f.tell()

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

            value_bytes = value.to_bytes(size, byteorder=byte_order)

            if is_nested:
                target = file_end
                f.seek(0, 2)
                if relative_offset:
                    f.write(b"\x00" * relative_offset)
                f.write(value_bytes)
                file_end += relative_offset + size
                f.seek(offset)
                f.write(target.to_bytes(4, byteorder="little"))
            else:
                f.seek(offset)
                f.write(value_bytes)


def _mingw_pe_offset_flags(image_base: int = PE_IMAGE_BASE) -> list[str]:
    """Linker flags for the low-alignment, runnable, offset-aware PE.

    ``FileAlignment == SectionAlignment`` (< 0x1000) makes the loader map the
    file flat, so ``file_offset == RVA`` — the PE analogue of the ELF linker
    trick.  ``-nostdlib -lkernel32 -e _start`` gives a freestanding entry that
    prints the banner via kernel32 (the Windows equivalent of raw syscalls).
    """
    return [
        "-nostdlib",
        "-lkernel32",
        "-e", "_start",
        f"-Wl,--image-base,{hex(image_base)}",
        f"-Wl,--file-alignment,{hex(PE_ALIGN)}",
        f"-Wl,--section-alignment,{hex(PE_ALIGN)}",
    ]


def _to_int(value) -> int:
    """Coerce a hex-string / decimal-string / int constant value to int."""
    if isinstance(value, str):
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    return value


def _verify_pe_offsets(
    binary_path: Path, offset_sections: list[tuple[int, bytes]], debug: bool = False
) -> None:
    """Assert every offset-constrained string landed at its exact file offset."""
    data = binary_path.read_bytes()
    for offset, blob in offset_sections:
        if not blob:
            continue
        if data[offset : offset + len(blob)] != blob:
            raise RuntimeError(
                f"PE offset placement failed: string not at file offset 0x{offset:x}"
            )
        if debug:
            print(f"[debug] verified string at file offset 0x{offset:x}")


def _patch_pe_constants(
    binary_path: Path,
    constants: list,
    data_start: int | None,
    debug: bool = False,
) -> None:
    """Patch non-structural integer constants into the PE at their file offsets.

    MZ (0x5A4D) and the PE signature (0x00004550) are already satisfied by the
    format, so they are skipped. Nested relative constants are resolved through
    the generated file's real pointer; direct constants below *data_start* are
    not patched because they fall inside the headers/code region.
    """
    data: bytes | None = None
    to_patch: list[tuple[int, int, int, str]] = []
    for entry in constants:
        offset = _entry_field(entry, "offset")
        if offset is None:
            continue
        value = _to_int(_entry_field(entry, "value"))
        size = _entry_field(entry, "size", 4)
        byte_order = _entry_field(entry, "byte_order", "little")
        nested = _entry_field(entry, "is_nested", False)
        relative_offset = _entry_field(entry, "relative_offset", 0)
        structural = (
            (not nested and offset == 0 and value == 0x5A4D)
            or (nested and offset == 0x3C and relative_offset == 0 and value == 0x00004550)
        )
        if structural:
            continue
        if nested:
            if data is None:
                data = binary_path.read_bytes()
            pointer_end = offset + 4
            if pointer_end > len(data):
                raise ValueError(f"nested PE pointer at 0x{offset:x} is outside the binary")
            target = int.from_bytes(data[offset:pointer_end], byteorder="little") + relative_offset
            if target + size > len(data):
                raise ValueError(f"nested PE target at 0x{target:x} is outside the binary")
            to_patch.append((target, value, size, byte_order))
            continue
        if data_start is None:
            continue
        if offset < data_start:
            print(
                f"Warning: constant at offset 0x{offset:x} is inside the PE "
                f"header/code region; skipped (use --scan-only to place it)."
            )
            continue
        to_patch.append((offset, value, size, byte_order))

    if not to_patch:
        return
    with open(binary_path, "r+b") as f:
        for offset, value, size, byte_order in to_patch:
            f.seek(offset)
            f.write(value.to_bytes(size, byteorder=byte_order))
            if debug:
                print(f"[debug] patched constant 0x{value:x} at file offset 0x{offset:x}")


def _requires_pe32(constants: list) -> bool:
    for entry in constants:
        if not _entry_field(entry, "is_nested", False):
            continue
        if _entry_field(entry, "relative_offset", 0) != 0x18:
            continue
        value = _to_int(_entry_field(entry, "value"))
        if _entry_field(entry, "size", 4) == 2 and value == 0x010B:
            return True
    return False


def _compile_pe_with_offsets(
    state: ArayGraphState,
    debug: bool = False,
    compiler: str = MINGW_GCC,
    image_base: int = PE_IMAGE_BASE,
) -> dict:
    """Compile a runnable PE that places offset-constrained strings exactly.

    Uses a low-alignment (flat-mapped) PE so ``file_offset == RVA``, and a
    two-pass build: pass 1 probes where the ``.oray`` section data lands (the
    MinGW linker prepends an unpredictable prefix), pass 2 rebuilds with the blob
    padded so each string falls on its requested file offset.
    """
    strings = state["rule_strings"]
    offset_strings = [s for s in strings if _entry_field(s, "offset") is not None]
    free_strings = [s for s in strings if _entry_field(s, "offset") is None]
    offset_sections = [
        (_entry_field(s, "offset"), _string_entry_bytes(s)) for s in offset_strings
    ]

    main_c = BUILD_DIR_WIN / "main.c"
    output_binary = BUILD_DIR_WIN / "app.exe"
    flags = _mingw_pe_offset_flags(image_base)

    # Pass 1 (probe): locate where the .oray section data starts.
    main_c.write_text(generate_pe_offset_c_source(PE_SENTINEL, free_strings))
    subprocess.run([compiler, "-o", str(output_binary), str(main_c), *flags], check=True)
    probe_data = output_binary.read_bytes()
    data_start = probe_data.find(PE_SENTINEL)
    if data_start < 0:
        raise RuntimeError("PE offset probe failed: .oray sentinel not found in binary")
    if debug:
        print(f"[debug] .oray section data starts at file offset 0x{data_start:x}")

    # Header constraints such as MZ at offset zero may already be satisfied by
    # the probe PE. Only section-placeable strings need to enter the .oray blob.
    placeable_sections: list[tuple[int, bytes]] = []
    for offset, data in offset_sections:
        if offset < data_start:
            if probe_data[offset:offset + len(data)] != data:
                raise ValueError(
                    f"offset 0x{offset:x} is inside the PE headers and is not "
                    "satisfied by the generated structure"
                )
        else:
            placeable_sections.append((offset, data))

    # Pass 2: build the padded blob so each placeable string lands exactly.
    blob = build_pe_offset_blob(placeable_sections, data_start)
    main_c.write_text(generate_pe_offset_c_source(blob, free_strings))
    subprocess.run([compiler, "-o", str(output_binary), str(main_c), *flags], check=True)

    _verify_pe_offsets(output_binary, offset_sections, debug=debug)
    _patch_pe_constants(output_binary, state.get("rule_constants", []), data_start, debug=debug)

    print(f"PE binary compiled (offset-aware): {output_binary}")
    return {}


def _compile_pe_binary(state: ArayGraphState, debug: bool = False) -> dict:
    """Compile a Windows PE executable using the MinGW cross-compiler.

    MinGW output is a standard PE/EXE with:
    - MZ header at offset 0  (satisfies ``uint16(0) == 0x5A4D``)
    - PE signature at the offset pointed to by uint32(0x3C)
      (satisfies ``uint32(uint32(0x3C)) == 0x00004550``)

    When any string carries an ``at`` offset constraint, dispatches to
    :func:`_compile_pe_with_offsets` (low-alignment, offset-aware).  Otherwise
    strings are embedded as plain global arrays; YARA scans the whole file, so
    no linker script or post-compilation patching is needed.
    """
    pe32 = _requires_pe32(state.get("rule_constants", []))
    compiler = MINGW_GCC_32 if pe32 else MINGW_GCC
    image_base = PE_IMAGE_BASE_32 if pe32 else PE_IMAGE_BASE
    _min_b, max_b = _parse_filesize_constraint(state.get("normalized_rule", ""))
    if max_b is not None or any(
        _entry_field(s, "offset") is not None for s in state["rule_strings"]
    ):
        BUILD_DIR_WIN.mkdir(parents=True, exist_ok=True)
        (BUILD_DIR_WIN / "normalized_rule.yar").write_text(state["normalized_rule"])
        return _compile_pe_with_offsets(
            state, debug=debug, compiler=compiler, image_base=image_base
        )

    BUILD_DIR_WIN.mkdir(parents=True, exist_ok=True)

    # write the normalized rule in build directory
    normalized_rule = state["normalized_rule"]
    normalized_rule_file = BUILD_DIR_WIN / "normalized_rule.yar"
    normalized_rule_file.write_text(normalized_rule)

    has_wide = any(
        "wide" in (e.get("format", "ascii") if isinstance(e, dict) else e.format)
        for e in state["rule_strings"]
    )

    lines: list[str] = ["#include <stdio.h>"]
    if has_wide:
        lines.append("#include <wchar.h>")
    lines.append("")

    if debug:
        entries = state["rule_strings"]
        print(f"[debug] strings ({len(entries)}):")
        for entry in entries:
            val = entry.get("value", "") if isinstance(entry, dict) else entry.value
            fmt = entry.get("format", "ascii") if isinstance(entry, dict) else entry.format
            print(f"  [{fmt:8s}]  {val!r}")

    for i, entry in enumerate(state["rule_strings"]):
        value = entry.get("value", "") if isinstance(entry, dict) else entry.value
        fmt = entry.get("format", "ascii") if isinstance(entry, dict) else entry.format
        if fmt == "widechar":
            lines.append(f'const wchar_t *ws_{i} = L"{_escape_c_string(value)}";')
        elif fmt == "hex":
            lines.append(f"unsigned char str_{i}[] = {_format_hex_initializer(value)};")
        else:
            lines.append(f"unsigned char str_{i}[] = {_format_ascii_initializer(value)};")

    lines.extend(["", f'int main(void) {{ puts("{BANNER}"); return 0; }}', ""])
    source_code = "\n".join(lines)

    main_c = BUILD_DIR_WIN / "main.c"
    output_binary = BUILD_DIR_WIN / "app.exe"
    main_c.write_text(source_code)

    subprocess.run(
        [compiler, "-o", str(output_binary), str(main_c)],
        check=True,
    )
    _patch_pe_constants(
        output_binary, state.get("rule_constants", []), data_start=None, debug=debug
    )

    print(f"PE binary compiled: {output_binary}")
    return {}


def _write_linux_artifact(
    state: ArayGraphState,
    constants: list,
    filesize_constraint: tuple[int | None, int | None] | None = None,
    debug: bool = False,
) -> dict:
    """Write a raw Linux binary artifact (scan-only path, no compiler needed).

    Also writes main.S and linker.ld to the build directory for inspection,
    mirroring the files produced by the full compiler path.
    """
    from aray.artifact_writer import write_linux_artifact

    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    (BUILD_DIR / "normalized_rule.yar").write_text(state["normalized_rule"])

    str_sections = _assign_offsets(state["rule_strings"], pack=True)
    if debug:
        _print_debug_sections(str_sections)

    (BUILD_DIR / "main.S").write_text(_generate_asm_source(str_sections))
    (BUILD_DIR / "linker.ld").write_text(
        _generate_linker_script([offset for offset, _ in str_sections])
    )

    artifact_bytes = write_linux_artifact(str_sections, constants, filesize_constraint=filesize_constraint, debug=debug)

    output = BUILD_DIR / "app"
    output.write_bytes(artifact_bytes)
    print(f"Scan-only artifact: {output}")
    return {}


def _write_pe_artifact(
    state: ArayGraphState,
    filesize_constraint: tuple[int | None, int | None] | None = None,
    debug: bool = False,
) -> dict:
    """Write a raw PE artifact (scan-only path, no compiler needed).

    Writes main.S documenting the exact byte placement — the same strategy
    used by the Linux scan-only path.  main.c is not written here because
    the scan-only PE artifact is a minimal raw PE64, not the binary that
    MinGW would produce by compiling main.c.
    """
    from aray.artifact_writer import write_pe_artifact

    BUILD_DIR_WIN.mkdir(parents=True, exist_ok=True)
    (BUILD_DIR_WIN / "normalized_rule.yar").write_text(state["normalized_rule"])

    str_sections = _assign_offsets(state["rule_strings"], pack=True)
    if debug:
        _print_debug_sections(str_sections)

    (BUILD_DIR_WIN / "main.S").write_text(_generate_asm_source(str_sections))

    artifact_bytes = write_pe_artifact(str_sections, [], filesize_constraint=filesize_constraint, debug=debug)

    output = BUILD_DIR_WIN / "app.exe"
    output.write_bytes(artifact_bytes)
    print(f"Scan-only PE artifact: {output}")
    return {}


def compile_binary(state: ArayGraphState, scan_only: bool = False, debug: bool = False) -> dict:
    """Compile (or write) a binary that matches the YARA rule.

    - PE rules (nested uint32 checks or wide strings): compiled with MinGW as a
      Windows EXE, or written as a minimal PE64 artifact when scan_only=True.
    - Linux rules: assembler source + custom linker script places each string
      section at the required file offset; compiled with ``gcc -static -nostdlib``
      and integer constants are patched post-compilation.  With scan_only=True
      a raw binary is written directly without invoking the compiler.
    """
    constants = state.get("rule_constants", [])
    strings = state.get("rule_strings", [])

    min_b, max_b = _parse_filesize_constraint(state.get("normalized_rule", ""))
    filesize_constraint: tuple[int | None, int | None] | None = (
        (min_b, max_b) if (min_b is not None or max_b is not None) else None
    )

    if debug and filesize_constraint:
        print(f"[debug] filesize constraint: min={min_b}  max={max_b}")

    if _is_pe_rule(constants, strings):
        if scan_only:
            return _write_pe_artifact(state, filesize_constraint=filesize_constraint, debug=debug)
        result = _compile_pe_binary(state, debug=debug)
        if filesize_constraint:
            _apply_filesize_padding(BUILD_DIR_WIN / "app.exe", min_b, max_b, debug=debug)
        return result

    # Linux path: filter out the ELF magic constant (not meaningful here).
    constants = [
        c for c in constants
        if (c.get("value") if isinstance(c, dict) else c.value) != "0x464C457F"
    ]

    if scan_only:
        return _write_linux_artifact(state, constants, filesize_constraint=filesize_constraint, debug=debug)

    # --- Linux ELF assembler path ---
    BUILD_DIR.mkdir(parents=True, exist_ok=True)

    normalized_rule = state["normalized_rule"]
    (BUILD_DIR / "normalized_rule.yar").write_text(normalized_rule)

    str_sections = _assign_offsets(state["rule_strings"], pack=True)
    if debug:
        _print_debug_sections(str_sections)

    source_code = _generate_asm_source(str_sections)
    linker_code = _generate_linker_script([offset for offset, _ in str_sections])

    linker_file = BUILD_DIR / "linker.ld"
    linker_file.write_text(linker_code)

    main_s = BUILD_DIR / "main.S"
    output_binary = BUILD_DIR / "app"
    main_s.write_text(source_code)

    subprocess.run(
        ["gcc", "-static", "-nostdlib", "-no-pie",
         "-o", str(output_binary), "-T", str(linker_file), str(main_s)],
        check=True,
    )

    _patch_constants(output_binary, constants)
    if filesize_constraint:
        _apply_filesize_padding(output_binary, min_b, max_b, debug=debug)

    print(f"Binary compiled: {output_binary}")
    return {}
