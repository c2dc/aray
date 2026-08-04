# Examples

The repository includes focused YARA rules that exercise each supported construction path. These examples are intentionally small enough to inspect while covering the same layout mechanisms used by the evaluation pipeline.

## Start with a Linux Artifact

[`rule0.yar`](https://github.com/c2dc/aray/blob/main/data/rules/rule0.yar) contains one unconstrained ASCII string:

```yara
rule rule0
{
    strings:
        $a = "dummy1"

    condition:
        $a
}
```

Generate and verify a compiler-free ELF scanner artifact:

```bash
uv run aray data/rules/rule0.yar --scan-only
yara data/rules/rule0.yar build/linux/app
```

Remove `--scan-only` to produce a runnable ELF through the assembler and linker backend.

## Generate a Windows PE

[`rule6.yar`](https://github.com/c2dc/aray/blob/main/data/rules/rule6.yar) checks the MZ header, follows `e_lfanew` to the PE signature, and requires an ASCII marker. Those structural checks route construction to the PE backend.

```bash
uv run aray data/rules/rule6.yar --scan-only
yara data/rules/rule6.yar build/windows/app.exe
```

Runnable PE generation requires MinGW. Scan-only mode directly writes a minimal PE64 scanner artifact and does not invoke a compiler.

## Pin Data to an Exact Offset

[`rule12.yar`](https://github.com/c2dc/aray/blob/main/data/rules/rule12.yar) requires an ASCII string at file offset `0x600` in a runnable PE:

```yara
condition:
    uint16(0) == 0x5A4D and
    uint32(uint32(0x3C)) == 0x00004550 and
    $s at 0x600
```

Aray builds a low-alignment PE in two passes. The first build discovers where MinGW placed the dedicated section; the second pads that section so the marker lands at `0x600`. Placement is then verified byte for byte.

## Sample Catalog

| File | Target | Capability |
|---|---|---|
| `rule0.yar` | ELF | Single ASCII string |
| `rule1.yar` | ELF | Multiple required strings |
| `rule2.yar` | ELF | Constrained and unconstrained strings |
| `rule3.yar` | ELF | Hex byte pattern |
| `rule4.yar` | ELF | Hex pattern at an exact offset |
| `rule5.yar` | ELF | Multiple exact offsets |
| `rule6.yar` | PE | MZ and nested PE-signature checks |
| `rule7.yar` | PE | Nested PE-signature check |
| `rule8.yar` | PE | Numeric `N of` normalization |
| `rule9.yar` | PE | ASCII and YARA `wide` strings |
| `rule10.yar` | PE | Backslash escaping in C source |
| `rule11.yar` | ELF | Regex normalization and judge retries |
| `rule12.yar` | PE | Runnable PE string at an exact offset |

The complete source catalog is available under [`data/rules`](https://github.com/c2dc/aray/tree/main/data/rules).

## Inspect the Output

Aray preserves intermediate files so construction can be audited:

| Target | Artifact | Intermediates |
|---|---|---|
| Linux ELF | `build/linux/app` | `normalized_rule.yar`, `main.S`, `linker.ld` |
| Windows PE | `build/windows/app.exe` | `normalized_rule.yar`, `main.c` or `main.S` |
| Generic | `build/generic/output{ext}` | `normalized_rule.yar` |

Use `--debug` to print pipeline transitions, assigned sections, offsets, and filesize decisions:

```bash
uv run aray data/rules/rule2.yar --debug --scan-only
```
