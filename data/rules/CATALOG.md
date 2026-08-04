# YARA Rule Catalog

| File | Rule name | Target | What it tests |
|------|-----------|--------|---------------|
| `rule0.yar` | `rule0` | Linux ELF | Baseline: single ASCII string, no offset constraint |
| `rule1.yar` | `rule1` | Linux ELF | Two ASCII strings, both must be present (`$a and $b`), no offset constraints |
| `rule2.yar` | `rule2` | Linux ELF | Mixed offset constraints: one ASCII string pinned at file offset `0x600` (`at`), one free |
| `rule3.yar` | `WildcardExample` | Linux ELF | Hex byte pattern (`{ E2 34 C8 FB }`), no offset constraint |
| `rule4.yar` | `rule2` | Linux ELF | Hex byte pattern pinned at file offset `0x600` combined with a free ASCII string |
| `rule5.yar` | `multi_offset` | Linux ELF | Two strings each with an explicit `at` offset (`$a at 0x600`, `$b at 0x800`) |
| `rule6.yar` | `maindll_mutex` | Windows PE | Full PE check: MZ header (`uint16(0) == 0x5A4D`), PE signature (`uint32(uint32(0x3C)) == 0x00004550`), and an ASCII string |
| `rule7.yar` | `maindll_mutex` | Windows PE | PE signature only (`uint32(uint32(0x3C)) == 0x00004550`) with an ASCII string — no explicit MZ header check |
| `rule8.yar` | `malware_apt15_exchange_tool` | Windows PE | Real-world APT15 rule: MZ header check (`uint16(0) == 0x5A4D`) with `15 of ($s*)` over 24 strings — exercises the normalize_rule node (expands count conditions) and multi-string PE matching |
| `rule9.yar` | `malware_apt15_exchange_tool` | Windows PE | APT15 rule variant: MZ header check (`uint16(0) == 0x5A4D`) with mixed ASCII and **wide** strings — first rule to exercise the `widechar` format path, generating `#include <wchar.h>` and `const wchar_t` declarations in the PE source |
| `rule10.yar` | `Mal_PotPlayer_DLL` | Windows PE | CVE-2015-2545: MZ header check (`uint16(0) == 0x5A4D`), fullword ASCII strings with backslash path (`\\update.dat`) — exercises C string backslash escaping in the PE codegen path |
| `rule11.yar` | `CVE_2012_0158_KeyBoy` | Linux ELF | CVE-2012-0158: `all of them` condition with a regex string `$c` — exercises the `normalize_rule` judge-retry loop (regex replaced, `all of them` preserved) |
| `rule12.yar` | `pe_string_at_offset` | Windows PE | MZ header + PE signature **and** an ASCII string pinned at file offset `0x600` (`$s at 0x600`) — first rule to exercise **offset-constrained strings on the runnable PE path**: a low-alignment PE compiled by MinGW that both satisfies `at` and runs under Wine |

## Notes

- Rules `rule0`–`rule5` produce Linux ELF binaries compiled with `gcc -static -nostdlib`.
- Rules `rule6`–`rule10` and `rule12` produce Windows PE binaries compiled with `x86_64-w64-mingw32-gcc`. The PE path is triggered by the presence of `uint16(0)==0x5A4D` (MZ) or `uint32(uint32(0x3C))==0x00004550` (PE sig) constants, or by any string with the `widechar` format (YARA `wide` modifier); see the [Windows PE backend](../../docs/architecture.md#windows-pe-backend) documentation.
- `rule12.yar` adds an `at` offset constraint to a PE rule. When a PE rule pins a string at a file offset, Aray builds a **low-alignment PE** (`FileAlignment == SectionAlignment`, so the loader maps the file flat and `file_offset == RVA` — the PE analogue of the ELF linker-script trick). The string is placed in a dedicated `.oray` section via a two-pass build (pass 1 probes where the section lands; pass 2 pads the section so the string falls on the exact offset). The binary still runs — its `_start` prints the banner via `kernel32` (`GetStdHandle`/`WriteFile`/`ExitProcess`), verified under Wine. Offsets below the section floor (inside the PE headers/code, ~`0x400`) are not placeable in a runnable PE; use `--scan-only` for those.
- `rule6.yar` and `rule7.yar` differ in that `rule6` explicitly asserts the MZ header in addition to the PE signature, while `rule7` relies on the PE signature alone. A MinGW-compiled binary satisfies both naturally.
- `rule8.yar` uses a `15 of ($s*)` count condition; the `normalize_rule` node expands this into an explicit string list before extraction.
- `rule10.yar` contains backslash-escaped strings (e.g. `"\\update.dat"`); the codegen layer escapes them correctly for C string literals via `_escape_c_string()`.
- `rule11.yar` contains a regex string (`$c`) and uses `all of them`; the `normalize_rule` node replaces the regex with a literal while preserving the variable name and the `all of them` condition.
