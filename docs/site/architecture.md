# Architecture

Aray is a deterministic-first rule interpreter connected to binary-construction backends, with LLM assistance for normalization and unsupported extraction syntax. Conventional code owns constructibility checks, typed extraction for the supported subset, byte encoding, layout, compilation, patching, and artifact writing.

<p align="center" markdown>
![Aray architecture showing configuration, role-specific LLMs, LangGraph orchestration, artifact backends, and external dependencies](diagrams/aray-architecture.svg){ width="900" }
</p>

## Pipeline Boundary

```text
YARA rule
   |
   v
deterministic read + normalization check
   |
   +-- supported subset --------------------------+
   |                                               |
   +-- complex rule -> normalize -> judge --------+  LLM-assisted
                                                   |
                                                   v
                                   constructibility preflight  deterministic
                                                   |
                                                   v
                                  extract strings + constants  deterministic first,
                                                               LLM fallback
                                                   |
                                                   v
                                typed Pydantic representation
                                                   |
                                                   v
                                    validate + route format
                                                   |
                          +------------------------+------------------------+
                          |                        |                        |
                          v                        v                        v
                     ELF backend              PE backend             generic writer
                          |                        |                        |
                          +------------------------+------------------------+
                                                   |
                                                   v
                                              artifact
                                                   |
                                                   v
                                      optional external YARA scan
```

LangGraph provides orchestration, state transitions, and bounded retries. It does not generate source code or binary bytes.

## Pipeline Stages

### Read Rule

`read_yara_rule` loads the requested file. For a ruleset, it lexically selects the first non-private rule and inlines only its reachable rule dependencies into one standalone rule; unrelated and subsequent rules are ignored. Anonymous strings are assigned stable `$__aray_anon_N` names before any LLM call.

### Decide Whether to Normalize

`check_normalization_needed` is a deterministic lexical check. It sends a rule through normalization when it finds:

- regex strings;
- hex wildcards (`??`, `A?`, or `?B`);
- hex jumps (`[N]` or `[N-M]`);
- `or` conditions;
- numeric count expressions such as `5 of ($a*)`.

Otherwise the original text becomes `normalized_rule` unchanged. This skips normalization and judging; supported extraction also proceeds without a model.

### Normalize and Judge

`normalize_rule` asks the normalization model to produce a simpler rule in the supported subset. `judge_rule` compares that result with the original.

Normalization produces a constructible subset, not a bidirectionally equivalent rule: every normalized match must satisfy the original, but selecting one complete `or` branch may intentionally match fewer files. Branches are grouped using YARA precedence (`not`, then `and`, then `or`) before simplification, so conditions are never carried across alternatives.

When several branches are valid, the normalizer prioritizes construction feasibility and cost. It avoids tight maximum file sizes that compiled artifacts cannot satisfy, large minimum or exact sizes that require padding, high exact offsets, format-forcing PE or wide-string requirements, and then excess strings, constants, and literal bytes. Before the LLM judge runs, YARA syntax, retained modifiers, count expansions, and regex/hex witnesses are checked deterministically. Safe repairs restore canonical anonymous names, exact modifiers, unambiguous count expansions, and retained values that do not require a model decision. The judge handles only cases not fully proven by these checks.

Retained string values are canonicalized by their original type:

| Original declaration | Deterministic treatment |
|---|---|
| Fixed literal | restore the exact original source value |
| Fixed hex sequence | restore the exact original byte pattern |
| Linear hex with `??`, `A?`, `?B`, `[N]`, or `[N-M]` | choose zero wildcard nibbles and expand the minimum jump exactly |
| Regex | keep the proposed fixed witness and test it with `yara-python` |
| Complex hex expression | keep the proposed witness and test it with `yara-python` |

This division keeps branch selection probabilistic while removing character counting and fixed-value transcription from the model. For example, `[29]` always expands to exactly 29 bytes, and a retained 252-character literal is restored byte for byte rather than regenerated. Unsupported complex hex expressions are never guessed by the canonicalizer.

- `passed`: continue to extraction.
- `uncertain`: currently continue to extraction.
- `failed`: retry normalization with feedback.
- Three failed attempts: run `fail_normalization` and terminate without constructing an artifact.

The batch normalizer retries failed verdicts and transient invocation errors up to three times. It writes output only after a passed verdict and removes stale output after failures or errors.

### Assess Constructibility

`assess_constructibility` runs after normalization/judging and before extraction.
It deterministically stops rules that require unsupported YARA `pe.*` or
`math.*` module semantics, infeasible prescribed whole-file cryptographic hash
preimages, unsatisfiable integer values, or a PE32 compiler that is not installed.
These terminal classifications reach `fail_construction` without invoking the
extraction fallback or an artifact backend.

### Extract Typed Data

`extract_strings` and `extract_constants` first parse the normalized rule with
`aray/yara_extraction.py`. The deterministic subset handles:

- condition-aware required and negated strings, `all`/`any` sets, and simple match counts;
- exact and ranged placements;
- ASCII/UTF-8 literals, fixed hex, `wide`, `ascii wide`, `fullword`, and `nocase` fields;
- `int16`, `uint16`, `uint32`, `uint16be`, and `uint32be` reads;
- nested PE-relative reads such as `uint16(uint32(0x3c)+0x18)`;
- `==`, `!=`, `<`, `<=`, `>`, and `>=` integer comparisons by selecting one concrete satisfying witness.

The resulting entries include values, formats, placement/count fields,
modifiers, integer width and byte order, and nested relative offsets. Pydantic
models validate this typed representation.

Only syntax outside that deterministic subset falls back to extraction model
calls. Structured output is attempted first; if a model or gateway cannot use
tool calls, `aray.llm._invoke_llm` injects the JSON schema into the prompt,
parses the response, and validates the same Pydantic model.

Schema validation constrains fallback response shape, not meaning. A fallback
model can still omit a pattern or assign a wrong offset; it cannot override a
successful deterministic extraction.

### Route the Artifact

`route_file_type` is pure computation. It generally chooses:

- `pe` for MZ/PE structural checks and ordinary wide-string rules;
- `generic` for fixed non-PE magic anchored at offset zero and low exact/ranged placements that require a flat scanner blob;
- `elf` for everything else.

Fixed non-PE headers and low ranged witnesses take precedence over PE hints,
including MZ-like evidence or a wide string, when generic construction is the
feasible placement path. Critical offset-zero claims are cross-checked against
the YARA text before they influence routing. This prevents a hallucinated
extraction offset from turning an ELF rule into a generic blob.

## Internal Representation

The typed pipeline boundary uses the Pydantic types in `aray/models.py`:

- `NormalizedYaraRule`;
- `YaraStringEntry` and `YaraStrings`;
- `YaraConstantEntry` and `YaraConstants`;
- `JudgeVerdict`.

Downstream code accepts these typed entries and converts them to byte ranges. The model never emits C, assembly, linker scripts, PE headers, or complete binary data.

## Byte Encoding

`aray/codegen.py` converts each string entry into bytes:

- ASCII and UTF-8 strings become their byte representation;
- hex patterns become parsed byte sequences;
- `wide` strings become UTF-16LE-compatible data;
- `ascii wide` declarations permit either encoding, so construction can use the cheaper ASCII witness;
- `fullword` witnesses reserve zero-valued boundaries so adjacent data cannot extend the word;
- unconstrained strings receive deterministic default offsets;
- exact and ranged strings retain or select a valid placement.

Constants are encoded using the extracted width and byte order:

| YARA condition | Encoding |
|---|---|
| `uint16(N) == V` | two little-endian bytes of `V` at file offset `N` |
| `uint32(N) == V` | four little-endian bytes of `V` at file offset `N` |
| `uint16be(N) == V` / `uint32be(N) == V` | big-endian bytes at file offset `N` |
| `uint32(uint32(0x3C)) == 0x00004550` | use the native PE `e_lfanew` pointer and signature |
| `uint16(uint32(0x3C)+0x18) == 0x010B` | select PE32 and patch/read relative to the actual `e_lfanew` target |

## Linux ELF Backend

### Runnable Mode

The runnable path avoids C and libc:

1. `_assign_offsets` resolves a file offset for every string.
2. `_generate_asm_source` emits one `.section .sec_0xNNN,"aw",@progbits` block per byte range.
3. `_generate_linker_script` places each section at `ELF_BASE + file_offset`.
4. The linker script declares `PHDRS { load PT_LOAD FILEHDR PHDRS; }`, making the first load segment start at file offset zero.
5. Therefore, for these sections, `file_offset = VMA - ELF_BASE`.
6. GCC links with `-static -nostdlib -no-pie`; `_start` uses raw x86-64 Linux syscalls to print a banner and exit.
7. Supported integer constants are patched at their exact file offsets after linking.

The output is `build/linux/app`. Generated `main.S` and `linker.ld` make the placement contract inspectable.

### Scan-Only Mode

`write_linux_artifact` creates a minimal ELF64 header and a zeroed buffer, then writes strings and supported constants directly at their offsets. The header has no program or section headers, so the result is intended for scanners rather than execution.

No compiler, assembler, linker, or libc is involved.

## Windows PE Backend

### Ordinary Runnable PE

Rules without string offset constraints use MinGW. Strings become C globals and wide strings become `wchar_t` globals. The resulting executable naturally contains:

- `MZ` at file offset zero;
- `e_lfanew` at `0x3C`;
- `PE\0\0` at the location referenced by `e_lfanew`.

This satisfies standard PE YARA checks without modifying structural header bytes.
Supported nested relative constants are resolved through the generated file's
actual `e_lfanew` value and patched at that computed target. A predicate such as
`uint16(uint32(0x3c)+0x18) == 0x10b` selects PE32 and therefore requires
`i686-w64-mingw32-gcc`; ordinary PE32+ uses the x86-64 compiler.

### Offset-Aware Runnable PE

A normal linker can move globals, so `$s at 0xNNN` requires a stronger layout contract. Aray builds a low-alignment PE using:

```text
-nostdlib -lkernel32 -e _start
--file-alignment=0x10
--section-alignment=0x10
```

Equal file and section alignment causes a flat mapping where file offsets correspond to RVAs. Construction uses two passes:

1. Compile a `.oray` section containing an eight-byte sentinel.
2. Find the sentinel's file offset to discover where MinGW placed section data.
3. Build a blob padded relative to that discovered start.
4. Recompile with the final blob.
5. Read the executable and verify every constrained byte range.

The freestanding `_start` uses `GetStdHandle`, `WriteFile`, and `ExitProcess`, allowing the result to run under Wine without a C runtime.

Runnable PE data cannot generally occupy offsets inside headers or code, typically below approximately `0x400`. Non-structural constants in that region are skipped with a warning. Use scan-only mode when scanner satisfaction matters more than execution.

### Scan-Only PE

`write_pe_artifact` directly writes:

- a DOS header with `MZ` and `e_lfanew`;
- a PE signature;
- a PE64 COFF/optional header;
- strings and supported constants at their assigned offsets.

The artifact is scanner-oriented, not a runnable replacement for MinGW output.
Its generated structure satisfies MZ and nested PE-signature checks, while the
direct writer places the other supported extracted constants.

## Generic Writer

Non-PE magic at offset zero routes to `write_generic`. It writes a plain buffer without adding executable headers:

- rule-owned magic remains at offset zero;
- other strings are packed from offset `0x10` unless constrained;
- supported constants are patched using their declared byte order;
- an extension is selected from known magic bytes.

Known extensions include `.php`, `.asp`, `.zip`, `.png`, `.jpg`, `.gif`, and `.doc`. Unknown magic produces an extensionless `output` file.

## Filesize Constraints

The backend parses `filesize` comparisons using `>`, `>=`, `<`, `<=`, and `==`, with optional `KB`, `MB`, or `GB` units. Multiple comparisons are combined into minimum and maximum bounds.

When an artifact is too small, Aray computes a valid target size and appends random bytes. If it already meets or exceeds an exclusive upper bound, it cannot be shrunk and a warning is printed.

The amount of required padding is deterministic for the current size and bounds; padding contents use `os.urandom`. Consequently, a padded artifact is not byte-for-byte reproducible.

## Construction Checks and External Verification

Internal checks include:

- Pydantic validation of LLM response structure;
- deterministic constructibility classification before extraction;
- deterministic extraction for supported normalized syntax;
- deterministic cross-validation of format-routing evidence;
- byte-for-byte verification of offset-aware PE strings;
- subprocess failure propagation through `check=True`;
- bounds and collision checks in layout helpers.

The normal `aray` CLI does not run YARA after construction. This preserves separation between construction and acceptance testing. Use the YARA CLI manually or `aray-eval`, which scans the generated artifact against the Aray-accepted normalized rule by default. `--validate-original` switches to the strictly associated upstream source rule. In the published staged evaluation, an identifier-restricted match against the associated upstream source rule is the operational end-to-end success criterion; it validates each concrete artifact but is not a universal proof of implication between predicates.

## Source Map

| Module | Responsibility |
|---|---|
| `aray/graph.py` | orchestration and retry edges |
| `aray/nodes.py` | rule loading, model-assisted stages, routing, generic dispatch |
| `aray/models.py` | typed model boundary |
| `aray/llm.py` | structured invocation and JSON fallback |
| `aray/capabilities.py` | deterministic constructibility preflight |
| `aray/yara_extraction.py` | deterministic string and integer extraction |
| `aray/codegen.py` | encoding, offsets, assembly, linker scripts, PE source |
| `aray/compiler.py` | ELF/PE toolchain backends, patching, placement checks |
| `aray/artifact_writer.py` | direct ELF64, PE64, and generic writers |
| `aray/evaluator.py` | batch construction and independent YARA verification |

## Known Limitations

- Only a subset of YARA is represented by the extraction schema and backends.
- Normalization may alter semantics, and judge acceptance is model-dependent.
- An `uncertain` pipeline judge verdict proceeds to extraction.
- Supported nested PE-relative integer expressions indicate PE structure; broader computed expressions remain limited.
- Full-compile output can vary with GCC, Binutils, or MinGW versions.
- Random filesize padding prevents byte-for-byte reproducibility.
- Rulesets process only the first non-private rule and its reachable dependency closure. Exactly one rule is sent to the LLM and written as output.
