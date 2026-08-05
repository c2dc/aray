# AGENTS.md

This file provides guidance to coding agents (Claude Code, opencode, etc.) when working with code in this repository.

## Project Overview

Aray generates non-malicious executable files that match YARA rules for security testing. It uses a LangGraph pipeline (LLM defaults to GPT-4.1) to extract string patterns and integer constants from YARA rules and embed them into benign executables. Supports ASCII strings, hex byte patterns, wide strings (YARA `wide` modifier), multiple `at` offset constraints, and condition constants (`uint16`/`uint32` checks including nested pointer expressions like `uint32(uint32(0x3C))`). Automatically detects Windows PE rules and compiles with MinGW (`x86_64-w64-mingw32-gcc`); rules with non-PE magic bytes anchored at offset 0 (PHP/ASP/ZIP/images) produce a generic byte-blob via `write_generic`; all other rules produce Linux ELF binaries.

## Commands

```bash
# Install dependencies
uv sync

# Linux ELF rule → build/linux/app
python main.py data/rules/rule0.yar

# Windows PE rule (MinGW auto-detected) → build/windows/app.exe
python main.py data/rules/rule6.yar

# Visualise the LangGraph pipeline
python main.py data/rules/rule0.yar --graph

# Use a custom model or API gateway
python main.py data/rules/rule0.yar --model gpt-4o
python main.py data/rules/rule0.yar --base-url http://localhost:4000 --model llama3

# Per-node model override (normalize vs extract roles)
python main.py data/rules/rule0.yar --normalize-model gpt-4.1 --extract-model gpt-4.1-mini
NORMALIZE_MODEL=gpt-4.1 EXTRACT_MODEL=gpt-4.1-mini python main.py data/rules/rule0.yar

# Disable streaming (for models/gateways that don't support it); structured
# output is attempted first and auto-falls back to prompt-based JSON when the
# model/gateway does not support tool calls — no flag needed.
python main.py data/rules/rule0.yar --no-stream --model llama3

# Write raw binary artifact without invoking the compiler
python main.py data/rules/rule0.yar --scan-only   # Linux → minimal ELF64
python main.py data/rules/rule6.yar --scan-only   # PE rule → minimal PE64

# Normalize files or directories and assess quality with an LLM judge
python normalize.py evaluation/rules/cve_rules/example.yar
python normalize.py evaluation/rules/cve_rules --output /tmp/norm_report.json
python normalize.py --config .normalizer          # uses [normalizer] section
uv run aray-normalize evaluation/rules/cve_rules  # via installed script

# Run tests — unit + integration (no LLM calls, ~4 s). The real-LLM e2e tests
# are skipped automatically when OPENAI_API_KEY is not set.
uv run pytest tests/ -v

# Run e2e tests with real LLM calls (~30 s, requires OPENAI_API_KEY)
uv run pytest -m llm -v
```

## Architecture

- `main.py` — 4-line backwards-compatible shim that delegates to `aray.cli.main()`.
- `aray/` — Python package containing all pipeline logic:
  - `cli.py` — `parse_args()` and `main()` (CLI entry point, `load_dotenv()` called here). Accepts a rule path and optional `--graph`, `--model`, `--base-url`, `--normalize-model`, `--extract-model`, `--normalize-base-url`, `--extract-base-url`, `--normalize-api-key`, `--extract-api-key`, `--no-stream`, `--normalize-no-stream`, `--extract-no-stream`, `--scan-only`, and `--debug` flags. Resolves per-role LLM config via a precedence chain: role CLI flag > role env var (`NORMALIZE_MODEL` / `EXTRACT_MODEL`, `NORMALIZE_BASE_URL` / `EXTRACT_BASE_URL`, `NORMALIZE_API_KEY` / `EXTRACT_API_KEY`) > shared `--model` / `OPENAI_MODEL`, `--base-url` / `OPENAI_BASE_URL`, `OPENAI_API_KEY` > default (`gpt-4.1`). Builds a `PipelineConfig` and passes it to `build_graph(config=...)`.
  - `config.py` — `LLMNodeConfig` and `PipelineConfig` dataclasses (`LLMNodeConfig`: `model`, `base_url`, `api_key`, `streaming`; `PipelineConfig` adds `use_structured_output`, `scan_only`, `streaming`, `debug`).
  - `constants.py` — `BUILD_DIR`, `BUILD_DIR_WIN`, `BUILD_DIR_GENERIC`, `ELF_BASE`, `BANNER`, `MINGW_GCC`, `DUMMY_API_KEY`, `PE_IMAGE_BASE`, `PE_ALIGN`, `PE_OFFSET_SECTION`, `PE_SENTINEL`, `DEFAULT_OFFSET_*`.
  - `models.py` — Pydantic models: `NormalizedYaraRule`, `YaraStringEntry`, `YaraStrings`, `YaraConstantEntry`, `YaraConstants`, `JudgeVerdict`.
  - `state.py` — `ArayGraphState` TypedDict.
  - `llm.py` — `_invoke_llm()` helper.
  - `codegen.py` — GNU assembler source and linker script generators, plus the PE offset-aware C-source generator (`generate_pe_offset_c_source()`, `build_pe_offset_blob()`).
  - `compiler.py` — `_is_pe_rule()`, `_patch_constants()`, `_compile_pe_binary()` (dispatches to `_compile_pe_with_offsets()` when a string carries an `at` offset), `compile_binary()` (accepts `scan_only` kwarg).
  - `artifact_writer.py` — Raw binary writers for `--scan-only` mode: `write_linux_artifact()` (minimal ELF64, strings at exact file offsets, non-nested constants patched) and `write_pe_artifact()` (minimal PE64, `NumberOfSections=0`, strings at exact file offsets, non-nested constants patched).
  - `nodes.py` — `read_yara_rule`, `check_normalization_needed`, `normalize_rule`, `judge_rule`, `fail_normalization`, `extract_strings`, `extract_constants`, `route_file_type`, `write_generic`, plus helpers `_requires_normalization` and `_judge_normalization`.
  - `graph.py` — `build_graph()` and `save_graph_png()`. `build_graph()` accepts a `PipelineConfig` (or `None` for defaults) and constructs separate `ChatOpenAI` instances for the `normalize` and `extract` roles; node functions receive `llm` and `use_structured` via `functools.partial`.
  - `normalizer.py` — Batch normalization evaluator: accepts YARA files or recursively walks directories, calls only the `normalize_rule` node per rule (no extraction/compilation), writes each normalized rule to the output root (mirroring directory inputs), uses an LLM-as-judge to assess semantic correctness, and writes a JSON report. Used by `normalize.py` and the `aray-normalize` script.

The pipeline uses a LangGraph StateGraph with the following flow:

```
START → read_yara → check_normalization_needed ─ needs=True  → normalize_rule → judge_rule ──(passed/uncertain/3×)──► extract_strings → extract_constants → route_file_type ──► compile          → END
                                                │                    ↑           ├──(failed, < 3×)────────────────────┘                                         └──► write_generic → END
                                                │                    │           └──(failed, 3×) → fail_normalization → END
                                                └ needs=False ────────┘
```

**Pipeline nodes:**
- `read_yara`: Reads the YARA rule from the path provided via CLI. For rulesets, extracts the first non-private rule block.
- `check_normalization_needed`: Deterministic (zero-LLM) regex check for features that need the LLM loop — regex strings, hex wildcards (`??`) / jumps (`[N]`/`[N-M]`), `or` conditions, and numeric count expressions (`N of …`). Sets `needs_normalization`; when `False` passes the raw rule straight through as `normalized_rule` and skips the LLM loop.
- `normalize_rule`: Uses an LLM (default: GPT-4.1) to generate a minimal constructible subset of the original. It removes regex conditions, replaces complex count expressions (e.g. `5 of ($a*)`) with explicit string lists, and selects complete `or` branches using YARA precedence plus a feasibility/cost ranking (filesize, padding, offsets, format constraints, and required evidence). Downstream nodes operate on `normalized_rule`.
- `judge_rule`: Deterministically validates retained regex replacements with `yara-python`, then uses the LLM to verify the normalized rule is a valid, correct subset and did not select a clearly more expensive branch over a cheaper constructible alternative. A failed regex witness or judge verdict retries `normalize_rule` (up to 3 attempts) or routes to `fail_normalization` when exhausted.
- `fail_normalization`: Terminal node reached when all normalization attempts fail; writes `normalization_error` and exits to END without extraction/compilation.
- `extract_strings`: Uses an LLM to extract strings (ASCII/hex/widechar) and their `at` offset constraints; sets `format="widechar"` for strings with the YARA `wide` modifier
- `extract_constants`: Uses an LLM to extract `uint16`/`uint32` integer comparisons from the condition section, recording each constant's `value`, `offset`, `size` (2 or 4 bytes), and `is_nested` flag
- `route_file_type`: Pure-computation node that inspects extracted constants/strings (cross-validated against the rule text) to set `file_type` to `"pe"`, `"elf"`, or `"generic"`, dispatching to `compile` or `write_generic`
- `write_generic`: Writes a plain byte-blob artifact (no ELF/PE structure) with the rule's own magic bytes at offset 0 and other strings packed tightly after `0x10`; extension auto-detected from the magic bytes
- `compile`: Branches on rule type:
  - **PE rules** (explicit `uint16(0)==0x5A4D` or `uint32(uint32(0x3C))==0x00004550` constants, or any `widechar`-format string): compiles with `x86_64-w64-mingw32-gcc`. The MinGW PE format naturally satisfies `uint16(0)==0x5A4D` (MZ header) and `uint32(uint32(0x3C))==0x00004550` (PE signature). Wide strings are emitted as `const wchar_t *ws_N = L"value";` with `#include <wchar.h>`; ASCII strings are embedded as plain global arrays. Output: `build/windows/app.exe`. With `--scan-only`, delegates to `write_pe_artifact()` instead: writes `main.S` (same `.section .sec_0xNNN` + `.byte` format as the Linux path) and a minimal PE64 with strings at their exact file offsets.
    - **PE rules with `at` offset constraints** (`_compile_pe_with_offsets()`): a plain MinGW link cannot place strings at a fixed file offset, so Aray builds a **low-alignment PE** — `-nostdlib -lkernel32 -e _start -Wl,--file-alignment,0x10 -Wl,--section-alignment,0x10` (constants `PE_ALIGN`, `PE_IMAGE_BASE`). With `FileAlignment == SectionAlignment` the loader maps the file flat, so `file_offset == RVA` (the PE analogue of the ELF `PHDRS` trick). Offset-constrained strings go into a `.oray` section built by a **two-pass** compile: pass 1 uses an 8-byte sentinel (`PE_SENTINEL`) to find where the section data lands; pass 2 pads the section so each string falls on its exact offset (`build_pe_offset_blob()`), then placement is verified byte-for-byte (`_verify_pe_offsets()`). The `_start` entry prints the banner via `kernel32` (`GetStdHandle`/`WriteFile`/`ExitProcess`) and exits cleanly, so the binary runs under Wine. Non-structural integer constants (not MZ/PE-sig, not nested) above the section floor are patched afterward (`_patch_pe_constants()`); offsets below the floor (~`0x400`, inside headers/code) are not placeable and warn to use `--scan-only`. Free strings (no `at`) remain ordinary globals.
  - **Linux rules**: generates a GNU assembler (`.S`) file with one `.section .sec_0xNNN,"aw",@progbits` + `.byte` block per string, and a `_start` routine using raw x86-64 Linux syscalls (write + exit, no libc). Compiles with `gcc -static -nostdlib -no-pie -T linker.ld`. The linker script uses `PHDRS { load PT_LOAD FILEHDR PHDRS; }` and `. = ELF_BASE + SIZEOF_HEADERS` to guarantee `p_offset=0` for the first PT_LOAD segment, so file offsets equal `VMA − ELF_BASE` (ELF_BASE = 0x400000). All VMAs remain above `vm.mmap_min_addr`. Non-nested integer constants are patched directly into the ELF at their file offsets after compilation. Output: `build/linux/app`. With `--scan-only`, delegates to `write_linux_artifact()` instead.

**Linux constant patching (post-compilation, non-nested only):**
- `uint16(N) == V` / `uint32(N) == V`: writes LE bytes of `V` at file offset `N`
- Nested expressions (`uint32(uint32(...))`) always route to the PE/MinGW path and are never patched into Linux ELFs

**State:** `ArayGraphState` (TypedDict) with fields: `name`, `rule_path`, `yara_rule`, `normalized_rule`, `rule_strings`, `rule_constants`, `has_condition`, `normalize_attempts`, `judge_verdict`, `judge_reason`, `normalize_history`, `needs_normalization`, `normalization_error`, `file_type`

## Key Directories

- `data/rules/` - Input YARA rule files (`.yar`)
- `build/linux/` - Linux ELF output (`main.S`, `linker.ld`, `app` binary, `normalized_rule.yar`)
- `build/windows/` - Windows PE output: full compile → `main.c`, `app.exe`, `normalized_rule.yar` (for `at`-offset PE rules, `main.c` embeds the `.oray` section and a freestanding `_start`); `--scan-only` → `main.S`, `app.exe`, `normalized_rule.yar`
- `build/generic/` - Generic byte-blob output (`output{ext}`, `normalized_rule.yar`)
- `tests/conftest.py` - Calls `load_dotenv()` before any tests run
- `tests/test_agent.py` - Unit and node-level integration tests (LLM mocked; requires `yara`+`gcc` for Linux integration, `yara`+`x86_64-w64-mingw32-gcc` for PE integration, optional `wine`/`wine64` for PE execution)
- `tests/test_e2e.py` - End-to-end pipeline tests: the real-LLM classes (`TestE2ELinux`, `TestE2EPE`, `TestE2ELinuxScanOnly`, `TestE2EPEScanOnly`, `TestE2ELinuxNoStructuredOutput`) are marked `@pytest.mark.llm` and skip without `OPENAI_API_KEY`; `TestE2EPipelineConfig` / `TestPipelineConfigUnstructured` are mocked and always run
- `tests/test_evaluator.py` - Unit tests for the evaluator (LLM mocked, always runs)
- `tests/test_normalizer.py` - Unit tests for the normalizer (LLM mocked, always runs)

## Configuration

Requires `OPENAI_API_KEY` in `.env` file — unless using a keyless local gateway (see below).

Optional env vars (can also be set in `.env`):
- `OPENAI_MODEL=<model-name>` — overrides default `gpt-4.1` for all roles; overridden by `--model` flag
- `OPENAI_BASE_URL=<url>` — points to an OpenAI-compatible gateway; overridden by `--base-url` flag
- `NORMALIZE_MODEL=<model-name>` — model for the `normalize_rule` node; overrides `OPENAI_MODEL`; overridden by `--normalize-model` flag
- `EXTRACT_MODEL=<model-name>` — model for `extract_strings` / `extract_constants` nodes; overrides `OPENAI_MODEL`; overridden by `--extract-model` flag
- `NORMALIZE_BASE_URL=<url>` / `EXTRACT_BASE_URL=<url>` — per-role endpoint for the normalize / extract roles; overrides `OPENAI_BASE_URL`; overridden by `--normalize-base-url` / `--extract-base-url`
- `NORMALIZE_API_KEY=<key>` / `EXTRACT_API_KEY=<key>` — per-role credentials; overrides `OPENAI_API_KEY`; overridden by `--normalize-api-key` / `--extract-api-key`

**Keyless gateways (Ollama, LiteLLM, ...):** a custom `base_url` without any `api_key` gets the placeholder `DUMMY_API_KEY` (`"not-needed"` from `aray/constants.py`) so the OpenAI SDK can construct a client. Applied in `aray/graph.py::_make_llm` and `aray/normalizer.py::run_normalization`; the default OpenAI endpoint (no `base_url`) still requires a real key and surfaces the standard "api_key must be set" error.

**Per-role LLM config (`aray/config.py`):**
- `LLMNodeConfig` — dataclass holding `model`, `base_url`, and `api_key` for one pipeline role
- `PipelineConfig` — dataclass with `normalize` and `extract` `LLMNodeConfig` fields, plus `use_structured_output: bool = True`, `scan_only: bool = False`, `streaming: bool = True`, and `debug: bool = False`; `PipelineConfig.from_model(model, base_url)` creates a single-model config for all roles
- `_invoke_llm(llm, schema, messages, use_structured=True)` — shared LLM invocation helper; uses `.with_structured_output()` when `use_structured=True` and **automatically falls back** to prompt-injected JSON schema parsing when the model/gateway does not support tool calls (or the structured response cannot be parsed) — no manual flag needed. `use_structured=False` skips the structured attempt entirely.
