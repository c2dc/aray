# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

#### Project website and GitHub Pages deployment
- **MkDocs Material website** (`mkdocs.yml`, `docs/site/index.md`): responsive project landing page with quick start, architecture boundary, artifact backends, published evaluation results, and research affiliation.
- **Search and discovery metadata** (`docs/theme/main.html`, `docs/site/robots.txt`): canonical URLs, Open Graph and Twitter metadata, sitemap discovery, and built-in documentation search.
- **Examples and custom presentation** (`docs/site/examples.md`, `docs/site/stylesheets/aray-v2.css`): focused ELF/PE workflows, the complete sample catalog, and a responsive white-and-red visual system inspired by the iFood palette.
- **Institutional collaboration footer** (`docs/theme/main.html`, `docs/site/assets/institutions/`): official ITA, USP, iFood, and Texas A&M University marks, full institution names, source provenance, and responsive links on every documentation page.
- **GitHub Pages workflow** (`.github/workflows/pages.yml`): strict MkDocs build and deployment to `https://c2dc.github.io/aray/` using commit-pinned GitHub Actions.
- **Documentation source layout** (`docs/README.md`, `docs/site/`, `docs/theme/`, `docs/sources/`): separates published pages and assets from build-only theme overrides and editable diagram/provenance sources; MkDocs and GitHub Pages now consume only the relevant directories.

#### Continuous integration and repository security
- **Deterministic CI** (`.github/workflows/ci.yml`): tests Python 3.12 and 3.13 with YARA, GCC, and MinGW available, generates branch coverage without making LLM calls, and validates wheel and source-distribution builds.
- **Codecov reporting** (`codecov.yml`, `README.md`): uploads coverage through GitHub OIDC, tracks project coverage against the previous result, requires 80% patch coverage, and exposes CI and coverage badges.
- **CodeQL and dependency review** (`.github/workflows/codeql.yml`, `.github/workflows/dependency-review.yml`): scans Python changes on pushes, pull requests, and a weekly schedule, and rejects pull requests that introduce dependencies with moderate-or-higher known vulnerabilities.
- **Dependabot updates** (`.github/dependabot.yml`): checks Python/uv and GitHub Actions dependencies weekly and groups each ecosystem into a single pull request.
- **Security baseline refresh** (`uv.lock`): upgraded the migrated dependency set to patched releases after enabling GitHub vulnerability alerts.

#### Architecture and pipeline determinism diagrams
- **System architecture overview** (`docs/sources/diagrams/aray-architecture.drawio`, `docs/site/diagrams/aray-architecture.svg`): editable draw.io source and shareable SVG showing the CLI, role-specific LLMs, LangGraph pipeline, artifact-generation paths, and external dependencies.
- **Detailed pipeline determinism map** (`docs/sources/diagrams/aray-pipeline-determinism.drawio`): two-page editable diagram separating pipeline control flow from artifact generation and explicitly classifying deterministic logic, LLM-driven non-determinism, random padding, and environment/toolchain-sensitive operations.
- **Pipeline SVG exports** (`docs/site/diagrams/aray-pipeline-determinism-flow.svg`, `docs/site/diagrams/aray-pipeline-determinism-artifacts.svg`): standalone views of the control-flow and artifact-generation pages for documentation and review.

#### OpenAI-compatible gateway documentation
- **Known gateway base URLs** (`README.md`): quick-reference table and CLI examples for OpenAI, Ollama, LiteLLM, and OpenRouter, including API-key expectations and compatibility notes.

#### Per-step streaming and structured-output overrides
- **`streaming` / `use_structured_output` fields on `LLMNodeConfig`** (`aray/config.py`): both are `bool | None` per-role overrides — `None` inherits the pipeline-wide `PipelineConfig` default; a bool overrides it for that role only.
- **`build_graph()` per-role resolution** (`aray/graph.py`): a `_resolve(node_val, shared)` helper picks the role override when set, otherwise the shared default. `normalize_rule` / `judge_rule` use the `normalize` role's resolved values; `extract_strings` / `extract_constants` use the `extract` role's. Each `ChatOpenAI` is built with its role's resolved `streaming`.
- **`--normalize-no-structured-output` / `--extract-no-structured-output` and `--normalize-no-stream` / `--extract-no-stream` CLI flags** (`aray/cli.py`, `aray/evaluator.py`): disable tool-call structured output or streaming for one role only. The global `--no-structured-output` / `--no-stream` still apply pipeline-wide; a role flag overrides the global for that role. Enables mixing a cloud model that supports tool calls + streaming (normalize/judge) with a local SLM that needs the compatibility flags (extract) in a single run.
- **`aray-eval` support** (`aray/evaluator.py`): four new `bool | None` override fields on `EvalConfig`, resolved by a `_role_override()` helper with `flag OR .evaluator key → False, else None` semantics, and threaded into each role's `LLMNodeConfig`.
- **`tests/test_evaluator.py`**: `_make_args` helper extended with the four new argparse defaults.

#### Per-step endpoint and API key (different provider per pipeline role)
- **`api_key` field on `LLMNodeConfig`** (`aray/config.py`): each pipeline role (`normalize`, `extract`) now carries its own `base_url` **and** `api_key`, so the two steps can target completely different providers (e.g. normalize on cloud GPT-4.1, extract on a local Ollama endpoint).
- **`build_graph()` per-role client construction** (`aray/graph.py`): a `_make_llm()` helper builds each `ChatOpenAI` from its role config, passing `base_url` / `api_key` **only when set** so unset values still fall back to `ChatOpenAI`'s own `OPENAI_BASE_URL` / `OPENAI_API_KEY` env defaults instead of being forced to `None`.
- **`--normalize-base-url` / `--extract-base-url` / `--normalize-api-key` / `--extract-api-key` CLI flags** (`aray/cli.py`, `aray/evaluator.py`): override the endpoint and key per role independently of the shared `--base-url` / `OPENAI_API_KEY`.
- **`NORMALIZE_BASE_URL` / `EXTRACT_BASE_URL` / `NORMALIZE_API_KEY` / `EXTRACT_API_KEY` env vars**: persistent per-role endpoint/key overrides. Precedence (highest → lowest): role CLI flag > role env var > shared `--base-url` / `OPENAI_BASE_URL` (endpoints) or `OPENAI_API_KEY` (keys).
- **`aray-eval` support** (`aray/evaluator.py`): four new fields on `EvalConfig` resolved with `flag > .evaluator key > env > shared` precedence and threaded into the per-run `PipelineConfig`. Report metadata now records `normalize_base_url` / `extract_base_url`; **API keys are never printed to stdout nor written to `report.json`**.
- **`main()` startup line**: both `aray` and `aray-eval` now print `Base URLs: normalize=<url>  extract=<url>` alongside the existing `Models:` line (endpoints only — keys are never shown).
- **`.env_example` template** (renamed from `.env_local`): documents the four new per-step variables in a dedicated section, with a worked mixed-provider example (normalize → OpenAI, extract → local Ollama).
- **`tests/test_evaluator.py`**: `_make_args` helper extended with the four new argparse defaults.

#### Per-step model logging at runtime
- **Model-in-use print in the extract nodes** (`aray/nodes.py`): `extract_strings` and `extract_constants` now print `[extract-strings] using model=<name>` / `[extract-constants] using model=<name>` at runtime, and `normalize_rule` prints `[normalize] using model=<name>`, so the actual model each step runs against is visible (not only the aggregated `Models:` line printed once at startup). Useful when `--normalize-model` and `--extract-model` differ.

#### Normalization early-exit on exhausted retries (`fail_normalization` node)
- **`fail_normalization` node** (`aray/nodes.py`): terminal node reached when `judge_rule` returns `"failed"` three consecutive times. Prints `[normalize] FAILED after N attempt(s): <reason>` to stdout and writes `normalization_error` to state, halting the pipeline before any extraction or compilation is attempted.
- **`_judge_router` updated** (`aray/graph.py`): now routes to `"fail_normalization"` instead of proceeding to `"extract_strings"` when `judge_verdict == "failed"` and `normalize_attempts >= 3`. Retry logic (< 3 attempts → `"normalize_rule"`) is unchanged.
- **`normalization_error: str | None` state field** (`aray/state.py`): set by `fail_normalization` with the last judge reason; `None` on the success path.
- **`normalize_verdict` / `normalize_reason` fields on `EvalResult`** (`aray/evaluator.py`): two new optional `str | None` fields exposed in `to_dict()` / JSON reports. On the normalization-failure path both are set to `"failed"` / the judge reason; on the success path they carry the last judge verdict and explanation.
- **`_run_one` early-exit in the evaluator** (`aray/evaluator.py`): after `invoke()`, if `final_state["normalization_error"]` is set the function returns immediately with `status="failed"`, `error="normalization failed: <reason>"`, and `yara_returncode=None` — no binary is sought and no YARA scan is run.
- **`tests/test_agent.py`**:
  - `TestBuildGraph.test_graph_has_expected_nodes` updated to assert `"fail_normalization"` is in the compiled graph.
  - New `TestFailNormalizationNode` (2 cases): node returns the judge reason as `normalization_error`; falls back to a non-empty default when `judge_reason` is absent.
  - New `TestJudgeRouter` (4 cases): routes to `"normalize_rule"` when attempts < 3; routes to `"fail_normalization"` when attempts ≥ 3; routes to `"extract_strings"` on `"passed"` and `"uncertain"` verdicts.
- **`tests/test_evaluator.py`**:
  - New `TestEvalResultNormalizeFields` (3 cases): `to_dict()` includes `normalize_verdict` and `normalize_reason`; both default to `None`.
  - New `TestRunOneNormalizationFailure` (1 case): when `invoke()` returns `normalization_error`, `_run_one` produces `status="failed"`, `normalize_verdict="failed"`, correct `normalize_reason`, and `yara_returncode=None`.

#### Scan-only E2E test classes
- **`TestE2ELinuxScanOnly`** (`tests/test_e2e.py`, `@pytest.mark.llm @requires_yara`): four tests exercising the full LLM pipeline with `scan_only=True` for Linux rules — YARA matches on `rule0` and `rule1`, expected artefacts present (`main.S`, `linker.ld`, `normalized_rule.yar`, `app`), and `gcc` never invoked.
- **`TestE2EPEScanOnly`** (`tests/test_e2e.py`, `@pytest.mark.llm @requires_yara`): four tests for the PE scan-only path — YARA matches on `rule6`, valid MZ header and PE signature at `e_lfanew`, expected artefacts present (`main.S`, `normalized_rule.yar`, `app.exe`), and `x86_64-w64-mingw32-gcc` never invoked.
- **`requires_yara` skip guard** added to `test_e2e.py`: marks tests as skipped when `yara` is not on PATH, without requiring `gcc` (used by the scan-only classes that need no compiler).
- **`_invoke` helper** (`tests/test_e2e.py`): `scan_only: bool = False` parameter added and forwarded to `PipelineConfig`.

### Fixed

#### Stale artifacts from previous backend runs
- **CLI build cleanup** (`aray/cli.py`): removes `build/linux`, `build/windows`, and `build/generic` immediately before pipeline invocation so the build tree represents only the current run. This prevents an old PE result from appearing current after normalization selects an ELF branch, or vice versa.

#### Architecture diagram URL
- **Nested-page image path** (`docs/site/architecture.md`): uses Markdown image rendering so MkDocs rewrites the diagram URL correctly for the `/aray/architecture/` route instead of requesting it below `/aray/architecture/diagrams/`.

#### Repository migration URL
- **Quick Start clone command** (`README.md`): updated the repository URL from the previous `New-Horizons-Team/aray` location to the official `c2dc/aray` repository.

#### `test_no_structured_output_flag_propagates` — forced normalization path
- The test was patching `read_yara_rule` with `"rule x { condition: true }"`, a rule that `check_normalization_needed` correctly identifies as already normalized — so `normalize_rule` and `judge_rule` were never called, giving 2 invocations instead of the expected 4. The mocked rule is now `"rule x { strings: $a = /test/ condition: $a }"` (contains a regex), which forces the LLM normalization loop and restores the expected 4-invocation count.

#### Deterministic normalization-check router node
- **`check_normalization_needed` node** (`aray/nodes.py`): inserted between `read_yara` and `normalize_rule`. Uses deterministic regex matching (zero LLM calls) to decide whether the rule needs LLM normalization. Five checks trigger normalization: regex strings (`$a = /…/`), hex wildcards (`??`) or jumps (`[N]`/`[N-M]`) inside `{ }` blocks, `or` in the condition, and numeric count expressions (`N of …`). `any of them` and `all of them` are intentionally excluded — they don't break downstream extraction and keeping them on the fast path avoids unnecessary LLM calls. When no normalization is needed, the raw rule is passed through as `normalized_rule` and the pipeline jumps directly to `extract_strings`, skipping `normalize_rule`, `judge_rule`, and all associated retries.
- **`_requires_normalization(rule_text) -> bool`** (`aray/nodes.py`): pure helper implementing the five-check detection logic. Exposed for testing.
- **`needs_normalization: bool` state field** (`aray/state.py`): set by `check_normalization_needed`; read by `_normalization_router` in `graph.py`.
- **`_normalization_router()`** (`aray/graph.py`): conditional-edge function that dispatches to `"normalize_rule"` or `"extract_strings"` based on `needs_normalization`; defaults to `True` (normalization) if the field is missing.
- **Progress messages**: `check_normalization_needed` prints `[normalize] rule requires normalization — running LLM loop` or `[normalize] rule is already normalized — skipping LLM loop` to stdout.
- **`tests/test_agent.py`**: new test class `TestRequiresNormalization` (16 cases: simple ASCII, clean hex, `any/all of them`, uint conditions → `False`; regex string, hex wildcard/jump, OR condition, numeric count, real CVE rules → `True`). New test class `TestCheckNormalizationNeededNode` (4 cases: fast-path sets `normalized_rule`, complex rule omits `normalized_rule`, OR condition, real rule0.yar). `TestBuildGraph.test_graph_has_expected_nodes` updated to assert `"check_normalization_needed"` is present.

### Fixed

#### Robust file-type routing against LLM offset hallucination
- **`route_file_type`** (`aray/nodes.py`): offset-0 routing is now cross-validated against the normalized rule text before classifying a rule as "generic". A string or constant is only considered to be at offset 0 if the rule text actually contains the corresponding expression — `$var at 0` for strings, `uint16(0)` / `uint32(0)` for constants. This prevents weaker models (e.g. local quantized models) from hallucinating `offset=0` on plain unconstrained strings like `$a = "dummy1"`, which previously caused incorrect "generic" routing and a plain byte-blob output instead of the expected Linux ELF binary.
- **`tests/test_agent.py`**: `test_offset0_constant_routes_to_generic` and `test_offset0_string_routes_to_generic` updated to supply a `norm_rule` that includes the actual `uint16(0)` / `at 0` expression, reflecting the new cross-validation requirement. Two new regression tests added: `test_offset0_constant_no_rule_text_routes_to_elf` and `test_offset0_string_no_rule_text_routes_to_elf` verify that a hallucinated `offset=0` without a matching rule-text expression falls through to `"elf"`.

#### Generic binary support (non-executable file types)
- **`route_file_type` node** (`aray/nodes.py`): pure-computation node inserted after `extract_constants`. Inspects extracted constants and strings to decide the target binary format: `"pe"` if `_is_pe_rule()` returns True; `"generic"` if any constant or string is anchored at file offset 0 (non-PE magic); `"elf"` otherwise.
- **`write_generic` node** (`aray/nodes.py`): writes a plain byte-blob artifact — no ELF or PE structure. Strings are placed at their exact file offsets using `_assign_offsets(pack=True, default_base=0x10)` to satisfy tight `filesize < N` constraints; constants are LE-patched at their offsets. Output: `build/generic/output{ext}`.
- **`write_generic_artifact()`** (`aray/artifact_writer.py`): allocates a zeroed buffer, writes each string/constant section at its exact offset, and auto-detects the file extension from the magic bytes at offset 0 — `.png`, `.jpg`, `.doc`, `.gif`, `.zip`, `.php`, `.asp`, or empty string for unrecognized formats. Returns a `(bytes, str)` tuple.
- **`BUILD_DIR_GENERIC`** (`aray/constants.py`): `Path("build/generic")` — output directory for generic artifacts.
- **`file_type` state field** (`aray/state.py`): `str` field (`"pe"` | `"elf"` | `"generic"`) set by `route_file_type` and read by `_file_type_router` in `graph.py`.
- **`_file_type_router()`** (`aray/graph.py`): conditional-edge function that dispatches to `"compile"` for PE/ELF rules and `"write_generic"` for generic rules.
- **`pack=True` parameter** added to `_assign_offsets()` (`aray/codegen.py`): when set, unconstrained strings are packed consecutively (offset advances by `len(data) + 1`) rather than at fixed `DEFAULT_OFFSET_STEP` intervals. Used by the generic path to avoid bloating past tight `filesize < N` constraints.
- **Evaluator generic-artifact support** (`aray/evaluator.py`): `_run_one` now patches `aray.constants.BUILD_DIR_GENERIC` to a per-run tmpdir; after the pipeline completes, it detects `output*` files in `generic_dir` and uses `normalized_rule.yar` as the YARA scan rule (the normalized first-rule-only file prevents false failures from multi-rule source files).
- **`tests/test_agent.py`**: new test classes `TestAssignOffsets` (pack mode), `TestRouteFileType` (8 cases: PE/generic/ELF routing), `TestWriteGenericArtifact` (11 cases: magic detection, offset placement, constants, padding), `TestWriteGenericNode` (4 cases: extension, magic bytes, normalized rule written, string packing), `TestEvaluatorRunOne` (5 cases: exact YARA CLI filename, normalized rule used for generic, PE uses original rule, no-binary failure, build-dir isolation).

#### Normalize prompt improvements
- **Escaped parentheses rule** (rule 1): explicit instruction that `\(` and `\)` in YARA regex are LITERAL characters that MUST appear verbatim in the minimum-match output string. Includes a worked step-by-step example (`/\$[a-z]+=explode\(chr\(\([0-9]+[-+][0-9]+\)\)/` → `"$a=explode(chr((0-0))"`).
- **`N of them` handling** (rule 3): when `N of them` / `N of ($prefix*)` is expanded and M > N strings are defined, exactly N strings are kept and the rest are REMOVED from the `strings:` section.
- **Unreferenced-string CRITICAL rule** (rule 8): every variable defined in `strings:` MUST appear in `condition:`. If simplification leaves a variable unreferenced, it must be removed from the strings section.
- **Double-quote escaping rule** (new rule 9): string values containing `"` must be written as `\"` inside the YARA string literal.
- **Single-rule output rule** (new rule 10): the normalizer must output exactly ONE rule.
- **OR-simplification example** added showing removal of unused string variables (`$jfif`, `$png`) after keeping only one branch (`$gif at 0`).

#### Judge prompt improvements
- **Unreferenced-string failure criterion**: YARA rejects rules where a string variable is defined in `strings:` but not referenced in `condition:`. The judge now explicitly marks such normalizations as `"failed"`.
- **Unescaped-quote failure criterion**: unescaped double-quotes inside string literals are now listed as a `"failed"` condition (YARA syntax error).

### Fixed

#### `_extract_first_rule_text` regex literal handling
- **`in_regex` state variable** (`aray/evaluator.py`): the brace-matching extractor now tracks YARA regex literals (`/pattern/`). When a `/` is encountered outside strings and comments, brace counting and `"` string detection are suspended until the matching closing `/`. Previously, a `"` character inside a regex (e.g. `/\$[a-z]{4}="[a-zA-Z0-9]{70}/`) incorrectly set `in_str=True`, causing the parser to miss the rule's closing `}` and include the next rule in the extracted text.

#### YARA hex wildcard and jump resolution
- **`_resolve_yara_hex()`** (`aray/codegen.py`): deterministic resolver for YARA hex pattern syntax — replaces `??` wildcards with `00` and `[N]`/`[N-M]` jump expressions with N (minimum) repetitions of `00`. Applied in both `_hex_str_to_bytes()` and `_format_hex_initializer()` so codegen never crashes on raw YARA hex patterns that haven't been fully normalized.
- **Normalize prompt rule 5**: LLM is now explicitly instructed to resolve wildcards and jumps during normalization, with four concrete examples covering `??`, `[N]`, `[N-M]`, and large ranges like `[1-100]`.
- **11 new unit tests** in `TestResolveYaraHex`: cover no-op, single/multiple wildcards, exact and ranged jumps, zero-minimum jumps, mixed patterns, and end-to-end `_hex_str_to_bytes` / `_format_hex_initializer` integration.

#### Judge node in the main pipeline
- **`judge_rule` pipeline node**: after `normalize_rule`, an LLM judge verifies the normalized rule is a valid, correct subset of the original using the same prompt and `JudgeVerdict` schema as `aray-normalize`. On a `failed` verdict the pipeline loops back to `normalize_rule` and retries; after 3 attempts it proceeds regardless, so the pipeline never stalls. Prints `[judge] attempt N/3 — <verdict>: <reason>` to stdout.
- **`normalize_attempts` / `judge_verdict` state fields** (`aray/state.py`): track retry count and last judge verdict across the `normalize_rule ↔ judge_rule` loop.
- **`_judge_normalization` / `_JUDGE_SYSTEM` moved to `aray/nodes.py`**: avoids a circular import (`normalizer.py` already imports `normalize_rule` from `nodes.py`); `normalizer.py` now imports these from `nodes.py`.

#### `--debug` flag
- **`--debug` CLI flag**: when set, prints `[debug] → node: <name>` to stdout before each pipeline node executes. Implemented via `_debug_wrap()` in `graph.py`, which wraps every node function; zero overhead when the flag is off.
- **`PipelineConfig.debug`**: new `bool` field (default `False`) wired from the CLI flag.
- **Extended to the compile node**: `debug=True` now also prints section placement (`[debug] sections (N): .sec_0xOFFSET  SIZE bytes  (hex preview...)`) before assembler/artifact generation on all Linux and PE scan-only paths. On the MinGW full-compile path, it prints the embedded string list (`[format]  value`) instead. Filesize constraint solving is printed when a `filesize` condition is present: parsed bounds (`min=`, `max=`), and the computed padding (`current + padding → final`).

#### Filesize constraint support
- **`_parse_filesize_constraint()`** (`aray/compiler.py`): regex-based parser for YARA `filesize` conditions — handles `>`, `>=`, `<`, `<=`, `==` operators and `KB`/`MB`/`GB` unit suffixes. Multiple constraints in the same rule are composed with AND logic (e.g. `filesize > 70KB and filesize < 110KB` → `min=71681, max=112640`). Returns `(min_bytes, max_bytes)` where either may be `None`.
- **`_compute_padding()`** (`aray/artifact_writer.py`): pure function that computes the number of random padding bytes to append. Returns `0` when the binary already satisfies the min bound or already exceeds the max (can't shrink). For a min-only constraint, targets `min + 1024` bytes; for bounded `[min, max]`, targets the midpoint clamped to `max - 1`.
- **`_apply_filesize_padding()`** (`aray/compiler.py`): appends `os.urandom(n)` to a compiled binary on disk. Prints a warning (and suggests `--scan-only`) if the binary already meets or exceeds the max bound.
- **All four compilation paths** now parse and apply filesize constraints: Linux full compile (after `_patch_constants`), Linux `--scan-only` (`write_linux_artifact`), PE full compile (after MinGW), PE `--scan-only` (`write_pe_artifact`).
- Rules with only a `filesize < N` bound whose artifact is already smaller than `N` produce no padding (constraint already satisfied). A warning is printed when the compiled binary exceeds the max and cannot be shrunk.

### Fixed

#### C string escaping in Windows PE codegen
- **`_escape_c_string()` helper** (`aray/codegen.py`): escapes backslashes (`\` → `\\`) and double quotes (`"` → `\"`) before embedding a string value in a C string literal. Fixes a compilation error where YARA strings containing backslashes (e.g. `"\\update.dat"`) produced invalid C (`"\update.dat"`).
- Applied to both `_format_ascii_initializer()` (ASCII strings) and the `wchar_t` wide-string declaration in `_compile_pe_binary()`.

#### Ruleset support (multi-rule files)
- **`_extract_first_rule_text()`** (`aray/evaluator.py`): brace-matching extractor that returns only the first complete rule block from a `.yar` file. Correctly skips string literals (`"..."` with backslash escapes), line comments (`//`), and block comments (`/* */`) to avoid false brace counts. Handles `private`/`global` rule modifiers. Falls back to the full text if no rule header is found.
- **`read_yara_rule` node** (`aray/nodes.py`): now calls `_extract_first_rule_text` before storing `yara_rule` in state, so multi-rule files are silently reduced to their first rule at pipeline entry. Uses a lazy import to avoid a circular dependency (`evaluator.py → graph.py → nodes.py`).
- **`aray-normalize` batch runner** (`aray/normalizer.py`): `_run_one` now extracts the first rule from the file before normalizing and before passing to the LLM judge. The output file contains only the normalized single rule.

#### New sample rules
- **`rule10.yar`** (`Mal_PotPlayer_DLL`, CVE-2015-2545): rule with a tight-size PE branch and an alternative fullword-string branch containing backslash paths (`\\update.dat`); normalization selects the cheaper string branch under YARA precedence.
- **`rule11.yar`** (`CVE_2012_0158_KeyBoy`, CVE-2012-0158): Linux ELF rule with a regex string (`$c`) and an `all of them` condition — exercises the `normalize_rule` judge-retry loop (regex replaced with a literal, variable kept, `all of them` preserved).

### Changed

#### Automatic structured-output fallback
- **`_invoke_llm` auto-fallback** (`aray/llm.py`): structured output (`.with_structured_output()`) is attempted first and automatically falls back to prompt-injected JSON schema parsing (strips markdown fences) when the model/gateway does not support tool calls or the structured response cannot be parsed. No manual flag is needed. Auth, rate-limit, and network errors still propagate (they are deliberately not treated as fallback triggers). A `[llm] structured output failed (<Type>: <msg>) — falling back to prompt-based JSON` line is printed to stdout on fallback.
- **Explicit `method="function_calling"`** (`aray/llm.py`): structured output now uses the tool-calling API instead of langchain-openai 1.1.7's default `method="json_schema"` (OpenAI Structured Outputs `response_format`). Ollama-compatible gateways ignore `response_format` and return markdown-fenced text, which made the SDK raise a spurious `ValueError` and forced a fallback on every call. The tool-calling API is honored by both OpenAI and Ollama, so supporting gateways now parse on the first attempt; genuinely tool-less gateways still hit the auto-fallback.
- **`tool_choice="auto"`** (`aray/llm.py`): the structured call no longer forces `tool_choice` to the tool name. Reasoning models on some OpenRouter providers (e.g. Alibaba's `qwen3.5-flash` in thinking mode) reject a forced `tool_choice` with HTTP 400 (`tool_choice does not support being set to required or object in thinking mode`), which previously pushed every call through the fallback. With `tool_choice="auto"` those models emit a real tool call on the first attempt; a model that instead answers in plain text still lands in the prompt-JSON fallback.
- **`--no-structured-output` / `--normalize-no-structured-output` / `--extract-no-structured-output` CLI flags removed** (`aray/cli.py`, `aray/evaluator.py`, `aray/normalizer.py`): the fallback is now automatic, so these flags and the corresponding `no_structured_output` keys in `.evaluator` / `.normalizer` config files are gone. `--no-stream` and its per-role variants remain.
- **`use_structured_output` removed from `LLMNodeConfig`** (`aray/config.py`): only the pipeline-wide `PipelineConfig.use_structured_output: bool = True` remains; per-role overrides are no longer supported. Set it to `False` to skip the structured attempt entirely (e.g. in tests).

#### Normalize prompt improvements
- **Rule 1** now explicitly states that when replacing a regex, the same variable name must be kept (do not remove the variable). This prevents the LLM from silently dropping a variable that is referenced by `all of them`.
- **Rule 7 (new)**: if a string variable must be removed, quantified references must be rewritten to use only required retained variables; `any of them` selects one witness instead of preserving an OR.
- **Second example** added to the normalize prompt demonstrating regex replacement while preserving the variable and the `all of them` condition.
- **Judge system prompt** updated to include rule 7 so the judge does not incorrectly mark as `failed` a normalization that correctly rewrites `all of them` after dropping a variable.
- **Constructible-subset contract** (`aray/nodes.py`, `aray/models.py`): normalization now explicitly requires implication in one direction (`normalized match => original match`) instead of incorrectly claiming bidirectional equivalence when selecting one OR branch.
- **Precedence-aware OR selection**: prompts now state YARA's `not` > `and` > `or` precedence, require complete branches, expand quantified string sets before comparison, and forbid carrying constraints across discarded alternatives.
- **Construction-cost ranking**: branch selection prioritizes feasibility, then avoids tight maximum sizes, large padding requirements, high exact offsets, format-forcing PE/nested/wide requirements, and excess evidence. The judge rejects clearly more expensive choices and feeds the cheaper branch back into retries.
- **`rule10.yar` regression**: documents and tests selection of `$s3 and $s4` over the `(MZ and filesize < 2KB and $x1)` branch, producing an ELF artifact that still matches the original rule.
- **Deterministic regex-witness validation** (`aray/yara_validation.py`): retained regex variables replaced by fixed literals are compiled and checked with `yara-python` before the LLM judge runs. Invalid witnesses return actionable retry feedback and cannot be accepted merely because they are non-empty.
- **`rule11.yar` regression**: the normalizer prompt now includes the exact shortest witness `52006F006F007400200045006E007400720079`; unit and real-LLM tests verify that the generated ELF matches the original regex rule.

#### GNU assembler codegen (Linux ELF path)
- **`_generate_asm_source()`** replaces `_generate_c_source()`: Linux strings are converted to raw bytes and emitted as `.section .sec_0xNNN,"aw",@progbits` + `.byte` directives in a GNU assembler source file (`main.S`). This guarantees deterministic byte placement; C compiler string folding, reordering, and alignment padding cannot interfere.
- **`_hex_str_to_bytes` / `_ascii_str_to_bytes` / `_wide_str_to_bytes` / `_int_to_le_bytes`**: low-level byte converters in `codegen.py`; `_assign_offsets` now returns `list[tuple[int, bytes]]`.
- **PHDRS linker directive**: The linker script now includes `PHDRS { load PT_LOAD FILEHDR PHDRS ; }` and assigns all sections `:load`. Without this, a pure assembler input causes `ld` to choose `p_offset=0x1000` for the first `PT_LOAD` segment — silently shifting all `at` constraints by 0x1000. The `FILEHDR`/`PHDRS` keywords force `p_offset=0` and re-establish the VMA ↔ file-offset identity.

#### `--scan-only` mode and `artifact_writer` module
- **`--scan-only` CLI flag**: produces a YARA-matchable raw binary without invoking any external compiler. Linux rules → minimal ELF64 artifact; PE rules → minimal PE64 artifact. Useful in toolchain-free environments (containers, air-gapped networks, CI pipelines).
- **`aray/artifact_writer.py`** (new module): `write_linux_artifact()` and `write_pe_artifact()` construct raw binaries using only Python's `struct` module. Both functions place strings at their exact file offsets and patch non-nested integer constants directly into the buffer. The PE artifact uses `NumberOfSections=0` — no `.data` section header is needed because YARA scans raw file bytes regardless of the section table.
- **`main.S` written alongside both scan-only artifacts**: `_write_linux_artifact` writes `main.S` and `linker.ld` to `build/linux/`; `_write_pe_artifact` writes `main.S` to `build/windows/`. Both use `_generate_asm_source` to document the intended byte placement in the same `.section`/`.byte` format as the full compilation path.
- **`PipelineConfig.scan_only`**: new `bool` field (default `False`); wired via `functools.partial` into the `compile` node.

#### Wide string support
- **`widechar` format in `YaraStringEntry`**: the LLM sets `format="widechar"` for strings with the YARA `wide` modifier. `_is_pe_rule` now routes any rule containing a `widechar` entry to the MinGW path; `_compile_pe_binary` emits a conditional `#include <wchar.h>` and `const wchar_t *ws_N = L"value";` declarations. MinGW stores these as UTF-16LE in `.rdata`, exactly what YARA's `wide` scanner expects.
- **`rule9.yar`**: APT15 variant adding `wide` modifiers to all 15 command-line flag strings (`$s10`–`$s24`); exercises the wide-string pipeline end-to-end.

#### Per-role LLM configuration
- **`LLMNodeConfig` / `PipelineConfig` dataclasses** (`aray/config.py`): `PipelineConfig` holds independent `LLMNodeConfig` fields for the `normalize` and `extract` roles, plus `use_structured_output` and `scan_only` flags.
- **`--normalize-model` / `--extract-model` CLI flags**: override the model per pipeline role independently of the global `--model` flag.
- **`NORMALIZE_MODEL` / `EXTRACT_MODEL` env vars**: persistent per-role model overrides via `.env` or shell environment.
- Four-tier precedence (highest → lowest): role CLI flag > role env var > global `--model` / `OPENAI_MODEL` > compiled-in default (`gpt-4.1`).
- **`--model` CLI flag**: override the LLM model for all roles.
- **`--base-url` CLI flag**: point Aray at any OpenAI-compatible API gateway. Overrides `OPENAI_BASE_URL` env var.
- **`OPENAI_MODEL` / `OPENAI_BASE_URL` env vars**: persistent global overrides.

#### Streaming control
- **`--no-stream` CLI flag**: disables LLM streaming on all pipeline nodes. Needed for models and API gateways that do not support the streaming response format (e.g. Ollama with certain models, simple reverse proxies).
- **`PipelineConfig.streaming`**: new `bool` field (default `True`) that is passed to each `ChatOpenAI` instance in `build_graph()`. Wired via `--no-stream` in the CLI and via the `no_stream` key in the `.evaluator` / `.normalizer` config files.

#### Batch evaluation framework (`aray-eval`)
- **`aray/evaluator.py`** (new module): batch-runs the full aray pipeline over a directory tree of `.yar` files, validates each generated binary with the YARA CLI, and writes a structured JSON report. Exposes `run_evaluation()`, `_write_report()`, and `_print_summary()`.
- **`evaluate.py`**: 4-line backwards-compatible shim delegating to `aray.evaluator.main()` (mirrors `main.py` / `evaluate.py` pattern).
- **`.evaluator` TOML config**: default config file specifying `directories`, optional `model`, `workers`, `scan_only`, `no_stream`, and `output` keys under the `[evaluator]` section.
- **`aray-eval` script entry** (`pyproject.toml`): `uv run aray-eval` invokes `aray.evaluator:main` directly.
- **Index-file detection** (`_is_index_file`): skips YARA aggregator files whose name matches `index.yar`, `*_index.yar`, or `index_*.yar`, or whose content starts with `include "`.
- **`tests/test_evaluator.py`**: unit tests for all evaluator helpers — file discovery, index detection, rule name extraction, `EvalResult.to_dict()`, config loading, config merging precedence, and summary formatting. No LLM calls; always runs.

#### Normalization evaluator with LLM-as-judge (`aray-normalize`)
- **`aray/normalizer.py`** (new module): batch-runs only the `normalize_rule` node over a directory tree of `.yar` files — no extraction or compilation. Writes each normalized rule to a mirrored output directory (`<output_root>/<input_dir_name>/<relative_path>`) for use as fine-tuning training data. An LLM-as-judge assesses each normalization for semantic correctness and writes a JSON report.
- **`normalize.py`**: 4-line backwards-compatible shim delegating to `aray.normalizer.main()`.
- **`.normalizer` TOML config**: default config file specifying `directories`, `output_root`, optional `model`, `judge_model`, `base_url`, `judge_base_url`, `workers`, `no_stream`, and `output` under the `[normalizer]` section.
- **`aray-normalize` script entry** (`pyproject.toml`): `uv run aray-normalize` invokes `aray.normalizer:main` directly.
- **Judge LLM** (`_judge_normalization`): uses a separate `ChatOpenAI` instance (default GPT-4.1, configurable via `--judge-model` / `--judge-base-url`) to assess each normalization against four criteria: pattern preservation, modifier preservation, YARA syntax validity, and simplicity. Verdicts: `passed`, `failed`, `uncertain` (uncertain maps conservatively to `status="failed"`). Output file is always written regardless of verdict.
- **`JudgeVerdict` Pydantic model** (`aray/models.py`): structured output schema for the LLM-as-judge with `verdict` (`Literal["passed", "failed", "uncertain"]`) and `reason` fields.
- **`tests/test_normalizer.py`**: unit tests for `_output_path_for`, `NormResult.to_dict`, `_judge_normalization` (prompt content, key phrases), `_run_one` (output file written, skipped for index files, uncertain→failed mapping, exception→error), and `_build_norm_config` (CLI/config/env precedence). No LLM calls; always runs.

#### Fallback LLM mode
- **`--no-structured-output` flag**: disables `.with_structured_output()` and falls back to prompt-injected JSON schema with plain-text response parsing (strips markdown fences). Enables use with models that do not support tool calls (Ollama, simple proxies).

#### Package refactoring
- **`aray/` Python package**: `agent.py` split into focused modules — `cli.py`, `graph.py`, `nodes.py`, `compiler.py`, `codegen.py`, `artifact_writer.py`, `llm.py`, `config.py`, `models.py`, `state.py`, `constants.py`. `main.py` reduced to a 4-line backwards-compatible shim delegating to `aray.cli.main()`.

### Fixed

#### Structured-output `None` fallback (no-tool-call models)
- **`_invoke_llm`** (`aray/llm.py`): when `with_structured_output(method="function_calling", tool_choice="auto")` returns `None` — i.e. the model answered without emitting a tool call (seen with reasoning models such as `moonshotai/kimi-k2.7-code` via OpenRouter) — Aray now retries via the prompt-based JSON path instead of crashing with `AttributeError: 'NoneType' object has no attribute 'rule'` (or `.strings` / `.constants`) in the pipeline nodes.
- **`_invoke_llm_json`** (`aray/llm.py`): now raises a clear, actionable `ValueError` when the model returns `None` content, empty content, or non-JSON text (previously a raw `AttributeError` on `.strip()` / `JSONDecodeError`).
- **`tests/test_agent.py`**: regression test `test_falls_back_when_structured_returns_none` plus `TestInvokeLlmJsonHardening` (None / empty / non-JSON fallback responses).

### Changed

- `build_graph()` now accepts a `PipelineConfig` (or `None` for defaults) and constructs separate `ChatOpenAI` instances for the `normalize` and `extract` roles. Node functions receive their LLM via `functools.partial`; the module-level `llm` singleton is removed.
- `build_graph()` passes `streaming=config.streaming` to each `ChatOpenAI` instance (previously streaming was always enabled with no way to disable it).
- `PipelineConfig` gains a `streaming: bool = True` field; propagated through `aray-eval` (`.evaluator` `no_stream` key) and `aray-normalize` (`.normalizer` `no_stream` key).
- Linux ELF build directory (`build/linux/`) now contains `main.S` (GNU assembler source) instead of `main.c`.
- `_assign_offsets` return type changed from `list[tuple[int, str]]` to `list[tuple[int, bytes]]`.
- `_format_hex_initializer` now accepts both space-separated (`"DE AD BE EF"`) and concatenated (`"DEADBEEF"`) hex strings (used only by the Windows PE C-source path).

### Fixed

#### Keyless local gateways (Ollama, LiteLLM) no longer require a dummy `OPENAI_API_KEY`
- **`DUMMY_API_KEY` constant** (`aray/constants.py`): `"not-needed"` placeholder used when a custom `base_url` is configured without any `api_key`, since the OpenAI SDK 2.x refuses to construct a `ChatOpenAI` client without *some* key even when the gateway ignores auth.
- **`build_graph` per-role client construction** (`aray/graph.py`): `_make_llm()` now sets `api_key=DUMMY_API_KEY` when the role config has a `base_url` but no `api_key`. The default OpenAI endpoint (no `base_url`) still passes no key, so a genuinely missing `OPENAI_API_KEY` surfaces the standard clear "api_key must be set" error.
- **`aray-normalize` batch runner** (`aray/normalizer.py`): the normalize and judge `ChatOpenAI` clients apply the same placeholder logic.
- **`tests/test_e2e.py::TestE2EPipelineConfig`**: three new mocked tests covering base_url-without-key → `api_key="not-needed"`, no base_url → no `api_key` kwarg, and explicit key wins over the placeholder.

## [0.3.0] - 2026-02-27

### Added

- **`normalize_rule` pipeline node**: uses GPT-4.1 structured output to produce a minimal equivalent YARA rule before extraction. Strips regex conditions and expands count expressions (e.g. `15 of ($s*)`) into explicit string lists so downstream nodes always receive a clean, unambiguous rule.
- **`extract_constants` pipeline node**: uses GPT-4.1 structured output to extract `uint16`/`uint32` integer comparisons from the condition section. Each entry records `value`, `offset`, `size` (2 or 4 bytes), and an `is_nested` flag for pointer-dereference expressions like `uint32(uint32(0x3C))`.
- **Windows PE compilation path**: rules containing `uint16(0)==0x5A4D` (MZ header) or `uint32(uint32(0x3C))==0x00004550` (PE signature) are now compiled with `x86_64-w64-mingw32-gcc` (MinGW). The resulting PE binary naturally satisfies both checks; strings are embedded as plain global arrays. Output is written to `build/windows/app.exe`.
- **Linux constant patching**: for non-nested integer constants in Linux rules, the compiled ELF binary is post-patched — `uint16(N)==V` / `uint32(N)==V` write the little-endian bytes of `V` at file offset `N` directly into the output binary.
- **`rule6.yar` / `rule7.yar`**: Windows PE rules exercising the MinGW path — `rule6` checks both MZ header and PE signature; `rule7` checks PE signature only.
- **`rule8.yar`**: real-world APT15 exchange-tool rule with `uint16(0)==0x5A4D` and `15 of ($s*)` over 24 strings, used to exercise the `normalize_rule` node end-to-end.
- **`data/rules/CATALOG.md`**: reference table documenting all nine rules, their targets, and what each one tests.
- **`TestYaraScanPE`** integration test class: compiles real PE binaries via MinGW, asserts YARA matches and valid MZ/PE magic, and runs the executable under Wine when available.
- **Execution tests** (`test_ruleN_runs`) for all Linux rules: compiles ELF binaries and asserts they exit with code 0 and print `BANNER`.

### Changed

- Pipeline flow updated: `read_yara → normalize_rule → extract_strings → extract_constants → compile`. All extraction nodes now operate on `normalized_rule` rather than the raw rule text.
- `ArayGraphState` gains a `normalized_rule` field; `has_condition` field added to track whether the rule body has a condition section.
- `compile` node branches on PE vs. Linux target based on constant metadata rather than heuristics.
- Renamed `ruletmp.yar` → `rule6.yar` and `ruletmp2.yar` → `rule7.yar` for consistency with the rest of the catalog.

## [0.2.0] - 2026-02-20

- Support multi-offset
- Add tests

### Changed

- Reorganized and renamed YARA rules for consistency (rule0–rule2)
- Remove template files: They are generated at runtime

### Added

- `rule3.yar` with hex string pattern for wildcard/hex support

## [0.1.0] - 2026-02-08

### Added

- Support for simple string matches in YARA rules
