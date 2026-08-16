# Evaluation

Aray includes two batch tools:

- `aray-eval` runs the complete pipeline, invokes the real YARA CLI on each artifact, and records end-to-end matches.
- `aray-normalize` evaluates only rule normalization and writes normalized rules to a mirrored directory tree.

## Deterministic Corpus Validation

Aray's primary artifact validation uses 416 real-world rules from
[Yara-Rules/rules](https://github.com/Yara-Rules/rules), fixed at upstream commit
`0f93570194a80d2f2032869055808b0ddcdfb360` and stored as a pre-normalized corpus.

| Mode | Matches | Preflight dispositions | Rules using an LLM | Success rate |
|---|---:|---:|---:|---:|
| Full compile, 1 worker | 406 | 10 | **0** | **97.6%** |

This is a validation of the deterministic pipeline, not a model evaluation:

- all 416 inputs were already normalized and skipped the normalization/judge loop;
- all 406 rules that passed capability preflight used deterministic string extraction;
- the same 406 rules used deterministic constant extraction;
- 10 rules stopped at preflight and never reached either extractor;
- no rule used normalization or extraction LLM fallback.

A canonical control run configured an intentionally unreachable endpoint at
`127.0.0.1:9`; it still completed with 406 matches and telemetry reported
`rules_using_llm=0`. Separate runs configured the extraction role as
`glm-5.2:cloud`, `qwen3.5:4b`, `phi-4:14b`, and `gpt-4.1` and produced the same
result without invoking those models. The names are inactive configuration
cross-checks, not comparable model measurements.

The [versioned machine-readable summary](assets/yara-rules-416-deterministic.json)
records the corpus commit and digest, execution mode, processing paths, result,
and failure set. Both x86-64 and i686 MinGW toolchains were installed.

### Dispositions and Failures

The validation records 406 `matched`, seven `unsupported`, two `infeasible`, and one
`unsatisfiable` dispositions. There are zero `unexplained_mismatch` and zero
`construction_failed` results.

| Failure category | Count | Current cases |
|---|---:|---|
| `unsupported_pe_module` | 7 | `APT_CrashOverride`, `APT_Shamoon_StoneDrill`, `MALW_Batel`, `MALW_IcedID`, `MALW_Pyinstaller`, `RANSOM_Stampado`, `peid` |
| `whole_file_hash_preimage` | 2 | `APT_Grasshopper`, `RAT_CrossRAT` |
| `integer_value_out_of_range` | 1 | `APT_Derusbi` |

The seven `pe.*` cases require these module-level semantics:

| Rule | Required `pe.*` semantics |
|---|---|
| `APT_CrashOverride` | `pe.characteristics`, `pe.exports` |
| `APT_Shamoon_StoneDrill` | `pe.number_of_resources`, `pe.number_of_sections`, `pe.number_of_signatures`, `pe.resources` |
| `MALW_Batel` | `pe.exports`, `pe.imports` |
| `MALW_IcedID` | `pe.EXECUTABLE_IMAGE`, `pe.RELOCS_STRIPPED`, `pe.characteristics`, `pe.sections` |
| `MALW_Pyinstaller` | `pe.number_of_resources` |
| `RANSOM_Stampado` | `pe.characteristics`, `pe.imports`, `pe.number_of_sections`, `pe.sections` |
| `peid` | `pe.entry_point` |

YARA `pe.*` conditions remain outside Aray's construction scope. Current code
classifies them as `unsupported` during capability preflight; they do not act as
PE routing evidence and do not reach extraction or construction.

## Evaluation

Evaluate one file:

```bash
uv run aray-eval evaluation/yara-repos/rules/cve_rules/CVE-2010-0805.yar --scan-only
```

Evaluate one directory:

```bash
uv run aray-eval evaluation/yara-repos/rules/cve_rules --scan-only
```

Evaluate any combination of files and directories with parallel workers:

```bash
uv run aray-eval \
  evaluation/yara-repos/rules/cve_rules \
  evaluation/yara-repos/rules/malware/APT_Casper.yar \
  --workers 4 \
  --scan-only \
  --output eval_report.json
```

Useful options:

| Option | Purpose |
|---|---|
| `--config PATH` | load defaults from TOML; default `.evaluator` |
| `--workers N` | run multiple rules concurrently |
| `--output PATH` | choose the JSON report path |
| `--keep-artifacts` | preserve per-rule temporary builds |
| `--scan-only` | avoid GCC and MinGW |
| `--model`, `--base-url` | shared model configuration |
| role-specific model, URL, key, reasoning, and streaming flags | same semantics as `aray` |

Without `--output`, reports are written to `evaluation/reports/<timestamp>/eval_report.json`.
The CLI prints the report's absolute path after writing it. When
`--keep-artifacts` is enabled, it also prints the absolute temporary directory
preserved for each evaluated rule.

Evaluation reports currently contain three top-level fields: `metadata`,
`results`, and `summary`. Metadata records counts, aggregate duration, and the
non-secret evaluator configuration. API keys are never written to reports.

`status` remains the coarse execution outcome: `passed`, `failed`, or `skipped`.
`disposition` explains the semantic outcome, including `matched`, `unsupported`,
`infeasible`, `unsatisfiable`, `normalization_failed`, `construction_failed`,
and `unexplained_mismatch`. A preflight disposition still has `status="failed"`
because no matching artifact was produced.

Each result records the rule path and name, status, error, duration, YARA output
and return code, configured model names, normalization verdict/reason,
disposition, failure category, normalization path, string/constant extraction
paths, and whether an LLM was actually used. The summary aggregates
`disposition_counts`, `failure_categories`, `processing_paths`, and `llm_usage`;
reports do not embed artifacts.

Calling `aray-eval` without arguments prints the standard help and exits with
status `0`. To process paths from `.evaluator` without positional inputs, pass
the configuration option explicitly: `aray-eval --config .evaluator`.

### Evaluator Configuration

`.evaluator` is a TOML file:

```toml
[evaluator]
directories = [
  "evaluation/yara-repos/rules/cve_rules",
  "evaluation/yara-repos/rules/malware",
]
model = "gpt-4.1"
base_url = "http://localhost:11434/v1"
# normalize_model = "gpt-4.1"
# extract_model = "gpt-4.1-mini"
# normalize_api_key = "sk-..."
# extract_api_key = "not-needed"
extract_reasoning_effort = "none"
extract_no_stream = true
workers = 4
scan_only = true
keep_artifacts = false
```

Configuration precedence is `CLI > TOML > environment > built-in default`.
Within one source, role-specific values override shared values. Consequently, a
shared `model` or `base_url` in `.evaluator` overrides even role-specific
`NORMALIZE_*` and `EXTRACT_*` environment variables. Positional files or
directories replace the configured input list. Despite its legacy name, the
TOML `directories` list also accepts individual `.yar` files. API keys are
never printed or included in reports.

Index files named `index.yar`, `*_index.yar`, or `index_*.yar`, and files beginning with an `include` directive, are skipped. Rulesets process only the first non-private rule, with reachable helpers inlined into one standalone rule. Every backend is scanned with that normalized rule rather than the original ruleset.

### Report Shape

The `metadata` object contains `timestamp`, `total`, `passed`, `failed`,
`skipped`, `duration_seconds`, and `config`. The `results` array contains one
`EvalResult` object per processed rule. The `summary` object contains
`disposition_counts`, `failure_categories`, `processing_paths`, and `llm_usage`.
This is the complete current report shape; consumers should not assume
additional diagnostics or manifests.

## Normalization Evaluator

`aray-normalize` runs normalization without extraction or artifact construction. It writes each normalized rule under an output tree that mirrors the input and asks a separate model to assess quality.

### Preserved Normalization Results

Normalization remains an explicitly model-dependent experiment and is reported
separately from deterministic artifact validation:

| Run | Scope | Passed | Failed | Already normalized | Duration |
|---|---:|---:|---:|---:|---:|
| GLM-5.2 normalizer and judge | 416 | 416 | 0 | 182 | 55m 00.854s |
| GPT-4.1 normalizer and judge | 416 | 407 | 9 | 182 | 14m 18.432s |
| GPT-4.1 targeted failure retest | 21 | 17 | 4 | 0 | 2m 04.308s |

The targeted retest is not directly comparable to either full-corpus run. The
three raw normalization reports remain under `evaluation/reports/`, and the
accepted GLM-5.2 corpus remains frozen under
`evaluation/normalized-glm-5.2-stable`; previous artifact-pipeline experiments
were removed.

Normalize one file:

```bash
uv run aray-normalize evaluation/yara-repos/rules/cve_rules/CVE-2010-0805.yar
```

The result of a standalone file is written directly below `--output-root`, for
example `evaluation/normalized/example.yar`. Directory inputs retain their
mirrored directory structure. At the end, the CLI lists the absolute path of
every normalized file and the report it generated.

```bash
uv run aray-normalize evaluation/yara-repos/rules/cve_rules
```

Custom output and judge:

```bash
uv run aray-normalize evaluation/yara-repos/rules/cve_rules \
  --output-root /tmp/normalized \
  --output /tmp/norm_report.json \
  --judge-model gpt-4.1 \
  --workers 4
```

Useful options:

| Option | Purpose |
|---|---|
| `--config PATH` | load defaults from TOML; default `.normalizer` |
| `--output-root PATH` | root for mirrored normalized rules |
| `--output PATH` | JSON quality report |
| `--workers N` | parallel normalization workers |
| `--model MODEL` | normalization model |
| `--judge-model MODEL` | independent judge model |
| `--base-url URL` | normalization endpoint |
| `--judge-base-url URL` | separate judge endpoint |
| `--normalize-api-key KEY` | normalization credential |
| `--judge-api-key KEY` | separate judge credential |
| `--no-stream` | disable streaming for both calls |

`.normalizer` example:

```toml
[normalizer]
directories = [
  "evaluation/yara-repos/rules/cve_rules",
  "evaluation/yara-repos/rules/malware",
]
output_root = "evaluation/normalized"
model = "gpt-4.1"
judge_model = "gpt-4.1"
base_url = "http://localhost:11434/v1"
# judge_base_url = "https://api.openai.com/v1"
# normalize_api_key = "not-needed"
# judge_api_key = "sk-..."
workers = 4
```

The normalizer uses the same `CLI > TOML > environment > default` precedence.
Its normalization settings fall back through `NORMALIZE_*`, then `OPENAI_*`.
The legacy TOML `directories` list accepts both individual `.yar` files and
directories.
Calling `aray-normalize` without arguments prints the standard help and exits
with status `0`. Use `aray-normalize --config .normalizer` to explicitly run
only the inputs configured in TOML.
Unless explicitly overridden, the judge inherits the effective normalization
model, endpoint, and credential. API keys are not stored in reports.

An input such as `evaluation/yara-repos/rules/cve_rules/Foo.yar` is written as `evaluation/normalized/cve_rules/Foo.yar`.

Only accepted candidates are retained. A `failed` or `uncertain` verdict removes
any stale output for that rule after retries are exhausted.

Retained regex replacements are validated deterministically with `yara-python` before the LLM judge runs. Judge criteria then include subset correctness, modifier preservation, YARA syntax, and construction cost:

- `passed`: accepted as a valid constructible subset of the original;
- `failed`: the rule is not a valid subset, has invalid syntax, or chooses a clearly more expensive branch when a cheaper constructible alternative exists;
- `uncertain`: treated as a failed quality result by the batch normalizer.

## Test Strategy

The deterministic test suite avoids real model calls by mocking the LLM boundary. This allows deterministic logic and toolchain integration to run locally and in CI without credentials.

```bash
uv run pytest -m "not llm" tests/ -v
```

Coverage includes:

- ASCII, UTF-8, hex, wildcard, jump, wide, `ascii wide`, `fullword`, and `nocase` encodings;
- exact, multiple, ranged, early-window, and invalid offset layouts;
- simple match-count multiplicity and negated-string exclusion;
- linker script generation and ELF placement;
- PE routing, two-pass placement, and byte verification;
- `int16`, little- and big-endian constant patching, and integer-width validation;
- narrow PE32 computed-header checks with the i686 MinGW backend;
- capability preflight for unsupported, infeasible, and unsatisfiable rules;
- generic magic detection and extensions;
- filesize parsing and padding calculations;
- normalization retries and terminal failure;
- structured-output fallback;
- direct scan-only writers;
- compilation followed by real YARA scans;
- runnable ELF execution and optional PE execution under Wine.

Tests that intentionally require normalization or extraction fallback are marked separately:

```bash
uv run pytest -m llm -v
```

They require `OPENAI_API_KEY` and are skipped automatically when it is absent.
Supported fixed rules may still take the deterministic path even inside broader
end-to-end scenarios. Explicitly selecting `not llm` guarantees an offline run.

## Interpreting Results

The current success rate uses a frozen, already-normalized corpus. Telemetry
records zero rules using an LLM, deterministic extraction for all 406 rules that
reached that stage, and 10 preflight terminations. It combines deterministic
constructibility assessment, extraction, format routing and construction,
full-compile toolchain behavior, and final acceptance by YARA. It does not
measure normalization, extraction-model quality, latency, cost, or provider
performance.

The results should not be read as full YARA-language coverage or as a guarantee
that every artifact is executable. In particular, `pe.*` remains outside scope.
Future capability or environment changes require a new full-corpus evaluation
before any updated rate can be published.
