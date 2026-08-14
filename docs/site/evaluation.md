# Evaluation

Aray includes two batch tools:

- `aray-eval` runs the complete pipeline, invokes the real YARA CLI on each artifact, and records end-to-end matches.
- `aray-normalize` evaluates only rule normalization and writes normalized rules to a mirrored directory tree.

## Published Results

The only official published results are the following two full-compile reports
over 416 rules from [Yara-Rules/rules](https://github.com/Yara-Rules/rules):

| Provider/model configuration | Official report | Passed | Failed | Success rate | Duration |
|---|---|---:|---:|---:|---:|
| GPT-4.1 | `evaluation/reports/2026-08-14T09-32-09-gpt-4.1/eval_report.json` | 404 | 12 | **97.1%** | 21m 52.6s |
| GLM-5.2 Cloud (`glm-5.2:cloud`) | `evaluation/reports/2026-08-14T13-07-22-eval-glm-5.2/eval_report.json` | 404 | 12 | **97.1%** | 51m 10.5s |

Both reports use exactly the same frozen input corpus and corpus hash:
`evaluation/normalized-glm-5.2-stable` and
`0ad4e608372828e1aaa996c6f1f15bd1629e4c8d4f087316f98b62caff5813a5`.
The rules had already been normalized, and no result entered the normalization
and judge loop. The reports measure
compatibility of each configured provider with the pipeline, deterministic
extraction, full-compile toolchains and backends, and final YARA verification.
For supported fixed constructs, deterministic extraction is authoritative; an
extraction-model response cannot override it.

These results must not be read as a model normalization leaderboard or combined
with earlier experiments, targeted reruns, or projections. Full-corpus runs with
smaller models such as Phi and Qwen are planned, but no results are published for
them yet.

### Report Completeness and Environment

Both official files use diagnostic schema 2.1 and contain all 416 per-rule
records. Their metadata and serialized results agree on 404 passed, 12 failed,
and zero skipped. The two runs used `scan_only=false`, structured output, one
worker, the same recorded Git commit, and the same Linux, Python, YARA, GCC, and
MinGW x86-64 environment. Both reports record a dirty worktree, so the commit ID
alone does not fully identify the source snapshot.

The environment did not contain `i686-w64-mingw32-gcc`. Two PE32 rules reached
construction but could not produce an artifact for that reason. They remain
failures in the observed 404/416 result; no adjusted success rate is published.

### Official Failures

The same 12 rules failed in both official runs:

| Category | Count | Official cases |
|---|---:|---|
| Unsupported YARA `pe.*` conditions | 7 | `APT_CrashOverride`, `APT_Shamoon_StoneDrill`, `MALW_Batel`, `MALW_IcedID`, `MALW_Pyinstaller`, `RANSOM_Stampado`, `peid` |
| Infeasible whole-file hash predicates | 2 | `APT_Grasshopper`, `RAT_CrossRAT` |
| Unsatisfiable out-of-range `uint32` equality | 1 | `APT_Derusbi` |
| Missing i686 MinGW compiler | 2 | `RAT_FlyingKitten`, `packer_compiler_signatures` |

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
uv run aray-eval evaluation/rules/cve_rules/example.yar --scan-only
```

Evaluate one directory:

```bash
uv run aray-eval evaluation/rules/cve_rules --scan-only
```

Evaluate any combination of files and directories with parallel workers:

```bash
uv run aray-eval \
  evaluation/rules/cve_rules \
  evaluation/rules/malware/example.yar \
  --workers 4 \
  --scan-only \
  --output eval_report.json
```

Rerun only failed cases from an earlier report:

```bash
REPORT=evaluation/reports/<run>/eval_report.json

uv run aray-eval \
  $(uv run python -c '
import json, sys
for result in json.load(open(sys.argv[1]))["results"]:
    if result["status"] == "failed":
        print(result["rule_path"])
' "$REPORT") \
  --model glm-5.2:cloud \
  --base-url http://localhost:11434/v1 \
  --workers 1 \
  --output evaluation/reports/failed-retest/eval_report.json
```

Positional paths replace the configured `.evaluator` input directories. The
targeted report contains only the selected failures; it is not automatically
merged with the earlier full-corpus report.

The two official schema 2.1 reports contain every failed record, so this command
can select all 12 cases from either report. A targeted rerun remains a separate
experiment and does not replace the published full-corpus baseline.

Useful options:

| Option | Purpose |
|---|---|
| `--config PATH` | load defaults from TOML; default `.evaluator` |
| `--workers N` | run multiple rules concurrently |
| `--output PATH` | choose the JSON report path |
| `--keep-artifacts` | preserve per-rule temporary builds |
| `--scan-only` | avoid GCC and MinGW |
| `--model`, `--base-url` | shared model configuration |
| role-specific model, URL, key, and streaming flags | same semantics as `aray` |

Without `--output`, reports are written to `evaluation/reports/<timestamp>/eval_report.json`.
The CLI prints the report's absolute path after writing it. When
`--keep-artifacts` is enabled, it also prints the absolute temporary directory
preserved for each evaluated rule.

Evaluation reports use the additive diagnostic schema
`aray.diagnostic-evaluation` version `2.1`. Existing result fields remain
available, with environment/tool metadata, structured failure fingerprints,
pipeline node timings and final state, compiler and YARA diagnostics, bounded
tracebacks, and SHA-256 manifests added for troubleshooting. Text is truncated
and credential-shaped fields and values are redacted; API keys are never
written. Report-level summaries include deterministic failure clusters and
disposition counts. Schema 2.1 also records corpus, source, selected-rule, and
normalized-rule hashes plus Git and toolchain provenance, and refuses to write a
report if the serialized result count differs from `metadata.total`.

`status` remains the coarse execution outcome: `passed`, `failed`, or `skipped`.
`disposition` explains the semantic outcome, including `matched`, `unsupported`,
`infeasible`, `unsatisfiable`, `normalization_failed`, `construction_failed`,
and `unexplained_mismatch`. A preflight disposition still has `status="failed"`
because no matching artifact was produced.

Each result also includes `artifact_analysis`, which records:

- artifact size, SHA-256, initial header bytes, and filesize satisfaction;
- every extracted string identifier, format, expected bytes, required and
  observed match counts, expected offset, and first observed offsets;
- expected and observed constant bytes, width, byte order, and offset status;
- unsupported `hash.*`, `pe.*`, and `math.*` references detected in the rule.

Compiler invocations retain sanitized argv, return code, duration, stdout, and
stderr. Pipeline exceptions retain a bounded traceback and the last known state,
even when no final LangGraph state is returned. Binary contents are not embedded
in the report.

Calling `aray-eval` without arguments prints the standard help and exits with
status `0`. To process paths from `.evaluator` without positional inputs, pass
the configuration option explicitly: `aray-eval --config .evaluator`.

### Evaluator Configuration

`.evaluator` is a TOML file:

```toml
[evaluator]
directories = [
  "evaluation/rules/cve_rules",
  "evaluation/rules/malware",
]
model = "gpt-4.1"
base_url = "http://localhost:11434/v1"
# normalize_model = "gpt-4.1"
# extract_model = "gpt-4.1-mini"
# normalize_api_key = "sk-..."
# extract_api_key = "not-needed"
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

```json
{
  "schema": {
    "name": "aray.diagnostic-evaluation",
    "version": "2.1"
  },
  "metadata": {
    "timestamp": "2026-03-08T14:22:01",
    "total": 42,
    "passed": 35,
    "failed": 5,
    "skipped": 2,
    "duration_seconds": 183.4,
    "corpus_sha256": "...",
    "config": {
      "model": "gpt-4.1",
      "workers": 4,
      "scan_only": true
    }
  },
  "summary": {
    "status_counts": {"passed": 35, "failed": 5, "skipped": 2},
    "disposition_counts": {"matched": 35, "unsupported": 3, "infeasible": 2, "skipped": 2},
    "failure_categories": {"infeasible_constraint": 2, "unsupported_capability": 3}
  },
  "failure_clusters": [],
  "results": [
    {
      "rule_path": "evaluation/rules/cve_rules/CVE-2010-0805.yar",
      "rule_name": "MSIETabularActivex",
      "status": "passed",
      "disposition": "matched",
      "error": null,
      "yara_stdout": "MSIETabularActivex /tmp/.../linux/app\n",
      "yara_returncode": 0,
      "normalize_model": "gpt-4.1",
      "extract_model": "gpt-4.1-mini",
      "normalize_verdict": "passed",
      "source_sha256": "...",
      "selected_rule_sha256": "...",
      "normalized_rule_sha256": "...",
      "failure": null,
      "pipeline": {
        "node_sequence": ["read_yara", "assess_constructibility", "extract_strings", "compile"],
        "nodes": [],
        "final_state": {}
      },
      "compiler_subprocesses": [],
      "yara_stderr": "",
      "artifacts": [
        {"path": "linux/app", "size": 1016, "sha256": "..."}
      ],
      "generated_files": [],
      "artifact_analysis": {
        "size_bytes": 1016,
        "strings": [],
        "constants": []
      }
    }
  ]
}
```

Each result distinguishes pipeline errors, normalization failures, preflight
classifications, build failures, YARA errors, and successful or unsuccessful
scans. Failure fingerprints are deterministic operational groupings;
byte-level `artifact_analysis` provides the finer evidence needed to separate
otherwise identical YARA no-match results.

## Normalization Evaluator

`aray-normalize` runs normalization without extraction or artifact construction. It writes each normalized rule under an output tree that mirrors the input and asks a separate model to assess quality.

Normalize one file:

```bash
uv run aray-normalize evaluation/rules/cve_rules/example.yar
```

The result of a standalone file is written directly below `--output-root`, for
example `evaluation/normalized/example.yar`. Directory inputs retain their
mirrored directory structure. At the end, the CLI lists the absolute path of
every normalized file and the report it generated.

```bash
uv run aray-normalize evaluation/rules/cve_rules
```

Custom output and judge:

```bash
uv run aray-normalize evaluation/rules/cve_rules \
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
  "evaluation/rules/cve_rules",
  "evaluation/rules/malware",
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

An input such as `evaluation/rules/cve_rules/Foo.yar` is written as `evaluation/normalized/cve_rules/Foo.yar`.

The normalized file is retained even when the judge returns `failed` or `uncertain`, making the output available for inspection and dataset work.

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

Real-model end-to-end tests are marked separately:

```bash
uv run pytest -m llm -v
```

They require `OPENAI_API_KEY` and are skipped automatically when it is absent. Explicitly selecting `not llm` is recommended for a guaranteed offline run, even when credentials exist in the environment.

## Interpreting Results

The official success rates use a frozen, already-normalized corpus. They combine
provider and extraction-call compatibility, authoritative deterministic
fixed-evidence extraction, deterministic format routing and construction,
full-compile toolchain behavior, and final acceptance by YARA. They do not
measure or compare normalization quality.

The results should not be read as full YARA-language coverage or as a guarantee
that every artifact is executable. In particular, `pe.*` remains outside scope.
Future capability or environment changes require a new full-corpus evaluation
before any updated rate can be published.
