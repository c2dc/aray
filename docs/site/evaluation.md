# Evaluation

Aray includes two batch tools:

- `aray-eval` runs the complete pipeline, invokes the real YARA CLI on each artifact, and records end-to-end matches.
- `aray-normalize` evaluates only rule normalization and writes normalized rules to a mirrored directory tree.

## Published Results

The published experiments used 416 rules from [Yara-Rules/rules](https://github.com/Yara-Rules/rules), covering exploit kits, CVEs, malware families, webshells, packers, email, and cryptography.

### Normalization

Two normalization-only runs used the same 416-rule corpus and one worker. In
each run, the normalization model also acted as the judge.

| Metric | GPT-4.1 | GLM-5.2 Cloud |
|---|---:|---:|
| Corpus size | 416 | 416 |
| Deterministic fast path | 179 (43.0%) | 179 (43.0%) |
| Rules sent to the model | 237 | 237 |
| Accepted after model call | 225 / 237 (94.9%) | 233 / 237 (98.3%) |
| Failed normalization | 12 | 4 |
| Total accepted | 404 / 416 (97.1%) | 412 / 416 (99.0%) |
| Reported duration, one worker | 2031.920 s | 3221.641 s |

[`glm-5.2:cloud`](https://ollama.com/library/glm-5.2) was accessed through the
Ollama client running locally at `http://localhost:11434/v1`; inference ran in
Ollama Cloud. GPT-4.1 inference was also cloud-hosted. This comparison is
therefore between two remotely hosted models, not between local and cloud
inference.

The four GLM-5.2 failures comprised one CVE rule, two malware rules, and one
exploit-kit rule. The judge identified two outputs missing the YARA `rule`
keyword, one incorrect rewrite of anonymous-string count semantics, and one
defined string left unreferenced.

These are self-judged acceptance rates: GPT-4.1 judged GPT-4.1 outputs and
GLM-5.2 judged GLM-5.2 outputs. They are useful for measuring each configured
normalization pipeline, but they are not independent semantic validation. The
duration values also include provider and network behavior from runs performed
at different times, so they should not be treated as a controlled latency
benchmark.

The deterministic fast path skips normalization and judging, not extraction.
The GLM-5.2 full-compile experiment processed the original rules through the
complete pipeline, assigning GLM-5.2 to normalization, judging, and extraction.
The scan-only and Qwen3.5:9b experiments instead consumed the stored
GPT-4.1-normalized corpus.

### End-to-End Synthesis

Full-compile results include the compiler toolchains and runnable-backend
constraints:

| Collection | Rules | GPT-4.1 full compile | GLM-5.2 full compile |
|---|---:|---:|---:|
| antidebug_antivm | 1 | 1 (100%) | 1 (100%) |
| crypto | 1 | 1 (100%) | 1 (100%) |
| cve_rules | 14 | 10 (71%) | 12 (86%) |
| email | 11 | 11 (100%) | 9 (82%) |
| exploit_kits | 11 | 11 (100%) | 11 (100%) |
| malware | 363 | 285 (79%) | 307 (85%) |
| packers | 6 | 3 (50%) | 4 (67%) |
| webshells | 9 | 8 (89%) | 8 (89%) |
| **Total** | **416** | **330 (79.3%)** | **353 (84.9%)** |

GLM-5.2 produced 23 more matching artifacts than GPT-4.1 in full-compile mode,
an improvement of 5.5 percentage points over the corpus. Most of the net gain
came from malware rules (307 versus 285), while GPT-4.1 performed better on the
email collection (11 versus 9). The runs reported durations of 5638.418 seconds
for GPT-4.1 and 5114.080 seconds for GLM-5.2, each with one worker. Because they
used different providers and were run at different times, these durations are
operational observations rather than a controlled latency benchmark.

Scan-only results use compiler-free scanner artifacts and are therefore shown
separately:

| Collection | Rules | GPT-4.1 scan-only | phi4:14b scan-only |
|---|---:|---:|---:|
| antidebug_antivm | 1 | 1 (100%) | 0 (0%) |
| crypto | 1 | 1 (100%) | 1 (100%) |
| cve_rules | 14 | 12 (86%) | 12 (86%) |
| email | 11 | 11 (100%) | 10 (91%) |
| exploit_kits | 11 | 11 (100%) | 6 (55%) |
| malware | 363 | 296 (82%) | 258 (71%) |
| packers | 6 | 3 (50%) | 1 (17%) |
| webshells | 9 | 9 (100%) | 6 (67%) |
| **Total** | **416** | **344 (82.7%)** | **294 (70.7%)** |

GPT-4.1 scan-only used structured output and streaming through an
OpenAI-compatible gateway. Its artifact distribution was 198 ELF, 123 PE, and
23 generic files. The phi4:14b run used Ollama on an RTX 3060 with 12 GB VRAM,
made no cloud API calls, and reported a duration of 4220.128 seconds with one
worker.

Of the 63 GLM-5.2 full-pipeline failures, 46 were post-synthesis YARA
mismatches, 11 were compiler failures, and 6 were other model, parsing, or
construction errors. Success means that the generated artifact produced an
actual match when scanned by the YARA CLI. A valid model response or successful
build alone does not count.

### Fully Local Qwen3.5:9b Experiment

[`qwen3.5:9b`](https://ollama.com/library/qwen3.5) was evaluated as a smaller
model running entirely through a local Ollama endpoint. It consumed the stored
normalized corpus and used the full-compile backends. Qwen3.5:9b was configured
for normalization, judging, string extraction, and constant extraction; all
model endpoints resolved to `http://localhost:11434/v1`. The run used one
worker and structured output on the same AMD Ryzen 9 7900X, 64 GB RAM, and
NVIDIA RTX 3060 12 GB environment as the phi4:14b experiment.

| Collection | Rules | Qwen3.5:9b full compile |
|---|---:|---:|
| antidebug_antivm | 1 | 0 (0%) |
| crypto | 1 | 1 (100%) |
| cve_rules | 14 | 8 (57%) |
| email | 11 | 4 (36%) |
| exploit_kits | 11 | 3 (27%) |
| malware | 363 | 118 (33%) |
| packers | 6 | 1 (17%) |
| webshells | 9 | 2 (22%) |
| **Total** | **416** | **137 (32.9%)** |

The run completed in 22512.680 seconds (approximately 6.25 hours). Each of the
137 successes represents an artifact that was synthesized locally and then
independently accepted by the YARA CLI. The result is reported separately from
phi4:14b because Qwen used full compilation while phi4 used scan-only artifacts.

| Failure category | Count | Share of 279 failures |
|---|---:|---:|
| Empty LLM response | 124 | 44.4% |
| YARA mismatch after synthesis | 114 | 40.9% |
| Malformed hex extraction | 11 | 3.9% |
| Schema validation failure | 9 | 3.2% |
| Non-JSON LLM response | 8 | 2.9% |
| Compiler failure | 6 | 2.2% |
| Other model or construction error | 6 | 2.2% |
| Integer conversion error | 1 | 0.4% |
| **Total** | **279** | **100.0%** |

The two dominant categories expose distinct improvement targets. Empty
responses call for bounded retries and more robust local structured-output
handling. YARA mismatches require semantic checks after extraction and a
feedback loop that retries synthesis using scanner results. Malformed hex and
schema failures can be detected deterministically before construction.

Future local-model work will evaluate Qwen in scan-only mode for a controlled
comparison with phi4:14b, add retries for empty or invalid responses, validate
extracted hex and constants before code generation, and use failed YARA scans
to guide targeted extraction or synthesis retries.

## Batch Evaluation

Evaluate one directory:

```bash
uv run aray-eval evaluation/rules/cve_rules --scan-only
```

Evaluate several directories with parallel workers:

```bash
uv run aray-eval \
  evaluation/rules/cve_rules \
  evaluation/rules/malware \
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
| role-specific model, URL, key, and streaming flags | same semantics as `aray` |

Without `--output`, reports are written to `evaluation/reports/<timestamp>/eval_report.json`.

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
`NORMALIZE_*` and `EXTRACT_*` environment variables. Positional directories
replace the configured directory list. API keys are never printed or included
in reports.

Index files named `index.yar`, `*_index.yar`, or `index_*.yar`, and files beginning with an `include` directive, are skipped. Rulesets process only the first non-private rule.

### Report Shape

```json
{
  "metadata": {
    "timestamp": "2026-03-08T14:22:01",
    "total": 42,
    "passed": 35,
    "failed": 5,
    "skipped": 2,
    "duration_seconds": 183.4,
    "config": {
      "model": "gpt-4.1",
      "workers": 4,
      "scan_only": true
    }
  },
  "results": [
    {
      "rule_path": "evaluation/rules/cve_rules/CVE-2010-0805.yar",
      "rule_name": "MSIETabularActivex",
      "status": "passed",
      "error": null,
      "yara_stdout": "MSIETabularActivex /tmp/.../linux/app\n",
      "yara_returncode": 0,
      "normalize_model": "gpt-4.1",
      "extract_model": "gpt-4.1-mini",
      "normalize_verdict": "passed"
    }
  ]
}
```

Each result distinguishes pipeline errors, normalization failures, build failures, YARA errors, and successful or unsuccessful scans.

## Normalization Evaluator

`aray-normalize` runs normalization without extraction or artifact construction. It writes each normalized rule under an output tree that mirrors the input and asks a separate model to assess quality.

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
Unless explicitly overridden, the judge inherits the effective normalization
model, endpoint, and credential. API keys are not stored in reports.

An input such as `evaluation/rules/cve_rules/Foo.yar` is written as `evaluation/normalized/cve_rules/Foo.yar`.

The normalized file is retained even when the judge returns `failed` or `uncertain`, making the output available for inspection and dataset work.

Judge criteria include pattern preservation, modifier preservation, YARA syntax, and simplicity:

- `passed`: accepted as semantically equivalent and valid;
- `failed`: patterns or semantics were lost, or syntax is invalid;
- `uncertain`: treated as a failed quality result by the batch normalizer.

## Test Strategy

The deterministic test suite avoids real model calls by mocking the LLM boundary. This allows deterministic logic and toolchain integration to run locally and in CI without credentials.

```bash
uv run pytest -m "not llm" tests/ -v
```

Coverage includes:

- ASCII, hex, wildcard, jump, and wide encodings;
- exact, multiple, and invalid offset layouts;
- linker script generation and ELF placement;
- PE routing, two-pass placement, and byte verification;
- little-endian constant patching;
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

The published success rates combine both sides of the system:

- nondeterministic normalization and extraction quality;
- deterministic format routing and construction capability;
- compatibility with the external compiler when full-compile mode is used;
- final acceptance by YARA.

They should not be read as full YARA-language coverage or as a guarantee that every artifact is executable. Scan-only results specifically measure scanner artifacts, while full-compile results include runnable backend constraints and toolchain behavior.
