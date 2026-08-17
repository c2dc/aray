# Configuration

Aray can use the official OpenAI API or any OpenAI-compatible endpoint. Normalization and extraction are separate roles and may use different models, providers, credentials, and streaming settings.

For the shortest setup, follow the [Quick Start](index.md#quick-start).

## Requirements

Aray runs on Linux and requires Python 3.12 or newer.

| Dependency | Required for |
|---|---|
| [`uv`](https://docs.astral.sh/uv/) | Python environment and command execution |
| OpenAI-compatible model | normalization and extraction fallback when deterministic handling is insufficient |
| `yara` CLI | manual verification and `aray-eval` |
| GCC and GNU Binutils | runnable Linux ELF output |
| MinGW `x86_64-w64-mingw32-gcc` | runnable PE32+ output |
| MinGW `i686-w64-mingw32-gcc` | runnable PE32 output for supported computed-header checks |
| Ollama | optional fully local model execution |
| Wine | optional PE execution tests |

Scan-only mode does not require GCC, Binutils, or MinGW.

On Debian or Ubuntu:

```bash
sudo apt update
sudo apt install -y yara

# Optional runnable backends
sudo apt install -y gcc binutils gcc-mingw-w64-x86-64 gcc-mingw-w64-i686
```

Install Python dependencies:

```bash
uv sync
```

Commands can then run through `uv run`; activating `.venv` is optional.

## OpenAI

Copy the environment template and set a key:

```bash
cp .env_example .env
```

```dotenv
OPENAI_API_KEY=sk-proj-...
OPENAI_MODEL=gpt-4.1
```

Then run:

```bash
uv run aray data/rules/rule0.yar --scan-only
```

GPT-4.1 is the compatibility default. It is not a requirement; any compatible model can be selected, and supported pre-normalized rules may complete without a model call.

## Local Ollama

```bash
ollama pull phi4:14b

uv run aray data/rules/rule0.yar \
  --model phi4:14b \
  --base-url http://localhost:11434/v1 \
  --no-stream \
  --scan-only
```

When `base_url` is set without an API key, Aray supplies `not-needed` so the OpenAI SDK can construct a client. The local gateway may ignore this credential.

Models known to need `--no-stream` through Ollama include `phi4:14b` and `qwen3.5:4b`. Structured output is still attempted and automatically falls back to prompt-based JSON when tool calls are unsupported.

## Ollama Cloud

Ollama also exposes cloud-hosted models through its locally running client. The
configuration example uses
[`glm-5.2:cloud`](https://ollama.com/library/glm-5.2): requests go to the local
Ollama OpenAI-compatible endpoint, while Ollama routes inference to its cloud
infrastructure.

```bash
# Verify that the local Ollama client can access the cloud-hosted model.
ollama run glm-5.2:cloud

uv run aray-normalize evaluation/yara-repos/rules/cve_rules \
  --model glm-5.2:cloud \
  --judge-model glm-5.2:cloud \
  --base-url http://localhost:11434/v1
```

The equivalent `.normalizer` settings are:

```toml
[normalizer]
directories = ["evaluation/yara-repos/rules/cve_rules"]
model = "glm-5.2:cloud"
judge_model = "glm-5.2:cloud"
base_url = "http://localhost:11434/v1"
```

The reported Aray normalization stage configured `glm-5.2:cloud` for normalization
and judging. Its retained report does not record the endpoint, so it does not
establish that the run used the local Ollama URL shown above. The stage's 416
accepted outputs form a frozen handoff to artifact realization. Those
pre-normalized inputs never reached any configured model during realization, so
the second-stage controls cannot compare providers or extraction models. The two
measurements isolate different stages of one Aray end-to-end lineage;
normalization is not external preprocessing.

When inference is actually required, the endpoint is local but the model is not:
rule content is sent to Ollama Cloud. The `not-needed` placeholder supplied by
Aray only satisfies the OpenAI client library when connecting to the local
gateway; Ollama manages access to its cloud service separately.

## Other Gateways

| Provider | Base URL | Credential |
|---|---|---|
| OpenAI | leave unset | `OPENAI_API_KEY` |
| Ollama | `http://localhost:11434/v1` | optional |
| LiteLLM | typically `http://localhost:4000` | deployment-dependent |
| OpenRouter | `https://openrouter.ai/api/v1` | OpenRouter API key |

Examples:

```bash
# LiteLLM
uv run aray rule.yar --base-url http://localhost:4000 --model llama3 --scan-only

# OpenRouter
uv run aray rule.yar \
  --base-url https://openrouter.ai/api/v1 \
  --model qwen/qwen3.5-flash-02-23 \
  --scan-only
```

OpenRouter throttling has been observed under sustained batch workloads.

## Separate Models per Role

Normalization handles regex replacement, count expansion, and semantic comparison, so it generally benefits more from a capable model. Deterministic extraction handles the supported subset; its fallback has a smaller structured output and can often use a cheaper or local model.

```bash
uv run aray rule.yar \
  --normalize-model gpt-4.1 \
  --extract-model gpt-4.1-mini
```

Roles can also target different providers:

```bash
uv run aray rule.yar \
  --normalize-model gpt-4.1 \
  --normalize-base-url https://api.openai.com/v1 \
  --normalize-api-key "$OPENAI_KEY" \
  --extract-model phi4:14b \
  --extract-base-url http://localhost:11434/v1 \
  --extract-reasoning-effort none \
  --extract-no-stream \
  --scan-only
```

## Environment Variables

| Variable | Purpose |
|---|---|
| `OPENAI_API_KEY` | shared API credential |
| `OPENAI_MODEL` | shared model, default `gpt-4.1` |
| `OPENAI_BASE_URL` | shared OpenAI-compatible endpoint |
| `NORMALIZE_MODEL` | normalization and judge model |
| `EXTRACT_MODEL` | string and constant extraction model |
| `NORMALIZE_BASE_URL` | normalization endpoint |
| `EXTRACT_BASE_URL` | extraction endpoint |
| `NORMALIZE_API_KEY` | normalization credential |
| `EXTRACT_API_KEY` | extraction credential |
| `OPENAI_REASONING_EFFORT` | shared reasoning effort (`none`, `low`, `medium`, `high`, `max`) |
| `NORMALIZE_REASONING_EFFORT` | normalization reasoning effort |
| `EXTRACT_REASONING_EFFORT` | extraction fallback reasoning effort |

Resolution precedence is:

```text
role CLI flag
  > role environment variable
  > shared CLI flag or shared environment variable
  > built-in default
```

For example, `--extract-model` overrides `EXTRACT_MODEL`, which overrides `--model` or `OPENAI_MODEL`.

## CLI Reference

Basic syntax:

```bash
uv run aray RULE_PATH [OPTIONS]
```

| Option | Purpose |
|---|---|
| `--scan-only` | directly write a scanner artifact without GCC or MinGW |
| `--debug` | print node transitions, sections, offsets, and filesize decisions |
| `--graph` | save the LangGraph visualization to `react_graph.png` |
| `--model MODEL` | model shared by both roles |
| `--base-url URL` | endpoint shared by both roles |
| `--normalize-model MODEL` | normalization and judge model |
| `--extract-model MODEL` | extraction model |
| `--normalize-base-url URL` | normalization endpoint |
| `--extract-base-url URL` | extraction endpoint |
| `--normalize-api-key KEY` | normalization credential |
| `--extract-api-key KEY` | extraction credential |
| `--reasoning-effort LEVEL` | reasoning effort shared by both roles |
| `--normalize-reasoning-effort LEVEL` | normalization reasoning effort |
| `--extract-reasoning-effort LEVEL` | extraction fallback reasoning effort |
| `--no-stream` | disable streaming for all model calls |
| `--normalize-no-stream` | disable streaming only for normalization and judging |
| `--extract-no-stream` | disable streaming only for extraction |

Use `uv run aray --help` for the CLI-generated reference.

## Build Modes

### Scan-Only

```bash
uv run aray rule.yar --scan-only
```

- Linux rules produce `build/linux/app`, a minimal ELF64 scanner artifact.
- PE rules produce `build/windows/app.exe`, a minimal PE64 scanner artifact.
- Generic rules always produce `build/generic/output{ext}` without a compiler.

Scan-only ELF and PE files are intended for YARA scanning and are not guaranteed to execute.

### Runnable

```bash
uv run aray rule.yar
```

- Linux uses `gcc -static -nostdlib -no-pie` and a generated linker script.
- PE32+ uses `x86_64-w64-mingw32-gcc`; supported narrow PE32 computed-header checks use `i686-w64-mingw32-gcc`.
- Generic formats remain compiler-free blobs.

## Debugging

```bash
uv run aray data/rules/rule2.yar --debug --scan-only
```

Debug output reports node transitions, normalization decisions, assigned byte sections, PE placement verification, and filesize padding calculations.

Common failures:

| Symptom | Resolution |
|---|---|
| `api_key must be set` | set `OPENAI_API_KEY`, or configure a local `--base-url` |
| malformed or unsupported tool calls | use a compatible model; JSON fallback is automatic |
| streaming errors | add `--no-stream` or a role-specific no-stream flag |
| `gcc` not found | install GCC or use `--scan-only` |
| MinGW executable not found | install `gcc-mingw-w64-x86-64` and `gcc-mingw-w64-i686`, or use `--scan-only` |
| `yara` not found | install the YARA CLI before verification or batch evaluation |

## Configuration Files

`.env_example` contains all model and provider variables.

Batch tools additionally support TOML files:

- `.evaluator` for `aray-eval`;
- `.normalizer` for `aray-normalize`.

Each batch CLI loads its corresponding file from the current directory when run
without arguments. `--config PATH` selects a different file explicitly.

Their precedence is `CLI > TOML > environment > built-in default`. A shared
TOML model or endpoint overrides role-specific environment variables, while a
role-specific TOML key overrides the shared TOML key. Both files contain
inline comments documenting every supported setting and its inheritance.

See [Evaluation](evaluation.md) for their fields and command examples.
