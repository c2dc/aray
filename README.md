<p align="center">
  <img src="docs/site/aray-logo.png" alt="Aray logo" width="180" />
</p>

# Aray

**Generate benign files that match YARA rules, without handling malware.**

<p align="center">
  <a href="https://blackhat.com/us-26/arsenal/schedule/#aray-benign-binary-synthesis-for-signature-validation-without-the-malware-52919">
    <img src="https://img.shields.io/badge/Black%20Hat%20USA%202026-Selected%20for%20Arsenal-d71920?style=for-the-badge&amp;labelColor=111111" alt="Selected for Black Hat USA 2026 Arsenal" />
  </a><br />
  <strong><a href="https://blackhat.com/us-26/arsenal/schedule/#aray-benign-binary-synthesis-for-signature-validation-without-the-malware-52919">Aray: Benign Binary Synthesis for Signature Validation Without the Malware</a></strong>
</p>

[![CI](https://github.com/c2dc/aray/actions/workflows/ci.yml/badge.svg)](https://github.com/c2dc/aray/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/c2dc/aray/graph/badge.svg)](https://codecov.io/gh/c2dc/aray)
[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-d71920)](https://c2dc.github.io/aray/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

<p align="center">
  <img src="docs/site/diagrams/aray-overview.svg" width="760" alt="A YARA rule flows through Aray and becomes a benign synthesized artifact" />
</p>

Aray turns a YARA rule into a Linux ELF, Windows PE, or format-specific byte blob for detection engineering and security testing. An LLM-assisted front end interprets the rule; a conventional, deterministic backend encodes the bytes, solves file-offset constraints, builds the artifact, and exposes the generated sources for inspection.

> **The model interprets the rule. Aray's engineering backend constructs and places every resulting byte.**

```console
$ uv run aray data/rules/rule0.yar --scan-only
$ yara data/rules/rule0.yar build/linux/app
rule0 build/linux/app
```

Validated on **416 real-world rules** from the [Yara-Rules community repository](https://github.com/Yara-Rules/rules). The two official full-compile reports, one using GPT-4.1 and one using GLM-5.2 Cloud, each recorded **404/416 matches (97.1%)** against the same frozen `evaluation/normalized-glm-5.2-stable` corpus. Because normalization was already frozen, these runs measure provider, pipeline, deterministic extraction, and backend compatibility; they do not compare normalization quality.

> [!WARNING]
> Aray is a research prototype under active development. APIs, CLI flags, supported YARA constructs, and artifact formats may change.

## Motivation

Security teams need realistic files to test detection and response workflows, but using live malware makes these exercises risky and expensive. Real samples require isolated infrastructure, strict handling procedures, and specialist oversight. These requirements make Disaster Recovery simulations and end-to-end security-control testing difficult to automate and repeat.

Aray generates benign artifacts that satisfy the static conditions expressed by YARA rules without reproducing the malicious behavior of the samples those rules describe. Teams can use these artifacts to exercise scanners, alert pipelines, incident-response automation, and recovery procedures in a controlled environment. The generated sources and deterministic construction stages also make each artifact inspectable; see [Architecture](docs/site/architecture.md) for the trust boundary and backend design.

The same workflow provides a testbed for YARA rule normalization and autonomous cyber-defense research. Researchers can study how complex detection logic is reduced to supported constraints, how those constraints are encoded into executable formats, and how automated defenses behave when presented with controlled bursts of benign detections. Such experiments can measure alert deduplication, queue saturation, response latency, and resilience to false-positive bursts without introducing live malware. See [Evaluation](docs/site/evaluation.md) for the current corpus, methodology, and end-to-end results.

## Quick Start

The shortest path uses scan-only mode. It writes a minimal scanner artifact directly, so GCC and MinGW are not required.

**Requirements:** Linux, Python 3.12+, [`uv`](https://docs.astral.sh/uv/), the `yara` CLI, and access to an OpenAI-compatible model.

```bash
git clone https://github.com/c2dc/aray.git
cd aray
uv sync

cp .env_example .env
# Edit .env and set OPENAI_API_KEY

uv run aray data/rules/rule0.yar --scan-only
yara data/rules/rule0.yar build/linux/app
```

A successful scan prints:

```text
rule0 build/linux/app
```

The generated `build/linux/app` is benign and contains the byte patterns needed to satisfy the rule.

### Run Fully Locally

With [Ollama](https://ollama.com) and `phi4:14b`, the rule never leaves the machine:

```bash
ollama pull phi4:14b

uv run aray data/rules/rule0.yar \
  --model phi4:14b \
  --base-url http://localhost:11434/v1 \
  --no-stream \
  --scan-only

yara data/rules/rule0.yar build/linux/app
```

No API key is needed for a keyless local gateway. Aray supplies the placeholder required by the OpenAI client library.

### Build a Runnable Executable

Remove `--scan-only` to use the executable backend:

```bash
sudo apt install gcc binutils

uv run aray data/rules/rule0.yar
./build/linux/app
yara data/rules/rule0.yar build/linux/app
```

Windows PE generation additionally requires the x86-64 and i686 MinGW toolchains:

```bash
sudo apt install gcc-mingw-w64-x86-64 gcc-mingw-w64-i686
uv run aray data/rules/rule6.yar
yara data/rules/rule6.yar build/windows/app.exe
```

## Common Tasks

| I want to... | Command |
|---|---|
| Generate a scanner artifact without a compiler | `uv run aray rule.yar --scan-only` |
| Generate a runnable ELF or PE | `uv run aray rule.yar` |
| Verify the output | `yara rule.yar build/linux/app` |
| Trace routing and byte placement | `uv run aray rule.yar --debug` |
| Evaluate rule files or directories | `uv run aray-eval rules/example.yar --scan-only` |
| Normalize rule files or directories | `uv run aray-normalize rules/` |
| Save the LangGraph visualization | `uv run aray rule.yar --graph` |

See [Configuration](docs/site/configuration.md) for model selection, gateways, environment variables, mixed providers, and all CLI options.

## How It Works

Aray separates probabilistic interpretation from deterministic artifact construction.

```text
read + select rule -> optional LLM normalize/judge
                  -> deterministic fixed-evidence extraction
                  -> PE / ELF / generic construction
                  -> YARA verification
```

1. **Read and classify the rule deterministically.** Aray selects the first non-private rule, inlines only its reachable rule dependencies into one standalone rule, and checks whether complex constructs require normalization.
2. **Interpret complex logic with constrained LLM calls.** Only rules containing features such as regex strings, hex wildcards or jumps, `or`, or numeric `N of` expressions enter the normalization-and-judge loop.
3. **Reject known terminal constraints in preflight.** Before extraction or routing, Aray classifies known unsupported `pe.*` conditions, infeasible whole-file hash preimages, and unsatisfiable integer equalities.
4. **Extract supported evidence deterministically.** Aray lexically derives fixed strings, modifiers, positive and negative references, exact and ranged placements, simple match counts, and endian-aware integer checks from the normalized rule. The extraction model is still invoked for compatibility and observability, but supported constructs use the deterministic result as authoritative input.
5. **Construct the artifact deterministically.** Python code assigns offsets, encodes ASCII/hex/wide strings, routes the target format, generates source or binary structures, patches constants, and applies file-size constraints.
6. **Verify independently.** `aray-eval` invokes the real YARA CLI against each generated artifact and records the result. For a single run, use the `yara` command shown in the Quick Start.

LangGraph orchestrates these stages; it does not generate the binaries. The binary construction logic lives in `aray/codegen.py`, `aray/compiler.py`, and `aray/artifact_writer.py`.

## Deterministic Engineering

The backend operates on typed string and constant entries. It does not ask the model to produce C, assembly, linker scripts, PE headers, or arbitrary binary data.

### Exact Layout

- **Linux ELF:** byte witnesses are packed into GNU assembler sections. A generated linker script uses `PT_LOAD FILEHDR PHDRS` and a fixed image base so YARA file offsets map to virtual addresses while keeping unconstrained executables compact. Endian-aware non-nested constants are patched at explicit file offsets.
- **Windows PE:** ordinary PE rules are compiled with MinGW and naturally satisfy MZ and PE-signature checks. Offset or tight-filesize rules use a compact low-alignment PE and a two-pass `.oray` build; Aray probes the section start, computes padding, rebuilds, patches safe DOS-stub range witnesses, and verifies requested placements byte for byte.
- **Generic formats:** PHP, ASP, ZIP, Office, ACE-like archives, PNG, JPEG, GIF, and other non-native magic or low-offset layouts are emitted as plain byte blobs, without an ELF or PE wrapper.

### Compiler-Free Writers

`--scan-only` bypasses GCC and MinGW. Aray writes minimal ELF64 or PE32/PE32+ structures directly and places rule-driven bytes at their assigned file offsets. These files are intended for scanning; they are not substitutes for the runnable artifacts produced by the compiler backends.

<p align="center">
  <img src="docs/site/diagrams/aray-pipeline-determinism-artifacts.svg" width="760" alt="Aray artifact backends and their reproducibility properties" />
</p>

### Auditable Output

The build directory contains the normalized rule and generated intermediates:

| Target | Output | Inspectable intermediates |
|---|---|---|
| Linux ELF | `build/linux/app` | `normalized_rule.yar`, `main.S`, `linker.ld` |
| Windows PE | `build/windows/app.exe` | `normalized_rule.yar`, `main.c` or `main.S` |
| Generic blob | `build/generic/output{ext}` | `normalized_rule.yar` |

The layout algorithm is deterministic for a given typed representation. Byte-for-byte reproducibility is not promised when external toolchains vary or when a `filesize` condition requires random padding.

Read [Architecture](docs/site/architecture.md) for the layout contracts, routing rules, constant encoding, retry behavior, and backend limitations.

## Where the LLM Is Used

Aray keeps the nondeterministic boundary narrow and explicit:

- **Normalization:** complex YARA constructs are simplified into a constructible subset supported by the backends. For `or` conditions, YARA precedence is preserved and complete branches are ranked by feasibility, filesize/padding cost, offset and format constraints, and required evidence. A deterministic pre-check skips this phase for already-supported rules.
- **Judging:** before the model judge runs, Aray restores retained fixed literals and fixed hex values from the original rule, derives canonical witnesses for linear hex wildcards and jumps, and validates regex and complex-hex witnesses with `yara-python`. A model then verifies remaining subset semantics and branch cost. A failed verdict retries normalization up to three times; three failures stop the pipeline before extraction or construction. An `uncertain` verdict currently proceeds.
- **Extraction calls and deterministic authority:** structured extraction is attempted first, with a validated prompt-based JSON fallback for models without tool-call support. For supported fixed constructs, Aray then parses the normalized YARA source deterministically and treats that representation as authoritative. This prevents model omissions, escape corruption, false offsets, and byte-order mistakes from reaching construction.

Schema validation guarantees structure, not semantic correctness. The deterministic parser protects supported fixed constructs, while normalization and unsupported expressions can still introduce semantic gaps. Corpus evaluation therefore uses the YARA engine as an external oracle. Different models can be assigned to normalization and extraction, including local OpenAI-compatible models.

## Supported Artifacts

| Capability | ELF | PE | Generic |
|---|:---:|:---:|:---:|
| ASCII strings | Yes | Yes | Yes |
| Hex byte patterns | Yes | Yes | Yes |
| YARA `wide`, `ascii wide`, `fullword`, `nocase` | Yes | Yes | Yes |
| Multiple `at` and simple `in` constraints | Yes | Yes | Yes |
| Simple `#string` match counts | Yes | Yes | Yes |
| `int16`, `uint16` / `uint32`, and big-endian variants | Yes | Limited in runnable PE | Yes |
| Nested PE-signature check | N/A | Native | N/A |
| Narrow PE32 computed-header checks | N/A | Yes, with i686 MinGW | N/A |
| Compiler-free `--scan-only` | Yes | Yes | Always compiler-free |
| Runnable output | Yes | Yes | Format-dependent blob |

Filesize comparisons using `>`, `>=`, `<`, `<=`, or `==`, with optional `KB`, `MB`, or `GB` suffixes, are parsed and applied after construction. Compact runnable ELF and low-alignment PE layouts satisfy many tight upper bounds; impossible bounds still produce a warning.

See the [sample rule catalog](data/rules/CATALOG.md) for focused examples of each supported path.

## Evaluation

Aray has two official full-compile reports over 416 public rules from [Yara-Rules/rules](https://github.com/Yara-Rules/rules):

| Provider/model configuration | Official report | Matches | Success rate | Duration |
|---|---|---:|---:|---:|
| GPT-4.1 | `evaluation/reports/2026-08-14T09-32-09-gpt-4.1/eval_report.json` | 404 / 416 | **97.1%** | 21m 52.6s |
| GLM-5.2 Cloud (`glm-5.2:cloud`) | `evaluation/reports/2026-08-14T13-07-22-eval-glm-5.2/eval_report.json` | 404 / 416 | **97.1%** | 51m 10.5s |

Both runs consume the identical frozen `evaluation/normalized-glm-5.2-stable` corpus and no rule entered the normalization-and-judge loop. They therefore measure compatibility of the configured provider with the pipeline, authoritative deterministic extraction, full-compile toolchains, backends, and final YARA verification. They are not a comparison of normalization quality.

Both schema 2.1 reports contain all 416 per-rule results. The same 12 rules did not match in each run: seven were classified as unsupported `pe.*` conditions, two as infeasible whole-file hash predicates, one as an unsatisfiable out-of-range `uint32` equality, and two as construction failures because `i686-w64-mingw32-gcc` was not installed in the evaluation environment. The published 97.1% rate is the observed result and is not adjusted for those missing-toolchain failures.

See [Evaluation](docs/site/evaluation.md) for the exact failure categories, the seven `pe.*` rules, methodology, report provenance, and batch commands. Full-corpus runs with smaller models such as Phi and Qwen are planned; no results are published for them yet.

## Tests

The deterministic suite makes no real LLM calls. Models are mocked while unit and integration tests exercise byte encoding, routing, offset assignment, linker generation, constant patching, direct artifact writing, retry behavior, compilation, execution, and YARA scanning.

```bash
# Unit and integration tests, always excluding real LLM calls
uv run pytest -m "not llm" tests/ -v

# Real-model end-to-end tests
uv run pytest -m llm -v
```

ELF integration tests require GCC and YARA. PE integration tests require MinGW and YARA; execution under Wine is optional.

## Limitations

- Aray implements a useful subset of YARA rather than the full language. Complex constructs are normalized and may lose semantics.
- LLM normalization can be wrong even when its response satisfies the schema. Deterministic extraction covers supported fixed constructs, but unsupported condition semantics remain.
- The normal `aray` command constructs an artifact but does not automatically run YARA; verify manually or use `aray-eval`.
- Exact PE data normally cannot occupy structural header/code bytes. Aray can use safe DOS-stub slack for supported early ranges and routes non-PE low-offset layouts to generic artifacts, but arbitrary PE header placement remains unsupported.
- `uint32(uint32(...))` is treated as a PE indicator and may misroute an unusual non-PE rule.
- Conditions using the YARA `pe` module remain outside scope. Preflight classifies them as `unsupported`; they do not trigger PE routing or construction.
- Narrow PE32 checks of the form `uint16(uint32(0x3c)+delta)` are supported through `i686-w64-mingw32-gcc`; broader computed header expressions remain limited.
- Fixed whole-file cryptographic hashes cannot generally be synthesized, and out-of-range integer equalities may be intrinsically unsatisfiable.
- Rulesets process only the first non-private rule. Reachable helper-rule dependencies are inlined deterministically; unrelated and subsequent rules are never sent to the LLM.

## Documentation

- [Project website](https://c2dc.github.io/aray/)
- [Architecture and deterministic backends](docs/site/architecture.md)
- [Configuration and model providers](docs/site/configuration.md)
- [Evaluation and batch tools](docs/site/evaluation.md)
- [Sample rule catalog](data/rules/CATALOG.md)

Build and preview the documentation locally:

```bash
uv sync --group docs
uv run mkdocs serve
```

## Project Layout

```text
aray/
  cli.py              CLI and configuration resolution
  graph.py            Pipeline orchestration
  nodes.py            Rule reading, interpretation, and routing
  codegen.py          Assembly, linker, and PE source generation
  compiler.py         Runnable ELF/PE backends and patching
  artifact_writer.py  Direct ELF64/PE32/PE32+/generic writers
  evaluator.py        Batch construction and YARA verification
  diagnostics.py      Bounded report diagnostics, manifests, and failure data
  yara_extraction.py  Deterministic fixed-evidence extraction
  normalizer.py       Batch normalization and judging
data/rules/           Focused example rules
evaluation/           Public rule corpus
tests/                Unit, integration, and end-to-end tests
```

## Project Affiliation and Research Team

Aray is a project of the **Lab-C2DC - Laboratory of Command and Control and Cyber-security** at the [Aeronautics Institute of Technology (ITA)](https://www.ita.br). The project is part of a research collaboration among ITA, the University of São Paulo (USP), iFood, and Texas A&M University (TAMU).

Aray was conceived and originally developed by **Emanuel Valente**.

The researchers involved in the project are:

- **Prof. Lourenço Alves Pereira Júnior** - ITA
- **Prof. Marcus Botacin** - Texas A&M University
- **Emanuel Valente** - PhD student at USP | Principal Cybersecurity Engineer at iFood.
- **Leonardo Chahud** - PhD student at ITA

## License

Copyright 2026 C2DC contributors.

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE)
for attribution information.
