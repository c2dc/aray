---
title: Aray | Benign YARA-Matching Artifact Generator
description: Aray converts YARA rules into benign Linux ELF, Windows PE, and format-specific artifacts for detection engineering and security testing.
hide:
  - navigation
  - toc
---

<section class="aray-hero">
  <div class="aray-hero__copy">
    <p class="aray-kicker">Detection engineering without live malware</p>
    <h1>Generate benign files that match YARA rules.</h1>
    <p class="aray-lead">Aray parses supported detection logic deterministically, uses LLM assistance only when needed, and constructs inspectable Linux ELF, Windows PE, and format-specific artifacts with conventional engineering backends.</p>
    <a class="aray-recognition" href="https://blackhat.com/us-26/arsenal/schedule/#aray-benign-binary-synthesis-for-signature-validation-without-the-malware-52919" aria-label="Aray was selected for presentation at Black Hat USA 2026 Arsenal">
      <span>Black Hat USA 2026</span>
      <strong>Selected for Arsenal</strong>
    </a>
    <div class="aray-actions">
      <a class="md-button md-button--primary" href="#quick-start">Get started</a>
      <a class="md-button" href="architecture/">Explore the architecture</a>
    </div>
  </div>
  <div class="aray-hero__visual">
    <img src="aray-logo.png" alt="Aray robot inspecting ELF and PE artifacts">
  </div>
</section>

<p align="center">
  <img src="diagrams/aray-overview.svg" width="760" alt="A YARA rule flows through Aray and becomes a benign synthesized artifact">
</p>

<div class="aray-metrics" markdown>

<div class="aray-metric" markdown>

<strong>416</strong>

Real-world rules evaluated

</div>

<div class="aray-metric" markdown>

<strong>97.6%</strong>

Official full-compile match rate

</div>

<div class="aray-metric" markdown>

<strong>406</strong>

YARA matches in the current baseline

</div>

<div class="aray-metric" markdown>

<strong>3</strong>

Artifact families: ELF, PE, generic

</div>

</div>

## Why Aray

Testing security controls with live malware creates avoidable risk, operational overhead, and handling requirements. Aray generates non-malicious artifacts that satisfy static YARA conditions without reproducing the malicious behavior of the samples those rules describe.

Use the artifacts to exercise:

- scanner and alert pipelines;
- incident-response and recovery automation;
- detection-rule validation;
- controlled false-positive and alert-volume experiments;
- research into YARA normalization and autonomous cyber defense.

!!! warning "Research prototype"
    Aray implements a useful subset of YARA and uses probabilistic models for rule interpretation. Always verify generated output with YARA and use it only in authorized testing environments.

## A Narrow Trust Boundary

<div class="aray-boundary" markdown>

<div markdown>

### Aray interprets

Complex rules may be normalized and judged by an LLM. Deterministic canonicalization restores retained fixed values, constructibility preflight rejects known terminal constraints, and supported strings, modifiers, placements, counts, and endian-aware integer checks are extracted directly into Pydantic models. Extraction uses a model only for syntax outside that subset.

</div>

<div markdown>

### Conventional code constructs

Python, assemblers, linkers, and direct binary writers own byte encoding, offset placement, header construction, constant patching, and filesize constraints.

</div>

<div markdown>

### YARA verifies

The batch evaluator invokes the real YARA CLI. A valid model response or a successful build does not count as success unless the resulting artifact matches.

</div>

</div>

```text
read + select rule -> optional LLM normalize/judge
                  -> deterministic constructibility preflight
                  -> deterministic fixed-evidence extraction
                  -> PE / ELF / generic construction
                  -> YARA verification
```

[Read the architecture details](architecture.md){ .md-button }

## Quick Start

The shortest path uses scan-only mode. It writes a minimal scanner artifact directly, without GCC or MinGW.

```console
$ git clone https://github.com/c2dc/aray.git
$ cd aray
$ uv sync
$ cp .env_example .env
$ uv run aray data/rules/rule0.yar --scan-only
$ yara data/rules/rule0.yar build/linux/app
rule0 build/linux/app
```

Requirements are Linux, Python 3.12+, [`uv`](https://docs.astral.sh/uv/), and the YARA CLI. Rules that require normalization or extraction fallback also need access to an OpenAI-compatible model; Aray supports fully local model execution through Ollama.

[Configure models and providers](configuration.md){ .md-button .md-button--primary }
[Browse focused examples](examples.md){ .md-button }

## Deterministic Backends

| Target | Construction strategy | Output |
|---|---|---|
| Linux ELF | GNU assembler sections and a linker script, or a direct minimal ELF64 writer | `build/linux/app` |
| Windows PE | MinGW with offset-aware two-pass placement, or a direct minimal PE32/PE32+ writer | `build/windows/app.exe` |
| Generic | Direct byte-blob writer preserving format magic at offset zero | `build/generic/output{ext}` |

Generated sources and normalized rules remain available in the build directory for inspection. The model never emits C, assembly, linker scripts, PE headers, or complete binary data.

## Published Evaluation

Aray was validated against 416 public rules from the Yara-Rules community repository. End-to-end success means the generated artifact produced an actual match when scanned by the YARA CLI.

| Corpus | Mode | Matches | Rules using an LLM |
|---|---|---:|---:|
| Yara-Rules, 416 normalized rules | Full compile, 1 worker | **406 / 416 (97.6%)** | **0** |

All 416 rules bypassed normalization. The 406 constructible rules used deterministic string and constant extraction, while seven unsupported `pe.*` rules, two infeasible whole-file hash preimages, and one unsatisfiable integer value stopped at capability preflight before extraction. There were zero unexplained mismatches and zero construction failures.

The extraction role was configured in separate control runs as GLM-5.2, Qwen 3.5, Phi-4, and GPT-4.1, but none of those models was invoked. The result measures deterministic coverage, artifact construction, installed toolchains, and final YARA acceptance, not provider quality.

[Review the methodology and collection breakdown](evaluation.md){ .md-button }
[Download the validation summary](assets/yara-rules-416-deterministic.json){ .md-button }

## Research Team

Aray is a project of **Lab-C2DC - Laboratory of Command and Control and Cyber-security** at the [Aeronautics Institute of Technology (ITA)](https://www.ita.br). It is part of a research collaboration among ITA, the University of Sao Paulo (USP), iFood, and Texas A&M University (TAMU).

[View the source on GitHub](https://github.com/c2dc/aray){ .md-button .md-button--primary }
