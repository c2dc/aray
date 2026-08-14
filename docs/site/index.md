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
    <p class="aray-lead">Aray interprets detection logic with an LLM, then uses deterministic engineering backends to construct inspectable Linux ELF, Windows PE, and format-specific artifacts.</p>
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

<strong>97.1%</strong>

Official full-compile match rate

</div>

<div class="aray-metric" markdown>

<strong>404</strong>

YARA matches in each official run

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

### The model interprets

Complex rules may be normalized and judged by an LLM. Deterministic canonicalization restores retained fixed values and derives linear hex witnesses before judging. Supported fixed strings, modifiers, placements, counts, and endian-aware integer checks are then extracted lexically into Pydantic models; model extraction cannot override these deterministic results.

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

Requirements are Linux, Python 3.12+, [`uv`](https://docs.astral.sh/uv/), the YARA CLI, and access to an OpenAI-compatible model. Aray also supports fully local model execution through Ollama.

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

Aray was evaluated against 416 public rules from the Yara-Rules community repository. End-to-end success means the generated artifact produced an actual match when scanned by the YARA CLI.

The only official published results are two full-compile reports:

| Provider/model configuration | Report | Matches | Success rate |
|---|---|---:|---:|
| GPT-4.1 | `2026-08-14T09-32-09-gpt-4.1` | 404 / 416 | **97.1%** |
| GLM-5.2 Cloud (`glm-5.2:cloud`) | `2026-08-14T13-07-22-eval-glm-5.2` | 404 / 416 | **97.1%** |

Both runs used the same frozen `evaluation/normalized-glm-5.2-stable` corpus, and no rule entered the normalization-and-judge loop. They measure provider, pipeline, authoritative deterministic extraction, toolchain, backend, and YARA compatibility; they do not compare normalization quality.

Both schema 2.1 reports retain all 416 per-rule results. Each records the same 12 non-matches: ten deterministic preflight dispositions and two construction failures caused by a missing i686 MinGW compiler in the evaluation environment. The 97.1% rate is not adjusted for those environmental failures. Full-corpus evaluations with smaller models such as Phi and Qwen are planned but not yet published.

[Review the methodology and collection breakdown](evaluation.md){ .md-button }

## Research Team

Aray is a project of **Lab-C2DC - Laboratory of Command and Control and Cyber-security** at the [Aeronautics Institute of Technology (ITA)](https://www.ita.br). It is part of a research collaboration among ITA, the University of Sao Paulo (USP), iFood, and Texas A&M University (TAMU).

[View the source on GitHub](https://github.com/c2dc/aray){ .md-button .md-button--primary }
