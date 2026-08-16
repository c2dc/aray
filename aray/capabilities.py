"""Deterministic constructibility checks before extraction and compilation."""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from typing import Literal

from aray.constants import MINGW_GCC_32
from aray.yara_extraction import (
    UnsatisfiableExtractionError,
    extract_constants_deterministic,
)
from aray.yara_source import _parse_source


Disposition = Literal[
    "constructible",
    "unsupported",
    "infeasible",
    "unsatisfiable",
    "construction_failed",
]


@dataclass(frozen=True)
class ConstructibilityAssessment:
    disposition: Disposition
    code: str | None = None
    reason: str | None = None


def _condition(rule_text: str) -> str:
    rules, _ = _parse_source(rule_text)
    rule = next((candidate for candidate in rules if not candidate.private), None)
    if rule is None:
        return ""
    start, end = rule.condition_span
    return rule.source[start:end]


def assess_constructibility(rule_text: str) -> ConstructibilityAssessment:
    """Classify known terminal constraints without invoking a model."""
    condition = _condition(rule_text)

    pe_features = sorted(set(re.findall(r"\bpe\.([A-Za-z_]\w*)", condition)))
    if pe_features:
        rendered = ", ".join(f"pe.{feature}" for feature in pe_features)
        return ConstructibilityAssessment(
            "unsupported",
            "unsupported_pe_module",
            f"conditions using the YARA pe module are not supported: {rendered}",
        )

    math_features = sorted(set(re.findall(r"\bmath\.([A-Za-z_]\w*)", condition)))
    if math_features:
        rendered = ", ".join(f"math.{feature}" for feature in math_features)
        return ConstructibilityAssessment(
            "unsupported",
            "unsupported_math_module",
            f"conditions using the YARA math module are not supported: {rendered}",
        )

    if re.search(
        r"\bhash\.(?:md5|sha1|sha256)\s*\(\s*0\s*,\s*filesize\s*\)\s*==\s*\"[0-9A-Fa-f]+\"",
        condition,
    ):
        return ConstructibilityAssessment(
            "infeasible",
            "whole_file_hash_preimage",
            "constructing a file with a prescribed whole-file cryptographic hash is infeasible",
        )

    try:
        constants = extract_constants_deterministic(rule_text)
    except UnsatisfiableExtractionError as exc:
        return ConstructibilityAssessment(
            "unsatisfiable", "integer_value_out_of_range", str(exc)
        )
    except ValueError:
        constants = []

    from aray.compiler import _requires_pe32

    if _requires_pe32(constants) and shutil.which(MINGW_GCC_32) is None:
        return ConstructibilityAssessment(
            "construction_failed",
            "missing_pe32_compiler",
            f"required PE32 compiler is not installed: {MINGW_GCC_32}",
        )

    return ConstructibilityAssessment("constructible")
