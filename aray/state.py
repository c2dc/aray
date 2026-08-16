"""LangGraph state definition for the aray pipeline."""

from typing import TypedDict


class ArayGraphState(TypedDict):
    """State passed through the LangGraph pipeline."""

    name: str
    rule_path: str
    yara_rule: str
    normalized_rule: str
    rule_strings: list[dict]
    rule_constants: list[dict]
    strings_extraction_source: str  # "deterministic" | "llm_fallback"
    constants_extraction_source: str  # "deterministic" | "llm_fallback"
    has_condition: bool
    normalize_attempts: int
    judge_verdict: str  # "passed" | "failed" | "uncertain" | ""
    judge_reason: str   # last judge explanation
    normalize_history: list[dict]  # [{attempt, rule, reason}, ...] accumulated across retries
    needs_normalization: bool  # set by check_normalization_needed; False → skip LLM loop
    normalization_error: str | None  # set by fail_normalization; None = success path
    constructibility: str
    constructibility_code: str | None
    constructibility_reason: str | None
    construction_error: str | None
    file_type: str  # "pe" | "elf" | "generic"
