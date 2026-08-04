"""LangGraph pipeline node functions for the aray pipeline."""

import re
from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from aray.llm import _invoke_llm
from aray.models import NormalizedYaraRule, YaraConstants, YaraStrings
from aray.state import ArayGraphState


def route_file_type(state: ArayGraphState) -> dict:
    """Determine target file type from extracted strings and constants.

    Sets ``state["file_type"]`` to one of:
    - ``"pe"``      — Windows PE rule (MZ/PE magic or wide strings)
    - ``"generic"`` — any non-PE rule with a constant or string anchored at offset 0
    - ``"elf"``     — everything else (Linux ELF)

    Offset-0 routing is cross-validated against the rule text to guard against
    weaker models hallucinating ``offset=0`` for unconstrained strings.
    """
    from aray.compiler import _is_pe_rule

    constants = state.get("rule_constants", [])
    strings = state.get("rule_strings", [])
    rule_text = state.get("normalized_rule", "")

    if _is_pe_rule(constants, strings):
        return {"file_type": "pe"}

    # Cross-check: the rule text must actually contain the offset-0 expression
    # before we trust the LLM-extracted offset (guards against hallucination).
    _has_uint_at_zero = bool(re.search(r'\buint(?:16|32)\s*\(\s*0\s*\)', rule_text, re.IGNORECASE))
    _has_string_at_zero = bool(re.search(r'\$\w+\s+at\s+0(?:x0*)?\b', rule_text))

    # Any constant anchored at offset 0 (but not PE magic) → generic binary
    for c in constants:
        offset = c.get("offset") if isinstance(c, dict) else c.offset
        if offset == 0 and _has_uint_at_zero:
            return {"file_type": "generic"}

    # Any string anchored at offset 0 → generic binary
    for s in strings:
        offset = s.get("offset") if isinstance(s, dict) else s.offset
        if offset == 0 and _has_string_at_zero:
            return {"file_type": "generic"}

    return {"file_type": "elf"}


def write_generic(state: ArayGraphState, debug: bool = False) -> dict:
    """Write a plain binary artifact (no ELF/PE structure) for generic file types.

    Strings and constants are placed at their exact file offsets; offset 0
    belongs to the rule's own magic bytes.  The output file extension is
    auto-detected from the magic bytes written at offset 0.
    """
    from aray.artifact_writer import write_generic_artifact
    from aray.codegen import _assign_offsets
    from aray.compiler import _parse_filesize_constraint, _print_debug_sections
    from aray.constants import BANNER, BUILD_DIR_GENERIC

    BUILD_DIR_GENERIC.mkdir(parents=True, exist_ok=True)
    (BUILD_DIR_GENERIC / "normalized_rule.yar").write_text(state["normalized_rule"])

    constants = state.get("rule_constants", [])
    # Use a small base offset and tight packing so that unconstrained strings
    # don't push the artifact past a tight filesize < N constraint.
    # 0x10 is safe: it clears any offset-0 magic bytes (uint16/uint32 constants).
    str_sections = _assign_offsets(state["rule_strings"], default_base=0x10, pack=True)
    if debug:
        _print_debug_sections(str_sections)

    min_b, max_b = _parse_filesize_constraint(state.get("normalized_rule", ""))
    filesize_constraint: tuple[int | None, int | None] | None = (
        (min_b, max_b) if (min_b is not None or max_b is not None) else None
    )
    if debug and filesize_constraint:
        print(f"[debug] filesize constraint: min={min_b}  max={max_b}")

    artifact_bytes, ext = write_generic_artifact(
        str_sections, constants, filesize_constraint=filesize_constraint, debug=debug
    )

    output = BUILD_DIR_GENERIC / f"output{ext}"
    output.write_bytes(artifact_bytes)
    print(f"{BANNER}")
    print(f"Generic artifact: {output}")
    return {}


def read_yara_rule(state: ArayGraphState) -> dict:
    """Read a YARA rule from the path specified in state.

    If the file contains multiple rules (a ruleset), only the first rule block
    is extracted and stored in state — subsequent rules are ignored.
    """
    from aray.evaluator import _extract_first_rule_text
    rule = Path(state["rule_path"]).read_text()
    return {"yara_rule": _extract_first_rule_text(rule)}


def _requires_normalization(rule_text: str) -> bool:
    """Return True if the rule needs LLM normalization, False if it can skip."""
    # 1. Regex string pattern
    if re.search(r'\$\w+\s*=\s*/', rule_text):
        return True
    # 2 & 3. Hex wildcards / jumps — scoped to { } blocks
    for block in re.findall(r'\{([^}]*)\}', rule_text):
        if '??' in block or re.search(r'\[\s*\d', block):
            return True
    # 4 & 5. Condition-level checks
    m = re.search(r'\bcondition\s*:(.*?)(?:\}|$)', rule_text, re.DOTALL | re.IGNORECASE)
    if m:
        cond = m.group(1)
        if re.search(r'\bor\b', cond):
            return True
        if re.search(r'\b\d+\s+of\b', cond):
            return True
    return False


def check_normalization_needed(state: ArayGraphState) -> dict:
    """Deterministically decide whether LLM normalization is needed.

    Sets ``needs_normalization`` in state.  When False, the raw rule is
    passed through as ``normalized_rule`` so the pipeline can skip the
    LLM normalize/judge loop entirely.
    """
    needed = _requires_normalization(state["yara_rule"])
    if needed:
        print("[normalize] rule requires normalization — running LLM loop")
        return {"needs_normalization": True}
    # Fast path: pass raw rule through as normalized_rule
    print("[normalize] rule is already normalized — skipping LLM loop")
    return {"needs_normalization": False, "normalized_rule": state["yara_rule"]}


def fail_normalization(state: ArayGraphState) -> dict:
    """Terminal node reached when normalization exhausts retries with 'failed' verdict."""
    reason = state.get("judge_reason", "normalization failed after max retries")
    attempts = state.get("normalize_attempts", 0)
    print(f"[normalize] FAILED after {attempts} attempt(s): {reason}")
    return {"normalization_error": reason}


def normalize_rule(state: ArayGraphState, llm: ChatOpenAI, use_structured: bool = True) -> dict:
    """Use LLM to normalize the YARA rule."""
    print(f"[normalize] using model={llm.model_name}")
    sys_msg = SystemMessage(
        content=(
            "You are a cybersecurity expert that normalizes YARA rules.\n\n"
            "Goal: produce the *minimal* YARA rule equivalent to the original — as simple as possible while still matching the same files.\n\n"
            "Rules:\n"
            "1. Remove all regex patterns from the strings section; replace them with a fixed explicit ASCII or hex string literal — keep the same variable name, do NOT remove the variable.\n"
            "   To derive the replacement literal from a complex regex, construct the SHORTEST string that the regex can match:\n"
            "   - Keep all literal characters (letters, digits, punctuation) exactly as they appear (unescaped).\n"
            "   - IMPORTANT: Escaped special characters in YARA regex (e.g. `\\(`, `\\)`, `\\[`, `\\]`, `\\.`, `\\$`) are LITERAL characters — include them verbatim in the output. For example, `\\(` → `(`, `\\)` → `)`, `\\.` → `.`, `\\$` → `$`.\n"
            "   - For optional quantifiers (`?`, `*`, `{,N}`) use 0 repetitions (empty).\n"
            "   - For required quantifiers (`+`, `{M}`, `{M,N}`) use the minimum M repetitions.\n"
            "   - For character classes like `[a-z0-9]` pick any single character from the class (e.g. `a`).\n"
            "   - For alternation `(a|b)` pick the shortest branch.\n"
            "   Example derivation:\n"
            "     Regex:   /basename\\/\\*[a-z0-9]{,6}\\*\\/\\(\\/\\*[a-z0-9]{,5}\\*\\/trim\\/\\*[a-z0-9]{,5}\\*\\/\\(\\/\\*[a-z0-9]{,5}\\*\\//\n"
            "     Literal: \"basename/**/(/**/trim/**/(/**/\"   (using 0 chars for every {,N} group)\n"
            "   Example derivation (escaped parens):\n"
            "     Regex:   /\\$[a-z]+=explode\\(chr\\(\\([0-9]+[-+][0-9]+\\)\\)/\n"
            "     Step by step: `\\$` → `$`, `[a-z]+` → `a`, `=explode` → `=explode`, `\\(` → `(`, `chr` → `chr`, `\\(` → `(`, `\\(` → `(`, `[0-9]+` → `0`, `[-+]` → `-`, `[0-9]+` → `0`, `\\)` → `)`, `\\)` → `)`\n"
            "     Literal: \"$a=explode(chr((0-0))\"\n"
            "2. Eliminate OR conditions: keep only the single simplest branch (fewest conditions).\n"
            "3. Replace count expressions like `5 of ($a*)` or `5 of them` with explicit string references.\n"
            "   When the original condition says `N of them` and there are M > N strings defined, pick N strings and REMOVE the other M-N strings from the strings section entirely.\n"
            "   Example: 6 strings defined ($s1–$s6), condition `5 of them` → keep any 5, say $s1–$s5; remove $s6 from strings section; write condition as `$s1 and $s2 and $s3 and $s4 and $s5`.\n"
            "4. Preserve all string modifiers (e.g. `wide`, `fullword`, `nocase`) exactly as they appear after the variable name — never remove them.\n"
            "5. In hex string patterns, replace all wildcard bytes (`??`) with `00`, and replace all jump expressions (`[N]` or `[N-M]`) with exactly N repetitions of `00` (use the minimum N).\n"
            "   Examples:\n"
            "   - `{ AB CD ?? EF }` → `{ AB CD 00 EF }`\n"
            "   - `{ F4 23 [4-6] 62 B4 }` → `{ F4 23 00 00 00 00 62 B4 }`\n"
            "   - `{ F4 23 [3] 62 B4 }` → `{ F4 23 00 00 00 62 B4 }`\n"
            "   - `{ F4 23 [1-100] 62 B4 }` → `{ F4 23 00 62 B4 }` (minimum is 1)\n"
            "6. Use standard YARA variable name syntax (no double-quoted variable names).\n"
            "7. Do not add comments or blank strings.\n"
            "8. If you must remove a string variable entirely (e.g. when eliminating OR conditions), update the condition accordingly: replace `all of them` with an explicit `and`-joined list of the remaining variables (e.g. `$a and $b and $d`), and replace `any of them` similarly with `$a or $b or $d`.\n"
            "   CRITICAL: every string variable defined in the `strings:` section MUST be referenced in the `condition:` section. If after simplification a variable is no longer referenced in the condition, REMOVE it from the strings section too.\n"
            "9. If the string value contains double-quote characters, escape them as `\\\"` inside the YARA string literal. For example, the text `(\"a\",\"\")` must appear as `(\\\"a\\\",\\\"\\\")` in the rule.\n"
            "10. Output exactly ONE rule. If the input contains only one rule, output only that rule.\n"
            "11. NEVER collapse the rule into a trivial shell. The normalized rule MUST preserve the same structural sections as the original:\n"
            "    - If the original has a `strings:` section, the normalized rule MUST also have a `strings:` section with at least one string variable.\n"
            "    - The `condition:` MUST reference at least one string variable or integer constant from the original.\n"
            "    - NEVER simplify the condition to just `true`, `false`, or any expression that ignores all string variables.\n"
            "    Examples of INVALID normalizations (DO NOT produce these):\n"
            "      rule Foo { condition: true }\n"
            "      rule Foo { condition: false }\n"
            "      rule Foo { strings: condition: any of them }  ← strings section empty\n\n"
            "Example simplification (OR condition — removing unreferenced strings):\n"
            "  BEFORE:\n"
            "    strings:\n"
            "      $gif = \"GIF87a\"\n"
            "      $png = { 89 50 4e 47 }\n"
            "      $php_tag = \"<?php\"\n"
            "    condition:\n"
            "      ($gif at 0 or $png at 0) and $php_tag\n"
            "  AFTER (keeping only the simplest branch $gif, removing unused $png):\n"
            "    strings:\n"
            "      $gif = \"GIF87a\"\n"
            "      $php_tag = \"<?php\"\n"
            "    condition:\n"
            "      $gif at 0 and $php_tag\n\n"
            "Example simplification (simple regex replacement):\n"
            "  BEFORE:\n"
            "    strings:\n"
            "      $a = \"hello\"\n"
            "      $b = /world[0-9]+/ nocase\n"
            "    condition:\n"
            "      all of them\n"
            "  AFTER:\n"
            "    strings:\n"
            "      $a = \"hello\"\n"
            "      $b = \"world1\" nocase\n"
            "    condition:\n"
            "      all of them\n\n"
            "Example simplification (complex regex with embedded comments/punctuation):\n"
            "  BEFORE:\n"
            "    strings:\n"
            "      $php = \"<?php\" ascii\n"
            "      $regexp = /basename\\/\\*[a-z0-9]{,6}\\*\\/\\(\\/\\*[a-z0-9]{,5}\\*\\/trim\\/\\*[a-z0-9]{,5}\\*\\/\\(\\/\\*[a-z0-9]{,5}\\*\\//\n"
            "    condition:\n"
            "      $php at 0 and $regexp\n"
            "  AFTER:\n"
            "    strings:\n"
            "      $php = \"<?php\" ascii\n"
            "      $regexp = \"basename/**/(/**/trim/**/(/**/\"\n"
            "    condition:\n"
            "      $php at 0 and $regexp\n"
        )
    )
    history = state.get("normalize_history", [])
    if history:
        prev_attempts = "\n\n".join(
            f"--- Attempt {h['attempt']} (REJECTED) ---\n"
            f"{h['rule']}\n"
            f"Judge feedback: {h['reason']}"
            for h in history
        )
        human_content = (
            f"=== ORIGINAL RULE ===\n{state['yara_rule']}\n\n"
            f"=== PREVIOUS FAILED ATTEMPT(S) ===\n{prev_attempts}\n\n"
            "=== YOUR TASK ===\n"
            "Normalize the ORIGINAL RULE again, strictly avoiding all mistakes flagged above."
        )
    else:
        human_content = state["yara_rule"]

    human_msg = HumanMessage(content=human_content)

    response = _invoke_llm(llm, NormalizedYaraRule, [sys_msg, human_msg], use_structured)
    return {
        "normalized_rule": response.rule,
        "normalize_attempts": state.get("normalize_attempts", 0) + 1,
    }


def extract_strings(state: ArayGraphState, llm: ChatOpenAI, use_structured: bool = True) -> dict:
    """Use LLM to extract strings from the YARA rule."""
    print(f"[extract-strings] using model={llm.model_name}")
    sys_msg = SystemMessage(
        content=(
            "You are a cybersecurity expert that extracts string entries from YARA rules.\n\n"
            "For every entry in the `strings:` section extract these fields:\n"
            "- `value`: the raw string content (no variable name, no modifiers, no surrounding quotes or braces).\n"
            "  For hex patterns keep the space-separated bytes exactly as written (e.g. `DE AD BE EF`).\n"
            "- `format`:\n"
            "  - `\"hex\"` — if the string is a hex pattern enclosed in `{ }`.\n"
            "  - `\"widechar\"` — if the string has the `wide` modifier.\n"
            "  - `\"ascii\"` — for all other text strings.\n"
            "- `offset`: integer file offset from an `at` constraint in the condition section\n"
            "  (e.g. `$a at 0x600` → 0x600). Set to null if no `at` constraint is present.\n"
        )
    )
    human_msg = HumanMessage(content=state["normalized_rule"])

    response = _invoke_llm(llm, YaraStrings, [sys_msg, human_msg], use_structured)
    has_condition = any(s.offset is not None for s in response.strings)
    return {"rule_strings": response.strings, "has_condition": has_condition}


def extract_constants(state: ArayGraphState, llm: ChatOpenAI, use_structured: bool = True) -> dict:
    """Use LLM to extract constants from the YARA rule."""
    print(f"[extract-constants] using model={llm.model_name}")
    sys_msg = SystemMessage(
        content=(
            "You are a cybersecurity expert that extracts integer constant checks from YARA rule conditions.\n\n"
            "Find every sub-expression of the form `uint16(...) == N` or `uint32(...) == N` and extract:\n"
            "- `value`: the hex literal on the RIGHT side of `==`, with `0x` prefix (e.g. `0x5A4D`).\n"
            "- `offset`: the literal integer inside the INNERMOST uint call (e.g. `0` for `uint16(0)`, `0x3C` for `uint32(uint32(0x3C))`).\n"
            "- `size`: byte width of the OUTERMOST function — `2` for `uint16`, `4` for `uint32`.\n"
            "- `is_nested`: `true` only when the expression is `uint32(uint32(...))` (doubly nested); `false` otherwise.\n\n"
            "Examples:\n"
            "  uint16(0) == 0x5A4D              → value=0x5A4D,     offset=0,    size=2, is_nested=false\n"
            "  uint32(0x3C) == 0x4550           → value=0x4550,     offset=0x3C, size=4, is_nested=false\n"
            "  uint32(uint32(0x3C)) == 0x4550   → value=0x4550,     offset=0x3C, size=4, is_nested=true\n"
        )
    )
    human_msg = HumanMessage(content=state["normalized_rule"])

    response = _invoke_llm(llm, YaraConstants, [sys_msg, human_msg], use_structured)
    has_condition = any(s.offset is not None for s in response.constants)
    return {"rule_constants": response.constants, "has_condition": has_condition}


# ---------------------------------------------------------------------------
# Judge
# ---------------------------------------------------------------------------

_JUDGE_SYSTEM = (
    "You are an expert YARA rule analyst. You will be given an original YARA rule and a\n"
    "normalized version produced by an LLM normalizer.\n\n"
    "The normalizer follows these rules:\n"
    "1. Removes regex patterns and replaces them with explicit ASCII or hex strings (variable kept, same name).\n"
    "   The replacement is the shortest literal string that the regex can match (using minimum quantifiers).\n"
    "   IMPORTANT: you CANNOT verify whether a regex replacement is correct — do NOT fail a normalization\n"
    "   solely because the replacement string looks different from the original regex. Accept any non-empty\n"
    "   ASCII/hex string as a valid replacement for a regex pattern.\n"
    "2. Eliminates OR conditions — keeps only the single simplest branch (fewest conditions).\n"
    "3. Replaces count expressions like `5 of ($a*)` with an explicit list of string references.\n"
    "4. Preserves all string modifiers (wide, fullword, nocase) exactly on any retained string.\n"
    "5. Uses standard YARA variable name syntax (no double-quoted variable names).\n"
    "6. Does not add comments or blank strings.\n"
    "7. If a string variable is removed, `all of them` / `any of them` is rewritten to list only the remaining variables.\n\n"
    "IMPORTANT: a correct normalization is a SUBSET of the original — it is expected and correct\n"
    "for the normalized rule to match fewer files (e.g. one branch of an OR, fewer strings).\n"
    "Do NOT mark a normalization as failed just because it matches fewer cases than the original.\n\n"
    "Mark as \"failed\" only if the normalized rule:\n"
    "- Introduces a string variable name that does not exist in the original rule, OR\n"
    "- Drops a modifier (wide, fullword, nocase) from a string that was retained, OR\n"
    "- Has invalid YARA syntax (including: unreferenced string variables defined in strings: but absent from condition:, or unescaped double-quotes inside string literals), OR\n"
    "- Is completely unrelated to the original (hallucinated rule), OR\n"
    "- Removes the entire `strings:` section when the original rule had one (even a single string must be preserved), OR\n"
    "- Replaces a meaningful condition with a trivial expression such as `true`, `false`, or `any of them` / `all of them` against an empty strings section, OR\n"
    "- Is a one-line or degenerate rule (e.g. `rule Foo { condition: true }`) that discards all string matching and integer constant logic from the original.\n\n"
    "IMPORTANT: YARA requires every variable defined in the strings: section to be referenced in the condition:. If the normalized rule defines a string variable (e.g. $s6) that does not appear anywhere in the condition:, that is a SYNTAX ERROR — mark as \"failed\".\n\n"
    "Mark as \"uncertain\" if the original rule is very complex and you cannot determine whether\n"
    "the normalization is structurally correct (e.g. complex condition logic).\n\n"
    "Verdict:\n"
    "- \"passed\": the normalized rule is a valid, correct subset of the original\n"
    "- \"failed\": violates one of the failure conditions above\n"
    "- \"uncertain\": you cannot determine correctness (e.g. extremely complex rule)"
)


def _judge_normalization(
    original: str,
    normalized: str,
    judge_llm: ChatOpenAI,
    use_structured: bool,
) -> "JudgeVerdict":
    """Ask the judge LLM to assess the normalization."""
    from aray.models import JudgeVerdict  # local import avoids top-level circular risk

    sys_msg = SystemMessage(content=_JUDGE_SYSTEM)
    human_msg = HumanMessage(
        content=(
            f"=== ORIGINAL RULE ===\n{original}\n\n"
            f"=== NORMALIZED RULE ===\n{normalized}"
        )
    )
    return _invoke_llm(judge_llm, JudgeVerdict, [sys_msg, human_msg], use_structured)


def judge_rule(state: ArayGraphState, llm: ChatOpenAI, use_structured: bool = True) -> dict:
    """Use the LLM judge to assess whether the normalized rule is valid.

    Stores the verdict and reason in state so the graph router can decide
    whether to retry normalization or proceed to extraction.  On failure,
    appends the rejected attempt and its reason to ``normalize_history`` so
    the next normalization pass has full context on what went wrong.
    """
    verdict = _judge_normalization(
        state["yara_rule"], state["normalized_rule"], llm, use_structured
    )
    attempts = state.get("normalize_attempts", 1)
    print(f"[judge] attempt {attempts}/3 — {verdict.verdict}: {verdict.reason}")

    history = list(state.get("normalize_history", []))
    if verdict.verdict == "failed":
        history.append({
            "attempt": attempts,
            "rule": state["normalized_rule"],
            "reason": verdict.reason,
        })

    return {
        "judge_verdict": verdict.verdict,
        "judge_reason": verdict.reason,
        "normalize_history": history,
    }
