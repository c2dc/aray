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
    _has_uint_at_zero = bool(
        re.search(
            r'\b(?:u?int(?:16|32)(?:be)?)\s*\(\s*0\s*\)',
            rule_text,
            re.IGNORECASE,
        )
    )
    _has_string_at_zero = bool(re.search(r'\$\w+\s+at\s+0(?:x0*)?\b', rule_text))
    _has_string_placement = bool(
        re.search(r'\$(?:\w+)?\s+(?:at|in\s*\()', rule_text, re.IGNORECASE)
    )

    # A fixed non-PE header wins over format hints such as a wide string. For
    # example, an OLE magic at offset zero must remain an OLE-like generic blob.
    for constant in constants:
        offset = constant.get("offset") if isinstance(constant, dict) else constant.offset
        value = constant.get("value") if isinstance(constant, dict) else constant.value
        size = constant.get("size", 4) if isinstance(constant, dict) else constant.size
        byte_order = (
            constant.get("byte_order", "little")
            if isinstance(constant, dict)
            else constant.byte_order
        )
        if offset == 0 and _has_uint_at_zero:
            numeric = int(value, 16) if isinstance(value, str) else value
            expected = numeric.to_bytes(size, byteorder=byte_order)
            if expected != b"MZ":
                return {"file_type": "generic"}

    # Ranged witnesses inside the header region are easier and safer to
    # construct as a flat scanner blob, even when integer checks resemble PE.
    for string in strings:
        range_start = (
            string.get("range_start")
            if isinstance(string, dict)
            else string.range_start
        )
        if range_start is not None and range_start < 0x200 and _has_string_placement:
            return {"file_type": "generic"}

    if _is_pe_rule(constants, strings):
        return {"file_type": "pe"}

    # Cross-check: the rule text must actually contain the offset-0 expression
    # before we trust the LLM-extracted offset (guards against hallucination).
    # Any constant anchored at offset 0 (but not PE magic) → generic binary
    for c in constants:
        offset = c.get("offset") if isinstance(c, dict) else c.offset
        if offset == 0 and _has_uint_at_zero:
            return {"file_type": "generic"}

    # Any string anchored at offset 0 → generic binary
    for s in strings:
        offset = s.get("offset") if isinstance(s, dict) else s.offset
        range_start = (
            s.get("range_start") if isinstance(s, dict) else s.range_start
        )
        if offset == 0 and _has_string_at_zero:
            return {"file_type": "generic"}
        # ELF headers occupy the low file region. Exact low offsets without PE
        # structural evidence are scanner blobs, not runnable ELF layouts.
        if offset is not None and offset < 0x200 and _has_string_placement:
            return {"file_type": "generic"}
        if range_start is not None and range_start < 0x200 and _has_string_placement:
            return {"file_type": "generic"}

    return {"file_type": "elf"}


def write_generic(state: ArayGraphState, debug: bool = False) -> dict:
    """Write a plain binary artifact (no ELF/PE structure) for generic file types.

    Strings and constants are placed at their exact file offsets; offset 0
    belongs to the rule's own magic bytes.  The output file extension is
    auto-detected from the magic bytes written at offset 0.
    """
    from aray.artifact_writer import write_generic_artifact
    from aray.codegen import _assign_offsets, _constants_to_sections
    from aray.compiler import _parse_filesize_constraint, _print_debug_sections
    from aray.constants import BANNER, BUILD_DIR_GENERIC

    BUILD_DIR_GENERIC.mkdir(parents=True, exist_ok=True)
    (BUILD_DIR_GENERIC / "normalized_rule.yar").write_text(state["normalized_rule"])

    constants = state.get("rule_constants", [])
    # Use a small base offset and tight packing so that unconstrained strings
    # don't push the artifact past a tight filesize < N constraint.
    # 0x10 is safe: it clears any offset-0 magic bytes (uint16/uint32 constants).
    constant_sections = _constants_to_sections(constants)
    str_sections = _assign_offsets(
        state["rule_strings"],
        default_base=0x10,
        pack=True,
        reserved_sections=constant_sections,
    )
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

    If the file contains multiple rules, only the first non-private rule and
    its reachable dependencies are synthesized into one standalone rule.
    """
    from aray.yara_source import select_yara_file

    selected = select_yara_file(Path(state["rule_path"]))
    return {"yara_rule": selected.text}


def _requires_normalization(rule_text: str) -> bool:
    """Return True if the rule needs LLM normalization, False if it can skip."""
    from aray.yara_source import _parse_source, _tokens

    rules, _ = _parse_source(rule_text)
    rule = next((candidate for candidate in rules if not candidate.private), None)
    if rule is not None:
        if rule.strings_span is not None:
            strings_text = rule.source[rule.strings_span[0]:rule.strings_span[1]]
            string_tokens = _tokens(strings_text)
            if any(token.kind == "regex" for token in string_tokens):
                return True
            for index, token in enumerate(string_tokens[:-1]):
                if token.value != "=" or string_tokens[index + 1].value != "{":
                    continue
                depth = 1
                block: list = []
                probe = index + 2
                while probe < len(string_tokens) and depth:
                    current = string_tokens[probe]
                    if current.value == "{":
                        depth += 1
                    elif current.value == "}":
                        depth -= 1
                    if depth:
                        block.append(current)
                    probe += 1
                if any(current.value == "?" for current in block) or any(
                    current.value == "["
                    and block[position + 1].kind == "number"
                    for position, current in enumerate(block[:-1])
                ):
                    return True
        cond = rule.source[rule.condition_span[0]:rule.condition_span[1]]
        tokens = _tokens(cond)
        if any(token.kind == "ident" and token.value.lower() == "or" for token in tokens):
            return True
        if any(
            token.kind == "number"
            and index + 1 < len(tokens)
            and tokens[index + 1].value.lower() == "of"
            for index, token in enumerate(tokens)
        ):
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
    from aray.yara_validation import validate_normalization

    validation_error = validate_normalization(state["yara_rule"], state["yara_rule"])
    if validation_error:
        raise ValueError(validation_error)
    # Fast path: pass raw rule through as normalized_rule
    print("[normalize] rule is already normalized — skipping LLM loop")
    return {"needs_normalization": False, "normalized_rule": state["yara_rule"]}


def fail_normalization(state: ArayGraphState) -> dict:
    """Terminal node reached when normalization exhausts retries with 'failed' verdict."""
    reason = state.get("judge_reason", "normalization failed after max retries")
    attempts = state.get("normalize_attempts", 0)
    print(f"[normalize] FAILED after {attempts} attempt(s): {reason}")
    return {"normalization_error": reason}


def assess_constructibility(state: ArayGraphState) -> dict:
    """Classify terminal unsupported or impossible constraints."""
    from aray.capabilities import assess_constructibility as assess

    result = assess(state["normalized_rule"])
    if result.disposition != "constructible":
        print(f"[preflight] {result.disposition}: {result.reason}")
    return {
        "constructibility": result.disposition,
        "constructibility_code": result.code,
        "constructibility_reason": result.reason,
    }


def fail_construction(state: ArayGraphState) -> dict:
    """Stop the graph when capability preflight rejects a rule."""
    return {
        "construction_error": state.get("constructibility_reason")
        or "rule is not constructible"
    }


def normalize_rule(state: ArayGraphState, llm: ChatOpenAI, use_structured: bool = True) -> dict:
    """Use LLM to normalize the YARA rule."""
    print(f"[normalize] using model={llm.model_name}")
    sys_msg = SystemMessage(
        content=(
            "You are a cybersecurity expert that normalizes YARA rules.\n\n"
            "Goal: produce the *minimal constructible subset* of the original YARA rule. Every file that matches the normalized rule MUST match the original rule, but the normalized rule may intentionally match fewer files.\n\n"
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
            "   Example derivation (hex-looking text must remain literal text):\n"
            "     Regex:   /5(\\{\\\\b0\\}|)[ ]*2006F00(\\{\\\\b0\\}|)[ ]*6F007(\\{\\\\b0\\}|)[ ]*400200045(\\{\\\\b0\\}|)[ ]*006(\\{\\\\b0\\}|)[ ]*E007(\\{\\\\b0\\}|)[ ]*400720079/\n"
            "     Choose the empty branch of every optional group and zero spaces for every `[ ]*`.\n"
            "     Literal: \"52006F006F007400200045006E007400720079\"\n"
            "     Do NOT decode or reinterpret hex-looking regex text; concatenate the literal characters matched by the regex.\n"
            "2. Eliminate OR conditions by keeping exactly one COMPLETE branch. Parse the boolean structure before simplifying: YARA precedence is `not`, then `and`, then `or`, unless parentheses override it. Therefore `A and B or C` means `(A and B) or C`, not `A and (B or C)`. Never move a condition from one OR branch into another, and never drop a required condition from the selected branch.\n"
            "   Select the cheapest constructible branch, not merely the branch that looks shortest. First expand `all of`, `any of`, and `N of` expressions mentally so every required string counts when branches are compared. Rank branches in this order:\n"
            "   a. Reject branches that are impossible or unlikely to fit the available artifact backends.\n"
            "   b. Prefer no `filesize` upper bound. A compiled artifact cannot be shrunk to satisfy a tight maximum; if every branch has a maximum, prefer the least restrictive feasible maximum.\n"
            "   c. Avoid large minimum or exact `filesize` requirements because satisfying them requires allocating and writing padding bytes.\n"
            "   d. Avoid exact string offsets, especially large offsets, because they constrain layout and can inflate the artifact.\n"
            "   e. Avoid format-forcing requirements when another branch does not need them: MZ/PE constants, nested integer-pointer checks, `wide` strings, and offset-aware PE construction add backend cost.\n"
            "   f. Finally prefer fewer required strings/constants and fewer total literal bytes. Break otherwise equal ties by keeping the earlier branch.\n"
            "   Filesize and format constraints belong only to the branch containing them. Once that branch is discarded, remove those constraints too.\n"
            "3. Replace count expressions like `5 of ($a*)` or `5 of them` with explicit string references.\n"
            "   When the original condition says `N of them` and there are M > N strings defined, pick N strings and REMOVE the other M-N strings from the strings section entirely.\n"
            "   Example: 6 strings defined ($s1–$s6), condition `5 of them` → keep any 5, say $s1–$s5; remove $s6 from strings section; write condition as `$s1 and $s2 and $s3 and $s4 and $s5`.\n"
            "   A quantified expression is one boolean operand: `A and 1 of ($x*)` must become `A and $x1`, never `$x1` or `A or $x1`.\n"
            "4. Preserve all string modifiers (e.g. `wide`, `fullword`, `nocase`) exactly. Never add or remove a modifier.\n"
            "5. In hex string patterns, replace wildcard nibbles deterministically: `??` → `00`, `A?` → `A0`, and `?B` → `0B`. Replace all jump expressions (`[N]` or `[N-M]`) with exactly N repetitions of `00` (use the minimum N).\n"
            "   Examples:\n"
            "   - `{ AB CD ?? EF }` → `{ AB CD 00 EF }`\n"
            "   - `{ 56 3? 2E ?A }` → `{ 56 30 2E 0A }`\n"
            "   - `{ F4 23 [4-6] 62 B4 }` → `{ F4 23 00 00 00 00 62 B4 }`\n"
            "   - `{ F4 23 [3] 62 B4 }` → `{ F4 23 00 00 00 62 B4 }`\n"
            "   - `{ F4 23 [1-100] 62 B4 }` → `{ F4 23 00 62 B4 }` (minimum is 1)\n"
            "6. Use standard YARA variable name syntax (no double-quoted variable names). Anonymous input strings are pre-named as `$__aray_anon_N`; preserve those exact names and never rename them to `$a`, `$s1`, or other aliases.\n"
            "7. Do not add comments or blank strings.\n"
            "8. If you must remove a string variable entirely (e.g. when eliminating OR conditions), update the condition accordingly. Replace `all of them` with an explicit `and`-joined list of the required retained variables (e.g. `$a and $b and $d`). For `any of them`, select one cheapest retained variable as the OR witness and remove the alternatives.\n"
            "   CRITICAL: every string variable defined in the `strings:` section MUST be referenced in the `condition:` section. If after simplification a variable is no longer referenced in the condition, REMOVE it from the strings section too.\n"
            "9. If the string value contains double-quote characters, escape them as `\\\"` inside the YARA string literal. For example, the text `(\"a\",\"\")` must appear as `(\\\"a\\\",\\\"\\\")` in the rule.\n"
            "10. Output exactly ONE complete rule with the `rule` keyword. Preserve required `import` directives before it, but never emit helper or additional rules.\n"
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
            "Example simplification (OR precedence and construction cost):\n"
            "  BEFORE, with $s3 and $s4 being all strings matching the $s* prefix:\n"
            "    condition:\n"
            "      uint16(0) == 0x5a4d and filesize < 2KB and $x1 or all of ($s*)\n"
            "  GROUPING (`and` binds more tightly than `or`):\n"
            "      (uint16(0) == 0x5a4d and filesize < 2KB and $x1) or ($s3 and $s4)\n"
            "  AFTER (choose the cheaper complete second branch):\n"
            "    strings:\n"
            "      $s3 = \"PotPlayer.dll\" fullword ascii\n"
            "      $s4 = \"\\\\update.dat\" fullword ascii\n"
            "    condition:\n"
            "      $s3 and $s4\n"
            "  Remove $x1, the MZ check, and the filesize bound; they belong only to the discarded PE branch.\n\n"
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
    from aray.yara_validation import canonicalize_normalization

    normalized_rule = canonicalize_normalization(state["yara_rule"], response.rule)
    return {
        "normalized_rule": normalized_rule,
        "normalize_attempts": state.get("normalize_attempts", 0) + 1,
    }


def extract_strings(state: ArayGraphState, llm: ChatOpenAI, use_structured: bool = True) -> dict:
    """Extract strings deterministically, falling back to the LLM if needed."""
    from aray.yara_extraction import (
        UnsupportedExtractionError,
        extract_strings_deterministic,
    )

    try:
        strings = extract_strings_deterministic(state["normalized_rule"])
        print("[extract-strings] deterministic")
        return {
            "rule_strings": strings,
            "strings_extraction_source": "deterministic",
            "has_condition": any(string.offset is not None for string in strings),
        }
    except UnsupportedExtractionError as exc:
        print(f"[extract-strings] deterministic fallback: {exc}")

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
    return {
        "rule_strings": response.strings,
        "strings_extraction_source": "llm_fallback",
        "has_condition": has_condition,
    }


def extract_constants(state: ArayGraphState, llm: ChatOpenAI, use_structured: bool = True) -> dict:
    """Extract constants deterministically, falling back to the LLM if needed."""
    from aray.yara_extraction import (
        UnsupportedExtractionError,
        extract_constants_deterministic,
    )

    try:
        constants = extract_constants_deterministic(state["normalized_rule"])
        print("[extract-constants] deterministic")
        return {
            "rule_constants": constants,
            "constants_extraction_source": "deterministic",
            "has_condition": state.get("has_condition", False)
            or any(constant.offset is not None for constant in constants),
        }
    except UnsupportedExtractionError as exc:
        print(f"[extract-constants] deterministic fallback: {exc}")

    print(f"[extract-constants] using model={llm.model_name}")
    sys_msg = SystemMessage(
        content=(
            "You are a cybersecurity expert that extracts integer constant checks from YARA rule conditions.\n\n"
            "Find every sub-expression of the form `uint16(...) == N` or `uint32(...) == N` and extract:\n"
            "- `value`: the hex literal on the RIGHT side of `==`, with `0x` prefix (e.g. `0x5A4D`).\n"
            "- `offset`: the literal integer inside the INNERMOST uint call (e.g. `0` for `uint16(0)`, `0x3C` for `uint32(uint32(0x3C))`).\n"
            "- `size`: byte width of the OUTERMOST function — `2` for `uint16`, `4` for `uint32`.\n"
            "- `is_nested`: `true` when the outer uint reads from an inner uint expression; `false` otherwise.\n\n"
            "Examples:\n"
            "  uint16(0) == 0x5A4D              → value=0x5A4D,     offset=0,    size=2, is_nested=false\n"
            "  uint32(0x3C) == 0x4550           → value=0x4550,     offset=0x3C, size=4, is_nested=false\n"
            "  uint32(uint32(0x3C)) == 0x4550   → value=0x4550,     offset=0x3C, size=4, is_nested=true\n"
        )
    )
    human_msg = HumanMessage(content=state["normalized_rule"])

    response = _invoke_llm(llm, YaraConstants, [sys_msg, human_msg], use_structured)
    has_condition = state.get("has_condition", False) or any(
        s.offset is not None for s in response.constants
    )
    return {
        "rule_constants": response.constants,
        "constants_extraction_source": "llm_fallback",
        "has_condition": has_condition,
    }


# ---------------------------------------------------------------------------
# Judge
# ---------------------------------------------------------------------------

_JUDGE_SYSTEM = (
    "You are an expert YARA rule analyst. You will be given an original YARA rule and a\n"
    "normalized version produced by an LLM normalizer.\n\n"
    "The normalizer follows these rules:\n"
    "1. Removes regex patterns and replaces them with explicit ASCII or hex strings (variable kept, same name).\n"
    "   The replacement is the shortest literal string that the regex can match (using minimum quantifiers).\n"
    "   Retained regex replacements are validated deterministically against the original YARA regex before this review.\n"
    "   If that precheck passed, do not reject a witness solely because it looks unusual.\n"
    "2. Eliminates OR conditions by keeping one complete branch. YARA precedence is `not`, then `and`, then `or`,\n"
    "   unless parentheses override it: `A and B or C` means `(A and B) or C`. Conditions must never be moved\n"
    "   between branches or dropped from inside the selected branch.\n"
    "3. Chooses the cheapest constructible branch after expanding `all of`, `any of`, and `N of` expressions.\n"
    "   Feasibility comes first; then prefer no tight filesize maximum, no large minimum/exact filesize padding,\n"
    "   no high exact offsets, no format-forcing PE/nested/wide requirements, and finally fewer/smaller strings\n"
    "   and constants. Filesize and format constraints from a discarded branch must also be discarded.\n"
    "4. Replaces count expressions like `5 of ($a*)` with an explicit list of string references.\n"
    "   It must retain exactly N witnesses. `A and 1 of ($x*)` becomes `A and $x1`, never `$x1` or `A or $x1`.\n"
    "5. Preserves all string modifiers (wide, fullword, nocase) exactly on any retained string, adding none.\n"
    "6. Uses standard YARA variable name syntax (no double-quoted variable names).\n"
    "7. Does not add comments or blank strings.\n"
    "8. If a string variable is removed, quantified references are rewritten to use only the required retained variables.\n\n"
    "IMPORTANT: a correct normalization is a SUBSET of the original — it is expected and correct\n"
    "for the normalized rule to match fewer files (e.g. one branch of an OR, fewer strings).\n"
    "Do NOT mark a normalization as failed just because it matches fewer cases than the original.\n\n"
    "For example, `uint16(0) == 0x5a4d and filesize < 2KB and $x1 or all of ($s*)` groups as\n"
    "`(MZ and filesize < 2KB and $x1) or ($s3 and $s4)`. The preferred normalization is `$s3 and $s4`:\n"
    "it is a complete original branch and avoids the tight-size PE branch.\n\n"
    "Mark as \"failed\" only if the normalized rule:\n"
    "- Introduces a string variable name that does not exist in the original rule, OR\n"
    "- Adds or drops a modifier (wide, fullword, nocase) from a string that was retained, OR\n"
    "- Has invalid YARA syntax (including: unreferenced string variables defined in strings: but absent from condition:, or unescaped double-quotes inside string literals), OR\n"
    "- Is completely unrelated to the original (hallucinated rule), OR\n"
    "- Removes the entire `strings:` section when the original rule had one (even a single string must be preserved), OR\n"
    "- Replaces a meaningful condition with a trivial expression such as `true`, `false`, or `any of them` / `all of them` against an empty strings section, OR\n"
    "- Is a one-line or degenerate rule (e.g. `rule Foo { condition: true }`) that discards all string matching and integer constant logic from the original, OR\n"
    "- Selects a clearly more expensive or infeasible OR branch when the original contains a cheaper constructible branch. In that case, mark it failed and name the cheaper branch in the reason.\n\n"
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
    from aray.yara_validation import normalization_is_proven, validate_normalization

    validation_error = validate_normalization(original, normalized)
    if validation_error:
        return JudgeVerdict(verdict="failed", reason=validation_error)
    if normalization_is_proven(original, normalized):
        return JudgeVerdict(
            verdict="passed",
            reason="Deterministic validation proved the complete count expansion and retained constraints.",
        )

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
