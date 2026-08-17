"""Deterministic semantic checks for normalized YARA rules."""

from __future__ import annotations

import re
from collections import Counter


_DECLARATION = re.compile(r"(?m)^[ \t]*(\$[A-Za-z0-9_]+)[ \t]*=[ \t]*")
_MODIFIER = re.compile(
    r"\b(ascii|base64|base64wide|fullword|nocase|private|wide|xor)\b"
    r"(?:\s*\([^\n)]*\))?",
    re.IGNORECASE,
)
_COUNT_EXPRESSION = re.compile(
    r"\b(\d+)\s+of\s+(them|\(\s*\$([A-Za-z0-9_]+)\*\s*\))",
    re.IGNORECASE,
)
_ALL_OF_THEM = re.compile(r"\ball\s+of\s+them\b", re.IGNORECASE)
_NAMED_REFERENCE = re.compile(r"\$[A-Za-z0-9_]+")


def _string_declarations(rule_text: str) -> dict[str, tuple[str, str, set[str]]]:
    """Return string declarations as name -> (kind, source value, modifiers)."""
    from aray.yara_source import _parse_source, _tokens

    try:
        rules, _ = _parse_source(rule_text)
    except ValueError:
        return {}
    rule = next((candidate for candidate in rules if not candidate.private), None)
    if rule is None or rule.strings_span is None:
        return {}
    section = rule.source[rule.strings_span[0]:rule.strings_span[1]]
    tokens = _tokens(section)
    declarations: dict[str, tuple[str, str, set[str]]] = {}
    anonymous_index = 0
    index = 0
    while index + 2 < len(tokens):
        if tokens[index].value != "$":
            index += 1
            continue
        if tokens[index + 1].value == "=":
            anonymous_index += 1
            name = f"$__anonymous_{anonymous_index}"
            value_token_index = index + 2
        elif (
            index + 3 < len(tokens)
            and tokens[index + 1].kind in {"ident", "number"}
            and tokens[index + 2].value == "="
        ):
            name = f"${tokens[index + 1].value}"
            value_token_index = index + 3
        else:
            index += 1
            continue
        value_token = tokens[value_token_index]
        if value_token.kind in {"string", "regex"}:
            kind = "literal" if value_token.kind == "string" else "regex"
            value_end_index = value_token_index
        elif value_token.value == "{":
            depth = 1
            value_end_index = value_token_index + 1
            while value_end_index < len(tokens) and depth:
                if tokens[value_end_index].value == "{":
                    depth += 1
                elif tokens[value_end_index].value == "}":
                    depth -= 1
                value_end_index += 1
            if depth:
                index += 1
                continue
            value_end_index -= 1
            kind = "hex"
        else:
            index += 1
            continue
        value_start = value_token.start
        value_end = tokens[value_end_index].end
        value = section[value_start:value_end]
        suffix_end = len(section)
        probe = value_end_index + 1
        next_declaration = len(tokens)
        while probe + 1 < len(tokens):
            if (
                tokens[probe].value == "$"
                and (
                    tokens[probe + 1].value == "="
                    or (
                        probe + 2 < len(tokens)
                        and tokens[probe + 1].kind in {"ident", "number"}
                        and tokens[probe + 2].value == "="
                    )
                )
            ):
                suffix_end = min(suffix_end, tokens[probe].start)
                next_declaration = probe
                break
            probe += 1
        suffix = " ".join(
            section[token.start:token.end]
            for token in tokens[value_end_index + 1:next_declaration]
            if token.start < suffix_end
        )
        modifiers = {
            re.sub(r"\s+", "", modifier.group(0)).lower()
            for modifier in _MODIFIER.finditer(suffix)
        }
        declarations[name] = (kind, value, modifiers)
        index = value_end_index + 1

    return declarations


def _decode_literal(source: str) -> bytes | None:
    result = bytearray()
    index = 1
    while index < len(source) - 1:
        char = source[index]
        if char != '\\':
            result.extend(char.encode("utf-8"))
            index += 1
            continue
        index += 1
        if index >= len(source) - 1:
            return None
        escape = source[index]
        if escape == 'x':
            digits = source[index + 1:index + 3]
            if len(digits) != 2 or not re.fullmatch(r"[0-9A-Fa-f]{2}", digits):
                return None
            result.append(int(digits, 16))
            index += 3
            continue
        escaped = {'"': b'"', '\\': b'\\', 'n': b'\n', 'r': b'\r', 't': b'\t'}
        if escape not in escaped:
            return None
        result.extend(escaped[escape])
        index += 1
    return bytes(result)


def _fixed_bytes(kind: str, source: str) -> bytes | None:
    if kind == "literal":
        return _decode_literal(source)
    if kind == "hex":
        tokens = source[1:-1].split()
        if not tokens or any(not re.fullmatch(r"[0-9A-Fa-f]{2}", token) for token in tokens):
            return None
        return bytes(int(token, 16) for token in tokens)
    return None


def _candidate_encodings(data: bytes, modifiers: set[str]) -> list[bytes]:
    if "wide" not in modifiers:
        return [data]
    wide = b"".join(bytes((byte, 0)) for byte in data)
    return [data, wide] if "ascii" in modifiers else [wide]


def _required_exact_offset(rule_text: str, name: str) -> int | None:
    """Return an exact offset required as a top-level conjunction term."""
    condition = _masked_code(_condition(rule_text))
    placement = re.compile(
        rf"{re.escape(name)}\s+at\s+(0[xX][0-9A-Fa-f]+|\d+)",
        re.IGNORECASE,
    )
    for term in _top_level_and_terms(condition):
        match = placement.fullmatch(_strip_outer_parentheses(term).strip())
        if match:
            value = match.group(1)
            return int(value, 16 if value.lower().startswith("0x") else 10)
    return None


def _regex_witness_contexts(
    data: bytes, exact_offset: int | None
) -> list[tuple[bytes, int]]:
    """Return boundary contexts in which the normalized literal may match."""
    guards = (b"!", b"A")
    if exact_offset == 0:
        prefixes = (b"",)
    elif exact_offset is None:
        prefixes = (b"", *guards)
    else:
        # Regex anchors distinguish offset zero from non-zero, not the exact value.
        prefixes = guards
    suffixes = (b"", *guards)
    return [
        (prefix + data + suffix, len(prefix))
        for prefix in prefixes
        for suffix in suffixes
    ]


def _validate_regex_replacements(original: str, normalized: str) -> str | None:
    try:
        import yara
    except ImportError:
        return None

    original_declarations = _string_declarations(original)
    normalized_declarations = _string_declarations(normalized)
    for name, (kind, regex_source, modifiers) in original_declarations.items():
        if (
            name.startswith("$__anonymous_")
            or kind != "regex"
            or name not in normalized_declarations
        ):
            continue
        candidate_kind, candidate_source, candidate_modifiers = normalized_declarations[name]
        candidate = _fixed_bytes(candidate_kind, candidate_source)
        if not candidate:
            return (
                f"Regex witness validation failed for {name}: replace it with a fixed, "
                "non-empty ASCII or hex literal accepted by the original regex."
            )
        original_modifier_text = " ".join(sorted(modifiers))
        candidate_modifier_text = " ".join(sorted(candidate_modifiers))
        exact_offset = _required_exact_offset(normalized, name)
        try:
            compiled_by_offset = {}
            counterexample = False
            for encoded in _candidate_encodings(candidate, candidate_modifiers):
                for data, offset in _regex_witness_contexts(encoded, exact_offset):
                    compiled = compiled_by_offset.get(offset)
                    if compiled is None:
                        source = (
                            "rule aray_regex_witness { strings: "
                            f"$original = {regex_source} {original_modifier_text} "
                            f"$candidate = {candidate_source} {candidate_modifier_text} "
                            "condition: "
                            f"($candidate at {offset}) and not ($original at {offset}) }}"
                        )
                        compiled = yara.compile(source=source)
                        compiled_by_offset[offset] = compiled
                    if compiled.match(data=data, timeout=1):
                        counterexample = True
                        break
                if counterexample:
                    break
        except yara.Error:
            return None
        if counterexample:
            return (
                f"Regex witness validation failed for {name}: {candidate_source} does not "
                "match the original YARA regex in every placement allowed by the normalized "
                "condition. Choose a non-anchored alternative, preserve a required `at 0` "
                "constraint, or select a different string witness."
            )
    return None


def _compiled_rules(source: str):
    import yara

    return list(yara.compile(source=source))


def _selected_rule_name(source: str) -> tuple[str | None, str | None]:
    from aray.yara_source import extract_first_rule_name

    try:
        name = extract_first_rule_name(source)
    except ValueError as error:
        return None, f"Original YARA source is invalid: {error}"
    if name is None:
        return None, "Original YARA source has no non-private rule."
    return name, None


def _canonicalize_missing_rule(source: str, expected_name: str) -> str:
    """Add only an unambiguous missing `rule` keyword for compilation."""
    if not source.startswith(expected_name):
        return source
    following = source[len(expected_name):len(expected_name) + 1]
    if following and not (following.isspace() or following in "{:"):
        return source
    return f"rule {source}"


def _restore_retained_modifiers(original: str, normalized: str) -> str:
    original_declarations = _string_declarations(original)
    candidate_declarations = _string_declarations(normalized)
    replacements: list[tuple[int, int, str]] = []
    for match in _DECLARATION.finditer(normalized):
        name = match.group(1)
        if name not in original_declarations or match.end() >= len(normalized):
            continue
        if (
            name in candidate_declarations
            and candidate_declarations[name][2] == original_declarations[name][2]
        ):
            continue
        opener = normalized[match.end()]
        if opener not in {'"', '/', '{'}:
            continue
        if opener == '{':
            close = normalized.find('}', match.end() + 1)
        else:
            close = match.end() + 1
            while close < len(normalized):
                if normalized[close] == '\\':
                    close += 2
                    continue
                if normalized[close] == opener:
                    break
                close += 1
        if close < 0 or close >= len(normalized):
            continue
        line_end = normalized.find('\n', close + 1)
        if line_end < 0:
            line_end = len(normalized)
        suffix = normalized[close + 1:line_end]
        if re.search(r"\b(?:condition|meta|strings)\s*:", suffix, re.IGNORECASE):
            continue
        comment_offsets = [
            position
            for marker in ("//", "/*")
            if (position := suffix.find(marker)) >= 0
        ]
        edit_end = close + 1 + min(comment_offsets) if comment_offsets else line_end
        modifiers = sorted(original_declarations[name][2])
        replacement = f" {' '.join(modifiers)}" if modifiers else ""
        replacements.append((close + 1, edit_end, replacement))
    for start, end, replacement in reversed(replacements):
        normalized = normalized[:start] + replacement + normalized[end:]
    return normalized


def _canonicalize_anonymous_aliases(original: str, normalized: str) -> str:
    from aray.yara_source import _replace, _tokens

    original_declarations = _string_declarations(original)
    candidate_declarations = _string_declarations(normalized)
    canonical = {
        name: declaration
        for name, declaration in original_declarations.items()
        if name.startswith("$__aray_anon_")
    }
    if not canonical:
        return normalized

    available = {
        name: declaration
        for name, declaration in canonical.items()
        if name not in candidate_declarations
    }
    named_aliases: dict[str, str] = {}
    anonymous_targets: list[str] = []
    for candidate_name, candidate_declaration in candidate_declarations.items():
        if candidate_name in original_declarations:
            continue
        target = next(
            (
                name
                for name, original_declaration in available.items()
                if _anonymous_declaration_matches(
                    original_declaration, candidate_declaration
                )
            ),
            None,
        )
        if target is None:
            continue
        available.pop(target)
        if candidate_name.startswith("$__anonymous_"):
            anonymous_targets.append(target)
        else:
            named_aliases[candidate_name] = target

    tokens = _tokens(normalized)
    replacements: list[tuple[int, int, str]] = []
    anonymous_index = 0
    for index, token in enumerate(tokens):
        if token.value not in {"$", "#", "@", "!"}:
            continue
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        if following is not None and following.kind in {"ident", "number"}:
            alias = f"${following.value}"
            if alias in named_aliases:
                replacements.append(
                    (following.start, following.end, named_aliases[alias][1:])
                )
            continue
        if token.value == "$" and following is not None and following.value == "=":
            if anonymous_index < len(anonymous_targets):
                replacements.append(
                    (token.start, token.end, anonymous_targets[anonymous_index])
                )
            anonymous_index += 1
            continue
        if token.value == "$" and len(anonymous_targets) == 1:
            replacements.append((token.start, token.end, anonymous_targets[0]))
    return _replace(normalized, replacements)


def _deterministic_hex_witness(source: str) -> str | None:
    """Resolve a linear YARA hex pattern to one fixed matching witness."""
    if not (source.startswith("{") and source.endswith("}")):
        return None
    tokens = source[1:-1].split()
    if not tokens:
        return None

    witness: list[str] = []
    for token in tokens:
        if re.fullmatch(r"[0-9A-Fa-f?]{2}", token):
            witness.append(token.replace("?", "0").upper())
            continue
        jump = re.fullmatch(r"\[(\d+)(?:-(\d+))?\]", token)
        if jump:
            witness.extend(["00"] * int(jump.group(1)))
            continue
        return None
    return "{ " + " ".join(witness) + " }"


def _canonical_retained_value(kind: str, source: str) -> str | None:
    """Return the canonical value for a retained declaration when unambiguous."""
    if kind == "literal":
        return source
    if kind != "hex":
        return None
    if "?" in source or "[" in source:
        return _deterministic_hex_witness(source)
    return source if _fixed_bytes(kind, source) is not None else None


def _canonicalize_retained_string_values(original: str, normalized: str) -> str:
    """Restore or derive values that do not require a model decision."""
    from aray.yara_source import _replace, _tokens

    originals = _string_declarations(original)
    tokens = _tokens(normalized)
    replacements: list[tuple[int, int, str]] = []
    for index in range(len(tokens) - 3):
        if (
            tokens[index].value != "$"
            or tokens[index + 1].kind not in {"ident", "number"}
            or tokens[index + 2].value != "="
        ):
            continue
        name = f"${tokens[index + 1].value}"
        declaration = originals.get(name)
        if declaration is None:
            continue
        canonical_value = _canonical_retained_value(declaration[0], declaration[1])
        if canonical_value is None:
            continue

        value = tokens[index + 3]
        if value.kind in {"string", "regex"}:
            value_end = value.end
        elif value.value == "{":
            depth = 1
            probe = index + 4
            while probe < len(tokens) and depth:
                if tokens[probe].value == "{":
                    depth += 1
                elif tokens[probe].value == "}":
                    depth -= 1
                probe += 1
            if depth:
                continue
            value_end = tokens[probe - 1].end
        else:
            continue
        replacements.append((value.start, value_end, canonical_value))

    return _replace(normalized, replacements)


def _expand_exact_retained_count(normalized: str) -> str:
    from aray.yara_source import _parse_source, _replace, _them_quantifiers

    try:
        rules, _ = _parse_source(normalized)
    except ValueError:
        return normalized
    rule = next((candidate for candidate in rules if not candidate.private), None)
    if rule is None:
        return normalized
    condition = rule.source[rule.condition_span[0]:rule.condition_span[1]]
    matches = _them_quantifiers(condition)
    if len(matches) != 1:
        return normalized
    start, end, prefix = matches[0]
    quantifier = prefix.split(None, 1)[0]
    if not quantifier.isdigit():
        return normalized
    declarations = list(_string_declarations(normalized))
    if int(quantifier) != len(declarations) or not declarations:
        return normalized
    replacement = " and ".join(declarations)
    condition = _replace(condition, [(start, end, replacement)])
    return _replace(
        normalized,
        [(rule.condition_span[0], rule.condition_span[1], condition)],
    )


def canonicalize_normalization(original: str, normalized: str) -> str:
    """Apply only deterministic, semantics-preserving candidate repairs."""
    expected_name, error = _selected_rule_name(original)
    if error or expected_name is None:
        return normalized
    candidate = _canonicalize_missing_rule(normalized, expected_name)
    candidate = _canonicalize_anonymous_aliases(original, candidate)
    candidate = _canonicalize_retained_string_values(original, candidate)
    candidate = _expand_exact_retained_count(candidate)
    return _restore_retained_modifiers(original, candidate)


def _rule_block(source: str, name: str) -> str:
    declaration = re.search(
        rf"\b(?:private\s+)?rule\s+{re.escape(name)}\b[^{{]*\{{",
        source,
        re.IGNORECASE,
    )
    if not declaration:
        return source

    start = declaration.start()
    depth = 0
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    index = declaration.end() - 1
    while index < len(source):
        char = source[index]
        following = source[index + 1:index + 2]
        if line_comment:
            line_comment = char != "\n"
        elif block_comment:
            if char == "*" and following == "/":
                block_comment = False
                index += 1
        elif quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char == "/" and following == "/":
            line_comment = True
            index += 1
        elif char == "/" and following == "*":
            block_comment = True
            index += 1
        elif char == '"':
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
        index += 1
    return source[start:]


def _condition(rule_text: str) -> str:
    from aray.yara_source import _parse_source

    try:
        rules, _ = _parse_source(rule_text)
    except ValueError:
        return ""
    rule = next((candidate for candidate in rules if not candidate.private), None)
    if rule is None:
        return ""
    return rule.source[rule.condition_span[0]:rule.condition_span[1]]


def _validate_modifiers(original: str, normalized: str) -> str | None:
    original_declarations = _string_declarations(original)
    for name, (_, _, candidate_modifiers) in _string_declarations(normalized).items():
        if name.startswith("$__anonymous_"):
            continue
        if name not in original_declarations:
            return f"String validation failed: {name} does not exist in the original rule."
        original_modifiers = original_declarations[name][2]
        if candidate_modifiers != original_modifiers:
            return (
                f"String modifier validation failed for {name}: expected "
                f"{sorted(original_modifiers)}, got {sorted(candidate_modifiers)}."
            )
    return None


def _validate_string_values(original: str, normalized: str) -> str | None:
    original_declarations = _string_declarations(original)
    for name, (candidate_kind, candidate_source, candidate_modifiers) in (
        _string_declarations(normalized).items()
    ):
        if name.startswith("$__anonymous_"):
            continue
        if name not in original_declarations:
            continue
        original_kind, original_source, original_modifiers = original_declarations[name]
        if original_kind == "literal":
            if candidate_kind != original_kind or candidate_source != original_source:
                return (
                    f"String value validation failed for {name}: retained fixed literals "
                    "must remain unchanged."
                )
            continue
        if original_kind != "hex":
            continue
        candidate = _fixed_bytes(candidate_kind, candidate_source)
        if not candidate:
            return (
                f"Hex witness validation failed for {name}: replace wildcards and jumps "
                "with a fixed, non-empty byte sequence."
            )
        modifier_text = " ".join(sorted(original_modifiers))
        source = (
            "rule aray_hex_witness { strings: "
            f"$w = {original_source} {modifier_text} condition: $w }}"
        )
        try:
            import yara

            compiled = yara.compile(source=source)
            matched = any(
                compiled.match(data=data, timeout=1)
                for data in _candidate_encodings(candidate, candidate_modifiers)
            )
        except ImportError:
            continue
        except yara.Error:
            continue
        if not matched:
            return (
                f"Hex witness validation failed for {name}: {candidate_source} does not "
                "match the original YARA hex pattern."
            )
    return None


def _anonymous_declaration_matches(
    original: tuple[str, str, set[str]],
    candidate: tuple[str, str, set[str]],
) -> bool:
    original_kind, original_source, original_modifiers = original
    candidate_kind, candidate_source, candidate_modifiers = candidate
    if original_modifiers != candidate_modifiers:
        return False
    modifier_text = " ".join(sorted(original_modifiers))
    original_rule = (
        f"rule Original {{ strings: $a = {original_source} {modifier_text} condition: $a }}"
    )
    candidate_rule = (
        f"rule Candidate {{ strings: $a = {candidate_source} {modifier_text} condition: $a }}"
    )
    if original_kind == "literal":
        return candidate_kind == "literal" and candidate_source == original_source
    if original_kind == "regex":
        return _validate_regex_replacements(original_rule, candidate_rule) is None
    if original_kind == "hex":
        return _validate_string_values(original_rule, candidate_rule) is None
    return False


def _validate_anonymous_declarations(original: str, normalized: str) -> str | None:
    originals = [
        declaration
        for name, declaration in _string_declarations(original).items()
        if name.startswith("$__anonymous_")
    ]
    candidates = [
        declaration
        for name, declaration in _string_declarations(normalized).items()
        if name.startswith("$__anonymous_")
    ]
    if len(candidates) > len(originals):
        return "Anonymous string validation failed: candidate added declarations."
    available = list(originals)
    for candidate in candidates:
        match_index = next(
            (
                index
                for index, original_declaration in enumerate(available)
                if _anonymous_declaration_matches(original_declaration, candidate)
            ),
            None,
        )
        if match_index is None:
            return (
                "Anonymous string validation failed: a retained declaration does not "
                "match any unused original declaration with the same modifiers."
            )
        available.pop(match_index)
    return None


def _masked_code(text: str) -> str:
    """Mask opaque literals/comments while preserving offsets for regex checks."""
    from aray.yara_source import _tokens

    masked = [" "] * len(text)
    for token in _tokens(text):
        if token.kind in {"string", "regex"}:
            continue
        masked[token.start:token.end] = text[token.start:token.end]
    return "".join(masked)


def _validate_count_expansions(original: str, normalized: str) -> str | None:
    original_condition = _condition(original)
    original_code = _masked_code(original_condition)
    expressions = list(_COUNT_EXPRESSION.finditer(original_code))
    if not expressions:
        return None
    without_counts = list(original_code)
    for expression in expressions:
        without_counts[expression.start():expression.end()] = " " * (
            expression.end() - expression.start()
        )
    without_counts_text = "".join(without_counts)
    if (
        len(expressions) != 1
        or re.search(r"\bor\b", original_code, re.IGNORECASE)
        or re.search(
            r"\b(?:all|any|none)\s+of\b|\$[A-Za-z0-9_]+\s*\*",
            without_counts_text,
            re.IGNORECASE,
        )
    ):
        return None

    normalized_condition = _condition(normalized)
    normalized_code = _masked_code(normalized_condition)
    if _COUNT_EXPRESSION.search(normalized_code):
        return "Count expansion validation failed: expand simple 'N of' expressions into named witnesses."
    if re.search(r"\bor\b", normalized_code, re.IGNORECASE):
        return "Count expansion validation failed: selected witnesses must be conjoined, not joined with 'or'."

    original_names = set(_string_declarations(original))
    normalized_references = set(_NAMED_REFERENCE.findall(normalized_code))
    mandatory = set(_NAMED_REFERENCE.findall(without_counts_text))
    missing_mandatory = mandatory - normalized_references
    if missing_mandatory:
        return (
            "Count expansion validation failed: missing mandatory string(s) "
            f"{sorted(missing_mandatory)}."
        )

    for expression in expressions:
        expected_count = int(expression.group(1))
        prefix = expression.group(3)
        eligible = (
            original_names
            if prefix is None
            else {name for name in original_names if name[1:].startswith(prefix)}
        )
        witnesses = normalized_references & eligible
        if len(witnesses) != expected_count:
            return (
                "Count expansion validation failed: expected exactly "
                f"{expected_count} witness(es) for {expression.group(0)!r}, got "
                f"{len(witnesses)} ({sorted(witnesses)})."
            )
    return None


def _strip_outer_parentheses(text: str) -> str:
    text = text.strip()
    while text.startswith("(") and text.endswith(")"):
        depth = 0
        encloses_all = True
        for index, char in enumerate(text):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0 and index != len(text) - 1:
                    encloses_all = False
                    break
        if not encloses_all or depth:
            break
        text = text[1:-1].strip()
    return text


def _top_level_and_terms(condition: str) -> list[str]:
    condition = _strip_outer_parentheses(condition)
    terms: list[str] = []
    depth = 0
    start = 0
    index = 0
    while index < len(condition):
        char = condition[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and condition[index:index + 3].lower() == "and":
            before = condition[index - 1:index]
            after = condition[index + 3:index + 4]
            if (not before or not (before.isalnum() or before == "_")) and (
                not after or not (after.isalnum() or after == "_")
            ):
                terms.append(condition[start:index])
                start = index + 3
                index += 2
        index += 1
    terms.append(condition[start:])
    return [_strip_outer_parentheses(term) for term in terms if term.strip()]


def _term_key(term: str) -> str:
    term = _strip_outer_parentheses(term)
    result: list[str] = []
    quote: str | None = None
    escaped = False
    for char in term:
        if quote is not None:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', '/'}:
            quote = char
            result.append(char)
        elif not char.isspace():
            result.append(char)
    return "".join(result)


def normalization_is_proven(original: str, normalized: str) -> bool:
    """Return True when supported checks prove the complete normalized condition."""
    if validate_normalization(original, normalized) is not None:
        return False
    expected_name, error = _selected_rule_name(original)
    if error or expected_name is None:
        return False
    original_rule = _rule_block(original, expected_name)
    normalized_rule = _rule_block(
        canonicalize_normalization(original, normalized), expected_name
    )
    original_condition = _condition(original_rule)
    original_code = _masked_code(original_condition)
    expressions = list(_COUNT_EXPRESSION.finditer(original_code))
    all_expressions = list(_ALL_OF_THEM.finditer(original_code))
    supported_expressions = [*expressions, *all_expressions]
    without_counts = list(original_code)
    for expression in supported_expressions:
        without_counts[expression.start():expression.end()] = " " * (
            expression.end() - expression.start()
        )
    without_counts_text = "".join(without_counts)
    if (
        len(supported_expressions) != 1
        or re.search(r"\bor\b", original_code, re.IGNORECASE)
        or re.search(
            r"\b(?:all|any|none)\s+of\b|\$[A-Za-z0-9_]+\s*\*",
            without_counts_text,
            re.IGNORECASE,
        )
    ):
        return False

    normalized_condition = _condition(normalized_rule)
    normalized_references = set(_NAMED_REFERENCE.findall(_masked_code(normalized_condition)))
    original_names = set(_string_declarations(original_rule))
    expected_terms: list[str] = []
    for term in _top_level_and_terms(original_condition):
        term_code = _masked_code(term).strip()
        expression = _COUNT_EXPRESSION.fullmatch(term_code)
        if expression is not None:
            prefix = expression.group(3)
            eligible = (
                original_names
                if prefix is None
                else {name for name in original_names if name[1:].startswith(prefix)}
            )
            expected_terms.extend(sorted(normalized_references & eligible))
        elif _ALL_OF_THEM.fullmatch(term_code):
            expected_terms.extend(sorted(original_names))
        else:
            expected_terms.append(term)

    return Counter(map(_term_key, expected_terms)) == Counter(
        map(_term_key, _top_level_and_terms(normalized_condition))
    )


def validate_normalization(original: str, normalized: str) -> str | None:
    """Return the first deterministic syntax or supported semantic validation error."""
    expected_name, error = _selected_rule_name(original)
    if error:
        return error
    assert expected_name is not None

    candidate = _canonicalize_missing_rule(normalized, expected_name)
    try:
        candidate_rules = _compiled_rules(candidate)
    except Exception as compile_error:
        return f"Normalized YARA syntax validation failed: {compile_error}"

    non_private = [rule.identifier for rule in candidate_rules if not rule.is_private]
    if len(candidate_rules) != 1 or len(non_private) != 1:
        return (
            "Normalized YARA must contain exactly one rule and it must be non-private; "
            f"found {len(candidate_rules)} total and {len(non_private)} non-private."
        )
    if non_private[0] != expected_name:
        return (
            f"Normalized YARA selected rule must be {expected_name!r}, "
            f"not {non_private[0]!r}."
        )

    original_rule = _rule_block(original, expected_name)
    normalized_rule = _rule_block(candidate, expected_name)
    for check in (
        _validate_anonymous_declarations,
        _validate_modifiers,
        _validate_string_values,
        _validate_count_expansions,
        _validate_regex_replacements,
    ):
        validation_error = check(original_rule, normalized_rule)
        if validation_error:
            return validation_error
    return None


def validate_regex_replacements(original: str, normalized: str) -> str | None:
    """Return an actionable error when a retained regex replacement is not a witness."""
    return _validate_regex_replacements(original, normalized)
