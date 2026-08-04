"""Deterministic semantic checks for normalized YARA rules."""

from __future__ import annotations

import re


_DECLARATION = re.compile(r"(?m)^[ \t]*(\$[A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*")
_MODIFIERS = {"ascii", "fullword", "nocase", "wide"}


def _string_declarations(rule_text: str) -> dict[str, tuple[str, str, set[str]]]:
    """Return string declarations as name -> (kind, source value, modifiers)."""
    strings_match = re.search(r"\bstrings\s*:", rule_text, re.IGNORECASE)
    if not strings_match:
        return {}
    condition_match = re.search(
        r"\bcondition\s*:", rule_text[strings_match.end():], re.IGNORECASE
    )
    end = (
        strings_match.end() + condition_match.start()
        if condition_match
        else len(rule_text)
    )
    section = rule_text[strings_match.end():end]
    declarations: dict[str, tuple[str, str, set[str]]] = {}

    for match in _DECLARATION.finditer(section):
        name = match.group(1)
        start = match.end()
        if start >= len(section):
            continue
        opener = section[start]
        if opener not in {'"', '/', '{'}:
            continue

        if opener == '{':
            close = section.find('}', start + 1)
            kind = "hex"
        else:
            close = start + 1
            while close < len(section):
                if section[close] == '\\':
                    close += 2
                    continue
                if section[close] == opener:
                    break
                close += 1
            kind = "literal" if opener == '"' else "regex"

        if close >= len(section) or section[close] != ('}' if opener == '{' else opener):
            continue
        value = section[start:close + 1]
        line_end = section.find('\n', close + 1)
        if line_end == -1:
            line_end = len(section)
        suffix = section[close + 1:line_end].split("//", 1)[0]
        modifiers = {
            token.lower()
            for token in re.findall(r"\b[A-Za-z]+\b", suffix)
            if token.lower() in _MODIFIERS
        }
        declarations[name] = (kind, value, modifiers)

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


def validate_regex_replacements(original: str, normalized: str) -> str | None:
    """Return an actionable error when a retained regex replacement is not a witness."""
    try:
        import yara
    except ImportError:
        return None

    original_declarations = _string_declarations(original)
    normalized_declarations = _string_declarations(normalized)
    for name, (kind, regex_source, modifiers) in original_declarations.items():
        if kind != "regex" or name not in normalized_declarations:
            continue
        candidate_kind, candidate_source, candidate_modifiers = normalized_declarations[name]
        candidate = _fixed_bytes(candidate_kind, candidate_source)
        if not candidate:
            return (
                f"Regex witness validation failed for {name}: replace it with a fixed, "
                "non-empty ASCII or hex literal accepted by the original regex."
            )
        modifier_text = " ".join(sorted(modifiers))
        source = (
            "rule aray_regex_witness { strings: "
            f"$w = {regex_source} {modifier_text} condition: $w }}"
        )
        try:
            compiled = yara.compile(source=source)
            matched = any(
                compiled.match(data=data, timeout=1)
                for data in _candidate_encodings(candidate, candidate_modifiers)
            )
        except yara.Error:
            return None
        if not matched:
            return (
                f"Regex witness validation failed for {name}: {candidate_source} does not "
                "match the original YARA regex. Derive a fixed literal by taking zero "
                "optional repetitions and the minimum required repetitions."
            )
    return None
