"""Deterministic extraction from normalized YARA rules."""

from __future__ import annotations

from aray.models import YaraConstantEntry, YaraStringEntry
from aray.yara_source import _parse_source, _tokens
from aray.yara_validation import _fixed_bytes, _string_declarations


class UnsupportedExtractionError(ValueError):
    """Raised when normalized syntax is outside the deterministic subset."""


class UnsatisfiableExtractionError(ValueError):
    """Raised when a fixed integer equality cannot be satisfied."""


def _selected_rule(rule_text: str):
    rules, _ = _parse_source(rule_text)
    rule = next((candidate for candidate in rules if not candidate.private), None)
    if rule is None:
        raise UnsupportedExtractionError("no public rule found")
    return rule


def _condition_tokens(rule_text: str):
    rule = _selected_rule(rule_text)
    start, end = rule.condition_span
    return _tokens(rule.source[start:end])


def _literal_entry(source: str, modifiers: set[str]) -> tuple[str, str]:
    data = _fixed_bytes("literal", source)
    if data is None:
        raise UnsupportedExtractionError(f"unsupported string literal {source!r}")

    wide_only = "wide" in modifiers and "ascii" not in modifiers
    if wide_only and any(byte > 0x7E for byte in data):
        raise UnsupportedExtractionError(
            "wide string contains a non-ASCII byte"
        )
    try:
        value = data.decode("utf-8")
    except UnicodeDecodeError:
        if wide_only:
            raise UnsupportedExtractionError(
                "wide string contains bytes that are not valid UTF-8"
            )
        return " ".join(f"{byte:02X}" for byte in data), "hex"

    # C string generation cannot safely represent embedded control bytes. An
    # exact hex witness remains valid for ordinary and `ascii wide` literals.
    if any(byte < 0x20 or byte == 0x7F for byte in data):
        if wide_only:
            raise UnsupportedExtractionError(
                "wide string contains an embedded control byte"
            )
        return " ".join(f"{byte:02X}" for byte in data), "hex"

    return value, "widechar" if wide_only else "ascii"


def _parse_range(tokens: list, start: int) -> tuple[int, int, int] | None:
    """Return (next token index, range start, range end)."""
    if start >= len(tokens) or tokens[start].value != "(":
        return None
    if start + 1 >= len(tokens) or tokens[start + 1].kind != "number":
        return None
    first = tokens[start + 1].value
    if ".." in first:
        parts = first.split("..")
        if len(parts) != 2 or not all(parts):
            return None
        if start + 2 >= len(tokens) or tokens[start + 2].value != ")":
            return None
        return start + 3, int(parts[0], 0), int(parts[1], 0)
    if (
        start + 4 >= len(tokens)
        or tokens[start + 2].value != "."
        or tokens[start + 3].value != "."
        or tokens[start + 4].kind != "number"
    ):
        return None
    if start + 5 >= len(tokens) or tokens[start + 5].value != ")":
        return None
    return start + 6, int(first, 0), int(tokens[start + 4].value, 0)


def _string_placements(
    rule_text: str, names: set[str]
) -> tuple[dict[str, list[int]], dict[str, tuple[int, int]], tuple[int, int] | None]:
    tokens = _condition_tokens(rule_text)
    offsets: dict[str, list[int]] = {}
    ranges: dict[str, tuple[int, int]] = {}
    anonymous_range: tuple[int, int] | None = None
    for index, token in enumerate(tokens):
        if token.value.lower() == "in" and index >= 1:
            parsed = _parse_range(tokens, index + 1)
            if parsed is None:
                continue
            _next, range_start, range_end = parsed
            if tokens[index - 1].value == "$":
                anonymous_range = (range_start, range_end)
                continue
            if (
                index >= 2
                and tokens[index - 2].value == "$"
                and tokens[index - 1].kind in {"ident", "number"}
            ):
                name = f"${tokens[index - 1].value}"
                if name not in names:
                    raise UnsupportedExtractionError(
                        f"string range references unknown identifier {name}"
                    )
                ranges[name] = (range_start, range_end)
            continue
        if token.value.lower() != "at":
            continue
        if (
            index < 2
            or index + 1 >= len(tokens)
            or tokens[index - 2].value != "$"
            or tokens[index - 1].kind not in {"ident", "number"}
            or tokens[index + 1].kind != "number"
        ):
            raise UnsupportedExtractionError(
                "string `at` constraint does not use a literal integer offset"
            )
        name = f"${tokens[index - 1].value}"
        if name not in names:
            raise UnsupportedExtractionError(
                f"string `at` constraint references unknown identifier {name}"
            )
        raw_offset = tokens[index + 1].value
        if "." in raw_offset:
            raise UnsupportedExtractionError(
                "string `at` constraint does not use an integer offset"
            )
        offset = int(raw_offset, 0)
        values = offsets.setdefault(name, [])
        if offset not in values:
            values.append(offset)
    return offsets, ranges, anonymous_range


def _comparison(tokens: list, start: int) -> tuple[str, int, int] | None:
    if start >= len(tokens):
        return None
    first = tokens[start].value
    if first in {"=", "!", "<", ">"} and start + 1 < len(tokens) and tokens[start + 1].value == "=":
        operator = first + "="
        value_index = start + 2
    elif first in {"<", ">"}:
        operator = first
        value_index = start + 1
    else:
        return None
    if value_index >= len(tokens) or tokens[value_index].kind != "number":
        return None
    return operator, int(tokens[value_index].value, 0), value_index + 1


def _string_requirements(
    rule_text: str, ordered_names: list[str]
) -> tuple[dict[str, int], set[str]]:
    """Return required positive occurrence counts and negative identifiers."""
    tokens = _condition_tokens(rule_text)
    names = set(ordered_names)
    required: dict[str, int] = {}
    negative: set[str] = set()

    for index in range(len(tokens) - 1):
        token = tokens[index]
        if token.value == "$" and tokens[index + 1].kind in {"ident", "number"}:
            name = f"${tokens[index + 1].value}"
            if name not in names:
                continue
            previous = tokens[index - 1].value.lower() if index else ""
            if previous == "not":
                negative.add(name)
            elif index + 2 >= len(tokens) or tokens[index + 2].value != "*":
                required[name] = max(required.get(name, 0), 1)
        elif token.value == "#" and tokens[index + 1].kind in {"ident", "number"}:
            name = f"${tokens[index + 1].value}"
            if name not in names:
                continue
            parsed = _comparison(tokens, index + 2)
            if parsed is None:
                raise UnsupportedExtractionError(f"unsupported match count for {name}")
            operator, count, _next = parsed
            if operator == ">":
                count += 1
            elif operator not in {"==", ">="}:
                raise UnsupportedExtractionError(f"unsupported match count operator {operator}")
            required[name] = max(required.get(name, 0), count)

    lower_values = [token.value.lower() for token in tokens]
    if any(
        token.kind == "number"
        and index + 1 < len(tokens)
        and lower_values[index + 1] == "of"
        for index, token in enumerate(tokens)
    ):
        raise UnsupportedExtractionError("numeric `of` expression requires normalization")
    for index in range(len(tokens) - 2):
        if lower_values[index] not in {"all", "any"} or lower_values[index + 1] != "of":
            continue
        quantifier = lower_values[index]
        candidates: list[str] = []
        if lower_values[index + 2] == "them":
            candidates = list(ordered_names)
        elif (
            index + 5 < len(tokens)
            and tokens[index + 2].value == "("
            and tokens[index + 3].value == "$"
            and tokens[index + 4].kind in {"ident", "number"}
            and tokens[index + 5].value == "*"
        ):
            prefix = f"${tokens[index + 4].value}"
            candidates = [name for name in ordered_names if name.startswith(prefix)]
        candidates = [name for name in candidates if name not in negative]
        if quantifier == "all":
            for name in candidates:
                required[name] = max(required.get(name, 0), 1)
        elif candidates and not any(name in required for name in candidates):
            required[candidates[0]] = 1

    conflict = negative & required.keys()
    if conflict:
        raise UnsatisfiableExtractionError(
            f"strings are required both present and absent: {', '.join(sorted(conflict))}"
        )
    return required, negative


def extract_strings_deterministic(rule_text: str) -> list[YaraStringEntry]:
    """Extract fixed string witnesses and literal offsets without an LLM."""
    declarations = _string_declarations(rule_text)
    ordered_names = list(declarations)
    offsets, ranges, anonymous_range = _string_placements(rule_text, set(declarations))
    required, _negative = _string_requirements(rule_text, ordered_names)
    entries: list[YaraStringEntry] = []

    for name, (kind, source, modifiers) in declarations.items():
        count = required.get(name, 0)
        if count == 0:
            continue
        if modifiers & {"base64", "base64wide"}:
            raise UnsupportedExtractionError(
                f"{name} uses an unsupported base64 string modifier"
            )
        if kind == "literal":
            value, format_ = _literal_entry(source, modifiers)
        elif kind == "hex":
            data = _fixed_bytes(kind, source)
            if data is None:
                raise UnsupportedExtractionError(
                    f"{name} contains a non-fixed hex pattern"
                )
            value = " ".join(f"{byte:02X}" for byte in data)
            format_ = "hex"
        else:
            raise UnsupportedExtractionError(f"{name} uses unsupported {kind} syntax")

        placements = offsets.get(name)
        range_ = ranges.get(name)
        if anonymous_range is not None and range_ is None and not placements:
            range_ = anonymous_range
        if placements:
            entries.extend(
                YaraStringEntry(
                    identifier=name,
                    value=value,
                    offset=offset,
                    format=format_,
                    ascii=kind == "literal" and ("wide" not in modifiers or "ascii" in modifiers),
                    wide="wide" in modifiers,
                    fullword="fullword" in modifiers,
                    nocase="nocase" in modifiers,
                )
                for offset in placements
            )
            count -= len(placements)
        if count > 0:
            entries.append(
                YaraStringEntry(
                    identifier=name,
                    value=value,
                    format=format_,
                    match_count=count,
                    ascii=kind == "literal" and ("wide" not in modifiers or "ascii" in modifiers),
                    wide="wide" in modifiers,
                    fullword="fullword" in modifiers,
                    nocase="nocase" in modifiers,
                    range_start=range_[0] if range_ else None,
                    range_end=range_[1] if range_ else None,
                )
            )

    return entries


_INTEGER_FUNCTIONS = {
    "uint16": (2, "little", False),
    "uint32": (4, "little", False),
    "int16": (2, "little", True),
    "uint16be": (2, "big", False),
    "uint32be": (4, "big", False),
}


def _parse_uint_call(
    tokens: list, start: int
) -> tuple[int, int, int, bool, str, bool, int]:
    """Return call end, width, base offset, nesting, endian, signed, delta."""
    function = tokens[start].value.lower()
    if function not in _INTEGER_FUNCTIONS:
        raise UnsupportedExtractionError(f"unsupported integer function {function}")
    if start + 2 >= len(tokens) or tokens[start + 1].value != "(":
        raise UnsupportedExtractionError(f"malformed {function} expression")

    width, byte_order, signed = _INTEGER_FUNCTIONS[function]
    argument = start + 2
    nested = (
        tokens[argument].kind == "ident"
        and tokens[argument].value.lower() in _INTEGER_FUNCTIONS
    )
    relative_offset = 0
    if nested:
        (
            inner_end,
            _inner_width,
            offset,
            inner_nested,
            _inner_order,
            _inner_signed,
            inner_delta,
        ) = _parse_uint_call(tokens, argument)
        if inner_nested:
            raise UnsupportedExtractionError("more than one nested uint dereference")
        if inner_delta:
            raise UnsupportedExtractionError("inner uint call contains arithmetic")
        closing = inner_end
        if (
            closing + 1 < len(tokens)
            and tokens[closing].value == "+"
            and tokens[closing + 1].kind == "number"
        ):
            relative_offset = int(tokens[closing + 1].value, 0)
            closing += 2
    else:
        if tokens[argument].kind != "number" or "." in tokens[argument].value:
            raise UnsupportedExtractionError(
                f"{function} offset is not a literal integer"
            )
        offset = int(tokens[argument].value, 0)
        closing = argument + 1

    if closing >= len(tokens) or tokens[closing].value != ")":
        raise UnsupportedExtractionError(
            f"{function} argument contains unsupported arithmetic"
        )
    return (
        closing + 1,
        width,
        offset,
        nested,
        byte_order,
        signed,
        relative_offset,
    )


def extract_constants_deterministic(rule_text: str) -> list[YaraConstantEntry]:
    """Extract literal uint16/uint32 equality checks without an LLM."""
    tokens = _condition_tokens(rule_text)
    entries: list[YaraConstantEntry] = []
    index = 0

    while index < len(tokens):
        token = tokens[index]
        if token.kind != "ident" or token.value.lower() not in _INTEGER_FUNCTIONS:
            index += 1
            continue

        end, size, offset, nested, byte_order, signed, relative_offset = _parse_uint_call(
            tokens, index
        )
        comparison = _comparison(tokens, end)
        if comparison is None:
            # Some normalized PE32 rules retain native header predicates such
            # as Characteristics masks and positive data-directory checks. The
            # PE32 toolchain satisfies these; they do not describe bytes Aray
            # should patch independently.
            if nested and relative_offset and end < len(tokens) and tokens[end].value in {"&", ">"}:
                index = end + 1
                continue
            raise UnsupportedExtractionError(
                f"{token.value} expression is not a literal equality check"
            )
        operator, compared_value, next_index = comparison
        if operator == "==":
            value = compared_value
        elif operator == ">":
            value = compared_value + 1
        elif operator == ">=":
            value = compared_value
        elif operator == "<" and compared_value > 0:
            value = compared_value - 1
        elif operator == "<=":
            value = compared_value
        elif operator == "!=":
            value = 0 if compared_value else 1
        else:
            raise UnsatisfiableExtractionError(
                f"{token.value} comparison has no constructible non-negative witness"
            )
        if value >= 1 << (size * 8):
            raise UnsatisfiableExtractionError(
                f"{token.value} equality value does not fit in {size} bytes"
            )
        entries.append(
            YaraConstantEntry(
                value=f"0x{value:0{size * 2}X}",
                offset=offset,
                size=size,
                is_nested=nested,
                byte_order=byte_order,
                signed=signed,
                relative_offset=relative_offset,
            )
        )
        index = next_index

    return entries
