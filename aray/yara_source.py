"""Deterministic selection of one standalone rule from YARA source text."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable


class YaraSourceError(ValueError):
    """Base class for source selection failures."""


class NoPublicRuleError(YaraSourceError):
    """Raised when a source has no non-private rule declaration."""


class AmbiguousRuleError(YaraSourceError):
    """Raised when a referenced rule has more than one declaration."""


class UnresolvedRuleError(YaraSourceError):
    """Raised when a condition references a rule that cannot be resolved."""


class RuleDependencyCycleError(YaraSourceError):
    """Raised when rule dependencies contain a cycle."""


RuleResolver = Callable[[str], str | None]


@dataclass(frozen=True)
class SelectedYaraSource:
    name: str
    text: str


@dataclass(frozen=True)
class _Token:
    kind: str
    value: str
    start: int
    end: int


@dataclass(frozen=True)
class _Rule:
    name: str
    private: bool
    global_: bool
    source: str
    start: int
    end: int
    strings_span: tuple[int, int] | None
    condition_header_start: int
    condition_span: tuple[int, int]


_CONDITION_WORDS = {
    "all", "and", "any", "ascii", "at", "base64", "base64wide",
    "contains", "defined", "endswith", "entrypoint", "false", "filesize",
    "for", "fullword", "icontains", "iendswith", "iequals", "in",
    "istartswith", "matches", "nocase", "none", "not", "of", "or",
    "kb", "mb", "startswith", "them", "true", "wide", "with", "xor",
}


def _tokens(source: str) -> list[_Token]:
    """Tokenize structural YARA syntax while making opaque text truly opaque."""
    result: list[_Token] = []
    i = 0
    while i < len(source):
        ch = source[i]
        if ch.isspace():
            i += 1
            continue
        if source.startswith("//", i):
            end = source.find("\n", i + 2)
            i = len(source) if end < 0 else end + 1
            continue
        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            if end < 0:
                raise YaraSourceError("unterminated block comment")
            i = end + 2
            continue
        if ch == '"':
            start = i
            i += 1
            while i < len(source):
                if source[i] == "\\":
                    i += 2
                elif source[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
            else:
                raise YaraSourceError("unterminated string literal")
            result.append(_Token("string", source[start:i], start, i))
            continue
        if ch == "/":
            start = i
            previous = result[-1].value if result else ""
            if previous not in {"=", "matches", "(", ","}:
                result.append(_Token("symbol", "/", i, i + 1))
                i += 1
                continue
            i += 1
            in_class = False
            while i < len(source):
                if source[i] == "\\":
                    i += 2
                elif source[i] == "[":
                    in_class = True
                    i += 1
                elif source[i] == "]":
                    in_class = False
                    i += 1
                elif source[i] == "/" and not in_class:
                    i += 1
                    while i < len(source) and source[i].isalpha():
                        i += 1
                    break
                elif source[i] == "\n":
                    # A slash with no same-line terminator is division, not regex.
                    i = start + 1
                    result.append(_Token("symbol", "/", start, i))
                    break
                else:
                    i += 1
            else:
                i = start + 1
                result.append(_Token("symbol", "/", start, i))
                continue
            if (
                i > start + 1
                and result[-1:]
                != [_Token("symbol", "/", start, start + 1)]
            ):
                result.append(_Token("regex", source[start:i], start, i))
            continue
        if ch.isdigit():
            start = i
            i += 1
            if result and result[-1].value in {"$", "#", "@", "!"}:
                while i < len(source) and (source[i].isalnum() or source[i] == "_"):
                    i += 1
                result.append(_Token("ident", source[start:i], start, i))
                continue
            if ch == "0" and i < len(source) and source[i] in {"x", "X"}:
                i += 1
                while i < len(source) and source[i] in "0123456789abcdefABCDEF":
                    i += 1
            else:
                while i < len(source) and (source[i].isdigit() or source[i] == "."):
                    i += 1
            result.append(_Token("number", source[start:i], start, i))
            continue
        if ch.isalpha() or ch == "_":
            start = i
            i += 1
            while i < len(source) and (source[i].isalnum() or source[i] == "_"):
                i += 1
            result.append(_Token("ident", source[start:i], start, i))
            continue
        result.append(_Token("symbol", ch, i, i + 1))
        i += 1
    return result


def _parse_source(source: str) -> tuple[list[_Rule], list[str]]:
    tokens = _tokens(source)
    rules: list[_Rule] = []
    imports: list[str] = []
    depth = 0
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if depth == 0 and token.value == "import" and i + 1 < len(tokens):
            module = tokens[i + 1]
            if module.kind == "string":
                imports.append(module.value[1:-1])
                i += 2
                continue
        if depth == 0 and token.value in {"private", "global", "rule"}:
            start_i = i
            qualifiers: list[str] = []
            while i < len(tokens) and tokens[i].value in {"private", "global"}:
                qualifiers.append(tokens[i].value)
                i += 1
            if i >= len(tokens) or tokens[i].value != "rule":
                i = start_i + 1
                continue
            if i + 1 >= len(tokens) or tokens[i + 1].kind != "ident":
                raise YaraSourceError("rule declaration has no name")
            name = tokens[i + 1].value
            open_i = i + 2
            while open_i < len(tokens) and tokens[open_i].value != "{":
                open_i += 1
            if open_i == len(tokens):
                raise YaraSourceError(f"rule {name!r} has no body")
            nested = 1
            close_i = open_i + 1
            while close_i < len(tokens) and nested:
                if tokens[close_i].value == "{":
                    nested += 1
                elif tokens[close_i].value == "}":
                    nested -= 1
                close_i += 1
            if nested:
                raise YaraSourceError(f"rule {name!r} has an unterminated body")
            close_token_i = close_i - 1
            sections: dict[str, tuple[int, int, int]] = {}
            body_depth = 1
            headers: list[tuple[str, int, int]] = []
            j = open_i + 1
            while j < close_token_i:
                value = tokens[j].value
                if value == "{":
                    body_depth += 1
                elif value == "}":
                    body_depth -= 1
                elif (
                    body_depth == 1
                    and value in {"meta", "strings", "condition"}
                    and j + 1 < close_token_i
                    and tokens[j + 1].value == ":"
                ):
                    headers.append((value, tokens[j].start, tokens[j + 1].end))
                j += 1
            for index, (section, _header_start, content_start) in enumerate(headers):
                content_end = (
                    headers[index + 1][1]
                    if index + 1 < len(headers)
                    else tokens[close_token_i].start
                )
                sections[section] = (_header_start, content_start, content_end)
            if "condition" not in sections:
                raise YaraSourceError(f"rule {name!r} has no condition section")
            rules.append(
                _Rule(
                    name=name,
                    private="private" in qualifiers,
                    global_="global" in qualifiers,
                    source=source,
                    start=tokens[start_i].start,
                    end=tokens[close_token_i].end,
                    strings_span=(sections["strings"][1], sections["strings"][2])
                    if "strings" in sections
                    else None,
                    condition_header_start=sections["condition"][0],
                    condition_span=(sections["condition"][1], sections["condition"][2]),
                )
            )
            i = close_i
            continue
        if token.value == "{":
            depth += 1
        elif token.value == "}" and depth:
            depth -= 1
        i += 1
    return rules, imports


def _replace(source: str, replacements: list[tuple[int, int, str]]) -> str:
    for start, end, value in sorted(replacements, reverse=True):
        source = source[:start] + value + source[end:]
    return source


def _string_ids(text: str) -> set[str]:
    tokens = _tokens(text)
    return {
        tokens[i + 1].value
        for i, token in enumerate(tokens[:-1])
        if token.value == "$" and tokens[i + 1].kind in {"ident", "number"}
    }


def _name_anonymous_strings(
    text: str,
    rule_name: str,
    used_strings: set[str],
) -> tuple[str, list[str]]:
    tokens = _tokens(text)
    replacements: list[tuple[int, int, str]] = []
    names: list[str] = []
    for index, token in enumerate(tokens[:-1]):
        if token.value != "$" or tokens[index + 1].value != "=":
            continue
        base = f"__{rule_name}_anon_{len(names) + 1}"
        candidate = base
        suffix = 2
        while candidate in used_strings:
            candidate = f"{base}_{suffix}"
            suffix += 1
        used_strings.add(candidate)
        names.append(candidate)
        replacements.append((token.start, token.end, f"${candidate}"))
    return _replace(text, replacements), names


def _rename_strings(text: str, names: dict[str, str]) -> str:
    tokens = _tokens(text)
    replacements = []
    for i, token in enumerate(tokens[:-1]):
        if token.value in {"$", "#", "@", "!"} and tokens[i + 1].kind in {"ident", "number"}:
            name = tokens[i + 1].value
            if name in names:
                replacements.append((tokens[i + 1].start, tokens[i + 1].end, names[name]))
            elif token.value == "$" and i + 2 < len(tokens) and tokens[i + 2].value == "*":
                prefixes = {
                    renamed[:len(renamed) - len(original)] + name
                    for original, renamed in names.items()
                    if original.startswith(name)
                }
                if len(prefixes) == 1:
                    replacements.append(
                        (tokens[i + 1].start, tokens[i + 1].end, prefixes.pop())
                    )
    return _replace(text, replacements)


def _them_quantifiers(condition: str) -> list[tuple[int, int, str]]:
    tokens = _tokens(condition)
    matches: list[tuple[int, int, str]] = []
    for index in range(len(tokens) - 2):
        quantifier = tokens[index]
        if not (
            quantifier.kind == "number"
            or quantifier.value.lower() in {"all", "any", "none"}
        ):
            continue
        if tokens[index + 1].value.lower() != "of" or tokens[index + 2].value.lower() != "them":
            continue
        matches.append(
            (
                quantifier.start,
                tokens[index + 2].end,
                condition[quantifier.start:tokens[index + 1].end],
            )
        )
    return matches


def _scope_them(condition: str, string_names: list[str]) -> str:
    matches = _them_quantifiers(condition)
    if not matches:
        return condition
    if not string_names:
        raise YaraSourceError("a rule using 'of them' has no named strings to scope")
    selector = "(" + ", ".join(f"${name}" for name in string_names) + ")"
    return _replace(
        condition,
        [(start, end, f"{prefix} {selector}") for start, end, prefix in matches],
    )


def select_yara_source(
    source: str,
    *,
    resolver: RuleResolver | None = None,
) -> SelectedYaraSource:
    """Select the first public rule and inline its transitive rule dependencies.

    ``resolver`` may explicitly provide source text for dependencies absent from
    the input. It is never called for a rule available in the same source.
    """
    source_rules, source_imports = _parse_source(source)
    selected = next((rule for rule in source_rules if not rule.private), None)
    if selected is None:
        raise NoPublicRuleError("YARA source contains no non-private rule")

    rules: dict[str, list[_Rule]] = {}
    imports = list(source_imports)
    implicit_globals = [
        rule for rule in source_rules if rule.global_ and rule.name != selected.name
    ]
    for rule in source_rules:
        rules.setdefault(rule.name, []).append(rule)

    selected_strings = (
        source[selected.strings_span[0]:selected.strings_span[1]]
        if selected.strings_span else ""
    )
    used_strings = _string_ids(selected_strings)
    selected_strings, _ = _name_anonymous_strings(
        selected_strings, "aray", used_strings
    )
    helper_strings: list[str] = []
    visiting: list[str] = []
    completed: dict[str, str] = {}

    def register_external(external: str) -> list[_Rule]:
        external_rules, external_imports = _parse_source(external)
        for module in external_imports:
            if module not in imports:
                imports.append(module)
        for rule in external_rules:
            existing = rules.setdefault(rule.name, [])
            if rule not in existing:
                existing.append(rule)
            if (
                rule.global_
                and rule.name != selected.name
                and rule not in implicit_globals
            ):
                implicit_globals.append(rule)
        return external_rules

    def load_rule(name: str) -> _Rule:
        matches = rules.get(name, [])
        if len(matches) > 1:
            raise AmbiguousRuleError(f"rule {name!r} has multiple declarations")
        if matches:
            return matches[0]
        external = resolver(name) if resolver is not None else None
        if external is None:
            raise UnresolvedRuleError(f"unresolved rule dependency {name!r}")
        external_rules = register_external(external)
        matches = [rule for rule in external_rules if rule.name == name]
        if len(matches) != 1:
            detail = "not found" if not matches else "ambiguous"
            raise AmbiguousRuleError(
                f"resolver source for {name!r} is {detail}"
            )
        return matches[0]

    def condition_identifiers(condition: str) -> list[_Token]:
        tokens = _tokens(condition)
        imported = set(imports)
        locals_ = {
            tokens[i + 2].value
            for i in range(len(tokens) - 3)
            if tokens[i].value == "for"
            and tokens[i + 1].value in {"all", "any", "none"}
            and tokens[i + 2].kind == "ident"
            and tokens[i + 3].value == "in"
        }
        result = []
        for i, token in enumerate(tokens):
            if token.kind != "ident" or token.value.lower() in _CONDITION_WORDS:
                continue
            previous = tokens[i - 1].value if i else ""
            following = tokens[i + 1].value if i + 1 < len(tokens) else ""
            if i > 1 and tokens[i - 2].value == "$" and tokens[i - 1].kind == "number":
                continue
            if previous in {"$", "#", "@", "!", "."} or following == "(":
                continue
            if token.value in imported or token.value in locals_ or following == ".":
                continue
            result.append(token)
        return result

    def inline_rule_sets(condition: str, current_rule_name: str) -> str:
        tokens = _tokens(condition)
        replacements: list[tuple[int, int, str]] = []
        index = 0
        while index + 3 < len(tokens):
            quantifier = tokens[index]
            if not (
                quantifier.kind == "number"
                or quantifier.value.lower() in {"all", "any", "none"}
            ):
                index += 1
                continue
            percentage = (
                quantifier.kind == "number"
                and index + 2 < len(tokens)
                and tokens[index + 1].value == "%"
            )
            of_index = index + 2 if percentage else index + 1
            if (
                of_index + 1 >= len(tokens)
                or tokens[of_index].value.lower() != "of"
                or tokens[of_index + 1].value != "("
            ):
                index += 1
                continue
            close = of_index + 2
            depth = 1
            while close < len(tokens) and depth:
                if tokens[close].value == "(":
                    depth += 1
                elif tokens[close].value == ")":
                    depth -= 1
                close += 1
            if depth:
                break
            selector_tokens = tokens[of_index + 2:close - 1]
            if not selector_tokens or any(token.value == "$" for token in selector_tokens):
                index = close
                continue
            dependency_names: list[str] = []
            selector_index = 0
            valid_selector = True
            while selector_index < len(selector_tokens):
                selector = selector_tokens[selector_index]
                if selector.kind != "ident" or selector.value.lower() == "them":
                    valid_selector = False
                    break
                if (
                    selector_index + 1 < len(selector_tokens)
                    and selector_tokens[selector_index + 1].value == "*"
                ):
                    matches = [
                        name
                        for name in rules
                        if name.startswith(selector.value) and name != current_rule_name
                    ]
                    if not matches and resolver is not None:
                        external = resolver(f"{selector.value}*")
                        if external is not None:
                            register_external(external)
                            matches = [
                                name
                                for name in rules
                                if name.startswith(selector.value)
                                and name != current_rule_name
                            ]
                    dependency_names.extend(matches)
                    selector_index += 2
                else:
                    dependency_names.append(selector.value)
                    selector_index += 1
                if selector_index < len(selector_tokens):
                    if selector_tokens[selector_index].value != ",":
                        valid_selector = False
                        break
                    selector_index += 1
            dependency_names = list(dict.fromkeys(dependency_names))
            if not valid_selector:
                index = close
                continue
            if not dependency_names:
                raise UnresolvedRuleError(
                    f"rule set dependency {condition[quantifier.start:tokens[close - 1].end]!r} has no matches"
                )
            value = quantifier.value.lower()
            if value == "all":
                chosen = dependency_names
                negate = False
            elif value == "none":
                chosen = dependency_names
                negate = True
            else:
                if value == "any":
                    required = 1
                elif percentage:
                    required = (int(value) * len(dependency_names) + 99) // 100
                else:
                    required = int(value)
                if required > len(dependency_names):
                    raise UnresolvedRuleError(
                        f"rule set dependency requires {required} of {len(dependency_names)} rules"
                    )
                if required == 0:
                    chosen = dependency_names
                    negate = True
                else:
                    chosen = dependency_names[:required]
                    negate = False
            terms = [f"({inline(load_rule(name))})" for name in chosen]
            if negate:
                replacement = " and ".join(f"not {term}" for term in terms)
            else:
                replacement = " and ".join(terms)
            replacements.append(
                (quantifier.start, tokens[close - 1].end, f"({replacement})")
            )
            index = close
        return _replace(condition, replacements)

    def inline(rule: _Rule) -> str:
        if rule.name in completed:
            return completed[rule.name]
        if rule.name in visiting:
            cycle = " -> ".join([*visiting[visiting.index(rule.name):], rule.name])
            raise RuleDependencyCycleError(f"rule dependency cycle: {cycle}")
        visiting.append(rule.name)

        string_text = (
            selected_strings
            if rule.name == selected.name
            else (
                rule.source[rule.strings_span[0]:rule.strings_span[1]]
                if rule.strings_span else ""
            )
        )
        rename: dict[str, str] = {}
        anonymous_names: list[str] = []
        if rule.name != selected.name:
            string_text, anonymous_names = _name_anonymous_strings(
                string_text, rule.name, used_strings
            )
            for old_name in sorted(_string_ids(string_text)):
                if old_name in anonymous_names:
                    continue
                base = f"__{rule.name}_{old_name}"
                candidate = base
                suffix = 2
                while candidate in used_strings:
                    candidate = f"{base}_{suffix}"
                    suffix += 1
                used_strings.add(candidate)
                rename[old_name] = candidate

        condition_start, condition_end = rule.condition_span
        condition = rule.source[condition_start:condition_end].strip()
        condition = _rename_strings(condition, rename)
        if rule.name != selected.name:
            scoped_names = sorted(
                {rename.get(name, name) for name in _string_ids(string_text)}
                | set(anonymous_names)
            )
            condition = _scope_them(condition, scoped_names)
        condition = inline_rule_sets(condition, rule.name)
        replacements: list[tuple[int, int, str]] = []
        for token in condition_identifiers(condition):
            dependency = load_rule(token.value)
            replacements.append((token.start, token.end, f"({inline(dependency)})"))
        condition = _replace(condition, replacements)

        if rule.name != selected.name and string_text.strip():
            helper_strings.append(_rename_strings(string_text, rename).strip())
        visiting.pop()
        completed[rule.name] = condition
        return condition

    selected_condition = inline(selected)
    global_index = 0
    while global_index < len(implicit_globals):
        global_rule = implicit_globals[global_index]
        selected_condition = f"({inline(global_rule)}) and ({selected_condition})"
        global_index += 1
    if helper_strings and _them_quantifiers(selected_condition):
        selected_condition = _scope_them(
            selected_condition, sorted(_string_ids(selected_strings))
        )
    rule_text = source[selected.start:selected.end]
    condition_start = selected.condition_span[0] - selected.start
    condition_end = selected.condition_span[1] - selected.start
    original_condition = rule_text[condition_start:condition_end]
    leading = len(original_condition) - len(original_condition.lstrip())
    trailing = len(original_condition) - len(original_condition.rstrip())
    suffix = original_condition[-trailing:] if trailing else ""
    replacement_condition = (
        original_condition[:leading] + selected_condition + suffix
    )
    edits = [(condition_start, condition_end, replacement_condition)]
    if selected.strings_span:
        strings_start = selected.strings_span[0] - selected.start
        strings_end = selected.strings_span[1] - selected.start
        edits.append((strings_start, strings_end, selected_strings))
    if helper_strings:
        merged = "\n        " + "\n        ".join(helper_strings) + "\n"
        if selected.strings_span:
            insert_at = selected.strings_span[1] - selected.start
            edits.append((insert_at, insert_at, merged))
        else:
            header_start = selected.condition_header_start - selected.start
            edits.append((header_start, header_start, f"strings:{merged}    "))
    rule_text = _replace(rule_text, edits)
    import_text = "\n".join(f'import "{module}"' for module in dict.fromkeys(imports))
    text = f"{import_text}\n\n{rule_text}" if import_text else rule_text
    return SelectedYaraSource(name=selected.name, text=text)


def select_yara_file(path: Path) -> SelectedYaraSource:
    """Select one standalone rule, resolving unique dependencies beside *path*."""
    source = path.read_text(errors="replace")
    sibling_sources: list[str] | None = None

    def resolve(name: str) -> str | None:
        nonlocal sibling_sources
        if sibling_sources is None:
            sibling_sources = [
                candidate.read_text(errors="replace")
                for candidate in sorted(path.parent.glob("*.yar"))
                if candidate != path
            ]
        matches: list[str] = []
        wildcard = name.endswith("*")
        prefix = name[:-1] if wildcard else name
        for sibling_source in sibling_sources:
            try:
                sibling_rules, _ = _parse_source(sibling_source)
            except YaraSourceError:
                continue
            if any(
                rule.name.startswith(prefix) if wildcard else rule.name == name
                for rule in sibling_rules
            ):
                matches.append(sibling_source)
        if wildcard:
            return "\n".join(matches) if matches else None
        if len(matches) > 1:
            raise AmbiguousRuleError(
                f"rule dependency {name!r} is declared in multiple sibling files"
            )
        return matches[0] if matches else None

    return select_yara_source(source, resolver=resolve)


def extract_first_rule_text(source: str) -> str:
    """Compatibility helper returning strict standalone selected rule text."""
    return select_yara_source(source).text


def extract_first_rule_name(source: str) -> str | None:
    """Compatibility helper returning the selected rule name, or ``None``."""
    rules, _imports = _parse_source(source)
    selected = next((rule for rule in rules if not rule.private), None)
    return selected.name if selected else None
