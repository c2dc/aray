import json
from pathlib import Path

import pytest

from aray.yara_validation import (
    canonicalize_normalization,
    normalization_is_proven,
    validate_normalization,
)
from aray.yara_source import select_yara_file


@pytest.mark.parametrize(
    "candidate",
    [
        "Expected { condition: true }",
        "Expected\n{ condition: true }",
        "Expected : tag\n{ condition: true }",
    ],
)
def test_safely_canonicalizes_three_missing_rule_shapes(candidate):
    assert validate_normalization("rule Expected { condition: true }", candidate) is None


def test_does_not_canonicalize_a_different_missing_rule_name():
    error = validate_normalization(
        "rule Expected { condition: true }", "Unexpected { condition: true }"
    )
    assert "syntax validation failed" in error


def test_requires_exactly_one_non_private_rule_with_selected_original_name():
    original = "private rule Helper { condition: true } rule Expected { condition: true }"
    assert validate_normalization(original, "rule Expected { condition: true }") is None

    error = validate_normalization(
        original,
        "rule Expected { condition: true } rule Extra { condition: true }",
    )
    assert "exactly one rule" in error

    error = validate_normalization(original, "rule Other { condition: true }")
    assert "must be 'Expected'" in error

    error = validate_normalization(
        original,
        "rule Expected { condition: true } private rule Extra { condition: true }",
    )
    assert "exactly one rule" in error


def test_rejects_added_nocase_modifier_on_retained_string():
    original = 'rule R { strings: $a = "value" condition: $a }'
    normalized = 'rule R { strings: $a = "value" nocase condition: $a }'
    error = validate_normalization(original, normalized)
    assert "modifier validation failed for $a" in error
    assert "nocase" in error


def test_canonicalization_restores_retained_modifiers():
    original = '''rule R {
strings:
    $a = "value"
condition:
    $a
}'''
    normalized = original.replace('"value"', '"value" nocase')
    candidate = canonicalize_normalization(original, normalized)
    assert "nocase" not in candidate
    assert validate_normalization(original, candidate) is None


def test_cve_2018_20250_candidate_is_valid():
    original = Path("evaluation/yara-repos/rules/cve_rules/CVE-2018-20250.yar").read_text()
    normalized = Path("evaluation/normalized-gpt-4.1/cve_rules/CVE-2018-20250.yar").read_text()
    assert validate_normalization(original, normalized) is None
    assert normalization_is_proven(original, normalized) is True


def _count_rule(condition: str, declaration_count: int = 18) -> str:
    declarations = "\n".join(
        f'$string{i} = "value{i}"' for i in range(declaration_count)
    )
    return f"rule Count {{ strings:\n{declarations}\ncondition: {condition} }}"


def test_bleedinglife_17_of_18_candidate_is_valid():
    original = Path(
        "evaluation/yara-repos/rules/exploit_kits/EK_BleedingLife.yar"
    ).read_text()
    normalized = Path(
        "evaluation/normalized-gpt-4.1/exploit_kits/EK_BleedingLife.yar"
    ).read_text()
    # yara-python rejects an unreferenced declaration, so retain the selected 17.
    normalized = normalized.replace('   $string17 = "Scene 1"\n', "")
    assert validate_normalization(original, normalized) is None
    assert normalization_is_proven(original, normalized) is True


@pytest.mark.parametrize("count", [16, 18])
def test_rejects_fewer_or_extra_count_witnesses(count):
    original = _count_rule("17 of them")
    witnesses = " and ".join(f"$string{i}" for i in range(count))
    error = validate_normalization(original, _count_rule(witnesses, count))
    assert "expected exactly 17 witness(es)" in error


def test_prefix_count_requires_mandatory_string_and_exactly_one_witness():
    original = """rule R {
strings:
    $A = "mandatory"
    $hexstring1 = { 01 }
    $hexstring2 = { 02 }
condition:
    $A and 1 of ($hexstring*)
}"""
    valid = """rule R {
strings:
    $A = "mandatory"
    $hexstring1 = { 01 }
condition:
    $A and $hexstring1
}"""
    assert validate_normalization(original, valid) is None

    error = validate_normalization(
        original, valid.replace("$A and $hexstring1", "$A or $hexstring1")
    )
    assert "must be conjoined" in error

    extra = valid.replace("condition:", "$hexstring2 = { 02 }\ncondition:").replace(
        "$A and $hexstring1", "$A and $hexstring1 and $hexstring2"
    )
    error = validate_normalization(original, extra)
    assert "expected exactly 1 witness(es)" in error


def test_rejects_hex_bytes_that_do_not_match_original_pattern():
    original = """rule R {
strings:
    $a = { 01 ?? 03 }
condition:
    $a
}"""
    normalized = original.replace("{ 01 ?? 03 }", "{ 01 02 04 }")
    error = validate_normalization(original, normalized)
    assert "Hex witness validation failed" in error


def test_validates_partial_nibble_hex_witness():
    original = """rule R {
strings:
    $a = { 56 3? ?A }
condition:
    $a
}"""
    valid = original.replace("{ 56 3? ?A }", "{ 56 30 0A }")
    invalid = original.replace("{ 56 3? ?A }", "{ 56 40 0A }")
    assert validate_normalization(original, valid) is None
    assert "Hex witness validation failed" in validate_normalization(original, invalid)


def test_canonicalizes_fixed_jump_with_exact_byte_count():
    original = """rule Ponmocup {
strings:
    $1100 = { 4D 5A 90 [29] 4C 04 }
condition:
    $1100
}"""
    wrong_witness = "{ 4D 5A 90 " + " ".join(["00"] * 28) + " 4C 04 }"
    normalized = original.replace("{ 4D 5A 90 [29] 4C 04 }", wrong_witness)

    candidate = canonicalize_normalization(original, normalized)

    expected_witness = "{ 4D 5A 90 " + " ".join(["00"] * 29) + " 4C 04 }"
    assert expected_witness in candidate
    assert validate_normalization(original, candidate) is None


def test_canonicalizes_ranged_jump_and_partial_wildcards():
    original = """rule R {
strings:
    $a = { 56 3? ?A [2-4] FF }
condition:
    $a
}"""
    normalized = original.replace(
        "{ 56 3? ?A [2-4] FF }", "{ 56 31 1A 00 FF }"
    )

    candidate = canonicalize_normalization(original, normalized)

    assert "{ 56 30 0A 00 00 FF }" in candidate
    assert validate_normalization(original, candidate) is None


def test_canonicalizes_long_retained_literal_without_counting_characters():
    original_value = "f" * 252
    normalized_value = "f" * 300
    original = f'''rule R {{
strings:
    $b = "{original_value}" nocase
condition:
    $b
}}'''
    normalized = original.replace(original_value, normalized_value)

    candidate = canonicalize_normalization(original, normalized)

    assert f'$b = "{original_value}" nocase' in candidate
    assert normalized_value not in candidate
    assert validate_normalization(original, candidate) is None


def test_canonicalizes_retained_literal_with_escapes():
    original = r'''rule R {
strings:
    $a = "quoted: \"value\"; path: C:\\tmp"
condition:
    $a
}'''
    normalized = original.replace(
        r'"quoted: \"value\"; path: C:\\tmp"', '"different"'
    )

    candidate = canonicalize_normalization(original, normalized)

    assert r'$a = "quoted: \"value\"; path: C:\\tmp"' in candidate
    assert validate_normalization(original, candidate) is None


def test_canonicalizes_retained_literal_emitted_as_hex():
    original = 'rule R { strings: $a = "ABC" condition: $a }'
    normalized = 'rule R { strings: $a = { 41 42 43 } condition: $a }'

    candidate = canonicalize_normalization(original, normalized)

    assert '$a = "ABC"' in candidate
    assert validate_normalization(original, candidate) is None


def test_canonicalizes_modified_fixed_hex_value():
    original = 'rule R { strings: $a = { DE AD BE EF } condition: $a }'
    normalized = 'rule R { strings: $a = { DE AD 00 EF } condition: $a }'

    candidate = canonicalize_normalization(original, normalized)

    assert '$a = { DE AD BE EF }' in candidate
    assert validate_normalization(original, candidate) is None


def test_does_not_canonicalize_regex_witness_back_to_regex():
    original = 'rule R { strings: $a = /ab+c/ condition: $a }'
    normalized = 'rule R { strings: $a = "abc" condition: $a }'

    candidate = canonicalize_normalization(original, normalized)

    assert '$a = "abc"' in candidate
    assert "/ab+c/" not in candidate
    assert validate_normalization(original, candidate) is None


def test_does_not_guess_witness_for_complex_hex_alternative():
    original = 'rule R { strings: $a = { ( 01 | 02 ) [2] FF } condition: $a }'
    normalized = 'rule R { strings: $a = { 02 00 00 FF } condition: $a }'

    candidate = canonicalize_normalization(original, normalized)

    assert '$a = { 02 00 00 FF }' in candidate
    assert validate_normalization(original, candidate) is None


def test_validates_anonymous_regex_replacements_by_declaration_order():
    original = 'rule R { strings: $ = /ab+c/ condition: any of them }'
    valid = 'rule R { strings: $ = "abc" condition: any of them }'
    invalid = 'rule R { strings: $ = "ac" condition: any of them }'
    assert validate_normalization(original, valid) is None
    assert "Anonymous string validation failed" in validate_normalization(original, invalid)


def test_anonymous_witness_can_retain_a_later_original_declaration():
    original = 'rule R { strings: $ = /foo/ $ = /bar/ condition: any of them }'
    normalized = 'rule R { strings: $ = "bar" condition: any of them }'
    assert validate_normalization(original, normalized) is None


def test_canonicalizes_named_alias_for_pre_named_anonymous_string():
    original = '''rule R {
strings:
    $__aray_anon_1 = "one"
    $__aray_anon_2 = "two"
condition:
    1 of them
}'''
    normalized = '''rule R {
strings:
    $chosen = "two"
condition:
    $chosen
}'''
    candidate = canonicalize_normalization(original, normalized)
    assert "$__aray_anon_2 = \"two\"" in candidate
    assert "$chosen" not in candidate
    assert validate_normalization(original, candidate) is None


def test_canonicalized_alias_updates_count_offset_and_length_references():
    original = '''rule R {
strings:
    $__aray_anon_1 = "one"
condition:
    #__aray_anon_1 > 0
}'''
    normalized = '''rule R {
strings:
    $x = "one"
condition:
    #x > 0 and @x[1] >= 0 and !x[1] == 3
}'''
    candidate = canonicalize_normalization(original, normalized)
    assert "#__aray_anon_1" in candidate
    assert "@__aray_anon_1[1]" in candidate
    assert "!__aray_anon_1[1]" in candidate
    assert "$x" not in candidate


def test_canonicalizes_single_anonymous_reference_and_exact_count():
    original = '''rule R {
strings:
    $__aray_anon_1 = "one"
    $__aray_anon_2 = "two"
condition:
    1 of them
}'''
    single = '''rule R {
strings:
    $ = "one"
condition:
    $
}'''
    single_candidate = canonicalize_normalization(original, single)
    assert "$__aray_anon_1 = \"one\"" in single_candidate
    assert "condition:\n    $__aray_anon_1" in single_candidate

    exact = '''rule R {
strings:
    $ = "one"
condition:
    1 of them
}'''
    exact_candidate = canonicalize_normalization(original, exact)
    assert "1 of them" not in exact_candidate
    assert "condition:\n    $__aray_anon_1" in exact_candidate


def test_validates_multiple_declarations_on_the_same_line():
    original = 'rule R { strings: $a = "a" $b = "b" condition: 1 of them }'
    normalized = 'rule R { strings: $a = "a" $b = "changed" condition: $a and $b }'
    error = validate_normalization(original, normalized)
    assert "value validation failed for $b" in error


def test_condition_literals_are_not_folded_when_proving_count_expansion():
    original = '''rule R {
strings:
    $a = "a"
condition:
    1 of them and "AB CD" == "AB CD"
}'''
    normalized = original.replace(
        '1 of them and "AB CD" == "AB CD"',
        '$a and "AB CD" == "abcd"',
    )
    assert validate_normalization(original, normalized) is None
    assert normalization_is_proven(original, normalized) is False


def test_count_text_inside_literal_is_not_treated_as_an_expression():
    original = '''rule R {
strings:
    $a = "a"
condition:
    $a and "1 of them" == "1 of them"
}'''
    assert validate_normalization(original, original) is None
    assert normalization_is_proven(original, original) is False


def test_all_of_them_expansion_can_be_proven_without_llm_judge():
    original = '''rule R {
strings:
    $a = /a+/
    $b = "b"
condition:
    all of them
}'''
    normalized = '''rule R {
strings:
    $a = "a"
    $b = "b"
condition:
    $a and $b
}'''
    assert validate_normalization(original, normalized) is None
    assert normalization_is_proven(original, normalized) is True


@pytest.mark.parametrize(
    "rule_name",
    [
        "malware_red_leaves_generic",
        "MW_neuron2_loader_strings",
        "FUDCrypter",
        "MSILStealer",
        "Maze",
    ],
)
def test_second_glm_round_anonymous_failures_are_canonicalized(rule_name):
    report = json.loads(
        Path(
            "evaluation/reports/2026-08-07T21-26-04-glm-5.2-2round/"
            "norm_report.json"
        ).read_text()
    )
    result = next(item for item in report["results"] if item["rule_name"] == rule_name)
    original = select_yara_file(Path(result["rule_path"])).text
    candidate = canonicalize_normalization(original, result["normalized_rule"])
    assert validate_normalization(original, candidate) is None


def test_modifier_words_inside_block_comments_are_not_restored_as_modifiers():
    path = Path("evaluation/yara-repos/rules/malware/MALW_Kraken.yar")
    original = select_yara_file(path).text
    candidate = canonicalize_normalization(original, original)
    assert "base64 fullword" not in candidate
    assert validate_normalization(original, candidate) is None


def test_modifier_words_inside_multiline_comments_are_ignored():
    original = '''rule R {
strings:
    $a = "CaseSensitive" /* nocase
        remains a comment */
condition:
    $a
}'''
    candidate = canonicalize_normalization(original, original)
    assert '"CaseSensitive" nocase' not in candidate
    assert "remains a comment */" in candidate
    assert validate_normalization(original, candidate) is None


def test_modifiers_on_following_line_are_preserved_and_validated():
    original = '''rule R {
strings:
    $a = "CaseSensitive"
        nocase
condition:
    $a
}'''
    normalized = '''rule R {
strings:
    $a = "CaseSensitive"
condition:
    $a
}'''
    assert "modifier validation failed" in validate_normalization(original, normalized)
    candidate = canonicalize_normalization(original, normalized)
    assert '"CaseSensitive" nocase' in candidate
    assert validate_normalization(original, candidate) is None
