"""Unit tests for aray/evaluator.py — no LLM calls."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aray.evaluator import (
    EvalConfig,
    EvalResult,
    OriginalRuleAssociation,
    _associate_original_rules,
    _build_eval_config,
    _execution_provenance,
    _extract_first_rule_name,
    _extract_first_rule_text,
    _find_yar_files,
    _has_yara_match,
    _is_index_file,
    _load_config_file,
    _print_summary,
    _run_one,
    _write_report,
    _yara_scan,
    main as evaluator_main,
    parse_args,
    run_evaluation,
)
from aray.yara_source import (
    AmbiguousRuleError,
    NoPublicRuleError,
    RuleDependencyCycleError,
    UnresolvedRuleError,
    select_yara_file,
    select_yara_source,
)


# ---------------------------------------------------------------------------
# _is_index_file
# ---------------------------------------------------------------------------

class TestIsIndexFile:
    def test_name_exact_index_yar(self, tmp_path):
        f = tmp_path / "index.yar"
        f.write_text('include "other.yar"\n')
        assert _is_index_file(f) is True

    def test_name_suffix_index_yar(self, tmp_path):
        f = tmp_path / "malware_index.yar"
        f.write_text("rule x { condition: true }")
        assert _is_index_file(f) is True

    def test_name_prefix_index_yar(self, tmp_path):
        f = tmp_path / "index_2024.yar"
        f.write_text("rule x { condition: true }")
        assert _is_index_file(f) is True

    def test_content_include_probe(self, tmp_path):
        f = tmp_path / "rules.yar"
        f.write_text('include "sub/rule1.yar"\ninclude "sub/rule2.yar"\n')
        assert _is_index_file(f) is True

    def test_normal_rule_not_index(self, tmp_path):
        f = tmp_path / "ransomware.yar"
        f.write_text('rule Ransom { strings: $a = "pay" condition: $a }')
        assert _is_index_file(f) is False

    def test_name_contains_index_but_not_pattern(self, tmp_path):
        # "myindex_rules.yar" does NOT match _index.yar$ or ^index.yar$ or ^index_
        f = tmp_path / "myindex_rules.yar"
        f.write_text('rule x { condition: true }')
        assert _is_index_file(f) is False

    def test_include_not_at_line_start(self, tmp_path):
        # Indented include should still match (MULTILINE anchors ^ to line start)
        f = tmp_path / "myrule.yar"
        f.write_text('/* header */\ninclude "other.yar"\n')
        assert _is_index_file(f) is True

    def test_include_keyword_inside_string_not_matched(self, tmp_path):
        # "include" inside a YARA string value — no leading whitespace + quote pattern
        f = tmp_path / "myrule.yar"
        f.write_text('rule x { strings: $a = "include \\"foo\\"" condition: $a }')
        assert _is_index_file(f) is False


# ---------------------------------------------------------------------------
# _find_yar_files
# ---------------------------------------------------------------------------

class TestFindYarFiles:
    def _make_tree(self, tmp_path: Path) -> list[Path]:
        """Build a small directory tree with a mix of real rules and index files."""
        sub = tmp_path / "sub"
        sub.mkdir()
        files = []
        for name, content in [
            ("rule_a.yar", 'rule a { condition: true }'),
            ("rule_b.yar", 'rule b { condition: true }'),
            ("index.yar", 'include "rule_a.yar"\ninclude "rule_b.yar"\n'),
            ("sub/rule_c.yar", 'rule c { condition: true }'),
            ("sub/index_sub.yar", 'include "rule_c.yar"\n'),
        ]:
            p = tmp_path / name
            p.write_text(content)
            files.append(p)
        return files

    def test_finds_non_index_yar_files(self, tmp_path):
        self._make_tree(tmp_path)
        result = _find_yar_files([tmp_path])
        names = [p.name for p in result]
        assert "rule_a.yar" in names
        assert "rule_b.yar" in names
        assert "rule_c.yar" in names

    def test_excludes_index_files(self, tmp_path):
        self._make_tree(tmp_path)
        result = _find_yar_files([tmp_path])
        names = [p.name for p in result]
        assert "index.yar" not in names
        assert "index_sub.yar" not in names

    def test_result_is_sorted(self, tmp_path):
        self._make_tree(tmp_path)
        result = _find_yar_files([tmp_path])
        assert result == sorted(result)

    def test_nonexistent_directory_ignored(self, tmp_path):
        result = _find_yar_files([tmp_path / "no_such_dir"])
        assert result == []

    def test_multiple_directories(self, tmp_path):
        dir1 = tmp_path / "d1"
        dir2 = tmp_path / "d2"
        dir1.mkdir()
        dir2.mkdir()
        (dir1 / "r1.yar").write_text('rule r1 { condition: true }')
        (dir2 / "r2.yar").write_text('rule r2 { condition: true }')
        result = _find_yar_files([dir1, dir2])
        names = [p.name for p in result]
        assert "r1.yar" in names
        assert "r2.yar" in names

    def test_accepts_single_yar_file(self, tmp_path):
        rule = tmp_path / "single.yar"
        rule.write_text('rule single { condition: true }')

        assert _find_yar_files([rule]) == [rule]

    def test_accepts_mixed_files_and_directories(self, tmp_path):
        directory = tmp_path / "rules"
        directory.mkdir()
        nested_rule = directory / "nested.yar"
        nested_rule.write_text('rule nested { condition: true }')
        single_rule = tmp_path / "single.yar"
        single_rule.write_text('rule single { condition: true }')

        assert _find_yar_files([single_rule, directory]) == sorted(
            [single_rule, nested_rule]
        )

    def test_ignores_non_yar_file(self, tmp_path):
        text_file = tmp_path / "rule.txt"
        text_file.write_text('rule ignored { condition: true }')

        assert _find_yar_files([text_file]) == []

    def test_excludes_standalone_index_file(self, tmp_path):
        index = tmp_path / "index.yar"
        index.write_text('include "other.yar"\n')

        assert _find_yar_files([index]) == []


class TestAssociateOriginalRules:
    @staticmethod
    def _write_rule(path: Path, name: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"rule {name} {{ condition: true }}")
        return path

    def test_matches_parent_directory_filename_and_rule_name(self, tmp_path):
        normalized = self._write_rule(
            tmp_path / "normalized" / "malware" / "sample.yar", "Sample"
        )
        original = self._write_rule(
            tmp_path / "upstream" / "rules" / "malware" / "sample.yar", "Sample"
        )

        association = _associate_original_rules([normalized], [original])[normalized]

        assert association == OriginalRuleAssociation(path=original)

    def test_chooses_longest_matching_path_suffix(self, tmp_path):
        normalized = self._write_rule(
            tmp_path / "normalized" / "nested" / "malware" / "sample.yar",
            "Sample",
        )
        shorter = self._write_rule(
            tmp_path / "source-a" / "malware" / "sample.yar", "Sample"
        )
        longer = self._write_rule(
            tmp_path / "source-b" / "nested" / "malware" / "sample.yar",
            "Sample",
        )

        association = _associate_original_rules(
            [normalized], [shorter, longer]
        )[normalized]

        assert association.path == longer

    def test_rejects_rule_name_mismatch(self, tmp_path):
        normalized = self._write_rule(
            tmp_path / "normalized" / "malware" / "sample.yar", "Normalized"
        )
        original = self._write_rule(
            tmp_path / "source" / "malware" / "sample.yar", "Original"
        )

        association = _associate_original_rules([normalized], [original])[normalized]

        assert association.path is None
        assert association.failure_category == "original_rule_name_mismatch"

    def test_rejects_ambiguous_best_match(self, tmp_path):
        normalized = self._write_rule(
            tmp_path / "normalized" / "malware" / "sample.yar", "Sample"
        )
        originals = [
            self._write_rule(
                tmp_path / root / "malware" / "sample.yar", "Sample"
            )
            for root in ("source-a", "source-b")
        ]

        association = _associate_original_rules([normalized], originals)[normalized]

        assert association.path is None
        assert association.failure_category == "original_rule_ambiguous"

    def test_requires_matching_parent_directory(self, tmp_path):
        normalized = self._write_rule(
            tmp_path / "normalized" / "malware" / "sample.yar", "Sample"
        )
        original = self._write_rule(
            tmp_path / "source" / "different" / "sample.yar", "Sample"
        )

        association = _associate_original_rules([normalized], [original])[normalized]

        assert association.failure_category == "original_rule_not_found"


# ---------------------------------------------------------------------------
# _extract_first_rule_name
# ---------------------------------------------------------------------------

class TestExtractFirstRuleText:
    _SINGLE = 'rule Foo { strings: $a = "bar" condition: $a }'
    _MULTI = (
        '/* license */\n'
        'rule First { strings: $a = "hello" condition: $a }\n'
        'rule Second { strings: $b = "world" condition: $b }\n'
    )

    def test_single_rule_returned_as_is(self):
        result = _extract_first_rule_text(self._SINGLE)
        assert result == self._SINGLE

    def test_multi_rule_returns_only_first(self):
        result = _extract_first_rule_text(self._MULTI)
        assert 'rule First' in result
        assert 'rule Second' not in result

    def test_strips_file_level_comments(self):
        result = _extract_first_rule_text(self._MULTI)
        assert result.startswith('rule First')

    def test_no_rule_never_falls_back_to_text(self):
        text = '/* no rules here */'
        with pytest.raises(NoPublicRuleError):
            _extract_first_rule_text(text)

    def test_hex_braces_not_miscounted(self):
        text = 'rule Hex { strings: $a = { DE AD BE EF } condition: $a }'
        result = _extract_first_rule_text(text)
        assert result == text

    def test_string_with_braces_not_miscounted(self):
        text = 'rule Str { strings: $a = "open{close}" condition: $a }'
        result = _extract_first_rule_text(text)
        assert result == text

    def test_global_modifier_not_skipped(self):
        text = 'global rule Guarded { condition: true }'
        result = _extract_first_rule_text(text)
        assert result == text

    def test_private_rule_only_is_explicit(self):
        text = 'private rule Hidden { condition: true }'
        with pytest.raises(NoPublicRuleError):
            _extract_first_rule_text(text)

    def test_private_rule_skipped_returns_next_public(self):
        text = (
            'private rule Helper { strings: $x = "secret" condition: $x }\n'
            'rule Public { strings: $a = "hello" condition: $a }\n'
        )
        result = _extract_first_rule_text(text)
        assert 'rule Public' in result
        assert 'rule Helper' not in result

    def test_multiple_private_rules_before_public(self):
        text = (
            'private rule A { condition: true }\n'
            'private rule B { condition: true }\n'
            'rule Real { strings: $s = "match" condition: $s }\n'
        )
        result = _extract_first_rule_text(text)
        assert 'rule Real' in result
        assert 'rule A' not in result
        assert 'rule B' not in result

    def test_line_comment_ignored(self):
        text = 'rule A {\n    // } this brace is a comment\n    condition: true\n}'
        result = _extract_first_rule_text(text)
        assert result == text

    def test_block_comment_ignored(self):
        text = 'rule A {\n    /* } */ condition: true\n}'
        result = _extract_first_rule_text(text)
        assert result == text


class TestExtractFirstRuleName:
    def test_single_rule(self):
        text = 'rule MyMalware { condition: true }'
        assert _extract_first_rule_name(text) == "MyMalware"

    def test_multi_rule_returns_first(self):
        text = 'rule First { condition: true }\nrule Second { condition: true }'
        assert _extract_first_rule_name(text) == "First"

    def test_no_rule_returns_none(self):
        assert _extract_first_rule_name("/* nothing here */") is None

    def test_rule_with_leading_whitespace(self):
        text = '\n  rule   SpacedOut { condition: true }'
        assert _extract_first_rule_name(text) == "SpacedOut"

    def test_empty_string(self):
        assert _extract_first_rule_name("") is None

    def test_private_then_public_returns_public_name(self):
        text = "private rule Helper { condition: true } rule Public { condition: true }"
        assert _extract_first_rule_name(text) == "Public"


class TestYaraSourceSelector:
    def test_fake_headers_in_comments_strings_and_regex_are_ignored(self):
        text = r'''
            // rule Comment { condition: true }
            /* private rule Block { condition: true } */
            rule Real {
                strings:
                    $a = "rule String { condition: true }"
                    $b = /rule Regex \{ condition: true \}/
                condition: any of them
            }
            rule Later { condition: true }
        '''
        selected = select_yara_source(text)
        assert selected.name == "Real"
        assert "rule Later" not in selected.text

    def test_retains_import_directives(self):
        text = 'import "pe"\nimport "hash"\nrule UsesImport { condition: pe.is_pe }'
        selected = select_yara_source(text)
        assert selected.text.startswith('import "pe"\nimport "hash"')

    def test_same_file_dependency_is_inlined(self):
        text = '''
            private rule Helper {
                strings: $needle = "helper"
                condition: $needle
            }
            rule Public {
                strings: $own = "public"
                condition: Helper and $own
            }
        '''
        selected = select_yara_source(text)
        assert "rule Helper" not in selected.text
        assert "$__Helper_needle = \"helper\"" in selected.text
        assert "($__Helper_needle) and $own" in selected.text

    def test_helper_them_scope_does_not_include_selected_strings(self):
        text = '''
            private rule Helper {
                strings: $h = "helper"
                condition: any of them
            }
            rule Public {
                strings: $p = "public"
                condition: Helper and $p
            }
        '''
        selected = select_yara_source(text)
        assert "any of ($__Helper_h)" in selected.text
        assert "any of them" not in selected.text

    def test_anonymous_helper_strings_are_named_and_scoped(self):
        text = '''
            private rule Helper {
                strings: $ = "one" $ = "two"
                condition: any of them
            }
            rule Public { condition: Helper }
        '''
        selected = select_yara_source(text)
        assert "$__Helper_anon_1 = \"one\"" in selected.text
        assert "$__Helper_anon_2 = \"two\"" in selected.text
        assert "any of ($__Helper_anon_1, $__Helper_anon_2)" in selected.text

    def test_selected_anonymous_strings_are_named_before_normalization(self):
        text = '''
            rule Public {
                strings: $ = "one" $ = "two"
                condition: 1 of them
            }
            rule Later { condition: true }
        '''
        selected = select_yara_source(text)
        assert "$__aray_anon_1 = \"one\"" in selected.text
        assert "$__aray_anon_2 = \"two\"" in selected.text
        assert "rule Later" not in selected.text
        assert "1 of them" in selected.text

    def test_private_global_rule_is_an_implicit_dependency(self):
        text = '''
            private global rule Gate {
                strings: $g = "gate"
                condition: $g
            }
            rule Public {
                strings: $p = "public"
                condition: $p
            }
        '''
        selected = select_yara_source(text)
        assert "$__Gate_g = \"gate\"" in selected.text
        assert "($__Gate_g) and ($p)" in selected.text

    def test_scoping_them_does_not_rewrite_condition_literals(self):
        text = '''
            private rule Helper {
                strings: $h = "helper"
                condition: any of them and "any of them" contains "them"
            }
            rule Public { condition: Helper }
        '''
        selected = select_yara_source(text)
        assert '"any of them" contains "them"' in selected.text
        assert "any of ($__Helper_h)" in selected.text

    def test_helper_string_names_are_collision_free(self):
        text = '''
            private rule Helper { strings: $x = "x" condition: $x }
            rule Public {
                strings: $__Helper_x = "occupied"
                condition: Helper and $__Helper_x
            }
        '''
        selected = select_yara_source(text)
        assert "$__Helper_x_2 = \"x\"" in selected.text
        assert "($__Helper_x_2)" in selected.text

    def test_helper_count_offset_and_length_references_are_renamed(self):
        text = '''
            private rule Helper {
                strings: $a = "x"
                condition: #a > 0 and @a[1] >= 0 and !a[1] == 1
            }
            rule Public { condition: Helper }
        '''
        selected = select_yara_source(text)
        assert "#__Helper_a" in selected.text
        assert "@__Helper_a[1]" in selected.text
        assert "!__Helper_a[1]" in selected.text

    def test_rule_set_dependency_selects_sufficient_reachable_subset(self):
        text = '''
            private rule dep_one { strings: $a = "one" condition: $a }
            private rule dep_two { strings: $b = "two" condition: $b }
            rule Public { condition: 1 of (dep_*) }
        '''
        selected = select_yara_source(text)
        assert "$__dep_one_a = \"one\"" in selected.text
        assert "$__dep_two_b" not in selected.text
        assert "dep_*" not in selected.text

    @pytest.mark.parametrize(
        ("quantifier", "expected"),
        [
            ("0", "not ($__dep_one_a) and not ($__dep_two_b)"),
            ("50%", "$__dep_one_a"),
        ],
    )
    def test_rule_set_zero_and_percentage_quantifiers(self, quantifier, expected):
        text = f'''
            private rule dep_one {{ strings: $a = "one" condition: $a }}
            private rule dep_two {{ strings: $b = "two" condition: $b }}
            rule Public {{ condition: {quantifier} of (dep_*) }}
        '''
        selected = select_yara_source(text)
        assert expected in selected.text

    def test_rule_set_dependency_can_resolve_sibling_files(self, tmp_path):
        (tmp_path / "one.yar").write_text(
            'private rule dep_one { strings: $a = "one" condition: $a }'
        )
        (tmp_path / "two.yar").write_text(
            'private rule dep_two { strings: $b = "two" condition: $b }'
        )
        target = tmp_path / "target.yar"
        target.write_text("rule Public { condition: 1 of (dep_*) }")
        selected = select_yara_file(target)
        assert "$__dep_one_a = \"one\"" in selected.text
        assert "dep_*" not in selected.text

    def test_transitive_dependencies_are_deterministic(self):
        text = '''
            private rule Leaf { strings: $x = "leaf" condition: $x }
            private rule Middle { condition: Leaf }
            rule Public { condition: Middle }
        '''
        first = select_yara_source(text).text
        assert first == select_yara_source(text).text
        assert "$__Leaf_x = \"leaf\"" in first
        assert "(($__Leaf_x))" in first

    def test_cycle_is_explicit(self):
        text = '''
            private rule A { condition: B }
            private rule B { condition: A }
            rule Public { condition: A }
        '''
        with pytest.raises(RuleDependencyCycleError, match="A -> B -> A"):
            select_yara_source(text)

    def test_unresolved_dependency_is_explicit(self):
        with pytest.raises(UnresolvedRuleError, match="Missing"):
            select_yara_source("rule Public { condition: Missing }")

    def test_resolver_can_supply_external_dependency(self):
        external = 'private rule External { strings: $x = "ext" condition: $x }'
        selected = select_yara_source(
            "rule Public { condition: External }",
            resolver=lambda name: external if name == "External" else None,
        )
        assert "$__External_x = \"ext\"" in selected.text

    def test_file_selector_resolves_unique_sibling_dependency(self, tmp_path):
        (tmp_path / "common.yar").write_text(
            'private rule External { strings: $x = "ext" condition: $x }'
        )
        target = tmp_path / "target.yar"
        target.write_text("rule Public { condition: External }")

        selected = select_yara_file(target)

        assert selected.name == "Public"
        assert "$__External_x = \"ext\"" in selected.text

    def test_duplicate_dependency_is_ambiguous(self):
        text = '''
            private rule Helper { condition: true }
            private rule Helper { condition: false }
            rule Public { condition: Helper }
        '''
        with pytest.raises(AmbiguousRuleError, match="multiple declarations"):
            select_yara_source(text)


# ---------------------------------------------------------------------------
# _yara_scan
# ---------------------------------------------------------------------------

class TestYaraScan:
    def test_calls_yara_with_correct_args(self, tmp_path):
        rule = tmp_path / "r.yar"
        binary = tmp_path / "app"
        rule.touch()
        binary.touch()

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "RuleName /tmp/app\n"
        mock_result.stderr = ""

        with patch("aray.evaluator.subprocess.run", return_value=mock_result) as mock_run:
            rc, stdout, stderr = _yara_scan(rule, binary)

        mock_run.assert_called_once_with(
            ["yara", str(rule), str(binary)],
            capture_output=True,
            text=True,
        )
        assert rc == 0
        assert stdout == "RuleName /tmp/app\n"
        assert stderr == ""

    def test_filters_by_rule_identifier_when_provided(self, tmp_path):
        rule = tmp_path / "r.yar"
        binary = tmp_path / "app"
        mock_result = MagicMock(returncode=0, stdout="Rule /tmp/app\n", stderr="")

        with patch("aray.evaluator.subprocess.run", return_value=mock_result) as mock_run:
            _yara_scan(rule, binary, "Rule")

        mock_run.assert_called_once_with(
            ["yara", "-i", "Rule", str(rule), str(binary)],
            capture_output=True,
            text=True,
        )

    def test_returns_nonzero_on_mismatch(self, tmp_path):
        rule = tmp_path / "r.yar"
        binary = tmp_path / "app"

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "error"

        with patch("aray.evaluator.subprocess.run", return_value=mock_result):
            rc, stdout, stderr = _yara_scan(rule, binary)

        assert rc == 1
        assert stdout == ""


# ---------------------------------------------------------------------------
# _has_yara_match
# ---------------------------------------------------------------------------

class TestHasYaraMatch:
    def test_plain_match_line(self):
        assert _has_yara_match("RuleName /tmp/app\n") is True

    def test_empty_stdout_no_match(self):
        assert _has_yara_match("") is False

    def test_only_warnings_no_match(self):
        stdout = (
            'warning: rule "Big_Numbers0" in rules.yar(11): string "$c0" may slow down scanning\n'
            'warning: rule "Big_Numbers1" in rules.yar(23): string "$c0" may slow down scanning\n'
        )
        assert _has_yara_match(stdout) is False

    def test_warnings_plus_match(self):
        stdout = (
            'warning: rule "Big_Numbers1" in rules.yar(23): string "$c0" may slow down scanning\n'
            "Big_Numbers0 /tmp/app\n"
        )
        assert _has_yara_match(stdout) is True

    def test_whitespace_only_lines_ignored(self):
        assert _has_yara_match("   \n\t\n") is False


# ---------------------------------------------------------------------------
# EvalResult.to_dict
# ---------------------------------------------------------------------------

class TestEvalResultToDict:
    def test_serialization(self):
        r = EvalResult(
            rule_path="evaluation/rules/cve_rules/CVE-2010-0805.yar",
            rule_name="MSIETabularActivex",
            status="passed",
            error=None,
            duration_seconds=4.21,
            yara_stdout="MSIETabularActivex /tmp/app\n",
            yara_returncode=0,
            normalize_model="gpt-4.1",
            extract_model="gpt-4.1-mini",
        )
        d = r.to_dict()
        assert d["rule_path"] == "evaluation/rules/cve_rules/CVE-2010-0805.yar"
        assert d["rule_name"] == "MSIETabularActivex"
        assert d["status"] == "passed"
        assert d["error"] is None
        assert d["duration_seconds"] == 4.21
        assert d["yara_stdout"] == "MSIETabularActivex /tmp/app\n"
        assert d["yara_returncode"] == 0
        assert d["normalize_model"] == "gpt-4.1"
        assert d["extract_model"] == "gpt-4.1-mini"
        assert d["normalization_source"] == "not_reached"
        assert d["strings_extraction_source"] == "not_reached"
        assert d["constants_extraction_source"] == "not_reached"
        assert d["llm_used"] is False

    def test_failed_result_dict(self):
        r = EvalResult(
            rule_path="evaluation/rules/bad.yar",
            rule_name=None,
            status="failed",
            error="subprocess error",
            duration_seconds=1.5,
            yara_stdout=None,
            yara_returncode=None,
            normalize_model="gpt-4.1",
            extract_model="gpt-4.1",
        )
        d = r.to_dict()
        assert d["status"] == "failed"
        assert d["error"] == "subprocess error"
        assert d["yara_stdout"] is None
        assert d["normalize_model"] == "gpt-4.1"
        assert d["extract_model"] == "gpt-4.1"


# ---------------------------------------------------------------------------
# _load_config_file
# ---------------------------------------------------------------------------

class TestLoadConfigFile:
    def test_valid_toml(self, tmp_path):
        cfg = tmp_path / ".evaluator"
        cfg.write_text('[evaluator]\ndirectories = ["evaluation/rules"]\nworkers = 2\n')
        result = _load_config_file(cfg)
        assert result["evaluator"]["directories"] == ["evaluation/rules"]
        assert result["evaluator"]["workers"] == 2

    def test_missing_file_returns_empty_dict(self, tmp_path):
        result = _load_config_file(tmp_path / "nonexistent")
        assert result == {}

    def test_invalid_toml_raises_value_error(self, tmp_path):
        cfg = tmp_path / ".evaluator"
        cfg.write_text("[invalid toml\n")
        with pytest.raises(ValueError, match="Invalid TOML"):
            _load_config_file(cfg)


# ---------------------------------------------------------------------------
# _print_summary
# ---------------------------------------------------------------------------

class TestPrintSummary:
    def _make_results(self, passed: int, failed: int, skipped: int) -> list[EvalResult]:
        results = []
        for _ in range(passed):
            results.append(EvalResult("p.yar", "R", "passed", None, 1.0, "R /tmp/app\n", 0, "gpt-4.1", "gpt-4.1"))
        for i in range(failed):
            results.append(EvalResult(f"f{i}.yar", "R", "failed", "some error", 1.0, None, None, "gpt-4.1", "gpt-4.1"))
        for _ in range(skipped):
            results.append(EvalResult("s.yar", None, "skipped", None, 0.0, None, None, "gpt-4.1", "gpt-4.1"))
        return results

    def test_summary_output(self, capsys):
        results = self._make_results(35, 5, 2)
        _print_summary(results)
        captured = capsys.readouterr().out
        assert "35/42" in captured
        assert " 5/42" in captured
        assert " 2/42" in captured

    def test_summary_shows_failed_rules(self, capsys):
        results = self._make_results(0, 2, 0)
        _print_summary(results)
        captured = capsys.readouterr().out
        assert "some error" in captured

    def test_summary_empty(self, capsys):
        _print_summary([])
        captured = capsys.readouterr().out
        assert "0/0" in captured

    def test_summary_all_passed(self, capsys):
        results = self._make_results(10, 0, 0)
        _print_summary(results)
        captured = capsys.readouterr().out
        assert "PASSED" in captured
        assert "Failed rules" not in captured


# ---------------------------------------------------------------------------
# _build_eval_config
# ---------------------------------------------------------------------------

class TestBuildEvalConfig:
    def _make_args(self, **kwargs):
        import argparse
        defaults = dict(
            dirs=[],
            model=None,
            normalize_model=None,
            extract_model=None,
            base_url=None,
            normalize_base_url=None,
            extract_base_url=None,
            normalize_api_key=None,
            extract_api_key=None,
            reasoning_effort=None,
            normalize_reasoning_effort=None,
            extract_reasoning_effort=None,
            normalize_no_stream=False,
            extract_no_stream=False,
            scan_only=False,
            no_stream=False,
            workers=None,
            output=None,
            keep_artifacts=False,
            validate_original=None,
            original_directories=None,
        )
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def test_cli_dirs_override_config(self):
        args = self._make_args(dirs=["cli_dir"])
        file_cfg = {"evaluator": {"directories": ["config_dir"]}}
        cfg = _build_eval_config(args, file_cfg)
        assert cfg.directories == ["cli_dir"]

    def test_config_file_dirs_used_when_no_cli_dirs(self):
        args = self._make_args(dirs=[])
        file_cfg = {"evaluator": {"directories": ["config_dir"]}}
        cfg = _build_eval_config(args, file_cfg)
        assert cfg.directories == ["config_dir"]

    def test_original_validation_from_toml(self):
        args = self._make_args()
        file_cfg = {
            "evaluator": {
                "validate_original": True,
                "original_directories": ["source-rules"],
            }
        }

        cfg = _build_eval_config(args, file_cfg)

        assert cfg.validate_original is True
        assert cfg.original_directories == ["source-rules"]

    def test_cli_original_directories_override_toml(self):
        args = self._make_args(
            validate_original=True,
            original_directories=["cli-source-a", "cli-source-b"],
        )
        file_cfg = {"evaluator": {"original_directories": ["toml-source"]}}

        cfg = _build_eval_config(args, file_cfg)

        assert cfg.validate_original is True
        assert cfg.original_directories == ["cli-source-a", "cli-source-b"]

    def test_cli_can_disable_original_validation_from_toml(self):
        args = self._make_args(validate_original=False)
        file_cfg = {"evaluator": {"validate_original": True}}

        cfg = _build_eval_config(args, file_cfg)

        assert cfg.validate_original is False

    def test_default_model_gpt41(self, monkeypatch):
        monkeypatch.delenv("OPENAI_MODEL", raising=False)
        args = self._make_args()
        cfg = _build_eval_config(args, {})
        assert cfg.model == "gpt-4.1"

    def test_cli_model_overrides_config(self):
        args = self._make_args(model="gpt-4o")
        file_cfg = {"evaluator": {"model": "gpt-4.1-mini"}}
        cfg = _build_eval_config(args, file_cfg)
        assert cfg.model == "gpt-4o"

    def test_toml_shared_values_override_role_environment(self, monkeypatch):
        monkeypatch.setenv("NORMALIZE_MODEL", "env-normalize")
        monkeypatch.setenv("EXTRACT_MODEL", "env-extract")
        monkeypatch.setenv("NORMALIZE_BASE_URL", "http://env-normalize")
        monkeypatch.setenv("EXTRACT_BASE_URL", "http://env-extract")
        args = self._make_args()
        file_cfg = {
            "evaluator": {
                "model": "toml-model",
                "base_url": "http://toml-gateway",
            }
        }

        cfg = _build_eval_config(args, file_cfg)

        assert cfg.normalize_model == "toml-model"
        assert cfg.extract_model == "toml-model"
        assert cfg.normalize_base_url == "http://toml-gateway"
        assert cfg.extract_base_url == "http://toml-gateway"

    def test_cli_shared_values_override_role_toml(self):
        args = self._make_args(model="cli-model", base_url="http://cli-gateway")
        file_cfg = {
            "evaluator": {
                "normalize_model": "toml-normalize",
                "extract_model": "toml-extract",
                "normalize_base_url": "http://toml-normalize",
                "extract_base_url": "http://toml-extract",
            }
        }

        cfg = _build_eval_config(args, file_cfg)

        assert cfg.normalize_model == "cli-model"
        assert cfg.extract_model == "cli-model"
        assert cfg.normalize_base_url == "http://cli-gateway"
        assert cfg.extract_base_url == "http://cli-gateway"

    def test_role_toml_values_override_shared_toml(self):
        args = self._make_args()
        file_cfg = {
            "evaluator": {
                "model": "shared-model",
                "normalize_model": "normalize-model",
                "base_url": "http://shared",
                "normalize_base_url": "http://normalize",
            }
        }

        cfg = _build_eval_config(args, file_cfg)

        assert cfg.normalize_model == "normalize-model"
        assert cfg.extract_model == "shared-model"
        assert cfg.normalize_base_url == "http://normalize"
        assert cfg.extract_base_url == "http://shared"

    def test_workers_default_1(self):
        args = self._make_args()
        cfg = _build_eval_config(args, {})
        assert cfg.workers == 1

    def test_workers_from_cli(self):
        args = self._make_args(workers=4)
        cfg = _build_eval_config(args, {})
        assert cfg.workers == 4

    def test_scan_only_flag(self):
        args = self._make_args(scan_only=True)
        cfg = _build_eval_config(args, {})
        assert cfg.scan_only is True

    def test_reasoning_effort_role_precedence(self, monkeypatch):
        monkeypatch.setenv("EXTRACT_REASONING_EFFORT", "low")
        args = self._make_args(reasoning_effort="medium")
        file_cfg = {
            "evaluator": {
                "normalize_reasoning_effort": "high",
                "extract_reasoning_effort": "none",
            }
        }

        cfg = _build_eval_config(args, file_cfg)

        assert cfg.normalize_reasoning_effort == "medium"
        assert cfg.extract_reasoning_effort == "medium"

    def test_role_reasoning_effort_overrides_shared_toml(self):
        args = self._make_args()
        file_cfg = {
            "evaluator": {
                "reasoning_effort": "medium",
                "extract_reasoning_effort": "none",
            }
        }

        cfg = _build_eval_config(args, file_cfg)

        assert cfg.normalize_reasoning_effort == "medium"
        assert cfg.extract_reasoning_effort == "none"


# ---------------------------------------------------------------------------
# _write_report path logic
# ---------------------------------------------------------------------------

class TestWriteReportPath:
    def _make_result(self) -> EvalResult:
        return EvalResult(
            rule_path="r.yar",
            rule_name="R",
            status="passed",
            error=None,
            duration_seconds=1.0,
            yara_stdout="R /tmp/app\n",
            yara_returncode=0,
            normalize_model="gpt-4.1",
            extract_model="gpt-4.1",
        )

    def test_auto_path_uses_timestamp_dir(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        cfg = EvalConfig(directories=[], output=None)
        run_ts = "2026-03-08T14-22-01"
        _write_report([self._make_result()], cfg, run_ts)
        expected = tmp_path / "evaluation" / "reports" / run_ts / "eval_report.json"
        assert expected.exists()
        assert f"Report written to {expected.resolve()}" in capsys.readouterr().out

    def test_explicit_output_path_used_as_is(self, tmp_path):
        out = str(tmp_path / "my.json")
        cfg = EvalConfig(directories=[], output=out)
        _write_report([self._make_result()], cfg, "2026-03-08T00-00-00")
        assert (tmp_path / "my.json").exists()
        assert not (tmp_path / "evaluation").exists()

    def test_report_aggregates_processing_paths(self, tmp_path):
        out = tmp_path / "report.json"
        cfg = EvalConfig(directories=[], output=str(out))
        deterministic = self._make_result()
        deterministic.normalization_source = "not_needed"
        deterministic.strings_extraction_source = "deterministic"
        deterministic.constants_extraction_source = "deterministic"
        fallback = self._make_result()
        fallback.normalization_source = "llm"
        fallback.strings_extraction_source = "llm_fallback"
        fallback.constants_extraction_source = "deterministic"
        fallback.llm_used = True

        _write_report([deterministic, fallback], cfg, "unused")

        report = json.loads(out.read_text())
        assert report["summary"]["processing_paths"] == {
            "normalization": {"not_needed": 1, "llm": 1},
            "strings_extraction": {"deterministic": 1, "llm_fallback": 1},
            "constants_extraction": {"deterministic": 2},
        }
        assert report["summary"]["llm_usage"] == {
            "rules_using_llm": 1,
            "rules_without_llm": 1,
        }

    def test_report_records_validation_oracle_config(self, tmp_path):
        out = tmp_path / "report.json"
        cfg = EvalConfig(
            directories=[],
            output=str(out),
            validate_original=True,
            original_directories=["upstream/rules"],
        )

        _write_report([self._make_result()], cfg, "unused")

        config = json.loads(out.read_text())["metadata"]["config"]
        assert config["validate_original"] is True
        assert config["original_directories"] == ["upstream/rules"]


class TestParseArgs:
    def test_no_arguments_uses_default_config(self, capsys):
        args = parse_args([])

        assert args.config == Path(".evaluator")
        assert args.dirs == []
        assert capsys.readouterr().out == ""

    def test_main_loads_evaluator_from_current_directory(
        self, tmp_path, monkeypatch, capsys
    ):
        (tmp_path / "rules").mkdir()
        (tmp_path / ".evaluator").write_text(
            '[evaluator]\ndirectories = ["rules"]\n'
        )
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("sys.argv", ["aray-eval"])

        evaluator_main()

        assert "No .yar files found." in capsys.readouterr().out

    def test_accepts_file_path(self):
        args = parse_args(["rule.yar"])

        assert args.dirs == ["rule.yar"]

    def test_accepts_original_validation_options(self):
        args = parse_args(
            [
                "normalized",
                "--validate-original",
                "--original-directory",
                "source-a",
                "--original-directory",
                "source-b",
            ]
        )

        assert args.validate_original is True
        assert args.original_directories == ["source-a", "source-b"]

    def test_accepts_disabling_original_validation(self):
        args = parse_args(["normalized", "--no-validate-original"])

        assert args.validate_original is False


# ---------------------------------------------------------------------------
# EvalResult normalize fields
# ---------------------------------------------------------------------------

class TestEvalResultNormalizeFields:
    def _make_result(self, **kwargs) -> EvalResult:
        defaults = dict(
            rule_path="r.yar",
            rule_name="R",
            status="passed",
            error=None,
            duration_seconds=1.0,
            yara_stdout="R /tmp/app\n",
            yara_returncode=0,
            normalize_model="gpt-4.1",
            extract_model="gpt-4.1",
        )
        defaults.update(kwargs)
        return EvalResult(**defaults)

    def test_to_dict_includes_normalize_verdict(self):
        r = self._make_result(normalize_verdict="passed")
        d = r.to_dict()
        assert "normalize_verdict" in d
        assert d["normalize_verdict"] == "passed"

    def test_to_dict_includes_normalize_reason(self):
        r = self._make_result(normalize_reason="looks good")
        d = r.to_dict()
        assert "normalize_reason" in d
        assert d["normalize_reason"] == "looks good"

    def test_normalize_fields_default_none(self):
        r = self._make_result()
        d = r.to_dict()
        assert d["normalize_verdict"] is None
        assert d["normalize_reason"] is None


class TestExecutionProvenance:
    def test_pre_normalized_deterministic_path(self):
        result = _execution_provenance(
            {
                "needs_normalization": False,
                "strings_extraction_source": "deterministic",
                "constants_extraction_source": "deterministic",
            }
        )

        assert result == {
            "normalization_source": "not_needed",
            "strings_extraction_source": "deterministic",
            "constants_extraction_source": "deterministic",
            "llm_used": False,
        }

    def test_preflight_path_did_not_reach_extraction(self):
        result = _execution_provenance({"needs_normalization": False})

        assert result["normalization_source"] == "not_needed"
        assert result["strings_extraction_source"] == "not_reached"
        assert result["constants_extraction_source"] == "not_reached"
        assert result["llm_used"] is False


# ---------------------------------------------------------------------------
# _run_one — normalization failure path
# ---------------------------------------------------------------------------

class TestRunOneNormalizationFailure:
    def test_normalization_failure_result(self, tmp_path):
        """When the graph returns normalization_error, _run_one returns a failed EvalResult."""
        rule = tmp_path / "bad.yar"
        rule.write_text('rule Bad { strings: $a = /regex/ condition: $a }')

        fake_state = {"normalization_error": "bad regex replacement"}

        mock_graph = MagicMock()
        mock_graph.invoke.return_value = fake_state

        cfg = EvalConfig(directories=[], keep_artifacts=True)

        with patch("aray.evaluator.build_graph", return_value=mock_graph):
            result = _run_one(rule, cfg)

        assert result.status == "failed"
        assert result.normalize_verdict == "failed"
        assert result.normalize_reason == "bad regex replacement"
        assert result.error is not None and result.error.startswith("normalization failed:")
        assert result.yara_returncode is None

    def test_prints_retained_artifact_directory(self, tmp_path, capsys):
        rule = tmp_path / "bad.yar"
        rule.write_text('rule Bad { strings: $a = /regex/ condition: $a }')
        artifact_dir = tmp_path / "artifacts"
        artifact_dir.mkdir()
        mock_graph = MagicMock()
        mock_graph.invoke.return_value = {"normalization_error": "bad rule"}
        cfg = EvalConfig(directories=[], keep_artifacts=True)

        with (
            patch("aray.evaluator.tempfile.mkdtemp", return_value=str(artifact_dir)),
            patch("aray.evaluator.build_graph", return_value=mock_graph),
        ):
            _run_one(rule, cfg)

        assert f"Artifacts kept at {artifact_dir.resolve()}" in capsys.readouterr().out


class TestRunOneOriginalValidation:
    @staticmethod
    def _fake_generic_invoke(_state):
        import aray.constants as constants

        constants.BUILD_DIR_GENERIC.mkdir(parents=True, exist_ok=True)
        (constants.BUILD_DIR_GENERIC / "normalized_rule.yar").write_text(
            'rule Sample { strings: $a = "normalized" condition: $a }'
        )
        (constants.BUILD_DIR_GENERIC / "output.bin").write_bytes(b"original")
        return {
            "needs_normalization": False,
            "strings_extraction_source": "deterministic",
            "constants_extraction_source": "deterministic",
        }

    def test_scans_selected_original_rule_with_identifier(self, tmp_path):
        normalized = tmp_path / "normalized" / "malware" / "sample.yar"
        original = tmp_path / "source" / "malware" / "sample.yar"
        normalized.parent.mkdir(parents=True)
        original.parent.mkdir(parents=True)
        normalized.write_text(
            'rule Sample { strings: $a = "normalized" condition: $a }'
        )
        original.write_text(
            'rule Sample { strings: $a = "original" condition: $a }'
        )
        mock_graph = MagicMock()
        mock_graph.invoke.side_effect = self._fake_generic_invoke
        calls = []

        def fake_yara_scan(scan_rule, binary, identifier):
            calls.append((scan_rule.read_text(), binary.name, identifier))
            return 0, f"Sample {binary}\n", ""

        cfg = EvalConfig(directories=[], validate_original=True)
        association = OriginalRuleAssociation(path=original)
        with (
            patch("aray.evaluator.build_graph", return_value=mock_graph),
            patch("aray.evaluator._yara_scan", side_effect=fake_yara_scan),
        ):
            result = _run_one(normalized, cfg, association)

        assert result.status == "passed"
        assert result.validation_source == "original"
        assert result.validation_rule_path == str(original)
        assert calls == [
            (
                'rule Sample { strings: $a = "original" condition: $a }',
                "output.bin",
                "Sample",
            )
        ]

    def test_missing_association_fails_without_running_pipeline(self, tmp_path):
        normalized = tmp_path / "sample.yar"
        normalized.write_text("rule Sample { condition: true }")
        mock_graph = MagicMock()
        cfg = EvalConfig(directories=[], validate_original=True)

        with patch("aray.evaluator.build_graph", return_value=mock_graph):
            result = _run_one(normalized, cfg)

        mock_graph.invoke.assert_not_called()
        assert result.status == "failed"
        assert result.disposition == "validation_rule_unavailable"
        assert result.failure_category == "original_rule_not_found"
        assert result.validation_source == "original"


class TestRunEvaluationOriginalAssociation:
    @staticmethod
    def _result(rule_path: Path) -> EvalResult:
        return EvalResult(
            rule_path=str(rule_path),
            rule_name="Sample",
            status="passed",
            error=None,
            duration_seconds=0,
            yara_stdout="Sample output.bin\n",
            yara_returncode=0,
        )

    def test_discovers_and_passes_original_association(self, tmp_path, capsys):
        normalized = tmp_path / "normalized" / "malware" / "sample.yar"
        original_root = tmp_path / "source"
        original = original_root / "malware" / "sample.yar"
        normalized.parent.mkdir(parents=True)
        original.parent.mkdir(parents=True)
        rule = "rule Sample { condition: true }"
        normalized.write_text(rule)
        original.write_text(rule)
        cfg = EvalConfig(
            directories=[],
            validate_original=True,
            original_directories=[str(original_root)],
        )
        result = self._result(normalized)

        with patch("aray.evaluator._run_one", return_value=result) as run_one:
            assert run_evaluation([normalized], cfg) == [result]

        association = run_one.call_args.args[2]
        assert association == OriginalRuleAssociation(path=original)
        assert (
            f"oracle=original normalized={normalized} source={original}"
            in capsys.readouterr().err
        )

    def test_prints_normalized_oracle_and_input_path(self, tmp_path, capsys):
        normalized = tmp_path / "normalized" / "sample.yar"
        normalized.parent.mkdir()
        normalized.write_text("rule Sample { condition: true }")
        cfg = EvalConfig(directories=[])
        result = self._result(normalized)

        with patch("aray.evaluator._run_one", return_value=result):
            run_evaluation([normalized], cfg)

        assert (
            f"oracle=normalized normalized={normalized} source={normalized}"
            in capsys.readouterr().err
        )

    def test_prints_unavailable_original_source(self, tmp_path, capsys):
        normalized = tmp_path / "normalized" / "sample.yar"
        normalized.parent.mkdir()
        normalized.write_text("rule Sample { condition: true }")
        cfg = EvalConfig(
            directories=[],
            validate_original=True,
            original_directories=[str(tmp_path / "missing")],
        )
        result = self._result(normalized)

        with patch("aray.evaluator._run_one", return_value=result):
            run_evaluation([normalized], cfg)

        assert (
            f"oracle=original normalized={normalized} source=<unavailable>"
            in capsys.readouterr().err
        )
