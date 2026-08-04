"""Unit tests for aray/evaluator.py — no LLM calls."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aray.evaluator import (
    EvalConfig,
    EvalResult,
    _build_eval_config,
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

    def test_no_rule_returns_text_unchanged(self):
        text = '/* no rules here */'
        assert _extract_first_rule_text(text) == text

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

    def test_private_rule_only_falls_back_to_text(self):
        text = 'private rule Hidden { condition: true }'
        # Only rule is private — no public rule to return; falls back to full text
        result = _extract_first_rule_text(text)
        assert result == text

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
            normalize_no_stream=False,
            extract_no_stream=False,
            scan_only=False,
            no_stream=False,
            workers=None,
            output=None,
            keep_artifacts=False,
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

    def test_auto_path_uses_timestamp_dir(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = EvalConfig(directories=[], output=None)
        run_ts = "2026-03-08T14-22-01"
        _write_report([self._make_result()], cfg, run_ts)
        expected = tmp_path / "evaluation" / "reports" / run_ts / "eval_report.json"
        assert expected.exists()

    def test_explicit_output_path_used_as_is(self, tmp_path):
        out = str(tmp_path / "my.json")
        cfg = EvalConfig(directories=[], output=out)
        _write_report([self._make_result()], cfg, "2026-03-08T00-00-00")
        assert (tmp_path / "my.json").exists()
        assert not (tmp_path / "evaluation").exists()


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
