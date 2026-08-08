"""Unit tests for aray/normalizer.py — no LLM calls."""

from __future__ import annotations

import argparse
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aray.models import JudgeVerdict, NormalizedYaraRule
from aray.nodes import judge_rule, normalize_rule
from aray.yara_validation import validate_regex_replacements
from aray.normalizer import (
    NormConfig,
    NormResult,
    _build_norm_config,
    _judge_normalization,
    _output_path_for,
    _print_summary,
    _run_one,
    _write_report,
    parse_args,
    run_normalization,
)


# ---------------------------------------------------------------------------
# _output_path_for
# ---------------------------------------------------------------------------

class TestOutputPathFor:
    def test_simple_file(self, tmp_path):
        input_dir = tmp_path / "cve_rules"
        input_dir.mkdir()
        rule = input_dir / "CVE-2010-0805.yar"
        rule.touch()
        output_root = tmp_path / "normalized"

        result = _output_path_for(rule, input_dir, output_root)
        assert result == output_root / "cve_rules" / "CVE-2010-0805.yar"

    def test_nested_file(self, tmp_path):
        input_dir = tmp_path / "antidebug_antivm"
        sub = input_dir / "sub"
        sub.mkdir(parents=True)
        rule = sub / "Bar.yar"
        rule.touch()
        output_root = tmp_path / "normalized"

        result = _output_path_for(rule, input_dir, output_root)
        assert result == output_root / "antidebug_antivm" / "sub" / "Bar.yar"

    def test_uses_input_dir_basename(self, tmp_path):
        # Even with an absolute deep path, only the basename of input_dir is used
        input_dir = tmp_path / "a" / "b" / "myrules"
        input_dir.mkdir(parents=True)
        rule = input_dir / "r.yar"
        rule.touch()
        output_root = tmp_path / "out"

        result = _output_path_for(rule, input_dir, output_root)
        assert result.parts[-3] == "out"
        assert result.parts[-2] == "myrules"
        assert result.parts[-1] == "r.yar"

    def test_standalone_file_is_written_directly_under_output_root(self, tmp_path):
        rule = tmp_path / "rules" / "standalone.yar"
        rule.parent.mkdir()
        rule.touch()
        output_root = tmp_path / "out"

        result = _output_path_for(rule, rule, output_root)

        assert result == output_root / "standalone.yar"


# ---------------------------------------------------------------------------
# NormResult.to_dict
# ---------------------------------------------------------------------------

class TestNormResultToDict:
    def test_passed_result(self):
        r = NormResult(
            rule_path="evaluation/rules/cve_rules/CVE-2010-0805.yar",
            rule_name="MSIETabularActivex",
            status="passed",
            normalized_rule="rule MSIETabularActivex { ... }",
            output_path="evaluation/normalized/cve_rules/CVE-2010-0805.yar",
            judge_verdict="passed",
            judge_reason="All strings preserved, valid YARA syntax.",
            error=None,
            duration_seconds=3.12,
            normalize_model="gpt-4.1",
            judge_model="gpt-4.1",
        )
        d = r.to_dict()
        assert d["rule_path"] == "evaluation/rules/cve_rules/CVE-2010-0805.yar"
        assert d["rule_name"] == "MSIETabularActivex"
        assert d["status"] == "passed"
        assert d["normalized_rule"] == "rule MSIETabularActivex { ... }"
        assert d["output_path"] == "evaluation/normalized/cve_rules/CVE-2010-0805.yar"
        assert d["judge_verdict"] == "passed"
        assert d["judge_reason"] == "All strings preserved, valid YARA syntax."
        assert d["error"] is None
        assert d["duration_seconds"] == 3.12
        assert d["normalize_model"] == "gpt-4.1"
        assert d["judge_model"] == "gpt-4.1"

    def test_error_result(self):
        r = NormResult(
            rule_path="bad.yar",
            rule_name=None,
            status="error",
            normalized_rule=None,
            output_path=None,
            judge_verdict=None,
            judge_reason=None,
            error="LLM timeout",
            duration_seconds=0.5,
            normalize_model="gpt-4.1",
            judge_model="gpt-4.1",
        )
        d = r.to_dict()
        assert d["status"] == "error"
        assert d["normalized_rule"] is None
        assert d["judge_verdict"] is None
        assert d["error"] == "LLM timeout"
        assert d["normalize_model"] == "gpt-4.1"
        assert d["judge_model"] == "gpt-4.1"

    def test_skipped_result(self):
        r = NormResult(
            rule_path="index.yar",
            rule_name=None,
            status="skipped",
            normalized_rule=None,
            output_path=None,
            judge_verdict=None,
            judge_reason=None,
            error=None,
            duration_seconds=0.0,
            normalize_model="gpt-4.1",
            judge_model="gpt-4.1",
        )
        d = r.to_dict()
        assert d["status"] == "skipped"
        assert d["duration_seconds"] == 0.0
        assert d["normalize_model"] == "gpt-4.1"
        assert d["judge_model"] == "gpt-4.1"


# ---------------------------------------------------------------------------
# normalize_rule prompt and retries
# ---------------------------------------------------------------------------

class TestNormalizeRulePrompt:
    _RULE10_CONDITION = (
        "uint16(0) == 0x5a4d and filesize < 2KB and $x1 or all of ($s*)"
    )

    def test_prompt_explains_precedence_and_construction_cost(self):
        captured_messages = []

        def _capture_invoke(llm, schema, messages, use_structured):
            captured_messages.extend(messages)
            return NormalizedYaraRule(rule="rule R { condition: true }")

        llm = MagicMock()
        llm.model_name = "test-model"
        with patch("aray.nodes._invoke_llm", side_effect=_capture_invoke):
            normalize_rule(
                {"yara_rule": f"rule R {{ condition: {self._RULE10_CONDITION} }}"},
                llm,
            )

        sys_content = captured_messages[0].content
        assert "minimal constructible subset" in sys_content
        assert "`not`, then `and`, then `or`" in sys_content
        assert "`A and B or C` means `(A and B) or C`" in sys_content
        assert "cheapest constructible branch" in sys_content
        assert "compiled artifact cannot be shrunk" in sys_content
        assert "allocating and writing padding bytes" in sys_content
        assert "exact string offsets" in sys_content
        assert "format-forcing requirements" in sys_content
        assert self._RULE10_CONDITION in sys_content
        assert "Remove $x1, the MZ check, and the filesize bound" in sys_content
        assert "52006F006F007400200045006E007400720079" in sys_content
        assert "Do NOT decode or reinterpret hex-looking regex text" in sys_content

    def test_retry_includes_expensive_branch_feedback(self):
        original = (
            'rule R { strings: $x1 = "x" $s3 = "a" $s4 = "b" '
            f"condition: {self._RULE10_CONDITION} }}"
        )
        expensive = "rule R { strings: $x1 = \"x\" condition: uint16(0) == 0x5a4d and filesize < 2KB and $x1 }"
        cheap = "rule R { strings: $s3 = \"a\" $s4 = \"b\" condition: $s3 and $s4 }"
        responses = iter([
            NormalizedYaraRule(rule=expensive),
            JudgeVerdict(
                verdict="failed",
                reason="Choose the cheaper complete $s3 and $s4 branch.",
            ),
            NormalizedYaraRule(rule=cheap),
        ])
        captured_messages = []

        def _scripted_invoke(llm, schema, messages, use_structured):
            captured_messages.append(messages)
            return next(responses)

        llm = MagicMock()
        llm.model_name = "test-model"
        with patch("aray.nodes._invoke_llm", side_effect=_scripted_invoke):
            state = {"yara_rule": original}
            state.update(normalize_rule(state, llm))
            state.update(judge_rule(state, llm))
            result = normalize_rule(state, llm)

        retry_message = captured_messages[2][1].content
        assert result["normalized_rule"] == cheap
        assert expensive in retry_message
        assert "Choose the cheaper complete $s3 and $s4 branch." in retry_message
        assert "Normalize the ORIGINAL RULE again" in retry_message


# ---------------------------------------------------------------------------
# deterministic regex witness validation
# ---------------------------------------------------------------------------

class TestRegexWitnessValidation:
    _VALID_WITNESS = "52006F006F007400200045006E007400720079"
    _INVALID_WITNESS = (
        "52006F007400200045006E0074002000730079007400650078002000760062006100"
        "7200740020004E0061006D006500"
    )

    @staticmethod
    def _rule11_with_literal(value: str) -> tuple[str, str]:
        original = Path("data/rules/rule11.yar").read_text()
        lines = []
        for line in original.splitlines():
            if line.strip().startswith("$c = /"):
                lines.append(f'      $c = "{value}" nocase')
            else:
                lines.append(line)
        return original, "\n".join(lines)

    def test_rule11_valid_witness_is_accepted(self):
        original, normalized = self._rule11_with_literal(self._VALID_WITNESS)
        assert validate_regex_replacements(original, normalized) is None

    def test_rule11_invalid_witness_is_rejected(self):
        original, normalized = self._rule11_with_literal(self._INVALID_WITNESS)
        error = validate_regex_replacements(original, normalized)
        assert error is not None
        assert "$c" in error
        assert "does not match the original YARA regex" in error

    def test_escaped_slash_regex_witness_is_accepted(self):
        original = r'rule R { strings: $a = /foo\/bar/ condition: $a }'
        normalized = r'rule R { strings: $a = "foo/bar" condition: $a }'
        assert validate_regex_replacements(original, normalized) is None

    def test_invalid_witness_bypasses_llm_judge(self):
        original, normalized = self._rule11_with_literal(self._INVALID_WITNESS)
        with patch("aray.nodes._invoke_llm") as mock_invoke:
            verdict = _judge_normalization(
                original, normalized, MagicMock(), use_structured=True
            )

        assert verdict.verdict == "failed"
        assert "Regex witness validation failed for $c" in verdict.reason
        mock_invoke.assert_not_called()


# ---------------------------------------------------------------------------
# _judge_normalization
# ---------------------------------------------------------------------------

class TestJudgeNormalization:
    def test_calls_invoke_llm_and_returns_verdict(self):
        expected = JudgeVerdict(verdict="passed", reason="Semantically equivalent.")
        with patch("aray.nodes._invoke_llm", return_value=expected) as mock_invoke:
            judge_llm = MagicMock()
            result = _judge_normalization(
                "rule A { condition: true }",
                "rule A { condition: true }",
                judge_llm,
                use_structured=True,
            )

        assert result.verdict == "passed"
        assert result.reason == "Semantically equivalent."
        mock_invoke.assert_called_once()

    def test_system_prompt_contains_key_phrases(self):
        """Verify the judge system message references the key assessment criteria."""
        expected = JudgeVerdict(verdict="uncertain", reason="Complex rule.")
        captured_messages = []

        def _capture_invoke(llm, schema, messages, use_structured):
            captured_messages.extend(messages)
            return expected

        with patch("aray.nodes._invoke_llm", side_effect=_capture_invoke):
            _judge_normalization(
                "rule Orig { condition: true }",
                "rule Orig { condition: true }",
                MagicMock(),
                use_structured=False,
            )

        sys_content = captured_messages[0].content
        assert "YARA rule analyst" in sys_content
        assert "passed" in sys_content
        assert "failed" in sys_content
        assert "uncertain" in sys_content
        assert "modifier" in sys_content
        # Subset semantics must be explicit in the prompt
        assert "SUBSET" in sys_content
        assert "OR" in sys_content
        assert "`not`, then `and`, then `or`" in sys_content
        assert "cheapest constructible branch" in sys_content
        assert "filesize" in sys_content
        assert "exact offsets" in sys_content
        assert "format-forcing PE/nested/wide" in sys_content
        assert "uint16(0) == 0x5a4d" in sys_content
        assert "preferred normalization is `$s3 and $s4`" in sys_content
        assert "validated deterministically" in sys_content

    def test_human_message_contains_both_rules(self):
        expected = JudgeVerdict(verdict="failed", reason="Missing string.")
        captured_messages = []

        def _capture_invoke(llm, schema, messages, use_structured):
            captured_messages.extend(messages)
            return expected

        original = "rule Orig { strings: $a = \"foo\" condition: $a }"
        normalized = "rule Orig { condition: true }"
        with patch("aray.nodes._invoke_llm", side_effect=_capture_invoke):
            _judge_normalization(original, normalized, MagicMock(), use_structured=True)

        human_content = captured_messages[1].content
        assert "ORIGINAL RULE" in human_content
        assert "NORMALIZED RULE" in human_content
        assert original in human_content
        assert normalized in human_content


# ---------------------------------------------------------------------------
# _run_one
# ---------------------------------------------------------------------------

class TestRunOne:
    def _make_config(self, output_root: str) -> NormConfig:
        return NormConfig(
            directories=[],
            output_root=output_root,
            model="gpt-4.1",
            judge_model="gpt-4.1",
        )

    def test_skipped_for_index_file(self, tmp_path):
        index = tmp_path / "index.yar"
        index.write_text('include "other.yar"\n')
        cfg = self._make_config(str(tmp_path / "out"))

        result = _run_one(index, tmp_path, cfg, MagicMock(), MagicMock())

        assert result.status == "skipped"
        assert result.normalized_rule is None
        assert result.output_path is None

    def test_skipped_when_file_has_only_private_rules(self, tmp_path):
        rule = tmp_path / "private.yar"
        rule.write_text('private rule Helper { condition: true }')
        cfg = self._make_config(str(tmp_path / "out"))

        with patch("aray.normalizer._normalize_one_rule") as normalize:
            result = _run_one(rule, tmp_path, cfg, MagicMock(), MagicMock())

        normalize.assert_not_called()
        assert result.status == "skipped"
        assert result.output_path is None

    def test_successful_normalization_writes_output(self, tmp_path):
        rule = tmp_path / "cve_rules" / "Foo.yar"
        rule.parent.mkdir()
        rule.write_text('rule Foo { strings: $a = /regex/ condition: $a }')

        output_root = tmp_path / "normalized"
        cfg = self._make_config(str(output_root))

        normalized_text = "rule Foo { condition: true }"
        verdict = JudgeVerdict(verdict="passed", reason="OK")

        with (
            patch("aray.normalizer._normalize_one_rule", return_value=normalized_text),
            patch("aray.normalizer._judge_normalization", return_value=verdict),
        ):
            result = _run_one(rule, rule.parent, cfg, MagicMock(), MagicMock())

        assert result.status == "passed"
        assert result.normalized_rule == normalized_text
        assert result.judge_verdict == "passed"
        assert result.error is None
        assert result.normalize_model == cfg.model
        assert result.judge_model == cfg.judge_model

        # Output file must have been written
        expected_out = output_root / "cve_rules" / "Foo.yar"
        assert expected_out.exists()
        assert expected_out.read_text() == normalized_text

    def test_standalone_file_writes_output_at_root(self, tmp_path):
        rule = tmp_path / "rules" / "Foo.yar"
        rule.parent.mkdir()
        rule.write_text('rule Foo { strings: $a = /regex/ condition: $a }')
        output_root = tmp_path / "normalized"
        cfg = self._make_config(str(output_root))
        normalized_text = "rule Foo { condition: true }"
        verdict = JudgeVerdict(verdict="passed", reason="OK")

        with (
            patch("aray.normalizer._normalize_one_rule", return_value=normalized_text),
            patch("aray.normalizer._judge_normalization", return_value=verdict),
        ):
            result = _run_one(rule, rule, cfg, MagicMock(), MagicMock())

        assert result.output_path == str(output_root / "Foo.yar")
        assert (output_root / "Foo.yar").read_text() == normalized_text

    def test_uncertain_verdict_maps_to_failed(self, tmp_path):
        rule = tmp_path / "rules" / "R.yar"
        rule.parent.mkdir()
        rule.write_text('rule R { strings: $a = /regex/ condition: $a }')

        cfg = self._make_config(str(tmp_path / "out"))
        verdict = JudgeVerdict(verdict="uncertain", reason="Too complex.")

        with (
            patch("aray.normalizer._normalize_one_rule", return_value="rule R { condition: true }"),
            patch("aray.normalizer._judge_normalization", return_value=verdict),
        ):
            result = _run_one(rule, rule.parent, cfg, MagicMock(), MagicMock())

        assert result.status == "failed"
        assert result.judge_verdict == "uncertain"

    def test_exception_returns_error_status(self, tmp_path):
        rule = tmp_path / "rules" / "R.yar"
        rule.parent.mkdir()
        rule.write_text('rule R { strings: $a = /regex/ condition: $a }')

        cfg = self._make_config(str(tmp_path / "out"))

        with patch("aray.normalizer._normalize_one_rule", side_effect=RuntimeError("LLM error")):
            result = _run_one(rule, rule.parent, cfg, MagicMock(), MagicMock())

        assert result.status == "error"
        assert "LLM error" in result.error
        assert result.normalized_rule is None

    def test_already_normalized_skips_llm(self, tmp_path):
        rule = tmp_path / "rules" / "Simple.yar"
        rule.parent.mkdir()
        # Simple rule with no regex/OR/count expressions — _requires_normalization returns False
        rule_text = 'rule Simple { strings: $a = "hello" condition: $a }'
        rule.write_text(rule_text)

        output_root = tmp_path / "normalized"
        cfg = self._make_config(str(output_root))

        with patch("aray.normalizer._normalize_one_rule") as mock_norm:
            result = _run_one(rule, rule.parent, cfg, MagicMock(), MagicMock())

        mock_norm.assert_not_called()
        assert result.already_normalized is True
        assert result.status == "passed"
        assert result.judge_verdict is None
        assert result.normalized_rule == rule_text
        # Output file must have been written
        expected_out = output_root / "rules" / "Simple.yar"
        assert expected_out.exists()
        assert expected_out.read_text() == rule_text

    def test_only_first_public_rule_is_sent_to_normalizer(self, tmp_path):
        rule = tmp_path / "rules" / "Multi.yar"
        rule.parent.mkdir()
        rule.write_text(
            'private rule Helper { strings: $h = "helper" condition: $h }\n'
            'rule First { strings: $a = /first[0-9]+/ condition: Helper and $a }\n'
            'rule Later { strings: $b = /later.*/ condition: $b }\n'
        )
        cfg = self._make_config(str(tmp_path / "out"))
        candidate = '''rule First {
strings:
    $a = "first0"
    $__Helper_h = "helper"
condition:
    $__Helper_h and $a
}'''
        verdict = JudgeVerdict(verdict="passed", reason="OK")

        with (
            patch("aray.normalizer._normalize_one_rule", return_value=candidate) as normalize,
            patch("aray.normalizer._judge_normalization", return_value=verdict),
        ):
            result = _run_one(rule, rule.parent, cfg, MagicMock(), MagicMock())

        selected = normalize.call_args.args[0]
        assert "rule First" in selected
        assert "rule Helper" not in selected
        assert "rule Later" not in selected
        assert "$__Helper_h" in selected
        assert result.status == "passed"

    def test_failed_attempt_is_retried_and_only_passed_candidate_is_written(self, tmp_path):
        rule = tmp_path / "rules" / "Retry.yar"
        rule.parent.mkdir()
        rule.write_text('rule Retry { strings: $a = /a+/ condition: $a }')
        output_root = tmp_path / "out"
        cfg = self._make_config(str(output_root))
        rejected = 'rule Retry { strings: $a = "b" condition: $a }'
        accepted = 'rule Retry { strings: $a = "a" condition: $a }'

        with (
            patch(
                "aray.normalizer._normalize_one_rule",
                side_effect=[rejected, accepted],
            ) as normalize,
            patch(
                "aray.normalizer._judge_normalization",
                side_effect=[
                    JudgeVerdict(verdict="failed", reason="bad witness"),
                    JudgeVerdict(verdict="passed", reason="OK"),
                ],
            ),
        ):
            result = _run_one(rule, rule.parent, cfg, MagicMock(), MagicMock())

        assert normalize.call_count == 2
        assert result.status == "passed"
        assert result.normalized_rule == accepted
        assert Path(result.output_path).read_text() == accepted

    def test_failed_run_removes_stale_output(self, tmp_path):
        rule = tmp_path / "rules" / "Failed.yar"
        rule.parent.mkdir()
        rule.write_text('rule Failed { strings: $a = /a+/ condition: $a }')
        output_root = tmp_path / "out"
        stale = output_root / "rules" / "Failed.yar"
        stale.parent.mkdir(parents=True)
        stale.write_text("stale")
        cfg = self._make_config(str(output_root))
        verdict = JudgeVerdict(verdict="failed", reason="invalid")

        with (
            patch(
                "aray.normalizer._normalize_one_rule",
                return_value='rule Failed { strings: $a = "bad" condition: $a }',
            ),
            patch("aray.normalizer._judge_normalization", return_value=verdict),
        ):
            result = _run_one(rule, rule.parent, cfg, MagicMock(), MagicMock())

        assert result.status == "failed"
        assert result.output_path is None
        assert not stale.exists()

    def test_unresolved_dependency_returns_error_instead_of_escaping(self, tmp_path):
        rule = tmp_path / "rules" / "Missing.yar"
        rule.parent.mkdir()
        rule.write_text("rule Missing { condition: UnknownHelper }")
        cfg = self._make_config(str(tmp_path / "out"))

        result = _run_one(rule, rule.parent, cfg, MagicMock(), MagicMock())

        assert result.status == "error"
        assert "UnknownHelper" in (result.error or "")

    def test_exception_removes_stale_output(self, tmp_path):
        rule = tmp_path / "rules" / "Error.yar"
        rule.parent.mkdir()
        rule.write_text('rule Error { strings: $a = /a+/ condition: $a }')
        output_root = tmp_path / "out"
        stale = output_root / "rules" / "Error.yar"
        stale.parent.mkdir(parents=True)
        stale.write_text("stale")
        cfg = self._make_config(str(output_root))

        with patch(
            "aray.normalizer._normalize_one_rule", side_effect=RuntimeError("boom")
        ):
            result = _run_one(rule, rule.parent, cfg, MagicMock(), MagicMock())

        assert result.status == "error"
        assert not stale.exists()

    def test_transient_errors_are_retried(self, tmp_path):
        rule = tmp_path / "rules" / "Transient.yar"
        rule.parent.mkdir()
        rule.write_text('rule Transient { strings: $a = /a+/ condition: $a }')
        cfg = self._make_config(str(tmp_path / "out"))
        accepted = 'rule Transient { strings: $a = "a" condition: $a }'

        with (
            patch(
                "aray.normalizer._normalize_one_rule",
                side_effect=[ConnectionError("closed"), accepted],
            ) as normalize,
            patch(
                "aray.normalizer._judge_normalization",
                return_value=JudgeVerdict(verdict="passed", reason="OK"),
            ),
        ):
            result = _run_one(rule, rule.parent, cfg, MagicMock(), MagicMock())

        assert normalize.call_count == 2
        assert result.status == "passed"


# ---------------------------------------------------------------------------
# _build_norm_config
# ---------------------------------------------------------------------------

class TestBuildNormConfig:
    def _make_args(self, **kwargs) -> argparse.Namespace:
        defaults = dict(
            dirs=[],
            model=None,
            judge_model=None,
            base_url=None,
            judge_base_url=None,
            normalize_api_key=None,
            judge_api_key=None,
            output_root=None,
            no_stream=False,
            workers=None,
            output=None,
        )
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def test_cli_dirs_override_config(self):
        args = self._make_args(dirs=["cli_dir"])
        file_cfg = {"normalizer": {"directories": ["config_dir"]}}
        cfg = _build_norm_config(args, file_cfg)
        assert cfg.directories == ["cli_dir"]

    def test_config_file_dirs_used_when_no_cli_dirs(self):
        args = self._make_args()
        file_cfg = {"normalizer": {"directories": ["config_dir"]}}
        cfg = _build_norm_config(args, file_cfg)
        assert cfg.directories == ["config_dir"]

    def test_default_model_gpt41(self, monkeypatch):
        monkeypatch.delenv("NORMALIZE_MODEL", raising=False)
        monkeypatch.delenv("OPENAI_MODEL", raising=False)
        args = self._make_args()
        cfg = _build_norm_config(args, {})
        assert cfg.model == "gpt-4.1"

    def test_default_judge_model_gpt41(self, monkeypatch):
        monkeypatch.delenv("NORMALIZE_MODEL", raising=False)
        monkeypatch.delenv("OPENAI_MODEL", raising=False)
        args = self._make_args()
        cfg = _build_norm_config(args, {})
        assert cfg.judge_model == "gpt-4.1"

    def test_judge_model_falls_back_to_openai_model_env(self, monkeypatch):
        monkeypatch.delenv("NORMALIZE_MODEL", raising=False)
        monkeypatch.setenv("OPENAI_MODEL", "my-gateway-model")
        args = self._make_args()
        cfg = _build_norm_config(args, {})
        assert cfg.judge_model == "my-gateway-model"

    def test_judge_base_url_falls_back_to_openai_base_url_env(self, monkeypatch):
        monkeypatch.delenv("NORMALIZE_BASE_URL", raising=False)
        monkeypatch.setenv("OPENAI_BASE_URL", "http://proxy:4000")
        args = self._make_args()
        cfg = _build_norm_config(args, {})
        assert cfg.judge_base_url == "http://proxy:4000"

    def test_judge_base_url_cli_overrides_env(self, monkeypatch):
        monkeypatch.setenv("OPENAI_BASE_URL", "http://proxy:4000")
        args = self._make_args(judge_base_url="http://judge:5000")
        cfg = _build_norm_config(args, {})
        assert cfg.judge_base_url == "http://judge:5000"

    def test_cli_model_overrides_config(self):
        args = self._make_args(model="gpt-4o")
        file_cfg = {"normalizer": {"model": "gpt-4.1-mini"}}
        cfg = _build_norm_config(args, file_cfg)
        assert cfg.model == "gpt-4o"

    def test_cli_judge_model_overrides_config(self):
        args = self._make_args(judge_model="gpt-4o-mini")
        file_cfg = {"normalizer": {"judge_model": "gpt-4.1"}}
        cfg = _build_norm_config(args, file_cfg)
        assert cfg.judge_model == "gpt-4o-mini"

    def test_toml_values_override_normalize_environment(self, monkeypatch):
        monkeypatch.setenv("NORMALIZE_MODEL", "env-model")
        monkeypatch.setenv("NORMALIZE_BASE_URL", "http://env-gateway")
        monkeypatch.setenv("NORMALIZE_API_KEY", "env-key")
        args = self._make_args()
        file_cfg = {
            "normalizer": {
                "model": "toml-model",
                "base_url": "http://toml-gateway",
                "normalize_api_key": "toml-key",
            }
        }

        cfg = _build_norm_config(args, file_cfg)

        assert cfg.model == "toml-model"
        assert cfg.judge_model == "toml-model"
        assert cfg.base_url == "http://toml-gateway"
        assert cfg.judge_base_url == "http://toml-gateway"
        assert cfg.normalize_api_key == "toml-key"
        assert cfg.judge_api_key == "toml-key"

    def test_judge_specific_toml_overrides_inherited_toml(self):
        args = self._make_args()
        file_cfg = {
            "normalizer": {
                "model": "normalize-model",
                "judge_model": "judge-model",
                "base_url": "http://normalize",
                "judge_base_url": "http://judge",
                "normalize_api_key": "normalize-key",
                "judge_api_key": "judge-key",
            }
        }

        cfg = _build_norm_config(args, file_cfg)

        assert cfg.judge_model == "judge-model"
        assert cfg.judge_base_url == "http://judge"
        assert cfg.judge_api_key == "judge-key"

    def test_cli_shared_values_override_judge_toml(self):
        args = self._make_args(
            model="cli-model",
            base_url="http://cli-gateway",
            normalize_api_key="cli-key",
        )
        file_cfg = {
            "normalizer": {
                "judge_model": "toml-judge",
                "judge_base_url": "http://toml-judge",
                "judge_api_key": "toml-judge-key",
            }
        }

        cfg = _build_norm_config(args, file_cfg)

        assert cfg.judge_model == "cli-model"
        assert cfg.judge_base_url == "http://cli-gateway"
        assert cfg.judge_api_key == "cli-key"

    def test_judge_base_url_separate_from_base_url(self):
        args = self._make_args(base_url="http://main:4000", judge_base_url="http://judge:4001")
        cfg = _build_norm_config(args, {})
        assert cfg.base_url == "http://main:4000"
        assert cfg.judge_base_url == "http://judge:4001"

    def test_output_root_default(self):
        args = self._make_args()
        cfg = _build_norm_config(args, {})
        assert cfg.output_root == "evaluation/normalized"

    def test_output_root_from_cli(self):
        args = self._make_args(output_root="/tmp/norm_out")
        cfg = _build_norm_config(args, {})
        assert cfg.output_root == "/tmp/norm_out"

    def test_workers_default_1(self):
        args = self._make_args()
        cfg = _build_norm_config(args, {})
        assert cfg.workers == 1

    def test_workers_from_cli(self):
        args = self._make_args(workers=4)
        cfg = _build_norm_config(args, {})
        assert cfg.workers == 4

    def test_no_stream_flag(self):
        args = self._make_args(no_stream=True)
        cfg = _build_norm_config(args, {})
        assert cfg.streaming is False

    def test_output_default(self):
        args = self._make_args()
        cfg = _build_norm_config(args, {})
        assert cfg.output is None

    def test_output_from_config(self):
        args = self._make_args()
        file_cfg = {"normalizer": {"output": "my_report.json"}}
        cfg = _build_norm_config(args, file_cfg)
        assert cfg.output == "my_report.json"


class TestRunNormalizationConfig:
    def test_forwards_resolved_api_keys(self):
        cfg = NormConfig(
            directories=[],
            base_url="http://normalize",
            judge_base_url="http://judge",
            normalize_api_key="normalize-key",
            judge_api_key="judge-key",
        )

        with patch("aray.normalizer.ChatOpenAI", return_value=MagicMock()) as chat_openai:
            results = run_normalization([], [], cfg)

        assert results == []
        assert chat_openai.call_args_list[0].kwargs["api_key"] == "normalize-key"
        assert chat_openai.call_args_list[1].kwargs["api_key"] == "judge-key"


# ---------------------------------------------------------------------------
# _load_config_file with [normalizer] section
# ---------------------------------------------------------------------------

class TestWriteReportPath:
    def _make_result(self) -> NormResult:
        return NormResult(
            rule_path="r.yar",
            rule_name="R",
            status="passed",
            normalized_rule="rule R { condition: true }",
            output_path="evaluation/normalized/r.yar",
            judge_verdict="passed",
            judge_reason="OK",
            error=None,
            duration_seconds=1.0,
            normalize_model="gpt-4.1",
            judge_model="gpt-4.1",
        )

    def test_auto_path_uses_timestamp_dir(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        cfg = NormConfig(directories=[], output=None)
        run_ts = "2026-03-08T14-22-01"
        _write_report([self._make_result()], cfg, run_ts)
        expected = tmp_path / "evaluation" / "reports" / run_ts / "norm_report.json"
        assert expected.exists()
        assert f"Report written to {expected.resolve()}" in capsys.readouterr().out

    def test_explicit_output_path_used_as_is(self, tmp_path):
        out = str(tmp_path / "my_norm.json")
        cfg = NormConfig(directories=[], output=out)
        _write_report([self._make_result()], cfg, "2026-03-08T00-00-00")
        assert (tmp_path / "my_norm.json").exists()
        assert not (tmp_path / "evaluation").exists()


class TestPrintSummary:
    def test_prints_generated_file_locations(self, tmp_path, capsys):
        output_path = tmp_path / "normalized" / "r.yar"
        result = NormResult(
            rule_path="r.yar",
            rule_name="R",
            status="passed",
            normalized_rule="rule R { condition: true }",
            output_path=str(output_path),
            judge_verdict="passed",
            judge_reason="OK",
            error=None,
            duration_seconds=1.0,
        )

        _print_summary([result])

        output = capsys.readouterr().out
        assert "Generated normalized files:" in output
        assert str(output_path.resolve()) in output


class TestParseArgs:
    def test_no_arguments_prints_help_and_exits_zero(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            parse_args([])

        captured = capsys.readouterr()
        assert excinfo.value.code == 0
        assert "usage: aray-normalize" in captured.out
        assert captured.err == ""

    def test_accepts_file_path(self):
        args = parse_args(["rule.yar"])

        assert args.dirs == ["rule.yar"]


class TestLoadConfigFileNormalizerSection:
    def test_normalizer_section_parsed(self, tmp_path):
        from aray.evaluator import _load_config_file

        cfg_file = tmp_path / ".normalizer"
        cfg_file.write_text(
            '[normalizer]\n'
            'directories = ["evaluation/rules/cve_rules"]\n'
            'workers = 2\n'
            'judge_model = "gpt-4o"\n'
        )
        result = _load_config_file(cfg_file)
        assert result["normalizer"]["directories"] == ["evaluation/rules/cve_rules"]
        assert result["normalizer"]["workers"] == 2
        assert result["normalizer"]["judge_model"] == "gpt-4o"
