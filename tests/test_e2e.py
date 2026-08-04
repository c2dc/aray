"""End-to-end pipeline tests.

TestE2ELinux / TestE2EPE  [@pytest.mark.llm]:
    Real LLM calls — validate prompts, structured-output parsing, and the
    full compile → YARA-scan round-trip.  Require a valid OPENAI_API_KEY in
    .env.  Run with:  pytest -m llm

TestE2EPipelineConfig:
    No LLM calls.  Verify that build_graph() wires ChatOpenAI correctly for
    each per-role model / base_url setting.
"""

import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aray.constants import BANNER
from aray.config import LLMNodeConfig, PipelineConfig
from aray.graph import build_graph

RULES_DIR = Path("data/rules")


# ---------------------------------------------------------------------------
# Skip guards
# ---------------------------------------------------------------------------

def _yara_available() -> bool:
    return shutil.which("yara") is not None


def _gcc_available() -> bool:
    return shutil.which("gcc") is not None


def _mingw_available() -> bool:
    return shutil.which("x86_64-w64-mingw32-gcc") is not None


def _api_key_available() -> bool:
    return bool(os.getenv("OPENAI_API_KEY"))


requires_api_key = pytest.mark.skipif(
    not _api_key_available(),
    reason="requires OPENAI_API_KEY to make real LLM calls",
)


requires_yara = pytest.mark.skipif(
    not _yara_available(),
    reason="requires yara on PATH",
)

requires_yara_and_gcc = pytest.mark.skipif(
    not (_yara_available() and _gcc_available()),
    reason="requires yara and gcc on PATH",
)

requires_mingw_and_yara = pytest.mark.skipif(
    not (_mingw_available() and _yara_available()),
    reason="requires x86_64-w64-mingw32-gcc and yara on PATH",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _yara_scan(rule_path: Path, binary: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["yara", str(rule_path), str(binary)],
        capture_output=True,
        text=True,
    )


def _invoke(
    rule_path: Path,
    tmp_path: Path,
    use_structured_output: bool = True,
    scan_only: bool = False,
) -> tuple[Path, Path]:
    """Run the full pipeline with real LLM calls; redirect build output to tmp_path."""
    default_model = os.getenv("OPENAI_MODEL") or "gpt-4.1"
    base_url = os.getenv("OPENAI_BASE_URL") or None
    normalize_model = os.getenv("NORMALIZE_MODEL") or default_model
    extract_model = os.getenv("EXTRACT_MODEL") or default_model
    config = PipelineConfig(
        normalize=LLMNodeConfig(model=normalize_model, base_url=base_url),
        extract=LLMNodeConfig(model=extract_model, base_url=base_url),
        use_structured_output=use_structured_output,
        scan_only=scan_only,
    )

    linux_dir = tmp_path / "linux"
    windows_dir = tmp_path / "windows"
    generic_dir = tmp_path / "generic"
    with (
        patch("aray.compiler.BUILD_DIR", linux_dir),
        patch("aray.compiler.BUILD_DIR_WIN", windows_dir),
        patch("aray.constants.BUILD_DIR_GENERIC", generic_dir),
    ):
        build_graph(config=config).invoke({"name": "aray", "rule_path": str(rule_path.resolve())})
    return linux_dir, windows_dir


# ---------------------------------------------------------------------------
# E2E — Linux ELF rules (real LLM)
# ---------------------------------------------------------------------------

@pytest.mark.llm
@requires_api_key
@requires_yara_and_gcc
class TestE2ELinux:
    """Full pipeline with real LLM calls → ELF binary → YARA scan."""

    def test_rule0_matches(self, tmp_path):
        """rule0: single ASCII string — LLM extracts it, ELF matches the rule."""
        rule = RULES_DIR / "rule0.yar"
        linux_dir, _ = _invoke(rule, tmp_path)
        assert (linux_dir / "app").exists(), "ELF binary not created"
        result = _yara_scan(rule, linux_dir / "app")
        assert result.returncode == 0
        assert "rule0" in result.stdout

    def test_rule0_runs(self, tmp_path):
        """rule0: generated ELF executes successfully and prints the banner."""
        rule = RULES_DIR / "rule0.yar"
        linux_dir, _ = _invoke(rule, tmp_path)
        result = subprocess.run([str(linux_dir / "app")], capture_output=True, text=True)
        assert result.returncode == 0
        assert BANNER in result.stdout

    def test_rule1_matches(self, tmp_path):
        """rule1: two ASCII strings — LLM extracts both, ELF matches the rule."""
        rule = RULES_DIR / "rule1.yar"
        linux_dir, _ = _invoke(rule, tmp_path)
        result = _yara_scan(rule, linux_dir / "app")
        assert result.returncode == 0
        assert "rule1" in result.stdout

    def test_linux_build_artefacts_created(self, tmp_path):
        """Pipeline writes all expected build artefacts for a Linux rule."""
        rule = RULES_DIR / "rule0.yar"
        linux_dir, _ = _invoke(rule, tmp_path)
        for name in ("main.S", "linker.ld", "normalized_rule.yar", "app"):
            assert (linux_dir / name).exists(), f"{name} missing from Linux build dir"


# ---------------------------------------------------------------------------
# E2E — Windows PE rules (real LLM)
# ---------------------------------------------------------------------------

@pytest.mark.llm
@requires_api_key
@requires_mingw_and_yara
class TestE2EPE:
    """Full pipeline with real LLM calls → PE binary → YARA scan."""

    def test_rule6_matches(self, tmp_path):
        """rule6: MZ + PE sig + mutex — LLM extracts them, PE matches the rule."""
        rule = RULES_DIR / "rule6.yar"
        _, win_dir = _invoke(rule, tmp_path)
        assert (win_dir / "app.exe").exists(), "PE binary not created"
        result = _yara_scan(rule, win_dir / "app.exe")
        assert result.returncode == 0
        assert "maindll_mutex" in result.stdout

    def test_rule9_wide_strings_match(self, tmp_path):
        """rule9: ASCII + widechar strings — LLM extracts them, PE matches the rule."""
        rule = RULES_DIR / "rule9.yar"
        _, win_dir = _invoke(rule, tmp_path)
        result = _yara_scan(rule, win_dir / "app.exe")
        assert result.returncode == 0
        assert "malware_apt15_exchange_tool" in result.stdout

    def test_pe_binary_structure(self, tmp_path):
        """Generated PE binary has valid MZ header and PE signature at e_lfanew."""
        rule = RULES_DIR / "rule6.yar"
        _, win_dir = _invoke(rule, tmp_path)
        data = (win_dir / "app.exe").read_bytes()
        assert data[0:2] == b"MZ", "Missing MZ magic"
        pe_off = int.from_bytes(data[0x3C:0x40], "little")
        assert data[pe_off:pe_off + 4] == b"PE\x00\x00", "Missing PE signature"

    def test_pe_build_artefacts_created(self, tmp_path):
        """Pipeline writes all expected build artefacts for a PE rule."""
        rule = RULES_DIR / "rule6.yar"
        _, win_dir = _invoke(rule, tmp_path)
        for name in ("main.c", "normalized_rule.yar", "app.exe"):
            assert (win_dir / name).exists(), f"{name} missing from Windows build dir"


# ---------------------------------------------------------------------------
# E2E — PipelineConfig wiring (mocked — no LLM calls needed)
# ---------------------------------------------------------------------------

class TestE2EPipelineConfig:
    """Verify per-role LLM model/base_url wiring inside build_graph."""

    def _capture_openai_calls(self, config: PipelineConfig) -> list[dict]:
        captured: list[dict] = []

        def fake_openai(**kwargs):
            captured.append(dict(kwargs))
            return MagicMock()

        with patch("aray.graph.ChatOpenAI", side_effect=fake_openai):
            build_graph(config=config)

        return captured

    def test_per_role_models_instantiated(self):
        """Each role's model name is passed to its own ChatOpenAI constructor."""
        config = PipelineConfig(
            normalize=LLMNodeConfig(model="strong-model"),
            extract=LLMNodeConfig(model="cheap-model"),
        )
        calls = self._capture_openai_calls(config)
        models = [c["model"] for c in calls]
        assert "strong-model" in models
        assert "cheap-model" in models

    def test_default_config_uses_gpt41(self):
        """build_graph() with no config creates both LLMs with the default gpt-4.1."""
        calls = self._capture_openai_calls(PipelineConfig())
        assert len(calls) == 2
        assert all(c["model"] == "gpt-4.1" for c in calls)

    def test_from_model_uses_same_model_for_both_roles(self):
        """PipelineConfig.from_model() forwards a single model name to both LLMs."""
        config = PipelineConfig.from_model(model="my-model")
        calls = self._capture_openai_calls(config)
        assert [c["model"] for c in calls] == ["my-model", "my-model"]

    def test_base_url_forwarded_per_role(self):
        """base_url in LLMNodeConfig is passed through to ChatOpenAI for each role."""
        config = PipelineConfig(
            normalize=LLMNodeConfig(model="m1", base_url="http://normalize-gw"),
            extract=LLMNodeConfig(model="m2", base_url="http://extract-gw"),
        )
        calls = self._capture_openai_calls(config)
        assert any(c.get("model") == "m1" and c.get("base_url") == "http://normalize-gw" for c in calls)
        assert any(c.get("model") == "m2" and c.get("base_url") == "http://extract-gw" for c in calls)

    def test_base_url_without_api_key_uses_dummy_key(self):
        """A custom base_url without an api_key gets the DUMMY_API_KEY placeholder,
        so local gateways (e.g. Ollama) work without any key configured."""
        config = PipelineConfig(
            normalize=LLMNodeConfig(model="m1", base_url="http://localhost:11434/v1"),
            extract=LLMNodeConfig(model="m2", base_url="http://localhost:11434/v1"),
        )
        calls = self._capture_openai_calls(config)
        assert all(c.get("base_url") == "http://localhost:11434/v1" for c in calls)
        assert all(c.get("api_key") == "not-needed" for c in calls)

    def test_no_base_url_passes_no_api_key(self):
        """Without a base_url, ChatOpenAI must NOT receive an api_key, so an
        unset OPENAI_API_KEY still surfaces as a clear client error."""
        config = PipelineConfig(
            normalize=LLMNodeConfig(model="m1"),
            extract=LLMNodeConfig(model="m2"),
        )
        calls = self._capture_openai_calls(config)
        assert all("api_key" not in c for c in calls)

    def test_explicit_api_key_forwarded(self):
        """A configured api_key wins over the placeholder."""
        config = PipelineConfig(
            normalize=LLMNodeConfig(model="m1", base_url="http://gw", api_key="secret-key"),
        )
        calls = self._capture_openai_calls(config)
        assert any(c.get("api_key") == "secret-key" for c in calls)


# ---------------------------------------------------------------------------
# E2E — PipelineConfig.use_structured_output wiring (mocked)
# ---------------------------------------------------------------------------

class TestPipelineConfigUnstructured:
    """Verify use_structured_output flag wiring in build_graph.

    Structured output is the default; the flag exists only as a programmatic
    escape hatch (the pipeline otherwise auto-falls back to prompt-based JSON
    when tool calls are unsupported).
    """

    def test_default_config_has_structured_output_true(self):
        """PipelineConfig() defaults to use_structured_output=True."""
        assert PipelineConfig().use_structured_output is True

    def test_no_structured_output_flag_propagates(self):
        """Nodes call _invoke_llm with use_structured=False when the config flag is set."""
        from aray.models import NormalizedYaraRule, YaraConstants, YaraStrings

        config = PipelineConfig(use_structured_output=False)
        invoke_llm_calls: list[bool] = []

        from aray.models import JudgeVerdict

        def spy_invoke_llm(llm, schema, messages, use_structured):
            invoke_llm_calls.append(use_structured)
            if schema is NormalizedYaraRule:
                return NormalizedYaraRule(rule="rule x { condition: true }")
            if schema is YaraStrings:
                return YaraStrings(strings=[])
            if schema is YaraConstants:
                return YaraConstants(constants=[])
            return JudgeVerdict(verdict="passed", reason="ok")

        # Rule with a regex — forces the normalize/judge LLM loop to run
        _needs_norm_rule = 'rule x { strings: $a = /test/ condition: $a }'
        with (
            patch("aray.graph.ChatOpenAI", return_value=MagicMock()),
            patch("aray.nodes._invoke_llm", side_effect=spy_invoke_llm),
            patch("aray.graph.read_yara_rule", return_value={"yara_rule": _needs_norm_rule}),
            patch("aray.graph.compile_binary", return_value={}),
        ):
            graph = build_graph(config=config)
            graph.invoke({"name": "test", "rule_path": "dummy.yar"})

        # normalize_rule + judge_rule + extract_strings + extract_constants
        assert len(invoke_llm_calls) == 4
        assert all(v is False for v in invoke_llm_calls)


# ---------------------------------------------------------------------------
# E2E — forced prompt-based JSON path (real LLM)
# ---------------------------------------------------------------------------

@pytest.mark.llm
@pytest.mark.no_structured_output
@requires_api_key
@requires_yara_and_gcc
class TestE2ELinuxNoStructuredOutput:
    """Full pipeline with use_structured_output=False → ELF binary → YARA scan.

    Exercises the prompt-based JSON fallback path directly (the mode the
    pipeline selects automatically when structured output is unavailable).
    Enable with:  pytest -m no_structured_output
                  pytest -m llm          (included in the broader llm suite)
    """

    def test_rule0_matches(self, tmp_path):
        """rule0: JSON-fallback LLM path extracts the string; ELF matches the rule."""
        rule = RULES_DIR / "rule0.yar"
        linux_dir, _ = _invoke(rule, tmp_path, use_structured_output=False)
        assert (linux_dir / "app").exists(), "ELF binary not created"
        result = _yara_scan(rule, linux_dir / "app")
        assert result.returncode == 0
        assert "rule0" in result.stdout

    def test_rule1_matches(self, tmp_path):
        """rule1: JSON-fallback extracts both strings; ELF matches the rule."""
        rule = RULES_DIR / "rule1.yar"
        linux_dir, _ = _invoke(rule, tmp_path, use_structured_output=False)
        result = _yara_scan(rule, linux_dir / "app")
        assert result.returncode == 0
        assert "rule1" in result.stdout

    def test_build_artefacts_created(self, tmp_path):
        """Pipeline writes all expected build artefacts when structured output is off."""
        rule = RULES_DIR / "rule0.yar"
        linux_dir, _ = _invoke(rule, tmp_path, use_structured_output=False)
        for name in ("main.S", "linker.ld", "normalized_rule.yar", "app"):
            assert (linux_dir / name).exists(), f"{name} missing from Linux build dir"


# ---------------------------------------------------------------------------
# E2E — Linux ELF rules with --scan-only (real LLM, no gcc needed)
# ---------------------------------------------------------------------------

@pytest.mark.llm
@requires_api_key
@requires_yara
class TestE2ELinuxScanOnly:
    """Full LLM pipeline with scan_only=True → raw ELF artifact → YARA scan."""

    def test_rule0_scan_only_matches(self, tmp_path):
        """rule0: scan-only path writes raw ELF; YARA still matches."""
        rule = RULES_DIR / "rule0.yar"
        linux_dir, _ = _invoke(rule, tmp_path, scan_only=True)
        assert (linux_dir / "app").exists(), "Artifact not created"
        result = _yara_scan(rule, linux_dir / "app")
        assert result.returncode == 0
        assert "rule0" in result.stdout

    def test_rule1_scan_only_matches(self, tmp_path):
        """rule1: two-string rule; scan-only raw ELF matches."""
        rule = RULES_DIR / "rule1.yar"
        linux_dir, _ = _invoke(rule, tmp_path, scan_only=True)
        result = _yara_scan(rule, linux_dir / "app")
        assert result.returncode == 0
        assert "rule1" in result.stdout

    def test_linux_scan_only_artefacts_created(self, tmp_path):
        """scan-only mode writes main.S, linker.ld, normalized_rule.yar, and app."""
        rule = RULES_DIR / "rule0.yar"
        linux_dir, _ = _invoke(rule, tmp_path, scan_only=True)
        for name in ("main.S", "linker.ld", "normalized_rule.yar", "app"):
            assert (linux_dir / name).exists(), f"{name} missing from Linux scan-only build dir"

    def test_linux_scan_only_no_compiler_invoked(self, tmp_path):
        """scan-only mode must not call gcc even though app artifact is produced."""
        rule = RULES_DIR / "rule0.yar"
        gcc_calls: list[list] = []
        _real_run = subprocess.run

        def _spy_run(cmd, *args, **kwargs):
            if isinstance(cmd, list) and cmd and "gcc" in cmd[0]:
                gcc_calls.append(cmd)
            return _real_run(cmd, *args, **kwargs)

        with patch("aray.compiler.subprocess.run", side_effect=_spy_run):
            _invoke(rule, tmp_path, scan_only=True)

        assert gcc_calls == [], f"gcc was invoked unexpectedly: {gcc_calls}"


# ---------------------------------------------------------------------------
# E2E — Windows PE rules with --scan-only (real LLM, no MinGW needed)
# ---------------------------------------------------------------------------

@pytest.mark.llm
@requires_api_key
@requires_yara
class TestE2EPEScanOnly:
    """Full LLM pipeline with scan_only=True → raw PE64 artifact → YARA scan."""

    def test_rule6_scan_only_matches(self, tmp_path):
        """rule6: scan-only path writes raw PE64; YARA still matches."""
        rule = RULES_DIR / "rule6.yar"
        _, win_dir = _invoke(rule, tmp_path, scan_only=True)
        assert (win_dir / "app.exe").exists(), "PE artifact not created"
        result = _yara_scan(rule, win_dir / "app.exe")
        assert result.returncode == 0
        assert "maindll_mutex" in result.stdout

    def test_pe_scan_only_structure(self, tmp_path):
        """scan-only PE64 must have valid MZ header and PE signature at e_lfanew."""
        rule = RULES_DIR / "rule6.yar"
        _, win_dir = _invoke(rule, tmp_path, scan_only=True)
        data = (win_dir / "app.exe").read_bytes()
        assert data[0:2] == b"MZ", "Missing MZ magic"
        pe_off = int.from_bytes(data[0x3C:0x40], "little")
        assert data[pe_off:pe_off + 4] == b"PE\x00\x00", "Missing PE signature"

    def test_pe_scan_only_artefacts_created(self, tmp_path):
        """scan-only PE mode writes main.S, normalized_rule.yar, and app.exe."""
        rule = RULES_DIR / "rule6.yar"
        _, win_dir = _invoke(rule, tmp_path, scan_only=True)
        for name in ("main.S", "normalized_rule.yar", "app.exe"):
            assert (win_dir / name).exists(), f"{name} missing from Windows scan-only build dir"

    def test_pe_scan_only_no_compiler_invoked(self, tmp_path):
        """scan-only PE mode must not call x86_64-w64-mingw32-gcc."""
        rule = RULES_DIR / "rule6.yar"
        mingw_calls: list[list] = []
        _real_run = subprocess.run

        def _spy_run(cmd, *args, **kwargs):
            if isinstance(cmd, list) and cmd and "mingw32-gcc" in cmd[0]:
                mingw_calls.append(cmd)
            return _real_run(cmd, *args, **kwargs)

        with patch("aray.compiler.subprocess.run", side_effect=_spy_run):
            _invoke(rule, tmp_path, scan_only=True)

        assert mingw_calls == [], f"mingw32-gcc was invoked unexpectedly: {mingw_calls}"
