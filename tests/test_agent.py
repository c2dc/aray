"""Tests for the aray agent pipeline."""

import shutil
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from langchain_core.exceptions import OutputParserException
from langchain_core.messages import HumanMessage, SystemMessage

from aray.constants import BANNER, BUILD_DIR_GENERIC, BUILD_DIR_WIN, MINGW_GCC
from aray.models import NormalizedYaraRule, YaraConstants, YaraConstantEntry, YaraStringEntry, YaraStrings
from aray.state import ArayGraphState
from aray.llm import _invoke_llm
from aray.artifact_writer import _compute_padding, write_generic_artifact, write_linux_artifact, write_pe_artifact
from aray.codegen import (
    _assign_offsets,
    _constants_to_sections,
    _format_ascii_initializer,
    _format_hex_initializer,
    _generate_asm_source,
    _generate_linker_script,
    _hex_str_to_bytes,
    _int_to_le_bytes,
    _resolve_yara_hex,
)
from aray.compiler import _parse_filesize_constraint, _patch_constants, compile_binary
from aray.nodes import _requires_normalization, check_normalization_needed, extract_constants, extract_strings, fail_normalization, normalize_rule, read_yara_rule, route_file_type, write_generic
from aray.evaluator import EvalConfig, _run_one
from aray.cli import _clean_build_outputs, parse_args

RULES_DIR = Path("data/rules")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_state(
    rule_path: str,
    rule_strings: list[YaraStringEntry],
    rule_constants: list[dict] | None = None,
) -> ArayGraphState:
    """Build a minimal ArayGraphState."""
    rule_text = Path(rule_path).read_text()
    return {
        "name": "test",
        "rule_path": rule_path,
        "yara_rule": rule_text,
        "normalized_rule": rule_text,
        "rule_strings": rule_strings,
        "rule_constants": rule_constants or [],
        "has_condition": any(s.offset is not None for s in rule_strings),
    }


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class TestYaraStringEntry:
    def test_ascii_no_offset(self):
        entry = YaraStringEntry(value="hello")
        assert entry.value == "hello"
        assert entry.offset is None
        assert entry.format == "ascii"

    def test_hex_with_offset(self):
        entry = YaraStringEntry(value="DE AD", offset=0x600, format="hex")
        assert entry.value == "DE AD"
        assert entry.offset == 0x600
        assert entry.format == "hex"

    def test_widechar_format(self):
        entry = YaraStringEntry(value="powershell.exe", format="widechar")
        assert entry.format == "widechar"

    def test_invalid_format_rejected(self):
        with pytest.raises(Exception):
            YaraStringEntry(value="x", format="wide")


class TestYaraStrings:
    def test_empty_strings_list(self):
        result = YaraStrings(strings=[])
        assert result.strings == []

    def test_multiple_entries(self):
        entries = [
            YaraStringEntry(value="a"),
            YaraStringEntry(value="FF", format="hex", offset=0x100),
        ]
        result = YaraStrings(strings=entries)
        assert len(result.strings) == 2


# ---------------------------------------------------------------------------
# Initializer helpers
# ---------------------------------------------------------------------------
class TestResolveYaraHex:
    def test_no_special_syntax(self):
        assert _resolve_yara_hex("AB CD EF") == "AB CD EF"

    def test_wildcard_single(self):
        assert _resolve_yara_hex("AB ?? EF") == "AB 00 EF"

    def test_wildcard_multiple(self):
        assert _resolve_yara_hex("AB ?? ?? EF") == "AB 00 00 EF"

    def test_jump_exact(self):
        assert _resolve_yara_hex("F4 23 [3] 62 B4") == "F4 23 00 00 00 62 B4"

    def test_jump_range_uses_minimum(self):
        assert _resolve_yara_hex("F4 23 [4-6] 62 B4") == "F4 23 00 00 00 00 62 B4"

    def test_jump_range_minimum_one(self):
        assert _resolve_yara_hex("F4 23 [1-100] 62 B4") == "F4 23 00 62 B4"

    def test_jump_zero_minimum(self):
        # [0-N] jump with minimum 0 → nothing inserted
        assert _resolve_yara_hex("AB [0-3] CD") == "AB CD"

    def test_mixed_wildcard_and_jump(self):
        assert _resolve_yara_hex("AB ?? [2-4] CD") == "AB 00 00 00 CD"

    def test_hex_str_to_bytes_with_wildcard(self):
        assert _hex_str_to_bytes("AB ?? CD") == bytes([0xAB, 0x00, 0xCD])

    def test_hex_str_to_bytes_with_jump(self):
        assert _hex_str_to_bytes("F4 23 [4-6] 62 B4") == bytes([0xF4, 0x23, 0x00, 0x00, 0x00, 0x00, 0x62, 0xB4])

    def test_format_hex_initializer_with_wildcard(self):
        assert _format_hex_initializer("AB ?? CD") == "{0xAB, 0x00, 0xCD}"


class TestFormatHexInitializer:
    def test_single_byte(self):
        assert _format_hex_initializer("AB") == "{0xAB}"

    def test_multiple_bytes(self):
        assert _format_hex_initializer("E2 34 C8 FB") == "{0xE2, 0x34, 0xC8, 0xFB}"

    def test_two_bytes(self):
        assert _format_hex_initializer("00 FF") == "{0x00, 0xFF}"

    def test_concatenated_hex(self):
        assert _format_hex_initializer("DEADBEEF") == "{0xDE, 0xAD, 0xBE, 0xEF}"


class TestFormatAsciiInitializer:
    def test_simple_string(self):
        assert _format_ascii_initializer("hello") == '{"hello"}'

    def test_string_with_dot(self):
        assert _format_ascii_initializer("skype.dat") == '{"skype.dat"}'

    def test_string_with_backslash(self):
        assert _format_ascii_initializer("\\update.dat") == '{"\\\\update.dat"}'

    def test_string_with_double_quote(self):
        assert _format_ascii_initializer('say "hi"') == '{"say \\"hi\\""}'


# ---------------------------------------------------------------------------
# _assign_offsets
# ---------------------------------------------------------------------------
class TestAssignOffsets:
    def test_explicit_offsets_preserved(self):
        strings = [
            YaraStringEntry(value="a", offset=0x600),
            YaraStringEntry(value="b", offset=0x800),
        ]
        result = _assign_offsets(strings)
        assert result[0][0] == 0x600
        assert result[1][0] == 0x800

    def test_no_offset_gets_defaults(self):
        strings = [
            YaraStringEntry(value="a"),
            YaraStringEntry(value="b"),
        ]
        result = _assign_offsets(strings, default_base=0x3000, step=0x100)
        assert result[0][0] == 0x3000
        assert result[1][0] == 0x3100

    def test_mixed_offsets(self):
        strings = [
            YaraStringEntry(value="a", offset=0x600),
            YaraStringEntry(value="b"),
            YaraStringEntry(value="c", offset=0x800),
        ]
        result = _assign_offsets(strings, default_base=0x3000, step=0x100)
        assert result[0][0] == 0x600
        assert result[1][0] == 0x3000
        assert result[2][0] == 0x800

    def test_hex_format_bytes(self):
        strings = [YaraStringEntry(value="E2 34", format="hex")]
        result = _assign_offsets(strings)
        assert result[0][1] == b"\xE2\x34"

    def test_ascii_format_bytes(self):
        strings = [YaraStringEntry(value="hello")]
        result = _assign_offsets(strings)
        assert result[0][1] == b"hello"

    def test_widechar_format_bytes(self):
        strings = [YaraStringEntry(value="hi", format="widechar")]
        result = _assign_offsets(strings)
        assert result[0][1] == "hi".encode("utf-16-le")

    def test_empty_list(self):
        assert _assign_offsets([]) == []

    def test_pack_mode_consecutive_offsets(self):
        """pack=True advances by len(data)+1 instead of the fixed step."""
        strings = [
            YaraStringEntry(value="abc"),   # 3 bytes
            YaraStringEntry(value="de"),    # 2 bytes
        ]
        result = _assign_offsets(strings, default_base=0x10, pack=True)
        assert result[0][0] == 0x10
        assert result[1][0] == 0x10 + 3 + 1   # 0x14

    def test_pack_mode_explicit_offset_unaffected(self):
        """pack=True does not alter strings that carry an explicit at-offset."""
        strings = [
            YaraStringEntry(value="abc", offset=0x600),
            YaraStringEntry(value="de"),
        ]
        result = _assign_offsets(strings, default_base=0x10, pack=True)
        assert result[0][0] == 0x600
        assert result[1][0] == 0x10


# ---------------------------------------------------------------------------
# _generate_asm_source
# ---------------------------------------------------------------------------
class TestGenerateAsmSource:
    def test_single_section(self):
        src = _generate_asm_source([(0x600, b"test")])
        assert ".sec_0x600" in src
        assert "0x74, 0x65, 0x73, 0x74" in src  # b"test"
        assert "_start" in src

    def test_multiple_sections(self):
        src = _generate_asm_source([(0x600, b"a"), (0x800, b"b")])
        assert ".sec_0x600" in src
        assert ".sec_0x800" in src

    def test_empty_sections(self):
        src = _generate_asm_source([])
        assert "_start" in src

    def test_skips_empty_data(self):
        src = _generate_asm_source([(0x600, b"")])
        assert ".sec_0x600" not in src
        assert "_start" in src

    def test_no_c_syntax(self):
        src = _generate_asm_source([])
        assert "#include" not in src
        assert "__attribute__" not in src

    def test_hex_bytes_in_section(self):
        src = _generate_asm_source([(0x3000, b"\xE2\x34\xC8\xFB")])
        assert "0xE2, 0x34, 0xC8, 0xFB" in src


# ---------------------------------------------------------------------------
# _generate_linker_script
# ---------------------------------------------------------------------------
class TestGenerateLinkerScript:
    def test_single_offset(self):
        script = _generate_linker_script([0x600])
        assert ". = 0x400600;" in script   # VMA = ELF_BASE + file_offset
        assert ".sec_0x600" in script
        assert ".text" in script

    def test_multiple_offsets_sorted(self):
        script = _generate_linker_script([0x800, 0x600])
        # Offsets must appear in ascending order
        pos_600 = script.index("0x600")
        pos_800 = script.index("0x800")
        assert pos_600 < pos_800

    def test_standard_sections_after_custom(self):
        script = _generate_linker_script([0x600])
        pos_custom = script.index(".sec_0x600")
        pos_text = script.index(".text")
        assert pos_custom < pos_text

    def test_empty_offsets(self):
        script = _generate_linker_script([])
        assert ".text" in script


# ---------------------------------------------------------------------------
# read_yara_rule node
# ---------------------------------------------------------------------------
class TestReadYaraRule:
    @pytest.mark.parametrize(
        "rule_file",
        ["rule0.yar", "rule1.yar", "rule2.yar", "rule3.yar", "rule4.yar", "rule5.yar"],
    )
    def test_reads_all_rules(self, rule_file):
        path = str(RULES_DIR / rule_file)
        state: ArayGraphState = {
            "name": "test",
            "rule_path": path,
            "yara_rule": "",
            "rule_strings": [],
            "has_condition": False,
        }
        result = read_yara_rule(state)
        assert "yara_rule" in result
        assert "rule" in result["yara_rule"]
        assert "strings:" in result["yara_rule"]

    def test_missing_file_raises(self, tmp_path):
        state: ArayGraphState = {
            "name": "test",
            "rule_path": str(tmp_path / "nonexistent.yar"),
            "yara_rule": "",
            "rule_strings": [],
            "has_condition": False,
        }
        with pytest.raises(FileNotFoundError):
            read_yara_rule(state)

    def test_reads_only_first_public_rule_and_reachable_helpers(self, tmp_path):
        path = tmp_path / "multi.yar"
        path.write_text(
            'private rule Helper { strings: $h = "helper" condition: $h }\n'
            'rule First { condition: Helper }\n'
            'rule Later { strings: $x = /later.*/ condition: $x }\n'
        )
        state: ArayGraphState = {
            "name": "test",
            "rule_path": str(path),
            "yara_rule": "",
            "rule_strings": [],
            "has_condition": False,
        }

        selected = read_yara_rule(state)["yara_rule"]

        assert "rule First" in selected
        assert "rule Helper" not in selected
        assert "rule Later" not in selected
        assert "$__Helper_h" in selected


# ---------------------------------------------------------------------------
# extract_strings node (LLM mocked)
# ---------------------------------------------------------------------------
def _mock_llm_response(entries: list[YaraStringEntry]):
    """Build a mock chain that returns a YaraStrings object."""
    mock_chain = MagicMock()
    mock_chain.invoke.return_value = YaraStrings(strings=entries)
    mock_llm = MagicMock()
    mock_llm.with_structured_output.return_value = mock_chain
    return mock_llm


class TestExtractStrings:
    """Test extract_strings with mocked LLM, one case per YARA rule."""

    def _run(self, rule_path: str, expected_entries: list[YaraStringEntry]):
        rule_text = Path(rule_path).read_text()
        state: ArayGraphState = {
            "name": "test",
            "rule_path": rule_path,
            "yara_rule": rule_text,
            "normalized_rule": rule_text,
            "rule_strings": [],
            "has_condition": False,
        }
        mock_llm = _mock_llm_response(expected_entries)
        return extract_strings(state, llm=mock_llm)

    def test_rule0_single_ascii(self):
        entries = [YaraStringEntry(value="dummy1")]
        result = self._run(str(RULES_DIR / "rule0.yar"), entries)
        assert len(result["rule_strings"]) == 1
        assert result["has_condition"] is False

    def test_rule1_two_ascii(self):
        entries = [
            YaraStringEntry(value="skype.dat"),
            YaraStringEntry(value="emanuel"),
        ]
        result = self._run(str(RULES_DIR / "rule1.yar"), entries)
        assert len(result["rule_strings"]) == 2
        assert result["has_condition"] is False

    def test_rule2_ascii_with_offset(self):
        entries = [
            YaraStringEntry(value="dummy1", offset=0x600),
            YaraStringEntry(value="dummy2"),
        ]
        result = self._run(str(RULES_DIR / "rule2.yar"), entries)
        assert result["has_condition"] is True
        assert result["rule_strings"][0].offset == 0x600

    def test_rule3_hex_no_offset(self):
        entries = [YaraStringEntry(value="E2 34 C8 FB", format="hex")]
        result = self._run(str(RULES_DIR / "rule3.yar"), entries)
        assert result["rule_strings"][0].format == "hex"
        assert result["has_condition"] is False

    def test_rule4_hex_with_offset_and_ascii(self):
        entries = [
            YaraStringEntry(value="E2 34 C8 FB", offset=0x600, format="hex"),
            YaraStringEntry(value="dummy2"),
        ]
        result = self._run(str(RULES_DIR / "rule4.yar"), entries)
        assert result["has_condition"] is True

    def test_rule5_multi_offset(self):
        entries = [
            YaraStringEntry(value="alpha", offset=0x600),
            YaraStringEntry(value="beta", offset=0x800),
        ]
        result = self._run(str(RULES_DIR / "rule5.yar"), entries)
        assert len(result["rule_strings"]) == 2
        assert result["has_condition"] is True
        assert result["rule_strings"][0].offset == 0x600
        assert result["rule_strings"][1].offset == 0x800

    def test_rule9_wide_and_ascii(self):
        entries = [
            YaraStringEntry(value="subjectname"),
            YaraStringEntry(value="/de", format="widechar"),
        ]
        result = self._run(str(RULES_DIR / "rule9.yar"), entries)
        assert any(e.format == "widechar" for e in result["rule_strings"])
        assert result["has_condition"] is False


# ---------------------------------------------------------------------------
# compile_binary node (subprocess mocked)
# ---------------------------------------------------------------------------
class TestCompileBinary:
    """Test generated assembler source, linker script, and gcc invocation."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        self.build_dir = tmp_path / "build"
        self.build_dir.mkdir()
        monkeypatch.setattr("aray.compiler.BUILD_DIR", self.build_dir)
        self._gcc_mock = MagicMock()
        self._subprocess_patcher = patch("aray.compiler.subprocess.run", self._gcc_mock)
        self._subprocess_patcher.start()

    @pytest.fixture(autouse=True)
    def _teardown(self):
        yield
        self._subprocess_patcher.stop()

    def _read_generated(self) -> tuple[str, str]:
        main_s = (self.build_dir / "main.S").read_text()
        linker = (self.build_dir / "linker.ld").read_text()
        return main_s, linker

    def test_rule0_single_ascii(self):
        """rule0: single ASCII string gets its own section at a default offset."""
        strings = [YaraStringEntry(value="dummy1")]
        state = _make_state(str(RULES_DIR / "rule0.yar"), strings)
        compile_binary(state)

        src, linker = self._read_generated()
        assert ".sec_0x3000" in src
        assert "0x3000" in linker
        assert "_start" in src
        self._gcc_mock.assert_called_once()

    def test_rule1_two_ascii_both_embedded(self):
        """rule1: both ASCII strings get their own sections."""
        strings = [
            YaraStringEntry(value="skype.dat"),
            YaraStringEntry(value="emanuel"),
        ]
        state = _make_state(str(RULES_DIR / "rule1.yar"), strings)
        compile_binary(state)

        src, linker = self._read_generated()
        assert ".sec_0x3000" in src
        assert ".sec_0x3100" in src

    def test_rule2_ascii_with_offset(self):
        """rule2: $a at 0x600 and $b at default offset."""
        strings = [
            YaraStringEntry(value="dummy1", offset=0x600),
            YaraStringEntry(value="dummy2"),
        ]
        state = _make_state(str(RULES_DIR / "rule2.yar"), strings)
        compile_binary(state)

        src, linker = self._read_generated()
        assert ".sec_0x600" in src
        assert "0x600" in linker

    def test_rule3_hex_no_offset(self):
        """rule3: hex bytes get a section at a default offset."""
        strings = [YaraStringEntry(value="E2 34 C8 FB", format="hex")]
        state = _make_state(str(RULES_DIR / "rule3.yar"), strings)
        compile_binary(state)

        src, _ = self._read_generated()
        assert "0xE2, 0x34, 0xC8, 0xFB" in src

    def test_rule4_hex_offset_and_ascii(self):
        """rule4: hex at 0x600 and ASCII at default offset."""
        strings = [
            YaraStringEntry(value="E2 34 C8 FB", offset=0x600, format="hex"),
            YaraStringEntry(value="dummy2"),
        ]
        state = _make_state(str(RULES_DIR / "rule4.yar"), strings)
        compile_binary(state)

        src, linker = self._read_generated()
        assert "0xE2, 0x34, 0xC8, 0xFB" in src
        assert "0x600" in linker

    def test_rule5_multi_offset(self):
        """rule5: two strings at different explicit offsets."""
        strings = [
            YaraStringEntry(value="alpha", offset=0x600),
            YaraStringEntry(value="beta", offset=0x800),
        ]
        state = _make_state(str(RULES_DIR / "rule5.yar"), strings)
        compile_binary(state)

        src, linker = self._read_generated()
        assert ".sec_0x600" in src
        assert ".sec_0x800" in src
        assert "0x600" in linker
        assert "0x800" in linker

    def test_gcc_receives_correct_paths(self):
        strings = [YaraStringEntry(value="test")]
        state = _make_state(str(RULES_DIR / "rule0.yar"), strings)
        compile_binary(state)

        cmd = self._gcc_mock.call_args[0][0]
        assert cmd[0] == "gcc"
        assert "-o" in cmd
        assert "-T" in cmd
        assert "-static" in cmd
        assert "-nostdlib" in cmd
        assert "-no-pie" in cmd
        assert str(self.build_dir / "app") in cmd
        assert str(self.build_dir / "main.S") in cmd

    def test_empty_strings_still_compiles(self):
        """No strings at all should produce a valid (minimal) binary."""
        state = _make_state(str(RULES_DIR / "rule0.yar"), [])
        compile_binary(state)

        src, linker = self._read_generated()
        assert "_start" in src
        assert ".text" in linker
        self._gcc_mock.assert_called_once()


# ---------------------------------------------------------------------------
# compile_binary PE node (subprocess mocked)
# ---------------------------------------------------------------------------
_MZ_CONST = [{"value": "0x5A4D", "offset": 0, "size": 2, "is_nested": False}]


class TestCompileBinaryPE:
    """Test generated main.c content for Windows PE (MinGW) compilation."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        self.build_dir = tmp_path / "build"
        self.build_dir.mkdir()
        monkeypatch.setattr("aray.compiler.BUILD_DIR_WIN", self.build_dir)
        self._gcc_mock = MagicMock()
        self._subprocess_patcher = patch("aray.compiler.subprocess.run", self._gcc_mock)
        self._subprocess_patcher.start()

    @pytest.fixture(autouse=True)
    def _teardown(self):
        yield
        self._subprocess_patcher.stop()

    def _read_main_c(self) -> str:
        return (self.build_dir / "main.c").read_text()

    def test_widechar_includes_wchar_h(self):
        strings = [YaraStringEntry(value="powershell.exe", format="widechar")]
        state = _make_state(str(RULES_DIR / "rule9.yar"), strings, rule_constants=_MZ_CONST)
        compile_binary(state)
        assert "#include <wchar.h>" in self._read_main_c()

    def test_widechar_generates_const_wchar_declaration(self):
        strings = [YaraStringEntry(value="powershell.exe", format="widechar")]
        state = _make_state(str(RULES_DIR / "rule9.yar"), strings, rule_constants=_MZ_CONST)
        compile_binary(state)
        assert 'const wchar_t *ws_0 = L"powershell.exe";' in self._read_main_c()

    def test_no_wide_strings_no_wchar_include(self):
        strings = [YaraStringEntry(value="hello")]
        state = _make_state(str(RULES_DIR / "rule6.yar"), strings, rule_constants=_MZ_CONST)
        compile_binary(state)
        assert "#include <wchar.h>" not in self._read_main_c()

    def test_mixed_ascii_and_wide_in_same_source(self):
        strings = [
            YaraStringEntry(value="subjectname"),
            YaraStringEntry(value="/de", format="widechar"),
        ]
        state = _make_state(str(RULES_DIR / "rule9.yar"), strings, rule_constants=_MZ_CONST)
        compile_binary(state)
        src = self._read_main_c()
        assert '{"subjectname"}' in src
        assert 'const wchar_t *ws_1 = L"/de";' in src

    def test_mingw_invoked(self):
        strings = [YaraStringEntry(value="test", format="widechar")]
        state = _make_state(str(RULES_DIR / "rule9.yar"), strings, rule_constants=_MZ_CONST)
        compile_binary(state)
        cmd = self._gcc_mock.call_args[0][0]
        assert cmd[0] == MINGW_GCC


# ---------------------------------------------------------------------------
# _int_to_le_bytes
# ---------------------------------------------------------------------------
class TestIntToLeBytes:
    def test_uint16_mz(self):
        assert _int_to_le_bytes(0x5A4D, 2) == b"\x4D\x5A"

    def test_uint32_pe(self):
        assert _int_to_le_bytes(0x00004550, 4) == b"\x50\x45\x00\x00"

    def test_zero_uint16(self):
        assert _int_to_le_bytes(0, 2) == b"\x00\x00"

    def test_uint32_arbitrary(self):
        assert _int_to_le_bytes(0x12345678, 4) == b"\x78\x56\x34\x12"


# ---------------------------------------------------------------------------
# _constants_to_sections
# ---------------------------------------------------------------------------
class TestConstantsToSections:
    def test_non_nested_uint16(self):
        constants = [{"value": 0x5A4D, "offset": 0, "size": 2, "is_nested": False}]
        result = _constants_to_sections(constants)
        assert result == [(0, b"\x4D\x5A")]

    def test_non_nested_uint32(self):
        constants = [{"value": 0x4550, "offset": 0x3C, "size": 4, "is_nested": False}]
        result = _constants_to_sections(constants)
        assert result == [(0x3C, b"\x50\x45\x00\x00")]

    def test_nested_places_pointer_and_value(self):
        constants = [{"value": 0x00004550, "offset": 0x3C, "size": 4, "is_nested": True}]
        result = _constants_to_sections(constants)
        assert len(result) == 2
        assert result[0] == (0x3C, b"\x00\x01\x00\x00")  # pointer to 0x100
        assert result[1] == (0x100, b"\x50\x45\x00\x00")  # value at 0x100

    def test_multiple_nested_increments_intermediate(self):
        constants = [
            {"value": 0x00004550, "offset": 0x3C, "size": 4, "is_nested": True},
            {"value": 0x00004550, "offset": 0x4E, "size": 4, "is_nested": True},
        ]
        result = _constants_to_sections(constants)
        assert len(result) == 4
        assert result[0] == (0x3C, b"\x00\x01\x00\x00")   # pointer -> 0x100
        assert result[1] == (0x100, b"\x50\x45\x00\x00")  # value at 0x100
        assert result[2] == (0x4E, b"\x10\x01\x00\x00")   # pointer -> 0x110
        assert result[3] == (0x110, b"\x50\x45\x00\x00")  # value at 0x110

    def test_none_offset_skipped(self):
        constants = [{"value": 0x5A4D, "offset": None, "size": 2, "is_nested": False}]
        result = _constants_to_sections(constants)
        assert result == []

    def test_empty_list(self):
        assert _constants_to_sections([]) == []

    def test_string_value_coercion(self):
        constants = [{"value": "0x5A4D", "offset": 0, "size": 2, "is_nested": False}]
        result = _constants_to_sections(constants)
        assert result == [(0, b"\x4D\x5A")]

    def test_decimal_string_value_coercion(self):
        constants = [{"value": "255", "offset": 0, "size": 2, "is_nested": False}]
        result = _constants_to_sections(constants)
        assert result == [(0, b"\xFF\x00")]


# ---------------------------------------------------------------------------
# _patch_constants
# ---------------------------------------------------------------------------
class TestPatchConstants:
    """Unit tests for _patch_constants using a real temp file."""

    def test_non_nested_writes_le_bytes(self, tmp_path):
        binary = tmp_path / "app"
        binary.write_bytes(b"\x00" * 0x200)
        _patch_constants(binary, [{"value": "0x5A4D", "offset": 0, "size": 2, "is_nested": False}])
        data = binary.read_bytes()
        assert data[0:2] == b"\x4D\x5A"

    def test_nested_appends_value_writes_pointer(self, tmp_path):
        binary = tmp_path / "app"
        binary.write_bytes(b"\x00" * 0x200)
        _patch_constants(binary, [{"value": "0x00004550", "offset": 0x3C, "size": 4, "is_nested": True}])
        data = binary.read_bytes()
        ptr = int.from_bytes(data[0x3C:0x40], "little")
        assert ptr == 0x200
        assert data[0x200:0x204] == b"\x50\x45\x00\x00"

    def test_multiple_nested_appended_sequentially(self, tmp_path):
        binary = tmp_path / "app"
        binary.write_bytes(b"\x00" * 0x200)
        constants = [
            {"value": "0x00004550", "offset": 0x3C, "size": 4, "is_nested": True},
            {"value": "0x00004550", "offset": 0x4E, "size": 4, "is_nested": True},
        ]
        _patch_constants(binary, constants)
        data = binary.read_bytes()
        ptr1 = int.from_bytes(data[0x3C:0x40], "little")
        ptr2 = int.from_bytes(data[0x4E:0x52], "little")
        assert ptr1 == 0x200
        assert ptr2 == 0x204
        assert data[0x200:0x204] == b"\x50\x45\x00\x00"
        assert data[0x204:0x208] == b"\x50\x45\x00\x00"

    def test_none_offset_skipped(self, tmp_path):
        binary = tmp_path / "app"
        original = b"\xAB" * 0x10
        binary.write_bytes(original)
        _patch_constants(binary, [{"value": "0x5A4D", "offset": None, "size": 2, "is_nested": False}])
        assert binary.read_bytes() == original

    def test_empty_constants_no_change(self, tmp_path):
        binary = tmp_path / "app"
        original = b"\xAB" * 0x10
        binary.write_bytes(original)
        _patch_constants(binary, [])
        assert binary.read_bytes() == original

    def test_integer_value_accepted(self, tmp_path):
        binary = tmp_path / "app"
        binary.write_bytes(b"\x00" * 0x10)
        _patch_constants(binary, [{"value": 0x5A4D, "offset": 0, "size": 2, "is_nested": False}])
        assert binary.read_bytes()[0:2] == b"\x4D\x5A"


# ---------------------------------------------------------------------------
# compile_binary with constants
# ---------------------------------------------------------------------------
class TestCompileBinaryWithConstants:
    """Test that compile_binary patches constants into the binary after compilation."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        self.build_dir = tmp_path / "build"
        self.build_dir.mkdir()
        monkeypatch.setattr("aray.compiler.BUILD_DIR", self.build_dir)

        # Simulate gcc producing a 0x400-byte binary
        def fake_gcc(cmd, check=False, **kwargs):
            if cmd[0] == "gcc" and "-o" in cmd:
                out = Path(cmd[cmd.index("-o") + 1])
                out.write_bytes(b"\x00" * 0x400)

        self._subprocess_patcher = patch("aray.compiler.subprocess.run", side_effect=fake_gcc)
        self._subprocess_patcher.start()

    @pytest.fixture(autouse=True)
    def _teardown(self):
        yield
        self._subprocess_patcher.stop()

    def test_uint16_bytes_patched(self):
        """uint16(0x100) == 0x1234: LE bytes appear at file offset 0x100."""
        constants = [{"value": "0x1234", "offset": 0x100, "size": 2, "is_nested": False}]
        state = _make_state(str(RULES_DIR / "rule0.yar"), [], rule_constants=constants)
        compile_binary(state)
        data = (self.build_dir / "app").read_bytes()
        assert data[0x100:0x102] == b"\x34\x12"

    def test_constants_not_in_asm_source(self):
        """Constants are patched post-compilation, not embedded as .byte sections."""
        constants = [{"value": "0x1234", "offset": 0x100, "size": 2, "is_nested": False}]
        state = _make_state(str(RULES_DIR / "rule0.yar"), [], rule_constants=constants)
        compile_binary(state)
        src = (self.build_dir / "main.S").read_text()
        # 0x34 and 0x12 are not banner bytes, so they must not appear in the asm
        assert ".sec_0x100" not in src

    def test_strings_still_in_asm_source(self):
        """String sections are still generated in main.S when constants are present."""
        constants = [{"value": "0x1234", "offset": 0x100, "size": 2, "is_nested": False}]
        strings = [YaraStringEntry(value="h31415927tttt")]
        state = _make_state(str(RULES_DIR / "rule0.yar"), strings, rule_constants=constants)
        compile_binary(state)
        src = (self.build_dir / "main.S").read_text()
        assert ".sec_" in src
        assert "_start" in src

    def test_no_constants_backward_compat(self):
        """Empty rule_constants: compilation works as before, no patching."""
        strings = [YaraStringEntry(value="dummy1")]
        state = _make_state(str(RULES_DIR / "rule0.yar"), strings)
        compile_binary(state)
        src = (self.build_dir / "main.S").read_text()
        assert ".sec_" in src
        assert "_start" in src


# ---------------------------------------------------------------------------
# artifact_writer
# ---------------------------------------------------------------------------
class TestArtifactWriter:
    """Unit tests for the scan-only artifact writers (no compiler needed)."""

    def test_linux_artifact_has_elf_header(self):
        data = write_linux_artifact([], [])
        assert data[0:4] == b"\x7fELF"

    def test_linux_artifact_no_elf_if_section_at_zero(self):
        sections = [(0, b"\xAB\xCD")]
        data = write_linux_artifact(sections, [])
        assert data[0:2] == b"\xAB\xCD"

    def test_linux_artifact_places_bytes_at_offset(self):
        sections = [(0x600, b"hello")]
        data = write_linux_artifact(sections, [])
        assert data[0x600:0x605] == b"hello"

    def test_linux_artifact_patches_non_nested_constant(self):
        sections = [(0x600, b"x")]
        constants = [{"value": "0x1234", "offset": 0x100, "size": 2, "is_nested": False}]
        data = write_linux_artifact(sections, constants)
        assert data[0x100:0x102] == b"\x34\x12"

    def test_linux_artifact_skips_nested_constant(self):
        constants = [{"value": "0x00004550", "offset": 0x3C, "size": 4, "is_nested": True}]
        data = write_linux_artifact([], constants)
        # nested constant not patched — bytes at 0x3C remain zero
        assert data[0x3C:0x40] == b"\x00\x00\x00\x00"

    def test_linux_artifact_multiple_sections(self):
        sections = [(0x600, b"alpha"), (0x800, b"beta")]
        data = write_linux_artifact(sections, [])
        assert data[0x600:0x605] == b"alpha"
        assert data[0x800:0x804] == b"beta"

    def test_pe_artifact_has_mz_magic(self):
        data = write_pe_artifact([], [])
        assert data[0:2] == b"MZ"

    def test_pe_artifact_has_pe_signature(self):
        data = write_pe_artifact([], [])
        e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
        assert data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"

    def test_pe_artifact_contains_string_bytes(self):
        sections = [(0x3000, b"h31415927tttt")]
        data = write_pe_artifact(sections, [])
        assert b"h31415927tttt" in data

    def test_pe_artifact_places_bytes_at_offset(self):
        sections = [(0x600, b"alpha"), (0x800, b"beta")]
        data = write_pe_artifact(sections, [])
        assert data[0x600:0x605] == b"alpha"
        assert data[0x800:0x804] == b"beta"

    def test_pe_artifact_patches_non_nested_constant(self):
        constants = [{"value": "0x1234", "offset": 0x500, "size": 2, "is_nested": False}]
        data = write_pe_artifact([], constants)
        assert data[0x500:0x502] == b"\x34\x12"

    def test_pe_artifact_skips_nested_constant(self):
        constants = [{"value": "0x00004550", "offset": 0x3C, "size": 4, "is_nested": True}]
        data = write_pe_artifact([], constants)
        # nested constant not patched — 0x3C still holds e_lfanew (0x40), not 0x4550
        e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
        assert data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"

    def test_pe_artifact_satisfies_uint16_uint32(self):
        """Verify the two YARA uint checks that rule6 uses."""
        data = write_pe_artifact([], [])
        assert int.from_bytes(data[0:2], "little") == 0x5A4D
        e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
        assert int.from_bytes(data[e_lfanew : e_lfanew + 4], "little") == 0x00004550


# ---------------------------------------------------------------------------
# scan_only dispatch in compile_binary
# ---------------------------------------------------------------------------
class TestScanOnly:
    """Test compile_binary(scan_only=True) for both Linux and PE paths."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        self.linux_dir = tmp_path / "linux"
        self.linux_dir.mkdir()
        self.win_dir = tmp_path / "windows"
        self.win_dir.mkdir()
        monkeypatch.setattr("aray.compiler.BUILD_DIR", self.linux_dir)
        monkeypatch.setattr("aray.compiler.BUILD_DIR_WIN", self.win_dir)

    def test_linux_scan_only_creates_artifact(self):
        strings = [YaraStringEntry(value="dummy1")]
        state = _make_state(str(RULES_DIR / "rule0.yar"), strings)
        compile_binary(state, scan_only=True)
        assert (self.linux_dir / "app").exists()

    def test_linux_scan_only_no_compiler_invoked(self):
        strings = [YaraStringEntry(value="dummy1")]
        state = _make_state(str(RULES_DIR / "rule0.yar"), strings)
        with patch("aray.compiler.subprocess.run") as mock_run:
            compile_binary(state, scan_only=True)
        mock_run.assert_not_called()

    def test_linux_scan_only_writes_asm_source(self):
        strings = [YaraStringEntry(value="dummy1", offset=0x600)]
        state = _make_state(str(RULES_DIR / "rule0.yar"), strings)
        compile_binary(state, scan_only=True)
        asm = (self.linux_dir / "main.S").read_text()
        assert ".section .sec_0x600" in asm
        assert "_start" in asm

    def test_linux_scan_only_writes_linker_script(self):
        strings = [YaraStringEntry(value="dummy1", offset=0x600)]
        state = _make_state(str(RULES_DIR / "rule0.yar"), strings)
        compile_binary(state, scan_only=True)
        ld = (self.linux_dir / "linker.ld").read_text()
        assert "PHDRS" in ld
        assert ".sec_0x600" in ld

    def test_linux_scan_only_bytes_at_correct_offset(self):
        strings = [YaraStringEntry(value="dummy1", offset=0x600)]
        state = _make_state(str(RULES_DIR / "rule0.yar"), strings)
        compile_binary(state, scan_only=True)
        data = (self.linux_dir / "app").read_bytes()
        assert data[0x600:0x606] == b"dummy1"

    def test_linux_scan_only_constants_patched(self):
        constants = [{"value": "0x1234", "offset": 0x100, "size": 2, "is_nested": False}]
        state = _make_state(str(RULES_DIR / "rule0.yar"), [], rule_constants=constants)
        compile_binary(state, scan_only=True)
        data = (self.linux_dir / "app").read_bytes()
        assert data[0x100:0x102] == b"\x34\x12"

    def test_pe_scan_only_creates_artifact(self):
        strings = [YaraStringEntry(value="test")]
        state = _make_state(str(RULES_DIR / "rule6.yar"), strings, rule_constants=_MZ_CONST)
        compile_binary(state, scan_only=True)
        assert (self.win_dir / "app.exe").exists()

    def test_pe_scan_only_no_compiler_invoked(self):
        strings = [YaraStringEntry(value="test")]
        state = _make_state(str(RULES_DIR / "rule6.yar"), strings, rule_constants=_MZ_CONST)
        with patch("aray.compiler.subprocess.run") as mock_run:
            compile_binary(state, scan_only=True)
        mock_run.assert_not_called()

    def test_pe_scan_only_has_mz_header(self):
        strings = [YaraStringEntry(value="test")]
        state = _make_state(str(RULES_DIR / "rule6.yar"), strings, rule_constants=_MZ_CONST)
        compile_binary(state, scan_only=True)
        data = (self.win_dir / "app.exe").read_bytes()
        assert data[0:2] == b"MZ"

    def test_pe_scan_only_has_pe_signature(self):
        strings = [YaraStringEntry(value="test")]
        state = _make_state(str(RULES_DIR / "rule6.yar"), strings, rule_constants=_MZ_CONST)
        compile_binary(state, scan_only=True)
        data = (self.win_dir / "app.exe").read_bytes()
        e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
        assert data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"

    def test_pe_scan_only_writes_asm_source(self):
        strings = [YaraStringEntry(value="h31415927tttt")]
        state = _make_state(str(RULES_DIR / "rule6.yar"), strings, rule_constants=_MZ_CONST)
        compile_binary(state, scan_only=True)
        asm = (self.win_dir / "main.S").read_text()
        assert ".section .sec_" in asm
        assert "_start" in asm

    def test_pe_scan_only_no_main_c(self):
        strings = [YaraStringEntry(value="h31415927tttt")]
        state = _make_state(str(RULES_DIR / "rule6.yar"), strings, rule_constants=_MZ_CONST)
        compile_binary(state, scan_only=True)
        assert not (self.win_dir / "main.c").exists()

    def test_pe_scan_only_bytes_at_correct_offset(self):
        strings = [YaraStringEntry(value="payload", offset=0x600)]
        state = _make_state(str(RULES_DIR / "rule6.yar"), strings, rule_constants=_MZ_CONST)
        compile_binary(state, scan_only=True)
        data = (self.win_dir / "app.exe").read_bytes()
        assert data[0x600:0x607] == b"payload"


# ---------------------------------------------------------------------------
# build_graph
# ---------------------------------------------------------------------------
class TestBuildGraph:
    def test_graph_has_expected_nodes(self):
        from aray.graph import build_graph

        with patch("aray.graph.ChatOpenAI", return_value=MagicMock()):
            graph = build_graph()
        node_names = set(graph.get_graph().nodes)
        assert "read_yara" in node_names
        assert "check_normalization_needed" in node_names
        assert "normalize_rule" in node_names
        assert "fail_normalization" in node_names
        assert "extract_strings" in node_names
        assert "compile" in node_names
        assert "route_file_type" in node_names
        assert "write_generic" in node_names


# ---------------------------------------------------------------------------
# fail_normalization node
# ---------------------------------------------------------------------------
class TestFailNormalizationNode:
    def test_sets_normalization_error(self):
        state = {
            "judge_reason": "bad rule",
            "normalize_attempts": 3,
        }
        result = fail_normalization(state)
        assert result == {"normalization_error": "bad rule"}

    def test_fallback_reason_when_no_judge_reason(self):
        state = {"normalize_attempts": 3}
        result = fail_normalization(state)
        assert "normalization_error" in result
        assert result["normalization_error"]  # non-empty string


# ---------------------------------------------------------------------------
# _judge_router
# ---------------------------------------------------------------------------
class TestJudgeRouter:
    def _router(self, verdict: str, attempts: int) -> str:
        from aray.graph import _judge_router
        state = {"judge_verdict": verdict, "normalize_attempts": attempts}
        return _judge_router(state)

    def test_routes_to_normalize_on_failed_attempts_below_max(self):
        assert self._router("failed", 1) == "normalize_rule"

    def test_routes_to_fail_normalization_when_exhausted(self):
        assert self._router("failed", 3) == "fail_normalization"

    def test_routes_to_extract_on_passed(self):
        assert self._router("passed", 1) == "extract_strings"

    def test_routes_to_extract_on_uncertain(self):
        assert self._router("uncertain", 1) == "extract_strings"


# ---------------------------------------------------------------------------
# _requires_normalization
# ---------------------------------------------------------------------------
class TestRequiresNormalization:
    def test_simple_ascii_rule_false(self):
        rule = 'rule r { strings: $a = "hello" condition: $a }'
        assert _requires_normalization(rule) is False

    def test_clean_hex_rule_false(self):
        rule = 'rule r { strings: $a = { DE AD BE EF } condition: $a }'
        assert _requires_normalization(rule) is False

    def test_any_of_them_false(self):
        rule = 'rule r { strings: $a = "x" $b = "y" condition: any of them }'
        assert _requires_normalization(rule) is False

    def test_all_of_them_false(self):
        rule = 'rule r { strings: $a = "x" condition: all of them }'
        assert _requires_normalization(rule) is False

    def test_uint_condition_only_false(self):
        rule = 'rule r { strings: $a = "x" condition: uint16(0) == 0x5A4D and $a }'
        assert _requires_normalization(rule) is False

    def test_regex_string_true(self):
        rule = 'rule r { strings: $a = /pattern/ condition: $a }'
        assert _requires_normalization(rule) is True

    def test_anonymous_regex_string_true(self):
        rule = 'rule r { strings: $ = /pattern/ condition: any of them }'
        assert _requires_normalization(rule) is True

    def test_hex_wildcard_true(self):
        rule = 'rule r { strings: $a = { AB ?? CD } condition: $a }'
        assert _requires_normalization(rule) is True

    @pytest.mark.parametrize("wildcard", ["3?", "?A"])
    def test_hex_partial_nibble_wildcard_true(self, wildcard):
        rule = f'rule r {{ strings: $a = {{ AB {wildcard} CD }} condition: $a }}'
        assert _requires_normalization(rule) is True

    def test_hex_jump_fixed_true(self):
        rule = 'rule r { strings: $a = { F4 [3] 62 } condition: $a }'
        assert _requires_normalization(rule) is True

    def test_hex_jump_range_true(self):
        rule = 'rule r { strings: $a = { F4 [4-6] 62 } condition: $a }'
        assert _requires_normalization(rule) is True

    def test_hex_syntax_inside_literal_or_comment_does_not_trigger(self):
        rule = (
            'rule r { strings: $a = "?? [3]" // { ?? [4-6] }\n'
            'condition: $a }'
        )
        assert _requires_normalization(rule) is False

    def test_or_condition_true(self):
        rule = 'rule r { strings: $a = "x" $b = "y" condition: $a or $b }'
        assert _requires_normalization(rule) is True

    def test_numeric_count_them_true(self):
        rule = 'rule r { strings: $a = "x" $b = "y" condition: 2 of them }'
        assert _requires_normalization(rule) is True

    def test_numeric_count_glob_true(self):
        rule = 'rule r { strings: $s1 = "x" $s2 = "y" condition: 1 of ($s*) }'
        assert _requires_normalization(rule) is True

    def test_condition_keywords_inside_literals_do_not_trigger_normalization(self):
        rule = (
            'rule r { strings: $a = "or 1 of them" '
            'condition: $a and "or 1 of them" == "or 1 of them" }'
        )
        assert _requires_normalization(rule) is False

    def test_rule0_file_false(self):
        rule_text = (RULES_DIR / "rule0.yar").read_text()
        assert _requires_normalization(rule_text) is False

    def test_rule8_file_true(self):
        rule_text = (RULES_DIR / "rule8.yar").read_text()
        assert _requires_normalization(rule_text) is True

    @pytest.mark.parametrize(
        "rule_path",
        [
            "evaluation/yara-repos/rules/malware/MALW_Regsubdat.yar",
            "evaluation/yara-repos/rules/malware/TOOLKIT_Wineggdrop.yar",
        ],
    )
    def test_second_glm_round_partial_nibble_rules_require_normalization(
        self, rule_path
    ):
        from aray.yara_source import select_yara_file

        assert _requires_normalization(select_yara_file(Path(rule_path)).text) is True


# ---------------------------------------------------------------------------
# check_normalization_needed node
# ---------------------------------------------------------------------------
class TestCheckNormalizationNeededNode:
    def _make_simple_state(self, rule_text: str) -> dict:
        return {
            "name": "test",
            "rule_path": "",
            "yara_rule": rule_text,
            "normalized_rule": "",
            "rule_strings": [],
            "rule_constants": [],
            "has_condition": False,
        }

    def test_simple_rule_fast_path(self):
        rule = 'rule r { strings: $a = "hello" condition: $a }'
        state = self._make_simple_state(rule)
        result = check_normalization_needed(state)
        assert result["needs_normalization"] is False
        assert result["normalized_rule"] == rule

    def test_complex_rule_needs_normalization(self):
        rule = 'rule r { strings: $a = /pattern/ condition: $a }'
        state = self._make_simple_state(rule)
        result = check_normalization_needed(state)
        assert result["needs_normalization"] is True
        assert "normalized_rule" not in result

    def test_or_condition_needs_normalization(self):
        rule = 'rule r { strings: $a = "x" $b = "y" condition: $a or $b }'
        state = self._make_simple_state(rule)
        result = check_normalization_needed(state)
        assert result["needs_normalization"] is True
        assert "normalized_rule" not in result

    def test_rule0_fast_path(self):
        rule_text = (RULES_DIR / "rule0.yar").read_text()
        state = self._make_simple_state(rule_text)
        result = check_normalization_needed(state)
        assert result["needs_normalization"] is False
        assert result["normalized_rule"] == rule_text


# ---------------------------------------------------------------------------
# Integration tests — compile real binaries and scan with `yara` CLI
# ---------------------------------------------------------------------------
def _yara_available() -> bool:
    return shutil.which("yara") is not None


def _gcc_available() -> bool:
    return shutil.which("gcc") is not None


requires_yara_and_gcc = pytest.mark.skipif(
    not (_yara_available() and _gcc_available()),
    reason="requires yara and gcc on PATH",
)


def _mingw_available() -> bool:
    return shutil.which("x86_64-w64-mingw32-gcc") is not None


def _wine_available() -> bool:
    return shutil.which("wine") is not None or shutil.which("wine64") is not None


requires_mingw_and_yara = pytest.mark.skipif(
    not (_mingw_available() and _yara_available()),
    reason="requires x86_64-w64-mingw32-gcc and yara on PATH",
)


def _compile_elf(
    tmp_path: Path,
    rule_path: Path,
    rule_strings: list[YaraStringEntry],
) -> Path:
    """Compile an ELF binary and return its path."""
    build_dir = tmp_path / "build"
    build_dir.mkdir(exist_ok=True)
    state = _make_state(str(rule_path), rule_strings)
    with patch("aray.compiler.BUILD_DIR", build_dir):
        compile_binary(state)
    binary = build_dir / "app"
    assert binary.exists(), f"Binary was not created at {binary}"
    return binary


def _compile_and_scan(
    tmp_path: Path,
    rule_path: Path,
    rule_strings: list[YaraStringEntry],
) -> subprocess.CompletedProcess:
    """Compile an ELF binary from the given strings and scan it with yara."""
    binary = _compile_elf(tmp_path, rule_path, rule_strings)
    return subprocess.run(
        ["yara", str(rule_path), str(binary)],
        capture_output=True,
        text=True,
    )


@requires_yara_and_gcc
class TestYaraScan:
    """End-to-end: compile binary then verify `yara` matches the rule."""

    def test_rule0_matches(self, tmp_path):
        """rule0: single ASCII string 'dummy1'."""
        strings = [YaraStringEntry(value="dummy1")]
        result = _compile_and_scan(tmp_path, RULES_DIR / "rule0.yar", strings)
        assert result.returncode == 0
        assert "rule0" in result.stdout

    def test_rule1_matches(self, tmp_path):
        """rule1: both ASCII strings now get embedded (one section each)."""
        strings = [
            YaraStringEntry(value="skype.dat"),
            YaraStringEntry(value="emanuel"),
        ]
        result = _compile_and_scan(tmp_path, RULES_DIR / "rule1.yar", strings)
        assert result.returncode == 0
        assert "rule1" in result.stdout

    def test_rule2_matches(self, tmp_path):
        """rule2: 'dummy1' at offset 0x600 and 'dummy2' without offset."""
        strings = [
            YaraStringEntry(value="dummy1", offset=0x600),
            YaraStringEntry(value="dummy2"),
        ]
        result = _compile_and_scan(tmp_path, RULES_DIR / "rule2.yar", strings)
        assert result.returncode == 0
        assert "rule2" in result.stdout

    def test_rule3_matches(self, tmp_path):
        """rule3: hex string { E2 34 C8 FB } without offset."""
        strings = [YaraStringEntry(value="E2 34 C8 FB", format="hex")]
        result = _compile_and_scan(tmp_path, RULES_DIR / "rule3.yar", strings)
        assert result.returncode == 0
        assert "WildcardExample" in result.stdout

    def test_rule4_matches(self, tmp_path):
        """rule4: hex { E2 34 C8 FB } at 0x600 and ASCII 'dummy2'."""
        strings = [
            YaraStringEntry(value="E2 34 C8 FB", offset=0x600, format="hex"),
            YaraStringEntry(value="dummy2"),
        ]
        result = _compile_and_scan(tmp_path, RULES_DIR / "rule4.yar", strings)
        assert result.returncode == 0
        assert "rule2" in result.stdout

    def test_rule5_multi_offset_matches(self, tmp_path):
        """rule5: 'alpha' at 0x600 and 'beta' at 0x800."""
        strings = [
            YaraStringEntry(value="alpha", offset=0x600),
            YaraStringEntry(value="beta", offset=0x800),
        ]
        result = _compile_and_scan(tmp_path, RULES_DIR / "rule5.yar", strings)
        assert result.returncode == 0
        assert "multi_offset" in result.stdout

    def test_no_match_on_empty_binary(self, tmp_path):
        """A binary with no real strings should not match rule1."""
        build_dir = tmp_path / "build"
        build_dir.mkdir()

        state = _make_state(str(RULES_DIR / "rule1.yar"), [])

        with patch("aray.compiler.BUILD_DIR", build_dir):
            compile_binary(state)

        binary = build_dir / "app"
        result = subprocess.run(
            ["yara", str(RULES_DIR / "rule1.yar"), str(binary)],
            capture_output=True,
            text=True,
        )
        assert "rule1" not in result.stdout

    def test_wrong_offset_no_match(self, tmp_path):
        """Strings placed at wrong offsets should not match a multi-offset rule."""
        strings = [
            YaraStringEntry(value="alpha", offset=0x900),  # rule5 expects 0x600
            YaraStringEntry(value="beta", offset=0xA00),   # rule5 expects 0x800
        ]
        result = _compile_and_scan(tmp_path, RULES_DIR / "rule5.yar", strings)
        assert "multi_offset" not in result.stdout

    def test_rule0_runs(self, tmp_path):
        """rule0: binary executes and prints the banner."""
        binary = _compile_elf(tmp_path, RULES_DIR / "rule0.yar", [YaraStringEntry(value="dummy1")])
        result = subprocess.run([str(binary)], capture_output=True, text=True)
        assert result.returncode == 0
        assert BANNER in result.stdout

    def test_rule1_runs(self, tmp_path):
        """rule1: binary executes and prints the banner."""
        strings = [YaraStringEntry(value="skype.dat"), YaraStringEntry(value="emanuel")]
        binary = _compile_elf(tmp_path, RULES_DIR / "rule1.yar", strings)
        result = subprocess.run([str(binary)], capture_output=True, text=True)
        assert result.returncode == 0
        assert BANNER in result.stdout

    def test_rule2_runs(self, tmp_path):
        """rule2: binary executes and prints the banner."""
        strings = [YaraStringEntry(value="dummy1", offset=0x600), YaraStringEntry(value="dummy2")]
        binary = _compile_elf(tmp_path, RULES_DIR / "rule2.yar", strings)
        result = subprocess.run([str(binary)], capture_output=True, text=True)
        assert result.returncode == 0
        assert BANNER in result.stdout

    def test_rule3_runs(self, tmp_path):
        """rule3: binary executes and prints the banner."""
        strings = [YaraStringEntry(value="E2 34 C8 FB", format="hex")]
        binary = _compile_elf(tmp_path, RULES_DIR / "rule3.yar", strings)
        result = subprocess.run([str(binary)], capture_output=True, text=True)
        assert result.returncode == 0
        assert BANNER in result.stdout

    def test_rule4_runs(self, tmp_path):
        """rule4: binary executes and prints the banner."""
        strings = [
            YaraStringEntry(value="E2 34 C8 FB", offset=0x600, format="hex"),
            YaraStringEntry(value="dummy2"),
        ]
        binary = _compile_elf(tmp_path, RULES_DIR / "rule4.yar", strings)
        result = subprocess.run([str(binary)], capture_output=True, text=True)
        assert result.returncode == 0
        assert BANNER in result.stdout

    def test_rule5_runs(self, tmp_path):
        """rule5: binary executes and prints the banner."""
        strings = [YaraStringEntry(value="alpha", offset=0x600), YaraStringEntry(value="beta", offset=0x800)]
        binary = _compile_elf(tmp_path, RULES_DIR / "rule5.yar", strings)
        result = subprocess.run([str(binary)], capture_output=True, text=True)
        assert result.returncode == 0
        assert BANNER in result.stdout


# ---------------------------------------------------------------------------
# Integration tests — compile Windows PE binaries and scan with `yara` CLI
# ---------------------------------------------------------------------------
def _compile_and_scan_pe(
    rule_path: str,
    rule_strings: list[YaraStringEntry],
    rule_constants: list[dict],
    tmp_path: Path,
) -> subprocess.CompletedProcess:
    """Compile a Windows PE binary from the given strings/constants and scan with yara."""
    build_dir = tmp_path / "build"
    build_dir.mkdir()
    state = _make_state(rule_path, rule_strings, rule_constants=rule_constants)
    with patch("aray.compiler.BUILD_DIR_WIN", build_dir):
        compile_binary(state)
    binary = build_dir / "app.exe"
    assert binary.exists(), f"PE binary was not created at {binary}"
    return subprocess.run(
        ["yara", rule_path, str(binary)],
        capture_output=True,
        text=True,
    )


@requires_mingw_and_yara
class TestYaraScanPE:
    """Integration tests: compile Windows PE binaries and verify YARA rule matches."""

    _MUTEX_STR = [YaraStringEntry(value="h31415927tttt")]
    _PE_SIG_CONST = [{"value": "0x00004550", "offset": 0x3C, "size": 4, "is_nested": True}]

    def test_rule6_matches(self, tmp_path):
        """rule6.yar: MZ + PE sig + string — MinGW PE satisfies all three."""
        result = _compile_and_scan_pe(
            str(RULES_DIR / "rule6.yar"), self._MUTEX_STR, self._PE_SIG_CONST, tmp_path
        )
        assert result.returncode == 0
        assert "maindll_mutex" in result.stdout

    def test_rule7_matches(self, tmp_path):
        """rule7.yar: PE sig + string (no explicit MZ check)."""
        result = _compile_and_scan_pe(
            str(RULES_DIR / "rule7.yar"), self._MUTEX_STR, self._PE_SIG_CONST, tmp_path
        )
        assert result.returncode == 0
        assert "maindll_mutex" in result.stdout

    def test_rule8_matches(self, tmp_path):
        """rule8.yar: APT15 tool — MZ header + 15 of 24 strings."""
        strings = [
            YaraStringEntry(value="/de"),
            YaraStringEntry(value="/sn"),
            YaraStringEntry(value="/sbn"),
            YaraStringEntry(value="/list"),
            YaraStringEntry(value="/enum"),
            YaraStringEntry(value="/save"),
            YaraStringEntry(value="/ao"),
            YaraStringEntry(value="/sl"),
            YaraStringEntry(value="/v or /t is null"),
            YaraStringEntry(value="2007"),
            YaraStringEntry(value="2010"),
            YaraStringEntry(value="2010sp1"),
            YaraStringEntry(value="2010sp2"),
            YaraStringEntry(value="2013"),
            YaraStringEntry(value="2013sp1"),
        ]
        mz_const = [{"value": "0x5A4D", "offset": 0, "size": 2, "is_nested": False}]
        result = _compile_and_scan_pe(
            str(RULES_DIR / "rule8.yar"), strings, mz_const, tmp_path
        )
        assert result.returncode == 0
        assert "malware_apt15_exchange_tool" in result.stdout

    def test_rule9_matches(self, tmp_path):
        """rule9.yar: APT15 with wide strings — mixed ASCII + widechar strings."""
        strings = [
            YaraStringEntry(value="subjectname"),
            YaraStringEntry(value="sendername"),
            YaraStringEntry(value="WebCredentials"),
            YaraStringEntry(value="ExchangeVersion"),
            YaraStringEntry(value="ExchangeCredentials"),
            YaraStringEntry(value="slfilename"),
            YaraStringEntry(value="EnumMail"),
            YaraStringEntry(value="EnumFolder"),
            YaraStringEntry(value="set_Credentials"),
            YaraStringEntry(value="/de", format="widechar"),
            YaraStringEntry(value="/sn", format="widechar"),
            YaraStringEntry(value="/sbn", format="widechar"),
            YaraStringEntry(value="/list", format="widechar"),
            YaraStringEntry(value="/enum", format="widechar"),
            YaraStringEntry(value="/save", format="widechar"),
        ]
        mz_const = [{"value": "0x5A4D", "offset": 0, "size": 2, "is_nested": False}]
        result = _compile_and_scan_pe(
            str(RULES_DIR / "rule9.yar"), strings, mz_const, tmp_path
        )
        assert result.returncode == 0
        assert "malware_apt15_exchange_tool" in result.stdout

    def test_pe_binary_is_pe_format(self, tmp_path):
        """Generated binary must be a Windows PE (MZ magic at offset 0, PE sig at e_lfanew)."""
        build_dir = tmp_path / "build"
        build_dir.mkdir()
        state = _make_state(
            str(RULES_DIR / "rule6.yar"), self._MUTEX_STR, rule_constants=self._PE_SIG_CONST
        )
        with patch("aray.compiler.BUILD_DIR_WIN", build_dir):
            compile_binary(state)
        binary = (build_dir / "app.exe").read_bytes()
        assert binary[0:2] == b"MZ"
        pe_off = int.from_bytes(binary[0x3C:0x40], "little")
        assert binary[pe_off : pe_off + 4] == b"PE\x00\x00"

    @pytest.mark.skipif(not _wine_available(), reason="requires wine or wine64 on PATH")
    def test_rule6_runs_with_wine(self, tmp_path):
        """rule6.yar PE executes under Wine and prints the banner."""
        build_dir = tmp_path / "build"
        build_dir.mkdir()
        state = _make_state(
            str(RULES_DIR / "rule6.yar"), self._MUTEX_STR, rule_constants=self._PE_SIG_CONST
        )
        with patch("aray.compiler.BUILD_DIR_WIN", build_dir):
            compile_binary(state)
        wine = shutil.which("wine64") or shutil.which("wine")
        result = subprocess.run(
            [wine, str(build_dir / "app.exe")],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert BANNER in result.stdout

    @pytest.mark.skipif(not _wine_available(), reason="requires wine or wine64 on PATH")
    def test_rule7_runs_with_wine(self, tmp_path):
        """rule7.yar PE executes under Wine and prints the banner."""
        build_dir = tmp_path / "build"
        build_dir.mkdir()
        state = _make_state(
            str(RULES_DIR / "rule7.yar"), self._MUTEX_STR, rule_constants=self._PE_SIG_CONST
        )
        with patch("aray.compiler.BUILD_DIR_WIN", build_dir):
            compile_binary(state)
        wine = shutil.which("wine64") or shutil.which("wine")
        result = subprocess.run(
            [wine, str(build_dir / "app.exe")],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert BANNER in result.stdout


# ---------------------------------------------------------------------------
# _invoke_llm / prompt-based JSON fallback
# ---------------------------------------------------------------------------
def _mock_llm_unstructured(json_content: str):
    """Build a mock LLM whose .invoke() returns a message with json_content."""
    mock_response = MagicMock()
    mock_response.content = json_content
    mock_llm = MagicMock()
    mock_llm.invoke.return_value = mock_response
    return mock_llm


class TestNoStructuredOutput:
    """Verify the prompt-based JSON fallback path (use_structured=False)."""

    def _rule0_state(self) -> ArayGraphState:
        rule_text = (RULES_DIR / "rule0.yar").read_text()
        return {
            "name": "test",
            "rule_path": str(RULES_DIR / "rule0.yar"),
            "yara_rule": rule_text,
            "normalized_rule": rule_text,
            "rule_strings": [],
            "rule_constants": [],
            "has_condition": False,
        }

    def test_extract_strings_unstructured(self):
        """Plain JSON response is parsed into YaraStringEntry objects."""
        json_resp = '{"strings": [{"value": "hello", "offset": null, "format": "ascii"}]}'
        mock_llm = _mock_llm_unstructured(json_resp)
        result = extract_strings(self._rule0_state(), llm=mock_llm, use_structured=False)
        assert len(result["rule_strings"]) == 1
        assert result["rule_strings"][0].value == "hello"
        assert result["has_condition"] is False

    def test_extract_strings_strips_markdown_fence(self):
        """Markdown code fences around JSON are stripped before parsing."""
        json_resp = '```json\n{"strings": [{"value": "world", "offset": null, "format": "ascii"}]}\n```'
        mock_llm = _mock_llm_unstructured(json_resp)
        result = extract_strings(self._rule0_state(), llm=mock_llm, use_structured=False)
        assert result["rule_strings"][0].value == "world"

    def test_normalize_rule_unstructured(self):
        """normalized_rule key is populated from a plain JSON response."""
        json_resp = '{"rule": "rule test { condition: true }"}'
        mock_llm = _mock_llm_unstructured(json_resp)
        result = normalize_rule(self._rule0_state(), llm=mock_llm, use_structured=False)
        assert result["normalized_rule"] == "rule test { condition: true }"

    def test_extract_constants_unstructured(self):
        """Constants are parsed from a plain JSON response."""
        json_resp = (
            '{"constants": [{"value": "0x5A4D", "offset": 0, "size": 2, "is_nested": false}]}'
        )
        mock_llm = _mock_llm_unstructured(json_resp)
        result = extract_constants(self._rule0_state(), llm=mock_llm, use_structured=False)
        assert len(result["rule_constants"]) == 1
        assert result["rule_constants"][0].value == "0x5A4D"

    def test_unstructured_calls_invoke_not_with_structured_output(self):
        """use_structured=False must call llm.invoke(), never llm.with_structured_output()."""
        json_resp = '{"strings": []}'
        mock_llm = _mock_llm_unstructured(json_resp)
        extract_strings(self._rule0_state(), llm=mock_llm, use_structured=False)
        mock_llm.invoke.assert_called_once()
        mock_llm.with_structured_output.assert_not_called()


class TestInvokeLlmAutoFallback:
    """Verify structured output auto-falls back to prompt-based JSON.

    The fallback activates automatically when the model/gateway does not
    support tool calls (or the structured response cannot be parsed) — no
    manual --no-structured-output flag is needed.
    """

    def _mock_llm(self, json_content: str, structured_exc: BaseException | None = None):
        mock_response = MagicMock()
        mock_response.content = json_content
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = mock_response
        structured_chain = MagicMock()
        if structured_exc is not None:
            structured_chain.invoke.side_effect = structured_exc
        mock_llm.with_structured_output.return_value = structured_chain
        return mock_llm

    def _messages(self) -> list:
        return [SystemMessage(content="sys"), HumanMessage(content="rule")]

    def test_structured_uses_function_calling_method(self):
        """Structured output must use the tool-calling API with tool_choice='auto'."""
        structured_chain = MagicMock()
        structured_chain.invoke.return_value = YaraStrings(
            strings=[YaraStringEntry(value="hi")]
        )
        mock_llm = MagicMock()
        mock_llm.with_structured_output.return_value = structured_chain
        result = _invoke_llm(mock_llm, YaraStrings, self._messages())
        assert result.strings[0].value == "hi"
        mock_llm.with_structured_output.assert_called_once_with(
            YaraStrings, method="function_calling", tool_choice="auto"
        )

    def test_falls_back_on_output_parser_exception(self):
        """Tool-call parse failure retries via the prompt-based JSON path."""
        json_resp = '{"strings": [{"value": "hello", "offset": null, "format": "ascii"}]}'
        mock_llm = self._mock_llm(json_resp, OutputParserException("no tool call emitted"))
        result = _invoke_llm(mock_llm, YaraStrings, self._messages())
        assert result.strings[0].value == "hello"
        mock_llm.with_structured_output.assert_called_once()
        mock_llm.invoke.assert_called_once()

    def test_falls_back_on_value_error(self):
        """A ValueError from the structured path also triggers the fallback."""
        json_resp = '{"strings": [{"value": "world", "offset": null, "format": "ascii"}]}'
        mock_llm = self._mock_llm(json_resp, ValueError("provider rejects tools"))
        result = _invoke_llm(mock_llm, YaraStrings, self._messages())
        assert result.strings[0].value == "world"
        mock_llm.invoke.assert_called_once()

    def test_falls_back_on_openai_bad_request(self):
        """An HTTP 400 rejecting the tool-call request falls back to JSON."""
        try:
            import openai
        except ImportError:
            pytest.skip("openai not installed")
        exc = openai.BadRequestError.__new__(openai.BadRequestError)
        json_resp = '{"strings": [{"value": "x", "offset": null, "format": "ascii"}]}'
        mock_llm = self._mock_llm(json_resp, exc)
        result = _invoke_llm(mock_llm, YaraStrings, self._messages())
        assert result.strings[0].value == "x"
        mock_llm.invoke.assert_called_once()

    def test_falls_back_when_structured_returns_none(self):
        """A structured call that returns None (model emitted no tool call) falls back."""
        json_resp = '{"strings": [{"value": "hello", "offset": null, "format": "ascii"}]}'
        mock_response = MagicMock()
        mock_response.content = json_resp
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = mock_response
        structured_chain = MagicMock()
        structured_chain.invoke.return_value = None
        mock_llm.with_structured_output.return_value = structured_chain
        result = _invoke_llm(mock_llm, YaraStrings, self._messages())
        assert result.strings[0].value == "hello"
        mock_llm.with_structured_output.assert_called_once_with(
            YaraStrings, method="function_calling", tool_choice="auto"
        )
        mock_llm.invoke.assert_called_once()

    def test_no_fallback_when_structured_succeeds(self):
        """A successful structured call never hits the JSON path."""
        mock_llm = MagicMock()
        structured_chain = MagicMock()
        structured_chain.invoke.return_value = YaraStrings(
            strings=[YaraStringEntry(value="hi")]
        )
        mock_llm.with_structured_output.return_value = structured_chain
        result = _invoke_llm(mock_llm, YaraStrings, self._messages())
        assert result.strings[0].value == "hi"
        mock_llm.invoke.assert_not_called()

    def test_no_fallback_on_unrelated_error(self):
        """Auth/network/programming errors propagate — JSON would not help."""
        mock_llm = self._mock_llm("{}", RuntimeError("boom"))
        with pytest.raises(RuntimeError):
            _invoke_llm(mock_llm, YaraStrings, self._messages())
        mock_llm.invoke.assert_not_called()


class TestInvokeLlmJsonHardening:
    """The prompt-based JSON fallback raises clear errors on unusable content."""

    def _messages(self) -> list:
        return [SystemMessage(content="sys"), HumanMessage(content="rule")]

    def _mock_llm(self, content):
        mock_response = MagicMock()
        mock_response.content = content
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = mock_response
        return mock_llm

    def test_none_content_raises_clear_error(self):
        """content=None must raise a clear ValueError, not an AttributeError."""
        with pytest.raises(ValueError, match="empty response"):
            _invoke_llm(self._mock_llm(None), YaraStrings, self._messages(), use_structured=False)

    def test_empty_content_raises_clear_error(self):
        """Blank content raises a clear ValueError."""
        with pytest.raises(ValueError, match="empty response"):
            _invoke_llm(self._mock_llm("   "), YaraStrings, self._messages(), use_structured=False)

    def test_non_json_content_raises_clear_error(self):
        """Non-JSON text raises a ValueError naming the schema, not a raw JSONDecodeError."""
        with pytest.raises(ValueError, match="non-JSON response"):
            _invoke_llm(self._mock_llm("sure, here it is"), YaraStrings, self._messages(), use_structured=False)


# ---------------------------------------------------------------------------
# _parse_filesize_constraint
# ---------------------------------------------------------------------------
class TestParseFilesizeConstraint:
    def test_greater_than_kb(self):
        assert _parse_filesize_constraint("filesize > 70KB") == (71681, None)

    def test_less_than_kb(self):
        assert _parse_filesize_constraint("filesize < 2KB") == (None, 2048)

    def test_both_bounds(self):
        assert _parse_filesize_constraint("filesize > 70KB and filesize < 110KB") == (71681, 112640)

    def test_greater_equal_kb(self):
        assert _parse_filesize_constraint("filesize >= 1KB") == (1024, None)

    def test_equal_bare(self):
        assert _parse_filesize_constraint("filesize == 1024") == (1024, 1025)

    def test_no_filesize(self):
        rule = "rule x { strings: $a = \"hello\" condition: $a }"
        assert _parse_filesize_constraint(rule) == (None, None)

    def test_megabyte_unit(self):
        assert _parse_filesize_constraint("filesize > 1MB") == (1048577, None)

    def test_bare_bytes(self):
        assert _parse_filesize_constraint("filesize > 1024") == (1025, None)


# ---------------------------------------------------------------------------
# _compute_padding
# ---------------------------------------------------------------------------
class TestComputePadding:
    def test_min_only_below_min(self):
        # current < min → pads to 1 KB above min
        n = _compute_padding(100, 5000, None)
        assert n > 0
        assert 100 + n >= 5000

    def test_max_only_below_max(self):
        # Only a max constraint, current already satisfies it → 0
        assert _compute_padding(100, None, 10000) == 0

    def test_both_below_min(self):
        # current < min < max → targets midpoint
        n = _compute_padding(100, 5000, 10000)
        result = 100 + n
        assert result >= 5000
        assert result < 10000

    def test_already_in_range(self):
        # min <= current < max → no padding
        assert _compute_padding(500, 100, 10000) == 0

    def test_current_at_min(self):
        # current == min → already satisfies, no padding
        assert _compute_padding(5000, 5000, 10000) == 0

    def test_current_exceeds_max(self):
        # current >= max → 0 (can't shrink)
        assert _compute_padding(10000, None, 10000) == 0

    def test_current_far_exceeds_max(self):
        assert _compute_padding(50000, 1000, 10000) == 0


# ---------------------------------------------------------------------------
# artifact_writer with filesize_constraint
# ---------------------------------------------------------------------------
class TestArtifactWriterFilesize:
    def test_linux_min_only_satisfied(self):
        sections = [(0x600, b"hello")]
        data = write_linux_artifact(sections, [], filesize_constraint=(5000, None))
        assert len(data) >= 5000

    def test_linux_max_only_no_padding(self):
        # Already below max — no padding expected
        sections = [(0x600, b"hello")]
        data = write_linux_artifact(sections, [], filesize_constraint=(None, 100000))
        assert len(data) < 100000

    def test_linux_both_bounds_in_range(self):
        sections = [(0x600, b"hello")]
        data = write_linux_artifact(sections, [], filesize_constraint=(5000, 20000))
        assert 5000 <= len(data) < 20000

    def test_linux_no_constraint_unchanged(self):
        sections = [(0x600, b"hello")]
        data_no = write_linux_artifact(sections, [])
        data_nc = write_linux_artifact(sections, [], filesize_constraint=None)
        assert data_no == data_nc

    def test_pe_min_only_satisfied(self):
        sections = [(0x3000, b"payload")]
        data = write_pe_artifact(sections, [], filesize_constraint=(5000, None))
        assert len(data) >= 5000

    def test_pe_max_only_no_padding(self):
        sections = [(0x3000, b"payload")]
        data = write_pe_artifact(sections, [], filesize_constraint=(None, 100000))
        assert len(data) < 100000

    def test_pe_both_bounds_in_range(self):
        sections = [(0x3000, b"payload")]
        data = write_pe_artifact(sections, [], filesize_constraint=(5000, 20000))
        assert 5000 <= len(data) < 20000


# ---------------------------------------------------------------------------
# compile_binary with filesize constraint (subprocess mocked)
# ---------------------------------------------------------------------------
class TestCompileBinaryWithFilesize:
    """Test that compile_binary pads the output binary to meet filesize constraints."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        self.build_dir = tmp_path / "build"
        self.build_dir.mkdir()
        monkeypatch.setattr("aray.compiler.BUILD_DIR", self.build_dir)

        # Simulate gcc producing a small binary (1024 bytes)
        def fake_gcc(cmd, check=False, **kwargs):
            if cmd[0] == "gcc" and "-o" in cmd:
                out = Path(cmd[cmd.index("-o") + 1])
                out.write_bytes(b"\x00" * 1024)

        self._subprocess_patcher = patch("aray.compiler.subprocess.run", side_effect=fake_gcc)
        self._subprocess_patcher.start()

    @pytest.fixture(autouse=True)
    def _teardown(self):
        yield
        self._subprocess_patcher.stop()

    def _make_filesize_state(self, filesize_condition: str) -> ArayGraphState:
        rule_path = str(RULES_DIR / "rule0.yar")
        base_rule = Path(rule_path).read_text()
        rule_with_filesize = base_rule.replace(
            "condition:", f"condition:\n        {filesize_condition} and"
        )
        return {
            "name": "test",
            "rule_path": rule_path,
            "yara_rule": rule_with_filesize,
            "normalized_rule": rule_with_filesize,
            "rule_strings": [],
            "rule_constants": [],
            "has_condition": False,
        }

    def test_filesize_min_constraint_applied(self):
        """Rule with filesize > 10KB; gcc produces 1 KB; final binary should be >= 10241 bytes."""
        state = self._make_filesize_state("filesize > 10KB")
        compile_binary(state)
        size = (self.build_dir / "app").stat().st_size
        assert size >= 10241  # 10*1024 + 1

    def test_no_filesize_no_extra_padding(self):
        """Rule without filesize; gcc produces 1024 bytes; binary stays 1024 bytes."""
        strings = [YaraStringEntry(value="dummy1")]
        state = _make_state(str(RULES_DIR / "rule0.yar"), strings)
        compile_binary(state)
        size = (self.build_dir / "app").stat().st_size
        assert size == 1024


# ---------------------------------------------------------------------------
# route_file_type node
# ---------------------------------------------------------------------------

def _generic_state(constants=None, strings=None, norm_rule="rule t { condition: true }"):
    return {
        "name": "test",
        "rule_path": str(RULES_DIR / "rule0.yar"),
        "yara_rule": norm_rule,
        "normalized_rule": norm_rule,
        "rule_strings": strings or [],
        "rule_constants": constants or [],
        "has_condition": False,
    }


class TestRouteFileType:
    def test_mz_constant_routes_to_pe(self):
        constants = [{"value": "0x5A4D", "offset": 0, "size": 2, "is_nested": False}]
        assert route_file_type(_generic_state(constants=constants)) == {"file_type": "pe"}

    def test_nested_pe_constant_routes_to_pe(self):
        constants = [{"value": "0x00004550", "offset": 0x3C, "size": 4, "is_nested": True}]
        assert route_file_type(_generic_state(constants=constants)) == {"file_type": "pe"}

    def test_offset0_constant_routes_to_generic(self):
        constants = [{"value": "0x253c", "offset": 0, "size": 2, "is_nested": False}]
        norm_rule = 'rule t { strings: $a = "x" condition: uint16(0) == 0x253c and $a }'
        assert route_file_type(_generic_state(constants=constants, norm_rule=norm_rule)) == {"file_type": "generic"}

    def test_offset0_string_routes_to_generic(self):
        strings = [YaraStringEntry(value="\x89PNG", offset=0)]
        norm_rule = 'rule t { strings: $a = "\x89PNG" condition: $a at 0 }'
        assert route_file_type(_generic_state(strings=strings, norm_rule=norm_rule)) == {"file_type": "generic"}

    def test_offset0_constant_no_rule_text_routes_to_elf(self):
        """LLM hallucinated offset=0 but rule text has no uint(0) → fall through to elf."""
        constants = [{"value": "0x253c", "offset": 0, "size": 2, "is_nested": False}]
        assert route_file_type(_generic_state(constants=constants)) == {"file_type": "elf"}

    def test_offset0_string_no_rule_text_routes_to_elf(self):
        """LLM hallucinated offset=0 but rule text has no 'at 0' → fall through to elf."""
        strings = [YaraStringEntry(value="dummy1", offset=0)]
        assert route_file_type(_generic_state(strings=strings)) == {"file_type": "elf"}

    def test_non_zero_offset_string_routes_to_elf(self):
        strings = [YaraStringEntry(value="hello", offset=0x600)]
        assert route_file_type(_generic_state(strings=strings)) == {"file_type": "elf"}

    def test_unconstrained_string_routes_to_elf(self):
        strings = [YaraStringEntry(value="hello")]
        assert route_file_type(_generic_state(strings=strings)) == {"file_type": "elf"}

    def test_empty_state_routes_to_elf(self):
        assert route_file_type(_generic_state()) == {"file_type": "elf"}

    def test_widechar_string_routes_to_pe(self):
        strings = [YaraStringEntry(value="mutex", format="widechar")]
        assert route_file_type(_generic_state(strings=strings)) == {"file_type": "pe"}


# ---------------------------------------------------------------------------
# write_generic_artifact
# ---------------------------------------------------------------------------

class TestWriteGenericArtifact:
    def test_asp_magic_detection(self):
        """Constant 0x253c (ASP <%>) at offset 0 → .asp extension."""
        constants = [{"value": "0x253c", "offset": 0, "size": 2, "is_nested": False}]
        buf, ext = write_generic_artifact([], constants)
        assert ext == ".asp"
        assert buf[0:2] == b"\x3c\x25"   # LE

    def test_png_magic_detection(self):
        sections = [(0, b"\x89PNG")]
        buf, ext = write_generic_artifact(sections, [])
        assert ext == ".png"

    def test_zip_magic_detection(self):
        sections = [(0, b"PK\x03\x04")]
        buf, ext = write_generic_artifact(sections, [])
        assert ext == ".zip"

    def test_gif_magic_detection(self):
        sections = [(0, b"GIF87a")]
        buf, ext = write_generic_artifact(sections, [])
        assert ext == ".gif"

    def test_jpg_magic_detection(self):
        sections = [(0, b"\xFF\xD8\xFF\xE0")]
        buf, ext = write_generic_artifact(sections, [])
        assert ext == ".jpg"

    def test_no_known_magic_empty_ext(self):
        sections = [(0x10, b"some data")]
        _, ext = write_generic_artifact(sections, [])
        assert ext == ""

    def test_string_placed_at_correct_offset(self):
        sections = [(0x10, b"hello")]
        buf, _ = write_generic_artifact(sections, [])
        assert buf[0x10:0x15] == b"hello"

    def test_constant_patched_at_offset_le(self):
        constants = [{"value": "0x253c", "offset": 0, "size": 2, "is_nested": False}]
        buf, _ = write_generic_artifact([], constants)
        assert buf[0:2] == b"\x3c\x25"

    def test_nested_constant_skipped(self):
        """Nested constants (PE path only) must not be patched into generic artifacts."""
        constants = [{"value": "0x4550", "offset": 0x3C, "size": 4, "is_nested": True}]
        buf, _ = write_generic_artifact([], constants)
        assert buf[0x3C:0x40] == b"\x00\x00\x00\x00"

    def test_min_buffer_size_0x200(self):
        buf, _ = write_generic_artifact([], [])
        assert len(buf) >= 0x200

    def test_filesize_padding_applied(self):
        buf, _ = write_generic_artifact([], [], filesize_constraint=(5000, None))
        assert len(buf) >= 5000

    def test_no_elf_header_at_offset_0(self):
        """Generic artifacts must NOT start with the ELF magic."""
        sections = [(0x10, b"data")]
        buf, _ = write_generic_artifact(sections, [])
        assert buf[0:4] != b"\x7fELF"


# ---------------------------------------------------------------------------
# write_generic node
# ---------------------------------------------------------------------------

class TestWriteGenericNode:
    """Test the write_generic pipeline node writes the artifact to the correct path."""

    def _asp_state(self, norm_rule="rule t { condition: uint16(0) == 0x253c }"):
        return {
            "name": "test",
            "rule_path": str(RULES_DIR / "rule0.yar"),
            "yara_rule": norm_rule,
            "normalized_rule": norm_rule,
            "rule_strings": [YaraStringEntry(value="response.write")],
            "rule_constants": [{"value": "0x253c", "offset": 0, "size": 2, "is_nested": False}],
            "has_condition": False,
        }

    def test_artifact_written_with_correct_extension(self, tmp_path, monkeypatch):
        generic_dir = tmp_path / "generic"
        monkeypatch.setattr("aray.constants.BUILD_DIR_GENERIC", generic_dir)
        write_generic(self._asp_state())
        assert (generic_dir / "output.asp").exists()

    def test_artifact_bytes_at_offset_0_match_magic(self, tmp_path, monkeypatch):
        generic_dir = tmp_path / "generic"
        monkeypatch.setattr("aray.constants.BUILD_DIR_GENERIC", generic_dir)
        write_generic(self._asp_state())
        data = (generic_dir / "output.asp").read_bytes()
        assert data[0:2] == b"\x3c\x25"   # <% in LE

    def test_normalized_rule_written(self, tmp_path, monkeypatch):
        generic_dir = tmp_path / "generic"
        monkeypatch.setattr("aray.constants.BUILD_DIR_GENERIC", generic_dir)
        norm = "rule custom { condition: uint16(0) == 0x253c }"
        state = self._asp_state(norm_rule=norm)
        write_generic(state)
        assert (generic_dir / "normalized_rule.yar").read_text() == norm

    def test_strings_packed_at_small_offset(self, tmp_path, monkeypatch):
        """Unconstrained strings start at 0x10 (not the ELF default 0x3000)."""
        generic_dir = tmp_path / "generic"
        monkeypatch.setattr("aray.constants.BUILD_DIR_GENERIC", generic_dir)
        state = _generic_state(
            strings=[YaraStringEntry(value="hello")],
            norm_rule="rule t { condition: true }",
        )
        write_generic(state)
        artifacts = list(generic_dir.glob("output*"))
        assert artifacts
        data = artifacts[0].read_bytes()
        assert data[0x10:0x15] == b"hello"
        assert len(data) < 0x3000   # well below the ELF default base


# ---------------------------------------------------------------------------
# Evaluator — _run_one YARA CLI argument passing
# ---------------------------------------------------------------------------

class TestEvaluatorRunOne:
    """Verify _run_one routes artifacts correctly and passes exact filenames to YARA."""

    def _write_rule(self, tmp_path: Path, name: str, body: str) -> Path:
        rule = tmp_path / f"{name}.yar"
        rule.write_text(f"rule {name} {{\n{body}\n}}\n")
        return rule

    def _make_fake_invoke(self, filename: str, content: bytes = b"\x00" * 32):
        """Return a pipeline invoke() side-effect writing *filename* to BUILD_DIR_GENERIC."""
        def fake_invoke(state):
            import aray.constants as _c
            _c.BUILD_DIR_GENERIC.mkdir(parents=True, exist_ok=True)
            (_c.BUILD_DIR_GENERIC / "normalized_rule.yar").write_text("rule x { condition: true }")
            (_c.BUILD_DIR_GENERIC / filename).write_bytes(content)
        return fake_invoke

    def test_file_with_only_private_rules_is_skipped(self, tmp_path):
        rule_path = tmp_path / "private.yar"
        rule_path.write_text('private rule Helper { condition: true }')
        mock_graph = MagicMock()

        with patch("aray.evaluator.build_graph", return_value=mock_graph):
            result = _run_one(rule_path, EvalConfig(directories=[]))

        mock_graph.invoke.assert_not_called()
        assert result.status == "skipped"
        assert "no non-private rule" in (result.error or "")

    def test_generic_artifact_filename_passed_to_yara(self, tmp_path):
        """_run_one must pass the exact generated filename as the binary arg to YARA."""
        rule_path = self._write_rule(
            tmp_path, "asp_test",
            '    strings:\n        $s1 = "hello"\n    condition:\n        uint16(0) == 0x253c and $s1'
        )
        eval_cfg = EvalConfig(directories=[])
        yara_calls: list[tuple] = []

        def fake_yara_scan(scan_rule, binary):
            yara_calls.append((scan_rule, binary))
            return (0, f"asp_test {binary}\n", "")

        mock_graph = MagicMock()
        mock_graph.invoke.side_effect = self._make_fake_invoke("output.asp", b"\x3c\x25hello")

        with (
            patch("aray.evaluator.build_graph", return_value=mock_graph),
            patch("aray.evaluator._yara_scan", side_effect=fake_yara_scan),
        ):
            result = _run_one(rule_path, eval_cfg)

        assert result.status == "passed", f"Expected passed, got error: {result.error}"
        assert len(yara_calls) == 1, "YARA must be called exactly once"
        _, binary_arg = yara_calls[0]
        assert binary_arg.name == "output.asp", (
            f"YARA CLI must receive the exact generated filename; got: {binary_arg.name}"
        )

    def test_generic_scans_with_normalized_rule_not_original(self, tmp_path):
        """Generic artifacts must be scanned with normalized_rule.yar (first rule only)."""
        rule_path = self._write_rule(
            tmp_path, "asp_test",
            '    strings:\n        $s1 = "hello"\n    condition:\n        uint16(0) == 0x253c and $s1'
        )
        eval_cfg = EvalConfig(directories=[])
        yara_calls: list[tuple] = []

        def fake_yara_scan(scan_rule, binary):
            yara_calls.append((scan_rule, binary))
            return (0, f"asp_test {binary}\n", "")

        mock_graph = MagicMock()
        mock_graph.invoke.side_effect = self._make_fake_invoke("output.asp", b"\x3c\x25hello")

        with (
            patch("aray.evaluator.build_graph", return_value=mock_graph),
            patch("aray.evaluator._yara_scan", side_effect=fake_yara_scan),
        ):
            _run_one(rule_path, eval_cfg)

        scan_rule_arg, _ = yara_calls[0]
        assert scan_rule_arg.name == "normalized_rule.yar", (
            f"Generic scan must use normalized_rule.yar; got: {scan_rule_arg.name}"
        )

    def test_pe_artifact_scanned_with_normalized_rule(self, tmp_path):
        """PE artifacts must be scanned with the selected normalized rule."""
        rule_path = self._write_rule(
            tmp_path, "pe_test",
            "    condition:\n        uint16(0) == 0x5A4D"
        )
        eval_cfg = EvalConfig(directories=[])
        yara_calls: list[tuple] = []

        def fake_yara_scan(scan_rule, binary):
            yara_calls.append((scan_rule, binary))
            return (0, f"pe_test {binary}\n", "")

        def fake_invoke_pe(state):
            import aray.compiler as _c
            _c.BUILD_DIR_WIN.mkdir(parents=True, exist_ok=True)
            (_c.BUILD_DIR_WIN / "app.exe").write_bytes(b"MZ" + b"\x00" * 62)
            (_c.BUILD_DIR_WIN / "normalized_rule.yar").write_text(
                "rule pe_test { condition: true }"
            )

        mock_graph = MagicMock()
        mock_graph.invoke.side_effect = fake_invoke_pe

        with (
            patch("aray.evaluator.build_graph", return_value=mock_graph),
            patch("aray.evaluator._yara_scan", side_effect=fake_yara_scan),
        ):
            result = _run_one(rule_path, eval_cfg)

        assert len(yara_calls) == 1
        scan_rule_arg, binary_arg = yara_calls[0]
        assert scan_rule_arg.name == "normalized_rule.yar"
        assert binary_arg.name == "app.exe"

    def test_no_artifact_produces_failed_result(self, tmp_path):
        """If the pipeline writes no output at all, status must be 'failed'."""
        rule_path = self._write_rule(
            tmp_path, "empty_test",
            "    condition:\n        true"
        )
        eval_cfg = EvalConfig(directories=[])
        mock_graph = MagicMock()
        mock_graph.invoke.return_value = {}   # writes nothing

        with patch("aray.evaluator.build_graph", return_value=mock_graph):
            result = _run_one(rule_path, eval_cfg)

        assert result.status == "failed"
        assert "No binary" in (result.error or "")

    def test_generic_build_dir_is_isolated_per_run(self, tmp_path):
        """Each _run_one call must write the generic artifact into its own tmpdir,
        not into the real build/generic directory."""
        rule_path = self._write_rule(
            tmp_path, "asp_test",
            '    strings:\n        $s1 = "hello"\n    condition:\n        uint16(0) == 0x253c and $s1'
        )
        eval_cfg = EvalConfig(directories=[])
        seen_dirs: list[Path] = []

        def fake_invoke(state):
            import aray.constants as _c
            seen_dirs.append(_c.BUILD_DIR_GENERIC)
            _c.BUILD_DIR_GENERIC.mkdir(parents=True, exist_ok=True)
            (_c.BUILD_DIR_GENERIC / "normalized_rule.yar").write_text("rule x {}")
            (_c.BUILD_DIR_GENERIC / "output.asp").write_bytes(b"\x3c\x25")

        def fake_yara_scan(scan_rule, binary):
            return (0, f"asp_test {binary}\n", "")

        mock_graph = MagicMock()
        mock_graph.invoke.side_effect = fake_invoke

        with (
            patch("aray.evaluator.build_graph", return_value=mock_graph),
            patch("aray.evaluator._yara_scan", side_effect=fake_yara_scan),
        ):
            _run_one(rule_path, eval_cfg)

        assert len(seen_dirs) == 1
        # The patched dir must NOT be the real build/generic
        assert seen_dirs[0] != BUILD_DIR_GENERIC


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
class TestCli:
    def test_clean_build_outputs_removes_all_backend_artifacts(self, tmp_path, monkeypatch):
        build_dirs = [tmp_path / "linux", tmp_path / "windows", tmp_path / "generic"]
        for build_dir in build_dirs:
            build_dir.mkdir()
            (build_dir / "stale-artifact").write_bytes(b"stale")

        monkeypatch.setattr("aray.cli.BUILD_DIR", build_dirs[0])
        monkeypatch.setattr("aray.cli.BUILD_DIR_WIN", build_dirs[1])
        monkeypatch.setattr("aray.cli.BUILD_DIR_GENERIC", build_dirs[2])

        _clean_build_outputs()

        assert all(not build_dir.exists() for build_dir in build_dirs)

    def test_no_rule_path_prints_help_and_exits_zero(self, capsys):
        """Bare invocation shows help and exits 0 instead of an argparse error."""
        with pytest.raises(SystemExit) as excinfo:
            parse_args([])
        assert excinfo.value.code == 0
        out = capsys.readouterr().out
        assert "usage: aray" in out
        assert "rule_path" in out

    def test_no_rule_path_prints_nothing_to_stderr(self, capsys):
        with pytest.raises(SystemExit):
            parse_args([])
        err = capsys.readouterr().err
        assert err == ""

    def test_parse_args_accepts_rule_path(self):
        args = parse_args(["data/rules/rule0.yar"])
        assert args.rule_path == Path("data/rules/rule0.yar")
