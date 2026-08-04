"""Pydantic models for YARA rule extraction."""

from typing import Literal

from pydantic import BaseModel, Field


class JudgeVerdict(BaseModel):
    """LLM-as-judge assessment of a normalized YARA rule."""

    verdict: Literal["passed", "failed", "uncertain"] = Field(
        description="passed = semantically equivalent and valid; failed = wrong or lossy; uncertain = cannot determine."
    )
    reason: str = Field(description="One-sentence explanation of the verdict.")


class NormalizedYaraRule(BaseModel):
    """A normalized YARA rule."""

    rule: str = Field(description="The normalized YARA rule.")


class YaraStringEntry(BaseModel):
    """A string from a YARA rule with optional offset constraint."""

    value: str = Field(description="The string value")
    offset: int | None = Field(
        default=None,
        description="File offset from 'at' condition in the condition section "
        "(e.g. 0x600), or null if no offset constraint",
    )
    format: Literal["ascii", "hex", "widechar"] = Field(default="ascii", description="The format of the string")


class YaraConstantEntry(BaseModel):
    """A constant from a YARA rule."""

    value: str = Field(
        description="The hex string on the RIGHT side of the == operator, with '0x' prefix. "
        "E.g. for 'uint16(0) == 0x5A4D' return '0x5A4D'; "
        "for 'uint32(uint32(0x3C)) == 0x00004550' return '0x00004550'."
    )
    offset: int | None = Field(
        default=None,
        description="The literal integer argument to the innermost uint function. "
        "For 'uint16(0)' or 'uint32(0x3C)' this is 0 or 0x3C respectively. "
        "For 'uint32(uint32(0x3C))' this is 0x3C (the inner offset, NOT the outer). "
        "Null if no offset can be determined.",
    )
    size: Literal[2, 4] = Field(
        description="Byte width of the OUTERMOST uint function: 2 for uint16, 4 for uint32"
    )
    is_nested: bool = Field(
        default=False,
        description="True ONLY when the expression is uint32(uint32(...)) (doubly nested). "
        "False for uint16(X) or uint32(X).",
    )


class YaraStrings(BaseModel):
    """Strings extracted from a YARA rule."""

    strings: list[YaraStringEntry]


class YaraConstants(BaseModel):
    """Constants extracted from a YARA rule."""

    constants: list[YaraConstantEntry]
