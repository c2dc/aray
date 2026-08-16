"""Pydantic models for YARA rule extraction."""

import re
from typing import Literal

from pydantic import BaseModel, Field, model_validator


class JudgeVerdict(BaseModel):
    """LLM-as-judge assessment of a normalized YARA rule."""

    verdict: Literal["passed", "failed", "uncertain"] = Field(
        description=(
            "passed = valid constructible subset of the original; failed = invalid, "
            "not a subset, or needlessly selects a clearly more expensive branch; "
            "uncertain = cannot determine."
        )
    )
    reason: str = Field(description="One-sentence explanation of the verdict.")


class NormalizedYaraRule(BaseModel):
    """A normalized YARA rule."""

    rule: str = Field(
        description=(
            "A minimal constructible YARA subset: every match of this rule must "
            "also match the original, though it may match fewer files."
        )
    )


class YaraStringEntry(BaseModel):
    """A string from a YARA rule with optional offset constraint."""

    identifier: str | None = Field(default=None, description="YARA string identifier")
    value: str = Field(description="The string value")
    offset: int | None = Field(
        default=None,
        description="File offset from 'at' condition in the condition section "
        "(e.g. 0x600), or null if no offset constraint",
    )
    format: Literal["ascii", "hex", "widechar"] = Field(default="ascii", description="The format of the string")
    match_count: int = Field(default=1, ge=1, description="Required witness occurrences")
    ascii: bool = Field(default=True, description="Whether the declaration permits ASCII bytes")
    wide: bool = Field(default=False, description="Whether the declaration permits wide bytes")
    fullword: bool = Field(default=False, description="Whether fullword matching is required")
    nocase: bool = Field(default=False, description="Whether case-insensitive matching is permitted")
    range_start: int | None = Field(default=None, ge=0)
    range_end: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_hex_value(self):
        if self.format != "hex":
            return self
        compact = self.value.replace(" ", "")
        if not compact or len(compact) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", compact):
            raise ValueError("hex string values must contain complete hexadecimal bytes")
        return self

    @model_validator(mode="after")
    def validate_placement(self):
        if (self.range_start is None) != (self.range_end is None):
            raise ValueError("range_start and range_end must be set together")
        if self.range_start is not None and self.range_start > self.range_end:
            raise ValueError("range_start must not exceed range_end")
        if self.offset is not None and self.range_start is not None:
            raise ValueError("a string cannot have both an exact offset and a range")
        return self


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
        description="True when the outer uint reads from an inner uint expression. "
        "False for uint16(X) or uint32(X) with a literal offset.",
    )
    byte_order: Literal["little", "big"] = Field(default="little")
    signed: bool = Field(default=False)
    relative_offset: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def validate_literal(self):
        if not re.fullmatch(r"0[xX][0-9A-Fa-f]+", self.value):
            raise ValueError("constant values must be hexadecimal literals with a 0x prefix")
        if int(self.value, 16) >= 1 << (self.size * 8):
            raise ValueError("constant value does not fit the declared size")
        if self.offset is not None and self.offset < 0:
            raise ValueError("constant offsets must be non-negative")
        return self


class YaraStrings(BaseModel):
    """Strings extracted from a YARA rule."""

    strings: list[YaraStringEntry]


class YaraConstants(BaseModel):
    """Constants extracted from a YARA rule."""

    constants: list[YaraConstantEntry]
