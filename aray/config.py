"""LLM configuration dataclasses for the aray pipeline."""

from dataclasses import dataclass, field
from typing import Literal


ReasoningEffort = Literal["none", "low", "medium", "high", "max"]


@dataclass
class LLMNodeConfig:
    """LLM settings for a single pipeline role.

    ``streaming`` is a per-role override: when left as ``None`` the role
    inherits the pipeline-wide default from ``PipelineConfig``; set to a bool
    to override that default for this role only.

    Structured output is always attempted and automatically falls back to
    prompt-based JSON when the model/gateway does not support tool calls, so it
    needs no per-role configuration.
    """
    model: str = "gpt-4.1"
    base_url: str | None = None
    api_key: str | None = None
    streaming: bool | None = None
    reasoning_effort: ReasoningEffort | None = None


@dataclass
class PipelineConfig:
    """Per-role LLM configuration for the full pipeline.

    Two logical roles:
    - normalize  : complex rewriting task; benefits from a stronger model
    - extract    : structured data extraction; cheaper/faster model is fine
    """
    normalize: LLMNodeConfig = field(default_factory=LLMNodeConfig)
    extract: LLMNodeConfig = field(default_factory=LLMNodeConfig)
    use_structured_output: bool = True
    scan_only: bool = False
    streaming: bool = True
    debug: bool = False

    @classmethod
    def from_model(cls, model: str = "gpt-4.1", base_url: str | None = None) -> "PipelineConfig":
        """Create a config that uses the same model for all roles (legacy behaviour)."""
        cfg = LLMNodeConfig(model=model, base_url=base_url)
        return cls(normalize=cfg, extract=cfg)
