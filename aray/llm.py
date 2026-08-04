"""LLM invocation helper for the aray pipeline."""

import json
import re

from langchain_core.exceptions import OutputParserException
from langchain_core.messages import SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel

try:
    import openai
except ImportError:  # pragma: no cover - transitive dependency of langchain-openai
    openai = None  # type: ignore[assignment]

# Exceptions that indicate structured output (tool-call API) is unavailable or
# the model failed to produce a parseable tool call.  These warrant retrying
# via the prompt-based JSON fallback.  Auth (401), rate-limit (429), and
# network errors are deliberately excluded — falling back would not help them.
if openai is not None:
    _STRUCTURED_FALLBACK_ERRORS: tuple[type[BaseException], ...] = (
        OutputParserException,
        ValueError,
        NotImplementedError,
        openai.BadRequestError,
        openai.NotFoundError,
        openai.InternalServerError,
    )
else:
    _STRUCTURED_FALLBACK_ERRORS = (
        OutputParserException,
        ValueError,
        NotImplementedError,
    )


def _invoke_llm_json(
    llm: ChatOpenAI,
    schema: type[BaseModel],
    messages: list,
) -> BaseModel:
    """Invoke LLM with a prompt-based JSON fallback.

    Injects the JSON Schema into the system prompt and parses the raw JSON
    response (strips markdown fences if present).
    """
    schema_json = json.dumps(schema.model_json_schema(), indent=2)
    injection = (
        "\n\nYou MUST respond with a single valid JSON object that conforms "
        "to the following JSON Schema. Output ONLY the JSON object — no "
        "explanation, no markdown fences, no extra text.\n\n"
        f"Schema:\n{schema_json}"
    )
    augmented = list(messages)
    augmented[0] = SystemMessage(content=augmented[0].content + injection)
    response = llm.invoke(augmented)
    content = response.content
    if not isinstance(content, str):
        content = str(content) if content is not None else ""
    raw = content.strip()
    raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.IGNORECASE)
    raw = re.sub(r"\s*```$", "", raw.strip())
    if not raw:
        raise ValueError(
            f"LLM returned an empty response; cannot parse JSON for schema {schema.__name__}"
        )
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"LLM returned a non-JSON response for schema {schema.__name__}: "
            f"{raw[:200]!r}"
        ) from exc
    return schema.model_validate(payload)


def _invoke_llm(
    llm: ChatOpenAI,
    schema: type[BaseModel],
    messages: list,
    use_structured: bool = True,
) -> BaseModel:
    """Invoke LLM with structured output, auto-falling back to JSON.

    Structured output (``method="function_calling"``, ``tool_choice="auto"``) is
    attempted first. ``tool_choice="auto"`` is used instead of forcing the tool
    because some providers (e.g. OpenRouter's Alibaba qwen3.5-flash in thinking
    mode) reject a forced ``tool_choice``. When the model or API gateway does
    not support tool calls (or the response cannot be parsed), the pipeline
    automatically retries with the prompt-based JSON fallback — no manual flag
    needed.  ``use_structured=False`` skips the structured attempt entirely.
    """
    if use_structured:
        try:
            result = llm.with_structured_output(
                schema, method="function_calling", tool_choice="auto"
            ).invoke(messages)
            if result is not None:
                return result
            print(
                "[llm] structured output returned None (model emitted no tool call)"
                " — falling back to prompt-based JSON"
            )
        except _STRUCTURED_FALLBACK_ERRORS as exc:
            print(
                f"[llm] structured output failed ({type(exc).__name__}: {exc})"
                " — falling back to prompt-based JSON"
            )
    return _invoke_llm_json(llm, schema, messages)
