"""LangGraph pipeline builder for the aray pipeline."""

import functools
from pathlib import Path

from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph

from aray.compiler import compile_binary
from aray.config import PipelineConfig
from aray.constants import DUMMY_API_KEY
from aray.nodes import assess_constructibility, check_normalization_needed, extract_constants, extract_strings, fail_construction, fail_normalization, judge_rule, normalize_rule, read_yara_rule, route_file_type, write_generic
from aray.state import ArayGraphState

_MAX_NORMALIZE_ATTEMPTS = 3


def _debug_wrap(name: str, fn, debug: bool):
    """Wrap a node function to print its name on entry when debug mode is on."""
    if not debug:
        return fn

    def _wrapped(state):
        print(f"[debug] → node: {name}")
        return fn(state)

    return _wrapped


def _file_type_router(state: ArayGraphState) -> str:
    """Route to 'compile' for PE/ELF rules, or 'write_generic' for everything else."""
    return "compile" if state.get("file_type") in ("pe", "elf") else "write_generic"


def _normalization_router(state: ArayGraphState) -> str:
    """Route to normalize_rule if needed, or continue to preflight."""
    return "normalize_rule" if state.get("needs_normalization", True) else "assess_constructibility"


def _judge_router(state: ArayGraphState) -> str:
    """Route back to normalize_rule on failure, or forward on pass/uncertain/exhausted."""
    if state.get("judge_verdict") == "failed":
        if state.get("normalize_attempts", 0) < _MAX_NORMALIZE_ATTEMPTS:
            return "normalize_rule"
        return "fail_normalization"   # exhausted retries — bail out
    return "assess_constructibility"


def _constructibility_router(state: ArayGraphState) -> str:
    return (
        "extract_strings"
        if state.get("constructibility") == "constructible"
        else "fail_construction"
    )


def build_graph(config: PipelineConfig | None = None) -> StateGraph:
    """Build and return the compiled LangGraph pipeline."""
    if config is None:
        config = PipelineConfig()

    def _resolve(node_val, shared):
        """Per-role override wins when set; otherwise inherit the pipeline default."""
        return shared if node_val is None else node_val

    def _make_llm(node: "LLMNodeConfig") -> ChatOpenAI:
        # Only pass base_url / api_key when set, so unset values fall back to
        # ChatOpenAI's own env defaults (OPENAI_BASE_URL / OPENAI_API_KEY)
        # instead of being forced to None.
        kwargs = {"model": node.model, "streaming": _resolve(node.streaming, config.streaming)}
        if node.reasoning_effort:
            kwargs["reasoning_effort"] = node.reasoning_effort
        if node.base_url:
            kwargs["base_url"] = node.base_url
        if node.api_key:
            kwargs["api_key"] = node.api_key
        elif node.base_url:
            # Gateways that ignore auth (e.g. local Ollama) still require the
            # openai SDK to see *some* key to construct a client.
            kwargs["api_key"] = DUMMY_API_KEY
        return ChatOpenAI(**kwargs)

    normalize_llm = _make_llm(config.normalize)
    extract_llm = _make_llm(config.extract)
    # Structured output is pipeline-wide; each node auto-falls back to
    # prompt-based JSON when the model/gateway does not support tool calls.
    use_structured = config.use_structured_output
    debug = config.debug

    def _w(name: str, fn):
        return _debug_wrap(name, fn, debug)

    builder = StateGraph(ArayGraphState)

    builder.add_node("read_yara", _w("read_yara", read_yara_rule))
    builder.add_node("check_normalization_needed", _w("check_normalization_needed", check_normalization_needed))
    builder.add_node("normalize_rule", _w("normalize_rule", functools.partial(normalize_rule, llm=normalize_llm, use_structured=use_structured)))
    builder.add_node("judge_rule", _w("judge_rule", functools.partial(judge_rule, llm=normalize_llm, use_structured=use_structured)))
    builder.add_node("extract_strings", _w("extract_strings", functools.partial(extract_strings, llm=extract_llm, use_structured=use_structured)))
    builder.add_node("extract_constants", _w("extract_constants", functools.partial(extract_constants, llm=extract_llm, use_structured=use_structured)))
    builder.add_node("fail_normalization", _w("fail_normalization", fail_normalization))
    builder.add_node("assess_constructibility", _w("assess_constructibility", assess_constructibility))
    builder.add_node("fail_construction", _w("fail_construction", fail_construction))
    builder.add_node("compile", _w("compile", functools.partial(compile_binary, scan_only=config.scan_only, debug=debug)))
    builder.add_node("route_file_type", _w("route_file_type", route_file_type))
    builder.add_node("write_generic", _w("write_generic", functools.partial(write_generic, debug=debug)))

    builder.add_edge(START, "read_yara")
    builder.add_edge("read_yara", "check_normalization_needed")
    builder.add_conditional_edges(
        "check_normalization_needed",
        _normalization_router,
        {"normalize_rule": "normalize_rule", "assess_constructibility": "assess_constructibility"},
    )
    builder.add_edge("normalize_rule", "judge_rule")
    builder.add_conditional_edges(
        "judge_rule", _judge_router,
        {"normalize_rule": "normalize_rule",
         "assess_constructibility": "assess_constructibility",
         "fail_normalization": "fail_normalization"},
    )
    builder.add_conditional_edges(
        "assess_constructibility",
        _constructibility_router,
        {"extract_strings": "extract_strings", "fail_construction": "fail_construction"},
    )
    builder.add_edge("extract_strings", "extract_constants")
    builder.add_edge("extract_constants", "route_file_type")
    builder.add_conditional_edges(
        "route_file_type", _file_type_router,
        {"compile": "compile", "write_generic": "write_generic"},
    )
    builder.add_edge("fail_normalization", END)
    builder.add_edge("fail_construction", END)
    builder.add_edge("compile", END)
    builder.add_edge("write_generic", END)

    return builder.compile()


def save_graph_png(graph: StateGraph, output_path: str = "react_graph.png") -> None:
    """Save a visualization of the graph to a PNG file."""
    png_bytes = graph.get_graph(xray=True).draw_mermaid_png()
    Path(output_path).write_bytes(png_bytes)
