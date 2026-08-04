"""CLI entry point for the aray pipeline."""

import argparse
import os
import shutil
import sys
from pathlib import Path

from dotenv import load_dotenv

from aray.config import LLMNodeConfig, PipelineConfig
from aray.constants import BUILD_DIR, BUILD_DIR_GENERIC, BUILD_DIR_WIN
from aray.graph import build_graph, save_graph_png


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="aray",
        description="Generate benign executables that match YARA rules for security testing.",
    )
    parser.add_argument("rule_path", type=Path, nargs="?", help="path to a .yar YARA rule file")
    parser.add_argument(
        "--graph",
        action="store_true",
        help="save pipeline graph visualization to react_graph.png",
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help="Base URL for OpenAI-compatible API gateway (e.g. http://localhost:4000). Overrides OPENAI_BASE_URL env var.",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Model name (e.g. gpt-4o, llama3). Overrides OPENAI_MODEL env var. Default: gpt-4.1.",
    )
    parser.add_argument(
        "--normalize-model",
        default=None,
        help="Model for the normalize_rule node. Overrides NORMALIZE_MODEL env var and --model.",
    )
    parser.add_argument(
        "--extract-model",
        default=None,
        help="Model for the extract_strings/extract_constants nodes. Overrides EXTRACT_MODEL env var and --model.",
    )
    parser.add_argument(
        "--normalize-base-url",
        default=None,
        help="Base URL for the normalize_rule node. Overrides NORMALIZE_BASE_URL env var and --base-url.",
    )
    parser.add_argument(
        "--extract-base-url",
        default=None,
        help="Base URL for the extract_strings/extract_constants nodes. Overrides EXTRACT_BASE_URL env var and --base-url.",
    )
    parser.add_argument(
        "--normalize-api-key",
        default=None,
        help="API key for the normalize_rule node. Overrides NORMALIZE_API_KEY env var and OPENAI_API_KEY.",
    )
    parser.add_argument(
        "--extract-api-key",
        default=None,
        help="API key for the extract_strings/extract_constants nodes. Overrides EXTRACT_API_KEY env var and OPENAI_API_KEY.",
    )
    parser.add_argument(
        "--no-stream",
        action="store_true",
        default=False,
        help=(
            "Disable streaming on LLM calls for ALL nodes. "
            "Use when the model or API gateway does not support streaming."
        ),
    )
    parser.add_argument(
        "--normalize-no-stream",
        action="store_true",
        default=False,
        help="Disable streaming for the normalize/judge nodes only (overrides --no-stream for this role).",
    )
    parser.add_argument(
        "--extract-no-stream",
        action="store_true",
        default=False,
        help="Disable streaming for the extract nodes only (overrides --no-stream for this role).",
    )
    parser.add_argument(
        "--scan-only",
        action="store_true",
        default=False,
        help=(
            "Write a raw binary artifact without invoking the compiler. "
            "Linux rules produce a minimal ELF64; PE rules produce a minimal PE64. "
            "Useful when gcc / MinGW is not available."
        ),
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Print the name of each pipeline node as it executes.",
    )
    args = parser.parse_args(argv)
    if args.rule_path is None:
        parser.print_help()
        raise SystemExit(0)
    return args


def _clean_build_outputs() -> None:
    """Remove artifacts from previous CLI runs before generating new output."""
    for build_dir in (BUILD_DIR, BUILD_DIR_WIN, BUILD_DIR_GENERIC):
        shutil.rmtree(build_dir, ignore_errors=True)


def main() -> None:
    load_dotenv()
    args = parse_args()

    if not args.rule_path.is_file():
        print(f"error: file not found: {args.rule_path}", file=sys.stderr)
        sys.exit(1)

    default_model = args.model or os.getenv("OPENAI_MODEL") or "gpt-4.1"
    base_url = args.base_url or os.getenv("OPENAI_BASE_URL") or None
    shared_api_key = os.getenv("OPENAI_API_KEY")

    normalize_model = args.normalize_model or os.getenv("NORMALIZE_MODEL") or default_model
    extract_model = args.extract_model or os.getenv("EXTRACT_MODEL") or default_model

    normalize_base_url = args.normalize_base_url or os.getenv("NORMALIZE_BASE_URL") or base_url
    extract_base_url = args.extract_base_url or os.getenv("EXTRACT_BASE_URL") or base_url
    normalize_api_key = args.normalize_api_key or os.getenv("NORMALIZE_API_KEY") or shared_api_key
    extract_api_key = args.extract_api_key or os.getenv("EXTRACT_API_KEY") or shared_api_key

    # Per-role streaming overrides: None inherits the global default below;
    # False only when the role's own flag is set. Structured output is always
    # attempted and automatically falls back to prompt-based JSON when the
    # model/gateway does not support tool calls.
    normalize_streaming = False if args.normalize_no_stream else None
    extract_streaming = False if args.extract_no_stream else None

    config = PipelineConfig(
        normalize=LLMNodeConfig(
            model=normalize_model, base_url=normalize_base_url, api_key=normalize_api_key,
            streaming=normalize_streaming,
        ),
        extract=LLMNodeConfig(
            model=extract_model, base_url=extract_base_url, api_key=extract_api_key,
            streaming=extract_streaming,
        ),
        scan_only=args.scan_only,
        streaming=not args.no_stream,
        debug=args.debug,
    )
    print(f"Models: normalize={normalize_model}  extract={extract_model}")
    print(f"Base URLs: normalize={normalize_base_url or 'default'}  extract={extract_base_url or 'default'}")
    graph = build_graph(config=config)

    if args.graph:
        save_graph_png(graph)
        print("Graph saved to react_graph.png")

    _clean_build_outputs()
    graph.invoke({"name": "aray", "rule_path": str(args.rule_path.resolve())})
