"""Batch normalization evaluator — runs normalize_rule over YARA rule paths."""

from __future__ import annotations

import argparse
import functools
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

from aray.evaluator import (
    _find_yar_files,
    _is_index_file,
    _load_config_file,
)
from aray.constants import DUMMY_API_KEY
from aray.nodes import _judge_normalization, _requires_normalization, normalize_rule
from aray.yara_source import NoPublicRuleError, select_yara_file


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class NormResult:
    rule_path: str
    rule_name: str | None
    status: Literal["passed", "failed", "skipped", "error"]
    normalized_rule: str | None
    output_path: str | None
    judge_verdict: Literal["passed", "failed", "uncertain"] | None
    judge_reason: str | None
    error: str | None
    duration_seconds: float
    normalize_model: str = ""
    judge_model: str = ""
    already_normalized: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class NormConfig:
    directories: list[str]
    output_root: str = "evaluation/normalized"
    model: str = "gpt-4.1"
    judge_model: str = "gpt-4.1"
    base_url: str | None = None
    judge_base_url: str | None = None
    normalize_api_key: str | None = None
    judge_api_key: str | None = None
    use_structured_output: bool = True
    streaming: bool = True
    workers: int = 1
    output: str | None = None


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def _output_path_for(rule_path: Path, input_path: Path, output_root: Path) -> Path:
    """Build the normalized path for a file or mirrored input directory."""
    if input_path.is_file():
        return output_root / rule_path.name
    relative = rule_path.relative_to(input_path)
    return output_root / input_path.name / relative


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def _normalize_one_rule(
    rule_text: str,
    llm: ChatOpenAI,
    use_structured: bool,
    history: list[dict] | None = None,
) -> str:
    """Call the normalize_rule node directly (no full graph)."""
    state = {
        "yara_rule": rule_text,
        "name": "aray",
        "rule_path": "",
        "normalize_history": history or [],
        "normalize_attempts": len(history or []),
    }
    result = functools.partial(normalize_rule, llm=llm, use_structured=use_structured)(state)
    return result["normalized_rule"]


# ---------------------------------------------------------------------------
# Per-rule runner
# ---------------------------------------------------------------------------

def _run_one(
    rule_path: Path,
    input_path: Path,
    norm_cfg: NormConfig,
    norm_llm: ChatOpenAI,
    judge_llm: ChatOpenAI,
) -> NormResult:
    import time

    t0 = time.monotonic()
    _normalize_model = norm_cfg.model
    _judge_model = norm_cfg.judge_model
    rule_name: str | None = None

    if _is_index_file(rule_path):
        return NormResult(
            rule_path=str(rule_path),
            rule_name=None,
            status="skipped",
            normalized_rule=None,
            output_path=None,
            judge_verdict=None,
            judge_reason=None,
            error=None,
            duration_seconds=0.0,
            normalize_model=_normalize_model,
            judge_model=_judge_model,
        )

    out_path = _output_path_for(rule_path, input_path, Path(norm_cfg.output_root))
    try:
        selected = select_yara_file(rule_path)
        first_rule = selected.text
        rule_name = selected.name

        if not _requires_normalization(first_rule):
            print(f"[normalize] {rule_path.name}: rule is already normalized — skipping LLM")
            from aray.yara_validation import validate_normalization

            validation_error = validate_normalization(first_rule, first_rule)
            if validation_error:
                raise ValueError(validation_error)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(first_rule)
            duration = time.monotonic() - t0
            return NormResult(
                rule_path=str(rule_path),
                rule_name=rule_name,
                status="passed",
                normalized_rule=first_rule,
                output_path=str(out_path),
                judge_verdict=None,
                judge_reason=None,
                error=None,
                duration_seconds=round(duration, 3),
                normalize_model=_normalize_model,
                judge_model=_judge_model,
                already_normalized=True,
            )

        history: list[dict] = []
        for attempt in range(1, 4):
            try:
                normalized_text = _normalize_one_rule(
                    first_rule,
                    norm_llm,
                    norm_cfg.use_structured_output,
                    history,
                )
                verdict = _judge_normalization(
                    first_rule, normalized_text, judge_llm, norm_cfg.use_structured_output
                )
            except Exception:
                if attempt == 3:
                    raise
                continue
            if verdict.verdict == "passed":
                break
            history.append({
                "attempt": attempt,
                "rule": normalized_text,
                "reason": verdict.reason,
            })

        if verdict.verdict == "passed":
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(normalized_text)
        else:
            out_path.unlink(missing_ok=True)

        status: Literal["passed", "failed"] = (
            "passed" if verdict.verdict == "passed" else "failed"
        )
        duration = time.monotonic() - t0
        return NormResult(
            rule_path=str(rule_path),
            rule_name=rule_name,
            status=status,
            normalized_rule=normalized_text,
            output_path=str(out_path) if verdict.verdict == "passed" else None,
            judge_verdict=verdict.verdict,
            judge_reason=verdict.reason,
            error=None,
            duration_seconds=round(duration, 3),
            normalize_model=_normalize_model,
            judge_model=_judge_model,
        )

    except NoPublicRuleError as exc:
        duration = time.monotonic() - t0
        out_path.unlink(missing_ok=True)
        return NormResult(
            rule_path=str(rule_path),
            rule_name=None,
            status="skipped",
            normalized_rule=None,
            output_path=None,
            judge_verdict=None,
            judge_reason=None,
            error=str(exc),
            duration_seconds=round(duration, 3),
            normalize_model=_normalize_model,
            judge_model=_judge_model,
        )
    except Exception as exc:  # noqa: BLE001
        duration = time.monotonic() - t0
        out_path.unlink(missing_ok=True)
        return NormResult(
            rule_path=str(rule_path),
            rule_name=rule_name,
            status="error",
            normalized_rule=None,
            output_path=None,
            judge_verdict=None,
            judge_reason=None,
            error=str(exc),
            duration_seconds=round(duration, 3),
            normalize_model=_normalize_model,
            judge_model=_judge_model,
        )


# ---------------------------------------------------------------------------
# Batch runner
# ---------------------------------------------------------------------------

def run_normalization(
    rule_paths: list[Path],
    input_paths: list[Path],
    norm_cfg: NormConfig,
) -> list[NormResult]:
    """Normalize rule_paths and return results, printing progress to stderr."""
    norm_base_url = norm_cfg.base_url or None
    judge_base_url = norm_cfg.judge_base_url or norm_cfg.base_url or None
    # The openai SDK requires *some* api_key to construct a client; gateways
    # that ignore auth (e.g. local Ollama) get a placeholder.
    norm_api_key = norm_cfg.normalize_api_key or (DUMMY_API_KEY if norm_base_url else None)
    judge_api_key = norm_cfg.judge_api_key or (DUMMY_API_KEY if judge_base_url else None)
    norm_llm = ChatOpenAI(
        model=norm_cfg.model,
        base_url=norm_base_url,
        streaming=norm_cfg.streaming,
        api_key=norm_api_key,
    )
    judge_llm = ChatOpenAI(
        model=norm_cfg.judge_model,
        base_url=judge_base_url,
        streaming=norm_cfg.streaming,
        api_key=judge_api_key,
    )

    total = len(rule_paths)
    results: list[NormResult] = []

    def _process(idx: int, rp: Path, input_path: Path) -> NormResult:
        result = _run_one(rp, input_path, norm_cfg, norm_llm, judge_llm)
        judge_info = f"judge: {result.judge_verdict}" if result.judge_verdict else result.status
        print(
            f"[{idx}/{total}] {rp} → {result.status} ({judge_info})",
            file=sys.stderr,
            flush=True,
        )
        return result

    if norm_cfg.workers <= 1:
        for i, (rp, input_path) in enumerate(zip(rule_paths, input_paths), 1):
            results.append(_process(i, rp, input_path))
    else:
        futures: list = []
        with ThreadPoolExecutor(max_workers=norm_cfg.workers) as executor:
            for i, (rp, input_path) in enumerate(zip(rule_paths, input_paths), 1):
                futures.append(executor.submit(_process, i, rp, input_path))
        for f in futures:
            results.append(f.result())

    return results


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _write_report(results: list[NormResult], norm_cfg: NormConfig, run_ts: str) -> None:
    passed = sum(1 for r in results if r.status == "passed")
    failed = sum(1 for r in results if r.status == "failed")
    skipped = sum(1 for r in results if r.status == "skipped")
    error = sum(1 for r in results if r.status == "error")
    total = len(results)
    total_duration = sum(r.duration_seconds for r in results)

    already_normalized = sum(1 for r in results if r.already_normalized)
    report = {
        "metadata": {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "total": total,
            "passed": passed,
            "already_normalized": already_normalized,
            "failed": failed,
            "skipped": skipped,
            "error": error,
            "duration_seconds": round(total_duration, 3),
            "config": {
                "model": norm_cfg.model,
                "judge_model": norm_cfg.judge_model,
                "output_root": norm_cfg.output_root,
                "workers": norm_cfg.workers,
            },
        },
        "results": [r.to_dict() for r in results],
    }

    out = (
        norm_cfg.output
        if norm_cfg.output
        else f"evaluation/reports/{run_ts}/norm_report.json"
    )
    output_path = Path(out)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2))
    print(f"Report written to {output_path.resolve()}")


def _print_summary(results: list[NormResult]) -> None:
    total = len(results)
    passed = [r for r in results if r.status == "passed"]
    failed = [r for r in results if r.status == "failed"]
    skipped = [r for r in results if r.status == "skipped"]
    errors = [r for r in results if r.status == "error"]
    already_norm = [r for r in results if r.already_normalized]

    def _pct(n: int) -> str:
        return f"({n / total * 100:.1f}%)" if total else "(0.0%)"

    print()
    print(f"PASSED  {len(passed):>4}/{total} {_pct(len(passed))}")
    print(f"  already normalized: {len(already_norm)}")
    print(f"FAILED  {len(failed):>4}/{total} {_pct(len(failed))}")
    print(f"SKIPPED {len(skipped):>4}/{total} {_pct(len(skipped))}")
    print(f"ERROR   {len(errors):>4}/{total} {_pct(len(errors))}")

    problem = failed + errors
    if problem:
        print("\nFailed/errored rules:")
        for r in problem:
            truncated = (r.error or r.judge_reason or "")[:120]
            print(f"  {r.rule_path}: {truncated}")

    generated = [Path(r.output_path).resolve() for r in results if r.output_path]
    if generated:
        print("\nGenerated normalized files:")
        for path in generated:
            print(f"  {path}")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _build_norm_config(args: argparse.Namespace, file_cfg: dict) -> NormConfig:
    """Merge CLI args > config-file [normalizer] > env vars > defaults."""
    nc = file_cfg.get("normalizer", {})

    # Keep the configuration field name for compatibility with existing
    # .normalizer files, but values may now be files or directories.
    directories = list(args.dirs) if args.dirs else nc.get("directories", [])

    model = (
        args.model
        or nc.get("model")
        or os.getenv("NORMALIZE_MODEL")
        or os.getenv("OPENAI_MODEL")
        or "gpt-4.1"
    )
    judge_model = (
        args.judge_model
        or args.model
        or nc.get("judge_model")
        or nc.get("model")
        or os.getenv("NORMALIZE_MODEL")
        or os.getenv("OPENAI_MODEL")
        or "gpt-4.1"
    )
    base_url = (
        args.base_url
        or nc.get("base_url")
        or os.getenv("NORMALIZE_BASE_URL")
        or os.getenv("OPENAI_BASE_URL")
        or None
    )
    judge_base_url = (
        args.judge_base_url
        or args.base_url
        or nc.get("judge_base_url")
        or nc.get("base_url")
        or os.getenv("NORMALIZE_BASE_URL")
        or os.getenv("OPENAI_BASE_URL")
        or None
    )
    normalize_api_key = (
        args.normalize_api_key
        or nc.get("normalize_api_key")
        or os.getenv("NORMALIZE_API_KEY")
        or os.getenv("OPENAI_API_KEY")
        or None
    )
    judge_api_key = (
        args.judge_api_key
        or args.normalize_api_key
        or nc.get("judge_api_key")
        or nc.get("normalize_api_key")
        or os.getenv("NORMALIZE_API_KEY")
        or os.getenv("OPENAI_API_KEY")
        or None
    )
    output_root = args.output_root or nc.get("output_root", "evaluation/normalized")
    no_stream = args.no_stream or nc.get("no_stream", False)
    workers = args.workers if args.workers is not None else nc.get("workers", 1)
    output = args.output or nc.get("output") or None

    return NormConfig(
        directories=directories,
        output_root=output_root,
        model=model,
        judge_model=judge_model,
        base_url=base_url or None,
        judge_base_url=judge_base_url or None,
        normalize_api_key=normalize_api_key,
        judge_api_key=judge_api_key,
        streaming=not no_stream,
        workers=workers,
        output=output,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="aray-normalize",
        description="Batch-normalize YARA rules and assess quality with an LLM judge.",
    )
    parser.add_argument(
        "dirs",
        nargs="*",
        metavar="PATH",
        help="YARA files or directories to process (overrides config file).",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(".normalizer"),
        metavar="PATH",
        help="Config file path (default: .normalizer).",
    )
    parser.add_argument(
        "--output-root",
        default=None,
        metavar="PATH",
        help="Root directory for normalized output (default: evaluation/normalized).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        metavar="N",
        help="Parallel workers (default: 1).",
    )
    parser.add_argument(
        "--output",
        default=None,
        metavar="PATH",
        help="JSON report output path (default: norm_report.json).",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Model for the normalize_rule node.",
    )
    parser.add_argument(
        "--judge-model",
        default=None,
        metavar="MODEL",
        help="Model for the LLM-as-judge (default: same as --model).",
    )
    parser.add_argument(
        "--base-url",
        default=None,
        metavar="URL",
        help="OpenAI-compatible base URL for the normalize node.",
    )
    parser.add_argument(
        "--judge-base-url",
        default=None,
        metavar="URL",
        help="OpenAI-compatible base URL for the judge (default: same as --base-url).",
    )
    parser.add_argument(
        "--normalize-api-key",
        default=None,
        metavar="KEY",
        help="API key for normalization. Overrides NORMALIZE_API_KEY and OPENAI_API_KEY.",
    )
    parser.add_argument(
        "--judge-api-key",
        default=None,
        metavar="KEY",
        help="API key for the judge (default: same as --normalize-api-key).",
    )
    parser.add_argument(
        "--no-stream",
        action="store_true",
        default=False,
        help="Disable streaming on all LLM calls.",
    )
    args_to_parse = sys.argv[1:] if argv is None else argv
    if not args_to_parse:
        parser.print_help()
        raise SystemExit(0)
    return parser.parse_args(args_to_parse)


def main() -> None:
    load_dotenv()
    args = parse_args()

    file_cfg = _load_config_file(args.config)
    norm_cfg = _build_norm_config(args, file_cfg)

    if not norm_cfg.directories:
        print(
            "error: no input paths specified — use positional args or set "
            "[normalizer] directories in the config file.",
            file=sys.stderr,
        )
        sys.exit(1)

    all_paths: list[Path] = []
    input_paths: list[Path] = []
    for value in norm_cfg.directories:
        input_path = Path(value)
        for yar in _find_yar_files([input_path]):
            all_paths.append(yar)
            input_paths.append(input_path)

    if not all_paths:
        print("No .yar files found.")
        return

    run_ts = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")

    print(f"Found {len(all_paths)} rule(s) to normalize.")
    print(f"Models: normalize={norm_cfg.model}  judge={norm_cfg.judge_model}")
    results = run_normalization(all_paths, input_paths, norm_cfg)
    _write_report(results, norm_cfg, run_ts)
    _print_summary(results)
