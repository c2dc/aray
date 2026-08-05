"""Evaluation framework for aray — batch-run the pipeline over YARA rule paths."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import tomllib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal
from unittest.mock import patch

from dotenv import load_dotenv

from aray.config import LLMNodeConfig, PipelineConfig
from aray.graph import build_graph


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class EvalResult:
    rule_path: str
    rule_name: str | None
    status: Literal["passed", "failed", "skipped"]
    error: str | None
    duration_seconds: float
    yara_stdout: str | None
    yara_returncode: int | None
    normalize_model: str = ""
    extract_model: str = ""
    normalize_verdict: str | None = None   # last judge verdict ("passed"/"failed"/"uncertain")
    normalize_reason: str | None = None    # last judge explanation

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EvalConfig:
    directories: list[str]
    model: str = "gpt-4.1"
    normalize_model: str | None = None
    extract_model: str | None = None
    base_url: str | None = None
    normalize_base_url: str | None = None
    extract_base_url: str | None = None
    normalize_api_key: str | None = None
    extract_api_key: str | None = None
    use_structured_output: bool = True
    normalize_streaming: bool | None = None
    extract_streaming: bool | None = None
    scan_only: bool = False
    streaming: bool = True
    workers: int = 1
    output: str | None = None
    keep_artifacts: bool = False


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

_INDEX_NAME_RE = re.compile(
    r'(?:^index\.yar$|_index\.yar$|^index_.*\.yar$)',
    re.IGNORECASE,
)
_INDEX_CONTENT_RE = re.compile(r'^include\s+"', re.MULTILINE)


def _is_index_file(path: Path) -> bool:
    """Return True if *path* is a YARA index file (aggregator, not a real rule)."""
    if _INDEX_NAME_RE.search(path.name):
        return True
    try:
        probe = path.read_bytes()[:4096].decode("utf-8", errors="replace")
        if _INDEX_CONTENT_RE.search(probe):
            return True
    except OSError:
        pass
    return False


def _find_yar_files(paths: list[str | Path]) -> list[Path]:
    """Return sorted non-index `.yar` files from files and directories."""
    found: list[Path] = []
    for path in paths:
        p = Path(path)
        if p.is_file():
            if p.suffix == ".yar" and not _is_index_file(p):
                found.append(p)
        elif p.is_dir():
            for yar in p.rglob("*.yar"):
                if not _is_index_file(yar):
                    found.append(yar)
    return sorted(found)


def _extract_first_rule_name(text: str) -> str | None:
    """Return the name of the first YARA rule found in *text*, or None."""
    m = re.search(r'^\s*(?:private\s+|global\s+)*rule\s+(\w+)', text, re.MULTILINE)
    return m.group(1) if m else None


def _extract_first_rule_text(text: str) -> str:
    """Return the first complete non-private YARA rule block from *text*.

    Strips file-level comments, include/import statements, and any subsequent
    rules — returning only the text from the first non-private ``rule`` keyword
    (including any ``global`` prefix) to its matching closing brace.
    Private rules are skipped entirely so downstream nodes always operate on a
    rule that can produce a standalone match.
    Falls back to *text* unchanged if no non-private rule header is found, so
    callers never receive an empty string.

    Handles string literals (``"..."``, with backslash escapes), line comments
    (``//``), and block comments (``/* ... */``) to avoid false brace counts.
    """
    search_start = 0
    while True:
        match = re.search(
            r'((?:(?:private|global)\s+)*)rule\s+\w+', text[search_start:]
        )
        if not match:
            return text  # fallback: no (more) rules found

        qualifiers = match.group(1)  # modifiers before "rule", e.g. "private "
        is_private = 'private' in qualifiers

        abs_start = search_start + match.start()
        pos = search_start + match.end()

        # Advance to the opening brace of the rule body
        while pos < len(text) and text[pos] != '{':
            pos += 1
        if pos >= len(text):
            if not is_private:
                return text[abs_start:]
            return text  # unclosed private rule at EOF — give up

        # Walk the body counting braces, skipping strings, comments, and regex literals
        depth = 0
        in_str = False
        in_regex = False
        in_line_comment = False
        in_block_comment = False

        while pos < len(text):
            ch = text[pos]

            if in_line_comment:
                if ch == '\n':
                    in_line_comment = False
            elif in_block_comment:
                if ch == '*' and pos + 1 < len(text) and text[pos + 1] == '/':
                    in_block_comment = False
                    pos += 1
            elif in_str:
                if ch == '\\':
                    pos += 1  # skip escaped character
                elif ch == '"':
                    in_str = False
            elif in_regex:
                if ch == '\\':
                    pos += 1  # skip escaped character inside regex
                elif ch == '/':
                    in_regex = False
            else:
                if ch == '/' and pos + 1 < len(text) and text[pos + 1] == '/':
                    in_line_comment = True
                    pos += 1
                elif ch == '/' and pos + 1 < len(text) and text[pos + 1] == '*':
                    in_block_comment = True
                    pos += 1
                elif ch == '/':
                    in_regex = True  # YARA regex literal: /pattern/
                elif ch == '"':
                    in_str = True
                elif ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        if not is_private:
                            return text[abs_start:pos + 1]
                        # Skip this private rule and search for the next one
                        search_start = pos + 1
                        break  # continue outer while True loop

            pos += 1
        else:
            # Reached end of text (unclosed rule body)
            if not is_private:
                return text[abs_start:]
            return text  # unclosed private rule — give up


# ---------------------------------------------------------------------------
# YARA scan helper
# ---------------------------------------------------------------------------

def _yara_scan(rule_path: Path, binary: Path) -> tuple[int, str, str]:
    """Run ``yara <rule_path> <binary>`` and return (returncode, stdout, stderr)."""
    result = subprocess.run(
        ["yara", str(rule_path), str(binary)],
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout, result.stderr


def _has_yara_match(stdout: str) -> bool:
    """Return True if *stdout* contains at least one YARA match line.

    YARA may print ``warning: ...`` lines to stdout (depending on version and
    configuration) before the actual match lines.  Those must not be mistaken
    for a match — only lines that do *not* start with ``warning:`` count.
    """
    return any(
        line.strip() and not line.startswith("warning:")
        for line in stdout.splitlines()
    )


# ---------------------------------------------------------------------------
# Pipeline runner
# ---------------------------------------------------------------------------

# Global lock — ensures BUILD_DIR patches don't race when workers > 1
_RUN_LOCK = threading.Lock()


def _run_one(rule_path: Path, eval_cfg: EvalConfig) -> EvalResult:
    """Run the full aray pipeline on *rule_path* and return an EvalResult."""
    import time

    rule_text = ""
    try:
        rule_text = rule_path.read_text(errors="replace")
    except OSError:
        pass
    rule_name = _extract_first_rule_name(rule_text)
    normalize_model = eval_cfg.normalize_model or eval_cfg.model
    extract_model = eval_cfg.extract_model or eval_cfg.model

    # Skip index files immediately (belt-and-suspenders in case caller missed it)
    # (per-step endpoint/key resolution happens below, before building the config)
    if _is_index_file(rule_path):
        return EvalResult(
            rule_path=str(rule_path),
            rule_name=rule_name,
            status="skipped",
            error=None,
            duration_seconds=0.0,
            yara_stdout=None,
            yara_returncode=None,
            normalize_model=normalize_model,
            extract_model=extract_model,
        )

    tmpdir = Path(tempfile.mkdtemp(prefix="aray_eval_"))
    linux_dir = tmpdir / "linux"
    windows_dir = tmpdir / "windows"
    generic_dir = tmpdir / "generic"

    t0 = time.monotonic()
    try:
        base_url = eval_cfg.base_url
        normalize_base_url = eval_cfg.normalize_base_url or base_url
        extract_base_url = eval_cfg.extract_base_url or base_url

        pipeline_cfg = PipelineConfig(
            normalize=LLMNodeConfig(
                model=normalize_model, base_url=normalize_base_url, api_key=eval_cfg.normalize_api_key,
                streaming=eval_cfg.normalize_streaming,
            ),
            extract=LLMNodeConfig(
                model=extract_model, base_url=extract_base_url, api_key=eval_cfg.extract_api_key,
                streaming=eval_cfg.extract_streaming,
            ),
            use_structured_output=eval_cfg.use_structured_output,
            scan_only=eval_cfg.scan_only,
            streaming=eval_cfg.streaming,
        )

        final_state = None
        with _RUN_LOCK:
            with (
                patch("aray.compiler.BUILD_DIR", linux_dir),
                patch("aray.compiler.BUILD_DIR_WIN", windows_dir),
                patch("aray.constants.BUILD_DIR_GENERIC", generic_dir),
            ):
                final_state = build_graph(config=pipeline_cfg).invoke(
                    {"name": "aray", "rule_path": str(rule_path.resolve())}
                )

        normalization_error = (final_state or {}).get("normalization_error")
        if normalization_error:
            duration = time.monotonic() - t0
            return EvalResult(
                rule_path=str(rule_path),
                rule_name=rule_name,
                status="failed",
                error=f"normalization failed: {normalization_error}",
                duration_seconds=round(duration, 3),
                yara_stdout=None,
                yara_returncode=None,
                normalize_model=normalize_model,
                extract_model=extract_model,
                normalize_verdict="failed",
                normalize_reason=normalization_error,
            )

        # Detect produced binary and the rule file to scan with.
        # For generic artifacts we scan with normalized_rule.yar (first rule only)
        # rather than the original multi-rule file; for PE/ELF we keep using
        # rule_path (existing behaviour, single-rule files in practice).
        binary: Path | None = None
        scan_rule = rule_path
        if (windows_dir / "app.exe").exists():
            binary = windows_dir / "app.exe"
        elif (linux_dir / "app").exists():
            binary = linux_dir / "app"
        else:
            # Generic artifact — find the first output.* file written by write_generic
            for f in sorted(generic_dir.glob("output*")):
                if f.is_file():
                    binary = f
                    break
            if binary is not None:
                norm = generic_dir / "normalized_rule.yar"
                if norm.exists():
                    scan_rule = norm

        if binary is None:
            raise FileNotFoundError("No binary produced by pipeline")

        rc, stdout, _stderr = _yara_scan(scan_rule, binary)
        passed = rc == 0 and _has_yara_match(stdout)
        duration = time.monotonic() - t0
        return EvalResult(
            rule_path=str(rule_path),
            rule_name=rule_name,
            status="passed" if passed else "failed",
            error=None if passed else f"YARA mismatch: rc={rc} stdout={stdout!r}",
            duration_seconds=round(duration, 3),
            yara_stdout=stdout,
            yara_returncode=rc,
            normalize_model=normalize_model,
            extract_model=extract_model,
            normalize_verdict=(final_state or {}).get("judge_verdict") or None,
            normalize_reason=(final_state or {}).get("judge_reason") or None,
        )

    except Exception as exc:  # noqa: BLE001
        duration = time.monotonic() - t0
        return EvalResult(
            rule_path=str(rule_path),
            rule_name=rule_name,
            status="failed",
            error=str(exc),
            duration_seconds=round(duration, 3),
            yara_stdout=None,
            yara_returncode=None,
            normalize_model=normalize_model,
            extract_model=extract_model,
        )
    finally:
        if not eval_cfg.keep_artifacts:
            shutil.rmtree(tmpdir, ignore_errors=True)
        else:
            print(f"Artifacts kept at {tmpdir.resolve()}")


# ---------------------------------------------------------------------------
# Batch runner
# ---------------------------------------------------------------------------

def run_evaluation(rule_paths: list[Path], eval_cfg: EvalConfig) -> list[EvalResult]:
    """Evaluate *rule_paths* and return results, printing progress to stderr."""
    total = len(rule_paths)
    results: list[EvalResult] = []

    def _process(idx: int, rp: Path) -> EvalResult:
        result = _run_one(rp, eval_cfg)
        print(
            f"[{idx}/{total}] {rp} → {result.status}",
            file=__import__("sys").stderr,
            flush=True,
        )
        return result

    if eval_cfg.workers <= 1:
        for i, rp in enumerate(rule_paths, 1):
            results.append(_process(i, rp))
    else:
        futures: list = []
        with ThreadPoolExecutor(max_workers=eval_cfg.workers) as executor:
            for i, rp in enumerate(rule_paths, 1):
                futures.append(executor.submit(_process, i, rp))
        for f in futures:
            results.append(f.result())

    return results


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _write_report(results: list[EvalResult], eval_cfg: EvalConfig, run_ts: str) -> None:
    """Write a JSON report; uses a timestamped path unless eval_cfg.output is set."""
    passed = sum(1 for r in results if r.status == "passed")
    failed = sum(1 for r in results if r.status == "failed")
    skipped = sum(1 for r in results if r.status == "skipped")
    total = len(results)
    total_duration = sum(r.duration_seconds for r in results)

    report = {
        "metadata": {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "total": total,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "duration_seconds": round(total_duration, 3),
            "config": {
                "model": eval_cfg.model,
                "normalize_model": eval_cfg.normalize_model,
                "extract_model": eval_cfg.extract_model,
                "base_url": eval_cfg.base_url,
                "normalize_base_url": eval_cfg.normalize_base_url,
                "extract_base_url": eval_cfg.extract_base_url,
                "use_structured_output": eval_cfg.use_structured_output,
                "scan_only": eval_cfg.scan_only,
                "workers": eval_cfg.workers,
            },
        },
        "results": [r.to_dict() for r in results],
    }

    out = (
        eval_cfg.output
        if eval_cfg.output
        else f"evaluation/reports/{run_ts}/eval_report.json"
    )
    output_path = Path(out)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2))
    print(f"Report written to {output_path.resolve()}")


def _print_summary(results: list[EvalResult]) -> None:
    """Print a human-readable summary to stdout."""
    total = len(results)
    passed = [r for r in results if r.status == "passed"]
    failed = [r for r in results if r.status == "failed"]
    skipped = [r for r in results if r.status == "skipped"]

    def _pct(n: int) -> str:
        return f"({n / total * 100:.1f}%)" if total else "(0.0%)"

    print()
    print(f"PASSED  {len(passed):>4}/{total} {_pct(len(passed))}")
    print(f"FAILED  {len(failed):>4}/{total} {_pct(len(failed))}")
    print(f"SKIPPED {len(skipped):>4}/{total} {_pct(len(skipped))}")

    if failed:
        print("\nFailed rules:")
        for r in failed:
            truncated = (r.error or "")[:120]
            print(f"  {r.rule_path}: {truncated}")


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def _load_config_file(path: Path) -> dict:
    """Load a TOML config file; return empty dict if not found."""
    if not path.exists():
        return {}
    try:
        return tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Invalid TOML in {path}: {exc}") from exc


def _build_eval_config(args: argparse.Namespace, file_cfg: dict) -> EvalConfig:
    """Merge CLI args > config-file [evaluator] > env vars > defaults."""
    ev = file_cfg.get("evaluator", {})

    # Input paths: CLI positional > config file. Keep the configuration field
    # name for compatibility with existing .evaluator files.
    if args.dirs:
        directories = list(args.dirs)
    else:
        directories = ev.get("directories", [])

    # Resolve each source completely before falling back to the next one. This
    # lets the batch config override even role-specific variables from .env.
    default_model = (
        args.model
        or ev.get("model")
        or os.getenv("OPENAI_MODEL")
        or "gpt-4.1"
    )
    base_url = (
        args.base_url
        or ev.get("base_url")
        or os.getenv("OPENAI_BASE_URL")
        or None
    )

    normalize_model: str | None = (
        args.normalize_model
        or args.model
        or ev.get("normalize_model")
        or ev.get("model")
        or os.getenv("NORMALIZE_MODEL")
        or os.getenv("OPENAI_MODEL")
        or "gpt-4.1"
    )
    extract_model: str | None = (
        args.extract_model
        or args.model
        or ev.get("extract_model")
        or ev.get("model")
        or os.getenv("EXTRACT_MODEL")
        or os.getenv("OPENAI_MODEL")
        or "gpt-4.1"
    )

    # Per-step endpoint: role/shared CLI > role/shared TOML > role/shared env.
    normalize_base_url: str | None = (
        args.normalize_base_url
        or args.base_url
        or ev.get("normalize_base_url")
        or ev.get("base_url")
        or os.getenv("NORMALIZE_BASE_URL")
        or os.getenv("OPENAI_BASE_URL")
        or None
    )
    extract_base_url: str | None = (
        args.extract_base_url
        or args.base_url
        or ev.get("extract_base_url")
        or ev.get("base_url")
        or os.getenv("EXTRACT_BASE_URL")
        or os.getenv("OPENAI_BASE_URL")
        or None
    )
    # Per-step API key: CLI > config file > step env > shared OPENAI_API_KEY
    shared_api_key = os.getenv("OPENAI_API_KEY")
    normalize_api_key: str | None = (
        args.normalize_api_key
        or ev.get("normalize_api_key")
        or os.getenv("NORMALIZE_API_KEY")
        or shared_api_key
    )
    extract_api_key: str | None = (
        args.extract_api_key
        or ev.get("extract_api_key")
        or os.getenv("EXTRACT_API_KEY")
        or shared_api_key
    )

    # Boolean / integer flags: CLI > config file > default
    scan_only = args.scan_only or ev.get("scan_only", False)
    no_stream = args.no_stream or ev.get("no_stream", False)
    workers = args.workers if args.workers is not None else ev.get("workers", 1)
    output = args.output or ev.get("output") or None
    keep_artifacts = args.keep_artifacts or ev.get("keep_artifacts", False)

    # Per-role streaming overrides: False only when the role's own flag / config
    # key is set; otherwise None so the role inherits the pipeline-wide value.
    # Structured output needs no override — it auto-falls back to prompt-based
    # JSON when the model/gateway does not support tool calls.
    def _role_override(cli_flag: bool, cfg_key: str) -> bool | None:
        return False if (cli_flag or ev.get(cfg_key, False)) else None

    normalize_streaming = _role_override(args.normalize_no_stream, "normalize_no_stream")
    extract_streaming = _role_override(args.extract_no_stream, "extract_no_stream")

    return EvalConfig(
        directories=directories,
        model=default_model,
        normalize_model=normalize_model,
        extract_model=extract_model,
        base_url=base_url,
        normalize_base_url=normalize_base_url,
        extract_base_url=extract_base_url,
        normalize_api_key=normalize_api_key,
        extract_api_key=extract_api_key,
        use_structured_output=True,
        normalize_streaming=normalize_streaming,
        extract_streaming=extract_streaming,
        scan_only=scan_only,
        streaming=not no_stream,
        workers=workers,
        output=output,
        keep_artifacts=keep_artifacts,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="aray-eval",
        description="Batch-evaluate aray against YARA rule files or directories.",
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
        default=Path(".evaluator"),
        metavar="PATH",
        help="Config file path (default: .evaluator).",
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
        help="JSON report output path (default: report.json).",
    )
    parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        default=False,
        help="Keep temporary build directories after each run (for debugging).",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Model for all pipeline roles. Overrides OPENAI_MODEL env var.",
    )
    parser.add_argument(
        "--normalize-model",
        default=None,
        metavar="M",
        help="Model for the normalize_rule node.",
    )
    parser.add_argument(
        "--extract-model",
        default=None,
        metavar="M",
        help="Model for the extract_strings/extract_constants nodes.",
    )
    parser.add_argument(
        "--base-url",
        default=None,
        metavar="URL",
        help="OpenAI-compatible API base URL.",
    )
    parser.add_argument(
        "--normalize-base-url",
        default=None,
        metavar="URL",
        help="Base URL for the normalize_rule node. Overrides NORMALIZE_BASE_URL env var and --base-url.",
    )
    parser.add_argument(
        "--extract-base-url",
        default=None,
        metavar="URL",
        help="Base URL for the extract nodes. Overrides EXTRACT_BASE_URL env var and --base-url.",
    )
    parser.add_argument(
        "--normalize-api-key",
        default=None,
        metavar="KEY",
        help="API key for the normalize_rule node. Overrides NORMALIZE_API_KEY env var and OPENAI_API_KEY.",
    )
    parser.add_argument(
        "--extract-api-key",
        default=None,
        metavar="KEY",
        help="API key for the extract nodes. Overrides EXTRACT_API_KEY env var and OPENAI_API_KEY.",
    )
    parser.add_argument(
        "--scan-only",
        action="store_true",
        default=False,
        help="Write raw binary artifact without invoking the compiler.",
    )
    parser.add_argument(
        "--no-stream",
        action="store_true",
        default=False,
        help="Disable streaming on LLM calls for ALL nodes.",
    )
    parser.add_argument(
        "--normalize-no-stream",
        action="store_true",
        default=False,
        help="Disable streaming for the normalize/judge nodes only.",
    )
    parser.add_argument(
        "--extract-no-stream",
        action="store_true",
        default=False,
        help="Disable streaming for the extract nodes only.",
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
    eval_cfg = _build_eval_config(args, file_cfg)

    if not eval_cfg.directories:
        print(
            "error: no input paths specified — use positional args or set "
            "[evaluator] directories in the config file.",
            file=sys.stderr,
        )
        sys.exit(1)

    run_ts = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")

    rule_paths = _find_yar_files(eval_cfg.directories)
    if not rule_paths:
        print("No .yar files found.")
        return

    normalize_model = eval_cfg.normalize_model or eval_cfg.model
    extract_model = eval_cfg.extract_model or eval_cfg.model
    normalize_base_url = eval_cfg.normalize_base_url or eval_cfg.base_url
    extract_base_url = eval_cfg.extract_base_url or eval_cfg.base_url
    print(f"Found {len(rule_paths)} rule(s) to evaluate.")
    print(f"Models: normalize={normalize_model}  extract={extract_model}")
    print(f"Base URLs: normalize={normalize_base_url or 'default'}  extract={extract_base_url or 'default'}")
    results = run_evaluation(rule_paths, eval_cfg)
    _write_report(results, eval_cfg, run_ts)
    _print_summary(results)
