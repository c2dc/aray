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
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal
from unittest.mock import patch

from dotenv import load_dotenv

from aray.config import LLMNodeConfig, PipelineConfig
from aray.graph import build_graph
from aray.yara_source import (
    extract_first_rule_name as _extract_first_rule_name,
    extract_first_rule_text as _extract_first_rule_text,
    select_yara_file,
)


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
    disposition: str | None = None
    failure_category: str | None = None
    normalization_source: str = "not_reached"
    strings_extraction_source: str = "not_reached"
    constants_extraction_source: str = "not_reached"
    llm_used: bool = False
    validation_source: Literal["normalized", "original"] = "normalized"
    validation_rule_path: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EvalConfig:
    directories: list[str]
    original_directories: list[str] = field(default_factory=list)
    validate_original: bool = False
    model: str = "gpt-4.1"
    normalize_model: str | None = None
    extract_model: str | None = None
    base_url: str | None = None
    normalize_base_url: str | None = None
    extract_base_url: str | None = None
    normalize_api_key: str | None = None
    extract_api_key: str | None = None
    normalize_reasoning_effort: str | None = None
    extract_reasoning_effort: str | None = None
    use_structured_output: bool = True
    normalize_streaming: bool | None = None
    extract_streaming: bool | None = None
    scan_only: bool = False
    streaming: bool = True
    workers: int = 1
    output: str | None = None
    keep_artifacts: bool = False


@dataclass(frozen=True)
class OriginalRuleAssociation:
    path: Path | None = None
    error: str | None = None
    failure_category: str | None = None


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


def _common_path_suffix_length(left: Path, right: Path) -> int:
    """Return the number of identical trailing path components."""
    count = 0
    for left_part, right_part in zip(reversed(left.parts), reversed(right.parts)):
        if left_part != right_part:
            break
        count += 1
    return count


def _associate_original_rules(
    rule_paths: list[Path], original_paths: list[Path]
) -> dict[Path, OriginalRuleAssociation]:
    """Associate normalized inputs with originals by path suffix and rule name."""
    original_names: dict[Path, str | None] = {}
    for original_path in original_paths:
        try:
            original_names[original_path] = _extract_first_rule_name(
                original_path.read_text(errors="replace")
            )
        except OSError:
            original_names[original_path] = None

    associations: dict[Path, OriginalRuleAssociation] = {}
    for rule_path in rule_paths:
        try:
            rule_name = _extract_first_rule_name(
                rule_path.read_text(errors="replace")
            )
        except OSError:
            rule_name = None

        path_candidates = [
            (candidate, _common_path_suffix_length(rule_path, candidate))
            for candidate in original_paths
            if candidate.name == rule_path.name
            and _common_path_suffix_length(rule_path, candidate) >= 2
        ]
        if not path_candidates:
            associations[rule_path] = OriginalRuleAssociation(
                error=(
                    f"No original rule matches the path suffix for {rule_path}"
                ),
                failure_category="original_rule_not_found",
            )
            continue

        named_candidates = [
            (candidate, score)
            for candidate, score in path_candidates
            if rule_name is not None and original_names[candidate] == rule_name
        ]
        if not named_candidates:
            associations[rule_path] = OriginalRuleAssociation(
                error=(
                    f"Original path candidates for {rule_path} do not contain "
                    f"the public rule {rule_name!r}"
                ),
                failure_category="original_rule_name_mismatch",
            )
            continue

        best_score = max(score for _candidate, score in named_candidates)
        best = [
            candidate for candidate, score in named_candidates if score == best_score
        ]
        if len(best) != 1:
            candidates = ", ".join(str(path) for path in best)
            associations[rule_path] = OriginalRuleAssociation(
                error=f"Ambiguous original rule for {rule_path}: {candidates}",
                failure_category="original_rule_ambiguous",
            )
            continue
        associations[rule_path] = OriginalRuleAssociation(path=best[0])

    return associations


# ---------------------------------------------------------------------------
# YARA scan helper
# ---------------------------------------------------------------------------

def _yara_scan(
    rule_path: Path, binary: Path, identifier: str | None = None
) -> tuple[int, str, str]:
    """Run ``yara <rule_path> <binary>`` and return (returncode, stdout, stderr)."""
    command = ["yara"]
    if identifier is not None:
        command.extend(["-i", identifier])
    command.extend([str(rule_path), str(binary)])
    result = subprocess.run(
        command,
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


def _execution_provenance(final_state: dict | None) -> dict:
    """Return model-use provenance recorded by the completed graph path."""
    state = final_state or {}
    if "needs_normalization" not in state:
        normalization_source = "not_reached"
    elif state["needs_normalization"]:
        normalization_source = "llm"
    else:
        normalization_source = "not_needed"

    strings_source = state.get("strings_extraction_source", "not_reached")
    constants_source = state.get("constants_extraction_source", "not_reached")
    return {
        "normalization_source": normalization_source,
        "strings_extraction_source": strings_source,
        "constants_extraction_source": constants_source,
        "llm_used": normalization_source == "llm"
        or strings_source == "llm_fallback"
        or constants_source == "llm_fallback",
    }


def _run_one(
    rule_path: Path,
    eval_cfg: EvalConfig,
    original_association: OriginalRuleAssociation | None = None,
) -> EvalResult:
    """Run the full aray pipeline on *rule_path* and return an EvalResult."""
    import time

    rule_text = ""
    try:
        rule_text = rule_path.read_text(errors="replace")
    except OSError:
        pass
    normalize_model = eval_cfg.normalize_model or eval_cfg.model
    extract_model = eval_cfg.extract_model or eval_cfg.model
    validation_source: Literal["normalized", "original"] = (
        "original" if eval_cfg.validate_original else "normalized"
    )
    try:
        rule_name = _extract_first_rule_name(rule_text)
    except Exception as exc:  # noqa: BLE001
        return EvalResult(
            rule_path=str(rule_path),
            rule_name=None,
            status="failed",
            error=str(exc),
            duration_seconds=0.0,
            yara_stdout=None,
            yara_returncode=None,
            normalize_model=normalize_model,
            extract_model=extract_model,
            validation_source=validation_source,
        )

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
            validation_source=validation_source,
        )
    if rule_name is None:
        return EvalResult(
            rule_path=str(rule_path),
            rule_name=None,
            status="skipped",
            error="YARA source contains no non-private rule",
            duration_seconds=0.0,
            yara_stdout=None,
            yara_returncode=None,
            normalize_model=normalize_model,
            extract_model=extract_model,
            validation_source=validation_source,
        )

    original_rule_path: Path | None = None
    original_rule_text: str | None = None
    if eval_cfg.validate_original:
        association = original_association or OriginalRuleAssociation(
            error=f"No original rule association was provided for {rule_path}",
            failure_category="original_rule_not_found",
        )
        if association.error or association.path is None:
            return EvalResult(
                rule_path=str(rule_path),
                rule_name=rule_name,
                status="failed",
                error=association.error,
                duration_seconds=0.0,
                yara_stdout=None,
                yara_returncode=None,
                normalize_model=normalize_model,
                extract_model=extract_model,
                disposition="validation_rule_unavailable",
                failure_category=association.failure_category,
                validation_source=validation_source,
            )
        original_rule_path = association.path
        try:
            selected_original = select_yara_file(original_rule_path)
        except Exception as exc:  # noqa: BLE001
            return EvalResult(
                rule_path=str(rule_path),
                rule_name=rule_name,
                status="failed",
                error=f"Unable to select original rule {original_rule_path}: {exc}",
                duration_seconds=0.0,
                yara_stdout=None,
                yara_returncode=None,
                normalize_model=normalize_model,
                extract_model=extract_model,
                disposition="validation_rule_unavailable",
                failure_category="original_rule_invalid",
                validation_source=validation_source,
                validation_rule_path=str(original_rule_path),
            )
        if selected_original.name != rule_name:
            return EvalResult(
                rule_path=str(rule_path),
                rule_name=rule_name,
                status="failed",
                error=(
                    f"Original rule name mismatch for {original_rule_path}: "
                    f"expected {rule_name!r}, got {selected_original.name!r}"
                ),
                duration_seconds=0.0,
                yara_stdout=None,
                yara_returncode=None,
                normalize_model=normalize_model,
                extract_model=extract_model,
                disposition="validation_rule_unavailable",
                failure_category="original_rule_name_mismatch",
                validation_source=validation_source,
                validation_rule_path=str(original_rule_path),
            )
        original_rule_text = selected_original.text

    tmpdir = Path(tempfile.mkdtemp(prefix="aray_eval_"))
    linux_dir = tmpdir / "linux"
    windows_dir = tmpdir / "windows"
    generic_dir = tmpdir / "generic"

    t0 = time.monotonic()
    final_state = None
    validation_fields = {
        "validation_source": validation_source,
        "validation_rule_path": (
            str(original_rule_path) if original_rule_path is not None else None
        ),
    }
    try:
        base_url = eval_cfg.base_url
        normalize_base_url = eval_cfg.normalize_base_url or base_url
        extract_base_url = eval_cfg.extract_base_url or base_url

        pipeline_cfg = PipelineConfig(
            normalize=LLMNodeConfig(
                model=normalize_model, base_url=normalize_base_url, api_key=eval_cfg.normalize_api_key,
                streaming=eval_cfg.normalize_streaming,
                reasoning_effort=eval_cfg.normalize_reasoning_effort,
            ),
            extract=LLMNodeConfig(
                model=extract_model, base_url=extract_base_url, api_key=eval_cfg.extract_api_key,
                streaming=eval_cfg.extract_streaming,
                reasoning_effort=eval_cfg.extract_reasoning_effort,
            ),
            use_structured_output=eval_cfg.use_structured_output,
            scan_only=eval_cfg.scan_only,
            streaming=eval_cfg.streaming,
        )

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
                disposition="normalization_failed",
                failure_category="normalization",
                **_execution_provenance(final_state),
                **validation_fields,
            )

        construction_error = (final_state or {}).get("construction_error")
        if construction_error:
            duration = time.monotonic() - t0
            disposition = (final_state or {}).get("constructibility") or "construction_failed"
            return EvalResult(
                rule_path=str(rule_path),
                rule_name=rule_name,
                status="failed",
                error=construction_error,
                duration_seconds=round(duration, 3),
                yara_stdout=None,
                yara_returncode=None,
                normalize_model=normalize_model,
                extract_model=extract_model,
                normalize_verdict=(final_state or {}).get("judge_verdict") or None,
                normalize_reason=(final_state or {}).get("judge_reason") or None,
                disposition=disposition,
                failure_category=(final_state or {}).get("constructibility_code"),
                **_execution_provenance(final_state),
                **validation_fields,
            )

        # Detect the produced binary and its generated normalized rule.
        binary: Path | None = None
        normalized_scan_rule: Path | None = None
        if (windows_dir / "app.exe").exists():
            binary = windows_dir / "app.exe"
            normalized_scan_rule = windows_dir / "normalized_rule.yar"
        elif (linux_dir / "app").exists():
            binary = linux_dir / "app"
            normalized_scan_rule = linux_dir / "normalized_rule.yar"
        else:
            # Generic artifact — find the first output.* file written by write_generic
            for f in sorted(generic_dir.glob("output*")):
                if f.is_file():
                    binary = f
                    break
            if binary is not None:
                normalized_scan_rule = generic_dir / "normalized_rule.yar"

        if binary is None:
            raise FileNotFoundError("No binary produced by pipeline")
        if normalized_scan_rule is None or not normalized_scan_rule.exists():
            raise FileNotFoundError("No normalized rule produced by pipeline")

        scan_rule = normalized_scan_rule
        identifier = None
        if original_rule_text is not None:
            scan_rule = tmpdir / "original_rule.yar"
            scan_rule.write_text(original_rule_text)
            identifier = rule_name

        if identifier is None:
            rc, stdout, stderr = _yara_scan(scan_rule, binary)
        else:
            rc, stdout, stderr = _yara_scan(scan_rule, binary, identifier)
        passed = rc == 0 and _has_yara_match(stdout)
        original_scan_error = validation_source == "original" and rc != 0
        duration = time.monotonic() - t0
        return EvalResult(
            rule_path=str(rule_path),
            rule_name=rule_name,
            status="passed" if passed else "failed",
            error=(
                None
                if passed
                else f"YARA mismatch: rc={rc} stdout={stdout!r} stderr={stderr!r}"
            ),
            duration_seconds=round(duration, 3),
            yara_stdout=stdout,
            yara_returncode=rc,
            normalize_model=normalize_model,
            extract_model=extract_model,
            normalize_verdict=(final_state or {}).get("judge_verdict") or None,
            normalize_reason=(final_state or {}).get("judge_reason") or None,
            disposition=(
                "matched"
                if passed
                else (
                    "validation_rule_unavailable"
                    if original_scan_error
                    else "unexplained_mismatch"
                )
            ),
            failure_category=(
                None
                if passed
                else (
                    "original_rule_scan_error"
                    if original_scan_error
                    else "yara_mismatch"
                )
            ),
            **_execution_provenance(final_state),
            **validation_fields,
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
            disposition="construction_failed",
            failure_category="pipeline_exception",
            **_execution_provenance(final_state),
            **validation_fields,
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
    associations: dict[Path, OriginalRuleAssociation] = {}
    if eval_cfg.validate_original:
        original_paths = list(
            dict.fromkeys(_find_yar_files(eval_cfg.original_directories))
        )
        associations = _associate_original_rules(rule_paths, original_paths)

    def _process(idx: int, rp: Path) -> EvalResult:
        association = associations.get(rp)
        oracle = "original" if eval_cfg.validate_original else "normalized"
        source = (
            str(association.path)
            if association is not None and association.path is not None
            else ("<unavailable>" if eval_cfg.validate_original else str(rp))
        )
        print(
            f"[{idx}/{total}] oracle={oracle} normalized={rp} source={source}",
            file=sys.stderr,
            flush=True,
        )
        result = _run_one(rp, eval_cfg, association)
        print(
            f"[{idx}/{total}] {rp} → {result.status}",
            file=sys.stderr,
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
                "normalize_reasoning_effort": eval_cfg.normalize_reasoning_effort,
                "extract_reasoning_effort": eval_cfg.extract_reasoning_effort,
                "use_structured_output": eval_cfg.use_structured_output,
                "scan_only": eval_cfg.scan_only,
                "validate_original": eval_cfg.validate_original,
                "original_directories": eval_cfg.original_directories,
                "workers": eval_cfg.workers,
            },
        },
        "results": [r.to_dict() for r in results],
        "summary": {
            "disposition_counts": dict(Counter(r.disposition or "unknown" for r in results)),
            "failure_categories": dict(
                Counter(r.failure_category for r in results if r.failure_category)
            ),
            "processing_paths": {
                "normalization": dict(Counter(r.normalization_source for r in results)),
                "strings_extraction": dict(
                    Counter(r.strings_extraction_source for r in results)
                ),
                "constants_extraction": dict(
                    Counter(r.constants_extraction_source for r in results)
                ),
            },
            "llm_usage": {
                "rules_using_llm": sum(r.llm_used for r in results),
                "rules_without_llm": sum(not r.llm_used for r in results),
            },
        },
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
    if args.original_directories:
        original_directories = list(args.original_directories)
    else:
        original_directories = ev.get("original_directories", [])

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
    normalize_reasoning_effort: str | None = (
        args.normalize_reasoning_effort
        or args.reasoning_effort
        or ev.get("normalize_reasoning_effort")
        or ev.get("reasoning_effort")
        or os.getenv("NORMALIZE_REASONING_EFFORT")
        or os.getenv("OPENAI_REASONING_EFFORT")
        or None
    )
    extract_reasoning_effort: str | None = (
        args.extract_reasoning_effort
        or args.reasoning_effort
        or ev.get("extract_reasoning_effort")
        or ev.get("reasoning_effort")
        or os.getenv("EXTRACT_REASONING_EFFORT")
        or os.getenv("OPENAI_REASONING_EFFORT")
        or None
    )

    # Boolean / integer flags: CLI > config file > default
    scan_only = args.scan_only or ev.get("scan_only", False)
    validate_original = (
        args.validate_original
        if args.validate_original is not None
        else ev.get("validate_original", False)
    )
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
        original_directories=original_directories,
        validate_original=validate_original,
        model=default_model,
        normalize_model=normalize_model,
        extract_model=extract_model,
        base_url=base_url,
        normalize_base_url=normalize_base_url,
        extract_base_url=extract_base_url,
        normalize_api_key=normalize_api_key,
        extract_api_key=extract_api_key,
        normalize_reasoning_effort=normalize_reasoning_effort,
        extract_reasoning_effort=extract_reasoning_effort,
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
        "--validate-original",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Validate each artifact with its associated original rule; "
            "--no-validate-original overrides an enabled config value."
        ),
    )
    parser.add_argument(
        "--original-directory",
        action="append",
        dest="original_directories",
        default=None,
        metavar="PATH",
        help=(
            "Original YARA corpus directory. Repeat to provide multiple roots; "
            "overrides original_directories in the config file."
        ),
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
        "--reasoning-effort",
        choices=("none", "low", "medium", "high", "max"),
        default=None,
        help="Reasoning effort for all LLM roles when supported by the provider.",
    )
    parser.add_argument(
        "--normalize-reasoning-effort",
        choices=("none", "low", "medium", "high", "max"),
        default=None,
        help="Reasoning effort for the normalize/judge nodes.",
    )
    parser.add_argument(
        "--extract-reasoning-effort",
        choices=("none", "low", "medium", "high", "max"),
        default=None,
        help="Reasoning effort for the extract nodes.",
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
    return parser.parse_args(sys.argv[1:] if argv is None else argv)


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
    if eval_cfg.validate_original:
        roots = ", ".join(eval_cfg.original_directories) or "none configured"
        print(f"Validation oracle: original rules ({roots})")
    else:
        print("Validation oracle: normalized rules")
    results = run_evaluation(rule_paths, eval_cfg)
    _write_report(results, eval_cfg, run_ts)
    _print_summary(results)
