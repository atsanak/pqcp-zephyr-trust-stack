#!/usr/bin/env python3
"""
Export PQCP benchmark matrix results into a publication-friendly CSV.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shlex
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

HOST_ENV_BLACKLIST = (
    "CFLAGS",
    "CXXFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "CPATH",
    "SDKROOT",
)

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_MATRIX = REPO_ROOT / "scripts" / "cost_of_assurance_matrix.json"
DEFAULT_OUTPUT = REPO_ROOT / "results" / "benchmark_results.csv"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the cost-of-assurance matrix and export benchmark CSV results."
    )
    parser.add_argument(
        "--matrix",
        type=Path,
        default=DEFAULT_MATRIX,
        help="Matrix JSON to execute (default: scripts/cost_of_assurance_matrix.json)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output CSV path (default: results/benchmark_results.csv)",
    )
    parser.add_argument(
        "--platform",
        default="qemu_x86_64",
        help="Board/platform to export (default: qemu_x86_64)",
    )
    parser.add_argument("--west-root", type=Path, help="Zephyr workspace root")
    parser.add_argument("--module-path", type=Path, help="PQCP module path")
    parser.add_argument("--west", help="Explicit west binary or command")
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="Run only the first three runnable matrix entries for pipeline smoke checks",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Echo commands")
    return parser.parse_args()


def detect_west_root(start: Path) -> Path:
    current = start.resolve()
    while current != current.parent:
        if (current / ".west").exists():
            return current
        current = current.parent
    return start.resolve()


def discover_west(explicit: Optional[str], west_root: Path, module_path: Path) -> List[str]:
    candidates: List[List[str]] = []

    if explicit:
        candidates.append(shlex.split(explicit))

    path_west = shutil_which("west")
    if path_west:
        candidates.append([path_west])

    for candidate in (
        west_root / ".venv/bin/west",
        module_path / ".venv/bin/west",
    ):
        if candidate.exists():
            candidates.append([str(candidate)])

    candidates.append([sys.executable, "-m", "west"])

    seen = set()
    for command in candidates:
        key = tuple(command)
        if key in seen:
            continue
        seen.add(key)
        try:
            result = subprocess.run(
                command + ["--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=10,
                check=False,
            )
        except OSError:
            continue
        if result.returncode == 0:
            return command

    raise RuntimeError("Unable to find a working west command")


def shutil_which(name: str) -> Optional[str]:
    for path_dir in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(path_dir) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def build_env() -> Dict[str, str]:
    env = os.environ.copy()
    for key in HOST_ENV_BLACKLIST:
        env.pop(key, None)
    return env


def load_matrix(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text())
    return list(data.get("runs", []))


def entry_is_runnable(entry: Dict[str, Any]) -> bool:
    run_mode = entry.get("run_mode")
    if run_mode is not None:
        return str(run_mode).strip().lower().replace("-", "_") == "run"
    if entry.get("build_only"):
        return False
    if "run" in entry or "build" in entry:
        run_enabled = bool(entry.get("run"))
        build_enabled = bool(entry.get("build"))
        if run_enabled:
            return True
        if build_enabled:
            return False
    return True


def select_entries(
    entries: Iterable[Dict[str, Any]],
    *,
    platform: str,
    smoke: bool,
) -> List[Dict[str, Any]]:
    runnable = [
        entry
        for entry in entries
        if entry.get("board") == platform and entry_is_runnable(entry)
    ]
    if smoke:
        return runnable[:3]
    return runnable


def run_matrix(
    matrix_entries: List[Dict[str, Any]],
    *,
    matrix_path: Path,
    output_dir: Path,
    west_root: Path,
    module_path: Path,
    west_cmd: List[str],
    verbose: bool,
) -> None:
    filtered_config = {"runs": matrix_entries}
    filtered_path = output_dir / "filtered_matrix.json"
    filtered_path.write_text(json.dumps(filtered_config, indent=2) + "\n")

    cmd = [
        sys.executable,
        str(module_path / "scripts" / "run_benchmarks.py"),
        "--config",
        str(filtered_path),
        "--output",
        str(output_dir),
        "--west-root",
        str(west_root),
        "--module-path",
        str(module_path),
        "--west",
        " ".join(west_cmd),
    ]
    if verbose:
        print("[export] Running matrix command:")
        print("         " + " ".join(shlex.quote(part) for part in cmd))

    result = subprocess.run(
        cmd,
        cwd=str(module_path),
        env=build_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
    if result.returncode != 0:
        raise RuntimeError(
            f"run_benchmarks.py exited with {result.returncode}"
        )


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def canonical_algorithm_name(name: str, level: int) -> str:
    mapping = {
        "MLKEM": "ML-KEM",
        "MLDSA": "ML-DSA",
    }
    base = mapping.get(name, name)
    return f"{base}-{level}" if level > 0 else base


def protocol_parameter_sets(
    metric_rows: Iterable[Dict[str, Any]],
) -> Dict[str, str]:
    suites: Dict[str, Dict[str, str]] = defaultdict(dict)
    for row in metric_rows:
        if row.get("component") != "protocol":
            continue
        operation = row.get("operation")
        algorithm = str(row.get("algorithm", ""))
        level = int(row.get("level", 0))
        if operation == "auth" and level > 0:
            suites[row["run_id"]]["sig"] = canonical_algorithm_name(algorithm, level)
        elif operation == "key_exchange" and level > 0:
            suites[row["run_id"]]["kem"] = canonical_algorithm_name(algorithm, level)

    resolved: Dict[str, str] = {}
    for run_id, parts in suites.items():
        kem = parts.get("kem")
        sig = parts.get("sig")
        if kem and sig:
            resolved[run_id] = f"{kem} + {sig}"
        elif kem:
            resolved[run_id] = kem
        elif sig:
            resolved[run_id] = sig
    return resolved


def normalize_operation(operation: str, metric: str) -> str:
    if metric in {"cycles", "time"}:
        return operation
    return f"{operation}_{metric}"


def to_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def export_rows(
    metric_rows: List[Dict[str, Any]],
    runs: List[Dict[str, Any]],
    *,
    platform: str,
) -> List[Dict[str, Any]]:
    run_lookup = {row["run_id"]: row for row in runs}
    protocol_sets = protocol_parameter_sets(metric_rows)
    exported: List[Dict[str, Any]] = []

    for row in metric_rows:
        if row.get("board") != platform:
            continue

        run_id = row["run_id"]
        run = run_lookup.get(run_id)
        if run is None:
            continue

        component = row.get("component")
        metric = str(row.get("metric", ""))
        unit = str(row.get("unit", ""))
        cycles = None
        time_us = None

        if unit == "cyc" or metric == "cycles":
            cycles = to_int(row.get("value"))
        elif unit == "us":
            time_us = to_int(row.get("value"))
        elif unit == "ms":
            raw = to_int(row.get("value"))
            time_us = raw * 1000 if raw is not None else None
        else:
            continue

        if cycles is None and time_us is None:
            continue

        if component == "protocol":
            suite = str(row.get("algorithm", "TLS13"))
            parameter_set = protocol_sets.get(run_id, str(run.get("sample", "")))
        else:
            suite = canonical_algorithm_name(str(row.get("algorithm", "")), 0)
            parameter_set = canonical_algorithm_name(
                str(row.get("algorithm", "")),
                int(row.get("level", 0)),
            )

        exported.append(
            {
                "suite": suite,
                "parameter_set": parameter_set,
                "implementation": run["implementation"],
                "backend": run["backend"],
                "operation": normalize_operation(str(row.get("operation", "")), metric),
                "cycles": cycles if cycles is not None else "",
                "time_us": time_us if time_us is not None else "",
                "rom_bytes": run.get("rom_bytes", ""),
                "ram_bytes": run.get("ram_bytes", ""),
                "platform": platform,
                "timestamp": row.get("timestamp", ""),
            }
        )

    return exported


def write_csv(rows: List[Dict[str, Any]], output_path: Path) -> None:
    fieldnames = [
        "suite",
        "parameter_set",
        "implementation",
        "backend",
        "operation",
        "cycles",
        "time_us",
        "rom_bytes",
        "ram_bytes",
        "platform",
        "timestamp",
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def metric_value_for_summary(row: Dict[str, Any]) -> Tuple[Optional[int], str]:
    cycles = to_int(row.get("cycles"))
    if cycles is not None:
        return cycles, "cycles"
    time_us = to_int(row.get("time_us"))
    if time_us is not None:
        return time_us, "us"
    return None, ""


def write_summary(rows: List[Dict[str, Any]], summary_path: Path) -> None:
    grouped: Dict[Tuple[str, str, str], Dict[str, Dict[str, Any]]] = defaultdict(dict)
    for row in rows:
        key = (row["suite"], row["parameter_set"], row["operation"])
        grouped[key][f"{row['implementation']}:{row['backend']}"] = row

    lines = [
        "# Benchmark Summary",
        "",
        "| Suite | Parameter Set | Operation | Metric | PQCP | Baseline | Overhead |",
        "|---|---|---|---|---:|---:|---:|",
    ]

    comparison_rows = 0
    for key in sorted(grouped):
        variants = grouped[key]
        pqcp_row = variants.get("pqcp:auto")
        baseline_row = variants.get("baseline:clean")
        if pqcp_row is None or baseline_row is None:
            continue

        pqcp_value, metric_unit = metric_value_for_summary(pqcp_row)
        baseline_value, baseline_unit = metric_value_for_summary(baseline_row)
        if pqcp_value is None or baseline_value is None:
            continue
        if metric_unit != baseline_unit or baseline_value == 0:
            continue

        overhead_pct = ((pqcp_value - baseline_value) / baseline_value) * 100.0
        suite, parameter_set, operation = key
        lines.append(
            f"| {suite} | {parameter_set} | {operation} | {metric_unit} | "
            f"{pqcp_value} | {baseline_value} | {overhead_pct:+.2f}% |"
        )
        comparison_rows += 1

    if comparison_rows == 0:
        lines.extend(
            [
                "",
                "No PQCP-vs-baseline comparison rows were present in this export slice.",
            ]
        )

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text("\n".join(lines) + "\n")


def validate_output(rows: List[Dict[str, Any]], output_path: Path) -> None:
    if not rows:
        raise RuntimeError("benchmark export produced no timing rows")
    header = output_path.read_text().splitlines()[0].strip()
    expected = "suite,parameter_set,implementation,backend,operation,cycles,time_us,rom_bytes,ram_bytes,platform,timestamp"
    if header != expected:
        raise RuntimeError(
            f"benchmark export CSV header mismatch: got '{header}', expected '{expected}'"
        )


def main() -> int:
    args = parse_args()
    module_path = args.module_path.resolve() if args.module_path else REPO_ROOT
    west_root = args.west_root.resolve() if args.west_root else detect_west_root(module_path)
    matrix_path = args.matrix.resolve()
    output_path = args.output.resolve()
    summary_path = output_path.with_name("benchmark_summary.md")
    west_cmd = discover_west(args.west, west_root, module_path)

    matrix_entries = select_entries(
        load_matrix(matrix_path),
        platform=args.platform,
        smoke=args.smoke,
    )
    if not matrix_entries:
        raise RuntimeError(
            f"No runnable matrix entries found for platform '{args.platform}'"
        )

    with tempfile.TemporaryDirectory(prefix="pqcp-export-results-") as tmpdir:
        run_output = Path(tmpdir) / "benchmark_run"
        run_output.mkdir(parents=True, exist_ok=True)
        run_matrix(
            matrix_entries,
            matrix_path=matrix_path,
            output_dir=run_output,
            west_root=west_root,
            module_path=module_path,
            west_cmd=west_cmd,
            verbose=args.verbose,
        )

        metric_rows = load_json(run_output / "consolidated_metrics.json")
        runs = load_json(run_output / "runs.json")
        exported = export_rows(metric_rows, runs, platform=args.platform)

    write_csv(exported, output_path)
    write_summary(exported, summary_path)
    validate_output(exported, output_path)

    print(
        f"[export] Wrote {len(exported)} benchmark rows to {output_path}"
    )
    print(f"[export] Wrote summary markdown to {summary_path}")
    print(f"[export] Generated at {datetime.now(timezone.utc).isoformat()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
