#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Analyze PQCP_CT_SAMPLE transcript markers for timing-smoke regressions."""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SAMPLE_RE = re.compile(
    r"^PQCP_CT_SAMPLE\s+alg=(?P<alg>\S+)\s+class=(?P<class>valid|invalid)\s+"
    r"idx=(?P<idx>\d+)\s+cycles=(?P<cycles>\d+)$"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transcript", type=Path, action="append", default=[])
    parser.add_argument("--transcript-dir", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest-output", type=Path)
    parser.add_argument("--min-samples", type=int, default=16)
    parser.add_argument("--relative-bound-percent", type=float, default=50.0)
    parser.add_argument("--t2-bound", type=float, default=10000.0)
    return parser.parse_args()


def transcript_paths(args: argparse.Namespace) -> list[Path]:
    paths = list(args.transcript)
    if args.transcript_dir:
        paths.extend(sorted(args.transcript_dir.glob("*.log")))
    return paths


def percentile(values: list[int], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil((pct / 100.0) * len(ordered)) - 1))
    return float(ordered[index])


def welch_t2(valid: list[int], invalid: list[int]) -> float:
    if len(valid) < 2 or len(invalid) < 2:
        return float("inf")
    mean_valid = statistics.fmean(valid)
    mean_invalid = statistics.fmean(invalid)
    var_valid = statistics.variance(valid)
    var_invalid = statistics.variance(invalid)
    denom = (var_valid / len(valid)) + (var_invalid / len(invalid))
    if denom == 0:
        return 0.0 if mean_valid == mean_invalid else float("inf")
    delta = mean_valid - mean_invalid
    return (delta * delta) / denom


def parse_samples(paths: list[Path]) -> tuple[dict[str, dict[str, list[dict[str, Any]]]], list[str]]:
    samples: dict[str, dict[str, list[dict[str, Any]]]] = {}
    sources: list[str] = []
    for path in paths:
        if not path.exists() or not path.is_file():
            continue
        body = path.read_text(encoding="utf-8", errors="replace")
        if "PQCP_CT_SAMPLE" in body:
            sources.append(str(path))
        for raw_line in body.splitlines():
            match = SAMPLE_RE.match(raw_line.strip())
            if not match:
                continue
            alg = match.group("alg")
            klass = match.group("class")
            idx = int(match.group("idx"))
            cycles = int(match.group("cycles"))
            samples.setdefault(alg, {"valid": [], "invalid": []})[klass].append(
                {"idx": idx, "cycles": cycles, "source": str(path)}
            )
    return samples, sources


def validate_indexes(alg: str, klass: str, rows: list[dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    indexes = [int(row["idx"]) for row in rows]
    duplicates = sorted({idx for idx in indexes if indexes.count(idx) > 1})
    if duplicates:
        failures.append(f"{alg}/{klass} has duplicate CT sample indexes: {duplicates}")
    expected = list(range(len(rows)))
    if sorted(indexes) != expected:
        failures.append(
            f"{alg}/{klass} CT sample indexes are not contiguous from 0: "
            f"observed={sorted(indexes)} expected={expected}"
        )
    return failures


def build_manifest(
    *,
    generated_at: str,
    sources: list[str],
    samples: dict[str, dict[str, list[dict[str, Any]]]],
    algorithms: list[dict[str, Any]],
) -> dict[str, Any]:
    rows = []
    by_alg = {item["algorithm"]: item for item in algorithms}
    for alg, by_class in sorted(samples.items()):
        valid = by_class.get("valid", [])
        invalid = by_class.get("invalid", [])
        rows.append(
            {
                "algorithm": alg,
                "valid_count": len(valid),
                "invalid_count": len(invalid),
                "valid_indexes": sorted(int(row["idx"]) for row in valid),
                "invalid_indexes": sorted(int(row["idx"]) for row in invalid),
                "passed": bool(by_alg.get(alg, {}).get("passed")),
                "sources": sorted({str(row["source"]) for row in [*valid, *invalid]}),
            }
        )
    return {
        "schema_version": 1,
        "generated_at": generated_at,
        "generator": "scripts/analyze_ct_samples.py",
        "sources": sources,
        "algorithms": rows,
        "summary": {
            "algorithms": len(rows),
            "total_samples": sum(row["valid_count"] + row["invalid_count"] for row in rows),
        },
    }


def analyze(args: argparse.Namespace) -> dict[str, Any]:
    failures: list[str] = []
    checks: list[dict[str, Any]] = []
    samples, sources = parse_samples(transcript_paths(args))
    if not samples:
        failures.append("no PQCP_CT_SAMPLE markers found")
    algorithms: list[dict[str, Any]] = []
    for alg, by_class in sorted(samples.items()):
        valid_rows = by_class.get("valid", [])
        invalid_rows = by_class.get("invalid", [])
        failures.extend(validate_indexes(alg, "valid", valid_rows))
        failures.extend(validate_indexes(alg, "invalid", invalid_rows))
        valid = [int(row["cycles"]) for row in valid_rows]
        invalid = [int(row["cycles"]) for row in invalid_rows]
        median_valid = float(statistics.median(valid)) if valid else 0.0
        median_invalid = float(statistics.median(invalid)) if invalid else 0.0
        lo = min(median_valid, median_invalid)
        hi = max(median_valid, median_invalid)
        rel = ((hi - lo) * 100.0 / lo) if lo > 0 else (0.0 if hi == 0 else float("inf"))
        t2 = welch_t2(valid, invalid)
        result = {
            "algorithm": alg,
            "valid_count": len(valid),
            "invalid_count": len(invalid),
            "median_valid": median_valid,
            "median_invalid": median_invalid,
            "p90_valid": percentile(valid, 90),
            "p90_invalid": percentile(invalid, 90),
            "p99_valid": percentile(valid, 99),
            "p99_invalid": percentile(invalid, 99),
            "median_delta": hi - lo,
            "relative_delta_percent": rel,
            "welch_t2": t2,
        }
        enough = len(valid) >= args.min_samples and len(invalid) >= args.min_samples
        counts_match = len(valid) == len(invalid)
        rel_ok = rel <= args.relative_bound_percent
        t_ok = t2 <= args.t2_bound or math.isfinite(t2) and t2 == 0.0
        passed = enough and counts_match and rel_ok and t_ok
        result["passed"] = passed
        checks.append({"check": "ct_samples", "algorithm": alg, "passed": passed})
        if not enough:
            failures.append(f"{alg} has insufficient CT samples")
        if not counts_match:
            failures.append(f"{alg} valid/invalid CT sample counts differ: {len(valid)} != {len(invalid)}")
        if not rel_ok:
            failures.append(f"{alg} median delta {rel:.2f}% exceeds {args.relative_bound_percent:.2f}%")
        if not t_ok:
            failures.append(f"{alg} Welch t^2 {t2:.2f} exceeds {args.t2_bound:.2f}")
        algorithms.append(result)
    generated_at = datetime.now(timezone.utc).isoformat()
    manifest = build_manifest(
        generated_at=generated_at,
        sources=sources,
        samples=samples,
        algorithms=algorithms,
    )
    return {
        "schema_version": 1,
        "generated_at": generated_at,
        "passed": not failures,
        "sources": sources,
        "summary": {"algorithms": len(algorithms), "failures": len(failures)},
        "algorithms": algorithms,
        "sample_manifest": manifest,
        "checks": checks,
        "failures": failures,
    }


def main() -> int:
    args = parse_args()
    result = analyze(args)
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.manifest_output:
        args.manifest_output.resolve().parent.mkdir(parents=True, exist_ok=True)
        args.manifest_output.resolve().write_text(
            json.dumps(result["sample_manifest"], indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if result["passed"]:
        print("PASS: CT sample analysis passed")
        print(f"  output: {args.output.resolve()}")
        return 0
    print("FAIL: CT sample analysis failed", file=sys.stderr)
    for failure in result["failures"]:
        print(f"  - {failure}", file=sys.stderr)
    print(f"  output: {args.output.resolve()}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
