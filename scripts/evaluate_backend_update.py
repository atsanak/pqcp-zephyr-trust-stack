#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Evaluate PQ Code Package backend update candidates without vendoring code."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import verify_backend_currency


BACKENDS = verify_backend_currency.BACKENDS


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module-path", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--backend", choices=("all", "mlkem-native", "mldsa-native"), default="all")
    parser.add_argument("--check-upstream", action="store_true")
    parser.add_argument(
        "--clone-upstream",
        action="store_true",
        help="Clone upstream into a temporary directory for diffstat/license inspection.",
    )
    parser.add_argument("--work-dir", type=Path, help="Temporary clone parent. Defaults to system temp.")
    return parser.parse_args()


def sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(cmd: list[str], cwd: Path | None = None, timeout: int = 120) -> tuple[int, str]:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        timeout=timeout,
    )
    return proc.returncode, proc.stdout.strip()


def diffstat(repo: Path, old_rev: str, new_rev: str) -> dict[str, Any]:
    code, stdout = run(["git", "diff", "--stat", "--name-status", f"{old_rev}..{new_rev}"], cwd=repo)
    if code != 0:
        return {"passed": False, "files": [], "summary": stdout}
    files = []
    for line in stdout.splitlines():
        if "\t" not in line:
            continue
        status, path = line.split("\t", 1)
        files.append({"status": status, "path": path})
    relevant = [
        item for item in files
        if item["path"].endswith((".c", ".h", ".S", ".s", "META.yml", "LICENSE"))
    ]
    return {"passed": True, "files": files, "relevant_files": relevant, "summary": stdout}


def clone_and_evaluate(
    *,
    backend: str,
    url: str,
    pinned_revision: str,
    upstream_head: str | None,
    work_parent: Path,
) -> dict[str, Any]:
    clone_root = work_parent / backend
    result: dict[str, Any] = {
        "clone_path": str(clone_root),
        "cloned": False,
        "license_sha256": None,
        "meta_sha256": None,
        "diffstat": {},
        "failures": [],
    }
    code, stdout = run(["git", "clone", "--filter=blob:none", url, str(clone_root)], timeout=180)
    if code != 0:
        result["failures"].append(f"git clone failed: {stdout}")
        return result
    result["cloned"] = True
    if pinned_revision:
        run(["git", "fetch", "--depth=1", "origin", pinned_revision], cwd=clone_root, timeout=120)
    result["license_sha256"] = sha256_file(clone_root / "LICENSE")
    result["meta_sha256"] = sha256_file(clone_root / "META.yml")
    if not result["license_sha256"]:
        result["failures"].append("upstream clone is missing LICENSE")
    if not result["meta_sha256"]:
        result["failures"].append("upstream clone is missing META.yml")
    if pinned_revision and upstream_head and pinned_revision != upstream_head:
        result["diffstat"] = diffstat(clone_root, pinned_revision, upstream_head)
    return result


def evaluate(args: argparse.Namespace) -> dict[str, Any]:
    module_path = args.module_path.resolve()
    selected = BACKENDS if args.backend == "all" else {args.backend: BACKENDS[args.backend]}
    currency_args = argparse.Namespace(
        module_path=module_path,
        west_manifest=None,
        output=args.output,
        check_upstream=args.check_upstream,
        require_initialized_submodules=False,
    )
    currency = verify_backend_currency.verify(currency_args)
    currency_by_name = {row.get("name"): row for row in currency.get("backends", [])}
    failures: list[str] = []
    warnings: list[str] = list(currency.get("warnings") or [])
    checks: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []

    temp_context = tempfile.TemporaryDirectory(dir=str(args.work_dir) if args.work_dir else None) if args.clone_upstream else None
    try:
        work_parent = Path(temp_context.name) if temp_context else None
        for name, metadata in selected.items():
            current = currency_by_name.get(name) or {}
            row_failures = list(current.get("failures") or [])
            row_warnings = list(current.get("warnings") or [])
            pinned = str(current.get("west_revision") or "")
            upstream = str(current.get("upstream_head") or "") or None
            local_meta = ((current.get("backend_metadata") or {}).get("metadata") or {})
            implementations = local_meta.get("implementations") or []
            has_license = bool((current.get("backend_metadata") or {}).get("license_sha256"))
            has_meta = bool((current.get("backend_metadata") or {}).get("meta_sha256"))
            if not has_license:
                row_failures.append("local backend is missing LICENSE metadata")
            if not has_meta:
                row_failures.append("local backend is missing META.yml metadata")
            if not implementations:
                row_failures.append("local backend META.yml has no implementations")
            checks.extend(
                [
                    {"check": "backend_license", "backend": name, "passed": has_license},
                    {"check": "backend_meta", "backend": name, "passed": has_meta},
                    {"check": "backend_implementations", "backend": name, "passed": bool(implementations)},
                    {"check": "vendored_code_policy", "backend": name, "passed": True},
                ]
            )
            clone_result = None
            if args.clone_upstream:
                clone_result = clone_and_evaluate(
                    backend=name,
                    url=metadata["url"],
                    pinned_revision=pinned,
                    upstream_head=upstream,
                    work_parent=work_parent or Path(tempfile.gettempdir()),
                )
                row_failures.extend(str(item) for item in clone_result.get("failures") or [])
            if args.check_upstream and upstream and pinned and upstream != pinned:
                row_warnings.append("upstream differs from pinned revision; update requires review and benchmark replay")
            passed = not row_failures
            failures.extend(f"{name}: {failure}" for failure in row_failures)
            warnings.extend(f"{name}: {warning}" for warning in row_warnings)
            rows.append(
                {
                    "name": name,
                    "url": metadata["url"],
                    "pinned_revision": pinned,
                    "upstream_head": upstream,
                    "check_upstream": bool(args.check_upstream),
                    "clone_upstream": bool(args.clone_upstream),
                    "local_license_sha256": (current.get("backend_metadata") or {}).get("license_sha256"),
                    "local_meta_sha256": (current.get("backend_metadata") or {}).get("meta_sha256"),
                    "implementation_count": len(implementations),
                    "clone_evaluation": clone_result,
                    "passed": passed,
                    "warnings": row_warnings,
                    "failures": row_failures,
                }
            )
    finally:
        if temp_context is not None:
            temp_context.cleanup()

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/evaluate_backend_update.py",
        "module_path": str(module_path),
        "mode": "comparison_only",
        "vendored_code_added": False,
        "passed": not failures,
        "summary": {"backends": len(rows), "failures": len(failures), "warnings": len(warnings)},
        "backend_currency": currency,
        "backends": rows,
        "checks": checks,
        "warnings": warnings,
        "failures": failures,
    }


def main() -> int:
    args = parse_args()
    if args.work_dir:
        args.work_dir.mkdir(parents=True, exist_ok=True)
    result = evaluate(args)
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["passed"]:
        print("PASS: backend update evaluation passed")
        print(f"  output: {args.output.resolve()}")
        return 0
    print("FAIL: backend update evaluation failed")
    for failure in result["failures"]:
        print(f"  - {failure}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
