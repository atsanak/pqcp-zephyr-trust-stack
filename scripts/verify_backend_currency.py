#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Verify PQ Code Package backend pin currency and local submodule wiring."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
HEX_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
BACKENDS = {
    "mlkem-native": {
        "west_path": "modules/crypto/mlkem-native",
        "submodule_path": "ext/mlkem-native",
        "url": "https://github.com/pq-code-package/mlkem-native",
    },
    "mldsa-native": {
        "west_path": "modules/crypto/mldsa-native",
        "submodule_path": "ext/mldsa-native",
        "url": "https://github.com/pq-code-package/mldsa-native",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module-path", type=Path, default=REPO_ROOT)
    parser.add_argument("--west-manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--check-upstream",
        action="store_true",
        help="Query upstream HEAD with git ls-remote. Skipped by default for deterministic local release checks.",
    )
    parser.add_argument(
        "--require-initialized-submodules",
        action="store_true",
        help="Fail if ext/mlkem-native or ext/mldsa-native are not initialized git submodules.",
    )
    return parser.parse_args()


def run_git(module_path: Path, *args: str) -> tuple[int, str, str]:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(module_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def parse_west_projects(path: Path) -> dict[str, dict[str, str]]:
    projects: dict[str, dict[str, str]] = {}
    remotes: dict[str, str] = {}
    current_remote: str | None = None
    current_project: str | None = None
    current_section: str | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if stripped == "remotes:":
            current_section = "remotes"
            current_project = None
            continue
        if stripped == "projects:":
            current_section = "projects"
            current_project = None
            current_remote = None
            continue
        if stripped.startswith("- name:"):
            name = stripped.split(":", 1)[1].strip().strip("'\"")
            if current_section == "remotes":
                current_remote = name
            elif current_section == "projects":
                current_project = name
                projects[current_project] = {"name": current_project}
            continue
        if current_section == "remotes" and current_remote and stripped.startswith("url-base:"):
            remotes[current_remote] = stripped.split(":", 1)[1].strip().strip("'\"")
            continue
        if current_section == "projects" and current_project and ":" in stripped:
            key, value = stripped.split(":", 1)
            projects[current_project][key.strip()] = value.strip().strip("'\"")
    for project in projects.values():
        remote = project.get("remote")
        if remote and remote in remotes:
            project["remote_url_base"] = remotes[remote]
            project["url"] = f"{remotes[remote].rstrip('/')}/{project['name']}"
    return projects


def parse_gitmodules(path: Path) -> dict[str, dict[str, str]]:
    modules: dict[str, dict[str, str]] = {}
    current: str | None = None
    if not path.exists():
        return modules
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if stripped.startswith("[submodule "):
            current = stripped.split('"', 2)[1]
            modules[current] = {"name": current}
            continue
        if current and "=" in stripped:
            key, value = stripped.split("=", 1)
            modules[current][key.strip()] = value.strip()
    return modules


def parse_submodule_status(module_path: Path) -> dict[str, dict[str, str]]:
    code, stdout, _stderr = run_git(module_path, "submodule", "status", "--recursive")
    if code != 0:
        return {}
    status: dict[str, dict[str, str]] = {}
    for line in stdout.splitlines():
        if not line:
            continue
        state = line[0]
        parts = line[1:].split()
        if len(parts) < 2:
            continue
        status[parts[1]] = {"state": state, "sha": parts[0]}
    return status


def local_head(module_path: Path, path: str) -> str | None:
    repo = module_path / path
    if not (repo / ".git").exists():
        return None
    code, stdout, _stderr = run_git(repo, "rev-parse", "HEAD")
    return stdout if code == 0 and HEX_SHA_RE.fullmatch(stdout) else None


def upstream_head(url: str) -> str | None:
    proc = subprocess.run(
        ["git", "ls-remote", url, "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
        timeout=30,
    )
    if proc.returncode != 0:
        return None
    fields = proc.stdout.strip().split()
    return fields[0] if fields and HEX_SHA_RE.fullmatch(fields[0]) else None


def verify(args: argparse.Namespace) -> dict[str, Any]:
    module_path = args.module_path.resolve()
    west_path = (args.west_manifest or module_path / "west.yml").resolve()
    gitmodules_path = module_path / ".gitmodules"
    west_projects = parse_west_projects(west_path)
    gitmodules = parse_gitmodules(gitmodules_path)
    submodules = parse_submodule_status(module_path)
    is_git_repo = (module_path / ".git").exists()
    failures: list[str] = []
    warnings: list[str] = []
    backend_rows: list[dict[str, Any]] = []

    for name, expected in BACKENDS.items():
        project = west_projects.get(name) or {}
        gitmodule = gitmodules.get(expected["submodule_path"]) or {}
        status = submodules.get(expected["submodule_path"]) or {}
        revision = str(project.get("revision") or "")
        submodule_sha = status.get("sha")
        state = status.get("state", "missing")
        checked_out_head = local_head(module_path, expected["submodule_path"])
        upstream = upstream_head(expected["url"]) if args.check_upstream else None

        row_failures: list[str] = []
        row_warnings: list[str] = []
        if not project:
            row_failures.append("missing from west.yml")
        if revision and not HEX_SHA_RE.fullmatch(revision):
            row_failures.append("west.yml revision is not a pinned 40-character SHA")
        if project.get("path") != expected["west_path"]:
            row_failures.append(
                f"west.yml path {project.get('path')!r} != expected {expected['west_path']!r}"
            )
        if project.get("url") and project.get("url") != expected["url"]:
            row_failures.append(f"west.yml URL {project.get('url')!r} != expected {expected['url']!r}")
        if not gitmodule:
            row_failures.append("missing from .gitmodules")
        else:
            if gitmodule.get("path") != expected["submodule_path"]:
                row_failures.append(
                    f".gitmodules path {gitmodule.get('path')!r} != expected {expected['submodule_path']!r}"
                )
            if gitmodule.get("url") != expected["url"]:
                row_failures.append(f".gitmodules URL {gitmodule.get('url')!r} != expected {expected['url']!r}")
        if submodule_sha and revision and submodule_sha != revision:
            row_failures.append(f"submodule status SHA {submodule_sha} != west.yml revision {revision}")
        if state == "-":
            message = "submodule is present in metadata but not initialized in ext/"
            if args.require_initialized_submodules:
                row_failures.append(message)
            else:
                row_warnings.append(message)
        elif state == "missing" and is_git_repo:
            row_failures.append("submodule status entry is missing")
        elif state == "missing":
            row_warnings.append("submodule status unavailable outside a git checkout")
        if checked_out_head and revision and checked_out_head != revision:
            row_failures.append(f"checked-out HEAD {checked_out_head} != west.yml revision {revision}")
        if args.check_upstream and upstream is None:
            row_warnings.append("upstream HEAD could not be resolved")
        if args.check_upstream and upstream and revision and upstream != revision:
            row_warnings.append(
                f"upstream HEAD {upstream} differs from pinned revision {revision}; "
                "review backend release notes before updating"
            )

        failures.extend(f"{name}: {failure}" for failure in row_failures)
        warnings.extend(f"{name}: {warning}" for warning in row_warnings)
        backend_rows.append(
            {
                "name": name,
                "expected_url": expected["url"],
                "west_path": project.get("path"),
                "submodule_path": expected["submodule_path"],
                "west_revision": revision,
                "submodule_status_sha": submodule_sha,
                "submodule_state": state,
                "checked_out_head": checked_out_head,
                "upstream_head": upstream,
                "upstream_checked": bool(args.check_upstream),
                "upstream_matches_pin": bool(upstream and revision and upstream == revision),
                "release_or_tag_metadata": "not queried",
                "passed": not row_failures,
                "warnings": row_warnings,
                "failures": row_failures,
            }
        )

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/verify_backend_currency.py",
        "module_path": str(module_path),
        "west_manifest": str(west_path),
        "check_upstream": bool(args.check_upstream),
        "require_initialized_submodules": bool(args.require_initialized_submodules),
        "passed": not failures,
        "summary": {
            "backends": len(backend_rows),
            "failures": len(failures),
            "warnings": len(warnings),
        },
        "backends": backend_rows,
        "warnings": warnings,
        "failures": failures,
    }


def main() -> int:
    args = parse_args()
    try:
        result = verify(args)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        result = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator": "scripts/verify_backend_currency.py",
            "passed": False,
            "summary": {"backends": 0, "failures": 1, "warnings": 0},
            "backends": [],
            "warnings": [],
            "failures": [str(exc)],
        }
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result.get("passed"):
        print("PASS: backend currency verification passed")
        print(f"  output: {args.output.resolve()}")
        return 0
    print("FAIL: backend currency verification failed", file=sys.stderr)
    for failure in result.get("failures", []):
        print(f"  - {failure}", file=sys.stderr)
    print(f"  output: {args.output.resolve()}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
