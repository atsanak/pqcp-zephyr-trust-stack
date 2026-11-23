#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run controlled tamper drills against a generated release evidence pack."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_POLICY = SCRIPT_DIR / "evidence_tamper_drill_policy.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_root", type=Path, help="release_check.py output root to test")
    parser.add_argument("--module-path", type=Path, default=REPO_ROOT)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--tag", help="Expected tag passed through to verify_release_evidence_pack.py")
    parser.add_argument(
        "--verifier",
        type=Path,
        default=SCRIPT_DIR / "verify_release_evidence_pack.py",
        help="Evidence-pack verifier executable/script.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Result JSON path. Defaults to <output-root>/evidence_tamper_drill_result.json.",
    )
    parser.add_argument(
        "--keep-workdir",
        action="store_true",
        help="Keep mutated pack copies for manual debugging.",
    )
    return parser.parse_args()


def load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"{label} not found: {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{label} root must be a JSON object: {path}")
    return raw


def decode_pointer(pointer: str) -> list[str]:
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise ValueError(f"JSON pointer must start with '/': {pointer}")
    return [part.replace("~1", "/").replace("~0", "~") for part in pointer.split("/")[1:]]


def set_json_pointer(document: Any, pointer: str, value: Any) -> None:
    parts = decode_pointer(pointer)
    if not parts:
        raise ValueError("refusing to replace the entire JSON document")
    cursor = document
    for part in parts[:-1]:
        if isinstance(cursor, list):
            cursor = cursor[int(part)]
        elif isinstance(cursor, dict):
            cursor = cursor[part]
        else:
            raise ValueError(f"cannot descend through non-container at {part!r}")
    leaf = parts[-1]
    if isinstance(cursor, list):
        cursor[int(leaf)] = value
    elif isinstance(cursor, dict):
        if leaf not in cursor:
            raise KeyError(f"JSON pointer leaf does not exist: {pointer}")
        cursor[leaf] = value
    else:
        raise ValueError(f"cannot set leaf on non-container at {leaf!r}")


def mutate_artifact(pack_root: Path, scenario: dict[str, Any]) -> tuple[bool, str | None]:
    artifact = scenario.get("artifact")
    if not isinstance(artifact, str) or not artifact:
        return False, "scenario artifact must be a non-empty string"
    artifact_path = (pack_root / artifact).resolve()
    try:
        artifact_path.relative_to(pack_root.resolve())
    except ValueError:
        return False, f"scenario artifact escapes pack root: {artifact}"
    if not artifact_path.exists() or not artifact_path.is_file():
        if scenario.get("required", True):
            return False, f"required artifact not found: {artifact}"
        return True, "not_applicable"

    mutation = scenario.get("mutation")
    if not isinstance(mutation, dict):
        return False, "scenario mutation must be an object"
    mutation_type = mutation.get("type")
    if mutation_type == "append_text":
        text = mutation.get("text")
        if not isinstance(text, str):
            return False, "append_text mutation requires string text"
        with artifact_path.open("a", encoding="utf-8") as handle:
            handle.write(text)
        return True, None
    if mutation_type == "set_json_pointer":
        pointer = mutation.get("pointer")
        if not isinstance(pointer, str):
            return False, "set_json_pointer mutation requires pointer"
        payload = load_json(artifact_path, f"artifact {artifact}")
        set_json_pointer(payload, pointer, mutation.get("value"))
        artifact_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return True, None
    return False, f"unsupported mutation type: {mutation_type!r}"


def ignore_generated_build_dirs(_dir: str, names: list[str]) -> set[str]:
    ignored: set[str] = set()
    for name in names:
        if name.endswith("_qemu") or name.startswith("build") or name.endswith("_build"):
            ignored.add(name)
        elif name in {"cost_of_assurance_smoke"}:
            ignored.add(name)
    return ignored


def copy_pack(source: Path, destination: Path) -> None:
    shutil.copytree(source, destination, ignore=ignore_generated_build_dirs)


def verifier_command(args: argparse.Namespace, pack_root: Path) -> list[str]:
    command = [sys.executable, str(args.verifier), str(pack_root), "--module-path", str(args.module_path)]
    if args.tag:
        command.extend(["--tag", args.tag])
    return command


def run_verifier(args: argparse.Namespace, pack_root: Path) -> dict[str, Any]:
    command = verifier_command(args, pack_root)
    result = subprocess.run(
        command,
        cwd=str(args.module_path),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return {
        "command": command,
        "returncode": result.returncode,
        "output": result.stdout,
    }


def run_scenario(args: argparse.Namespace, scenario: dict[str, Any], work_root: Path) -> dict[str, Any]:
    scenario_id = scenario.get("id", "<unnamed>")
    pack_copy = work_root / str(scenario_id)
    copy_pack(args.output_root, pack_copy)
    mutated, mutation_error = mutate_artifact(pack_copy, scenario)
    if not mutated:
        return {
            "id": scenario_id,
            "passed": False,
            "status": "setup_failed",
            "failure_reason": mutation_error,
            "verifier_returncode": None,
            "matched_failure_fragments": [],
        }
    if mutation_error == "not_applicable":
        return {
            "id": scenario_id,
            "passed": scenario.get("required", True) is False,
            "status": "not_applicable",
            "failure_reason": None,
            "verifier_returncode": None,
            "matched_failure_fragments": [],
        }

    verifier = run_verifier(args, pack_copy)
    output = str(verifier.get("output") or "")
    expected = scenario.get("expected_failure_contains") or []
    if not isinstance(expected, list):
        expected = []
    matched = [fragment for fragment in expected if isinstance(fragment, str) and fragment in output]
    verifier_failed = verifier["returncode"] != 0
    passed = verifier_failed and len(matched) == len([item for item in expected if isinstance(item, str)])
    failure_reason = None
    if verifier["returncode"] == 0:
        failure_reason = "mutated evidence pack unexpectedly passed verification"
    elif not passed:
        failure_reason = "mutated evidence pack failed, but not with the expected failure fragment(s)"
    return {
        "id": scenario_id,
        "passed": passed,
        "status": "detected" if passed else "failed",
        "artifact": scenario.get("artifact"),
        "mutation": scenario.get("mutation"),
        "verifier_returncode": verifier["returncode"],
        "expected_failure_contains": expected,
        "matched_failure_fragments": matched,
        "failure_reason": failure_reason,
    }


def run_drill(args: argparse.Namespace) -> dict[str, Any]:
    args.output_root = args.output_root.resolve()
    args.module_path = args.module_path.resolve()
    policy = load_json(args.policy.resolve(), "tamper drill policy")
    scenarios = policy.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError("tamper drill policy must contain a non-empty scenarios list")

    base = run_verifier(args, args.output_root)
    base_passed = base["returncode"] == 0
    scenario_results: list[dict[str, Any]] = []
    workdir_path: str | None = None
    if base_passed:
        if args.keep_workdir:
            work_root = args.output_root / ".tamper_drill_work"
            if work_root.exists():
                shutil.rmtree(work_root)
            work_root.mkdir(parents=True)
            workdir_path = str(work_root)
            for scenario in scenarios:
                scenario_results.append(run_scenario(args, scenario, work_root))
        else:
            with tempfile.TemporaryDirectory(prefix="pqcp-tamper-drill-") as temp:
                work_root = Path(temp)
                for scenario in scenarios:
                    scenario_results.append(run_scenario(args, scenario, work_root))

    failures: list[str] = []
    if not base_passed:
        failures.append("base evidence pack does not pass verification")
    for scenario in scenario_results:
        if scenario.get("passed") is not True:
            failures.append(f"{scenario.get('id')}: {scenario.get('failure_reason') or scenario.get('status')}")

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/run_evidence_tamper_drill.py",
        "policy": {
            "path": str(args.policy.resolve()),
            "schema_version": policy.get("schema_version"),
            "scenario_count": len(scenarios),
        },
        "output_root": str(args.output_root),
        "workdir": workdir_path,
        "base_verification": {
            "passed": base_passed,
            "returncode": base["returncode"],
            "command": base["command"],
        },
        "summary": {
            "scenario_count": len(scenario_results),
            "detected_count": sum(1 for item in scenario_results if item.get("passed") is True),
            "failure_count": len(failures),
        },
        "passed": not failures,
        "scenarios": scenario_results,
        "failures": failures,
    }


def main() -> int:
    args = parse_args()
    output_path = args.output or (args.output_root / "evidence_tamper_drill_result.json")
    try:
        result = run_drill(args)
    except Exception as exc:  # noqa: BLE001 - command-line tool should report structured failure.
        result = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator": "scripts/run_evidence_tamper_drill.py",
            "passed": False,
            "summary": {"scenario_count": 0, "detected_count": 0, "failure_count": 1},
            "scenarios": [],
            "failures": [str(exc)],
        }
    output_path.resolve().parent.mkdir(parents=True, exist_ok=True)
    output_path.resolve().write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result.get("passed") is True:
        print("PASS: evidence tamper drill detected all configured mutations")
        print(f"  output: {output_path.resolve()}")
        return 0
    print("FAIL: evidence tamper drill found replay weakness", file=sys.stderr)
    for failure in result.get("failures", []):
        print(f"  - {failure}", file=sys.stderr)
    print(f"  output: {output_path.resolve()}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
