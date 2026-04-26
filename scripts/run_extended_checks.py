#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Developer-oriented extended checks for the PQCP Zephyr module.

This helper keeps heavier static-analysis style checks out of the fast smoke CI
while making them easy to run locally or from a scheduled/manual workflow.
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, Optional

HOST_ENV_BLACKLIST = (
    "CFLAGS",
    "CXXFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "CPATH",
    "SDKROOT",
)

DEFAULT_ANALYSIS_PATHS = [
    "include/pqcp_zephyr/acvp_cmd.h",
    "include/pqcp_zephyr/bench.h",
    "include/pqcp_zephyr/mlkem.h",
    "include/pqcp_zephyr/mldsa.h",
    "include/pqcp_zephyr/rng.h",
    "include/pqcp_zephyr/tls_selftest.h",
    "include/pqcp_zephyr/version.h",
    "src/acvp_cmd.c",
    "src/bench_primitive.c",
    "src/bench_protocol.c",
    "src/mlkem_baseline.c",
    "src/mlkem_zephyr.c",
    "src/mldsa_baseline.c",
    "src/mldsa_streaming.c",
    "src/mldsa_zephyr.c",
    "src/pqclean_randombytes.c",
    "src/rng_common.c",
    "src/rng_custom.c",
    "src/rng_deterministic.c",
    "src/rng_psa.c",
    "src/rng_zephyr_entropy.c",
    "src/psa_mlkem_driver.c",
    "src/psa_mldsa_driver.c",
    "src/tls_selftest.c",
]

DEFAULT_COMPATIBILITY_TARGETS = [
    "tests/ztest_primitive",
    "tests/ztest_acvp_serial",
    "tests/ztest_tls_selftest",
]

VERSION_STRING_RE = re.compile(r'^#define\s+PQCP_VERSION_STRING\s+"([^"]+)"$', re.MULTILINE)
CHANGELOG_VERSION_RE = re.compile(r"^## \[([0-9]+\.[0-9]+\.[0-9]+)\]", re.MULTILINE)
README_MANIFEST_REQUIRED_SNIPPETS = [
    "url: https://github.com/atsana01/pqcp-zephyr-trust-stack",
    "revision: main  # Prefer a pinned tag or commit for release integration",
    "matches both `PQCP_VERSION_STRING`",
    "top release entry in `CHANGELOG.md`",
]

DEFAULT_COST_OF_ASSURANCE_REGRESSION_FILE = Path(
    "scripts/qemu_cost_of_assurance_regression.json"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run extended PQCP developer checks")
    parser.add_argument("--west-root", type=Path, help="Zephyr workspace root")
    parser.add_argument("--module-path", type=Path, help="PQCP module path")
    parser.add_argument("--west", help="Explicit west binary or command")
    parser.add_argument("--board", default="qemu_x86_64", help="Board for graph/config checks")
    parser.add_argument(
        "--target",
        default="tests/ztest_primitive",
        help="Target application used to configure a graphviz-ready build",
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=Path("build-extended-checks"),
        help="Build directory for the graphviz/configure stage",
    )
    parser.add_argument(
        "--graphviz-out",
        type=Path,
        default=Path("benchmark_results/extended/pqcp-cmake-graph.dot"),
        help="Path for the generated CMake graphviz output",
    )
    parser.add_argument("--cppcheck", help="Explicit cppcheck binary")
    parser.add_argument(
        "--zephyr-ref",
        default=os.environ.get("ZEPHYR_REF", "unknown"),
        help="Zephyr tag/branch/commit being validated (used in reports)",
    )
    parser.add_argument("--skip-graphviz", action="store_true", help="Skip graphviz generation")
    parser.add_argument("--skip-cppcheck", action="store_true", help="Skip cppcheck analysis")
    parser.add_argument(
        "--run-compatibility-smoke",
        action="store_true",
        help="Run a small build-only Zephyr compatibility smoke on selected targets",
    )
    parser.add_argument(
        "--compatibility-board",
        default="qemu_x86_64",
        help="Board used for Zephyr compatibility smoke builds",
    )
    parser.add_argument(
        "--compatibility-board-list",
        action="append",
        dest="compatibility_boards",
        help=(
            "Optional comma-separated board list for compatibility smoke "
            "(for example: qemu_x86_64,nucleo_h743zi)"
        ),
    )
    parser.add_argument(
        "--compatibility-build-dir-root",
        type=Path,
        default=Path("benchmark_results/extended/compatibility"),
        help="Root directory for compatibility smoke build trees",
    )
    parser.add_argument(
        "--compatibility-target",
        action="append",
        dest="compatibility_targets",
        help="Additional application path to build during compatibility smoke",
    )
    parser.add_argument(
        "--run-cost-of-assurance-smoke",
        action="store_true",
        help="Run a tiny qemu_x86_64 cost-of-assurance pipeline smoke",
    )
    parser.add_argument(
        "--cost-of-assurance-output-root",
        type=Path,
        default=Path("benchmark_results/extended/cost_of_assurance_smoke"),
        help="Output directory for the cost-of-assurance smoke artifacts",
    )
    parser.add_argument(
        "--cost-of-assurance-regression-file",
        type=Path,
        default=DEFAULT_COST_OF_ASSURANCE_REGRESSION_FILE,
        help="Checked-in qemu_x86_64 cost-of-assurance regression thresholds",
    )
    parser.add_argument(
        "--run-mcu-protocol-budgets",
        action="store_true",
        help=(
            "Run the nucleo_h743zi protocol build-only footprint matrix and enforce "
            "ROM/RAM budgets. Requires a configured Zephyr ARM toolchain. Opt-in "
            "because it performs real cross-compile builds."
        ),
    )
    parser.add_argument(
        "--mcu-protocol-output-root",
        type=Path,
        default=Path("benchmark_results/extended/mcu_protocol_footprint"),
        help="Output directory for MCU protocol footprint artifacts",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail if an optional tool is unavailable instead of skipping it",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose command logging")
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

    path_west = shutil.which("west")
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

    raise RuntimeError("Unable to find a working west command.")


def build_env() -> dict[str, str]:
    env = os.environ.copy()
    for key in HOST_ENV_BLACKLIST:
        env.pop(key, None)
    return env


def run_command(
    cmd: List[str],
    *,
    cwd: Path,
    env: dict[str, str],
    verbose: bool,
) -> subprocess.CompletedProcess[str]:
    if verbose:
        print(" ".join(cmd))

    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )


def find_tool(explicit: Optional[str], name: str) -> Optional[List[str]]:
    if explicit:
        return shlex.split(explicit)

    path = shutil.which(name)
    if path:
        return [path]

    return None


def configure_graphviz_build(
    *,
    west_cmd: List[str],
    west_root: Path,
    module_path: Path,
    board: str,
    target: str,
    build_dir: Path,
    env: dict[str, str],
    verbose: bool,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        *west_cmd,
        "build",
        "-p",
        "always",
        "-d",
        str(build_dir),
        "-b",
        board,
        str(module_path / target),
        "--",
        f"-DZEPHYR_EXTRA_MODULES={module_path}",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
    ]
    return run_command(cmd, cwd=west_root, env=env, verbose=verbose)


def run_graphviz(
    *,
    build_dir: Path,
    output_path: Path,
    env: dict[str, str],
    verbose: bool,
) -> subprocess.CompletedProcess[str]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["cmake", f"--graphviz={output_path}", str(build_dir)]
    return run_command(cmd, cwd=build_dir.parent, env=env, verbose=verbose)


def run_cppcheck(
    *,
    cppcheck_cmd: List[str],
    module_path: Path,
    env: dict[str, str],
    verbose: bool,
    targets: Iterable[str],
) -> subprocess.CompletedProcess[str]:
    cmd = [
        *cppcheck_cmd,
        "--quiet",
        "--enable=warning,style,performance,portability",
        "--error-exitcode=2",
        "--inline-suppr",
        "--suppress=missingIncludeSystem",
        "--suppress=unusedStructMember",
        "--template={severity}:{id}:{file}:{line}:{message}",
        f"-I{module_path / 'include'}",
        *[str(module_path / target) for target in targets],
    ]
    return run_command(cmd, cwd=module_path, env=env, verbose=verbose)


def read_version_string(module_path: Path) -> str:
    match = VERSION_STRING_RE.search((module_path / "include/pqcp_zephyr/version.h").read_text())
    if match is None:
        raise RuntimeError("Unable to find PQCP_VERSION_STRING in include/pqcp_zephyr/version.h")
    return match.group(1)


def read_changelog_version(module_path: Path) -> str:
    match = CHANGELOG_VERSION_RE.search((module_path / "CHANGELOG.md").read_text())
    if match is None:
        raise RuntimeError("Unable to find a release heading in CHANGELOG.md")
    return match.group(1)


def check_version_sync(module_path: Path) -> bool:
    version_header = read_version_string(module_path)
    changelog_version = read_changelog_version(module_path)
    print("\n[release] Checking version metadata")
    print(f"[release] PQCP_VERSION_STRING : {version_header}")
    print(f"[release] CHANGELOG top entry : {changelog_version}")
    if version_header != changelog_version:
        print("[release] Version metadata is out of sync")
        return False
    print("[release] Version metadata is in sync")
    return True


def check_manifest_guidance(module_path: Path) -> bool:
    readme_text = (module_path / "README.md").read_text()

    print("[release] README manifest guidance")
    missing = [
        snippet for snippet in README_MANIFEST_REQUIRED_SNIPPETS
        if snippet not in readme_text
    ]
    if missing:
        for snippet in missing:
            print(f"[release] Missing README snippet: {snippet}")
        return False

    print("[release] README manifest snippet and pinning guidance are present")
    return True


def parse_compatibility_boards(
    single_board: str,
    board_values: Optional[List[str]],
) -> List[str]:
    if not board_values:
        return [single_board]

    boards: List[str] = []
    for raw_value in board_values:
        for item in raw_value.split(","):
            board = item.strip()
            if board:
                boards.append(board)

    if not boards:
        raise RuntimeError("compatibility board list must contain at least one board")

    return boards


def run_compatibility_smoke(
    *,
    west_cmd: List[str],
    west_root: Path,
    module_path: Path,
    boards: Iterable[str],
    build_dir_root: Path,
    env: dict[str, str],
    verbose: bool,
    zephyr_ref: str,
    targets: Iterable[str],
) -> int:
    selected_targets = list(targets)
    if not selected_targets:
        return 0

    build_dir_root.mkdir(parents=True, exist_ok=True)
    print(f"\n[compat] Zephyr ref : {zephyr_ref}")
    print("[compat] Boards:")
    for board in boards:
        print(f"  - {board}")
    print("[compat] Targets:")
    for target in selected_targets:
        print(f"  - {target}")

    for board in boards:
        board_dir = build_dir_root / board.replace("/", "_")
        for target in selected_targets:
            build_dir = board_dir / target.replace("/", "_")
            cmd = [
                *west_cmd,
                "build",
                "-p",
                "always",
                "-d",
                str(build_dir),
                "-b",
                board,
                str(module_path / target),
                "--",
                f"-DZEPHYR_EXTRA_MODULES={module_path}",
            ]
            result = run_command(cmd, cwd=west_root, env=env, verbose=verbose)
            if result.returncode != 0:
                print(result.stdout)
                return result.returncode
            print(f"[compat] Build OK: {board} / {target} -> {build_dir}")

    print("[compat] Compatibility smoke completed successfully")
    return 0


def summarize_cppcheck(output: str) -> Counter[str]:
    counts: Counter[str] = Counter()

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        parts = line.split(":", 4)
        if len(parts) != 5:
            continue

        severity = parts[0].strip()
        if severity:
            counts[severity] += 1

    return counts


def format_counter_summary(counts: Counter[str]) -> str:
    if not counts:
        return "no findings"

    order = ("error", "warning", "style", "performance", "portability", "information")
    items = [f"{severity}={counts[severity]}" for severity in order if counts[severity]]
    for severity in sorted(counts):
        if severity not in order:
            items.append(f"{severity}={counts[severity]}")
    return ", ".join(items)


def load_csv_rows(path: Path) -> List[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader)


def load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text())


def find_matching_row(
    rows: List[dict[str, str]],
    selectors: dict[str, object],
) -> Optional[dict[str, str]]:
    for row in rows:
        if all(str(row.get(key, "")) == str(value) for key, value in selectors.items()):
            return row
    return None


def parse_numeric_metric(row: dict[str, str], metric: str, label: str) -> float:
    raw = row.get(metric, "")
    if raw == "":
        raise RuntimeError(f"{label} is missing metric '{metric}'")
    try:
        return float(raw)
    except ValueError as exc:
        raise RuntimeError(f"{label} metric '{metric}' is not numeric: {raw}") from exc


def evaluate_cost_of_assurance_regressions(
    *,
    module_path: Path,
    primitive_rows: List[dict[str, str]],
    protocol_rows: List[dict[str, str]],
    regression_file: Path,
) -> int:
    config_path = (
        regression_file.resolve()
        if regression_file.is_absolute()
        else (module_path / regression_file).resolve()
    )
    config = load_json(config_path)
    comparisons = config.get("comparisons", [])
    if not isinstance(comparisons, list) or not comparisons:
        raise RuntimeError(
            f"cost-of-assurance regression file {config_path} has no comparisons"
        )

    print(f"[cost] Numeric regression thresholds: {config_path}")

    failures: list[str] = []

    for item in comparisons:
        if not isinstance(item, dict):
            raise RuntimeError("cost-of-assurance regression entries must be objects")

        name = str(item.get("name", "unnamed-comparison"))
        row_type = str(item.get("row_type", "primitive")).strip().lower()
        if row_type not in {"primitive", "protocol"}:
            raise RuntimeError(
                f"[cost] Comparison {name} has unsupported row_type '{row_type}'"
            )
        selected_rows = primitive_rows if row_type == "primitive" else protocol_rows
        candidate_selectors = dict(item.get("candidate", {}))
        baseline_selectors = dict(item.get("baseline", {}))
        shared_selectors = dict(item.get("selectors", {}))
        for key in ("board", "profile", "sample", "algorithm", "level"):
            value = item.get(key)
            if value is not None:
                shared_selectors[key] = value
        candidate_selectors.update(shared_selectors)
        baseline_selectors.update(shared_selectors)

        candidate = find_matching_row(selected_rows, candidate_selectors)
        baseline = find_matching_row(selected_rows, baseline_selectors)
        if candidate is None:
            failures.append(
                f"Missing candidate row for {name}: {candidate_selectors}"
            )
            continue
        if baseline is None:
            failures.append(
                f"Missing baseline row for {name}: {baseline_selectors}"
            )
            continue

        metrics = item.get("metrics", {})
        if not isinstance(metrics, dict) or not metrics:
            raise RuntimeError(f"[cost] Comparison {name} has no metrics configured")

        print(f"[cost] Regression comparison: {name}")
        for metric_name, raw_rule in metrics.items():
            if not isinstance(raw_rule, dict):
                raise RuntimeError(
                    f"[cost] Comparison {name} metric {metric_name} must be an object"
                )
            if "max_ratio" not in raw_rule and "max_candidate" not in raw_rule:
                raise RuntimeError(
                    f"[cost] Comparison {name} metric {metric_name} must define "
                    "max_ratio and/or max_candidate"
                )

            try:
                candidate_value = parse_numeric_metric(
                    candidate,
                    metric_name,
                    f"{name} candidate",
                )
            except RuntimeError as exc:
                failures.append(str(exc))
                continue

            baseline_value: float | None = None
            if "max_ratio" in raw_rule:
                try:
                    baseline_value = parse_numeric_metric(
                        baseline,
                        metric_name,
                        f"{name} baseline",
                    )
                except RuntimeError as exc:
                    failures.append(str(exc))
                    continue
                if baseline_value <= 0.0:
                    failures.append(
                        f"[cost] Baseline metric {metric_name} for {name} must be > 0"
                    )
                    continue

            status_bits: list[str] = [f"candidate={candidate_value:.2f}"]
            if baseline_value is not None:
                ratio = candidate_value / baseline_value
                max_ratio = float(raw_rule["max_ratio"])
                status_bits.extend(
                    [
                        f"baseline={baseline_value:.2f}",
                        f"ratio={ratio:.2f} (limit {max_ratio:.2f})",
                    ]
                )
                if ratio > max_ratio:
                    print(
                        f"  - {metric_name}: " + ", ".join(status_bits)
                    )
                    failures.append(
                        f"{name} metric {metric_name}: ratio "
                        f"{ratio:.2f} > {max_ratio:.2f}"
                    )

            if "max_candidate" in raw_rule:
                max_candidate = float(raw_rule["max_candidate"])
                status_bits.append(
                    f"absolute_limit={max_candidate:.2f}"
                )
                if candidate_value > max_candidate:
                    print(
                        f"  - {metric_name}: " + ", ".join(status_bits)
                    )
                    failures.append(
                        f"{name} metric {metric_name}: candidate "
                        f"{candidate_value:.2f} > absolute limit {max_candidate:.2f}"
                    )

            print(f"  - {metric_name}: " + ", ".join(status_bits))

    if failures:
        print("[cost] Regression failures detected:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    return 0


def run_mcu_protocol_budget_check(
    *,
    west_root: Path,
    module_path: Path,
    env: dict[str, str],
    verbose: bool,
    output_root: Path,
) -> int:
    print("\n[mcu] Running nucleo_h743zi protocol footprint and budget checks")
    result = run_command(
        [
            sys.executable,
            str(module_path / "scripts/check_resource_budgets.py"),
            "--west-root",
            str(west_root),
            "--module-path",
            str(module_path),
            "--output-root",
            str(output_root),
        ],
        cwd=module_path,
        env=env,
        verbose=verbose,
    )
    if result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
    return result.returncode


def run_cost_of_assurance_smoke(
    *,
    west_root: Path,
    module_path: Path,
    env: dict[str, str],
    verbose: bool,
    output_root: Path,
    regression_file: Path,
) -> int:
    output_root.mkdir(parents=True, exist_ok=True)
    benchmark_script = module_path / "scripts/run_benchmarks.py"
    summarize_script = module_path / "scripts/summarize_cost_of_assurance.py"

    print("\n[cost] Running qemu_x86_64 cost-of-assurance smoke")
    print("[cost] Samples:")
    print("  - pqcp_basic_kem")
    print("  - pqcp_basic_sig")
    print("  - pqcp_bench_protocol")
    print("[cost] Implementations/backends:")
    print("  - pqcp / auto")
    print("  - baseline / clean")

    run_result = run_command(
        [
            sys.executable,
            str(benchmark_script),
            "--cost-of-assurance-matrix",
            "--board",
            "qemu_x86_64",
            "--samples",
            "pqcp_basic_kem",
            "pqcp_basic_sig",
            "pqcp_bench_protocol",
            "--backend-policies",
            "auto",
            "clean",
            "--output",
            str(output_root),
            "--west-root",
            str(west_root),
            "--module-path",
            str(module_path),
        ],
        cwd=west_root,
        env=env,
        verbose=verbose,
    )
    if run_result.returncode != 0:
        print(run_result.stdout)
        return run_result.returncode

    summarize_result = run_command(
        [
            sys.executable,
            str(summarize_script),
            "--input-dir",
            str(output_root),
        ],
        cwd=west_root,
        env=env,
        verbose=verbose,
    )
    if summarize_result.returncode != 0:
        print(summarize_result.stdout)
        return summarize_result.returncode

    builds = load_csv_rows(output_root / "cost_of_assurance_builds.csv")
    primitives = load_csv_rows(output_root / "cost_of_assurance_primitives.csv")
    protocols = load_csv_rows(output_root / "cost_of_assurance_protocols.csv")

    required_primitive_rows = [
        {
            "board": "qemu_x86_64",
            "sample": "pqcp_basic_kem",
            "implementation": "pqcp",
            "backend": "auto",
        },
        {
            "board": "qemu_x86_64",
            "sample": "pqcp_basic_kem",
            "implementation": "baseline",
            "backend": "clean",
        },
        {
            "board": "qemu_x86_64",
            "sample": "pqcp_basic_sig",
            "implementation": "pqcp",
            "backend": "auto",
        },
        {
            "board": "qemu_x86_64",
            "sample": "pqcp_basic_sig",
            "implementation": "baseline",
            "backend": "clean",
        },
    ]
    for selectors in required_primitive_rows:
        if find_matching_row(primitives, selectors) is None:
            print(f"[cost] Missing primitive comparison row: {selectors}")
            return 1

    required_protocol_rows = [
        {
            "board": "qemu_x86_64",
            "profile": "MCU_MINIMAL",
            "sample": "pqcp_bench_protocol",
            "implementation": "pqcp",
            "backend": "auto",
            "key_exchange_algorithm": "MLKEM",
            "key_exchange_level": 768,
            "auth_algorithm": "MLDSA",
            "auth_level": 65,
            "suite_mode": "pure_pq",
        },
        {
            "board": "qemu_x86_64",
            "profile": "MCU_MINIMAL",
            "sample": "pqcp_bench_protocol",
            "implementation": "baseline",
            "backend": "clean",
            "key_exchange_algorithm": "MLKEM",
            "key_exchange_level": 768,
            "auth_algorithm": "MLDSA",
            "auth_level": 65,
            "suite_mode": "pure_pq",
        },
        {
            "board": "qemu_x86_64",
            "profile": "COA_QEMU_SINGLE_LEVEL",
            "sample": "pqcp_bench_protocol",
            "implementation": "pqcp",
            "backend": "auto",
            "key_exchange_algorithm": "MLKEM",
            "key_exchange_level": 512,
            "auth_algorithm": "MLDSA",
            "auth_level": 87,
            "suite_mode": "pure_pq",
        },
        {
            "board": "qemu_x86_64",
            "profile": "COA_QEMU_SINGLE_LEVEL",
            "sample": "pqcp_bench_protocol",
            "implementation": "baseline",
            "backend": "clean",
            "key_exchange_algorithm": "MLKEM",
            "key_exchange_level": 512,
            "auth_algorithm": "MLDSA",
            "auth_level": 87,
            "suite_mode": "pure_pq",
        },
    ]
    for selectors in required_protocol_rows:
        if find_matching_row(protocols, selectors) is None:
            print(f"[cost] Missing protocol comparison row: {selectors}")
            return 1

    if len(builds) < 4:
        print("[cost] Expected at least four build rows from the smoke run")
        return 1

    regression_result = evaluate_cost_of_assurance_regressions(
        module_path=module_path,
        primitive_rows=primitives,
        protocol_rows=protocols,
        regression_file=regression_file,
    )
    if regression_result != 0:
        return regression_result

    print(
        f"[cost] Smoke completed successfully: builds={len(builds)}, "
        f"primitives={len(primitives)}, protocols={len(protocols)}"
    )
    return 0


def main() -> int:
    args = parse_args()
    module_path = args.module_path.resolve() if args.module_path else Path(__file__).resolve().parent.parent
    west_root = args.west_root.resolve() if args.west_root else detect_west_root(Path.cwd())
    build_dir = args.build_dir.resolve()
    graphviz_out = args.graphviz_out.resolve()
    env = build_env()

    west_cmd = discover_west(args.west, west_root, module_path)

    print("PQCP Extended Checks")
    print(f"  west root : {west_root}")
    print(f"  module    : {module_path}")
    print(f"  west cmd  : {' '.join(west_cmd)}")
    print(f"  zephyr    : {args.zephyr_ref}")

    if not check_version_sync(module_path):
        return 1
    if not check_manifest_guidance(module_path):
        return 1

    if not args.skip_graphviz:
        print(f"\n[graphviz] Configuring {args.target} for {args.board}")
        print(f"[graphviz] Build directory: {build_dir}")
        print(f"[graphviz] Output path:     {graphviz_out}")
        build_result = configure_graphviz_build(
            west_cmd=west_cmd,
            west_root=west_root,
            module_path=module_path,
            board=args.board,
            target=args.target,
            build_dir=build_dir,
            env=env,
            verbose=args.verbose,
        )
        if build_result.returncode != 0:
            print(build_result.stdout)
            return build_result.returncode

        graph_result = run_graphviz(
            build_dir=build_dir,
            output_path=graphviz_out,
            env=env,
            verbose=args.verbose,
        )
        if graph_result.returncode != 0:
            print(graph_result.stdout)
            return graph_result.returncode

        print(f"[graphviz] Wrote {graphviz_out}")

    if not args.skip_cppcheck:
        cppcheck_cmd = find_tool(args.cppcheck, "cppcheck")
        if cppcheck_cmd is None:
            message = "cppcheck not found"
            if args.strict:
                print(message)
                return 1
            print(f"[cppcheck] {message}; skipping")
        else:
            analysis_paths = [module_path / target for target in DEFAULT_ANALYSIS_PATHS]
            print("\n[cppcheck] Checking focused PQCP sources")
            print("[cppcheck] Analysed paths:")
            for path in analysis_paths:
                print(f"  - {path.relative_to(module_path)}")
            cppcheck_result = run_cppcheck(
                cppcheck_cmd=cppcheck_cmd,
                module_path=module_path,
                env=env,
                verbose=args.verbose,
                targets=DEFAULT_ANALYSIS_PATHS,
            )
            cppcheck_summary = format_counter_summary(
                summarize_cppcheck(cppcheck_result.stdout)
            )
            if cppcheck_result.returncode != 0:
                print(f"[cppcheck] Findings summary: {cppcheck_summary}")
                print(cppcheck_result.stdout)
                return cppcheck_result.returncode
            if cppcheck_result.stdout.strip():
                print(f"[cppcheck] Findings summary: {cppcheck_summary}")
                print(cppcheck_result.stdout)
            else:
                print("[cppcheck] Findings summary: no findings")
            print("[cppcheck] Completed without findings")

    if args.run_compatibility_smoke:
        compatibility_targets = args.compatibility_targets or DEFAULT_COMPATIBILITY_TARGETS
        compatibility_boards = parse_compatibility_boards(
            args.compatibility_board,
            args.compatibility_boards,
        )
        compat_result = run_compatibility_smoke(
            west_cmd=west_cmd,
            west_root=west_root,
            module_path=module_path,
            boards=compatibility_boards,
            build_dir_root=args.compatibility_build_dir_root.resolve(),
            env=env,
            verbose=args.verbose,
            zephyr_ref=args.zephyr_ref,
            targets=compatibility_targets,
        )
        if compat_result != 0:
            return compat_result

    if args.run_mcu_protocol_budgets:
        mcu_budget_result = run_mcu_protocol_budget_check(
            west_root=west_root,
            module_path=module_path,
            env=env,
            verbose=args.verbose,
            output_root=args.mcu_protocol_output_root.resolve(),
        )
        if mcu_budget_result != 0:
            return mcu_budget_result
    else:
        print(
            "\n[mcu] Skipping nucleo_h743zi protocol footprint and budget checks "
            "(pass --run-mcu-protocol-budgets to enable; release_check.py runs this step directly)."
        )

    if args.run_cost_of_assurance_smoke:
        coa_result = run_cost_of_assurance_smoke(
            west_root=west_root,
            module_path=module_path,
            env=env,
            verbose=args.verbose,
            output_root=args.cost_of_assurance_output_root.resolve(),
            regression_file=args.cost_of_assurance_regression_file,
        )
        if coa_result != 0:
            return coa_result

    print("\nExtended checks completed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
