#!/usr/bin/env python3
"""
PQCP benchmark orchestration.

Builds and runs a configurable board/profile/sample matrix, captures per-run
logs, parses PQCP_METRIC output, and writes consolidated CSV/JSON artifacts.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
PARSER_SPEC = importlib.util.spec_from_file_location(
    "pqcp_parse_logs", SCRIPT_DIR / "parse_logs.py"
)
if PARSER_SPEC is None or PARSER_SPEC.loader is None:
    raise RuntimeError("Unable to load parse_logs.py")
PARSER_MODULE = importlib.util.module_from_spec(PARSER_SPEC)
PARSER_SPEC.loader.exec_module(PARSER_MODULE)

parse_log_file = PARSER_MODULE.parse_log_file
write_metrics_csv = PARSER_MODULE.write_metrics_csv
write_primitive_csv = PARSER_MODULE.write_primitive_csv
write_protocol_csv = PARSER_MODULE.write_protocol_csv
write_summary = PARSER_MODULE.write_summary

DEFAULT_BOARDS = ["qemu_x86_64", "mps2/an385"]
DEFAULT_MATRIX_SAMPLES = [
    "pqcp_basic_kem",
    "pqcp_basic_sig",
    "pqcp_streaming_hash_mldsa",
    "pqcp_tls_mbedtls_psa",
    "pqcp_bench_protocol",
]

PROFILES: Dict[str, Dict[str, str]] = {
    "MCU_MINIMAL": {
        "kconfig": "CONFIG_PQCP_PROFILE_MCU_MINIMAL=y",
        "description": "Conservative production-oriented MCU profile",
    },
    "GATEWAY": {
        "kconfig": "CONFIG_PQCP_PROFILE_GATEWAY=y",
        "description": "PSA/TLS capable gateway profile",
    },
    "NATIVE_LAB": {
        "kconfig": "CONFIG_PQCP_PROFILE_NATIVE_LAB=y",
        "description": "Lab/development profile with benchmarking",
    },
}

DEFAULT_BENCHMARK_MATRIX = SCRIPT_DIR / "benchmark_matrix.json"
DEFAULT_PROFILE_VALIDATION_MATRIX = SCRIPT_DIR / "profile_validation_matrix.json"
HOST_ENV_BLACKLIST = (
    "CFLAGS",
    "CXXFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "CPATH",
    "SDKROOT",
)

SAMPLES: Dict[str, Dict[str, Any]] = {
    "pqcp_basic_kem": {
        "path": "samples/pqcp_basic_kem",
        "profiles": ["MCU_MINIMAL", "GATEWAY", "NATIVE_LAB"],
        "boards": DEFAULT_BOARDS,
        "overlays": [],
        "run_timeout": 45,
    },
    "pqcp_basic_sig": {
        "path": "samples/pqcp_basic_sig",
        "profiles": ["MCU_MINIMAL", "GATEWAY", "NATIVE_LAB"],
        "boards": DEFAULT_BOARDS,
        "overlays": [],
        "run_timeout": 45,
    },
    "pqcp_streaming_hash_mldsa": {
        "path": "samples/pqcp_streaming_hash_mldsa",
        "profiles": ["GATEWAY", "NATIVE_LAB"],
        "boards": DEFAULT_BOARDS,
        "overlays": [],
        "run_timeout": 60,
    },
    "pqcp_tls_mbedtls_psa": {
        "path": "samples/pqcp_tls_mbedtls_psa",
        "profiles": ["GATEWAY", "NATIVE_LAB"],
        "boards": ["qemu_x86_64"],
        "overlays": ["overlay-selftest.conf"],
        "run_timeout": 60,
    },
    "pqcp_bench_protocol": {
        "path": "samples/pqcp_bench_protocol",
        "profiles": ["MCU_MINIMAL", "GATEWAY", "NATIVE_LAB"],
        "boards": DEFAULT_BOARDS,
        "overlays": [],
        "run_timeout": 60,
    },
    "pqcp_kat_deterministic": {
        "path": "samples/pqcp_kat_deterministic",
        "profiles": ["NATIVE_LAB"],
        "boards": ["qemu_x86_64"],
        "overlays": [],
        "run_timeout": 60,
    },
}


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    timed_out: bool


@dataclass
class RunSpec:
    run_id: str
    board: str
    profile: str
    sample: str
    app_path: str
    overlays: List[str]
    extra_kconfig: List[str]
    run_timeout: int


@dataclass
class RunRecord:
    run_id: str
    board: str
    profile: str
    sample: str
    app_path: str
    build_dir: str
    log_path: str
    build_ok: bool
    run_ok: bool
    timed_out: bool
    metric_count: int
    size_text: int
    size_data: int
    size_bss: int


def slugify(value: str) -> str:
    return value.replace("/", "_").replace(" ", "_").lower()


def default_timeout_for_path(app_path: str) -> int:
    return 120 if app_path.startswith("tests/") else 60


def make_run_id(board: str, profile: str, label: str) -> str:
    return "__".join([slugify(board), slugify(profile), slugify(label)])


def normalize_overlays(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value]


def load_config_file(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(path)

    if path.suffix in {".yml", ".yaml"}:
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError("PyYAML is required for YAML config files") from exc
        return yaml.safe_load(path.read_text()) or {}

    return json.loads(path.read_text())


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

    raise RuntimeError(
        "Unable to find a working west command. Pass --west or activate a Zephyr venv."
    )


def discover_size_tool() -> Optional[List[str]]:
    for tool in ("llvm-size", "size"):
        path = shutil.which(tool)
        if path:
            return [path]
    return None


class BenchmarkRunner:
    def __init__(
        self,
        west_root: Path,
        module_path: Path,
        output_dir: Path,
        west_cmd: List[str],
        build_only: bool,
        default_timeout: int,
        verbose: bool,
    ) -> None:
        self.west_root = west_root
        self.module_path = module_path
        self.output_dir = output_dir
        self.west_cmd = west_cmd
        self.build_only = build_only
        self.default_timeout = default_timeout
        self.verbose = verbose
        self.command_env = self._build_command_env()
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.size_tool = discover_size_tool()
        self.records: List[RunRecord] = []
        self.metric_rows: List[Dict[str, Any]] = []
        self.all_results: List[Dict[str, Any]] = []

        (self.output_dir / "runs").mkdir(parents=True, exist_ok=True)
        (self.output_dir / "build").mkdir(parents=True, exist_ok=True)

    def _build_command_env(self) -> Dict[str, str]:
        env = os.environ.copy()
        for key in HOST_ENV_BLACKLIST:
            env.pop(key, None)
        return env

    def _cleanup_qemu(self, build_dir: Path) -> None:
        pid_path = build_dir / "qemu.pid"
        if not pid_path.exists():
            return

        try:
            pid = int(pid_path.read_text().strip())
        except (OSError, ValueError):
            pid_path.unlink(missing_ok=True)
            return

        try:
            ps_result = subprocess.run(
                ["ps", "-p", str(pid), "-o", "command="],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
                check=False,
            )
            command = ps_result.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            command = ""

        if "qemu" in command and str(build_dir) in command:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except PermissionError:
                pass

        pid_path.unlink(missing_ok=True)

    def _run_command(
        self,
        cmd: List[str],
        *,
        cwd: Path,
        timeout: Optional[int] = None,
    ) -> CommandResult:
        if self.verbose:
            print(" ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                cwd=str(cwd),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
                env=self.command_env,
                check=False,
            )
            return CommandResult(result.returncode, result.stdout, False)
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode(errors="replace")
            return CommandResult(124, stdout, True)

    def _write_extra_conf(self, run_dir: Path, spec: RunSpec) -> Optional[Path]:
        lines = [PROFILES[spec.profile]["kconfig"], *spec.extra_kconfig]
        lines = [line.strip() for line in lines if line and line.strip()]
        if not lines:
            return None

        conf_path = run_dir / "extra.conf"
        conf_path.write_text("\n".join(lines) + "\n")
        return conf_path

    def _build(self, spec: RunSpec, run_dir: Path) -> CommandResult:
        build_dir = self.output_dir / "build" / spec.run_id
        if build_dir.exists():
            shutil.rmtree(build_dir)

        app_dir = self.module_path / spec.app_path
        overlay_args = [
            str(app_dir / overlay) for overlay in spec.overlays
        ]
        extra_conf = self._write_extra_conf(run_dir, spec)

        cmd = [
            *self.west_cmd,
            "build",
            "-d",
            str(build_dir),
            "-b",
            spec.board,
            str(app_dir),
            "--pristine",
            "--",
            f"-DZEPHYR_EXTRA_MODULES={self.module_path}",
        ]

        if overlay_args:
            cmd.append(f"-DOVERLAY_CONFIG={';'.join(overlay_args)}")
        if extra_conf is not None:
            cmd.append(f"-DEXTRA_CONF_FILE={extra_conf}")

        return self._run_command(cmd, cwd=self.west_root)

    def _run_sample(self, spec: RunSpec) -> CommandResult:
        if self.build_only:
            return CommandResult(0, "", False)

        build_dir = self.output_dir / "build" / spec.run_id
        self._cleanup_qemu(build_dir)
        run_timeout = spec.run_timeout or self.default_timeout
        if self.default_timeout:
            run_timeout = min(run_timeout, self.default_timeout) if run_timeout else self.default_timeout

        if spec.board.startswith("native_"):
            binary = build_dir / "zephyr/zephyr.exe"
            if not binary.exists():
                return CommandResult(1, f"Binary not found: {binary}\n", False)
            return self._run_command(
                [str(binary)],
                cwd=self.west_root,
                timeout=run_timeout,
            )

        return self._run_command(
            [*self.west_cmd, "build", "-d", str(build_dir), "-t", "run"],
            cwd=self.west_root,
            timeout=run_timeout,
        )

    def _get_code_size(self, spec: RunSpec) -> Dict[str, int]:
        build_dir = self.output_dir / "build" / spec.run_id
        elf_path = build_dir / "zephyr/zephyr.elf"
        if self.size_tool is None or not elf_path.exists():
            return {}

        result = self._run_command([*self.size_tool, str(elf_path)], cwd=self.west_root)
        if result.returncode != 0:
            return {}

        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0].isdigit():
                return {
                    "text": int(parts[0]),
                    "data": int(parts[1]),
                    "bss": int(parts[2]),
                    "total": int(parts[3]),
                }

        return {}

    def _enrich_metric_rows(
        self,
        spec: RunSpec,
        log_path: Path,
        parsed: List[Dict[str, Any]],
        sizes: Dict[str, int],
    ) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        metadata = {
            "timestamp": self.timestamp,
            "run_id": spec.run_id,
            "board": spec.board,
            "profile": spec.profile,
            "sample": spec.sample,
            "app_path": spec.app_path,
            "overlays": ";".join(spec.overlays),
            "extra_kconfig": ";".join(spec.extra_kconfig),
            "log_path": str(log_path),
        }

        for item in parsed:
            enriched = {**metadata, **item}
            self.all_results.append(enriched)

            if item.get("type") == "pqcp_metric":
                rows.append(
                    {
                        **metadata,
                        "component": item["component"],
                        "operation": item["operation"],
                        "algorithm": item["algorithm"],
                        "level": item["level"],
                        "metric": item["metric"],
                        "value": item["value"],
                        "unit": item["unit"],
                    }
                )

        for name, value in sizes.items():
            rows.append(
                {
                    **metadata,
                    "component": "build",
                    "operation": "artifact",
                    "algorithm": "zephyr",
                    "level": 0,
                    "metric": f"{name}_bytes",
                    "value": value,
                    "unit": "B",
                }
            )

        return rows

    def run_one(self, spec: RunSpec) -> None:
        run_dir = self.output_dir / "runs" / spec.run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        print(f"\n[{spec.run_id}] {spec.board} / {spec.profile} / {spec.sample}")
        build_result = self._build(spec, run_dir)
        (run_dir / "build.log").write_text(build_result.stdout)

        if build_result.returncode != 0:
            print("  build failed")
            self.records.append(
                RunRecord(
                    run_id=spec.run_id,
                    board=spec.board,
                    profile=spec.profile,
                    sample=spec.sample,
                    app_path=spec.app_path,
                    build_dir=str(self.output_dir / "build" / spec.run_id),
                    log_path=str(run_dir / "run.log"),
                    build_ok=False,
                    run_ok=False,
                    timed_out=False,
                    metric_count=0,
                    size_text=0,
                    size_data=0,
                    size_bss=0,
                )
            )
            return

        sizes = self._get_code_size(spec)
        run_result = self._run_sample(spec)
        self._cleanup_qemu(self.output_dir / "build" / spec.run_id)
        log_text = run_result.stdout
        log_path = run_dir / "run.log"
        log_path.write_text(log_text)

        parsed = parse_log_file(log_path) if log_text else []
        write_metrics_csv(parsed, run_dir / "run_metrics.csv")
        write_primitive_csv(parsed, run_dir / "run_primitives.csv")
        write_protocol_csv(parsed, run_dir / "run_protocols.csv")
        write_summary(parsed, run_dir / "run_summary.txt")

        enriched_rows = self._enrich_metric_rows(spec, log_path, parsed, sizes)
        self.metric_rows.extend(enriched_rows)

        record = RunRecord(
            run_id=spec.run_id,
            board=spec.board,
            profile=spec.profile,
            sample=spec.sample,
            app_path=spec.app_path,
            build_dir=str(self.output_dir / "build" / spec.run_id),
            log_path=str(log_path),
            build_ok=True,
            run_ok=(run_result.returncode == 0 or run_result.timed_out),
            timed_out=run_result.timed_out,
            metric_count=len(enriched_rows),
            size_text=sizes.get("text", 0),
            size_data=sizes.get("data", 0),
            size_bss=sizes.get("bss", 0),
        )
        self.records.append(record)

        status = "timed out with partial output" if run_result.timed_out else "completed"
        print(f"  run {status}, captured {len(enriched_rows)} consolidated metrics")

    def write_outputs(self) -> None:
        record_path = self.output_dir / "runs.json"
        record_path.write_text(
            json.dumps([asdict(record) for record in self.records], indent=2)
        )

        all_results_path = self.output_dir / "all_results.json"
        all_results_path.write_text(json.dumps(self.all_results, indent=2))

        metrics_json_path = self.output_dir / "consolidated_metrics.json"
        metrics_json_path.write_text(json.dumps(self.metric_rows, indent=2))

        metrics_csv_path = self.output_dir / "consolidated_metrics.csv"
        fieldnames = [
            "timestamp",
            "run_id",
            "board",
            "profile",
            "sample",
            "app_path",
            "overlays",
            "extra_kconfig",
            "component",
            "operation",
            "algorithm",
            "level",
            "metric",
            "value",
            "unit",
            "log_path",
        ]
        with metrics_csv_path.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.metric_rows)

        print(f"\nWrote run metadata:      {record_path}")
        print(f"Wrote parsed JSON:       {all_results_path}")
        print(f"Wrote consolidated JSON: {metrics_json_path}")
        print(f"Wrote consolidated CSV:  {metrics_csv_path}")


def expand_runs(
    *,
    boards: Iterable[str],
    profiles: Iterable[str],
    samples: Iterable[str],
    extra_kconfig: List[str],
) -> List[RunSpec]:
    specs: List[RunSpec] = []

    for board in boards:
        for profile in profiles:
            for sample in samples:
                sample_info = SAMPLES[sample]
                if board not in sample_info["boards"]:
                    continue
                if profile not in sample_info["profiles"]:
                    continue

                run_id = "__".join(
                    [slugify(board), slugify(profile), slugify(sample)]
                )
                specs.append(
                    RunSpec(
                        run_id=run_id,
                        board=board,
                        profile=profile,
                        sample=sample,
                        app_path=sample_info["path"],
                        overlays=list(sample_info.get("overlays", [])),
                        extra_kconfig=list(extra_kconfig),
                        run_timeout=int(sample_info.get("run_timeout", 0)),
                    )
                )

    return specs


def expand_runs_from_config(config: Dict[str, Any], cli_kconfig: List[str]) -> List[RunSpec]:
    if config and all(key in PROFILES for key in config.keys()):
        specs: List[RunSpec] = []
        for profile, entries in config.items():
            for item in entries:
                target = item["target"]
                label = item.get("sample", Path(target).name)
                overlays = normalize_overlays(item.get("overlays"))
                if item.get("overlay"):
                    overlays.append(str(item["overlay"]))
                specs.append(
                    RunSpec(
                        run_id=item.get(
                            "run_id",
                            make_run_id(item["board"], profile, label),
                        ),
                        board=item["board"],
                        profile=profile,
                        sample=label,
                        app_path=target,
                        overlays=overlays,
                        extra_kconfig=[
                            *item.get("extra_kconfig", []),
                            *cli_kconfig,
                        ],
                        run_timeout=int(
                            item.get("run_timeout", default_timeout_for_path(target))
                        ),
                    )
                )
        return specs

    if "runs" in config:
        specs: List[RunSpec] = []
        for item in config["runs"]:
            sample = item.get("sample")
            target = item.get("target")
            sample_info = SAMPLES.get(sample, {}) if sample else {}
            app_path = item.get("app_path") or target or sample_info.get("path")
            if app_path is None:
                raise KeyError("Each run must define either sample, target, or app_path")

            label = sample or Path(app_path).name
            overlays = normalize_overlays(item.get("overlays"))
            if item.get("overlay"):
                overlays.append(str(item["overlay"]))
            run_id = item.get(
                "run_id",
                make_run_id(item["board"], item["profile"], label),
            )
            specs.append(
                RunSpec(
                    run_id=run_id,
                    board=item["board"],
                    profile=item["profile"],
                    sample=label,
                    app_path=app_path,
                    overlays=overlays or list(sample_info.get("overlays", [])),
                    extra_kconfig=[
                        *item.get("extra_kconfig", []),
                        *cli_kconfig,
                    ],
                    run_timeout=int(
                        item.get(
                            "run_timeout",
                            sample_info.get("run_timeout", default_timeout_for_path(app_path)),
                        )
                    ),
                )
            )
        return specs

    return expand_runs(
        boards=config.get("boards", DEFAULT_BOARDS),
        profiles=config.get("profiles", list(PROFILES.keys())),
        samples=config.get("samples", DEFAULT_MATRIX_SAMPLES),
        extra_kconfig=[*config.get("extra_kconfig", []), *cli_kconfig],
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PQCP benchmark matrix runner")
    mode_group = parser.add_mutually_exclusive_group()
    parser.add_argument("--board", help="Single board")
    parser.add_argument("--boards", nargs="+", help="Boards for matrix mode")
    parser.add_argument("--profile", choices=list(PROFILES), help="Single profile")
    parser.add_argument("--profiles", nargs="+", choices=list(PROFILES), help="Profiles for matrix mode")
    parser.add_argument("--sample", choices=list(SAMPLES), help="Single sample")
    parser.add_argument("--samples", nargs="+", choices=list(SAMPLES), help="Samples for matrix mode")
    parser.add_argument("--matrix", action="store_true", help="Run a board/profile/sample matrix")
    mode_group.add_argument("--config", type=Path, help="JSON or YAML matrix config")
    mode_group.add_argument("--benchmark-matrix", action="store_true",
                            help="Run the curated benchmark matrix")
    mode_group.add_argument("--profile-validation", action="store_true",
                            help="Run the curated profile validation matrix")
    parser.add_argument("--output", "-o", type=Path, default=Path("benchmark_results"), help="Output directory")
    parser.add_argument("--west-root", type=Path, help="West workspace root")
    parser.add_argument("--module-path", type=Path, help="PQCP module path")
    parser.add_argument("--west", help="Explicit west binary or command")
    parser.add_argument("--kconfig", action="append", default=[], help="Extra Kconfig line, e.g. CONFIG_FOO=y")
    parser.add_argument("--timeout", type=int, default=180, help="Default run timeout in seconds")
    parser.add_argument("--build-only", action="store_true", help="Build without running")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose command logging")
    return parser.parse_args()


def detect_west_root(start: Path) -> Path:
    current = start.resolve()
    while current != current.parent:
        if (current / ".west").exists():
            return current
        current = current.parent
    return start.resolve()


def main() -> int:
    args = parse_args()
    west_root = args.west_root.resolve() if args.west_root else detect_west_root(Path.cwd())
    module_path = args.module_path.resolve() if args.module_path else SCRIPT_DIR.parent
    output_dir = args.output.resolve()

    west_cmd = discover_west(args.west, west_root, module_path)

    print("PQCP Benchmark Runner")
    print(f"  west root : {west_root}")
    print(f"  module    : {module_path}")
    print(f"  west cmd  : {' '.join(west_cmd)}")
    print(f"  output    : {output_dir}")

    if args.benchmark_matrix:
        specs = expand_runs_from_config(
            load_config_file(DEFAULT_BENCHMARK_MATRIX), args.kconfig
        )
    elif args.profile_validation:
        specs = expand_runs_from_config(
            load_config_file(DEFAULT_PROFILE_VALIDATION_MATRIX), args.kconfig
        )
    elif args.config:
        specs = expand_runs_from_config(load_config_file(args.config), args.kconfig)
    elif args.sample:
        specs = expand_runs(
            boards=[args.board or "qemu_x86_64"],
            profiles=[args.profile or "MCU_MINIMAL"],
            samples=[args.sample],
            extra_kconfig=args.kconfig,
        )
    elif args.matrix or args.samples or args.boards or args.profiles:
        specs = expand_runs(
            boards=args.boards or ([args.board] if args.board else DEFAULT_BOARDS),
            profiles=args.profiles or ([args.profile] if args.profile else list(PROFILES.keys())),
            samples=args.samples or DEFAULT_MATRIX_SAMPLES,
            extra_kconfig=args.kconfig,
        )
    else:
        specs = expand_runs(
            boards=[args.board or "qemu_x86_64"],
            profiles=[args.profile or "MCU_MINIMAL"],
            samples=["pqcp_basic_kem", "pqcp_basic_sig"],
            extra_kconfig=args.kconfig,
        )

    if not specs:
        print("No runnable benchmark combinations matched the selected matrix.")
        return 1

    runner = BenchmarkRunner(
        west_root=west_root,
        module_path=module_path,
        output_dir=output_dir,
        west_cmd=west_cmd,
        build_only=args.build_only,
        default_timeout=args.timeout,
        verbose=args.verbose,
    )

    for spec in specs:
        runner.run_one(spec)

    runner.write_outputs()
    return 0 if any(record.metric_count > 0 for record in runner.records) else 1


if __name__ == "__main__":
    sys.exit(main())
