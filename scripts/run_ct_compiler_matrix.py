#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build and measure the ML-KEM-768 relational trace across SDK compilers."""

import argparse
from collections import Counter, deque
from contextlib import redirect_stdout
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys

import ct_static_scan as static
import ct_trace_analysis as cta
import run_ct_trace_checks as trace

TARGETS = ("x86_64", trace.CORTEX_M3_TARGET)
LABELS = [(key << 8) | ciphertext for key in range(8) for ciphertext in range(6)]
OPT_FLAG = re.compile(r"-O(?:[0-9]+|s|g|z|fast)?$")


@dataclass(frozen=True)
class Variant:
    compiler: str
    opt: str
    lto: bool = False

    def cmake_flags(self) -> tuple[str, ...]:
        toolchain = "llvm" if self.compiler == "clang" else "gnu"
        flags = [f"-DZEPHYR_TOOLCHAIN_VARIANT=zephyr/{toolchain}",
                 "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"]
        if self.opt in {"-O2", "-O3"}:
            flags.append("-DCONFIG_SPEED_OPTIMIZATIONS=y")
        # Zephyr selects -Oz for Clang's default size profile.
        if self.opt == "-O3" or (self.compiler == "clang" and self.opt == "-Os"):
            flags.append(f"-DEXTRA_CFLAGS={self.opt}")
        if self.opt == "-Og":
            flags.append("-DCONFIG_DEBUG_OPTIMIZATIONS=y")
        if self.lto:
            flags.extend(("-DCONFIG_LTO=y", "-DCONFIG_ISR_TABLES_LOCAL_DECLARATION=y"))
        return tuple(flags)


VARIANTS = {
    "gcc-Os": Variant("gcc", "-Os"),
    "gcc-O2": Variant("gcc", "-O2"),
    "gcc-O3": Variant("gcc", "-O3"),
    "gcc-Og": Variant("gcc", "-Og"),
    "gcc-Os-lto": Variant("gcc", "-Os", lto=True),
    "clang-Os": Variant("clang", "-Os"),
    "clang-O2": Variant("clang", "-O2"),
    "clang-O3": Variant("clang", "-O3"),
}


class ConfigMismatch(ValueError):
    """The ML-KEM translation units used a different build configuration."""


def find_compiler(args: list[str]) -> Path:
    for arg in args:
        if arg.startswith("-"):
            break
        name = Path(arg).name
        if re.fullmatch(r"(?:[\w.-]+-)?(?:gcc|clang)(?:-\d+)?", name):
            return Path(arg)
    raise ConfigMismatch(f"no GCC or Clang executable in {args[:3]!r}")


def verify_compile_commands(build: Path, variant: Variant) -> dict:
    try:
        entries = json.loads((build / "compile_commands.json").read_text(encoding="utf-8"))
        units = {}
        for entry in entries:
            source = Path(entry["file"])
            if "ext/mlkem-native/" not in source.as_posix() or source.suffix != ".c":
                continue
            args = entry.get("arguments") or shlex.split(entry["command"])
            cc = find_compiler(args)
            family = "clang" if re.search(r"(?:^|-)clang(?:-\d+)?$", cc.name) else "gcc"
            opt = next((arg for arg in reversed(args) if OPT_FLAG.fullmatch(arg)), None)
            lto_flag = next((arg for arg in reversed(args)
                             if arg in {"-flto", "-fno-lto"} or arg.startswith("-flto=")),
                            "-fno-lto")
            actual = Variant(family, opt, lto_flag != "-fno-lto")
            if actual != variant:
                raise ConfigMismatch(f"{source.name}: expected {variant}, found {actual}")
            units[str(cc)] = units.get(str(cc), 0) + 1
    except (KeyError, OSError, json.JSONDecodeError) as exc:
        raise ConfigMismatch(f"cannot read ML-KEM compile commands: {exc}") from exc
    if len(units) != 1:
        raise ConfigMismatch(f"expected one compiler in ML-KEM C commands, found {units}")
    path, count = next(iter(units.items()))
    compiler = subprocess.run([path, "--version"], text=True, capture_output=True,
                              check=True).stdout.splitlines()[0]
    return {"cc": variant.compiler, "compiler": compiler, "compiler_path": path,
            "opt": variant.opt, "lto": variant.lto, "translation_units": count}


def source_sites(elf: Path, pcs: list[int], sdk: Path | None) -> dict:
    if not pcs:
        return {}
    result = subprocess.run(
        [static.sdk_tool("cortex-m3", "addr2line", sdk), "-e", elf,
         "-f", "-i", "-a", *(hex(pc) for pc in pcs)],
        check=True, capture_output=True, text=True,
    )
    sites = {}
    current = None
    lines = iter(result.stdout.splitlines())
    for line in lines:
        if re.fullmatch(r"0x[0-9a-fA-F]+", line):
            current = sites.setdefault(int(line, 16), [])
        elif current is not None:
            source = next(lines, "??:0").split(" (discriminator ", 1)[0]
            source = source.removeprefix(str(trace.MODULE_PATH) + "/")
            current.append({"function": line, "location": source})
    return sites


def analyze_cell(target: str, text: str, elf: Path, env: dict, sdk: Path | None) -> dict:
    regions = cta.parse_trace(text)
    if [region.label for region in regions] != LABELS:
        raise cta.TraceError("expected all 48 key/ciphertext regions in workload order")
    base = cta.analyze(regions)
    inv = static.inventory(elf, target, sdk)
    result = {
        "instructions": sorted(base.instructions),
        "divergent_channels": sorted({channel for channel, _, _ in base.divergent}),
        "regions": base.regions,
        "ndiv": sorted(base.ndiv),
        "static_vlat": len(inv["vlat"]),
        "static_branches": sum(inv["branches"].values()),
        "static_precision": None,
        "recall": None,
        "secret_sites": [],
        "status": "CLEAN" if base.clean else "FAIL",
    }
    if target == "x86_64":
        return result
    vlat = cta.analyze_vlat(regions, cta.parse_vlat(text),
                            long_mul_variable=trace.LONG_MUL_VARIABLE[target])
    agreement = static.cross_validate(inv, vlat)
    pcs = agreement["secret_varying_pcs"]
    functions = trace.functions_for(elf, pcs, env)
    source = source_sites(elf, pcs, sdk)
    reasons = {pc: why for pc, _, why in vlat.fail_sites}
    result.update(
        static_agreement=agreement, static_precision=agreement["precision"],
        recall=agreement["recall"],
        secret_sites=[
            {"pc": hex(pc), "function": inv["vlat"].get(pc, (functions.get(pc, "?"),))[0],
             "kind": cta.VLAT_KINDS[vlat.sites[pc]], "source": source.get(pc, []),
             "model_violation": reasons.get(pc)}
            for pc in pcs
        ],
    )
    if not vlat.clean or agreement["dynamic_only"] or agreement["kind_mismatches"]:
        result["status"] = "FAIL"
    elif pcs:
        result["status"] = "CANDIDATE"
    return result


def error_excerpt(log: Path, exc: Exception) -> str:
    with log.open(encoding="utf-8", errors="replace") as handle:
        lines = deque((line.rstrip() for line in handle if line.strip()), maxlen=20)
    return "\n".join([*lines, str(exc)])


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_cell(target: str, name: str, out: Path, sdk: Path | None, **setup) -> dict:
    variant = VARIANTS[name]
    build = out / f"{target}-{name}"
    output = out / f"trace-{target}-{name}.txt"
    log = out / f"{target}-{name}.log"
    print(f"[ct-compiler] {target} {name} (log {log})", flush=True)
    cell = {"target": target, "variant": name, "expected_cc": variant.compiler,
            "expected_opt": variant.opt, "expected_lto": variant.lto, "log": log.name}
    runner = trace.trace_once if target == "x86_64" else trace.trace_core
    target_args = {} if target == "x86_64" else {"target": target}
    try:
        with log.open("w", encoding="utf-8") as handle, redirect_stdout(handle):
            text = runner(
                trace.MODULE_PATH, build, output, opt="default",
                extra_cmake=variant.cmake_flags(),
                after_build=lambda directory: cell.update(
                    verify_compile_commands(directory, variant)),
                **target_args, **setup,
            )
        elf = build / "zephyr" / "zephyr.elf"
        cell.update(analyze_cell(target, text, elf, setup["env"], sdk))
        device = (build / "ct_trace_device.log").read_text(encoding="utf-8", errors="replace")
        digests = re.findall(r"PQCP_CT_SSDIGEST (0x[0-9a-f]{8})", device)
        if len(digests) != 1:
            raise cta.TraceError("workload did not emit one shared-secret digest")
        cell.update(elf_sha256=sha256(elf), trace_sha256=sha256(output),
                    workload_digest=digests[0])
    except (trace.TraceBuildError, ConfigMismatch) as exc:
        cell.update(status="BUILD_FAIL" if isinstance(exc, trace.TraceBuildError)
                    else "CONFIG_MISMATCH", error=error_excerpt(log, exc))
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        cell.update(status="FAIL", error=error_excerpt(log, exc))
    return cell


def site_key(site: dict) -> tuple | None:
    for frame in site["source"]:
        if frame["location"].startswith(("ext/", "src/")):
            return site["kind"], frame["location"]
    return None


def compare_lto(cells: list[dict]) -> list[dict]:
    by_cell = {(cell["target"], cell["variant"]): cell for cell in cells}
    comparisons = []
    for lto in cells:
        if not lto["expected_lto"]:
            continue
        base = by_cell.get((lto["target"], lto["variant"].removesuffix("-lto")))
        if base is None or "workload_digest" not in base or "workload_digest" not in lto:
            continue
        old = Counter(site_key(site) for site in base["secret_sites"])
        new = Counter(site_key(site) for site in lto["secret_sites"])
        additional = [f"{kind}@{location}" for (kind, location) in sorted(
            key for key in (new - old).elements() if key is not None)]
        channels = sorted(set(lto["divergent_channels"]) - set(base["divergent_channels"]))
        comparisons.append({"target": lto["target"], "variant": lto["variant"],
                            "additional_sites": additional, "additional_channels": channels,
                            "unresolved_sites": new[None] + old[None]})
    return comparisons


def format_cell(cell: dict) -> str:
    sites = ",".join(f"{s['function']}@{s['pc']}" for s in cell.get("secret_sites", []))
    insns = ",".join(map(str, cell.get("instructions", [])))
    return (f"PQCP_CT_COMPILER target={cell['target']} variant={cell['variant']} "
            f"cc={cell.get('cc', 'na')} opt={cell.get('opt', 'na')} "
            f"lto={int(cell['lto']) if 'lto' in cell else 'na'} "
            f"status={cell['status']} insns={insns or 'na'} secret_sites={sites or 'na'} "
            f"static_precision={static.format_rate(cell.get('static_precision'))} "
            f"recall={static.format_rate(cell.get('recall'))}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS, nargs="+", default=TARGETS)
    parser.add_argument("--variant", choices=VARIANTS, nargs="+", default=list(VARIANTS))
    parser.add_argument("--west-root", type=Path)
    parser.add_argument("--west")
    parser.add_argument("--sdk", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--qemu-plugin-inc", type=Path)
    parser.add_argument("--strict-build", action="store_true")
    args = parser.parse_args()
    env = trace.clean_env()
    if args.sdk:
        args.sdk = args.sdk.resolve()
        env["ZEPHYR_SDK_INSTALL_DIR"] = str(args.sdk)
    out = (args.output_dir or trace.MODULE_PATH / "build-ct-compiler").resolve()
    out.mkdir(parents=True, exist_ok=True)
    report = out / "compiler_matrix.json"
    report.unlink(missing_ok=True)
    try:
        west_root = trace.detect_west_root(args.west_root or trace.MODULE_PATH)
        west_cmd = trace.discover_west(args.west, west_root, trace.MODULE_PATH)
        inc = args.qemu_plugin_inc or trace.detect_plugin_include(env)
        if inc is None:
            raise RuntimeError("could not locate qemu-plugin.h")
        plugin = trace.build_plugin(inc, env)
    except (RuntimeError, OSError) as exc:
        print(f"[ct-compiler] FAIL: {exc}")
        return 1

    cells = []
    for target in dict.fromkeys(args.target):
        for name in dict.fromkeys(args.variant):
            cell = run_cell(target, name, out, args.sdk, west_root=west_root,
                            west_cmd=west_cmd, env=env, plugin=plugin)
            cells.append(cell)
            print(format_cell(cell), flush=True)
            if "error" in cell:
                print(cell["error"], flush=True)
    counts = Counter(cell["status"] for cell in cells)
    comparisons = compare_lto(cells)
    digest_count = len({cell["workload_digest"] for cell in cells if "workload_digest" in cell})
    failed = (
        counts["FAIL"] or counts["CONFIG_MISMATCH"] or digest_count != 1
        or any(cell["status"] == "BUILD_FAIL"
               and (args.strict_build or cell["expected_cc"] != "clang") for cell in cells)
        or any(row["additional_sites"] or row["additional_channels"]
               or row["unresolved_sites"] for row in comparisons)
    )
    status = "FAIL" if failed else "PASS"
    report.write_text(json.dumps({"status": status, "cells": cells,
                                  "lto_comparisons": comparisons},
                                 sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(f"PQCP_CT_COMPILER_MATRIX cells={len(cells)} clean={counts['CLEAN']} "
          f"candidate={counts['CANDIDATE']} fail={counts['FAIL']} "
          f"build_fail={counts['BUILD_FAIL']} config_mismatch={counts['CONFIG_MISMATCH']} "
          f"digests={digest_count} status={status}")
    return int(bool(failed))


if __name__ == "__main__":
    sys.exit(main())
