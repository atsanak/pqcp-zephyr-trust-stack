#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Relational leakage test of ML-KEM-768 decapsulation on the deployed image.

Builds tests/ztest_ct_trace for qemu_x86_64, runs it under the
pqcp_ct_trace TCG plugin and requires every decapsulation region of one key
(8 keys x 6 ciphertexts: 1 valid, 5 corrupted) to be indistinguishable on four
channels: executed instruction addresses, exact data addresses, 64-byte
cache lines and the dividend of every div/idiv. See scripts/ct_trace_analysis.py
for the metrics and docs/ct-trace-leakage.md for scope and non-claims.

Not a constant-time proof; x86_64 under emulation, no microarchitecture.
"""

import argparse
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
MODULE_PATH = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

import ct_trace_analysis as cta  # noqa: E402
from local_workflow import (  # noqa: E402
    clean_env, detect_west_root, discover_west, run_command)
from run_ct_instruction_checks import (  # noqa: E402
    detect_plugin_include, glib_cflags, qemu_run_command, resolve_symbol)

PLUGIN_DIR = MODULE_PATH / "tools" / "tcg_ct_plugin"
TEST_APP_RELATIVE = "tests/ztest_ct_trace"
DEVICE_MARKER = "PQCP_CT_TRACE_APP alg=MLKEM-768"
ALG = "MLKEM-768"
OPT_FLAGS = {
    "default": [],
    # Zephyr's default is already -Os, so "default" covers size.
    "speed": ["-DCONFIG_SPEED_OPTIMIZATIONS=y"],
    "debug": ["-DCONFIG_DEBUG_OPTIMIZATIONS=y"],
}


def build_plugin(plugin_inc: Path, env: dict) -> Path:
    ext = "dylib" if sys.platform == "darwin" else "so"
    run_command(["make", "-C", str(PLUGIN_DIR), "clean"],
                cwd=MODULE_PATH, env=env, timeout=60)
    run_command(["make", "-C", str(PLUGIN_DIR),
                 f"QEMU_PLUGIN_INC={plugin_inc}",
                 f"GLIB_CFLAGS={glib_cflags()}"],
                cwd=MODULE_PATH, env=env, timeout=120)
    path = PLUGIN_DIR / f"libpqcp_ct_trace.{ext}"
    if not path.exists():
        raise RuntimeError(f"plugin not built at {path}")
    return path


def trace_once(module: Path, build_dir: Path, outfile: Path, *, opt: str,
               west_root: Path, west_cmd: list, env: dict, plugin: Path,
               timeout: int = 300, app: str = TEST_APP_RELATIVE,
               marker: str = DEVICE_MARKER,
               event_symbol: str | None = None,
               board: str = "qemu_x86_64",
               extra_cmake: tuple = (),
               residue: bool = False) -> str:
    """Build `module`'s trace app, run it under the plugin, return the trace."""
    run_command(
        [*west_cmd, "build", "-p", "always", "-b", board,
         str(module / app), "-d", str(build_dir), "--",
         f"-DZEPHYR_EXTRA_MODULES={module}", *OPT_FLAGS[opt],
         *extra_cmake],
        cwd=west_root, env=env, timeout=600)
    if board == "qemu_x86_64":
        run_command(["ninja", "-C", str(build_dir),
                     "zephyr/qemu_locore_image_target",
                     "zephyr/qemu_main_image_target"],
                    cwd=module, env=env, timeout=120)
    elf = build_dir / "zephyr" / "zephyr.elf"
    begin = resolve_symbol(elf, "pqcp_ct_region_begin", env)
    end = resolve_symbol(elf, "pqcp_ct_region_end", env)
    event_arg = ""
    if event_symbol is not None:
        event_arg = f",event=0x{resolve_symbol(elf, event_symbol, env):x}"
    if outfile.exists():
        outfile.unlink()
    device_log = build_dir / "ct_trace_device.log"
    cmd = qemu_run_command(build_dir)
    binary, rest = cmd.split(" ", 1)
    res_arg = ",residue=1" if residue else ""
    cmd = (f"{binary} -plugin {plugin},begin=0x{begin:x},end=0x{end:x}"
           f"{event_arg}{res_arg},outfile={outfile} {rest}")
    with device_log.open("w") as handle:
        proc = subprocess.Popen(cmd, shell=True, cwd=str(build_dir), env=env,
                                stdout=handle, stderr=subprocess.STDOUT,
                                start_new_session=True)
        deadline = time.time() + timeout
        while time.time() < deadline and proc.poll() is None:
            if marker in device_log.read_text(errors="replace"):
                time.sleep(1)
                break
            time.sleep(1)
        if proc.poll() is None:
            os.killpg(os.getpgid(proc.pid), signal.SIGINT)
            time.sleep(2)
            if proc.poll() is None:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    if marker not in device_log.read_text(errors="replace"):
        raise RuntimeError("device marker not observed:\n" +
                           device_log.read_text(errors="replace")[-1500:])
    if not outfile.exists():
        raise RuntimeError("plugin produced no trace output")
    return outfile.read_text()


CORTEX_M3_TARGET = "cortex-m3"
CORE_BOARDS = {"cortex-m3": "mps2/an385", "cortex-m4": "mps2/an386",
               "cortex-m33": "mps2/an521/cpu0"}
# M3 long multiplies terminate early on operand size (ARM DDI 0337); M4's
# are single-cycle. Both share the variable-latency divider.
LONG_MUL_VARIABLE = {"cortex-m3": True, "cortex-m4": False,
                     "cortex-m33": False}


def kem_level_kwargs(level: int, out: Path) -> dict:
    """Marker and Kconfig overlay for one ML-KEM parameter set."""
    if level == 768:
        return {}
    overlay = (out / f"kem{level}.conf").resolve()
    overlay.write_text("CONFIG_PQCP_MLKEM_LEVEL_768=n\n"
                       f"CONFIG_PQCP_MLKEM_LEVEL_{level}=y\n",
                       encoding="utf-8")
    return {"marker": f"PQCP_CT_TRACE_APP alg=MLKEM-{level}",
            "extra_cmake": (f"-DEXTRA_CONF_FILE={overlay}",)}


def trace_core(module: Path, build_dir: Path, outfile: Path, *, opt: str,
               target: str = CORTEX_M3_TARGET, **kwargs) -> str:
    return trace_once(module, build_dir, outfile, opt=opt,
                      board=CORE_BOARDS[target], **kwargs)


def functions_for(elf: Path, pcs, env: dict) -> dict:
    """pc -> containing function name, from the ELF symbol table."""
    import bisect  # noqa: PLC0415
    sdk = Path.home() / "zephyr-sdk-1.0.1"
    candidates = [str(sdk / "gnu" / "arm-zephyr-eabi" / "bin" /
                      "arm-zephyr-eabi-nm"),
                  str(sdk / "arm-zephyr-eabi" / "bin" / "arm-zephyr-eabi-nm"),
                  str(sdk / "gnu" / "x86_64-zephyr-elf" / "bin" /
                      "x86_64-zephyr-elf-nm"),
                  shutil.which("nm") or "nm"]
    addrs, names = [], []
    for nm in candidates:
        if not Path(nm).exists() and nm != (shutil.which("nm") or "nm"):
            continue
        out = subprocess.run([nm, "-n", str(elf)], capture_output=True,
                             text=True, env=env).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[1] in "tTwW":
                addrs.append(int(parts[0], 16) & ~1)
                names.append(parts[2])
        if addrs:
            break
    result = {}
    for pc in pcs:
        i = bisect.bisect_right(addrs, pc) - 1
        result[pc] = names[i] if i >= 0 else "?"
    return result


def report_models(text: str, elf: Path, env: dict, alg: str, opt: str,
                  target: str, *, declassified: bool) -> "cta.ModelComparison":
    """Evaluate the documented and the CMEmu latency model on one trace."""
    regions = cta.parse_trace(text)
    records = cta.parse_vlat(text)
    cmp_ = cta.compare_latency_models(regions, records,
                                      compare_counts=not declassified)
    fns = functions_for(elf, cmp_.documented | cmp_.cmemu, env)
    doc_v = cm_v = None
    if declassified:
        segments = cta.parse_segments(text)
        doc_v = len(cta.analyze_declassified(
            regions, segments,
            channels=cta.CORE_CHANNELS["cortex-m3"]).violations)
        cm_v = len(cta.analyze_declassified(
            regions, segments,
            channels=cta.CORE_CHANNELS["cortex-m3-cmemu"]).violations)
    print(cta.format_models_marker(cmp_, alg, opt, target, fns, doc_v, cm_v))
    if not declassified:
        print(cta.format_cycles_marker(cta.modelled_cycles(regions, records),
                                       alg, opt, target))
    for pc in sorted(cmp_.cmemu_only):
        print(f"[ct-trace] cmemu-only site "
              f"{cta.VLAT_KINDS[cmp_.kinds[pc]]} at 0x{pc:x} in "
              f"{fns.get(pc, '?')}")
    return cmp_


def run_core(args, out: Path, west_root: Path, west_cmd: list, env: dict,
             plugin: Path) -> int:
    target = args.target
    level = 768 if args.kem_level == "all" else int(args.kem_level)
    alg = f"MLKEM-{level}"
    kw = kem_level_kwargs(level, out)
    failed = False
    for opt in args.opt or ["default", "speed", "debug"]:
        print(f"[ct-trace] ML-KEM decapsulation on {target} "
              f"({CORE_BOARDS[target]}), optimisation={opt}")
        text = trace_core(MODULE_PATH, out / f"build-{target}-{opt}",
                          out / f"trace-{target}-{opt}.txt", opt=opt,
                          target=target, west_root=west_root,
                          west_cmd=west_cmd, env=env, plugin=plugin, **kw)
        analysis = cta.analyze_vlat(
            cta.parse_trace(text), cta.parse_vlat(text),
            long_mul_variable=LONG_MUL_VARIABLE[target])
        print(cta.format_vlat_marker(analysis, alg, opt, target))
        if target == CORTEX_M3_TARGET:
            report_models(text, out / f"build-{target}-{opt}" / "zephyr" /
                          "zephyr.elf", env, alg, opt, target,
                          declassified=False)
        for pc, kind in analysis.candidate_sites:
            print(f"[ct-trace] candidate {cta.VLAT_KINDS[kind]} at "
                  f"0x{pc:x}: exact operands vary with the secret "
                  f"(documented latency model clean)")
        for pc, kind, why in analysis.fail_sites:
            print(f"[ct-trace] FAIL site {cta.VLAT_KINDS[kind]} at "
                  f"0x{pc:x}: {why}")
        if not analysis.clean:
            failed = True
    if failed:
        print(f"[ct-trace] FAIL: operand-dependent latency or address-level "
              f"divergence on {target}")
        return 1
    print(f"[ct-trace] PASS: no secret-dependent operand latency under the "
          f"documented {target} model")
    return 0


def report_residue(text: str, elf: Path, env: dict, alg: str, opt: str,
                   target: str) -> None:
    import ct_residue_analysis as ra  # noqa: PLC0415
    res = ra.analyze(text)
    pcs = set(res.by_pc)
    fns = functions_for(elf, pcs, env) if pcs else {}
    print(ra.format_marker(res, alg, opt, target, fns))


def run_core_mldsa(args, out: Path, west_root: Path, west_cmd: list,
                   env: dict, plugin: Path) -> int:
    """Declassification-aware ML-DSA-65 signing on a Cortex-M core."""
    target = args.target
    failed = False
    measured_only = True   # only documented-model multiply findings so far
    positive_control = False
    for opt in args.opt or ["default", "speed", "debug"]:
        print(f"[ct-trace] ML-DSA-65 signing on {target} "
              f"({CORE_BOARDS[target]}), optimisation={opt}")
        text = trace_core(MODULE_PATH, out / f"build-{target}-dsa-{opt}",
                          out / f"trace-{target}-dsa-{opt}.txt", opt=opt,
                          target=target, west_root=west_root,
                          west_cmd=west_cmd, env=env, plugin=plugin,
                          timeout=1500, app=MLDSA_APP, marker=MLDSA_MARKER,
                          event_symbol="pqcp_ct_event", residue=args.residue)
        if args.residue:
            report_residue(text, out / f"build-{target}-dsa-{opt}" / "zephyr" /
                           "zephyr.elf", env, "MLDSA-65", opt, target)
        regions = cta.parse_trace(text)
        analysis = cta.analyze_declassified(
            regions, cta.parse_segments(text),
            channels=cta.CORE_CHANNELS[target])
        sites = cta.analyze_vlat(
            regions, cta.parse_vlat(text),
            long_mul_variable=LONG_MUL_VARIABLE[target],
            compare_counts=False)
        print(cta.format_vlat_declass_marker(analysis, sites, "MLDSA-65",
                                             opt, target))
        if target == CORTEX_M3_TARGET:
            report_models(text, out / f"build-{target}-dsa-{opt}" / "zephyr" /
                          "zephyr.elf", env, "MLDSA-65", opt, target,
                          declassified=True)
        for pc, kind, why in sites.fail_sites:
            print(f"[ct-trace] site {cta.VLAT_KINDS[kind]} at 0x{pc:x}: "
                  f"{why}")
        for kind, group, region, seq, detail in analysis.violations[:4]:
            print(f"[ct-trace] violation {kind} group={group} "
                  f"region={region} seq={seq}")
        if not analysis.clean:
            failed = True
            bad = [v for v in analysis.violations if v[0] != "vmul"]
            measured_only = measured_only and not bad
            positive_control = positive_control or any(
                v[0] == "vmul" for v in analysis.violations)
    if failed and args.measure:
        # Inventory mode: the documented-model multiply findings are the
        # measurement; anything on another channel is still a failure.
        if measured_only and positive_control:
            print(f"[ct-trace] MEASURED: {target} signing leaks only "
                  f"through operand-size-dependent long multiplies")
            return 0
        print(f"[ct-trace] FAIL: unexpected behaviour on {target}")
        return 1
    if failed:
        print(f"[ct-trace] FAIL: signing shows secret-dependent behaviour "
              f"on {target}")
        return 1
    print(f"[ct-trace] PASS: every comparable segment is identical on "
          f"every {target} channel")
    return 0


def read_sig_digest(build_dir: Path) -> str | None:
    log = (build_dir / "ct_trace_device.log").read_text(errors="replace")
    match = re.search(r"PQCP_CT_SIGDIGEST (0x[0-9a-f]{8}) signatures=(\d+)",
                      log)
    return f"{match.group(1)}/{match.group(2)}" if match else None


def run_core_mlkem_mitigated(args, out: Path, west_root: Path,
                             west_cmd: list, env: dict,
                             plugin: Path) -> int:
    """Claim 17: the operand-offset repair of the compress_d10 multiply must
    remove the CMEmu-only site, keep the documented model clean, leave the
    shared secrets unchanged and cost only a few instructions."""
    import mlkem_fixed_latency as fixed  # noqa: PLC0415

    target = args.target
    problems = fixed.check()
    if problems:
        print("\n".join(f"[ct-trace] {p}" for p in problems))
        return 1
    failed = False
    with tempfile.TemporaryDirectory(prefix="pqcp-ct-kemfix-") as tmp:
        patched = fixed.materialise(Path(tmp) / "module")
        levels = (512, 768, 1024) if args.kem_level == "all" else \
            (int(args.kem_level),)
        for level, opt in [(lv, o) for lv in levels for o in
                           (args.opt or ["default", "speed", "debug"])]:
            alg = f"MLKEM-{level}"
            kw = kem_level_kwargs(level, out)
            res = {}
            for name, module in (("stock", MODULE_PATH),
                                 ("patched", patched)):
                print(f"[ct-trace] ML-KEM-768 decapsulation on {target}, "
                      f"{name} build, optimisation={opt}")
                build = out / f"build-{target}-kem{level}-{name}-{opt}"
                text = trace_core(module, build,
                                  out / f"trace-{target}-kem{level}-{name}-{opt}.txt",
                                  opt=opt, target=target,
                                  west_root=west_root, west_cmd=west_cmd,
                                  env=env, plugin=plugin, **kw)
                models = report_models(text, build / "zephyr" / "zephyr.elf",
                                       env, alg, f"{opt}-{name}", target,
                                       declassified=False)
                log = (build / "ct_trace_device.log").read_text(
                    errors="replace")
                m = re.search(r"PQCP_CT_SSDIGEST (0x[0-9a-f]{8})", log)
                res[name] = (models, m.group(1) if m else None,
                             sum(r.insns for r in cta.parse_trace(text)))
            (sm, sd, si), (pm, pd, pi) = res["stock"], res["patched"]
            overhead = 100.0 * (pi - si) / max(si, 1)
            issues = []
            if not sm.cmemu_only:
                issues.append("stock build shows no CMEmu-only site "
                              "(positive control lost)")
            if pm.documented or pm.cmemu:
                issues.append("patched build still has a failing site")
            if sd is None or sd != pd:
                issues.append(f"shared-secret digest differs: {sd} vs {pd}")
            print(f"PQCP_CT_TRACE_VLAT_MITIGATION_KEM "
                  f"{'FAIL' if issues else 'PASS'} alg={alg} target={target} "
                  f"opt={opt} stock_cmemu_only={len(sm.cmemu_only)} "
                  f"patched_documented_sites={len(pm.documented)} "
                  f"patched_cmemu_sites={len(pm.cmemu)} "
                  f"ss_digest_match={int(sd is not None and sd == pd)} "
                  f"insn_overhead_pct={overhead:.2f}")
            for issue in issues:
                print(f"[ct-trace] FAIL: {issue}")
            failed = failed or bool(issues)
    if not failed:
        print("[ct-trace] PASS: the repair removes the finding at every "
              "parameter set and level without changing the output")
    return 1 if failed else 0


def run_core_mldsa_mitigated(args, out: Path, west_root: Path,
                             west_cmd: list, env: dict,
                             plugin: Path) -> int:
    """Closed loop for claim 15: the stock Cortex-M3 signing image must show
    the long-multiply finding (positive control), the fixed-latency build
    must show none on any channel, and both must produce the same signatures
    (digest) and the same control flow, with the instruction overhead
    measured."""
    import mldsa_fixed_latency as fixed  # noqa: PLC0415

    target = args.target
    problems = fixed.check()
    if problems:
        print("\n".join(f"[ct-trace] {p}" for p in problems))
        return 1
    failed = False
    with tempfile.TemporaryDirectory(prefix="pqcp-ct-fixed-") as tmp:
        patched = fixed.materialise(Path(tmp) / "module")
        for opt in args.opt or ["default", "speed", "debug"]:
            results = {}
            for name, module in (("stock", MODULE_PATH),
                                 ("patched", patched)):
                print(f"[ct-trace] ML-DSA-65 signing on {target}, "
                      f"{name} build, optimisation={opt}")
                build = out / f"build-{target}-dsa-{name}-{opt}"
                text = trace_core(module, build,
                                  out / f"trace-{target}-dsa-{name}-{opt}.txt",
                                  opt=opt, target=target,
                                  west_root=west_root, west_cmd=west_cmd,
                                  env=env, plugin=plugin, timeout=1500,
                                  app=MLDSA_APP, marker=MLDSA_MARKER,
                                  event_symbol="pqcp_ct_event")
                regions = cta.parse_trace(text)
                decl = cta.analyze_declassified(
                    regions, cta.parse_segments(text),
                    channels=cta.CORE_CHANNELS[target])
                sites = cta.analyze_vlat(
                    regions, cta.parse_vlat(text),
                    long_mul_variable=LONG_MUL_VARIABLE[target],
                    compare_counts=False)
                print(f"[ct-trace] latency models, {name} build")
                models = report_models(
                    text, build / "zephyr" / "zephyr.elf", env, "MLDSA-65",
                    f"{opt}-{name}", target, declassified=True)
                results[name] = {
                    "decl": decl, "sites": sites, "models": models,
                    "digest": read_sig_digest(build),
                    "insns": sum(r.insns for r in regions)}
            stock, patched_r = results["stock"], results["patched"]
            stock_vmul = sum(1 for v in stock["decl"].violations
                             if v[0] == "vmul")
            overhead = (100.0 * (patched_r["insns"] - stock["insns"]) /
                        max(stock["insns"], 1))
            issues = []
            if stock_vmul == 0:
                issues.append("stock build shows no long-multiply finding "
                              "(positive control lost)")
            if not patched_r["decl"].clean:
                issues.append(f"patched build still has "
                              f"{len(patched_r['decl'].violations)} "
                              f"violation(s)")
            if patched_r["sites"].fail_sites:
                issues.append(f"patched build still has "
                              f"{len(patched_r['sites'].fail_sites)} "
                              f"attributed site(s)")
            if (stock["digest"] is None or
                    stock["digest"] != patched_r["digest"]):
                issues.append(f"signature digest differs: "
                              f"{stock['digest']} vs {patched_r['digest']}")
            print(f"PQCP_CT_TRACE_VLAT_MITIGATION "
                  f"{'FAIL' if issues else 'PASS'} alg=MLDSA-65 "
                  f"target={target} opt={opt} "
                  f"stock_vmul_violations={stock_vmul} "
                  f"stock_sites={len(stock['sites'].fail_sites)} "
                  f"patched_violations={len(patched_r['decl'].violations)} "
                  f"patched_sites={len(patched_r['sites'].fail_sites)} "
                  f"patched_testable={patched_r['decl'].testable} "
                  f"sig_digest_match="
                  f"{int(stock['digest'] == patched_r['digest'])} "
                  f"insn_overhead_pct={overhead:.1f}")
            for issue in issues:
                print(f"[ct-trace] FAIL: {issue}")
            failed = failed or bool(issues)
    if not failed:
        print("[ct-trace] PASS: the patch removes the finding at every level "
              "without changing the signatures")
    return 1 if failed else 0


MLDSA_APP = "tests/ztest_ct_trace_mldsa"
MLDSA_MARKER = "PQCP_CT_TRACE_APP alg=MLDSA-65"


def run_mldsa(args, out: Path, west_root: Path, west_cmd: list, env: dict,
              plugin: Path) -> int:
    failed = False
    for opt in args.opt or ["default", "speed", "debug"]:
        print(f"[ct-trace] ML-DSA-65 signing (declassification-aware), "
              f"optimisation={opt}")
        text = trace_once(MODULE_PATH, out / f"build-mldsa-{opt}",
                          out / f"trace-mldsa-{opt}.txt", opt=opt,
                          west_root=west_root, west_cmd=west_cmd, env=env,
                          plugin=plugin, timeout=900, app=MLDSA_APP,
                          marker=MLDSA_MARKER,
                          event_symbol="pqcp_ct_event", residue=args.residue)
        if args.residue:
            report_residue(text, out / f"build-mldsa-{opt}" / "zephyr" /
                           "zephyr.elf", env, "MLDSA-65", opt, "x86_64")
        regions = cta.parse_trace(text)
        analysis = cta.analyze_declassified(regions, cta.parse_segments(text))
        print(cta.format_declass_marker(analysis, "MLDSA-65", opt))
        print(f"[ct-trace] events/region={sorted(analysis.iterations_seen)} "
              f"singleton_segments={analysis.singleton}")
        if not analysis.clean:
            failed = True
            for kind, group, region, seq, detail in analysis.violations[:8]:
                print(f"[ct-trace] violation {kind} group={group} "
                      f"region={region} seq={seq}: {detail}")
    if failed:
        print("[ct-trace] FAIL: signing behaviour depends on the secret "
              "beyond the declassified values")
        return 1
    print("[ct-trace] PASS: every comparable segment is identical on every "
          "modelled channel")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--west-root", type=Path)
    parser.add_argument("--west")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--qemu-plugin-inc", type=Path)
    parser.add_argument("--alg", choices=("mlkem", "mldsa"), default="mlkem",
                        help="mlkem: decapsulation (whole-region relation); "
                             "mldsa: signing (declassification-aware "
                             "segment relation)")
    parser.add_argument("--target", choices=("x86_64", *CORE_BOARDS),
                        default="x86_64",
                        help="x86_64: qemu_x86_64 (default); cortex-m3 / "
                             "cortex-m4: mps2/an385 / mps2/an386 with the "
                             "operand-latency channel")
    parser.add_argument("--kem-level", choices=("512", "768", "1024", "all"),
                        default="768",
                        help="ML-KEM parameter set (Cortex-M3); `all` runs "
                             "the three with --mitigated")
    parser.add_argument("--residue", action="store_true",
                        help="ML-DSA signing: also record stack words left "
                             "below the caller after the call and compare "
                             "them across secret variants")
    parser.add_argument("--measure", action="store_true",
                        help="Cortex-M signing: exit 0 when the only "
                             "findings are documented-model long-multiply "
                             "violations (an inventory, not a pass)")
    parser.add_argument("--mitigated", action="store_true",
                        help="Cortex-M3 signing: also build the fixed-latency "
                             "multiplication patch and require it to remove "
                             "the long-multiply finding without changing "
                             "the signatures")
    parser.add_argument("--rediscover", action="store_true",
                        help="re-inject known leak patterns and require the "
                             "test to catch them (sensitivity/specificity)")
    parser.add_argument("--opt", action="append",
                        choices=sorted(OPT_FLAGS), default=None,
                        help="optimisation level(s); default: default,speed,debug")
    args = parser.parse_args()

    if shutil.which("make") is None:
        print("[ct-trace] SKIP: no make")
        return 0
    env = clean_env()
    out = args.output_dir or (MODULE_PATH / "build-ct-trace")
    out.mkdir(parents=True, exist_ok=True)
    inc = args.qemu_plugin_inc or detect_plugin_include(env)
    if inc is None:
        print("[ct-trace] FAIL: could not locate qemu-plugin.h")
        return 1
    west_root = detect_west_root(args.west_root or MODULE_PATH)
    west_cmd = discover_west(args.west, west_root, MODULE_PATH)
    plugin = build_plugin(inc, env)

    if args.target != "x86_64":
        if args.rediscover:
            if args.alg != "mlkem" or args.target != CORTEX_M3_TARGET:
                print("[ct-trace] FAIL: --rediscover on a Cortex-M target "
                      "supports --alg mlkem --target cortex-m3")
                return 1
            import ct_leak_rediscovery_m3 as m3_leaks  # noqa: PLC0415

            def run_m3_trace(tree, build_dir, outfile, opt):
                return trace_core(tree, build_dir, outfile, opt=opt,
                                  west_root=west_root, west_cmd=west_cmd,
                                  env=env, plugin=plugin)

            only = set(os.environ.get("PQCP_CT_LEAK_ONLY", "").split(",")) - {""}
            return m3_leaks.rediscover(run_m3_trace,
                                       (args.opt or ["default"])[0],
                                       only or None)
        if args.alg == "mlkem" and args.mitigated:
            return run_core_mlkem_mitigated(args, out, west_root, west_cmd,
                                            env, plugin)
        if args.alg == "mldsa" and args.mitigated:
            return run_core_mldsa_mitigated(args, out, west_root, west_cmd,
                                            env, plugin)
        if args.alg == "mldsa":
            return run_core_mldsa(args, out, west_root, west_cmd, env,
                                  plugin)
        return run_core(args, out, west_root, west_cmd, env, plugin)

    if args.rediscover and args.alg == "mldsa":
        import ct_leak_rediscovery_mldsa as dsa_leaks  # noqa: PLC0415

        def run_dsa_trace(tree, build_dir, outfile, opt):
            return trace_once(tree, build_dir, outfile, opt=opt,
                              west_root=west_root, west_cmd=west_cmd,
                              env=env, plugin=plugin, timeout=900,
                              app=MLDSA_APP, marker=MLDSA_MARKER,
                              event_symbol="pqcp_ct_event")

        only = set(os.environ.get("PQCP_CT_LEAK_ONLY", "").split(",")) - {""}
        return dsa_leaks.rediscover(run_dsa_trace,
                                    (args.opt or ["default"])[0],
                                    only or None)

    if args.rediscover:
        import ct_leak_rediscovery as leaks  # noqa: PLC0415

        def run_trace(tree, build_dir, outfile, opt):
            return trace_once(tree, build_dir, outfile, opt=opt,
                              west_root=west_root, west_cmd=west_cmd,
                              env=env, plugin=plugin)

        only = set(os.environ.get("PQCP_CT_LEAK_ONLY", "").split(",")) - {""}
        return leaks.rediscover(run_trace, (args.opt or ["default"])[0],
                                only or None)

    if args.alg == "mldsa":
        return run_mldsa(args, out, west_root, west_cmd, env, plugin)

    failed = False
    for opt in args.opt or ["default", "speed", "debug"]:
        print(f"[ct-trace] ML-KEM-768 decapsulation, optimisation={opt}")
        text = trace_once(MODULE_PATH, out / f"build-{opt}",
                          out / f"trace-{opt}.txt", opt=opt,
                          west_root=west_root, west_cmd=west_cmd, env=env,
                          plugin=plugin)
        analysis = cta.analyze(cta.parse_trace(text))
        print(cta.format_marker(analysis, ALG, opt))
        print(f"[ct-trace] cross-key distinct={analysis.cross_group_distinct} "
              f"(public-dependent, informational)")
        print(f"[ct-trace] "
              f"insns/region={sorted(analysis.instructions)} "
              f"div/region={sorted(analysis.ndiv)}")
        if not analysis.clean:
            failed = True
            for channel, index, fingerprint in analysis.divergent[:8]:
                print(f"[ct-trace] divergent {channel} region={index} "
                      f"{fingerprint}")
    if failed:
        print("[ct-trace] FAIL: decapsulation is distinguishable on at "
              "least one channel")
        return 1
    print("[ct-trace] PASS: every region is indistinguishable on every "
          "modelled channel")
    return 0


if __name__ == "__main__":
    sys.exit(main())
