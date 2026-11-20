#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
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
import shutil
import signal
import subprocess
import sys
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
               timeout: int = 300) -> str:
    """Build `module`'s trace app, run it under the plugin, return the trace."""
    run_command(
        [*west_cmd, "build", "-p", "always", "-b", "qemu_x86_64",
         str(module / TEST_APP_RELATIVE), "-d", str(build_dir), "--",
         f"-DZEPHYR_EXTRA_MODULES={module}", *OPT_FLAGS[opt]],
        cwd=west_root, env=env, timeout=600)
    run_command(["ninja", "-C", str(build_dir),
                 "zephyr/qemu_locore_image_target",
                 "zephyr/qemu_main_image_target"],
                cwd=module, env=env, timeout=120)
    elf = build_dir / "zephyr" / "zephyr.elf"
    begin = resolve_symbol(elf, "pqcp_ct_region_begin", env)
    end = resolve_symbol(elf, "pqcp_ct_region_end", env)
    if outfile.exists():
        outfile.unlink()
    device_log = build_dir / "ct_trace_device.log"
    cmd = qemu_run_command(build_dir)
    binary, rest = cmd.split(" ", 1)
    cmd = (f"{binary} -plugin {plugin},begin=0x{begin:x},end=0x{end:x},"
           f"outfile={outfile} {rest}")
    with device_log.open("w") as handle:
        proc = subprocess.Popen(cmd, shell=True, cwd=str(build_dir), env=env,
                                stdout=handle, stderr=subprocess.STDOUT,
                                start_new_session=True)
        deadline = time.time() + timeout
        while time.time() < deadline and proc.poll() is None:
            if DEVICE_MARKER in device_log.read_text(errors="replace"):
                time.sleep(1)
                break
            time.sleep(1)
        if proc.poll() is None:
            os.killpg(os.getpgid(proc.pid), signal.SIGINT)
            time.sleep(2)
            if proc.poll() is None:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    if DEVICE_MARKER not in device_log.read_text(errors="replace"):
        raise RuntimeError("device marker not observed:\n" +
                           device_log.read_text(errors="replace")[-1500:])
    if not outfile.exists():
        raise RuntimeError("plugin produced no trace output")
    return outfile.read_text()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--west-root", type=Path)
    parser.add_argument("--west")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--qemu-plugin-inc", type=Path)
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

    if args.rediscover:
        import ct_leak_rediscovery as leaks  # noqa: PLC0415

        def run_trace(tree, build_dir, outfile, opt):
            return trace_once(tree, build_dir, outfile, opt=opt,
                              west_root=west_root, west_cmd=west_cmd,
                              env=env, plugin=plugin)

        only = set(os.environ.get("PQCP_CT_LEAK_ONLY", "").split(",")) - {""}
        return leaks.rediscover(run_trace, (args.opt or ["default"])[0],
                                only or None)

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
