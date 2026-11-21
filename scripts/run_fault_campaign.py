#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Exhaustive single-instruction fault campaign on the deployed PQC image.

Builds tests/ztest_fault_oracle for qemu_x86_64, then for every instruction in
the ML-KEM-768 decapsulation and ML-DSA-65 verify code applies each fault
model (SKIP, JCC_INV) to a copy of the image, runs it under QEMU and
classifies the observations by cryptographic meaning (scripts/fault_oracle.py).

Calibration before any result is trusted:
  * three unfaulted runs must give identical, valid observations
  * identity patches (same bytes written back) must all come out NO_EFFECT

Permanent faults only, single fault per run, x86_64 under emulation. See
docs/fault-campaign.md for scope and non-claims.
"""

import argparse
import json
import os
import random
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
MODULE_PATH = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

import fault_gdb  # noqa: E402
import fault_inject as fi  # noqa: E402
import fault_oracle as fo  # noqa: E402
from local_workflow import (  # noqa: E402
    clean_env, detect_west_root, discover_west, run_command)
from run_ct_instruction_checks import qemu_run_command  # noqa: E402

TEST_APP_RELATIVE = "tests/ztest_fault_oracle"
DEFAULT_TARGETS = (
    "PQCP_MLKEM_NATIVE_MLKEM768_dec",
    "pqcp_mlkem_decapsulate",
    "PQCP_MLDSA_NATIVE_MLDSA65_verify",
    "PQCP_MLDSA_NATIVE_MLDSA65_verify_internal",
    "pqcp_mldsa_verify",
)
SDK_GNU = "zephyr-sdk-*/gnu/x86_64-zephyr-elf/bin"


def sdk_tool(name: str) -> str:
    for base in sorted(Path.home().glob(SDK_GNU)):
        tool = base / f"x86_64-zephyr-elf-{name}"
        if tool.exists():
            return str(tool)
    found = shutil.which(f"x86_64-zephyr-elf-{name}")
    if found:
        return found
    raise RuntimeError(f"x86_64-zephyr-elf-{name} not found in the SDK")


VARIANTS = {
    # plain: no boot self-test. boot: the existing valid-only power-on test.
    # boot-negative: the same plus negative vectors.
    "plain": [],
    "boot": ["-DCONFIG_PQCP_KAT_BOOT_VERIFY=y"],
    "boot-negative": ["-DCONFIG_PQCP_KAT_BOOT_VERIFY=y",
                      "-DCONFIG_PQCP_KAT_BOOT_VERIFY_NEGATIVE=y"],
    # Runtime countermeasures layered on boot-negative.
    "canary": ["-DCONFIG_PQCP_KAT_BOOT_VERIFY=y",
               "-DCONFIG_PQCP_KAT_BOOT_VERIFY_NEGATIVE=y",
               "-DCONFIG_PQCP_FAULT_CANARY=y"],
    "duplicate": ["-DCONFIG_PQCP_KAT_BOOT_VERIFY=y",
                  "-DCONFIG_PQCP_KAT_BOOT_VERIFY_NEGATIVE=y",
                  "-DCONFIG_PQCP_FAULT_DUPLICATE=y"],
    "hardened": ["-DCONFIG_PQCP_KAT_BOOT_VERIFY=y",
                 "-DCONFIG_PQCP_KAT_BOOT_VERIFY_NEGATIVE=y",
                 "-DCONFIG_PQCP_FAULT_CANARY=y",
                 "-DCONFIG_PQCP_FAULT_DUPLICATE=y"],
}


def build_image(module: Path, build_dir: Path, west_root: Path,
                west_cmd: list, env: dict, extra: list = ()) -> Path:
    run_command(
        [*west_cmd, "build", "-p", "always", "-b", "qemu_x86_64",
         str(module / TEST_APP_RELATIVE), "-d", str(build_dir), "--",
         f"-DZEPHYR_EXTRA_MODULES={module}", *extra],
        cwd=west_root, env=env, timeout=600)
    run_command(["ninja", "-C", str(build_dir),
                 "zephyr/qemu_locore_image_target",
                 "zephyr/qemu_main_image_target"],
                cwd=module, env=env, timeout=120)
    return build_dir


def qemu_command(build_dir: Path, image: Path) -> str:
    """The build's own QEMU command, retargeted at a patched image copy."""
    cmd = qemu_run_command(build_dir)
    main = str(build_dir / "zephyr" / "zephyr-qemu-main.elf")
    if main not in cmd:
        raise RuntimeError("qemu command does not load zephyr-qemu-main.elf")
    cmd = cmd.replace(main, str(image))
    # signal=off: the run is headless and must not react to a stray ^C.
    return cmd.replace("-chardev stdio,id=con,mux=on",
                       "-chardev stdio,id=con,mux=on,signal=off")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run_image(build_dir: Path, image: Path, env: dict, timeout: int,
              gdb_action=None) -> tuple[str, bool]:
    """Run one image; return (serial text, timed_out).

    gdb_action(gdb) runs against QEMU's gdbstub while the guest is halted at
    reset (-S); it applies a timed fault and detaches, after which the guest
    runs to completion.
    """
    command = qemu_command(build_dir, image)
    port = 0
    if gdb_action is not None:
        port = free_port()
        command += f" -S -gdb tcp:127.0.0.1:{port}"
    with tempfile.TemporaryDirectory(prefix="pqcp-fault-run-") as tmp:
        log = Path(tmp) / "serial.log"
        with log.open("w") as handle:
            proc = subprocess.Popen(
                command, shell=True, cwd=tmp, env=env,
                stdin=subprocess.DEVNULL, stdout=handle,
                stderr=subprocess.STDOUT, start_new_session=True)
            deadline = time.time() + timeout
            timed_out = False
            try:
                if gdb_action is not None:
                    gdb = fault_gdb.Gdb.connect(port)
                    gdb_action(gdb)
            except (fault_gdb.GdbError, OSError) as exc:
                log.write_text(log.read_text(errors="replace") +
                               f"\nPQCP_FAULT_HARNESS_ERROR {exc}\n")
            while True:
                if proc.poll() is not None:
                    break
                text = log.read_text(errors="replace")
                if "PQCP_FAULT_DONE" in text:
                    time.sleep(0.3)
                    break
                if time.time() > deadline:
                    timed_out = True
                    break
                time.sleep(0.25)
            if proc.poll() is None:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        return log.read_text(errors="replace"), timed_out


def collect_faults(elf: Path, targets) -> list:
    nm, objdump = sdk_tool("nm"), sdk_tool("objdump")
    faults = []
    for name in targets:
        start, end = fi.function_range(nm, elf, name)
        faults += fi.faults_for(
            name, fi.disassemble(objdump, elf, start, end), start)
    return faults


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--west-root", type=Path)
    parser.add_argument("--west")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--sample", type=int, default=0,
                        help="random subset of N faults (seeded); 0 = all")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--target", action="append")
    parser.add_argument("--controls", type=int, default=6)
    parser.add_argument("--variant", choices=sorted(VARIANTS),
                        default="plain")
    parser.add_argument("--timing", choices=("at-boot", "post-boot",
                                             "transient"), default="at-boot",
                        help="at-boot patches the image (permanent from "
                             "reset); post-boot writes the patch through the "
                             "gdbstub at the first arm point; transient "
                             "applies it once on the k-th execution")
    parser.add_argument("--sites-from", type=Path,
                        help="campaign JSON whose exploitable fault ids are "
                             "the transient candidates")
    parser.add_argument("--hit-max", type=int, default=2)
    args = parser.parse_args()

    env = clean_env()
    out = (args.output_dir or (MODULE_PATH / "build-fault-campaign")).resolve()
    out.mkdir(parents=True, exist_ok=True)
    west_root = detect_west_root(args.west_root or MODULE_PATH)
    west_cmd = discover_west(args.west, west_root, MODULE_PATH)
    build_dir = out / "build"
    build_image(MODULE_PATH, build_dir, west_root, west_cmd, env,
                VARIANTS[args.variant])
    main_elf = build_dir / "zephyr" / "zephyr-qemu-main.elf"
    image = main_elf.read_bytes()
    sym_elf = build_dir / "zephyr" / "zephyr.elf"

    # Calibration 1: golden determinism.
    images = out / "images"
    shutil.rmtree(images, ignore_errors=True)
    images.mkdir()
    golden_texts = []
    for i in range(3):
        text, _ = run_image(build_dir, main_elf, env, args.timeout)
        golden_texts.append(text)
    observations = [fo.parse(t)[0] for t in golden_texts]
    golden = observations[0]
    problems = fo.validate_golden(golden)
    if any(o != golden for o in observations[1:]):
        problems.append("golden runs are not identical")
    if problems:
        print("[fault] FAIL: golden calibration: " + "; ".join(problems))
        print(golden_texts[0][-1500:])
        return 1
    print("[fault] golden: 3 identical valid runs")

    faults = collect_faults(sym_elf, args.target or DEFAULT_TARGETS)
    rng = random.Random(args.seed)
    if args.sample and args.sample < len(faults):
        faults = rng.sample(faults, args.sample)
    print(f"[fault] {len(faults)} faults over "
          f"{len({f.function for f in faults})} functions", flush=True)

    nm = sdk_tool("nm")
    arm = fi.function_range(nm, sym_elf, "pqcp_fault_arm")[0]
    if args.timing == "transient":
        if not args.sites_from:
            print("[fault] FAIL: --timing transient needs --sites-from")
            return 1
        wanted = {e["id"] for e in json.loads(
            args.sites_from.read_text())["exploitable"]}
        faults = [f for f in faults if f.ident in wanted]
        if not faults:
            print("[fault] FAIL: no transient candidates matched")
            return 1
        work = [(f, scenario, hit) for f in faults
                for scenario in range(1, 8)
                for hit in range(1, args.hit_max + 1)]
    else:
        work = [(f, 0, 0) for f in faults]

    def execute(fault, scenario, hit, path=None):
        """Run one fault with the selected timing; return (text, timed_out)."""
        if args.timing == "at-boot":
            target = path or images / "run.elf"
            target.write_bytes(fi.apply_fault(image, fault))
            try:
                return run_image(build_dir, target, env, args.timeout)
            finally:
                target.unlink(missing_ok=True)
        if args.timing == "post-boot":
            return run_image(
                build_dir, main_elf, env, args.timeout,
                lambda gdb: fault_gdb.run_post_boot(
                    gdb, arm, fault.addr, fault.new, fault.old))
        return run_image(
            build_dir, main_elf, env, args.timeout,
            lambda gdb: fault_gdb.run_transient(
                gdb, arm, fault.addr, fault.new, fault.old, scenario, hit))

    # Calibration 2: identity patches must change nothing.
    controls = rng.sample(faults, min(args.controls, len(faults)))
    bad_controls = 0
    for f in controls:
        same = fi.Fault(f.function, f.addr, "SKIP", f.old, f.old, f.text,
                        f.base)
        text, timed = execute(same, 1, 1, images / "control.elf")
        if fo.classify(golden, text, timed_out=timed) != "NO_EFFECT":
            bad_controls += 1
    if bad_controls:
        print(f"[fault] FAIL: {bad_controls}/{len(controls)} identity "
              "controls changed behaviour; results would be untrustworthy")
        return 1
    print(f"[fault] controls: {len(controls)}/{len(controls)} identity "
          f"patches NO_EFFECT (timing={args.timing})")

    def one(item):
        index, (fault, scenario, hit) = item
        text, timed = execute(fault, scenario, hit,
                              images / f"f{index}.elf")
        return fault, fo.classify(golden, text, timed_out=timed)

    results = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for n, item in enumerate(pool.map(one, enumerate(work)), 1):
            results.append(item)
            if n % 50 == 0:
                print(f"[fault] {n}/{len(work)}", flush=True)

    totals = Counter(cls for _, cls in results)
    per_function = {}
    for fault, cls in results:
        per_function.setdefault(fault.function, Counter())[cls] += 1
    exploitable = [(f, c) for f, c in results if c in fo.EXPLOITABLE]
    report = {
        "schema_version": 1, "variant": args.variant,
        "timing": args.timing,
        "sites": len(results),
        "totals": dict(totals),
        "per_function": {k: dict(v) for k, v in per_function.items()},
        "exploitable": [{"id": i, "model": m, "class": c, "insn": t}
                        for i, m, c, t in sorted({
                            (f.ident, f.model, c, f.text)
                            for f, c in exploitable})],
    }
    (out / "fault_campaign.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for function, counts in sorted(per_function.items()):
        print(f"[fault] {function}: " + " ".join(
            f"{k}={counts[k]}" for k in fo.CLASSES if counts[k]))
    for fault, cls in exploitable[:20]:
        print(f"[fault] EXPLOITABLE {cls} {fault.ident} ({fault.text})")
    kem = totals["KEM_FO_BYPASS"]
    sig = totals["SIG_VERIFY_BYPASS"]
    print(f"PQCP_FAULT_CAMPAIGN variant={args.variant} "
          f"sites={len(results)} "
          f"kem_fo_bypass={kem} sig_verify_bypass={sig} "
          f"detected_boot={totals['DETECTED_BOOT']} "
          f"detected_runtime={totals['DETECTED_RUNTIME']} "
          f"fail_safe={totals['FAIL_SAFE']} corrupt={totals['CORRUPT']} "
          f"no_effect={totals['NO_EFFECT']} crash={totals['CRASH']} "
          f"timeout={totals['TIMEOUT']} controls_ok={len(controls)}/"
          f"{len(controls)} timing={args.timing} "
          f"exploitable_sites={len({f.ident for f, _ in exploitable})}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
