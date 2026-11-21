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


def build_image(module: Path, build_dir: Path, west_root: Path,
                west_cmd: list, env: dict) -> Path:
    run_command(
        [*west_cmd, "build", "-p", "always", "-b", "qemu_x86_64",
         str(module / TEST_APP_RELATIVE), "-d", str(build_dir), "--",
         f"-DZEPHYR_EXTRA_MODULES={module}"],
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


def run_image(build_dir: Path, image: Path, env: dict,
              timeout: int) -> tuple[str, bool]:
    """Run one image; return (serial text, timed_out)."""
    with tempfile.TemporaryDirectory(prefix="pqcp-fault-run-") as tmp:
        log = Path(tmp) / "serial.log"
        with log.open("w") as handle:
            proc = subprocess.Popen(
                qemu_command(build_dir, image), shell=True, cwd=tmp, env=env,
                stdin=subprocess.DEVNULL, stdout=handle,
                stderr=subprocess.STDOUT, start_new_session=True)
            deadline = time.time() + timeout
            timed_out = False
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
        faults += fi.faults_for(name, fi.disassemble(objdump, elf, start, end))
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
    args = parser.parse_args()

    env = clean_env()
    out = args.output_dir or (MODULE_PATH / "build-fault-campaign")
    out.mkdir(parents=True, exist_ok=True)
    west_root = detect_west_root(args.west_root or MODULE_PATH)
    west_cmd = discover_west(args.west, west_root, MODULE_PATH)
    build_dir = out / "build"
    build_image(MODULE_PATH, build_dir, west_root, west_cmd, env)
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

    # Calibration 2: identity patches must change nothing.
    controls = rng.sample(faults, min(args.controls, len(faults)))
    bad_controls = 0
    for f in controls:
        same = fi.Fault(f.function, f.addr, "SKIP", f.old, f.old, f.text)
        path = images / "control.elf"
        path.write_bytes(fi.apply_fault(image, same))
        text, timed = run_image(build_dir, path, env, args.timeout)
        if fo.classify(golden, text, timed_out=timed) != "NO_EFFECT":
            bad_controls += 1
    if bad_controls:
        print(f"[fault] FAIL: {bad_controls}/{len(controls)} identity "
              "controls changed behaviour; results would be untrustworthy")
        return 1
    print(f"[fault] controls: {len(controls)}/{len(controls)} identity "
          "patches NO_EFFECT")

    def one(item):
        index, fault = item
        path = images / f"f{index}.elf"
        path.write_bytes(fi.apply_fault(image, fault))
        try:
            text, timed = run_image(build_dir, path, env, args.timeout)
            return fault, fo.classify(golden, text, timed_out=timed)
        finally:
            path.unlink(missing_ok=True)

    results = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for n, item in enumerate(pool.map(one, enumerate(faults)), 1):
            results.append(item)
            if n % 50 == 0:
                print(f"[fault] {n}/{len(faults)}", flush=True)

    totals = Counter(cls for _, cls in results)
    per_function = {}
    for fault, cls in results:
        per_function.setdefault(fault.function, Counter())[cls] += 1
    exploitable = [(f, c) for f, c in results if c in fo.EXPLOITABLE]
    report = {
        "schema_version": 1, "sites": len(results),
        "totals": dict(totals),
        "per_function": {k: dict(v) for k, v in per_function.items()},
        "exploitable": [{"id": f.ident, "model": f.model, "class": c,
                         "insn": f.text} for f, c in exploitable],
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
    print(f"PQCP_FAULT_CAMPAIGN sites={len(results)} "
          f"kem_fo_bypass={kem} sig_verify_bypass={sig} "
          f"fail_safe={totals['FAIL_SAFE']} corrupt={totals['CORRUPT']} "
          f"no_effect={totals['NO_EFFECT']} crash={totals['CRASH']} "
          f"timeout={totals['TIMEOUT']} controls_ok={len(controls)}/"
          f"{len(controls)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
