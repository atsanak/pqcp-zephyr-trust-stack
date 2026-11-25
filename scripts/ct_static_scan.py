#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inventory conditional instructions and compare Cortex-M sites with a trace.

A static match establishes instruction coverage at observed addresses. The
inventory does not classify conditional branches as public or secret.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess

import ct_trace_analysis as cta
from run_ct_trace_checks import LONG_MUL_VARIABLE, clean_env, functions_for

SCOPE = re.compile(r"^(PQCP_MLKEM_NATIVE_|mlk_|pqcp_)")
SYMBOL = re.compile(r"^\s*[0-9a-fA-F]+ <([^>]+)>:$")
INSN = re.compile(r"^\s*([0-9a-fA-F]+):\s+([a-z][a-z0-9.]*)\s*(.*)$")
ARM_VLAT = frozenset(cta.VLAT_KINDS.values())
ARM_CC = ("eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc",
          "hi", "ls", "ge", "lt", "gt", "le")
ARM_BRANCH = frozenset({"cbz", "cbnz", *("b" + cc for cc in ARM_CC)})
ARM_MNEMONICS = {op + cc: op for op in ARM_VLAT for cc in (*ARM_CC, "al", "")}
X86_DIV = re.compile(r"i?div[bwlq]?")
X86_PREFIXES = {"bnd", "notrack", "rep", "repe", "repz", "repne", "repnz"}
TARGETS = ("x86_64", *LONG_MUL_VARIABLE)


def sdk_tool(target: str, tool: str, sdk: Path | None = None) -> Path:
    prefix = "x86_64-zephyr-elf" if target == "x86_64" else "arm-zephyr-eabi"
    root = sdk or Path(os.environ.get("ZEPHYR_SDK_INSTALL_DIR")
                       or Path.home() / "zephyr-sdk-1.0.1")
    for directory in (root / "gnu" / prefix, root / prefix):
        path = directory / "bin" / f"{prefix}-{tool}"
        if path.is_file():
            return path
    raise FileNotFoundError(f"{prefix}-{tool} was not found in {root}")


def parse_disassembly(output: str) -> dict:
    functions = {}
    instructions = None
    for line in output.splitlines():
        symbol = SYMBOL.fullmatch(line)
        if symbol:
            name = symbol[1]
            instructions = functions.setdefault(name, []) if SCOPE.match(name) else None
        elif instructions is not None and (insn := INSN.fullmatch(line)):
            instructions.append((int(insn[1], 16), insn[2], insn[3]))
    return functions


def disassemble(elf: Path, target: str, sdk: Path | None = None) -> dict:
    result = subprocess.run(
        [sdk_tool(target, "objdump", sdk), "-d", "--no-show-raw-insn", elf],
        check=True, capture_output=True, text=True,
    )
    return parse_disassembly(result.stdout)


def classify(mnemonic: str, operands: str, target: str) -> tuple[str, str]:
    if target == "x86_64":
        while mnemonic in X86_PREFIXES and operands:
            mnemonic, _, operands = operands.expandtabs().strip().partition(" ")
            operands = operands.lstrip()
        if X86_DIV.fullmatch(mnemonic):
            return "vlat", mnemonic
        if (mnemonic.startswith("j") and not mnemonic.startswith("jmp")
                or mnemonic in {"loop", "loope", "loopne", "loopz", "loopnz"}):
            return "branches", mnemonic
        if mnemonic.startswith(("cmov", "set")):
            return "predicated", mnemonic
    else:
        mnemonic = mnemonic.partition(".")[0]
        if mnemonic in ARM_MNEMONICS:
            return "vlat", ARM_MNEMONICS[mnemonic]
        if mnemonic in ARM_BRANCH:
            return "branches", mnemonic
        if re.fullmatch(r"it[te]{0,3}", mnemonic):
            return "predicated", mnemonic
    return "", mnemonic


def inventory_functions(functions: dict, target: str) -> dict:
    inv = {"vlat": {}, "branches": {}, "predicated": {}}
    for fn, instructions in functions.items():
        inv["branches"][fn] = inv["predicated"][fn] = 0
        for pc, mnemonic, operands in instructions:
            category, op = classify(mnemonic, operands, target)
            if category == "vlat":
                inv[category][pc] = (fn, op)
            elif category:
                inv[category][fn] += 1
    return inv


def inventory(elf: Path, target: str, sdk: Path | None = None) -> dict:
    functions = disassemble(elf, target, sdk)
    if not functions:
        raise ValueError(f"no in-scope functions in {elf}")
    return inventory_functions(functions, target)


def cross_validate(inv: dict, vlat_analysis: cta.VlatAnalysis) -> dict:
    static = inv["vlat"]
    dynamic = vlat_analysis.sites
    # Require instruction-kind agreement as well as address agreement.
    matched = {pc for pc, kind in dynamic.items()
               if pc in static and static[pc][1] == cta.VLAT_KINDS[kind]}
    dynamic_only = set(dynamic) - set(static)
    mismatches = set(dynamic) & set(static) - matched
    varying = {site[0] for site in (*vlat_analysis.fail_sites,
                                    *vlat_analysis.candidate_sites)}
    return {
        "static_vlat": len(static),
        "executed": len(matched),
        "dynamic_only": len(dynamic_only),
        "dynamic_only_pcs": sorted(dynamic_only),
        "kind_mismatches": sorted(mismatches),
        "secret_varying": len(varying),
        "secret_varying_pcs": sorted(varying),
        "precision": len(varying & matched) / len(static) if static else None,
        "recall": len(matched) / len(dynamic) if dynamic else None,
        "static_branches": sum(inv["branches"].values()),
        "predicated": sum(inv["predicated"].values()),
    }


def project_counts(inv: dict) -> dict:
    counts = {fn: {"branches": branches, "vlat": 0}
              for fn, branches in inv["branches"].items()
              if fn.startswith("pqcp_") and not fn.startswith("pqcp_ct_")}
    for fn, _ in inv["vlat"].values():
        if fn in counts:
            counts[fn]["vlat"] += 1
    return counts


def ratchet(current: dict, baseline: dict) -> list[str]:
    issues = []
    for fn, counts in sorted(current.items()):
        if fn not in baseline:
            issues.append(f"{fn}: missing baseline entry")
            continue
        for key, count in counts.items():
            if count > baseline[fn][key]:
                issues.append(f"{fn}: {key} grew from {baseline[fn][key]} to {count}")
    return issues


def format_rate(value: float | None) -> str:
    return "na" if value is None else f"{value:.3f}"


def format_xval(target: str, result: dict) -> str:
    status = "FAIL" if result["dynamic_only"] or result["kind_mismatches"] else "PASS"
    return (f"PQCP_CT_STATIC_XVAL target={target} "
            f"static_vlat={result['static_vlat']} executed={result['executed']} "
            f"dynamic_only={result['dynamic_only']} "
            f"kind_mismatches={len(result['kind_mismatches'])} "
            f"secret_varying={result['secret_varying']} "
            f"precision={format_rate(result['precision'])} "
            f"recall={format_rate(result['recall'])} "
            f"static_branches={result['static_branches']} "
            f"predicated={result['predicated']} status={status}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--trace", type=Path)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--sdk", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--write-baseline", action="store_true")
    args = parser.parse_args()
    if args.trace and args.target == "x86_64":
        parser.error("x86 traces record division fingerprints without per-site addresses")
    if args.write_baseline and not args.baseline:
        parser.error("--write-baseline requires --baseline")

    try:
        inv = inventory(args.elf, args.target, args.sdk)
        if args.baseline:
            counts = project_counts(inv)
            if not counts:
                raise ValueError("no project functions to ratchet")
            if args.write_baseline:
                args.baseline.write_text(
                    json.dumps({"target": args.target, "functions": counts},
                               indent=2, sort_keys=True) + "\n", encoding="utf-8")
            else:
                baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
                if baseline["target"] != args.target:
                    raise ValueError(f"baseline target is {baseline['target']}")
                errors = ratchet(counts, baseline["functions"])
                for error in errors:
                    print(f"[ct-static] {error}")
                print(f"PQCP_CT_STATIC_RATCHET target={args.target} "
                      f"functions={len(counts)} status={'FAIL' if errors else 'PASS'}")
                if errors:
                    return 1
        if args.trace:
            trace = args.trace.read_text(encoding="utf-8")
            analysis = cta.analyze_vlat(
                cta.parse_trace(trace), cta.parse_vlat(trace),
                long_mul_variable=LONG_MUL_VARIABLE[args.target])
            result = cross_validate(inv, analysis)
            pcs = {*result["dynamic_only_pcs"], *result["kind_mismatches"],
                   *result["secret_varying_pcs"]}
            for pc, fn in sorted(functions_for(args.elf, pcs, clean_env()).items()):
                static_op = inv["vlat"].get(pc, ("", "-"))[1]
                print(f"[ct-static] {fn}@0x{pc:x} static={static_op} "
                      f"dynamic={cta.VLAT_KINDS[analysis.sites[pc]]}")
            print(format_xval(args.target, result))
            return int(bool(result["dynamic_only"] or result["kind_mismatches"]))
        print(json.dumps(inv, sort_keys=True, indent=2))
    except (KeyError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"[ct-static] FAIL: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
