#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Scan ML-KEM decapsulation disassembly for variable-latency division."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_TARGET_PATTERNS = (
    "decap",
    "crypto_kem_dec",
    "indcpa_dec",
    "poly_tomsg",
    "poly_compress",
    "poly_decompress",
    "mlkem",
    "kyber",
)
DEFAULT_EXCLUDE_PATTERNS = (
    "ztest",
    "_wrapper",
    "test_",
    "run_mlkem_decap_ct_smoke",
)
DIVISION_RE = re.compile(r"\b(?:idiv|div|udiv|sdiv)[a-z0-9_.]*\b", re.IGNORECASE)
SYMBOL_RE = re.compile(r"^\s*[0-9a-fA-F]+\s+<([^>]+)>:\s*$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--elf", type=Path, help="ELF image to disassemble with objdump.")
    source.add_argument("--disassembly", type=Path, help="Pre-generated objdump -d text.")
    parser.add_argument("--objdump", help="Objdump executable. Defaults to llvm-objdump or objdump.")
    parser.add_argument(
        "--target-pattern",
        action="append",
        dest="target_patterns",
        help="Case-insensitive symbol substring to include. May be repeated.",
    )
    parser.add_argument(
        "--exclude-pattern",
        action="append",
        dest="exclude_patterns",
        help=(
            "Case-insensitive symbol substring to exclude from policy scanning. "
            "May be repeated; defaults exclude ztest/test harness symbols."
        ),
    )
    parser.add_argument(
        "--allow-missing-targets",
        action="store_true",
        help="Return success if no target symbols are found, but record a degraded result.",
    )
    parser.add_argument("--output", type=Path, required=True, help="Result JSON path.")
    return parser.parse_args()


def discover_objdump(explicit: str | None) -> str:
    if explicit:
        return explicit
    for candidate in ("llvm-objdump", "arm-zephyr-eabi-objdump", "objdump"):
        path = shutil.which(candidate)
        if path:
            return path
    raise RuntimeError("unable to find objdump; pass --objdump explicitly")


def disassemble_elf(elf: Path, objdump: str) -> str:
    proc = subprocess.run(
        [objdump, "-d", str(elf)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"{objdump} failed with {proc.returncode}")
    return proc.stdout


def symbol_is_target(
    symbol: str,
    patterns: tuple[str, ...],
    exclude_patterns: tuple[str, ...],
) -> bool:
    lowered = symbol.lower()
    if any(pattern.lower() in lowered for pattern in exclude_patterns):
        return False
    return any(pattern.lower() in lowered for pattern in patterns)


def scan_disassembly(
    text: str,
    patterns: tuple[str, ...],
    exclude_patterns: tuple[str, ...],
) -> dict[str, Any]:
    current_symbol: str | None = None
    current_is_target = False
    target_symbols: set[str] = set()
    findings: list[dict[str, Any]] = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        match = SYMBOL_RE.match(line)
        if match:
            current_symbol = match.group(1)
            current_is_target = symbol_is_target(current_symbol, patterns, exclude_patterns)
            if current_is_target:
                target_symbols.add(current_symbol)
            continue

        if not current_is_target or current_symbol is None:
            continue

        mnemonic = DIVISION_RE.search(line)
        if mnemonic:
            findings.append(
                {
                    "symbol": current_symbol,
                    "line_number": line_number,
                    "mnemonic": mnemonic.group(0),
                    "line": line.strip(),
                }
            )

    return {
        "target_symbols": sorted(target_symbols),
        "findings": findings,
    }


def build_result(
    *,
    source: Path,
    disassembly: str,
    patterns: tuple[str, ...],
    allow_missing_targets: bool,
    exclude_patterns: tuple[str, ...] = DEFAULT_EXCLUDE_PATTERNS,
) -> dict[str, Any]:
    scan = scan_disassembly(disassembly, patterns, exclude_patterns)
    failures: list[str] = []

    if not scan["target_symbols"] and not allow_missing_targets:
        failures.append(
            "no ML-KEM decapsulation-related symbols matched target patterns: "
            + ", ".join(patterns)
        )
    for finding in scan["findings"]:
        failures.append(
            f"{finding['symbol']} contains variable-latency division "
            f"{finding['mnemonic']} at disassembly line {finding['line_number']}"
        )

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": str(source),
        "policy": {
            "name": "mlkem_decap_no_variable_latency_division",
            "target_patterns": list(patterns),
            "exclude_patterns": list(exclude_patterns),
            "disallowed_mnemonics": ["div", "idiv", "udiv", "sdiv"],
            "allow_missing_targets": allow_missing_targets,
        },
        "passed": not failures,
        "target_symbol_count": len(scan["target_symbols"]),
        "target_symbols": scan["target_symbols"],
        "finding_count": len(scan["findings"]),
        "findings": scan["findings"],
        "failures": failures,
    }


def main() -> int:
    args = parse_args()
    patterns = tuple(args.target_patterns or DEFAULT_TARGET_PATTERNS)
    exclude_patterns = tuple(args.exclude_patterns or DEFAULT_EXCLUDE_PATTERNS)
    try:
        if args.disassembly:
            source = args.disassembly.resolve()
            text = source.read_text(encoding="utf-8")
        else:
            source = args.elf.resolve()
            text = disassemble_elf(source, discover_objdump(args.objdump))
        result = build_result(
            source=source,
            disassembly=text,
            patterns=patterns,
            exclude_patterns=exclude_patterns,
            allow_missing_targets=args.allow_missing_targets,
        )
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        result = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "passed": False,
            "failures": [str(exc)],
            "target_symbol_count": 0,
            "target_symbols": [],
            "finding_count": 0,
            "findings": [],
        }

    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["passed"]:
        print("CT instruction policy passed")
        print(f"  output: {args.output.resolve()}")
        return 0

    print("CT instruction policy failed:", file=sys.stderr)
    for failure in result.get("failures", []):
        print(f"  - {failure}", file=sys.stderr)
    print(f"  output: {args.output.resolve()}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
