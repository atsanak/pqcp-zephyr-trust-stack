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
DEFAULT_REQUIRED_SYMBOL_GROUPS = {
    "api_decap": (
        "pqcp_mlkem_decapsulate",
        "crypto_kem_dec",
        "decapsulate",
        "decap",
    ),
}
DIVISION_RE = re.compile(r"\b(?:idiv|div|udiv|sdiv)[a-z0-9_.]*\b", re.IGNORECASE)
DIVISION_HELPER_RE = re.compile(
    r"\b(?:__aeabi_(?:uidiv|idiv|uldiv|ldiv)(?:mod)?|"
    r"__udiv(?:si|di)3|__div(?:si|di)3|"
    r"__umod(?:si|di)3|__mod(?:si|di)3)\b",
    re.IGNORECASE,
)
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
    parser.add_argument(
        "--required-symbol-group",
        action="append",
        dest="required_symbol_groups",
        help=(
            "Required ML-KEM decapsulation symbol group. Supported built-in "
            "group: api_decap. May be repeated."
        ),
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


def symbol_is_excluded_match(
    symbol: str,
    patterns: tuple[str, ...],
    exclude_patterns: tuple[str, ...],
) -> bool:
    lowered = symbol.lower()
    return (
        any(pattern.lower() in lowered for pattern in patterns)
        and any(pattern.lower() in lowered for pattern in exclude_patterns)
    )


def scan_disassembly(
    text: str,
    patterns: tuple[str, ...],
    exclude_patterns: tuple[str, ...],
) -> dict[str, Any]:
    current_symbol: str | None = None
    current_is_target = False
    target_symbols: set[str] = set()
    excluded_symbols: set[str] = set()
    findings: list[dict[str, Any]] = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        match = SYMBOL_RE.match(line)
        if match:
            current_symbol = match.group(1)
            current_is_target = symbol_is_target(current_symbol, patterns, exclude_patterns)
            if current_is_target:
                target_symbols.add(current_symbol)
            elif symbol_is_excluded_match(current_symbol, patterns, exclude_patterns):
                excluded_symbols.add(current_symbol)
            continue

        if not current_is_target or current_symbol is None:
            continue

        mnemonic = DIVISION_RE.search(line)
        helper = DIVISION_HELPER_RE.search(line)
        if mnemonic or helper:
            findings.append(
                {
                    "symbol": current_symbol,
                    "line_number": line_number,
                    "mnemonic": (mnemonic or helper).group(0),
                    "line": line.strip(),
                }
            )

    return {
        "target_symbols": sorted(target_symbols),
        "excluded_matching_symbols": sorted(excluded_symbols),
        "findings": findings,
    }


def required_group_coverage(
    target_symbols: list[str],
    required_groups: tuple[str, ...],
) -> dict[str, dict[str, Any]]:
    coverage: dict[str, dict[str, Any]] = {}
    for group in required_groups:
        patterns = DEFAULT_REQUIRED_SYMBOL_GROUPS.get(group)
        if patterns is None:
            coverage[group] = {"passed": False, "patterns": [], "matches": [], "failure": "unknown required group"}
            continue
        matches = [
            symbol
            for symbol in target_symbols
            if any(pattern.lower() in symbol.lower() for pattern in patterns)
        ]
        coverage[group] = {
            "passed": bool(matches),
            "patterns": list(patterns),
            "matches": matches,
        }
    return coverage


def build_result(
    *,
    source: Path,
    disassembly: str,
    patterns: tuple[str, ...],
    allow_missing_targets: bool,
    exclude_patterns: tuple[str, ...] = DEFAULT_EXCLUDE_PATTERNS,
    required_symbol_groups: tuple[str, ...] = ("api_decap",),
) -> dict[str, Any]:
    scan = scan_disassembly(disassembly, patterns, exclude_patterns)
    failures: list[str] = []
    coverage = required_group_coverage(scan["target_symbols"], required_symbol_groups)

    if not scan["target_symbols"] and not allow_missing_targets:
        if scan.get("excluded_matching_symbols"):
            failures.append(
                "only harness/test symbols matched ML-KEM decapsulation target patterns: "
                + ", ".join(scan["excluded_matching_symbols"])
            )
        else:
            failures.append(
                "no ML-KEM decapsulation-related symbols matched target patterns: "
                + ", ".join(patterns)
            )
    for group, item in coverage.items():
        if not item.get("passed") and not allow_missing_targets:
            failures.append(f"required symbol group {group!r} was not covered")
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
            "required_symbol_groups": list(required_symbol_groups),
            "disallowed_mnemonics": [
                "div",
                "idiv",
                "udiv",
                "sdiv",
                "__aeabi_uidiv",
                "__aeabi_idiv",
                "__udivsi3",
                "__divsi3",
            ],
            "allow_missing_targets": allow_missing_targets,
        },
        "passed": not failures,
        "target_symbol_count": len(scan["target_symbols"]),
        "target_symbols": scan["target_symbols"],
        "excluded_matching_symbols": scan["excluded_matching_symbols"],
        "symbol_coverage": coverage,
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
            required_symbol_groups=tuple(args.required_symbol_groups or ("api_decap",)),
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
