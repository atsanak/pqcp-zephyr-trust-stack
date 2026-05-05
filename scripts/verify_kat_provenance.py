#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Verify checked-in ACVP KAT vectors against vendored NIST ACVP fixtures."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Tuple


SCRIPT_DIR = Path(__file__).resolve().parent
MODULE_ROOT = SCRIPT_DIR.parent
DEFAULT_HEADER = MODULE_ROOT / "tests/ztest_acvp_kat/src/kat_vectors.h"
DEFAULT_VECTORS_DIR = MODULE_ROOT / "tests/ztest_acvp_kat/nist_vectors"

HEADER_STRING_RE = re.compile(
    r"static const char (?P<name>[A-Z0-9_]+)\[\]\s*=\s*\n"
    r"(?P<body>(?:\s*\"[0-9A-F]+\"\n)+)\s*;",
    re.MULTILINE,
)
HEADER_DEFINE_RE = re.compile(
    r"^#define (?P<name>[A-Z0-9_]+)\s+(?P<value>\d+)\s*$",
    re.MULTILINE,
)
STRING_RE = re.compile(r"\"([0-9A-F]+)\"")


@dataclass(frozen=True)
class VectorSpec:
    fixture: str
    parameter_set: str
    operation: str
    constant_order: Tuple[str, ...]


VECTOR_SPECS: Tuple[VectorSpec, ...] = (
    VectorSpec(
        fixture="mlkem_512_keygen.json",
        parameter_set="ML-KEM-512",
        operation="keygen",
        constant_order=(
            "MLKEM512_KEYGEN_D_HEX",
            "MLKEM512_KEYGEN_Z_HEX",
            "MLKEM512_KEYGEN_PK_HEX",
            "MLKEM512_KEYGEN_SK_HEX",
        ),
    ),
    VectorSpec(
        fixture="mlkem_512_encaps.json",
        parameter_set="ML-KEM-512",
        operation="encaps",
        constant_order=(
            "MLKEM512_ENCAPS_PK_HEX",
            "MLKEM512_ENCAPS_SK_HEX",
            "MLKEM512_ENCAPS_MESSAGE_HEX",
            "MLKEM512_ENCAPS_CT_HEX",
            "MLKEM512_ENCAPS_SS_HEX",
        ),
    ),
    VectorSpec(
        fixture="mlkem_768_keygen.json",
        parameter_set="ML-KEM-768",
        operation="keygen",
        constant_order=(
            "MLKEM768_KEYGEN_D_HEX",
            "MLKEM768_KEYGEN_Z_HEX",
            "MLKEM768_KEYGEN_PK_HEX",
            "MLKEM768_KEYGEN_SK_HEX",
        ),
    ),
    VectorSpec(
        fixture="mlkem_768_encaps.json",
        parameter_set="ML-KEM-768",
        operation="encaps",
        constant_order=(
            "MLKEM768_ENCAPS_PK_HEX",
            "MLKEM768_ENCAPS_SK_HEX",
            "MLKEM768_ENCAPS_MESSAGE_HEX",
            "MLKEM768_ENCAPS_CT_HEX",
            "MLKEM768_ENCAPS_SS_HEX",
        ),
    ),
    VectorSpec(
        fixture="mlkem_1024_keygen.json",
        parameter_set="ML-KEM-1024",
        operation="keygen",
        constant_order=(
            "MLKEM1024_KEYGEN_D_HEX",
            "MLKEM1024_KEYGEN_Z_HEX",
            "MLKEM1024_KEYGEN_PK_HEX",
            "MLKEM1024_KEYGEN_SK_HEX",
        ),
    ),
    VectorSpec(
        fixture="mlkem_1024_encaps.json",
        parameter_set="ML-KEM-1024",
        operation="encaps",
        constant_order=(
            "MLKEM1024_ENCAPS_PK_HEX",
            "MLKEM1024_ENCAPS_SK_HEX",
            "MLKEM1024_ENCAPS_MESSAGE_HEX",
            "MLKEM1024_ENCAPS_CT_HEX",
            "MLKEM1024_ENCAPS_SS_HEX",
        ),
    ),
    VectorSpec(
        fixture="mldsa_44_siggen.json",
        parameter_set="ML-DSA-44",
        operation="siggen",
        constant_order=(
            "MLDSA44_SIGN_MESSAGE_HEX",
            "MLDSA44_SIGN_CONTEXT_HEX",
            "MLDSA44_SIGN_PK_HEX",
            "MLDSA44_SIGN_SK_HEX",
            "MLDSA44_SIGN_SIG_HEX",
        ),
    ),
    VectorSpec(
        fixture="mldsa_44_sigver.json",
        parameter_set="ML-DSA-44",
        operation="sigver",
        constant_order=(
            "MLDSA44_VERIFY_MESSAGE_HEX",
            "MLDSA44_VERIFY_CONTEXT_HEX",
            "MLDSA44_VERIFY_PK_HEX",
            "MLDSA44_VERIFY_SIG_HEX",
            "MLDSA44_VERIFY_EXPECT_PASS",
        ),
    ),
    VectorSpec(
        fixture="mldsa_65_siggen.json",
        parameter_set="ML-DSA-65",
        operation="siggen",
        constant_order=(
            "MLDSA65_SIGN_MESSAGE_HEX",
            "MLDSA65_SIGN_CONTEXT_HEX",
            "MLDSA65_SIGN_PK_HEX",
            "MLDSA65_SIGN_SK_HEX",
            "MLDSA65_SIGN_SIG_HEX",
        ),
    ),
    VectorSpec(
        fixture="mldsa_65_sigver.json",
        parameter_set="ML-DSA-65",
        operation="sigver",
        constant_order=(
            "MLDSA65_VERIFY_MESSAGE_HEX",
            "MLDSA65_VERIFY_CONTEXT_HEX",
            "MLDSA65_VERIFY_PK_HEX",
            "MLDSA65_VERIFY_SIG_HEX",
            "MLDSA65_VERIFY_EXPECT_PASS",
        ),
    ),
    VectorSpec(
        fixture="mldsa_87_siggen.json",
        parameter_set="ML-DSA-87",
        operation="siggen",
        constant_order=(
            "MLDSA87_SIGN_MESSAGE_HEX",
            "MLDSA87_SIGN_CONTEXT_HEX",
            "MLDSA87_SIGN_PK_HEX",
            "MLDSA87_SIGN_SK_HEX",
            "MLDSA87_SIGN_SIG_HEX",
        ),
    ),
    VectorSpec(
        fixture="mldsa_87_sigver.json",
        parameter_set="ML-DSA-87",
        operation="sigver",
        constant_order=(
            "MLDSA87_VERIFY_MESSAGE_HEX",
            "MLDSA87_VERIFY_CONTEXT_HEX",
            "MLDSA87_VERIFY_PK_HEX",
            "MLDSA87_VERIFY_SIG_HEX",
            "MLDSA87_VERIFY_EXPECT_PASS",
        ),
    ),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Cross-check kat_vectors.h against vendored NIST ACVP fixtures"
    )
    parser.add_argument(
        "--header",
        type=Path,
        default=DEFAULT_HEADER,
        help="Path to tests/ztest_acvp_kat/src/kat_vectors.h",
    )
    parser.add_argument(
        "--vectors-dir",
        type=Path,
        default=DEFAULT_VECTORS_DIR,
        help="Directory containing vendored reduced NIST ACVP JSON fixtures",
    )
    parser.add_argument(
        "--emit-header",
        type=Path,
        help="Optional output path to regenerate kat_vectors.h from the fixture directory",
    )
    return parser.parse_args()


def load_header_constants(path: Path) -> tuple[Dict[str, str], Dict[str, int]]:
    text = path.read_text(encoding="utf-8")
    string_constants: Dict[str, str] = {}
    numeric_constants: Dict[str, int] = {}

    for match in HEADER_STRING_RE.finditer(text):
        body = match.group("body")
        string_constants[match.group("name")] = "".join(STRING_RE.findall(body))

    for match in HEADER_DEFINE_RE.finditer(text):
        numeric_constants[match.group("name")] = int(match.group("value"), 10)

    return string_constants, numeric_constants


def load_fixture(path: Path) -> tuple[dict, dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"Missing NIST ACVP fixture: {path}") from exc

    try:
        group = data["testGroups"][0]
        test = group["tests"][0]
    except (KeyError, IndexError) as exc:
        raise RuntimeError(f"Fixture {path} does not contain testGroups[0].tests[0]") from exc

    return group, test


def fixture_constants(
    spec: VectorSpec, vectors_dir: Path
) -> tuple[Dict[str, str], Dict[str, int], dict]:
    fixture_path = vectors_dir / spec.fixture
    group, test = load_fixture(fixture_path)

    if group.get("parameterSet") != spec.parameter_set:
        raise RuntimeError(
            f"{fixture_path} parameterSet mismatch: "
            f"expected {spec.parameter_set}, got {group.get('parameterSet')}"
        )

    strings: Dict[str, str] = {}
    numeric: Dict[str, int] = {}

    if spec.operation == "keygen":
        prefix = spec.parameter_set.replace("ML-KEM-", "MLKEM")
        strings.update(
            {
                f"{prefix}_KEYGEN_D_HEX": test["d"],
                f"{prefix}_KEYGEN_Z_HEX": test["z"],
                f"{prefix}_KEYGEN_PK_HEX": test["ek"],
                f"{prefix}_KEYGEN_SK_HEX": test["dk"],
            }
        )
    elif spec.operation == "encaps":
        prefix = spec.parameter_set.replace("ML-KEM-", "MLKEM")
        strings.update(
            {
                f"{prefix}_ENCAPS_PK_HEX": test["ek"],
                f"{prefix}_ENCAPS_SK_HEX": test["dk"],
                f"{prefix}_ENCAPS_MESSAGE_HEX": test["m"],
                f"{prefix}_ENCAPS_CT_HEX": test["c"],
                f"{prefix}_ENCAPS_SS_HEX": test["k"],
            }
        )
    elif spec.operation == "siggen":
        prefix = spec.parameter_set.replace("ML-DSA-", "MLDSA")
        strings.update(
            {
                f"{prefix}_SIGN_MESSAGE_HEX": test["message"],
                f"{prefix}_SIGN_CONTEXT_HEX": test["context"],
                f"{prefix}_SIGN_PK_HEX": test["pk"],
                f"{prefix}_SIGN_SK_HEX": test["sk"],
                f"{prefix}_SIGN_SIG_HEX": test["signature"],
            }
        )
    elif spec.operation == "sigver":
        prefix = spec.parameter_set.replace("ML-DSA-", "MLDSA")
        strings.update(
            {
                f"{prefix}_VERIFY_MESSAGE_HEX": test["message"],
                f"{prefix}_VERIFY_CONTEXT_HEX": test["context"],
                f"{prefix}_VERIFY_PK_HEX": test["pk"],
                f"{prefix}_VERIFY_SIG_HEX": test["signature"],
            }
        )
        numeric[f"{prefix}_VERIFY_EXPECT_PASS"] = 1 if test["testPassed"] else 0
    else:
        raise RuntimeError(f"Unhandled vector spec operation: {spec.operation}")

    metadata = {
        "fixture": spec.fixture,
        "parameter_set": spec.parameter_set,
        "operation": spec.operation,
        "tgId": group["tgId"],
        "tcId": test["tcId"],
    }

    return strings, numeric, metadata


def load_all_fixture_constants(
    vectors_dir: Path,
) -> tuple[Dict[str, str], Dict[str, int], Dict[str, dict]]:
    string_constants: Dict[str, str] = {}
    numeric_constants: Dict[str, int] = {}
    metadata: Dict[str, dict] = {}

    for spec in VECTOR_SPECS:
        strings, numeric, meta = fixture_constants(spec, vectors_dir)
        for name in spec.constant_order:
            if name in strings:
                string_constants[name] = strings[name]
            elif name in numeric:
                numeric_constants[name] = numeric[name]
            else:
                raise RuntimeError(
                    f"{spec.fixture} did not produce required constant {name}"
                )
        metadata[spec.fixture] = meta

    return string_constants, numeric_constants, metadata


def format_c_string(name: str, value: str) -> str:
    lines = [f"static const char {name}[] ="]
    for index in range(0, len(value), 64):
        lines.append(f'    "{value[index:index + 64]}"')
    lines.append("    ;")
    return "\n".join(lines)


def render_header(
    string_constants: Dict[str, str],
    numeric_constants: Dict[str, int],
    metadata: Dict[str, dict],
) -> str:
    lines = [
        "/* SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation */",
        "/*",
        " * Vendored ACVP KAT vectors for all FIPS 203 / FIPS 204 parameter sets.",
        " *",
        " * These constants are generated from tests/ztest_acvp_kat/nist_vectors/",
        " * via scripts/verify_kat_provenance.py --emit-header.",
        " */",
        "#ifndef PQCP_ZTEST_ACVP_KAT_VECTORS_H",
        "#define PQCP_ZTEST_ACVP_KAT_VECTORS_H",
        "",
    ]

    for spec in VECTOR_SPECS:
        meta = metadata[spec.fixture]
        lines.extend(
            [
                "/*",
                f" * Source: tests/ztest_acvp_kat/nist_vectors/{spec.fixture}",
                f" * NIST ACVP test group {meta['tgId']}, test case {meta['tcId']}.",
                " * Verified by: scripts/verify_kat_provenance.py",
                " */",
            ]
        )

        for name in spec.constant_order:
            if name in string_constants:
                lines.append(format_c_string(name, string_constants[name]))
            else:
                lines.append(f"#define {name} {numeric_constants[name]}")
            lines.append("")

    lines.append("#endif /* PQCP_ZTEST_ACVP_KAT_VECTORS_H */")
    lines.append("")
    return "\n".join(lines)


def verify_vectors(
    header_strings: Dict[str, str],
    header_numeric: Dict[str, int],
    fixture_strings: Dict[str, str],
    fixture_numeric: Dict[str, int],
) -> list[str]:
    mismatches: list[str] = []

    for name, expected in fixture_strings.items():
        actual = header_strings.get(name)
        if actual is None:
            mismatches.append(f"missing string constant: {name}")
            continue
        if actual.upper() != expected.upper():
            mismatches.append(
                f"{name} mismatch: header starts {actual[:32]}, expected starts {expected[:32]}"
            )

    for name, expected in fixture_numeric.items():
        actual = header_numeric.get(name)
        if actual is None:
            mismatches.append(f"missing numeric constant: {name}")
            continue
        if actual != expected:
            mismatches.append(f"{name} mismatch: header={actual}, expected={expected}")

    return mismatches


def main() -> int:
    args = parse_args()
    vectors_dir = args.vectors_dir.resolve()

    fixture_strings, fixture_numeric, metadata = load_all_fixture_constants(vectors_dir)

    if args.emit_header is not None:
        args.emit_header.parent.mkdir(parents=True, exist_ok=True)
        args.emit_header.write_text(
            render_header(fixture_strings, fixture_numeric, metadata),
            encoding="utf-8",
        )
        print(f"Wrote {args.emit_header}")
        return 0

    header_strings, header_numeric = load_header_constants(args.header)
    mismatches = verify_vectors(
        header_strings, header_numeric, fixture_strings, fixture_numeric
    )
    if mismatches:
        print("KAT provenance verification failed:", file=sys.stderr)
        for mismatch in mismatches:
            print(f"  - {mismatch}", file=sys.stderr)
        return 1

    print(f"KAT provenance verified against vendored NIST ACVP fixtures in {vectors_dir}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
