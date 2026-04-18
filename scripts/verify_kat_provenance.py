#!/usr/bin/env python3
"""Verify the checked-in ACVP KAT vectors against official NIST ACVP JSON."""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
MODULE_ROOT = SCRIPT_DIR.parent
DEFAULT_HEADER = MODULE_ROOT / "tests/ztest_acvp_kat/src/kat_vectors.h"
BASE_URL = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files"

HEADER_RE = re.compile(
    r"static const char (?P<name>[A-Z0-9_]+)\[\]\s*=\s*\n"
    r"(?P<body>(?:\s*\"[0-9A-F]+\"\n)+)\s*;",
    re.MULTILINE,
)
STRING_RE = re.compile(r"\"([0-9A-F]+)\"")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Cross-check tests/ztest_acvp_kat vectors against NIST ACVP JSON"
    )
    parser.add_argument(
        "--header",
        type=Path,
        default=DEFAULT_HEADER,
        help="Path to tests/ztest_acvp_kat/src/kat_vectors.h",
    )
    parser.add_argument(
        "--emit-header",
        type=Path,
        help="Optional output path to regenerate kat_vectors.h from the official JSON",
    )
    return parser.parse_args()


def fetch_json(path: str) -> dict:
    with urllib.request.urlopen(f"{BASE_URL}/{path}") as response:
        return json.load(response)


def load_header_constants(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    constants: dict[str, str] = {}
    for match in HEADER_RE.finditer(text):
        body = match.group("body")
        constants[match.group("name")] = "".join(STRING_RE.findall(body))
    return constants


def first_mlkem768_keygen() -> tuple[dict, dict]:
    data = fetch_json("ML-KEM-keyGen-FIPS203/internalProjection.json")
    for group in data["testGroups"]:
        if group.get("parameterSet") == "ML-KEM-768":
            return group, group["tests"][0]
    raise RuntimeError("ML-KEM-768 keyGen vector not found")


def first_mlkem768_encap() -> tuple[dict, dict]:
    data = fetch_json("ML-KEM-encapDecap-FIPS203/internalProjection.json")
    for group in data["testGroups"]:
        if (
            group.get("parameterSet") == "ML-KEM-768"
            and group.get("function") == "encapsulation"
        ):
            return group, group["tests"][0]
    raise RuntimeError("ML-KEM-768 encapsulation vector not found")


def first_mldsa65_siggen() -> tuple[dict, dict]:
    data = fetch_json("ML-DSA-sigGen-FIPS204/internalProjection.json")
    for group in data["testGroups"]:
        if (
            group.get("parameterSet") == "ML-DSA-65"
            and group.get("signatureInterface") == "external"
            and group.get("deterministic") is True
        ):
            return group, group["tests"][0]
    raise RuntimeError("ML-DSA-65 deterministic external sigGen vector not found")


def first_mldsa65_sigver() -> tuple[dict, dict]:
    prompt = fetch_json("ML-DSA-sigVer-FIPS204/prompt.json")
    expected = fetch_json("ML-DSA-sigVer-FIPS204/expectedResults.json")
    validity = {
        (group["tgId"], test["tcId"]): test["testPassed"]
        for group in expected["testGroups"]
        for test in group["tests"]
    }

    for group in prompt["testGroups"]:
        if (
            group.get("parameterSet") == "ML-DSA-65"
            and group.get("signatureInterface") == "external"
        ):
            for test in group["tests"]:
                if validity.get((group["tgId"], test["tcId"])):
                    return group, test
    raise RuntimeError("ML-DSA-65 valid sigVer vector not found")


def official_vectors() -> dict[str, str]:
    mlkem_keygen_group, mlkem_keygen = first_mlkem768_keygen()
    mlkem_encap_group, mlkem_encap = first_mlkem768_encap()
    mldsa_siggen_group, mldsa_siggen = first_mldsa65_siggen()
    mldsa_sigver_group, mldsa_sigver = first_mldsa65_sigver()

    return {
        "MLKEM768_KEYGEN_D_HEX": mlkem_keygen["d"],
        "MLKEM768_KEYGEN_Z_HEX": mlkem_keygen["z"],
        "MLKEM768_KEYGEN_PK_HEX": mlkem_keygen["ek"],
        "MLKEM768_KEYGEN_SK_HEX": mlkem_keygen["dk"],
        "MLKEM768_ENCAPS_PK_HEX": mlkem_encap["ek"],
        "MLKEM768_ENCAPS_SK_HEX": mlkem_encap["dk"],
        "MLKEM768_ENCAPS_MESSAGE_HEX": mlkem_encap["m"],
        "MLKEM768_ENCAPS_CT_HEX": mlkem_encap["c"],
        "MLKEM768_ENCAPS_SS_HEX": mlkem_encap["k"],
        "MLDSA65_SIGN_MESSAGE_HEX": mldsa_siggen["message"],
        "MLDSA65_SIGN_CONTEXT_HEX": mldsa_siggen["context"],
        "MLDSA65_SIGN_PK_HEX": mldsa_siggen["pk"],
        "MLDSA65_SIGN_SK_HEX": mldsa_siggen["sk"],
        "MLDSA65_SIGN_SIG_HEX": mldsa_siggen["signature"],
        "MLDSA65_VERIFY_MESSAGE_HEX": mldsa_sigver["message"],
        "MLDSA65_VERIFY_CONTEXT_HEX": mldsa_sigver["context"],
        "MLDSA65_VERIFY_PK_HEX": mldsa_sigver["pk"],
        "MLDSA65_VERIFY_SIG_HEX": mldsa_sigver["signature"],
        "__MLKEM_KEYGEN_TGID__": str(mlkem_keygen_group["tgId"]),
        "__MLKEM_KEYGEN_TCID__": str(mlkem_keygen["tcId"]),
        "__MLKEM_ENCAP_TGID__": str(mlkem_encap_group["tgId"]),
        "__MLKEM_ENCAP_TCID__": str(mlkem_encap["tcId"]),
        "__MLDSA_SIGGEN_TGID__": str(mldsa_siggen_group["tgId"]),
        "__MLDSA_SIGGEN_TCID__": str(mldsa_siggen["tcId"]),
        "__MLDSA_SIGVER_TGID__": str(mldsa_sigver_group["tgId"]),
        "__MLDSA_SIGVER_TCID__": str(mldsa_sigver["tcId"]),
    }


def format_c_string(name: str, value: str) -> str:
    lines = [f"static const char {name}[] ="]
    for index in range(0, len(value), 64):
        lines.append(f'    "{value[index:index + 64]}"')
    lines.append("    ;")
    return "\n".join(lines)


def render_header(vectors: dict[str, str]) -> str:
    lines = [
        "/* SPDX-License-Identifier: Apache-2.0 */",
        "/*",
        " * ML-KEM-768 KAT vectors: NIST ACVP ML-KEM keyGen-FIPS203 test group",
        f" * {vectors['__MLKEM_KEYGEN_TGID__']}, test case {vectors['__MLKEM_KEYGEN_TCID__']}, and",
        " * encapDecap-FIPS203 encapsulation test group",
        f" * {vectors['__MLKEM_ENCAP_TGID__']}, test case {vectors['__MLKEM_ENCAP_TCID__']}.",
        f" * Sources: {BASE_URL}/ML-KEM-keyGen-FIPS203/internalProjection.json",
        f" *          {BASE_URL}/ML-KEM-encapDecap-FIPS203/internalProjection.json",
        " *",
        " * ML-DSA-65 KAT vectors: NIST ACVP ML-DSA sigGen-FIPS204 deterministic",
        " * external signature test group",
        f" * {vectors['__MLDSA_SIGGEN_TGID__']}, test case {vectors['__MLDSA_SIGGEN_TCID__']}, and",
        " * sigVer-FIPS204 external signature test group",
        f" * {vectors['__MLDSA_SIGVER_TGID__']}, test case {vectors['__MLDSA_SIGVER_TCID__']}.",
        f" * Sources: {BASE_URL}/ML-DSA-sigGen-FIPS204/internalProjection.json",
        f" *          {BASE_URL}/ML-DSA-sigVer-FIPS204/prompt.json",
        f" *          {BASE_URL}/ML-DSA-sigVer-FIPS204/expectedResults.json",
        " *",
        " * Verified by scripts/verify_kat_provenance.py.",
        " */",
        "#ifndef PQCP_ZTEST_ACVP_KAT_VECTORS_H",
        "#define PQCP_ZTEST_ACVP_KAT_VECTORS_H",
        "",
    ]

    for name in (
        "MLKEM768_KEYGEN_D_HEX",
        "MLKEM768_KEYGEN_Z_HEX",
        "MLKEM768_KEYGEN_PK_HEX",
        "MLKEM768_KEYGEN_SK_HEX",
        "MLKEM768_ENCAPS_PK_HEX",
        "MLKEM768_ENCAPS_SK_HEX",
        "MLKEM768_ENCAPS_MESSAGE_HEX",
        "MLKEM768_ENCAPS_CT_HEX",
        "MLKEM768_ENCAPS_SS_HEX",
        "MLDSA65_SIGN_MESSAGE_HEX",
        "MLDSA65_SIGN_CONTEXT_HEX",
        "MLDSA65_SIGN_PK_HEX",
        "MLDSA65_SIGN_SK_HEX",
        "MLDSA65_SIGN_SIG_HEX",
        "MLDSA65_VERIFY_MESSAGE_HEX",
        "MLDSA65_VERIFY_CONTEXT_HEX",
        "MLDSA65_VERIFY_PK_HEX",
        "MLDSA65_VERIFY_SIG_HEX",
    ):
        lines.append(format_c_string(name, vectors[name]))
        lines.append("")

    lines.append("#endif /* PQCP_ZTEST_ACVP_KAT_VECTORS_H */")
    lines.append("")
    return "\n".join(lines)


def verify_vectors(header_constants: dict[str, str], vectors: dict[str, str]) -> list[str]:
    mismatches: list[str] = []
    for name, expected in vectors.items():
        if name.startswith("__"):
            continue
        actual = header_constants.get(name)
        if actual is None:
            mismatches.append(f"missing constant: {name}")
            continue
        if actual.upper() != expected.upper():
            mismatches.append(
                f"{name} mismatch: header starts {actual[:32]}, expected starts {expected[:32]}"
            )
    return mismatches


def main() -> int:
    args = parse_args()
    vectors = official_vectors()

    if args.emit_header is not None:
        args.emit_header.parent.mkdir(parents=True, exist_ok=True)
        args.emit_header.write_text(render_header(vectors), encoding="utf-8")
        print(f"Wrote {args.emit_header}")
        return 0

    header_constants = load_header_constants(args.header)
    mismatches = verify_vectors(header_constants, vectors)
    if mismatches:
        print("KAT provenance verification failed:", file=sys.stderr)
        for mismatch in mismatches:
            print(f"  - {mismatch}", file=sys.stderr)
        return 1

    print("KAT provenance verified against NIST ACVP JSON.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
