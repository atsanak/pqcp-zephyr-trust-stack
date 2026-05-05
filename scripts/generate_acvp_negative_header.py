#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Render scripts/acvp_negative_scenarios.json into a C header.

The generated header backs tests/ztest_acvp_serial_negative, which
exercises the ACVP serial harness against every documented negative
scenario directly through pqcp_acvp_process_command() rather than by
grepping a positive-run transcript. Cases that depend on the streaming
consume_char timeout path (e.g. append_newline=false) are skipped at
generation time and remain covered by tests/ztest_acvp_serial.

Run this script whenever scripts/acvp_negative_scenarios.json changes:

    python3 scripts/generate_acvp_negative_header.py

The script also runs in --check mode for CI / pre-commit usage.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCENARIOS = REPO_ROOT / "scripts/acvp_negative_scenarios.json"
DEFAULT_OUTPUT = REPO_ROOT / "tests/ztest_acvp_serial_negative/src/scenarios.h"
HEADER_GUARD = "PQCP_ZTEST_ACVP_NEGATIVE_SCENARIOS_H"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scenarios", type=Path, default=DEFAULT_SCENARIOS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if the on-disk header would differ from the "
        "regenerated one. Used in CI/pre-commit to catch drift.",
    )
    return parser.parse_args()


def encode_c_string(value: str) -> str:
    """Encode a Python string into a C string literal with explicit hex escapes
    for any non-printable byte. The wire grammar uses ASCII-printable command
    text plus deliberately injected control characters in some scenarios; we
    must round-trip those bytes exactly.
    """
    out = ['"']
    for byte in value.encode("utf-8"):
        if byte == 0x22:  # '"'
            out.append('\\"')
        elif byte == 0x5C:  # '\\'
            out.append("\\\\")
        elif 0x20 <= byte <= 0x7E:
            out.append(chr(byte))
        else:
            out.append(f"\\x{byte:02x}")
    out.append('"')
    return "".join(out)


def collect_cases(scenarios: dict) -> list[dict]:
    cases: list[dict] = []
    for scenario in scenarios.get("scenarios", []) or []:
        if not isinstance(scenario, dict):
            continue
        for case in scenario.get("expected_errors", []) or []:
            if not isinstance(case, dict):
                continue
            command = case.get("command")
            response = case.get("response")
            name = case.get("name")
            if not isinstance(command, str) or not isinstance(response, str):
                continue
            if not isinstance(name, str) or not name:
                continue
            # Cases with append_newline=false rely on the streaming
            # readline-timeout path which is exercised by
            # ztest_acvp_serial::test_readline_timeout. The dispatcher in
            # pqcp_acvp_process_command receives complete lines, so those
            # cases cannot be replayed here.
            if case.get("append_newline") is False:
                continue
            cases.append({
                "name": name,
                "command": command,
                "expected_response": response,
            })
    return cases


def render(cases: list[dict]) -> str:
    lines = [
        "/* SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation */",
        "/*",
        " * Auto-generated from scripts/acvp_negative_scenarios.json by",
        " * scripts/generate_acvp_negative_header.py. Do not edit by hand.",
        " */",
        f"#ifndef {HEADER_GUARD}",
        f"#define {HEADER_GUARD}",
        "",
        "#include <stddef.h>",
        "",
        "struct pqcp_acvp_negative_case {",
        "    const char *name;",
        "    const char *command;",
        "    const char *expected_response;",
        "};",
        "",
        f"#define PQCP_ACVP_NEGATIVE_CASE_COUNT {len(cases)}",
        "",
        "static const struct pqcp_acvp_negative_case pqcp_acvp_negative_cases[] = {",
    ]
    for case in cases:
        lines.append("    {")
        lines.append(f"        .name = {encode_c_string(case['name'])},")
        lines.append(f"        .command = {encode_c_string(case['command'])},")
        lines.append(
            f"        .expected_response = {encode_c_string(case['expected_response'])},"
        )
        lines.append("    },")
    lines.extend([
        "};",
        "",
        f"#endif /* {HEADER_GUARD} */",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    scenarios = json.loads(args.scenarios.read_text(encoding="utf-8"))
    cases = collect_cases(scenarios)
    if not cases:
        print(
            "generate_acvp_negative_header: no replay-eligible cases produced; "
            "check the input fixture",
            file=sys.stderr,
        )
        return 1
    rendered = render(cases)
    if args.check:
        existing = args.output.read_text(encoding="utf-8") if args.output.exists() else ""
        if existing != rendered:
            print(
                f"generate_acvp_negative_header: {args.output} is out of date; "
                "rerun without --check to refresh.",
                file=sys.stderr,
            )
            return 2
        print(f"OK: {args.output} matches {args.scenarios}")
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(f"[INFO] wrote {len(cases)} cases to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
