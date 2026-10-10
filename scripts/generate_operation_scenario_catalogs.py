#!/usr/bin/env python3
"""Generate two-operation scenario witnesses for runtime and channel policy."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import generate_operation_conformance_catalogs as conformance


Decision = tuple[str, str, str, str, str, str, str]


@dataclass(frozen=True)
class Domain:
    filename: str
    symbol: str
    domain_token: str
    conditions: list[str]
    operations: list[str]
    condition_prefix: str
    operation_prefix: str
    decide: Callable[[str, str], Decision]
    stateful: bool


RUNTIME_OPERATIONS = [
    "START",
    "STOP",
    "TICK",
    "AUDIT",
    "LOCKDOWN",
    "RECOVER",
    "SUBMIT_JOB",
    "WRITE_CHECKPOINT",
]

CHANNEL_OPERATIONS = [
    "STREAM_OPEN",
    "REKEY_PREPARE",
    "REKEY_COMMIT",
    "PATH_CHALLENGE",
    "PEER_DRAIN",
    "KEEPALIVE",
    "GOAWAY",
    "ERROR",
]


DOMAINS = [
    Domain(
        "runtime_policy_scenario_catalog.c",
        "runtime_policy",
        "PQCP_OPERATION_SCENARIO_RUNTIME_POLICY",
        [
            "UNINITIALIZED",
            "INITIALIZED",
            "RUNNING",
            "DEGRADED",
            "DRAINING",
            "LOCKDOWN",
            "RECOVERING",
            "TERMINATED",
        ],
        RUNTIME_OPERATIONS,
        "PQCP_RUNTIME_POLICY_",
        "PQCP_RUNTIME_COMMAND_",
        conformance.runtime_policy_decision,
        True,
    ),
    Domain(
        "runtime_resource_scenario_catalog.c",
        "runtime_resource",
        "PQCP_OPERATION_SCENARIO_RUNTIME_RESOURCE",
        [
            "AVAILABLE",
            "JOBS_ELEVATED",
            "HIGH",
            "CRITICAL",
            "JOBS_EXHAUSTED",
            "MEMORY_EXHAUSTED",
            "QUARANTINED",
            "FAILED",
        ],
        RUNTIME_OPERATIONS,
        "PQCP_RUNTIME_RESOURCE_",
        "PQCP_RUNTIME_COMMAND_",
        conformance.runtime_resource_decision,
        False,
    ),
    Domain(
        "runtime_recovery_scenario_catalog.c",
        "runtime_recovery",
        "PQCP_OPERATION_SCENARIO_RUNTIME_RECOVERY",
        [
            "HEALTHY",
            "TRANSIENT_IO",
            "QUEUE_STALL",
            "RESOURCE_PRESSURE",
            "KEY_STORE_INVALID",
            "AUDIT_INVALID",
            "LOCKDOWN",
            "UNRECOVERABLE",
        ],
        RUNTIME_OPERATIONS,
        "PQCP_RUNTIME_RECOVERY_",
        "PQCP_RUNTIME_COMMAND_",
        conformance.runtime_recovery_decision,
        False,
    ),
    Domain(
        "protected_channel_policy_scenario_catalog.c",
        "channel_policy",
        "PQCP_OPERATION_SCENARIO_CHANNEL_POLICY",
        [
            "NEW",
            "NEGOTIATING",
            "ESTABLISHED",
            "REKEY_PREPARED",
            "MIGRATING",
            "DRAINING",
            "FAILED",
            "TERMINATED",
        ],
        CHANNEL_OPERATIONS,
        "PQCP_CHANNEL_POLICY_",
        "PQCP_CHANNEL_CONTROL_",
        conformance.channel_policy_decision,
        True,
    ),
    Domain(
        "protected_channel_path_scenario_catalog.c",
        "channel_path",
        "PQCP_OPERATION_SCENARIO_CHANNEL_PATH",
        [
            "PRIMARY_HEALTHY",
            "PRIMARY_SLOW",
            "PRIMARY_FAILED",
            "CANDIDATE_VALIDATED",
            "MIGRATING",
            "DRAINING",
            "NO_VALID_PATH",
            "TERMINATED",
        ],
        CHANNEL_OPERATIONS,
        "PQCP_CHANNEL_PATH_CONDITION_",
        "PQCP_CHANNEL_CONTROL_",
        conformance.channel_path_decision,
        False,
    ),
    Domain(
        "protected_channel_fault_scenario_catalog.c",
        "channel_fault",
        "PQCP_OPERATION_SCENARIO_CHANNEL_FAULT",
        [
            "NONE",
            "TRANSIENT_IO",
            "TIMEOUT",
            "FLOW_CONTROL",
            "AUTHENTICATION",
            "REPLAY",
            "INTERNAL",
            "TERMINAL",
        ],
        CHANNEL_OPERATIONS,
        "PQCP_CHANNEL_FAULT_",
        "PQCP_CHANNEL_CONTROL_",
        conformance.channel_fault_decision,
        False,
    ),
]


def integer_literal(value: str) -> int:
    return int(value.removesuffix("U"), 0)


def error_succeeded(value: str) -> bool:
    return value in {"0", "0U"}


def result_for(
    domain: Domain,
    initial_condition: str,
    first_operation: str,
    second_operation: str,
) -> tuple[str, Decision, Decision, int, str]:
    first = domain.decide(initial_condition, first_operation)
    if domain.stateful and error_succeeded(first[6]):
        second_condition = first[1].removeprefix(domain.condition_prefix)
    else:
        second_condition = initial_condition
    second = domain.decide(second_condition, second_operation)
    aggregate_reason = integer_literal(first[5]) | integer_literal(second[5])
    terminal_error = first[6] if not error_succeeded(first[6]) else second[6]
    return second_condition, first, second, aggregate_reason, terminal_error


def render(domain: Domain) -> str:
    if len(domain.conditions) != 8 or len(domain.operations) != 8:
        raise ValueError(f"{domain.symbol} must define exactly 8x8x8 scenarios")

    lines = [
        "/*",
        " * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation",
        " *",
        " * Generated by scripts/generate_operation_scenario_catalogs.py.",
        " * Do not edit by hand.",
        " */",
        "",
        "#include <errno.h>",
        "",
        '#include "operation_scenario_internal.h"',
        "",
        f"static const struct pqcp_operation_scenario_case {domain.symbol}_scenarios[] = {{",
    ]
    for initial_condition in domain.conditions:
        for first_operation in domain.operations:
            for second_operation in domain.operations:
                (
                    second_condition,
                    first,
                    second,
                    aggregate_reason,
                    terminal_error,
                ) = result_for(
                    domain,
                    initial_condition,
                    first_operation,
                    second_operation,
                )
                condition_token = (
                    f"{domain.condition_prefix}{initial_condition}"
                )
                first_token = (
                    f"{domain.operation_prefix}{first_operation}"
                )
                second_token = (
                    f"{domain.operation_prefix}{second_operation}"
                )
                second_condition_token = (
                    f"{domain.condition_prefix}{second_condition}"
                )
                lines.extend(
                    [
                        "\t{",
                        f"\t\t.initial_condition = {condition_token},",
                        f"\t\t.first_operation = {first_token}, .second_operation = {second_token},",
                        "\t\t.expected = {",
                        f"\t\t\t.second_condition = {second_condition_token},",
                        f"\t\t\t.first_decision = {first[0]}, .first_next_state = {first[1]},",
                        f"\t\t\t.first_reason_mask = {first[5]}, .first_error = {first[6]},",
                        f"\t\t\t.second_decision = {second[0]}, .second_next_state = {second[1]},",
                        f"\t\t\t.second_reason_mask = {second[5]}, .second_error = {second[6]},",
                        f"\t\t\t.aggregate_reason_mask = {aggregate_reason}U, .terminal_error = {terminal_error},",
                        "\t\t},",
                        "\t},",
                    ]
                )
    lines.extend(
        [
            "};",
            "",
            f"size_t pqcp_{domain.symbol}_scenario_catalog_count(void)",
            "{",
            f"\treturn ARRAY_SIZE({domain.symbol}_scenarios);",
            "}",
            "",
            f"int pqcp_{domain.symbol}_scenario_catalog_get(",
            "\tsize_t index,",
            "\tstruct pqcp_operation_scenario_case *test_case)",
            "{",
            f"\tif (index >= ARRAY_SIZE({domain.symbol}_scenarios) ||",
            "\t    test_case == NULL) {",
            "\t\treturn -EINVAL;",
            "\t}",
            f"\t*test_case = {domain.symbol}_scenarios[index];",
            "\ttest_case->schema_version =",
            "\t\tPQCP_OPERATION_SCENARIO_SCHEMA_VERSION;",
            f"\ttest_case->domain = {domain.domain_token};",
            "\ttest_case->case_id =",
            "\t\tPQCP_OPERATION_SCENARIO_CASE_ID(",
            "\t\t\ttest_case->domain,",
            "\t\t\ttest_case->initial_condition,",
            "\t\t\ttest_case->first_operation,",
            "\t\t\ttest_case->second_operation);",
            "\treturn 0;",
            "}",
            "",
            f"int pqcp_{domain.symbol}_scenario_catalog_audit(void)",
            "{",
            f"\tif (ARRAY_SIZE({domain.symbol}_scenarios) !=",
            "\t    PQCP_OPERATION_SCENARIO_CASES_PER_DOMAIN) {",
            "\t\treturn -EBADMSG;",
            "\t}",
            f"\tfor (size_t index = 0U;",
            f"\t     index < ARRAY_SIZE({domain.symbol}_scenarios);",
            "\t     ++index) {",
            "\t\tstruct pqcp_operation_scenario_case test_case;",
            "\t\tint ret;",
            "",
            f"\t\tret = pqcp_{domain.symbol}_scenario_catalog_get(",
            "\t\t\tindex, &test_case);",
            "\t\tif (ret != 0) {",
            "\t\t\treturn ret;",
            "\t\t}",
            "\t\tret = pqcp_operation_scenario_verify(",
            "\t\t\t&test_case);",
            "\t\tif (ret != 0) {",
            "\t\t\treturn ret;",
            "\t\t}",
            "\t}",
            "\treturn 0;",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    args = parser.parse_args()

    mismatches: list[str] = []
    for domain in DOMAINS:
        output = args.repo_root / "src" / domain.filename
        content = render(domain)
        if args.check:
            if not output.exists() or output.read_text() != content:
                mismatches.append(str(output))
        else:
            output.write_text(content)
    if mismatches:
        for mismatch in mismatches:
            print(f"stale generated scenario catalog: {mismatch}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
