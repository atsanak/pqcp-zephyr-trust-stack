#!/usr/bin/env python3
"""Generate replayable witnesses for every operational policy decision."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import generate_runtime_channel_policy_catalogs as policy


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
    lookup_type: str
    lookup_function: str
    comparison: list[str]


def runtime_policy_decision(condition: str, operation: str) -> Decision:
    action, next_state, error, reason = policy.runtime_decision(
        condition, operation
    )
    return (
        f"PQCP_RUNTIME_POLICY_{action}",
        f"PQCP_RUNTIME_POLICY_{next_state}",
        "0U",
        "0U",
        "0U",
        f"{reason}U",
        error,
    )


def runtime_resource_decision(condition: str, operation: str) -> Decision:
    decision, concurrency, ttl, penalty, reason, error = (
        policy.runtime_resource_decision(condition, operation)
    )
    return (
        f"PQCP_RUNTIME_RESOURCE_{decision}",
        "0U",
        f"{concurrency}U",
        f"{ttl}U",
        f"{penalty}U",
        f"{reason}U",
        error,
    )


def runtime_recovery_decision(condition: str, operation: str) -> Decision:
    directive, next_state, attempts, delay, reason, error = (
        policy.runtime_recovery_decision(condition, operation)
    )
    return (
        f"PQCP_RUNTIME_RECOVERY_{directive}",
        f"PQCP_RUNTIME_POLICY_{next_state}",
        f"{attempts}U",
        f"{delay}U",
        "0U",
        f"{reason}U",
        error,
    )


def channel_policy_decision(condition: str, operation: str) -> Decision:
    action, next_state, error, reason = policy.channel_decision(
        condition, operation
    )
    return (
        f"PQCP_CHANNEL_POLICY_{action}",
        f"PQCP_CHANNEL_POLICY_{next_state}",
        "0U",
        "0U",
        "0U",
        f"{reason}U",
        error,
    )


def channel_path_decision(condition: str, operation: str) -> Decision:
    decision, timeout, hysteresis, reason, next_state, error = (
        policy.channel_path_decision(condition, operation)
    )
    return (
        f"PQCP_CHANNEL_PATH_{decision}",
        f"PQCP_CHANNEL_POLICY_{next_state}",
        f"{timeout}U",
        f"{hysteresis}U",
        "0U",
        f"{reason}U",
        error,
    )


def channel_fault_decision(condition: str, operation: str) -> Decision:
    directive, next_state, attempts, delay, reason, error = (
        policy.channel_fault_decision(condition, operation)
    )
    return (
        f"PQCP_CHANNEL_FAULT_{directive}",
        f"PQCP_CHANNEL_POLICY_{next_state}",
        f"{attempts}U",
        f"{delay}U",
        "0U",
        f"{reason}U",
        error,
    )


DOMAINS = [
    Domain(
        "runtime_policy_conformance_catalog.c",
        "runtime_policy",
        "PQCP_OPERATION_CONFORMANCE_RUNTIME_POLICY",
        policy.RUNTIME_STATES,
        policy.RUNTIME_COMMANDS,
        "PQCP_RUNTIME_POLICY_",
        "PQCP_RUNTIME_COMMAND_",
        runtime_policy_decision,
        "struct pqcp_runtime_policy_decision",
        "pqcp_runtime_policy_lookup",
        [
            "actual.action != test_case->decision",
            "actual.next_state != test_case->next_state",
            "actual.flags != test_case->reason_mask",
            "actual.error != test_case->expected_error",
        ],
    ),
    Domain(
        "runtime_resource_conformance_catalog.c",
        "runtime_resource",
        "PQCP_OPERATION_CONFORMANCE_RUNTIME_RESOURCE",
        policy.RUNTIME_RESOURCE_CONDITIONS,
        policy.RUNTIME_COMMANDS,
        "PQCP_RUNTIME_RESOURCE_",
        "PQCP_RUNTIME_COMMAND_",
        runtime_resource_decision,
        "struct pqcp_runtime_resource_policy_decision",
        "pqcp_runtime_resource_policy_lookup",
        [
            "actual.disposition != test_case->decision",
            "actual.maximum_concurrency != test_case->parameter0",
            "actual.reservation_ttl_ms != test_case->parameter1",
            "actual.priority_penalty != test_case->parameter2",
            "actual.reason_mask != test_case->reason_mask",
            "actual.error != test_case->expected_error",
        ],
    ),
    Domain(
        "runtime_recovery_conformance_catalog.c",
        "runtime_recovery",
        "PQCP_OPERATION_CONFORMANCE_RUNTIME_RECOVERY",
        policy.RUNTIME_RECOVERY_CONDITIONS,
        policy.RUNTIME_COMMANDS,
        "PQCP_RUNTIME_RECOVERY_",
        "PQCP_RUNTIME_COMMAND_",
        runtime_recovery_decision,
        "struct pqcp_runtime_recovery_policy_decision",
        "pqcp_runtime_recovery_policy_lookup",
        [
            "actual.directive != test_case->decision",
            "actual.next_state != test_case->next_state",
            "actual.maximum_attempts != test_case->parameter0",
            "actual.delay_ms != test_case->parameter1",
            "actual.reason_mask != test_case->reason_mask",
            "actual.error != test_case->expected_error",
        ],
    ),
    Domain(
        "protected_channel_policy_conformance_catalog.c",
        "channel_policy",
        "PQCP_OPERATION_CONFORMANCE_CHANNEL_POLICY",
        policy.CHANNEL_STATES,
        policy.CHANNEL_CONTROLS,
        "PQCP_CHANNEL_POLICY_",
        "PQCP_CHANNEL_CONTROL_",
        channel_policy_decision,
        "struct pqcp_channel_policy_decision",
        "pqcp_channel_policy_lookup",
        [
            "actual.action != test_case->decision",
            "actual.next_state != test_case->next_state",
            "actual.flags != test_case->reason_mask",
            "actual.error != test_case->expected_error",
        ],
    ),
    Domain(
        "protected_channel_path_conformance_catalog.c",
        "channel_path",
        "PQCP_OPERATION_CONFORMANCE_CHANNEL_PATH",
        policy.CHANNEL_PATH_CONDITIONS,
        policy.CHANNEL_CONTROLS,
        "PQCP_CHANNEL_PATH_CONDITION_",
        "PQCP_CHANNEL_CONTROL_",
        channel_path_decision,
        "struct pqcp_channel_path_policy_decision",
        "pqcp_channel_path_policy_lookup",
        [
            "actual.disposition != test_case->decision",
            "actual.next_state != test_case->next_state",
            "actual.probe_timeout_ms != test_case->parameter0",
            "actual.migration_hysteresis_bps != test_case->parameter1",
            "actual.reason_mask != test_case->reason_mask",
            "actual.error != test_case->expected_error",
        ],
    ),
    Domain(
        "protected_channel_fault_conformance_catalog.c",
        "channel_fault",
        "PQCP_OPERATION_CONFORMANCE_CHANNEL_FAULT",
        policy.CHANNEL_FAULT_CONDITIONS,
        policy.CHANNEL_CONTROLS,
        "PQCP_CHANNEL_FAULT_",
        "PQCP_CHANNEL_CONTROL_",
        channel_fault_decision,
        "struct pqcp_channel_fault_policy_decision",
        "pqcp_channel_fault_policy_lookup",
        [
            "actual.directive != test_case->decision",
            "actual.next_state != test_case->next_state",
            "actual.maximum_attempts != test_case->parameter0",
            "actual.delay_ms != test_case->parameter1",
            "actual.reason_mask != test_case->reason_mask",
            "actual.error != test_case->expected_error",
        ],
    ),
]


def render(domain: Domain) -> str:
    lines = [
        "/*",
        " * SPDX-License-Identifier: MIT",
        " *",
        " * Generated by scripts/generate_operation_conformance_catalogs.py.",
        " * Do not edit by hand.",
        " */",
        "",
        "#include <errno.h>",
        "",
        '#include "operation_conformance_internal.h"',
        "",
        f"static const struct pqcp_operation_conformance_case {domain.symbol}_catalog[] = {{",
    ]
    for condition_index, condition in enumerate(domain.conditions):
        for operation_index, operation in enumerate(domain.operations):
            (
                decision,
                next_state,
                parameter0,
                parameter1,
                parameter2,
                reason,
                error,
            ) = domain.decide(condition, operation)
            condition_token = f"{domain.condition_prefix}{condition}"
            operation_token = f"{domain.operation_prefix}{operation}"
            lines.extend(
                [
                    "\t{",
                    f"\t\t.condition = {condition_token}, .operation = {operation_token},",
                    f"\t\t.decision = {decision}, .next_state = {next_state},",
                    f"\t\t.parameter0 = {parameter0}, .parameter1 = {parameter1},",
                    f"\t\t.parameter2 = {parameter2}, .reason_mask = {reason},",
                    f"\t\t.expected_error = {error},",
                    "\t},",
                ]
            )
    lines.extend(
        [
            "};",
            "",
            f"size_t pqcp_{domain.symbol}_conformance_catalog_count(void)",
            "{",
            f"\treturn ARRAY_SIZE({domain.symbol}_catalog);",
            "}",
            "",
            f"int pqcp_{domain.symbol}_conformance_catalog_get(",
            "\tsize_t index,",
            "\tstruct pqcp_operation_conformance_case *test_case)",
            "{",
            f"\tif (index >= ARRAY_SIZE({domain.symbol}_catalog) ||",
            "\t    test_case == NULL) {",
            "\t\treturn -EINVAL;",
            "\t}",
            f"\t*test_case = {domain.symbol}_catalog[index];",
            "\ttest_case->schema_version =",
            "\t\tPQCP_OPERATION_CONFORMANCE_SCHEMA_VERSION;",
            f"\ttest_case->domain = {domain.domain_token};",
            "\ttest_case->case_id =",
            "\t\tPQCP_OPERATION_CONFORMANCE_CASE_ID(",
            "\t\t\ttest_case->domain,",
            "\t\t\ttest_case->condition,",
            "\t\t\ttest_case->operation);",
            "\treturn 0;",
            "}",
            "",
            f"int pqcp_{domain.symbol}_conformance_catalog_audit(void)",
            "{",
            f"\tif (ARRAY_SIZE({domain.symbol}_catalog) !=",
            "\t    PQCP_OPERATION_CONFORMANCE_CASES_PER_DOMAIN) {",
            "\t\treturn -EBADMSG;",
            "\t}",
            f"\tfor (size_t index = 0U;",
            f"\t     index < ARRAY_SIZE({domain.symbol}_catalog);",
            "\t     ++index) {",
            "\t\tstruct pqcp_operation_conformance_case test_case_value;",
            "\t\tconst struct pqcp_operation_conformance_case *test_case =",
            "\t\t\t&test_case_value;",
            f"\t\t{domain.lookup_type} actual;",
            "\t\tint ret;",
            "",
            f"\t\tret = pqcp_{domain.symbol}_conformance_catalog_get(",
            "\t\t\tindex, &test_case_value);",
            "\t\tif (ret != 0) {",
            "\t\t\treturn ret;",
            "\t\t}",
            "\t\tif (test_case->schema_version !=",
            "\t\t\t    PQCP_OPERATION_CONFORMANCE_SCHEMA_VERSION ||",
            f"\t\t    test_case->domain != {domain.domain_token} ||",
            "\t\t    test_case->case_id !=",
            "\t\t\t    PQCP_OPERATION_CONFORMANCE_CASE_ID(",
            "\t\t\t\ttest_case->domain,",
            "\t\t\t\ttest_case->condition,",
            "\t\t\t\ttest_case->operation)) {",
            "\t\t\treturn -EBADMSG;",
            "\t\t}",
            f"\t\tret = {domain.lookup_function}(",
            "\t\t\t(enum "
            + (
                "pqcp_runtime_policy_state"
                if domain.symbol == "runtime_policy"
                else "pqcp_runtime_resource_condition"
                if domain.symbol == "runtime_resource"
                else "pqcp_runtime_recovery_condition"
                if domain.symbol == "runtime_recovery"
                else "pqcp_channel_policy_state"
                if domain.symbol == "channel_policy"
                else "pqcp_channel_path_condition"
                if domain.symbol == "channel_path"
                else "pqcp_channel_fault_condition"
            )
            + ")test_case->condition,",
            "\t\t\t(enum "
            + (
                "pqcp_runtime_command_kind"
                if domain.symbol.startswith("runtime_")
                else "pqcp_channel_control_kind"
            )
            + ")test_case->operation,",
            "\t\t\t&actual);",
            "\t\tif (ret != 0) {",
            "\t\t\treturn ret;",
            "\t\t}",
            "\t\tif (",
        ]
    )
    for index, comparison in enumerate(domain.comparison):
        suffix = " ||" if index + 1 < len(domain.comparison) else ") {"
        lines.append(f"\t\t    {comparison}{suffix}")
    lines.extend(
        [
            "\t\t\treturn -EBADMSG;",
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
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="directory for the generated C sources (default: <repo>/build/generated)",
    )
    args = parser.parse_args()
    out_dir = (args.output_dir or args.repo_root / "build" / "generated").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    mismatches: list[str] = []
    for domain in DOMAINS:
        output = out_dir / domain.filename
        content = render(domain)
        if args.check:
            if not output.exists() or output.read_text() != content:
                mismatches.append(str(output))
        else:
            output.write_text(content)
    if mismatches:
        for mismatch in mismatches:
            print(f"stale generated catalog: {mismatch}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
