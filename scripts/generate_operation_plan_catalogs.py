#!/usr/bin/env python3
"""Generate replayable composite runtime and channel operation-plan witnesses."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_runtime_channel_policy_catalogs as policy  # noqa: E402


FNV1A_OFFSET_BASIS = "UINT64_C(14695981039346656037)"
FNV1A_PRIME = "UINT64_C(1099511628211)"
SCENARIOS = ["BASELINE", "STRESS"]


def error_or(error: str, fallback: str) -> str:
    return error if error != "0" else fallback


def runtime_context(
    scenario: str,
    state_index: int,
    command_index: int,
) -> tuple[str, str]:
    if scenario == "BASELINE":
        return "AVAILABLE", "HEALTHY"
    resource_index = (state_index * 5 + command_index * 3) % len(
        policy.RUNTIME_RESOURCE_CONDITIONS
    )
    recovery_index = (state_index * 7 + command_index * 11) % len(
        policy.RUNTIME_RECOVERY_CONDITIONS
    )
    return (
        policy.RUNTIME_RESOURCE_CONDITIONS[resource_index],
        policy.RUNTIME_RECOVERY_CONDITIONS[recovery_index],
    )


def channel_context(
    scenario: str,
    state_index: int,
    control_index: int,
) -> tuple[str, str]:
    if scenario == "BASELINE":
        return "PRIMARY_HEALTHY", "NONE"
    path_index = (state_index * 5 + control_index * 3) % len(
        policy.CHANNEL_PATH_CONDITIONS
    )
    fault_index = (state_index * 7 + control_index * 11) % len(
        policy.CHANNEL_FAULT_CONDITIONS
    )
    return (
        policy.CHANNEL_PATH_CONDITIONS[path_index],
        policy.CHANNEL_FAULT_CONDITIONS[fault_index],
    )


def runtime_plan(
    state: str,
    resource: str,
    recovery: str,
    command: str,
) -> tuple[str, str, int, int, int, int, int, int, str]:
    state_action, state_next, state_error, state_reason = (
        policy.runtime_decision(state, command)
    )
    (
        resource_action,
        concurrency,
        reservation_ttl,
        priority_penalty,
        resource_reason,
        resource_error,
    ) = policy.runtime_resource_decision(resource, command)
    (
        recovery_action,
        recovery_next,
        retry_limit,
        retry_delay,
        recovery_reason,
        recovery_error,
    ) = policy.runtime_recovery_decision(recovery, command)
    reason = state_reason | resource_reason | recovery_reason

    if recovery_action == "TERMINATE":
        return (
            "TERMINATE",
            "TERMINATED",
            concurrency,
            reservation_ttl,
            priority_penalty,
            retry_limit,
            retry_delay,
            reason,
            error_or(recovery_error, "-ESHUTDOWN"),
        )
    if recovery_action == "LOCK_DOWN":
        return (
            "LOCKDOWN",
            "LOCKDOWN",
            concurrency,
            reservation_ttl,
            priority_penalty,
            retry_limit,
            retry_delay,
            reason,
            error_or(recovery_error, "-EACCES"),
        )
    if state_action == "DENY":
        return (
            "DENY",
            state_next,
            concurrency,
            reservation_ttl,
            priority_penalty,
            retry_limit,
            retry_delay,
            reason,
            error_or(state_error, "-EACCES"),
        )
    if resource_action == "DENY":
        return (
            "DENY",
            state,
            concurrency,
            reservation_ttl,
            priority_penalty,
            retry_limit,
            retry_delay,
            reason,
            error_or(resource_error, "-EDQUOT"),
        )

    recovery_dispositions = {
        "RESTART": "RECOVER",
        "ROLLBACK": "RECOVER",
        "ROTATE_KEYS": "RECOVER",
        "CHECKPOINT": "CHECKPOINT",
        "DRAIN": "DRAIN",
        "RETRY": "RETRY",
        "BACKOFF": "RETRY",
    }
    if recovery_action in recovery_dispositions:
        return (
            recovery_dispositions[recovery_action],
            recovery_next,
            concurrency,
            reservation_ttl,
            priority_penalty,
            retry_limit,
            retry_delay,
            reason,
            recovery_error,
        )

    resource_dispositions = {
        "REQUIRE_RECOVERY": ("RECOVER", "RECOVERING"),
        "REQUIRE_CHECKPOINT": ("CHECKPOINT", "CHECKPOINTING"),
        "ALLOW_RECLAIM": ("RECLAIM", state),
        "ALLOW_THROTTLED": ("THROTTLE", state),
    }
    if resource_action in resource_dispositions:
        disposition, next_state = resource_dispositions[resource_action]
        return (
            disposition,
            next_state,
            concurrency,
            reservation_ttl,
            priority_penalty,
            retry_limit,
            retry_delay,
            reason,
            resource_error,
        )

    state_dispositions = {
        "ALLOW": "ALLOW",
        "ALLOW_IDEMPOTENT": "ALLOW_IDEMPOTENT",
        "ALLOW_READ_ONLY": "ALLOW_READ_ONLY",
        "REQUIRE_DRAIN": "DRAIN",
        "REQUIRE_MAINTENANCE": "MAINTENANCE",
        "REQUIRE_RECOVERY": "RECOVER",
    }
    return (
        state_dispositions[state_action],
        state_next,
        concurrency,
        reservation_ttl,
        priority_penalty,
        retry_limit,
        retry_delay,
        reason,
        state_error,
    )


def channel_plan(
    state: str,
    path: str,
    fault: str,
    control: str,
) -> tuple[str, str, int, int, int, int, int, str]:
    state_action, state_next, state_error, state_reason = (
        policy.channel_decision(state, control)
    )
    (
        path_action,
        probe_timeout,
        hysteresis,
        path_reason,
        path_next,
        path_error,
    ) = policy.channel_path_decision(path, control)
    (
        fault_action,
        fault_next,
        retry_limit,
        retry_delay,
        fault_reason,
        fault_error,
    ) = policy.channel_fault_decision(fault, control)
    reason = state_reason | path_reason | fault_reason

    if fault_action == "TERMINATE_CHANNEL":
        return (
            "TERMINATE",
            "TERMINATED",
            probe_timeout,
            hysteresis,
            retry_limit,
            retry_delay,
            reason,
            error_or(fault_error, "-ESHUTDOWN"),
        )
    if fault_action == "CLOSE_CHANNEL":
        return (
            "CLOSE",
            fault_next,
            probe_timeout,
            hysteresis,
            retry_limit,
            retry_delay,
            reason,
            error_or(fault_error, "-ECONNABORTED"),
        )
    if path_action == "CLOSE":
        return (
            "CLOSE",
            path_next,
            probe_timeout,
            hysteresis,
            retry_limit,
            retry_delay,
            reason,
            error_or(path_error, "-ESHUTDOWN"),
        )
    if state_action == "DENY":
        return (
            "DENY",
            state_next,
            probe_timeout,
            hysteresis,
            retry_limit,
            retry_delay,
            reason,
            error_or(state_error, "-EACCES"),
        )
    if path_action == "DENY":
        return (
            "DENY",
            state,
            probe_timeout,
            hysteresis,
            retry_limit,
            retry_delay,
            reason,
            error_or(path_error, "-EHOSTUNREACH"),
        )

    fault_dispositions = {
        "DRAIN_CHANNEL": "DRAIN",
        "RESET_STREAM": "RESET_STREAM",
        "REKEY_CHANNEL": "REKEY",
        "MIGRATE_PATH": "MIGRATE_PATH",
        "RETRY": "RETRY",
        "BACKOFF": "RETRY",
    }
    if fault_action in fault_dispositions:
        return (
            fault_dispositions[fault_action],
            fault_next,
            probe_timeout,
            hysteresis,
            retry_limit,
            retry_delay,
            reason,
            fault_error,
        )
    if fault_action == "OBSERVE" and fault_error != "0":
        return (
            "RETRY",
            fault_next,
            probe_timeout,
            hysteresis,
            retry_limit,
            retry_delay,
            reason,
            fault_error,
        )

    state_dispositions = {
        "ALLOW": "ALLOW",
        "CLOSE_ON_FAILURE": "ALLOW",
        "ALLOW_IDEMPOTENT": "ALLOW_IDEMPOTENT",
        "REQUIRE_ESTABLISHED": "REQUIRE_ESTABLISHED",
        "REQUIRE_REKEY": "REKEY",
        "REQUIRE_DRAIN": "DRAIN",
    }
    state_disposition = state_dispositions[state_action]
    if state_disposition not in {"ALLOW", "ALLOW_IDEMPOTENT"}:
        return (
            state_disposition,
            state_next,
            probe_timeout,
            hysteresis,
            retry_limit,
            retry_delay,
            reason,
            state_error,
        )

    path_dispositions = {
        "ALLOW_PROBE": "PROBE_PATH",
        "ALLOW_MIGRATE": "MIGRATE_PATH",
        "ALLOW_DRAIN": "DRAIN",
        "REQUIRE_REKEY": "REKEY",
    }
    if path_action in path_dispositions:
        return (
            path_dispositions[path_action],
            path_next,
            probe_timeout,
            hysteresis,
            retry_limit,
            retry_delay,
            reason,
            path_error,
        )
    return (
        state_disposition,
        state_next,
        probe_timeout,
        hysteresis,
        retry_limit,
        retry_delay,
        reason,
        state_error,
    )


def common_helpers(case_type: str) -> list[str]:
    return [
        f"static uint64_t fingerprint_u32(uint64_t value, uint32_t word)",
        "{",
        "\tfor (size_t index = 0U; index < sizeof(word); ++index) {",
        "\t\tvalue ^= (uint8_t)(word >> (index * 8U));",
        f"\t\tvalue *= {FNV1A_PRIME};",
        "\t}",
        "\treturn value;",
        "}",
        "",
        f"static uint64_t fingerprint_case(",
        "\tuint64_t value,",
        f"\tconst struct {case_type} *test_case)",
        "{",
    ]


def render_runtime() -> str:
    lines = [
        "/*",
        " * SPDX-License-Identifier: MIT",
        " *",
        " * Generated by scripts/generate_operation_plan_catalogs.py.",
        " * Do not edit by hand.",
        " */",
        "",
        "#include <errno.h>",
        "",
        "#include <zephyr/sys/util.h>",
        "",
        "#include <pqcp_zephyr/operation_plan_conformance.h>",
        "",
        "static const struct pqcp_runtime_operation_plan_case runtime_plan_catalog[] = {",
    ]
    for scenario in SCENARIOS:
        for state_index, state in enumerate(policy.RUNTIME_STATES):
            for command_index, command in enumerate(policy.RUNTIME_COMMANDS):
                resource, recovery = runtime_context(
                    scenario, state_index, command_index
                )
                (
                    disposition,
                    next_state,
                    concurrency,
                    reservation_ttl,
                    priority_penalty,
                    retry_limit,
                    retry_delay,
                    reason,
                    error,
                ) = runtime_plan(state, resource, recovery, command)
                lines.extend(
                    [
                        "\t{",
                        f"\t\t.scenario = PQCP_OPERATION_PLAN_SCENARIO_{scenario},",
                        "\t\t.context = {",
                        f"\t\t\t.state = PQCP_RUNTIME_POLICY_{state},",
                        f"\t\t\t.resource_condition = PQCP_RUNTIME_RESOURCE_{resource},",
                        f"\t\t\t.recovery_condition = PQCP_RUNTIME_RECOVERY_{recovery},",
                        f"\t\t\t.command = PQCP_RUNTIME_COMMAND_{command},",
                        "\t\t},",
                        f"\t\t.disposition = PQCP_RUNTIME_PLAN_{disposition},",
                        f"\t\t.next_state = PQCP_RUNTIME_POLICY_{next_state},",
                        f"\t\t.maximum_concurrency = {concurrency}U,",
                        f"\t\t.reservation_ttl_ms = {reservation_ttl}U,",
                        f"\t\t.priority_penalty = {priority_penalty}U,",
                        f"\t\t.retry_limit = {retry_limit}U,",
                        f"\t\t.retry_delay_ms = {retry_delay}U,",
                        f"\t\t.reason_mask = {reason}U,",
                        f"\t\t.expected_error = {error},",
                        "\t},",
                    ]
                )
    lines.extend(
        [
            "};",
            "",
            "size_t pqcp_runtime_operation_plan_conformance_count(void)",
            "{",
            "\treturn ARRAY_SIZE(runtime_plan_catalog);",
            "}",
            "",
            "int pqcp_runtime_operation_plan_conformance_get(",
            "\tsize_t index,",
            "\tstruct pqcp_runtime_operation_plan_case *test_case)",
            "{",
            "\tif (index >= ARRAY_SIZE(runtime_plan_catalog) ||",
            "\t    test_case == NULL) {",
            "\t\treturn -EINVAL;",
            "\t}",
            "\t*test_case = runtime_plan_catalog[index];",
            "\ttest_case->schema_version =",
            "\t\tPQCP_OPERATION_PLAN_CONFORMANCE_SCHEMA_VERSION;",
            "\ttest_case->case_id = PQCP_OPERATION_PLAN_CASE_ID(",
            "\t\tPQCP_OPERATION_PLAN_CONFORMANCE_RUNTIME,",
            "\t\ttest_case->scenario, test_case->context.state,",
            "\t\ttest_case->context.command);",
            "\treturn 0;",
            "}",
            "",
            "int pqcp_runtime_operation_plan_conformance_find(",
            "\tenum pqcp_operation_plan_scenario scenario,",
            "\tenum pqcp_runtime_policy_state state,",
            "\tenum pqcp_runtime_command_kind command,",
            "\tstruct pqcp_runtime_operation_plan_case *test_case)",
            "{",
            "\tif (scenario < PQCP_OPERATION_PLAN_SCENARIO_BASELINE ||",
            "\t    scenario >= PQCP_OPERATION_PLAN_SCENARIO_COUNT ||",
            "\t    state < PQCP_RUNTIME_POLICY_UNINITIALIZED ||",
            "\t    state > PQCP_RUNTIME_POLICY_TERMINATED ||",
            "\t    command < PQCP_RUNTIME_COMMAND_NONE ||",
            "\t    command >= PQCP_RUNTIME_COMMAND_KIND_COUNT ||",
            "\t    test_case == NULL) {",
            "\t\treturn -EINVAL;",
            "\t}",
            "\tfor (size_t index = 0U;",
            "\t     index < ARRAY_SIZE(runtime_plan_catalog); ++index) {",
            "\t\tif (runtime_plan_catalog[index].scenario == scenario &&",
            "\t\t    runtime_plan_catalog[index].context.state == state &&",
            "\t\t    runtime_plan_catalog[index].context.command == command) {",
            "\t\t\treturn pqcp_runtime_operation_plan_conformance_get(",
            "\t\t\t\tindex, test_case);",
            "\t\t}",
            "\t}",
            "\treturn -ENOENT;",
            "}",
            "",
        ]
    )
    lines.extend(common_helpers("pqcp_runtime_operation_plan_case"))
    fields = [
        "schema_version",
        "case_id",
        "scenario",
        "context.state",
        "context.resource_condition",
        "context.recovery_condition",
        "context.command",
        "disposition",
        "next_state",
        "maximum_concurrency",
        "reservation_ttl_ms",
        "priority_penalty",
        "retry_limit",
        "retry_delay_ms",
        "reason_mask",
        "expected_error",
    ]
    for field in fields:
        lines.append(
            f"\tvalue = fingerprint_u32(value, (uint32_t)test_case->{field});"
        )
    lines.extend(
        [
            "\treturn value;",
            "}",
            "",
            "int pqcp_runtime_operation_plan_conformance_fingerprint(",
            "\tuint64_t *fingerprint)",
            "{",
            f"\tuint64_t value = {FNV1A_OFFSET_BASIS};",
            "\tstruct pqcp_runtime_operation_plan_case test_case;",
            "",
            "\tif (fingerprint == NULL) {",
            "\t\treturn -EINVAL;",
            "\t}",
            "\tfor (size_t index = 0U;",
            "\t     index < ARRAY_SIZE(runtime_plan_catalog); ++index) {",
            "\t\tint ret = pqcp_runtime_operation_plan_conformance_get(",
            "\t\t\tindex, &test_case);",
            "",
            "\t\tif (ret != 0) {",
            "\t\t\treturn ret;",
            "\t\t}",
            "\t\tvalue = fingerprint_case(value, &test_case);",
            "\t}",
            "\t*fingerprint = value;",
            "\treturn 0;",
            "}",
            "",
            "int pqcp_runtime_operation_plan_conformance_audit(void)",
            "{",
            "\tif (ARRAY_SIZE(runtime_plan_catalog) !=",
            "\t    PQCP_RUNTIME_OPERATION_PLAN_CONFORMANCE_CASES) {",
            "\t\treturn -EBADMSG;",
            "\t}",
            "\tfor (size_t index = 0U;",
            "\t     index < ARRAY_SIZE(runtime_plan_catalog); ++index) {",
            "\t\tstruct pqcp_runtime_operation_plan_case test_case;",
            "\t\tstruct pqcp_runtime_operation_plan actual;",
            "\t\tint ret;",
            "",
            "\t\tret = pqcp_runtime_operation_plan_conformance_get(",
            "\t\t\tindex, &test_case);",
            "\t\tif (ret != 0) {",
            "\t\t\treturn ret;",
            "\t\t}",
            "\t\tret = pqcp_runtime_operation_plan(",
            "\t\t\t&test_case.context, &actual);",
            "\t\tif (ret != 0 ||",
            "\t\t    test_case.schema_version !=",
            "\t\t\t    PQCP_OPERATION_PLAN_CONFORMANCE_SCHEMA_VERSION ||",
            "\t\t    test_case.case_id != PQCP_OPERATION_PLAN_CASE_ID(",
            "\t\t\t    PQCP_OPERATION_PLAN_CONFORMANCE_RUNTIME,",
            "\t\t\t    test_case.scenario, test_case.context.state,",
            "\t\t\t    test_case.context.command) ||",
            "\t\t    actual.disposition != test_case.disposition ||",
            "\t\t    actual.next_state != test_case.next_state ||",
            "\t\t    actual.maximum_concurrency !=",
            "\t\t\t    test_case.maximum_concurrency ||",
            "\t\t    actual.reservation_ttl_ms !=",
            "\t\t\t    test_case.reservation_ttl_ms ||",
            "\t\t    actual.priority_penalty !=",
            "\t\t\t    test_case.priority_penalty ||",
            "\t\t    actual.retry_limit != test_case.retry_limit ||",
            "\t\t    actual.retry_delay_ms !=",
            "\t\t\t    test_case.retry_delay_ms ||",
            "\t\t    actual.reason_mask != test_case.reason_mask ||",
            "\t\t    actual.error != test_case.expected_error) {",
            "\t\t\treturn -EBADMSG;",
            "\t\t}",
            "\t}",
            "\treturn 0;",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def render_channel() -> str:
    lines = [
        "/*",
        " * SPDX-License-Identifier: MIT",
        " *",
        " * Generated by scripts/generate_operation_plan_catalogs.py.",
        " * Do not edit by hand.",
        " */",
        "",
        "#include <errno.h>",
        "",
        "#include <zephyr/sys/util.h>",
        "",
        "#include <pqcp_zephyr/operation_plan_conformance.h>",
        "",
        "static const struct pqcp_channel_operation_plan_case channel_plan_catalog[] = {",
    ]
    for scenario in SCENARIOS:
        for state_index, state in enumerate(policy.CHANNEL_STATES):
            for control_index, control in enumerate(policy.CHANNEL_CONTROLS):
                path, fault = channel_context(
                    scenario, state_index, control_index
                )
                (
                    disposition,
                    next_state,
                    probe_timeout,
                    hysteresis,
                    retry_limit,
                    retry_delay,
                    reason,
                    error,
                ) = channel_plan(state, path, fault, control)
                lines.extend(
                    [
                        "\t{",
                        f"\t\t.scenario = PQCP_OPERATION_PLAN_SCENARIO_{scenario},",
                        "\t\t.context = {",
                        f"\t\t\t.state = PQCP_CHANNEL_POLICY_{state},",
                        f"\t\t\t.path_condition = PQCP_CHANNEL_PATH_CONDITION_{path},",
                        f"\t\t\t.fault_condition = PQCP_CHANNEL_FAULT_{fault},",
                        f"\t\t\t.control = PQCP_CHANNEL_CONTROL_{control},",
                        "\t\t},",
                        f"\t\t.disposition = PQCP_CHANNEL_PLAN_{disposition},",
                        f"\t\t.next_state = PQCP_CHANNEL_POLICY_{next_state},",
                        f"\t\t.probe_timeout_ms = {probe_timeout}U,",
                        f"\t\t.migration_hysteresis_bps = {hysteresis}U,",
                        f"\t\t.retry_limit = {retry_limit}U,",
                        f"\t\t.retry_delay_ms = {retry_delay}U,",
                        f"\t\t.reason_mask = {reason}U,",
                        f"\t\t.expected_error = {error},",
                        "\t},",
                    ]
                )
    lines.extend(
        [
            "};",
            "",
            "size_t pqcp_channel_operation_plan_conformance_count(void)",
            "{",
            "\treturn ARRAY_SIZE(channel_plan_catalog);",
            "}",
            "",
            "int pqcp_channel_operation_plan_conformance_get(",
            "\tsize_t index,",
            "\tstruct pqcp_channel_operation_plan_case *test_case)",
            "{",
            "\tif (index >= ARRAY_SIZE(channel_plan_catalog) ||",
            "\t    test_case == NULL) {",
            "\t\treturn -EINVAL;",
            "\t}",
            "\t*test_case = channel_plan_catalog[index];",
            "\ttest_case->schema_version =",
            "\t\tPQCP_OPERATION_PLAN_CONFORMANCE_SCHEMA_VERSION;",
            "\ttest_case->case_id = PQCP_OPERATION_PLAN_CASE_ID(",
            "\t\tPQCP_OPERATION_PLAN_CONFORMANCE_CHANNEL,",
            "\t\ttest_case->scenario, test_case->context.state,",
            "\t\ttest_case->context.control);",
            "\treturn 0;",
            "}",
            "",
            "int pqcp_channel_operation_plan_conformance_find(",
            "\tenum pqcp_operation_plan_scenario scenario,",
            "\tenum pqcp_channel_policy_state state,",
            "\tenum pqcp_channel_control_kind control,",
            "\tstruct pqcp_channel_operation_plan_case *test_case)",
            "{",
            "\tif (scenario < PQCP_OPERATION_PLAN_SCENARIO_BASELINE ||",
            "\t    scenario >= PQCP_OPERATION_PLAN_SCENARIO_COUNT ||",
            "\t    state < PQCP_CHANNEL_POLICY_NEW ||",
            "\t    state > PQCP_CHANNEL_POLICY_TERMINATED ||",
            "\t    control < PQCP_CHANNEL_CONTROL_NONE ||",
            "\t    control >= PQCP_CHANNEL_CONTROL_KIND_COUNT ||",
            "\t    test_case == NULL) {",
            "\t\treturn -EINVAL;",
            "\t}",
            "\tfor (size_t index = 0U;",
            "\t     index < ARRAY_SIZE(channel_plan_catalog); ++index) {",
            "\t\tif (channel_plan_catalog[index].scenario == scenario &&",
            "\t\t    channel_plan_catalog[index].context.state == state &&",
            "\t\t    channel_plan_catalog[index].context.control == control) {",
            "\t\t\treturn pqcp_channel_operation_plan_conformance_get(",
            "\t\t\t\tindex, test_case);",
            "\t\t}",
            "\t}",
            "\treturn -ENOENT;",
            "}",
            "",
        ]
    )
    lines.extend(common_helpers("pqcp_channel_operation_plan_case"))
    fields = [
        "schema_version",
        "case_id",
        "scenario",
        "context.state",
        "context.path_condition",
        "context.fault_condition",
        "context.control",
        "disposition",
        "next_state",
        "probe_timeout_ms",
        "migration_hysteresis_bps",
        "retry_limit",
        "retry_delay_ms",
        "reason_mask",
        "expected_error",
    ]
    for field in fields:
        lines.append(
            f"\tvalue = fingerprint_u32(value, (uint32_t)test_case->{field});"
        )
    lines.extend(
        [
            "\treturn value;",
            "}",
            "",
            "int pqcp_channel_operation_plan_conformance_fingerprint(",
            "\tuint64_t *fingerprint)",
            "{",
            f"\tuint64_t value = {FNV1A_OFFSET_BASIS};",
            "\tstruct pqcp_channel_operation_plan_case test_case;",
            "",
            "\tif (fingerprint == NULL) {",
            "\t\treturn -EINVAL;",
            "\t}",
            "\tfor (size_t index = 0U;",
            "\t     index < ARRAY_SIZE(channel_plan_catalog); ++index) {",
            "\t\tint ret = pqcp_channel_operation_plan_conformance_get(",
            "\t\t\tindex, &test_case);",
            "",
            "\t\tif (ret != 0) {",
            "\t\t\treturn ret;",
            "\t\t}",
            "\t\tvalue = fingerprint_case(value, &test_case);",
            "\t}",
            "\t*fingerprint = value;",
            "\treturn 0;",
            "}",
            "",
            "int pqcp_channel_operation_plan_conformance_audit(void)",
            "{",
            "\tif (ARRAY_SIZE(channel_plan_catalog) !=",
            "\t    PQCP_CHANNEL_OPERATION_PLAN_CONFORMANCE_CASES) {",
            "\t\treturn -EBADMSG;",
            "\t}",
            "\tfor (size_t index = 0U;",
            "\t     index < ARRAY_SIZE(channel_plan_catalog); ++index) {",
            "\t\tstruct pqcp_channel_operation_plan_case test_case;",
            "\t\tstruct pqcp_channel_operation_plan actual;",
            "\t\tint ret;",
            "",
            "\t\tret = pqcp_channel_operation_plan_conformance_get(",
            "\t\t\tindex, &test_case);",
            "\t\tif (ret != 0) {",
            "\t\t\treturn ret;",
            "\t\t}",
            "\t\tret = pqcp_channel_operation_plan(",
            "\t\t\t&test_case.context, &actual);",
            "\t\tif (ret != 0 ||",
            "\t\t    test_case.schema_version !=",
            "\t\t\t    PQCP_OPERATION_PLAN_CONFORMANCE_SCHEMA_VERSION ||",
            "\t\t    test_case.case_id != PQCP_OPERATION_PLAN_CASE_ID(",
            "\t\t\t    PQCP_OPERATION_PLAN_CONFORMANCE_CHANNEL,",
            "\t\t\t    test_case.scenario, test_case.context.state,",
            "\t\t\t    test_case.context.control) ||",
            "\t\t    actual.disposition != test_case.disposition ||",
            "\t\t    actual.next_state != test_case.next_state ||",
            "\t\t    actual.probe_timeout_ms !=",
            "\t\t\t    test_case.probe_timeout_ms ||",
            "\t\t    actual.migration_hysteresis_bps !=",
            "\t\t\t    test_case.migration_hysteresis_bps ||",
            "\t\t    actual.retry_limit != test_case.retry_limit ||",
            "\t\t    actual.retry_delay_ms !=",
            "\t\t\t    test_case.retry_delay_ms ||",
            "\t\t    actual.reason_mask != test_case.reason_mask ||",
            "\t\t    actual.error != test_case.expected_error) {",
            "\t\t\treturn -EBADMSG;",
            "\t\t}",
            "\t}",
            "\treturn 0;",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def update_file(path: Path, content: str, check: bool) -> bool:
    rendered = content.rstrip() + "\n"
    current = path.read_text(encoding="utf-8") if path.exists() else None
    if current == rendered:
        return True
    if check:
        print(f"out of date: {path}")
        return False
    path.write_text(rendered, encoding="utf-8")
    print(f"wrote {path}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    args = parser.parse_args()
    root = args.repo_root.resolve()
    results = [
        update_file(
            root / "src/runtime_operation_plan_conformance_catalog.c",
            render_runtime(),
            args.check,
        ),
        update_file(
            root / "src/protected_channel_operation_plan_conformance_catalog.c",
            render_channel(),
            args.check,
        ),
    ]
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
