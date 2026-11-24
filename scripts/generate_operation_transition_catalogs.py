#!/usr/bin/env python3
"""Generate stateful runtime and protected-channel transition witnesses."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import generate_runtime_channel_policy_catalogs as policy
import generate_operation_plan_catalogs as planner


SCHEMA_VERSION = 1
STEPS_PER_TRACE = 8
SEQUENCES_PER_STATE = 32
FNV1A_OFFSET_BASIS = 14695981039346656037
FNV1A_PRIME = 1099511628211

# Keep fingerprints independent of the host Python errno table. These are the
# errno values used by the Zephyr SDK/newlib ABI that compiles the catalogs.
ZEPHYR_ERRNO_VALUES = {
    "EIO": 5,
    "EAGAIN": 11,
    "EACCES": 13,
    "EBUSY": 16,
    "EINVAL": 22,
    "EROFS": 30,
    "EPROTO": 71,
    "EBADMSG": 77,
    "ECONNRESET": 104,
    "ENOBUFS": 105,
    "ESHUTDOWN": 110,
    "ETIMEDOUT": 116,
    "EHOSTUNREACH": 118,
    "EALREADY": 120,
    "ENOTCONN": 128,
    "EDQUOT": 132,
    "ESTALE": 133,
    "ENOTRECOVERABLE": 141,
    "EKEYREJECTED": 147,
}

RUNTIME_ACTIONS = [
    "DENY",
    "ALLOW",
    "ALLOW_IDEMPOTENT",
    "ALLOW_READ_ONLY",
    "REQUIRE_DRAIN",
    "REQUIRE_MAINTENANCE",
    "REQUIRE_RECOVERY",
]
RUNTIME_RESOURCE_DISPOSITIONS = [
    "DENY",
    "ALLOW",
    "ALLOW_THROTTLED",
    "ALLOW_RECLAIM",
    "REQUIRE_CHECKPOINT",
    "REQUIRE_RECOVERY",
]
RUNTIME_RECOVERY_DIRECTIVES = [
    "IGNORE",
    "OBSERVE",
    "RETRY",
    "BACKOFF",
    "DRAIN",
    "CHECKPOINT",
    "ROLLBACK",
    "ROTATE_KEYS",
    "LOCK_DOWN",
    "RESTART",
    "TERMINATE",
]
CHANNEL_ACTIONS = [
    "DENY",
    "ALLOW",
    "ALLOW_IDEMPOTENT",
    "REQUIRE_ESTABLISHED",
    "REQUIRE_REKEY",
    "REQUIRE_DRAIN",
    "CLOSE_ON_FAILURE",
]
CHANNEL_PATH_DISPOSITIONS = [
    "DENY",
    "ALLOW",
    "ALLOW_PROBE",
    "ALLOW_MIGRATE",
    "ALLOW_DRAIN",
    "REQUIRE_REKEY",
    "CLOSE",
]
CHANNEL_FAULT_DIRECTIVES = [
    "IGNORE",
    "OBSERVE",
    "RETRY",
    "BACKOFF",
    "RESET_STREAM",
    "REKEY_CHANNEL",
    "MIGRATE_PATH",
    "DRAIN_CHANNEL",
    "CLOSE_CHANNEL",
    "TERMINATE_CHANNEL",
]


@dataclass(frozen=True)
class RuntimeStep:
    resource_condition: str
    recovery_condition: str
    command: str
    action: str
    disposition: str
    directive: str
    next_state: str
    error: str
    permitted: bool


@dataclass(frozen=True)
class ChannelStep:
    path_condition: str
    fault_condition: str
    control: str
    action: str
    disposition: str
    directive: str
    next_state: str
    error: str
    permitted: bool


def error_value(token: str) -> int:
    if token == "0":
        return 0
    if not token.startswith("-E"):
        raise ValueError(f"unsupported errno token: {token}")
    name = token[1:]
    if name not in ZEPHYR_ERRNO_VALUES:
        raise ValueError(f"unsupported Zephyr errno token: {token}")
    return -ZEPHYR_ERRNO_VALUES[name]


def error_token(value: int) -> str:
    if value == 0:
        return "0"
    for name, number in ZEPHYR_ERRNO_VALUES.items():
        if -number == value:
            return f"-{name}"
    raise ValueError(f"unsupported errno value: {value}")


def fingerprint_u32(fingerprint: int, value: int) -> int:
    value &= 0xFFFFFFFF
    for index in range(4):
        fingerprint ^= (value >> (index * 8)) & 0xFF
        fingerprint = (fingerprint * FNV1A_PRIME) & 0xFFFFFFFFFFFFFFFF
    return fingerprint


def trace_id(domain: int, initial_state: int, sequence: int) -> int:
    return (
        ((domain & 0xFF) << 24)
        | ((initial_state & 0xFF) << 16)
        | (sequence & 0xFFFF)
    )


def operation_index(
    initial_state: int,
    sequence: int,
    step: int,
    count: int,
) -> int:
    stride = 2 * (sequence % 8) + 1
    return (initial_state + sequence + step * stride) % count


def condition_index(
    initial_state: int,
    sequence: int,
    step: int,
    multiplier: int,
    count: int,
) -> int:
    return (
        initial_state * multiplier
        + sequence * (multiplier + 2)
        + step * (multiplier + 4)
    ) % count


def runtime_step(
    state: str,
    resource_condition: str,
    recovery_condition: str,
    command: str,
) -> RuntimeStep:
    action, policy_state, policy_error, _ = policy.runtime_decision(
        state, command
    )
    (
        disposition,
        _,
        _,
        _,
        _,
        resource_error,
    ) = policy.runtime_resource_decision(resource_condition, command)
    (
        directive,
        recovery_state,
        _,
        _,
        _,
        recovery_error,
    ) = policy.runtime_recovery_decision(recovery_condition, command)

    (
        plan_disposition,
        next_state,
        _,
        _,
        _,
        _,
        _,
        _,
        plan_error,
    ) = planner.runtime_plan(
        state,
        resource_condition,
        recovery_condition,
        command,
    )
    result_error = error_value(plan_error)
    permitted = (
        plan_disposition not in {"DENY", "LOCKDOWN", "TERMINATE"}
        and result_error == 0
    )

    return RuntimeStep(
        resource_condition=resource_condition,
        recovery_condition=recovery_condition,
        command=command,
        action=action,
        disposition=disposition,
        directive=directive,
        next_state=next_state,
        error=error_token(result_error),
        permitted=permitted,
    )


def channel_step(
    state: str,
    path_condition: str,
    fault_condition: str,
    control: str,
) -> ChannelStep:
    action, policy_state, policy_error, _ = policy.channel_decision(
        state, control
    )
    (
        disposition,
        _,
        _,
        _,
        path_state,
        path_error,
    ) = policy.channel_path_decision(path_condition, control)
    (
        directive,
        fault_state,
        _,
        _,
        _,
        fault_error,
    ) = policy.channel_fault_decision(fault_condition, control)

    (
        plan_disposition,
        next_state,
        _,
        _,
        _,
        _,
        _,
        plan_error,
    ) = planner.channel_plan(
        state,
        path_condition,
        fault_condition,
        control,
    )
    result_error = error_value(plan_error)
    permitted = (
        plan_disposition not in {"DENY", "CLOSE", "TERMINATE"}
        and result_error == 0
    )

    return ChannelStep(
        path_condition=path_condition,
        fault_condition=fault_condition,
        control=control,
        action=action,
        disposition=disposition,
        directive=directive,
        next_state=next_state,
        error=error_token(result_error),
        permitted=permitted,
    )


def runtime_trace_fingerprint(
    identifier: int,
    initial_state: str,
    steps: list[RuntimeStep],
) -> int:
    fingerprint = FNV1A_OFFSET_BASIS
    fingerprint = fingerprint_u32(fingerprint, SCHEMA_VERSION)
    fingerprint = fingerprint_u32(fingerprint, identifier)
    fingerprint = fingerprint_u32(
        fingerprint, policy.RUNTIME_STATES.index(initial_state)
    )
    for step in steps:
        values = [
            policy.RUNTIME_RESOURCE_CONDITIONS.index(
                step.resource_condition
            ),
            policy.RUNTIME_RECOVERY_CONDITIONS.index(
                step.recovery_condition
            ),
            policy.RUNTIME_COMMANDS.index(step.command),
            RUNTIME_ACTIONS.index(step.action),
            RUNTIME_RESOURCE_DISPOSITIONS.index(step.disposition),
            RUNTIME_RECOVERY_DIRECTIVES.index(step.directive),
            policy.RUNTIME_STATES.index(step.next_state),
            error_value(step.error),
            int(step.permitted),
        ]
        for value in values:
            fingerprint = fingerprint_u32(fingerprint, value)
    return fingerprint


def channel_trace_fingerprint(
    identifier: int,
    initial_state: str,
    steps: list[ChannelStep],
) -> int:
    fingerprint = FNV1A_OFFSET_BASIS
    fingerprint = fingerprint_u32(fingerprint, SCHEMA_VERSION)
    fingerprint = fingerprint_u32(fingerprint, identifier)
    fingerprint = fingerprint_u32(
        fingerprint, policy.CHANNEL_STATES.index(initial_state)
    )
    for step in steps:
        values = [
            policy.CHANNEL_PATH_CONDITIONS.index(step.path_condition),
            policy.CHANNEL_FAULT_CONDITIONS.index(step.fault_condition),
            policy.CHANNEL_CONTROLS.index(step.control),
            CHANNEL_ACTIONS.index(step.action),
            CHANNEL_PATH_DISPOSITIONS.index(step.disposition),
            CHANNEL_FAULT_DIRECTIVES.index(step.directive),
            policy.CHANNEL_STATES.index(step.next_state),
            error_value(step.error),
            int(step.permitted),
        ]
        for value in values:
            fingerprint = fingerprint_u32(fingerprint, value)
    return fingerprint


def runtime_traces() -> list[tuple[int, str, list[RuntimeStep], int]]:
    traces = []
    for state_index, initial_state in enumerate(policy.RUNTIME_STATES):
        for sequence in range(SEQUENCES_PER_STATE):
            current_state = initial_state
            steps = []
            for step_index in range(STEPS_PER_TRACE):
                command = policy.RUNTIME_COMMANDS[
                    operation_index(
                        state_index,
                        sequence,
                        step_index,
                        len(policy.RUNTIME_COMMANDS),
                    )
                ]
                resource_condition = policy.RUNTIME_RESOURCE_CONDITIONS[
                    condition_index(
                        state_index,
                        sequence,
                        step_index,
                        3,
                        len(policy.RUNTIME_RESOURCE_CONDITIONS),
                    )
                ]
                recovery_condition = policy.RUNTIME_RECOVERY_CONDITIONS[
                    condition_index(
                        state_index,
                        sequence,
                        step_index,
                        5,
                        len(policy.RUNTIME_RECOVERY_CONDITIONS),
                    )
                ]
                generated = runtime_step(
                    current_state,
                    resource_condition,
                    recovery_condition,
                    command,
                )
                steps.append(generated)
                current_state = generated.next_state
            identifier = trace_id(0, state_index, sequence)
            traces.append(
                (
                    identifier,
                    initial_state,
                    steps,
                    runtime_trace_fingerprint(
                        identifier, initial_state, steps
                    ),
                )
            )
    return traces


def channel_traces() -> list[tuple[int, str, list[ChannelStep], int]]:
    traces = []
    for state_index, initial_state in enumerate(policy.CHANNEL_STATES):
        for sequence in range(SEQUENCES_PER_STATE):
            current_state = initial_state
            steps = []
            for step_index in range(STEPS_PER_TRACE):
                control = policy.CHANNEL_CONTROLS[
                    operation_index(
                        state_index,
                        sequence,
                        step_index,
                        len(policy.CHANNEL_CONTROLS),
                    )
                ]
                path_condition = policy.CHANNEL_PATH_CONDITIONS[
                    condition_index(
                        state_index,
                        sequence,
                        step_index,
                        7,
                        len(policy.CHANNEL_PATH_CONDITIONS),
                    )
                ]
                fault_condition = policy.CHANNEL_FAULT_CONDITIONS[
                    condition_index(
                        state_index,
                        sequence,
                        step_index,
                        9,
                        len(policy.CHANNEL_FAULT_CONDITIONS),
                    )
                ]
                generated = channel_step(
                    current_state,
                    path_condition,
                    fault_condition,
                    control,
                )
                steps.append(generated)
                current_state = generated.next_state
            identifier = trace_id(1, state_index, sequence)
            traces.append(
                (
                    identifier,
                    initial_state,
                    steps,
                    channel_trace_fingerprint(
                        identifier, initial_state, steps
                    ),
                )
            )
    return traces


def render_runtime() -> str:
    lines = [
        "/*",
        " * SPDX-License-Identifier: MIT",
        " *",
        " * Generated by scripts/generate_operation_transition_catalogs.py.",
        " * Do not edit by hand.",
        " */",
        "",
        "#include <errno.h>",
        "#include <string.h>",
        "",
        "#include <zephyr/sys/util.h>",
        "",
        '#include "operation_transition_internal.h"',
        "",
        f"#define TRANSITION_SEQUENCES_PER_STATE {SEQUENCES_PER_STATE}U",
        "",
        "static const uint64_t runtime_transition_fingerprints[] = {",
    ]
    for _, _, _, fingerprint in runtime_traces():
        lines.append(f"\tUINT64_C(0x{fingerprint:016x}),")
    lines.extend(
        [
            "};",
            "",
            "static size_t operation_index(",
            "\tsize_t initial_state, size_t sequence, size_t step,",
            "\tsize_t count)",
            "{",
            "\tsize_t stride = 2U * (sequence % 8U) + 1U;",
            "",
            "\treturn (initial_state + sequence + step * stride) % count;",
            "}",
            "",
            "static size_t condition_index(",
            "\tsize_t initial_state, size_t sequence, size_t step,",
            "\tsize_t multiplier, size_t count)",
            "{",
            "\treturn (initial_state * multiplier +",
            "\t\tsequence * (multiplier + 2U) +",
            "\t\tstep * (multiplier + 4U)) % count;",
            "}",
            "",
            "size_t pqcp_runtime_transition_catalog_count(void)",
            "{",
            "\treturn ARRAY_SIZE(runtime_transition_fingerprints);",
            "}",
            "",
            "int pqcp_runtime_transition_catalog_get(",
            "\tsize_t index,",
            "\tstruct pqcp_runtime_transition_trace *trace)",
            "{",
            "\tsize_t initial_state;",
            "\tsize_t sequence;",
            "",
            "\tif (index >= ARRAY_SIZE(runtime_transition_fingerprints) ||",
            "\t    trace == NULL) {",
            "\t\treturn -EINVAL;",
            "\t}",
            "\tinitial_state =",
            "\t\tindex / TRANSITION_SEQUENCES_PER_STATE;",
            "\tsequence = index % TRANSITION_SEQUENCES_PER_STATE;",
            "\tmemset(trace, 0, sizeof(*trace));",
            "\ttrace->schema_version =",
            "\t\tPQCP_OPERATION_TRANSITION_SCHEMA_VERSION;",
            "\ttrace->trace_id =",
            "\t\tPQCP_OPERATION_TRANSITION_TRACE_ID(",
            "\t\t\tPQCP_OPERATION_TRANSITION_RUNTIME,",
            "\t\t\tinitial_state, sequence);",
            "\ttrace->initial_state =",
            "\t\t(enum pqcp_runtime_policy_state)initial_state;",
            "\ttrace->step_count =",
            "\t\tPQCP_OPERATION_TRANSITION_STEPS_PER_TRACE;",
            "\tfor (size_t step = 0U;",
            "\t     step < trace->step_count; ++step) {",
            "\t\ttrace->steps[step].command =",
            "\t\t\t(enum pqcp_runtime_command_kind)",
            "\t\t\t\toperation_index(",
            "\t\t\t\t\tinitial_state, sequence, step,",
            "\t\t\t\t\tPQCP_RUNTIME_POLICY_COMMAND_COUNT);",
            "\t\ttrace->steps[step].resource_condition =",
            "\t\t\t(enum pqcp_runtime_resource_condition)",
            "\t\t\t\tcondition_index(",
            "\t\t\t\t\tinitial_state, sequence, step, 3U,",
            "\t\t\t\t\tPQCP_RUNTIME_RESOURCE_CONDITION_COUNT);",
            "\t\ttrace->steps[step].recovery_condition =",
            "\t\t\t(enum pqcp_runtime_recovery_condition)",
            "\t\t\t\tcondition_index(",
            "\t\t\t\t\tinitial_state, sequence, step, 5U,",
            "\t\t\t\t\tPQCP_RUNTIME_RECOVERY_CONDITION_COUNT);",
            "\t}",
            "\ttrace->expected_fingerprint =",
            "\t\truntime_transition_fingerprints[index];",
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
        " * Generated by scripts/generate_operation_transition_catalogs.py.",
        " * Do not edit by hand.",
        " */",
        "",
        "#include <errno.h>",
        "#include <string.h>",
        "",
        "#include <zephyr/sys/util.h>",
        "",
        '#include "operation_transition_internal.h"',
        "",
        f"#define TRANSITION_SEQUENCES_PER_STATE {SEQUENCES_PER_STATE}U",
        "",
        "static const uint64_t channel_transition_fingerprints[] = {",
    ]
    for _, _, _, fingerprint in channel_traces():
        lines.append(f"\tUINT64_C(0x{fingerprint:016x}),")
    lines.extend(
        [
            "};",
            "",
            "static size_t operation_index(",
            "\tsize_t initial_state, size_t sequence, size_t step,",
            "\tsize_t count)",
            "{",
            "\tsize_t stride = 2U * (sequence % 8U) + 1U;",
            "",
            "\treturn (initial_state + sequence + step * stride) % count;",
            "}",
            "",
            "static size_t condition_index(",
            "\tsize_t initial_state, size_t sequence, size_t step,",
            "\tsize_t multiplier, size_t count)",
            "{",
            "\treturn (initial_state * multiplier +",
            "\t\tsequence * (multiplier + 2U) +",
            "\t\tstep * (multiplier + 4U)) % count;",
            "}",
            "",
            "size_t pqcp_channel_transition_catalog_count(void)",
            "{",
            "\treturn ARRAY_SIZE(channel_transition_fingerprints);",
            "}",
            "",
            "int pqcp_channel_transition_catalog_get(",
            "\tsize_t index,",
            "\tstruct pqcp_channel_transition_trace *trace)",
            "{",
            "\tsize_t initial_state;",
            "\tsize_t sequence;",
            "",
            "\tif (index >= ARRAY_SIZE(channel_transition_fingerprints) ||",
            "\t    trace == NULL) {",
            "\t\treturn -EINVAL;",
            "\t}",
            "\tinitial_state =",
            "\t\tindex / TRANSITION_SEQUENCES_PER_STATE;",
            "\tsequence = index % TRANSITION_SEQUENCES_PER_STATE;",
            "\tmemset(trace, 0, sizeof(*trace));",
            "\ttrace->schema_version =",
            "\t\tPQCP_OPERATION_TRANSITION_SCHEMA_VERSION;",
            "\ttrace->trace_id =",
            "\t\tPQCP_OPERATION_TRANSITION_TRACE_ID(",
            "\t\t\tPQCP_OPERATION_TRANSITION_CHANNEL,",
            "\t\t\tinitial_state, sequence);",
            "\ttrace->initial_state =",
            "\t\t(enum pqcp_channel_policy_state)initial_state;",
            "\ttrace->step_count =",
            "\t\tPQCP_OPERATION_TRANSITION_STEPS_PER_TRACE;",
            "\tfor (size_t step = 0U;",
            "\t     step < trace->step_count; ++step) {",
            "\t\ttrace->steps[step].control =",
            "\t\t\t(enum pqcp_channel_control_kind)",
            "\t\t\t\toperation_index(",
            "\t\t\t\t\tinitial_state, sequence, step,",
            "\t\t\t\t\tPQCP_CHANNEL_POLICY_CONTROL_COUNT);",
            "\t\ttrace->steps[step].path_condition =",
            "\t\t\t(enum pqcp_channel_path_condition)",
            "\t\t\t\tcondition_index(",
            "\t\t\t\t\tinitial_state, sequence, step, 7U,",
            "\t\t\t\t\tPQCP_CHANNEL_PATH_CONDITION_COUNT);",
            "\t\ttrace->steps[step].fault_condition =",
            "\t\t\t(enum pqcp_channel_fault_condition)",
            "\t\t\t\tcondition_index(",
            "\t\t\t\t\tinitial_state, sequence, step, 9U,",
            "\t\t\t\t\tPQCP_CHANNEL_FAULT_CONDITION_COUNT);",
            "\t}",
            "\ttrace->expected_fingerprint =",
            "\t\tchannel_transition_fingerprints[index];",
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

    outputs = {
        out_dir / "runtime_transition_conformance_catalog.c": render_runtime(),
        out_dir / "protected_channel_transition_conformance_catalog.c": render_channel(),
    }
    mismatches = []
    for output, content in outputs.items():
        if args.check:
            if not output.exists() or output.read_text() != content:
                mismatches.append(str(output))
        else:
            output.write_text(content)
    if mismatches:
        for mismatch in mismatches:
            print(f"stale generated transition catalog: {mismatch}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
