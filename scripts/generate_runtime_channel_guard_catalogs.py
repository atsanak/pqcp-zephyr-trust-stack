#!/usr/bin/env python3
"""Generate exhaustive runtime and protected-channel guard catalogs."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import generate_runtime_channel_policy_catalogs as base


RUNTIME_AUTHORIZATION_CONDITIONS = [
    "ANONYMOUS",
    "AUTHENTICATED",
    "OPERATOR",
    "SECURITY_OFFICER",
    "AUDITOR",
    "AUTOMATION",
    "BREAK_GLASS",
    "TOKEN_EXPIRED",
    "TOKEN_REVOKED",
    "TENANT_MISMATCH",
    "OWNER_MISMATCH",
    "REPLAY_SUSPECTED",
    "CLOCK_UNTRUSTED",
    "POLICY_STALE",
    "QUARANTINED",
    "TERMINATED",
]

RUNTIME_CONTINUITY_CONDITIONS = [
    "HEALTHY",
    "REPLICA_LAGGING",
    "CHECKPOINT_STALE",
    "CHECKPOINT_MISSING",
    "EVENT_CHAIN_STALE",
    "EVENT_CHAIN_INVALID",
    "KEY_STORE_DEGRADED",
    "IDENTITY_DEGRADED",
    "WORKSPACE_PRESSURE",
    "QUEUE_SATURATED",
    "CLOCK_ROLLBACK",
    "EPOCH_DIVERGED",
    "PARTITIONED",
    "FAILOVER_ACTIVE",
    "READ_ONLY",
    "TERMINATED",
]

CHANNEL_EPOCH_CONDITIONS = [
    "CURRENT",
    "ROTATION_DUE",
    "ROTATION_OVERDUE",
    "PREPARED_LOCAL",
    "PREPARED_PEER",
    "ACCEPTED",
    "COMMITTING",
    "PEER_AHEAD",
    "PEER_BEHIND",
    "CONFIRMATION_INVALID",
    "SECRET_EXHAUSTED",
    "EXPORTER_CHANGED",
    "TICKET_STALE",
    "REPLAY_SUSPECTED",
    "LOCKED",
    "TERMINATED",
]

CHANNEL_STREAM_CONDITIONS = [
    "IDLE",
    "OPENING_LOCAL",
    "OPENING_PEER",
    "OPEN",
    "HALF_CLOSED_LOCAL",
    "HALF_CLOSED_PEER",
    "DRAINING",
    "RESET_LOCAL",
    "RESET_PEER",
    "FLOW_BLOCKED_LOCAL",
    "FLOW_BLOCKED_PEER",
    "SEQUENCE_GAP",
    "SEQUENCE_REPLAY",
    "CONNECTION_DRAINING",
    "CLOSED",
    "TERMINATED",
]


Decision = tuple[str, ...]


def runtime_authorization_decision(
    condition: str,
    command: str,
) -> Decision:
    read_only = {
        "AUDIT",
        "BUILD_EVIDENCE",
        "READ_HEALTH",
        "READ_SNAPSHOT",
    }
    operator_work = {
        "START",
        "STOP",
        "TICK",
        "SELFTEST",
        "OPEN_SESSION",
        "CLOSE_SESSION",
        "DRAIN_SESSION",
        "SUBMIT_JOB",
        "CANCEL_JOB",
        "BEGIN_TRANSACTION",
        "COMMIT_TRANSACTION",
        "ROLLBACK_TRANSACTION",
        "BEGIN_MIGRATION",
        "PROMOTE_MIGRATION",
        "ROLLBACK_MIGRATION",
        "ISSUE_LEASE",
        "REVOKE_LEASE",
        "RECONCILE_LEASES",
        "RUN_CAMPAIGN",
    }
    security_work = {
        "LOCKDOWN",
        "RECOVER",
        "ROTATE_KEYS",
        "EXPIRE_KEYS",
        "ROTATE_IDENTITIES",
        "TRANSITION_PROFILE",
        "WRITE_CHECKPOINT",
        "RESTORE_CHECKPOINT",
    }

    if command == "NONE":
        return "DENY", "0", "4", "1", "-EINVAL"
    if condition == "TERMINATED":
        return "DENY", "0", "5", "2", "-ESHUTDOWN"
    if condition == "BREAK_GLASS":
        return "ALLOW", "4", "5", "4", "0"
    if condition == "SECURITY_OFFICER":
        audit = "4" if command in security_work else "3"
        return "ALLOW", "3", audit, "8", "0"
    if condition == "OPERATOR":
        if command in security_work:
            return "REQUIRE_SECURITY_OFFICER", "3", "4", "16", "-EACCES"
        disposition = "ALLOW_READ_ONLY" if command in read_only else "ALLOW"
        return disposition, "2", "2", "32", "0"
    if condition == "AUDITOR":
        if command in read_only:
            return "ALLOW_READ_ONLY", "2", "3", "64", "0"
        return "DENY", "2", "4", "128", "-EACCES"
    if condition == "AUTOMATION":
        if command in read_only:
            return "ALLOW_READ_ONLY", "2", "2", "256", "0"
        if command in operator_work:
            return "ALLOW", "2", "3", "512", "0"
        return "REQUIRE_SECURITY_OFFICER", "3", "4", "1024", "-EACCES"
    if condition == "AUTHENTICATED":
        if command in read_only:
            return "ALLOW_READ_ONLY", "1", "2", "2048", "0"
        return "REQUIRE_OPERATOR", "2", "3", "4096", "-EACCES"
    if condition == "ANONYMOUS":
        if command == "READ_HEALTH":
            return "ALLOW_READ_ONLY", "0", "2", "8192", "0"
        return "REQUIRE_FRESH_TOKEN", "1", "3", "16384", "-EACCES"
    if condition in {"TOKEN_EXPIRED", "TOKEN_REVOKED"}:
        return "REQUIRE_FRESH_TOKEN", "1", "4", "32768", "-EKEYREJECTED"
    if condition in {"TENANT_MISMATCH", "OWNER_MISMATCH"}:
        return "DENY", "2", "4", "65536", "-EACCES"
    if condition in {"REPLAY_SUSPECTED", "QUARANTINED"}:
        return "QUARANTINE", "4", "5", "131072", "-EACCES"
    if condition in {"CLOCK_UNTRUSTED", "POLICY_STALE"}:
        if command in read_only:
            return "ALLOW_READ_ONLY", "2", "4", "262144", "0"
        if command in {"LOCKDOWN", "RECOVER"}:
            return "REQUIRE_BREAK_GLASS", "4", "5", "524288", "-EAGAIN"
        return "DENY", "3", "4", "1048576", "-EAGAIN"
    return "DENY", "0", "5", "2097152", "-EACCES"


def runtime_continuity_decision(
    condition: str,
    command: str,
) -> Decision:
    read_only = {
        "AUDIT",
        "BUILD_EVIDENCE",
        "READ_HEALTH",
        "READ_SNAPSHOT",
    }
    release_work = {
        "STOP",
        "CLOSE_SESSION",
        "DRAIN_SESSION",
        "CANCEL_JOB",
        "EXPIRE_KEYS",
        "ROLLBACK_TRANSACTION",
        "ROLLBACK_MIGRATION",
        "REVOKE_LEASE",
    }
    recovery_work = {
        "LOCKDOWN",
        "RECOVER",
        "WRITE_CHECKPOINT",
        "RESTORE_CHECKPOINT",
        "RECONCILE_LEASES",
    }
    allocating_work = {
        "START",
        "OPEN_SESSION",
        "SUBMIT_JOB",
        "BEGIN_TRANSACTION",
        "BEGIN_MIGRATION",
        "ISSUE_LEASE",
        "RUN_CAMPAIGN",
    }

    if command == "NONE":
        return "DENY", "FAILED", "0", "1", "-EINVAL"
    if condition == "TERMINATED":
        return "TERMINATE", "TERMINATED", "0", "2", "-ESHUTDOWN"
    if condition == "HEALTHY":
        return "ALLOW", "RUNNING", "0", "4", "0"
    if command in read_only:
        state = "LOCKDOWN" if condition in {
            "EVENT_CHAIN_INVALID",
            "CLOCK_ROLLBACK",
            "EPOCH_DIVERGED",
        } else "DEGRADED"
        return "ALLOW_READ_ONLY", state, "0", "8", "0"
    if condition in {"EVENT_CHAIN_INVALID", "CLOCK_ROLLBACK", "EPOCH_DIVERGED"}:
        if command in recovery_work:
            return "RECONCILE", "RECOVERING", "0", "16", "0"
        return "LOCK_DOWN", "LOCKDOWN", "0", "32", "-EBADMSG"
    if condition in {"CHECKPOINT_STALE", "CHECKPOINT_MISSING"}:
        if command in {"WRITE_CHECKPOINT", "RESTORE_CHECKPOINT"}:
            return "CHECKPOINT", "CHECKPOINTING", "0", "64", "0"
        if command in release_work:
            return "ALLOW", "DEGRADED", "0", "128", "0"
        return "DEFER", "DEGRADED", "250", "256", "-EAGAIN"
    if condition in {"KEY_STORE_DEGRADED", "IDENTITY_DEGRADED"}:
        if command in recovery_work | release_work:
            return "RECONCILE", "RECOVERING", "100", "512", "0"
        if command in allocating_work or command in {
            "ROTATE_KEYS",
            "ROTATE_IDENTITIES",
        }:
            return "DEFER", "DEGRADED", "500", "1024", "-EAGAIN"
        return "ALLOW", "DEGRADED", "0", "2048", "0"
    if condition in {
        "REPLICA_LAGGING",
        "EVENT_CHAIN_STALE",
        "WORKSPACE_PRESSURE",
        "QUEUE_SATURATED",
    }:
        if command in release_work | recovery_work:
            return "ALLOW", "DEGRADED", "0", "4096", "0"
        if command in allocating_work:
            return "DEFER", "DEGRADED", "200", "8192", "-EAGAIN"
        return "ALLOW", "DEGRADED", "0", "16384", "0"
    if condition == "PARTITIONED":
        if command in {"BEGIN_MIGRATION", "PROMOTE_MIGRATION", "RECOVER"}:
            return "FAILOVER", "MIGRATING", "100", "32768", "0"
        if command in release_work:
            return "ALLOW", "DEGRADED", "0", "65536", "0"
        return "DEFER", "DEGRADED", "1000", "131072", "-EHOSTUNREACH"
    if condition == "FAILOVER_ACTIVE":
        if command in {
            "RECOVER",
            "PROMOTE_MIGRATION",
            "ROLLBACK_MIGRATION",
            "RECONCILE_LEASES",
        }:
            return "FAILOVER", "MIGRATING", "0", "262144", "0"
        if command in allocating_work:
            return "DEFER", "MIGRATING", "250", "524288", "-EAGAIN"
        return "ALLOW", "MIGRATING", "0", "1048576", "0"
    if condition == "READ_ONLY":
        if command in release_work | recovery_work:
            return "ALLOW_READ_ONLY", "MAINTENANCE", "0", "2097152", "0"
        return "DENY", "MAINTENANCE", "0", "4194304", "-EROFS"
    return "DENY", "FAILED", "0", "8388608", "-EIO"


def channel_epoch_decision(
    condition: str,
    control: str,
) -> Decision:
    rekey = {
        "REKEY_PREPARE",
        "REKEY_ACCEPT",
        "REKEY_COMMIT",
        "REKEY_ABORT",
        "KEY_UPDATE_REQUEST",
        "KEY_UPDATE_ACK",
    }
    ticket = {
        "TICKET_REQUEST",
        "TICKET_ISSUE",
        "TICKET_ACCEPT",
        "TICKET_REJECT",
    }
    liveness = {
        "KEEPALIVE",
        "KEEPALIVE_ACK",
        "PEER_HEALTH",
        "AUDIT_REQUEST",
        "AUDIT_RESPONSE",
    }
    drain = {"PEER_DRAIN", "PEER_DRAINED", "GOAWAY", "ERROR"}

    if control == "NONE":
        return "DENY", "FAILED", "0", "1", "-EINVAL"
    if condition == "TERMINATED":
        return "TERMINATE", "TERMINATED", "0", "2", "-ESHUTDOWN"
    if condition == "CURRENT":
        return "ALLOW", "ESTABLISHED", "4096", "4", "0"
    if condition == "ROTATION_DUE":
        if control in rekey | liveness | drain:
            return "ALLOW", "REKEY_PREPARED", "256", "8", "0"
        return "REQUIRE_REKEY", "REKEY_PREPARED", "0", "16", "-EAGAIN"
    if condition == "ROTATION_OVERDUE":
        if control in rekey | liveness | drain:
            return "ALLOW_REKEY_ONLY", "REKEY_PREPARED", "0", "32", "0"
        return "ALLOW_REKEY_ONLY", "REKEY_PREPARED", "0", "64", "-EKEYREJECTED"
    if condition in {
        "PREPARED_LOCAL",
        "PREPARED_PEER",
        "ACCEPTED",
        "COMMITTING",
    }:
        state = "REKEY_ACCEPTED" if condition == "ACCEPTED" else "REKEY_COMMITTING"
        if control in rekey | liveness | drain:
            return "ALLOW_REKEY_ONLY", state, "0", "128", "0"
        return "ALLOW_REKEY_ONLY", state, "0", "256", "-EBUSY"
    if condition in {"PEER_AHEAD", "PEER_BEHIND"}:
        if control in rekey | ticket | liveness:
            return "RESYNC", "RECOVERING", "0", "512", "0"
        return "RESYNC", "SUSPENDED", "0", "1024", "-ESTALE"
    if condition == "SECRET_EXHAUSTED":
        if control in ticket:
            return "REJECT", "REKEY_PREPARED", "0", "2048", "-EKEYREJECTED"
        if control in rekey | liveness | drain:
            return "ALLOW_REKEY_ONLY", "REKEY_PREPARED", "0", "4096", "0"
        return "REQUIRE_REKEY", "REKEY_PREPARED", "0", "8192", "-EAGAIN"
    if condition == "TICKET_STALE":
        if control in ticket:
            return "REJECT", "ESTABLISHED", "0", "16384", "-ESTALE"
        return "ALLOW", "ESTABLISHED", "2048", "32768", "0"
    if condition in {
        "CONFIRMATION_INVALID",
        "EXPORTER_CHANGED",
        "REPLAY_SUSPECTED",
    }:
        if control in drain:
            return "CLOSE", "CLOSING", "0", "65536", "0"
        return "CLOSE", "CLOSING", "0", "131072", "-EBADMSG"
    if condition == "LOCKED":
        if control in liveness | drain:
            return "CLOSE", "CLOSING", "0", "262144", "0"
        return "REJECT", "SUSPENDED", "0", "524288", "-EACCES"
    return "REJECT", "FAILED", "0", "1048576", "-EIO"


def channel_stream_decision(
    condition: str,
    control: str,
) -> Decision:
    stream_controls = {
        "STREAM_OPEN",
        "STREAM_ACCEPT",
        "STREAM_REFUSE",
        "STREAM_CLOSE",
        "STREAM_RESET",
        "STREAM_WINDOW",
        "CONNECTION_WINDOW",
    }
    close_controls = {
        "STREAM_CLOSE",
        "STREAM_RESET",
        "STREAM_WINDOW",
        "CONNECTION_WINDOW",
    }
    liveness = {
        "KEEPALIVE",
        "KEEPALIVE_ACK",
        "PEER_HEALTH",
        "AUDIT_REQUEST",
        "AUDIT_RESPONSE",
    }
    drain = {"PEER_DRAIN", "PEER_DRAINED", "GOAWAY", "ERROR"}

    if control == "NONE":
        return "DENY", "FAILED", "0", "1", "-EINVAL"
    if condition == "TERMINATED":
        return "TERMINATE", "TERMINATED", "0", "2", "-ESHUTDOWN"
    if condition == "SEQUENCE_REPLAY":
        return "CLOSE_CHANNEL", "CLOSING", "0", "4", "-EBADMSG"
    if condition == "SEQUENCE_GAP":
        if control in close_controls | liveness:
            return "RESET_STREAM", "ESTABLISHED", "0", "8", "0"
        return "RESET_STREAM", "ESTABLISHED", "0", "16", "-EPROTO"
    if condition == "CONNECTION_DRAINING":
        if control in close_controls | liveness | drain:
            return "DRAIN", "DRAINING", "0", "32", "0"
        return "DRAIN", "DRAINING", "0", "64", "-ESHUTDOWN"
    if condition == "CLOSED":
        if control in {"STREAM_CLOSE", "STREAM_RESET"} | liveness | drain:
            return "ALLOW_CONTROL_ONLY", "CLOSED", "0", "128", "0"
        return "DENY", "CLOSED", "0", "256", "-ENOTCONN"
    if control not in stream_controls:
        return "ALLOW_CONTROL_ONLY", "ESTABLISHED", "0", "512", "0"
    if condition == "IDLE":
        if control == "STREAM_OPEN":
            return "ALLOW", "ESTABLISHED", "0", "1024", "0"
        return "REQUIRE_OPEN", "ESTABLISHED", "0", "2048", "-ENOTCONN"
    if condition in {"OPENING_LOCAL", "OPENING_PEER"}:
        if control in {
            "STREAM_ACCEPT",
            "STREAM_REFUSE",
            "STREAM_CLOSE",
            "STREAM_RESET",
            "STREAM_WINDOW",
        }:
            return "ALLOW", "ESTABLISHED", "0", "4096", "0"
        if control == "STREAM_OPEN":
            return "REQUIRE_OPEN", "ESTABLISHED", "0", "8192", "-EALREADY"
        return "ALLOW_CONTROL_ONLY", "ESTABLISHED", "0", "16384", "0"
    if condition == "OPEN":
        if control == "STREAM_OPEN":
            return "REQUIRE_OPEN", "ESTABLISHED", "0", "32768", "-EALREADY"
        return "ALLOW", "ESTABLISHED", "0", "65536", "0"
    if condition in {"HALF_CLOSED_LOCAL", "HALF_CLOSED_PEER"}:
        if control in close_controls:
            return "ALLOW", "DRAINING", "0", "131072", "0"
        return "DRAIN", "DRAINING", "0", "262144", "-ESHUTDOWN"
    if condition == "DRAINING":
        if control in close_controls:
            return "DRAIN", "DRAINING", "0", "524288", "0"
        return "DRAIN", "DRAINING", "0", "1048576", "-ESHUTDOWN"
    if condition in {"RESET_LOCAL", "RESET_PEER"}:
        if control in {"STREAM_RESET", "STREAM_CLOSE"}:
            return "RESET_STREAM", "ESTABLISHED", "0", "2097152", "0"
        return "RESET_STREAM", "ESTABLISHED", "0", "4194304", "-ECONNRESET"
    if condition in {"FLOW_BLOCKED_LOCAL", "FLOW_BLOCKED_PEER"}:
        if control in {"STREAM_WINDOW", "CONNECTION_WINDOW", "STREAM_RESET"}:
            return "ALLOW", "ESTABLISHED", "0", "8388608", "0"
        return "BACKPRESSURE", "ESTABLISHED", "25", "16777216", "-EAGAIN"
    return "DENY", "FAILED", "0", "33554432", "-EIO"


@dataclass(frozen=True)
class Catalog:
    filename: str
    header: str
    struct_name: str
    array_name: str
    conditions: list[str]
    condition_type: str
    condition_prefix: str
    condition_count: str
    operations: list[str]
    operation_type: str
    operation_prefix: str
    operation_count: str
    operation_field: str
    lookup_name: str
    audit_name: str
    value_fields: tuple[str, ...]
    decide: Callable[[str, str], Decision]
    maximum_value: str
    primary_field: str
    denied_value: str
    has_next_state: bool


CATALOGS = [
    Catalog(
        "runtime_authorization_policy_catalog.c",
        "runtime_guard.h",
        "pqcp_runtime_authorization_policy_decision",
        "runtime_authorization_catalog",
        RUNTIME_AUTHORIZATION_CONDITIONS,
        "pqcp_runtime_authorization_condition",
        "PQCP_RUNTIME_AUTHORIZATION_",
        "PQCP_RUNTIME_AUTHORIZATION_CONDITION_COUNT",
        base.RUNTIME_COMMANDS,
        "pqcp_runtime_command_kind",
        "PQCP_RUNTIME_COMMAND_",
        "PQCP_RUNTIME_POLICY_COMMAND_COUNT",
        "command",
        "pqcp_runtime_authorization_policy_lookup",
        "pqcp_runtime_authorization_policy_catalog_audit",
        (
            "disposition",
            "required_assurance",
            "audit_level",
            "reason_mask",
            "error",
        ),
        runtime_authorization_decision,
        "PQCP_RUNTIME_AUTHORIZATION_QUARANTINE",
        "disposition",
        "PQCP_RUNTIME_AUTHORIZATION_DENY",
        False,
    ),
    Catalog(
        "runtime_continuity_policy_catalog.c",
        "runtime_guard.h",
        "pqcp_runtime_continuity_policy_decision",
        "runtime_continuity_catalog",
        RUNTIME_CONTINUITY_CONDITIONS,
        "pqcp_runtime_continuity_condition",
        "PQCP_RUNTIME_CONTINUITY_",
        "PQCP_RUNTIME_CONTINUITY_CONDITION_COUNT",
        base.RUNTIME_COMMANDS,
        "pqcp_runtime_command_kind",
        "PQCP_RUNTIME_COMMAND_",
        "PQCP_RUNTIME_POLICY_COMMAND_COUNT",
        "command",
        "pqcp_runtime_continuity_policy_lookup",
        "pqcp_runtime_continuity_policy_catalog_audit",
        ("directive", "next_state", "delay_ms", "reason_mask", "error"),
        runtime_continuity_decision,
        "PQCP_RUNTIME_CONTINUITY_TERMINATE",
        "directive",
        "PQCP_RUNTIME_CONTINUITY_DENY",
        True,
    ),
    Catalog(
        "protected_channel_epoch_policy_catalog.c",
        "protected_channel_guard.h",
        "pqcp_channel_epoch_policy_decision",
        "channel_epoch_catalog",
        CHANNEL_EPOCH_CONDITIONS,
        "pqcp_channel_epoch_condition",
        "PQCP_CHANNEL_EPOCH_",
        "PQCP_CHANNEL_EPOCH_CONDITION_COUNT",
        base.CHANNEL_CONTROLS,
        "pqcp_channel_control_kind",
        "PQCP_CHANNEL_CONTROL_",
        "PQCP_CHANNEL_POLICY_CONTROL_COUNT",
        "control",
        "pqcp_channel_epoch_policy_lookup",
        "pqcp_channel_epoch_policy_catalog_audit",
        ("directive", "next_state", "maximum_frames", "reason_mask", "error"),
        channel_epoch_decision,
        "PQCP_CHANNEL_EPOCH_TERMINATE",
        "directive",
        "PQCP_CHANNEL_EPOCH_DENY",
        True,
    ),
    Catalog(
        "protected_channel_stream_policy_catalog.c",
        "protected_channel_guard.h",
        "pqcp_channel_stream_policy_decision",
        "channel_stream_catalog",
        CHANNEL_STREAM_CONDITIONS,
        "pqcp_channel_stream_condition",
        "PQCP_CHANNEL_STREAM_CONDITION_",
        "PQCP_CHANNEL_STREAM_CONDITION_COUNT",
        base.CHANNEL_CONTROLS,
        "pqcp_channel_control_kind",
        "PQCP_CHANNEL_CONTROL_",
        "PQCP_CHANNEL_POLICY_CONTROL_COUNT",
        "control",
        "pqcp_channel_stream_policy_lookup",
        "pqcp_channel_stream_policy_catalog_audit",
        ("directive", "next_state", "retry_after_ms", "reason_mask", "error"),
        channel_stream_decision,
        "PQCP_CHANNEL_STREAM_DIRECTIVE_TERMINATE",
        "directive",
        "PQCP_CHANNEL_STREAM_DIRECTIVE_DENY",
        True,
    ),
]


def enum_value(catalog: Catalog, field: str, value: str) -> str:
    if field == "disposition":
        return f"PQCP_RUNTIME_AUTHORIZATION_{value}"
    if field == "directive":
        if catalog.array_name == "runtime_continuity_catalog":
            return f"PQCP_RUNTIME_CONTINUITY_{value}"
        if catalog.array_name == "channel_epoch_catalog":
            return f"PQCP_CHANNEL_EPOCH_{value}"
        return f"PQCP_CHANNEL_STREAM_DIRECTIVE_{value}"
    if field == "next_state":
        prefix = (
            "PQCP_RUNTIME_POLICY_"
            if catalog.array_name.startswith("runtime_")
            else "PQCP_CHANNEL_POLICY_"
        )
        return f"{prefix}{value}"
    if field == "error":
        return value
    return f"{value}U"


def render(catalog: Catalog) -> str:
    lines = [
        "/*",
        " * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation",
        " *",
        " * Generated by scripts/generate_runtime_channel_guard_catalogs.py.",
        " * Do not edit by hand.",
        " */",
        "",
        "#include <errno.h>",
        "",
        f"#include <pqcp_zephyr/{catalog.header}>",
        "",
        f"static const struct {catalog.struct_name}",
        f"\t{catalog.array_name}",
        f"\t[{catalog.condition_count}]",
        f"\t[{catalog.operation_count}] = {{",
    ]
    for condition in catalog.conditions:
        for operation in catalog.operations:
            values = catalog.decide(condition, operation)
            lines.extend(
                [
                    f"\t[{catalog.condition_prefix}{condition}]",
                    f"\t[{catalog.operation_prefix}{operation}] = {{",
                    f"\t\t.condition = {catalog.condition_prefix}{condition},",
                    f"\t\t.{catalog.operation_field} = "
                    f"{catalog.operation_prefix}{operation},",
                ]
            )
            for field, value in zip(catalog.value_fields, values, strict=True):
                lines.append(f"\t\t.{field} = {enum_value(catalog, field, value)},")
            lines.append("\t},")
    lines.extend(
        [
            "};",
            "",
            f"int {catalog.lookup_name}(",
            f"\tenum {catalog.condition_type} condition,",
            f"\tenum {catalog.operation_type} {catalog.operation_field},",
            f"\tstruct {catalog.struct_name} *decision)",
            "{",
            f"\tif (condition < {catalog.condition_prefix}{catalog.conditions[0]} ||",
            f"\t    condition >= {catalog.condition_count} ||",
            f"\t    {catalog.operation_field} < {catalog.operation_prefix}{catalog.operations[0]} ||",
            f"\t    {catalog.operation_field} >= "
            + (
                "PQCP_RUNTIME_COMMAND_KIND_COUNT ||"
                if catalog.operation_field == "command"
                else "PQCP_CHANNEL_CONTROL_KIND_COUNT ||"
            ),
            "\t    decision == NULL) {",
            "\t\treturn -EINVAL;",
            "\t}",
            f"\t*decision = {catalog.array_name}[condition]"
            f"[{catalog.operation_field}];",
            "\treturn 0;",
            "}",
            "",
            f"int {catalog.audit_name}(void)",
            "{",
            "\tfor (size_t condition = 0U;",
            f"\t     condition < {catalog.condition_count}; ++condition) {{",
            f"\t\tfor (size_t operation = 0U;",
            f"\t\t     operation < {catalog.operation_count}; ++operation) {{",
            f"\t\t\tconst struct {catalog.struct_name} *entry =",
            f"\t\t\t\t&{catalog.array_name}[condition][operation];",
            "",
            "\t\t\tif ((size_t)entry->condition != condition ||",
            f"\t\t\t    (size_t)entry->{catalog.operation_field} != operation ||",
            f"\t\t\t    entry->{catalog.primary_field} >",
            f"\t\t\t\t{catalog.maximum_value} ||",
            "\t\t\t    entry->reason_mask == 0U) {",
            "\t\t\t\treturn -EBADMSG;",
            "\t\t\t}",
        ]
    )
    if catalog.has_next_state:
        runtime = catalog.array_name.startswith("runtime_")
        first = "PQCP_RUNTIME_POLICY_UNINITIALIZED" if runtime else "PQCP_CHANNEL_POLICY_NEW"
        last = "PQCP_RUNTIME_POLICY_TERMINATED" if runtime else "PQCP_CHANNEL_POLICY_TERMINATED"
        lines.extend(
            [
                f"\t\t\tif (entry->next_state < {first} ||",
                f"\t\t\t    entry->next_state > {last}) {{",
                "\t\t\t\treturn -EBADMSG;",
                "\t\t\t}",
            ]
        )
    lines.extend(
        [
            f"\t\t\tif (entry->{catalog.primary_field} ==",
            f"\t\t\t\t    {catalog.denied_value} &&",
            "\t\t\t    entry->error == 0) {",
            "\t\t\t\treturn -EBADMSG;",
            "\t\t\t}",
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
        update_file(root / "src" / catalog.filename, render(catalog), args.check)
        for catalog in CATALOGS
    ]
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
