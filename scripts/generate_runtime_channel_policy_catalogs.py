#!/usr/bin/env python3
"""Generate exhaustive runtime and protected-channel policy catalogs.

The operational policy APIs deliberately expose every state/command pair.
Keeping the 1,024 decisions generated from compact policy definitions avoids
implicit fall-through behavior while preserving a reviewable C artifact.
"""

from __future__ import annotations

import argparse
from pathlib import Path


RUNTIME_STATES = [
    "UNINITIALIZED",
    "INITIALIZED",
    "STARTING",
    "RUNNING",
    "DEGRADED",
    "DRAINING",
    "STOPPING",
    "STOPPED",
    "LOCKDOWN",
    "RECOVERING",
    "MIGRATING",
    "CHECKPOINTING",
    "RESTORING",
    "MAINTENANCE",
    "FAILED",
    "TERMINATED",
]

RUNTIME_COMMANDS = [
    "NONE",
    "START",
    "STOP",
    "TICK",
    "SELFTEST",
    "AUDIT",
    "LOCKDOWN",
    "RECOVER",
    "OPEN_SESSION",
    "CLOSE_SESSION",
    "DRAIN_SESSION",
    "SUBMIT_JOB",
    "CANCEL_JOB",
    "ROTATE_KEYS",
    "EXPIRE_KEYS",
    "ROTATE_IDENTITIES",
    "TRANSITION_PROFILE",
    "WRITE_CHECKPOINT",
    "RESTORE_CHECKPOINT",
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
    "BUILD_EVIDENCE",
    "READ_HEALTH",
    "READ_SNAPSHOT",
]

CHANNEL_STATES = [
    "NEW",
    "NEGOTIATING",
    "AUTHENTICATING",
    "ESTABLISHED",
    "REKEY_PREPARED",
    "REKEY_ACCEPTED",
    "REKEY_COMMITTING",
    "RESUMING",
    "MIGRATING",
    "DRAINING",
    "CLOSING",
    "CLOSED",
    "FAILED",
    "SUSPENDED",
    "RECOVERING",
    "TERMINATED",
]

CHANNEL_CONTROLS = [
    "NONE",
    "STREAM_OPEN",
    "STREAM_ACCEPT",
    "STREAM_REFUSE",
    "STREAM_CLOSE",
    "STREAM_RESET",
    "STREAM_WINDOW",
    "CONNECTION_WINDOW",
    "REKEY_PREPARE",
    "REKEY_ACCEPT",
    "REKEY_COMMIT",
    "REKEY_ABORT",
    "TICKET_REQUEST",
    "TICKET_ISSUE",
    "TICKET_ACCEPT",
    "TICKET_REJECT",
    "PATH_CHALLENGE",
    "PATH_RESPONSE",
    "PEER_HEALTH",
    "PEER_DRAIN",
    "PEER_DRAINED",
    "KEEPALIVE",
    "KEEPALIVE_ACK",
    "PROFILE_OFFER",
    "PROFILE_ACCEPT",
    "PROFILE_REJECT",
    "KEY_UPDATE_REQUEST",
    "KEY_UPDATE_ACK",
    "GOAWAY",
    "ERROR",
    "AUDIT_REQUEST",
    "AUDIT_RESPONSE",
]

RUNTIME_RESOURCE_CONDITIONS = [
    "AVAILABLE",
    "JOBS_ELEVATED",
    "KEYS_ELEVATED",
    "SESSIONS_ELEVATED",
    "WORKSPACES_ELEVATED",
    "MEMORY_ELEVATED",
    "HIGH",
    "CRITICAL",
    "JOBS_EXHAUSTED",
    "KEYS_EXHAUSTED",
    "SESSIONS_EXHAUSTED",
    "WORKSPACES_EXHAUSTED",
    "MEMORY_EXHAUSTED",
    "QUARANTINED",
    "RECLAIMING",
    "FAILED",
]

RUNTIME_RECOVERY_CONDITIONS = [
    "HEALTHY",
    "TRANSIENT_IO",
    "TRANSIENT_CRYPTO",
    "QUEUE_STALL",
    "DEADLINE_MISS",
    "RESOURCE_PRESSURE",
    "KEY_STORE_INVALID",
    "SESSION_INVALID",
    "EXECUTOR_INVALID",
    "AUDIT_INVALID",
    "CHECKPOINT_INVALID",
    "IDENTITY_INVALID",
    "POLICY_VIOLATION",
    "REPEATED_FAILURE",
    "LOCKDOWN",
    "UNRECOVERABLE",
]

CHANNEL_PATH_CONDITIONS = [
    "PRIMARY_HEALTHY",
    "PRIMARY_SLOW",
    "PRIMARY_IDLE",
    "PRIMARY_FAILED",
    "CANDIDATE_PROBING",
    "CANDIDATE_VALIDATED",
    "CANDIDATE_FASTER",
    "CANDIDATE_SLOWER",
    "MIGRATING",
    "DRAINING",
    "REKEYING",
    "RESUMING",
    "PEER_SUSPECT",
    "PEER_UNREACHABLE",
    "NO_VALID_PATH",
    "TERMINATED",
]

CHANNEL_FAULT_CONDITIONS = [
    "NONE",
    "TRANSIENT_IO",
    "TIMEOUT",
    "FLOW_CONTROL",
    "STREAM_PROTOCOL",
    "CONTROL_PROTOCOL",
    "AUTHENTICATION",
    "REPLAY",
    "REKEY",
    "TICKET",
    "PATH_VALIDATION",
    "PEER_SUSPECT",
    "PEER_UNREACHABLE",
    "POLICY",
    "INTERNAL",
    "TERMINAL",
]


def runtime_decision(state: str, command: str) -> tuple[str, str, str, int]:
    action = "DENY"
    next_state = state
    error = "-EACCES"
    flags = 0

    if command == "NONE":
        return action, next_state, "-EINVAL", flags
    if state == "TERMINATED":
        return action, next_state, "-ESHUTDOWN", flags
    if command in {"AUDIT", "READ_HEALTH", "READ_SNAPSHOT"}:
        if state != "UNINITIALIZED":
            return "ALLOW_READ_ONLY", state, "0", 1
        return action, next_state, "-EAGAIN", flags
    if command == "START" and state in {"INITIALIZED", "STOPPED"}:
        return "ALLOW_IDEMPOTENT", "RUNNING", "0", 2
    if command == "STOP" and state in {
        "RUNNING",
        "DEGRADED",
        "MAINTENANCE",
        "DRAINING",
    }:
        return "REQUIRE_DRAIN", "STOPPED", "0", 4
    if command == "TICK" and state in {
        "RUNNING",
        "DEGRADED",
        "MIGRATING",
        "MAINTENANCE",
        "DRAINING",
    }:
        return "ALLOW_IDEMPOTENT", state, "0", 8
    if command == "SELFTEST" and state in {
        "INITIALIZED",
        "RUNNING",
        "DEGRADED",
        "MAINTENANCE",
        "STOPPED",
    }:
        return "ALLOW", state, "0", 16
    if command == "LOCKDOWN" and state not in {
        "UNINITIALIZED",
        "TERMINATED",
        "LOCKDOWN",
    }:
        return "ALLOW_IDEMPOTENT", "LOCKDOWN", "0", 32
    if command == "LOCKDOWN" and state == "LOCKDOWN":
        return "ALLOW_IDEMPOTENT", "LOCKDOWN", "0", 32
    if command == "RECOVER" and state in {
        "LOCKDOWN",
        "FAILED",
        "DEGRADED",
        "RECOVERING",
    }:
        return "REQUIRE_RECOVERY", "RUNNING", "0", 64
    if command in {"OPEN_SESSION", "SUBMIT_JOB", "ISSUE_LEASE"}:
        if state == "RUNNING":
            return "ALLOW", state, "0", 128
        if state == "DEGRADED":
            return "REQUIRE_MAINTENANCE", state, "-EAGAIN", 256
        return action, next_state, "-ESHUTDOWN", flags
    if command in {
        "CLOSE_SESSION",
        "DRAIN_SESSION",
        "CANCEL_JOB",
        "REVOKE_LEASE",
        "RECONCILE_LEASES",
    } and state in {
        "RUNNING",
        "DEGRADED",
        "DRAINING",
        "LOCKDOWN",
        "MAINTENANCE",
    }:
        return "ALLOW_IDEMPOTENT", state, "0", 512
    if command in {
        "ROTATE_KEYS",
        "EXPIRE_KEYS",
        "ROTATE_IDENTITIES",
        "TRANSITION_PROFILE",
    } and state in {"RUNNING", "DEGRADED", "MAINTENANCE"}:
        return "REQUIRE_MAINTENANCE", state, "0", 1024
    if command == "WRITE_CHECKPOINT" and state in {
        "RUNNING",
        "DEGRADED",
        "MAINTENANCE",
        "STOPPED",
    }:
        return "ALLOW_IDEMPOTENT", "CHECKPOINTING", "0", 2048
    if command == "RESTORE_CHECKPOINT" and state in {
        "INITIALIZED",
        "STOPPED",
        "FAILED",
        "LOCKDOWN",
    }:
        return "REQUIRE_RECOVERY", "RESTORING", "0", 4096
    if command == "BEGIN_TRANSACTION" and state in {
        "RUNNING",
        "MAINTENANCE",
    }:
        return "ALLOW", state, "0", 8192
    if command in {"COMMIT_TRANSACTION", "ROLLBACK_TRANSACTION"} and state in {
        "RUNNING",
        "DEGRADED",
        "MAINTENANCE",
        "LOCKDOWN",
    }:
        return "ALLOW_IDEMPOTENT", state, "0", 16384
    if command == "BEGIN_MIGRATION" and state in {
        "RUNNING",
        "MAINTENANCE",
    }:
        return "REQUIRE_DRAIN", "MIGRATING", "0", 32768
    if command in {"PROMOTE_MIGRATION", "ROLLBACK_MIGRATION"} and state in {
        "MIGRATING",
        "DEGRADED",
        "LOCKDOWN",
    }:
        target = "RUNNING" if command == "PROMOTE_MIGRATION" else "MAINTENANCE"
        return "ALLOW_IDEMPOTENT", target, "0", 65536
    if command in {"RUN_CAMPAIGN", "BUILD_EVIDENCE"} and state in {
        "RUNNING",
        "DEGRADED",
        "MAINTENANCE",
        "STOPPED",
    }:
        return "ALLOW_READ_ONLY", state, "0", 131072
    return action, next_state, error, flags


def channel_decision(state: str, control: str) -> tuple[str, str, str, int]:
    action = "DENY"
    next_state = state
    error = "-EACCES"
    flags = 0

    if control == "NONE":
        return action, next_state, "-EINVAL", flags
    if state == "TERMINATED":
        return action, next_state, "-ESHUTDOWN", flags
    if control == "ERROR":
        return "CLOSE_ON_FAILURE", "FAILED", "0", 1
    if control in {"AUDIT_REQUEST", "AUDIT_RESPONSE", "PEER_HEALTH"}:
        if state not in {"NEW", "CLOSED", "TERMINATED"}:
            return "ALLOW_IDEMPOTENT", state, "0", 2
        return action, next_state, "-ENOTCONN", flags
    if control in {"PROFILE_OFFER", "PROFILE_ACCEPT", "PROFILE_REJECT"}:
        if state in {"NEW", "NEGOTIATING", "AUTHENTICATING", "RESUMING"}:
            target = "AUTHENTICATING" if control == "PROFILE_ACCEPT" else "NEGOTIATING"
            return "ALLOW_IDEMPOTENT", target, "0", 4
        return action, next_state, "-EALREADY", flags
    if control in {
        "STREAM_OPEN",
        "STREAM_ACCEPT",
        "STREAM_REFUSE",
        "STREAM_CLOSE",
        "STREAM_RESET",
        "STREAM_WINDOW",
        "CONNECTION_WINDOW",
    }:
        if state == "ESTABLISHED":
            return "REQUIRE_ESTABLISHED", state, "0", 8
        if state == "DRAINING" and control in {
            "STREAM_CLOSE",
            "STREAM_RESET",
            "STREAM_WINDOW",
            "CONNECTION_WINDOW",
        }:
            return "ALLOW_IDEMPOTENT", state, "0", 16
        return action, next_state, "-ESHUTDOWN", flags
    if control == "REKEY_PREPARE" and state == "ESTABLISHED":
        return "REQUIRE_REKEY", "REKEY_PREPARED", "0", 32
    if control == "REKEY_ACCEPT" and state == "REKEY_PREPARED":
        return "REQUIRE_REKEY", "REKEY_ACCEPTED", "0", 64
    if control == "REKEY_COMMIT" and state in {
        "REKEY_ACCEPTED",
        "REKEY_COMMITTING",
    }:
        return "REQUIRE_REKEY", "ESTABLISHED", "0", 128
    if control == "REKEY_ABORT" and state in {
        "REKEY_PREPARED",
        "REKEY_ACCEPTED",
        "REKEY_COMMITTING",
    }:
        return "ALLOW_IDEMPOTENT", "ESTABLISHED", "0", 256
    if control in {
        "TICKET_REQUEST",
        "TICKET_ISSUE",
        "TICKET_ACCEPT",
        "TICKET_REJECT",
    } and state in {"ESTABLISHED", "RESUMING"}:
        target = "ESTABLISHED" if control in {"TICKET_ACCEPT", "TICKET_REJECT"} else state
        return "ALLOW_IDEMPOTENT", target, "0", 512
    if control in {"PATH_CHALLENGE", "PATH_RESPONSE"} and state in {
        "ESTABLISHED",
        "MIGRATING",
    }:
        return "ALLOW_IDEMPOTENT", "MIGRATING", "0", 1024
    if control == "PEER_DRAIN" and state == "ESTABLISHED":
        return "REQUIRE_DRAIN", "DRAINING", "0", 2048
    if control == "PEER_DRAINED" and state == "DRAINING":
        return "REQUIRE_DRAIN", "CLOSING", "0", 4096
    if control in {"KEEPALIVE", "KEEPALIVE_ACK"} and state in {
        "ESTABLISHED",
        "DRAINING",
        "SUSPENDED",
        "RECOVERING",
    }:
        return "ALLOW_IDEMPOTENT", state, "0", 8192
    if control in {"KEY_UPDATE_REQUEST", "KEY_UPDATE_ACK"} and state in {
        "ESTABLISHED",
        "REKEY_PREPARED",
        "REKEY_ACCEPTED",
    }:
        return "REQUIRE_REKEY", state, "0", 16384
    if control == "GOAWAY" and state not in {
        "NEW",
        "CLOSED",
        "TERMINATED",
    }:
        return "REQUIRE_DRAIN", "DRAINING", "0", 32768
    return action, next_state, error, flags


def runtime_resource_decision(
    condition: str,
    command: str,
) -> tuple[str, int, int, int, int, str]:
    if command == "NONE":
        return "DENY", 0, 0, 0, 1, "-EINVAL"

    read_only = {"AUDIT", "READ_HEALTH", "READ_SNAPSHOT", "BUILD_EVIDENCE"}
    release_work = {
        "STOP",
        "CLOSE_SESSION",
        "DRAIN_SESSION",
        "CANCEL_JOB",
        "EXPIRE_KEYS",
        "REVOKE_LEASE",
        "ROLLBACK_TRANSACTION",
        "ROLLBACK_MIGRATION",
    }
    recovery_work = {
        "RECOVER",
        "WRITE_CHECKPOINT",
        "RESTORE_CHECKPOINT",
        "RECONCILE_LEASES",
    }
    allocates_jobs = {"SUBMIT_JOB", "SELFTEST", "RUN_CAMPAIGN"}
    allocates_keys = {"ROTATE_KEYS", "ROTATE_IDENTITIES"}
    allocates_sessions = {"OPEN_SESSION", "ISSUE_LEASE"}
    allocates_workspace = allocates_jobs | {"BEGIN_MIGRATION", "RUN_CAMPAIGN"}

    if command in read_only:
        return "ALLOW", 4, 30000, 0, 2, "0"
    if condition == "FAILED":
        if command in recovery_work | release_work:
            return "REQUIRE_RECOVERY", 1, 5000, 100, 4, "0"
        return "DENY", 0, 0, 100, 8, "-EIO"
    if condition == "QUARANTINED":
        if command in recovery_work | release_work:
            return "REQUIRE_RECOVERY", 1, 5000, 90, 16, "0"
        return "DENY", 0, 0, 90, 32, "-EACCES"
    if condition == "RECLAIMING":
        if command in release_work | recovery_work:
            return "ALLOW_RECLAIM", 2, 10000, 60, 64, "0"
        return "ALLOW_THROTTLED", 1, 2000, 70, 128, "-EAGAIN"
    if condition.endswith("_EXHAUSTED"):
        blocked = set()
        if condition == "JOBS_EXHAUSTED":
            blocked = allocates_jobs
        elif condition == "KEYS_EXHAUSTED":
            blocked = allocates_keys
        elif condition == "SESSIONS_EXHAUSTED":
            blocked = allocates_sessions
        elif condition in {"WORKSPACES_EXHAUSTED", "MEMORY_EXHAUSTED"}:
            blocked = allocates_workspace
        if command in release_work:
            return "ALLOW_RECLAIM", 4, 5000, 40, 256, "0"
        if command in recovery_work:
            return "REQUIRE_CHECKPOINT", 1, 5000, 60, 512, "0"
        if command in blocked:
            return "DENY", 0, 0, 100, 1024, "-EDQUOT"
        return "ALLOW_THROTTLED", 1, 1000, 80, 2048, "0"
    if condition == "CRITICAL":
        if command in release_work | recovery_work:
            return "ALLOW_RECLAIM", 2, 5000, 40, 4096, "0"
        return "ALLOW_THROTTLED", 1, 1000, 80, 8192, "0"
    if condition == "HIGH":
        if command in release_work:
            return "ALLOW_RECLAIM", 4, 10000, 20, 16384, "0"
        return "ALLOW_THROTTLED", 2, 5000, 50, 32768, "0"
    if condition.endswith("_ELEVATED"):
        return "ALLOW_THROTTLED", 4, 15000, 20, 65536, "0"
    return "ALLOW", 8, 30000, 0, 131072, "0"


def runtime_recovery_decision(
    condition: str,
    command: str,
) -> tuple[str, str, int, int, int, str]:
    if command == "NONE":
        return "IGNORE", "FAILED", 0, 0, 1, "-EINVAL"
    if command in {"AUDIT", "READ_HEALTH", "READ_SNAPSHOT"}:
        state = "RUNNING" if condition == "HEALTHY" else "DEGRADED"
        return "OBSERVE", state, 0, 0, 2, "0"
    if condition == "HEALTHY":
        return "IGNORE", "RUNNING", 0, 0, 4, "0"
    if condition in {"TRANSIENT_IO", "TRANSIENT_CRYPTO"}:
        directive = "RETRY" if command in {"TICK", "SUBMIT_JOB"} else "BACKOFF"
        return directive, "DEGRADED", 3, 100, 8, "0"
    if condition in {"QUEUE_STALL", "DEADLINE_MISS"}:
        if command in {"CANCEL_JOB", "DRAIN_SESSION", "STOP"}:
            return "DRAIN", "DRAINING", 1, 0, 16, "0"
        return "BACKOFF", "DEGRADED", 2, 250, 32, "0"
    if condition == "RESOURCE_PRESSURE":
        if command in {"WRITE_CHECKPOINT", "STOP", "DRAIN_SESSION"}:
            return "CHECKPOINT", "CHECKPOINTING", 1, 0, 64, "0"
        return "DRAIN", "DRAINING", 1, 100, 128, "0"
    if condition in {"KEY_STORE_INVALID", "IDENTITY_INVALID"}:
        if command in {"ROTATE_KEYS", "ROTATE_IDENTITIES", "RECOVER"}:
            return "ROTATE_KEYS", "RECOVERING", 1, 0, 256, "0"
        return "LOCK_DOWN", "LOCKDOWN", 1, 0, 512, "-EKEYREJECTED"
    if condition == "SESSION_INVALID":
        if command in {"CLOSE_SESSION", "DRAIN_SESSION", "RECOVER"}:
            return "ROLLBACK", "RECOVERING", 1, 0, 1024, "0"
        return "DRAIN", "DRAINING", 1, 0, 2048, "-EBADMSG"
    if condition == "EXECUTOR_INVALID":
        if command in {"RECOVER", "SELFTEST"}:
            return "RESTART", "RECOVERING", 1, 250, 4096, "0"
        return "LOCK_DOWN", "LOCKDOWN", 1, 0, 8192, "-EIO"
    if condition == "AUDIT_INVALID":
        return "LOCK_DOWN", "LOCKDOWN", 1, 0, 16384, "-EBADMSG"
    if condition == "CHECKPOINT_INVALID":
        if command in {"RESTORE_CHECKPOINT", "ROLLBACK_TRANSACTION", "RECOVER"}:
            return "ROLLBACK", "RECOVERING", 1, 0, 32768, "0"
        return "LOCK_DOWN", "LOCKDOWN", 1, 0, 65536, "-EBADMSG"
    if condition == "POLICY_VIOLATION":
        return "LOCK_DOWN", "LOCKDOWN", 1, 0, 131072, "-EACCES"
    if condition == "REPEATED_FAILURE":
        if command == "RECOVER":
            return "RESTART", "RECOVERING", 1, 1000, 262144, "0"
        return "CHECKPOINT", "CHECKPOINTING", 1, 0, 524288, "-EAGAIN"
    if condition == "LOCKDOWN":
        if command == "RECOVER":
            return "RESTART", "RECOVERING", 1, 500, 1048576, "0"
        return "LOCK_DOWN", "LOCKDOWN", 0, 0, 2097152, "-ESHUTDOWN"
    return "TERMINATE", "TERMINATED", 0, 0, 4194304, "-ENOTRECOVERABLE"


def channel_path_decision(
    condition: str,
    control: str,
) -> tuple[str, int, int, int, str, str]:
    if control == "NONE":
        return "DENY", 0, 0, 1, "FAILED", "-EINVAL"
    path_controls = {"PATH_CHALLENGE", "PATH_RESPONSE"}
    rekey_controls = {
        "REKEY_PREPARE",
        "REKEY_ACCEPT",
        "REKEY_COMMIT",
        "REKEY_ABORT",
        "KEY_UPDATE_REQUEST",
        "KEY_UPDATE_ACK",
    }
    drain_controls = {"PEER_DRAIN", "PEER_DRAINED", "GOAWAY"}
    liveness_controls = {
        "KEEPALIVE",
        "KEEPALIVE_ACK",
        "PEER_HEALTH",
        "AUDIT_REQUEST",
        "AUDIT_RESPONSE",
    }
    if condition == "TERMINATED":
        return "CLOSE", 0, 0, 2, "TERMINATED", "-ESHUTDOWN"
    if condition == "NO_VALID_PATH":
        if control in path_controls | liveness_controls:
            return "ALLOW_PROBE", 5000, 0, 4, "MIGRATING", "0"
        return "DENY", 0, 0, 8, "SUSPENDED", "-EHOSTUNREACH"
    if condition == "PEER_UNREACHABLE":
        if control in path_controls | drain_controls:
            return "ALLOW_DRAIN", 3000, 0, 16, "DRAINING", "0"
        return "CLOSE", 0, 0, 32, "CLOSING", "-ETIMEDOUT"
    if condition in {"PRIMARY_FAILED", "CANDIDATE_FASTER"}:
        if control in path_controls | liveness_controls:
            return "ALLOW_MIGRATE", 5000, 1000, 64, "MIGRATING", "0"
        return "ALLOW", 5000, 1000, 128, "MIGRATING", "0"
    if condition in {"CANDIDATE_PROBING", "CANDIDATE_VALIDATED"}:
        if control in path_controls:
            return "ALLOW_PROBE", 5000, 1000, 256, "MIGRATING", "0"
        return "ALLOW", 5000, 1000, 512, "ESTABLISHED", "0"
    if condition == "MIGRATING":
        if control in path_controls | liveness_controls:
            return "ALLOW_MIGRATE", 5000, 1000, 1024, "MIGRATING", "0"
        return "ALLOW", 5000, 1000, 2048, "MIGRATING", "0"
    if condition == "DRAINING":
        if control in drain_controls | liveness_controls:
            return "ALLOW_DRAIN", 3000, 0, 4096, "DRAINING", "0"
        return "DENY", 0, 0, 8192, "DRAINING", "-ESHUTDOWN"
    if condition == "REKEYING":
        if control in rekey_controls | liveness_controls:
            return "REQUIRE_REKEY", 5000, 0, 16384, "REKEY_COMMITTING", "0"
        return "DENY", 0, 0, 32768, "REKEY_PREPARED", "-EBUSY"
    if condition == "RESUMING":
        if control.startswith("TICKET_") or control in liveness_controls:
            return "ALLOW", 5000, 0, 65536, "RESUMING", "0"
        return "DENY", 0, 0, 131072, "RESUMING", "-EAGAIN"
    if condition in {"PRIMARY_SLOW", "PRIMARY_IDLE", "PEER_SUSPECT"}:
        if control in path_controls:
            return "ALLOW_PROBE", 5000, 1500, 262144, "MIGRATING", "0"
        return "ALLOW", 5000, 1500, 524288, "ESTABLISHED", "0"
    return "ALLOW", 5000, 1000, 1048576, "ESTABLISHED", "0"


def channel_fault_decision(
    condition: str,
    control: str,
) -> tuple[str, str, int, int, int, str]:
    if control == "NONE":
        return "IGNORE", "FAILED", 0, 0, 1, "-EINVAL"
    if condition == "NONE":
        return "IGNORE", "ESTABLISHED", 0, 0, 2, "0"
    if control in {"AUDIT_REQUEST", "AUDIT_RESPONSE", "PEER_HEALTH"}:
        return "OBSERVE", "SUSPENDED", 0, 0, 4, "0"
    if condition == "TRANSIENT_IO":
        return "RETRY", "ESTABLISHED", 3, 100, 8, "0"
    if condition == "TIMEOUT":
        return "BACKOFF", "SUSPENDED", 3, 250, 16, "-ETIMEDOUT"
    if condition == "FLOW_CONTROL":
        if control in {"STREAM_WINDOW", "CONNECTION_WINDOW"}:
            return "RETRY", "ESTABLISHED", 2, 50, 32, "0"
        return "RESET_STREAM", "ESTABLISHED", 1, 0, 64, "-ENOBUFS"
    if condition == "STREAM_PROTOCOL":
        return "RESET_STREAM", "ESTABLISHED", 1, 0, 128, "-EPROTO"
    if condition == "CONTROL_PROTOCOL":
        return "DRAIN_CHANNEL", "DRAINING", 1, 0, 256, "-EPROTO"
    if condition in {"AUTHENTICATION", "REPLAY", "POLICY"}:
        return "CLOSE_CHANNEL", "CLOSING", 0, 0, 512, "-EACCES"
    if condition == "REKEY":
        if control.startswith("REKEY_") or control.startswith("KEY_UPDATE_"):
            return "REKEY_CHANNEL", "REKEY_PREPARED", 1, 0, 1024, "0"
        return "DRAIN_CHANNEL", "DRAINING", 1, 0, 2048, "-EKEYREJECTED"
    if condition == "TICKET":
        if control.startswith("TICKET_"):
            return "RETRY", "RESUMING", 1, 0, 4096, "0"
        return "OBSERVE", "ESTABLISHED", 0, 0, 8192, "-EBADMSG"
    if condition == "PATH_VALIDATION":
        if control in {"PATH_CHALLENGE", "PATH_RESPONSE"}:
            return "MIGRATE_PATH", "MIGRATING", 2, 100, 16384, "0"
        return "BACKOFF", "SUSPENDED", 2, 250, 32768, "-EHOSTUNREACH"
    if condition == "PEER_SUSPECT":
        return "OBSERVE", "SUSPENDED", 1, 500, 65536, "0"
    if condition == "PEER_UNREACHABLE":
        return "MIGRATE_PATH", "MIGRATING", 1, 0, 131072, "-EHOSTUNREACH"
    if condition == "INTERNAL":
        return "CLOSE_CHANNEL", "FAILED", 0, 0, 262144, "-EIO"
    return "TERMINATE_CHANNEL", "TERMINATED", 0, 0, 524288, "-ESHUTDOWN"


def emit_string_function(
    function: str,
    enum_type: str,
    enum_prefix: str,
    values: list[str],
) -> list[str]:
    lines = [
        f"const char *{function}(",
        f"\t{enum_type} value)",
        "{",
        "\tswitch (value) {",
    ]
    for value in values:
        lines.extend(
            [
                f"\tcase {enum_prefix}{value}:",
                f'\t\treturn "{value.lower().replace("_", "-")}";',
            ]
        )
    lines.extend(["\tdefault:", '\t\treturn "unknown";', "\t}", "}", ""])
    return lines


def runtime_source() -> str:
    lines = [
        "/*",
        " * SPDX-License-Identifier: MIT",
        " *",
        " * Generated by scripts/generate_runtime_channel_policy_catalogs.py.",
        " * Do not edit by hand.",
        " */",
        "",
        "#include <errno.h>",
        "",
        "#include <pqcp_zephyr/runtime_operations.h>",
        "",
        "static const struct pqcp_runtime_policy_decision runtime_catalog",
        "\t[PQCP_RUNTIME_POLICY_STATE_COUNT]",
        "\t[PQCP_RUNTIME_POLICY_COMMAND_COUNT] = {",
    ]
    for state in RUNTIME_STATES:
        for command in RUNTIME_COMMANDS:
            action, next_state, error, flags = runtime_decision(state, command)
            lines.extend(
                [
                    f"\t[PQCP_RUNTIME_POLICY_{state}]",
                    f"\t[PQCP_RUNTIME_COMMAND_{command}] = {{",
                    f"\t\t.state = PQCP_RUNTIME_POLICY_{state},",
                    f"\t\t.command = PQCP_RUNTIME_COMMAND_{command},",
                    f"\t\t.action = PQCP_RUNTIME_POLICY_{action},",
                    f"\t\t.next_state = PQCP_RUNTIME_POLICY_{next_state},",
                    f"\t\t.error = {error},",
                    f"\t\t.flags = {flags}U,",
                    "\t},",
                    "",
                    "",
                    "",
                ]
            )
    lines.extend(
        [
            "};",
            "",
            "int pqcp_runtime_policy_lookup(",
            "\tenum pqcp_runtime_policy_state state,",
            "\tenum pqcp_runtime_command_kind command,",
            "\tstruct pqcp_runtime_policy_decision *decision)",
            "{",
            "\tif (state < PQCP_RUNTIME_POLICY_UNINITIALIZED ||",
            "\t    state >= PQCP_RUNTIME_POLICY_STATE_COUNT ||",
            "\t    command < PQCP_RUNTIME_COMMAND_NONE ||",
            "\t    command >= PQCP_RUNTIME_COMMAND_KIND_COUNT ||",
            "\t    decision == NULL) {",
            "\t\treturn -EINVAL;",
            "\t}",
            "\t*decision = runtime_catalog[state][command];",
            "\treturn 0;",
            "}",
            "",
            "int pqcp_runtime_policy_catalog_audit(void)",
            "{",
            "\tfor (size_t state = 0U;",
            "\t     state < PQCP_RUNTIME_POLICY_STATE_COUNT; ++state) {",
            "\t\tfor (size_t command = 0U;",
            "\t\t     command < PQCP_RUNTIME_POLICY_COMMAND_COUNT;",
            "\t\t     ++command) {",
            "\t\t\tconst struct pqcp_runtime_policy_decision *entry =",
            "\t\t\t\t&runtime_catalog[state][command];",
            "",
            "\t\t\tif ((size_t)entry->state != state ||",
            "\t\t\t    (size_t)entry->command != command ||",
            "\t\t\t    entry->action >",
            "\t\t\t\tPQCP_RUNTIME_POLICY_REQUIRE_RECOVERY ||",
            "\t\t\t    entry->next_state <",
            "\t\t\t\tPQCP_RUNTIME_POLICY_UNINITIALIZED ||",
            "\t\t\t    entry->next_state >",
            "\t\t\t\tPQCP_RUNTIME_POLICY_TERMINATED) {",
            "\t\t\t\treturn -EBADMSG;",
            "\t\t\t}",
            "\t\t\tif (entry->action == PQCP_RUNTIME_POLICY_DENY &&",
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
    lines.extend(
        emit_string_function(
            "pqcp_runtime_command_kind_str",
            "enum pqcp_runtime_command_kind",
            "PQCP_RUNTIME_COMMAND_",
            RUNTIME_COMMANDS,
        )
    )
    lines.extend(
        emit_string_function(
            "pqcp_runtime_policy_state_str",
            "enum pqcp_runtime_policy_state",
            "PQCP_RUNTIME_POLICY_",
            RUNTIME_STATES,
        )
    )
    return "\n".join(lines)


def channel_source() -> str:
    lines = [
        "/*",
        " * SPDX-License-Identifier: MIT",
        " *",
        " * Generated by scripts/generate_runtime_channel_policy_catalogs.py.",
        " * Do not edit by hand.",
        " */",
        "",
        "#include <errno.h>",
        "",
        "#include <pqcp_zephyr/protected_channel_operations.h>",
        "",
        "static const struct pqcp_channel_policy_decision channel_catalog",
        "\t[PQCP_CHANNEL_POLICY_STATE_COUNT]",
        "\t[PQCP_CHANNEL_POLICY_CONTROL_COUNT] = {",
    ]
    for state in CHANNEL_STATES:
        for control in CHANNEL_CONTROLS:
            action, next_state, error, flags = channel_decision(state, control)
            lines.extend(
                [
                    f"\t[PQCP_CHANNEL_POLICY_{state}]",
                    f"\t[PQCP_CHANNEL_CONTROL_{control}] = {{",
                    f"\t\t.state = PQCP_CHANNEL_POLICY_{state},",
                    f"\t\t.control = PQCP_CHANNEL_CONTROL_{control},",
                    f"\t\t.action = PQCP_CHANNEL_POLICY_{action},",
                    f"\t\t.next_state = PQCP_CHANNEL_POLICY_{next_state},",
                    f"\t\t.error = {error},",
                    f"\t\t.flags = {flags}U,",
                    "\t},",
                    "",
                    "",
                    "",
                ]
            )
    lines.extend(
        [
            "};",
            "",
            "int pqcp_channel_policy_lookup(",
            "\tenum pqcp_channel_policy_state state,",
            "\tenum pqcp_channel_control_kind control,",
            "\tstruct pqcp_channel_policy_decision *decision)",
            "{",
            "\tif (state < PQCP_CHANNEL_POLICY_NEW ||",
            "\t    state >= PQCP_CHANNEL_POLICY_STATE_COUNT ||",
            "\t    control < PQCP_CHANNEL_CONTROL_NONE ||",
            "\t    control >= PQCP_CHANNEL_CONTROL_KIND_COUNT ||",
            "\t    decision == NULL) {",
            "\t\treturn -EINVAL;",
            "\t}",
            "\t*decision = channel_catalog[state][control];",
            "\treturn 0;",
            "}",
            "",
            "int pqcp_channel_policy_catalog_audit(void)",
            "{",
            "\tfor (size_t state = 0U;",
            "\t     state < PQCP_CHANNEL_POLICY_STATE_COUNT; ++state) {",
            "\t\tfor (size_t control = 0U;",
            "\t\t     control < PQCP_CHANNEL_POLICY_CONTROL_COUNT;",
            "\t\t     ++control) {",
            "\t\t\tconst struct pqcp_channel_policy_decision *entry =",
            "\t\t\t\t&channel_catalog[state][control];",
            "",
            "\t\t\tif ((size_t)entry->state != state ||",
            "\t\t\t    (size_t)entry->control != control ||",
            "\t\t\t    entry->action >",
            "\t\t\t\tPQCP_CHANNEL_POLICY_CLOSE_ON_FAILURE ||",
            "\t\t\t    entry->next_state < PQCP_CHANNEL_POLICY_NEW ||",
            "\t\t\t    entry->next_state >",
            "\t\t\t\tPQCP_CHANNEL_POLICY_TERMINATED) {",
            "\t\t\t\treturn -EBADMSG;",
            "\t\t\t}",
            "\t\t\tif (entry->action == PQCP_CHANNEL_POLICY_DENY &&",
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
    lines.extend(
        emit_string_function(
            "pqcp_channel_control_kind_str",
            "enum pqcp_channel_control_kind",
            "PQCP_CHANNEL_CONTROL_",
            CHANNEL_CONTROLS,
        )
    )
    lines.extend(
        emit_string_function(
            "pqcp_channel_policy_state_str",
            "enum pqcp_channel_policy_state",
            "PQCP_CHANNEL_POLICY_",
            CHANNEL_STATES,
        )
    )
    return "\n".join(lines)


def runtime_resource_source() -> str:
    lines = [
        "/*",
        " * SPDX-License-Identifier: MIT",
        " *",
        " * Generated exhaustive runtime resource-admission decisions.",
        " * Do not edit by hand.",
        " */",
        "",
        "#include <errno.h>",
        "",
        "#include <pqcp_zephyr/runtime_operations.h>",
        "",
        "static const struct pqcp_runtime_resource_policy_decision",
        "\truntime_resource_catalog",
        "\t[PQCP_RUNTIME_RESOURCE_CONDITION_COUNT]",
        "\t[PQCP_RUNTIME_POLICY_COMMAND_COUNT] = {",
    ]
    for condition in RUNTIME_RESOURCE_CONDITIONS:
        for command in RUNTIME_COMMANDS:
            disposition, concurrency, ttl, penalty, reason, error = (
                runtime_resource_decision(condition, command)
            )
            lines.extend(
                [
                    f"\t[PQCP_RUNTIME_RESOURCE_{condition}]",
                    f"\t[PQCP_RUNTIME_COMMAND_{command}] = {{",
                    f"\t\t.condition = PQCP_RUNTIME_RESOURCE_{condition},",
                    f"\t\t.command = PQCP_RUNTIME_COMMAND_{command},",
                    f"\t\t.disposition = PQCP_RUNTIME_RESOURCE_{disposition},",
                    f"\t\t.maximum_concurrency = {concurrency}U,",
                    f"\t\t.reservation_ttl_ms = {ttl}U,",
                    f"\t\t.priority_penalty = {penalty}U,",
                    f"\t\t.reason_mask = {reason}U,",
                    f"\t\t.error = {error},",
                    "\t},",
                ]
            )
    lines.extend(
        [
            "};",
            "",
            "int pqcp_runtime_resource_policy_lookup(",
            "\tenum pqcp_runtime_resource_condition condition,",
            "\tenum pqcp_runtime_command_kind command,",
            "\tstruct pqcp_runtime_resource_policy_decision *decision)",
            "{",
            "\tif (condition < PQCP_RUNTIME_RESOURCE_AVAILABLE ||",
            "\t    condition >= PQCP_RUNTIME_RESOURCE_CONDITION_COUNT ||",
            "\t    command < PQCP_RUNTIME_COMMAND_NONE ||",
            "\t    command >= PQCP_RUNTIME_COMMAND_KIND_COUNT ||",
            "\t    decision == NULL) {",
            "\t\treturn -EINVAL;",
            "\t}",
            "\t*decision = runtime_resource_catalog[condition][command];",
            "\treturn 0;",
            "}",
            "",
            "int pqcp_runtime_resource_policy_catalog_audit(void)",
            "{",
            "\tfor (size_t condition = 0U;",
            "\t     condition < PQCP_RUNTIME_RESOURCE_CONDITION_COUNT;",
            "\t     ++condition) {",
            "\t\tfor (size_t command = 0U;",
            "\t\t     command < PQCP_RUNTIME_POLICY_COMMAND_COUNT;",
            "\t\t     ++command) {",
            "\t\t\tconst struct pqcp_runtime_resource_policy_decision",
            "\t\t\t\t*entry =",
            "\t\t\t\t\t&runtime_resource_catalog",
            "\t\t\t\t\t\t[condition][command];",
            "",
            "\t\t\tif ((size_t)entry->condition != condition ||",
            "\t\t\t    (size_t)entry->command != command ||",
            "\t\t\t    entry->disposition >",
            "\t\t\t\tPQCP_RUNTIME_RESOURCE_REQUIRE_RECOVERY ||",
            "\t\t\t    entry->reason_mask == 0U) {",
            "\t\t\t\treturn -EBADMSG;",
            "\t\t\t}",
            "\t\t\tif (entry->disposition ==",
            "\t\t\t\t    PQCP_RUNTIME_RESOURCE_DENY &&",
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


def runtime_recovery_source() -> str:
    lines = [
        "/*",
        " * SPDX-License-Identifier: MIT",
        " *",
        " * Generated exhaustive runtime recovery decisions.",
        " * Do not edit by hand.",
        " */",
        "",
        "#include <errno.h>",
        "",
        "#include <pqcp_zephyr/runtime_operations.h>",
        "",
        "static const struct pqcp_runtime_recovery_policy_decision",
        "\truntime_recovery_catalog",
        "\t[PQCP_RUNTIME_RECOVERY_CONDITION_COUNT]",
        "\t[PQCP_RUNTIME_POLICY_COMMAND_COUNT] = {",
    ]
    for condition in RUNTIME_RECOVERY_CONDITIONS:
        for command in RUNTIME_COMMANDS:
            directive, next_state, attempts, delay, reason, error = (
                runtime_recovery_decision(condition, command)
            )
            lines.extend(
                [
                    f"\t[PQCP_RUNTIME_RECOVERY_{condition}]",
                    f"\t[PQCP_RUNTIME_COMMAND_{command}] = {{",
                    f"\t\t.condition = PQCP_RUNTIME_RECOVERY_{condition},",
                    f"\t\t.command = PQCP_RUNTIME_COMMAND_{command},",
                    f"\t\t.directive = PQCP_RUNTIME_RECOVERY_{directive},",
                    f"\t\t.next_state = PQCP_RUNTIME_POLICY_{next_state},",
                    f"\t\t.maximum_attempts = {attempts}U,",
                    f"\t\t.delay_ms = {delay}U,",
                    f"\t\t.reason_mask = {reason}U,",
                    f"\t\t.error = {error},",
                    "\t},",
                ]
            )
    lines.extend(
        [
            "};",
            "",
            "int pqcp_runtime_recovery_policy_lookup(",
            "\tenum pqcp_runtime_recovery_condition condition,",
            "\tenum pqcp_runtime_command_kind command,",
            "\tstruct pqcp_runtime_recovery_policy_decision *decision)",
            "{",
            "\tif (condition < PQCP_RUNTIME_RECOVERY_HEALTHY ||",
            "\t    condition >= PQCP_RUNTIME_RECOVERY_CONDITION_COUNT ||",
            "\t    command < PQCP_RUNTIME_COMMAND_NONE ||",
            "\t    command >= PQCP_RUNTIME_COMMAND_KIND_COUNT ||",
            "\t    decision == NULL) {",
            "\t\treturn -EINVAL;",
            "\t}",
            "\t*decision = runtime_recovery_catalog[condition][command];",
            "\treturn 0;",
            "}",
            "",
            "int pqcp_runtime_recovery_policy_catalog_audit(void)",
            "{",
            "\tfor (size_t condition = 0U;",
            "\t     condition < PQCP_RUNTIME_RECOVERY_CONDITION_COUNT;",
            "\t     ++condition) {",
            "\t\tfor (size_t command = 0U;",
            "\t\t     command < PQCP_RUNTIME_POLICY_COMMAND_COUNT;",
            "\t\t     ++command) {",
            "\t\t\tconst struct pqcp_runtime_recovery_policy_decision",
            "\t\t\t\t*entry =",
            "\t\t\t\t\t&runtime_recovery_catalog",
            "\t\t\t\t\t\t[condition][command];",
            "",
            "\t\t\tif ((size_t)entry->condition != condition ||",
            "\t\t\t    (size_t)entry->command != command ||",
            "\t\t\t    entry->directive >",
            "\t\t\t\tPQCP_RUNTIME_RECOVERY_TERMINATE ||",
            "\t\t\t    entry->next_state <",
            "\t\t\t\tPQCP_RUNTIME_POLICY_UNINITIALIZED ||",
            "\t\t\t    entry->next_state >",
            "\t\t\t\tPQCP_RUNTIME_POLICY_TERMINATED ||",
            "\t\t\t    entry->reason_mask == 0U) {",
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


def channel_path_policy_source() -> str:
    lines = [
        "/*",
        " * SPDX-License-Identifier: MIT",
        " *",
        " * Generated exhaustive protected-channel path decisions.",
        " * Do not edit by hand.",
        " */",
        "",
        "#include <errno.h>",
        "",
        "#include <pqcp_zephyr/protected_channel_operations.h>",
        "",
        "static const struct pqcp_channel_path_policy_decision",
        "\tchannel_path_catalog",
        "\t[PQCP_CHANNEL_PATH_CONDITION_COUNT]",
        "\t[PQCP_CHANNEL_POLICY_CONTROL_COUNT] = {",
    ]
    for condition in CHANNEL_PATH_CONDITIONS:
        for control in CHANNEL_CONTROLS:
            disposition, timeout, hysteresis, reason, next_state, error = (
                channel_path_decision(condition, control)
            )
            lines.extend(
                [
                    f"\t[PQCP_CHANNEL_PATH_CONDITION_{condition}]",
                    f"\t[PQCP_CHANNEL_CONTROL_{control}] = {{",
                    f"\t\t.condition = PQCP_CHANNEL_PATH_CONDITION_{condition},",
                    f"\t\t.control = PQCP_CHANNEL_CONTROL_{control},",
                    f"\t\t.disposition = PQCP_CHANNEL_PATH_{disposition},",
                    f"\t\t.probe_timeout_ms = {timeout}U,",
                    f"\t\t.migration_hysteresis_bps = {hysteresis}U,",
                    f"\t\t.reason_mask = {reason}U,",
                    f"\t\t.next_state = PQCP_CHANNEL_POLICY_{next_state},",
                    f"\t\t.error = {error},",
                    "\t},",
                ]
            )
    lines.extend(
        [
            "};",
            "",
            "int pqcp_channel_path_policy_lookup(",
            "\tenum pqcp_channel_path_condition condition,",
            "\tenum pqcp_channel_control_kind control,",
            "\tstruct pqcp_channel_path_policy_decision *decision)",
            "{",
            "\tif (condition <",
            "\t\t    PQCP_CHANNEL_PATH_CONDITION_PRIMARY_HEALTHY ||",
            "\t    condition >= PQCP_CHANNEL_PATH_CONDITION_COUNT ||",
            "\t    control < PQCP_CHANNEL_CONTROL_NONE ||",
            "\t    control >= PQCP_CHANNEL_CONTROL_KIND_COUNT ||",
            "\t    decision == NULL) {",
            "\t\treturn -EINVAL;",
            "\t}",
            "\t*decision = channel_path_catalog[condition][control];",
            "\treturn 0;",
            "}",
            "",
            "int pqcp_channel_path_policy_catalog_audit(void)",
            "{",
            "\tfor (size_t condition = 0U;",
            "\t     condition < PQCP_CHANNEL_PATH_CONDITION_COUNT;",
            "\t     ++condition) {",
            "\t\tfor (size_t control = 0U;",
            "\t\t     control < PQCP_CHANNEL_POLICY_CONTROL_COUNT;",
            "\t\t     ++control) {",
            "\t\t\tconst struct pqcp_channel_path_policy_decision",
            "\t\t\t\t*entry =",
            "\t\t\t\t\t&channel_path_catalog",
            "\t\t\t\t\t\t[condition][control];",
            "",
            "\t\t\tif ((size_t)entry->condition != condition ||",
            "\t\t\t    (size_t)entry->control != control ||",
            "\t\t\t    entry->disposition >",
            "\t\t\t\tPQCP_CHANNEL_PATH_CLOSE ||",
            "\t\t\t    entry->next_state <",
            "\t\t\t\tPQCP_CHANNEL_POLICY_NEW ||",
            "\t\t\t    entry->next_state >",
            "\t\t\t\tPQCP_CHANNEL_POLICY_TERMINATED ||",
            "\t\t\t    entry->reason_mask == 0U) {",
            "\t\t\t\treturn -EBADMSG;",
            "\t\t\t}",
            "\t\t\tif (entry->disposition ==",
            "\t\t\t\t    PQCP_CHANNEL_PATH_DENY &&",
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


def channel_fault_policy_source() -> str:
    lines = [
        "/*",
        " * SPDX-License-Identifier: MIT",
        " *",
        " * Generated exhaustive protected-channel fault decisions.",
        " * Do not edit by hand.",
        " */",
        "",
        "#include <errno.h>",
        "",
        "#include <pqcp_zephyr/protected_channel_operations.h>",
        "",
        "static const struct pqcp_channel_fault_policy_decision",
        "\tchannel_fault_catalog",
        "\t[PQCP_CHANNEL_FAULT_CONDITION_COUNT]",
        "\t[PQCP_CHANNEL_POLICY_CONTROL_COUNT] = {",
    ]
    for condition in CHANNEL_FAULT_CONDITIONS:
        for control in CHANNEL_CONTROLS:
            directive, next_state, attempts, delay, reason, error = (
                channel_fault_decision(condition, control)
            )
            lines.extend(
                [
                    f"\t[PQCP_CHANNEL_FAULT_{condition}]",
                    f"\t[PQCP_CHANNEL_CONTROL_{control}] = {{",
                    f"\t\t.condition = PQCP_CHANNEL_FAULT_{condition},",
                    f"\t\t.control = PQCP_CHANNEL_CONTROL_{control},",
                    f"\t\t.directive = PQCP_CHANNEL_FAULT_{directive},",
                    f"\t\t.next_state = PQCP_CHANNEL_POLICY_{next_state},",
                    f"\t\t.maximum_attempts = {attempts}U,",
                    f"\t\t.delay_ms = {delay}U,",
                    f"\t\t.reason_mask = {reason}U,",
                    f"\t\t.error = {error},",
                    "\t},",
                ]
            )
    lines.extend(
        [
            "};",
            "",
            "int pqcp_channel_fault_policy_lookup(",
            "\tenum pqcp_channel_fault_condition condition,",
            "\tenum pqcp_channel_control_kind control,",
            "\tstruct pqcp_channel_fault_policy_decision *decision)",
            "{",
            "\tif (condition < PQCP_CHANNEL_FAULT_NONE ||",
            "\t    condition >= PQCP_CHANNEL_FAULT_CONDITION_COUNT ||",
            "\t    control < PQCP_CHANNEL_CONTROL_NONE ||",
            "\t    control >= PQCP_CHANNEL_CONTROL_KIND_COUNT ||",
            "\t    decision == NULL) {",
            "\t\treturn -EINVAL;",
            "\t}",
            "\t*decision = channel_fault_catalog[condition][control];",
            "\treturn 0;",
            "}",
            "",
            "int pqcp_channel_fault_policy_catalog_audit(void)",
            "{",
            "\tfor (size_t condition = 0U;",
            "\t     condition < PQCP_CHANNEL_FAULT_CONDITION_COUNT;",
            "\t     ++condition) {",
            "\t\tfor (size_t control = 0U;",
            "\t\t     control < PQCP_CHANNEL_POLICY_CONTROL_COUNT;",
            "\t\t     ++control) {",
            "\t\t\tconst struct pqcp_channel_fault_policy_decision",
            "\t\t\t\t*entry =",
            "\t\t\t\t\t&channel_fault_catalog",
            "\t\t\t\t\t\t[condition][control];",
            "",
            "\t\t\tif ((size_t)entry->condition != condition ||",
            "\t\t\t    (size_t)entry->control != control ||",
            "\t\t\t    entry->directive >",
            "\t\t\t\tPQCP_CHANNEL_FAULT_TERMINATE_CHANNEL ||",
            "\t\t\t    entry->next_state <",
            "\t\t\t\tPQCP_CHANNEL_POLICY_NEW ||",
            "\t\t\t    entry->next_state >",
            "\t\t\t\tPQCP_CHANNEL_POLICY_TERMINATED ||",
            "\t\t\t    entry->reason_mask == 0U) {",
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
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="directory for the generated C sources (default: <repo>/build/generated)",
    )
    args = parser.parse_args()
    out_dir = (args.output_dir or args.repo_root / "build" / "generated").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    root = args.repo_root.resolve()
    results = [
        update_file(
            out_dir / "runtime_policy_catalog.c",
            runtime_source(),
            args.check,
        ),
        update_file(
            out_dir / "protected_channel_policy_catalog.c",
            channel_source(),
            args.check,
        ),
        update_file(
            out_dir / "runtime_resource_policy_catalog.c",
            runtime_resource_source(),
            args.check,
        ),
        update_file(
            out_dir / "runtime_recovery_policy_catalog.c",
            runtime_recovery_source(),
            args.check,
        ),
        update_file(
            out_dir / "protected_channel_path_policy_catalog.c",
            channel_path_policy_source(),
            args.check,
        ),
        update_file(
            out_dir / "protected_channel_fault_policy_catalog.c",
            channel_fault_policy_source(),
            args.check,
        ),
    ]
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
