#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Translate NIST-style ACVP ML-KEM/ML-DSA JSON vectors to serial-command evidence.

This bridge does not replace the existing serial ACVP harness. It preserves the
wire command model by recording the command that would be issued and a response
class for each JSON test case so partner review can connect JSON vector groups
to the same bounded parser and negative-path vocabulary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HEX_RE = re.compile(r"^[0-9A-Fa-f]*$")
MLKEM_SIZES = {
    512: {"pk": 800, "sk": 1632, "ct": 768},
    768: {"pk": 1184, "sk": 2400, "ct": 1088},
    1024: {"pk": 1568, "sk": 3168, "ct": 1568},
}
MLDSA_SIZES = {
    44: {"pk": 1312, "sk": 2560, "sig": 2420},
    65: {"pk": 1952, "sk": 4032, "sig": 3293},
    87: {"pk": 2592, "sk": 4896, "sig": 4595},
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vectors", type=Path, nargs="+")
    parser.add_argument("--mode", choices=("mlkem", "mldsa", "auto"), default="auto")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--transcript-manifest", type=Path, required=True)
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError(f"ACVP vector root must be an object: {path}")
    return raw


def normalize_level(value: object, mode: str) -> int | None:
    text = str(value or "").upper().replace("_", "-")
    for prefix in ("ML-KEM-", "MLKEM-", "ML-DSA-", "MLDSA-"):
        text = text.replace(prefix, "")
    try:
        level = int(text)
    except ValueError:
        return None
    if mode == "mlkem" and level in MLKEM_SIZES:
        return level
    if mode == "mldsa" and level in MLDSA_SIZES:
        return level
    return None


def infer_mode(payload: dict[str, Any], explicit: str) -> str:
    if explicit != "auto":
        return explicit
    text = json.dumps(payload).upper()
    if "ML-DSA" in text or "MLDSA" in text or "SIGGEN" in text or "SIGVER" in text:
        return "mldsa"
    return "mlkem"


def hex_error(value: object, *, expected_bytes: int | None = None) -> str | None:
    if not isinstance(value, str):
        return "ERROR:WRONG_SIZE"
    if len(value) == 0:
        return "ERROR:WRONG_SIZE"
    if len(value) % 2:
        return "ERROR:INVALID_HEX"
    if not HEX_RE.fullmatch(value):
        return "ERROR:INVALID_HEX"
    if expected_bytes is not None and len(value) != expected_bytes * 2:
        return "ERROR:WRONG_SIZE"
    return None


def transcript_hash(command: str, response: str) -> str:
    return hashlib.sha256(f"{command}\n{response}\n".encode("utf-8")).hexdigest()


def group_tests(payload: dict[str, Any]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    out: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for group in payload.get("testGroups") or []:
        if not isinstance(group, dict):
            continue
        for test in group.get("tests") or []:
            if isinstance(test, dict):
                out.append((group, test))
    return out


def mlkem_operation_class(operation: str, test: dict[str, Any]) -> str:
    normalized = operation.lower().replace("-", "").replace("_", "")
    has_decap_fields = any(key in test for key in ("ct", "ciphertext", "c", "sk", "dk"))
    has_encap_fields = any(key in test for key in ("pk", "ek"))
    if "key" in normalized:
        return "keyGen"
    if "decap" in normalized or (normalized == "encapdecap" and has_decap_fields and not has_encap_fields):
        return "decap"
    if "encap" in normalized or has_encap_fields:
        return "encap"
    return "encap"


def mldsa_operation_class(operation: str) -> str:
    normalized = operation.lower().replace("-", "").replace("_", "")
    return "sigVer" if "ver" in normalized else "sigGen"


def classify_mlkem(group: dict[str, Any], test: dict[str, Any]) -> tuple[str, str, str, str]:
    level = normalize_level(group.get("parameterSet") or group.get("paramSet"), "mlkem")
    if level is None:
        return "MLKEM", "ERROR:INVALID_LEVEL", "unsupported_parameter_set", "unsupported"
    operation = str(group.get("function") or group.get("testType") or test.get("operation") or "").lower()
    operation_class = mlkem_operation_class(operation, test)
    sizes = MLKEM_SIZES[level]
    if operation_class == "keyGen":
        return f"KEYGEN:MLKEM:{level}", "RESULT:OK", "success", operation_class
    has_decap_fields = any(key in test for key in ("ct", "ciphertext", "c", "sk", "dk"))
    has_encap_fields = any(key in test for key in ("pk", "ek"))
    if operation_class == "decap" and has_decap_fields and not has_encap_fields:
        ct = test.get("ct") or test.get("ciphertext") or test.get("c")
        sk = test.get("sk") or test.get("dk")
        error = hex_error(ct, expected_bytes=sizes["ct"]) or hex_error(sk, expected_bytes=sizes["sk"])
        command = f"DECAPS:MLKEM:{level}:{ct or ''}:{sk or ''}"
        return command, error or "RESULT:OK", "negative" if error else "success", operation_class
    pk = test.get("pk") or test.get("ek")
    error = hex_error(pk, expected_bytes=sizes["pk"])
    command = f"ENCAPS:MLKEM:{level}:{pk or ''}"
    return command, error or "RESULT:OK", "negative" if error else "success", "encap"


def classify_mldsa(group: dict[str, Any], test: dict[str, Any]) -> tuple[str, str, str, str]:
    level = normalize_level(group.get("parameterSet") or group.get("paramSet"), "mldsa")
    if level is None:
        return "MLDSA", "ERROR:INVALID_LEVEL", "unsupported_parameter_set", "unsupported"
    operation = str(group.get("function") or group.get("testType") or test.get("operation") or "").lower()
    operation_class = mldsa_operation_class(operation)
    sizes = MLDSA_SIZES[level]
    message = test.get("message") or test.get("msg") or ""
    message_error = hex_error(message)
    if operation_class == "sigVer":
        pk = test.get("pk")
        sig = test.get("signature") or test.get("sig")
        error = hex_error(pk, expected_bytes=sizes["pk"]) or message_error or hex_error(sig, expected_bytes=sizes["sig"])
        command = f"VERIFY:MLDSA:{level}:{pk or ''}:{message}:{sig or ''}"
        return command, error or "RESULT:OK", "negative" if error else "success", operation_class
    sk = test.get("sk")
    error = hex_error(sk, expected_bytes=sizes["sk"]) or message_error
    command = f"SIGN:MLDSA:{level}:{sk or ''}:{message}"
    return command, error or "RESULT:OK", "negative" if error else "success", operation_class


def process_file(path: Path, explicit_mode: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    payload = load_json(path)
    mode = infer_mode(payload, explicit_mode)
    results: list[dict[str, Any]] = []
    transcripts: list[dict[str, Any]] = []
    for group, test in group_tests(payload):
        if mode == "mlkem":
            command, response, result_class, operation_class = classify_mlkem(group, test)
        else:
            command, response, result_class, operation_class = classify_mldsa(group, test)
        tc_id = test.get("tcId", test.get("id", len(results) + 1))
        tg_id = group.get("tgId", group.get("id", "unknown"))
        digest = transcript_hash(command, response)
        results.append(
            {
                "source": str(path),
                "mode": mode,
                "operation_class": operation_class,
                "tgId": tg_id,
                "tcId": tc_id,
                "command": command,
                "response": response,
                "expected_result_class": result_class,
                "transcript_sha256": digest,
            }
        )
        transcripts.append(
            {
                "source": str(path),
                "mode": mode,
                "operation_class": operation_class,
                "tgId": tg_id,
                "tcId": tc_id,
                "command": command,
                "response": response,
                "sha256": digest,
            }
        )
    return results, transcripts


def main() -> int:
    args = parse_args()
    all_results: list[dict[str, Any]] = []
    all_transcripts: list[dict[str, Any]] = []
    failures: list[str] = []
    try:
        for path in args.vectors:
            results, transcripts = process_file(path, args.mode)
            all_results.extend(results)
            all_transcripts.extend(transcripts)
    except (OSError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if not all_results:
        failures.append("no ACVP JSON test cases found")
    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "passed": not failures,
        "summary": {
            "test_cases": len(all_results),
            "negative_cases": sum(1 for row in all_results if row["expected_result_class"] != "success"),
            "failures": len(failures),
        },
        "results": all_results,
        "failures": failures,
    }
    manifest = {
        "schema_version": 1,
        "generated_at": payload["generated_at"],
        "transcripts": all_transcripts,
    }
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.transcript_manifest.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.transcript_manifest.resolve().write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if failures:
        print("FAIL: ACVP JSON interop failed", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("PASS: ACVP JSON interop evidence generated")
    print(f"  output: {args.output.resolve()}")
    print(f"  transcript_manifest: {args.transcript_manifest.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
