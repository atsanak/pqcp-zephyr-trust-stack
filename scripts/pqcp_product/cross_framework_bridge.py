#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Cross-framework PQC evidence import, comparison, scoring, and planning."""

from __future__ import annotations

import csv
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from statistics import median
from typing import Any, Iterable

from .catalog import ExperimentCatalog
from .deployment_decision import DeploymentScenario
from .errors import Diagnostic, error, warning
from .fs import json_digest, load_json, sha256_file, utc_now, write_json_atomic, write_text_atomic

SOURCE_TYPES = {
    "oqs",
    "pqm4",
    "mupq",
    "rustpq",
    "quantcrypt",
    "supercop",
    "ebacs",
    "mlkem-native",
    "pqc-leo",
    "generic-csv",
    "local",
}

CANONICAL_FIELDS = {
    "framework",
    "source_type",
    "algorithm",
    "parameter_set",
    "operation",
    "implementation",
    "target_architecture",
    "board",
    "device_class",
    "security_level",
    "cycles",
    "latency_us",
    "stack_bytes",
    "heap_bytes",
    "ram_bytes",
    "flash_bytes",
    "energy_uj",
    "compiler",
    "configuration",
    "benchmark_context",
    "reproducibility",
    "verification_status",
}

DEFAULT_ALIASES: dict[str, tuple[str, ...]] = {
    "algorithm": ("algorithm", "alg", "scheme", "primitive", "kem", "sig"),
    "parameter_set": ("parameter_set", "parameter", "param", "level", "variant", "claimed_nist_level"),
    "operation": ("operation", "op", "primitive_op", "bench", "test"),
    "implementation": ("implementation", "impl", "backend", "variant_impl"),
    "target_architecture": ("target_architecture", "arch", "architecture", "cpu", "platform"),
    "board": ("board", "target", "device", "platform_name", "machine"),
    "device_class": ("device_class", "target_class", "platform_class"),
    "security_level": ("security_level", "nist_level", "level"),
    "cycles": ("cycles", "median_cycles", "cycles_median", "median", "cpucycles"),
    "latency_us": ("latency_us", "time_us", "median_us", "us"),
    "stack_bytes": ("stack_bytes", "stack", "stack_usage", "stack_b"),
    "heap_bytes": ("heap_bytes", "heap", "malloc_bytes"),
    "ram_bytes": ("ram_bytes", "ram", "memory", "sram", "working_set"),
    "flash_bytes": ("flash_bytes", "flash", "rom", "code_size", "text_bytes"),
    "energy_uj": ("energy_uj", "energy", "uj"),
    "compiler": ("compiler", "toolchain", "cc"),
    "configuration": ("configuration", "config", "flags", "opt"),
    "benchmark_context": ("benchmark_context", "context", "source", "dataset"),
    "reproducibility": ("reproducibility", "repro", "runs"),
    "verification_status": ("verification_status", "status", "state"),
}


@dataclass(frozen=True)
class FrameworkSource:
    source_name: str
    source_type: str
    supported_algorithms: tuple[str, ...]
    operations: tuple[str, ...]
    target_class: str
    result_fields: tuple[str, ...]
    confidence_level: str
    limitations: tuple[str, ...]
    import_status: str
    local_model_compatibility: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_name": self.source_name,
            "source_type": self.source_type,
            "supported_algorithms": list(self.supported_algorithms),
            "operations": list(self.operations),
            "target_class": self.target_class,
            "result_fields": list(self.result_fields),
            "confidence_level": self.confidence_level,
            "limitations": list(self.limitations),
            "import_status": self.import_status,
            "local_model_compatibility": self.local_model_compatibility,
        }


@dataclass(frozen=True)
class NormalizedEvidenceRecord:
    framework: str
    source_type: str
    source_file: str
    row_number: int
    algorithm: str
    parameter_set: str
    operation: str
    implementation: str
    target_architecture: str
    board: str
    device_class: str
    security_level: int | None = None
    cycles: float | None = None
    latency_us: float | None = None
    stack_bytes: float | None = None
    heap_bytes: float | None = None
    ram_bytes: float | None = None
    flash_bytes: float | None = None
    energy_uj: float | None = None
    benchmark_context: str = ""
    compiler: str = ""
    configuration: str = ""
    reproducibility: str = ""
    source_confidence: float = 0.5
    verification_status: str = ""
    import_warnings: tuple[str, ...] = ()
    missing_fields: tuple[str, ...] = ()
    raw_digest: str = ""

    def key(self) -> tuple[str, str, str, str]:
        return (self.algorithm, self.parameter_set, self.operation, self.target_class())

    def option_key(self) -> tuple[str, str, str]:
        return (self.algorithm, self.parameter_set, self.target_class())

    def target_class(self) -> str:
        if self.device_class:
            return self.device_class
        if self.board:
            board = self.board.lower()
            if "nucleo" in board or "stm32" in board:
                return "cortex-m"
            if "qemu" in board:
                return "qemu"
            if "native" in board:
                return "native-host"
            return board
        return self.target_architecture or "unknown"

    def numeric_metrics(self) -> dict[str, float]:
        out = {}
        for name in ("cycles", "latency_us", "stack_bytes", "heap_bytes", "ram_bytes", "flash_bytes", "energy_uj"):
            value = getattr(self, name)
            if value is not None and not math.isnan(value):
                out[name] = value
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "source_type": self.source_type,
            "source_file": self.source_file,
            "row_number": self.row_number,
            "algorithm": self.algorithm,
            "parameter_set": self.parameter_set,
            "operation": self.operation,
            "implementation": self.implementation,
            "target_architecture": self.target_architecture,
            "board": self.board,
            "device_class": self.device_class,
            "security_level": self.security_level,
            "cycles": self.cycles,
            "latency_us": self.latency_us,
            "stack_bytes": self.stack_bytes,
            "heap_bytes": self.heap_bytes,
            "ram_bytes": self.ram_bytes,
            "flash_bytes": self.flash_bytes,
            "energy_uj": self.energy_uj,
            "benchmark_context": self.benchmark_context,
            "compiler": self.compiler,
            "configuration": self.configuration,
            "reproducibility": self.reproducibility,
            "source_confidence": round(self.source_confidence, 4),
            "verification_status": self.verification_status,
            "import_warnings": list(self.import_warnings),
            "missing_fields": list(self.missing_fields),
            "raw_digest": self.raw_digest,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "NormalizedEvidenceRecord":
        return cls(
            framework=str(raw.get("framework", "")),
            source_type=str(raw.get("source_type", "")),
            source_file=str(raw.get("source_file", "")),
            row_number=int(raw.get("row_number", 0) or 0),
            algorithm=str(raw.get("algorithm", "")),
            parameter_set=str(raw.get("parameter_set", "")),
            operation=str(raw.get("operation", "")),
            implementation=str(raw.get("implementation", "")),
            target_architecture=str(raw.get("target_architecture", "")),
            board=str(raw.get("board", "")),
            device_class=str(raw.get("device_class", "")),
            security_level=_optional_int(raw.get("security_level")),
            cycles=_optional_float(raw.get("cycles")),
            latency_us=_optional_float(raw.get("latency_us")),
            stack_bytes=_optional_float(raw.get("stack_bytes")),
            heap_bytes=_optional_float(raw.get("heap_bytes")),
            ram_bytes=_optional_float(raw.get("ram_bytes")),
            flash_bytes=_optional_float(raw.get("flash_bytes")),
            energy_uj=_optional_float(raw.get("energy_uj")),
            benchmark_context=str(raw.get("benchmark_context", "")),
            compiler=str(raw.get("compiler", "")),
            configuration=str(raw.get("configuration", "")),
            reproducibility=str(raw.get("reproducibility", "")),
            source_confidence=float(raw.get("source_confidence", 0.5) or 0.5),
            verification_status=str(raw.get("verification_status", "")),
            import_warnings=tuple(str(item) for item in raw.get("import_warnings", [])),
            missing_fields=tuple(str(item) for item in raw.get("missing_fields", [])),
            raw_digest=str(raw.get("raw_digest", "")),
        )


def framework_sources() -> dict[str, FrameworkSource]:
    return {
        "oqs": FrameworkSource(
            "Open Quantum Safe / liboqs",
            "oqs",
            ("ML-KEM", "ML-DSA", "SLH-DSA", "HQC", "FrodoKEM", "BIKE", "Classic McEliece", "Falcon", "SPHINCS+"),
            ("keygen", "encaps", "decaps", "sign", "verify"),
            "host-library",
            ("algorithm", "operation", "cycles", "latency_us", "implementation", "compiler"),
            "medium-high",
            ("host-library benchmark context is not automatically embedded-target comparable",),
            "csv/json adapter",
            "compatible after target-class and implementation metadata are attached",
        ),
        "pqm4": FrameworkSource(
            "mupq / pqm4",
            "pqm4",
            ("ML-KEM", "ML-DSA", "HQC", "Saber", "NTRU", "Falcon", "SPHINCS+"),
            ("keygen", "encaps", "decaps", "sign", "verify"),
            "cortex-m4",
            ("cycles", "stack_bytes", "flash_bytes", "implementation", "board"),
            "high-for-embedded",
            ("board/toolchain details must be preserved for fair comparison",),
            "csv/text adapter",
            "highly compatible with constrained-target evidence after normalization",
        ),
        "mupq": FrameworkSource(
            "mupq generic",
            "mupq",
            ("PQC KEMs", "PQC signatures"),
            ("keygen", "encaps", "decaps", "sign", "verify"),
            "embedded-benchmark-harness",
            ("cycles", "stack_bytes", "implementation", "target_architecture"),
            "medium-high",
            ("format varies by harness and target",),
            "generic CSV/text adapter",
            "compatible when imported with aliases",
        ),
        "rustpq": FrameworkSource(
            "rustpq / pqcrypto",
            "rustpq",
            ("ML-KEM", "ML-DSA", "Classic McEliece", "Falcon", "SPHINCS+"),
            ("keygen", "encaps", "decaps", "sign", "verify"),
            "rust-library",
            ("algorithm", "operation", "latency_us", "implementation"),
            "medium",
            ("library API evidence is not the same as Zephyr firmware evidence",),
            "generic CSV adapter",
            "compatible as external reference evidence only",
        ),
        "quantcrypt": FrameworkSource(
            "QuantCrypt",
            "quantcrypt",
            ("ML-KEM", "ML-DSA", "SLH-DSA"),
            ("keygen", "encaps", "decaps", "sign", "verify"),
            "python-library",
            ("algorithm", "operation", "latency_us", "implementation"),
            "medium",
            ("Python package evidence is useful for workflow comparison, not embedded performance",),
            "generic CSV adapter",
            "compatible as API/workflow reference evidence",
        ),
        "supercop": FrameworkSource(
            "SUPERCOP / eBACS",
            "supercop",
            ("PQC KEMs", "PQC signatures", "classical primitives"),
            ("keygen", "encaps", "decaps", "sign", "verify"),
            "cross-platform-benchmark-table",
            ("cycles", "implementation", "target_architecture", "compiler"),
            "high-for-benchmarking",
            ("simple tables require context before embedded deployment interpretation",),
            "simple table adapter",
            "compatible after operation and platform context are normalized",
        ),
        "mlkem-native": FrameworkSource(
            "PQ Code Package mlkem-native issue/status evidence",
            "mlkem-native",
            ("ML-KEM",),
            ("status", "keygen", "encaps", "decaps"),
            "backend-status",
            ("verification_status", "implementation", "configuration"),
            "medium",
            ("issue metadata is maturity/status evidence, not benchmark evidence",),
            "json status adapter",
            "compatible as backend maturity and verification-status evidence",
        ),
        "pqc-leo": FrameworkSource(
            "PQC-LEO",
            "pqc-leo",
            ("PQC KEMs", "PQC signatures"),
            ("benchmark", "evaluation"),
            "deployment-evaluation",
            ("latency_us", "energy_uj", "device_class"),
            "medium",
            ("format and target assumptions must be preserved",),
            "generic CSV adapter",
            "compatible as external deployment-evaluation evidence",
        ),
        "local": FrameworkSource(
            "Local Zephyr/QEMU evidence pack",
            "local",
            ("ML-KEM", "ML-DSA"),
            ("keygen", "encaps", "decaps", "sign", "verify", "handshake"),
            "zephyr-qemu-and-board",
            ("cycles", "latency_us", "stack_bytes", "ram_bytes", "flash_bytes", "artifacts"),
            "high-for-this-repo",
            ("QEMU is regression evidence unless promoted to physical hardware",),
            "native evidence-pack and CSV adapter",
            "canonical local evidence model",
        ),
    }


def import_external_evidence(
    *,
    source_type: str,
    input_paths: list[Path],
    output_root: Path,
    aliases: dict[str, str] | None = None,
) -> dict[str, Any]:
    if source_type not in SOURCE_TYPES:
        raise ValueError(f"unsupported source_type: {source_type}")
    output_root.mkdir(parents=True, exist_ok=True)
    diagnostics: list[Diagnostic] = []
    records: list[NormalizedEvidenceRecord] = []
    for path in input_paths:
        if not path.exists():
            diagnostics.append(error("bridge_input_missing", str(path), "input evidence file is missing"))
            continue
        try:
            if source_type == "mlkem-native":
                records.extend(_import_mlkem_status(path, diagnostics))
            elif source_type == "oqs":
                records.extend(_import_oqs(path, diagnostics, aliases or {}))
            elif source_type in {"pqm4", "mupq"}:
                records.extend(_import_pqm4(path, source_type, diagnostics, aliases or {}))
            elif source_type in {"supercop", "ebacs"}:
                records.extend(_import_supercop(path, diagnostics, aliases or {}))
            else:
                records.extend(_import_generic(path, source_type, diagnostics, aliases or {}))
        except Exception as exc:
            diagnostics.append(error("bridge_import_failed", str(path), str(exc)))
    result = _normalized_payload(source_type, input_paths, records, diagnostics)
    normalized_json = output_root / "normalized-evidence.json"
    normalized_csv = output_root / "normalized-evidence.csv"
    write_json_atomic(normalized_json, result)
    write_text_atomic(normalized_csv, _records_csv(records))
    manifest = _cross_framework_manifest(
        source_type=source_type,
        input_paths=input_paths,
        normalized_json=normalized_json,
        normalized_csv=normalized_csv,
        records=records,
        diagnostics=diagnostics,
    )
    write_json_atomic(output_root / "cross-framework-evidence-manifest.json", manifest)
    return result


def verify_cross_framework_evidence_manifest(
    *,
    manifest_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    diagnostics: list[Diagnostic] = []
    if not manifest_path.exists():
        diagnostics.append(error("bridge_manifest_missing", str(manifest_path), "cross-framework evidence manifest is missing"))
        result = _manifest_verification_result(manifest_path, [], diagnostics)
        write_json_atomic(output_root / "cross-framework-evidence-manifest-result.json", result)
        write_text_atomic(output_root / "cross-framework-evidence-manifest-result.md", _render_manifest_verification(result))
        return result

    manifest = load_json(manifest_path)
    manifest_root = manifest_path.parent
    checks: list[dict[str, Any]] = []
    artifacts = manifest.get("normalized_artifacts", [])
    if not isinstance(artifacts, list) or not artifacts:
        diagnostics.append(error("bridge_manifest_artifacts_missing", str(manifest_path), "manifest does not list normalized artifacts"))
    for artifact in artifacts if isinstance(artifacts, list) else []:
        if not isinstance(artifact, dict):
            diagnostics.append(error("bridge_manifest_artifact_shape", str(manifest_path), "artifact entry must be an object"))
            continue
        rel = str(artifact.get("path", ""))
        expected = str(artifact.get("sha256", ""))
        path = manifest_root / rel
        if not rel or not path.exists():
            diagnostics.append(error("bridge_manifest_artifact_missing", rel or str(manifest_path), "normalized evidence artifact is missing"))
            checks.append({"path": rel, "expected_sha256": expected, "actual_sha256": None, "status": "FAIL"})
            continue
        actual = sha256_file(path)
        status = "PASS" if actual == expected else "FAIL"
        if status == "FAIL":
            diagnostics.append(error("bridge_manifest_hash_mismatch", rel, "normalized evidence artifact hash changed"))
        checks.append({"path": rel, "expected_sha256": expected, "actual_sha256": actual, "status": status})

    for item in manifest.get("input_files", []):
        if not isinstance(item, dict):
            continue
        path_text = str(item.get("path", ""))
        expected = item.get("sha256")
        if not path_text or expected is None:
            continue
        path = Path(path_text)
        if not path.exists():
            diagnostics.append(warning("bridge_source_input_unavailable", path_text, "original input file is not available for source replay"))
            continue
        actual = sha256_file(path)
        if actual != expected:
            diagnostics.append(error("bridge_source_input_hash_mismatch", path_text, "original input file hash changed since import"))

    expected_count = int(manifest.get("record_count", 0) or 0)
    record_digests = manifest.get("record_digests", [])
    if not isinstance(record_digests, list) or len(record_digests) != expected_count:
        diagnostics.append(error("bridge_manifest_record_digest_count", str(manifest_path), "record digest count does not match record_count"))

    result = _manifest_verification_result(manifest_path, checks, diagnostics)
    write_json_atomic(output_root / "cross-framework-evidence-manifest-result.json", result)
    write_text_atomic(output_root / "cross-framework-evidence-manifest-result.md", _render_manifest_verification(result))
    return result


def audit_cross_framework_evidence(
    *,
    evidence_paths: list[Path],
    output_root: Path,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    records, diagnostics = load_normalized_records(evidence_paths)
    if not records:
        diagnostics.append(error("bridge_audit_no_records", ",".join(str(path) for path in evidence_paths), "no normalized evidence records were loaded"))

    duplicate_keys: dict[str, int] = {}
    for record in records:
        digest_key = json_digest(
            {
                "source_type": record.source_type,
                "algorithm": record.algorithm,
                "parameter_set": record.parameter_set,
                "operation": record.operation,
                "implementation": record.implementation,
                "target_class": record.target_class(),
                "metrics": record.numeric_metrics(),
                "raw_digest": record.raw_digest,
            }
        )
        duplicate_keys[digest_key] = duplicate_keys.get(digest_key, 0) + 1
        _audit_record(record, diagnostics)
    duplicate_count = sum(count - 1 for count in duplicate_keys.values() if count > 1)
    if duplicate_count:
        diagnostics.append(error("bridge_audit_duplicate_records", "normalized evidence", f"{duplicate_count} duplicate normalized record(s) detected"))

    source_types = sorted({record.source_type for record in records})
    algorithms = sorted({record.algorithm for record in records if record.algorithm})
    target_classes = sorted({record.target_class() for record in records})
    metric_counts: dict[str, int] = {}
    for record in records:
        for metric in record.numeric_metrics():
            metric_counts[metric] = metric_counts.get(metric, 0) + 1

    comparable_groups = _comparable_group_summaries(records)
    if records and "local" not in source_types:
        diagnostics.append(warning("bridge_audit_local_missing", "normalized evidence", "dataset has external evidence but no local Zephyr/QEMU baseline"))
    if records and len(set(source_types) - {"local"}) == 0:
        diagnostics.append(warning("bridge_audit_external_missing", "normalized evidence", "dataset has local evidence but no independent external baseline"))
    if records and not comparable_groups:
        diagnostics.append(warning("bridge_audit_no_comparable_pairs", "normalized evidence", "no local/external records share algorithm, parameter, operation, target class, and metric"))

    result = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": "FAIL" if any(diag.is_error for diag in diagnostics) else ("WARN" if diagnostics else "PASS"),
        "passed": not any(diag.is_error for diag in diagnostics),
        "summary": {
            "record_count": len(records),
            "source_types": source_types,
            "algorithms": algorithms,
            "target_classes": target_classes,
            "metric_counts": dict(sorted(metric_counts.items())),
            "comparable_group_count": len(comparable_groups),
            "duplicate_record_count": duplicate_count,
        },
        "comparable_groups": comparable_groups,
        "diagnostics": [diag.to_dict() for diag in diagnostics],
    }
    write_json_atomic(output_root / "cross-framework-evidence-audit.json", result)
    write_text_atomic(output_root / "cross-framework-evidence-audit.md", _render_evidence_audit(result))
    return result


def framework_comparability_matrix(
    *,
    evidence_paths: list[Path],
    output_root: Path,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    records, diagnostics = load_normalized_records(evidence_paths)
    pairs: list[dict[str, Any]] = []
    for index, left in enumerate(records):
        for right in records[index + 1 :]:
            if (left.algorithm, left.parameter_set, left.operation) != (right.algorithm, right.parameter_set, right.operation):
                continue
            if left.source_type == right.source_type and left.raw_digest == right.raw_digest:
                continue
            pairs.append(_comparability_pair(left, right))
    gaps = _comparability_gaps(records, pairs)
    if records and not pairs:
        diagnostics.append(warning("bridge_comparability_no_pairs", "normalized evidence", "no same-algorithm/operation evidence pairs were found"))
    if records and not any(pair["status"] == "directly_comparable" for pair in pairs):
        diagnostics.append(warning("bridge_comparability_no_direct_pair", "normalized evidence", "no local/external pair is directly comparable"))
    if gaps:
        diagnostics.append(warning("bridge_comparability_gaps", "normalized evidence", f"{len(gaps)} comparison gap(s) require experiments or metadata"))
    status_counts: dict[str, int] = {}
    for pair in pairs:
        status_counts[pair["status"]] = status_counts.get(pair["status"], 0) + 1
    result = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": "FAIL" if any(diag.is_error for diag in diagnostics) else ("WARN" if diagnostics else "PASS"),
        "passed": not any(diag.is_error for diag in diagnostics),
        "summary": {
            "record_count": len(records),
            "pair_count": len(pairs),
            "status_counts": dict(sorted(status_counts.items())),
            "gap_count": len(gaps),
        },
        "pairs": pairs,
        "gaps": gaps,
        "diagnostics": [diag.to_dict() for diag in diagnostics],
    }
    write_json_atomic(output_root / "cross-framework-comparability-matrix.json", result)
    write_text_atomic(output_root / "cross-framework-comparability-matrix.md", _render_comparability_matrix(result))
    return result


def compare_frameworks(*, evidence_paths: list[Path], output_root: Path) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    records, diagnostics = load_normalized_records(evidence_paths)
    grouped: dict[tuple[str, str, str, str], list[NormalizedEvidenceRecord]] = {}
    for record in records:
        grouped.setdefault(record.key(), []).append(record)
    comparisons: list[dict[str, Any]] = []
    for key, rows in sorted(grouped.items()):
        sources = sorted({row.source_type for row in rows})
        local = [row for row in rows if row.source_type == "local"]
        external = [row for row in rows if row.source_type != "local"]
        numeric = _best_metric_name(rows)
        item = {
            "key": list(key),
            "sources": sources,
            "metric": numeric,
            "status": "not_comparable",
            "reason": "",
            "local_value": None,
            "external_median": None,
            "ratio": None,
        }
        if not local:
            item["reason"] = "external evidence exists but no local Zephyr/QEMU evidence was provided"
            diagnostics.append(warning("bridge_missing_local_baseline", ":".join(key), item["reason"]))
        elif not external:
            item["reason"] = "local evidence exists but no independent external framework baseline was provided"
            diagnostics.append(warning("bridge_missing_external_baseline", ":".join(key), item["reason"]))
        elif numeric is None:
            item["reason"] = "records share a key but have no common numeric metric"
            diagnostics.append(warning("bridge_metric_missing", ":".join(key), item["reason"]))
        else:
            local_values = [_metric_value(row, numeric) for row in local]
            ext_values = [_metric_value(row, numeric) for row in external]
            local_values = [value for value in local_values if value is not None]
            ext_values = [value for value in ext_values if value is not None]
            if not local_values or not ext_values:
                item["reason"] = f"{numeric} is missing from local or external records"
            else:
                local_value = median(local_values)
                ext_value = median(ext_values)
                ratio = local_value / ext_value if ext_value else None
                item.update({"local_value": local_value, "external_median": ext_value, "ratio": ratio})
                if ratio is None:
                    item["status"] = "not_comparable"
                    item["reason"] = "external median is zero"
                elif ratio > 4.0 or ratio < 0.25:
                    item["status"] = "suspicious_disagreement"
                    item["reason"] = "local/external metric differs by more than 4x"
                    diagnostics.append(warning("bridge_suspicious_disagreement", ":".join(key), item["reason"]))
                elif ratio > 1.10:
                    item["status"] = "local_worse"
                    item["reason"] = "local metric is higher than the external median"
                elif ratio < 0.90:
                    item["status"] = "local_better"
                    item["reason"] = "local metric is lower than the external median"
                else:
                    item["status"] = "comparable"
                    item["reason"] = "local and external metrics are within 10 percent"
        comparisons.append(item)
    summary = {
        "total": len(comparisons),
        "comparable": sum(1 for item in comparisons if item["status"] == "comparable"),
        "not_comparable": sum(1 for item in comparisons if item["status"] == "not_comparable"),
        "suspicious": sum(1 for item in comparisons if item["status"] == "suspicious_disagreement"),
    }
    result = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": "WARN" if diagnostics else "PASS",
        "passed": True,
        "summary": summary,
        "comparisons": comparisons,
        "diagnostics": [diag.to_dict() for diag in diagnostics],
    }
    write_json_atomic(output_root / "cross-framework-comparison.json", result)
    write_text_atomic(output_root / "cross-framework-comparison.md", _render_comparison(result))
    return result


def score_evidence(
    *,
    evidence_paths: list[Path],
    output_root: Path,
    scenario_path: Path | None = None,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    records, diagnostics = load_normalized_records(evidence_paths)
    scenario = DeploymentScenario.from_path(scenario_path) if scenario_path else None
    groups: dict[tuple[str, str, str], list[NormalizedEvidenceRecord]] = {}
    for record in records:
        groups.setdefault(record.option_key(), []).append(record)
    scores = [_score_group(key, rows, scenario) for key, rows in sorted(groups.items())]
    scores.sort(key=lambda item: (-item["deployment_confidence"], item["reviewer_risk_score"]))
    result = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": "WARN" if diagnostics else "PASS",
        "passed": True,
        "scenario": scenario.to_dict() if scenario else None,
        "scores": scores,
        "top_option": scores[0] if scores else None,
        "diagnostics": [diag.to_dict() for diag in diagnostics],
    }
    write_json_atomic(output_root / "cross-framework-evidence-scores.json", result)
    write_text_atomic(output_root / "cross-framework-evidence-scores.md", _render_scores(result))
    return result


def plan_cross_framework_experiments(
    *,
    evidence_paths: list[Path],
    module_path: Path,
    output_root: Path,
    catalog_path: Path | None = None,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    records, diagnostics = load_normalized_records(evidence_paths)
    catalog = ExperimentCatalog(module_path, catalog_path)
    plans = _cross_framework_plans(records, catalog)
    result = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": "WARN" if plans else "PASS",
        "passed": True,
        "experiment_count": len(plans),
        "experiments": plans,
        "diagnostics": [diag.to_dict() for diag in diagnostics],
    }
    write_json_atomic(output_root / "cross-framework-experiment-plan.json", result)
    write_text_atomic(output_root / "cross-framework-experiment-plan.md", _render_experiment_plan(result))
    return result


def ecosystem_gap_report(
    *,
    evidence_paths: list[Path],
    output_root: Path,
    pack: Path | None = None,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    records, diagnostics = load_normalized_records(evidence_paths)
    observed = sorted({record.source_type for record in records})
    missing = sorted(set(framework_sources()) - set(observed) - {"local"})
    claim_support = cross_framework_claim_support(records)
    pack_artifacts = _pack_artifacts(pack) if pack else []
    repo_addition = {
        "gap": "external PQC frameworks expose implementations or benchmark outputs, but not a shared constrained-deployment evidence layer",
        "bridge_capability": "normalize heterogeneous framework outputs, compare them with local Zephyr/QEMU evidence, score deployment readiness, and propose missing experiments",
        "local_pack_artifacts": pack_artifacts[:20],
    }
    result = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": "WARN" if missing else "PASS",
        "passed": True,
        "framework_sources": [source.to_dict() for source in framework_sources().values()],
        "observed_sources": observed,
        "missing_sources": missing,
        "repository_addition": repo_addition,
        "claim_support": claim_support,
        "diagnostics": [diag.to_dict() for diag in diagnostics],
    }
    write_json_atomic(output_root / "ecosystem-gap-report.json", result)
    write_text_atomic(output_root / "ecosystem-gap-report.md", _render_ecosystem_report(result))
    return result


def cross_framework_claim_matrix(
    *,
    evidence_paths: list[Path],
    output_root: Path,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    records, diagnostics = load_normalized_records(evidence_paths)
    claims = _claim_matrix_items(records)
    blocking = {"unsupported", "not_comparable"}
    status = "FAIL" if any(diag.is_error for diag in diagnostics) else ("WARN" if diagnostics or any(item["support"] in blocking for item in claims) else "PASS")
    result = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": status,
        "passed": not any(diag.is_error for diag in diagnostics),
        "summary": {
            "claim_count": len(claims),
            "support_counts": _support_counts(claims),
            "record_count": len(records),
            "source_types": sorted({record.source_type for record in records}),
        },
        "claims": claims,
        "diagnostics": [diag.to_dict() for diag in diagnostics],
    }
    write_json_atomic(output_root / "cross-framework-claim-matrix.json", result)
    write_text_atomic(output_root / "cross-framework-claim-matrix.md", _render_claim_matrix(result))
    return result


def assess_cross_framework_provenance(
    *,
    evidence_paths: list[Path],
    output_root: Path,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    records, diagnostics = load_normalized_records(evidence_paths)
    if not records:
        diagnostics.append(error("bridge_provenance_no_records", ",".join(str(path) for path in evidence_paths), "no normalized evidence records were loaded"))
    items = [_provenance_item(record) for record in records]
    source_summary: dict[str, dict[str, Any]] = {}
    for item in items:
        source_type = item["record"]["source_type"]
        summary = source_summary.setdefault(
            source_type,
            {
                "record_count": 0,
                "paper_usable_count": 0,
                "product_usable_count": 0,
                "average_score": 0.0,
                "min_score": 100.0,
                "blocking_missing": [],
            },
        )
        summary["record_count"] += 1
        summary["paper_usable_count"] += int(item["paper_usable"])
        summary["product_usable_count"] += int(item["product_usable"])
        summary["average_score"] += item["score"]
        summary["min_score"] = min(summary["min_score"], item["score"])
        summary["blocking_missing"].extend(item["blocking_missing"])
    for summary in source_summary.values():
        count = summary["record_count"] or 1
        summary["average_score"] = round(summary["average_score"] / count, 2)
        summary["min_score"] = 0.0 if summary["min_score"] == 100.0 and count == 0 else round(summary["min_score"], 2)
        summary["blocking_missing"] = sorted(set(summary["blocking_missing"]))
    if items and not any(item["paper_usable"] for item in items):
        diagnostics.append(warning("bridge_provenance_no_paper_usable_records", "normalized evidence", "no imported record has enough provenance for paper-grade comparison"))
    if items and not any(item["product_usable"] for item in items):
        diagnostics.append(warning("bridge_provenance_no_product_usable_records", "normalized evidence", "no imported record has enough provenance for product-grade review"))
    low_quality = [item for item in items if item["quality"] == "low"]
    if low_quality:
        diagnostics.append(warning("bridge_provenance_low_quality_records", "normalized evidence", f"{len(low_quality)} record(s) have low provenance quality"))
    result = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": "FAIL" if any(diag.is_error for diag in diagnostics) else ("WARN" if diagnostics else "PASS"),
        "passed": not any(diag.is_error for diag in diagnostics),
        "summary": {
            "record_count": len(records),
            "paper_usable_count": sum(1 for item in items if item["paper_usable"]),
            "product_usable_count": sum(1 for item in items if item["product_usable"]),
            "source_summary": dict(sorted(source_summary.items())),
        },
        "records": items,
        "diagnostics": [diag.to_dict() for diag in diagnostics],
    }
    write_json_atomic(output_root / "cross-framework-provenance-assessment.json", result)
    write_text_atomic(output_root / "cross-framework-provenance-assessment.md", _render_provenance_assessment(result))
    return result


def cross_framework_claim_support(records: list[NormalizedEvidenceRecord]) -> list[dict[str, Any]]:
    claims = []
    claims.append(_claim_support(
        "ML-KEM constrained deployment is supported by local and external evidence",
        [record for record in records if record.algorithm == "ML-KEM"],
        require_local=True,
        require_external=True,
    ))
    claims.append(_claim_support(
        "ML-DSA signing bottleneck is externally and locally measurable",
        [record for record in records if record.algorithm == "ML-DSA" and record.operation in {"sign", "verify", "keygen"}],
        require_local=True,
        require_external=True,
    ))
    claims.append(_claim_support(
        "HQC fallback has resource-cost evidence",
        [record for record in records if record.algorithm == "HQC"],
        require_local=False,
        require_external=True,
    ))
    mlkem768 = [record for record in records if record.algorithm == "ML-KEM" and record.parameter_set == "768"]
    claims.append(_claim_support(
        "ML-KEM-768 is a balanced operating point across evidence sources",
        mlkem768,
        require_local=True,
        require_external=True,
    ))
    target_classes = {record.target_class() for record in records}
    frameworks = {record.source_type for record in records}
    if len(target_classes) >= 2 and len(frameworks) >= 2:
        support = "cross_framework_supported"
    elif len(frameworks) >= 2:
        support = "not_comparable"
    elif records:
        support = "partially_supported"
    else:
        support = "unsupported"
    claims.append({
        "claim": "Cross-target benchmark comparison is reproducible across frameworks",
        "support": support,
        "source_types": sorted(frameworks),
        "supporting_records": len(records),
        "missing_artifacts": [] if support == "cross_framework_supported" else ["records from at least two target classes and two frameworks"],
        "risk_level": _risk_for_support(support),
        "next_experiment": "import pqm4/SUPERCOP plus local Zephyr/QEMU rows for a common algorithm-operation-target class",
    })
    return claims


def load_normalized_records(paths: list[Path]) -> tuple[list[NormalizedEvidenceRecord], list[Diagnostic]]:
    diagnostics: list[Diagnostic] = []
    records: list[NormalizedEvidenceRecord] = []
    for path in paths:
        if not path.exists():
            diagnostics.append(error("bridge_evidence_missing", str(path), "normalized evidence file is missing"))
            continue
        payload = load_json(path)
        raw_records = payload.get("records", payload if isinstance(payload, list) else [])
        if not isinstance(raw_records, list):
            diagnostics.append(error("bridge_evidence_shape", str(path), "normalized evidence file must contain records[]"))
            continue
        for index, raw in enumerate(raw_records):
            if not isinstance(raw, dict):
                diagnostics.append(error("bridge_record_shape", f"{path}:{index}", "record must be an object"))
                continue
            records.append(NormalizedEvidenceRecord.from_dict(raw))
    return records, diagnostics


def _import_generic(
    path: Path,
    source_type: str,
    diagnostics: list[Diagnostic],
    aliases: dict[str, str],
) -> list[NormalizedEvidenceRecord]:
    if path.suffix.lower() == ".json":
        payload = load_json(path)
        rows = payload.get("records", payload.get("results", payload.get("benchmarks", payload if isinstance(payload, list) else [])))
        if not isinstance(rows, list):
            diagnostics.append(error("bridge_json_shape", str(path), "JSON input must contain records/results/benchmarks list"))
            return []
        return [_record_from_mapping(row, path, idx + 1, source_type, aliases, diagnostics) for idx, row in enumerate(rows) if isinstance(row, dict)]
    return _import_csv(path, source_type, diagnostics, aliases)


def _import_oqs(path: Path, diagnostics: list[Diagnostic], aliases: dict[str, str]) -> list[NormalizedEvidenceRecord]:
    return _import_generic(path, "oqs", diagnostics, aliases)


def _import_pqm4(path: Path, source_type: str, diagnostics: list[Diagnostic], aliases: dict[str, str]) -> list[NormalizedEvidenceRecord]:
    if path.suffix.lower() == ".csv":
        return _import_csv(path, source_type, diagnostics, aliases)
    return _import_simple_text(path, source_type, diagnostics, default_device="cortex-m4")


def _import_supercop(path: Path, diagnostics: list[Diagnostic], aliases: dict[str, str]) -> list[NormalizedEvidenceRecord]:
    if path.suffix.lower() == ".csv":
        return _import_csv(path, "supercop", diagnostics, aliases)
    return _import_simple_text(path, "supercop", diagnostics, default_device="cross-platform-benchmark")


def _import_csv(
    path: Path,
    source_type: str,
    diagnostics: list[Diagnostic],
    aliases: dict[str, str],
) -> list[NormalizedEvidenceRecord]:
    records: list[NormalizedEvidenceRecord] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            diagnostics.append(error("bridge_csv_header", str(path), "input CSV has no header"))
            return []
        for row_number, row in enumerate(reader, start=2):
            records.append(_record_from_mapping(row, path, row_number, source_type, aliases, diagnostics))
    return records


def _import_simple_text(
    path: Path,
    source_type: str,
    diagnostics: list[Diagnostic],
    *,
    default_device: str,
) -> list[NormalizedEvidenceRecord]:
    records: list[NormalizedEvidenceRecord] = []
    for row_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.replace(",", " ").split()
        if len(parts) < 4 or parts[0].lower() in {"algorithm", "scheme", "primitive"}:
            continue
        if len(parts) >= 5 and parts[1].isdigit():
            raw = {
                "algorithm": parts[0],
                "parameter_set": parts[1],
                "operation": parts[2],
                "cycles": parts[3],
                "implementation": parts[4],
                "device_class": default_device,
                "benchmark_context": source_type,
            }
            if len(parts) >= 6:
                raw["stack_bytes"] = parts[5]
        else:
            raw = {
                "algorithm": parts[0],
                "operation": parts[1],
                "cycles": parts[2],
                "implementation": parts[3],
                "device_class": default_device,
                "benchmark_context": source_type,
            }
            if len(parts) >= 5:
                raw["stack_bytes"] = parts[4]
        records.append(_record_from_mapping(raw, path, row_number, source_type, {}, diagnostics))
    return records


def _import_mlkem_status(path: Path, diagnostics: list[Diagnostic]) -> list[NormalizedEvidenceRecord]:
    payload = load_json(path)
    items = payload.get("issues", payload.get("records", payload if isinstance(payload, list) else []))
    if not isinstance(items, list):
        diagnostics.append(error("bridge_mlkem_status_shape", str(path), "mlkem-native status JSON must contain issues[] or records[]"))
        return []
    records: list[NormalizedEvidenceRecord] = []
    for index, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            continue
        labels = " ".join(str(label) for label in item.get("labels", []))
        state = str(item.get("state", item.get("status", "unknown")))
        title = str(item.get("title", item.get("summary", "")))
        records.append(
            NormalizedEvidenceRecord(
                framework="PQ Code Package mlkem-native",
                source_type="mlkem-native",
                source_file=str(path),
                row_number=index,
                algorithm="ML-KEM",
                parameter_set=str(item.get("parameter_set", item.get("level", ""))),
                operation="status",
                implementation="mlkem-native",
                target_architecture="portable-c",
                board="",
                device_class="backend-status",
                benchmark_context=title,
                configuration=labels,
                reproducibility=str(item.get("url", item.get("html_url", ""))),
                source_confidence=0.65,
                verification_status=state,
                missing_fields=("cycles", "latency_us", "memory"),
                raw_digest=_raw_digest(item),
            )
        )
    return records


def _record_from_mapping(
    raw: dict[str, Any],
    path: Path,
    row_number: int,
    source_type: str,
    aliases: dict[str, str],
    diagnostics: list[Diagnostic],
) -> NormalizedEvidenceRecord:
    normalized = {field: _field(raw, field, aliases) for field in CANONICAL_FIELDS}
    raw_algorithm = str(normalized["algorithm"])
    algorithm = _normalize_algorithm(raw_algorithm)
    operation = _normalize_operation(normalized["operation"])
    parameter = _normalize_parameter(str(normalized["parameter_set"]), raw_algorithm, algorithm)
    missing = tuple(field for field in ("algorithm", "operation") if not normalized[field])
    warnings: list[str] = []
    if not normalized["board"] and not normalized["target_architecture"] and not normalized["device_class"]:
        warnings.append("target metadata missing")
    if not any(normalized[field] for field in ("cycles", "latency_us", "stack_bytes", "ram_bytes", "flash_bytes", "energy_uj", "verification_status")):
        warnings.append("no numeric metric or status field found")
    for item in warnings:
        diagnostics.append(warning("bridge_record_warning", f"{path}:{row_number}", item))
    source = framework_sources().get(source_type)
    return NormalizedEvidenceRecord(
        framework=source.source_name if source else source_type,
        source_type=source_type,
        source_file=str(path),
        row_number=row_number,
        algorithm=algorithm,
        parameter_set=parameter,
        operation=operation,
        implementation=str(normalized["implementation"] or source_type),
        target_architecture=str(normalized["target_architecture"]),
        board=str(normalized["board"]),
        device_class=str(normalized["device_class"] or (source.target_class if source else "")),
        security_level=_optional_int(normalized["security_level"]) or _infer_security_level(algorithm, parameter),
        cycles=_optional_float(normalized["cycles"]),
        latency_us=_optional_float(normalized["latency_us"]),
        stack_bytes=_optional_float(normalized["stack_bytes"]),
        heap_bytes=_optional_float(normalized["heap_bytes"]),
        ram_bytes=_optional_float(normalized["ram_bytes"]),
        flash_bytes=_optional_float(normalized["flash_bytes"]),
        energy_uj=_optional_float(normalized["energy_uj"]),
        benchmark_context=str(normalized["benchmark_context"]),
        compiler=str(normalized["compiler"]),
        configuration=str(normalized["configuration"]),
        reproducibility=str(normalized["reproducibility"]),
        source_confidence=_source_confidence(source_type),
        verification_status=str(normalized["verification_status"]),
        import_warnings=tuple(warnings),
        missing_fields=missing,
        raw_digest=_raw_digest(raw),
    )


def _normalized_payload(
    source_type: str,
    input_paths: list[Path],
    records: list[NormalizedEvidenceRecord],
    diagnostics: list[Diagnostic],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "source_type": source_type,
        "input_files": [{"path": str(path), "sha256": sha256_file(path) if path.exists() else None} for path in input_paths],
        "framework_source": framework_sources().get(source_type, framework_sources()["local"]).to_dict(),
        "record_count": len(records),
        "records": [record.to_dict() for record in records],
        "diagnostics": [diag.to_dict() for diag in diagnostics],
        "status": "WARN" if diagnostics else "PASS",
        "passed": not any(diag.is_error for diag in diagnostics),
    }


def _cross_framework_manifest(
    *,
    source_type: str,
    input_paths: list[Path],
    normalized_json: Path,
    normalized_csv: Path,
    records: list[NormalizedEvidenceRecord],
    diagnostics: list[Diagnostic],
) -> dict[str, Any]:
    source = framework_sources().get(source_type, framework_sources()["local"]).to_dict()
    algorithm_counts: dict[str, int] = {}
    operation_counts: dict[str, int] = {}
    target_counts: dict[str, int] = {}
    metric_counts: dict[str, int] = {}
    for record in records:
        algorithm_counts[record.algorithm] = algorithm_counts.get(record.algorithm, 0) + 1
        operation_counts[record.operation] = operation_counts.get(record.operation, 0) + 1
        target_counts[record.target_class()] = target_counts.get(record.target_class(), 0) + 1
        for metric in record.numeric_metrics():
            metric_counts[metric] = metric_counts.get(metric, 0) + 1
    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "source_type": source_type,
        "source_model_digest": json_digest(source),
        "input_files": [{"path": str(path), "sha256": sha256_file(path) if path.exists() else None} for path in input_paths],
        "normalized_artifacts": [
            {
                "path": normalized_json.name,
                "sha256": sha256_file(normalized_json),
                "media_type": "application/json",
            },
            {
                "path": normalized_csv.name,
                "sha256": sha256_file(normalized_csv),
                "media_type": "text/csv",
            },
        ],
        "record_count": len(records),
        "record_digests": [_record_digest(record) for record in records],
        "summary": {
            "algorithm_counts": dict(sorted(algorithm_counts.items())),
            "operation_counts": dict(sorted(operation_counts.items())),
            "target_counts": dict(sorted(target_counts.items())),
            "metric_counts": dict(sorted(metric_counts.items())),
            "diagnostic_count": len(diagnostics),
            "error_count": sum(1 for diag in diagnostics if diag.is_error),
            "warning_count": sum(1 for diag in diagnostics if not diag.is_error),
        },
    }


def _record_digest(record: NormalizedEvidenceRecord) -> str:
    return json_digest(record.to_dict())


def _manifest_verification_result(manifest_path: Path, checks: list[dict[str, Any]], diagnostics: list[Diagnostic]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "manifest_path": str(manifest_path),
        "status": "FAIL" if any(diag.is_error for diag in diagnostics) else ("WARN" if diagnostics else "PASS"),
        "passed": not any(diag.is_error for diag in diagnostics),
        "artifact_checks": checks,
        "diagnostics": [diag.to_dict() for diag in diagnostics],
    }


def _audit_record(record: NormalizedEvidenceRecord, diagnostics: list[Diagnostic]) -> None:
    location = f"{record.source_file}:{record.row_number}"
    required = {
        "source_type": record.source_type,
        "algorithm": record.algorithm,
        "operation": record.operation,
        "implementation": record.implementation,
        "target": record.target_class(),
    }
    for field, value in required.items():
        if not value or value == "unknown":
            diagnostics.append(error("bridge_audit_required_field_missing", location, f"record is missing required field {field}"))
    if record.source_type not in SOURCE_TYPES:
        diagnostics.append(error("bridge_audit_unknown_source", location, f"unsupported source_type {record.source_type!r}"))
    if not record.raw_digest:
        diagnostics.append(error("bridge_audit_raw_digest_missing", location, "record is not bound to an imported raw row digest"))
    if not record.numeric_metrics() and not record.verification_status:
        diagnostics.append(error("bridge_audit_no_evidence_value", location, "record has neither numeric metrics nor verification/status evidence"))
    constrained = record.target_class().lower()
    if any(marker in constrained for marker in ("cortex", "mcu", "stm32", "nucleo")):
        if not any(value is not None for value in (record.stack_bytes, record.ram_bytes, record.flash_bytes, record.heap_bytes)):
            diagnostics.append(warning("bridge_audit_constrained_memory_missing", location, "constrained-target record lacks footprint metrics"))
    if record.source_type == "local" and not record.reproducibility:
        diagnostics.append(warning("bridge_audit_local_reproducibility_missing", location, "local evidence record does not name transcript/run reproducibility metadata"))


def _comparable_group_summaries(records: list[NormalizedEvidenceRecord]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str, str], list[NormalizedEvidenceRecord]] = {}
    for record in records:
        groups.setdefault(record.key(), []).append(record)
    summaries: list[dict[str, Any]] = []
    for key, rows in sorted(groups.items()):
        source_types = {row.source_type for row in rows}
        if "local" not in source_types or not (source_types - {"local"}):
            continue
        metrics = sorted(set.intersection(*(set(row.numeric_metrics()) for row in rows if row.numeric_metrics())) if all(row.numeric_metrics() for row in rows) else set())
        if not metrics:
            continue
        summaries.append(
            {
                "key": list(key),
                "source_types": sorted(source_types),
                "metrics": metrics,
                "record_count": len(rows),
            }
        )
    return summaries


def _comparability_pair(left: NormalizedEvidenceRecord, right: NormalizedEvidenceRecord) -> dict[str, Any]:
    left_metrics = left.numeric_metrics()
    right_metrics = right.numeric_metrics()
    common_metrics = sorted(set(left_metrics) & set(right_metrics))
    reasons: list[str] = []
    if left.target_class() != right.target_class():
        reasons.append("target_class_mismatch")
    if not common_metrics:
        reasons.append("no_common_numeric_metric")
    source_pair = _source_pair_type(left, right)
    metric_ratios = []
    suspicious = False
    for metric in common_metrics:
        denominator = right_metrics[metric]
        ratio = None if denominator == 0 else left_metrics[metric] / denominator
        if ratio is not None and (ratio > 4.0 or ratio < 0.25):
            suspicious = True
        metric_ratios.append(
            {
                "metric": metric,
                "left_value": left_metrics[metric],
                "right_value": right_metrics[metric],
                "ratio": None if ratio is None else round(ratio, 6),
            }
        )
    if suspicious:
        reasons.append("suspicious_metric_ratio")
    if reasons:
        status = "not_comparable" if any(reason in reasons for reason in ("target_class_mismatch", "no_common_numeric_metric")) else "comparable_with_warning"
    elif source_pair == "local_external":
        status = "directly_comparable"
    elif source_pair == "external_external":
        status = "external_baseline_pair"
    else:
        status = "local_repeat_or_variant"
    return {
        "subject": {
            "algorithm": left.algorithm,
            "parameter_set": left.parameter_set,
            "operation": left.operation,
        },
        "status": status,
        "source_pair_type": source_pair,
        "left": _record_ref(left),
        "right": _record_ref(right),
        "common_metrics": common_metrics,
        "metric_ratios": metric_ratios,
        "reasons": reasons,
    }


def _source_pair_type(left: NormalizedEvidenceRecord, right: NormalizedEvidenceRecord) -> str:
    source_types = {left.source_type, right.source_type}
    if "local" in source_types and len(source_types) > 1:
        return "local_external"
    if left.source_type == "local" and right.source_type == "local":
        return "local_local"
    return "external_external"


def _record_ref(record: NormalizedEvidenceRecord) -> dict[str, Any]:
    return {
        "source_type": record.source_type,
        "implementation": record.implementation,
        "target_class": record.target_class(),
        "source_file": record.source_file,
        "row_number": record.row_number,
        "record_digest": _record_digest(record),
    }


def _comparability_gaps(records: list[NormalizedEvidenceRecord], pairs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[NormalizedEvidenceRecord]] = {}
    for record in records:
        grouped.setdefault((record.algorithm, record.parameter_set, record.operation), []).append(record)
    direct_subjects = {
        (pair["subject"]["algorithm"], pair["subject"]["parameter_set"], pair["subject"]["operation"])
        for pair in pairs
        if pair["status"] == "directly_comparable"
    }
    gaps: list[dict[str, Any]] = []
    for subject, rows in sorted(grouped.items()):
        if subject in direct_subjects:
            continue
        source_types = {row.source_type for row in rows}
        target_classes = {row.target_class() for row in rows}
        metric_names = {name for row in rows for name in row.numeric_metrics()}
        missing = []
        if "local" not in source_types:
            missing.append("local Zephyr/QEMU evidence")
        if not (source_types - {"local"}):
            missing.append("independent external baseline")
        if len(target_classes) > 1:
            missing.append("shared target class")
        if not metric_names:
            missing.append("numeric performance or footprint metric")
        gaps.append(
            {
                "subject": {"algorithm": subject[0], "parameter_set": subject[1], "operation": subject[2]},
                "source_types": sorted(source_types),
                "target_classes": sorted(target_classes),
                "metrics": sorted(metric_names),
                "missing": missing or ["direct comparability metadata"],
                "next_step": _gap_next_step(missing),
            }
        )
    return gaps


def _gap_next_step(missing: list[str]) -> str:
    if "local Zephyr/QEMU evidence" in missing:
        return "run or import local Zephyr/QEMU evidence for this algorithm and operation"
    if "independent external baseline" in missing:
        return "import pqm4, SUPERCOP/eBACS, OQS, or paper baseline rows with matching target metadata"
    if "shared target class" in missing:
        return "add explicit target/device-class metadata or collect a matching target-class baseline"
    if "numeric performance or footprint metric" in missing:
        return "collect cycles, latency, stack, RAM, flash, or energy metrics"
    return "add enough source and target metadata to explain direct comparability"


def _claim_matrix_items(records: list[NormalizedEvidenceRecord]) -> list[dict[str, Any]]:
    definitions = [
        {
            "id": "mlkem.constrained_deployment",
            "claim": "ML-KEM is feasible on constrained embedded targets",
            "selector": lambda row: row.algorithm == "ML-KEM",
            "require_local": True,
            "require_external": True,
            "require_direct_pair": True,
        },
        {
            "id": "mldsa.signing_bottleneck",
            "claim": "ML-DSA signing is measurable as a constrained-target bottleneck",
            "selector": lambda row: row.algorithm == "ML-DSA" and row.operation == "sign",
            "require_local": True,
            "require_external": True,
            "require_direct_pair": True,
        },
        {
            "id": "hqc.fallback_resource_cost",
            "claim": "HQC fallback has resource-cost evidence",
            "selector": lambda row: row.algorithm == "HQC",
            "require_local": False,
            "require_external": True,
            "require_direct_pair": False,
        },
        {
            "id": "mlkem768.balanced_operating_point",
            "claim": "ML-KEM-768 is a balanced operating point across evidence sources",
            "selector": lambda row: row.algorithm == "ML-KEM" and row.parameter_set == "768",
            "require_local": True,
            "require_external": True,
            "require_direct_pair": True,
        },
        {
            "id": "comparison.cross_target_reproducibility",
            "claim": "The system supports reproducible cross-target benchmarking",
            "selector": lambda row: bool(row.algorithm and row.operation),
            "require_local": True,
            "require_external": True,
            "require_direct_pair": False,
            "require_two_targets": True,
        },
        {
            "id": "product.partner_evidence_pack",
            "claim": "The tool can produce partner-review evidence grounded in local and external sources",
            "selector": lambda row: bool(row.raw_digest),
            "require_local": True,
            "require_external": True,
            "require_direct_pair": False,
        },
    ]
    return [_claim_matrix_item(definition, records) for definition in definitions]


def _claim_matrix_item(definition: dict[str, Any], records: list[NormalizedEvidenceRecord]) -> dict[str, Any]:
    selected = [record for record in records if definition["selector"](record)]
    source_types = {record.source_type for record in selected}
    target_classes = {record.target_class() for record in selected}
    metrics = {metric for record in selected for metric in record.numeric_metrics()}
    pairs = _direct_pairs_for_claim(selected)
    missing = []
    if not selected:
        missing.append("normalized evidence records for this claim")
    if definition.get("require_local") and "local" not in source_types:
        missing.append("local Zephyr/QEMU evidence")
    if definition.get("require_external") and not (source_types - {"local"}):
        missing.append("independent external framework evidence")
    if definition.get("require_direct_pair") and selected and not pairs:
        missing.append("directly comparable local/external row pair")
    if definition.get("require_two_targets") and len(target_classes) < 2:
        missing.append("at least two target classes")
    if selected and not metrics and not any(record.verification_status for record in selected):
        missing.append("numeric metric or verification/status evidence")
    support = _claim_matrix_support(definition, selected, source_types, pairs, target_classes, missing)
    return {
        "id": definition["id"],
        "claim": definition["claim"],
        "support": support,
        "risk_level": _risk_for_support(support),
        "source_types": sorted(source_types),
        "target_classes": sorted(target_classes),
        "metrics": sorted(metrics),
        "supporting_evidence": [_record_ref(record) for record in selected[:12]],
        "direct_comparison_pairs": pairs[:8],
        "missing_artifacts": missing,
        "next_experiment": _claim_next_experiment(definition, missing),
    }


def _direct_pairs_for_claim(records: list[NormalizedEvidenceRecord]) -> list[dict[str, Any]]:
    pairs = []
    for index, left in enumerate(records):
        for right in records[index + 1 :]:
            if (left.algorithm, left.parameter_set, left.operation, left.target_class()) != (
                right.algorithm,
                right.parameter_set,
                right.operation,
                right.target_class(),
            ):
                continue
            if _source_pair_type(left, right) != "local_external":
                continue
            pair = _comparability_pair(left, right)
            if pair["status"] in {"directly_comparable", "comparable_with_warning"}:
                pairs.append(pair)
    return pairs


def _claim_matrix_support(
    definition: dict[str, Any],
    selected: list[NormalizedEvidenceRecord],
    source_types: set[str],
    direct_pairs: list[dict[str, Any]],
    target_classes: set[str],
    missing: list[str],
) -> str:
    if not selected:
        return "unsupported"
    local = "local" in source_types
    external = bool(source_types - {"local"})
    if definition.get("require_direct_pair") and local and external and not direct_pairs:
        return "not_comparable"
    if definition.get("require_two_targets") and len(target_classes) < 2:
        return "partially_supported"
    if not missing and local and external:
        return "cross_framework_supported"
    if not missing and external:
        return "externally_supported"
    if local and not external:
        return "locally_supported"
    if external and not local:
        return "externally_supported" if not definition.get("require_local") else "partially_supported"
    return "partially_supported"


def _claim_next_experiment(definition: dict[str, Any], missing: list[str]) -> str:
    if not missing:
        return "no blocking experiment required; use repeat measurements to improve confidence"
    claim_id = str(definition["id"])
    if "directly comparable local/external row pair" in missing:
        return f"collect matching local and external rows for {claim_id} with the same algorithm, operation, target class, and metric"
    if "local Zephyr/QEMU evidence" in missing:
        return f"run local Zephyr/QEMU benchmark or status capture for {claim_id}"
    if "independent external framework evidence" in missing:
        return f"import pqm4, SUPERCOP/eBACS, OQS, or paper baseline evidence for {claim_id}"
    if "at least two target classes" in missing:
        return f"add a second target class, for example QEMU plus cortex-m4, for {claim_id}"
    return f"add the missing evidence artifacts for {claim_id}"


def _support_counts(claims: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for claim in claims:
        support = str(claim.get("support", "unknown"))
        counts[support] = counts.get(support, 0) + 1
    return dict(sorted(counts.items()))


def _provenance_item(record: NormalizedEvidenceRecord) -> dict[str, Any]:
    score = 20.0
    strengths: list[str] = []
    missing: list[str] = []
    blocking_missing: list[str] = []
    metrics = record.numeric_metrics()
    required_fields = {
        "algorithm": record.algorithm,
        "operation": record.operation,
        "implementation": record.implementation,
        "target_class": record.target_class(),
        "raw_digest": record.raw_digest,
    }
    for field, value in required_fields.items():
        if value and value != "unknown":
            score += 8
            strengths.append(field)
        else:
            missing.append(field)
            blocking_missing.append(field)
    if metrics:
        score += min(16, 4 * len(metrics))
        strengths.append("numeric_metrics")
    elif record.verification_status:
        score += 10
        strengths.append("verification_status")
    else:
        missing.append("numeric metric or verification status")
        blocking_missing.append("numeric metric or verification status")
    if record.benchmark_context:
        score += 8
        strengths.append("benchmark_context")
    else:
        missing.append("benchmark context/source dataset")
    if record.reproducibility:
        score += 10
        strengths.append("reproducibility")
    else:
        missing.append("reproducibility reference")
    if record.compiler:
        score += 5
        strengths.append("compiler")
    else:
        missing.append("compiler/toolchain")
    if record.configuration:
        score += 5
        strengths.append("configuration")
    else:
        missing.append("configuration/build flags")
    if record.security_level is not None:
        score += 4
        strengths.append("security_level")
    else:
        missing.append("security level")
    if record.source_type in {"pqm4", "supercop", "ebacs", "oqs"} and record.source_file:
        score += 5
        strengths.append("recognized_external_source")
    if record.source_type == "local" and record.reproducibility:
        score += 5
        strengths.append("local_replay_reference")
    score = min(100.0, score)
    if blocking_missing:
        quality = "low"
    elif score >= 78:
        quality = "high"
    elif score >= 58:
        quality = "medium"
    else:
        quality = "low"
    paper_usable = quality in {"high", "medium"} and bool(metrics or record.verification_status)
    product_usable = quality == "high" and bool(record.reproducibility) and not blocking_missing
    calibrated_confidence = min(1.0, max(0.0, record.source_confidence * (0.55 + score / 200.0)))
    return {
        "record": _record_ref(record),
        "subject": {
            "algorithm": record.algorithm,
            "parameter_set": record.parameter_set,
            "operation": record.operation,
        },
        "score": round(score, 2),
        "quality": quality,
        "paper_usable": paper_usable,
        "product_usable": product_usable,
        "calibrated_source_confidence": round(calibrated_confidence, 4),
        "strengths": sorted(set(strengths)),
        "missing": sorted(set(missing)),
        "blocking_missing": sorted(set(blocking_missing)),
    }


def _records_csv(records: list[NormalizedEvidenceRecord]) -> str:
    fields = [
        "framework",
        "source_type",
        "algorithm",
        "parameter_set",
        "operation",
        "implementation",
        "target_architecture",
        "board",
        "device_class",
        "security_level",
        "cycles",
        "latency_us",
        "stack_bytes",
        "heap_bytes",
        "ram_bytes",
        "flash_bytes",
        "energy_uj",
        "benchmark_context",
        "compiler",
        "configuration",
        "reproducibility",
        "source_confidence",
        "verification_status",
    ]
    rows = [",".join(fields)]
    for record in records:
        payload = record.to_dict()
        rows.append(",".join(_csv_cell(payload.get(field)) for field in fields))
    return "\n".join(rows) + "\n"


def _score_group(
    key: tuple[str, str, str],
    rows: list[NormalizedEvidenceRecord],
    scenario: DeploymentScenario | None,
) -> dict[str, Any]:
    source_types = {row.source_type for row in rows}
    target_classes = {row.target_class() for row in rows}
    numeric_names = {name for row in rows for name in row.numeric_metrics()}
    local_present = "local" in source_types
    external_count = len(source_types - {"local"})
    source_diversity = len(source_types)
    provenance = [_provenance_item(row) for row in rows]
    avg_conf = sum(item["calibrated_source_confidence"] for item in provenance) / len(provenance)
    avg_provenance_score = sum(item["score"] for item in provenance) / len(provenance)
    perf = bool(numeric_names & {"cycles", "latency_us"})
    memory = bool(numeric_names & {"stack_bytes", "heap_bytes", "ram_bytes", "flash_bytes"})
    status = any(row.verification_status for row in rows)
    reproducible = any(row.reproducibility for row in rows) or source_diversity >= 2
    target_relevant = _target_relevant(rows, scenario)
    operation_relevant = _operation_relevant(key[0], scenario)
    missing = []
    for name, present in {
        "performance": perf,
        "memory": memory,
        "local": local_present,
        "external_baseline": external_count > 0,
        "reproducibility": reproducible,
        "target_relevance": target_relevant,
        "operation_relevance": operation_relevant,
    }.items():
        if not present:
            missing.append(name)
    evidence_score = min(100.0, 20 + 10 * source_diversity + 15 * int(perf) + 15 * int(memory) + 15 * int(local_present) + 10 * int(reproducible) + 10 * int(status))
    deployment_confidence = min(100.0, evidence_score * 0.65 + avg_conf * 25 + (10 if target_relevant else 0) + (10 if operation_relevant else -25))
    research_novelty = min(100.0, 25 + 15 * min(source_diversity, 4) + 15 * int(local_present and external_count > 0) + 10 * int(len(target_classes) > 1) + 10 * int(memory))
    product_readiness = min(100.0, 15 + 20 * int(local_present) + 20 * int(perf) + 20 * int(memory) + 15 * int(status) + 10 * int(reproducible))
    if scenario:
        product_readiness -= _budget_penalty(rows, scenario)
        deployment_confidence -= _budget_penalty(rows, scenario) * 0.7
        if not operation_relevant:
            product_readiness -= 25
    risk = max(0.0, 100 - (deployment_confidence * 0.55 + product_readiness * 0.35 + research_novelty * 0.10))
    return {
        "option": {"algorithm": key[0], "parameter_set": key[1], "target_class": key[2]},
        "record_count": len(rows),
        "source_types": sorted(source_types),
        "target_classes": sorted(target_classes),
        "metrics_present": sorted(numeric_names),
        "missing_evidence": missing,
        "average_provenance_score": round(avg_provenance_score, 2),
        "evidence_score": round(evidence_score, 2),
        "deployment_confidence": round(max(0.0, deployment_confidence), 2),
        "research_novelty_score": round(research_novelty, 2),
        "product_readiness_score": round(max(0.0, product_readiness), 2),
        "reviewer_risk_score": round(risk, 2),
    }


def _cross_framework_plans(records: list[NormalizedEvidenceRecord], catalog: ExperimentCatalog) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[NormalizedEvidenceRecord]] = {}
    for record in records:
        groups.setdefault((record.algorithm, record.parameter_set), []).append(record)
    plans: list[dict[str, Any]] = []
    for (algorithm, parameter), rows in sorted(groups.items()):
        source_types = {row.source_type for row in rows}
        target_classes = {row.target_class() for row in rows}
        metrics = {name for row in rows for name in row.numeric_metrics()}
        if "local" not in source_types:
            plans.append(_plan_item(algorithm, parameter, "local", "qemu_x86_64", "cycles", "Add local Zephyr/QEMU evidence to connect external numbers to this repository.", catalog))
        if len(source_types - {"local"}) == 0:
            plans.append(_plan_item(algorithm, parameter, "pqm4-or-supercop", "cortex-m", "cycles", "Add independent external baseline evidence for reviewer comparison.", catalog))
        if not metrics & {"stack_bytes", "ram_bytes", "flash_bytes"}:
            plans.append(_plan_item(algorithm, parameter, "local", "constrained-target", "memory", "Add footprint evidence because constrained deployment needs more than speed.", catalog))
        if len(target_classes) < 2:
            plans.append(_plan_item(algorithm, parameter, "pqm4", "cortex-m4", "cycles+stack", "Add a second target class to separate QEMU regression evidence from embedded evidence.", catalog))
    seen: set[tuple[str, str, str, str]] = set()
    deduped = []
    for item in plans:
        key = (item["algorithm"], item["parameter_set"], item["framework_or_baseline"], item["metric"])
        if key in seen:
            continue
        seen.add(key)
        item["priority"] = len(deduped) + 1
        deduped.append(item)
    return deduped[:25]


def _plan_item(
    algorithm: str,
    parameter: str,
    framework: str,
    target: str,
    metric: str,
    reason: str,
    catalog: ExperimentCatalog,
) -> dict[str, Any]:
    return {
        "priority": 0,
        "algorithm": algorithm,
        "parameter_set": parameter,
        "target": target,
        "framework_or_baseline": framework,
        "operation": _default_operation(algorithm),
        "metric": metric,
        "why_needed": reason,
        "claim_supported": f"{algorithm}-{parameter} constrained deployment evidence is cross-framework comparable",
        "expected_artifact": "normalized-evidence.json plus benchmark transcript or imported source table",
        "acceptance_criteria": [
            "normalized record contains algorithm, operation, target class, implementation, and source type",
            "at least one performance or footprint metric is numeric",
            "comparison engine classifies the pair as comparable or explicitly not_comparable",
        ],
        "catalog_experiment_ids": _catalog_matches(catalog, algorithm, metric),
    }


def _claim_support(
    claim: str,
    rows: list[NormalizedEvidenceRecord],
    *,
    require_local: bool,
    require_external: bool,
) -> dict[str, Any]:
    source_types = {row.source_type for row in rows}
    local = "local" in source_types
    external = bool(source_types - {"local"})
    if require_local and require_external and local and external:
        support = "cross_framework_supported"
    elif require_local and local and not require_external:
        support = "locally_supported"
    elif require_external and external and not require_local:
        support = "externally_supported"
    elif local:
        support = "locally_supported"
    elif external:
        support = "externally_supported"
    elif rows:
        support = "partially_supported"
    else:
        support = "unsupported"
    missing = []
    if require_local and not local:
        missing.append("local Zephyr/QEMU evidence")
    if require_external and not external:
        missing.append("independent external framework evidence")
    if rows and require_local and require_external and local and external:
        local_targets = {row.target_class() for row in rows if row.source_type == "local"}
        external_targets = {row.target_class() for row in rows if row.source_type != "local"}
        if not (local_targets & external_targets):
            support = "not_comparable"
            if "shared target class" not in missing:
                missing.append("shared target class")
    return {
        "claim": claim,
        "support": support,
        "source_types": sorted(source_types),
        "supporting_records": len(rows),
        "missing_artifacts": missing,
        "risk_level": _risk_for_support(support),
        "next_experiment": "generate or import the missing source/target evidence and rerun compare-frameworks",
    }


def _pack_artifacts(pack: Path | None) -> list[str]:
    if not pack:
        return []
    manifest = pack / "evidence-pack-manifest.json"
    if not manifest.exists():
        return []
    payload = load_json(manifest)
    return [str(item.get("relative_path", "")) for item in payload.get("artifacts", []) if isinstance(item, dict)]


def _field(raw: dict[str, Any], canonical: str, aliases: dict[str, str]) -> Any:
    explicit = aliases.get(canonical)
    if explicit and raw.get(explicit) not in (None, ""):
        return raw.get(explicit)
    for alias in DEFAULT_ALIASES.get(canonical, (canonical,)):
        if raw.get(alias) not in (None, ""):
            return raw.get(alias)
    return raw.get(canonical, "")


def _normalize_algorithm(value: Any) -> str:
    text = str(value).strip()
    compact = text.replace("-", "").replace("_", "").replace(" ", "").upper()
    if compact in {"KYBER", "MLKEM"}:
        return "ML-KEM"
    if compact.startswith("MLKEM"):
        return "ML-KEM"
    if compact in {"DILITHIUM", "MLDSA"}:
        return "ML-DSA"
    if compact.startswith("MLDSA"):
        return "ML-DSA"
    if compact.startswith("HQC"):
        return "HQC"
    return text


def _normalize_parameter(value: str, raw_algorithm: str, algorithm: str) -> str:
    text = str(value).strip()
    compact = text.replace("-", "").replace("_", "").replace(" ", "").upper()
    if text:
        return text
    raw_compact = raw_algorithm.replace("-", "").replace("_", "").replace(" ", "").upper()
    for marker in ("512", "768", "1024", "44", "65", "87", "128", "192", "256"):
        if marker in compact or marker in raw_compact:
            return marker
    if algorithm == "ML-KEM":
        return ""
    return text


def _normalize_operation(value: Any) -> str:
    text = str(value).strip().lower().replace("_", "").replace("-", "")
    return {
        "keypair": "keygen",
        "keygen": "keygen",
        "keygeneration": "keygen",
        "encaps": "encaps",
        "encapsulation": "encaps",
        "decaps": "decaps",
        "decapsulation": "decaps",
        "sign": "sign",
        "siggen": "sign",
        "verify": "verify",
        "sigver": "verify",
        "open": "verify",
        "status": "status",
    }.get(text, text or "unknown")


def _optional_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return None
    return None if math.isnan(numeric) or math.isinf(numeric) else numeric


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(str(value).replace("Level", "").replace("level", "").strip())
    except ValueError:
        return None


def _infer_security_level(algorithm: str, parameter: str) -> int | None:
    mapping = {"512": 1, "768": 3, "1024": 5, "44": 2, "65": 3, "87": 5, "128": 1, "192": 3, "256": 5}
    return mapping.get(str(parameter))


def _source_confidence(source_type: str) -> float:
    return {
        "local": 0.85,
        "pqm4": 0.82,
        "mupq": 0.78,
        "supercop": 0.80,
        "ebacs": 0.80,
        "oqs": 0.72,
        "mlkem-native": 0.65,
        "rustpq": 0.58,
        "quantcrypt": 0.52,
        "pqc-leo": 0.60,
        "generic-csv": 0.45,
    }.get(source_type, 0.50)


def _raw_digest(raw: Any) -> str:
    import hashlib
    return hashlib.sha256(json.dumps(raw, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _csv_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    if any(ch in text for ch in ",\"\n"):
        return '"' + text.replace('"', '""') + '"'
    return text


def _best_metric_name(rows: list[NormalizedEvidenceRecord]) -> str | None:
    for name in ("cycles", "latency_us", "stack_bytes", "ram_bytes", "flash_bytes"):
        if any(_metric_value(row, name) is not None for row in rows):
            return name
    return None


def _metric_value(row: NormalizedEvidenceRecord, name: str) -> float | None:
    value = getattr(row, name)
    return value if value is not None and not math.isnan(value) else None


def _target_relevant(rows: list[NormalizedEvidenceRecord], scenario: DeploymentScenario | None) -> bool:
    if scenario is None:
        return True
    wanted = {scenario.target_board.lower(), scenario.target_architecture.lower(), scenario.device_class.lower()}
    for row in rows:
        values = {row.board.lower(), row.target_architecture.lower(), row.device_class.lower(), row.target_class().lower()}
        if wanted & values:
            return True
    return False


def _operation_relevant(algorithm: str, scenario: DeploymentScenario | None) -> bool:
    if scenario is None:
        return True
    if scenario.operation_type in {"KEM", "onboarding", "reconnect", "telemetry_session"}:
        return algorithm in {"ML-KEM", "HQC"}
    if scenario.operation_type in {"signature", "firmware_update"}:
        return algorithm in {"ML-DSA", "SLH-DSA", "Falcon"}
    if scenario.operation_type == "hybrid_tls":
        return algorithm in {"ML-KEM", "ML-DSA"}
    return True


def _budget_penalty(rows: list[NormalizedEvidenceRecord], scenario: DeploymentScenario) -> float:
    penalty = 0.0
    if scenario.latency_budget_us is not None:
        latencies = [row.latency_us for row in rows if row.latency_us is not None]
        if latencies and min(latencies) > scenario.latency_budget_us:
            penalty += 20
    if scenario.memory_budget_bytes is not None:
        memories = [value for row in rows for value in (row.ram_bytes, row.flash_bytes) if value is not None]
        if memories and min(memories) > scenario.memory_budget_bytes:
            penalty += 20
    if scenario.stack_limit_bytes is not None:
        stacks = [row.stack_bytes for row in rows if row.stack_bytes is not None]
        if stacks and min(stacks) > scenario.stack_limit_bytes:
            penalty += 15
    return penalty


def _default_operation(algorithm: str) -> str:
    return "encaps" if algorithm in {"ML-KEM", "HQC"} else "sign"


def _catalog_matches(catalog: ExperimentCatalog, algorithm: str, metric: str) -> list[str]:
    needles = [algorithm.lower().replace("-", ""), metric.lower()]
    matches = []
    for experiment in catalog.experiments:
        body = " ".join([
            experiment.id,
            experiment.objective,
            experiment.research_value,
            experiment.product_value,
            *experiment.commands,
            *experiment.expected_outputs,
        ]).lower().replace("-", "")
        if any(needle in body for needle in needles):
            matches.append(experiment.id)
    return matches[:8]


def _risk_for_support(support: str) -> str:
    return {
        "cross_framework_supported": "low",
        "locally_supported": "medium",
        "externally_supported": "medium",
        "partially_supported": "medium",
        "not_comparable": "high",
        "unsupported": "high",
    }.get(support, "medium")


def _render_comparison(result: dict[str, Any]) -> str:
    lines = ["# Cross-Framework Comparison", "", f"Status: {result['status']}", "", "| Key | Status | Metric | Ratio | Reason |", "|---|---|---|---:|---|"]
    for item in result["comparisons"]:
        ratio = "" if item["ratio"] is None else f"{item['ratio']:.4f}"
        lines.append(f"| {' / '.join(item['key'])} | {item['status']} | {item['metric'] or ''} | {ratio} | {item['reason']} |")
    return "\n".join(lines) + "\n"


def _render_scores(result: dict[str, Any]) -> str:
    lines = ["# Cross-Framework Evidence Scores", "", f"Status: {result['status']}", "", "| Option | Evidence | Deployment | Research | Product | Risk |", "|---|---:|---:|---:|---:|---:|"]
    for item in result["scores"]:
        option = item["option"]
        name = f"{option['algorithm']}-{option['parameter_set']} on {option['target_class']}"
        lines.append(f"| {name} | {item['evidence_score']} | {item['deployment_confidence']} | {item['research_novelty_score']} | {item['product_readiness_score']} | {item['reviewer_risk_score']} |")
    return "\n".join(lines) + "\n"


def _render_experiment_plan(result: dict[str, Any]) -> str:
    lines = ["# Cross-Framework Experiment Plan", "", f"Status: {result['status']}", ""]
    for item in result["experiments"]:
        lines.append(f"{item['priority']}. {item['algorithm']}-{item['parameter_set']} {item['operation']} on {item['target']} via {item['framework_or_baseline']}")
        lines.append(f"   Metric: {item['metric']}; artifact: {item['expected_artifact']}")
        lines.append(f"   Why: {item['why_needed']}")
    return "\n".join(lines) + "\n"


def _render_ecosystem_report(result: dict[str, Any]) -> str:
    lines = ["# Ecosystem Gap Report", "", f"Status: {result['status']}", ""]
    lines.append(f"Observed sources: {', '.join(result['observed_sources']) or 'none'}")
    lines.append(f"Missing sources: {', '.join(result['missing_sources']) or 'none'}")
    lines.append("")
    lines.append(result["repository_addition"]["gap"])
    lines.append("")
    lines.append("| Claim | Support | Risk | Missing |")
    lines.append("|---|---|---|---|")
    for item in result["claim_support"]:
        lines.append(f"| {item['claim']} | {item['support']} | {item['risk_level']} | {', '.join(item['missing_artifacts']) or 'none'} |")
    return "\n".join(lines) + "\n"


def _render_manifest_verification(result: dict[str, Any]) -> str:
    lines = ["# Cross-Framework Evidence Manifest Verification", "", f"Status: {result['status']}", ""]
    lines.append("| Artifact | Status | Expected | Actual |")
    lines.append("|---|---|---|---|")
    for item in result["artifact_checks"]:
        actual = item.get("actual_sha256") or "missing"
        lines.append(f"| {item.get('path', '')} | {item.get('status', '')} | `{item.get('expected_sha256', '')}` | `{actual}` |")
    if result["diagnostics"]:
        lines.append("")
        lines.append("## Diagnostics")
        for diag in result["diagnostics"]:
            level = "ERROR" if diag.get("severity") == "error" else "WARN"
            lines.append(f"- {level} `{diag.get('code')}` {diag.get('location')}: {diag.get('message')}")
    return "\n".join(lines) + "\n"


def _render_evidence_audit(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = ["# Cross-Framework Evidence Audit", "", f"Status: {result['status']}", ""]
    lines.append(f"Records: {summary['record_count']}")
    lines.append(f"Sources: {', '.join(summary['source_types']) or 'none'}")
    lines.append(f"Algorithms: {', '.join(summary['algorithms']) or 'none'}")
    lines.append(f"Targets: {', '.join(summary['target_classes']) or 'none'}")
    lines.append("")
    lines.append("## Metrics")
    if summary["metric_counts"]:
        for name, count in summary["metric_counts"].items():
            lines.append(f"- {name}: {count}")
    else:
        lines.append("- none")
    lines.append("")
    lines.append("## Comparable Groups")
    if result["comparable_groups"]:
        lines.append("| Key | Sources | Metrics | Records |")
        lines.append("|---|---|---|---:|")
        for item in result["comparable_groups"]:
            lines.append(f"| {' / '.join(item['key'])} | {', '.join(item['source_types'])} | {', '.join(item['metrics'])} | {item['record_count']} |")
    else:
        lines.append("No directly comparable local/external groups were found.")
    if result["diagnostics"]:
        lines.append("")
        lines.append("## Diagnostics")
        for diag in result["diagnostics"]:
            level = "ERROR" if diag.get("severity") == "error" else "WARN"
            lines.append(f"- {level} `{diag.get('code')}` {diag.get('location')}: {diag.get('message')}")
    return "\n".join(lines) + "\n"


def _render_comparability_matrix(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = ["# Cross-Framework Comparability Matrix", "", f"Status: {result['status']}", ""]
    lines.append(f"Records: {summary['record_count']}; pairs: {summary['pair_count']}; gaps: {summary['gap_count']}")
    lines.append("")
    lines.append("| Subject | Status | Sources | Metrics | Reasons |")
    lines.append("|---|---|---|---|---|")
    for pair in result["pairs"]:
        subject = pair["subject"]
        subject_text = f"{subject['algorithm']}-{subject['parameter_set']} {subject['operation']}"
        sources = f"{pair['left']['source_type']} vs {pair['right']['source_type']}"
        lines.append(f"| {subject_text} | {pair['status']} | {sources} | {', '.join(pair['common_metrics']) or 'none'} | {', '.join(pair['reasons']) or 'direct'} |")
    if result["gaps"]:
        lines.append("")
        lines.append("## Gaps")
        for gap in result["gaps"]:
            subject = gap["subject"]
            lines.append(f"- {subject['algorithm']}-{subject['parameter_set']} {subject['operation']}: {', '.join(gap['missing'])}; next: {gap['next_step']}")
    if result["diagnostics"]:
        lines.append("")
        lines.append("## Diagnostics")
        for diag in result["diagnostics"]:
            level = "ERROR" if diag.get("severity") == "error" else "WARN"
            lines.append(f"- {level} `{diag.get('code')}` {diag.get('location')}: {diag.get('message')}")
    return "\n".join(lines) + "\n"


def _render_claim_matrix(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = ["# Cross-Framework Claim Matrix", "", f"Status: {result['status']}", ""]
    lines.append(f"Claims: {summary['claim_count']}; records: {summary['record_count']}; sources: {', '.join(summary['source_types']) or 'none'}")
    lines.append("")
    lines.append("| Claim | Support | Risk | Sources | Missing |")
    lines.append("|---|---|---|---|---|")
    for item in result["claims"]:
        lines.append(
            f"| {item['claim']} | {item['support']} | {item['risk_level']} | "
            f"{', '.join(item['source_types']) or 'none'} | {', '.join(item['missing_artifacts']) or 'none'} |"
        )
    if result["diagnostics"]:
        lines.append("")
        lines.append("## Diagnostics")
        for diag in result["diagnostics"]:
            level = "ERROR" if diag.get("severity") == "error" else "WARN"
            lines.append(f"- {level} `{diag.get('code')}` {diag.get('location')}: {diag.get('message')}")
    return "\n".join(lines) + "\n"


def _render_provenance_assessment(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = ["# Cross-Framework Evidence Provenance Assessment", "", f"Status: {result['status']}", ""]
    lines.append(f"Records: {summary['record_count']}; paper usable: {summary['paper_usable_count']}; product usable: {summary['product_usable_count']}")
    lines.append("")
    lines.append("## Source Summary")
    lines.append("| Source | Records | Avg Score | Min Score | Paper | Product | Missing |")
    lines.append("|---|---:|---:|---:|---:|---:|---|")
    for source, item in summary["source_summary"].items():
        lines.append(
            f"| {source} | {item['record_count']} | {item['average_score']} | {item['min_score']} | "
            f"{item['paper_usable_count']} | {item['product_usable_count']} | {', '.join(item['blocking_missing']) or 'none'} |"
        )
    lines.append("")
    lines.append("## Records")
    lines.append("| Subject | Source | Quality | Score | Paper | Product | Missing |")
    lines.append("|---|---|---|---:|---|---|---|")
    for item in result["records"]:
        subject = item["subject"]
        record = item["record"]
        subject_text = f"{subject['algorithm']}-{subject['parameter_set']} {subject['operation']}"
        lines.append(
            f"| {subject_text} | {record['source_type']} | {item['quality']} | {item['score']} | "
            f"{item['paper_usable']} | {item['product_usable']} | {', '.join(item['missing']) or 'none'} |"
        )
    if result["diagnostics"]:
        lines.append("")
        lines.append("## Diagnostics")
        for diag in result["diagnostics"]:
            level = "ERROR" if diag.get("severity") == "error" else "WARN"
            lines.append(f"- {level} `{diag.get('code')}` {diag.get('location')}: {diag.get('message')}")
    return "\n".join(lines) + "\n"
