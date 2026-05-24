#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Evidence pack builder and replay validator."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .errors import Diagnostic, error, warning
from .fs import discover_files, media_type_for, relative_id, sha256_file, utc_now, write_json_atomic
from .models import EvidenceArtifact, EvidencePackManifest
from .reproducibility import capture_reproducibility_snapshot

MANIFEST_NAME = "evidence-pack-manifest.json"
SUMMARY_NAME = "evidence-pack-summary.json"


class EvidencePackBuilder:
    """Collect artifacts under an output root and bind them to hashes."""

    def __init__(self, module_path: Path):
        self.module_path = module_path.resolve()

    def build(
        self,
        *,
        output_root: Path,
        pack_id: str,
        profile: str,
        tag: str | None = None,
        required: Iterable[str] = (),
    ) -> EvidencePackManifest:
        output_root = output_root.resolve()
        output_root.mkdir(parents=True, exist_ok=True)
        required_set = set(required)
        diagnostics: list[Diagnostic] = []
        artifacts: list[EvidenceArtifact] = []
        for path in discover_files(output_root):
            rel = path.relative_to(output_root).as_posix()
            if rel in {MANIFEST_NAME, SUMMARY_NAME}:
                continue
            artifacts.append(
                EvidenceArtifact(
                    artifact_id=relative_id(path, output_root),
                    relative_path=rel,
                    absolute_path=str(path),
                    sha256=sha256_file(path),
                    size_bytes=path.stat().st_size,
                    media_type=media_type_for(path),
                    required=rel in required_set,
                    status="present",
                )
            )
        present = {item.relative_path for item in artifacts}
        for rel in sorted(required_set - present):
            diagnostics.append(error("artifact_missing", rel, "required artifact missing from output root"))
        if not artifacts:
            diagnostics.append(warning("artifact_empty", str(output_root), "evidence pack contains no artifacts"))
        manifest = EvidencePackManifest(
            schema_version=1,
            pack_id=pack_id,
            output_root=str(output_root),
            generated_at=utc_now(),
            profile=profile,
            tag=tag,
            artifacts=tuple(sorted(artifacts, key=lambda item: item.relative_path)),
            diagnostics=tuple(diagnostics),
            metadata={"reproducibility": capture_reproducibility_snapshot(self.module_path).to_dict()},
        )
        write_json_atomic(output_root / MANIFEST_NAME, manifest.to_dict())
        write_json_atomic(output_root / SUMMARY_NAME, summarize_pack(manifest))
        return manifest

    def validate(self, *, output_root: Path) -> dict[str, object]:
        output_root = output_root.resolve()
        manifest_path = output_root / MANIFEST_NAME
        diagnostics: list[Diagnostic] = []
        if not manifest_path.exists():
            diagnostics.append(error("manifest_missing", str(manifest_path), "evidence pack manifest is missing"))
            return _validation_result(False, diagnostics, [])
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        artifacts = payload.get("artifacts", [])
        checked: list[dict[str, object]] = []
        for artifact in artifacts:
            rel = artifact.get("relative_path", "")
            expected = artifact.get("sha256", "")
            path = output_root / rel
            if not rel or not path.exists():
                diagnostics.append(error("artifact_missing", str(rel), "manifested artifact is missing"))
                checked.append({"relative_path": rel, "status": "missing"})
                continue
            actual = sha256_file(path)
            status = "pass" if actual == expected else "fail"
            if status != "pass":
                diagnostics.append(error("hash_mismatch", str(rel), "artifact hash does not match manifest"))
            checked.append({"relative_path": rel, "expected_sha256": expected, "actual_sha256": actual, "status": status})
        passed = not any(item.is_error for item in diagnostics)
        result = _validation_result(passed, diagnostics, checked)
        write_json_atomic(output_root / "evidence-pack-validation.json", result)
        return result


def summarize_pack(manifest: EvidencePackManifest) -> dict[str, object]:
    required = [artifact for artifact in manifest.artifacts if artifact.required]
    by_type: dict[str, int] = {}
    total_bytes = 0
    for artifact in manifest.artifacts:
        by_type[artifact.media_type] = by_type.get(artifact.media_type, 0) + 1
        total_bytes += artifact.size_bytes
    return {
        "schema_version": 1,
        "pack_id": manifest.pack_id,
        "passed": manifest.passed(),
        "artifact_count": len(manifest.artifacts),
        "required_artifact_count": len(required),
        "total_bytes": total_bytes,
        "media_type_counts": dict(sorted(by_type.items())),
        "diagnostic_count": len(manifest.diagnostics),
    }


def _validation_result(passed: bool, diagnostics: list[Diagnostic], checked: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "passed": passed,
        "checked_artifacts": checked,
        "diagnostics": [item.to_dict() for item in diagnostics],
    }
