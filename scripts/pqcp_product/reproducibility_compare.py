#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Cross-run reproducibility comparison for evidence packs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import Diagnostic, error, warning
from .fs import sha256_file, utc_now, write_json_atomic, write_text_atomic

MANIFEST_NAME = "evidence-pack-manifest.json"
STABLE_METADATA_KEYS = ("schema_version", "pack_id", "profile", "tag")
VOLATILE_ARTIFACT_KEYS = {"absolute_path"}


def compare_evidence_packs(*, packs: list[Path], output_root: Path) -> dict[str, Any]:
    """Compare two or more evidence pack manifests and artifact hashes."""

    output_root.mkdir(parents=True, exist_ok=True)
    diagnostics: list[Diagnostic] = []
    if len(packs) < 2:
        diagnostics.append(error("repro_pack_count", "packs", "at least two evidence packs are required"))
        result = _result("FAIL", packs, [], diagnostics, [])
        _write_outputs(output_root, result)
        return result

    loaded: list[dict[str, Any]] = []
    for pack in packs:
        manifest_path = pack / MANIFEST_NAME
        if not manifest_path.exists():
            diagnostics.append(error("repro_manifest_missing", str(manifest_path), "evidence pack manifest is missing"))
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            diagnostics.append(error("repro_manifest_json", str(manifest_path), f"manifest JSON is invalid: {exc}"))
            continue
        loaded.append({"pack": pack, "manifest_path": manifest_path, "manifest": manifest})

    if len(loaded) < 2:
        diagnostics.append(error("repro_manifest_floor", "packs", "fewer than two readable manifests"))
        result = _result("FAIL", packs, loaded, diagnostics, [])
        _write_outputs(output_root, result)
        return result

    baseline = loaded[0]
    comparisons: list[dict[str, Any]] = []
    baseline_manifest = baseline["manifest"]
    baseline_artifacts = _artifact_map(baseline_manifest)
    for candidate in loaded[1:]:
        candidate_manifest = candidate["manifest"]
        candidate_artifacts = _artifact_map(candidate_manifest)
        comparison = {
            "baseline_pack": str(baseline["pack"]),
            "candidate_pack": str(candidate["pack"]),
            "metadata": _compare_metadata(baseline_manifest, candidate_manifest, diagnostics, str(candidate["pack"])),
            "artifacts": _compare_artifacts(
                baseline_artifacts,
                candidate_artifacts,
                diagnostics,
                baseline_pack=baseline["pack"],
                candidate_pack=candidate["pack"],
            ),
        }
        comparisons.append(comparison)

    status = _status_from_diagnostics(diagnostics)
    result = _result(status, packs, loaded, diagnostics, comparisons)
    _write_outputs(output_root, result)
    return result


def _artifact_map(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    artifacts: dict[str, dict[str, Any]] = {}
    for artifact in manifest.get("artifacts", []):
        rel = str(artifact.get("relative_path", ""))
        if rel:
            artifacts[rel] = dict(artifact)
    return artifacts


def _compare_metadata(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    diagnostics: list[Diagnostic],
    location: str,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for key in STABLE_METADATA_KEYS:
        base_value = baseline.get(key)
        candidate_value = candidate.get(key)
        match = base_value == candidate_value
        if not match:
            diagnostics.append(
                error(
                    "repro_metadata_mismatch",
                    f"{location}:{key}",
                    f"stable metadata differs: {base_value!r} != {candidate_value!r}",
                )
            )
        rows.append({"key": key, "baseline": base_value, "candidate": candidate_value, "match": match})
    return {"stable_keys": rows}


def _compare_artifacts(
    baseline_artifacts: dict[str, dict[str, Any]],
    candidate_artifacts: dict[str, dict[str, Any]],
    diagnostics: list[Diagnostic],
    *,
    baseline_pack: Path,
    candidate_pack: Path,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    all_paths = sorted(set(baseline_artifacts) | set(candidate_artifacts))
    for rel in all_paths:
        base = baseline_artifacts.get(rel)
        candidate = candidate_artifacts.get(rel)
        if base is None:
            diagnostics.append(warning("repro_extra_artifact", f"{candidate_pack}:{rel}", "candidate has extra artifact"))
            rows.append({"relative_path": rel, "status": "extra", "required": bool(candidate and candidate.get("required"))})
            continue
        required = bool(base.get("required"))
        if candidate is None:
            diag = error if required else warning
            diagnostics.append(diag("repro_missing_artifact", f"{candidate_pack}:{rel}", "candidate is missing artifact"))
            rows.append({"relative_path": rel, "status": "missing", "required": required})
            continue
        if not _artifact_file_exists(candidate_pack, candidate):
            diag = error if required else warning
            diagnostics.append(diag("repro_missing_artifact", f"{candidate_pack}:{rel}", "candidate artifact file is missing"))
            rows.append({"relative_path": rel, "status": "missing", "required": required})
            continue
        if not _artifact_file_exists(baseline_pack, base):
            diag = error if required else warning
            diagnostics.append(diag("repro_missing_artifact", f"{baseline_pack}:{rel}", "baseline artifact file is missing"))
            rows.append({"relative_path": rel, "status": "missing", "required": required})
            continue
        base_hash = _actual_or_manifest_hash(baseline_pack, base)
        candidate_hash = _actual_or_manifest_hash(candidate_pack, candidate)
        status = "match" if base_hash == candidate_hash else "changed"
        if status == "changed":
            diag = error if required else warning
            diagnostics.append(
                diag(
                    "repro_hash_drift",
                    f"{candidate_pack}:{rel}",
                    f"{'required' if required else 'optional'} artifact hash changed",
                )
            )
        rows.append(
            {
                "relative_path": rel,
                "required": required,
                "baseline_sha256": base_hash,
                "candidate_sha256": candidate_hash,
                "status": status,
            }
        )
    return {"artifact_count": len(rows), "rows": rows}


def _actual_or_manifest_hash(pack: Path, artifact: dict[str, Any]) -> str:
    rel = artifact.get("relative_path")
    if rel:
        path = pack / str(rel)
        if path.exists():
            return sha256_file(path)
    return str(artifact.get("sha256", ""))


def _artifact_file_exists(pack: Path, artifact: dict[str, Any]) -> bool:
    rel = artifact.get("relative_path")
    return bool(rel and (pack / str(rel)).exists())


def _status_from_diagnostics(diagnostics: list[Diagnostic]) -> str:
    if any(item.is_error for item in diagnostics):
        return "FAIL"
    if any(item.is_warning for item in diagnostics):
        return "WARN"
    return "PASS"


def _result(
    status: str,
    packs: list[Path],
    loaded: list[dict[str, Any]],
    diagnostics: list[Diagnostic],
    comparisons: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": status,
        "passed": status != "FAIL",
        "pack_roots": [str(pack) for pack in packs],
        "manifest_count": len(loaded),
        "comparisons": comparisons,
        "diagnostics": [item.to_dict() for item in diagnostics],
    }


def _write_outputs(output_root: Path, result: dict[str, Any]) -> None:
    write_json_atomic(output_root / "cross-run-reproducibility-report.json", result)
    write_text_atomic(output_root / "cross-run-reproducibility-summary.md", render_reproducibility_summary(result))


def render_reproducibility_summary(result: dict[str, Any]) -> str:
    lines = [
        "# Cross-Run Reproducibility",
        "",
        f"Status: **{result['status']}**",
        f"Manifests compared: {result['manifest_count']}",
        "",
    ]
    for comparison in result.get("comparisons", []):
        lines.append(f"## {comparison['candidate_pack']}")
        for row in comparison.get("artifacts", {}).get("rows", []):
            marker = "OK" if row.get("status") == "match" else row.get("status", "unknown").upper()
            lines.append(f"- `{row['relative_path']}`: {marker}")
        lines.append("")
    if result.get("diagnostics"):
        lines.append("## Diagnostics")
        for diag in result["diagnostics"]:
            lines.append(f"- {diag['severity'].upper()} `{diag['code']}` `{diag['location']}`: {diag['message']}")
    return "\n".join(lines).rstrip() + "\n"
