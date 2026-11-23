#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate a PQC assurance evidence graph from the asset trace map."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_TRACE_MAP = SCRIPT_DIR / "pqc_asset_trace_map.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace-map", type=Path, default=DEFAULT_TRACE_MAP)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--cbom", type=Path, required=True)
    parser.add_argument("--attestation", type=Path)
    parser.add_argument("--transcript-manifest", type=Path)
    parser.add_argument("--release-manifest", type=Path)
    parser.add_argument("--policy-result", type=Path)
    parser.add_argument("--ct-instruction-policy-result", type=Path)
    parser.add_argument("--module-path", type=Path, default=REPO_ROOT)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--output-md", type=Path, required=True)
    return parser.parse_args()


def load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"{label} not found: {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError(f"{label} root must be a JSON object: {path}")
    return raw


def ledger_claims(ledger: dict[str, Any]) -> set[str]:
    claims = ledger.get("claims")
    if not isinstance(claims, list):
        raise RuntimeError("assurance ledger claims must be a list")
    return {
        claim["id"]
        for claim in claims
        if isinstance(claim, dict) and isinstance(claim.get("id"), str)
    }


def cbom_components(cbom: dict[str, Any]) -> set[str]:
    components = cbom.get("components")
    if not isinstance(components, list):
        raise RuntimeError("PQC CBOM components must be a list")
    return {
        component["name"]
        for component in components
        if isinstance(component, dict) and isinstance(component.get("name"), str)
    }


def add_node(
    nodes: dict[str, dict[str, Any]],
    *,
    node_id: str,
    node_type: str,
    label: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    nodes.setdefault(
        node_id,
        {
            "id": node_id,
            "type": node_type,
            "label": label,
            "metadata": metadata or {},
        },
    )


def add_edge(edges: list[dict[str, str]], source: str, target: str, relationship: str) -> None:
    edge = {"from": source, "to": target, "relationship": relationship}
    if edge not in edges:
        edges.append(edge)


def require_string_list(asset: dict[str, Any], key: str) -> list[str]:
    value = asset.get(key)
    if value is None:
        raise RuntimeError(f"asset {asset.get('id', '<unknown>')} missing {key}")
    if not isinstance(value, list):
        raise RuntimeError(f"asset {asset.get('id', '<unknown>')} {key} must be a list")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise RuntimeError(
                f"asset {asset.get('id', '<unknown>')} {key} entries must be non-empty strings"
            )
        result.append(item)
    return result


def build_graph(
    *,
    trace_map_path: Path,
    ledger_path: Path,
    cbom_path: Path,
    module_path: Path = REPO_ROOT,
    attestation_path: Path | None = None,
    transcript_manifest_path: Path | None = None,
    release_manifest_path: Path | None = None,
    policy_result_path: Path | None = None,
    ct_instruction_policy_result_path: Path | None = None,
) -> dict[str, Any]:
    trace_map = load_json(trace_map_path, "PQC asset trace map")
    ledger = load_json(ledger_path, "assurance ledger")
    cbom = load_json(cbom_path, "PQC CBOM")
    known_claims = ledger_claims(ledger)
    known_components = cbom_components(cbom)

    assets = trace_map.get("assets")
    if trace_map.get("schema_version") != 1:
        raise RuntimeError(
            f"unsupported PQC asset trace map schema_version {trace_map.get('schema_version')!r}"
        )
    if not isinstance(assets, list) or not assets:
        raise RuntimeError("PQC asset trace map must contain at least one asset")

    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []
    failures: list[str] = []

    artifact_paths = {
        "ledger": ledger_path,
        "cbom": cbom_path,
        "attestation": attestation_path,
        "transcript_manifest": transcript_manifest_path,
        "release_manifest": release_manifest_path,
        "policy_result": policy_result_path,
        "ct_instruction_policy_result": ct_instruction_policy_result_path,
    }
    for name, path in artifact_paths.items():
        if path is None:
            continue
        if not path.exists():
            failures.append(f"artifact not found: {name} -> {path}")
            continue
        add_node(
            nodes,
            node_id=f"artifact:{name}",
            node_type="artifact",
            label=path.name,
            metadata={"path": str(path)},
        )

    seen_assets: set[str] = set()
    for asset in assets:
        if not isinstance(asset, dict):
            failures.append("asset entry must be a JSON object")
            continue
        asset_id = asset.get("id")
        if not isinstance(asset_id, str) or not asset_id.strip():
            failures.append("asset missing non-empty id")
            continue
        if asset_id in seen_assets:
            failures.append(f"duplicate asset id: {asset_id}")
            continue
        seen_assets.add(asset_id)
        asset_node = f"asset:{asset_id}"
        add_node(
            nodes,
            node_id=asset_node,
            node_type="asset",
            label=str(asset.get("name") or asset_id),
            metadata={"category": asset.get("category")},
        )

        component = asset.get("cbom_component")
        if component is not None:
            if component not in known_components:
                failures.append(f"asset {asset_id} CBOM component missing: {component}")
            component_node = f"cbom:{component}"
            add_node(nodes, node_id=component_node, node_type="cbom_component", label=str(component))
            add_edge(edges, asset_node, component_node, "inventoried_as")
            add_edge(edges, component_node, "artifact:cbom", "declared_in")

        for rel_path in require_string_list(asset, "source_files"):
            exists = (module_path / rel_path).exists()
            if not exists:
                failures.append(f"asset {asset_id} source file not found: {rel_path}")
            file_node = f"file:{rel_path}"
            add_node(
                nodes,
                node_id=file_node,
                node_type="source_file",
                label=rel_path,
                metadata={"exists": exists},
            )
            add_edge(edges, asset_node, file_node, "implemented_by")

        for symbol in require_string_list(asset, "kconfig_symbols"):
            symbol_node = f"kconfig:{symbol}"
            add_node(nodes, node_id=symbol_node, node_type="kconfig_symbol", label=symbol)
            add_edge(edges, asset_node, symbol_node, "configured_by")

        for test_path in require_string_list(asset, "ztests"):
            exists = (module_path / test_path).exists()
            if not exists:
                failures.append(f"asset {asset_id} ztest path not found: {test_path}")
            test_node = f"test:{test_path}"
            add_node(
                nodes,
                node_id=test_node,
                node_type="ztest",
                label=test_path,
                metadata={"exists": exists},
            )
            add_edge(edges, asset_node, test_node, "tested_by")

        for claim_id in require_string_list(asset, "claim_ids"):
            if claim_id not in known_claims:
                failures.append(f"asset {asset_id} claim id missing from ledger: {claim_id}")
            claim_node = f"claim:{claim_id}"
            add_node(
                nodes,
                node_id=claim_node,
                node_type="claim",
                label=claim_id,
                metadata={"present_in_ledger": claim_id in known_claims},
            )
            add_edge(edges, asset_node, claim_node, "supported_by_claim")
            add_edge(edges, claim_node, "artifact:ledger", "declared_in")

        for marker in require_string_list(asset, "transcript_markers"):
            marker_node = f"marker:{asset_id}:{marker}"
            add_node(nodes, node_id=marker_node, node_type="transcript_marker", label=marker)
            add_edge(edges, asset_node, marker_node, "evidenced_by_marker")
            if transcript_manifest_path:
                add_edge(edges, marker_node, "artifact:transcript_manifest", "bound_by")

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": ledger.get("project", "pqcp-zephyr-trust-stack"),
        "version": ledger.get("version"),
        "tag": ledger.get("tag"),
        "head_sha": ledger.get("head_sha"),
        "dirty": ledger.get("dirty"),
        "summary": {
            "assets": len(seen_assets),
            "nodes": len(nodes),
            "edges": len(edges),
            "failures": len(failures),
        },
        "failures": failures,
        "nodes": sorted(nodes.values(), key=lambda node: node["id"]),
        "edges": sorted(edges, key=lambda edge: (edge["from"], edge["to"], edge["relationship"])),
    }


def render_markdown(graph: dict[str, Any]) -> str:
    lines = [
        "# PQC Evidence Graph",
        "",
        f"- Schema: {graph.get('schema_version')}",
        f"- Version: {graph.get('version')}",
        f"- Tag: {graph.get('tag')}",
        f"- Head SHA: {graph.get('head_sha')}",
        f"- Assets: {graph.get('summary', {}).get('assets')}",
        f"- Nodes: {graph.get('summary', {}).get('nodes')}",
        f"- Edges: {graph.get('summary', {}).get('edges')}",
        "",
    ]
    failures = graph.get("failures") or []
    if failures:
        lines.append("## Failures")
        lines.append("")
        for failure in failures:
            lines.append(f"- {failure}")
        lines.append("")

    lines.append("## Assets")
    lines.append("")
    asset_nodes = [node for node in graph.get("nodes", []) if node.get("type") == "asset"]
    for node in asset_nodes:
        outgoing = [
            edge
            for edge in graph.get("edges", [])
            if edge.get("from") == node.get("id")
        ]
        lines.append(f"### {node.get('label')}")
        lines.append("")
        lines.append(f"- Asset ID: `{node.get('id')}`")
        lines.append(f"- Category: `{(node.get('metadata') or {}).get('category')}`")
        lines.append(f"- Evidence edges: {len(outgoing)}")
        lines.append("")

    lines.append("## Claim Links")
    lines.append("")
    claim_nodes = [node for node in graph.get("nodes", []) if node.get("type") == "claim"]
    for node in claim_nodes:
        lines.append(f"- `{node.get('label')}`")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    try:
        graph = build_graph(
            trace_map_path=args.trace_map,
            ledger_path=args.ledger,
            cbom_path=args.cbom,
            module_path=args.module_path,
            attestation_path=args.attestation,
            transcript_manifest_path=args.transcript_manifest,
            release_manifest_path=args.release_manifest,
            policy_result_path=args.policy_result,
            ct_instruction_policy_result_path=args.ct_instruction_policy_result,
        )
    except (OSError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(graph, indent=2) + "\n", encoding="utf-8")
    args.output_md.write_text(render_markdown(graph), encoding="utf-8")

    if graph["failures"]:
        print("PQC evidence graph failed:", file=sys.stderr)
        for failure in graph["failures"]:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(
        "PQC evidence graph generated: "
        f"{graph['summary']['assets']} assets, "
        f"{graph['summary']['nodes']} nodes, "
        f"{graph['summary']['edges']} edges"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
