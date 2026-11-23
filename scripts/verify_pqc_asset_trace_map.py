#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify the PQC asset-to-evidence trace map used by the Assurance Passport."""

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
    parser.add_argument("--ledger", type=Path)
    parser.add_argument("--cbom", type=Path)
    parser.add_argument("--module-path", type=Path, default=REPO_ROOT)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def load_json(path: Path, label: str, failures: list[str]) -> Any:
    if not path.exists():
        failures.append(f"{label} not found: {path}")
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        failures.append(f"{label} is not valid JSON: {exc}")
        return {}


def kconfig_symbols(module_path: Path) -> set[str]:
    symbols: set[str] = set()
    for path in [module_path / "Kconfig", module_path / "zephyr/Kconfig"]:
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("config "):
                symbols.add(stripped.split(None, 1)[1])
            elif stripped.startswith("menuconfig "):
                symbols.add(stripped.split(None, 1)[1])
    return symbols


def ledger_claims(ledger_path: Path | None, failures: list[str]) -> set[str] | None:
    if ledger_path is None:
        return None
    ledger = load_json(ledger_path, "assurance ledger", failures)
    if not isinstance(ledger, dict):
        failures.append("assurance ledger root must be a JSON object")
        return set()
    claims = ledger.get("claims")
    if not isinstance(claims, list):
        failures.append("assurance ledger claims must be a list")
        return set()
    return {
        claim["id"]
        for claim in claims
        if isinstance(claim, dict) and isinstance(claim.get("id"), str)
    }


def cbom_components(cbom_path: Path | None, failures: list[str]) -> set[str] | None:
    if cbom_path is None:
        return None
    cbom = load_json(cbom_path, "PQC CBOM", failures)
    if not isinstance(cbom, dict):
        failures.append("PQC CBOM root must be a JSON object")
        return set()
    components = cbom.get("components")
    if not isinstance(components, list):
        failures.append("PQC CBOM components must be a list")
        return set()
    return {
        component["name"]
        for component in components
        if isinstance(component, dict) and isinstance(component.get("name"), str)
    }


def require_string_list(asset: dict[str, Any], key: str, failures: list[str]) -> list[str]:
    value = asset.get(key)
    if value is None:
        failures.append(f"asset {asset.get('id', '<unknown>')} missing {key}")
        return []
    if not isinstance(value, list):
        failures.append(f"asset {asset.get('id', '<unknown>')} {key} must be a list")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            failures.append(
                f"asset {asset.get('id', '<unknown>')} {key}[{index}] must be a non-empty string"
            )
            continue
        result.append(item)
    return result


def verify_trace_map(
    *,
    trace_map_path: Path = DEFAULT_TRACE_MAP,
    module_path: Path = REPO_ROOT,
    ledger_path: Path | None = None,
    cbom_path: Path | None = None,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: list[dict[str, Any]] = []
    trace_map = load_json(trace_map_path, "PQC asset trace map", failures)
    known_kconfig = kconfig_symbols(module_path)
    known_claims = ledger_claims(ledger_path, failures)
    known_components = cbom_components(cbom_path, failures)

    if not isinstance(trace_map, dict):
        failures.append("PQC asset trace map root must be a JSON object")
        assets: list[Any] = []
    else:
        if trace_map.get("schema_version") != 1:
            failures.append(
                f"unsupported PQC asset trace map schema_version {trace_map.get('schema_version')!r}"
            )
        assets = trace_map.get("assets") if isinstance(trace_map.get("assets"), list) else []
        if not assets:
            failures.append("PQC asset trace map must contain at least one asset")

    seen_ids: set[str] = set()
    for asset in assets:
        if not isinstance(asset, dict):
            failures.append("asset entry must be a JSON object")
            continue
        asset_id = asset.get("id")
        if not isinstance(asset_id, str) or not asset_id.strip():
            failures.append("asset missing non-empty id")
            continue
        if asset_id in seen_ids:
            failures.append(f"duplicate asset id: {asset_id}")
        seen_ids.add(asset_id)

        name = asset.get("name")
        if not isinstance(name, str) or not name.strip():
            failures.append(f"asset {asset_id} missing non-empty name")

        for rel_path in require_string_list(asset, "source_files", failures):
            path = module_path / rel_path
            ok = path.exists()
            checks.append({"check": "source_file", "asset": asset_id, "path": rel_path, "passed": ok})
            if not ok:
                failures.append(f"asset {asset_id} source file not found: {rel_path}")

        for rel_path in require_string_list(asset, "ztests", failures):
            path = module_path / rel_path
            ok = path.exists()
            checks.append({"check": "ztest_path", "asset": asset_id, "path": rel_path, "passed": ok})
            if not ok:
                failures.append(f"asset {asset_id} ztest path not found: {rel_path}")

        for symbol in require_string_list(asset, "kconfig_symbols", failures):
            ok = symbol in known_kconfig
            checks.append({"check": "kconfig_symbol", "asset": asset_id, "symbol": symbol, "passed": ok})
            if not ok:
                failures.append(f"asset {asset_id} Kconfig symbol not found: {symbol}")

        for marker in require_string_list(asset, "transcript_markers", failures):
            ok = bool(marker.strip())
            checks.append({"check": "transcript_marker", "asset": asset_id, "marker": marker, "passed": ok})

        claim_ids = require_string_list(asset, "claim_ids", failures)
        if known_claims is not None:
            for claim_id in claim_ids:
                ok = claim_id in known_claims
                checks.append({"check": "ledger_claim", "asset": asset_id, "claim_id": claim_id, "passed": ok})
                if not ok:
                    failures.append(f"asset {asset_id} claim id missing from ledger: {claim_id}")

        component = asset.get("cbom_component")
        if component is not None:
            if not isinstance(component, str) or not component.strip():
                failures.append(f"asset {asset_id} cbom_component must be null or non-empty string")
            elif known_components is not None:
                ok = component in known_components
                checks.append(
                    {
                        "check": "cbom_component",
                        "asset": asset_id,
                        "component": component,
                        "passed": ok,
                    }
                )
                if not ok:
                    failures.append(f"asset {asset_id} CBOM component missing: {component}")

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "trace_map": str(trace_map_path),
        "asset_count": len(seen_ids),
        "passed": not failures,
        "failures": failures,
        "checks": checks,
    }


def main() -> int:
    args = parse_args()
    result = verify_trace_map(
        trace_map_path=args.trace_map,
        module_path=args.module_path,
        ledger_path=args.ledger,
        cbom_path=args.cbom,
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if result["passed"]:
        print(f"PQC asset trace map passed: {result['asset_count']} assets")
        return 0
    print("PQC asset trace map failed:", file=sys.stderr)
    for failure in result["failures"]:
        print(f"  - {failure}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
