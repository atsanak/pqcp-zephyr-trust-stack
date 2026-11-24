# SPDX-License-Identifier: MIT
"""Render the generated decision catalogs for tools that scan C sources.

The catalogs are produced at configure time by CMakeLists.txt and are not
kept in src/. Audit scripts that reason about every C module call
render_generated_sources() to get the same files in a scratch directory.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parent.parent

CATALOG_GENERATORS = (
    "generate_runtime_channel_policy_catalogs.py",
    "generate_runtime_channel_guard_catalogs.py",
    "generate_operation_conformance_catalogs.py",
    "generate_operation_plan_catalogs.py",
    "generate_operation_scenario_catalogs.py",
    "generate_operation_transition_catalogs.py",
)


def render_generated_sources(output_dir: Path, root: Path = MODULE_ROOT) -> list[Path]:
    """Run every catalog generator into output_dir and return the C files."""
    output_dir.mkdir(parents=True, exist_ok=True)
    for name in CATALOG_GENERATORS:
        if not (root / "scripts" / name).exists():
            continue
        subprocess.run(
            [sys.executable, str(root / "scripts" / name),
             "--repo-root", str(root), "--output-dir", str(output_dir)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
    return sorted(output_dir.glob("*.c"))
