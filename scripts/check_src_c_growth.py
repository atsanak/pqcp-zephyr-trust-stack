#!/usr/bin/env python3
"""Prove net line growth for tracked top-level src/*.c files."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import PurePosixPath


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args])


def source_paths(revision: str) -> list[str]:
    output = git("ls-tree", "-r", "--name-only", revision, "--", "src")
    paths = output.decode().splitlines()
    return sorted(
        path
        for path in paths
        if PurePosixPath(path).parent == PurePosixPath("src")
        and path.endswith(".c")
    )


def line_count(revision: str) -> tuple[int, int]:
    paths = source_paths(revision)
    lines = 0
    for path in paths:
        content = git("show", f"{revision}:{path}")
        lines += content.count(b"\n")
        if content and not content.endswith(b"\n"):
            lines += 1
    return len(paths), lines


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--target", default="HEAD")
    parser.add_argument("--minimum", type=int, default=20_000)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    baseline_sha = git("rev-parse", args.baseline).decode().strip()
    target_sha = git("rev-parse", args.target).decode().strip()
    baseline_files, baseline_lines = line_count(baseline_sha)
    target_files, target_lines = line_count(target_sha)
    growth = target_lines - baseline_lines

    print(f"baseline_sha={baseline_sha}")
    print(f"baseline_src_c_files={baseline_files}")
    print(f"baseline_src_c_lines={baseline_lines}")
    print(f"target_sha={target_sha}")
    print(f"target_src_c_files={target_files}")
    print(f"target_src_c_lines={target_lines}")
    print(f"net_new_src_c_lines={growth}")
    print(f"required_net_new_src_c_lines={args.minimum}")
    if growth < args.minimum:
        print("result=FAIL")
        return 1
    print("result=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
