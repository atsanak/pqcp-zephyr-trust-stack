#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Filesystem helpers with deterministic paths and atomic writes."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .errors import ConfigurationError, Diagnostic, error


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigurationError(f"missing JSON file: {path}") from exc
    except json.JSONDecodeError as exc:
        diag = error("invalid_json", str(path), f"JSON parsing failed: {exc}")
        raise ConfigurationError(f"invalid JSON file: {path}", [diag]) from exc


def write_json_atomic(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    write_text_atomic(path, text)


def write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp_name, path)
    finally:
        tmp_path = Path(tmp_name)
        if tmp_path.exists():
            tmp_path.unlink()


def safe_relpath(path: str | Path) -> str:
    text = str(path).replace("\\", "/")
    parts = [part for part in text.split("/") if part not in {"", "."}]
    if any(part == ".." for part in parts) or text.startswith("/"):
        raise ConfigurationError(f"unsafe relative path: {path}")
    return "/".join(parts)


def ensure_within_root(root: Path, child: Path) -> Path:
    root_resolved = root.resolve()
    child_resolved = child.resolve()
    try:
        child_resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise ConfigurationError(f"path escapes output root: {child}") from exc
    return child_resolved


def deterministic_slug(value: str, max_length: int = 96) -> str:
    out = []
    for char in value.lower():
        if char.isalnum():
            out.append(char)
        elif char in {"-", "_", "."}:
            out.append(char)
        else:
            out.append("-")
    slug = "".join(out).strip("-._")
    while "--" in slug:
        slug = slug.replace("--", "-")
    if not slug:
        slug = "item"
    if len(slug) > max_length:
        digest = sha256_text(value)[:12]
        slug = f"{slug[: max_length - 13]}-{digest}"
    return slug


def discover_files(root: Path, *, include_hidden: bool = False) -> list[Path]:
    files: list[Path] = []
    if not root.exists():
        return files
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if not include_hidden and any(part.startswith(".") for part in rel.parts):
            continue
        files.append(path)
    return sorted(files)


def media_type_for(path: Path) -> str:
    suffix = path.suffix.lower()
    mapping = {
        ".json": "application/json",
        ".md": "text/markdown",
        ".txt": "text/plain",
        ".log": "text/plain",
        ".csv": "text/csv",
        ".html": "text/html",
        ".xml": "application/xml",
        ".yaml": "application/yaml",
        ".yml": "application/yaml",
    }
    return mapping.get(suffix, "application/octet-stream")


def copy_file_with_hash(src: Path, dst: Path) -> dict[str, Any]:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return {
        "source": str(src),
        "destination": str(dst),
        "sha256": sha256_file(dst),
        "size_bytes": dst.stat().st_size,
    }


def validate_required_paths(root: Path, required: Iterable[str]) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    for item in required:
        rel = safe_relpath(item)
        path = root / rel
        if not path.exists():
            diagnostics.append(error("artifact_missing", rel, "required artifact is missing"))
    return diagnostics


def relative_id(path: Path, root: Path) -> str:
    rel = path.relative_to(root).as_posix()
    return deterministic_slug(rel.replace("/", "."))


def mkdir_clean(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def json_digest(payload: Any) -> str:
    return sha256_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def read_text_lossless(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def write_command_transcript(path: Path, command: str, stdout: str, stderr: str, returncode: int) -> str:
    transcript = (
        f"$ {command}\n"
        "--- stdout ---\n"
        f"{stdout}"
        "\n--- stderr ---\n"
        f"{stderr}"
        "\n--- returncode ---\n"
        f"{returncode}\n"
    )
    write_text_atomic(path, transcript)
    return sha256_text(transcript)


def count_text_lines(path: Path) -> int:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return sum(1 for _ in handle)
    except FileNotFoundError:
        return 0


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in discover_files(root):
        rel = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(rel)
        digest.update(b"\0")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()
