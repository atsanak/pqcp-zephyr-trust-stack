#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Prepare local release artifacts without depending on GitHub Actions."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from check_version_consistency import (  # noqa: E402
    normalize_tag,
    parse_cmake_version,
    parse_header_version,
    validate_changelog,
)
from extract_changelog_section import extract_section  # noqa: E402

CHANGELOG_HEADER_RE = re.compile(
    r"^## \[(?P<version>[^\]]+)\](?:\s+-\s+(?P<date>\d{4}-\d{2}-\d{2}))?$",
    re.MULTILINE,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create local release notes, API documentation, and a small "
            "machine-readable release manifest without using GitHub Actions."
        )
    )
    parser.add_argument(
        "--module-path",
        type=Path,
        default=REPO_ROOT,
        help="PQCP module repository root",
    )
    parser.add_argument(
        "--version",
        help="Release version to package. Defaults to PQCP_VERSION_STRING.",
    )
    parser.add_argument(
        "--tag",
        help="Release tag to verify. Defaults to v<version>.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output/release"),
        help="Directory for generated release bundle artifacts.",
    )
    parser.add_argument(
        "--doxygen",
        default=shutil.which("doxygen"),
        help="Path to doxygen. Defaults to the first doxygen on PATH.",
    )
    parser.add_argument(
        "--skip-api-docs",
        action="store_true",
        help="Skip API documentation generation.",
    )
    parser.add_argument(
        "--require-tag-on-head",
        action="store_true",
        help=(
            "Fail if the selected tag does not point to the currently "
            "checked-out commit. Useful when producing an exact tag bundle."
        ),
    )
    parser.add_argument(
        "--require-clean",
        action="store_true",
        help="Fail if the working tree has uncommitted changes.",
    )
    parser.add_argument(
        "--exact-tag",
        action="store_true",
        help=(
            "Strict publishing mode: require a clean checkout and require the "
            "selected tag to point to HEAD."
        ),
    )
    parser.add_argument(
        "--verify-remote-tag",
        action="store_true",
        help="Verify origin has the selected tag object and peeled commit.",
    )
    parser.add_argument(
        "--keep-existing-output",
        action="store_true",
        help=(
            "Do not clean output/release/<tag> before writing. By default the "
            "bundle directory is recreated so stale files cannot survive."
        ),
    )
    return parser.parse_args()


def run(cmd: list[str], cwd: Path, *, input_text: str | None = None) -> str:
    result = subprocess.run(
        cmd,
        cwd=str(cwd),
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        command = " ".join(cmd)
        raise RuntimeError(f"{command} failed with exit {result.returncode}:\n{result.stdout}")
    return result.stdout.strip()


def git(module_path: Path, *args: str) -> str:
    return run(["git", *args], module_path)


def git_optional(module_path: Path, *args: str) -> str | None:
    """Run git and return stripped stdout, or None on non-zero exit.

    Used for queries that may legitimately fail (for example "does this
    tag exist locally?" inside a CI checkout that did not fetch tags).
    """
    result = subprocess.run(
        ["git", *args],
        cwd=str(module_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_release_date(changelog_text: str, version: str) -> str:
    for match in CHANGELOG_HEADER_RE.finditer(changelog_text):
        if match.group("version") == version:
            release_date = match.group("date")
            if not release_date:
                raise RuntimeError(
                    f"CHANGELOG.md [{version}] header is missing an ISO release date"
                )
            return release_date
    raise RuntimeError(f"CHANGELOG.md is missing a [{version}] section")


def parse_west_revision(module_path: Path, project_name: str) -> str | None:
    west_path = module_path / "west.yml"
    if not west_path.exists():
        return None

    in_project = False
    for raw_line in west_path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("- name:"):
            in_project = stripped == f"- name: {project_name}"
            continue
        if in_project and stripped.startswith("revision:"):
            return stripped.split(":", 1)[1].strip().strip("'\"")
    return None


def parse_west_dependencies(module_path: Path) -> dict[str, str]:
    dependencies: dict[str, str] = {}
    for name in ("zephyr", "mlkem-native", "mldsa-native"):
        revision = parse_west_revision(module_path, name)
        if revision is not None:
            dependencies[name] = revision
    return dependencies


def verify_remote_tag(module_path: Path, tag: str, tag_object: str, tag_commit: str) -> None:
    """Verify that origin has the local tag object and peeled commit."""
    output = git(module_path, "ls-remote", "origin", f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}")
    remote: dict[str, str] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 2:
            remote[parts[1]] = parts[0]

    object_ref = f"refs/tags/{tag}"
    commit_ref = f"refs/tags/{tag}^{{}}"
    if remote.get(object_ref) != tag_object:
        raise RuntimeError(
            f"origin {object_ref} mismatch: expected {tag_object}, "
            f"found {remote.get(object_ref, '<missing>')}"
        )
    if remote.get(commit_ref) != tag_commit:
        raise RuntimeError(
            f"origin {commit_ref} mismatch: expected {tag_commit}, "
            f"found {remote.get(commit_ref, '<missing>')}"
        )


def prepare_bundle_dir(bundle_dir: Path, tag: str, *, keep_existing: bool) -> None:
    """Create an idempotent generated bundle directory."""
    if bundle_dir.name != tag:
        raise RuntimeError(
            f"refusing to prepare unsafe bundle path {bundle_dir}: "
            f"final directory name must match tag {tag}"
        )
    if bundle_dir.exists() and not keep_existing:
        shutil.rmtree(bundle_dir)
    bundle_dir.mkdir(parents=True, exist_ok=True)


def generate_api_docs(module_path: Path, bundle_dir: Path, doxygen: str | None) -> Path:
    if doxygen is None:
        raise RuntimeError("doxygen was not found on PATH; install it or pass --skip-api-docs")

    source_doxyfile = module_path / "docs/Doxyfile"
    if not source_doxyfile.exists():
        raise RuntimeError(f"Doxyfile not found at {source_doxyfile}")

    docs_root = bundle_dir / "api-docs"
    warning_log = bundle_dir / "doxygen-warnings.log"
    generated_doxyfile = bundle_dir / "Doxyfile.generated"
    config = source_doxyfile.read_text(encoding="utf-8")
    config += "\n# Local release-bundle overrides\n"
    config += f"OUTPUT_DIRECTORY = {docs_root}\n"
    config += "HTML_OUTPUT = html\n"
    config += f"WARN_LOGFILE = {warning_log}\n"
    generated_doxyfile.write_text(config, encoding="utf-8")

    output = run([doxygen, str(generated_doxyfile)], module_path)
    warnings = warning_log.read_text(encoding="utf-8") if warning_log.exists() else ""
    if warnings.strip():
        raise RuntimeError(f"Doxygen emitted warnings:\n{warnings}")
    if "warning:" in output.lower():
        raise RuntimeError(f"Doxygen emitted warnings:\n{output}")

    index = docs_root / "html/index.html"
    if not index.exists():
        raise RuntimeError(f"Doxygen did not generate {index}")
    return index


def write_manifest(
    *,
    module_path: Path,
    bundle_dir: Path,
    version: str,
    tag: str,
    release_date: str,
    release_notes_path: Path,
    api_docs_index: Path | None,
) -> Path:
    head_commit = git(module_path, "rev-parse", "HEAD")
    tag_object = git_optional(module_path, "rev-parse", f"refs/tags/{tag}")
    tag_commit = git_optional(module_path, "rev-parse", f"refs/tags/{tag}^{{}}")
    if tag_commit is None:
        # Tag not present locally (CI checkout without --tags). The
        # outer main() already accepted this when --tag was inferred;
        # bind the manifest to HEAD so downstream verifiers see a
        # coherent source_commit and a tag_commit pointing at the same
        # checkout.
        tag_commit = head_commit
    dirty = bool(git(module_path, "status", "--porcelain"))
    dependencies = parse_west_dependencies(module_path)
    passport_root = bundle_dir.parent.parent
    passport_artifacts = {}
    for name in (
        "pqc_cbom.cdx.json",
        "pqc_attestation.intoto.json",
        "pqc_policy_result.json",
        "pqc_assurance_digest.json",
        "pqc_assurance_profile_result.json",
        "pqc_evidence_quality_result.json",
        "pqc_migration_readiness.json",
        "pqc_migration_readiness.md",
    ):
        candidate = passport_root / name
        if candidate.exists() and candidate.is_file():
            passport_artifacts[name] = {
                "path": str(candidate.relative_to(passport_root)),
                "sha256": sha256_file(candidate),
            }

    manifest = {
        "schema_version": 1,
        "project": "pqcp-zephyr-trust-stack",
        "version": version,
        "tag": tag,
        "release_date": release_date,
        "source_commit": head_commit,
        "tag_object": tag_object,
        "tag_commit": tag_commit,
        "tag_points_to_head": tag_commit == head_commit,
        "working_tree_dirty": dirty,
        "zephyr_revision": dependencies.get("zephyr"),
        "dependencies": dependencies,
        "release_notes": {
            "path": release_notes_path.name,
            "sha256": sha256_file(release_notes_path),
        },
        "api_docs": (
            {
                "index": str(api_docs_index.relative_to(bundle_dir)),
            }
            if api_docs_index is not None
            else None
        ),
        "passport_artifacts": passport_artifacts,
    }

    manifest_path = bundle_dir / f"release-manifest-{tag}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest_path


def main() -> int:
    args = parse_args()
    module_path = args.module_path.resolve()

    version = args.version or parse_header_version(module_path)
    tag_explicit = args.tag is not None
    tag = args.tag or f"v{version}"
    if normalize_tag(tag) != version:
        raise RuntimeError(f"tag {tag!r} does not match version {version!r}")

    header_version = parse_header_version(module_path)
    cmake_version = parse_cmake_version(module_path)
    failures = []
    if version != header_version:
        failures.append(f"requested version={version} does not match version.h={header_version}")
    if header_version != cmake_version:
        failures.append(f"version.h={header_version} does not match CMakeLists.txt={cmake_version}")
    failures.extend(validate_changelog(module_path / "CHANGELOG.md", version))
    if failures:
        raise RuntimeError("release metadata validation failed:\n  - " + "\n  - ".join(failures))

    # Verify the tag exists before doing any expensive work. If --tag was
    # passed explicitly the tag MUST exist locally (this is a
    # release-publishing path). If the tag was inferred from version.h
    # (no --tag), an absent local tag is allowed — for example, CI
    # checkouts that did not fetch tags. In that case we record that the
    # tag was unresolved and continue with HEAD as the source commit.
    head_commit = git(module_path, "rev-parse", "HEAD")
    tag_object = git_optional(module_path, "rev-parse", f"refs/tags/{tag}")
    tag_commit = git_optional(module_path, "rev-parse", f"refs/tags/{tag}^{{}}")
    if tag_object is None or tag_commit is None:
        if tag_explicit or args.exact_tag or args.require_tag_on_head or args.verify_remote_tag:
            raise RuntimeError(
                f"git rev-parse refs/tags/{tag} failed and --tag/--exact-tag/"
                "--require-tag-on-head/--verify-remote-tag was requested. Fetch "
                f"the tag with `git fetch origin --tags` (or `git fetch origin tag {tag}`)."
            )
        print(
            f"[warn] inferred tag {tag} is not present locally; continuing with "
            "head_commit only. Pass --tag <tag> after fetching tags to bind the "
            "manifest to the tag object.",
            flush=True,
        )
        tag_commit = head_commit
        tag_object = None
    working_tree_dirty = bool(git(module_path, "status", "--porcelain"))
    if (args.require_clean or args.exact_tag) and working_tree_dirty:
        raise RuntimeError("working tree is dirty; commit, stash, or clean changes first")
    if (args.require_tag_on_head or args.exact_tag) and tag_commit != head_commit:
        raise RuntimeError(
            f"{tag} points to {tag_commit}, but the current checkout is {head_commit}"
        )
    if args.verify_remote_tag:
        verify_remote_tag(module_path, tag, tag_object, tag_commit)

    changelog_text = (module_path / "CHANGELOG.md").read_text(encoding="utf-8")
    release_date = parse_release_date(changelog_text, version)
    release_notes = extract_section(changelog_text, version)

    output_dir = args.output_dir
    if not output_dir.is_absolute():
        output_dir = module_path / output_dir
    bundle_dir = output_dir / tag
    prepare_bundle_dir(bundle_dir, tag, keep_existing=args.keep_existing_output)

    release_notes_path = bundle_dir / f"release-notes-{tag}.md"
    release_notes_path.write_text(release_notes, encoding="utf-8")

    api_docs_index = None
    if not args.skip_api_docs:
        api_docs_index = generate_api_docs(module_path, bundle_dir, args.doxygen)

    manifest_path = write_manifest(
        module_path=module_path,
        bundle_dir=bundle_dir,
        version=version,
        tag=tag,
        release_date=release_date,
        release_notes_path=release_notes_path,
        api_docs_index=api_docs_index,
    )

    print("Local release bundle prepared")
    print(f"  version       : {version}")
    print(f"  tag           : {tag}")
    print(f"  tag object    : {tag_object}")
    print(f"  tag commit    : {tag_commit}")
    print(f"  source commit : {head_commit}")
    print(f"  dirty         : {working_tree_dirty}")
    if tag_commit != head_commit:
        print("  note          : tag does not point to current HEAD; manifest records both")
    print(f"  output        : {bundle_dir}")
    print(f"  notes         : {release_notes_path}")
    print(f"  manifest      : {manifest_path}")
    if api_docs_index is not None:
        print(f"  api docs      : {api_docs_index}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
