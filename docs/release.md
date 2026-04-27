# Local Release Packaging

This repository can prepare release artifacts locally without GitHub Actions.
Use this path when Actions minutes, billing, or the GitHub Release workflow are
unavailable but the code/tag side has already been validated.

## What This Produces

`scripts/prepare_release_bundle.py` writes an ignored local bundle under
`output/release/<tag>/` containing:

- `release-notes-<tag>.md`, extracted from the matching `CHANGELOG.md` section
- `release-manifest-<tag>.json`, recording version, tag object, tag commit,
  current source commit, release date, Zephyr revision, and dependency pins
- `api-docs/html/`, generated from `docs/Doxyfile`

The script does not mutate repository source files.

## Exact-Tag Release Bundle

For artifacts that exactly match the release tag, run from a checkout of the
tag itself:

```bash
git fetch origin --tags
git checkout v1.0.0
python3 scripts/prepare_release_bundle.py --require-tag-on-head
```

The `--require-tag-on-head` flag fails if the selected tag does not point to
the current checkout. That is the recommended mode for publishing replacement
assets for a tagged release.

## Maintainer-Branch Bundle

For post-tag maintainer hardening work, run from `main` without
`--require-tag-on-head`:

```bash
python3 scripts/prepare_release_bundle.py --tag v1.0.0
```

When the current branch has moved beyond the tag, the manifest records both
`source_commit` and `tag_commit` and sets `tag_points_to_head=false`. This is
useful for auditing local documentation/package work, but it should not be
presented as the exact tagged source bundle.

## Validation

Before relying on a local bundle, run:

```bash
python3 -m py_compile scripts/*.py
python3 scripts/check_version_consistency.py --changelog CHANGELOG.md --tag v1.0.0
python3 scripts/release_check.py
python3 scripts/prepare_release_bundle.py --tag v1.0.0
```

If GitHub Actions is later restored, rerun the normal release workflow and
compare the generated release notes with `output/release/v1.0.0/release-notes-v1.0.0.md`.
