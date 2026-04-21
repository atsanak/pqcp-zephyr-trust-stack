## Summary

<!-- One or two sentences describing the user-visible change. Call out
     whether this is a bug fix, new feature, refactor, or docs/CI work. -->

## Changes

<!-- Bulleted list of the concrete changes in this PR. Link to files,
     scripts, Kconfig symbols, or CI jobs where useful. -->

-

## Testing

<!-- Describe the verification you ran. Include the exact commands and
     their outcomes. Paste relevant PQCP_METRIC, ACVP, or ztest output
     lines. -->

-

## Release notes

<!-- If this PR introduces a user-visible change, add the CHANGELOG
     line you expect to land under [Unreleased] and delete this
     comment. If not, just write "No user-visible change". -->

## Checklist

- [ ] `python3 -m py_compile scripts/*.py` passes
- [ ] `python3 scripts/run_extended_checks.py --strict` passes locally
- [ ] New or changed C code compiles with `-Wall -Wextra -Werror` on
      both ARM and x86 targets covered by CI
- [ ] No absolute filesystem paths (`/Users/...`, `C:\Users\...`,
      `/home/<name>/...`) are added to any committed file
- [ ] CHANGELOG.md `[Unreleased]` section updated if this change is
      user-visible (API, Kconfig, wire protocol, release gate)
- [ ] Public contracts in `include/pqcp_zephyr/acvp_cmd.h`,
      `PQCP_METRIC` log format, regression JSON field names, or
      benchmark provenance schema are unchanged — or, if changed, the
      rationale and the upgrade path are documented in the commit body
- [ ] Relevant ztest / sample covers the new or changed behaviour
- [ ] For security-sensitive changes: filed a draft GitHub Security
      Advisory first (see `SECURITY.md`)

## Related issues

Fixes #
