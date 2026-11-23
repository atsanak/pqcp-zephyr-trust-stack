# Contributing

Thank you for helping improve this project.

This project is MIT-licensed. By submitting a contribution you agree that it
is licensed under the same terms (see [`LICENSE`](LICENSE)), that it is your own
work or you have the right to submit it, and that it does not knowingly violate
third-party intellectual property, confidentiality, employment or licensing
obligations. Make sure your employer, university or organization does not claim
ownership of what you submit, and do not submit confidential code, private data
or anything you are not authorized to share.

## Development workflow

Use conventional commit subjects such as `fix(ci): ...`, `docs(api): ...`, or
`test(kat): ...`. Keep each pull request focused on one logical change.

Before opening a pull request, run the fastest applicable checks locally:

```bash
python3 -m py_compile scripts/*.py
python3 scripts/test_local_release_workflows.py
python3 scripts/test_assurance_ledger.py
python3 scripts/test_release_evidence_pack.py
python3 scripts/check_version_consistency.py --changelog CHANGELOG.md --tag v1.0.0
```

For release-sensitive changes, also run:

```bash
python3 scripts/release_check.py --tag v1.0.0 --output-root /tmp/pqcp-release-check
```

Do not change stable public C APIs, ACVP wire-format tokens, or
`PQCP_METRIC` field ordering without discussing the compatibility impact first.
