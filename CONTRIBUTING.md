# Contributing

Thank you for helping improve this project.

This is a proprietary collaborative project, not an open-source project.

By contributing to this repository, you agree to the following:

1. You are submitting your contribution for the purpose of improving this project in collaboration with Angelos Tsanaktsidis.

2. Your contribution is your own original work, or you have the legal right to submit it.

3. Your contribution does not knowingly violate any third-party intellectual property, confidentiality, employment, or licensing obligations.

4. Angelos Tsanaktsidis may use, modify, integrate, reproduce, and maintain your contribution as part of this project.

5. Submitting a contribution does not give you ownership of the overall project.

6. Submitting a contribution does not give you permission to copy, distribute, commercialize, deploy, or reuse the project outside the permissions stated in the LICENSE file.

7. All contributions must respect the proprietary nature of this repository.

Before contributing, please make sure that your employer, university, or organization does not claim ownership over the contribution you are submitting.

Do not submit confidential code, private data, third-party proprietary material, or anything you are not authorized to share.

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
