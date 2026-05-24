# Evidence Schema Contract And Product Data Boundary

The audit and market strategy identify a missing product layer: stable evidence-pack schemas. Without schemas, every partner dashboard, customer integration, or paper artifact reviewer must infer JSON structure from producer scripts. That is brittle and not product-grade.

This patch introduces `schemas/evidence/` and `scripts/validate_evidence_schemas.py` as the explicit data boundary between release-pack producers and downstream consumers.

## What This Adds

- A catalog of release-pack artifacts and the profiles that require them.
- Per-artifact schemas for ledger, transcript manifest, benchmark provenance, CBOM, policy result, attestation, reference values, campaign outputs, partner scorecards, and device-evidence outputs.
- A standard-library validator that checks catalog health, artifact shape, CSV columns, SHA-256 formats, safe paths, claim IDs, and cross-artifact metadata alignment.
- Tests with synthetic release packs that prove missing artifacts, malformed hashes, stale release metadata, and transcript hash drift fail loudly.

## Why This Matters

Research reviewers need stable artifacts to reproduce experiments. Product partners need stable data contracts before building dashboards, internal policy checks, or supplier-review workflows. The schema contract does not replace semantic replay; it gives replay a documented input boundary.

## Relationship To Existing Verifiers

- `scripts/verify_release_evidence_pack.py` remains the semantic replay verifier.
- `scripts/validate_evidence_schemas.py` validates artifact shape and product-facing data contracts.
- `schemas/evidence/evidence_schema_catalog.json` declares which artifacts are required for each pack profile.

## Recommended Release Flow

```bash
python3 scripts/release_check.py --tag v1.0.0 --output-root /tmp/pqcp-release-pack
python3 scripts/validate_evidence_schemas.py --output-root /tmp/pqcp-release-pack --tag v1.0.0 --profile partner_review
python3 scripts/verify_release_evidence_pack.py /tmp/pqcp-release-pack --tag v1.0.0
```

For dashboards, use the catalog to discover artifacts instead of hard-coding paths. For product releases, update schemas before changing artifact shape.

## Profile Contract Matrix

This matrix is generated from `schemas/evidence/evidence_schema_catalog.json`. It is intentionally duplicated in human-readable documentation so product reviewers can see which artifacts become mandatory as a pack moves from a local QEMU release to partner review and product-MVP readiness.

| Artifact | CI Fast | QEMU Release | Partner Review | Product MVP | Hardware Review |
| --- | --- | --- | --- | --- | --- |
| `acvp_json_interop_result` | no | no | yes | yes | no |
| `acvp_json_schema_result` | no | no | yes | yes | no |
| `acvp_json_transcript_manifest` | no | no | yes | yes | no |
| `acvp_negative_scenario_floor_result` | no | no | yes | yes | no |
| `assurance_ledger` | no | yes | yes | yes | no |
| `assurance_ledger_markdown` | no | yes | yes | no | no |
| `assurance_report_html` | no | no | yes | yes | no |
| `backend_contract_result` | no | no | yes | yes | no |
| `backend_update_evaluation` | no | no | yes | no | no |
| `benchmark_campaign_result` | no | no | yes | yes | no |
| `benchmark_campaign_verify_result` | no | no | yes | yes | no |
| `benchmark_confidence_result` | no | no | yes | yes | no |
| `benchmark_provenance` | no | yes | yes | yes | no |
| `benchmark_results_csv` | no | yes | yes | yes | no |
| `benchmark_summary_markdown` | no | no | yes | no | no |
| `cost_of_assurance_evidence` | no | yes | yes | yes | no |
| `ct_campaign_result` | no | no | yes | no | no |
| `ct_instruction_policy_result` | no | no | yes | yes | no |
| `ct_sample_analysis_result` | no | no | yes | no | no |
| `device_evidence_token` | no | no | yes | no | no |
| `device_evidence_token_result` | no | no | yes | no | no |
| `evidence_tamper_drill_result` | no | no | yes | yes | no |
| `evidence_transcript_manifest` | no | yes | yes | yes | no |
| `external_non_native_inventory` | no | no | yes | no | no |
| `firmware_assurance_status_result` | no | no | yes | no | no |
| `firmware_digest_header` | no | no | yes | no | no |
| `mcu_protocol_footprint_csv` | no | no | yes | yes | no |
| `paper_comparison_campaign_csv` | no | no | yes | no | no |
| `paper_comparison_campaign_json` | no | no | yes | no | no |
| `partner_review_scorecard` | no | no | yes | yes | no |
| `partner_review_scorecard_markdown` | no | no | yes | yes | no |
| `partner_review_scorecard_result` | no | no | yes | yes | no |
| `pqc_appraisal_evidence` | no | no | yes | yes | no |
| `pqc_appraisal_result` | no | no | yes | yes | no |
| `pqc_asset_trace_result` | no | no | yes | yes | no |
| `pqc_assurance_digest` | no | no | yes | yes | no |
| `pqc_assurance_profile_result` | no | no | yes | yes | no |
| `pqc_attestation` | no | no | yes | yes | no |
| `pqc_build_provenance` | no | no | yes | yes | no |
| `pqc_build_provenance_result` | no | no | yes | yes | no |
| `pqc_cbom` | no | no | yes | yes | no |
| `pqc_claim_closure_result` | no | no | yes | yes | no |
| `pqc_environment_result` | no | no | yes | yes | no |
| `pqc_evidence_graph_json` | no | no | yes | yes | no |
| `pqc_evidence_graph_markdown` | no | no | yes | no | no |
| `pqc_evidence_quality_result` | no | no | yes | yes | no |
| `pqc_migration_readiness_json` | no | no | yes | yes | no |
| `pqc_migration_readiness_markdown` | no | no | yes | no | no |
| `pqc_policy_result` | no | no | yes | yes | no |
| `pqc_reference_values` | no | no | yes | yes | no |
| `pqc_reference_values_result` | no | no | yes | yes | no |
| `provider_scope_result` | no | no | yes | yes | no |
| `release_manifest` | no | yes | yes | yes | no |
| `release_notes_markdown` | no | no | yes | yes | no |
| `release_reference_values_result` | no | no | yes | yes | no |

## Failure Modes The Contract Catches

### Missing required artifact

A product-MVP or partner-review pack omits an artifact that the selected profile requires. The validator fails before a dashboard can silently show incomplete evidence.

Recommended response: fix the producer, fixture, schema, or documentation so the pack contract remains explicit. Do not bypass the validator by deleting the scenario or weakening the profile requirement.

### Malformed SHA-256

A digest field is not lowercase 64-character hex. The validator fails at the exact JSON path.

Recommended response: fix the producer, fixture, schema, or documentation so the pack contract remains explicit. Do not bypass the validator by deleting the scenario or weakening the profile requirement.

### Unsafe relative path

A transcript or artifact path is absolute or attempts to escape the pack root. The validator rejects it as unsafe for offline review tooling.

Recommended response: fix the producer, fixture, schema, or documentation so the pack contract remains explicit. Do not bypass the validator by deleting the scenario or weakening the profile requirement.

### CSV shape drift

Benchmark or footprint CSV files lose required columns such as operation, algorithm, implementation, board, suite, ROM bytes, or RAM bytes.

Recommended response: fix the producer, fixture, schema, or documentation so the pack contract remains explicit. Do not bypass the validator by deleting the scenario or weakening the profile requirement.

### Ledger and release-manifest drift

The ledger and release manifest disagree on version, tag, source commit, or dirty-tree state.

Recommended response: fix the producer, fixture, schema, or documentation so the pack contract remains explicit. Do not bypass the validator by deleting the scenario or weakening the profile requirement.

### Transcript hash drift

A transcript file exists but no longer hashes to the value recorded by the manifest.

Recommended response: fix the producer, fixture, schema, or documentation so the pack contract remains explicit. Do not bypass the validator by deleting the scenario or weakening the profile requirement.

### Policy claim drift

A policy result names required claims that do not exist in the ledger.

Recommended response: fix the producer, fixture, schema, or documentation so the pack contract remains explicit. Do not bypass the validator by deleting the scenario or weakening the profile requirement.

### Attestation subject drift

An attestation subject is missing a valid SHA-256 digest.

Recommended response: fix the producer, fixture, schema, or documentation so the pack contract remains explicit. Do not bypass the validator by deleting the scenario or weakening the profile requirement.

### Reference-value drift

Reference values disagree with ledger version or tag metadata.

Recommended response: fix the producer, fixture, schema, or documentation so the pack contract remains explicit. Do not bypass the validator by deleting the scenario or weakening the profile requirement.

### Catalog drift

A new artifact is documented without a schema, or a schema is missing a title/schema marker.

Recommended response: fix the producer, fixture, schema, or documentation so the pack contract remains explicit. Do not bypass the validator by deleting the scenario or weakening the profile requirement.

## Dashboard Data Binding Guidance

### `acvp_json_interop_result`

- Read path: `acvp_json_interop_result.json`
- Validate with: `artifacts/acvp_json_interop_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `acvp_json_schema_result`

- Read path: `acvp_json_schema_result.json`
- Validate with: `artifacts/acvp_json_schema_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: release replay verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `acvp_json_transcript_manifest`

- Read path: `acvp_json_transcript_manifest.json`
- Validate with: `artifacts/acvp_json_transcript_manifest.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Binds release claims to exact execution output.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `acvp_negative_scenario_floor_result`

- Read path: `acvp_negative_scenario_floor_result.json`
- Validate with: `artifacts/acvp_negative_scenario_floor_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `assurance_ledger`

- Read path: `assurance_ledger.json`
- Validate with: `artifacts/assurance_ledger.schema.json`
- Artifact type: `json`
- Required for: `qemu_release`, `partner_review`, `product_mvp`
- Dashboard use: partner reviewer and dashboard
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `assurance_ledger_markdown`

- Read path: `assurance_ledger.md`
- Validate with: `artifacts/text_artifact.schema.json`
- Artifact type: `markdown`
- Required for: `qemu_release`, `partner_review`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `assurance_report_html`

- Read path: `assurance_report.html`
- Validate with: `artifacts/text_artifact.schema.json`
- Artifact type: `html`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `backend_contract_result`

- Read path: `backend_contract_result.json`
- Validate with: `artifacts/backend_contract_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: security reviewer
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `backend_update_evaluation`

- Read path: `backend_update_evaluation.json`
- Validate with: `artifacts/backend_update_evaluation.schema.json`
- Artifact type: `json`
- Required for: `partner_review`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `benchmark_campaign_result`

- Read path: `benchmark_campaign_result.json`
- Validate with: `artifacts/benchmark_campaign_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: benchmark reviewer and paper appendix
- Value shown to reviewer: Makes performance evidence reproducible, comparable, and auditable.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `benchmark_campaign_verify_result`

- Read path: `benchmark_campaign_verify_result.json`
- Validate with: `artifacts/benchmark_campaign_verify_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: release replay verifier
- Value shown to reviewer: Makes performance evidence reproducible, comparable, and auditable.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `benchmark_confidence_result`

- Read path: `benchmark_confidence_result.json`
- Validate with: `artifacts/benchmark_confidence_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: benchmark reviewer and paper appendix
- Value shown to reviewer: Makes performance evidence reproducible, comparable, and auditable.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `benchmark_provenance`

- Read path: `benchmark_provenance.json`
- Validate with: `artifacts/benchmark_provenance.schema.json`
- Artifact type: `json`
- Required for: `qemu_release`, `partner_review`, `product_mvp`
- Dashboard use: benchmark reviewer and paper appendix
- Value shown to reviewer: Makes performance evidence reproducible, comparable, and auditable.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `benchmark_results_csv`

- Read path: `benchmark_results.csv`
- Validate with: `artifacts/csv_artifact.schema.json`
- Artifact type: `csv`
- Required for: `qemu_release`, `partner_review`, `product_mvp`
- Dashboard use: benchmark reviewer and paper appendix
- Value shown to reviewer: Makes performance evidence reproducible, comparable, and auditable.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `benchmark_summary_markdown`

- Read path: `benchmark_summary.md`
- Validate with: `artifacts/text_artifact.schema.json`
- Artifact type: `markdown`
- Required for: `partner_review`
- Dashboard use: benchmark reviewer and paper appendix
- Value shown to reviewer: Makes performance evidence reproducible, comparable, and auditable.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `cost_of_assurance_evidence`

- Read path: `cost_of_assurance_evidence.json`
- Validate with: `artifacts/cost_of_assurance_evidence.schema.json`
- Artifact type: `json`
- Required for: `qemu_release`, `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `ct_campaign_result`

- Read path: `ct_campaign_result.json`
- Validate with: `artifacts/ct_campaign_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`
- Dashboard use: security reviewer
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `ct_instruction_policy_result`

- Read path: `ct_instruction_policy_result.json`
- Validate with: `artifacts/ct_instruction_policy_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: security reviewer
- Value shown to reviewer: Converts raw evidence into an explicit accept/reject decision.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `ct_sample_analysis_result`

- Read path: `ct_sample_analysis_result.json`
- Validate with: `artifacts/ct_sample_analysis_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`
- Dashboard use: security reviewer
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `device_evidence_token`

- Read path: `device_evidence_token.json`
- Validate with: `artifacts/device_evidence_token.schema.json`
- Artifact type: `json`
- Required for: `partner_review`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `device_evidence_token_result`

- Read path: `device_evidence_token_result.json`
- Validate with: `artifacts/device_evidence_token_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `evidence_tamper_drill_result`

- Read path: `evidence_tamper_drill_result.json`
- Validate with: `artifacts/evidence_tamper_drill_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `evidence_transcript_manifest`

- Read path: `transcripts/evidence_transcript_manifest.json`
- Validate with: `artifacts/evidence_transcript_manifest.schema.json`
- Artifact type: `json`
- Required for: `qemu_release`, `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Binds release claims to exact execution output.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `external_non_native_inventory`

- Read path: `liboqs_non_native_inventory.json`
- Validate with: `artifacts/external_non_native_inventory.schema.json`
- Artifact type: `json`
- Required for: `partner_review`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `firmware_assurance_status_result`

- Read path: `firmware_assurance_status_result.json`
- Validate with: `artifacts/firmware_assurance_status_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `firmware_digest_header`

- Read path: `generated/pqcp_assurance_digest_generated.h`
- Validate with: `artifacts/firmware_digest_header.schema.json`
- Artifact type: `header`
- Required for: `partner_review`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `mcu_protocol_footprint_csv`

- Read path: `mcu_protocol_footprint/cost_of_assurance_protocols_mcu.csv`
- Validate with: `artifacts/csv_artifact.schema.json`
- Artifact type: `csv`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `paper_comparison_campaign_csv`

- Read path: `paper_comparison_campaign.csv`
- Validate with: `artifacts/paper_comparison_campaign_csv.schema.json`
- Artifact type: `csv`
- Required for: `partner_review`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `paper_comparison_campaign_json`

- Read path: `paper_comparison_campaign.json`
- Validate with: `artifacts/paper_comparison_campaign.schema.json`
- Artifact type: `json`
- Required for: `partner_review`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `partner_review_scorecard`

- Read path: `partner_review_scorecard.json`
- Validate with: `artifacts/partner_review_scorecard.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: partner reviewer and dashboard
- Value shown to reviewer: Provides a concise partner-facing review summary.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `partner_review_scorecard_markdown`

- Read path: `partner_review_scorecard.md`
- Validate with: `artifacts/text_artifact.schema.json`
- Artifact type: `markdown`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Provides a concise partner-facing review summary.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `partner_review_scorecard_result`

- Read path: `partner_review_scorecard_result.json`
- Validate with: `artifacts/partner_review_scorecard_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Provides a concise partner-facing review summary.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `pqc_appraisal_evidence`

- Read path: `pqc_appraisal_evidence.json`
- Validate with: `artifacts/pqc_appraisal_evidence.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `pqc_appraisal_result`

- Read path: `pqc_appraisal_result.json`
- Validate with: `artifacts/pqc_appraisal_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `pqc_asset_trace_result`

- Read path: `pqc_asset_trace_result.json`
- Validate with: `artifacts/pqc_asset_trace_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `pqc_assurance_digest`

- Read path: `pqc_assurance_digest.json`
- Validate with: `artifacts/pqc_assurance_digest.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `pqc_assurance_profile_result`

- Read path: `pqc_assurance_profile_result.json`
- Validate with: `artifacts/pqc_assurance_profile_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `pqc_attestation`

- Read path: `pqc_attestation.intoto.json`
- Validate with: `artifacts/pqc_attestation.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `pqc_build_provenance`

- Read path: `pqc_build_provenance.slsa.json`
- Validate with: `artifacts/pqc_build_provenance.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `pqc_build_provenance_result`

- Read path: `pqc_build_provenance_result.json`
- Validate with: `artifacts/pqc_build_provenance_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `pqc_cbom`

- Read path: `pqc_cbom.cdx.json`
- Validate with: `artifacts/pqc_cbom.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: partner reviewer and dashboard
- Value shown to reviewer: Lets partners inspect crypto inventory and provider scope.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `pqc_claim_closure_result`

- Read path: `pqc_claim_closure_result.json`
- Validate with: `artifacts/pqc_claim_closure_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `pqc_environment_result`

- Read path: `pqc_environment_result.json`
- Validate with: `artifacts/pqc_environment_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `pqc_evidence_graph_json`

- Read path: `pqc_evidence_graph.json`
- Validate with: `artifacts/pqc_evidence_graph_json.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `pqc_evidence_graph_markdown`

- Read path: `pqc_evidence_graph.md`
- Validate with: `artifacts/pqc_evidence_graph_markdown.schema.json`
- Artifact type: `markdown`
- Required for: `partner_review`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `pqc_evidence_quality_result`

- Read path: `pqc_evidence_quality_result.json`
- Validate with: `artifacts/pqc_evidence_quality_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `pqc_migration_readiness_json`

- Read path: `pqc_migration_readiness.json`
- Validate with: `artifacts/pqc_migration_readiness.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `pqc_migration_readiness_markdown`

- Read path: `pqc_migration_readiness.md`
- Validate with: `artifacts/text_artifact.schema.json`
- Artifact type: `markdown`
- Required for: `partner_review`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `pqc_policy_result`

- Read path: `pqc_policy_result.json`
- Validate with: `artifacts/pqc_policy_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: partner reviewer and dashboard
- Value shown to reviewer: Converts raw evidence into an explicit accept/reject decision.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `pqc_reference_values`

- Read path: `pqc_reference_values.json`
- Validate with: `artifacts/pqc_reference_values.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `pqc_reference_values_result`

- Read path: `pqc_reference_values_result.json`
- Validate with: `artifacts/pqc_reference_values_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `provider_scope_result`

- Read path: `provider_scope_result.json`
- Validate with: `artifacts/provider_scope_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `release_manifest`

- Read path: `local_release_bundle/{tag}/release-manifest-{tag}.json`
- Validate with: `artifacts/release_manifest.schema.json`
- Artifact type: `json`
- Required for: `qemu_release`, `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `release_notes_markdown`

- Read path: `local_release_bundle/{tag}/release-notes-{tag}.md`
- Validate with: `artifacts/text_artifact.schema.json`
- Artifact type: `markdown`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

### `release_reference_values_result`

- Read path: `release_reference_values_result.json`
- Validate with: `artifacts/release_reference_values_result.schema.json`
- Artifact type: `json`
- Required for: `partner_review`, `product_mvp`
- Dashboard use: offline release verifier
- Value shown to reviewer: Stabilizes release evidence so tools can replay and inspect it.

Binding rule: show values from this artifact only after the schema validator accepts the artifact. If the artifact is absent because the selected profile does not require it, show `not required for this profile`, not a fabricated value.

## Acceptance Rules For Product Work

1. Every new partner-facing JSON artifact must have a schema file and catalog entry before it is consumed by a dashboard or product CLI.
2. Every artifact required by `product_mvp` must have a synthetic fixture in `scripts/testdata/evidence_schema_pack/product_mvp`.
3. Every schema change must keep `python3 scripts/test_evidence_schema_contract.py` passing.
4. Every generated path in an artifact must be relative to the pack root or artifact-specific directory.
5. Every digest field exposed to partners must use lowercase SHA-256 hex unless a future schema explicitly version-gates a new digest algorithm.
6. Every benchmark CSV used in product-facing reports must keep operation, algorithm, and implementation columns.
7. Every board or hardware artifact must distinguish physical hardware evidence from QEMU/native-simulator regression evidence.
8. Every policy result used in partner review must fail on missing required claims rather than silently downgrading them.
9. Every evidence pack dashboard must treat schema validation failure as a blocking ingest error.
10. Every old pack compatibility path must be documented by profile and schema version rather than inferred from code comments.
