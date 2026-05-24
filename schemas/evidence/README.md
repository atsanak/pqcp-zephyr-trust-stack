# Evidence Schema Contract

Status: product-facing evidence-pack data contract for local release packs.

This directory defines the stable artifact contract used by `scripts/validate_evidence_schemas.py`.
The contract is intentionally separate from the semantic replay verifier. Replay answers whether evidence is internally consistent; schemas answer whether partner tools, dashboards, and product workflows can parse the pack without reverse-engineering every producer script.

## Profiles

- `ci_fast`: Fast local/CI gate contract for artifacts that should exist without full Passport generation.
- `qemu_release`: Full local QEMU/native-sim release contract for replayable evidence packs.
- `partner_review`: Partner-review contract requiring the major Passport, policy, benchmark, and report artifacts.
- `product_mvp`: Minimum product-grade contract for supported customer evaluation packs.
- `hardware_review`: Extension point for future physical-board evidence packs.

## Validation Commands

```bash
python3 scripts/validate_evidence_schemas.py --catalog schemas/evidence/evidence_schema_catalog.json --output-root /tmp/pqcp-release-pack --tag v1.0.0 --profile partner_review
python3 scripts/validate_evidence_schemas.py --catalog schemas/evidence/evidence_schema_catalog.json --mode catalog-only
python3 scripts/validate_evidence_schemas.py --catalog schemas/evidence/evidence_schema_catalog.json --list-contracts
```

## Contract Inventory

| ID | Path | Type | Required Profiles | Producer | Product Value |
| --- | --- | --- | --- | --- | --- |
| `acvp_json_interop_result` | `acvp_json_interop_result.json` | `json` | `partner_review`, `product_mvp` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `acvp_json_schema_result` | `acvp_json_schema_result.json` | `json` | `partner_review`, `product_mvp` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `acvp_json_transcript_manifest` | `acvp_json_transcript_manifest.json` | `json` | `partner_review`, `product_mvp` | scripts/release_check.py | Binds release claims to exact execution output. |
| `acvp_negative_scenario_floor_result` | `acvp_negative_scenario_floor_result.json` | `json` | `partner_review`, `product_mvp` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `assurance_ledger` | `assurance_ledger.json` | `json` | `qemu_release`, `partner_review`, `product_mvp` | scripts/generate_assurance_ledger.py | Stabilizes release evidence so tools can replay and inspect it. |
| `assurance_ledger_markdown` | `assurance_ledger.md` | `markdown` | `qemu_release`, `partner_review` | scripts/generate_assurance_ledger.py | Stabilizes release evidence so tools can replay and inspect it. |
| `assurance_report_html` | `assurance_report.html` | `html` | `partner_review`, `product_mvp` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `backend_contract_result` | `backend_contract_result.json` | `json` | `partner_review`, `product_mvp` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `backend_update_evaluation` | `backend_update_evaluation.json` | `json` | `partner_review` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `benchmark_campaign_result` | `benchmark_campaign_result.json` | `json` | `partner_review`, `product_mvp` | benchmark tooling | Makes performance evidence reproducible, comparable, and auditable. |
| `benchmark_campaign_verify_result` | `benchmark_campaign_verify_result.json` | `json` | `partner_review`, `product_mvp` | benchmark tooling | Makes performance evidence reproducible, comparable, and auditable. |
| `benchmark_confidence_result` | `benchmark_confidence_result.json` | `json` | `partner_review`, `product_mvp` | benchmark tooling | Makes performance evidence reproducible, comparable, and auditable. |
| `benchmark_provenance` | `benchmark_provenance.json` | `json` | `qemu_release`, `partner_review`, `product_mvp` | benchmark tooling | Makes performance evidence reproducible, comparable, and auditable. |
| `benchmark_results_csv` | `benchmark_results.csv` | `csv` | `qemu_release`, `partner_review`, `product_mvp` | benchmark tooling | Makes performance evidence reproducible, comparable, and auditable. |
| `benchmark_summary_markdown` | `benchmark_summary.md` | `markdown` | `partner_review` | benchmark tooling | Makes performance evidence reproducible, comparable, and auditable. |
| `cost_of_assurance_evidence` | `cost_of_assurance_evidence.json` | `json` | `qemu_release`, `partner_review`, `product_mvp` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `ct_campaign_result` | `ct_campaign_result.json` | `json` | `partner_review` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `ct_instruction_policy_result` | `ct_instruction_policy_result.json` | `json` | `partner_review`, `product_mvp` | scripts/verify_assurance_policy.py | Converts raw evidence into an explicit accept/reject decision. |
| `ct_sample_analysis_result` | `ct_sample_analysis_result.json` | `json` | `partner_review` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `device_evidence_token` | `device_evidence_token.json` | `json` | `partner_review` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `device_evidence_token_result` | `device_evidence_token_result.json` | `json` | `partner_review` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `evidence_tamper_drill_result` | `evidence_tamper_drill_result.json` | `json` | `partner_review`, `product_mvp` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `evidence_transcript_manifest` | `transcripts/evidence_transcript_manifest.json` | `json` | `qemu_release`, `partner_review`, `product_mvp` | scripts/release_check.py | Binds release claims to exact execution output. |
| `external_non_native_inventory` | `liboqs_non_native_inventory.json` | `json` | `partner_review` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `firmware_assurance_status_result` | `firmware_assurance_status_result.json` | `json` | `partner_review` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `firmware_digest_header` | `generated/pqcp_assurance_digest_generated.h` | `header` | `partner_review` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `mcu_protocol_footprint_csv` | `mcu_protocol_footprint/cost_of_assurance_protocols_mcu.csv` | `csv` | `partner_review`, `product_mvp` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `paper_comparison_campaign_csv` | `paper_comparison_campaign.csv` | `csv` | `partner_review` | benchmark tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `paper_comparison_campaign_json` | `paper_comparison_campaign.json` | `json` | `partner_review` | benchmark tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `partner_review_scorecard` | `partner_review_scorecard.json` | `json` | `partner_review`, `product_mvp` | scripts/generate_partner_review_scorecard.py | Provides a concise partner-facing review summary. |
| `partner_review_scorecard_markdown` | `partner_review_scorecard.md` | `markdown` | `partner_review`, `product_mvp` | scripts/generate_partner_review_scorecard.py | Provides a concise partner-facing review summary. |
| `partner_review_scorecard_result` | `partner_review_scorecard_result.json` | `json` | `partner_review`, `product_mvp` | scripts/generate_partner_review_scorecard.py | Provides a concise partner-facing review summary. |
| `pqc_appraisal_evidence` | `pqc_appraisal_evidence.json` | `json` | `partner_review`, `product_mvp` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `pqc_appraisal_result` | `pqc_appraisal_result.json` | `json` | `partner_review`, `product_mvp` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `pqc_asset_trace_result` | `pqc_asset_trace_result.json` | `json` | `partner_review`, `product_mvp` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `pqc_assurance_digest` | `pqc_assurance_digest.json` | `json` | `partner_review`, `product_mvp` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `pqc_assurance_profile_result` | `pqc_assurance_profile_result.json` | `json` | `partner_review`, `product_mvp` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `pqc_attestation` | `pqc_attestation.intoto.json` | `json` | `partner_review`, `product_mvp` | scripts/generate_pqc_attestation.py | Stabilizes release evidence so tools can replay and inspect it. |
| `pqc_build_provenance` | `pqc_build_provenance.slsa.json` | `json` | `partner_review`, `product_mvp` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `pqc_build_provenance_result` | `pqc_build_provenance_result.json` | `json` | `partner_review`, `product_mvp` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `pqc_cbom` | `pqc_cbom.cdx.json` | `json` | `partner_review`, `product_mvp` | scripts/export_pqc_cbom.py | Lets partners inspect crypto inventory and provider scope. |
| `pqc_claim_closure_result` | `pqc_claim_closure_result.json` | `json` | `partner_review`, `product_mvp` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `pqc_environment_result` | `pqc_environment_result.json` | `json` | `partner_review`, `product_mvp` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `pqc_evidence_graph_json` | `pqc_evidence_graph.json` | `json` | `partner_review`, `product_mvp` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `pqc_evidence_graph_markdown` | `pqc_evidence_graph.md` | `markdown` | `partner_review` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `pqc_evidence_quality_result` | `pqc_evidence_quality_result.json` | `json` | `partner_review`, `product_mvp` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `pqc_migration_readiness_json` | `pqc_migration_readiness.json` | `json` | `partner_review`, `product_mvp` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `pqc_migration_readiness_markdown` | `pqc_migration_readiness.md` | `markdown` | `partner_review` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `pqc_policy_result` | `pqc_policy_result.json` | `json` | `partner_review`, `product_mvp` | scripts/verify_assurance_policy.py | Converts raw evidence into an explicit accept/reject decision. |
| `pqc_reference_values` | `pqc_reference_values.json` | `json` | `partner_review`, `product_mvp` | reference-value tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `pqc_reference_values_result` | `pqc_reference_values_result.json` | `json` | `partner_review`, `product_mvp` | reference-value tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `provider_scope_result` | `provider_scope_result.json` | `json` | `partner_review`, `product_mvp` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `release_manifest` | `local_release_bundle/{tag}/release-manifest-{tag}.json` | `json` | `qemu_release`, `partner_review`, `product_mvp` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `release_notes_markdown` | `local_release_bundle/{tag}/release-notes-{tag}.md` | `markdown` | `partner_review`, `product_mvp` | release evidence tooling | Stabilizes release evidence so tools can replay and inspect it. |
| `release_reference_values_result` | `release_reference_values_result.json` | `json` | `partner_review`, `product_mvp` | reference-value tooling | Stabilizes release evidence so tools can replay and inspect it. |

## Integration Guidance

### `acvp_json_interop_result`

- Path: `acvp_json_interop_result.json`
- Schema: `artifacts/acvp_json_interop_result.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: ACVP JSON vector translation evidence with serial transcript bindings.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `acvp_json_schema_result`

- Path: `acvp_json_schema_result.json`
- Schema: `artifacts/acvp_json_schema_result.schema.json`
- Producer: release evidence tooling
- Primary consumer: release replay verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: ACVP JSON operation-coverage replay result.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `acvp_json_transcript_manifest`

- Path: `acvp_json_transcript_manifest.json`
- Schema: `artifacts/acvp_json_transcript_manifest.schema.json`
- Producer: scripts/release_check.py
- Primary consumer: offline release verifier
- Product value: Binds release claims to exact execution output.
- Contract description: Evidence transcript manifest binding commands and QEMU/stdout logs to hashes.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `acvp_negative_scenario_floor_result`

- Path: `acvp_negative_scenario_floor_result.json`
- Schema: `artifacts/acvp_negative_scenario_floor_result.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Append-only ACVP negative scenario compatibility-floor validation result.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `assurance_ledger`

- Path: `assurance_ledger.json`
- Schema: `artifacts/assurance_ledger.schema.json`
- Producer: scripts/generate_assurance_ledger.py
- Primary consumer: partner reviewer and dashboard
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Assurance Ledger machine-readable claim/evidence status.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `assurance_ledger_markdown`

- Path: `assurance_ledger.md`
- Schema: `artifacts/text_artifact.schema.json`
- Producer: scripts/generate_assurance_ledger.py
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Human-readable ledger with the same claim identifiers as the JSON ledger.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `assurance_report_html`

- Path: `assurance_report.html`
- Schema: `artifacts/text_artifact.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Self-contained HTML report for release evidence review.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `backend_contract_result`

- Path: `backend_contract_result.json`
- Schema: `artifacts/backend_contract_result.schema.json`
- Producer: release evidence tooling
- Primary consumer: security reviewer
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Backend provider contract result with scan coverage and pinned native backend SHAs.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `backend_update_evaluation`

- Path: `backend_update_evaluation.json`
- Schema: `artifacts/backend_update_evaluation.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Comparison-only review of pinned native backend metadata and optional upstream drift.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `benchmark_campaign_result`

- Path: `benchmark_campaign_result.json`
- Schema: `artifacts/benchmark_campaign_result.schema.json`
- Producer: benchmark tooling
- Primary consumer: benchmark reviewer and paper appendix
- Product value: Makes performance evidence reproducible, comparable, and auditable.
- Contract description: Repeated benchmark campaign statistics and metadata.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `benchmark_campaign_verify_result`

- Path: `benchmark_campaign_verify_result.json`
- Schema: `artifacts/benchmark_campaign_verify_result.schema.json`
- Producer: benchmark tooling
- Primary consumer: release replay verifier
- Product value: Makes performance evidence reproducible, comparable, and auditable.
- Contract description: Replay result for benchmark campaign statistics and metadata.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `benchmark_confidence_result`

- Path: `benchmark_confidence_result.json`
- Schema: `artifacts/benchmark_confidence_result.schema.json`
- Producer: benchmark tooling
- Primary consumer: benchmark reviewer and paper appendix
- Product value: Makes performance evidence reproducible, comparable, and auditable.
- Contract description: Replay result for distribution shape, sample balance, and confidence tier.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `benchmark_provenance`

- Path: `benchmark_provenance.json`
- Schema: `artifacts/benchmark_provenance.schema.json`
- Producer: benchmark tooling
- Primary consumer: benchmark reviewer and paper appendix
- Product value: Makes performance evidence reproducible, comparable, and auditable.
- Contract description: Benchmark CSV provenance sidecar.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `benchmark_results_csv`

- Path: `benchmark_results.csv`
- Schema: `artifacts/csv_artifact.schema.json`
- Producer: benchmark tooling
- Primary consumer: benchmark reviewer and paper appendix
- Product value: Makes performance evidence reproducible, comparable, and auditable.
- Contract description: Primitive/protocol benchmark CSV with required operation metadata columns.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `benchmark_summary_markdown`

- Path: `benchmark_summary.md`
- Schema: `artifacts/text_artifact.schema.json`
- Producer: benchmark tooling
- Primary consumer: benchmark reviewer and paper appendix
- Product value: Makes performance evidence reproducible, comparable, and auditable.
- Contract description: Human-readable benchmark summary generated next to benchmark_results.csv.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `cost_of_assurance_evidence`

- Path: `cost_of_assurance_evidence.json`
- Schema: `artifacts/cost_of_assurance_evidence.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Per-metric cost-of-assurance guardrail evidence.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `ct_campaign_result`

- Path: `ct_campaign_result.json`
- Schema: `artifacts/ct_campaign_result.schema.json`
- Producer: release evidence tooling
- Primary consumer: security reviewer
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Replay result over CT sample campaign manifest.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `ct_instruction_policy_result`

- Path: `ct_instruction_policy_result.json`
- Schema: `artifacts/ct_instruction_policy_result.schema.json`
- Producer: scripts/verify_assurance_policy.py
- Primary consumer: security reviewer
- Product value: Converts raw evidence into an explicit accept/reject decision.
- Contract description: ML-KEM decapsulation instruction-policy scan result.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `ct_sample_analysis_result`

- Path: `ct_sample_analysis_result.json`
- Schema: `artifacts/ct_sample_analysis_result.schema.json`
- Producer: release evidence tooling
- Primary consumer: security reviewer
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Replay result for optional raw CT sample timing markers.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `device_evidence_token`

- Path: `device_evidence_token.json`
- Schema: `artifacts/device_evidence_token.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Firmware device-evidence marker captured from assurance-status sample.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `device_evidence_token_result`

- Path: `device_evidence_token_result.json`
- Schema: `artifacts/device_evidence_token_result.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Replay result for firmware device-evidence token.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `evidence_tamper_drill_result`

- Path: `evidence_tamper_drill_result.json`
- Schema: `artifacts/evidence_tamper_drill_result.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Result proving selected evidence mutations fail replay verification.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `evidence_transcript_manifest`

- Path: `transcripts/evidence_transcript_manifest.json`
- Schema: `artifacts/evidence_transcript_manifest.schema.json`
- Producer: scripts/release_check.py
- Primary consumer: offline release verifier
- Product value: Binds release claims to exact execution output.
- Contract description: Evidence transcript manifest binding commands and QEMU/stdout logs to hashes.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `external_non_native_inventory`

- Path: `liboqs_non_native_inventory.json`
- Schema: `artifacts/external_non_native_inventory.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Experimental external-provider inventory for schemes outside the native provider families.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `firmware_assurance_status_result`

- Path: `firmware_assurance_status_result.json`
- Schema: `artifacts/firmware_assurance_status_result.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Replay result for firmware assurance status transcript markers.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `firmware_digest_header`

- Path: `generated/pqcp_assurance_digest_generated.h`
- Schema: `artifacts/firmware_digest_header.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Generated C header carrying assurance digest root for firmware binding.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `mcu_protocol_footprint_csv`

- Path: `mcu_protocol_footprint/cost_of_assurance_protocols_mcu.csv`
- Schema: `artifacts/csv_artifact.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Build-only MCU ROM/RAM footprint CSV for protocol suites.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `paper_comparison_campaign_csv`

- Path: `paper_comparison_campaign.csv`
- Schema: `artifacts/paper_comparison_campaign_csv.schema.json`
- Producer: benchmark tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Normalized CSV export for pqm4/SUPERCOP-style comparison workflows.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `paper_comparison_campaign_json`

- Path: `paper_comparison_campaign.json`
- Schema: `artifacts/paper_comparison_campaign.schema.json`
- Producer: benchmark tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Normalized external/reference comparison campaign metadata.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `partner_review_scorecard`

- Path: `partner_review_scorecard.json`
- Schema: `artifacts/partner_review_scorecard.schema.json`
- Producer: scripts/generate_partner_review_scorecard.py
- Primary consumer: partner reviewer and dashboard
- Product value: Provides a concise partner-facing review summary.
- Contract description: Compact partner-facing triage view over release evidence.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `partner_review_scorecard_markdown`

- Path: `partner_review_scorecard.md`
- Schema: `artifacts/text_artifact.schema.json`
- Producer: scripts/generate_partner_review_scorecard.py
- Primary consumer: offline release verifier
- Product value: Provides a concise partner-facing review summary.
- Contract description: Human-readable compact partner scorecard.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `partner_review_scorecard_result`

- Path: `partner_review_scorecard_result.json`
- Schema: `artifacts/partner_review_scorecard_result.schema.json`
- Producer: scripts/generate_partner_review_scorecard.py
- Primary consumer: offline release verifier
- Product value: Provides a concise partner-facing review summary.
- Contract description: Replay result for partner scorecard hashes and summaries.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `pqc_appraisal_evidence`

- Path: `pqc_appraisal_evidence.json`
- Schema: `artifacts/pqc_appraisal_evidence.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Mode-specific evidence appraisal inputs.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `pqc_appraisal_result`

- Path: `pqc_appraisal_result.json`
- Schema: `artifacts/pqc_appraisal_result.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Mode-specific evidence appraisal replay result.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `pqc_asset_trace_result`

- Path: `pqc_asset_trace_result.json`
- Schema: `artifacts/pqc_asset_trace_result.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Asset-to-source/Kconfig/claim/test/marker/CBOM trace-map validation result.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `pqc_assurance_digest`

- Path: `pqc_assurance_digest.json`
- Schema: `artifacts/pqc_assurance_digest.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Stable assurance digest manifest.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `pqc_assurance_profile_result`

- Path: `pqc_assurance_profile_result.json`
- Schema: `artifacts/pqc_assurance_profile_result.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Profile replay result for production, validation, lab, smoke, and test-only separation.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `pqc_attestation`

- Path: `pqc_attestation.intoto.json`
- Schema: `artifacts/pqc_attestation.schema.json`
- Producer: scripts/generate_pqc_attestation.py
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Unsigned in-toto Statement-style PQC assurance attestation.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `pqc_build_provenance`

- Path: `pqc_build_provenance.slsa.json`
- Schema: `artifacts/pqc_build_provenance.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: SLSA-shaped build provenance statement.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `pqc_build_provenance_result`

- Path: `pqc_build_provenance_result.json`
- Schema: `artifacts/pqc_build_provenance_result.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Replay result for SLSA-shaped build provenance.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `pqc_cbom`

- Path: `pqc_cbom.cdx.json`
- Schema: `artifacts/pqc_cbom.schema.json`
- Producer: scripts/export_pqc_cbom.py
- Primary consumer: partner reviewer and dashboard
- Product value: Lets partners inspect crypto inventory and provider scope.
- Contract description: CycloneDX-style cryptographic bill of materials.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `pqc_claim_closure_result`

- Path: `pqc_claim_closure_result.json`
- Schema: `artifacts/pqc_claim_closure_result.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Post-policy closure result checking assembled Passport artifacts agree.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `pqc_environment_result`

- Path: `pqc_environment_result.json`
- Schema: `artifacts/pqc_environment_result.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Replay result for west/workflow/release-manifest/CBOM environment consistency.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `pqc_evidence_graph_json`

- Path: `pqc_evidence_graph.json`
- Schema: `artifacts/pqc_evidence_graph_json.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Graph-form asset/source/test/claim/marker/CBOM relationships.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `pqc_evidence_graph_markdown`

- Path: `pqc_evidence_graph.md`
- Schema: `artifacts/pqc_evidence_graph_markdown.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Human-readable evidence graph summary.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `pqc_evidence_quality_result`

- Path: `pqc_evidence_quality_result.json`
- Schema: `artifacts/pqc_evidence_quality_result.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Evidence-class replay result for required claims.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `pqc_migration_readiness_json`

- Path: `pqc_migration_readiness.json`
- Schema: `artifacts/pqc_migration_readiness.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Generated profile summary for partner review and maintenance planning.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `pqc_migration_readiness_markdown`

- Path: `pqc_migration_readiness.md`
- Schema: `artifacts/text_artifact.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Human-readable migration readiness report.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `pqc_policy_result`

- Path: `pqc_policy_result.json`
- Schema: `artifacts/pqc_policy_result.schema.json`
- Producer: scripts/verify_assurance_policy.py
- Primary consumer: partner reviewer and dashboard
- Product value: Converts raw evidence into an explicit accept/reject decision.
- Contract description: Partner-review policy replay result.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `pqc_reference_values`

- Path: `pqc_reference_values.json`
- Schema: `artifacts/pqc_reference_values.schema.json`
- Producer: reference-value tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Release reference values for replay and future device evidence.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `pqc_reference_values_result`

- Path: `pqc_reference_values_result.json`
- Schema: `artifacts/pqc_reference_values_result.schema.json`
- Producer: reference-value tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Replay result for reference values.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `provider_scope_result`

- Path: `provider_scope_result.json`
- Schema: `artifacts/provider_scope_result.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Replay result checking CBOM provider metadata against backend contract and inventory.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `release_manifest`

- Path: `local_release_bundle/{tag}/release-manifest-{tag}.json`
- Schema: `artifacts/release_manifest.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Local release bundle manifest.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `release_notes_markdown`

- Path: `local_release_bundle/{tag}/release-notes-{tag}.md`
- Schema: `artifacts/text_artifact.schema.json`
- Producer: release evidence tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Release notes extracted from CHANGELOG for the selected tag.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

### `release_reference_values_result`

- Path: `release_reference_values_result.json`
- Schema: `artifacts/release_reference_values_result.schema.json`
- Producer: reference-value tooling
- Primary consumer: offline release verifier
- Product value: Stabilizes release evidence so tools can replay and inspect it.
- Contract description: Replay result for release reference values, backend contract, and provider scope.

Product rule: do not remove or rename this artifact from a profile without updating the catalog, schema tests, release documentation, and any dashboard data bindings that consume it.

## Design Rules

- Schemas describe artifact shape; replay verifiers enforce deeper semantic relationships.
- New product-facing artifacts require a catalog entry, schema file, test coverage, and release documentation.
- QEMU/local evidence must remain labeled separately from physical-board evidence.
- Generated output roots remain ignored; schemas and validators are the committed contract.
- The contract must not make certification, formal side-channel, or hardware claims unless the corresponding evidence exists.
