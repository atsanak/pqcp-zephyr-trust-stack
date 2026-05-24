# Research Experiment Catalog

This document summarizes `scripts/research_experiment_catalog.json`. The catalog turns the long-form audit into executable research and product-readiness experiments. Each entry names repository inputs, commands, positive controls, negative controls, expected outputs, acceptance criteria, and product value.

## Validation

```bash
python3 scripts/validate_research_experiment_catalog.py
python3 scripts/test_research_experiment_catalog.py
```

## Experiment Inventory

| ID | Category | Objective |
| --- | --- | --- |
| `claim.release_version_consistency` | `claim_replay` | Replay and falsify assurance claim release.version_consistency as an independently inspectable paper artifact. |
| `claim.release_tag_integrity` | `claim_replay` | Replay and falsify assurance claim release.tag_integrity as an independently inspectable paper artifact. |
| `claim.kat_offline_provenance` | `claim_replay` | Replay and falsify assurance claim kat.offline_provenance as an independently inspectable paper artifact. |
| `claim.kat_mlkem_512` | `claim_replay` | Replay and falsify assurance claim kat.mlkem_512 as an independently inspectable paper artifact. |
| `claim.kat_mlkem_768` | `claim_replay` | Replay and falsify assurance claim kat.mlkem_768 as an independently inspectable paper artifact. |
| `claim.kat_mlkem_1024` | `claim_replay` | Replay and falsify assurance claim kat.mlkem_1024 as an independently inspectable paper artifact. |
| `claim.kat_mldsa_44` | `claim_replay` | Replay and falsify assurance claim kat.mldsa_44 as an independently inspectable paper artifact. |
| `claim.kat_mldsa_65` | `claim_replay` | Replay and falsify assurance claim kat.mldsa_65 as an independently inspectable paper artifact. |
| `claim.kat_mldsa_87` | `claim_replay` | Replay and falsify assurance claim kat.mldsa_87 as an independently inspectable paper artifact. |
| `claim.benchmark_csv_validity` | `claim_replay` | Replay and falsify assurance claim benchmark.csv_validity as an independently inspectable paper artifact. |
| `claim.benchmark_provenance_binding` | `claim_replay` | Replay and falsify assurance claim benchmark.provenance_binding as an independently inspectable paper artifact. |
| `claim.benchmark_mlkem_throughput` | `claim_replay` | Replay and falsify assurance claim benchmark.mlkem_throughput as an independently inspectable paper artifact. |
| `claim.benchmark_mldsa_throughput` | `claim_replay` | Replay and falsify assurance claim benchmark.mldsa_throughput as an independently inspectable paper artifact. |
| `claim.benchmark_distribution_quality` | `claim_replay` | Replay and falsify assurance claim benchmark.distribution_quality as an independently inspectable paper artifact. |
| `claim.cost_of_assurance_guardrails` | `claim_replay` | Replay and falsify assurance claim cost_of_assurance.guardrails as an independently inspectable paper artifact. |
| `claim.release_local_bundle` | `claim_replay` | Replay and falsify assurance claim release.local_bundle as an independently inspectable paper artifact. |
| `claim.release_transcript_binding` | `claim_replay` | Replay and falsify assurance claim release.transcript_binding as an independently inspectable paper artifact. |
| `claim.acvp_negative_path_rejection` | `claim_replay` | Replay and falsify assurance claim acvp.negative_path_rejection as an independently inspectable paper artifact. |
| `claim.acvp_timeout_recovery` | `claim_replay` | Replay and falsify assurance claim acvp.timeout_recovery as an independently inspectable paper artifact. |
| `claim.acvp_negative_scenarios_replay` | `claim_replay` | Replay and falsify assurance claim acvp.negative_scenarios_replay as an independently inspectable paper artifact. |
| `claim.acvp_mlkem_negative_paths` | `claim_replay` | Replay and falsify assurance claim acvp.mlkem_negative_paths as an independently inspectable paper artifact. |
| `claim.acvp_mldsa_negative_paths` | `claim_replay` | Replay and falsify assurance claim acvp.mldsa_negative_paths as an independently inspectable paper artifact. |
| `claim.acvp_negative_scenario_floor` | `claim_replay` | Replay and falsify assurance claim acvp.negative_scenario_floor as an independently inspectable paper artifact. |
| `claim.security_asan_clean` | `claim_replay` | Replay and falsify assurance claim security.asan_clean as an independently inspectable paper artifact. |
| `claim.security_ubsan_clean` | `claim_replay` | Replay and falsify assurance claim security.ubsan_clean as an independently inspectable paper artifact. |
| `claim.boot_kat_self_verify` | `claim_replay` | Replay and falsify assurance claim boot.kat_self_verify as an independently inspectable paper artifact. |
| `claim.security_ct_smoke` | `claim_replay` | Replay and falsify assurance claim security.ct_smoke as an independently inspectable paper artifact. |
| `claim.security_mlkem_decap_instruction_policy` | `claim_replay` | Replay and falsify assurance claim security.mlkem_decap_instruction_policy as an independently inspectable paper artifact. |
| `claim.supply_chain_cbom_crypto_inventory` | `claim_replay` | Replay and falsify assurance claim supply_chain.cbom_crypto_inventory as an independently inspectable paper artifact. |
| `claim.supply_chain_pqc_assurance_attestation` | `claim_replay` | Replay and falsify assurance claim supply_chain.pqc_assurance_attestation as an independently inspectable paper artifact. |
| `claim.supply_chain_crypto_asset_traceability` | `claim_replay` | Replay and falsify assurance claim supply_chain.crypto_asset_traceability as an independently inspectable paper artifact. |
| `claim.supply_chain_evidence_graph_integrity` | `claim_replay` | Replay and falsify assurance claim supply_chain.evidence_graph_integrity as an independently inspectable paper artifact. |
| `claim.release_policy_pass` | `claim_replay` | Replay and falsify assurance claim release.policy_pass as an independently inspectable paper artifact. |
| `claim.firmware_assurance_digest_manifest` | `claim_replay` | Replay and falsify assurance claim firmware.assurance_digest_manifest as an independently inspectable paper artifact. |
| `claim.firmware_assurance_digest_embeddable` | `claim_replay` | Replay and falsify assurance claim firmware.assurance_digest_embeddable as an independently inspectable paper artifact. |
| `claim.supply_chain_assurance_profile_policy` | `claim_replay` | Replay and falsify assurance claim supply_chain.assurance_profile_policy as an independently inspectable paper artifact. |
| `claim.supply_chain_evidence_quality_index` | `claim_replay` | Replay and falsify assurance claim supply_chain.evidence_quality_index as an independently inspectable paper artifact. |
| `claim.crypto_agility_profile_separation` | `claim_replay` | Replay and falsify assurance claim crypto_agility.profile_separation as an independently inspectable paper artifact. |
| `claim.release_migration_readiness` | `claim_replay` | Replay and falsify assurance claim release.migration_readiness as an independently inspectable paper artifact. |
| `claim.security_production_rng_policy` | `claim_replay` | Replay and falsify assurance claim security.production_rng_policy as an independently inspectable paper artifact. |
| `claim.release_reference_values` | `claim_replay` | Replay and falsify assurance claim release.reference_values as an independently inspectable paper artifact. |
| `claim.firmware_assurance_status_report` | `claim_replay` | Replay and falsify assurance claim firmware.assurance_status_report as an independently inspectable paper artifact. |
| `claim.acvp_json_interop` | `claim_replay` | Replay and falsify assurance claim acvp.json_interop as an independently inspectable paper artifact. |
| `claim.supply_chain_slsa_build_provenance` | `claim_replay` | Replay and falsify assurance claim supply_chain.slsa_build_provenance as an independently inspectable paper artifact. |
| `claim.security_ct_sample_analysis` | `claim_replay` | Replay and falsify assurance claim security.ct_sample_analysis as an independently inspectable paper artifact. |
| `claim.release_evidence_appraisal_profile` | `claim_replay` | Replay and falsify assurance claim release.evidence_appraisal_profile as an independently inspectable paper artifact. |
| `claim.supply_chain_backend_update_evaluation` | `claim_replay` | Replay and falsify assurance claim supply_chain.backend_update_evaluation as an independently inspectable paper artifact. |
| `claim.benchmark_campaign_reproducibility` | `claim_replay` | Replay and falsify assurance claim benchmark.campaign_reproducibility as an independently inspectable paper artifact. |
| `claim.benchmark_external_reference_context` | `claim_replay` | Replay and falsify assurance claim benchmark.external_reference_context as an independently inspectable paper artifact. |
| `claim.security_ct_campaign_analysis` | `claim_replay` | Replay and falsify assurance claim security.ct_campaign_analysis as an independently inspectable paper artifact. |
| `claim.acvp_json_schema_coverage` | `claim_replay` | Replay and falsify assurance claim acvp.json_schema_coverage as an independently inspectable paper artifact. |
| `claim.firmware_device_evidence_token` | `claim_replay` | Replay and falsify assurance claim firmware.device_evidence_token as an independently inspectable paper artifact. |
| `claim.release_strict_partner_policy` | `claim_replay` | Replay and falsify assurance claim release.strict_partner_policy as an independently inspectable paper artifact. |
| `claim.supply_chain_backend_contract` | `claim_replay` | Replay and falsify assurance claim supply_chain.backend_contract as an independently inspectable paper artifact. |
| `claim.supply_chain_liboqs_non_native_scope` | `claim_replay` | Replay and falsify assurance claim supply_chain.liboqs_non_native_scope as an independently inspectable paper artifact. |
| `claim.benchmark_paper_comparison_export` | `claim_replay` | Replay and falsify assurance claim benchmark.paper_comparison_export as an independently inspectable paper artifact. |
| `claim.release_reference_provider_scope` | `claim_replay` | Replay and falsify assurance claim release.reference_provider_scope as an independently inspectable paper artifact. |
| `asset.crypto_mlkem_512` | `asset_traceability` | Prove asset crypto.mlkem_512 traces from repository source to claims, tests, transcript markers, and CBOM inventory. |
| `asset.crypto_mlkem_768` | `asset_traceability` | Prove asset crypto.mlkem_768 traces from repository source to claims, tests, transcript markers, and CBOM inventory. |
| `asset.crypto_mlkem_1024` | `asset_traceability` | Prove asset crypto.mlkem_1024 traces from repository source to claims, tests, transcript markers, and CBOM inventory. |
| `asset.crypto_mldsa_44` | `asset_traceability` | Prove asset crypto.mldsa_44 traces from repository source to claims, tests, transcript markers, and CBOM inventory. |
| `asset.crypto_mldsa_65` | `asset_traceability` | Prove asset crypto.mldsa_65 traces from repository source to claims, tests, transcript markers, and CBOM inventory. |
| `asset.crypto_mldsa_87` | `asset_traceability` | Prove asset crypto.mldsa_87 traces from repository source to claims, tests, transcript markers, and CBOM inventory. |
| `asset.validation_acvp_serial` | `asset_traceability` | Prove asset validation.acvp_serial traces from repository source to claims, tests, transcript markers, and CBOM inventory. |
| `asset.validation_tls_selftest` | `asset_traceability` | Prove asset validation.tls_selftest traces from repository source to claims, tests, transcript markers, and CBOM inventory. |
| `asset.rng_zephyr_entropy` | `asset_traceability` | Prove asset rng.zephyr_entropy traces from repository source to claims, tests, transcript markers, and CBOM inventory. |
| `asset.rng_psa` | `asset_traceability` | Prove asset rng.psa traces from repository source to claims, tests, transcript markers, and CBOM inventory. |
| `asset.rng_deterministic_test` | `asset_traceability` | Prove asset rng.deterministic_test traces from repository source to claims, tests, transcript markers, and CBOM inventory. |
| `asset.boot_kat_self_verify` | `asset_traceability` | Prove asset boot.kat_self_verify traces from repository source to claims, tests, transcript markers, and CBOM inventory. |
| `asset.security_ct_smoke` | `asset_traceability` | Prove asset security.ct_smoke traces from repository source to claims, tests, transcript markers, and CBOM inventory. |
| `asset.crypto_slhdsa_external` | `asset_traceability` | Prove asset crypto.slhdsa.external traces from repository source to claims, tests, transcript markers, and CBOM inventory. |
| `asset.crypto_hqc_external` | `asset_traceability` | Prove asset crypto.hqc.external traces from repository source to claims, tests, transcript markers, and CBOM inventory. |
| `artifact.acvp_json_interop_result` | `artifact_schema` | Validate product-facing artifact acvp_json_interop_result against its schema and profile requirement. |
| `artifact.acvp_json_schema_result` | `artifact_schema` | Validate product-facing artifact acvp_json_schema_result against its schema and profile requirement. |
| `artifact.acvp_json_transcript_manifest` | `artifact_schema` | Validate product-facing artifact acvp_json_transcript_manifest against its schema and profile requirement. |
| `artifact.acvp_negative_scenario_floor_result` | `artifact_schema` | Validate product-facing artifact acvp_negative_scenario_floor_result against its schema and profile requirement. |
| `artifact.assurance_ledger` | `artifact_schema` | Validate product-facing artifact assurance_ledger against its schema and profile requirement. |
| `artifact.assurance_ledger_markdown` | `artifact_schema` | Validate product-facing artifact assurance_ledger_markdown against its schema and profile requirement. |
| `artifact.assurance_report_html` | `artifact_schema` | Validate product-facing artifact assurance_report_html against its schema and profile requirement. |
| `artifact.backend_contract_result` | `artifact_schema` | Validate product-facing artifact backend_contract_result against its schema and profile requirement. |
| `artifact.backend_update_evaluation` | `artifact_schema` | Validate product-facing artifact backend_update_evaluation against its schema and profile requirement. |
| `artifact.benchmark_campaign_result` | `artifact_schema` | Validate product-facing artifact benchmark_campaign_result against its schema and profile requirement. |
| `artifact.benchmark_campaign_verify_result` | `artifact_schema` | Validate product-facing artifact benchmark_campaign_verify_result against its schema and profile requirement. |
| `artifact.benchmark_confidence_result` | `artifact_schema` | Validate product-facing artifact benchmark_confidence_result against its schema and profile requirement. |
| `artifact.benchmark_provenance` | `artifact_schema` | Validate product-facing artifact benchmark_provenance against its schema and profile requirement. |
| `artifact.benchmark_results_csv` | `artifact_schema` | Validate product-facing artifact benchmark_results_csv against its schema and profile requirement. |
| `artifact.benchmark_summary_markdown` | `artifact_schema` | Validate product-facing artifact benchmark_summary_markdown against its schema and profile requirement. |
| `artifact.cost_of_assurance_evidence` | `artifact_schema` | Validate product-facing artifact cost_of_assurance_evidence against its schema and profile requirement. |
| `artifact.ct_campaign_result` | `artifact_schema` | Validate product-facing artifact ct_campaign_result against its schema and profile requirement. |
| `artifact.ct_instruction_policy_result` | `artifact_schema` | Validate product-facing artifact ct_instruction_policy_result against its schema and profile requirement. |
| `artifact.ct_sample_analysis_result` | `artifact_schema` | Validate product-facing artifact ct_sample_analysis_result against its schema and profile requirement. |
| `artifact.device_evidence_token` | `artifact_schema` | Validate product-facing artifact device_evidence_token against its schema and profile requirement. |
| `artifact.device_evidence_token_result` | `artifact_schema` | Validate product-facing artifact device_evidence_token_result against its schema and profile requirement. |
| `artifact.evidence_tamper_drill_result` | `artifact_schema` | Validate product-facing artifact evidence_tamper_drill_result against its schema and profile requirement. |
| `artifact.evidence_transcript_manifest` | `artifact_schema` | Validate product-facing artifact evidence_transcript_manifest against its schema and profile requirement. |
| `artifact.external_non_native_inventory` | `artifact_schema` | Validate product-facing artifact external_non_native_inventory against its schema and profile requirement. |
| `artifact.firmware_assurance_status_result` | `artifact_schema` | Validate product-facing artifact firmware_assurance_status_result against its schema and profile requirement. |
| `artifact.firmware_digest_header` | `artifact_schema` | Validate product-facing artifact firmware_digest_header against its schema and profile requirement. |
| `artifact.mcu_protocol_footprint_csv` | `artifact_schema` | Validate product-facing artifact mcu_protocol_footprint_csv against its schema and profile requirement. |
| `artifact.paper_comparison_campaign_csv` | `artifact_schema` | Validate product-facing artifact paper_comparison_campaign_csv against its schema and profile requirement. |
| `artifact.paper_comparison_campaign_json` | `artifact_schema` | Validate product-facing artifact paper_comparison_campaign_json against its schema and profile requirement. |
| `artifact.partner_review_scorecard` | `artifact_schema` | Validate product-facing artifact partner_review_scorecard against its schema and profile requirement. |
| `artifact.partner_review_scorecard_markdown` | `artifact_schema` | Validate product-facing artifact partner_review_scorecard_markdown against its schema and profile requirement. |
| `artifact.partner_review_scorecard_result` | `artifact_schema` | Validate product-facing artifact partner_review_scorecard_result against its schema and profile requirement. |
| `artifact.pqc_appraisal_evidence` | `artifact_schema` | Validate product-facing artifact pqc_appraisal_evidence against its schema and profile requirement. |
| `artifact.pqc_appraisal_result` | `artifact_schema` | Validate product-facing artifact pqc_appraisal_result against its schema and profile requirement. |
| `artifact.pqc_asset_trace_result` | `artifact_schema` | Validate product-facing artifact pqc_asset_trace_result against its schema and profile requirement. |
| `artifact.pqc_assurance_digest` | `artifact_schema` | Validate product-facing artifact pqc_assurance_digest against its schema and profile requirement. |
| `artifact.pqc_assurance_profile_result` | `artifact_schema` | Validate product-facing artifact pqc_assurance_profile_result against its schema and profile requirement. |
| `artifact.pqc_attestation` | `artifact_schema` | Validate product-facing artifact pqc_attestation against its schema and profile requirement. |
| `artifact.pqc_build_provenance` | `artifact_schema` | Validate product-facing artifact pqc_build_provenance against its schema and profile requirement. |
| `artifact.pqc_build_provenance_result` | `artifact_schema` | Validate product-facing artifact pqc_build_provenance_result against its schema and profile requirement. |
| `artifact.pqc_cbom` | `artifact_schema` | Validate product-facing artifact pqc_cbom against its schema and profile requirement. |
| `artifact.pqc_claim_closure_result` | `artifact_schema` | Validate product-facing artifact pqc_claim_closure_result against its schema and profile requirement. |
| `artifact.pqc_environment_result` | `artifact_schema` | Validate product-facing artifact pqc_environment_result against its schema and profile requirement. |
| `artifact.pqc_evidence_graph_json` | `artifact_schema` | Validate product-facing artifact pqc_evidence_graph_json against its schema and profile requirement. |
| `artifact.pqc_evidence_graph_markdown` | `artifact_schema` | Validate product-facing artifact pqc_evidence_graph_markdown against its schema and profile requirement. |
| `artifact.pqc_evidence_quality_result` | `artifact_schema` | Validate product-facing artifact pqc_evidence_quality_result against its schema and profile requirement. |
| `artifact.pqc_migration_readiness_json` | `artifact_schema` | Validate product-facing artifact pqc_migration_readiness_json against its schema and profile requirement. |
| `artifact.pqc_migration_readiness_markdown` | `artifact_schema` | Validate product-facing artifact pqc_migration_readiness_markdown against its schema and profile requirement. |
| `artifact.pqc_policy_result` | `artifact_schema` | Validate product-facing artifact pqc_policy_result against its schema and profile requirement. |
| `artifact.pqc_reference_values` | `artifact_schema` | Validate product-facing artifact pqc_reference_values against its schema and profile requirement. |
| `artifact.pqc_reference_values_result` | `artifact_schema` | Validate product-facing artifact pqc_reference_values_result against its schema and profile requirement. |
| `artifact.provider_scope_result` | `artifact_schema` | Validate product-facing artifact provider_scope_result against its schema and profile requirement. |
| `artifact.release_manifest` | `artifact_schema` | Validate product-facing artifact release_manifest against its schema and profile requirement. |
| `artifact.release_notes_markdown` | `artifact_schema` | Validate product-facing artifact release_notes_markdown against its schema and profile requirement. |
| `artifact.release_reference_values_result` | `artifact_schema` | Validate product-facing artifact release_reference_values_result against its schema and profile requirement. |
| `benchmark.paper_comparable_campaign` | `benchmark_methodology` | Run repeated benchmark campaigns and compare distribution statistics against accepted metadata requirements. |
| `benchmark.external_reference_import` | `benchmark_methodology` | Import external reference rows only when source, clock, compiler, platform, statistic, and environment metadata are present. |
| `acvp.malformed_then_valid_recovery` | `acvp_interop` | Prove malformed ACVP JSON or serial input does not poison the following valid command. |
| `acvp.operation_schema_coverage` | `acvp_interop` | Validate explicit operation coverage for key generation, encapsulation, decapsulation, signing, and verification workflows. |
| `ct.sample_balance` | `side_channel_smoke` | Require balanced valid and invalid CT sample classes with contiguous indexes before accepting timing-smoke analysis. |
| `ct.instruction_policy_coverage` | `side_channel_smoke` | Require decapsulation symbol coverage so instruction scanning cannot pass by scanning only harness code. |
| `hardware.uart_transcript_capture` | `hardware_promotion` | Capture physical-board UART output and hash it into a board evidence result. |
| `hardware.entropy_source_review` | `hardware_promotion` | Record board entropy source assumptions before promoting a profile beyond QEMU/local evidence. |
| `product.cli_release_pack` | `product_packaging` | Expose stable product-facing commands over internal scripts for build-pack, verify-pack, policy replay, and schema validation. |
| `product.dashboard_ingest_contract` | `product_packaging` | Load dashboard values only from schema-validated artifacts and show not-required states for omitted profile artifacts. |
| `product.customer_policy_overlay` | `product_packaging` | Support customer policy overlays without editing repository defaults or weakening baseline policy requirements. |
| `product.signed_pack_readiness` | `product_packaging` | Prepare detached signature workflow and key-custody documentation while keeping unsigned evidence clearly labeled. |
