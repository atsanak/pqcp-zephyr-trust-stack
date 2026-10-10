# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
# PQCP Zephyr Trust Stack - CMake Build Configuration
#
# This module provides ML-KEM (FIPS-203) and ML-DSA (FIPS-204) implementations
# using the PQ Code Package's mlkem-native and mldsa-native libraries.

cmake_minimum_required(VERSION 3.20.0)

set(PQCP_PROJECT_VERSION "1.0.0")

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(PQCPZephyrTrustStack VERSION ${PQCP_PROJECT_VERSION} LANGUAGES C)
endif()

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/include/pqcp_zephyr/version.h" PQCP_VERSION_HEADER_TEXT)
string(
  REGEX MATCH
  "#define[ \t]+PQCP_VERSION_STRING[ \t]+\"([0-9]+\\.[0-9]+\\.[0-9]+)\""
  PQCP_VERSION_HEADER_MATCH
  "${PQCP_VERSION_HEADER_TEXT}"
)

if(NOT CMAKE_MATCH_1)
  message(FATAL_ERROR
    "Unable to parse PQCP_VERSION_STRING from "
    "${CMAKE_CURRENT_SOURCE_DIR}/include/pqcp_zephyr/version.h"
  )
endif()

set(PQCP_HEADER_VERSION "${CMAKE_MATCH_1}")

if(NOT PQCP_PROJECT_VERSION STREQUAL PQCP_HEADER_VERSION)
  message(FATAL_ERROR
    "PQCP version mismatch: CMakeLists.txt declares ${PQCP_PROJECT_VERSION} "
    "but version.h declares ${PQCP_HEADER_VERSION}"
  )
endif()

# Module registration for west
if(CONFIG_PQCP)

# =============================================================================
# Module Paths
# =============================================================================
set(PQCP_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(PQCP_INC ${PQCP_DIR}/include)
set(PQCP_SRC ${PQCP_DIR}/src)
set(PQCP_EXT ${PQCP_DIR}/ext)
set(PQCP_WORKSPACE_CRYPTO_DIR ${PQCP_DIR}/../modules/crypto)

# External library paths
if(EXISTS ${PQCP_EXT}/mlkem-native/mlkem)
    set(MLKEM_NATIVE_DIR ${PQCP_EXT}/mlkem-native)
elseif(EXISTS ${PQCP_WORKSPACE_CRYPTO_DIR}/mlkem-native/mlkem)
    set(MLKEM_NATIVE_DIR ${PQCP_WORKSPACE_CRYPTO_DIR}/mlkem-native)
else()
    set(MLKEM_NATIVE_DIR ${PQCP_EXT}/mlkem-native)
endif()

if(EXISTS ${PQCP_EXT}/mldsa-native/mldsa)
    set(MLDSA_NATIVE_DIR ${PQCP_EXT}/mldsa-native)
elseif(EXISTS ${PQCP_WORKSPACE_CRYPTO_DIR}/mldsa-native/mldsa)
    set(MLDSA_NATIVE_DIR ${PQCP_WORKSPACE_CRYPTO_DIR}/mldsa-native)
else()
    set(MLDSA_NATIVE_DIR ${PQCP_EXT}/mldsa-native)
endif()

# =============================================================================
# Include Paths
# =============================================================================
zephyr_include_directories(${PQCP_INC})

# =============================================================================
# Common Sources
# =============================================================================
zephyr_library_named(pqcp_common)

if(CONFIG_PQCP_MBEDTLS_THREADING)
    # TF-PSA 1.x owns the threading configuration shared with Mbed TLS 4.
    zephyr_include_directories(${PQCP_INC}/pqcp_zephyr/mbedtls_threading)
    zephyr_compile_definitions(MBEDTLS_THREADING_C MBEDTLS_THREADING_ALT)
    zephyr_library_sources(${PQCP_SRC}/mbedtls_threading_zephyr.c)
endif()

# RNG abstraction - select ONE backend
if(CONFIG_PQCP_RNG_DETERMINISTIC_TEST)
    # Deterministic RNG for testing (overrides custom)
    zephyr_library_sources(${PQCP_SRC}/rng_deterministic.c)
elseif(CONFIG_PQCP_RNG_ZEPHYR_ENTROPY)
    zephyr_library_sources(${PQCP_SRC}/rng_zephyr_entropy.c)
elseif(CONFIG_PQCP_RNG_PSA)
    zephyr_library_sources(${PQCP_SRC}/rng_psa.c)
elseif(CONFIG_PQCP_RNG_CUSTOM)
    zephyr_library_sources(${PQCP_SRC}/rng_custom.c)
endif()

# Common RNG interface
zephyr_library_sources(${PQCP_SRC}/rng_common.c)

if(CONFIG_PQCP_ASSURANCE_STATUS)
    zephyr_library_sources(${PQCP_SRC}/assurance_status.c)
endif()

if(CONFIG_PQCP_PROVIDER_CONTRACT)
    zephyr_library_sources(${PQCP_SRC}/provider_contract.c)
endif()

if(CONFIG_PQCP_BUILD_MANIFEST)
    zephyr_library_sources(${PQCP_SRC}/build_manifest.c)
endif()

if(CONFIG_PQCP_EVIDENCE_SESSION)
    zephyr_library_sources(${PQCP_SRC}/evidence_session.c)
endif()

if(CONFIG_PQCP_EVIDENCE_TRANSCRIPT)
    zephyr_library_sources(${PQCP_SRC}/evidence_transcript.c)
endif()

if(CONFIG_PQCP_FIRMWARE_POLICY)
    zephyr_library_sources(${PQCP_SRC}/firmware_policy.c)
endif()

if(CONFIG_PQCP_CAPABILITY_DESCRIPTOR)
    zephyr_library_sources(${PQCP_SRC}/capability_descriptor.c)
endif()

if(CONFIG_PQCP_CAPABILITY_EXTENSION)
    zephyr_library_sources(${PQCP_SRC}/capability_extension.c)
endif()

if(CONFIG_PQCP_FIRMWARE_SCORECARD)
    zephyr_library_sources(${PQCP_SRC}/firmware_scorecard.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_ADVISOR)
    zephyr_library_sources(${PQCP_SRC}/deployment_advisor.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_ROBUSTNESS)
    zephyr_library_sources(${PQCP_SRC}/deployment_robustness.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_CAMPAIGN)
    zephyr_library_sources(${PQCP_SRC}/deployment_campaign.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_TRANSCRIPT)
    zephyr_library_sources(${PQCP_SRC}/deployment_transcript.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_APPRAISAL)
    zephyr_library_sources(${PQCP_SRC}/deployment_appraisal.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_CLAIMS)
    zephyr_library_sources(${PQCP_SRC}/deployment_claims.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_TRACE_BUILDER)
    zephyr_library_sources(${PQCP_SRC}/deployment_trace_builder.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_PIPELINE)
    zephyr_library_sources(${PQCP_SRC}/deployment_pipeline.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_BUDGET)
    zephyr_library_sources(${PQCP_SRC}/deployment_budget.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_EXPERIMENT_PLAN)
    zephyr_library_sources(${PQCP_SRC}/deployment_experiment_plan.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_REVIEW_PACKET)
    zephyr_library_sources(${PQCP_SRC}/deployment_review_packet.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_REVIEW_VERIFIER)
    zephyr_library_sources(${PQCP_SRC}/deployment_review_verifier.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_REVIEW_AUDIT)
    zephyr_library_sources(${PQCP_SRC}/deployment_review_audit.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_RELEASE_GATE)
    zephyr_library_sources(${PQCP_SRC}/deployment_release_gate.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_DEVICE_TOKEN)
    zephyr_library_sources(${PQCP_SRC}/deployment_device_token.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_DEVICE_TOKEN_REPLAY)
    zephyr_library_sources(${PQCP_SRC}/deployment_device_token_replay.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_DEVICE_TOKEN_AUDIT)
    zephyr_library_sources(${PQCP_SRC}/deployment_device_token_audit.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_DEVICE_GATE)
    zephyr_library_sources(${PQCP_SRC}/deployment_device_gate.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_DEVICE_PACKET)
    zephyr_library_sources(${PQCP_SRC}/deployment_device_packet.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_DEVICE_PACKET_REPLAY)
    zephyr_library_sources(${PQCP_SRC}/deployment_device_packet_replay.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_DEVICE_PACKET_AUDIT)
    zephyr_library_sources(${PQCP_SRC}/deployment_device_packet_audit.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_EVIDENCE_VERDICT)
    zephyr_library_sources(${PQCP_SRC}/deployment_evidence_verdict.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_EVIDENCE_VERDICT_REPLAY)
    zephyr_library_sources(${PQCP_SRC}/deployment_evidence_verdict_replay.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_EVIDENCE_VERDICT_AUDIT)
    zephyr_library_sources(${PQCP_SRC}/deployment_evidence_verdict_audit.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_EVIDENCE_SEAL)
    zephyr_library_sources(${PQCP_SRC}/deployment_evidence_seal.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_EVIDENCE_SEAL_REPLAY)
    zephyr_library_sources(${PQCP_SRC}/deployment_evidence_seal_replay.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT)
    zephyr_library_sources(${PQCP_SRC}/deployment_evidence_seal_audit.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_ASSURANCE_PASSPORT)
    zephyr_library_sources(${PQCP_SRC}/deployment_assurance_passport.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY)
    zephyr_library_sources(${PQCP_SRC}/deployment_assurance_passport_replay.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_PASSPORT_SIGNATURE)
    zephyr_library_sources(${PQCP_SRC}/deployment_passport_signature.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_MARKER_RENDER)
    zephyr_library_sources(${PQCP_SRC}/deployment_marker_render.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_TAMPER_ENGINE)
    zephyr_library_sources(${PQCP_SRC}/deployment_tamper_engine.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_TAMPER_MATRIX)
    zephyr_library_sources(${PQCP_SRC}/deployment_tamper_matrix.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY)
    zephyr_library_sources(${PQCP_SRC}/deployment_tamper_matrix_replay.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT)
    zephyr_library_sources(${PQCP_SRC}/deployment_tamper_matrix_audit.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_EVIDENCE_TRAIL)
    zephyr_library_sources(${PQCP_SRC}/deployment_evidence_trail.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY)
    zephyr_library_sources(${PQCP_SRC}/deployment_evidence_trail_replay.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT)
    zephyr_library_sources(${PQCP_SRC}/deployment_evidence_trail_audit.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_EVIDENCE_CODEC)
    zephyr_library_sources(${PQCP_SRC}/deployment_evidence_codec.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_EVIDENCE_CAPSULE)
    zephyr_library_sources(${PQCP_SRC}/deployment_evidence_capsule.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY)
    zephyr_library_sources(${PQCP_SRC}/deployment_evidence_capsule_replay.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_EVIDENCE_JOURNAL)
    zephyr_library_sources(${PQCP_SRC}/deployment_evidence_journal.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY)
    zephyr_library_sources(${PQCP_SRC}/deployment_evidence_journal_replay.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT)
    zephyr_library_sources(${PQCP_SRC}/deployment_evidence_journal_audit.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_FLEET_CONSENSUS)
    zephyr_library_sources(${PQCP_SRC}/deployment_fleet_consensus.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_FLEET_POLICY)
    zephyr_library_sources(${PQCP_SRC}/deployment_fleet_policy.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE)
    zephyr_library_sources(${PQCP_SRC}/deployment_evidence_archive.c)
endif()

if(CONFIG_PQCP_ADAPTIVE_CONTROL)
    zephyr_library_sources(
        ${PQCP_SRC}/adaptive_common.c
        ${PQCP_SRC}/adaptive_profile.c
        ${PQCP_SRC}/adaptive_telemetry.c
        ${PQCP_SRC}/adaptive_forecast.c
        ${PQCP_SRC}/adaptive_threat.c
        ${PQCP_SRC}/adaptive_resource.c
        ${PQCP_SRC}/adaptive_policy.c
        ${PQCP_SRC}/adaptive_optimizer.c
        ${PQCP_SRC}/adaptive_downgrade.c
        ${PQCP_SRC}/adaptive_transition.c
        ${PQCP_SRC}/adaptive_session.c
        ${PQCP_SRC}/adaptive_workload.c
        ${PQCP_SRC}/adaptive_resilience.c
        ${PQCP_SRC}/adaptive_event_log.c
        ${PQCP_SRC}/adaptive_fleet.c
        ${PQCP_SRC}/adaptive_snapshot.c
        ${PQCP_SRC}/adaptive_calibration.c
        ${PQCP_SRC}/adaptive_control.c
    )
endif()

if(CONFIG_PQCP_RUNTIME)
    zephyr_library_sources(
        ${PQCP_SRC}/runtime_common.c
        ${PQCP_SRC}/runtime_capability.c
        ${PQCP_SRC}/runtime_profile.c
        ${PQCP_SRC}/runtime_key_store.c
        ${PQCP_SRC}/runtime_key_store_volatile.c
        ${PQCP_SRC}/runtime_key_store_psa.c
        ${PQCP_SRC}/runtime_workspace.c
        ${PQCP_SRC}/runtime_measurement.c
        ${PQCP_SRC}/runtime_executor.c
        ${PQCP_SRC}/runtime_executor_mlkem.c
        ${PQCP_SRC}/runtime_executor_mldsa.c
        ${PQCP_SRC}/runtime_executor_symmetric.c
        ${PQCP_SRC}/runtime_session.c
        ${PQCP_SRC}/runtime_snapshot.c
        ${PQCP_SRC}/runtime_key_policy.c
        ${PQCP_SRC}/runtime_audit.c
        ${PQCP_SRC}/runtime_health.c
        ${PQCP_SRC}/runtime_controller.c
        ${PQCP_SRC}/runtime_recovery.c
        ${PQCP_SRC}/runtime_campaign.c
        ${PQCP_SRC}/runtime_identity.c
        ${PQCP_SRC}/runtime_admission.c
        ${PQCP_SRC}/runtime_rotation.c
        ${PQCP_SRC}/runtime_circuit.c
        ${PQCP_SRC}/runtime_evidence_summary.c
        ${PQCP_SRC}/runtime_service.c
        ${PQCP_SRC}/runtime_selftest.c
        ${PQCP_SRC}/runtime_transaction.c
        ${PQCP_SRC}/runtime_migration.c
        ${PQCP_SRC}/runtime_lease.c
        ${PQCP_SRC}/runtime_event_bus.c
        ${PQCP_SRC}/runtime_scheduler_policy.c
        ${PQCP_SRC}/runtime_checkpoint_store.c
        ${PQCP_SRC}/runtime_command_router.c
        ${PQCP_SRC}/runtime_metrics.c
        ${PQCP_SRC}/runtime_orchestrator.c
        ${PQCP_SRC}/runtime_resource_governor.c
        ${PQCP_SRC}/runtime_policy_catalog.c
        ${PQCP_SRC}/runtime_resource_policy_catalog.c
        ${PQCP_SRC}/runtime_recovery_policy_catalog.c
        ${PQCP_SRC}/runtime_operation_planner.c
    )
endif()

if(CONFIG_PQCP_CRYPTO_BROKER)
    zephyr_library_sources(
        ${PQCP_SRC}/crypto_broker.c
        ${PQCP_SRC}/crypto_broker_authorization.c
        ${PQCP_SRC}/crypto_broker_dispatch.c
        ${PQCP_SRC}/crypto_broker_ledger.c
        ${PQCP_SRC}/crypto_broker_receipt.c
    )
endif()

if(CONFIG_PQCP_RUNTIME_JOURNAL)
    zephyr_library_sources(${PQCP_SRC}/runtime_journal.c)
endif()
if(CONFIG_PQCP_RUNTIME_JOURNAL_FLASH)
    zephyr_library_sources(${PQCP_SRC}/runtime_journal_flash.c)
endif()

if(CONFIG_PQCP_PROTECTED_CHANNEL)
    zephyr_library_sources(
        ${PQCP_SRC}/protected_channel_codec.c
        ${PQCP_SRC}/protected_channel_transcript.c
        ${PQCP_SRC}/protected_channel_replay.c
        ${PQCP_SRC}/protected_channel_transport.c
        ${PQCP_SRC}/protected_channel_kdf.c
        ${PQCP_SRC}/protected_channel_record.c
        ${PQCP_SRC}/protected_channel_handshake.c
        ${PQCP_SRC}/protected_channel_memory.c
        ${PQCP_SRC}/protected_channel_fragment.c
        ${PQCP_SRC}/protected_channel_policy.c
        ${PQCP_SRC}/protected_channel_journal.c
        ${PQCP_SRC}/protected_channel_supervisor.c
        ${PQCP_SRC}/protected_channel_control_codec.c
        ${PQCP_SRC}/protected_channel_flow_control.c
        ${PQCP_SRC}/protected_channel_mux.c
        ${PQCP_SRC}/protected_channel_rekey.c
        ${PQCP_SRC}/protected_channel_resumption.c
        ${PQCP_SRC}/protected_channel_peer_health.c
        ${PQCP_SRC}/protected_channel_path_manager.c
        ${PQCP_SRC}/protected_channel_operations.c
        ${PQCP_SRC}/protected_channel_policy_catalog.c
        ${PQCP_SRC}/protected_channel_path_policy_catalog.c
        ${PQCP_SRC}/protected_channel_fault_policy_catalog.c
        ${PQCP_SRC}/protected_channel_operation_planner.c
    )
endif()

if(CONFIG_PQCP_FLEET_TRUST)
    zephyr_library_sources(
        ${PQCP_SRC}/fleet_cbor.c
        ${PQCP_SRC}/fleet_sha256.c
        ${PQCP_SRC}/fleet_protocol.c
        ${PQCP_SRC}/fleet_store.c
        ${PQCP_SRC}/fleet_enrollment.c
        ${PQCP_SRC}/fleet_registrar.c
        ${PQCP_SRC}/fleet_policy_engine.c
        ${PQCP_SRC}/fleet_command_engine.c
        ${PQCP_SRC}/fleet_update_manager.c
        ${PQCP_SRC}/fleet_audit_ledger.c
        ${PQCP_SRC}/fleet_journal.c
        ${PQCP_SRC}/fleet_telemetry.c
        ${PQCP_SRC}/fleet_attestation.c
        ${PQCP_SRC}/fleet_reconciliation.c
        ${PQCP_SRC}/fleet_operations.c
        ${PQCP_SRC}/fleet_secure_time.c
        ${PQCP_SRC}/fleet_revocation_index.c
        ${PQCP_SRC}/fleet_rollout.c
        ${PQCP_SRC}/fleet_health_monitor.c
        ${PQCP_SRC}/fleet_lease_manager.c
        ${PQCP_SRC}/fleet_recovery_manager.c
        ${PQCP_SRC}/fleet_peer_registry.c
        ${PQCP_SRC}/fleet_admission_controller.c
        ${PQCP_SRC}/fleet_risk_engine.c
        ${PQCP_SRC}/fleet_maintenance_scheduler.c
    )
endif()

if(CONFIG_PQCP_FLEET_TRANSPARENCY)
    zephyr_library_sources(
        ${PQCP_SRC}/fleet_transparency_merkle.c
        ${PQCP_SRC}/fleet_transparency_log.c
        ${PQCP_SRC}/fleet_transparency_proof.c
        ${PQCP_SRC}/fleet_transparency_checkpoint.c
        ${PQCP_SRC}/fleet_transparency_witness.c
        ${PQCP_SRC}/fleet_transparency_gossip.c
    )
endif()

if(CONFIG_PQCP_FLEET_APPROVAL)
    zephyr_library_sources(
        ${PQCP_SRC}/fleet_approval_policy.c
        ${PQCP_SRC}/fleet_approval_session.c
        ${PQCP_SRC}/fleet_approval_receipt.c
    )
endif()

if(CONFIG_PQCP_FLEET_ARTIFACT_CORE)
    zephyr_library_sources(
        ${PQCP_SRC}/fleet_cbor_map.c
        ${PQCP_SRC}/fleet_cose_sign1.c
        ${PQCP_SRC}/fleet_cose_key.c
        ${PQCP_SRC}/fleet_eat_profile.c
        ${PQCP_SRC}/fleet_rats.c
        ${PQCP_SRC}/fleet_artifact_ffi.c
    )
endif()

if(CONFIG_PQCP_FLEET_POLICY_VM)
    zephyr_library_sources(
        ${PQCP_SRC}/fleet_policy_vm.c
        ${PQCP_SRC}/fleet_policy_verify.c
        ${PQCP_SRC}/fleet_policy_codec.c
        ${PQCP_SRC}/fleet_policy_builtins.c
        ${PQCP_SRC}/fleet_policy_explain.c
        ${PQCP_SRC}/fleet_policy_store.c
        ${PQCP_SRC}/fleet_policy_rollout.c
    )
endif()

if(CONFIG_PQCP_FLEET_CONVERGENCE)
    zephyr_library_sources(
        ${PQCP_SRC}/fleet_delivery.c
        ${PQCP_SRC}/fleet_receipt.c
        ${PQCP_SRC}/fleet_desired_state.c
        ${PQCP_SRC}/fleet_convergence.c
        ${PQCP_SRC}/fleet_artifact_cache.c
        ${PQCP_SRC}/fleet_snapshot_sync.c
        ${PQCP_SRC}/fleet_transport_mux.c
        ${PQCP_SRC}/fleet_recovery_orchestrator.c
    )
endif()

if(CONFIG_PQCP_EDGE_SECURITY)
    zephyr_library_sources(
        ${PQCP_SRC}/edge_security_common.c
        ${PQCP_SRC}/edge_identity_directory.c
        ${PQCP_SRC}/edge_service_registry.c
        ${PQCP_SRC}/edge_access_engine.c
        ${PQCP_SRC}/edge_route_table.c
        ${PQCP_SRC}/edge_session_registry.c
        ${PQCP_SRC}/edge_traffic_governor.c
        ${PQCP_SRC}/edge_circuit_breaker.c
        ${PQCP_SRC}/edge_message_queue.c
        ${PQCP_SRC}/edge_replay_guard.c
        ${PQCP_SRC}/edge_fragment_manager.c
        ${PQCP_SRC}/edge_message_ratchet.c
        ${PQCP_SRC}/edge_topic_registry.c
        ${PQCP_SRC}/edge_group_manager.c
        ${PQCP_SRC}/edge_delivery_manager.c
        ${PQCP_SRC}/edge_vault_store.c
        ${PQCP_SRC}/edge_vault_acl.c
        ${PQCP_SRC}/edge_vault_version.c
        ${PQCP_SRC}/edge_vault_lease.c
        ${PQCP_SRC}/edge_vault_journal.c
        ${PQCP_SRC}/edge_replication_manager.c
        ${PQCP_SRC}/edge_snapshot_manager.c
        ${PQCP_SRC}/edge_signal_engine.c
        ${PQCP_SRC}/edge_incident_manager.c
        ${PQCP_SRC}/edge_playbook_engine.c
        ${PQCP_SRC}/edge_evidence_store.c
        ${PQCP_SRC}/edge_containment_manager.c
        ${PQCP_SRC}/edge_continuity_manager.c
        ${PQCP_SRC}/edge_posture_engine.c
        ${PQCP_SRC}/edge_attestation_manager.c
        ${PQCP_SRC}/edge_policy_distributor.c
        ${PQCP_SRC}/edge_rotation_manager.c
        ${PQCP_SRC}/edge_anomaly_engine.c
        ${PQCP_SRC}/edge_resource_monitor.c
        ${PQCP_SRC}/edge_audit_exporter.c
        ${PQCP_SRC}/edge_recovery_coordinator.c
        ${PQCP_SRC}/edge_dlp_engine.c
        ${PQCP_SRC}/edge_trust_federation.c
        ${PQCP_SRC}/edge_credential_cache.c
        ${PQCP_SRC}/edge_isolation_manager.c
        ${PQCP_SRC}/edge_provenance_ledger.c
        ${PQCP_SRC}/edge_workload_scheduler.c
        ${PQCP_SRC}/edge_sla_monitor.c
        ${PQCP_SRC}/edge_config_manager.c
        ${PQCP_SRC}/edge_compliance.c
        ${PQCP_SRC}/edge_runtime_admission.c
        ${PQCP_SRC}/edge_security_runtime.c
    )
endif()

if(CONFIG_PQCP_SOVEREIGN_RUNTIME)
    zephyr_library_sources(
        ${PQCP_SRC}/sovereign_artifact_catalog.c
        ${PQCP_SRC}/sovereign_sbom_registry.c
        ${PQCP_SRC}/sovereign_build_attestation.c
        ${PQCP_SRC}/sovereign_release_policy.c
        ${PQCP_SRC}/sovereign_transparency_log.c
        ${PQCP_SRC}/sovereign_tenant_registry.c
        ${PQCP_SRC}/sovereign_namespace_manager.c
        ${PQCP_SRC}/sovereign_residency_engine.c
        ${PQCP_SRC}/sovereign_purpose_engine.c
        ${PQCP_SRC}/sovereign_privacy_budget.c
        ${PQCP_SRC}/sovereign_data_contract.c
        ${PQCP_SRC}/sovereign_consent_ledger.c
        ${PQCP_SRC}/sovereign_retention_manager.c
        ${PQCP_SRC}/sovereign_egress_engine.c
        ${PQCP_SRC}/sovereign_approval_quorum.c
        ${PQCP_SRC}/sovereign_key_ceremony.c
        ${PQCP_SRC}/sovereign_secret_distributor.c
        ${PQCP_SRC}/sovereign_ceremony_authorization.c
        ${PQCP_SRC}/sovereign_custody_ledger.c
        ${PQCP_SRC}/sovereign_event.c
        ${PQCP_SRC}/sovereign_event_ledger.c
        ${PQCP_SRC}/sovereign_audit_cbor.c
        ${PQCP_SRC}/sovereign_audit_cef.c
        ${PQCP_SRC}/sovereign_audit_ocsf.c
        ${PQCP_SRC}/sovereign_channel_codec.c
        ${PQCP_SRC}/sovereign_channel_assembler.c
        ${PQCP_SRC}/sovereign_channel_flow.c
        ${PQCP_SRC}/sovereign_channel_resume.c
        ${PQCP_SRC}/sovereign_channel_broker.c
        ${PQCP_SRC}/sovereign_channel_server.c
        ${PQCP_SRC}/sovereign_channel_client.c
        ${PQCP_SRC}/sovereign_policy_common.c
        ${PQCP_SRC}/sovereign_network_policy.c
        ${PQCP_SRC}/sovereign_placement_engine.c
        ${PQCP_SRC}/sovereign_rollout_controller.c
        ${PQCP_SRC}/sovereign_rollback_coordinator.c
        ${PQCP_SRC}/sovereign_dependency_graph.c
        ${PQCP_SRC}/sovereign_risk_graph.c
        ${PQCP_SRC}/sovereign_threat_intelligence.c
        ${PQCP_SRC}/sovereign_forensic_timeline.c
        ${PQCP_SRC}/sovereign_control_catalog.c
        ${PQCP_SRC}/sovereign_exception_manager.c
        ${PQCP_SRC}/sovereign_evidence_packager.c
        ${PQCP_SRC}/sovereign_regulator_exporter.c
        ${PQCP_SRC}/sovereign_continuity_exerciser.c
        ${PQCP_SRC}/sovereign_recovery_quorum.c
        ${PQCP_SRC}/sovereign_cost_governor.c
        ${PQCP_SRC}/sovereign_continuity_objective.c
        ${PQCP_SRC}/sovereign_recovery_point.c
        ${PQCP_SRC}/sovereign_authority_lease.c
        ${PQCP_SRC}/sovereign_fencing.c
        ${PQCP_SRC}/sovereign_recovery_plan.c
        ${PQCP_SRC}/sovereign_recovery_orchestrator.c
        ${PQCP_SRC}/sovereign_continuity_audit.c
        ${PQCP_SRC}/sovereign_runtime.c
    )
endif()

if(CONFIG_PQCP_FLEET_STORE_ITS)
    zephyr_library_sources(
        ${PQCP_SRC}/fleet_store_its.c
    )
endif()

if(CONFIG_PQCP_OPERATION_CONFORMANCE_CATALOGS)
    zephyr_library_sources(
        ${PQCP_SRC}/operation_conformance.c
        ${PQCP_SRC}/runtime_policy_conformance_catalog.c
        ${PQCP_SRC}/runtime_resource_conformance_catalog.c
        ${PQCP_SRC}/runtime_recovery_conformance_catalog.c
        ${PQCP_SRC}/protected_channel_policy_conformance_catalog.c
        ${PQCP_SRC}/protected_channel_path_conformance_catalog.c
        ${PQCP_SRC}/protected_channel_fault_conformance_catalog.c
        ${PQCP_SRC}/operation_plan_conformance.c
        ${PQCP_SRC}/runtime_operation_plan_conformance_catalog.c
        ${PQCP_SRC}/protected_channel_operation_plan_conformance_catalog.c
    )
endif()

if(CONFIG_PQCP_OPERATION_SCENARIO_CATALOGS)
    zephyr_library_sources(
        ${PQCP_SRC}/operation_scenario.c
        ${PQCP_SRC}/runtime_policy_scenario_catalog.c
        ${PQCP_SRC}/runtime_resource_scenario_catalog.c
        ${PQCP_SRC}/runtime_recovery_scenario_catalog.c
        ${PQCP_SRC}/protected_channel_policy_scenario_catalog.c
        ${PQCP_SRC}/protected_channel_path_scenario_catalog.c
        ${PQCP_SRC}/protected_channel_fault_scenario_catalog.c
    )
endif()

if(CONFIG_PQCP_RUNTIME_CHANNEL_GUARD_CATALOGS)
    zephyr_library_sources(
        ${PQCP_SRC}/runtime_guard.c
        ${PQCP_SRC}/runtime_authorization_policy_catalog.c
        ${PQCP_SRC}/runtime_continuity_policy_catalog.c
        ${PQCP_SRC}/protected_channel_guard.c
        ${PQCP_SRC}/protected_channel_epoch_policy_catalog.c
        ${PQCP_SRC}/protected_channel_stream_policy_catalog.c
    )
endif()

if(CONFIG_PQCP_OPERATION_TRANSITION_CATALOGS)
    zephyr_library_sources(
        ${PQCP_SRC}/operation_transition.c
        ${PQCP_SRC}/runtime_transition_conformance_catalog.c
        ${PQCP_SRC}/protected_channel_transition_conformance_catalog.c
    )
endif()

if(CONFIG_PQCP_PROTECTED_CHANNEL_MBEDTLS)
    zephyr_library_sources(
        ${PQCP_SRC}/protected_channel_mbedtls.c
        ${PQCP_SRC}/protected_channel_tls.c
    )
endif()

if(CONFIG_PQCP_FIRMWARE_EVIDENCE)
    zephyr_library_sources(${PQCP_SRC}/firmware_evidence.c)
endif()

# =============================================================================
# ML-KEM Library
# =============================================================================
if(CONFIG_PQCP_MLKEM)
    zephyr_library_named(pqcp_mlkem)

    # Check for mlkem-native availability
    if(EXISTS ${MLKEM_NATIVE_DIR}/mlkem)
        set(PQCP_MLKEM_LEVEL_COUNT 0)
        if(CONFIG_PQCP_MLKEM_LEVEL_512)
            math(EXPR PQCP_MLKEM_LEVEL_COUNT "${PQCP_MLKEM_LEVEL_COUNT} + 1")
        endif()
        if(CONFIG_PQCP_MLKEM_LEVEL_768)
            math(EXPR PQCP_MLKEM_LEVEL_COUNT "${PQCP_MLKEM_LEVEL_COUNT} + 1")
        endif()
        if(CONFIG_PQCP_MLKEM_LEVEL_1024)
            math(EXPR PQCP_MLKEM_LEVEL_COUNT "${PQCP_MLKEM_LEVEL_COUNT} + 1")
        endif()

        if(CONFIG_PQCP_MLKEM_MULTI_LEVEL OR PQCP_MLKEM_LEVEL_COUNT GREATER 1)
            set(MLKEM_MULTILEVEL_DIR
                ${MLKEM_NATIVE_DIR}/examples/monolithic_build_multilevel)
            zephyr_include_directories(${MLKEM_MULTILEVEL_DIR})
            zephyr_include_directories(${MLKEM_MULTILEVEL_DIR}/mlkem_native)
            zephyr_include_directories(${MLKEM_MULTILEVEL_DIR}/mlkem_native/src)
            zephyr_compile_definitions(PQCP_MLKEM_MULTILEVEL_BUILD=1)
        else()
            zephyr_include_directories(${MLKEM_NATIVE_DIR})
            zephyr_include_directories(${MLKEM_NATIVE_DIR}/mlkem)
            zephyr_include_directories(${MLKEM_NATIVE_DIR}/mlkem/src)
            # Determine security level to build
            if(CONFIG_PQCP_MLKEM_LEVEL_512)
                set(MLKEM_K 2)
                set(MLK_PARAM_SET 512)
            elseif(CONFIG_PQCP_MLKEM_LEVEL_768)
                set(MLKEM_K 3)
                set(MLK_PARAM_SET 768)
            elseif(CONFIG_PQCP_MLKEM_LEVEL_1024)
                set(MLKEM_K 4)
                set(MLK_PARAM_SET 1024)
            else()
                # Default to ML-KEM-768
                set(MLKEM_K 3)
                set(MLK_PARAM_SET 768)
            endif()

            zephyr_compile_definitions(MLKEM_K=${MLKEM_K})
            zephyr_compile_definitions(MLK_CONFIG_PARAMETER_SET=${MLK_PARAM_SET})
        endif()
        
        # Backend selection
        if(CONFIG_PQCP_IMPLEMENTATION_BASELINE OR CONFIG_PQCP_BACKEND_FORCE_C)
            zephyr_compile_definitions(MLKEM_USE_NATIVE=0)
        elseif(CONFIG_PQCP_BACKEND_FORCE_NATIVE)
            zephyr_compile_definitions(MLKEM_USE_NATIVE=1)
        endif()
        
        # Reduced RAM mode
        if(CONFIG_PQCP_REDUCE_RAM)
            zephyr_compile_definitions(MLKEM_USE_REDUCE_RAM=1)
        endif()
        
        # Compile mlkem-native either in single-level or multilevel mode.
        if(CONFIG_PQCP_MLKEM_MULTI_LEVEL OR PQCP_MLKEM_LEVEL_COUNT GREATER 1)
            zephyr_library_sources(${MLKEM_MULTILEVEL_DIR}/mlkem_native_all.c)
        else()
            zephyr_library_sources(${MLKEM_NATIVE_DIR}/mlkem/mlkem_native.c)
        endif()
        
        # Compile our Zephyr wrapper
        zephyr_library_sources(${PQCP_SRC}/mlkem_zephyr.c)
        
        # FIPS-202 (SHA-3/SHAKE) - use bundled or external
        if(NOT CONFIG_PQCP_FIPS202_EXTERNAL)
            # Use bundled FIPS-202 from mlkem-native
            if(EXISTS ${MLKEM_NATIVE_DIR}/mlkem/src/fips202)
                zephyr_include_directories(${MLKEM_NATIVE_DIR}/mlkem/src/fips202)
            endif()
        endif()
    else()
        message(WARNING "mlkem-native not found at ${MLKEM_NATIVE_DIR}. "
                        "Please run 'git submodule update --init' or use FetchContent.")
        # Provide stub implementation
        zephyr_library_sources(${PQCP_SRC}/mlkem_zephyr.c)
    endif()
    
    zephyr_library_link_libraries(pqcp_common)
endif()

# =============================================================================
# ML-DSA Library
# =============================================================================
if(CONFIG_PQCP_MLDSA)
    zephyr_library_named(pqcp_mldsa)

    # Check for mldsa-native availability
    if(EXISTS ${MLDSA_NATIVE_DIR}/mldsa)
        set(PQCP_MLDSA_LEVEL_COUNT 0)
        if(CONFIG_PQCP_MLDSA_LEVEL_44)
            math(EXPR PQCP_MLDSA_LEVEL_COUNT "${PQCP_MLDSA_LEVEL_COUNT} + 1")
        endif()
        if(CONFIG_PQCP_MLDSA_LEVEL_65)
            math(EXPR PQCP_MLDSA_LEVEL_COUNT "${PQCP_MLDSA_LEVEL_COUNT} + 1")
        endif()
        if(CONFIG_PQCP_MLDSA_LEVEL_87)
            math(EXPR PQCP_MLDSA_LEVEL_COUNT "${PQCP_MLDSA_LEVEL_COUNT} + 1")
        endif()

        if(CONFIG_PQCP_MLDSA_MULTI_LEVEL OR PQCP_MLDSA_LEVEL_COUNT GREATER 1)
            set(MLDSA_MULTILEVEL_DIR
                ${MLDSA_NATIVE_DIR}/examples/monolithic_build_multilevel)
            zephyr_include_directories(${MLDSA_MULTILEVEL_DIR})
            zephyr_include_directories(${MLDSA_MULTILEVEL_DIR}/mldsa_native)
            zephyr_include_directories(${MLDSA_MULTILEVEL_DIR}/mldsa_native/src)
            zephyr_compile_definitions(PQCP_MLDSA_MULTILEVEL_BUILD=1)
        else()
            zephyr_include_directories(${MLDSA_NATIVE_DIR})
            zephyr_include_directories(${MLDSA_NATIVE_DIR}/mldsa)
            zephyr_include_directories(${MLDSA_NATIVE_DIR}/mldsa/src)
            # Determine security level
            if(CONFIG_PQCP_MLDSA_LEVEL_44)
                set(MLDSA_MODE 2)
                set(MLD_PARAM_SET 44)
            elseif(CONFIG_PQCP_MLDSA_LEVEL_65)
                set(MLDSA_MODE 3)
                set(MLD_PARAM_SET 65)
            elseif(CONFIG_PQCP_MLDSA_LEVEL_87)
                set(MLDSA_MODE 5)
                set(MLD_PARAM_SET 87)
            else()
                # Default to ML-DSA-65
                set(MLDSA_MODE 3)
                set(MLD_PARAM_SET 65)
            endif()

            zephyr_compile_definitions(MLDSA_MODE=${MLDSA_MODE})
            zephyr_compile_definitions(MLD_CONFIG_PARAMETER_SET=${MLD_PARAM_SET})
        endif()
        
        # Backend selection
        if(CONFIG_PQCP_IMPLEMENTATION_BASELINE OR CONFIG_PQCP_BACKEND_FORCE_C)
            zephyr_compile_definitions(MLDSA_USE_NATIVE=0)
        elseif(CONFIG_PQCP_BACKEND_FORCE_NATIVE)
            zephyr_compile_definitions(MLDSA_USE_NATIVE=1)
        endif()
        
        # Reduced RAM mode
        if(CONFIG_PQCP_REDUCE_RAM)
            zephyr_compile_definitions(MLDSA_USE_REDUCE_RAM=1)
        endif()
        
        # Compile mldsa-native either in single-level or multilevel mode.
        if(CONFIG_PQCP_MLDSA_MULTI_LEVEL OR PQCP_MLDSA_LEVEL_COUNT GREATER 1)
            zephyr_library_sources(${MLDSA_MULTILEVEL_DIR}/mldsa_native_all.c)
        else()
            zephyr_library_sources(${MLDSA_NATIVE_DIR}/mldsa/mldsa_native.c)
        endif()
        
        # Compile our Zephyr wrapper
        zephyr_library_sources(${PQCP_SRC}/mldsa_zephyr.c)
        
        # Streaming API
        if(CONFIG_PQCP_MLDSA_STREAMING)
            zephyr_library_sources(${PQCP_SRC}/mldsa_streaming.c)
        endif()
        
        # FIPS-202 (SHA-3/SHAKE) - use bundled or external
        if(NOT CONFIG_PQCP_FIPS202_EXTERNAL)
            if(EXISTS ${MLDSA_NATIVE_DIR}/mldsa/src/fips202)
                zephyr_include_directories(${MLDSA_NATIVE_DIR}/mldsa/src/fips202)
            endif()
        endif()
    else()
        message(WARNING "mldsa-native not found at ${MLDSA_NATIVE_DIR}. "
                        "Please run 'git submodule update --init' or use FetchContent.")
        zephyr_library_sources(${PQCP_SRC}/mldsa_zephyr.c)
    endif()
    
    zephyr_library_link_libraries(pqcp_common)
endif()

# Shared TLS self-test helpers
if(CONFIG_PQCP_TLS_SELFTEST)
    zephyr_library_named(pqcp_tls_selftest)
    zephyr_library_sources(${PQCP_SRC}/tls_selftest.c)
    zephyr_library_link_libraries(pqcp_common)
    zephyr_library_link_libraries(pqcp_mlkem)
    zephyr_library_link_libraries(pqcp_mldsa)
endif()

# Boot-time power-on self-test (FIPS-style)
if(CONFIG_PQCP_KAT_BOOT_VERIFY)
    zephyr_library_named(pqcp_kat_boot_verify)
    zephyr_library_sources(${PQCP_SRC}/kat_boot_verify.c)
    zephyr_library_link_libraries(pqcp_common)
    if(CONFIG_PQCP_MLKEM)
        zephyr_library_link_libraries(pqcp_mlkem)
    endif()
    if(CONFIG_PQCP_MLDSA)
        zephyr_library_link_libraries(pqcp_mldsa)
    endif()
endif()

# =============================================================================
# PSA Crypto Driver Shims
# =============================================================================
if(CONFIG_PQCP_PSA_DRIVER)
    zephyr_library_named(pqcp_psa_driver)
    
    if(CONFIG_PQCP_PSA_DRIVER_MLDSA)
        zephyr_library_sources(${PQCP_SRC}/psa_mldsa_driver.c)
    endif()
    
    if(CONFIG_PQCP_PSA_DRIVER_MLKEM)
        zephyr_library_sources(${PQCP_SRC}/psa_mlkem_driver.c)
    endif()
    
    zephyr_library_link_libraries(pqcp_common)
    
    if(CONFIG_PQCP_MLKEM)
        zephyr_library_link_libraries(pqcp_mlkem)
    endif()
    
    if(CONFIG_PQCP_MLDSA)
        zephyr_library_link_libraries(pqcp_mldsa)
    endif()

endif()

# =============================================================================
# ACVP Command Library
# =============================================================================
if(CONFIG_PQCP_ACVP)
    zephyr_library_named(pqcp_acvp)
    
    zephyr_library_sources(${PQCP_SRC}/acvp_cmd.c)
    
    zephyr_library_link_libraries(pqcp_common)
    
    if(CONFIG_PQCP_MLKEM)
        zephyr_library_link_libraries(pqcp_mlkem)
    endif()
    
    if(CONFIG_PQCP_MLDSA)
        zephyr_library_link_libraries(pqcp_mldsa)
    endif()

    if(CONFIG_PQCP_TLS_SELFTEST)
        zephyr_library_link_libraries(pqcp_tls_selftest)
    endif()
endif()

# =============================================================================
# Benchmarking Support
# =============================================================================
if(CONFIG_PQCP_BENCH)
    zephyr_library_named(pqcp_bench)
    
    zephyr_library_sources(${PQCP_SRC}/bench_primitive.c)
    
    # Protocol benchmark is always included (simulated mode)
    # Real networking benchmarks require CONFIG_PQCP_BENCH_PROTOCOL
    if(CONFIG_PQCP_TLS_SELFTEST)
        zephyr_library_sources(${PQCP_SRC}/bench_protocol.c)
    endif()
    
    zephyr_library_link_libraries(pqcp_common)
    
    if(CONFIG_PQCP_MLKEM)
        zephyr_library_link_libraries(pqcp_mlkem)
    endif()
    
    if(CONFIG_PQCP_MLDSA)
        zephyr_library_link_libraries(pqcp_mldsa)
    endif()

    if(CONFIG_PQCP_TLS_SELFTEST)
        zephyr_library_link_libraries(pqcp_tls_selftest)
    endif()
endif()

endif() # CONFIG_PQCP
