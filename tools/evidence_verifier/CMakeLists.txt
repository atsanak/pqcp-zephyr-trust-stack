# SPDX-License-Identifier: MIT
#
# Host build for pqcp-evidence-verify.
#
# Compiles the UNMODIFIED firmware replay-verifier translation units against
# a minimal printk->stdio shim. This is a plain hosted CMake project: no
# Zephyr, no west, no cross toolchain. The shim include directory must stay
# FIRST so <zephyr/sys/printk.h> resolves to the alias header.

cmake_minimum_required(VERSION 3.20.0)
project(pqcp_evidence_verifier C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(PQCP_VERIFIER_SANITIZE "Build the verifier with ASan+UBSan" OFF)
if(PQCP_VERIFIER_SANITIZE)
    set(PQCP_VERIFIER_SAN_FLAGS -fsanitize=address,undefined
                                -fno-sanitize-recover=all -g)
    add_compile_options(${PQCP_VERIFIER_SAN_FLAGS})
    add_link_options(${PQCP_VERIFIER_SAN_FLAGS})
endif()

set(PQCP_MODULE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")

# mldsa-native single-compilation-unit host build, ML-DSA-65 only. Built as
# its own library without -Werror: it is vendored upstream code compiled with
# the same MLDSA_MODE/parameter-set defines the firmware build uses.
add_library(mldsa65_host STATIC
    ${PQCP_MODULE_ROOT}/ext/mldsa-native/mldsa/mldsa_native.c
    src/host_randombytes.c
)
target_include_directories(mldsa65_host PUBLIC
    ${PQCP_MODULE_ROOT}/ext/mldsa-native
    ${PQCP_MODULE_ROOT}/ext/mldsa-native/mldsa
)
target_compile_definitions(mldsa65_host PUBLIC
    MLDSA_MODE=3
    MLD_CONFIG_PARAMETER_SET=65
)

add_executable(pqcp-evidence-verify
    src/main.c
    src/host_tokens.c
    src/passport_parse.c
    src/signature_check.c
    src/host_sha256.c
    src/receipt_mldsa_ops.c
    src/receipt_codec.c
    src/receipt_verify.c
    # Transparent appraisal receipts: the unmodified firmware RFC 9162 log,
    # proof and checkpoint code plus the host-portable CBOR codec.
    ${PQCP_MODULE_ROOT}/src/experimental/fleet/fleet_cbor_map.c
    ${PQCP_MODULE_ROOT}/src/experimental/fleet/fleet_transparency_merkle.c
    ${PQCP_MODULE_ROOT}/src/experimental/fleet/fleet_transparency_log.c
    ${PQCP_MODULE_ROOT}/src/experimental/fleet/fleet_transparency_proof.c
    ${PQCP_MODULE_ROOT}/src/experimental/fleet/fleet_transparency_checkpoint.c
    ${PQCP_MODULE_ROOT}/src/evidence/deployment_evidence_verdict_replay.c
    ${PQCP_MODULE_ROOT}/src/evidence/deployment_evidence_seal_replay.c
    ${PQCP_MODULE_ROOT}/src/evidence/deployment_assurance_passport_replay.c
    ${PQCP_MODULE_ROOT}/src/evidence/deployment_tamper_matrix_replay.c
    ${PQCP_MODULE_ROOT}/src/evidence/deployment_evidence_trail_replay.c
)

target_include_directories(pqcp-evidence-verify PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/shim
    ${PQCP_MODULE_ROOT}/include
)

target_link_libraries(pqcp-evidence-verify PRIVATE mldsa65_host)
target_compile_options(pqcp-evidence-verify PRIVATE -Wall -Wextra -Werror)

add_executable(pqcp-sovereign-signature-verify src/sovereign_signature_verify.c)
target_link_libraries(pqcp-sovereign-signature-verify PRIVATE mldsa65_host)
target_compile_options(pqcp-sovereign-signature-verify PRIVATE -Wall -Wextra -Werror)

# FIPS 180-4 known-answer test for the host SHA-256 used by the appraisal
# receipt path. Run: ctest, or build/pqcp-host-sha256-test.
add_executable(pqcp-host-sha256-test
    tests/test_host_sha256.c
    src/host_sha256.c
)
target_include_directories(pqcp-host-sha256-test PRIVATE
    ${PQCP_MODULE_ROOT}/include
)
target_compile_options(pqcp-host-sha256-test PRIVATE -Wall -Wextra -Werror)

enable_testing()
add_test(NAME host_sha256_fips180 COMMAND pqcp-host-sha256-test)
