# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
#
# Host build for pqcp-evidence-register: the append-only appraisal log tool.
#
# Reuses the verifier's host SHA-256 / ML-DSA / CBOR codec sources and the
# UNMODIFIED firmware RFC 9162 transparency code. Deterministic and seed-file
# driven: the linked randombytes stub aborts if anything ever reaches it.
# Sanitizers: -DPQCP_REGISTER_SANITIZE=ON builds with ASan+UBSan.

cmake_minimum_required(VERSION 3.20.0)
project(pqcp_evidence_register C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(PQCP_REGISTER_SANITIZE "Build with ASan+UBSan" OFF)

set(PQCP_MODULE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")
set(PQCP_VERIFIER_DIR "${CMAKE_CURRENT_LIST_DIR}/../evidence_verifier")

add_library(mldsa65_register STATIC
    ${PQCP_MODULE_ROOT}/ext/mldsa-native/mldsa/mldsa_native.c
    ${PQCP_VERIFIER_DIR}/src/host_randombytes.c
)
target_include_directories(mldsa65_register PUBLIC
    ${PQCP_MODULE_ROOT}/ext/mldsa-native
    ${PQCP_MODULE_ROOT}/ext/mldsa-native/mldsa
)
target_compile_definitions(mldsa65_register PUBLIC
    MLDSA_MODE=3
    MLD_CONFIG_PARAMETER_SET=65
)

add_executable(pqcp-evidence-register
    src/main.c
    ${PQCP_VERIFIER_DIR}/src/host_sha256.c
    ${PQCP_VERIFIER_DIR}/src/receipt_mldsa_ops.c
    ${PQCP_VERIFIER_DIR}/src/receipt_codec.c
    ${PQCP_MODULE_ROOT}/src/fleet_cbor_map.c
    ${PQCP_MODULE_ROOT}/src/fleet_transparency_merkle.c
    ${PQCP_MODULE_ROOT}/src/fleet_transparency_log.c
    ${PQCP_MODULE_ROOT}/src/fleet_transparency_proof.c
    ${PQCP_MODULE_ROOT}/src/fleet_transparency_checkpoint.c
)
target_include_directories(pqcp-evidence-register PRIVATE
    ${PQCP_VERIFIER_DIR}/src
    ${PQCP_MODULE_ROOT}/include
)
target_link_libraries(pqcp-evidence-register PRIVATE mldsa65_register)
target_compile_options(pqcp-evidence-register PRIVATE -Wall -Wextra -Werror)

if(PQCP_REGISTER_SANITIZE)
    set(PQCP_REGISTER_SAN_FLAGS -fsanitize=address,undefined
                                -fno-sanitize-recover=all -g)
    target_compile_options(pqcp-evidence-register PRIVATE
                           ${PQCP_REGISTER_SAN_FLAGS})
    target_link_options(pqcp-evidence-register PRIVATE
                        ${PQCP_REGISTER_SAN_FLAGS})
    target_compile_options(mldsa65_register PRIVATE
                           ${PQCP_REGISTER_SAN_FLAGS})
    target_link_options(mldsa65_register PRIVATE ${PQCP_REGISTER_SAN_FLAGS})
endif()
