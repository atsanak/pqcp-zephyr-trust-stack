# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
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
    src/signature_check.c
    ${PQCP_MODULE_ROOT}/src/deployment_evidence_verdict_replay.c
    ${PQCP_MODULE_ROOT}/src/deployment_evidence_seal_replay.c
    ${PQCP_MODULE_ROOT}/src/deployment_assurance_passport_replay.c
)

target_include_directories(pqcp-evidence-verify PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/shim
    ${PQCP_MODULE_ROOT}/include
)

target_link_libraries(pqcp-evidence-verify PRIVATE mldsa65_host)
target_compile_options(pqcp-evidence-verify PRIVATE -Wall -Wextra -Werror)
