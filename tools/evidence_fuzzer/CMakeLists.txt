# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
#
# Host build for pqcp-evidence-fuzz.
#
# Compiles the UNMODIFIED firmware replay-verifier parsers plus the host
# passport/signature adapters under ASan+UBSan with no-recover semantics:
# any memory error or undefined behavior aborts the process, so a clean
# exit is the fuzzing verdict. Sanitizers can be disabled for debugging
# with -DPQCP_FUZZ_SANITIZE=OFF.

cmake_minimum_required(VERSION 3.20.0)
project(pqcp_evidence_fuzzer C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(PQCP_FUZZ_SANITIZE "Build the fuzzer with ASan+UBSan" ON)

set(PQCP_MODULE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")
set(PQCP_VERIFIER_DIR "${CMAKE_CURRENT_LIST_DIR}/../evidence_verifier")

add_library(mldsa65_fuzz STATIC
    ${PQCP_MODULE_ROOT}/ext/mldsa-native/mldsa/mldsa_native.c
    ${PQCP_VERIFIER_DIR}/src/host_randombytes.c
)
target_include_directories(mldsa65_fuzz PUBLIC
    ${PQCP_MODULE_ROOT}/ext/mldsa-native
    ${PQCP_MODULE_ROOT}/ext/mldsa-native/mldsa
)
target_compile_definitions(mldsa65_fuzz PUBLIC
    MLDSA_MODE=3
    MLD_CONFIG_PARAMETER_SET=65
)

# Edge-coverage instrumentation goes on the TARGET parsers only, so
# coverage pressure (and corpus evolution) tracks the code under test, not
# the harness or the crypto backend.
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(PQCP_FUZZ_COV_FLAG -fsanitize-coverage=trace-pc-guard)
else()
    set(PQCP_FUZZ_COV_FLAG -fsanitize-coverage=trace-pc)
endif()

add_library(fuzz_targets OBJECT
    ${PQCP_VERIFIER_DIR}/src/host_tokens.c
    ${PQCP_VERIFIER_DIR}/src/passport_parse.c
    ${PQCP_VERIFIER_DIR}/src/signature_check.c
    ${PQCP_MODULE_ROOT}/src/deployment_evidence_verdict_replay.c
    ${PQCP_MODULE_ROOT}/src/deployment_evidence_seal_replay.c
)
target_include_directories(fuzz_targets PRIVATE
    ${PQCP_VERIFIER_DIR}/shim
    ${PQCP_VERIFIER_DIR}/src
    ${PQCP_MODULE_ROOT}/include
)
target_link_libraries(fuzz_targets PRIVATE mldsa65_fuzz)
target_compile_options(fuzz_targets PRIVATE -Wall -Wextra -Werror
                       ${PQCP_FUZZ_COV_FLAG})

add_executable(pqcp-evidence-fuzz
    src/main.c
    $<TARGET_OBJECTS:fuzz_targets>
)

target_include_directories(pqcp-evidence-fuzz PRIVATE
    ${PQCP_VERIFIER_DIR}/shim
    ${PQCP_VERIFIER_DIR}/src
    ${PQCP_MODULE_ROOT}/include
)

target_link_libraries(pqcp-evidence-fuzz PRIVATE mldsa65_fuzz)
target_compile_options(pqcp-evidence-fuzz PRIVATE -Wall -Wextra -Werror)

if(PQCP_FUZZ_SANITIZE)
    set(PQCP_FUZZ_SAN_FLAGS -fsanitize=address,undefined
                            -fno-sanitize-recover=all -g)
    target_compile_options(pqcp-evidence-fuzz PRIVATE ${PQCP_FUZZ_SAN_FLAGS})
    target_link_options(pqcp-evidence-fuzz PRIVATE ${PQCP_FUZZ_SAN_FLAGS})
    target_compile_options(fuzz_targets PRIVATE ${PQCP_FUZZ_SAN_FLAGS})
    target_compile_options(mldsa65_fuzz PRIVATE ${PQCP_FUZZ_SAN_FLAGS})
    target_link_options(mldsa65_fuzz PRIVATE ${PQCP_FUZZ_SAN_FLAGS})
endif()
