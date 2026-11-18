# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation

cmake_minimum_required(VERSION 3.20.0)

set(PQCP_LOCAL_MODULE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")
include(${PQCP_LOCAL_MODULE_ROOT}/cmake/pqcp_local_module.cmake)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ztest_edge_model)

# test_common.h (principal/digest fixtures, T0, CAP_ALL) is shared with the
# edge security suite, so the two suites move together.
target_include_directories(app PRIVATE
    ${PQCP_LOCAL_MODULE_ROOT}/src
    ${PQCP_LOCAL_MODULE_ROOT}/tests/ztest_edge_security/src
    ${CMAKE_CURRENT_LIST_DIR}/src)
target_sources(app PRIVATE
    src/main.c
    src/model_harness.c
    src/test_harness.c)
