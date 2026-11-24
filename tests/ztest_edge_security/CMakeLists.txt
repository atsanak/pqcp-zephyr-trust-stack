# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.20.0)

set(PQCP_LOCAL_MODULE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")
include(${PQCP_LOCAL_MODULE_ROOT}/cmake/pqcp_local_module.cmake)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ztest_edge_security)

target_include_directories(app PRIVATE
    ${PQCP_LOCAL_MODULE_ROOT}/src/internal
    ${CMAKE_CURRENT_LIST_DIR}/src)
target_sources(app PRIVATE
    src/main.c
    src/test_identity.c
    src/test_messaging.c
    src/test_vault.c
    src/test_incident.c
    src/test_governance.c
    src/test_runtime.c)
