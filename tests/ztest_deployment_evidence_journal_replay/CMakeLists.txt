# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.20.0)

set(PQCP_LOCAL_MODULE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")
include(${PQCP_LOCAL_MODULE_ROOT}/cmake/pqcp_local_module.cmake)
set(EXTRA_CONF_FILE
  "${CMAKE_CURRENT_LIST_DIR}/../common/deployment_evidence_test.conf"
)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pqcp_ztest_deployment_evidence_journal_replay)

target_sources(app PRIVATE
  src/main.c
  ../common/deployment_evidence_archive_fixture.c
)
target_include_directories(app PRIVATE ../common)
