# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.20.0)

set(PQCP_LOCAL_MODULE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")
include(${PQCP_LOCAL_MODULE_ROOT}/cmake/pqcp_local_module.cmake)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pqcp_ztest_ct_trace_mldsa)

# Turn mldsa-native's upstream declassification annotations into trace events:
# the shim <valgrind/memcheck.h> routes VALGRIND_MAKE_MEM_DEFINED to
# pqcp_ct_declassify() below. The library itself is not modified.
zephyr_include_directories(${CMAKE_CURRENT_LIST_DIR}/shim)
zephyr_compile_definitions(MLD_CONFIG_CT_TESTING_ENABLED)

target_sources(app PRIVATE src/main.c)
# Keep the markers un-inlined so the TCG plugin can hook their guest addresses.
target_compile_options(app PRIVATE -fno-inline)
