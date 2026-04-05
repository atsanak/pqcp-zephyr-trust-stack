# SPDX-License-Identifier: Apache-2.0
# PQCP Zephyr Trust Stack - CMake Build Configuration
#
# This module provides ML-KEM (FIPS-203) and ML-DSA (FIPS-204) implementations
# using the PQ Code Package's mlkem-native and mldsa-native libraries.

cmake_minimum_required(VERSION 3.20.0)

# Module registration for west
if(CONFIG_PQCP)

# =============================================================================
# Module Paths
# =============================================================================
set(PQCP_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(PQCP_INC ${PQCP_DIR}/include)
set(PQCP_SRC ${PQCP_DIR}/src)
set(PQCP_EXT ${PQCP_DIR}/ext)

# External library paths (submodules or FetchContent)
set(MLKEM_NATIVE_DIR ${PQCP_EXT}/mlkem-native)
set(MLDSA_NATIVE_DIR ${PQCP_EXT}/mldsa-native)

# =============================================================================
# Include Paths
# =============================================================================
zephyr_include_directories(${PQCP_INC})

# =============================================================================
# Common Sources
# =============================================================================
zephyr_library_named(pqcp_common)

# RNG abstraction
if(CONFIG_PQCP_RNG_ZEPHYR_ENTROPY)
    zephyr_library_sources(${PQCP_SRC}/rng_zephyr_entropy.c)
elseif(CONFIG_PQCP_RNG_PSA)
    zephyr_library_sources(${PQCP_SRC}/rng_psa.c)
elseif(CONFIG_PQCP_RNG_CUSTOM)
    zephyr_library_sources(${PQCP_SRC}/rng_custom.c)
endif()

# Deterministic RNG for testing
if(CONFIG_PQCP_RNG_DETERMINISTIC_TEST)
    zephyr_library_sources(${PQCP_SRC}/rng_deterministic.c)
endif()

# Common RNG interface
zephyr_library_sources(${PQCP_SRC}/rng_common.c)

# =============================================================================
# ML-KEM Library
# =============================================================================
if(CONFIG_PQCP_MLKEM)
    zephyr_library_named(pqcp_mlkem)
    
    # Check for mlkem-native availability
    if(EXISTS ${MLKEM_NATIVE_DIR}/mlkem)
        zephyr_include_directories(${MLKEM_NATIVE_DIR})
        zephyr_include_directories(${MLKEM_NATIVE_DIR}/mlkem)
        zephyr_include_directories(${MLKEM_NATIVE_DIR}/mlkem/src)
        
        # Determine security level to build
        if(CONFIG_PQCP_MLKEM_LEVEL_512)
            set(MLKEM_K 2)
        elseif(CONFIG_PQCP_MLKEM_LEVEL_768)
            set(MLKEM_K 3)
        elseif(CONFIG_PQCP_MLKEM_LEVEL_1024)
            set(MLKEM_K 4)
        else()
            # Default to ML-KEM-768
            set(MLKEM_K 3)
        endif()
        
        zephyr_compile_definitions(MLKEM_K=${MLKEM_K})
        
        # Backend selection
        if(CONFIG_PQCP_BACKEND_FORCE_C)
            zephyr_compile_definitions(MLKEM_USE_NATIVE=0)
        elseif(CONFIG_PQCP_BACKEND_FORCE_NATIVE)
            zephyr_compile_definitions(MLKEM_USE_NATIVE=1)
        endif()
        
        # Reduced RAM mode
        if(CONFIG_PQCP_REDUCE_RAM)
            zephyr_compile_definitions(MLKEM_USE_REDUCE_RAM=1)
        endif()
        
        # Core mlkem-native sources
        # Note: In a real build, these would be the actual mlkem-native source files
        # For now, we compile our wrapper which calls the library
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
        zephyr_include_directories(${MLDSA_NATIVE_DIR})
        zephyr_include_directories(${MLDSA_NATIVE_DIR}/mldsa)
        zephyr_include_directories(${MLDSA_NATIVE_DIR}/mldsa/src)
        
        # Determine security level
        if(CONFIG_PQCP_MLDSA_LEVEL_44)
            set(MLDSA_MODE 2)
        elseif(CONFIG_PQCP_MLDSA_LEVEL_65)
            set(MLDSA_MODE 3)
        elseif(CONFIG_PQCP_MLDSA_LEVEL_87)
            set(MLDSA_MODE 5)
        else()
            # Default to ML-DSA-65
            set(MLDSA_MODE 3)
        endif()
        
        zephyr_compile_definitions(MLDSA_MODE=${MLDSA_MODE})
        
        # Backend selection
        if(CONFIG_PQCP_BACKEND_FORCE_C)
            zephyr_compile_definitions(MLDSA_USE_NATIVE=0)
        elseif(CONFIG_PQCP_BACKEND_FORCE_NATIVE)
            zephyr_compile_definitions(MLDSA_USE_NATIVE=1)
        endif()
        
        # Reduced RAM mode
        if(CONFIG_PQCP_REDUCE_RAM)
            zephyr_compile_definitions(MLDSA_USE_REDUCE_RAM=1)
        endif()
        
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
# Benchmarking Support
# =============================================================================
if(CONFIG_PQCP_BENCH)
    zephyr_library_named(pqcp_bench)
    
    zephyr_library_sources(${PQCP_SRC}/bench_primitive.c)
    
    if(CONFIG_PQCP_BENCH_PROTOCOL)
        zephyr_library_sources(${PQCP_SRC}/bench_protocol.c)
    endif()
    
    zephyr_library_link_libraries(pqcp_common)
    
    if(CONFIG_PQCP_MLKEM)
        zephyr_library_link_libraries(pqcp_mlkem)
    endif()
    
    if(CONFIG_PQCP_MLDSA)
        zephyr_library_link_libraries(pqcp_mldsa)
    endif()
endif()

endif() # CONFIG_PQCP
