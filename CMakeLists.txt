cmake_minimum_required(VERSION 3.20)

# Use modern Boost config mode (CMake 3.30+ removes FindBoost module)
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

project(Unicity VERSION 1.0.0 LANGUAGES CXX C)

# =============================================================================
# Platform Requirements
# =============================================================================
# Unicity requires __int128 support for ASERT difficulty algorithm (Bitcoin Cash pattern)
# Supported platforms: Linux, macOS (GCC/Clang)
# NOT supported: Windows/MSVC

if(MSVC OR WIN32)
    message(FATAL_ERROR "Windows/MSVC is not supported. Unicity requires __int128 support (GCC/Clang on Linux/macOS).")
endif()

if(NOT CMAKE_SYSTEM_NAME MATCHES "Linux|Darwin")
    message(WARNING "Unicity is tested on Linux and macOS only. Other Unix-like systems may work but are not officially supported.")
endif()

# =============================================================================
# Build Configuration
# =============================================================================

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Default to Release build
if(NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "")
    set(CMAKE_BUILD_TYPE "Release")
endif()

# Keep assert() active in all build types (matches Bitcoin Core).
# Asserts guard consensus-critical invariants like genesis hash checks.
string(REPLACE "-DNDEBUG" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
string(REPLACE "-DNDEBUG" "" CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")

option(BUILD_TESTING "Build tests" ON)

# =============================================================================
# Sanitizer Support
# =============================================================================
# Usage:
#   cmake -DSANITIZER=thread ..    # ThreadSanitizer (data races)
#   cmake -DSANITIZER=address ..   # AddressSanitizer (memory errors)
#   cmake -DSANITIZER=undefined .. # UndefinedBehaviorSanitizer
#
set(SANITIZER "" CACHE STRING "Enable sanitizer (thread, address, undefined)")

if(SANITIZER)
    message(STATUS "Building with ${SANITIZER} sanitizer")

    if(SANITIZER STREQUAL "thread")
        set(SANITIZER_FLAGS "-fsanitize=thread -g -O1")
        set(SANITIZER_NAME "ThreadSanitizer")
    elseif(SANITIZER STREQUAL "address")
        set(SANITIZER_FLAGS "-fsanitize=address -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1")
        set(SANITIZER_NAME "AddressSanitizer")
    elseif(SANITIZER STREQUAL "undefined")
        set(SANITIZER_FLAGS "-fsanitize=undefined -fno-omit-frame-pointer -g -O1")
        set(SANITIZER_NAME "UndefinedBehaviorSanitizer")
    else()
        message(FATAL_ERROR "Unknown sanitizer: ${SANITIZER}")
    endif()

    message(STATUS "${SANITIZER_NAME} flags: ${SANITIZER_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SANITIZER_FLAGS}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SANITIZER_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${SANITIZER_FLAGS}")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${SANITIZER_FLAGS}")
endif()

# =============================================================================
# Code Coverage Support
# =============================================================================
# Usage:
#   cmake -DCODE_COVERAGE=ON -DCMAKE_BUILD_TYPE=Debug ..
#   make
#   make coverage        # Run tests and generate HTML report
#   open coverage/index.html
#
option(CODE_COVERAGE "Enable code coverage (requires lcov/gcov)" OFF)

if(CODE_COVERAGE)
    if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
        message(WARNING "Code coverage requires Debug build for accurate results")
    endif()

    # Include the coverage module
    include(cmake/3rdparty/CodeCoverage.cmake)
    append_coverage_compiler_flags()

    # Setup coverage target
    setup_target_for_coverage_lcov(
        NAME coverage
        EXECUTABLE unicity_tests
        BASE_DIRECTORY "${PROJECT_SOURCE_DIR}"
        EXCLUDE
            "${PROJECT_SOURCE_DIR}/test/*"
            "${PROJECT_SOURCE_DIR}/build/*"
            "${PROJECT_SOURCE_DIR}/build-coverage/*"
            "${PROJECT_SOURCE_DIR}/fuzz/*"
            "${PROJECT_SOURCE_DIR}/_deps/*"
            "/usr/*"
            "/opt/*"
            "*/catch_amalgamated.*"
            "*/nlohmann/*"
            "*/asio/*"
            "*/spdlog/*"
            "*/fmt/*"
            "*/_deps/*"
        LCOV_ARGS --ignore-errors source --ignore-errors unsupported --ignore-errors inconsistent --ignore-errors gcov --ignore-errors format --ignore-errors count --ignore-errors unused
        GENHTML_ARGS --ignore-errors inconsistent --ignore-errors corrupt --ignore-errors category
    )

    message(STATUS "Code coverage enabled - use 'make coverage' after building")
endif()

# Static analysis with cppcheck
option(ENABLE_CPPCHECK "Enable cppcheck static analysis target" ON)
if(ENABLE_CPPCHECK)
    include(cmake/cppcheck.cmake)
endif()

# =============================================================================
# Find System Dependencies
# =============================================================================

find_package(Threads REQUIRED)

# =============================================================================
# Fetch External Dependencies
# =============================================================================

include(FetchContent)

# Standalone Asio (header-only, no Boost dependency)
FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG        asio-1-30-2
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(asio)

# Create interface target for Asio
add_library(asio INTERFACE)
target_include_directories(asio INTERFACE ${asio_SOURCE_DIR}/asio/include)
target_compile_definitions(asio INTERFACE ASIO_STANDALONE)

# RandomX - ASIC-resistant proof-of-work
FetchContent_Declare(
    randomx
    GIT_REPOSITORY https://github.com/unicitynetwork/RandomX.git
    GIT_TAG        origin/master
    GIT_SHALLOW    TRUE
)
set(RANDOMX_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(RANDOMX_BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(randomx)

# fmt - Fast formatting library
FetchContent_Declare(
    fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG        10.2.1
    GIT_SHALLOW    TRUE
)

# Disable consteval in fmt when using OSS-Fuzz (strict clang)
# This prevents "call to consteval function is not a constant expression" errors
if(DEFINED ENV{LIB_FUZZING_ENGINE})
    set(FMT_CONSTEVAL "" CACHE STRING "Disable consteval for OSS-Fuzz" FORCE)
endif()

FetchContent_MakeAvailable(fmt)

# Apply compile definitions to fmt target
if(TARGET fmt)
    target_compile_definitions(fmt PUBLIC FMT_CONSTEVAL=)
endif()

# spdlog - Logging library (uses external fmt)
set(SPDLOG_USE_STD_FORMAT OFF CACHE BOOL "" FORCE)
set(SPDLOG_FMT_EXTERNAL ON CACHE BOOL "" FORCE)
FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG        v1.12.0
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(spdlog)

# nlohmann/json - JSON for Modern C++
FetchContent_Declare(
    json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(json)

# miniupnpc - UPnP NAT traversal
FetchContent_Declare(
    miniupnpc
    GIT_REPOSITORY https://github.com/miniupnp/miniupnp.git
    GIT_TAG        miniupnpc_2_2_5
    GIT_SHALLOW    TRUE
    SOURCE_SUBDIR  miniupnpc
)
set(UPNPC_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(UPNPC_BUILD_SAMPLE OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(miniupnpc)

# miniupnpc exports headers at include/*.h but we include as <miniupnpc/*.h>
# Copy headers so we can #include <miniupnpc/miniupnpc.h>
set(MINIUPNPC_WRAPPER_DIR ${CMAKE_BINARY_DIR}/miniupnpc_wrapper)
file(MAKE_DIRECTORY ${MINIUPNPC_WRAPPER_DIR})
file(COPY ${miniupnpc_SOURCE_DIR}/miniupnpc/include/ DESTINATION ${MINIUPNPC_WRAPPER_DIR}/miniupnpc)

# =============================================================================
# Core Libraries
# =============================================================================

# Util Library - General utilities (crypto, logging, time, network address validation, string parsing)
add_library(util STATIC
    src/util/files.cpp
    src/util/fs_lock.cpp
    src/util/logging.cpp
    src/util/rate_limiter.cpp
    src/util/siphash.cpp
    src/util/time.cpp
    src/util/sha256.cpp
    src/util/uint.cpp
    src/util/arith_uint256.cpp
    src/util/netaddress.cpp
    src/util/string_parsing.cpp
    src/util/ntp.cpp
)

target_include_directories(util PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_definitions(util PRIVATE DISABLE_OPTIMIZED_SHA256)
target_link_libraries(util PUBLIC spdlog::spdlog asio)

# Chain Library - Blockchain logic (consensus, validation, mining)
add_library(chain STATIC
    src/chain/randomx_pow.cpp
    src/chain/block.cpp
    src/chain/pow.cpp
    src/chain/notifications.cpp
    src/chain/block_index.cpp
    src/chain/chain.cpp
    src/chain/block_manager.cpp
    src/chain/chainparams.cpp
    src/chain/validation.cpp
    src/chain/chainstate_manager.cpp
    src/chain/timedata.cpp
    src/chain/miner.cpp
)

target_include_directories(chain PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

FetchContent_GetProperties(randomx)
if(randomx_POPULATED)
    target_include_directories(chain PUBLIC ${randomx_SOURCE_DIR}/src)
endif()

target_link_libraries(chain PUBLIC
    util
    randomx
    nlohmann_json::nlohmann_json
)

# Network Library - P2P networking and RPC
add_library(network STATIC
    src/network/protocol.cpp
    src/network/connection_types.cpp
    src/network/message.cpp
    src/network/peer.cpp
    src/network/addr_manager.cpp
    src/network/ban_manager.cpp
    src/network/misbehavior_manager.cpp
    src/network/connection_manager.cpp
    src/network/eviction_manager.cpp
    src/network/anchor_manager.cpp
    src/network/header_sync_manager.cpp
    src/network/message_dispatcher.cpp
    src/network/addr_relay_manager.cpp
    src/network/network_manager.cpp
    src/network/real_transport.cpp
    src/network/nat_manager.cpp
    src/network/rpc_server.cpp
    src/network/rpc_client.cpp
)

target_include_directories(network PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/miniupnpc_wrapper
)

target_link_libraries(network PUBLIC
    chain
    asio
    nlohmann_json::nlohmann_json
    libminiupnpc-static
)

# =============================================================================
# Executables
# =============================================================================

# Main node executable
add_executable(unicityd
    src/main.cpp
    src/application.cpp
)

target_include_directories(unicityd PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(unicityd PRIVATE
    Threads::Threads
    asio
    network
)

set_target_properties(unicityd PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# CLI tool
add_executable(unicity-cli src/cli.cpp)

target_include_directories(unicity-cli PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(unicity-cli PRIVATE network)

set_target_properties(unicity-cli PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# =============================================================================
# Fuzzing Targets (libFuzzer or standalone)
# =============================================================================

option(ENABLE_FUZZING "Build fuzz targets with libFuzzer" OFF)

if(ENABLE_FUZZING)
    message(STATUS "Fuzzing enabled - building fuzz targets")

    # Check if we're in OSS-Fuzz environment
    if(DEFINED ENV{LIB_FUZZING_ENGINE})
        # OSS-Fuzz provides LIB_FUZZING_ENGINE
        set(FUZZING_ENGINE $ENV{LIB_FUZZING_ENGINE})
        message(STATUS "Using OSS-Fuzz fuzzing engine")
    else()
        # Check if libFuzzer is available (requires link test, not just compile)
        include(CheckCXXSourceCompiles)
        set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer")

        # On macOS with Homebrew LLVM, add libc++ path
        if(APPLE AND CMAKE_CXX_COMPILER MATCHES "homebrew")
            set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -L/opt/homebrew/opt/llvm/lib/c++ -Wl,-rpath,/opt/homebrew/opt/llvm/lib/c++")
        endif()

        check_cxx_source_compiles("
            #include <cstdint>
            #include <cstddef>
            extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
                return 0;
            }
        " HAS_LIBFUZZER)

        if(HAS_LIBFUZZER)
            set(FUZZING_ENGINE "-fsanitize=fuzzer")

            # On macOS with Homebrew LLVM, we need to use Homebrew's libc++
            if(APPLE AND CMAKE_CXX_COMPILER MATCHES "homebrew")
                set(FUZZING_ENGINE "${FUZZING_ENGINE} -L/opt/homebrew/opt/llvm/lib/c++ -Wl,-rpath,/opt/homebrew/opt/llvm/lib/c++")
            endif()

            message(STATUS "Using libFuzzer")
        else()
            # Fallback: provide standalone fuzz driver (for testing structure)
            message(WARNING "libFuzzer not available. Fuzz targets will use standalone driver.")
            message(WARNING "Install llvm/clang with fuzzer support for actual fuzzing.")
            set(FUZZING_ENGINE "")
            add_definitions(-DSTANDALONE_FUZZ_TARGET_DRIVER)
        endif()

        # Clear CMAKE_REQUIRED_FLAGS
        set(CMAKE_REQUIRED_FLAGS "")
    endif()

    # Common function to create fuzz target
    function(add_fuzz_target target_name source_file)
        # If using standalone driver, add it to sources
        if(NOT HAS_LIBFUZZER AND NOT DEFINED ENV{LIB_FUZZING_ENGINE})
            add_executable(${target_name}
                ${source_file}
                ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/standalone_fuzz_driver.cpp
            )
        else()
            add_executable(${target_name} ${source_file})
        endif()

        target_include_directories(${target_name} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/src
        )

        target_link_libraries(${target_name} PRIVATE
            chain
            network
        )

        # Add fuzzing engine (if available)
        if(FUZZING_ENGINE)
            target_link_libraries(${target_name} PRIVATE ${FUZZING_ENGINE})
        endif()

        # Optimization flags for fuzzing
        # O2 helps avoid consteval issues with spdlog on newer compilers
        target_compile_options(${target_name} PRIVATE -O2 -g)

        set_target_properties(${target_name} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/fuzz
        )
    endfunction()

    # Create fuzz targets
    add_fuzz_target(fuzz_asert_difficulty fuzz/fuzz_asert_difficulty.cpp)
    add_fuzz_target(fuzz_randomx_pow fuzz/fuzz_randomx_pow.cpp)
    add_fuzz_target(fuzz_netaddr_parsing fuzz/fuzz_netaddr_parsing.cpp)
    add_fuzz_target(fuzz_header_validation fuzz/fuzz_header_validation.cpp)
    add_fuzz_target(fuzz_block_locator fuzz/fuzz_block_locator.cpp)
    add_fuzz_target(fuzz_block_header fuzz/fuzz_block_header.cpp)
    add_fuzz_target(fuzz_varint fuzz/fuzz_varint.cpp)
    add_fuzz_target(fuzz_messages fuzz/fuzz_messages.cpp)
    add_fuzz_target(fuzz_message_header fuzz/fuzz_message_header.cpp)
    add_fuzz_target(fuzz_chain_reorg fuzz/fuzz_chain_reorg.cpp)
    add_fuzz_target(fuzz_atomic_write fuzz/fuzz_atomic_write.cpp)
    add_fuzz_target(fuzz_read_file fuzz/fuzz_read_file.cpp)
    add_fuzz_target(fuzz_lock_directory fuzz/fuzz_lock_directory.cpp)

    message(STATUS "Fuzz targets will be built in: ${CMAKE_BINARY_DIR}/fuzz")
endif()

# =============================================================================
# Subdirectories
# =============================================================================

if(BUILD_TESTING)
    add_subdirectory(test)
endif()
add_subdirectory(tools/genesis_miner)
