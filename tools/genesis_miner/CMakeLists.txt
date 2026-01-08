cmake_minimum_required(VERSION 3.20)

project(GenesisMinr VERSION 0.1.0 LANGUAGES CXX C)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find required packages
find_package(Threads REQUIRED)

# Fetch external dependencies
include(FetchContent)

# RandomX library from Unicity's fork
message(STATUS "Fetching RandomX from Unicity fork...")
FetchContent_Declare(
  randomx
  GIT_REPOSITORY https://github.com/unicitynetwork/RandomX.git
  GIT_TAG        origin/master
  GIT_SHALLOW    TRUE
)

# Disable RandomX tests and benchmarks
set(RANDOMX_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(RANDOMX_BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(randomx)

# Get randomx include directory
FetchContent_GetProperties(randomx)

# spdlog for logging
message(STATUS "Fetching spdlog v1.12.0...")
FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG        v1.12.0
  GIT_SHALLOW    TRUE
)

FetchContent_MakeAvailable(spdlog)

# Include directories from main project
set(UNICITY_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)
include_directories(
    ${UNICITY_ROOT}/include
    ${UNICITY_ROOT}/src
)

# Create genesis miner executable
add_executable(genesis_miner
    genesis_miner.cpp
    ${UNICITY_ROOT}/src/util/sha256.cpp
    ${UNICITY_ROOT}/src/util/uint.cpp
    ${UNICITY_ROOT}/src/util/arith_uint256.cpp
    ${UNICITY_ROOT}/src/chain/randomx_pow.cpp
    ${UNICITY_ROOT}/src/chain/block.cpp
    ${UNICITY_ROOT}/src/util/logging.cpp
)

# Add randomx include directory
if(randomx_POPULATED)
    target_include_directories(genesis_miner PRIVATE ${randomx_SOURCE_DIR}/src)
endif()

# Disable optimized SHA256 (SSE4/AVX2/SHANI) since we don't have implementation files
target_compile_definitions(genesis_miner PRIVATE DISABLE_OPTIMIZED_SHA256)

target_link_libraries(genesis_miner PRIVATE
    Threads::Threads
    randomx
    spdlog::spdlog
)

# Set output directory
set_target_properties(genesis_miner PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
