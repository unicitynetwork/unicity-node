# cppcheck static analysis integration
#
# Usage:
#   cmake -B build -DENABLE_CPPCHECK=ON
#   cmake --build build --target cppcheck
#
# Or run manually:
#   cppcheck --project=build/compile_commands.json

find_program(CPPCHECK_BIN cppcheck)

if(NOT CPPCHECK_BIN)
  message(STATUS "cppcheck not found - target disabled")
  return()
endif()

message(STATUS "cppcheck found: ${CPPCHECK_BIN}")

# Get cppcheck version
execute_process(
  COMMAND ${CPPCHECK_BIN} --version
  OUTPUT_VARIABLE CPPCHECK_VERSION
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
message(STATUS "cppcheck version: ${CPPCHECK_VERSION}")

# Collect source files (production code only)
file(GLOB_RECURSE CPPCHECK_SOURCES
  ${PROJECT_SOURCE_DIR}/src/*.cpp
  ${PROJECT_SOURCE_DIR}/src/*.hpp
  ${PROJECT_SOURCE_DIR}/include/*.hpp
  ${PROJECT_SOURCE_DIR}/include/*.h
)

# Suppressions file
set(CPPCHECK_SUPPRESSIONS_FILE "${PROJECT_SOURCE_DIR}/.cppcheck-suppressions")

# Build cppcheck arguments
set(CPPCHECK_ARGS
  --enable=warning,style,performance,portability
  --std=c++20
  --inline-suppr
  --suppress=missingIncludeSystem
  --suppress=normalCheckLevelMaxBranches
  -I ${PROJECT_SOURCE_DIR}/include
)

# Add suppressions file if it exists
if(EXISTS ${CPPCHECK_SUPPRESSIONS_FILE})
  list(APPEND CPPCHECK_ARGS --suppressions-list=${CPPCHECK_SUPPRESSIONS_FILE})
endif()

# Create cppcheck target
add_custom_target(cppcheck
  COMMAND ${CPPCHECK_BIN}
    ${CPPCHECK_ARGS}
    ${PROJECT_SOURCE_DIR}/src
  COMMENT "Running cppcheck static analysis..."
  VERBATIM
)

# Create cppcheck-xml target for CI integration
add_custom_target(cppcheck-xml
  COMMAND ${CPPCHECK_BIN}
    ${CPPCHECK_ARGS}
    --xml
    --output-file=${CMAKE_BINARY_DIR}/cppcheck-report.xml
    ${PROJECT_SOURCE_DIR}/src
  COMMENT "Running cppcheck with XML output..."
  VERBATIM
)

# Option to run cppcheck during build (slower)
option(CPPCHECK_ON_BUILD "Run cppcheck on every build" OFF)
if(CPPCHECK_ON_BUILD)
  set(CMAKE_CXX_CPPCHECK ${CPPCHECK_BIN} ${CPPCHECK_ARGS})
endif()
