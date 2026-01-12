#!/bin/bash
# Quick build and run script for unicity_tests

set -e

echo "========================================"
echo "Building unicity_tests"
echo "========================================"

# Go to project root
cd "$(dirname "$0")/.."

# Create build directory if needed
if [ ! -d "build" ]; then
    mkdir build
fi

cd build

# Run CMake
echo ""
echo "Running CMake..."
cmake ..

# Build tests
echo ""
echo "Building unicity_tests..."
make unicity_tests -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

# Run tests
echo ""
echo "========================================"
echo "Running tests..."
echo "========================================"
./bin/unicity_tests "$@"

echo ""
echo "========================================"
echo "Tests complete!"
echo "========================================"
