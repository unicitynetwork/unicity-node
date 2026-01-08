#!/bin/bash
# Quick build and run script for test2

set -e

echo "========================================"
echo "Building test2 with improved framework"
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

# Build test2
echo ""
echo "Building unicity_tests2..."
make unicity_tests2 -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

# Run tests
echo ""
echo "========================================"
echo "Running tests..."
echo "========================================"
./unicity_tests2 "$@"

echo ""
echo "========================================"
echo "Tests complete!"
echo "========================================"
