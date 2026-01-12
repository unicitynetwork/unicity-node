# Sanitizer Usage Guide

## Overview

- **AddressSanitizer (ASan)**: Detects memory errors (use-after-free, buffer overflows, leaks)
- **ThreadSanitizer (TSan)**: Detects data races and deadlocks
- **UndefinedBehaviorSanitizer (UBSan)**: Detects undefined behavior

## Quick Start

```bash
# Build with AddressSanitizer
cmake -B build -DSANITIZER=address -DCMAKE_BUILD_TYPE=Debug
cmake --build build

# Run tests
./build/bin/unicity_tests

# Build with ThreadSanitizer
cmake -B build -DSANITIZER=thread -DCMAKE_BUILD_TYPE=Debug
cmake --build build
./build/bin/unicity_tests

# Build with UndefinedBehaviorSanitizer
cmake -B build -DSANITIZER=undefined -DCMAKE_BUILD_TYPE=Debug
cmake --build build
./build/bin/unicity_tests
```

## What Each Sanitizer Catches

### AddressSanitizer (ASan)

- Heap buffer overflow
- Stack buffer overflow
- Use-after-free
- Memory leaks
- Use-after-scope

### ThreadSanitizer (TSan)

- Data races (concurrent access to shared memory)
- Deadlocks
- Lock order inversions

### UndefinedBehaviorSanitizer (UBSan)

- Signed integer overflow
- Division by zero
- Null pointer dereference
- Misaligned pointers
- Invalid casts

## Suppressions

For known false positives (e.g., in third-party libraries):

```bash
# Create tsan.supp
cat > tsan.supp << EOF
race:boost::asio::detail::*
EOF

# Run with suppression
TSAN_OPTIONS="suppressions=tsan.supp" ./build/bin/unicity_tests
```

## Combining with Coverage

```bash
cmake -B build -DSANITIZER=address -DCOVERAGE=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build
./build/bin/unicity_tests
gcovr --html-details coverage.html
```

## Performance Impact

| Sanitizer | Slowdown | Memory Overhead |
|-----------|----------|-----------------|
| ASan      | 2x       | 3x             |
| TSan      | 5-15x    | 5-10x          |
| UBSan     | 1.5x     | Minimal        |

## CI Integration

Sanitizers are run automatically in CI. To run locally before pushing:

```bash
# Clean build with each sanitizer
for san in address thread undefined; do
  rm -rf build
  cmake -B build -DSANITIZER=$san -DCMAKE_BUILD_TYPE=Debug
  cmake --build build
  ./build/bin/unicity_tests || echo "FAILED: $san"
done
```
