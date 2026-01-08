# Sanitizer Usage Guide

## Overview

- **ThreadSanitizer (TSan)**: Detects data races and deadlocks
- **AddressSanitizer (ASan)**: Detects memory errors (use-after-free, buffer overflows, leaks)
- **UndefinedBehaviorSanitizer (UBSan)**: Detects undefined behavior

## Quick Start

### Testing Unit Tests

```bash
# Run all tests with ThreadSanitizer
./scripts/run_sanitizers.sh thread

# Run specific tests with AddressSanitizer
./scripts/run_sanitizers.sh address "[lifecycle]"

# Run all sanitizers
./scripts/run_sanitizers.sh all
```

### Testing Main Binary

```bash
# Test the main unicity binary with all sanitizers (10 seconds each)
./scripts/test_binary_with_sanitizers.sh

# Run for longer duration (30 seconds each)
./scripts/test_binary_with_sanitizers.sh 30
```


### Manual Usage

```bash
# Configure with sanitizer
rm -rf build && mkdir build && cd build
cmake -DSANITIZER=thread -DCMAKE_BUILD_TYPE=Debug ..

# Build
cmake --build . --target unicity_tests -j8

# Run tests
./bin/unicity_tests
```

## What Each Sanitizer Catches

### ThreadSanitizer (TSan)

**Detects:**
- Data races (concurrent access to shared memory)
- Deadlocks
- Lock order inversions


### AddressSanitizer (ASan)

**Detects:**
- Heap buffer overflow
- Stack buffer overflow
- Use-after-free
- Memory leaks
- Use-after-scope



### UndefinedBehaviorSanitizer (UBSan)

**Detects:**
- Signed integer overflow
- Division by zero
- Null pointer dereference
- Misaligned pointers
- Invalid casts

```bash
# Create tsan.supp
cat > tsan.supp << EOF
race:boost::asio::detail::*
EOF

# Run with suppression
TSAN_OPTIONS="suppressions=tsan.supp" ./bin/unicity_tests
```

### 4. Combine with Code Coverage

```bash
# Build with sanitizer AND coverage
cmake -DSANITIZER=address -DCMAKE_CXX_FLAGS="--coverage" ..
```

## Performance Impact

| Sanitizer | Slowdown | Memory Overhead |
|-----------|----------|-----------------|
| TSan      | 5-15x    | 5-10x          |
| ASan      | 2x       | 3x             |
| UBSan     | 1.5x     | Minimal        |



---

