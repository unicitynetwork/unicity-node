# Contributing to unicity-node

Thank you for your interest in contributing to the Unicity Node! This document covers
how to get your development environment set up, the coding standards we follow, and
the process for submitting changes.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Commit Messages](#commit-messages)
- [Review Process](#review-process)

---

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone git@github.com:<your-username>/unicity-node.git
   cd unicity-node
   ```
3. **Add upstream** remote:
   ```bash
   git remote add upstream https://github.com/unicitynetwork/unicity-node.git
   ```

---

## Development Setup

### Prerequisites

- C++20-capable compiler: **Clang 18+** (recommended) or **GCC 11+**
- **CMake 3.20+**
- **Boost** (system, filesystem)
- **libminiupnpc**
- **Python 3.9+** (for functional tests)

### Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(nproc)
```

### Build with Sanitizers

```bash
# AddressSanitizer
cmake -B build -DSANITIZER=address -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j$(nproc)

# ThreadSanitizer
cmake -B build -DSANITIZER=thread -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j$(nproc)

# UndefinedBehaviorSanitizer
cmake -B build -DSANITIZER=undefined -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j$(nproc)
```

---

## Coding Standards

- **C++20** throughout; use modern idioms (ranges, concepts, structured bindings)
- Follow the existing **clang-format** style (run `clang-format -i` before committing)
- Run **clang-tidy** and address all warnings
- Run **cppcheck** for static analysis
- No `assert()` for consensus invariants in release builds — use explicit error handling
- No raw owning pointers; prefer `std::unique_ptr` / `std::shared_ptr`
- Thread safety: the network layer uses a single-threaded Asio reactor — do not introduce
  locking without discussion

### Auto-format

```bash
find src include -name "*.cpp" -o -name "*.h" | xargs clang-format -i
```

---

## Testing

### Unit Tests

```bash
# Run all fast tests
./build/bin/unicity_tests -d yes "~[real]" "~[rpc]" "~[slow]"

# Run everything including slow tests
./build/bin/unicity_tests -d yes
```

### Functional Tests

```bash
cd test/functional
python3 test_runner.py
```

### Adding Tests

- Unit tests live in `test/unit/` and use **Catch2**
- Functional tests live in `test/functional/` and use the Python test framework
- New consensus rules **must** have unit tests
- New P2P message handling **must** have functional tests

---

## Submitting Changes

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```
2. **Make your changes**, committing incrementally with clear messages
3. **Run the full test suite** locally before pushing
4. **Push** and open a Pull Request against `main`
5. Fill out the **PR template** completely

### Branch Naming

| Type        | Pattern                  |
|-------------|--------------------------|
| Feature     | `feat/<short-description>` |
| Bug fix     | `fix/<short-description>`  |
| CI/tooling  | `ci/<short-description>`   |
| Docs        | `docs/<short-description>` |
| Refactor    | `refactor/<short-description>` |

---

## Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>(<scope>): <short summary>

[optional body]

[optional footer]
```

**Types**: `feat`, `fix`, `ci`, `docs`, `refactor`, `test`, `perf`, `chore`

**Examples**:
```
fix(ci): correct SANITIZER flag name in pr-ci.yml
feat(chain): add block timestamp validation
docs(arch): remove stale Orphan Pool references
```

---

## Review Process

- All PRs require at least **one approving review** from a maintainer
- CI must be green (all `build-test` and `functional-tests` jobs passing)
- Consensus-critical changes require **two approving reviews**
- Maintainers may request changes; please address all review comments
- Squash or rebase before merge if commit history is noisy

---

## Security Issues

Please do **not** open public issues for security vulnerabilities.
See [SECURITY.md](SECURITY.md) for the responsible disclosure process.
