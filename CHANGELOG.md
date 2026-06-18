# Changelog

All notable changes to unicity-node will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project does not yet use semantic versioning — entries are tracked by date.

---

## [Unreleased]

### Added
- `SECURITY.md` — responsible disclosure policy and security best practices for node operators
- `CONTRIBUTING.md` — developer setup guide, coding standards, testing instructions, and PR process
- `.github/PULL_REQUEST_TEMPLATE` — structured PR checklist including consensus-impact flag
- `.github/ISSUE_TEMPLATE/bug_report.yml` — structured bug report form
- `.github/ISSUE_TEMPLATE/feature_request.yml` — structured feature request form
- `.github/ISSUE_TEMPLATE/consensus_issue.yml` — dedicated template for consensus-critical issues
- `.github/ISSUE_TEMPLATE/config.yml` — disables blank issues, links security contact
- `CHANGELOG.md` — this file

### Changed
- `CMakeLists.txt` — pinned RandomX dependency to a specific commit SHA
  (`051d4424394cf8d1f8d0bfff581f0729f2753341`) instead of floating `origin/master`,
  eliminating supply chain and reproducibility risk
- `.github/workflows/pr-ci.yml` — fixed sanitizer flag typo (`-DSANITIZE` → `-DSANITIZER`)
  so AddressSanitizer and UBSan are now actually enabled in CI
- `.github/workflows/pr-ci.yml` — added macOS 14 (Apple Silicon) CI job
- `.github/workflows/pr-ci.yml` — added dedicated `ASan` and `UBSan` CI jobs (Linux Clang 18)
- `.github/workflows/pr-ci.yml` — added `functional-tests` CI job that runs the Python
  functional test suite on every PR
- `.github/workflows/pr-ci.yml` — `nproc` call made portable for macOS
  (`nproc 2>/dev/null || sysctl -n hw.logicalcpu`)
- `docs/ARCHITECTURE.md` — removed stale Orphan Pool component from architecture diagram
  (Orphan Pool was removed in February 2026; headers now flow directly into ActiveTipCandidates)
- `docs/ARCHITECTURE.md` — updated DoS protection section to reflect current candidate tip limits

---

## [Pre-release] — 2026-01-08 to 2026-04-14

_Initial development. No versioned releases yet._

### Core Architecture
- Headers-only C++20 blockchain node (no transactions, UTXO, or mempool)
- Single-threaded Asio reactor network layer — no locking required
- Bitcoin Core-inspired P2P protocol (version handshake, headers sync, addr relay)
- RandomX proof-of-work with two-phase verification:
  - ~1ms commitment check (fast pre-filter)
  - ~50ms full RandomX verification (only after commitment passes)
- ASERT difficulty adjustment algorithm (same as Bitcoin Cash)
- Chain state persistence with reorg support
- RPC via Unix domain socket (no TCP exposure)
- Eclipse attack resistance (diversified peer selection)

### Dependencies
- RandomX (Unicity fork) — ASIC-resistant PoW
- Asio (standalone) — async I/O
- spdlog + fmt — structured logging
- nlohmann/json — JSON serialization
- miniupnpc — UPnP/NAT traversal
- Catch2 — unit testing

### CI / Tooling
- GitHub Actions CI: Linux Clang 18, Linux GCC 11
- Coverity static analysis workflow
- OSS-Fuzz integration (13 fuzz targets)
- clang-format, clang-tidy, cppcheck enforcement
- Docker multi-stage build (Ubuntu 22.04)
- Ansible deployment scripts
