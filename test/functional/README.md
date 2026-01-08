# Functional Tests README

This directory contains Python-based functional tests that drive one or more Unicity nodes (`unicityd`) via the local RPC (Unix socket) and, where needed, P2P connections. Tests cover consensus rules, networking behavior, misbehavior handling, orphan-pool controls, and various workflow scenarios.

Highlights:
- Deterministic consensus tests using a testnet/regtest-only `submitheader` RPC. PoW bypass via `skip_pow=true` is **regtest-only**.
- P2P misbehavior and disconnection tests via a test-only `reportmisbehavior` RPC.
- Orphan pool inspection and eviction via `getorphanstats`, `addorphanheader`, and `evictorphans` RPCs.
- A flexible test runner with discovery, filtering (`-k`), per-test timeouts, and optional JUnit XML output for CI.

## Prerequisites
- Build Unicity in `build/` so `build/bin/unicityd` and `build/bin/unicity-cli` exist.
  - Example:
    - `cmake -S . -B build -DCMAKE_BUILD_TYPE=Release`
    - `cmake --build build -j$(nproc)`
- Python 3 available on your path.
- Optional: set `UNICITYD` env var to point to a custom `unicityd` binary. The test framework will auto-detect `build/bin/unicityd` otherwise.

## Quick start
- Run the default functional suite (auto-discovers safe/fast tests):
  - `python3 test/functional/test_runner.py`
- Filter tests by substring (runs only matching scripts from the included set):
  - `python3 test/functional/test_runner.py -k consensus_`
  - `python3 test/functional/test_runner.py -k rpc_`
- Run a single test directly (including slow/excluded tests):
  - `python3 test/functional/orphan_pool_tests.py`
  - `python3 test/functional/p2p_batching.py`  (slow; requires prebuilt chain, see below)
- Increase the per-test timeout (seconds) or export JUnit XML:
  - `python3 test/functional/test_runner.py --timeout 1200 --junit functional-results.xml`

Notes:
- The runner intentionally excludes slow/advanced scripts (see `exclude_files` in `test/functional/test_runner.py`). Use direct invocation to run these, or edit the exclude list locally.
- Tests set the working directory to the repo root automatically; you can invoke the runner from anywhere.

## Test framework basics
- Class: `test/functional/test_framework/test_node.py::TestNode`
  - Spins up `unicityd` with a dedicated datadir.
  - Chains:
    - `chain="regtest"` (default)
    - `chain="testnet"` (some tests use this; mainnet is not used by functional tests).
  - RPCs are executed via `unicity-cli` over the per-node Unix domain socket in the node datadir (`node.sock`).
  - Logs: `debug.log` in each node’s datadir. The framework prints tail content on failure.
  - Extra daemon args can be passed via `extra_args=["--nolisten", "--port=...", "--listen"]` etc.

## Test categories (examples)
- Consensus
  - `consensus_timestamp_bounds.py` (MTP/future-time window via `submitheader ... skip_pow=true`)
  - `consensus_difficulty_regtest.py` (powLimit fixed on regtest)
  - `consensus_asert_difficulty_testnet.py` (ASERT evolution using `getnextworkrequired`)
- Networking / P2P
  - `p2p_misbehavior_scores.py` (disconnects and scoring via `reportmisbehavior`)
  - `p2p_batching.py` (headers batching of 2000; slow by design)
  - `p2p_*` and `feature_*` scripts cover sync, fork resolution, IBD restart/resume, etc.
- Orphan pool
  - `orphan_pool_tests.py` (add/list/evict orphans, per-peer counts)
- RPC surface
  - `rpc_errors_and_help.py` (unknown command, bad params, help behavior)
  - `rpc_ban_persistence.py` (banlist persists across restart; `clearbanned`)

The test runner (`test/functional/test_runner.py`) discovers files starting with `feature_`, `test_`, `p2p_`, `rpc_`, `basic_`, `consensus_`, `orphan_`, excluding the slow/advanced list.

## Test-only RPCs (regtest/testnet only)
These RPCs exist solely to enable deterministic functional testing. They are disabled on mainnet builds or at runtime on mainnet.

- `submitheader <100-byte-hex> [skip_pow]`
  - Submits a raw 100-byte header (hex) on regtest/testnet. When `skip_pow=true`, bypasses full PoW and runs contextual checks only, but **only on regtest**. On testnet, `skip_pow=true` is rejected with a clear error to avoid accidental PoW skipping on public networks.
  - Returns `{ "success": true, "hash": "..." }` on accept or `{ "error": "..." }` on failure.
- `getnextworkrequired`
  - Returns the expected `nBits` for the next header at the current tip. Useful for ASERT tests on testnet/regtest.
- `disconnectnode <peer_id | host[:port]>`
  - Immediately disconnects a peer (if connected).
- `clearbanned`
  - Clears persistent ban entries.
- Orphan pool controls
  - `addorphanheader <100-byte-hex> [peer_id]`
  - `getorphanstats` → `{ "count": N, "by_peer": [{"peer_id": P, "count": C}, ...] }`
  - `evictorphans` → `{ "evicted": N }`
- Misbehavior injection
  - `reportmisbehavior <peer_id> <type> [arg]`
    - Types include: `invalid_pow`, `non_continuous <k>`, `oversized`, `low_work`, `invalid_header`, `too_many_orphans`, `increment_unconnecting <k>`, `reset_unconnecting`, `clear_discouraged`.
    - Response includes `{ "peer_existed_before": bool, "peer_exists_after": bool }`.

Tip: Many tests use `setmocktime` to control future-time validation and expiry windows.

## Slow/advanced tests
- `p2p_batching.py` syncs large header sets over P2P, performing full PoW verification per header; expect ~tens of headers/sec on a single validation thread.
  - Run directly: `python3 test/functional/p2p_batching.py`
  - Requires prebuilt chain assets under `test/functional/test_chains/` (e.g., `chain_12000_blocks/`). If missing, generate with the helper script(s) in this directory.
- `feature_multinode_sync.py`, `feature_chaos_convergence.py`, `feature_ibd_restart_resume.py` are also opt-in and can take longer.

Wire-level adversarial injector
- The Node Simulator (real TCP) builds to build/bin/node_simulator and lives under test/wire/.
- You can drive it from functional tests (see adversarial_headers_wire.py) or run it manually.

Performance tips (optional):
- Reduce logs (avoid `-debug` flags) for I/O-heavy tests.
- When measuring logic (not PoW), prefer `submitheader ... skip_pow=true` and regtest.
- For faster PoW, run on a Linux host with RandomX fast mode and huge pages, or parallelize PoW verification behind an in-order commit. These optimizations are not required for correctness.

## Prebuilt chains (for batching and persistence tests)
Some tests expect pre-mined chains under `test/functional/test_chains/`:
- `chain_200_blocks/`, `chain_2500_blocks/`, `chain_12000_blocks/`

If absent, you can regenerate them using the helper scripts here (these may take time):
- `python3 test/functional/regenerate_test_chains.py`

Note: The generation helpers assume a standard `unicityd` layout; if your binary name/path differs, update the scripts or export `UNICITYD` so the framework finds your daemon.

### Using Git LFS for prebuilt chains
To keep the repository slim while storing large test assets, we recommend tracking prebuilt chains with Git LFS.

- Install once locally:
  - `git lfs install`
- Track only the prebuilt chains:
  - `git lfs track "test/functional/test_chains/**"`
  - Commit the generated `.gitattributes` file.
- CI: ensure checkout pulls LFS content (already configured in `.github/workflows/functional-tests.yml`).

You can always regenerate locally with the helper scripts if LFS assets are not present.

## CI integration
- GitHub Actions workflow runs the default functional suite by default: `.github/workflows/functional-tests.yml`
- Locally, you can reproduce with:
  - `python3 test/functional/test_runner.py --timeout 1200 --junit functional-results.xml`

## Troubleshooting
- "No test scripts found!":
  - Your `-k` filter might be too restrictive, or you targeted a script that’s excluded by default. Run the script directly or adjust the exclude list in the runner.
- `unicityd not found`:
  - Build the project so `build/bin/unicityd` exists, or set `UNICITYD` to the full path of your daemon.
- Port conflicts:
  - Use `--nolisten` for single-node tests, or let the framework allocate ports dynamically. Multi-node tests tend to bind ephemeral ports automatically.
- Missing prebuilt chains for batching:
  - Regenerate with `regenerate_test_chains.py` or adjust the test to a smaller dataset.

## Adding new tests
- Place new scripts here with a filename starting with one of: `feature_`, `test_`, `p2p_`, `rpc_`, `basic_`, `consensus_`, `orphan_`.
- Keep long/advanced tests out of the default run by adding them to `exclude_files` in `test_runner.py`.
- Prefer deterministic setups (regtest, `setmocktime`, and test-only RPCs) to avoid flakiness.
