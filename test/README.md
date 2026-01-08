# Test Suite

Comprehensive test coverage for the Unicity node implementation.

## Important: Docker Tests Use Raw P2P Sockets (NOT RPC)

**Docker tests connect via raw TCP P2P protocol, not RPC.**

The node does not expose RPC over HTTP in Docker tests. All communication uses:
- Raw TCP sockets to port 29590 (P2P port)
- Manual P2P message construction (VERSION, VERACK, HEADERS, etc.)
- Binary protocol with magic bytes, checksums, and payloads

```python
# CORRECT: Raw P2P socket connection
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_ip, 29590))  # P2P port
s.send(create_version_message())  # Manual P2P message

# WRONG: Do NOT use RPC in Docker tests
# node.rpc("getpeerinfo")  # NO - RPC is not available
# requests.post("http://node:8332", ...)  # NO - no HTTP RPC
```

See `functional/docker_eclipse/run_eclipse_tests.py` for the canonical pattern:
- `create_message(command, payload)` - Build P2P message with checksum
- `create_version_message()` - Build VERSION handshake
- `docker_exec(container, script)` - Run Python socket code in container

## Quick Start

```bash
# Build all tests
cmake -S . -B build
cmake --build build

# Run C++ unit tests (fast)
./build/bin/unicity_tests

# Run specific test by tag
./build/bin/unicity_tests "[dos]"
./build/bin/unicity_tests "[adversarial]"

# Run specific test by name pattern
./build/bin/unicity_tests "*header_sync*"

# Run Python functional test
python test/functional/p2p_invalid_messages.py

# Run wire-level attack simulator
./build/bin/node_simulator --test all
```

## Directory Structure

```
test/
├── unit/                    # C++ unit tests (isolated component tests)
├── network/                 # C++ network/P2P tests (simulated network)
├── chain/                   # C++ chain integration tests
├── security/                # C++ security regression tests
├── wire/                    # Wire-level protocol tools (real TCP)
├── functional/              # Python functional tests (real node)
│   ├── docker_*/            # Docker-based multi-node test suites
│   └── test_framework/      # Python test utilities
├── benchmark/               # Performance benchmarks
└── fuzz/                    # Fuzzing targets (in ../fuzz/)
```

## Test Categories

### 1. Unit Tests (`unit/`)

Isolated component tests using mocks. Fast, no I/O.

| File | Purpose |
|------|---------|
| `message_tests.cpp` | P2P message serialization/deserialization |
| `protocol_tests.cpp` | Protocol constants, limits, validation |
| `block_*.cpp` | Block/header structures and validation |
| `chainstate_*.cpp` | Chain state management |
| `banman_*.cpp` | Ban manager logic |
| `anchor_manager_*.cpp` | Anchor connection persistence |
| `miner_*.cpp` | Mining functionality |
| `validation_*.cpp` | Consensus validation rules |
| `randomx_*.cpp` | RandomX PoW integration |

Run: `./build/bin/unicity_tests "[unit]"` or by file pattern.

### 2. Network Tests (`network/`)

P2P networking tests using simulated network infrastructure.

| Subdirectory | Purpose |
|--------------|---------|
| `dos/` | DoS protection (rate limiting, oversized messages, floods) |
| `peer/` | Peer connection lifecycle, adversarial scenarios |
| `manager/` | Header sync manager, IBD gating |
| `handshake/` | P2P handshake edge cases, timeouts |
| `block_announcement/` | Block relay, INV handling |
| `addr/` | Address manager, GETADDR routing |
| `eviction/` | Peer eviction under connection pressure |
| `limits/` | Connection limits, slot exhaustion |
| `security/` | Eclipse attack simulations |
| `infra/` | Test infrastructure (SimulatedNetwork, SimulatedNode) |

Key test files:
- `peer/adversarial_tests.cpp` - Malformed messages, protocol attacks
- `dos/ping_pong_tests.cpp` - PING/PONG flood handling
- `manager/header_sync_adversarial_tests.cpp` - Header sync attacks
- `malformed_message_tests.cpp` - Invalid message handling

Run: `./build/bin/unicity_tests "[network]"` or `"[dos]"`, `"[adversarial]"`.

### 3. Chain Tests (`chain/`)

Blockchain integration tests (orphan handling, reorgs, threading).

| File | Purpose |
|------|---------|
| `orphan_*.cpp` | Orphan pool DoS, edge cases, thread safety |
| `chain_e2e_tests.cpp` | End-to-end chain operations |
| `invalidateblock_chain_tests.cpp` | Block invalidation |
| `stress_threading_tests.cpp` | Concurrent chain operations |

### 4. Security Tests (`security/`)

Security-focused regression tests.

| File | Purpose |
|------|---------|
| `security_quick_tests.cpp` | Fast security checks (VarInt limits, message sizes) |
| `security_attack_simulations.cpp` | Attack scenario simulations |

### 5. Wire Tests (`wire/`)

Real TCP protocol testing (not simulated).

**node_simulator** - Connects to a live node and sends malformed P2P messages:

```bash
./build/bin/node_simulator --help

# Available tests:
#   invalid-pow       - Headers with invalid PoW
#   oversized         - Oversized headers message
#   non-continuous    - Non-continuous headers
#   bad-magic         - Wrong message magic bytes
#   bad-checksum      - Corrupted checksum
#   truncation        - Truncated payload
#   slow-loris        - Slow data drip attack
```

### 6. Python Functional Tests (`functional/`)

Integration tests against a real running node.

#### Standalone Tests

| Test | Purpose |
|------|---------|
| `p2p_invalid_messages.py` | Invalid message handling (wrong magic, bad checksum) |
| `p2p_misbehavior_scores.py` | Misbehavior scoring and banning |
| `p2p_dos_headers.py` | Header-based DoS attacks |
| `p2p_eclipse_resistance.py` | Eclipse attack resistance |
| `p2p_eviction.py` | Peer eviction behavior |
| `p2p_ibd.py` | Initial Block Download |
| `consensus_*.py` | Consensus rules (difficulty, timestamps) |
| `feature_*.py` | Feature tests (reorgs, persistence, sync) |
| `adversarial_*_wire.py` | Wire-level attacks via node_simulator |

Run: `python test/functional/<test>.py`

#### Docker Test Suites (`functional/docker_*/`)

Multi-node tests with isolated Docker networks.

| Suite | Purpose |
|-------|---------|
| `docker_anchor/` | Anchor connection persistence for eclipse resistance |
| `docker_ban/` | Ban manager behavior across restarts |
| `docker_discovery/` | Peer discovery, ADDR relay, netgroup diversity |
| `docker_eclipse/` | Eclipse attack scenarios with multiple attackers |
| `docker_eviction/` | Eviction under connection pressure |
| `docker_header_sync/` | Header synchronization adversarial scenarios |
| `docker_partition/` | Network partition and healing |

Each suite has:
- `docker-compose.yml` - Network topology definition
- `run_*.py` - Test runner script

Run:
```bash
cd test/functional/docker_eclipse
docker-compose up -d
python run_eclipse_tests.py
docker-compose down -v
```

### 7. Benchmarks (`benchmark/`)

Performance measurement.

| File | Purpose |
|------|---------|
| `randomx_bench.cpp` | RandomX hashing throughput |
| `header_validation_bench.cpp` | Header validation speed |
| `addr_manager_bench.cpp` | Address manager operations |

Run: `./build/bin/unicity_bench`

### 8. Fuzz Tests (`../fuzz/`)

Fuzzing targets for AFL/libFuzzer.

| Target | Purpose |
|--------|---------|
| `fuzz_messages.cpp` | All 9 message types (VERSION, HEADERS, INV, etc.) |
| `fuzz_message_header.cpp` | 24-byte message header parsing |
| `fuzz_varint.cpp` | VarInt encoding/decoding |
| `fuzz_block_header.cpp` | Block header deserialization |
| `fuzz_header_validation.cpp` | Header validation logic |
| `fuzz_randomx_pow.cpp` | RandomX proof-of-work |
| `fuzz_chain_reorg.cpp` | Chain reorganization |

Run:
```bash
./build/bin/fuzz_messages corpus/ -max_len=4096
```

## Test Tags (Catch2)

Common tags for filtering tests:

| Tag | Description |
|-----|-------------|
| `[unit]` | Unit tests |
| `[network]` | Network/P2P tests |
| `[dos]` | DoS protection tests |
| `[adversarial]` | Adversarial/attack scenarios |
| `[security]` | Security-focused tests |
| `[handshake]` | Handshake tests |
| `[headers]` | Header-related tests |
| `[sync]` | Synchronization tests |
| `[eviction]` | Eviction tests |
| `[quickwin]` | Fast-running tests |

## Test Infrastructure

### SimulatedNetwork (`network/infra/`)

In-memory network simulation for deterministic testing:

```cpp
SimulatedNetwork network(port);
SimulatedNode victim(1, &network);
SimulatedNode attacker(2, &network);
attacker.ConnectTo(victim.GetId());
network.SendMessage(attacker.GetId(), victim.GetId(), malicious_msg);
```

### MockTransportConnection (`network/infra/`)

Mock TCP connection for unit testing peer behavior:

```cpp
auto mock_conn = std::make_shared<MockTransportConnection>();
auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
mock_conn->simulate_receive(malformed_message);
CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
```

### Python Test Framework (`functional/test_framework/`)

Utilities for Python functional tests:

```python
from test_framework.test_node import TestNode
from test_framework.util import pick_free_port

node = TestNode(0, datadir, binary_path, extra_args=["--regtest"])
node.start()
node.rpc("getinfo")
node.stop()
```

## Adding New Tests

### C++ Unit Test

```cpp
// test/unit/my_feature_tests.cpp
#include "catch_amalgamated.hpp"

TEST_CASE("My feature works", "[unit][myfeature]") {
    SECTION("basic case") {
        CHECK(my_function() == expected);
    }
    SECTION("edge case") {
        CHECK_THROWS(my_function_with_bad_input());
    }
}
```

Add to `test/CMakeLists.txt`:
```cmake
set(TEST_SOURCES
    ...
    unit/my_feature_tests.cpp
)
```

### Python Functional Test

```python
#!/usr/bin/env python3
"""Test description."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode
from util import pick_free_port

def main():
    # Setup, run tests, cleanup
    return 0 if passed else 1

if __name__ == "__main__":
    sys.exit(main())
```

## CI Integration

Tests are run in CI with:

```bash
# Fast tests (unit + network simulation)
./build/bin/unicity_tests --exclude-tags="[slow]"

# Full test suite
./build/bin/unicity_tests

# Python functional tests
python test/functional/test_runner.py
```

## Coverage

Generate coverage report:

```bash
cmake -S . -B build -DCOVERAGE=ON
cmake --build build
./build/bin/unicity_tests
gcovr --html-details coverage.html
```
