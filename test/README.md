# Test Suite

Comprehensive test coverage for the Unicity node implementation.

## Quick Start

```bash
# Build all tests
cmake -S . -B build
cmake --build build

# Run C++ tests
./build/bin/unicity_tests

# Run by tag
./build/bin/unicity_tests "[dos]"
./build/bin/unicity_tests "[adversarial]"

# Run by name pattern
./build/bin/unicity_tests "*header_sync*"

# Run Python functional test
python test/functional/p2p_invalid_messages.py

# Run wire-level attack simulator
./build/bin/node_simulator --host 127.0.0.1 --port 29590 --test all
```

## Directory Structure

```
test/
├── unit/                    # Fast isolated component tests
├── integration-network/     # P2P network tests (simulated)
│   ├── dos/                 # DoS protection
│   ├── peer/                # Peer lifecycle
│   ├── security/            # Eclipse attack simulations
│   └── infra/               # Test infrastructure
├── integration-chain/       # Chain tests (reorgs, validation)
├── wire/                    # Wire-level protocol tools
├── functional/              # Python tests against real node
│   ├── docker_*/            # Multi-node Docker tests
│   └── test_framework/      # Python utilities
├── benchmark/               # Performance benchmarks
└── common/                  # Shared test utilities
```

## Test Categories

### Unit Tests (`unit/`)

Fast, isolated tests with no I/O. Organized by component:

- `addr_manager/` - Address manager logic
- `chain/` - Block, header, chainstate, validation
- `network/` - Message serialization, protocol constants
- `util/` - Utilities, serialization, threading

### Network Integration Tests (`integration-network/`)

P2P tests using simulated network infrastructure.

| Directory | Purpose |
|-----------|---------|
| `dos/` | Rate limiting, floods, oversized messages |
| `peer/` | Connection lifecycle, adversarial scenarios |
| `handshake/` | Handshake edge cases, timeouts |
| `manager/` | Header sync, IBD gating |
| `security/` | Eclipse attack simulations |
| `infra/` | SimulatedNetwork, TestOrchestrator |

### Chain Integration Tests (`integration-chain/`)

| File | Purpose |
|------|---------|
| `chain_e2e_tests.cpp` | End-to-end chain operations |
| `invalidateblock_chain_tests.cpp` | Block invalidation and recovery |
| `reorg_multi_node_tests.cpp` | Multi-node reorganization |

### Wire Tests (`wire/`)

Real TCP protocol testing via `node_simulator`. Connects to a live node and sends malformed P2P messages. See `wire/README.md` for the full list of 50+ test scenarios.

### Python Functional Tests (`functional/`)

Integration tests against a real running node:

- `p2p_*.py` - P2P protocol tests
- `consensus_*.py` - Consensus rule tests
- `feature_*.py` - Feature tests (reorgs, persistence)
- `adversarial_*_wire.py` - Wire attacks via node_simulator
- `docker_*/` - Multi-node Docker test suites

### Benchmarks (`benchmark/`)

```bash
./build/bin/unicity_bench
```

## Writing C++ Tests

### Basic Structure

```cpp
#include "catch2/catch_amalgamated.hpp"

TEST_CASE("Feature works", "[unit][feature]") {
    SECTION("basic case") {
        REQUIRE(my_function() == expected);
    }
    SECTION("edge case") {
        REQUIRE_THROWS(my_function_with_bad_input());
    }
}
```

Files in `unit/`, `integration-network/`, and `integration-chain/` are automatically discovered - no CMake registration needed.

### Network Integration Test

```cpp
#include "catch2/catch_amalgamated.hpp"
#include "test_orchestrator.hpp"
#include "simulated_node.hpp"
#include "attack_simulated_node.hpp"

TEST_CASE("DoS: Invalid PoW headers", "[dos][adversarial]") {
    auto params = chain::CreateRegtestParams();
    SimulatedNetwork network(42);
    TestOrchestrator orchestrator(&network);

    SimulatedNode victim(1, &network, params.get());
    AttackSimulatedNode attacker(2, &network, params.get());
    victim.Start();
    attacker.Start();

    // Build chain
    victim.SetBypassPOWValidation(true);
    for (int i = 0; i < 10; i++) {
        victim.MineBlock();
    }

    // Connect and sync
    victim.ConnectTo(attacker.GetAddress());
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));
    REQUIRE(orchestrator.WaitForSync(victim, attacker));

    // Attack
    victim.SetBypassPOWValidation(false);
    attacker.SendInvalidPoWHeaders(1, victim.GetTipHash(), 1);
    orchestrator.AdvanceTime(std::chrono::seconds(2));

    // Verify protection
    orchestrator.AssertPeerDiscouraged(victim, attacker);
    REQUIRE(orchestrator.WaitForPeerCount(victim, 0));
}
```

### TestOrchestrator API

```cpp
// Connection
orchestrator.WaitForConnection(node_a, node_b);
orchestrator.WaitForDisconnect(victim, attacker);
orchestrator.WaitForPeerCount(node, 2);

// Sync
orchestrator.WaitForSync(node_a, node_b);
orchestrator.WaitForHeight(node, 10);
orchestrator.WaitForTip(node, expected_hash);

// Assertions
orchestrator.AssertPeerDiscouraged(victim, attacker);
orchestrator.AssertPeerNotDiscouraged(victim, trusted);
orchestrator.AssertMisbehaviorScore(victim, attacker, 100);
orchestrator.AssertPeerCount(node, 3);
orchestrator.AssertHeight(node, 10);

// Time control
orchestrator.AdvanceTime(std::chrono::seconds(2));

// Custom conditions
orchestrator.WaitForCondition([]() { return check(); }, std::chrono::seconds(5));
```

### Attack Methods

```cpp
NodeSimulator attacker(2, &network, params.get());

attacker.SendInvalidPoWHeaders(victim_id, prev_hash, count);
attacker.SendUnconnectingHeaders(victim_id, count);
attacker.SendNonContinuousHeaders(victim_id, prev_hash);
attacker.SendOversizedHeaders(victim_id, 2500);  // Max is 2000
attacker.SendLowWorkHeaders(victim_id, header_hashes);
attacker.EnableStalling(true);
attacker.MineBlockPrivate();
```

## Writing Python Tests

```python
#!/usr/bin/env python3
"""Test description."""

import sys
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode
from util import pick_free_port

def main():
    test_dir = Path(tempfile.mkdtemp(prefix="unicity_test_"))
    binary = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    try:
        port = pick_free_port()
        node = TestNode(0, test_dir / "node0", binary, extra_args=[f"--port={port}"])
        node.start()

        # Test logic here
        info = node.get_info()
        assert "blocks" in info

        print("PASSED")
        return 0
    except Exception as e:
        print(f"FAILED: {e}")
        return 1
    finally:
        if node.is_running():
            node.stop()
        shutil.rmtree(test_dir, ignore_errors=True)

if __name__ == "__main__":
    sys.exit(main())
```

### Docker Tests

Docker test suites (`functional/docker_*/`) use raw P2P sockets, not RPC:

```python
# Raw TCP to P2P port
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((node_ip, 29590))
s.send(create_version_message())
```

See `functional/docker_eclipse/run_eclipse_tests.py` for the canonical pattern.

## Test Tags

| Tag | Description |
|-----|-------------|
| `[unit]` | Unit tests |
| `[network]` | Network/P2P tests |
| `[dos]` | DoS protection |
| `[adversarial]` | Attack scenarios |
| `[handshake]` | Handshake tests |
| `[headers]` | Header tests |
| `[sync]` | Sync tests |
| `[eviction]` | Eviction tests |

## CI / Coverage

```bash
# Fast tests
./build/bin/unicity_tests --exclude-tags="[slow]"

# Full suite
./build/bin/unicity_tests

# Python tests
python test/functional/test_runner.py

# Coverage
cmake -S . -B build -DCOVERAGE=ON
cmake --build build
./build/bin/unicity_tests
gcovr --html-details coverage.html
```
