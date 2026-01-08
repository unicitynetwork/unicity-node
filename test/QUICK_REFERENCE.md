# Test2 Framework - Quick Reference

## 30-Second Setup

```cpp
#include "catch2/catch.hpp"
#include "test_orchestrator.hpp"
#include "network_observer.hpp"
#include "simulated_node.hpp"
#include "attack_simulated_node.hpp"
#include "chain/params.hpp"

TEST_CASE("My test", "[mytag]") {
    auto params = chain::CreateRegtestParams();
    SimulatedNetwork network(42);
    TestOrchestrator orchestrator(&network);
    NetworkObserver observer;
    AutoDumpOnFailure auto_dump(observer);
    
    SimulatedNode node1(1, &network, params.get());
    SimulatedNode node2(2, &network, params.get());
    node1.Start();
    node2.Start();
    
    // Your test logic here
    
    auto_dump.MarkSuccess();
}
```

## TestOrchestrator Cheat Sheet

### Connection
```cpp
// Wait for connection
REQUIRE(orchestrator.WaitForConnection(node_a, node_b));

// Wait for specific count
REQUIRE(orchestrator.WaitForPeerCount(node, 2));

// Wait for disconnect
REQUIRE(orchestrator.WaitForDisconnect(victim, attacker));
```

### Sync
```cpp
// Wait for nodes to sync
REQUIRE(orchestrator.WaitForSync(node_a, node_b));

// Wait for height
REQUIRE(orchestrator.WaitForHeight(node, 10));

// Wait for specific tip
REQUIRE(orchestrator.WaitForTip(node, expected_hash));
```

### Assertions
```cpp
// Peer discouraged?
orchestrator.AssertPeerDiscouraged(victim, attacker);
orchestrator.AssertPeerNotDiscouraged(victim, trusted);

// Misbehavior score
orchestrator.AssertMisbehaviorScore(victim, attacker, 100);

// Peer count
orchestrator.AssertPeerCount(node, 3);

// Chain state
orchestrator.AssertHeight(node, 10);
orchestrator.AssertTip(node, hash);
```

### Timing
```cpp
// Advance time
orchestrator.AdvanceTime(std::chrono::seconds(2));
orchestrator.AdvanceTime(std::chrono::milliseconds(500));

// Custom wait
REQUIRE(orchestrator.WaitForCondition(
    []() { return some_check(); },
    std::chrono::seconds(5)
));
```

## NetworkObserver Cheat Sheet

### Event Tracking
```cpp
// Test phases
observer.OnCustomEvent("TEST_START", -1, "Description");
observer.OnCustomEvent("PHASE", -1, "Setting up");
observer.OnCustomEvent("TEST_END", -1, "PASSED");

// Network events
observer.OnMessageSent(from, to, "headers", 500);
observer.OnPeerConnected(node_a, node_b, peer_id);
observer.OnPeerDisconnected(node_a, node_b, "reason");

// DoS events
observer.OnMisbehaviorScoreChanged(node_id, peer_id, 0, 100, "reason");
observer.OnBanStatusChanged(node_id, address, "discouraged");

// Chain events
observer.OnBlockMined(node_id, hash, height);
observer.OnValidationFailed(node_id, "header", "invalid_pow");
```

### Auto-Dump
```cpp
AutoDumpOnFailure auto_dump(observer);
// Test code - if REQUIRE fails, timeline dumps automatically
auto_dump.MarkSuccess();  // Prevent dump on success
```

## Common Patterns

### DoS Attack Test
```cpp
TEST_CASE("DoS: Attack type", "[dos]") {
    auto params = chain::CreateRegtestParams();
    SimulatedNetwork network(42);
    TestOrchestrator orchestrator(&network);
    NetworkObserver observer;
    AutoDumpOnFailure auto_dump(observer);
    
    SimulatedNode victim(1, &network, params.get());
    AttackSimulatedNode attacker(2, &network, params.get());
    victim.Start();
    attacker.Start();
    
    observer.OnCustomEvent("TEST_START", -1, "Attack test");
    
    // Build chain
    victim.SetBypassPOWValidation(true);
    for (int i = 0; i < 10; i++) {
        victim.MineBlock();
    }
    
    // Connect and sync
    victim.ConnectTo(attacker.GetAddress());
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));
    REQUIRE(orchestrator.WaitForSync(victim, attacker));
    
    // Launch attack
    victim.SetBypassPOWValidation(false);
    attacker.SendInvalidPoWHeaders(1, victim.GetTipHash(), 1);
    orchestrator.AdvanceTime(std::chrono::seconds(2));
    
    // Verify protection
    orchestrator.AssertPeerDiscouraged(victim, attacker);
    REQUIRE(orchestrator.WaitForPeerCount(victim, 0));
    
    observer.OnCustomEvent("TEST_END", -1, "PASSED");
    auto_dump.MarkSuccess();
}
```

### Permission Test
```cpp
TEST_CASE("Permission: NoBan test", "[permissions][noban]") {
    auto params = chain::CreateRegtestParams();
    SimulatedNetwork network(123);
    TestOrchestrator orchestrator(&network);
    NetworkObserver observer;
    AutoDumpOnFailure auto_dump(observer);
    
    SimulatedNode victim(1, &network, params.get());
    AttackSimulatedNode attacker(2, &network, params.get());
    victim.Start();
    attacker.Start();
    
    // Build chain
    victim.SetBypassPOWValidation(true);
    for (int i = 0; i < 5; i++) {
        victim.MineBlock();
    }
    
    // Set NoBan permission
    victim.SetInboundPermissions(NetPermissionFlags::NoBan);
    
    // Connect
    victim.ConnectTo(attacker.GetAddress());
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));
    REQUIRE(orchestrator.WaitForSync(victim, attacker));
    
    // Attack
    victim.SetBypassPOWValidation(false);
    attacker.SendInvalidPoWHeaders(1, victim.GetTipHash(), 1);
    orchestrator.AdvanceTime(std::chrono::seconds(2));
    
    // Verify NoBan behavior
    orchestrator.AssertPeerCount(victim, 1);  // Still connected!
    orchestrator.AssertPeerNotDiscouraged(victim, attacker);
    orchestrator.AssertMisbehaviorScore(victim, attacker, 100);  // Score tracked
    
    auto_dump.MarkSuccess();
}
```

### Multi-Node Test
```cpp
TEST_CASE("Multi-node scenario", "[network]") {
    auto params = chain::CreateRegtestParams();
    SimulatedNetwork network(456);
    TestOrchestrator orchestrator(&network);
    
    SimulatedNode node1(1, &network, params.get());
    SimulatedNode node2(2, &network, params.get());
    SimulatedNode node3(3, &network, params.get());
    
    node1.Start();
    node2.Start();
    node3.Start();
    
    // Build chain on node1
    node1.SetBypassPOWValidation(true);
    for (int i = 0; i < 10; i++) {
        node1.MineBlock();
    }
    
    // Connect all nodes
    node1.ConnectTo(node2.GetAddress());
    node1.ConnectTo(node3.GetAddress());
    
    REQUIRE(orchestrator.WaitForConnection(node1, node2));
    REQUIRE(orchestrator.WaitForConnection(node1, node3));
    
    // Wait for sync
    REQUIRE(orchestrator.WaitForSync(node1, node2));
    REQUIRE(orchestrator.WaitForSync(node1, node3));
    
    // Verify all at same height
    orchestrator.AssertHeight(node1, 10);
    orchestrator.AssertHeight(node2, 10);
    orchestrator.AssertHeight(node3, 10);
}
```

## Attack Methods

```cpp
AttackSimulatedNode attacker(2, &network, params.get());

// Invalid PoW
attacker.SendInvalidPoWHeaders(victim_id, prev_hash, count);

// Orphan headers
attacker.SendOrphanHeaders(victim_id, count);

// Non-continuous headers
attacker.SendNonContinuousHeaders(victim_id, prev_hash);

// Oversized message
attacker.SendOversizedHeaders(victim_id, 2500);  // Max is 2000

// Low-work headers
attacker.SendLowWorkHeaders(victim_id, header_hashes);

// Enable stalling
attacker.EnableStalling(true);

// Mine privately
auto hash = attacker.MineBlockPrivate();
```

## Running Tests

```bash
# All tests
./unicity_tests2

# Specific tag
./unicity_tests2 "[dos]"
./unicity_tests2 "[permissions]"
./unicity_tests2 "[noban]"

# Specific test
./unicity_tests2 "DoS: Invalid PoW"

# Verbose
./unicity_tests2 -v

# List tests
./unicity_tests2 --list-tests
```

## Troubleshooting

### Test Times Out
```cpp
// Enable verbose logging
orchestrator.SetVerbose(true);

// Check you called Start()
victim.Start();
attacker.Start();

// Increase timeout
orchestrator.WaitForConnection(victim, attacker, std::chrono::seconds(10));
```

### No Timeline Output
```cpp
// Make sure AutoDumpOnFailure is created
AutoDumpOnFailure auto_dump(observer);

// Add event tracking
observer.OnCustomEvent("PHASE", -1, "Description");

// Manual dump for debugging
observer.DumpTimeline();
```

### Wrong Assertion
```cpp
// ❌ WRONG - checks ban list
REQUIRE(victim.IsBanned(attacker.GetAddress()));

// ✅ CORRECT - checks discourage list
orchestrator.AssertPeerDiscouraged(victim, attacker);
```

### ID Confusion
```cpp
// ❌ WRONG - using node_id
int score = peer_manager.GetMisbehaviorScore(attacker.GetId());

// ✅ CORRECT - using peer_id via orchestrator
orchestrator.AssertMisbehaviorScore(victim, attacker, 100);
```

## Key Rules

1. **Always use TestOrchestrator** for timing - no manual loops
2. **Always use NetworkObserver** with AutoDumpOnFailure
3. **Never use node_id** for PeerManager queries - use `orchestrator.GetPeerId()`
4. **Use IsDiscouraged** not IsBanned for DoS checks
5. **Call MarkSuccess()** at end of test to prevent unnecessary dumps
6. **Set BypassPOWValidation(false)** BEFORE attack, not before

## Complete Example

```cpp
TEST_CASE("Complete example", "[example]") {
    // 1. Setup
    auto params = chain::CreateRegtestParams();
    SimulatedNetwork network(42);
    TestOrchestrator orchestrator(&network);
    NetworkObserver observer;
    AutoDumpOnFailure auto_dump(observer);
    
    SimulatedNode victim(1, &network, params.get());
    AttackSimulatedNode attacker(2, &network, params.get());
    victim.Start();
    attacker.Start();
    
    observer.OnCustomEvent("TEST_START", -1, "My test");
    
    // 2. Build chain
    observer.OnCustomEvent("PHASE", -1, "Building chain");
    victim.SetBypassPOWValidation(true);
    for (int i = 0; i < 10; i++) {
        auto hash = victim.MineBlock();
        observer.OnBlockMined(1, hash.ToString(), victim.GetHeight());
    }
    
    // 3. Connect
    observer.OnCustomEvent("PHASE", -1, "Connecting");
    victim.ConnectTo(attacker.GetAddress());
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));
    observer.OnPeerConnected(1, 2, orchestrator.GetPeerId(victim, attacker));
    
    // 4. Sync
    observer.OnCustomEvent("PHASE", -1, "Syncing");
    REQUIRE(orchestrator.WaitForSync(victim, attacker));
    orchestrator.AssertHeight(attacker, 10);
    
    // 5. Attack
    victim.SetBypassPOWValidation(false);
    observer.OnCustomEvent("PHASE", -1, "Attacking");
    attacker.SendInvalidPoWHeaders(1, victim.GetTipHash(), 1);
    observer.OnMessageSent(2, 1, "invalid_pow", 100);
    
    // 6. Process
    orchestrator.AdvanceTime(std::chrono::seconds(2));
    
    // 7. Verify
    observer.OnCustomEvent("PHASE", -1, "Verifying");
    orchestrator.AssertPeerDiscouraged(victim, attacker);
    REQUIRE(orchestrator.WaitForPeerCount(victim, 0));
    orchestrator.AssertHeight(victim, 10);
    
    // 8. Success
    observer.OnCustomEvent("TEST_END", -1, "PASSED");
    auto_dump.MarkSuccess();
}
```


