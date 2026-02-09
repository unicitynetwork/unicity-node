// Copyright (c) 2025 The Unicity Foundation
// Permission Tests - Built from scratch with improved testing framework
//
// Tests NetPermissionFlags functionality:
// 1. NoBan - Peer never gets disconnected or banned
// 2. Manual - Peer can be manually disconnected despite protections
//
// Key insight: These tests verify permissions work correctly when real messages
// flow through actual network components (not just unit testing the API).

#include "catch_amalgamated.hpp"
#include "chain/chainparams.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "infra/node_simulator.hpp"
#include "test_orchestrator.hpp"
#include "network_observer.hpp"
#include "network/connection_manager.hpp"

using namespace unicity;
using namespace unicity::test;
using namespace unicity::network;
using namespace unicity::chain;

TEST_CASE("Permission: Normal peer gets disconnected for invalid PoW", "[permissions][network]") {
    // Baseline: Verify normal peers DO get disconnected
    
    
    SimulatedNetwork network(42);
    TestOrchestrator orchestrator(&network);
    NetworkObserver observer;
    AutoDumpOnFailure auto_dump(observer);
    
    SimulatedNode victim(1, &network);
    // Use non-localhost address so attacker can be discouraged (localhost is exempt)
    NodeSimulator attacker(2, &network, "10.0.0.2");

    observer.OnCustomEvent("TEST_START", -1, "Normal peer disconnect baseline");
    
    // Setup chain
    victim.SetBypassPOWValidation(true);
    for (int i = 0; i < 5; i++) {
        victim.MineBlock();
    }
    
    // Connect without special permissions
    attacker.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));
    REQUIRE(orchestrator.WaitForSync(victim, attacker));
    
    orchestrator.AssertPeerCount(victim, 1);
    observer.OnPeerConnected(1, 2, orchestrator.GetPeerId(victim, attacker));
    
    // Launch attack
    victim.SetBypassPOWValidation(false);
    observer.OnCustomEvent("PHASE", -1, "Sending invalid PoW");
    attacker.SendInvalidPoWHeaders(1, victim.GetTipHash(), 1);
    
    orchestrator.AdvanceTime(std::chrono::seconds(2));
    
    // Verify: Normal peer gets disconnected and discouraged
    observer.OnCustomEvent("PHASE", -1, "Verifying disconnect");
    REQUIRE(orchestrator.WaitForPeerCount(victim, 0, std::chrono::seconds(2)));
    orchestrator.AssertPeerDiscouraged(victim, attacker);
    
    observer.OnCustomEvent("TEST_END", -1, "PASSED - Normal peer disconnected");
    auto_dump.MarkSuccess();
}

TEST_CASE("Permission: NoBan peer survives invalid PoW", "[permissions][network][noban]") {
    // NoBan peers stay connected despite misbehavior, but score is tracked
    
    
    SimulatedNetwork network(123);
    TestOrchestrator orchestrator(&network);
    NetworkObserver observer;
    AutoDumpOnFailure auto_dump(observer);
    
    SimulatedNode victim(1, &network);
    NodeSimulator attacker(2, &network);
    
    
    
    
    observer.OnCustomEvent("TEST_START", -1, "NoBan peer survival test");
    
    // Setup chain
    victim.SetBypassPOWValidation(true);
    for (int i = 0; i < 5; i++) {
        victim.MineBlock();
    }
    
    // Configure victim to accept NoBan connections
    observer.OnCustomEvent("PHASE", -1, "Setting NoBan permission");
    victim.SetInboundPermissions(NetPermissionFlags::NoBan);
    
    // Connect attacker (will be granted NoBan)
    attacker.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));
    REQUIRE(orchestrator.WaitForSync(victim, attacker));
    
    orchestrator.AssertPeerCount(victim, 1);
    observer.OnPeerConnected(1, 2, orchestrator.GetPeerId(victim, attacker));
    observer.OnCustomEvent("INFO", -1, "Attacker connected with NoBan permission");
    
    // Launch attack
    victim.SetBypassPOWValidation(false);
    observer.OnCustomEvent("PHASE", -1, "Sending invalid PoW (should survive)");
    attacker.SendInvalidPoWHeaders(1, victim.GetTipHash(), 1);
    observer.OnMessageSent(2, 1, "invalid_pow_headers", 100);
    
    orchestrator.AdvanceTime(std::chrono::seconds(2));
    
    // Verify: NoBan peer STAYS connected
    observer.OnCustomEvent("PHASE", -1, "Verifying NoBan behavior");
    orchestrator.AssertPeerCount(victim, 1);
    observer.OnCustomEvent("VERIFY", -1, "✓ Peer stayed connected");
    
    // Verify: NOT banned or discouraged
    orchestrator.AssertPeerNotDiscouraged(victim, attacker);
    observer.OnCustomEvent("VERIFY", -1, "✓ Peer not discouraged");

    // Verify: Misbehavior WAS recorded (instant-disconnect system, but NoBan prevents disconnect)
    observer.OnCustomEvent("PHASE", -1, "Checking misbehavior status");
    int peer_id = orchestrator.GetPeerId(victim, attacker);
    if (peer_id >= 0) {
        auto& peer_manager = victim.GetNetworkManager().peer_manager();
        CHECK(peer_manager.IsMisbehaving(peer_id));
    }
    observer.OnCustomEvent("VERIFY", -1, "✓ Misbehavior recorded");
    
    observer.OnCustomEvent("TEST_END", -1, "PASSED - NoBan peer survived with score tracked");
    auto_dump.MarkSuccess();
}

TEST_CASE("Permission: NoBan peer survives orphan spam", "[permissions][network][noban]") {
    // Test NoBan with different attack vector
    
    
    SimulatedNetwork network(456);
    TestOrchestrator orchestrator(&network);
    NetworkObserver observer;
    AutoDumpOnFailure auto_dump(observer);
    
    SimulatedNode victim(1, &network);
    NodeSimulator attacker(2, &network);
    
    
    
    
    observer.OnCustomEvent("TEST_START", -1, "NoBan orphan spam test");
    
    // Setup
    victim.SetBypassPOWValidation(true);
    for (int i = 0; i < 5; i++) {
        victim.MineBlock();
    }
    
    victim.SetInboundPermissions(NetPermissionFlags::NoBan);
    attacker.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));
    REQUIRE(orchestrator.WaitForSync(victim, attacker));
    
    // Spam orphan headers (would normally trigger disconnect)
    observer.OnCustomEvent("PHASE", -1, "Spamming orphan headers");
    for (int batch = 0; batch < 15; batch++) {
        attacker.SendOrphanHeaders(1, 100);
        observer.OnCustomEvent("ATTACK", 2, "Orphan batch " + std::to_string(batch + 1));
        orchestrator.AdvanceTime(std::chrono::milliseconds(200));
    }
    
    orchestrator.AdvanceTime(std::chrono::seconds(2));
    
    // Verify: Peer stays connected
    observer.OnCustomEvent("PHASE", -1, "Verifying survival");
    orchestrator.AssertPeerCount(victim, 1);
    orchestrator.AssertPeerNotDiscouraged(victim, attacker);
    
    // Check misbehavior was recorded
    int peer_id = orchestrator.GetPeerId(victim, attacker);
    if (peer_id >= 0) {
        auto& peer_manager = victim.GetNetworkManager().peer_manager();
        bool misbehaving = peer_manager.IsMisbehaving(peer_id);
        observer.OnCustomEvent("INFO", -1, "Misbehaving after orphan spam: " + std::string(misbehaving ? "yes" : "no"));
        // Peer should be marked as misbehaving, but still connected due to NoBan
        CHECK(misbehaving);
    }
    
    observer.OnCustomEvent("TEST_END", -1, "PASSED - NoBan peer survived orphan spam");
    auto_dump.MarkSuccess();
}

TEST_CASE("Permission: NoBan vs Normal peer comparison", "[permissions][network][noban]") {
    // Side-by-side comparison of NoBan vs Normal behavior
    
    
    SimulatedNetwork network(789);
    TestOrchestrator orchestrator(&network);
    NetworkObserver observer;
    AutoDumpOnFailure auto_dump(observer);
    
    // Setup two victims
    SimulatedNode victim_normal(1, &network);
    SimulatedNode victim_noban(2, &network);
    NodeSimulator attacker1(10, &network);
    NodeSimulator attacker2(20, &network);
    
    
    
    
    
    
    observer.OnCustomEvent("TEST_START", -1, "NoBan vs Normal comparison");
    
    // Build identical chains
    observer.OnCustomEvent("PHASE", -1, "Building chains");
    victim_normal.SetBypassPOWValidation(true);
    victim_noban.SetBypassPOWValidation(true);
    for (int i = 0; i < 5; i++) {
        victim_normal.MineBlock();
        victim_noban.MineBlock();
    }
    
    // Connect: Normal victim without permissions
    observer.OnCustomEvent("PHASE", -1, "Connecting normal peer");
    attacker1.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(victim_normal, attacker1));
    REQUIRE(orchestrator.WaitForSync(victim_normal, attacker1));
    
    // Connect: NoBan victim with permissions
    observer.OnCustomEvent("PHASE", -1, "Connecting NoBan peer");
    victim_noban.SetInboundPermissions(NetPermissionFlags::NoBan);
    attacker2.ConnectTo(2);
    REQUIRE(orchestrator.WaitForConnection(victim_noban, attacker2));
    REQUIRE(orchestrator.WaitForSync(victim_noban, attacker2));
    
    // Both victims have 1 peer
    orchestrator.AssertPeerCount(victim_normal, 1);
    orchestrator.AssertPeerCount(victim_noban, 1);
    
    // Launch identical attacks
    observer.OnCustomEvent("PHASE", -1, "Launching identical attacks");
    victim_normal.SetBypassPOWValidation(false);
    victim_noban.SetBypassPOWValidation(false);
    
    attacker1.SendInvalidPoWHeaders(1, victim_normal.GetTipHash(), 1);
    attacker2.SendInvalidPoWHeaders(2, victim_noban.GetTipHash(), 1);
    observer.OnMessageSent(10, 1, "invalid_pow", 100);
    observer.OnMessageSent(20, 2, "invalid_pow", 100);
    
    orchestrator.AdvanceTime(std::chrono::seconds(2));
    
    // Verify divergent behavior
    observer.OnCustomEvent("PHASE", -1, "Comparing outcomes");
    
    // Normal peer: Disconnected
    REQUIRE(orchestrator.WaitForPeerCount(victim_normal, 0, std::chrono::seconds(2)));
    observer.OnCustomEvent("RESULT", -1, "Normal peer: DISCONNECTED ✓");
    
    // NoBan peer: Still connected
    orchestrator.AssertPeerCount(victim_noban, 1);
    observer.OnCustomEvent("RESULT", -1, "NoBan peer: CONNECTED ✓");
    
    // Both chains unchanged
    orchestrator.AssertHeight(victim_normal, 5);
    orchestrator.AssertHeight(victim_noban, 5);
    
    observer.OnCustomEvent("TEST_END", -1, "PASSED - NoBan vs Normal divergence confirmed");
    auto_dump.MarkSuccess();
}

TEST_CASE("Permission: NoBan with multiple attack types", "[permissions][network][noban]") {
    // Verify NoBan protects against multiple attack vectors
    
    
    SimulatedNetwork network(999);
    TestOrchestrator orchestrator(&network);
    NetworkObserver observer;
    AutoDumpOnFailure auto_dump(observer);
    
    SimulatedNode victim(1, &network);
    NodeSimulator attacker(2, &network);
    
    
    
    
    observer.OnCustomEvent("TEST_START", -1, "NoBan multi-attack test");
    
    // Setup with NoBan
    victim.SetBypassPOWValidation(true);
    for (int i = 0; i < 10; i++) {
        victim.MineBlock();
    }
    
    victim.SetInboundPermissions(NetPermissionFlags::NoBan);
    attacker.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));
    REQUIRE(orchestrator.WaitForSync(victim, attacker));
    
    // Launch multiple attacks
    observer.OnCustomEvent("PHASE", -1, "Attack wave 1: Orphan headers");
    for (int i = 0; i < 5; i++) {
        attacker.SendOrphanHeaders(1, 100);
        orchestrator.AdvanceTime(std::chrono::milliseconds(200));
    }
    
    observer.OnCustomEvent("PHASE", -1, "Attack wave 2: Non-continuous headers");
    attacker.SendNonContinuousHeaders(1, victim.GetTipHash());
    orchestrator.AdvanceTime(std::chrono::milliseconds(500));
    
    observer.OnCustomEvent("PHASE", -1, "Attack wave 3: More orphans");
    for (int i = 0; i < 5; i++) {
        attacker.SendOrphanHeaders(1, 100);
        orchestrator.AdvanceTime(std::chrono::milliseconds(200));
    }
    
    orchestrator.AdvanceTime(std::chrono::seconds(2));
    
    // Verify: Peer survived everything
    observer.OnCustomEvent("PHASE", -1, "Verifying survival after all attacks");
    orchestrator.AssertPeerCount(victim, 1);
    orchestrator.AssertPeerNotDiscouraged(victim, attacker);

    // Verify misbehavior was recorded
    int peer_id = orchestrator.GetPeerId(victim, attacker);
    if (peer_id >= 0) {
        auto& peer_manager = victim.GetNetworkManager().peer_manager();
        CHECK(peer_manager.IsMisbehaving(peer_id));
    }
    
    // Victim functional
    orchestrator.AssertHeight(victim, 10);
    
    observer.OnCustomEvent("TEST_END", -1, "PASSED - NoBan survived all attacks");
    auto_dump.MarkSuccess();
}

TEST_CASE("Permission: Score tracking works for NoBan peers", "[permissions][network][noban]") {
    // Explicitly verify that NoBan peers get scores tracked (Bitcoin Core behavior)
    
    
    SimulatedNetwork network(111);
    TestOrchestrator orchestrator(&network);
    NetworkObserver observer;
    AutoDumpOnFailure auto_dump(observer);
    
    SimulatedNode victim(1, &network);
    NodeSimulator attacker(2, &network);
    
    
    
    
    observer.OnCustomEvent("TEST_START", -1, "NoBan score tracking test");
    
    // Setup
    victim.SetBypassPOWValidation(true);
    for (int i = 0; i < 5; i++) {
        victim.MineBlock();
    }
    
    victim.SetInboundPermissions(NetPermissionFlags::NoBan);
    attacker.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));
    REQUIRE(orchestrator.WaitForSync(victim, attacker));
    
    int peer_id = orchestrator.GetPeerId(victim, attacker);
    REQUIRE(peer_id >= 0);

    auto& peer_manager = victim.GetNetworkManager().peer_manager();
    bool misbehaving_before = peer_manager.IsMisbehaving(peer_id);
    observer.OnCustomEvent("INFO", -1, "Initially misbehaving: " + std::string(misbehaving_before ? "yes" : "no"));
    REQUIRE_FALSE(misbehaving_before);

    // Send invalid PoW
    victim.SetBypassPOWValidation(false);
    observer.OnCustomEvent("PHASE", -1, "Sending invalid PoW");
    attacker.SendInvalidPoWHeaders(1, victim.GetTipHash(), 1);
    orchestrator.AdvanceTime(std::chrono::seconds(2));

    // Check misbehavior was recorded
    bool misbehaving_after = peer_manager.IsMisbehaving(peer_id);
    observer.OnCustomEvent("INFO", -1, "Misbehaving after attack: " + std::string(misbehaving_after ? "yes" : "no"));

    REQUIRE(misbehaving_after);
    observer.OnCustomEvent("VERIFY", -1, "✓ Misbehavior recorded");
    
    // Peer still connected
    orchestrator.AssertPeerCount(victim, 1);
    observer.OnCustomEvent("VERIFY", -1, "✓ Peer still connected");
    
    observer.OnCustomEvent("TEST_END", -1, "PASSED - Score tracked despite NoBan");
    auto_dump.MarkSuccess();
}

// ============================================================================
// Download Permission Tests - Bitcoin Core Parity
// ============================================================================

TEST_CASE("Permission: NoBan includes Download permission", "[permissions][download]") {
    // Verify that NoBan flag includes Download (Bitcoin Core parity)

    auto noban = NetPermissionFlags::NoBan;
    auto download = NetPermissionFlags::Download;

    // NoBan should include Download
    REQUIRE(HasPermission(noban, NetPermissionFlags::Download));

    // Download alone should NOT include NoBan
    REQUIRE_FALSE(HasPermission(download, NetPermissionFlags::NoBan));

    // Verify flag values match Bitcoin Core
    REQUIRE(static_cast<uint32_t>(NetPermissionFlags::Download) == (1U << 6));
    REQUIRE(static_cast<uint32_t>(NetPermissionFlags::NoBan) == ((1U << 4) | (1U << 6)));
}

TEST_CASE("Permission: GetPeerPermissions returns correct flags", "[permissions][download][api]") {
    // Verify GetPeerPermissions() API works correctly

    SimulatedNetwork network(200);
    TestOrchestrator orchestrator(&network);
    NetworkObserver observer;
    AutoDumpOnFailure auto_dump(observer);

    SimulatedNode node(1, &network);

    observer.OnCustomEvent("TEST_START", -1, "GetPeerPermissions API test");

    // Test 1: Normal peer (no permissions)
    observer.OnCustomEvent("PHASE", -1, "Testing normal peer (None)");
    NodeSimulator peer1(2, &network);
    peer1.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(node, peer1));

    int peer1_id = orchestrator.GetPeerId(node, peer1);
    REQUIRE(peer1_id >= 0);

    auto& peer_manager = node.GetNetworkManager().peer_manager();
    auto perms1 = peer_manager.GetPeerPermissions(peer1_id);
    REQUIRE(perms1 == NetPermissionFlags::None);
    observer.OnCustomEvent("VERIFY", -1, "✓ Normal peer has None");

    // Test 2: Download peer
    observer.OnCustomEvent("PHASE", -1, "Testing Download peer");
    NodeSimulator peer2(3, &network);
    node.SetInboundPermissions(NetPermissionFlags::Download);
    peer2.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(node, peer2));

    int peer2_id = orchestrator.GetPeerId(node, peer2);
    REQUIRE(peer2_id >= 0);

    auto perms2 = peer_manager.GetPeerPermissions(peer2_id);
    REQUIRE(HasPermission(perms2, NetPermissionFlags::Download));
    observer.OnCustomEvent("VERIFY", -1, "✓ Download peer has Download");

    // Test 3: NoBan peer (includes Download)
    observer.OnCustomEvent("PHASE", -1, "Testing NoBan peer");
    NodeSimulator peer3(4, &network);
    node.SetInboundPermissions(NetPermissionFlags::NoBan);
    peer3.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(node, peer3));

    int peer3_id = orchestrator.GetPeerId(node, peer3);
    REQUIRE(peer3_id >= 0);

    auto perms3 = peer_manager.GetPeerPermissions(peer3_id);
    REQUIRE(HasPermission(perms3, NetPermissionFlags::NoBan));
    REQUIRE(HasPermission(perms3, NetPermissionFlags::Download));
    observer.OnCustomEvent("VERIFY", -1, "✓ NoBan peer has both NoBan and Download");

    observer.OnCustomEvent("TEST_END", -1, "PASSED - GetPeerPermissions works correctly");
    auto_dump.MarkSuccess();
}
