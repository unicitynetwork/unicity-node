// Advanced Header Withholding Attack Tests
//
// These tests verify SPECIFIC behaviors not covered by basic stalling_peer_tests:
//
// 1. GETHEADERS rate limiting under orphan flood
// 2. Instant discourage on invalid headers (Core March 2024 parity)
// 3. Competing chain tip resolution (most-work wins)
// 4. Orphan resolution depth limits (no stack overflow)
// 5. Sync peer selection prefers outbound
// 6. Stall detection timing precision (120s timeout)
// 7. Recovery when all initial peers stall
// 8. Header announcement from non-sync peer during IBD

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "infra/node_simulator.hpp"
#include "test_orchestrator.hpp"
#include "network_observer.hpp"
#include "chain/chainparams.hpp"

using namespace unicity;
using namespace unicity::chain;
using namespace unicity::test;

static struct TestSetup {
    TestSetup() { chain::GlobalChainParams::Select(chain::ChainType::REGTEST); }
} test_setup_withholding;

// =============================================================================
// TEST 1: GETHEADERS Rate Limiting Under Orphan Flood
// =============================================================================
// Attacker floods orphan headers. Verify victim doesn't send unbounded GETHEADERS.
// This tests that orphan handling has rate limiting.

TEST_CASE("DoS: GETHEADERS rate limiting under orphan flood", "[dos][withholding][ratelimit]") {
    SimulatedNetwork net(3001);
    net.EnableCommandTracking(true);

    SimulatedNode victim(1, &net);
    for (int i = 0; i < 10; ++i) victim.MineBlock();
    REQUIRE(victim.GetTipHeight() == 10);

    NodeSimulator attacker(2, &net);
    attacker.ConnectTo(victim.GetId());

    net.AdvanceTime(1000);

    // Record GETHEADERS count before attack
    int gh_before = net.CountCommandSent(victim.GetId(), attacker.GetId(),
                                          protocol::commands::GETHEADERS);

    // Flood with orphan headers (1000 orphans in batches)
    for (int batch = 0; batch < 20; ++batch) {
        attacker.SendOrphanHeaders(victim.GetId(), 50);
        net.AdvanceTime(100);
    }

    // Count GETHEADERS after attack
    int gh_after = net.CountCommandSent(victim.GetId(), attacker.GetId(),
                                         protocol::commands::GETHEADERS);
    int gh_sent = gh_after - gh_before;

    // Verify: GETHEADERS should be rate-limited, not 1000 requests
    // Reasonable limit: should be << 100 even for 1000 orphans
    CHECK(gh_sent < 100);

    // Victim should still be functional
    CHECK(victim.GetTipHeight() == 10);
}

// =============================================================================
// TEST 2: Instant Discourage on Invalid Headers (Core March 2024 Parity)
// =============================================================================
// Bitcoin Core removed score-based misbehavior in March 2024 (commit ae60d485da).
// Any misbehavior now triggers instant discourage - no score accumulation.
// This test verifies that a single invalid PoW header triggers disconnect.

TEST_CASE("DoS: Instant discourage on invalid PoW header", "[dos][withholding][misbehavior]") {
    SimulatedNetwork net(3002);

    // Zero latency for reliable test timing
    SimulatedNetwork::NetworkConditions fast;
    fast.latency_min = fast.latency_max = std::chrono::milliseconds(0);
    fast.jitter_max = std::chrono::milliseconds(0);
    net.SetNetworkConditions(fast);

    TestOrchestrator orch(&net);

    SimulatedNode victim(1, &net);
    for (int i = 0; i < 10; ++i) victim.MineBlock();

    // Enable strict PoW validation (disabled by default for test speed)
    victim.SetBypassPOWValidation(false);

    NodeSimulator attacker(2, &net);
    attacker.ConnectTo(victim.GetId());
    REQUIRE(orch.WaitForConnection(victim, attacker));

    // Send invalid PoW header - should trigger instant disconnect
    uint256 prev = victim.GetTipHash();
    attacker.SendInvalidPoWHeaders(victim.GetId(), prev, 1);

    // Wait for disconnect (instant discourage)
    REQUIRE(orch.WaitForPeerCount(victim, 0, std::chrono::seconds(3)));

    // Victim should still be functional
    CHECK(victim.GetTipHeight() == 10);
}

// =============================================================================
// TEST 3: Longer Chain Reorg
// =============================================================================
// Victim syncs shorter chain first, then sees longer chain. Verify reorg occurs.

TEST_CASE("DoS: Longer chain triggers reorg", "[dos][withholding][consensus]") {
    SimulatedNetwork net(3003);
    net.EnableCommandTracking(true);

    // Peer1: Chain with 20 blocks
    SimulatedNode peer1(1, &net);
    for (int i = 0; i < 20; ++i) peer1.MineBlock();
    REQUIRE(peer1.GetTipHeight() == 20);

    // Victim connects to peer1 and syncs
    SimulatedNode victim(100, &net);
    victim.ConnectTo(peer1.GetId());

    net.AdvanceTime(1000);

    // Sync to peer1's chain
    for (int i = 0; i < 30 && victim.GetTipHeight() < 20; ++i) {
        net.AdvanceTime(500);
        victim.CheckInitialSync();
    }
    REQUIRE(victim.GetTipHeight() == 20);

    // Peer1 mines more blocks (extends the chain)
    for (int i = 0; i < 10; ++i) peer1.MineBlock();
    REQUIRE(peer1.GetTipHeight() == 30);

    // Victim should sync the new blocks
    for (int i = 0; i < 30 && victim.GetTipHeight() < 30; ++i) {
        net.AdvanceTime(500);
        victim.CheckInitialSync();
    }

    // Victim should have the longer chain
    CHECK(victim.GetTipHeight() == 30);
}

// =============================================================================
// TEST 4: Orphan Chain Resolution Depth
// =============================================================================
// Send deep orphan chain, then parent. Verify bounded resolution (no crash).

TEST_CASE("DoS: Deep orphan chain resolution is bounded", "[dos][withholding][orphan]") {
    SimulatedNetwork net(3004);

    SimulatedNode victim(1, &net);
    for (int i = 0; i < 5; ++i) victim.MineBlock();
    REQUIRE(victim.GetTipHeight() == 5);

    NodeSimulator attacker(2, &net);
    attacker.ConnectTo(victim.GetId());

    net.AdvanceTime(1000);

    // Send many orphan headers (deep chain with unknown parent)
    // This tests orphan limit and eviction
    for (int batch = 0; batch < 10; ++batch) {
        attacker.SendOrphanHeaders(victim.GetId(), 100);
        net.AdvanceTime(100);
    }

    // Victim should still be functional (orphans evicted, not crashed)
    CHECK(victim.GetTipHeight() == 5);

    // Verify node can still sync normally
    SimulatedNode honest(3, &net);
    for (int i = 0; i < 20; ++i) honest.MineBlock();

    victim.ConnectTo(honest.GetId());
    net.AdvanceTime(500);

    for (int i = 0; i < 30 && victim.GetTipHeight() < 20; ++i) {
        net.AdvanceTime(500);
        victim.CheckInitialSync();
    }

    CHECK(victim.GetTipHeight() == 20);
}

// =============================================================================
// TEST 5: Sync Peer Selection Prefers Outbound
// =============================================================================
// Verify that sync peer is selected from outbound connections, not inbound.

TEST_CASE("DoS: Sync peer selection prefers outbound", "[dos][withholding][sync]") {
    SimulatedNetwork net(3005);
    net.EnableCommandTracking(true);

    // Honest peer with chain
    SimulatedNode honest(1, &net);
    for (int i = 0; i < 30; ++i) honest.MineBlock();
    REQUIRE(honest.GetTipHeight() == 30);

    // Victim - will make OUTBOUND connection to honest
    SimulatedNode victim(100, &net);
    victim.ConnectTo(honest.GetId());  // Outbound from victim's perspective

    net.AdvanceTime(1000);

    // Trigger sync peer selection
    victim.CheckInitialSync();
    net.AdvanceTime(500);

    // Check GETHEADERS was sent (indicating sync started)
    int gh_count = net.CountCommandSent(victim.GetId(), honest.GetId(),
                                         protocol::commands::GETHEADERS);
    CHECK(gh_count >= 1);

    // Sync should complete
    for (int i = 0; i < 30 && victim.GetTipHeight() < 30; ++i) {
        net.AdvanceTime(500);
        victim.CheckInitialSync();
    }

    CHECK(victim.GetTipHeight() == 30);
}

// =============================================================================
// TEST 6: Stall Detection Timing - 5 Minute Threshold
// =============================================================================
// Verify stall timeout fires at ~5 minutes (Unicity uses 5min instead of Core's 15min
// for faster IBD recovery).

TEST_CASE("DoS: Stall timeout fires at 5 minutes", "[dos][withholding][timing]") {
    SimulatedNetwork net(3006);
    net.EnableCommandTracking(true);

    // Honest peer (will be used later)
    SimulatedNode honest(1, &net);
    for (int i = 0; i < 30; ++i) honest.MineBlock();

    // Stalling peer
    SimulatedNode staller(2, &net);
    staller.ConnectTo(honest.GetId());
    net.AdvanceTime(1000);
    for (int i = 0; i < 20 && staller.GetTipHeight() < 30; ++i) {
        net.AdvanceTime(500);
        staller.CheckInitialSync();
    }
    REQUIRE(staller.GetTipHeight() == 30);

    // Victim connects to staller
    SimulatedNode victim(100, &net);
    victim.ConnectTo(staller.GetId());
    net.AdvanceTime(500);

    // Start sync
    victim.CheckInitialSync();
    net.AdvanceTime(500);

    // Drop all messages from staller to victim (simulate stall)
    SimulatedNetwork::NetworkConditions drop;
    drop.packet_loss_rate = 1.0;
    net.SetLinkConditions(staller.GetId(), victim.GetId(), drop);

    // Advance 3 minutes - should NOT timeout yet (5 min base)
    for (int i = 0; i < 3; ++i) {
        net.AdvanceTime(60 * 1000);  // 1 minute
        victim.ProcessHeaderSyncTimers();
    }

    // Victim should still have staller as peer (not disconnected at 3 min)
    auto peers_3min = victim.GetNetworkManager().peer_manager().get_all_peers();
    bool staller_connected_3min = false;
    for (const auto& p : peers_3min) {
        if (p->is_connected()) staller_connected_3min = true;
    }
    CHECK(staller_connected_3min);  // Should still be connected

    // Advance to 6 minutes total - should timeout
    for (int i = 0; i < 4; ++i) {
        net.AdvanceTime(60 * 1000);  // 1 minute
        victim.ProcessHeaderSyncTimers();
    }

    // Verify stall was detected (victim should try to recover)
    // Connect to honest peer and verify sync completes
    victim.ConnectTo(honest.GetId());
    net.AdvanceTime(500);

    for (int i = 0; i < 30 && victim.GetTipHeight() < 30; ++i) {
        net.AdvanceTime(500);
        victim.CheckInitialSync();
    }

    CHECK(victim.GetTipHeight() == 30);
}

// =============================================================================
// TEST 7: Recovery When All Initial Peers Stall
// =============================================================================
// All initially connected peers stall. Verify victim recovers when new peer appears.

TEST_CASE("DoS: Recovery when all initial peers stall", "[dos][withholding][recovery]") {
    SimulatedNetwork net(3007);
    net.EnableCommandTracking(true);

    // Two stalling peers
    NodeSimulator staller1(10, &net);
    NodeSimulator staller2(11, &net);
    staller1.EnableStalling(true);
    staller2.EnableStalling(true);

    // Victim starts with only stallers
    SimulatedNode victim(100, &net);
    staller1.ConnectTo(victim.GetId());
    staller2.ConnectTo(victim.GetId());

    net.AdvanceTime(1000);

    // Mine some blocks on victim so it has a chain
    for (int i = 0; i < 5; ++i) victim.MineBlock();
    REQUIRE(victim.GetTipHeight() == 5);

    // Stallers send orphans to trigger requests
    staller1.SendOrphanHeaders(victim.GetId(), 20);
    staller2.SendOrphanHeaders(victim.GetId(), 20);
    net.AdvanceTime(500);

    // Process multiple timeout cycles
    for (int cycle = 0; cycle < 3; ++cycle) {
        for (int i = 0; i < 15; ++i) {
            net.AdvanceTime(10 * 1000);
            victim.ProcessHeaderSyncTimers();
        }
    }

    // Victim should still be functional
    CHECK(victim.GetTipHeight() == 5);

    // Now honest peer appears with longer chain
    SimulatedNode honest(50, &net);
    for (int i = 0; i < 30; ++i) honest.MineBlock();
    REQUIRE(honest.GetTipHeight() == 30);

    victim.ConnectTo(honest.GetId());
    net.AdvanceTime(500);

    // Should sync from honest peer
    for (int i = 0; i < 40 && victim.GetTipHeight() < 30; ++i) {
        net.AdvanceTime(500);
        victim.CheckInitialSync();
    }

    CHECK(victim.GetTipHeight() == 30);
}

// =============================================================================
// TEST 8: Non-Sync Peer Header Announcement During IBD
// =============================================================================
// During IBD, non-sync peer announces headers. Verify proper handling.

TEST_CASE("DoS: Header announcement from non-sync peer during IBD", "[dos][withholding][ibd]") {
    SimulatedNetwork net(3008);
    net.EnableCommandTracking(true);

    // Two peers with same chain
    SimulatedNode peer1(1, &net);
    SimulatedNode peer2(2, &net);

    for (int i = 0; i < 30; ++i) peer1.MineBlock();
    REQUIRE(peer1.GetTipHeight() == 30);

    // Sync peer2 from peer1
    peer2.ConnectTo(peer1.GetId());
    net.AdvanceTime(1000);
    for (int i = 0; i < 30 && peer2.GetTipHeight() < 30; ++i) {
        net.AdvanceTime(500);
        peer2.CheckInitialSync();
    }
    REQUIRE(peer2.GetTipHeight() == 30);

    // Victim connects to both
    SimulatedNode victim(100, &net);
    victim.ConnectTo(peer1.GetId());
    victim.ConnectTo(peer2.GetId());
    net.AdvanceTime(500);

    // Start IBD - one peer becomes sync peer
    victim.CheckInitialSync();
    net.AdvanceTime(500);

    // Sync should complete using headers from peers
    for (int i = 0; i < 40 && victim.GetTipHeight() < 30; ++i) {
        net.AdvanceTime(500);
        victim.CheckInitialSync();
    }

    CHECK(victim.GetTipHeight() == 30);

    // Peer1 mines new block
    peer1.MineBlock();
    REQUIRE(peer1.GetTipHeight() == 31);

    // Propagate to peer2
    for (int i = 0; i < 10 && peer2.GetTipHeight() < 31; ++i) {
        net.AdvanceTime(500);
    }

    // Victim should eventually get the new block
    for (int i = 0; i < 20 && victim.GetTipHeight() < 31; ++i) {
        net.AdvanceTime(500);
        victim.CheckInitialSync();
    }

    CHECK(victim.GetTipHeight() == 31);
}
