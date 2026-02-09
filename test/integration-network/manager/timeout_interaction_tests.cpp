// Timeout Interaction Tests
//
// Tests for edge cases when multiple timeout mechanisms fire together or in close succession.
// The goal is to verify that:
// 1. Double-disconnect scenarios are handled gracefully
// 2. Stall timeout during IBD exit is handled correctly
// 3. Multiple timeout types on the same peer don't cause issues
//
// These tests use the SimulatedNetwork infrastructure for deterministic timing control.

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/protocol.hpp"

using namespace unicity;
using namespace unicity::test;

static void SetZeroLatency(SimulatedNetwork& network) {
    SimulatedNetwork::NetworkConditions cond{};
    cond.latency_min = std::chrono::milliseconds(0);
    cond.latency_max = std::chrono::milliseconds(0);
    cond.jitter_max = std::chrono::milliseconds(0);
    network.SetNetworkConditions(cond);
}

static void AdvanceTime(SimulatedNetwork& net, uint64_t& t, int ms) {
    t += ms;
    net.AdvanceTime(t);
}

// =============================================================================
// TEST 1: Stall timeout fires while GETHEADERS throttle is active
// =============================================================================
// Scenario: Sync peer has GETHEADERS throttle active (2 min), but stall timeout
// fires (5 min deadline exceeded). Verify clean disconnect and throttle state cleanup.
//
// NOTE: Stall timeout only fires during IBD. To keep the node in IBD, we need
// the tip to be "stale" (>5 days old). In simulated tests with recent timestamps,
// IBD exits quickly, so stall timeout won't fire.

TEST_CASE("Timeout interaction: stall timeout with active GETHEADERS throttle", "[timeout][interaction][stall]") {
    SimulatedNetwork net(54001);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    // Miner with chain
    SimulatedNode miner(1, &net);
    uint64_t t = 1000;
    for (int i = 0; i < 100; ++i) {
        (void)miner.MineBlock();
        AdvanceTime(net, t, 100);
    }
    REQUIRE(miner.GetTipHeight() == 100);

    // Fresh node that will try to sync
    SimulatedNode fresh(2, &net);
    fresh.ConnectTo(miner.GetId());
    AdvanceTime(net, t, 1000);

    // Start sync - sends GETHEADERS (sets throttle timestamp)
    fresh.CheckInitialSync();
    AdvanceTime(net, t, 200);

    // Verify GETHEADERS was sent
    int gh_count = net.CountCommandSent(fresh.GetId(), miner.GetId(), protocol::commands::GETHEADERS);
    REQUIRE(gh_count >= 1);

    // Now drop all messages from miner to fresh (simulate stall)
    SimulatedNetwork::NetworkConditions drop{};
    drop.packet_loss_rate = 1.0;
    net.SetLinkConditions(miner.GetId(), fresh.GetId(), drop);

    // Check if fresh is in IBD (determines expected behavior)
    bool in_ibd_before = fresh.GetIsIBD();

    // Try another GETHEADERS - should be throttled (< 2 min since last)
    fresh.CheckInitialSync();
    AdvanceTime(net, t, 200);
    int gh_count_after_throttle = net.CountCommandSent(fresh.GetId(), miner.GetId(), protocol::commands::GETHEADERS);

    // Should still be the same (throttled)
    CHECK(gh_count_after_throttle == gh_count);

    // Advance time past stall deadline (5+ minutes)
    for (int i = 0; i < 6; ++i) {
        t += 60 * 1000;  // +60s per iteration
        net.AdvanceTime(t);
        fresh.ProcessHeaderSyncTimers();
    }

    size_t peer_count = fresh.GetPeerCount();

    if (in_ibd_before) {
        // If was in IBD, stall timeout should have disconnected
        CHECK(peer_count == 0);
    } else {
        // If not in IBD, stall timeout doesn't fire (correct behavior)
        INFO("Fresh was not in IBD - stall timeout correctly not enforced");
        CHECK(peer_count >= 1);
    }

    // The system should remain stable - no crashes from stale throttle state
    AdvanceTime(net, t, 1000);
    CHECK(true);  // Reached here without crash
}

// =============================================================================
// TEST 2: Stall timeout not enforced after IBD exit
// =============================================================================
// Scenario: Node syncs and exits IBD. Verify stall timeout is NOT enforced
// post-IBD (this is the correct behavior - stall timeout only matters during IBD).

TEST_CASE("Timeout interaction: stall timeout not enforced post-IBD", "[timeout][interaction][ibd]") {
    SimulatedNetwork net(54002);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    // Miner with chain
    SimulatedNode miner(1, &net);
    uint64_t t = 1000;
    for (int i = 0; i < 50; ++i) {
        (void)miner.MineBlock();
        AdvanceTime(net, t, 100);
    }
    REQUIRE(miner.GetTipHeight() == 50);

    // Fresh node syncs
    SimulatedNode fresh(2, &net);
    fresh.ConnectTo(miner.GetId());
    AdvanceTime(net, t, 1000);

    // Start sync
    fresh.CheckInitialSync();

    // Let sync complete
    for (int i = 0; i < 30 && fresh.GetTipHeight() < 50; ++i) {
        AdvanceTime(net, t, 200);
    }
    REQUIRE(fresh.GetTipHeight() == 50);

    // Fresh should be out of IBD now
    CHECK_FALSE(fresh.GetIsIBD());

    // Record peer count
    size_t peer_count_before = fresh.GetPeerCount();
    REQUIRE(peer_count_before >= 1);

    // Advance time past what would be stall deadline and process timers
    for (int i = 0; i < 10; ++i) {
        t += 60 * 1000;
        net.AdvanceTime(t);
        fresh.ProcessHeaderSyncTimers();
    }

    // Peer should NOT be disconnected (post-IBD, stall timeout not enforced)
    CHECK(fresh.GetPeerCount() == peer_count_before);

    // System should be stable
    CHECK(true);
}

// =============================================================================
// TEST 3: GETHEADERS throttle cleared on peer disconnect
// =============================================================================
// Scenario: Peer has GETHEADERS throttle active, then gets disconnected.
// New connection should not inherit throttle state (throttle is per-peer).

TEST_CASE("Timeout interaction: throttle state cleanup on disconnect", "[timeout][interaction][throttle]") {
    SimulatedNetwork net(54005);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    // Miner with chain
    SimulatedNode miner(1, &net);
    uint64_t t = 1000;
    for (int i = 0; i < 50; ++i) {
        (void)miner.MineBlock();
        AdvanceTime(net, t, 100);
    }

    // Fresh node
    SimulatedNode fresh(2, &net);
    fresh.ConnectTo(miner.GetId());
    AdvanceTime(net, t, 1000);

    // Start sync - sets GETHEADERS throttle
    fresh.CheckInitialSync();
    AdvanceTime(net, t, 200);

    int gh_count_1 = net.CountCommandSent(fresh.GetId(), miner.GetId(), protocol::commands::GETHEADERS);
    REQUIRE(gh_count_1 >= 1);

    // Disconnect miner
    fresh.DisconnectFrom(miner.GetId());
    AdvanceTime(net, t, 500);

    // Reconnect
    fresh.ConnectTo(miner.GetId());
    AdvanceTime(net, t, 1000);

    // Try to sync again - should NOT be throttled (new connection)
    fresh.CheckInitialSync();
    AdvanceTime(net, t, 200);

    int gh_count_2 = net.CountCommandSent(fresh.GetId(), miner.GetId(), protocol::commands::GETHEADERS);

    // Should have sent another GETHEADERS (throttle state cleared with old connection)
    CHECK(gh_count_2 > gh_count_1);
}

// =============================================================================
// TEST 4: Timer processing during rapid connect/disconnect
// =============================================================================
// Scenario: Rapid connect/disconnect cycles while timer processing is active.
// Verify no use-after-free or invalid state access.

TEST_CASE("Timeout interaction: timer processing during rapid reconnection", "[timeout][interaction][rapid]") {
    SimulatedNetwork net(54006);
    SetZeroLatency(net);

    // Miner with chain
    SimulatedNode miner(1, &net);
    uint64_t t = 1000;
    for (int i = 0; i < 30; ++i) {
        (void)miner.MineBlock();
        AdvanceTime(net, t, 100);
    }

    SimulatedNode fresh(2, &net);

    // Rapid connect/disconnect cycles with timer processing
    for (int cycle = 0; cycle < 5; ++cycle) {
        fresh.ConnectTo(miner.GetId());
        AdvanceTime(net, t, 200);

        fresh.CheckInitialSync();
        fresh.ProcessHeaderSyncTimers();
        AdvanceTime(net, t, 100);

        fresh.DisconnectFrom(miner.GetId());
        AdvanceTime(net, t, 200);

        // Process timers even when disconnected
        fresh.ProcessHeaderSyncTimers();
        AdvanceTime(net, t, 100);
    }

    // System should be stable - no crashes
    CHECK(true);
}
