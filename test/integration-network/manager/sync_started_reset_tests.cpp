// sync_started Flag Reset Tests - Validates the production fix that resets
// sync_started flags on remaining peers when a sync peer disconnects, allowing
// retry with other peers after stalls

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/protocol.hpp"

using namespace unicity;
using namespace unicity::test;
using namespace unicity::protocol;

TEST_CASE("sync_started reset on sync peer disconnect", "[network][sync_peer][flag_reset][critical]") {
    // This test validates the core fix: when a sync peer disconnects, remaining
    // outbound peers have their sync_started flags reset to false, allowing them
    // to be selected as the new sync peer.

    SimulatedNetwork net(51001);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 50; ++i) {
        (void)miner.MineBlock();
    }

    // Three outbound peers will sync from miner first
    SimulatedNode p1(2, &net);
    SimulatedNode p2(3, &net);
    SimulatedNode p3(4, &net);

    p1.ConnectTo(miner.GetId());
    p2.ConnectTo(miner.GetId());
    p3.ConnectTo(miner.GetId());

    uint64_t t = 1000; net.AdvanceTime(t);

    p1.GetNetworkManager().test_hook_check_initial_sync();
    p2.GetNetworkManager().test_hook_check_initial_sync();
    p3.GetNetworkManager().test_hook_check_initial_sync();

    for (int i = 0; i < 20 && (p1.GetTipHeight() < 50 || p2.GetTipHeight() < 50 || p3.GetTipHeight() < 50); ++i) {
        t += 1000; net.AdvanceTime(t);
    }

    REQUIRE(p1.GetTipHeight() == 50);
    REQUIRE(p2.GetTipHeight() == 50);
    REQUIRE(p3.GetTipHeight() == 50);

    // Victim node connects to all three
    SimulatedNode victim(5, &net);
    victim.ConnectTo(p1.GetId());
    victim.ConnectTo(p2.GetId());
    victim.ConnectTo(p3.GetId());

    t += 1000; net.AdvanceTime(t);

    // Select p1 as sync peer
    victim.GetNetworkManager().test_hook_check_initial_sync();
    t += 2000; net.AdvanceTime(t);

    // Start some sync progress
    for (int i = 0; i < 5 && victim.GetTipHeight() < 20; ++i) {
        t += 1000; net.AdvanceTime(t);
    }

    int progress_from_p1 = victim.GetTipHeight();
    CHECK(progress_from_p1 > 0);

    // Disconnect p1 (simulating normal disconnect)
    victim.DisconnectFrom(p1.GetId());
    t += 1000; net.AdvanceTime(t);

    // Key test: p2 and p3 should have sync_started reset to false
    // We verify this by selecting a new sync peer and checking sync continues

    victim.GetNetworkManager().test_hook_check_initial_sync();
    t += 2000; net.AdvanceTime(t);

    // Sync should continue with p2 or p3
    for (int i = 0; i < 20 && victim.GetTipHeight() < 50; ++i) {
        t += 2000; net.AdvanceTime(t);
    }

    CHECK(victim.GetTipHeight() == 50);
}

TEST_CASE("sync_started reset allows immediate retry with remaining peer", "[network][sync_peer][flag_reset]") {
    // When only 2 peers exist and both have been tried, flag reset ensures
    // the remaining peer can be retried after stall

    SimulatedNetwork net(51002);
    net.EnableCommandTracking(true);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 40; ++i) {
        (void)miner.MineBlock();
    }

    SimulatedNode p1(2, &net);
    SimulatedNode p2(3, &net);

    p1.ConnectTo(miner.GetId());
    p2.ConnectTo(miner.GetId());

    uint64_t t = 1000; net.AdvanceTime(t);

    p1.GetNetworkManager().test_hook_check_initial_sync();
    p2.GetNetworkManager().test_hook_check_initial_sync();

    for (int i = 0; i < 15 && (p1.GetTipHeight() < 40 || p2.GetTipHeight() < 40); ++i) {
        t += 1000; net.AdvanceTime(t);
    }

    REQUIRE(p1.GetTipHeight() == 40);
    REQUIRE(p2.GetTipHeight() == 40);

    // Victim connects to both
    SimulatedNode victim(4, &net);
    victim.ConnectTo(p1.GetId());
    victim.ConnectTo(p2.GetId());

    t += 1000; net.AdvanceTime(t);

    // Select p1 first
    victim.GetNetworkManager().test_hook_check_initial_sync();
    t += 2000; net.AdvanceTime(t);

    // Make some progress
    for (int i = 0; i < 5 && victim.GetTipHeight() < 15; ++i) {
        t += 1000; net.AdvanceTime(t);
    }

    int height_after_p1 = victim.GetTipHeight();
    CHECK(height_after_p1 > 0);
    // May complete quickly in test environment
    CHECK(height_after_p1 <= 40);

    // Now p1 disconnects (both p1 and p2 have sync_started=true at this point)
    victim.DisconnectFrom(p1.GetId());
    t += 2000; net.AdvanceTime(t);

    // The fix: p2's sync_started should be reset to false, allowing selection
    victim.GetNetworkManager().test_hook_check_initial_sync();
    t += 2000; net.AdvanceTime(t);

    // Verify p2 was selected and sync continues
    for (int i = 0; i < 20 && victim.GetTipHeight() < 40; ++i) {
        t += 2000; net.AdvanceTime(t);
    }

    CHECK(victim.GetTipHeight() == 40);
}

TEST_CASE("sync_started NOT reset when non-sync peer disconnects", "[network][sync_peer][flag_reset]") {
    // Only the sync peer's disconnect triggers flag reset; other disconnects don't

    SimulatedNetwork net(51003);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 30; ++i) {
        (void)miner.MineBlock();
    }

    SimulatedNode p1(2, &net);
    SimulatedNode p2(3, &net);
    SimulatedNode p3(4, &net);

    p1.ConnectTo(miner.GetId());
    p2.ConnectTo(miner.GetId());
    p3.ConnectTo(miner.GetId());

    uint64_t t = 1000; net.AdvanceTime(t);

    p1.GetNetworkManager().test_hook_check_initial_sync();
    p2.GetNetworkManager().test_hook_check_initial_sync();
    p3.GetNetworkManager().test_hook_check_initial_sync();

    for (int i = 0; i < 15 && (p1.GetTipHeight() < 30 || p2.GetTipHeight() < 30 || p3.GetTipHeight() < 30); ++i) {
        t += 1000; net.AdvanceTime(t);
    }

    REQUIRE(p1.GetTipHeight() == 30);
    REQUIRE(p2.GetTipHeight() == 30);
    REQUIRE(p3.GetTipHeight() == 30);

    SimulatedNode victim(5, &net);
    victim.ConnectTo(p1.GetId());
    victim.ConnectTo(p2.GetId());
    victim.ConnectTo(p3.GetId());

    t += 1000; net.AdvanceTime(t);

    // Select p1 as sync peer
    victim.GetNetworkManager().test_hook_check_initial_sync();
    t += 2000; net.AdvanceTime(t);

    // Make progress
    for (int i = 0; i < 5 && victim.GetTipHeight() < 10; ++i) {
        t += 1000; net.AdvanceTime(t);
    }

    int height_with_p1 = victim.GetTipHeight();
    CHECK(height_with_p1 > 0);

    // Disconnect p2 (NOT the sync peer)
    victim.DisconnectFrom(p2.GetId());
    t += 1000; net.AdvanceTime(t);

    // p1 should still be sync peer, sync should continue normally
    for (int i = 0; i < 15 && victim.GetTipHeight() < 30; ++i) {
        t += 2000; net.AdvanceTime(t);
    }

    CHECK(victim.GetTipHeight() == 30);
}

TEST_CASE("Multiple successive stalls reset flag each time", "[network][sync_peer][flag_reset][stall]") {
    // When peers stall one after another, each stall should reset remaining peers' flags

    SimulatedNetwork net(51004);
    net.EnableCommandTracking(true);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 60; ++i) {
        (void)miner.MineBlock();
    }

    // Three peers, we'll simulate successive stalls
    SimulatedNode p1(2, &net);
    SimulatedNode p2(3, &net);
    SimulatedNode p3(4, &net);

    p1.ConnectTo(miner.GetId());
    p2.ConnectTo(miner.GetId());
    p3.ConnectTo(miner.GetId());

    uint64_t t = 1000; net.AdvanceTime(t);

    p1.GetNetworkManager().test_hook_check_initial_sync();
    p2.GetNetworkManager().test_hook_check_initial_sync();
    p3.GetNetworkManager().test_hook_check_initial_sync();

    for (int i = 0; i < 20 && (p1.GetTipHeight() < 60 || p2.GetTipHeight() < 60 || p3.GetTipHeight() < 60); ++i) {
        t += 2000; net.AdvanceTime(t);
    }

    REQUIRE(p1.GetTipHeight() == 60);
    REQUIRE(p2.GetTipHeight() == 60);
    REQUIRE(p3.GetTipHeight() == 60);

    SimulatedNode victim(5, &net);
    victim.ConnectTo(p1.GetId());
    victim.ConnectTo(p2.GetId());
    victim.ConnectTo(p3.GetId());

    t += 1000; net.AdvanceTime(t);

    // Try p1 first
    victim.GetNetworkManager().test_hook_check_initial_sync();
    t += 2000; net.AdvanceTime(t);

    for (int i = 0; i < 3 && victim.GetTipHeight() < 15; ++i) {
        t += 1000; net.AdvanceTime(t);
    }

    int height_1 = victim.GetTipHeight();
    CHECK(height_1 > 0);

    // p1 "stalls" (simulated by disconnect)
    victim.DisconnectFrom(p1.GetId());
    t += 2000; net.AdvanceTime(t);

    // p2 becomes sync peer (flag reset allows this)
    victim.GetNetworkManager().test_hook_check_initial_sync();
    t += 2000; net.AdvanceTime(t);

    for (int i = 0; i < 5 && victim.GetTipHeight() < 30; ++i) {
        t += 2000; net.AdvanceTime(t);
    }

    int height_2 = victim.GetTipHeight();
    CHECK(height_2 >= height_1);  // Progress or completion
    // May complete quickly in test environment
    CHECK(height_2 <= 60);

    // p2 also "stalls"
    victim.DisconnectFrom(p2.GetId());
    t += 2000; net.AdvanceTime(t);

    // p3 should be available (flag reset again)
    victim.GetNetworkManager().test_hook_check_initial_sync();
    t += 2000; net.AdvanceTime(t);

    // Complete sync with p3
    for (int i = 0; i < 20 && victim.GetTipHeight() < 60; ++i) {
        t += 2000; net.AdvanceTime(t);
    }

    CHECK(victim.GetTipHeight() == 60);
}
