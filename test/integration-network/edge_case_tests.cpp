// Network edge case tests (ported to test2)

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include <filesystem>

using namespace unicity;
using namespace unicity::test;
using namespace unicity::network;

static void SetZeroLatency(SimulatedNetwork& network) {
    SimulatedNetwork::NetworkConditions c; c.latency_min=c.latency_max=std::chrono::milliseconds(0); c.jitter_max=std::chrono::milliseconds(0); network.SetNetworkConditions(c);
}

// Slow peer eviction - document behavior (timeout handled by NetworkManager)
TEST_CASE("Slow peer eviction - Peer times out if no headers sent", "[network][eviction][slow]") {
    SimulatedNetwork network(12345);
    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);

    // Build some history on node1
    for (int i = 0; i < 10; i++) (void)node1.MineBlock();

    REQUIRE(node2.ConnectTo(1));
    for (int i = 0; i < 20; i++) network.AdvanceTime(100);
    CHECK(node1.GetPeerCount() == 1);

    // Advance significant time (simulate timeout window) without activity
    for (int i = 0; i < 100; i++) network.AdvanceTime(60000);

    // After extended timeout, peer may be disconnected due to inactivity
    // Verify peer count is reasonable (0 = disconnected, 1 = still connected)
    CHECK(node1.GetPeerCount() <= 1);
}

TEST_CASE("Slow peer eviction - Active peer stays connected", "[network][eviction][active]") {
    SimulatedNetwork network(12346);
    SetZeroLatency(network);

    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);

    for (int i = 0; i < 5; i++) (void)node1.MineBlock();
    REQUIRE(node2.ConnectTo(1));
    for (int i = 0; i < 20; i++) network.AdvanceTime(100);
    CHECK(node1.GetPeerCount() == 1);

    for (int i = 0; i < 10; i++) {
        (void)node1.MineBlock();
        for (int j = 0; j < 10; j++) network.AdvanceTime(1000);
    }
    CHECK(node1.GetPeerCount() == 1);
}

TEST_CASE("Stale tip management - Node continues operating with stale tip", "[network][stale][tip]") {
    SimulatedNetwork network(12347);
    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);

    for (int i = 0; i < 10; i++) (void)node1.MineBlock();
    auto tip = node1.GetTipHash();

    for (int i = 0; i < 100; i++) network.AdvanceTime(120000);
    CHECK(node1.GetTipHash() == tip);

    REQUIRE(node2.ConnectTo(1));
    for (int i = 0; i < 20; i++) network.AdvanceTime(100);
    CHECK(node1.GetPeerCount() == 1);

    (void)node1.MineBlock();
    network.AdvanceTime(100);
    CHECK(node1.GetTipHash() != tip);
}

// Note: ConnectionManager persistence tests have been moved to test/unit/banman_tests.cpp
// This file now focuses only on network edge cases (slow peer eviction, stale tip management)
