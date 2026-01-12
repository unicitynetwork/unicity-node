// Block Announcement - Comprehensive integration test

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"

using namespace unicity;
using namespace unicity::test;

// Set no latency and jitter for deterministic timing
static void SetZeroLatency(SimulatedNetwork& network) {
    SimulatedNetwork::NetworkConditions cond{};
    cond.latency_min = std::chrono::milliseconds(0);
    cond.latency_max = std::chrono::milliseconds(0);
    cond.jitter_max = std::chrono::milliseconds(0);
    network.SetNetworkConditions(cond);
}

// Advance simulated time in small steps to mimic real network timing
static void AdvanceSeconds(SimulatedNetwork& network, int seconds) {
    for (int i = 0; i < seconds * 5; ++i) {
        network.AdvanceTime(network.GetCurrentTime() + 200);
    }
}

TEST_CASE("BlockAnnouncement - Comprehensive integration", "[block_announcement][integration]") {
    SimulatedNetwork network(12345);
    SetZeroLatency(network);
    network.EnableCommandTracking(true);

    // Create nodes
    SimulatedNode node0(0, &network);
    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);

    // Connect peers and make them READY
    node1.ConnectTo(0);
    node2.ConnectTo(0);
    AdvanceSeconds(network, 2);

    REQUIRE(node0.GetPeerCount() == 2);

    // Mine initial block - all READY peers should receive it
    int tip1_before = node1.GetTipHeight();
    int tip2_before = node2.GetTipHeight();

    (void)node0.MineBlock();
    AdvanceSeconds(network, 2);

    CHECK(node1.GetTipHeight() >= tip1_before + 1);
    CHECK(node2.GetTipHeight() >= tip2_before + 1);

    // Test announce_tip_to_peers and flush
    node0.GetNetworkManager().announce_tip_to_peers();
    node0.GetNetworkManager().flush_block_announcements();

    // Mine additional block and verify periodic reannounce after TTL expiry
    AdvanceSeconds(network, 11 * 60);  // advance > TTL

    int tip1_mid = node1.GetTipHeight();
    int tip2_mid = node2.GetTipHeight();

    (void)node0.MineBlock();
    AdvanceSeconds(network, 2);

    CHECK(node1.GetTipHeight() >= tip1_mid + 1);
    CHECK(node2.GetTipHeight() >= tip2_mid + 1);

    // Disconnect node2 and verify flush and announces are safe
    node2.DisconnectFrom(0);
    AdvanceSeconds(network, 1);

    REQUIRE(node0.GetPeerCount() == 1);

    // Should not crash
    node0.GetNetworkManager().flush_block_announcements();
    node0.GetNetworkManager().announce_tip_to_peers();

    // Final block mining - remaining peer should receive it
    int tip1_final_before = node1.GetTipHeight();

    (void)node0.MineBlock();
    AdvanceSeconds(network, 2);

    CHECK(node1.GetTipHeight() >= tip1_final_before + 1);
}
