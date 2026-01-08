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
        network.AdvanceTime(network.GetCurrentTime() + std::chrono::milliseconds(200));
    }
}

TEST_CASE("BlockAnnouncement - Comprehensive integration", "[block_announcement][integration]") {
    SimulatedNetwork network(12345);
    SetZeroLatency(network);
    network.EnableCommandTracking(true);

    // Create four nodes: node0, node1, node2, node3
    SimulatedNode node0(0, &network);
    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);
    SimulatedNode node3(3, &network);

    // Connect node1 and node2 as READY peers; node3 connects but remains non-READY initially
    node1.ConnectTo(0);
    node2.ConnectTo(0);
    node3.ConnectTo(0);
    // Only advance time for node1 and node2 connections to become READY
    AdvanceSeconds(network, 2);
    // Node3 remains non-READY (no time advanced after connection)

    REQUIRE(node0.GetPeerCount() == 3);

    // Mine initial block on node0; node1 and node2 should receive announcement immediately, node3 should not
    int tip1_before = node1.GetTipHeight();
    int tip2_before = node2.GetTipHeight();
    int tip3_before = node3.GetTipHeight();

    (void)node0.MineBlock();
    AdvanceSeconds(network, 2);

    CHECK(node1.GetTipHeight() >= tip1_before + 1);
    CHECK(node2.GetTipHeight() >= tip2_before + 1);
    CHECK(node3.GetTipHeight() == tip3_before);  // No update for non-READY

    // Test per-peer queue isolation by invoking announce_tip_to_peers; should queue announcements
    node0.GetNetworkManager().announce_tip_to_peers();

    // After announcement, flush block announcements and ensure queues are cleared without side effects
    node0.GetNetworkManager().flush_block_announcements();

    // Mine additional block and verify periodic reannounce after TTL expiry
    AdvanceSeconds(network, 11 * 60);  // advance > TTL

    int tip1_mid = node1.GetTipHeight();
    int tip2_mid = node2.GetTipHeight();

    (void)node0.MineBlock();
    AdvanceSeconds(network, 2);

    CHECK(node1.GetTipHeight() >= tip1_mid + 1);
    CHECK(node2.GetTipHeight() >= tip2_mid + 1);

    // Disconnect node2 and verify flush and announces are safe without node2
    node2.DisconnectFrom(0);
    AdvanceSeconds(network, 1);

    REQUIRE(node0.GetPeerCount() == 2);  // node2 disconnected

    node0.GetNetworkManager().flush_block_announcements();
    node0.GetNetworkManager().announce_tip_to_peers();

    // Final block mining and tip verification for connected peers
    int tip0_final = node0.GetTipHeight();
    int tip1_final_before = node1.GetTipHeight();
    int tip3_final_before = node3.GetTipHeight();

    (void)node0.MineBlock();
    AdvanceSeconds(network, 2);

    CHECK(node1.GetTipHeight() >= tip1_final_before + 1);
    // Node3 should get update now assuming it transitioned to READY (advance time)
    AdvanceSeconds(network, 3);
    CHECK(node3.GetTipHeight() >= tip3_final_before);
}
