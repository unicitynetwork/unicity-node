// Block Announcement - Basic tests (direct HEADERS)

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"

using namespace unicity;
using namespace unicity::test;

static void SetZeroLatency(SimulatedNetwork& network) {
    SimulatedNetwork::NetworkConditions conditions;
    conditions.latency_min = std::chrono::milliseconds(0);
    conditions.latency_max = std::chrono::milliseconds(0);
    conditions.jitter_max = std::chrono::milliseconds(0);
    network.SetNetworkConditions(conditions);
}

static void AdvanceSeconds(SimulatedNetwork& net, int seconds) {
    for (int i = 0; i < seconds * 5; ++i) {
        net.AdvanceTime(200);
    }
}

static struct TestSetup {
    TestSetup() { chain::GlobalChainParams::Select(chain::ChainType::REGTEST); }
} setup_once;

TEST_CASE("Announcement - HEADERS on new block (immediate)", "[block_announcement][basic]") {
    SimulatedNetwork net(1001);
    SetZeroLatency(net);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);

    b.ConnectTo(1);
    AdvanceSeconds(net, 2);

    // Mine first block to exit IBD (IBD state captured before tip update)
    (void)a.MineBlock();
    AdvanceSeconds(net, 1);

    // Mine second block - post-IBD, announced via HEADERS
    int b_tip_before = b.GetTipHeight();
    (void)a.MineBlock();
    AdvanceSeconds(net, 2);

    // b should have synced
    CHECK(b.GetTipHeight() >= b_tip_before + 1);
}

TEST_CASE("Announcement - Multi-peer propagation", "[block_announcement][multi]") {
    SimulatedNetwork net(1004);
    SetZeroLatency(net);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);
    SimulatedNode c(3, &net);
    SimulatedNode d(4, &net);

    b.ConnectTo(1); c.ConnectTo(1); d.ConnectTo(1);
    AdvanceSeconds(net, 2);

    // Mine first block to exit IBD
    (void)a.MineBlock();
    AdvanceSeconds(net, 1);

    int b_tip_before = b.GetTipHeight();
    int c_tip_before = c.GetTipHeight();
    int d_tip_before = d.GetTipHeight();

    // Mine second block - post-IBD, all peers receive HEADERS
    (void)a.MineBlock();
    AdvanceSeconds(net, 2);

    CHECK(b.GetTipHeight() >= b_tip_before + 1);
    CHECK(c.GetTipHeight() >= c_tip_before + 1);
    CHECK(d.GetTipHeight() >= d_tip_before + 1);
}

TEST_CASE("Announcement - Competing forks propagate via HEADERS", "[block_announcement][fork]") {
    // A and B both connected to C (hub). A and B mine competing blocks at the
    // same height BEFORE the network processes messages. Both HEADERS reach C.
    // This catches any optimization that skips peers already at the same height
    // (which would break fork convergence).

    SimulatedNetwork net(1010);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);
    SimulatedNode c(3, &net);

    // Phase 1: Everyone syncs through A (B→A, C→A)
    b.ConnectTo(1);
    c.ConnectTo(1);
    AdvanceSeconds(net, 2);

    // A mines 2 blocks — announced to B and C directly
    (void)a.MineBlock();
    AdvanceSeconds(net, 2);
    (void)a.MineBlock();
    AdvanceSeconds(net, 2);

    // All at height 2
    REQUIRE(a.GetTipHeight() == 2);
    REQUIRE(b.GetTipHeight() == 2);
    REQUIRE(c.GetTipHeight() == 2);

    // Phase 2: Rearrange to star topology: A -- C -- B
    // Disconnect B from A, connect B to C
    b.Disconnect(1);
    AdvanceSeconds(net, 1);
    b.ConnectTo(3);
    AdvanceSeconds(net, 2);

    // Take HEADERS baseline before fork mining
    int baseline_a = net.CountCommandSent(a.GetId(), c.GetId(), protocol::commands::HEADERS);
    int baseline_b = net.CountCommandSent(b.GetId(), c.GetId(), protocol::commands::HEADERS);

    // Phase 3: Mine competing blocks BEFORE network delivers anything.
    // MineBlock calls ProcessEvents() on the local node only — messages
    // are queued in the SimulatedNetwork but not delivered until AdvanceTime.
    uint256 fork_a = a.MineBlock();
    REQUIRE(!fork_a.IsNull());
    REQUIRE(a.GetTipHeight() == 3);

    uint256 fork_b = b.MineBlock();
    REQUIRE(!fork_b.IsNull());
    REQUIRE(b.GetTipHeight() == 3);
    REQUIRE(fork_a != fork_b);  // Different blocks at same height

    // C is still at height 2 (no network delivery yet)
    REQUIRE(c.GetTipHeight() == 2);

    // Phase 4: Let the network deliver both HEADERS to C
    AdvanceSeconds(net, 2);

    // C received HEADERS from BOTH forks
    int headers_from_a = net.CountCommandSent(a.GetId(), c.GetId(), protocol::commands::HEADERS);
    int headers_from_b = net.CountCommandSent(b.GetId(), c.GetId(), protocol::commands::HEADERS);
    CHECK(headers_from_a > baseline_a);
    CHECK(headers_from_b > baseline_b);

    // C resolved to height 3 (first-seen fork wins, both valid)
    CHECK(c.GetTipHeight() == 3);
}
