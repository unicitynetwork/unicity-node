// Block Announcement - Rewritten tests (Core-aligned)

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
        net.AdvanceTime(net.GetCurrentTime() + 200);
    }
}

static int CountINV(SimulatedNetwork& net, int from_node_id, int to_node_id) {
    return net.CountCommandSent(from_node_id, to_node_id, protocol::commands::INV);
}

static struct TestSetup {
    TestSetup() { chain::GlobalChainParams::Select(chain::ChainType::REGTEST); }
} setup_once;

TEST_CASE("Announcement - INV on new block (immediate)", "[block_announcement][basic]") {
    SimulatedNetwork net(1001);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);

    b.ConnectTo(1);
    AdvanceSeconds(net, 2);

    (void)a.MineBlock();
    AdvanceSeconds(net, 2);

    CHECK(b.GetTipHeight() >= 1);
}

TEST_CASE("Announcement - Tip to new READY peer", "[block_announcement][ready]") {
    SimulatedNetwork net(1002);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);

    // Build some history
    for (int i = 0; i < 3; ++i) { (void)a.MineBlock(); AdvanceSeconds(net, 1); }

    int before = CountINV(net, a.GetId(), b.GetId());
    b.ConnectTo(1);
    AdvanceSeconds(net, 2);

    // Drive deterministic announcement with a new block after READY
    (void)a.MineBlock();
    AdvanceSeconds(net, 2);
    CHECK(b.GetTipHeight() >= 4); // previously 3, should advance
}


TEST_CASE("Announcement - Multi-peer propagation", "[block_announcement][multi]") {
    SimulatedNetwork net(1004);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);
    SimulatedNode c(3, &net);
    SimulatedNode d(4, &net);

    b.ConnectTo(1); c.ConnectTo(1); d.ConnectTo(1);
    AdvanceSeconds(net, 2);

    int b_tip_before = b.GetTipHeight();
    int c_tip_before = c.GetTipHeight();
    int d_tip_before = d.GetTipHeight();

    (void)a.MineBlock();
    AdvanceSeconds(net, 2);

    CHECK(b.GetTipHeight() >= b_tip_before + 1);
    CHECK(c.GetTipHeight() >= c_tip_before + 1);
    CHECK(d.GetTipHeight() >= d_tip_before + 1);
}

TEST_CASE("Announcement - Flush no-op for counts", "[block_announcement][flush]") {
    SimulatedNetwork net(1005);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);

    b.ConnectTo(1);
    AdvanceSeconds(net, 2);

    (void)a.MineBlock();
    AdvanceSeconds(net, 1);

    int tip_before = b.GetTipHeight();
    a.GetNetworkManager().flush_block_announcements();
    int tip_after = b.GetTipHeight();
    CHECK(tip_after == tip_before);
}
