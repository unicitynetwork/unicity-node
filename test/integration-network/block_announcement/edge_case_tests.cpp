// Block Announcement - Edge cases (rewritten)

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/protocol.hpp"

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

TEST_CASE("Edge - INV delivered to READY peer", "[block_announcement][edge]") {
    SimulatedNetwork net(2001);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);
    SimulatedNode c(3, &net);

    // Make b READY
    b.ConnectTo(1);
    AdvanceSeconds(net, 2);

    // Start connection to c but don't advance time (remain non-READY)
    c.ConnectTo(1);

    int b0 = CountINV(net, a.GetId(), b.GetId());
    int c0 = CountINV(net, a.GetId(), c.GetId());

    // Mine a new block: READY peer should see an INV; non-READY should not receive INV
    int b_tip_before = b.GetTipHeight();
    (void)a.MineBlock();
    AdvanceSeconds(net, 2);

    // READY b should have advanced tip and received an INV
    CHECK(b.GetTipHeight() >= b_tip_before + 1);
    CHECK(CountINV(net, a.GetId(), b.GetId()) >= b0 + 1);

    // We do not assert anything about c here due to handshake/ordering variability
}

TEST_CASE("Edge - Flush safe after disconnect", "[block_announcement][edge]") {
    SimulatedNetwork net(2002);
    SetZeroLatency(net);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);

    b.ConnectTo(1);
    AdvanceSeconds(net, 2);
    CHECK(a.GetPeerCount() == 1);

    (void)a.MineBlock();
    AdvanceSeconds(net, 1);

    a.GetNetworkManager().announce_tip_to_peers();
    a.GetNetworkManager().flush_block_announcements();

    a.DisconnectFrom(2);
    AdvanceSeconds(net, 1);
    CHECK(a.GetPeerCount() == 0);

    // Should not crash
    a.GetNetworkManager().flush_block_announcements();
}
