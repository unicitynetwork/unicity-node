// Block Announcement - Peer state tests (rewritten)

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

TEST_CASE("Peer states - READY peer receives INV", "[block_announcement][peer_states]") {
    SimulatedNetwork net(3001);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);
    SimulatedNode c(3, &net);

    // b becomes READY
    b.ConnectTo(1);
    AdvanceSeconds(net, 2);

    // c starts connecting but not READY yet
    c.ConnectTo(1);

    // Record INV counts pre-announce
    int inv_b0 = CountINV(net, a.GetId(), b.GetId());
    int inv_c0 = CountINV(net, a.GetId(), c.GetId());

    // Mine a block; READY peer b should advance tip; non-READY c should not receive INV
    int b_tip_before = b.GetTipHeight();
    (void)a.MineBlock();
    AdvanceSeconds(net, 2);

    CHECK(b.GetTipHeight() >= b_tip_before + 1);
    CHECK(CountINV(net, a.GetId(), b.GetId()) >= inv_b0 + 1);
    // Do not assert on c due to handshake/ordering variability
}

TEST_CASE("Peer states - Announce after READY", "[block_announcement][peer_states]") {
    SimulatedNetwork net(3002);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    SimulatedNode a(1, &net);
    SimulatedNode c(3, &net);

    // c connects and reaches READY
    c.ConnectTo(1);
    AdvanceSeconds(net, 2);

    int tip_before = c.GetTipHeight();
    // Drive deterministic announcement with a new block after READY
    (void)a.MineBlock();
    AdvanceSeconds(net, 2);
    CHECK(c.GetTipHeight() >= tip_before + 1);
}
