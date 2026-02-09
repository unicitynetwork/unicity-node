#include "catch_amalgamated.hpp"
#include "chain/validation.hpp"
#include "infra/simulated_network.hpp"
#include "chain/validation.hpp"
#include "infra/simulated_node.hpp"
#include "network/protocol.hpp"

using namespace unicity;
using namespace unicity::test;

static void SetZeroLatency(SimulatedNetwork& network) {
    SimulatedNetwork::NetworkConditions c;
    c.latency_min = c.latency_max = std::chrono::milliseconds(0);
    c.jitter_max = std::chrono::milliseconds(0);
    c.packet_loss_rate = 0.0;
    network.SetNetworkConditions(c);
}

TEST_CASE("Post-IBD block announcement triggers sync", "[network][post-ibd]") {
    SimulatedNetwork net(924242);
    SetZeroLatency(net);

    // Two nodes: A (miner), B (follower)
    SimulatedNode A(1, &net);
    SimulatedNode B(2, &net);

    // Connect B -> A
    REQUIRE(B.ConnectTo(A.GetId()));
    uint64_t t = 100; net.AdvanceTime(t);

    // Mine initial chain and sync B (exit IBD)
    for (int i = 0; i < 20; ++i) {
        (void)A.MineBlock();
        t += 50; net.AdvanceTime(t);
    }
    REQUIRE(A.GetTipHeight() == 20);
    REQUIRE(B.GetTipHeight() == 20);

    // Mine one more block on A; B receives direct HEADERS announcement and syncs
    (void)A.MineBlock();
    for (int i = 0; i < 5; ++i) { t += 50; net.AdvanceTime(t); }

    REQUIRE(B.GetTipHeight() == A.GetTipHeight());
}
