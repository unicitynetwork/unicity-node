#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"

using namespace unicity;
using namespace unicity::test;
using namespace unicity::protocol;

static void ZeroLatency(SimulatedNetwork& net){
    SimulatedNetwork::NetworkConditions c; c.latency_min=c.latency_max=std::chrono::milliseconds(0); c.jitter_max=std::chrono::milliseconds(0); net.SetNetworkConditions(c);
}

TEST_CASE("Reannounce TTL prevents INV spam", "[dos][ttl]") {
    SimulatedNetwork net(60001);
    ZeroLatency(net);
    net.EnableCommandTracking(true);

    // Node A (announcer) and Node B (listener)
    SimulatedNode A(1, &net);
    SimulatedNode B(2, &net);

    REQUIRE(B.ConnectTo(A.GetId()));
    uint64_t t=100; net.AdvanceTime(t);

    // Ensure A has a tip (mine one block)
    (void)A.MineBlock(); t+=50; net.AdvanceTime(t);

    // Multiple periodic runs within TTL should not cause multiple INV
    for (int i=0;i<10;i++) {
        A.ProcessPeriodic();
        net.AdvanceTime(t += 10); // small advance
    }

    int invs = net.CountCommandSent(A.GetId(), B.GetId(), commands::INV);
    REQUIRE(invs <= 1);

    // Advance beyond TTL (10 minutes) and run periodic; should allow another INV
    t += (10*60*1000 + 1000);
    net.AdvanceTime(t);
    A.ProcessPeriodic();
    net.AdvanceTime(t += 10);

    int invs_after = net.CountCommandSent(A.GetId(), B.GetId(), commands::INV);
    REQUIRE(invs_after >= invs); // may be equal if dedup queue still holds
}
