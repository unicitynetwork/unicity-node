// Networking component tests: peer counts, reorg sync, disconnect propagation

#include "test_helper.hpp"
#include "test_orchestrator.hpp"

using namespace unicity;
using namespace unicity::test;

TEST_CASE("ConnectionManager inbound/outbound counts", "[network][peers]") {
    SimulatedNetwork network(777);
    TestOrchestrator orch(&network);

    SimulatedNode a(1, &network);
    SimulatedNode b(2, &network);

    // b dials a
    REQUIRE(b.ConnectTo(1));
    REQUIRE(orch.WaitForConnection(a, b));

    // Verify counts
    REQUIRE(a.GetInboundPeerCount() == 1);
    REQUIRE(a.GetOutboundPeerCount() == 0);
    REQUIRE(b.GetOutboundPeerCount() == 1);
    REQUIRE(b.GetInboundPeerCount() == 0);
}

TEST_CASE("Three-node header sync and reorg", "[network][sync][reorg]") {
    SimulatedNetwork network(888);
    TestOrchestrator orch(&network);

    SimulatedNode a(1, &network);
    SimulatedNode b(2, &network);
    SimulatedNode c(3, &network);

    // Build diverging chains
    for (int i = 0; i < 3; ++i) a.MineBlock();   // A: 3
    b.MineBlock();                                 // B: 1
    for (int i = 0; i < 5; ++i) c.MineBlock();   // C: 5 (best)

    // Connect A <-> B and sync
    REQUIRE(b.ConnectTo(1));
    REQUIRE(orch.WaitForConnection(a, b));
    REQUIRE(orch.WaitForSync(a, b));
    orch.AssertHeight(a, 3);
    orch.AssertHeight(b, 3);

    // Now connect both A and B to C; they should reorg to height 5
    REQUIRE(a.ConnectTo(3));
    REQUIRE(b.ConnectTo(3));
    REQUIRE(orch.WaitForConnection(a, c));
    REQUIRE(orch.WaitForConnection(b, c));

    REQUIRE(orch.WaitForHeight(a, 5));
    REQUIRE(orch.WaitForHeight(b, 5));
    REQUIRE(orch.WaitForSync(a, c));
    REQUIRE(orch.WaitForSync(b, c));
}

TEST_CASE("Disconnect propagation to both peers", "[network][disconnect]") {
    SimulatedNetwork network(9991);
    TestOrchestrator orch(&network);

    SimulatedNode a(1, &network);
    SimulatedNode b(2, &network);

    REQUIRE(b.ConnectTo(1));
    REQUIRE(orch.WaitForConnection(a, b));

    // Initiate disconnect from b's side
    b.DisconnectFrom(1);

    // Both should eventually see zero peers
    REQUIRE(orch.WaitForPeerCount(a, 0));
    REQUIRE(orch.WaitForPeerCount(b, 0));
}
