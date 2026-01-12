// Multi-peer initial sync test: ensure only one source of headers

#include "test_helper.hpp"
#include "test_orchestrator.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/protocol.hpp"

using namespace unicity;
using namespace unicity::test;

TEST_CASE("Initial sync: node connects to 3 synced peers and should use only one source", "[network][sync][multi-peer-sync]") {
    SimulatedNetwork network(424242);
    TestOrchestrator orch(&network);

    // Peers: A,B,C are in sync at height 100; D is empty and will connect to all three
    SimulatedNode A(1, &network);
    SimulatedNode B(2, &network);
    SimulatedNode C(3, &network);
    SimulatedNode D(4, &network);

    // Speed up by bypassing PoW
    A.SetBypassPOWValidation(true);
    B.SetBypassPOWValidation(true);
    C.SetBypassPOWValidation(true);
    D.SetBypassPOWValidation(true);

    // Build chain on A: 100 blocks
    for (int i = 0; i < 100; ++i) {
        A.MineBlock();
    }
    orch.AssertHeight(A, 100);

    // Sync B and C to A
    REQUIRE(B.ConnectTo(1));
    REQUIRE(orch.WaitForConnection(A, B));
    REQUIRE(orch.WaitForSync(A, B));
    REQUIRE(C.ConnectTo(1));
    REQUIRE(orch.WaitForConnection(A, C));
    REQUIRE(orch.WaitForSync(A, C));

    // Verify A,B,C are all at 100
    orch.AssertHeight(B, 100);
    orch.AssertHeight(C, 100);

    // Enable command tracking to observe GETHEADERS fanout from D
    network.EnableCommandTracking(true);

    // D connects to all three peers
    REQUIRE(D.ConnectTo(1));
    REQUIRE(orch.WaitForConnection(D, A));
    REQUIRE(D.ConnectTo(2));
    REQUIRE(orch.WaitForConnection(D, B));
    REQUIRE(D.ConnectTo(3));
    REQUIRE(orch.WaitForConnection(D, C));

    // Advance simulated time to allow initial sync and any follow-up peer switches
    for (int i = 0; i < 150; ++i) { // 15 seconds simulated
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Count distinct peers D sent GETHEADERS to (should be 1 if single source policy)
    int distinct = network.CountDistinctPeersSent(4, protocol::commands::GETHEADERS);

    // Correct behavior: exactly one
    REQUIRE(distinct == 1);
}
