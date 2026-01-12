// Duplicate connection tests (ported to test2)

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "test_orchestrator.hpp"

using namespace unicity;
using namespace unicity::test;

TEST_CASE("Duplicate connection attempt does not create extra outbound peer", "[network][duplicate]") {
    SimulatedNetwork network(2620);
    TestOrchestrator orch(&network);

    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);

    REQUIRE(node1.ConnectTo(2));
    REQUIRE(orch.WaitForConnection(node1, node2));

    size_t outbound_before = node1.GetOutboundPeerCount();

    // Second attempt to connect to the same node should not increase outbound count
    bool second = node1.ConnectTo(2);
    (void)second;

    orch.AdvanceTime(std::chrono::milliseconds(200));

    // It is acceptable if the second attempt triggers a brief disconnect; the key
    // requirement is that we never exceed one outbound connection to the same peer.
    REQUIRE(node1.GetOutboundPeerCount() <= 1);
}
