// VERSION Handshake edge case tests (ported to test2)

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"
#include "test_orchestrator.hpp"

using namespace unicity;
using namespace unicity::test;

static void SetZeroLatency(SimulatedNetwork& network) {
    SimulatedNetwork::NetworkConditions conditions;
    conditions.latency_min = std::chrono::milliseconds(0);
    conditions.latency_max = std::chrono::milliseconds(0);
    conditions.jitter_max = std::chrono::milliseconds(0);
    network.SetNetworkConditions(conditions);
}

TEST_CASE("VERSION - Handshake completes within timeout", "[network][handshake][timeout]") {
    SimulatedNetwork network(12345);
    SetZeroLatency(network);

    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);
    TestOrchestrator orch(&network);

    node1.ConnectTo(2);
    REQUIRE(orch.WaitForConnection(node1, node2, std::chrono::seconds(10)));
}

TEST_CASE("VERSION - Handshake with network latency", "[network][handshake][integration]") {
    SimulatedNetwork network(12346);
    SimulatedNetwork::NetworkConditions conditions;
    conditions.latency_min = std::chrono::milliseconds(50);
    conditions.latency_max = std::chrono::milliseconds(100);
    network.SetNetworkConditions(conditions);

    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);
    TestOrchestrator orch(&network);

    node1.ConnectTo(2);
    REQUIRE(orch.WaitForConnection(node1, node2, std::chrono::seconds(15)));
}
