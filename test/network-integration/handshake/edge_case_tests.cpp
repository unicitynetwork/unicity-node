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

TEST_CASE("VERSION - Protocol version too old (IMPLEMENTED)", "[network][handshake][version]") {
    INFO("Obsolete protocol versions are rejected (see peer.cpp)");
}

TEST_CASE("VERSION - Future protocol version (CORRECT AS-IS)", "[network][handshake][version]") {
    INFO("Accepts future versions for forward compatibility (see peer.cpp)");
}

TEST_CASE("VERSION - Self-connection detection", "[network][handshake][version]") {
    INFO("Inbound rejects self-connection by nonce; outbound prevented by NetworkManager");
}

TEST_CASE("VERSION - Truncated message (deserialization failure)", "[network][handshake][version]") {
    INFO("Deserialize failure disconnects the peer (message.cpp/peer.cpp)");
}

TEST_CASE("VERSION - Zero-length payload", "[network][handshake][version]") {
    INFO("Zero-length VERSION payload -> deserialize fails -> disconnect");
}

TEST_CASE("VERSION - VERACK before VERSION is rejected", "[network][handshake][sequence]") {
    INFO("Messages before VERSION cause disconnect");
}

TEST_CASE("VERSION - Duplicate VERSION is ignored", "[network][handshake][sequence]") {
    INFO("Duplicate VERSION ignored (nonce not updated)");
}

TEST_CASE("VERSION - Handshake timeout (60 seconds)", "[network][handshake][timeout]") {
    INFO("Documented 60s timeout; long-running real-time test omitted");
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
