// DoS: Per-peer send queue cap on slow-reading peer

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "test_orchestrator.hpp"
#include "chain/chainparams.hpp"
#include "network/protocol.hpp"

using namespace unicity;
using namespace unicity::test;

TEST_CASE("DoS: Per-peer send queue cap on slow-reading peer", "[dos][network][send-queue]") {
    // Simulate a slow-reading peer that causes send queue buildup
    // Strategy: Node A sends many large messages to Node B, but B has very slow receive rate
    // This causes A's send queue to fill up, triggering disconnect

    SimulatedNetwork network(1617);

    TestOrchestrator orchestrator(&network);
    SimulatedNode node_a(1, &network);
    SimulatedNode node_b(2, &network);

    REQUIRE(node_a.ConnectTo(2));
    REQUIRE(orchestrator.WaitForConnection(node_a, node_b));

    // After handshake, create slow read conditions from A->B
    // This simulates B being slow to read from socket
    SimulatedNetwork::NetworkConditions slow_read;
    slow_read.latency_min = std::chrono::milliseconds(0);
    slow_read.latency_max = std::chrono::milliseconds(1);
    slow_read.jitter_max  = std::chrono::milliseconds(0);
    slow_read.bandwidth_bytes_per_sec = 10 * 1024; // 10 KB/s - very slow
    network.SetLinkConditions(1, 2, slow_read);

    // Send many large PING messages to exceed DEFAULT_SEND_QUEUE_SIZE (5 MB)
    // Each PING is ~32 bytes (header + nonce), so we need many of them
    // Let's send messages totaling ~6 MB worth of data
    const size_t target_bytes = protocol::DEFAULT_SEND_QUEUE_SIZE + 1024 * 1024; // 6 MB
    const size_t pings_needed = target_bytes / 100; // Rough estimate

    // Send messages rapidly - faster than the slow link can drain
    for (size_t i = 0; i < pings_needed; ++i) {
        // Use PING messages as they're lightweight and don't require complex setup
        auto ping_msg = std::make_unique<message::PingMessage>(i);
        node_a.SendMessage(2, std::move(ping_msg));

        // Process a bit to allow some messages to queue up
        if (i % 100 == 0) {
            orchestrator.AdvanceTime(std::chrono::milliseconds(10));
        }
    }

    // Give time for send queue to build up and trigger disconnect
    orchestrator.AdvanceTime(std::chrono::seconds(5));

    // Verify that node_a disconnected node_b due to send queue overflow
    // Node A should have 0 peers (disconnected B)
    REQUIRE(orchestrator.WaitForPeerCount(node_a, 0, std::chrono::seconds(3)));
}

TEST_CASE("DoS: Send queue does not overflow with reasonable message rate", "[dos][network][send-queue]") {
    // Verify that normal message sending doesn't trigger send queue overflow

    SimulatedNetwork network(1618);

    TestOrchestrator orchestrator(&network);
    SimulatedNode node_a(1, &network);
    SimulatedNode node_b(2, &network);

    REQUIRE(node_a.ConnectTo(2));
    REQUIRE(orchestrator.WaitForConnection(node_a, node_b));

    // Normal network conditions
    SimulatedNetwork::NetworkConditions normal;
    normal.latency_min = std::chrono::milliseconds(10);
    normal.latency_max = std::chrono::milliseconds(50);
    normal.jitter_max  = std::chrono::milliseconds(10);
    normal.bandwidth_bytes_per_sec = 1024 * 1024; // 1 MB/s - reasonable
    network.SetLinkConditions(1, 2, normal);

    // Send reasonable number of messages (well below limit)
    for (size_t i = 0; i < 100; ++i) {
        auto ping_msg = std::make_unique<message::PingMessage>(i);
        node_a.SendMessage(2, std::move(ping_msg));
        orchestrator.AdvanceTime(std::chrono::milliseconds(10));
    }

    // Give time for messages to be delivered
    orchestrator.AdvanceTime(std::chrono::seconds(2));

    // Verify connection is still alive
    CHECK(node_a.GetPeerCount() == 1);
    CHECK(node_b.GetPeerCount() == 1);
}
