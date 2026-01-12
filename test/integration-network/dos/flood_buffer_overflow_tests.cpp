// DoS: Message flood triggers recv buffer overflow protection

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "test_orchestrator.hpp"
#include "network/message.hpp"
#include "chain/chainparams.hpp"

using namespace unicity;
using namespace unicity::test;

TEST_CASE("DoS: Message flood triggers recv buffer overflow protection", "[dos][network][flood]") {
    // No explicit rate-limiter, but recv buffer overflow guard should kick in
    SimulatedNetwork network(1515);
    // Make delivery fast
    SimulatedNetwork::NetworkConditions fast;
    fast.latency_min = std::chrono::milliseconds(0);
    fast.latency_max = std::chrono::milliseconds(1);
    fast.jitter_max  = std::chrono::milliseconds(0);
    fast.bandwidth_bytes_per_sec = 0; // unlimited
    network.SetNetworkConditions(fast);

    TestOrchestrator orchestrator(&network);
    SimulatedNode victim(1, &network);
    SimulatedNode attacker(2, &network);

    REQUIRE(attacker.ConnectTo(1));
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));

    // Craft header-only messages with inflated length and partial payload chunks to accumulate quickly
    uint32_t declared_len = 1024 * 1024; // 1 MB declared payload per message
    protocol::MessageHeader hdr(protocol::magic::REGTEST, protocol::commands::PING, declared_len);
    auto hdr_bytes = message::serialize_header(hdr);

    std::vector<uint8_t> chunk(256 * 1024, 0); // 256 KB partial payload

    // Send enough messages to exceed DEFAULT_RECV_FLOOD_SIZE (5 MB)
    for (int i = 0; i < 30; ++i) {
        std::vector<uint8_t> msg;
        msg.reserve(hdr_bytes.size() + chunk.size());
        msg.insert(msg.end(), hdr_bytes.begin(), hdr_bytes.end());
        msg.insert(msg.end(), chunk.begin(), chunk.end());
        network.SendMessage(attacker.GetId(), victim.GetId(), msg);
    }

    orchestrator.AdvanceTime(std::chrono::seconds(2));

    // Expect disconnect due to receive buffer overflow guard
    REQUIRE(orchestrator.WaitForPeerCount(victim, 0, std::chrono::seconds(2)));
}
