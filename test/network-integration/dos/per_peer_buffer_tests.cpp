// DoS: Per-peer receive buffer cap on raw flood

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "test_orchestrator.hpp"
#include "chain/chainparams.hpp"

using namespace unicity;
using namespace unicity::test;

TEST_CASE("DoS: Per-peer receive buffer cap on raw flood", "[dos][network][per-peer-buffer]") {
    // Flood with raw bytes (no valid header) faster than processing
    SimulatedNetwork network(1616);

    TestOrchestrator orchestrator(&network);
    SimulatedNode victim(1, &network);
    SimulatedNode attacker(2, &network);

    REQUIRE(attacker.ConnectTo(1));
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));

    // After handshake, set fast delivery from attacker->victim
    SimulatedNetwork::NetworkConditions fast;
    fast.latency_min = std::chrono::milliseconds(0);
    fast.latency_max = std::chrono::milliseconds(1);
    fast.jitter_max  = std::chrono::milliseconds(0);
    fast.bandwidth_bytes_per_sec = 0;
    network.SetLinkConditions(2, 1, fast);

    // Raw chunks without even a full header (e.g. 100KB each)
    std::vector<uint8_t> raw(100 * 1024, 0xAB);

    // Send many chunks to exceed DEFAULT_RECV_FLOOD_SIZE (5 MB)
    for (int i = 0; i < 100; ++i) {
        network.SendMessage(attacker.GetId(), victim.GetId(), raw);
    }

    orchestrator.AdvanceTime(std::chrono::seconds(2));

    REQUIRE(orchestrator.WaitForPeerCount(victim, 0, std::chrono::seconds(2)));
}
