// Header sync tests

#include "test_helper.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "test_orchestrator.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"

using namespace unicity;
using namespace unicity::test;

TEST_CASE("Header sync: locator size and hash_stop semantics", "[network][sync][headers]") {
    SimulatedNetwork network(20202);
    TestOrchestrator orch(&network);

    SimulatedNode A(1, &network);
    SimulatedNode D(4, &network);

    A.SetBypassPOWValidation(true);
    D.SetBypassPOWValidation(true);

    // Small chain is enough to trigger at least one GETHEADERS
    for (int i = 0; i < 20; ++i) {
        A.MineBlock();
    }

    network.EnableCommandTracking(true);

    REQUIRE(D.ConnectTo(1));
    REQUIRE(orch.WaitForConnection(D, A));

    // Give time for initial GETHEADERS
    for (int i = 0; i < 30; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    auto payloads = network.GetCommandPayloads(4, 1, protocol::commands::GETHEADERS);
    REQUIRE(!payloads.empty());

    // Parse the first payload and check constraints
    message::GetHeadersMessage msg;
    REQUIRE(msg.deserialize(payloads.front().data(), payloads.front().size()));

    // Locator size bounded by MAX_LOCATOR_SZ and non-zero
    REQUIRE(msg.block_locator_hashes.size() > 0);
    REQUIRE(msg.block_locator_hashes.size() <= protocol::MAX_LOCATOR_SZ);

    // hash_stop should be zero (we request as many as possible)
    bool all_zero = true;
    for (auto b : msg.hash_stop) { if (b != 0) { all_zero = false; break; } }
    REQUIRE(all_zero);
}
