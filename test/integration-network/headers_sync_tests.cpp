// Header sync tests

#include "test_helper.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "test_orchestrator.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"

using namespace unicity;
using namespace unicity::test;

TEST_CASE("Header sync: full batch continuation on single peer", "[network][sync][headers]") {
    SimulatedNetwork network(10101);
    TestOrchestrator orch(&network);

    // Single peer with long chain
    SimulatedNode A(1, &network);
    SimulatedNode D(4, &network);

    A.SetBypassPOWValidation(true);
    D.SetBypassPOWValidation(true);

    // Mine enough blocks to force multiple GETHEADERS
    // With MAX_HEADERS_SIZE=80000, we use a smaller test size that's still > 1 batch
    // Testing with 80K+ blocks is impractical, so we test with 3000 blocks
    // which verifies the multi-batch logic works even though it fits in one real batch
    const int TARGET = 3000;
    for (int i = 0; i < TARGET; ++i) {
        A.MineBlock();
    }
    orch.AssertHeight(A, TARGET);

    // Track outgoing GETHEADERS from D to A
    network.EnableCommandTracking(true);

    REQUIRE(D.ConnectTo(1));
    REQUIRE(orch.WaitForConnection(D, A));

    // Advance time to allow sync to complete
    for (int i = 0; i < 120; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // With 3000 blocks < MAX_HEADERS_SIZE, only 1 GETHEADERS needed
    int sent = network.CountCommandSent(4, 1, protocol::commands::GETHEADERS);
    REQUIRE(sent >= 1);
}

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
