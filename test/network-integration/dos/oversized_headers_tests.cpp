// DoS: Oversized HEADERS message triggers disconnect

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "infra/node_simulator.hpp"
#include "test_orchestrator.hpp"
#include "network_observer.hpp"
#include "chain/chainparams.hpp"

using namespace unicity;
using namespace unicity::chain;
using namespace unicity::test;

static struct TestSetup {
    TestSetup() { chain::GlobalChainParams::Select(chain::ChainType::REGTEST); }
} test_setup_oversized_headers;

TEST_CASE("DoS: Oversized message triggers disconnect", "[dos][network]") {
    SimulatedNetwork network(456);
    TestOrchestrator orchestrator(&network);
    NetworkObserver observer;
    AutoDumpOnFailure auto_dump(observer);

    SimulatedNode victim(1, &network);
    NodeSimulator attacker(2, &network);

    observer.OnCustomEvent("TEST_START", -1, "Oversized message DoS test");

    // Setup
    victim.SetBypassPOWValidation(true);
    for (int i = 0; i < 5; i++) {
        victim.MineBlock();
    }

    attacker.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));
    REQUIRE(orchestrator.WaitForSync(victim, attacker));

    // Attack: Send message exceeding MAX_HEADERS_SIZE (80000)
    observer.OnCustomEvent("PHASE", -1, "Sending oversized message (80001 headers)");
    attacker.SendOversizedHeaders(1, 80001);
    observer.OnMessageSent(2, 1, "oversized_headers", 8000100);

    orchestrator.AdvanceTime(std::chrono::seconds(2));

    // Verify: Should disconnect (oversized message is protocol violation)
    observer.OnCustomEvent("PHASE", -1, "Verifying disconnect");
    REQUIRE(orchestrator.WaitForPeerCount(victim, 0, std::chrono::seconds(2)));

    orchestrator.AssertHeight(victim, 5);
    observer.OnCustomEvent("TEST_END", -1, "PASSED - Oversized message rejected");
    auto_dump.MarkSuccess();
}
