// DoS: Orphan header spam triggers protection

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
} test_setup_orphan_spam;

TEST_CASE("DoS: Orphan header spam triggers protection", "[dos][network]") {
    SimulatedNetwork network(123);
    TestOrchestrator orchestrator(&network);
    NetworkObserver observer;
    AutoDumpOnFailure auto_dump(observer);

    SimulatedNode victim(1, &network);
    NodeSimulator attacker(2, &network);

    observer.OnCustomEvent("TEST_START", -1, "Orphan spam DoS test");

    // Build chain and connect
    observer.OnCustomEvent("PHASE", -1, "Setup");
    victim.SetBypassPOWValidation(true);
    for (int i = 0; i < 5; i++) {
        victim.MineBlock();
    }

    attacker.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));
    REQUIRE(orchestrator.WaitForSync(victim, attacker));

    // Launch attack: Send many orphan headers (unknown parents)
    observer.OnCustomEvent("PHASE", -1, "Sending orphan header spam");

    // Send multiple batches to accumulate misbehavior score
    for (int batch = 0; batch < 10; batch++) {
        attacker.SendOrphanHeaders(1, 100);  // 100 orphan headers per batch
        observer.OnCustomEvent("ATTACK", 2, "Batch " + std::to_string(batch + 1) + " of orphans sent");
        orchestrator.AdvanceTime(std::chrono::milliseconds(300));
    }

    observer.OnCustomEvent("PHASE", -1, "Processing attack");
    orchestrator.AdvanceTime(std::chrono::seconds(2));

    // Verify: Attacker should be disconnected after threshold
    observer.OnCustomEvent("PHASE", -1, "Verifying protection");
    REQUIRE(orchestrator.WaitForPeerCount(victim, 0, std::chrono::seconds(2)));

    // Victim should be unaffected
    orchestrator.AssertHeight(victim, 5);
    observer.OnCustomEvent("TEST_END", -1, "PASSED - Orphan spam protected");
    auto_dump.MarkSuccess();
}
