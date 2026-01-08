// DoS: Invalid PoW headers trigger discourage

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
} test_setup_invalid_pow;

TEST_CASE("DoS: Invalid PoW headers trigger discourage", "[dos][network]") {
    SimulatedNetwork network(42);
    TestOrchestrator orchestrator(&network);
    NetworkObserver observer;
    AutoDumpOnFailure auto_dump(observer);

    SimulatedNode victim(1, &network);
    NodeSimulator attacker(2, &network);

    observer.OnCustomEvent("TEST_START", -1, "Invalid PoW DoS test");

    // Phase 1: Build legitimate chain
    observer.OnCustomEvent("PHASE", -1, "Building victim chain");
    victim.SetBypassPOWValidation(true);
    for (int i = 0; i < 10; i++) {
        auto hash = victim.MineBlock();
        observer.OnBlockMined(1, hash.ToString(), victim.GetTipHeight());
    }

    // Phase 2: Connect and sync
    observer.OnCustomEvent("PHASE", -1, "Connecting nodes");
    attacker.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));
    orchestrator.AssertPeerCount(victim, 1);

    REQUIRE(orchestrator.WaitForSync(victim, attacker));
    orchestrator.AssertHeight(attacker, 10);
    observer.OnCustomEvent("PHASE", -1, "Nodes synced at height 10");

    // Phase 3: Launch attack
    victim.SetBypassPOWValidation(false);  // Enable validation BEFORE attack
    observer.OnCustomEvent("PHASE", -1, "Launching invalid PoW attack");

    attacker.SendInvalidPoWHeaders(1, victim.GetTipHash(), 1);
    observer.OnMessageSent(2, 1, "headers_invalid_pow", 100);

    // Phase 4: Verify protection
    observer.OnCustomEvent("PHASE", -1, "Verifying DoS protection");
    orchestrator.AdvanceTime(std::chrono::seconds(2));

    // Attacker should be discouraged and disconnected
    orchestrator.AssertPeerDiscouraged(victim, attacker);
    REQUIRE(orchestrator.WaitForPeerCount(victim, 0, std::chrono::seconds(2)));
    observer.OnPeerDisconnected(1, 2, "invalid_pow_100_points");

    // Victim chain should be unchanged
    orchestrator.AssertHeight(victim, 10);

    observer.OnCustomEvent("TEST_END", -1, "PASSED - Invalid PoW correctly rejected");
    auto_dump.MarkSuccess();
}
