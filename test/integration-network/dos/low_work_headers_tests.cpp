// DoS: Deep fork headers handling
//
// This test verifies behavior when headers from a deep fork are received.
//
// IMPORTANT: Fork-depth based rejection was REMOVED because it caused chain splits
// (nodes at different heights would disagree on header validity).
//
// Current protection mechanisms:
// 1. Work-threshold check: When nMinimumChainWork > 0, batches with insufficient
//    cumulative work are rejected. Currently nMinimumChainWork = 0 (disabled).
// 2. PruneStaleSideChains: Periodically removes stale side-chain headers.
// 3. PoW cost: Attacker must spend significant resources to create valid headers.
// 4. TrySwitchToNewTip: Deep reorgs halt the node (policy, not consensus).
//
// With nMinimumChainWork = 0, deep fork headers are ACCEPTED but won't become
// active chain (insufficient work). This is safe because:
// - Headers require valid PoW (expensive)
// - Pruning cleans up stale forks
// - No consensus divergence

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
} test_setup_low_work;

TEST_CASE("DoS: Deep fork headers are accepted but don't become active", "[dos][network]") {
    // With fork-depth rejection removed, deep fork headers are accepted.
    // They won't become the active chain due to insufficient work.
    // This prevents chain splits while still protecting via PoW cost.

    SimulatedNetwork network(789);
    TestOrchestrator orchestrator(&network);
    NetworkObserver observer;
    AutoDumpOnFailure auto_dump(observer);

    SimulatedNode victim(1, &network);
    NodeSimulator attacker(2, &network);

    observer.OnCustomEvent("TEST_START", -1, "Deep fork headers acceptance test");

    // Victim builds a chain to height 100
    observer.OnCustomEvent("PHASE", -1, "Building victim chain (100 blocks)");
    victim.SetBypassPOWValidation(true);
    for (int i = 0; i < 100; i++) {
        victim.MineBlock();
    }
    auto victim_tip_before = victim.GetTipHash();

    // Attacker builds independent chain (from genesis)
    observer.OnCustomEvent("PHASE", -1, "Attacker building deep fork (10 blocks from genesis)");
    attacker.SetBypassPOWValidation(true);
    std::vector<uint256> attacker_chain;
    for (int i = 0; i < 10; i++) {
        auto hash = attacker.MineBlockPrivate();
        attacker_chain.push_back(hash);
    }

    // Connect
    attacker.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));
    // Ensure handshake completes before sending headers
    for (int i = 0; i < 20; ++i) orchestrator.AdvanceTime(std::chrono::milliseconds(100));

    // Send deep fork headers
    observer.OnCustomEvent("PHASE", -1, "Sending deep fork headers");
    attacker.SendLowWorkHeaders(1, attacker_chain);
    orchestrator.AdvanceTime(std::chrono::seconds(2));

    // Verify behavior:
    observer.OnCustomEvent("PHASE", -1, "Verifying behavior");

    // 1. Peer should remain CONNECTED (headers accepted, no penalty)
    orchestrator.AssertPeerCount(victim, 1);
    observer.OnCustomEvent("VERIFY", -1, "Peer still connected after deep fork headers");

    // 2. Victim's active chain unchanged (fork has less work)
    orchestrator.AssertHeight(victim, 100);
    REQUIRE(victim.GetTipHash() == victim_tip_before);
    observer.OnCustomEvent("VERIFY", -1, "Victim active chain unchanged");

    observer.OnCustomEvent("TEST_END", -1, "PASSED - Deep fork headers accepted but didn't become active");
    auto_dump.MarkSuccess();
}
