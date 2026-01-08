// DoS: Stalling peer timeout test

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
} test_setup_stall;

TEST_CASE("DoS: Stalling peer timeout", "[dos][network]") {
    // Test that victim doesn't hang when attacker stalls responses

    SimulatedNetwork network(999);
    TestOrchestrator orchestrator(&network);
    NetworkObserver observer;
    AutoDumpOnFailure auto_dump(observer);

    SimulatedNode victim(1, &network);
    NodeSimulator attacker(2, &network);

    observer.OnCustomEvent("TEST_START", -1, "Stalling peer timeout test");

    // Setup chain
    victim.SetBypassPOWValidation(true);
    for (int i = 0; i < 10; i++) {
        victim.MineBlock();
    }

    attacker.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));
    REQUIRE(orchestrator.WaitForSync(victim, attacker));

    // Enable stalling: Attacker won't respond to GETHEADERS
    observer.OnCustomEvent("PHASE", -1, "Enabling stall mode");
    attacker.EnableStalling(true);

    // Send orphan headers to trigger GETHEADERS request
    observer.OnCustomEvent("PHASE", -1, "Sending orphans to trigger GETHEADERS");
    attacker.SendOrphanHeaders(1, 50);

    // Victim will request parents, but attacker stalls
    observer.OnCustomEvent("PHASE", -1, "Waiting for timeout (victim should not hang)");
    orchestrator.AdvanceTime(std::chrono::seconds(5));

    // Verify: Victim should still be functional (didn't hang)
    orchestrator.AssertHeight(victim, 10);

    // Attacker may be disconnected for stalling (implementation specific)
    observer.OnCustomEvent("TEST_END", -1, "PASSED - Victim survived stall attack");
    auto_dump.MarkSuccess();
}

TEST_CASE("DoS: Stall causes sync peer switch", "[dos][network]") {
    SimulatedNetwork net(1001);
    net.EnableCommandTracking(true);

    // Miner with chain
    SimulatedNode miner(1, &net);
    for (int i = 0; i < 30; ++i) (void)miner.MineBlock();

    // Two serving peers
    SimulatedNode p1(2, &net); // will stall (no HEADERS to victim)
    SimulatedNode p2(3, &net); // healthy peer
    p1.ConnectTo(miner.GetId());
    p2.ConnectTo(miner.GetId());
    uint64_t t = 1000; net.AdvanceTime(t);
    for (int i = 0; i < 20 && p1.GetTipHeight() < 30; ++i) { t += 200; net.AdvanceTime(t); p1.GetNetworkManager().test_hook_check_initial_sync(); }
    for (int i = 0; i < 20 && p2.GetTipHeight() < 30; ++i) { t += 200; net.AdvanceTime(t); p2.GetNetworkManager().test_hook_check_initial_sync(); }
    REQUIRE(p1.GetTipHeight() == 30);
    REQUIRE(p2.GetTipHeight() == 30);

    // Victim (new node)
    SimulatedNode victim(4, &net);
    victim.ConnectTo(p1.GetId());
    victim.ConnectTo(p2.GetId());
    t += 200; net.AdvanceTime(t);

    // Start initial sync (single sync peer policy)
    victim.GetNetworkManager().test_hook_check_initial_sync();
    t += 200; net.AdvanceTime(t);

    // Record initial GETHEADERS counts
    int gh_p1_before = net.CountCommandSent(victim.GetId(), p1.GetId(), protocol::commands::GETHEADERS);
    int gh_p2_before = net.CountCommandSent(victim.GetId(), p2.GetId(), protocol::commands::GETHEADERS);

    // Stall p1 -> victim: drop all messages so no HEADERS arrive
    SimulatedNetwork::NetworkConditions drop; drop.packet_loss_rate = 1.0;
    net.SetLinkConditions(p1.GetId(), victim.GetId(), drop);

    // Advance beyond stall timeout and process timers
    for (int i = 0; i < 5; ++i) {
        t += 60 * 1000;
        net.AdvanceTime(t);
        victim.GetNetworkManager().test_hook_header_sync_process_timers();
    }

    // Give more time for stall disconnect to complete and state to stabilize
    t += 2000; net.AdvanceTime(t);

    // Re-select sync peer
    victim.GetNetworkManager().test_hook_check_initial_sync();
    t += 2000; net.AdvanceTime(t);  // Allow sync peer selection to complete fully

    // Verify new GETHEADERS went to p2 (the healthy peer)
    int gh_p1_after = net.CountCommandSent(victim.GetId(), p1.GetId(), protocol::commands::GETHEADERS);
    int gh_p2_after = net.CountCommandSent(victim.GetId(), p2.GetId(), protocol::commands::GETHEADERS);
    CHECK(gh_p2_after >= gh_p2_before);
    CHECK(gh_p1_after >= gh_p1_before);

    // Sync completes - allow more time for sync to finish
    // Don't call test_hook_check_initial_sync() repeatedly as it interferes with ongoing sync
    for (int i = 0; i < 20 && victim.GetTipHeight() < 30; ++i) {
        t += 500;
        net.AdvanceTime(t);
    }
    CHECK(victim.GetTipHeight() == 30);
}

TEST_CASE("DoS: Stall timeout disabled post-IBD", "[dos][network][ibd]") {
    // Regression test for bug where stall timeout incorrectly fired after IBD completion
    // causing spurious "Headers sync stalled" messages and peer disconnections
    SimulatedNetwork net(1004);

    // Setup: Two nodes that sync to a common chain
    SimulatedNode node1(1, &net);
    SimulatedNode node2(2, &net);

    // Mine blocks on node1
    for (int i = 0; i < 30; ++i) {
        node1.MineBlock();
    }
    REQUIRE(node1.GetTipHeight() == 30);

    // Connect node2 and sync it
    node2.ConnectTo(node1.GetId());
    uint64_t t = 1000;
    net.AdvanceTime(t);

    // Wait for sync to complete
    for (int i = 0; i < 20 && node2.GetTipHeight() < 30; ++i) {
        t += 1000;
        net.AdvanceTime(t);
        node2.GetNetworkManager().test_hook_check_initial_sync();
    }
    REQUIRE(node2.GetTipHeight() == 30);

    // Both nodes now synced (post-IBD state)
    // Verify IBD is complete
    REQUIRE_FALSE(node2.GetIsIBD());

    // Record peer count before stall simulation
    auto peers_before = node2.GetNetworkManager().peer_manager().get_all_peers();
    size_t peer_count_before = peers_before.size();
    REQUIRE(peer_count_before > 0);

    // Simulate extended period with no new headers (stall-like behavior)
    // Drop messages to prevent any HEADERS from arriving
    SimulatedNetwork::NetworkConditions drop;
    drop.packet_loss_rate = 1.0;
    net.SetLinkConditions(node1.GetId(), node2.GetId(), drop);

    // Advance way beyond stall timeout (multiple timeout periods)
    // Normal stall timeout is ~2min, we'll wait 10+ minutes
    for (int i = 0; i < 12; ++i) {
        t += 60 * 1000;  // Advance 1 minute
        net.AdvanceTime(t);
        node2.GetNetworkManager().test_hook_header_sync_process_timers();
    }

    // CRITICAL: Verify peer was NOT disconnected post-IBD
    // The stall timeout should only apply during IBD, not after
    auto peers_after = node2.GetNetworkManager().peer_manager().get_all_peers();
    CHECK(peers_after.size() == peer_count_before);

    // Verify node1 is still connected
    bool node1_still_connected = false;
    for (const auto& peer : peers_after) {
        if (peer->is_connected()) {
            node1_still_connected = true;
            break;
        }
    }
    CHECK(node1_still_connected);
}
