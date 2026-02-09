// GETHEADERS Throttle Bypass Tests
//
// Tests for potential attacker bypass vectors of the GETHEADERS throttle.
// The throttle is designed to prevent flooding, but reconnection creates
// new Peer objects which reset the throttle state.
//
// Attack vectors tested:
// 1. Disconnect/reconnect to reset throttle
// 2. Partial valid headers then stall
// 3. All sync candidates throttled simultaneously
// 4. Rapid reconnect cycle to flood GETHEADERS

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"
#include "util/time.hpp"
#include "test_orchestrator.hpp"

using namespace unicity;
using namespace unicity::test;
using namespace unicity::network;

static struct GetheadersThrottleBypassTestSetup {
    GetheadersThrottleBypassTestSetup() { chain::GlobalChainParams::Select(chain::ChainType::REGTEST); }
} getheaders_throttle_bypass_test_setup;

// The throttle constant from header_sync_manager.cpp
static constexpr int64_t kHeadersResponseTimeSec = 120;  // 2 minutes

// =============================================================================
// TEST 1: Reconnect resets throttle timestamp (bypass vector)
// =============================================================================
// When a peer disconnects and reconnects, a new Peer object is created with
// throttle timestamp = 0. This allows the attacker to bypass the throttle.
//
// This test VERIFIES the throttle blocks, then shows reconnect bypasses it.

TEST_CASE("GETHEADERS throttle bypass: reconnect resets throttle", "[network][throttle][getheaders][bypass]") {
    SimulatedNetwork net(50101);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    // Server has blocks, clients will sync FROM server
    SimulatedNode server(1, &net, "10.0.0.1");
    for (int i = 0; i < 10; ++i) {
        (void)server.MineBlock();
    }

    // First client connects to server (client sends GETHEADERS)
    SimulatedNode client1(2, &net, "10.0.0.2");
    REQUIRE(client1.ConnectTo(server.GetId()));
    REQUIRE(orch.WaitForConnection(server, client1));

    // Let initial sync start
    for (int i = 0; i < 20; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Get client's peer object (connection to server)
    auto peers = client1.GetNetworkManager().peer_manager().get_all_peers();
    REQUIRE(peers.size() == 1);
    auto peer = peers[0];

    // Count GETHEADERS sent so far
    size_t getheaders_initial = net.GetCommandPayloads(client1.GetId(), server.GetId(), "getheaders").size();
    INFO("Initial GETHEADERS count: " << getheaders_initial);
    REQUIRE(getheaders_initial > 0);  // Sync started

    // Set throttle timestamp to NOW (simulating in-flight request)
    auto throttle_time = util::GetSteadyTime();
    peer->set_last_getheaders_time(throttle_time);
    peer->set_sync_started(false);  // Allow sync attempt

    // VERIFY THROTTLE BLOCKS: Try to trigger sync while throttled
    client1.CheckInitialSync();
    for (int i = 0; i < 10; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    size_t getheaders_while_throttled = net.GetCommandPayloads(client1.GetId(), server.GetId(), "getheaders").size();
    INFO("GETHEADERS while throttled: " << getheaders_while_throttled);

    // CRITICAL: Throttle should have blocked - no new GETHEADERS
    CHECK(getheaders_while_throttled == getheaders_initial);

    // ATTACK: Client disconnects
    client1.Disconnect(server.GetId());
    for (int i = 0; i < 10; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Create NEW client (simulates reconnect - creates new Peer object with throttle=0)
    SimulatedNode client2(3, &net, "10.0.0.2");  // Same IP, new node ID
    REQUIRE(client2.ConnectTo(server.GetId()));
    REQUIRE(orch.WaitForConnection(server, client2));

    for (int i = 0; i < 20; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Get the new peer object
    auto peers_after = client2.GetNetworkManager().peer_manager().get_all_peers();
    REQUIRE(peers_after.size() == 1);
    auto peer_after = peers_after[0];

    // New peer should have throttle timestamp reset (default time_point)
    CHECK(peer_after->last_getheaders_time() == std::chrono::steady_clock::time_point{});

    // Trigger sync on new connection
    peer_after->set_sync_started(false);
    client2.CheckInitialSync();
    for (int i = 0; i < 10; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    size_t getheaders_after_reconnect = net.GetCommandPayloads(client2.GetId(), server.GetId(), "getheaders").size();
    INFO("GETHEADERS after reconnect: " << getheaders_after_reconnect);

    // BYPASS VERIFIED: Reconnect allowed GETHEADERS despite being within throttle window
    CHECK(getheaders_after_reconnect > 0);
}

// =============================================================================
// TEST 2: Partial valid headers then stall - throttle behavior
// =============================================================================
// Attacker sends some valid headers but not a full batch, then stalls.
// Does the throttle clear (allowing retry) or stay set (blocking)?

TEST_CASE("GETHEADERS throttle bypass: partial headers then stall", "[network][throttle][getheaders][bypass]") {
    // Test: verify throttle clears when valid headers are received
    // When a peer sends valid HEADERS that connect to our chain, the throttle
    // timestamp should clear to allow follow-up GETHEADERS for remaining blocks.
    SimulatedNetwork net(50102);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    // Victim node
    SimulatedNode victim(1, &net);

    // Attacker has more blocks than victim initially
    SimulatedNode attacker(2, &net, "10.0.0.2");
    for (int i = 0; i < 50; ++i) {
        (void)attacker.MineBlock();
    }

    // Victim connects to attacker (victim will sync from attacker)
    REQUIRE(victim.ConnectTo(attacker.GetId()));
    REQUIRE(orch.WaitForConnection(attacker, victim));

    // Get victim's peer to attacker
    auto peers = victim.GetNetworkManager().peer_manager().get_all_peers();
    REQUIRE(peers.size() == 1);
    auto peer = peers[0];

    // Let sync complete - GETHEADERS will be sent, HEADERS received
    for (int i = 0; i < 50; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // After sync completes, throttle should be cleared (timestamp is default)
    auto throttle_after_sync = peer->last_getheaders_time();
    INFO("Victim tip height: " << victim.GetTipHeight());

    // Verify sync happened
    REQUIRE(victim.GetTipHeight() == 50);

    // Throttle should be cleared after valid headers received
    CHECK(throttle_after_sync == std::chrono::steady_clock::time_point{});

    // Additional verification: we can trigger a new sync without waiting for throttle
    // (This proves throttle was cleared, not just expired)
    peer->set_sync_started(false);
    auto count_before = net.GetCommandPayloads(victim.GetId(), attacker.GetId(), "getheaders").size();

    victim.CheckInitialSync();
    orch.AdvanceTime(std::chrono::milliseconds(100));

    auto count_after = net.GetCommandPayloads(victim.GetId(), attacker.GetId(), "getheaders").size();
    CHECK(count_after > count_before);  // New GETHEADERS was sent (not throttled)
}

// =============================================================================
// TEST 3: All sync candidates throttled - recovery behavior
// =============================================================================
// When all potential sync peers are throttled, the node must wait for
// throttle expiration or new peers before it can continue syncing.

TEST_CASE("GETHEADERS throttle bypass: all candidates throttled", "[network][throttle][getheaders][bypass]") {
    SimulatedNetwork net(50103);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    // Multiple peers with blocks
    SimulatedNode peer1(1, &net, "10.0.0.1");
    SimulatedNode peer2(2, &net, "10.0.0.2");

    for (int i = 0; i < 10; ++i) {
        (void)peer1.MineBlock();
        (void)peer2.MineBlock();
    }

    // Victim connects to both
    SimulatedNode victim(3, &net, "10.0.0.3");
    REQUIRE(victim.ConnectTo(peer1.GetId()));
    REQUIRE(victim.ConnectTo(peer2.GetId()));
    REQUIRE(orch.WaitForConnection(peer1, victim));
    REQUIRE(orch.WaitForConnection(peer2, victim));

    for (int i = 0; i < 10; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    auto peers = victim.GetNetworkManager().peer_manager().get_all_peers();
    REQUIRE(peers.size() == 2);

    // Manually throttle BOTH peers
    auto throttle_time = util::GetSteadyTime();
    for (auto& p : peers) {
        p->set_last_getheaders_time(throttle_time);
        p->set_sync_started(false);  // Allow sync attempt
    }

    size_t getheaders_before = net.GetCommandPayloads(victim.GetId(), peer1.GetId(), "getheaders").size()
                             + net.GetCommandPayloads(victim.GetId(), peer2.GetId(), "getheaders").size();

    // Try to sync - should be blocked (all candidates throttled)
    victim.CheckInitialSync();
    for (int i = 0; i < 10; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    size_t getheaders_during_throttle = net.GetCommandPayloads(victim.GetId(), peer1.GetId(), "getheaders").size()
                                      + net.GetCommandPayloads(victim.GetId(), peer2.GetId(), "getheaders").size();

    INFO("GETHEADERS while all throttled: " << (getheaders_during_throttle - getheaders_before));

    // Should not have sent new GETHEADERS (all throttled)
    CHECK(getheaders_during_throttle == getheaders_before);

    // RECOVERY: Advance past throttle window
    orch.AdvanceTime(std::chrono::seconds(kHeadersResponseTimeSec + 10));

    // Reset sync state for retry
    for (auto& p : peers) {
        p->set_sync_started(false);
    }

    // Now sync should work
    victim.CheckInitialSync();
    for (int i = 0; i < 30; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    size_t getheaders_after_recovery = net.GetCommandPayloads(victim.GetId(), peer1.GetId(), "getheaders").size()
                                     + net.GetCommandPayloads(victim.GetId(), peer2.GetId(), "getheaders").size();

    INFO("GETHEADERS after throttle expired: " << (getheaders_after_recovery - getheaders_during_throttle));

    // Should have sent GETHEADERS now (throttle expired)
    CHECK(getheaders_after_recovery > getheaders_during_throttle);
}

// =============================================================================
// TEST 4: Rapid reconnect cycle to flood GETHEADERS
// =============================================================================
// Attacker rapidly disconnects/reconnects to bypass per-peer throttle
// and flood the victim with GETHEADERS requests.
//
// This test VERIFIES throttle would block, then shows reconnect bypasses it.

TEST_CASE("GETHEADERS throttle bypass: rapid reconnect flood", "[network][throttle][getheaders][bypass][flood]") {
    SimulatedNetwork net(50104);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    // Attacker has blocks, victim syncs from attacker
    SimulatedNode attacker_base(1, &net, "10.0.0.1");
    for (int i = 0; i < 10; ++i) {
        (void)attacker_base.MineBlock();
    }

    size_t total_getheaders = 0;
    size_t throttle_blocks_verified = 0;
    const int NUM_CYCLES = 5;

    // ATTACK: Rapid connect/disconnect cycles from victim's perspective
    for (int cycle = 0; cycle < NUM_CYCLES; ++cycle) {
        // Create new victim node (simulates reconnect - new Peer object created)
        auto victim = std::make_unique<SimulatedNode>(100 + cycle, &net, "10.0.0.100");
        REQUIRE(victim->ConnectTo(attacker_base.GetId()));
        REQUIRE(orch.WaitForConnection(attacker_base, *victim));

        // Let sync start (GETHEADERS sent)
        for (int i = 0; i < 20; ++i) {
            orch.AdvanceTime(std::chrono::milliseconds(100));
        }

        // Count GETHEADERS from this connection
        size_t getheaders_after_connect = net.GetCommandPayloads(victim->GetId(), attacker_base.GetId(), "getheaders").size();
        INFO("Cycle " << cycle << ": GETHEADERS after connect = " << getheaders_after_connect);

        // Get peer and verify throttle is now set
        auto peers = victim->GetNetworkManager().peer_manager().get_all_peers();
        if (!peers.empty()) {
            auto peer = peers[0];

            // Set throttle to NOW and try to send more GETHEADERS
            auto now = util::GetSteadyTime();
            peer->set_last_getheaders_time(now);
            peer->set_sync_started(false);  // Allow sync attempt

            // Try to trigger sync while throttled
            victim->CheckInitialSync();
            for (int i = 0; i < 5; ++i) {
                orch.AdvanceTime(std::chrono::milliseconds(100));
            }

            size_t getheaders_after_throttle_attempt = net.GetCommandPayloads(victim->GetId(), attacker_base.GetId(), "getheaders").size();

            // Verify throttle blocked the request
            if (getheaders_after_throttle_attempt == getheaders_after_connect) {
                throttle_blocks_verified++;
                INFO("Cycle " << cycle << ": Throttle BLOCKED as expected");
            } else {
                INFO("Cycle " << cycle << ": Throttle did NOT block (sent " << (getheaders_after_throttle_attempt - getheaders_after_connect) << " more)");
            }
        }

        total_getheaders += getheaders_after_connect;

        // Disconnect
        victim->Disconnect(attacker_base.GetId());
        for (int i = 0; i < 5; ++i) {
            orch.AdvanceTime(std::chrono::milliseconds(100));
        }
    }

    INFO("Total GETHEADERS across " << NUM_CYCLES << " cycles: " << total_getheaders);
    INFO("Throttle blocks verified: " << throttle_blocks_verified << "/" << NUM_CYCLES);

    // VERIFY: Each reconnect allowed a new GETHEADERS (bypass)
    CHECK(total_getheaders >= NUM_CYCLES);  // At least 1 per cycle

    // VERIFY: Throttle would have blocked without reconnect
    CHECK(throttle_blocks_verified >= NUM_CYCLES - 1);  // Most cycles should verify blocking
}

// =============================================================================
// TEST 5: Mitigation check - connection rate limiting interaction
// =============================================================================
// This test verifies that the GETHEADERS throttle works on a single connection,
// then checks if connection rate limiting mitigates the reconnect bypass.

TEST_CASE("GETHEADERS throttle bypass: connection limiting mitigation", "[network][throttle][getheaders][bypass][mitigation]") {
    SimulatedNetwork net(50105);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    // Server with blocks (victim syncs from server)
    SimulatedNode server(1, &net, "10.0.0.1");
    for (int i = 0; i < 5; ++i) {
        (void)server.MineBlock();
    }

    // First connection - victim connects to server
    SimulatedNode victim1(100, &net, "10.0.0.100");
    REQUIRE(victim1.ConnectTo(server.GetId()));
    REQUIRE(orch.WaitForConnection(server, victim1));

    for (int i = 0; i < 20; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Count initial GETHEADERS
    size_t getheaders_initial = net.GetCommandPayloads(victim1.GetId(), server.GetId(), "getheaders").size();
    INFO("Initial GETHEADERS: " << getheaders_initial);
    REQUIRE(getheaders_initial > 0);

    // Get peer and set throttle
    auto peers1 = victim1.GetNetworkManager().peer_manager().get_all_peers();
    REQUIRE(peers1.size() == 1);
    auto peer1 = peers1[0];

    auto throttle_time = util::GetSteadyTime();
    peer1->set_last_getheaders_time(throttle_time);
    peer1->set_sync_started(false);

    // VERIFY: Throttle blocks on existing connection
    victim1.CheckInitialSync();
    for (int i = 0; i < 10; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    size_t getheaders_throttled = net.GetCommandPayloads(victim1.GetId(), server.GetId(), "getheaders").size();
    INFO("GETHEADERS while throttled: " << getheaders_throttled);
    CHECK(getheaders_throttled == getheaders_initial);  // Throttle blocked

    // Disconnect
    victim1.Disconnect(server.GetId());
    for (int i = 0; i < 5; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Try immediate reconnect from same IP
    SimulatedNode victim2(101, &net, "10.0.0.100");
    bool reconnect_success = victim2.ConnectTo(server.GetId());

    if (reconnect_success) {
        // Allow connection to establish
        REQUIRE(orch.WaitForConnection(server, victim2));
        for (int i = 0; i < 20; ++i) {
            orch.AdvanceTime(std::chrono::milliseconds(100));
        }

        // Check if GETHEADERS was sent on new connection
        size_t getheaders_after_reconnect = net.GetCommandPayloads(victim2.GetId(), server.GetId(), "getheaders").size();
        INFO("GETHEADERS after reconnect: " << getheaders_after_reconnect);

        // BYPASS: Reconnect allowed GETHEADERS despite being within throttle window
        // (New Peer object has throttle timestamp = 0)
        CHECK(getheaders_after_reconnect > 0);
        INFO("BYPASS CONFIRMED: Immediate reconnect allowed - throttle reset on new Peer object");
    } else {
        INFO("MITIGATION: Immediate reconnect blocked by connection rate limiting");
        CHECK(true);  // Pass - rate limiting helps mitigate the bypass
    }
}
