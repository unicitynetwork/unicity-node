// Sync Peer Edge Case Tests - Validates sync peer behavior under unusual conditions
// These tests verify sync works correctly in various edge case scenarios.
// NOTE: These are functional/integration tests, not unit tests for specific flag behavior.

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "infra/node_simulator.hpp"
#include "network/protocol.hpp"
#include "network/peer_misbehavior.hpp"

using namespace unicity;
using namespace unicity::test;
using namespace unicity::protocol;

// =============================================================================
// Test 1: Sync peer stalls, node falls back to alternate peer
// =============================================================================
TEST_CASE("Sync peer stall triggers fallback to alternate peer", "[network][sync_peer][edge_case][stall_fallback]") {
    // When sync peer stops responding (headers blocked), the node should
    // eventually time out and successfully sync with another available peer.

    SimulatedNetwork net(53001);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 50; ++i) {
        (void)miner.MineBlock();
    }

    // Two peers sync from miner
    SimulatedNode p1(2, &net);
    SimulatedNode p2(3, &net);

    p1.ConnectTo(miner.GetId());
    p2.ConnectTo(miner.GetId());

    uint64_t t = 1000;
    net.AdvanceTime(t);

    p1.CheckInitialSync();
    p2.CheckInitialSync();

    for (int i = 0; i < 20 && (p1.GetTipHeight() < 50 || p2.GetTipHeight() < 50); ++i) {
        t += 1000;
        net.AdvanceTime(t);
    }

    REQUIRE(p1.GetTipHeight() == 50);
    REQUIRE(p2.GetTipHeight() == 50);

    // Victim connects to both peers
    SimulatedNode victim(4, &net);
    victim.ConnectTo(p1.GetId());
    victim.ConnectTo(p2.GetId());

    t += 1000;
    net.AdvanceTime(t);

    // Select p1 as sync peer
    victim.CheckInitialSync();
    t += 2000;
    net.AdvanceTime(t);

    // Make some progress
    for (int i = 0; i < 5 && victim.GetTipHeight() < 15; ++i) {
        t += 1000;
        net.AdvanceTime(t);
    }

    int initial_progress = victim.GetTipHeight();
    CHECK(initial_progress > 0);

    // Now simulate stall by blocking HEADERS messages from p1 to victim
    SimulatedNetwork::NetworkConditions block_headers;
    block_headers.blocked_commands.insert("headers");
    net.SetLinkConditions(p1.GetId(), victim.GetId(), block_headers);

    // Advance time past the stall timeout (headers sync timeout is typically 2+ minutes)
    // We need to advance gradually to allow ProcessTimers to detect the stall
    for (int i = 0; i < 150; ++i) {
        t += 1000;  // 1 second increments
        net.AdvanceTime(t);
    }

    // At this point, p1 should have been disconnected due to stall
    // p2's sync_started flag should have been reset

    // Unblock headers for victim to receive from p2
    net.SetLinkConditions(p1.GetId(), victim.GetId(), SimulatedNetwork::NetworkConditions{});

    // Try to select new sync peer (should select p2 since flags were reset)
    victim.CheckInitialSync();
    t += 2000;
    net.AdvanceTime(t);

    // Sync should complete with p2
    for (int i = 0; i < 30 && victim.GetTipHeight() < 50; ++i) {
        t += 2000;
        net.AdvanceTime(t);
    }

    CHECK(victim.GetTipHeight() == 50);
}

// =============================================================================
// Test 2: Reconnect to former sync peer works correctly
// =============================================================================
TEST_CASE("Reconnect to former sync peer allows sync completion", "[network][sync_peer][edge_case][reconnect]") {
    // When a peer disconnects mid-sync and reconnects, sync should complete.
    // New connections get fresh state, so the peer is eligible for selection.

    SimulatedNetwork net(53002);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 40; ++i) {
        (void)miner.MineBlock();
    }

    SimulatedNode p1(2, &net);
    p1.ConnectTo(miner.GetId());

    uint64_t t = 1000;
    net.AdvanceTime(t);

    p1.CheckInitialSync();

    for (int i = 0; i < 15 && p1.GetTipHeight() < 40; ++i) {
        t += 1000;
        net.AdvanceTime(t);
    }

    REQUIRE(p1.GetTipHeight() == 40);

    // Victim connects to p1
    SimulatedNode victim(3, &net);
    victim.ConnectTo(p1.GetId());

    t += 1000;
    net.AdvanceTime(t);

    // Select p1 as sync peer
    victim.CheckInitialSync();
    t += 2000;
    net.AdvanceTime(t);

    // Make some progress
    for (int i = 0; i < 5 && victim.GetTipHeight() < 15; ++i) {
        t += 1000;
        net.AdvanceTime(t);
    }

    int progress_before_disconnect = victim.GetTipHeight();
    CHECK(progress_before_disconnect > 0);
    CHECK(progress_before_disconnect <= 40);

    // Disconnect from p1
    victim.DisconnectFrom(p1.GetId());
    t += 1000;
    net.AdvanceTime(t);

    // Reconnect to p1 (same node)
    victim.ConnectTo(p1.GetId());
    t += 2000;
    net.AdvanceTime(t);

    // p1 should be selectable again (fresh connection, sync_started=false)
    victim.CheckInitialSync();
    t += 2000;
    net.AdvanceTime(t);

    // Sync should complete
    for (int i = 0; i < 20 && victim.GetTipHeight() < 40; ++i) {
        t += 2000;
        net.AdvanceTime(t);
    }

    CHECK(victim.GetTipHeight() == 40);
}

// =============================================================================
// Test 3: Cycling through peers then reconnecting completes sync
// =============================================================================
TEST_CASE("Peer cycling with reconnection completes sync", "[network][sync_peer][edge_case][peer_cycling]") {
    // When peers are cycled through (connect/disconnect), reconnecting peers
    // get fresh connection state and sync can complete.

    SimulatedNetwork net(53003);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 60; ++i) {
        (void)miner.MineBlock();
    }

    // Three peers sync from miner
    SimulatedNode p1(2, &net);
    SimulatedNode p2(3, &net);
    SimulatedNode p3(4, &net);

    p1.ConnectTo(miner.GetId());
    p2.ConnectTo(miner.GetId());
    p3.ConnectTo(miner.GetId());

    uint64_t t = 1000;
    net.AdvanceTime(t);

    p1.CheckInitialSync();
    p2.CheckInitialSync();
    p3.CheckInitialSync();

    for (int i = 0; i < 25 && (p1.GetTipHeight() < 60 || p2.GetTipHeight() < 60 || p3.GetTipHeight() < 60); ++i) {
        t += 2000;
        net.AdvanceTime(t);
    }

    REQUIRE(p1.GetTipHeight() == 60);
    REQUIRE(p2.GetTipHeight() == 60);
    REQUIRE(p3.GetTipHeight() == 60);

    // Victim connects to all three
    SimulatedNode victim(5, &net);
    victim.ConnectTo(p1.GetId());
    victim.ConnectTo(p2.GetId());
    victim.ConnectTo(p3.GetId());

    t += 1000;
    net.AdvanceTime(t);

    // Force all peers to have sync_started=true by cycling through them
    // First, select p1
    victim.CheckInitialSync();
    t += 2000;
    net.AdvanceTime(t);

    // Disconnect p1 to trigger p2 selection
    victim.DisconnectFrom(p1.GetId());
    t += 1000;
    net.AdvanceTime(t);

    victim.CheckInitialSync();
    t += 2000;
    net.AdvanceTime(t);

    // Disconnect p2 to trigger p3 selection
    victim.DisconnectFrom(p2.GetId());
    t += 1000;
    net.AdvanceTime(t);

    victim.CheckInitialSync();
    t += 2000;
    net.AdvanceTime(t);

    // Now only p3 is connected and it's the sync peer
    // All peers that were connected had sync_started set

    // Make some progress with p3
    for (int i = 0; i < 5 && victim.GetTipHeight() < 20; ++i) {
        t += 2000;
        net.AdvanceTime(t);
    }

    int progress = victim.GetTipHeight();
    CHECK(progress > 0);

    // Reconnect p1 and p2
    victim.ConnectTo(p1.GetId());
    victim.ConnectTo(p2.GetId());
    t += 2000;
    net.AdvanceTime(t);

    // Now disconnect p3 (the sync peer) - this should reset flags on p1 and p2
    victim.DisconnectFrom(p3.GetId());
    t += 1000;
    net.AdvanceTime(t);

    // Select new sync peer (p1 or p2 should be available now)
    victim.CheckInitialSync();
    t += 2000;
    net.AdvanceTime(t);

    // Complete sync
    for (int i = 0; i < 30 && victim.GetTipHeight() < 60; ++i) {
        t += 2000;
        net.AdvanceTime(t);
    }

    CHECK(victim.GetTipHeight() == 60);
}

// =============================================================================
// Test 4: IBD to post-IBD transition with sync peer
// =============================================================================
TEST_CASE("IBD to post-IBD transition works with active sync peer", "[network][sync_peer][edge_case][ibd_transition]") {
    // Verifies that completing IBD while syncing doesn't break subsequent
    // block relay. This is a functional test of the IBD transition.

    SimulatedNetwork net(53004);

    SimulatedNode miner(1, &net);
    // Create a small chain that will allow IBD to complete quickly
    for (int i = 0; i < 20; ++i) {
        (void)miner.MineBlock();
    }

    SimulatedNode p1(2, &net);
    p1.ConnectTo(miner.GetId());

    uint64_t t = 1000;
    net.AdvanceTime(t);

    p1.CheckInitialSync();

    for (int i = 0; i < 15 && p1.GetTipHeight() < 20; ++i) {
        t += 1000;
        net.AdvanceTime(t);
    }

    REQUIRE(p1.GetTipHeight() == 20);

    // Victim connects to p1
    SimulatedNode victim(3, &net);
    victim.ConnectTo(p1.GetId());

    t += 1000;
    net.AdvanceTime(t);

    // Victim should be in IBD
    CHECK(victim.GetIsIBD() == true);

    // Select sync peer and start syncing
    victim.CheckInitialSync();
    t += 2000;
    net.AdvanceTime(t);

    // Sync to completion (this should exit IBD)
    for (int i = 0; i < 20 && victim.GetTipHeight() < 20; ++i) {
        t += 2000;
        net.AdvanceTime(t);
    }

    CHECK(victim.GetTipHeight() == 20);

    // After IBD completion, the node should handle new blocks normally
    // Mine more blocks and verify they propagate
    for (int i = 0; i < 5; ++i) {
        (void)miner.MineBlock();
    }

    // Sync new blocks to p1
    for (int i = 0; i < 10 && p1.GetTipHeight() < 25; ++i) {
        t += 2000;
        net.AdvanceTime(t);
    }

    REQUIRE(p1.GetTipHeight() == 25);

    // Victim should receive the new blocks via normal block relay
    for (int i = 0; i < 15 && victim.GetTipHeight() < 25; ++i) {
        t += 2000;
        net.AdvanceTime(t);
    }

    CHECK(victim.GetTipHeight() == 25);
}

// =============================================================================
// Test 5: Rapid connect/disconnect cycles don't crash
// =============================================================================
TEST_CASE("Rapid peer churn completes sync without crash", "[network][sync_peer][edge_case][rapid_churn]") {
    // Stress test: rapidly connecting and disconnecting shouldn't crash
    // or leave the node unable to sync when it finally stabilizes.

    SimulatedNetwork net(53005);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 30; ++i) {
        (void)miner.MineBlock();
    }

    SimulatedNode p1(2, &net);
    p1.ConnectTo(miner.GetId());

    uint64_t t = 1000;
    net.AdvanceTime(t);

    p1.CheckInitialSync();

    for (int i = 0; i < 15 && p1.GetTipHeight() < 30; ++i) {
        t += 1000;
        net.AdvanceTime(t);
    }

    REQUIRE(p1.GetTipHeight() == 30);

    SimulatedNode victim(3, &net);

    // Rapid churn: connect, disconnect, reconnect multiple times
    for (int cycle = 0; cycle < 5; ++cycle) {
        victim.ConnectTo(p1.GetId());
        t += 500;
        net.AdvanceTime(t);

        victim.CheckInitialSync();
        t += 500;
        net.AdvanceTime(t);

        victim.DisconnectFrom(p1.GetId());
        t += 500;
        net.AdvanceTime(t);
    }

    // After churn, connect and sync properly
    victim.ConnectTo(p1.GetId());
    t += 2000;
    net.AdvanceTime(t);

    victim.CheckInitialSync();
    t += 2000;
    net.AdvanceTime(t);

    // Should be able to sync successfully
    for (int i = 0; i < 25 && victim.GetTipHeight() < 30; ++i) {
        t += 2000;
        net.AdvanceTime(t);
    }

    CHECK(victim.GetTipHeight() == 30);
}

// =============================================================================
// Test 6: Network partition (all peers disconnect) then recovery
// =============================================================================
TEST_CASE("Network partition recovery allows sync completion", "[network][sync_peer][edge_case][partition_recovery]") {
    // When all peers disconnect (simulating network partition), then one
    // reconnects, sync should complete normally.

    SimulatedNetwork net(53006);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 40; ++i) {
        (void)miner.MineBlock();
    }

    SimulatedNode p1(2, &net);
    SimulatedNode p2(3, &net);
    SimulatedNode p3(4, &net);

    p1.ConnectTo(miner.GetId());
    p2.ConnectTo(miner.GetId());
    p3.ConnectTo(miner.GetId());

    uint64_t t = 1000;
    net.AdvanceTime(t);

    p1.CheckInitialSync();
    p2.CheckInitialSync();
    p3.CheckInitialSync();

    for (int i = 0; i < 20 && (p1.GetTipHeight() < 40 || p2.GetTipHeight() < 40 || p3.GetTipHeight() < 40); ++i) {
        t += 2000;
        net.AdvanceTime(t);
    }

    REQUIRE(p1.GetTipHeight() == 40);
    REQUIRE(p2.GetTipHeight() == 40);
    REQUIRE(p3.GetTipHeight() == 40);

    // Victim connects to all three
    SimulatedNode victim(5, &net);
    victim.ConnectTo(p1.GetId());
    victim.ConnectTo(p2.GetId());
    victim.ConnectTo(p3.GetId());

    t += 1000;
    net.AdvanceTime(t);

    // Select sync peer
    victim.CheckInitialSync();
    t += 2000;
    net.AdvanceTime(t);

    // Make some progress
    for (int i = 0; i < 5 && victim.GetTipHeight() < 15; ++i) {
        t += 1000;
        net.AdvanceTime(t);
    }

    CHECK(victim.GetTipHeight() > 0);

    // Disconnect all three peers simultaneously (simulating network partition)
    victim.DisconnectFrom(p1.GetId());
    victim.DisconnectFrom(p2.GetId());
    victim.DisconnectFrom(p3.GetId());

    t += 1000;
    net.AdvanceTime(t);

    // No peers left - sync peer should be cleared
    // Reconnect one peer
    victim.ConnectTo(p1.GetId());
    t += 2000;
    net.AdvanceTime(t);

    // Should be able to select p1 as sync peer (fresh connection)
    victim.CheckInitialSync();
    t += 2000;
    net.AdvanceTime(t);

    // Complete sync
    for (int i = 0; i < 25 && victim.GetTipHeight() < 40; ++i) {
        t += 2000;
        net.AdvanceTime(t);
    }

    CHECK(victim.GetTipHeight() == 40);
}

// =============================================================================
// Test 7: Post-sync block relay from peer that extends chain
// =============================================================================
TEST_CASE("Post-sync block relay delivers new blocks", "[network][sync_peer][edge_case][post_sync_relay]") {
    // After initial sync completes, when the sync peer's chain extends,
    // new blocks should be delivered via normal block relay (INV/getdata).
    // This tests the transition from header sync to steady-state block relay.

    SimulatedNetwork net(53007);

    // Miner has 30 blocks initially
    SimulatedNode miner(1, &net);
    for (int i = 0; i < 30; ++i) {
        (void)miner.MineBlock();
    }

    // p1 syncs to miner (has 30 blocks)
    SimulatedNode p1(2, &net);
    p1.ConnectTo(miner.GetId());

    uint64_t t = 1000;
    net.AdvanceTime(t);

    p1.CheckInitialSync();

    for (int i = 0; i < 15 && p1.GetTipHeight() < 30; ++i) {
        t += 1000;
        net.AdvanceTime(t);
    }

    REQUIRE(p1.GetTipHeight() == 30);

    // Victim connects to p1 and syncs to 30 blocks
    SimulatedNode victim(3, &net);
    victim.ConnectTo(p1.GetId());

    t += 1000;
    net.AdvanceTime(t);

    victim.CheckInitialSync();

    for (int i = 0; i < 20 && victim.GetTipHeight() < 30; ++i) {
        t += 2000;
        net.AdvanceTime(t);
    }

    REQUIRE(victim.GetTipHeight() == 30);

    // At this point, victim is synced with p1 at height 30
    // p1 should have sent empty headers, victim keeps p1 as sync peer

    // Now miner extends the chain
    for (int i = 0; i < 10; ++i) {
        (void)miner.MineBlock();
    }

    // Let p1 sync the new blocks from miner
    for (int i = 0; i < 15 && p1.GetTipHeight() < 40; ++i) {
        t += 2000;
        net.AdvanceTime(t);
    }

    REQUIRE(p1.GetTipHeight() == 40);

    // p1 should announce the new blocks to victim via block relay
    // Victim should receive them
    for (int i = 0; i < 20 && victim.GetTipHeight() < 40; ++i) {
        t += 2000;
        net.AdvanceTime(t);
    }

    CHECK(victim.GetTipHeight() == 40);
}

// =============================================================================
// Test 8: sync_started flag reset code path validation
//
// NOTE: This test is CONTRIVED. It uses NoBan permission to keep a misbehaving
// peer connected, which is not a realistic scenario. In practice:
// - Peers that send invalid headers get disconnected immediately
// - We would never retry syncing with a known-malicious peer
//
// The fix being tested (resetting sync_started on remaining peers when sync peer
// disconnects) appears to be defensive/future-proofing code. This test validates
// the code path works, but the real-world scenario where it matters is unclear.
// =============================================================================
TEST_CASE("sync_started flag reset on disconnect - contrived NoBan scenario", "[network][sync_peer][edge_case][flag_reset][contrived]") {
    // CONTRIVED SCENARIO using NoBan to force two peers to have sync_started=true:
    // 1. A (attacker) is selected as sync peer (A.sync_started=true)
    // 2. A sends invalid headers -> ClearSyncPeer called
    // 3. A stays connected because of NoBan permission (sync_started still true!)
    // 4. B is selected as sync peer (B.sync_started=true)
    // 5. Now BOTH have sync_started=true
    // 6. B disconnects
    // 7. Without fix: A.sync_started=true -> A skipped -> no sync peer -> stuck
    // 8. With fix: A.sync_started reset -> A can be retried
    //
    // In reality, we wouldn't want to retry with A (it sent invalid headers!),
    // but this test validates the flag reset mechanism works.

    SimulatedNetwork net(53008);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 50; ++i) {
        (void)miner.MineBlock();
    }

    // attacker is a NodeSimulator that can send invalid headers
    // It also syncs from miner so it has valid chain for later retry
    NodeSimulator attacker(2, &net);
    attacker.ConnectTo(miner.GetId());

    // p2 is a normal node with valid chain
    SimulatedNode p2(3, &net);
    p2.ConnectTo(miner.GetId());

    uint64_t t = 1000;
    net.AdvanceTime(t);

    attacker.CheckInitialSync();
    p2.CheckInitialSync();

    for (int i = 0; i < 20 && (attacker.GetTipHeight() < 50 || p2.GetTipHeight() < 50); ++i) {
        t += 1000;
        net.AdvanceTime(t);
    }

    REQUIRE(attacker.GetTipHeight() == 50);
    REQUIRE(p2.GetTipHeight() == 50);

    // Victim node
    SimulatedNode victim(4, &net);

    // Connect to attacker with NoBan permission (so attacker won't be disconnected for misbehavior)
    // We need to use the NetworkManager's connect_to directly to pass permissions
    {
        protocol::NetworkAddress addr;
        addr.services = protocol::ServiceFlags::NODE_NETWORK;
        addr.port = static_cast<uint16_t>(protocol::ports::REGTEST + attacker.GetId());
        // Set IPv4-mapped IPv6 address for attacker
        std::string attacker_ip = attacker.GetAddress();
        asio::error_code ec;
        auto ip_addr = asio::ip::make_address(attacker_ip, ec);
        REQUIRE(!ec);
        if (ip_addr.is_v4()) {
            auto v6_mapped = asio::ip::make_address_v6(asio::ip::v4_mapped, ip_addr.to_v4());
            auto bytes = v6_mapped.to_bytes();
            std::copy(bytes.begin(), bytes.end(), addr.ip.begin());
        }
        // Connect with NoBan permission
        auto result = victim.GetNetworkManager().connect_to(addr, network::NetPermissionFlags::NoBan);
        REQUIRE(result == network::ConnectionResult::Success);
    }

    t += 2000;
    net.AdvanceTime(t);

    // Select attacker as sync peer
    victim.CheckInitialSync();
    t += 500;
    net.AdvanceTime(t);

    // Let minimal sync progress happen (just enough to confirm sync started)
    // Don't let it complete - we need to test the attack scenario
    t += 500;
    net.AdvanceTime(t);

    int height_before_attack = victim.GetTipHeight();
    // Sync may or may not have made progress, but that's OK - the important thing is
    // testing the flag reset, not the sync progress
    // Note: height_before_attack could be 0 (no progress yet) or higher (some progress)

    // Now attacker sends invalid PoW headers
    // This triggers ClearSyncPeer but attacker stays connected (NoBan)
    // attacker.sync_started remains true
    attacker.SendInvalidPoWHeaders(victim.GetId(), victim.GetTipHash(), 1);
    t += 1000;
    net.AdvanceTime(t);

    // At this point:
    // - ClearSyncPeer was called (sync_peer_id = NO_SYNC_PEER)
    // - attacker is still connected (NoBan prevented disconnect)
    // - attacker.sync_started is still true (ClearSyncPeer doesn't reset it)

    // Connect victim to p2
    victim.ConnectTo(p2.GetId());
    t += 2000;
    net.AdvanceTime(t);

    // CheckInitialSync should skip attacker (sync_started=true) and select p2
    victim.CheckInitialSync();
    t += 2000;
    net.AdvanceTime(t);

    // Now: attacker.sync_started=true, p2.sync_started=true, sync_peer=p2
    // Let some time pass for sync with p2
    for (int i = 0; i < 3; ++i) {
        t += 500;
        net.AdvanceTime(t);
    }

    // Don't check height here - sync may complete quickly and that's fine
    // The important test is whether attacker can be re-selected after p2 disconnects

    // Disconnect p2 - this is the key moment!
    // OnPeerDisconnected should reset attacker.sync_started
    victim.DisconnectFrom(p2.GetId());
    t += 1000;
    net.AdvanceTime(t);

    // Now: sync_peer=NONE, attacker still connected
    // Without fix: attacker.sync_started=true -> can't select -> stuck
    // With fix: attacker.sync_started=false -> can select -> sync continues

    // Try to select sync peer again
    victim.CheckInitialSync();
    t += 2000;
    net.AdvanceTime(t);

    // If fix works, attacker should be selected and sync should complete
    for (int i = 0; i < 30 && victim.GetTipHeight() < 50; ++i) {
        t += 2000;
        net.AdvanceTime(t);
    }

    // Sync completed means attacker was re-selected (flag was reset)
    CHECK(victim.GetTipHeight() == 50);
}

// =============================================================================
// Test 9: INV-triggered sync peer adoption during IBD
// Tests sync_started state management
// =============================================================================
TEST_CASE("INV announcement triggers sync peer adoption during IBD", "[network][sync_peer][edge_case][inv_adoption]") {
    // During IBD with no sync peer, an outbound peer announcing via INV
    // should be adopted as sync peer.

    SimulatedNetwork net(53009);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 30; ++i) {
        (void)miner.MineBlock();
    }

    // p1 syncs from miner
    SimulatedNode p1(2, &net);
    p1.ConnectTo(miner.GetId());

    uint64_t t = 1000;
    net.AdvanceTime(t);

    p1.CheckInitialSync();

    for (int i = 0; i < 15 && p1.GetTipHeight() < 30; ++i) {
        t += 1000;
        net.AdvanceTime(t);
    }

    REQUIRE(p1.GetTipHeight() == 30);

    // Victim connects to p1 (outbound from victim's perspective)
    SimulatedNode victim(3, &net);
    victim.ConnectTo(p1.GetId());

    t += 1000;
    net.AdvanceTime(t);

    // Don't call test_hook_check_initial_sync - let INV trigger adoption
    // Victim is in IBD, has no sync peer

    // Miner extends chain
    for (int i = 0; i < 5; ++i) {
        (void)miner.MineBlock();
    }

    // p1 syncs new blocks
    for (int i = 0; i < 10 && p1.GetTipHeight() < 35; ++i) {
        t += 1000;
        net.AdvanceTime(t);
    }

    REQUIRE(p1.GetTipHeight() == 35);

    // p1 will announce new blocks via INV to victim
    // This should trigger adoption of p1 as sync peer
    for (int i = 0; i < 30 && victim.GetTipHeight() < 35; ++i) {
        t += 2000;
        net.AdvanceTime(t);
    }

    // Victim should have synced via INV-triggered adoption
    CHECK(victim.GetTipHeight() == 35);
}

// =============================================================================
// Test 10: Headers from non-sync peer during active sync
// =============================================================================
TEST_CASE("Headers from non-sync peer are processed correctly", "[network][sync_peer][edge_case][unsolicited_headers]") {
    // When syncing from peer A, if peer B sends unsolicited headers,
    // they should still be processed (headers are always welcome).

    SimulatedNetwork net(53010);

    // Two miners with different chains
    SimulatedNode miner1(1, &net);
    SimulatedNode miner2(2, &net);

    // miner1 has 30 blocks
    for (int i = 0; i < 30; ++i) {
        (void)miner1.MineBlock();
    }

    // miner2 has 40 blocks (longer chain)
    for (int i = 0; i < 40; ++i) {
        (void)miner2.MineBlock();
    }

    // p1 syncs from miner1 (30 blocks)
    SimulatedNode p1(3, &net);
    p1.ConnectTo(miner1.GetId());

    uint64_t t = 1000;
    net.AdvanceTime(t);
    p1.CheckInitialSync();

    for (int i = 0; i < 15 && p1.GetTipHeight() < 30; ++i) {
        t += 1000;
        net.AdvanceTime(t);
    }
    REQUIRE(p1.GetTipHeight() == 30);

    // p2 syncs from miner2 (40 blocks)
    SimulatedNode p2(4, &net);
    p2.ConnectTo(miner2.GetId());

    t += 1000;
    net.AdvanceTime(t);
    p2.CheckInitialSync();

    for (int i = 0; i < 20 && p2.GetTipHeight() < 40; ++i) {
        t += 1000;
        net.AdvanceTime(t);
    }
    REQUIRE(p2.GetTipHeight() == 40);

    // Victim connects to p1 first, then p2
    SimulatedNode victim(5, &net);
    victim.ConnectTo(p1.GetId());

    t += 1000;
    net.AdvanceTime(t);

    // Select p1 as sync peer
    victim.CheckInitialSync();
    t += 2000;
    net.AdvanceTime(t);

    // Start syncing with p1
    for (int i = 0; i < 5 && victim.GetTipHeight() < 15; ++i) {
        t += 1000;
        net.AdvanceTime(t);
    }

    int height_from_p1 = victim.GetTipHeight();
    CHECK(height_from_p1 > 0);

    // Now connect to p2 (has longer chain)
    victim.ConnectTo(p2.GetId());
    t += 2000;
    net.AdvanceTime(t);

    // p2 will announce its longer chain
    // Even though p1 is sync peer, p2's headers should be processed
    for (int i = 0; i < 30 && victim.GetTipHeight() < 40; ++i) {
        t += 2000;
        net.AdvanceTime(t);
    }

    // Victim should end up with p2's longer chain
    CHECK(victim.GetTipHeight() == 40);
}

// =============================================================================
// Test 11: Sync peer disconnects mid-batch (partial headers received)
// =============================================================================
TEST_CASE("Sync peer disconnect mid-batch continues with another peer", "[network][sync_peer][edge_case][mid_batch_disconnect]") {
    // If sync peer sends partial headers then disconnects,
    // another peer should continue from where we left off.

    SimulatedNetwork net(53011);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 100; ++i) {
        (void)miner.MineBlock();
    }

    // Both peers sync full chain from miner
    SimulatedNode p1(2, &net);
    SimulatedNode p2(3, &net);

    p1.ConnectTo(miner.GetId());
    p2.ConnectTo(miner.GetId());

    uint64_t t = 1000;
    net.AdvanceTime(t);

    p1.CheckInitialSync();
    p2.CheckInitialSync();

    for (int i = 0; i < 40 && (p1.GetTipHeight() < 100 || p2.GetTipHeight() < 100); ++i) {
        t += 2000;
        net.AdvanceTime(t);
    }

    REQUIRE(p1.GetTipHeight() == 100);
    REQUIRE(p2.GetTipHeight() == 100);

    // Victim connects to both
    SimulatedNode victim(4, &net);
    victim.ConnectTo(p1.GetId());
    victim.ConnectTo(p2.GetId());

    t += 1000;
    net.AdvanceTime(t);

    // Select p1 as sync peer
    victim.CheckInitialSync();
    t += 2000;
    net.AdvanceTime(t);

    // Sync partially with p1
    for (int i = 0; i < 10 && victim.GetTipHeight() < 40; ++i) {
        t += 2000;
        net.AdvanceTime(t);
    }

    int partial_height = victim.GetTipHeight();
    CHECK(partial_height > 0);
    // Note: Sync may complete quickly in test environment, that's OK
    // The important thing is to test the disconnect/recovery path

    // Disconnect p1 (may be mid-sync or after completion)
    victim.DisconnectFrom(p1.GetId());
    t += 1000;
    net.AdvanceTime(t);

    // p2 should become sync peer (flag reset allows this)
    victim.CheckInitialSync();
    t += 2000;
    net.AdvanceTime(t);

    // Complete sync with p2
    for (int i = 0; i < 40 && victim.GetTipHeight() < 100; ++i) {
        t += 2000;
        net.AdvanceTime(t);
    }

    // Should complete to full height
    CHECK(victim.GetTipHeight() == 100);
}

// =============================================================================
// Test 12: Feeler connection during sync should not interfere
// =============================================================================
TEST_CASE("Feeler connections do not interfere with sync peer", "[network][sync_peer][edge_case][feeler]") {
    // Feeler connections (short-lived probes) should not be selected as sync peer
    // and should not disrupt ongoing sync.
    // Note: Feelers auto-disconnect after handshake, so they shouldn't affect sync.

    SimulatedNetwork net(53012);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 50; ++i) {
        (void)miner.MineBlock();
    }

    SimulatedNode p1(2, &net);
    p1.ConnectTo(miner.GetId());

    uint64_t t = 1000;
    net.AdvanceTime(t);

    p1.CheckInitialSync();

    for (int i = 0; i < 20 && p1.GetTipHeight() < 50; ++i) {
        t += 1000;
        net.AdvanceTime(t);
    }

    REQUIRE(p1.GetTipHeight() == 50);

    // Victim connects to p1 (regular outbound)
    SimulatedNode victim(3, &net);
    victim.ConnectTo(p1.GetId());

    t += 1000;
    net.AdvanceTime(t);

    // Select p1 as sync peer
    victim.CheckInitialSync();
    t += 2000;
    net.AdvanceTime(t);

    // Start syncing
    for (int i = 0; i < 5 && victim.GetTipHeight() < 20; ++i) {
        t += 1000;
        net.AdvanceTime(t);
    }

    int height_mid_sync = victim.GetTipHeight();
    CHECK(height_mid_sync > 0);

    // Simulate a feeler-like connection: short connection that disconnects quickly
    // Create another node that connects briefly then disconnects
    SimulatedNode feeler_target(4, &net);
    feeler_target.ConnectTo(miner.GetId());
    t += 500;
    net.AdvanceTime(t);

    // feeler_target connects to victim (inbound to victim)
    feeler_target.ConnectTo(victim.GetId());
    t += 500;
    net.AdvanceTime(t);

    // Disconnect quickly (simulating feeler behavior)
    feeler_target.DisconnectFrom(victim.GetId());
    t += 500;
    net.AdvanceTime(t);

    // Original sync should continue unaffected
    for (int i = 0; i < 30 && victim.GetTipHeight() < 50; ++i) {
        t += 2000;
        net.AdvanceTime(t);
    }

    CHECK(victim.GetTipHeight() == 50);
}

// =============================================================================
// Test 13: Inbound-only node CAN sync (fallback to inbound when no outbound)
// =============================================================================
TEST_CASE("Inbound-only node syncs from inbound peer as fallback", "[network][sync_peer][edge_case][inbound_only]") {
    // Bitcoin Core behavior: PREFER outbound peers for sync, but FALL BACK to
    // inbound peers when no outbound peers are available. This matches
    // net_processing.cpp SendMessages logic where sync_blocks_and_headers_from_peer
    // is set for inbound when m_num_preferred_download_peers == 0.

    SimulatedNetwork net(53013);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 30; ++i) {
        (void)miner.MineBlock();
    }

    // p1 syncs from miner
    SimulatedNode p1(2, &net);

    p1.ConnectTo(miner.GetId());

    uint64_t t = 1000;
    net.AdvanceTime(t);

    p1.CheckInitialSync();

    for (int i = 0; i < 15 && p1.GetTipHeight() < 30; ++i) {
        t += 1000;
        net.AdvanceTime(t);
    }

    REQUIRE(p1.GetTipHeight() == 30);

    // Victim has NO outbound connections
    SimulatedNode victim(3, &net);

    // p1 connects TO victim (inbound from victim's perspective)
    p1.ConnectTo(victim.GetId());

    t += 1000;
    net.AdvanceTime(t);

    // Verify victim has inbound connection
    CHECK(victim.GetInboundPeerCount() == 1);
    CHECK(victim.GetOutboundPeerCount() == 0);

    // Try to select sync peer - should fall back to inbound
    victim.CheckInitialSync();
    t += 2000;
    net.AdvanceTime(t);

    // Sync should work via inbound peer fallback
    for (int i = 0; i < 20 && victim.GetTipHeight() < 30; ++i) {
        t += 2000;
        net.AdvanceTime(t);
    }

    // Victim should have synced from inbound peer
    CHECK(victim.GetTipHeight() == 30);
}
