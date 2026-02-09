// GETHEADERS throttling tests - Bitcoin Core parity
// Tests for the 2-minute throttle on GETHEADERS requests per peer
//
// The throttle works as follows:
// 1. When GETHEADERS is sent, peer->last_getheaders_time_ is set to current time
// 2. Subsequent GETHEADERS to same peer are blocked until 2 minutes elapse
// 3. Timestamp is cleared when valid HEADERS response is received
// 4. Throttle is per-peer (throttling peer A doesn't affect peer B)

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"
#include "util/time.hpp"

using namespace unicity;
using namespace unicity::test;
using namespace unicity::network;

// The throttle constant from header_sync_manager.cpp
static constexpr int64_t kHeadersResponseTimeSec = 120;  // 2 minutes

TEST_CASE("GETHEADERS throttle - timestamp lifecycle", "[network][throttle][getheaders]") {
    // Core test: verify timestamp is set on send and cleared on valid response
    SimulatedNetwork network(50001);

    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);

    for (int i = 0; i < 5; ++i) {
        (void)node1.MineBlock();
    }

    node2.ConnectTo(node1.GetId());
    network.AdvanceTime(1000);

    auto peers = node2.GetNetworkManager().peer_manager().get_all_peers();
    REQUIRE(!peers.empty());
    auto peer = peers[0];

    SECTION("timestamp starts at zero") {
        CHECK(peer->last_getheaders_time() == std::chrono::steady_clock::time_point{});
    }

    SECTION("timestamp set when GETHEADERS sent") {
        CHECK(peer->last_getheaders_time() == std::chrono::steady_clock::time_point{});

        node2.CheckInitialSync();
        network.AdvanceTime(100);

        // Timestamp should now be set
        CHECK(peer->last_getheaders_time() != std::chrono::steady_clock::time_point{});
    }

    SECTION("timestamp cleared after valid HEADERS received") {
        node2.CheckInitialSync();
        network.AdvanceTime(100);

        REQUIRE(peer->last_getheaders_time() != std::chrono::steady_clock::time_point{});

        // Let sync complete - HEADERS will be received
        for (int i = 0; i < 20; ++i) {
            network.AdvanceTime(100);
        }

        // Timestamp should be cleared
        CHECK(peer->last_getheaders_time() == std::chrono::steady_clock::time_point{});
        CHECK(node2.GetTipHeight() == 5);
    }
}

TEST_CASE("GETHEADERS throttle - blocks requests within 2 minutes", "[network][throttle][getheaders]") {
    // Test: Set throttle timestamp, try to sync, verify blocked; wait 2 min, verify allowed
    SimulatedNetwork network(50002);
    network.EnableCommandTracking(true);

    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);

    for (int i = 0; i < 5; ++i) {
        (void)node1.MineBlock();
    }

    node2.ConnectTo(node1.GetId());
    network.AdvanceTime(1000);

    // Let initial sync complete
    for (int i = 0; i < 20; ++i) {
        network.AdvanceTime(100);
    }
    REQUIRE(node2.GetTipHeight() == 5);

    auto peers = node2.GetNetworkManager().peer_manager().get_all_peers();
    REQUIRE(!peers.empty());
    auto peer = peers[0];

    // After sync, timestamp should be cleared
    REQUIRE(peer->last_getheaders_time() == std::chrono::steady_clock::time_point{});

    auto count_before = network.GetCommandPayloads(node2.GetId(), node1.GetId(), "getheaders").size();

    // Now manually set timestamp to simulate an in-flight GETHEADERS request
    auto throttle_timestamp = util::GetSteadyTime();
    peer->set_last_getheaders_time(throttle_timestamp);

    SECTION("requests blocked while throttle active") {
        // Advance 60 seconds (within 2-minute throttle window)
        network.AdvanceTime(60000);

        // Reset sync_started to allow sync attempt
        peer->set_sync_started(false);

        // Try to send GETHEADERS - should be throttled
        node2.CheckInitialSync();
        network.AdvanceTime(100);

        auto count_after = network.GetCommandPayloads(node2.GetId(), node1.GetId(), "getheaders").size();
        CHECK(count_after == count_before);  // No new GETHEADERS - throttled!
        CHECK(peer->last_getheaders_time() == throttle_timestamp);  // Timestamp unchanged
    }

    SECTION("requests allowed after 2 minutes") {
        // Advance past 2-minute throttle
        network.AdvanceTime((kHeadersResponseTimeSec + 10) * 1000);

        // Reset sync_started to allow sync attempt
        peer->set_sync_started(false);

        // Try to send GETHEADERS - should succeed now
        node2.CheckInitialSync();
        network.AdvanceTime(100);

        auto count_after = network.GetCommandPayloads(node2.GetId(), node1.GetId(), "getheaders").size();
        CHECK(count_after > count_before);  // New GETHEADERS sent

        // Timestamp should be updated to new time
        CHECK(peer->last_getheaders_time() > throttle_timestamp);
    }
}

TEST_CASE("GETHEADERS throttle - per-peer independence", "[network][throttle][getheaders]") {
    // Test: Throttling peer A should NOT affect peer B
    SimulatedNetwork network(50003);
    network.EnableCommandTracking(true);

    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);

    // node1 has blocks
    for (int i = 0; i < 5; ++i) {
        (void)node1.MineBlock();
    }

    // node2 connects to node1
    node2.ConnectTo(node1.GetId());
    network.AdvanceTime(1000);

    // Let sync complete
    for (int i = 0; i < 20; ++i) {
        network.AdvanceTime(100);
    }
    REQUIRE(node2.GetTipHeight() == 5);

    auto peers = node2.GetNetworkManager().peer_manager().get_all_peers();
    REQUIRE(peers.size() == 1);
    auto peer = peers[0];

    // Clear state for test
    REQUIRE(peer->last_getheaders_time() == std::chrono::steady_clock::time_point{});

    // Set throttle on this peer
    auto throttle_time = util::GetSteadyTime();
    peer->set_last_getheaders_time(throttle_time);

    // Now connect a NEW node (node3) to node1
    SimulatedNode node3(3, &network);
    node3.ConnectTo(node1.GetId());
    network.AdvanceTime(100);

    // Let node3 sync
    for (int i = 0; i < 20; ++i) {
        network.AdvanceTime(100);
    }

    // node3 should have synced (its peer to node1 is NOT throttled)
    CHECK(node3.GetTipHeight() == 5);

    // node2's peer should still be throttled (timestamp unchanged)
    CHECK(peer->last_getheaders_time() == throttle_time);

    // Verify: node3's peer to node1 has cleared throttle (completed sync)
    auto node3_peers = node3.GetNetworkManager().peer_manager().get_all_peers();
    REQUIRE(!node3_peers.empty());
    CHECK(node3_peers[0]->last_getheaders_time() == std::chrono::steady_clock::time_point{});
}

TEST_CASE("GETHEADERS throttle - valid HEADERS enables immediate follow-up", "[network][throttle][getheaders]") {
    // When valid HEADERS clears throttle, new blocks can be fetched immediately
    SimulatedNetwork network(50004);
    network.EnableCommandTracking(true);

    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);

    for (int i = 0; i < 5; ++i) {
        (void)node1.MineBlock();
    }

    node2.ConnectTo(node1.GetId());
    network.AdvanceTime(1000);
    node2.CheckInitialSync();

    for (int i = 0; i < 20; ++i) {
        network.AdvanceTime(100);
    }
    REQUIRE(node2.GetTipHeight() == 5);

    auto peers = node2.GetNetworkManager().peer_manager().get_all_peers();
    REQUIRE(!peers.empty());
    auto peer = peers[0];

    // After sync, throttle should be cleared
    CHECK(peer->last_getheaders_time() == std::chrono::steady_clock::time_point{});

    // Mine another block - node2 receives direct HEADERS announcement and syncs immediately
    (void)node1.MineBlock();

    for (int i = 0; i < 20; ++i) {
        network.AdvanceTime(100);
    }

    CHECK(node2.GetTipHeight() == 6);
}

TEST_CASE("GETHEADERS throttle - empty HEADERS also clears throttle", "[network][throttle][getheaders]") {
    // Test: When already synced, GETHEADERS gets empty HEADERS response,
    // which should still clear the throttle (code path at line 331).
    SimulatedNetwork network(50005);
    network.EnableCommandTracking(true);

    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);

    // Mine blocks on node1, sync node2
    for (int i = 0; i < 5; ++i) {
        (void)node1.MineBlock();
    }

    node2.ConnectTo(node1.GetId());
    network.AdvanceTime(1000);

    // Let sync complete
    for (int i = 0; i < 20; ++i) {
        network.AdvanceTime(100);
    }
    REQUIRE(node2.GetTipHeight() == 5);

    auto peers = node2.GetNetworkManager().peer_manager().get_all_peers();
    REQUIRE(!peers.empty());
    auto peer = peers[0];

    // After sync, throttle should be cleared
    REQUIRE(peer->last_getheaders_time() == std::chrono::steady_clock::time_point{});

    // Record GETHEADERS count before test
    auto count_before = network.GetCommandPayloads(node2.GetId(), node1.GetId(), "getheaders").size();

    // Manually set throttle timestamp, then trigger GETHEADERS when already synced
    // This will result in empty HEADERS (we're synced, nothing new)
    auto throttle_time = util::GetSteadyTime();
    peer->set_last_getheaders_time(throttle_time);

    // Advance past throttle window
    network.AdvanceTime((kHeadersResponseTimeSec + 10) * 1000);

    // Reset sync_started to allow another sync attempt
    peer->set_sync_started(false);

    // Trigger GETHEADERS - we're already synced so response will be empty HEADERS
    node2.CheckInitialSync();
    network.AdvanceTime(100);

    // Verify GETHEADERS was sent
    auto count_after = network.GetCommandPayloads(node2.GetId(), node1.GetId(), "getheaders").size();
    REQUIRE(count_after > count_before);

    // Let the empty HEADERS response come back
    for (int i = 0; i < 10; ++i) {
        network.AdvanceTime(100);
    }

    // Throttle should be cleared by empty HEADERS response (line 331)
    CHECK(peer->last_getheaders_time() == std::chrono::steady_clock::time_point{});

    // Verify we're still synced (nothing changed)
    CHECK(node2.GetTipHeight() == 5);
}

TEST_CASE("GETHEADERS throttle - functional sync despite throttle", "[network][throttle][getheaders]") {
    // End-to-end test: rapid block production still syncs correctly
    // The throttle + clearing mechanism should allow all blocks to sync
    SimulatedNetwork network(50006);

    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);

    // Initial sync
    for (int i = 0; i < 5; ++i) {
        (void)node1.MineBlock();
    }

    node2.ConnectTo(node1.GetId());
    network.AdvanceTime(1000);
    node2.CheckInitialSync();

    for (int i = 0; i < 20; ++i) {
        network.AdvanceTime(100);
    }
    REQUIRE(node2.GetTipHeight() == 5);

    // Rapid block production
    for (int i = 0; i < 20; ++i) {
        (void)node1.MineBlock();
        network.AdvanceTime(500);  // 500ms between blocks
    }

    // Allow sync to complete
    for (int i = 0; i < 50; ++i) {
        network.AdvanceTime(100);
    }

    // All blocks should have synced despite throttle
    // (throttle clears on each valid HEADERS response)
    CHECK(node2.GetTipHeight() == 25);
}
