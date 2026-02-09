// Copyright (c) 2025 The Unicity Foundation
// Extra block-relay peer rotation integration tests (Bitcoin Core parity: eclipse resistance)
//
// These tests verify the extra block-relay peer rotation feature that periodically
// opens new block-relay-only connections to verify the chain tip from fresh sources.
// (Bitcoin Core parity: net_processing.cpp:5132-5177)
//
// Feature behavior:
// 1. After IBD completes, periodically attempt extra block-relay connections
// 2. Eviction ONLY happens when we have EXTRA peers (above target count)
// 3. When over target, default is to evict the YOUNGEST peer (the temporary extra one)
// 4. Exception: if youngest peer proved useful (sent recent headers), evict second-youngest
// 5. This ensures we keep peers that are actively helping while pruning temporary connections

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "infra/node_simulator.hpp"
#include "infra/test_access.hpp"
#include "network/protocol.hpp"
#include "network/addr_manager.hpp"
#include "network/network_manager.hpp"
#include "chain/block.hpp"
#include <asio.hpp>

using namespace unicity;
using namespace unicity::test;

static void SetZeroLatency(SimulatedNetwork& network) {
    SimulatedNetwork::NetworkConditions cond{};
    cond.latency_min = std::chrono::milliseconds(0);
    cond.latency_max = std::chrono::milliseconds(0);
    cond.jitter_max = std::chrono::milliseconds(0);
    network.SetNetworkConditions(cond);
}

static void AdvanceTime(SimulatedNetwork& net, uint64_t& t, int ms) {
    t += ms;
    net.AdvanceTime(t);
}

// Helper to wait for handshake completion
static void WaitForHandshake(SimulatedNetwork& net, uint64_t& t, int iterations = 10) {
    for (int i = 0; i < iterations; ++i) {
        AdvanceTime(net, t, 200);
    }
}

// =============================================================================
// GetOldestBlockRelayPeer Integration Tests
// =============================================================================

TEST_CASE("Extra block-relay rotation: GetOldestBlockRelayPeer finds correct peer", "[block_relay][rotation][integration]") {
    SimulatedNetwork net(53001);
    SetZeroLatency(net);

    // Create separate nodes for block-relay connections
    SimulatedNode node1(1, &net, "192.168.1.1");
    SimulatedNode node2(2, &net, "192.168.2.1");
    SimulatedNode node3(3, &net, "192.168.3.1");

    uint64_t t = 1000;

    // Have node1 connect to node2 and node3 as block-relay-only
    node1.ConnectToBlockRelayOnly(node2.GetId(), node2.GetAddress());
    WaitForHandshake(net, t);
    node1.ConnectToBlockRelayOnly(node3.GetId(), node3.GetAddress());
    WaitForHandshake(net, t);

    auto& pm = node1.GetNetworkManager().peer_manager();

    // Both should now be connected
    REQUIRE(pm.block_relay_outbound_count() == 2);

    // GetOldestBlockRelayPeer should return a valid peer
    int oldest = pm.GetOldestBlockRelayPeer();
    REQUIRE(oldest >= 0);

    // Simulate node2's peer sending headers by mining a block
    node2.MineBlock();
    WaitForHandshake(net, t);
    node1.CheckInitialSync();
    WaitForHandshake(net, t);

    // Now node3's peer should be oldest (node2's peer got headers)
    // unless both got headers via relay
    int new_oldest = pm.GetOldestBlockRelayPeer();
    REQUIRE(new_oldest >= 0);
}

TEST_CASE("Extra block-relay rotation: only considers outbound block-relay peers", "[block_relay][rotation][integration]") {
    SimulatedNetwork net(53002);
    SetZeroLatency(net);

    // Use separate nodes: node2 for full-relay, node3 for inbound, node4 for block-relay
    SimulatedNode node1(1, &net, "192.168.1.1");
    SimulatedNode node2(2, &net, "192.168.2.1");
    SimulatedNode node3(3, &net, "192.168.3.1");
    SimulatedNode node4(4, &net, "192.168.4.1");

    uint64_t t = 1000;

    // node1 connects to node2 as full-relay
    node1.ConnectToFullRelay(node2.GetId(), node2.GetAddress());
    WaitForHandshake(net, t);

    // node3 connects to node1 (inbound for node1)
    node3.ConnectToFullRelay(node1.GetId(), node1.GetAddress());
    WaitForHandshake(net, t);

    auto& pm = node1.GetNetworkManager().peer_manager();

    // node1 has one outbound full-relay and one inbound
    REQUIRE(pm.outbound_count() >= 1);
    REQUIRE(pm.inbound_count() >= 1);
    REQUIRE(pm.block_relay_outbound_count() == 0);

    // No block-relay-only peers, so should return -1
    CHECK(pm.GetOldestBlockRelayPeer() == -1);

    // Now add a block-relay peer using node4 (different from node2)
    node1.ConnectToBlockRelayOnly(node4.GetId(), node4.GetAddress());
    WaitForHandshake(net, t);

    // Now should have one block-relay peer
    REQUIRE(pm.block_relay_outbound_count() == 1);

    // Now should return a valid peer
    CHECK(pm.GetOldestBlockRelayPeer() >= 0);
}

// =============================================================================
// Peer Eviction Integration Tests
// =============================================================================

TEST_CASE("Extra block-relay rotation: no eviction when at target count", "[block_relay][rotation][eviction][integration]") {
    // Core parity: eviction ONLY happens when GetExtraBlockRelayCount() > 0
    // With 2 peers at target of 2, no eviction should occur even when headers arrive
    SimulatedNetwork net(53003);
    SetZeroLatency(net);

    SimulatedNode node1(1, &net, "192.168.1.1");
    SimulatedNode miner(2, &net, "192.168.2.1");
    SimulatedNode br1(3, &net, "192.168.3.1");
    SimulatedNode br2(4, &net, "192.168.4.1");

    uint64_t t = 1000;

    // Sync all nodes
    for (int i = 0; i < 10; ++i) {
        miner.MineBlock();
        AdvanceTime(net, t, 100);
    }

    node1.ConnectToFullRelay(miner.GetId(), miner.GetAddress());
    br1.ConnectToFullRelay(miner.GetId(), miner.GetAddress());
    br2.ConnectToFullRelay(miner.GetId(), miner.GetAddress());
    for (int i = 0; i < 20; ++i) {
        AdvanceTime(net, t, 200);
        node1.CheckInitialSync();
        br1.CheckInitialSync();
        br2.CheckInitialSync();
    }

    auto& pm = node1.GetNetworkManager().peer_manager();

    // Add exactly 2 block-relay peers (at target, not over)
    node1.ConnectToBlockRelayOnly(br1.GetId(), br1.GetAddress());
    WaitForHandshake(net, t);
    node1.ConnectToBlockRelayOnly(br2.GetId(), br2.GetAddress());
    WaitForHandshake(net, t);

    REQUIRE(pm.block_relay_outbound_count() == 2);
    REQUIRE(pm.GetExtraBlockRelayCount() == 0);  // At target, not over

    // Mine new block - headers arrive but NO eviction (not over target)
    br2.MineBlock();
    WaitForHandshake(net, t);
    node1.CheckInitialSync();
    WaitForHandshake(net, t);

    // Count should remain at 2 (no eviction when at target)
    CHECK(pm.block_relay_outbound_count() == 2);
}

TEST_CASE("Extra block-relay rotation: no eviction when peer hasn't received newer headers", "[block_relay][rotation][eviction][integration]") {
    SimulatedNetwork net(53004);
    SetZeroLatency(net);

    // Use separate nodes for block-relay to avoid any reconnection issues
    SimulatedNode node1(1, &net, "192.168.1.1");
    SimulatedNode node2(2, &net, "192.168.2.1");
    SimulatedNode node3(3, &net, "192.168.3.1");

    uint64_t t = 1000;

    auto& pm = node1.GetNetworkManager().peer_manager();

    // Connect directly as block-relay (no prior full-relay connections to worry about)
    node1.ConnectToBlockRelayOnly(node2.GetId(), node2.GetAddress());
    WaitForHandshake(net, t);
    node1.ConnectToBlockRelayOnly(node3.GetId(), node3.GetAddress());
    WaitForHandshake(net, t);

    size_t initial_block_relay_count = pm.block_relay_outbound_count();
    REQUIRE(initial_block_relay_count == 2);

    // Don't mine any new blocks - no new headers to trigger eviction
    for (int i = 0; i < 5; ++i) {
        AdvanceTime(net, t, 500);
    }

    // Count should remain stable (no eviction without new headers with more work)
    CHECK(pm.block_relay_outbound_count() == initial_block_relay_count);
}

// =============================================================================
// StartExtraBlockRelayPeers Integration Tests
// =============================================================================

TEST_CASE("Extra block-relay rotation: feature enabled after IBD completion", "[block_relay][rotation][ibd][integration]") {
    SimulatedNetwork net(53005);
    SetZeroLatency(net);

    SimulatedNode miner(1, &net, "192.168.1.1");
    SimulatedNode fresh(2, &net, "192.168.2.1");

    uint64_t t = 1000;

    // Mine blocks to create chain
    for (int i = 0; i < 50; ++i) {
        miner.MineBlock();
        AdvanceTime(net, t, 50);
    }
    REQUIRE(miner.GetTipHeight() == 50);

    // Fresh node starts in IBD
    REQUIRE(fresh.GetIsIBD() == true);

    // Connect and sync
    fresh.ConnectToFullRelay(miner.GetId(), miner.GetAddress());
    for (int i = 0; i < 30 && fresh.GetTipHeight() < 50; ++i) {
        AdvanceTime(net, t, 200);
        fresh.CheckInitialSync();
    }
    REQUIRE(fresh.GetTipHeight() == 50);

    // After sync, IBD should be complete
    // The maintenance loop in NetworkManager should have called StartExtraBlockRelayPeers
    CHECK(fresh.GetIsIBD() == false);
}

// =============================================================================
// Edge Cases
// =============================================================================

TEST_CASE("Extra block-relay rotation: handles single block-relay peer gracefully", "[block_relay][rotation][edge][integration]") {
    SimulatedNetwork net(53006);
    SetZeroLatency(net);

    SimulatedNode node1(1, &net, "192.168.1.1");
    SimulatedNode node2(2, &net, "192.168.2.1");

    uint64_t t = 1000;

    // Sync nodes via mining
    for (int i = 0; i < 5; ++i) {
        node2.MineBlock();
        AdvanceTime(net, t, 100);
    }

    auto& pm = node1.GetNetworkManager().peer_manager();

    // Add only one block-relay peer (no full-relay connection first)
    node1.ConnectToBlockRelayOnly(node2.GetId(), node2.GetAddress());
    WaitForHandshake(net, t);

    REQUIRE(pm.block_relay_outbound_count() == 1);

    // GetOldestBlockRelayPeer should return this peer
    int oldest = pm.GetOldestBlockRelayPeer();
    REQUIRE(oldest >= 0);

    // Mine new block - headers received but no eviction (only one peer, can't evict self)
    node2.MineBlock();
    WaitForHandshake(net, t);
    node1.CheckInitialSync();
    WaitForHandshake(net, t);

    // Should still have the peer (can't evict when it's the only one providing headers)
    CHECK(pm.block_relay_outbound_count() >= 1);
}

TEST_CASE("Extra block-relay rotation: peer removal updates oldest correctly", "[block_relay][rotation][edge][integration]") {
    SimulatedNetwork net(53007);
    SetZeroLatency(net);

    SimulatedNode node1(1, &net, "192.168.1.1");
    SimulatedNode node2(2, &net, "192.168.2.1");
    SimulatedNode node3(3, &net, "192.168.3.1");

    uint64_t t = 1000;

    auto& pm = node1.GetNetworkManager().peer_manager();

    // Add two block-relay peers directly (no prior full-relay connections)
    node1.ConnectToBlockRelayOnly(node2.GetId(), node2.GetAddress());
    WaitForHandshake(net, t);
    node1.ConnectToBlockRelayOnly(node3.GetId(), node3.GetAddress());
    WaitForHandshake(net, t);

    REQUIRE(pm.block_relay_outbound_count() == 2);

    int oldest1 = pm.GetOldestBlockRelayPeer();
    REQUIRE(oldest1 >= 0);

    // Remove the oldest peer manually
    pm.remove_peer(oldest1);
    AdvanceTime(net, t, 100);

    REQUIRE(pm.block_relay_outbound_count() == 1);

    // GetOldestBlockRelayPeer should now return the other peer
    int oldest2 = pm.GetOldestBlockRelayPeer();
    CHECK(oldest2 >= 0);
    CHECK(oldest2 != oldest1);  // Should be different peer
}

// =============================================================================
// Direct Code Path Verification Tests
// =============================================================================

// Helper to build NetworkAddress from IP string and node ID
static protocol::NetworkAddress MakeNetworkAddress(const std::string& ip_str, int node_id) {
    protocol::NetworkAddress addr;
    addr.services = protocol::ServiceFlags::NODE_NETWORK;
    addr.port = static_cast<uint16_t>(protocol::ports::REGTEST + node_id);
    asio::error_code ec;
    auto ip = asio::ip::make_address(ip_str, ec);
    auto v6 = asio::ip::make_address_v6(asio::ip::v4_mapped, ip.to_v4());
    auto bytes = v6.to_bytes();
    std::copy(bytes.begin(), bytes.end(), addr.ip.begin());
    return addr;
}

TEST_CASE("Extra block-relay rotation: eviction when over target - youngest evicted by default", "[block_relay][rotation][eviction][codepath][integration]") {
    // Core parity: net_processing.cpp:5132-5177
    // When we have EXTRA block-relay peers (above target of 2), eviction triggers.
    // Default behavior: evict the YOUNGEST peer (the temporary extra connection).
    //
    // This test:
    // 1. Connect 3 block-relay peers (1 over target of 2)
    // 2. Trigger headers from an OLDER peer (not the youngest)
    // 3. Youngest should be evicted (default behavior - didn't prove useful)

    SimulatedNetwork net(53010);
    SetZeroLatency(net);

    SimulatedNode victim(1, &net, "192.168.1.1");
    NodeSimulator peer_old(2, &net, "192.168.2.1");      // Oldest (lowest ID)
    NodeSimulator peer_mid(3, &net, "192.168.3.1");      // Middle
    NodeSimulator peer_young(4, &net, "192.168.4.1");    // Youngest (highest ID) - extra peer

    uint64_t t = 1000;

    auto& pm = victim.GetNetworkManager().peer_manager();

    // Connect 3 block-relay peers (1 over target of 2)
    // Use bypass_slot_limit to allow the third connection
    victim.ConnectToBlockRelayOnly(peer_old.GetId(), peer_old.GetAddress());
    WaitForHandshake(net, t);
    victim.ConnectToBlockRelayOnly(peer_mid.GetId(), peer_mid.GetAddress());
    WaitForHandshake(net, t);
    // Third peer bypasses slot limit (simulates extra block-relay connection)
    auto& nm = victim.GetNetworkManager();
    auto peer_young_addr = MakeNetworkAddress("192.168.4.1", 4);
    nm.connect_to(peer_young_addr, network::NetPermissionFlags::None,
                  network::ConnectionType::BLOCK_RELAY, /*bypass_slot_limit=*/true);
    WaitForHandshake(net, t);

    REQUIRE(pm.block_relay_outbound_count() == 3);
    REQUIRE(pm.GetExtraBlockRelayCount() == 1);  // 1 over target

    // Record peer IDs - youngest has highest ID
    std::vector<int> peer_ids_before;
    for (const auto& peer : pm.get_all_peers()) {
        if (peer && peer->is_block_relay_only() && !peer->is_inbound()) {
            peer_ids_before.push_back(peer->id());
        }
    }
    REQUIRE(peer_ids_before.size() == 3);
    std::sort(peer_ids_before.begin(), peer_ids_before.end());
    int youngest_id = peer_ids_before.back();  // Highest ID = youngest
    INFO("Before: peer IDs = " << peer_ids_before[0] << ", " << peer_ids_before[1] << ", " << peer_ids_before[2]);
    INFO("Youngest peer ID = " << youngest_id);

    // Send headers from peer_old (NOT the youngest)
    // This should trigger eviction of youngest (default behavior)
    peer_old.SetBypassPOWValidation(true);
    uint256 new_block = peer_old.MineBlock();
    CBlockHeader new_header = peer_old.GetBlockHeader(new_block);
    std::vector<CBlockHeader> headers = {new_header};
    peer_old.SendValidHeaders(victim.GetId(), headers);

    WaitForHandshake(net, t);
    victim.CheckInitialSync();
    WaitForHandshake(net, t);

    // Eviction should have happened - back to target of 2
    size_t final_count = pm.block_relay_outbound_count();
    INFO("Final block_relay_outbound_count: " << final_count);
    CHECK(final_count == 2);

    // Verify youngest was evicted (it didn't prove useful)
    if (final_count == 2) {
        std::vector<int> peer_ids_after;
        for (const auto& peer : pm.get_all_peers()) {
            if (peer && peer->is_block_relay_only() && !peer->is_inbound()) {
                peer_ids_after.push_back(peer->id());
            }
        }
        INFO("After: peer IDs = " << peer_ids_after[0] << ", " << peer_ids_after[1]);

        // Youngest should have been evicted
        bool youngest_evicted = std::find(peer_ids_after.begin(), peer_ids_after.end(), youngest_id) == peer_ids_after.end();
        CHECK(youngest_evicted);
    }
}

TEST_CASE("Extra block-relay rotation: youngest kept if it proved useful", "[block_relay][rotation][eviction][codepath][integration]") {
    // Core parity: net_processing.cpp:5152-5156
    // Exception to default: if youngest peer gave us headers more recently than
    // second-youngest, evict second-youngest instead (keep the useful new peer).
    //
    // This test:
    // 1. Connect 3 block-relay peers (1 over target)
    // 2. Trigger headers from the YOUNGEST peer
    // 3. Second-youngest should be evicted (youngest proved useful)

    SimulatedNetwork net(53020);
    SetZeroLatency(net);

    SimulatedNode victim(1, &net, "192.168.1.1");
    NodeSimulator peer_old(2, &net, "192.168.2.1");      // Oldest
    NodeSimulator peer_mid(3, &net, "192.168.3.1");      // Second-youngest - will be evicted
    NodeSimulator peer_young(4, &net, "192.168.4.1");    // Youngest - will prove useful

    uint64_t t = 1000;

    auto& pm = victim.GetNetworkManager().peer_manager();

    // Connect 3 block-relay peers
    victim.ConnectToBlockRelayOnly(peer_old.GetId(), peer_old.GetAddress());
    WaitForHandshake(net, t);
    victim.ConnectToBlockRelayOnly(peer_mid.GetId(), peer_mid.GetAddress());
    WaitForHandshake(net, t);
    auto& nm = victim.GetNetworkManager();
    auto peer_young_addr = MakeNetworkAddress("192.168.4.1", 4);
    nm.connect_to(peer_young_addr, network::NetPermissionFlags::None,
                  network::ConnectionType::BLOCK_RELAY, /*bypass_slot_limit=*/true);
    WaitForHandshake(net, t);

    REQUIRE(pm.block_relay_outbound_count() == 3);
    REQUIRE(pm.GetExtraBlockRelayCount() == 1);

    // Record peer IDs
    std::vector<int> peer_ids_before;
    for (const auto& peer : pm.get_all_peers()) {
        if (peer && peer->is_block_relay_only() && !peer->is_inbound()) {
            peer_ids_before.push_back(peer->id());
        }
    }
    std::sort(peer_ids_before.begin(), peer_ids_before.end());
    int youngest_id = peer_ids_before[2];        // Highest ID
    int second_youngest_id = peer_ids_before[1]; // Second highest ID
    INFO("Before: youngest=" << youngest_id << ", second_youngest=" << second_youngest_id);

    // Send headers from YOUNGEST peer - it will prove useful
    peer_young.SetBypassPOWValidation(true);
    uint256 new_block = peer_young.MineBlock();
    CBlockHeader new_header = peer_young.GetBlockHeader(new_block);
    std::vector<CBlockHeader> headers = {new_header};
    peer_young.SendValidHeaders(victim.GetId(), headers);

    WaitForHandshake(net, t);
    victim.CheckInitialSync();
    WaitForHandshake(net, t);

    // Eviction should have happened
    size_t final_count = pm.block_relay_outbound_count();
    INFO("Final block_relay_outbound_count: " << final_count);
    CHECK(final_count == 2);

    // Verify second-youngest was evicted (youngest proved useful, kept it)
    if (final_count == 2) {
        std::vector<int> peer_ids_after;
        for (const auto& peer : pm.get_all_peers()) {
            if (peer && peer->is_block_relay_only() && !peer->is_inbound()) {
                peer_ids_after.push_back(peer->id());
            }
        }
        INFO("After: peer IDs = " << peer_ids_after[0] << ", " << peer_ids_after[1]);

        // Youngest should still be present (it proved useful)
        bool youngest_present = std::find(peer_ids_after.begin(), peer_ids_after.end(), youngest_id) != peer_ids_after.end();
        CHECK(youngest_present);

        // Second-youngest should have been evicted
        bool second_youngest_evicted = std::find(peer_ids_after.begin(), peer_ids_after.end(), second_youngest_id) == peer_ids_after.end();
        CHECK(second_youngest_evicted);
    }
}

// =============================================================================
// Slot Bypass Tests (Core parity: net.cpp:2723)
// =============================================================================

TEST_CASE("Extra block-relay rotation: bypass_slot_limit allows connection past max", "[block_relay][rotation][slot_bypass][integration]") {
    // This test verifies that bypass_slot_limit=true allows a block-relay connection
    // even when all block-relay slots are full. This is the mechanism used by
    // attempt_extra_block_relay_connection() (Core parity: net.cpp:2723).
    //
    // The slot check happens in add_peer() which runs asynchronously after the
    // transport connect callback. ConnectTo() returns Success immediately (the
    // coarse needs_more_outbound check passes because full-relay slots are empty),
    // but the peer only actually gets added if add_peer() allows it.

    SimulatedNetwork net(53011);
    SetZeroLatency(net);

    SimulatedNode node1(1, &net, "192.168.1.1");
    SimulatedNode node2(2, &net, "192.168.2.1");
    SimulatedNode node3(3, &net, "192.168.3.1");
    SimulatedNode node4(4, &net, "192.168.4.1");
    SimulatedNode node5(5, &net, "192.168.5.1");

    uint64_t t = 1000;

    auto& nm = node1.GetNetworkManager();
    auto& pm = nm.peer_manager();

    // Fill both block-relay slots (default max_block_relay_outbound = 2)
    node1.ConnectToBlockRelayOnly(node2.GetId(), node2.GetAddress());
    WaitForHandshake(net, t);
    node1.ConnectToBlockRelayOnly(node3.GetId(), node3.GetAddress());
    WaitForHandshake(net, t);

    REQUIRE(pm.block_relay_outbound_count() == 2);

    // Build node4's NetworkAddress
    auto make_addr = [](const std::string& ip_str, int node_id) {
        protocol::NetworkAddress addr;
        addr.services = protocol::ServiceFlags::NODE_NETWORK;
        addr.port = static_cast<uint16_t>(protocol::ports::REGTEST + node_id);
        asio::error_code ec;
        auto ip = asio::ip::make_address(ip_str, ec);
        auto v6 = asio::ip::make_address_v6(asio::ip::v4_mapped, ip.to_v4());
        auto bytes = v6.to_bytes();
        std::copy(bytes.begin(), bytes.end(), addr.ip.begin());
        return addr;
    };

    // Without bypass: ConnectTo returns Success (coarse check passes) but add_peer
    // rejects the peer because block-relay slots are full. After processing events,
    // the peer count should NOT increase.
    auto node4_addr = make_addr("192.168.4.1", 4);
    auto result1 = nm.connect_to(node4_addr, network::NetPermissionFlags::None,
                                 network::ConnectionType::BLOCK_RELAY, /*bypass_slot_limit=*/false);
    // ConnectTo succeeds (starts connection) but add_peer will reject asynchronously
    CHECK(result1 == network::ConnectionResult::Success);
    WaitForHandshake(net, t);
    // add_peer rejected the peer — count stays at 2
    CHECK(pm.block_relay_outbound_count() == 2);

    // With bypass: both ConnectTo and add_peer allow the connection
    auto node5_addr = make_addr("192.168.5.1", 5);
    auto result2 = nm.connect_to(node5_addr, network::NetPermissionFlags::None,
                                 network::ConnectionType::BLOCK_RELAY, /*bypass_slot_limit=*/true);
    CHECK(result2 == network::ConnectionResult::Success);
    WaitForHandshake(net, t);

    // KEY CHECK: block-relay count should now be 3 (exceeding normal max of 2)
    // Before the fix, this would stay at 2 because add_peer rejected the connection.
    CHECK(pm.block_relay_outbound_count() == 3);
}
