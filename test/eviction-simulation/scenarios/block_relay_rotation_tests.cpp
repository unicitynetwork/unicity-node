// Copyright (c) 2025 The Unicity Foundation
// Block-relay peer rotation simulation tests
//
// These tests verify that the extra block-relay peer rotation mechanism
// (eclipse attack resistance) effectively rotates
// stale peers and maintains connection freshness.

#include "catch_amalgamated.hpp"
#include "eviction_test_network.hpp"

#include <set>

using namespace unicity::test::evicsim;

// =============================================================================
// BLOCK-RELAY ROTATION: Header-Triggered Rotation
// =============================================================================

TEST_CASE("Rotation: CheckRotationNeeded detects stale peers", "[evicsim][rotation][trigger]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Connect two block-relay peers at different times
  auto peer1_id = net.CreateNode("9.1.0.1");
  REQUIRE(net.Connect(victim_id, peer1_id, SimConnectionType::BLOCK_RELAY));

  // Advance time before connecting peer2 so they have different timestamps
  net.AdvanceTime(std::chrono::seconds(60));

  auto peer2_id = net.CreateNode("9.2.0.1");
  REQUIRE(net.Connect(victim_id, peer2_id, SimConnectionType::BLOCK_RELAY));

  // At this point:
  // - peer1: connected at T0, last_headers_received = T0
  // - peer2: connected at T60, last_headers_received = T60
  // peer1 is oldest (T0 < T60)

  // peer2 just connected with headers at T60, peer1 has T0
  // CheckRotationNeeded checks if sending_peer's headers > oldest's headers
  // peer2 (T60) > peer1 (T0), so rotation is needed
  int should_evict = net.CheckRotationNeeded(victim_id, peer2_id);
  REQUIRE(should_evict == peer1_id);

  // Now peer1 sends headers (update to current time)
  net.AdvanceTime(std::chrono::seconds(60));  // Now at T120
  net.SimulateHeadersReceived(victim_id, peer1_id);

  // peer1 now has T120, peer2 still has T60
  // If peer1 checks, peer2 is oldest but peer1's headers aren't "newer" (peer1 is sending)
  // Actually CheckRotationNeeded is called when a peer SENDS headers
  // So peer1 sending means we check if peer1's time > oldest (peer2)
  // peer1 (T120) > peer2 (T60), so peer2 should be evicted now
  should_evict = net.CheckRotationNeeded(victim_id, peer1_id);
  REQUIRE(should_evict == peer2_id);

  // If peer2 also sends headers at T120
  net.SimulateHeadersReceived(victim_id, peer2_id);
  // Now both have T120, no rotation needed (equal timestamps)
  // Actually peer2's time is now T120, peer1 is oldest at T120 too
  // With equal timestamps, no rotation needed
  // But wait - we need to check the actual oldest now
  // GetOldestBlockRelayPeer returns the one with smallest last_headers_received
  // Both are T120 now, so implementation detail determines which is "oldest"
  // The key is that neither is significantly staler than the other
}

TEST_CASE("Rotation: Only block-relay peers trigger rotation check", "[evicsim][rotation][trigger]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");

  // Connect full-relay and block-relay peers
  auto full_relay_id = net.CreateNode("9.1.0.1");
  auto block_relay1_id = net.CreateNode("9.2.0.1");
  auto block_relay2_id = net.CreateNode("9.3.0.1");

  REQUIRE(net.Connect(victim_id, full_relay_id, SimConnectionType::OUTBOUND_FULL_RELAY));
  REQUIRE(net.Connect(victim_id, block_relay1_id, SimConnectionType::BLOCK_RELAY));
  net.AdvanceTime(std::chrono::seconds(60));
  REQUIRE(net.Connect(victim_id, block_relay2_id, SimConnectionType::BLOCK_RELAY));

  net.AdvanceTime(std::chrono::seconds(120));

  // Full-relay peer sending headers should not trigger rotation
  net.SimulateHeadersReceived(victim_id, full_relay_id);
  REQUIRE(net.CheckRotationNeeded(victim_id, full_relay_id) == -1);

  // Block-relay peer sending headers should trigger rotation check
  net.SimulateHeadersReceived(victim_id, block_relay2_id);
  REQUIRE(net.CheckRotationNeeded(victim_id, block_relay2_id) == block_relay1_id);
}

TEST_CASE("Rotation: No rotation when block-relay slots not full", "[evicsim][rotation][trigger]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");

  // Connect only one block-relay peer (slots not full)
  auto peer_id = net.CreateNode("9.1.0.1");
  REQUIRE(net.Connect(victim_id, peer_id, SimConnectionType::BLOCK_RELAY));

  net.AdvanceTime(std::chrono::seconds(120));
  net.SimulateHeadersReceived(victim_id, peer_id);

  // No rotation needed - slots not full
  REQUIRE(net.CheckRotationNeeded(victim_id, peer_id) == -1);
}

// =============================================================================
// BLOCK-RELAY ROTATION: Basic Behavior
// =============================================================================

TEST_CASE("Rotation: Oldest block-relay peer identified correctly", "[evicsim][rotation][basic]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Create block-relay targets in different netgroups
  auto peer1_id = net.CreateNode("9.1.0.1");
  auto peer2_id = net.CreateNode("9.2.0.1");

  // Connect peer1 first (at T0)
  REQUIRE(net.Connect(victim_id, peer1_id, SimConnectionType::BLOCK_RELAY));

  // Advance time (to T60)
  net.AdvanceTime(std::chrono::seconds(60));

  // Connect peer2 (at T60, so peer2's last_headers_received = T60)
  REQUIRE(net.Connect(victim_id, peer2_id, SimConnectionType::BLOCK_RELAY));

  // peer1 should be oldest (last_headers_received = T0, peer2's = T60)
  int oldest = victim->GetOldestBlockRelayPeer();
  REQUIRE(oldest == peer1_id);

  // Advance time more (to T120)
  net.AdvanceTime(std::chrono::seconds(60));

  // Now peer1 receives headers (update timestamp to T120)
  net.SimulateHeadersReceived(victim_id, peer1_id);

  // Now peer2 should be oldest (peer1=T120, peer2=T60)
  oldest = victim->GetOldestBlockRelayPeer();
  REQUIRE(oldest == peer2_id);
}

TEST_CASE("Rotation: Stale peer evicted when new headers arrive", "[evicsim][rotation][eviction]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Fill block-relay slots
  auto stale_id = net.CreateNode("9.1.0.1");
  auto active_id = net.CreateNode("9.2.0.1");

  REQUIRE(net.Connect(victim_id, stale_id, SimConnectionType::BLOCK_RELAY));
  net.AdvanceTime(std::chrono::seconds(60));
  REQUIRE(net.Connect(victim_id, active_id, SimConnectionType::BLOCK_RELAY));

  // Both connected
  REQUIRE(victim->BlockRelayCount() == 2);

  // Active peer sends headers regularly
  net.SimulateHeadersReceived(victim_id, active_id);
  net.AdvanceTime(std::chrono::seconds(300));
  net.SimulateHeadersReceived(victim_id, active_id);

  // Stale peer never sends headers - oldest
  int oldest = victim->GetOldestBlockRelayPeer();
  REQUIRE(oldest == stale_id);

  // Create new candidate in different netgroup
  auto fresh_id = net.CreateNode("9.3.0.1");

  // Rotation: evict oldest, connect fresh
  REQUIRE(net.TryRotateBlockRelay(victim_id, {fresh_id}));

  // Verify stale peer evicted
  REQUIRE_FALSE(victim->IsConnectedTo(stale_id));

  // Verify fresh peer connected
  REQUIRE(victim->IsConnectedTo(fresh_id));

  // Active peer still connected
  REQUIRE(victim->IsConnectedTo(active_id));

  // Rotation count incremented
  REQUIRE(victim->block_relay_rotations == 1);
}

// =============================================================================
// BLOCK-RELAY ROTATION: Eclipse Attack Resistance
// =============================================================================

TEST_CASE("Rotation: Attacker stale peers rotate out", "[evicsim][rotation][eclipse]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Connect attacker as block-relay (pretends to be honest initially)
  auto attacker_id = net.CreateNode("44.1.0.1");
  REQUIRE(net.Connect(victim_id, attacker_id, SimConnectionType::BLOCK_RELAY));

  // Also connect honest peer
  auto honest_id = net.CreateNode("9.1.0.1");
  net.AdvanceTime(std::chrono::seconds(60));
  REQUIRE(net.Connect(victim_id, honest_id, SimConnectionType::BLOCK_RELAY));

  // Honest peer sends headers
  net.SimulateHeadersReceived(victim_id, honest_id);

  // Time passes, attacker never sends headers
  net.AdvanceTime(std::chrono::seconds(600));
  net.SimulateHeadersReceived(victim_id, honest_id);

  // Attacker should be oldest
  int oldest = victim->GetOldestBlockRelayPeer();
  REQUIRE(oldest == attacker_id);

  // Create new honest candidate
  auto new_honest_id = net.CreateNode("9.2.0.1");

  // Rotation evicts attacker
  REQUIRE(net.TryRotateBlockRelay(victim_id, {new_honest_id}));

  // Attacker gone
  REQUIRE_FALSE(victim->IsConnectedTo(attacker_id));

  // Both honest peers connected
  REQUIRE(victim->IsConnectedTo(honest_id));
  REQUIRE(victim->IsConnectedTo(new_honest_id));

  INFO("Eclipse attack mitigated: stale attacker rotated out");
}

TEST_CASE("Rotation: Multiple rotation cycles clear attackers", "[evicsim][rotation][eclipse][multi]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Fill with 2 attacker block-relay peers
  auto attacker1_id = net.CreateNode("44.1.0.1");
  auto attacker2_id = net.CreateNode("44.2.0.1");

  REQUIRE(net.Connect(victim_id, attacker1_id, SimConnectionType::BLOCK_RELAY));
  net.AdvanceTime(std::chrono::seconds(10));
  REQUIRE(net.Connect(victim_id, attacker2_id, SimConnectionType::BLOCK_RELAY));

  REQUIRE(victim->BlockRelayCount() == 2);

  // Prepare honest candidates
  std::vector<int> honest_candidates;
  for (int i = 1; i <= 5; ++i) {
    honest_candidates.push_back(net.CreateNode("9." + std::to_string(i) + ".0.1"));
  }

  // Simulate multiple rotation cycles
  for (int cycle = 0; cycle < 3; ++cycle) {
    net.AdvanceTime(std::chrono::seconds(600));  // Time passes

    // Honest peers in network send headers to their connections
    // (Not to victim because victim isn't connected to them yet)

    // Try rotation
    net.TryRotateBlockRelay(victim_id, honest_candidates);
  }

  // After rotations, both attackers should be evicted
  REQUIRE_FALSE(victim->IsConnectedTo(attacker1_id));
  REQUIRE_FALSE(victim->IsConnectedTo(attacker2_id));

  // Victim should have block-relay connections to honest peers
  REQUIRE(victim->BlockRelayCount() == 2);

  INFO("Rotation cycles: " << victim->block_relay_rotations);
  REQUIRE(victim->block_relay_rotations >= 2);
}

// =============================================================================
// BLOCK-RELAY ROTATION: Rotation Effectiveness Metrics
// =============================================================================

TEST_CASE("Rotation: Measure rotation effectiveness over time", "[evicsim][rotation][metrics]") {
  EvictionTestNetwork net(42);

  // Create 10 honest nodes
  std::vector<int> honest_nodes;
  for (int i = 1; i <= 10; ++i) {
    honest_nodes.push_back(net.CreateNode("9." + std::to_string(i) + ".0.1"));
  }

  // Create victim
  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Connect initial block-relay peers
  REQUIRE(net.Connect(victim_id, honest_nodes[0], SimConnectionType::BLOCK_RELAY));
  net.AdvanceTime(std::chrono::seconds(10));
  REQUIRE(net.Connect(victim_id, honest_nodes[1], SimConnectionType::BLOCK_RELAY));

  // Track which honest nodes have been block-relay connected
  std::set<int> seen_block_relay;
  seen_block_relay.insert(honest_nodes[0]);
  seen_block_relay.insert(honest_nodes[1]);

  // Simulate rotation over 20 cycles
  // Some peers send headers, some don't (stale)
  for (int cycle = 0; cycle < 20; ++cycle) {
    net.AdvanceTime(std::chrono::seconds(300));

    // Random peer sends headers (simulating active peer)
    auto peers = victim->GetConnectedPeerIds();
    if (!peers.empty()) {
      auto it = peers.begin();
      std::advance(it, cycle % peers.size());
      net.SimulateHeadersReceived(victim_id, *it);
    }

    // Try rotation with remaining honest candidates
    std::vector<int> candidates;
    for (int h : honest_nodes) {
      if (!victim->IsConnectedTo(h)) {
        candidates.push_back(h);
      }
    }
    if (net.TryRotateBlockRelay(victim_id, candidates)) {
      // Record newly connected peer
      for (int h : candidates) {
        if (victim->IsConnectedTo(h)) {
          seen_block_relay.insert(h);
        }
      }
    }
  }

  INFO("Total rotations: " << victim->block_relay_rotations);
  INFO("Unique block-relay peers seen: " << seen_block_relay.size());

  // Should have rotated through multiple peers
  REQUIRE(victim->block_relay_rotations > 0);

  // If rotation is working, we should see variety
  REQUIRE(seen_block_relay.size() > 2);
}

// =============================================================================
// BLOCK-RELAY ROTATION: Netgroup Diversity
// =============================================================================

TEST_CASE("Rotation: Rotation respects netgroup diversity", "[evicsim][rotation][diversity]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Connect initial block-relay peers from different netgroups
  auto peer1_id = net.CreateNode("9.1.0.1");
  auto peer2_id = net.CreateNode("9.2.0.1");

  REQUIRE(net.Connect(victim_id, peer1_id, SimConnectionType::BLOCK_RELAY));
  net.AdvanceTime(std::chrono::seconds(60));
  REQUIRE(net.Connect(victim_id, peer2_id, SimConnectionType::BLOCK_RELAY));

  // Time passes, peer1 becomes stale
  net.AdvanceTime(std::chrono::seconds(300));
  net.SimulateHeadersReceived(victim_id, peer2_id);

  // Try to rotate with candidate in SAME netgroup as peer1
  auto same_ng_id = net.CreateNode("9.1.0.2");  // Same /16 as peer1

  // Rotation should fail (same netgroup)
  REQUIRE_FALSE(net.TryRotateBlockRelay(victim_id, {same_ng_id}));

  // peer1 still connected (no valid candidate)
  REQUIRE(victim->IsConnectedTo(peer1_id));

  // Now try with different netgroup candidate
  auto diff_ng_id = net.CreateNode("9.3.0.1");  // Different /16

  REQUIRE(net.TryRotateBlockRelay(victim_id, {diff_ng_id}));

  // peer1 evicted, diff_ng connected
  REQUIRE_FALSE(victim->IsConnectedTo(peer1_id));
  REQUIRE(victim->IsConnectedTo(diff_ng_id));

  // Block-relay connections are from unique netgroups
  auto dist = victim->GetNetgroupDistribution();
  for (const auto& [peer_id, info] : victim->connections) {
    if (info.type == SimConnectionType::BLOCK_RELAY) {
      REQUIRE(dist[info.netgroup] == 1);
    }
  }
}
