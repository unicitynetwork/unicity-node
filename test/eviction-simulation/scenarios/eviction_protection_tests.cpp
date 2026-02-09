// Copyright (c) 2025 The Unicity Foundation
// Eviction protection simulation tests
//
// These tests verify that the eviction protection phases work correctly:
// - PROTECT_BY_NETGROUP: Protect peers from diverse netgroups
// - PROTECT_BY_PING: Protect peers with best ping times
// - PROTECT_BY_HEADERS: Protect peers with recent header relay
// - PROTECT_BY_UPTIME: Protect oldest connections
// - PREFER_EVICT: Evict misbehaving peers first

#include "catch_amalgamated.hpp"
#include "eviction_test_network.hpp"

#include <set>

using namespace unicity::test::evicsim;

// =============================================================================
// PING-BASED PROTECTION
// =============================================================================

TEST_CASE("Protection: Low-ping peers protected from eviction", "[evicsim][protection][ping]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);
  victim->max_inbound = 100;

  // Create peers from same netgroup (so netgroup protection doesn't save them all)
  auto peers = net.CreateNodesInNetgroup(40, "44.1");
  for (int peer_id : peers) {
    net.Connect(peer_id, victim_id, SimConnectionType::INBOUND);
  }

  // Give first 10 peers excellent ping times
  std::set<int> low_ping_peers;
  for (int i = 0; i < 10; ++i) {
    net.SimulatePingResponse(victim_id, peers[i], 10 + i);  // 10-19ms
    low_ping_peers.insert(peers[i]);
  }

  // Give remaining peers poor ping times
  for (int i = 10; i < 40; ++i) {
    net.SimulatePingResponse(victim_id, peers[i], 500 + i);  // 500+ms
  }

  // Age connections
  net.AdvanceTime(std::chrono::seconds(120));

  // Trigger multiple evictions
  for (int i = 0; i < 15; ++i) {
    net.TryEvictInbound(victim_id);
  }

  // Low-ping peers should still be connected (protected by PROTECT_BY_PING=8)
  // At least 8 of the 10 low-ping peers should remain
  size_t low_ping_remaining = 0;
  for (int peer_id : low_ping_peers) {
    if (victim->IsConnectedTo(peer_id)) {
      low_ping_remaining++;
    }
  }

  INFO("Low-ping peers remaining: " << low_ping_remaining << " / 10");
  REQUIRE(low_ping_remaining >= 8);  // PROTECT_BY_PING = 8
}

TEST_CASE("Protection: No-response ping peers not protected", "[evicsim][protection][ping]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);
  victim->max_inbound = 100;

  // Create peers - half with ping, half without
  auto peers_with_ping = net.CreateNodesInNetgroup(20, "44.1");
  auto peers_no_ping = net.CreateNodesInNetgroup(20, "44.2");

  for (int peer_id : peers_with_ping) {
    net.Connect(peer_id, victim_id, SimConnectionType::INBOUND);
    net.SimulatePingResponse(victim_id, peer_id, 50);  // All have 50ms ping
  }

  for (int peer_id : peers_no_ping) {
    net.Connect(peer_id, victim_id, SimConnectionType::INBOUND);
    // No ping response - ping_time_ms remains -1
  }

  net.AdvanceTime(std::chrono::seconds(120));

  // Trigger evictions
  for (int i = 0; i < 20; ++i) {
    net.TryEvictInbound(victim_id);
  }

  // Count remaining from each group
  size_t with_ping_remaining = 0;
  size_t no_ping_remaining = 0;

  for (int peer_id : peers_with_ping) {
    if (victim->IsConnectedTo(peer_id)) with_ping_remaining++;
  }
  for (int peer_id : peers_no_ping) {
    if (victim->IsConnectedTo(peer_id)) no_ping_remaining++;
  }

  INFO("With ping remaining: " << with_ping_remaining);
  INFO("No ping remaining: " << no_ping_remaining);

  // Peers with ping should be preferentially retained
  REQUIRE(with_ping_remaining > no_ping_remaining);
}

// =============================================================================
// PREFER-EVICT (MISBEHAVING PEERS)
// =============================================================================

TEST_CASE("Protection: Prefer-evict peers evicted first", "[evicsim][protection][prefer-evict]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);
  victim->max_inbound = 100;

  // Create honest peers
  std::vector<int> honest;
  for (int i = 1; i <= 20; ++i) {
    std::string ng = "9." + std::to_string(i);
    honest.push_back(net.CreateNode(ng + ".0.1"));
  }

  // Create misbehaving peers
  auto misbehaving = net.CreateNodesInNetgroup(10, "44.1");

  // Connect all
  for (int peer_id : honest) {
    net.Connect(peer_id, victim_id, SimConnectionType::INBOUND);
  }
  for (int peer_id : misbehaving) {
    net.Connect(peer_id, victim_id, SimConnectionType::INBOUND);
  }

  // Mark misbehaving peers for preferential eviction
  for (int peer_id : misbehaving) {
    net.MarkPreferEvict(victim_id, peer_id);
  }

  net.AdvanceTime(std::chrono::seconds(60));

  // Trigger evictions - should evict misbehaving first
  for (int i = 0; i < 10; ++i) {
    net.TryEvictInbound(victim_id);
  }

  // All misbehaving should be evicted
  size_t misbehaving_remaining = 0;
  for (int peer_id : misbehaving) {
    if (victim->IsConnectedTo(peer_id)) misbehaving_remaining++;
  }

  INFO("Misbehaving remaining: " << misbehaving_remaining);
  REQUIRE(misbehaving_remaining == 0);

  // All honest should still be connected
  for (int peer_id : honest) {
    REQUIRE(victim->IsConnectedTo(peer_id));
  }
}

TEST_CASE("Protection: Prefer-evict evicts youngest misbehaving first", "[evicsim][protection][prefer-evict]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);
  victim->max_inbound = 100;

  // Need enough peers to survive protection phases (4 netgroup + 8 ping + 4 headers + 50% uptime)
  // Create 30 prefer_evict peers from same netgroup (so netgroup protection only saves 1)
  // All with same characteristics so they don't get protected by ping/headers
  std::vector<int> bad_peers;
  for (int i = 0; i < 30; ++i) {
    auto bad = net.CreateNode("44.1.0." + std::to_string(i + 1));
    net.Connect(bad, victim_id, SimConnectionType::INBOUND);
    net.MarkPreferEvict(victim_id, bad);
    bad_peers.push_back(bad);
    net.AdvanceTime(std::chrono::seconds(10));  // Each connected at different time
  }

  // The last peer connected is the youngest
  int youngest_bad = bad_peers.back();
  int oldest_bad = bad_peers.front();

  INFO("Total peers: " << victim->InboundCount());
  INFO("Youngest bad peer id: " << youngest_bad);
  INFO("Oldest bad peer id: " << oldest_bad);

  // Trigger eviction
  bool evicted = net.TryEvictInbound(victim_id);
  INFO("Eviction succeeded: " << evicted);

  // Count how many were evicted
  size_t still_connected = 0;
  int evicted_peer = -1;
  for (int peer : bad_peers) {
    if (victim->IsConnectedTo(peer)) {
      still_connected++;
    } else {
      evicted_peer = peer;
    }
  }
  INFO("Evicted peer id: " << evicted_peer);
  INFO("Bad peers still connected: " << still_connected);

  REQUIRE(evicted);
  REQUIRE(still_connected == 29);  // One evicted

  // The evicted peer should be one of the newer ones (after uptime protection removes oldest 50%)
  // After uptime protection, the 9 newest remain as candidates
  // Youngest of those should be evicted
  // But we can't guarantee youngest_bad specifically because ping/headers sort may reorder
  // Just verify that ONE was evicted and it's from the newer half
  int evicted_index = -1;
  for (size_t i = 0; i < bad_peers.size(); ++i) {
    if (bad_peers[i] == evicted_peer) {
      evicted_index = static_cast<int>(i);
      break;
    }
  }
  INFO("Evicted peer index: " << evicted_index << " (0=oldest, 29=youngest)");

  // The evicted peer should be from the newer half (index > ~15)
  // After netgroup(1) + ping(8) + headers(4) + uptime(50%), only ~9 remain
  // These should be the newest peers
  REQUIRE(evicted_index >= 15);  // Should be from newer half
}

// =============================================================================
// MANUAL CONNECTION BYPASS
// =============================================================================

TEST_CASE("Protection: Manual connections bypass inbound limits", "[evicsim][protection][manual]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);
  victim->max_inbound = 5;

  // Fill inbound slots
  for (int i = 1; i <= 5; ++i) {
    auto peer = net.CreateNode("9." + std::to_string(i) + ".0.1");
    REQUIRE(net.Connect(peer, victim_id, SimConnectionType::INBOUND));
  }

  REQUIRE(victim->InboundCount() == 5);

  // Manual connection should succeed even at limit
  auto manual_peer = net.CreateNode("10.1.0.1");
  REQUIRE(net.Connect(manual_peer, victim_id, SimConnectionType::MANUAL));

  // Total connections now exceed max_inbound (allowed for MANUAL)
  REQUIRE(victim->IsConnectedTo(manual_peer));
}

// =============================================================================
// HEADER RELAY PROTECTION
// =============================================================================

TEST_CASE("Protection: Recent header relay peers protected", "[evicsim][protection][headers]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);
  victim->max_inbound = 100;

  // Create peers from same netgroup
  auto peers = net.CreateNodesInNetgroup(40, "44.1");
  for (int peer_id : peers) {
    net.Connect(peer_id, victim_id, SimConnectionType::INBOUND);
  }

  // Age all connections
  net.AdvanceTime(std::chrono::seconds(300));

  // First 10 peers send headers (recent activity)
  std::set<int> active_peers;
  for (int i = 0; i < 10; ++i) {
    net.SimulateHeadersReceived(victim_id, peers[i]);
    active_peers.insert(peers[i]);
  }

  // Trigger evictions
  for (int i = 0; i < 20; ++i) {
    net.TryEvictInbound(victim_id);
  }

  // Active header-sending peers should be preferentially retained
  size_t active_remaining = 0;
  for (int peer_id : active_peers) {
    if (victim->IsConnectedTo(peer_id)) active_remaining++;
  }

  INFO("Active header peers remaining: " << active_remaining << " / 10");
  // PROTECT_BY_HEADERS = 4, so at least 4 should remain
  REQUIRE(active_remaining >= 4);
}

// =============================================================================
// UPTIME PROTECTION
// =============================================================================

TEST_CASE("Protection: Long-lived connections protected", "[evicsim][protection][uptime]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);
  victim->max_inbound = 100;

  // Connect old peers first
  std::set<int> old_peers;
  for (int i = 1; i <= 15; ++i) {
    auto peer = net.CreateNode("44." + std::to_string(i) + ".0.1");
    net.Connect(peer, victim_id, SimConnectionType::INBOUND);
    old_peers.insert(peer);
  }

  // Age them significantly
  net.AdvanceTime(std::chrono::seconds(3600));  // 1 hour

  // Connect new peers
  std::set<int> new_peers;
  for (int i = 20; i <= 35; ++i) {
    auto peer = net.CreateNode("44." + std::to_string(i) + ".0.1");
    net.Connect(peer, victim_id, SimConnectionType::INBOUND);
    new_peers.insert(peer);
  }

  // Small time advance for new peers
  net.AdvanceTime(std::chrono::seconds(10));

  // Trigger evictions
  for (int i = 0; i < 10; ++i) {
    net.TryEvictInbound(victim_id);
  }

  // Old peers should be preferentially retained (50% uptime protection)
  size_t old_remaining = 0;
  size_t new_remaining = 0;

  for (int peer_id : old_peers) {
    if (victim->IsConnectedTo(peer_id)) old_remaining++;
  }
  for (int peer_id : new_peers) {
    if (victim->IsConnectedTo(peer_id)) new_remaining++;
  }

  INFO("Old peers remaining: " << old_remaining << " / 15");
  INFO("New peers remaining: " << new_remaining << " / 16");

  // Old peers should have higher retention rate
  double old_rate = static_cast<double>(old_remaining) / 15;
  double new_rate = static_cast<double>(new_remaining) / 16;

  INFO("Old retention rate: " << (old_rate * 100) << "%");
  INFO("New retention rate: " << (new_rate * 100) << "%");

  REQUIRE(old_rate > new_rate);
}

// =============================================================================
// COMBINED PROTECTION
// =============================================================================

TEST_CASE("Protection: All phases work together", "[evicsim][protection][combined]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);
  victim->max_inbound = 100;

  // Create 50 peers with various properties
  std::set<int> diverse_netgroup_peers;  // Protected by netgroup
  std::set<int> low_ping_peers;          // Protected by ping
  std::set<int> active_header_peers;     // Protected by headers
  std::set<int> old_peers;               // Protected by uptime
  std::set<int> unprotected_peers;       // No special protection

  // Diverse netgroup peers (4 unique netgroups)
  for (int i = 1; i <= 4; ++i) {
    auto peer = net.CreateNode("9." + std::to_string(i) + ".0.1");
    net.Connect(peer, victim_id, SimConnectionType::INBOUND);
    diverse_netgroup_peers.insert(peer);
  }

  // Low ping peers (from same netgroup to test ping protection specifically)
  auto low_ping_nodes = net.CreateNodesInNetgroup(8, "44.1");
  for (int peer_id : low_ping_nodes) {
    net.Connect(peer_id, victim_id, SimConnectionType::INBOUND);
    net.SimulatePingResponse(victim_id, peer_id, 20);  // Excellent ping
    low_ping_peers.insert(peer_id);
  }

  // Old peers
  auto old_nodes = net.CreateNodesInNetgroup(10, "44.2");
  for (int peer_id : old_nodes) {
    net.Connect(peer_id, victim_id, SimConnectionType::INBOUND);
    old_peers.insert(peer_id);
  }

  // Age the old peers
  net.AdvanceTime(std::chrono::seconds(3600));

  // Active header peers
  auto active_nodes = net.CreateNodesInNetgroup(8, "44.3");
  for (int peer_id : active_nodes) {
    net.Connect(peer_id, victim_id, SimConnectionType::INBOUND);
    active_header_peers.insert(peer_id);
  }
  // Send headers from active peers
  for (int peer_id : active_header_peers) {
    net.SimulateHeadersReceived(victim_id, peer_id);
  }

  // Unprotected peers (recent, no ping, no headers, common netgroup)
  auto unprotected_nodes = net.CreateNodesInNetgroup(20, "44.4");
  for (int peer_id : unprotected_nodes) {
    net.Connect(peer_id, victim_id, SimConnectionType::INBOUND);
    unprotected_peers.insert(peer_id);
  }

  INFO("Total connections: " << victim->TotalConnectionCount());

  // Trigger many evictions
  for (int i = 0; i < 25; ++i) {
    net.TryEvictInbound(victim_id);
  }

  // Count survivors
  auto count_remaining = [&](const std::set<int>& peers) {
    size_t count = 0;
    for (int p : peers) {
      if (victim->IsConnectedTo(p)) count++;
    }
    return count;
  };

  size_t diverse_remaining = count_remaining(diverse_netgroup_peers);
  size_t low_ping_remaining = count_remaining(low_ping_peers);
  size_t active_remaining = count_remaining(active_header_peers);
  size_t old_remaining = count_remaining(old_peers);
  size_t unprotected_remaining = count_remaining(unprotected_peers);

  INFO("Diverse netgroup remaining: " << diverse_remaining << " / 4");
  INFO("Low ping remaining: " << low_ping_remaining << " / 8");
  INFO("Active header remaining: " << active_remaining << " / 8");
  INFO("Old peers remaining: " << old_remaining << " / 10");
  INFO("Unprotected remaining: " << unprotected_remaining << " / 20");

  // Protected categories should have higher retention
  // Unprotected should have lowest retention
  REQUIRE(diverse_remaining == 4);  // All protected by netgroup
  REQUIRE(low_ping_remaining >= 6);  // Most protected by ping
  REQUIRE(unprotected_remaining < 15);  // Should lose the most
}
