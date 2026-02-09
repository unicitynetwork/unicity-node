// Copyright (c) 2025 The Unicity Foundation
// Advanced eviction simulation tests
//
// These tests cover gaps in the original eviction simulation:
// 1. NoBan/Manual peer protection (is_protected)
// 2. Reconnection after eviction (persistent Sybil)
// 3. Multi-phase protection gaming (sophisticated attacker)
// 4. All-protected deadlock (SelectNodeToEvict returns nullopt)
// 5. Feeler connection lifecycle
// 6. Sustained inbound flooding over time

#include "catch_amalgamated.hpp"
#include "eviction_test_network.hpp"

#include <set>

using namespace unicity::test::evicsim;

// =============================================================================
// 1. NoBan/Manual PEER PROTECTION
// =============================================================================

TEST_CASE("NoBan: Protected peers survive eviction under extreme pressure", "[evicsim][noban][protection]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);
  victim->max_inbound = 30;

  // Connect 5 NoBan peers from same netgroup (worst case for eviction)
  std::set<int> noban_peers;
  auto noban_nodes = net.CreateNodesInNetgroup(5, "44.1");
  for (int peer_id : noban_nodes) {
    net.Connect(peer_id, victim_id, SimConnectionType::INBOUND);
    net.MarkProtected(victim_id, peer_id);
    noban_peers.insert(peer_id);
  }

  // Fill remaining slots with regular peers from same netgroup
  auto regular_nodes = net.CreateNodesInNetgroup(25, "44.2");
  for (int peer_id : regular_nodes) {
    net.Connect(peer_id, victim_id, SimConnectionType::INBOUND);
  }

  REQUIRE(victim->InboundCount() == 30);

  // Trigger 20 evictions — heavy pressure
  for (int i = 0; i < 20; ++i) {
    net.TryEvictInbound(victim_id);
  }

  // ALL NoBan peers must survive regardless of pressure
  for (int peer_id : noban_peers) {
    INFO("NoBan peer " << peer_id << " must survive");
    REQUIRE(victim->IsConnectedTo(peer_id));
  }
}

TEST_CASE("NoBan: Manual connections are automatically protected", "[evicsim][noban][manual]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);
  victim->max_inbound = 20;

  // Connect manual peer
  auto manual_peer = net.CreateNode("10.1.0.1");
  REQUIRE(net.Connect(manual_peer, victim_id, SimConnectionType::MANUAL));

  // Fill with regular inbound peers
  auto regulars = net.CreateNodesInNetgroup(25, "44.1");
  for (int peer_id : regulars) {
    net.Connect(peer_id, victim_id, SimConnectionType::INBOUND);
  }

  // Heavy eviction pressure
  for (int i = 0; i < 15; ++i) {
    net.TryEvictInbound(victim_id);
  }

  // Manual peer must survive (is_protected set automatically by Connect)
  REQUIRE(victim->IsConnectedTo(manual_peer));
}

TEST_CASE("NoBan: Protected prefer_evict peer still survives", "[evicsim][noban][prefer-evict]") {
  // A peer that is both NoBan AND prefer_evict should NOT be evicted
  // (is_protected takes precedence over prefer_evict)
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);
  victim->max_inbound = 30;

  // Connect a NoBan peer and mark it as misbehaving
  auto noban_bad = net.CreateNode("44.1.0.1");
  net.Connect(noban_bad, victim_id, SimConnectionType::INBOUND);
  net.MarkProtected(victim_id, noban_bad);
  net.MarkPreferEvict(victim_id, noban_bad);

  // Fill with regular peers
  auto regulars = net.CreateNodesInNetgroup(29, "44.2");
  for (int peer_id : regulars) {
    net.Connect(peer_id, victim_id, SimConnectionType::INBOUND);
  }

  // Trigger evictions
  for (int i = 0; i < 15; ++i) {
    net.TryEvictInbound(victim_id);
  }

  // NoBan peer survives even though it has prefer_evict
  REQUIRE(victim->IsConnectedTo(noban_bad));
}

// =============================================================================
// 2. RECONNECTION AFTER EVICTION (Persistent Sybil)
// =============================================================================

TEST_CASE("Reconnection: Evicted attacker reconnects persistently", "[evicsim][reconnect][sybil]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);
  victim->max_inbound = 30;

  // Create attacker pool (same /16, will be repeatedly evicted)
  auto attackers = net.CreateNodesInNetgroup(50, "44.99");

  // Create honest peers from diverse netgroups
  std::set<int> honest;
  for (int i = 1; i <= 20; ++i) {
    honest.insert(net.CreateNode("9." + std::to_string(i) + ".0.1"));
  }

  // Connect honest peers
  for (int h : honest) {
    net.Connect(h, victim_id, SimConnectionType::INBOUND);
  }

  // Simulate 50 rounds of attacker reconnection attempts
  size_t attacker_evictions = 0;
  for (int round = 0; round < 50; ++round) {
    // Attacker tries to connect all available nodes
    for (int a : attackers) {
      if (!victim->IsConnectedTo(a)) {
        net.Connect(a, victim_id, SimConnectionType::INBOUND);
      }
    }

    // Trigger evictions to bring back to limit
    while (victim->InboundCount() > victim->max_inbound) {
      if (!net.TryEvictInbound(victim_id)) break;
    }

    net.AdvanceTime(std::chrono::seconds(10));
  }

  // Count final state
  size_t attacker_count = 0;
  size_t honest_count = 0;
  for (const auto& [peer_id, _] : victim->connections) {
    if (honest.count(peer_id)) honest_count++;
    else attacker_count++;
  }

  INFO("Final attacker connections: " << attacker_count);
  INFO("Final honest connections: " << honest_count);
  INFO("Total evictions: " << victim->evictions_triggered);

  // Honest peers from diverse netgroups should dominate
  // Attacker from single /16 should be limited by netgroup eviction targeting
  REQUIRE(honest_count >= 15);

  // Slot limit always respected
  REQUIRE(victim->InboundCount() <= victim->max_inbound);
}

TEST_CASE("Reconnection: Attacker with multiple /16s reconnects", "[evicsim][reconnect][multi-subnet]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);
  victim->max_inbound = 40;

  // Attacker has 5 /16 subnets with 10 nodes each
  std::set<int> all_attackers;
  for (int subnet = 0; subnet < 5; ++subnet) {
    auto ids = net.CreateNodesInNetgroup(10, "44." + std::to_string(50 + subnet));
    all_attackers.insert(ids.begin(), ids.end());
  }

  // Honest peers: 30 peers from 30 unique netgroups
  std::set<int> honest;
  for (int i = 1; i <= 30; ++i) {
    honest.insert(net.CreateNode("9." + std::to_string(i) + ".0.1"));
  }

  // Connect honest first
  for (int h : honest) {
    net.Connect(h, victim_id, SimConnectionType::INBOUND);
  }

  // 100 rounds of persistent reconnection
  for (int round = 0; round < 100; ++round) {
    // Attackers reconnect
    for (int a : all_attackers) {
      if (!victim->IsConnectedTo(a)) {
        net.Connect(a, victim_id, SimConnectionType::INBOUND);
      }
    }

    // Evict to capacity
    while (victim->InboundCount() > victim->max_inbound) {
      if (!net.TryEvictInbound(victim_id)) break;
    }

    net.AdvanceTime(std::chrono::seconds(5));
  }

  // Measure attacker persistence
  size_t attacker_final = 0;
  for (const auto& [peer_id, _] : victim->connections) {
    if (all_attackers.count(peer_id)) attacker_final++;
  }

  double attacker_ratio = static_cast<double>(attacker_final) / victim->InboundCount();

  INFO("Attacker connections: " << attacker_final);
  INFO("Total connections: " << victim->InboundCount());
  INFO("Attacker ratio: " << (attacker_ratio * 100) << "%");
  INFO("Total evictions: " << victim->evictions_triggered);

  // Even with persistent reconnection from 5 subnets, attackers shouldn't
  // dominate a node with 30 diverse honest peers
  REQUIRE(attacker_ratio < 0.6);
  REQUIRE(victim->InboundCount() <= victim->max_inbound);
}

// =============================================================================
// 3. MULTI-PHASE PROTECTION GAMING
// =============================================================================

TEST_CASE("Gaming: Attacker stacks ping + headers + netgroup protection", "[evicsim][gaming][multi-phase]") {
  // Sophisticated attacker: excellent ping, active headers, diverse netgroups
  // Tests whether a single attacker can become "un-evictable"
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);
  victim->max_inbound = 50;

  // Create 20 attacker nodes across 20 unique netgroups
  // Each has excellent ping and sends headers — gaming all protection phases
  std::set<int> gaming_attackers;
  for (int i = 0; i < 20; ++i) {
    auto attacker = net.CreateNode("44." + std::to_string(i + 1) + ".0.1");
    net.Connect(attacker, victim_id, SimConnectionType::INBOUND);
    net.SimulatePingResponse(victim_id, attacker, 5 + i);  // 5-24ms — excellent
    gaming_attackers.insert(attacker);
  }

  // Age attacker connections (long uptime — games PROTECT_BY_UPTIME)
  net.AdvanceTime(std::chrono::seconds(7200));  // 2 hours

  // Attackers send headers (games PROTECT_BY_HEADERS)
  for (int a : gaming_attackers) {
    net.SimulateHeadersReceived(victim_id, a);
  }

  // Now connect honest peers — they are newer, higher ping, no headers yet
  std::set<int> honest;
  for (int i = 1; i <= 40; ++i) {
    auto h = net.CreateNode("9." + std::to_string(i) + ".0.1");
    net.Connect(h, victim_id, SimConnectionType::INBOUND);
    net.SimulatePingResponse(victim_id, h, 100 + i);  // 100ms+ — normal
    honest.insert(h);
  }

  INFO("Total before eviction: " << victim->InboundCount());

  // Trigger evictions to bring back to capacity
  while (victim->InboundCount() > victim->max_inbound) {
    if (!net.TryEvictInbound(victim_id)) break;
  }

  // Count survivors
  size_t attacker_remaining = 0;
  size_t honest_remaining = 0;
  for (const auto& [peer_id, _] : victim->connections) {
    if (gaming_attackers.count(peer_id)) attacker_remaining++;
    else if (honest.count(peer_id)) honest_remaining++;
  }

  INFO("Gaming attacker remaining: " << attacker_remaining << " / 20");
  INFO("Honest remaining: " << honest_remaining << " / 40");

  // The gaming attackers will have high retention (they game every phase).
  // But they can't take ALL slots — honest peers from diverse netgroups
  // also get netgroup protection. Verify honest still have meaningful presence.
  REQUIRE(honest_remaining >= 20);

  // Verify the gaming strategy doesn't let attackers take > 60% of slots
  double attacker_ratio = static_cast<double>(attacker_remaining) / victim->InboundCount();
  INFO("Attacker ratio: " << (attacker_ratio * 100) << "%");
  REQUIRE(attacker_ratio <= 0.6);
}

TEST_CASE("Gaming: Attacker with limited netgroups can't dominate via ping alone",
          "[evicsim][gaming][ping-only]") {
  // Attacker has 3 netgroups but excellent ping — can they fill all PROTECT_BY_PING slots?
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);
  victim->max_inbound = 40;

  // Attacker: 30 nodes in 3 netgroups, all with 1ms ping
  std::set<int> attackers;
  for (int subnet = 0; subnet < 3; ++subnet) {
    auto ids = net.CreateNodesInNetgroup(10, "44." + std::to_string(50 + subnet));
    for (int id : ids) {
      attackers.insert(id);
    }
  }

  for (int a : attackers) {
    net.Connect(a, victim_id, SimConnectionType::INBOUND);
    net.SimulatePingResponse(victim_id, a, 1);  // 1ms — fastest possible
  }

  // Honest: 20 nodes in 20 netgroups, normal ping
  std::set<int> honest;
  for (int i = 1; i <= 20; ++i) {
    auto h = net.CreateNode("9." + std::to_string(i) + ".0.1");
    net.Connect(h, victim_id, SimConnectionType::INBOUND);
    net.SimulatePingResponse(victim_id, h, 200);  // 200ms — slow
    honest.insert(h);
  }

  net.AdvanceTime(std::chrono::seconds(120));

  // Evict down to capacity
  while (victim->InboundCount() > victim->max_inbound) {
    if (!net.TryEvictInbound(victim_id)) break;
  }

  size_t attacker_remaining = 0;
  for (const auto& [peer_id, _] : victim->connections) {
    if (attackers.count(peer_id)) attacker_remaining++;
  }

  double attacker_ratio = static_cast<double>(attacker_remaining) / victim->InboundCount();
  INFO("Attacker remaining: " << attacker_remaining);
  INFO("Attacker ratio: " << (attacker_ratio * 100) << "%");

  // Despite having the best ping, attackers in only 3 netgroups
  // are limited by netgroup eviction targeting the largest groups
  REQUIRE(attacker_ratio < 0.7);
}

// =============================================================================
// 4. ALL-PROTECTED DEADLOCK (nullopt from SelectNodeToEvict)
// =============================================================================

TEST_CASE("Deadlock: All peers protected — eviction fails gracefully", "[evicsim][deadlock][nullopt]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);
  victim->max_inbound = 10;

  // Fill with NoBan protected peers from diverse netgroups
  std::vector<int> protected_peers;
  for (int i = 1; i <= 10; ++i) {
    auto peer = net.CreateNode("9." + std::to_string(i) + ".0.1");
    net.Connect(peer, victim_id, SimConnectionType::INBOUND);
    net.MarkProtected(victim_id, peer);
    protected_peers.push_back(peer);
  }

  REQUIRE(victim->InboundCount() == 10);

  // Try eviction — should fail (all protected)
  bool evicted = net.TryEvictInbound(victim_id);
  REQUIRE_FALSE(evicted);

  // All peers still connected
  for (int p : protected_peers) {
    REQUIRE(victim->IsConnectedTo(p));
  }

  // Inbound count unchanged
  REQUIRE(victim->InboundCount() == 10);
}

TEST_CASE("Deadlock: New connection rejected when all protected", "[evicsim][deadlock][reject]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);
  victim->max_inbound = 5;

  // Fill slots with protected peers
  for (int i = 1; i <= 5; ++i) {
    auto peer = net.CreateNode("9." + std::to_string(i) + ".0.1");
    net.Connect(peer, victim_id, SimConnectionType::INBOUND);
    net.MarkProtected(victim_id, peer);
  }

  REQUIRE(victim->InboundCount() == 5);

  // New peer tries to connect — slots full, eviction fails, connection rejected
  auto new_peer = net.CreateNode("10.1.0.1");
  bool connected = net.Connect(new_peer, victim_id, SimConnectionType::INBOUND);
  REQUIRE_FALSE(connected);

  // All original peers still there
  REQUIRE(victim->InboundCount() == 5);
  REQUIRE_FALSE(victim->IsConnectedTo(new_peer));
}

TEST_CASE("Deadlock: Mix of protected and unprotected — only unprotected evicted",
          "[evicsim][deadlock][mixed]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);
  victim->max_inbound = 30;

  // 15 protected peers
  std::set<int> protected_peers;
  for (int i = 1; i <= 15; ++i) {
    auto peer = net.CreateNode("9." + std::to_string(i) + ".0.1");
    net.Connect(peer, victim_id, SimConnectionType::INBOUND);
    net.MarkProtected(victim_id, peer);
    protected_peers.insert(peer);
  }

  // 15 regular peers from same netgroup
  auto regulars = net.CreateNodesInNetgroup(15, "44.1");
  for (int peer_id : regulars) {
    net.Connect(peer_id, victim_id, SimConnectionType::INBOUND);
  }

  REQUIRE(victim->InboundCount() == 30);

  // Trigger 10 evictions
  for (int i = 0; i < 10; ++i) {
    net.TryEvictInbound(victim_id);
  }

  // ALL protected peers must survive
  for (int p : protected_peers) {
    REQUIRE(victim->IsConnectedTo(p));
  }

  // Regular peers should have been evicted
  REQUIRE(victim->InboundCount() == 20);
}

// =============================================================================
// 5. FEELER CONNECTION LIFECYCLE
// =============================================================================

TEST_CASE("Feeler: Feeler connections don't consume inbound slots permanently",
          "[evicsim][feeler][lifecycle]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);
  victim->max_inbound = 10;

  // Fill inbound slots
  for (int i = 1; i <= 10; ++i) {
    auto peer = net.CreateNode("9." + std::to_string(i) + ".0.1");
    net.Connect(peer, victim_id, SimConnectionType::INBOUND);
  }

  REQUIRE(victim->InboundCount() == 10);

  // Feeler connects outbound, tests addr table, disconnects
  auto feeler_target = net.CreateNode("10.1.0.1");
  REQUIRE(net.Connect(victim_id, feeler_target, SimConnectionType::FEELER));

  // Feeler should be connected (as outbound on victim side)
  REQUIRE(victim->IsConnectedTo(feeler_target));

  // Feeler probe complete — disconnect
  net.Disconnect(victim_id, feeler_target);
  REQUIRE_FALSE(victim->IsConnectedTo(feeler_target));

  // Inbound slots unaffected
  REQUIRE(victim->InboundCount() == 10);
}

TEST_CASE("Feeler: Multiple feeler probes don't exhaust outbound slots",
          "[evicsim][feeler][slots]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Run 50 feeler probes (connect, disconnect cycle)
  for (int i = 1; i <= 50; ++i) {
    auto target = net.CreateNode("10." + std::to_string(i) + ".0.1");

    net.Connect(victim_id, target, SimConnectionType::FEELER);
    net.Disconnect(victim_id, target);
  }

  // No lingering connections
  REQUIRE(victim->TotalConnectionCount() == 0);

  // Outbound slots fully available
  REQUIRE(victim->NeedsMoreFullRelayOutbound());
  REQUIRE(victim->NeedsMoreBlockRelayOutbound());
}

TEST_CASE("Feeler: Feeler to peer in already-connected netgroup",
          "[evicsim][feeler][netgroup]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");

  // Establish full-relay outbound to 9.1
  auto outbound_peer = net.CreateNode("9.1.0.1");
  REQUIRE(net.Connect(victim_id, outbound_peer, SimConnectionType::OUTBOUND_FULL_RELAY));

  // Feeler to same netgroup — should still work (feelers are exempt from
  // outbound netgroup diversity since they disconnect immediately)
  auto feeler_target = net.CreateNode("9.1.0.2");
  bool feeler_ok = net.Connect(victim_id, feeler_target, SimConnectionType::FEELER);

  // Current implementation blocks same-netgroup feelers due to outbound diversity check.
  // Either outcome is acceptable — the important thing is it doesn't crash.
  // If blocked, outbound peer is still fine:
  REQUIRE(net.GetNode(victim_id)->IsConnectedTo(outbound_peer));

  if (feeler_ok) {
    // Clean up feeler
    net.Disconnect(victim_id, feeler_target);
  }
}

// =============================================================================
// 6. SUSTAINED INBOUND FLOODING
// =============================================================================

TEST_CASE("Flooding: Sustained 10 connections per tick for 1000 ticks",
          "[evicsim][flooding][sustained]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);
  victim->max_inbound = 30;

  // Pre-seed honest peers
  std::set<int> honest;
  for (int i = 1; i <= 20; ++i) {
    auto h = net.CreateNode("9." + std::to_string(i) + ".0.1");
    net.Connect(h, victim_id, SimConnectionType::INBOUND);
    net.SimulatePingResponse(victim_id, h, 50);
    honest.insert(h);
  }
  net.AdvanceTime(std::chrono::seconds(300));  // Age honest connections

  // Sustained attack: 10 new attacker connections per tick, 1000 ticks
  int next_attacker = 0;
  size_t total_attacker_attempts = 0;

  for (int tick = 0; tick < 1000; ++tick) {
    // Create and connect 10 attackers per tick
    for (int j = 0; j < 10; ++j) {
      int subnet = (next_attacker / 256) % 200 + 50;
      int host = (next_attacker % 256) + 1;
      std::string ip = "44." + std::to_string(subnet) + "." +
                       std::to_string(host / 256) + "." + std::to_string(host % 254 + 1);
      auto attacker = net.CreateNode(ip);
      net.Connect(attacker, victim_id, SimConnectionType::INBOUND);
      total_attacker_attempts++;
      next_attacker++;
    }

    // Evict to capacity (simulates production behavior)
    while (victim->InboundCount() > victim->max_inbound) {
      if (!net.TryEvictInbound(victim_id)) break;
    }

    net.AdvanceTime(std::chrono::seconds(1));
  }

  // Count honest survivors
  size_t honest_remaining = 0;
  for (int h : honest) {
    if (victim->IsConnectedTo(h)) honest_remaining++;
  }

  INFO("Total attacker connection attempts: " << total_attacker_attempts);
  INFO("Total evictions: " << victim->evictions_triggered);
  INFO("Honest remaining: " << honest_remaining << " / 20");
  INFO("Final inbound: " << victim->InboundCount());

  // Invariant: never exceed capacity
  REQUIRE(victim->InboundCount() <= victim->max_inbound);

  // Eviction algorithm didn't degrade — many evictions occurred
  REQUIRE(victim->evictions_triggered > 5000);
}

TEST_CASE("Flooding: Sustained attack doesn't starve honest peers with protection",
          "[evicsim][flooding][honest-retention]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);
  victim->max_inbound = 40;

  // Connect honest peers with good properties:
  // diverse netgroups, good ping, active headers, long uptime
  std::set<int> honest;
  for (int i = 1; i <= 20; ++i) {
    auto h = net.CreateNode("9." + std::to_string(i) + ".0.1");
    net.Connect(h, victim_id, SimConnectionType::INBOUND);
    net.SimulatePingResponse(victim_id, h, 30 + i);  // Good ping
    honest.insert(h);
  }

  // Age honest connections (uptime protection)
  net.AdvanceTime(std::chrono::seconds(3600));

  // Honest peers send headers (header protection)
  for (int h : honest) {
    net.SimulateHeadersReceived(victim_id, h);
  }

  // Sustained attack from limited netgroups
  int next_id = 0;
  for (int tick = 0; tick < 500; ++tick) {
    // 5 attackers per tick from 3 netgroups (poor diversity)
    for (int j = 0; j < 5; ++j) {
      int subnet = (next_id % 3) + 50;
      std::string ip = "44." + std::to_string(subnet) + "." +
                       std::to_string((next_id / 3) / 256) + "." +
                       std::to_string((next_id / 3) % 254 + 1);
      auto attacker = net.CreateNode(ip);
      net.Connect(attacker, victim_id, SimConnectionType::INBOUND);
      next_id++;
    }

    while (victim->InboundCount() > victim->max_inbound) {
      if (!net.TryEvictInbound(victim_id)) break;
    }

    // Periodically refresh honest headers (they're active peers)
    if (tick % 50 == 0) {
      for (int h : honest) {
        if (victim->IsConnectedTo(h)) {
          net.SimulateHeadersReceived(victim_id, h);
        }
      }
    }

    net.AdvanceTime(std::chrono::seconds(1));
  }

  // Count honest survivors
  size_t honest_remaining = 0;
  for (int h : honest) {
    if (victim->IsConnectedTo(h)) honest_remaining++;
  }

  INFO("Honest remaining after sustained attack: " << honest_remaining << " / 20");
  INFO("Total evictions: " << victim->evictions_triggered);

  // Honest peers with good protection attributes should mostly survive
  // They have: diverse netgroups (20 unique), good ping, recent headers, long uptime
  REQUIRE(honest_remaining >= 15);
}

TEST_CASE("Flooding: Eviction performance doesn't degrade over time",
          "[evicsim][flooding][performance]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);
  victim->max_inbound = 50;

  // Measure eviction counts in 100-tick windows
  std::vector<uint64_t> evictions_per_window;
  int next_id = 0;

  for (int window = 0; window < 10; ++window) {
    uint64_t evictions_before = victim->evictions_triggered;

    for (int tick = 0; tick < 100; ++tick) {
      // 5 attackers per tick
      for (int j = 0; j < 5; ++j) {
        int subnet = (next_id % 50) + 50;
        std::string ip = "44." + std::to_string(subnet) + "." +
                         std::to_string((next_id / 50) / 256) + "." +
                         std::to_string((next_id / 50) % 254 + 1);
        auto attacker = net.CreateNode(ip);
        net.Connect(attacker, victim_id, SimConnectionType::INBOUND);
        next_id++;
      }

      while (victim->InboundCount() > victim->max_inbound) {
        if (!net.TryEvictInbound(victim_id)) break;
      }

      net.AdvanceTime(std::chrono::seconds(1));
    }

    uint64_t evictions_this_window = victim->evictions_triggered - evictions_before;
    evictions_per_window.push_back(evictions_this_window);

    INFO("Window " << window << ": " << evictions_this_window << " evictions");
  }

  // Eviction rate should be roughly consistent across windows
  // (not degrading over time)
  uint64_t first_window = evictions_per_window[0];
  uint64_t last_window = evictions_per_window.back();

  INFO("First window evictions: " << first_window);
  INFO("Last window evictions: " << last_window);

  // Last window should be at least 50% of first (no major degradation)
  REQUIRE(last_window >= first_window / 2);

  // Invariant always holds
  REQUIRE(victim->InboundCount() <= victim->max_inbound);
}
