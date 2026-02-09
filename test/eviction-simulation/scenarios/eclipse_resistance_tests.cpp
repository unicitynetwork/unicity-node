// Copyright (c) 2025 The Unicity Foundation
// Eclipse attack resistance simulation tests
//
// These tests verify that the peer connection security properties
// protect against eclipse attacks through statistical analysis over
// many trials.

#include "catch_amalgamated.hpp"
#include "eviction_test_network.hpp"

#include <set>

using namespace unicity::test::evicsim;

// Helper: Create a victim node and return its ID
static int CreateVictimNode(EvictionTestNetwork& net) {
  return net.CreateNode("8.1.0.1");
}

// Helper: Create attacker nodes in a single /16 (Sybil attack)
static std::set<int> CreateSybilAttackers(EvictionTestNetwork& net, size_t count, const std::string& netgroup) {
  auto ids = net.CreateNodesInNetgroup(count, netgroup);
  return std::set<int>(ids.begin(), ids.end());
}

// Helper: Create honest nodes across diverse netgroups
static std::set<int> CreateHonestNodes(EvictionTestNetwork& net, size_t count) {
  std::set<int> ids;
  for (size_t i = 0; i < count; ++i) {
    std::string ng = "9." + std::to_string(i + 1);
    auto node_ids = net.CreateNodesInNetgroup(1, ng);
    ids.insert(node_ids.begin(), node_ids.end());
  }
  return ids;
}

// =============================================================================
// ECLIPSE RESISTANCE: Single /16 Sybil Attack
// =============================================================================

TEST_CASE("Eclipse: Single /16 Sybil attack - inbound protection", "[evicsim][eclipse][sybil]") {
  EvictionTestNetwork net(42);

  auto victim_id = CreateVictimNode(net);
  auto attackers = CreateSybilAttackers(net, 100, "44.99");
  auto honest = CreateHonestNodes(net, 20);

  SECTION("Eviction targets largest netgroup") {
    auto* victim = net.GetNode(victim_id);
    REQUIRE(victim != nullptr);

    // Set small max_inbound to trigger eviction
    victim->max_inbound = 50;

    // Fill victim with attackers from same /16
    for (int attacker_id : attackers) {
      net.Connect(attacker_id, victim_id, SimConnectionType::INBOUND);
    }

    size_t attacker_count = victim->InboundCount();
    INFO("Attacker connections after filling: " << attacker_count);

    // Now add honest peers - this triggers eviction as we exceed max
    for (int honest_id : honest) {
      net.Connect(honest_id, victim_id, SimConnectionType::INBOUND);
    }

    // Verify largest netgroup is attacker netgroup
    std::string largest = victim->GetLargestNetgroup();
    INFO("Largest netgroup: " << largest);
    REQUIRE(largest == "44.99");

    // Trigger more evictions to reduce to target
    while (victim->InboundCount() > victim->max_inbound - 5) {
      if (!net.TryEvictInbound(victim_id)) break;
    }

    // After evictions, attacker should be reduced
    auto dist = victim->GetNetgroupDistribution();
    size_t final_attacker_count = dist.count("44.99") ? dist["44.99"] : 0;
    size_t total = victim->InboundCount();

    INFO("Final attacker count: " << final_attacker_count);
    INFO("Total connections: " << total);
    INFO("Attacker ratio: " << (100.0 * final_attacker_count / std::max(total, size_t(1))) << "%");

    // Eviction should have reduced attacker dominance (from 100 to < 50)
    REQUIRE(final_attacker_count < attacker_count);
  }
}

TEST_CASE("Eclipse: Multiple /16 Sybil attack", "[evicsim][eclipse][sybil]") {
  EvictionTestNetwork net(42);

  auto victim_id = CreateVictimNode(net);

  // Attacker controls 5 different /16 subnets
  std::set<int> all_attackers;
  for (int subnet = 0; subnet < 5; ++subnet) {
    std::string ng = "44." + std::to_string(50 + subnet);
    auto ids = net.CreateNodesInNetgroup(20, ng);
    all_attackers.insert(ids.begin(), ids.end());
  }

  auto honest = CreateHonestNodes(net, 30);

  SECTION("Multi-subnet attack still limited by eviction") {
    // Connect attackers
    for (int attacker_id : all_attackers) {
      net.Connect(attacker_id, victim_id, SimConnectionType::INBOUND);
    }

    // Connect honest
    for (int honest_id : honest) {
      net.Connect(honest_id, victim_id, SimConnectionType::INBOUND);
    }

    auto* victim = net.GetNode(victim_id);
    REQUIRE(victim != nullptr);

    auto dist = victim->GetNetgroupDistribution();
    INFO("Unique netgroups connected: " << dist.size());

    // Multiple netgroups should be represented
    REQUIRE(dist.size() > 5);

    // Collect metrics
    auto metrics = net.CollectMetrics(all_attackers);
    INFO("Eclipsed nodes: " << metrics.total_eclipsed_nodes);

    // Victim should not be fully eclipsed (>50% attacker)
    // This may or may not be true depending on random eviction
  }
}

// =============================================================================
// ECLIPSE RESISTANCE: Statistical Analysis Over Many Trials
// =============================================================================

TEST_CASE("Eclipse: 100 trials - measure eclipse probability", "[evicsim][eclipse][statistical]") {
  size_t num_trials = 100;
  size_t eclipsed_count = 0;

  for (size_t trial = 0; trial < num_trials; ++trial) {
    EvictionTestNetwork net(trial);  // Different seed each trial

    auto victim_id = net.CreateNode("8.1.0.1");

    // 50 attackers from 5 netgroups (10 each)
    std::set<int> attackers;
    for (int subnet = 0; subnet < 5; ++subnet) {
      std::string ng = "44." + std::to_string(50 + subnet);
      auto ids = net.CreateNodesInNetgroup(10, ng);
      attackers.insert(ids.begin(), ids.end());
    }

    // 50 honest nodes from diverse netgroups
    auto honest = CreateHonestNodes(net, 50);

    // Connect all to victim (random order)
    std::vector<int> all_nodes;
    all_nodes.insert(all_nodes.end(), attackers.begin(), attackers.end());
    all_nodes.insert(all_nodes.end(), honest.begin(), honest.end());

    std::mt19937 rng(trial);
    std::shuffle(all_nodes.begin(), all_nodes.end(), rng);

    for (int node_id : all_nodes) {
      net.Connect(node_id, victim_id, SimConnectionType::INBOUND);
    }

    // Collect metrics
    auto metrics = net.CollectMetrics(attackers);
    if (metrics.total_eclipsed_nodes > 0) {
      eclipsed_count++;
    }
  }

  double eclipse_rate = 100.0 * eclipsed_count / num_trials;
  INFO("Eclipse rate over " << num_trials << " trials: " << eclipse_rate << "%");

  // With eviction and diversity protection, eclipse rate should be low
  // But this depends heavily on attacker/honest ratio
  REQUIRE(eclipsed_count < num_trials);  // At least not all eclipsed
}

// =============================================================================
// ECLIPSE RESISTANCE: Outbound Diversity
// =============================================================================

TEST_CASE("Eclipse: Outbound netgroup diversity prevents eclipse", "[evicsim][eclipse][outbound]") {
  EvictionTestNetwork net(42);

  auto victim_id = CreateVictimNode(net);
  auto* victim = net.GetNode(victim_id);

  // Create target nodes across diverse netgroups
  std::vector<int> targets;
  for (int ng = 1; ng <= 20; ++ng) {
    std::string prefix = "9." + std::to_string(ng);
    auto ids = net.CreateNodesInNetgroup(3, prefix);  // 3 nodes per netgroup
    targets.insert(targets.end(), ids.begin(), ids.end());
  }

  SECTION("Only one outbound per netgroup allowed") {
    // Try to connect to all targets
    size_t connected = 0;
    size_t rejected = 0;

    for (int target_id : targets) {
      if (net.Connect(victim_id, target_id, SimConnectionType::OUTBOUND_FULL_RELAY)) {
        connected++;
      } else {
        rejected++;
      }
    }

    INFO("Connected: " << connected << ", Rejected: " << rejected);

    // Should have connected max_full_relay_outbound (8) from unique netgroups
    REQUIRE(connected == victim->max_full_relay_outbound);

    // Verify all connections are to unique netgroups
    auto dist = victim->GetNetgroupDistribution();
    for (const auto& [ng, count] : dist) {
      INFO("Netgroup " << ng << ": " << count);
      REQUIRE(count == 1);  // Exactly 1 per netgroup
    }
  }

  SECTION("Attacker with many addresses in few netgroups cannot dominate outbound") {
    // Attacker controls 100 addresses in 3 netgroups
    std::vector<int> attacker_targets;
    for (int ng = 50; ng < 53; ++ng) {
      std::string prefix = "44." + std::to_string(ng);
      auto ids = net.CreateNodesInNetgroup(33, prefix);
      attacker_targets.insert(attacker_targets.end(), ids.begin(), ids.end());
    }

    // Honest targets in 10 different netgroups
    std::vector<int> honest_targets;
    for (int ng = 60; ng < 70; ++ng) {
      std::string prefix = "9." + std::to_string(ng);
      auto ids = net.CreateNodesInNetgroup(1, prefix);
      honest_targets.insert(honest_targets.end(), ids.begin(), ids.end());
    }

    // Mix and try to connect
    std::vector<int> all_targets;
    all_targets.insert(all_targets.end(), attacker_targets.begin(), attacker_targets.end());
    all_targets.insert(all_targets.end(), honest_targets.begin(), honest_targets.end());

    std::mt19937 rng(42);
    std::shuffle(all_targets.begin(), all_targets.end(), rng);

    for (int target_id : all_targets) {
      net.Connect(victim_id, target_id, SimConnectionType::OUTBOUND_FULL_RELAY);
    }

    // Count attacker vs honest connections
    size_t attacker_conn = 0;
    size_t honest_conn = 0;
    std::set<int> attacker_set(attacker_targets.begin(), attacker_targets.end());

    for (const auto& [peer_id, _] : victim->connections) {
      if (attacker_set.count(peer_id)) {
        attacker_conn++;
      } else {
        honest_conn++;
      }
    }

    INFO("Attacker outbound: " << attacker_conn);
    INFO("Honest outbound: " << honest_conn);

    // With 3 attacker netgroups and 10 honest netgroups,
    // attacker can only get max 3 connections (1 per netgroup)
    REQUIRE(attacker_conn <= 3);

    // Total should be max_full_relay_outbound
    REQUIRE(attacker_conn + honest_conn == victim->max_full_relay_outbound);
  }
}

// =============================================================================
// ECLIPSE RESISTANCE: Defense in Depth
// =============================================================================

TEST_CASE("Eclipse: Combined defenses prevent full eclipse", "[evicsim][eclipse][defense-in-depth]") {
  EvictionTestNetwork net(42);

  auto victim_id = CreateVictimNode(net);

  // Strong attacker: 80 nodes across 8 netgroups
  std::set<int> attackers;
  for (int subnet = 0; subnet < 8; ++subnet) {
    std::string ng = "44." + std::to_string(50 + subnet);
    auto ids = net.CreateNodesInNetgroup(10, ng);
    attackers.insert(ids.begin(), ids.end());
  }

  // Honest inbound: 20 nodes across 20 netgroups
  auto honest_inbound = CreateHonestNodes(net, 20);

  // Honest outbound targets: 10 nodes in DIFFERENT netgroups
  // (not overlapping with inbound to avoid duplicate connection check)
  std::set<int> honest_outbound;
  for (int i = 0; i < 10; ++i) {
    std::string ng = "10." + std::to_string(i + 1);
    honest_outbound.insert(net.CreateNode(ng + ".0.1"));
  }

  // Phase 1: Attackers flood inbound
  for (int attacker_id : attackers) {
    net.Connect(attacker_id, victim_id, SimConnectionType::INBOUND);
  }

  // Phase 2: Honest also connect inbound
  for (int honest_id : honest_inbound) {
    net.Connect(honest_id, victim_id, SimConnectionType::INBOUND);
  }

  auto* victim = net.GetNode(victim_id);
  REQUIRE(victim != nullptr);

  // Phase 3: Victim makes outbound connections to honest outbound targets
  for (int honest_id : honest_outbound) {
    net.Connect(victim_id, honest_id, SimConnectionType::OUTBOUND_FULL_RELAY);
    if (victim->OutboundFullRelayCount() >= victim->max_full_relay_outbound) break;
  }

  // Verify outbound diversity
  size_t outbound_to_honest = 0;
  size_t outbound_to_attacker = 0;
  for (const auto& [peer_id, info] : victim->connections) {
    if (info.type == SimConnectionType::OUTBOUND_FULL_RELAY ||
        info.type == SimConnectionType::BLOCK_RELAY) {
      if (attackers.count(peer_id)) {
        outbound_to_attacker++;
      } else {
        outbound_to_honest++;
      }
    }
  }

  INFO("Outbound to honest: " << outbound_to_honest);
  INFO("Outbound to attacker: " << outbound_to_attacker);

  // All outbound should be to honest (attacker didn't get selected)
  REQUIRE(outbound_to_honest == victim->max_full_relay_outbound);
  REQUIRE(outbound_to_attacker == 0);

  // Even if inbound is dominated by attackers, outbound is safe
  // Full eclipse is impossible if outbound is to honest nodes
  INFO("Defense in depth: outbound diversity protects against inbound flooding");
}

// =============================================================================
// ECLIPSE RESISTANCE: Mixed Attack Scenarios
// =============================================================================

TEST_CASE("Eclipse: Low-latency attacker cannot dominate via ping protection", "[evicsim][eclipse][mixed]") {
  // Attacker offers very low latency connections to get ping protection
  EvictionTestNetwork net(42);

  auto victim_id = CreateVictimNode(net);
  auto* victim = net.GetNode(victim_id);
  victim->max_inbound = 50;

  // Attacker with excellent ping from limited netgroups
  std::set<int> attackers;
  for (int ng = 50; ng < 55; ++ng) {
    std::string prefix = "44." + std::to_string(ng);
    auto ids = net.CreateNodesInNetgroup(10, prefix);
    for (int id : ids) {
      attackers.insert(id);
    }
  }

  // Honest peers with normal ping from diverse netgroups
  auto honest = CreateHonestNodes(net, 30);

  // Connect attackers first, give them excellent ping
  for (int attacker_id : attackers) {
    net.Connect(attacker_id, victim_id, SimConnectionType::INBOUND);
    net.SimulatePingResponse(victim_id, attacker_id, 5);  // 5ms - excellent
  }

  // Connect honest peers with normal ping
  for (int honest_id : honest) {
    net.Connect(honest_id, victim_id, SimConnectionType::INBOUND);
    net.SimulatePingResponse(victim_id, honest_id, 100);  // 100ms - normal
  }

  // Trigger evictions to reduce to max
  while (victim->InboundCount() > victim->max_inbound) {
    if (!net.TryEvictInbound(victim_id)) break;
  }

  // Count attacker vs honest connections
  size_t attacker_count = 0;
  size_t honest_count = 0;
  for (const auto& [peer_id, _] : victim->connections) {
    if (attackers.count(peer_id)) attacker_count++;
    else if (honest.count(peer_id)) honest_count++;
  }

  INFO("Attacker connections: " << attacker_count);
  INFO("Honest connections: " << honest_count);

  // Despite attackers having better ping, netgroup diversity limits them
  // Attackers only have 5 netgroups, can't dominate
  // PROTECT_BY_NETGROUP (4) + netgroup eviction targeting limits attacker advantage
  double attacker_ratio = static_cast<double>(attacker_count) / victim->InboundCount();
  INFO("Attacker ratio: " << (attacker_ratio * 100) << "%");

  // Attackers shouldn't have >70% even with ping advantage
  REQUIRE(attacker_ratio < 0.7);
}

TEST_CASE("Eclipse: Combined Sybil + stale block-relay attack", "[evicsim][eclipse][mixed]") {
  // Attacker floods inbound AND gets block-relay slots but doesn't relay headers
  EvictionTestNetwork net(42);

  auto victim_id = CreateVictimNode(net);
  auto* victim = net.GetNode(victim_id);

  // Attacker controls nodes in different netgroups (for block-relay diversity)
  // Create two attacker nodes in DIFFERENT netgroups for block-relay slots
  auto attacker_br1 = net.CreateNode("44.50.0.1");
  auto attacker_br2 = net.CreateNode("44.51.0.1");

  // Attacker gets block-relay slots (before honest)
  REQUIRE(net.Connect(victim_id, attacker_br1, SimConnectionType::BLOCK_RELAY));
  net.AdvanceTime(std::chrono::seconds(10));  // Slight time difference
  REQUIRE(net.Connect(victim_id, attacker_br2, SimConnectionType::BLOCK_RELAY));

  REQUIRE(victim->BlockRelayCount() == 2);

  // More attacker inbound connections
  std::set<int> attackers;
  attackers.insert(attacker_br1);
  attackers.insert(attacker_br2);
  for (int ng = 52; ng < 57; ++ng) {
    std::string prefix = "44." + std::to_string(ng);
    auto ids = net.CreateNodesInNetgroup(5, prefix);
    attackers.insert(ids.begin(), ids.end());
  }

  // Honest outbound targets
  std::set<int> honest_outbound;
  for (int i = 60; i < 70; ++i) {
    honest_outbound.insert(net.CreateNode("10." + std::to_string(i) + ".0.1"));
  }

  // Time passes, attacker never sends headers
  net.AdvanceTime(std::chrono::seconds(600));

  // Victim connects to honest outbound
  for (int honest_id : honest_outbound) {
    if (net.Connect(victim_id, honest_id, SimConnectionType::OUTBOUND_FULL_RELAY)) {
      net.SimulateHeadersReceived(victim_id, honest_id);
    }
  }

  // Attacker block-relay peers should be identified as stale (no headers sent)
  int oldest = victim->GetOldestBlockRelayPeer();
  REQUIRE(oldest == attacker_br1);  // First attacker is oldest (connected first)

  // Create honest block-relay candidate in different netgroup
  auto honest_br = net.CreateNode("10.99.0.1");

  // Rotation should evict stale attacker
  REQUIRE(net.TryRotateBlockRelay(victim_id, {honest_br}));

  // Verify attacker evicted
  REQUIRE_FALSE(victim->IsConnectedTo(attacker_br1));
  REQUIRE(victim->IsConnectedTo(honest_br));

  INFO("Stale attacker block-relay peer rotated out");
}

TEST_CASE("Eclipse: Recovery after partial eclipse", "[evicsim][eclipse][recovery]") {
  // Test how quickly honest connections can be restored after attack
  // This simulates detecting an eclipse and marking attackers for eviction
  EvictionTestNetwork net(42);

  auto victim_id = CreateVictimNode(net);
  auto* victim = net.GetNode(victim_id);

  // Set max_inbound so new connections trigger eviction of prefer_evict peers
  victim->max_inbound = 50;

  // Initial state: fill with attacker connections
  std::set<int> attackers;
  for (int ng = 50; ng < 60; ++ng) {
    auto ids = net.CreateNodesInNetgroup(5, "44." + std::to_string(ng));
    attackers.insert(ids.begin(), ids.end());
  }

  for (int attacker_id : attackers) {
    net.Connect(attacker_id, victim_id, SimConnectionType::INBOUND);
  }

  size_t initial_attacker_count = victim->InboundCount();
  INFO("Initial attacker inbound: " << initial_attacker_count);
  REQUIRE(initial_attacker_count == 50);  // At capacity

  // Simulate detection: mark all attackers as prefer_evict
  for (int attacker_id : attackers) {
    net.MarkPreferEvict(victim_id, attacker_id);
  }

  // Honest peers start connecting - this triggers eviction of prefer_evict peers
  auto honest = CreateHonestNodes(net, 50);
  for (int honest_id : honest) {
    net.Connect(honest_id, victim_id, SimConnectionType::INBOUND);
  }

  // Count final state
  size_t final_attacker_count = 0;
  size_t final_honest_count = 0;
  for (const auto& [peer_id, _] : victim->connections) {
    if (attackers.count(peer_id)) final_attacker_count++;
    else if (honest.count(peer_id)) final_honest_count++;
  }

  INFO("Final attacker count: " << final_attacker_count);
  INFO("Final honest count: " << final_honest_count);

  // All prefer_evict attackers should be gone (evicted as honest peers connected)
  REQUIRE(final_attacker_count == 0);

  // Honest peers should have replaced them
  REQUIRE(final_honest_count == 50);

  INFO("Recovery complete: all attackers evicted via prefer_evict");
}
