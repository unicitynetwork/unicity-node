// Copyright (c) 2025 The Unicity Foundation
// Netgroup diversity enforcement simulation tests
//
// These tests verify that the per-netgroup limits and diversity enforcement
// mechanisms work correctly under various conditions.

#include "catch_amalgamated.hpp"
#include "eviction_test_network.hpp"

#include <set>
#include <map>

using namespace unicity::test::evicsim;

// =============================================================================
// NETGROUP DIVERSITY: Basic Enforcement
// =============================================================================

TEST_CASE("Diversity: One outbound per netgroup enforced", "[evicsim][diversity][outbound]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Create targets in same /16
  auto targets = net.CreateNodesInNetgroup(10, "9.1");

  // First connection succeeds
  REQUIRE(net.Connect(victim_id, targets[0], SimConnectionType::OUTBOUND_FULL_RELAY));

  // Subsequent connections to same netgroup fail
  for (size_t i = 1; i < targets.size(); ++i) {
    REQUIRE_FALSE(net.Connect(victim_id, targets[i], SimConnectionType::OUTBOUND_FULL_RELAY));
  }

  // Verify only 1 connection to 9.1
  auto dist = victim->GetNetgroupDistribution();
  REQUIRE(dist["9.1"] == 1);
}

TEST_CASE("Diversity: Multiple netgroups can connect", "[evicsim][diversity][outbound]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Create targets in different /16s
  std::vector<int> targets;
  for (int i = 1; i <= 10; ++i) {
    std::string ng = "9." + std::to_string(i);
    targets.push_back(net.CreateNode(ng + ".0.1"));
  }

  // Connect to each
  size_t connected = 0;
  for (int target_id : targets) {
    if (net.Connect(victim_id, target_id, SimConnectionType::OUTBOUND_FULL_RELAY)) {
      connected++;
    }
  }

  // Should connect to max_full_relay_outbound unique netgroups
  REQUIRE(connected == victim->max_full_relay_outbound);

  // All connections are to unique netgroups
  auto dist = victim->GetNetgroupDistribution();
  for (const auto& [ng, count] : dist) {
    REQUIRE(count == 1);
  }

  INFO("Connected to " << dist.size() << " unique netgroups");
}

// =============================================================================
// NETGROUP DIVERSITY: Block-Relay Slots
// =============================================================================

TEST_CASE("Diversity: Block-relay respects netgroup diversity", "[evicsim][diversity][blockrelay]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Create targets in different netgroups
  auto br1 = net.CreateNode("10.1.0.1");
  auto br2 = net.CreateNode("10.2.0.1");
  auto br3_same = net.CreateNode("10.1.0.2");  // Same /16 as br1

  // Connect first two block-relay
  REQUIRE(net.Connect(victim_id, br1, SimConnectionType::BLOCK_RELAY));
  REQUIRE(net.Connect(victim_id, br2, SimConnectionType::BLOCK_RELAY));

  // Slots full
  REQUIRE(victim->BlockRelayCount() == victim->max_block_relay_outbound);

  // Can't connect another (slots full)
  REQUIRE_FALSE(net.Connect(victim_id, br3_same, SimConnectionType::BLOCK_RELAY));

  // Disconnect one
  net.Disconnect(victim_id, br1);

  // Still can't connect br3_same because br2 is in a different netgroup,
  // but wait - actually now we have a slot and br3_same is in same netgroup as br1 (which is disconnected)
  // Actually, netgroup diversity check looks at currently connected peers
  // br3_same is in 10.1 netgroup, br2 is in 10.2 - should be OK now
  REQUIRE(net.Connect(victim_id, br3_same, SimConnectionType::BLOCK_RELAY));
}

// =============================================================================
// NETGROUP DIVERSITY: Eviction Targets Largest Netgroup
// =============================================================================

TEST_CASE("Diversity: Eviction targets largest inbound netgroup", "[evicsim][diversity][eviction]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Max inbound to hold all peers (we test eviction behavior, not slot limits)
  victim->max_inbound = 100;

  // Connect 30 from same netgroup (44.99) - enough to have candidates after protection
  // Protection phases: 4 netgroup + 8 ping + 4 headers + 50% uptime
  // Need 30+ to ensure some remain for eviction from largest netgroup
  auto sybil_cluster = net.CreateNodesInNetgroup(30, "44.99");
  for (int peer_id : sybil_cluster) {
    net.Connect(peer_id, victim_id, SimConnectionType::INBOUND);
  }

  // Connect 8 from diverse netgroups (to occupy netgroup protection slots)
  std::vector<int> honest;
  for (int i = 1; i <= 8; ++i) {
    std::string ng = "9." + std::to_string(i);
    honest.push_back(net.CreateNode(ng + ".0.1"));
  }
  for (int peer_id : honest) {
    net.Connect(peer_id, victim_id, SimConnectionType::INBOUND);
  }

  REQUIRE(victim->InboundCount() == 38);

  // Age connections
  net.AdvanceTime(std::chrono::seconds(120));

  // Largest netgroup should be 44.99
  REQUIRE(victim->GetLargestNetgroup() == "44.99");

  // Trigger eviction
  REQUIRE(net.TryEvictInbound(victim_id));

  // Should have evicted from 44.99
  auto dist = victim->GetNetgroupDistribution();
  REQUIRE(dist["44.99"] == 29);  // Was 30, now 29

  // Honest peers all still connected
  for (int peer_id : honest) {
    REQUIRE(victim->IsConnectedTo(peer_id));
  }
}

TEST_CASE("Diversity: Multiple evictions reduce dominant netgroup", "[evicsim][diversity][eviction]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  victim->max_inbound = 100;

  // Connect 40 from same netgroup - enough for multiple evictions after protection
  auto attackers = net.CreateNodesInNetgroup(40, "44.50");
  for (int peer_id : attackers) {
    net.Connect(peer_id, victim_id, SimConnectionType::INBOUND);
  }

  // Connect 8 from diverse netgroups
  std::vector<int> honest;
  for (int i = 1; i <= 8; ++i) {
    std::string ng = "9." + std::to_string(i);
    honest.push_back(net.CreateNode(ng + ".0.1"));
  }
  for (int peer_id : honest) {
    net.Connect(peer_id, victim_id, SimConnectionType::INBOUND);
  }

  // Age connections
  net.AdvanceTime(std::chrono::seconds(120));

  size_t initial_count = victim->GetNetgroupDistribution()["44.50"];
  INFO("Initial attacker count: " << initial_count);

  // Trigger multiple evictions
  for (int i = 0; i < 20; ++i) {
    if (!net.TryEvictInbound(victim_id)) break;
  }

  auto dist = victim->GetNetgroupDistribution();
  INFO("44.50 count after evictions: " << dist["44.50"]);

  // Attacker count significantly reduced (at least 5 evicted)
  REQUIRE(dist["44.50"] < initial_count - 5);

  // Honest peers still connected
  for (int peer_id : honest) {
    REQUIRE(victim->IsConnectedTo(peer_id));
  }
}

// =============================================================================
// NETGROUP DIVERSITY: Statistical Analysis
// =============================================================================

TEST_CASE("Diversity: 100 trials - outbound always diverse", "[evicsim][diversity][statistical]") {
  size_t violations = 0;

  for (size_t trial = 0; trial < 100; ++trial) {
    EvictionTestNetwork net(trial);

    auto victim_id = net.CreateNode("8.1.0.1");
    auto* victim = net.GetNode(victim_id);

    // Create mixed pool of targets (some share netgroups)
    std::vector<int> targets;
    for (int ng = 1; ng <= 5; ++ng) {
      std::string prefix = "9." + std::to_string(ng);
      auto ids = net.CreateNodesInNetgroup(5, prefix);  // 5 nodes per netgroup
      targets.insert(targets.end(), ids.begin(), ids.end());
    }

    // Shuffle targets
    std::mt19937 rng(trial);
    std::shuffle(targets.begin(), targets.end(), rng);

    // Try to connect to all
    for (int target_id : targets) {
      net.Connect(victim_id, target_id, SimConnectionType::OUTBOUND_FULL_RELAY);
    }

    // Check: all outbound to unique netgroups
    auto dist = victim->GetNetgroupDistribution();
    for (const auto& [ng, count] : dist) {
      if (count > 1) {
        violations++;
        break;
      }
    }
  }

  INFO("Diversity violations: " << violations << " / 100");
  REQUIRE(violations == 0);
}

// =============================================================================
// NETGROUP DIVERSITY: Edge Cases
// =============================================================================

TEST_CASE("Diversity: No targets in new netgroups - outbound stalls", "[evicsim][diversity][edge]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Create targets all in same netgroup
  auto targets = net.CreateNodesInNetgroup(20, "9.1");

  // Try to connect
  size_t connected = 0;
  for (int target_id : targets) {
    if (net.Connect(victim_id, target_id, SimConnectionType::OUTBOUND_FULL_RELAY)) {
      connected++;
    }
  }

  // Only 1 can connect (all same netgroup)
  REQUIRE(connected == 1);
  REQUIRE(victim->OutboundFullRelayCount() == 1);

  // Needs more outbound but can't find diverse targets
  REQUIRE(victim->NeedsMoreFullRelayOutbound());
}

TEST_CASE("Diversity: Disconnected peer's netgroup becomes available", "[evicsim][diversity][edge]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Connect to target in 9.1
  auto target1 = net.CreateNode("9.1.0.1");
  REQUIRE(net.Connect(victim_id, target1, SimConnectionType::OUTBOUND_FULL_RELAY));

  // Can't connect to another in 9.1
  auto target2 = net.CreateNode("9.1.0.2");
  REQUIRE_FALSE(net.Connect(victim_id, target2, SimConnectionType::OUTBOUND_FULL_RELAY));

  // Disconnect target1
  net.Disconnect(victim_id, target1);

  // Now 9.1 netgroup is available again
  REQUIRE(net.Connect(victim_id, target2, SimConnectionType::OUTBOUND_FULL_RELAY));
}

// =============================================================================
// NETGROUP DIVERSITY: Metrics
// =============================================================================

TEST_CASE("Diversity: Metrics show diversity level", "[evicsim][diversity][metrics]") {
  EvictionTestNetwork net(42);

  // Create network with mix of honest and attacker nodes
  std::set<int> attackers;
  for (int i = 0; i < 3; ++i) {
    std::string ng = "44." + std::to_string(50 + i);
    auto ids = net.CreateNodesInNetgroup(10, ng);
    attackers.insert(ids.begin(), ids.end());
  }

  std::set<int> honest;
  for (int i = 1; i <= 20; ++i) {
    std::string ng = "9." + std::to_string(i);
    honest.insert(net.CreateNode(ng + ".0.1"));
  }

  // Create victim and connect
  auto victim_id = net.CreateNode("8.1.0.1");

  // Connect attackers as inbound
  for (int a : attackers) {
    net.Connect(a, victim_id, SimConnectionType::INBOUND);
  }

  // Connect honest as outbound
  for (int h : honest) {
    net.Connect(victim_id, h, SimConnectionType::OUTBOUND_FULL_RELAY);
  }

  // Collect metrics
  auto metrics = net.CollectMetrics(attackers);

  INFO("Avg netgroup diversity: " << metrics.avg_netgroup_diversity);
  INFO("Avg largest netgroup ratio: " << metrics.avg_largest_netgroup_ratio);
  INFO("Eclipsed nodes: " << metrics.total_eclipsed_nodes);

  // With proper diversity, largest netgroup ratio should be reasonable
  // Not all connections from single netgroup
}
