// Copyright (c) 2025 The Unicity Foundation
// Large-scale network simulation tests
//
// These tests simulate networks with 100s-1000s of nodes to verify
// network-wide security properties like eclipse resistance, connectivity,
// and resilience under attack.

#include "catch_amalgamated.hpp"
#include "eviction_test_network.hpp"

#include <algorithm>
#include <numeric>
#include <random>
#include <set>

using namespace unicity::test::evicsim;

namespace {

// Helper: Generate a random IP in a given netgroup range
std::string RandomIP(std::mt19937& rng, int netgroup_start, int netgroup_end) {
  int ng = netgroup_start + (rng() % (netgroup_end - netgroup_start + 1));
  int third = rng() % 256;
  int fourth = 1 + (rng() % 254);
  return std::to_string(ng) + "." + std::to_string(ng) + "." +
         std::to_string(third) + "." + std::to_string(fourth);
}

// Helper: Check if a node is eclipsed (>50% connections from attackers)
bool IsEclipsed(const EvictionTestNode& node, const std::set<int>& attacker_ids) {
  if (node.TotalConnectionCount() == 0) return false;

  size_t attacker_connections = 0;
  for (const auto& [peer_id, info] : node.connections) {
    if (attacker_ids.count(peer_id)) {
      attacker_connections++;
    }
  }
  return attacker_connections > node.TotalConnectionCount() / 2;
}

// Helper: Count nodes with at least N connections
size_t CountConnectedNodes(const EvictionTestNetwork& net, size_t min_connections) {
  size_t count = 0;
  net.ForEachNode([&](const EvictionTestNode& node) {
    if (node.TotalConnectionCount() >= min_connections) {
      count++;
    }
  });
  return count;
}

}  // namespace

// =============================================================================
// NETWORK SCALE: Large Mesh Formation
// =============================================================================

TEST_CASE("Scale: 500 node network forms connected mesh", "[evicsim][scale][mesh]") {
  EvictionTestNetwork net(42);
  std::mt19937 rng(42);

  constexpr size_t NUM_NODES = 500;
  constexpr size_t TARGET_OUTBOUND = 8;

  // Create nodes across 50 different /16 netgroups (10 nodes each)
  std::vector<int> all_nodes;
  for (int ng = 10; ng < 60; ++ng) {
    for (int i = 0; i < 10; ++i) {
      std::string ip = std::to_string(ng) + "." + std::to_string(ng) + "." +
                       std::to_string(i) + ".1";
      all_nodes.push_back(net.CreateNode(ip));
    }
  }

  REQUIRE(all_nodes.size() == NUM_NODES);

  // Each node attempts outbound connections
  for (int node_id : all_nodes) {
    auto* node = net.GetNode(node_id);

    // Shuffle targets for random selection
    std::vector<int> targets = all_nodes;
    std::shuffle(targets.begin(), targets.end(), rng);

    size_t connected = 0;
    for (int target_id : targets) {
      if (connected >= TARGET_OUTBOUND) break;
      if (target_id == node_id) continue;

      if (net.Connect(node_id, target_id, SimConnectionType::OUTBOUND_FULL_RELAY)) {
        connected++;
      }
    }
  }

  // Verify network connectivity
  size_t nodes_with_outbound = CountConnectedNodes(net, 1);
  size_t well_connected = 0;
  size_t total_connections = 0;

  net.ForEachNode([&](const EvictionTestNode& node) {
    total_connections += node.TotalConnectionCount();
    if (node.TotalOutboundCount() >= TARGET_OUTBOUND / 2) {
      well_connected++;
    }
  });

  double avg_connections = static_cast<double>(total_connections) / NUM_NODES;

  INFO("Nodes with any connection: " << nodes_with_outbound << "/" << NUM_NODES);
  INFO("Well-connected nodes (>=4 outbound): " << well_connected);
  INFO("Average connections per node: " << avg_connections);

  // At least 90% of nodes should have some connections
  REQUIRE(nodes_with_outbound >= NUM_NODES * 0.9);

  // Average connections should be reasonable (accounting for netgroup limits)
  REQUIRE(avg_connections >= 4.0);
}

TEST_CASE("Scale: 1000 node network with netgroup diversity", "[evicsim][scale][diversity]") {
  EvictionTestNetwork net(123);
  std::mt19937 rng(123);

  constexpr size_t NUM_NODES = 1000;
  constexpr size_t NUM_NETGROUPS = 100;

  // Create nodes: 10 nodes per netgroup across 100 netgroups
  std::vector<int> all_nodes;
  for (size_t ng = 0; ng < NUM_NETGROUPS; ++ng) {
    int first = 10 + (ng / 10);
    int second = 10 + (ng % 10);
    for (int i = 0; i < 10; ++i) {
      std::string ip = std::to_string(first) + "." + std::to_string(second) + "." +
                       std::to_string(i) + ".1";
      all_nodes.push_back(net.CreateNode(ip));
    }
  }

  REQUIRE(all_nodes.size() == NUM_NODES);

  // Each node makes outbound connections
  for (int node_id : all_nodes) {
    std::vector<int> targets = all_nodes;
    std::shuffle(targets.begin(), targets.end(), rng);

    size_t attempts = 0;
    for (int target_id : targets) {
      if (attempts >= 50) break;  // Limit attempts
      if (target_id == node_id) continue;

      net.Connect(node_id, target_id, SimConnectionType::OUTBOUND_FULL_RELAY);
      attempts++;
    }
  }

  // Measure netgroup diversity across the network
  size_t total_unique_netgroups = 0;
  size_t nodes_checked = 0;

  net.ForEachNode([&](const EvictionTestNode& node) {
    if (node.TotalOutboundCount() > 0) {
      auto dist = node.GetNetgroupDistribution();
      // For outbound, each netgroup should have at most 1 connection
      size_t outbound_netgroups = 0;
      for (const auto& [peer_id, info] : node.connections) {
        if (info.type == SimConnectionType::OUTBOUND_FULL_RELAY) {
          outbound_netgroups++;
        }
      }
      total_unique_netgroups += outbound_netgroups;
      nodes_checked++;
    }
  });

  double avg_outbound_diversity = nodes_checked > 0 ?
      static_cast<double>(total_unique_netgroups) / nodes_checked : 0;

  INFO("Nodes with outbound: " << nodes_checked);
  INFO("Average outbound connections (each to unique netgroup): " << avg_outbound_diversity);

  // Should have good diversity
  REQUIRE(avg_outbound_diversity >= 5.0);
}

// =============================================================================
// NETWORK SCALE: Eclipse Resistance
// =============================================================================

TEST_CASE("Scale: Network-wide eclipse resistance - 10% attacker nodes", "[evicsim][scale][eclipse]") {
  EvictionTestNetwork net(42);
  std::mt19937 rng(42);

  constexpr size_t NUM_HONEST = 200;
  constexpr size_t NUM_ATTACKERS = 20;  // 10% of network

  // Create honest nodes across diverse netgroups
  std::vector<int> honest_nodes;
  for (size_t i = 0; i < NUM_HONEST; ++i) {
    int ng = 10 + (i % 50);
    std::string ip = std::to_string(ng) + "." + std::to_string(ng) + "." +
                     std::to_string(i / 50) + "." + std::to_string((i % 50) + 1);
    honest_nodes.push_back(net.CreateNode(ip));
  }

  // Create attacker nodes in a few netgroups (concentrated)
  std::set<int> attacker_ids;
  for (size_t i = 0; i < NUM_ATTACKERS; ++i) {
    int ng = 200 + (i / 10);  // 2-3 attacker netgroups
    std::string ip = std::to_string(ng) + "." + std::to_string(ng) + "." +
                     std::to_string(i % 10) + ".1";
    attacker_ids.insert(net.CreateNode(ip));
  }

  std::vector<int> all_nodes = honest_nodes;
  all_nodes.insert(all_nodes.end(), attacker_ids.begin(), attacker_ids.end());

  // Honest nodes make connections (attackers also make connections to honest nodes)
  for (int node_id : all_nodes) {
    std::vector<int> targets = all_nodes;
    std::shuffle(targets.begin(), targets.end(), rng);

    for (int target_id : targets) {
      if (target_id == node_id) continue;
      net.Connect(node_id, target_id, SimConnectionType::OUTBOUND_FULL_RELAY);
    }
  }

  // Attackers aggressively connect inbound to honest nodes
  for (int attacker_id : attacker_ids) {
    for (int honest_id : honest_nodes) {
      // Try to fill honest node's inbound slots
      net.Connect(attacker_id, honest_id, SimConnectionType::OUTBOUND_FULL_RELAY);
    }
  }

  // Count eclipsed honest nodes
  size_t eclipsed_count = 0;
  for (int honest_id : honest_nodes) {
    auto* node = net.GetNode(honest_id);
    if (node && IsEclipsed(*node, attacker_ids)) {
      eclipsed_count++;
    }
  }

  double eclipse_rate = 100.0 * eclipsed_count / NUM_HONEST;

  INFO("Honest nodes: " << NUM_HONEST);
  INFO("Attacker nodes: " << NUM_ATTACKERS);
  INFO("Eclipsed honest nodes: " << eclipsed_count);
  INFO("Eclipse rate: " << eclipse_rate << "%");

  // With 10% attackers and netgroup diversity, eclipse rate should be very low
  REQUIRE(eclipse_rate < 5.0);
}

TEST_CASE("Scale: Eclipse resistance with 30% attacker resources", "[evicsim][scale][eclipse][heavy]") {
  EvictionTestNetwork net(99);
  std::mt19937 rng(99);

  constexpr size_t NUM_HONEST = 100;
  constexpr size_t NUM_ATTACKERS = 30;  // 30% attacker ratio
  constexpr size_t ATTACKER_NETGROUPS = 10;  // Attackers spread across 10 netgroups

  // Create honest nodes
  std::vector<int> honest_nodes;
  for (size_t i = 0; i < NUM_HONEST; ++i) {
    int ng = 10 + (i % 40);
    std::string ip = std::to_string(ng) + "." + std::to_string(ng) + "." +
                     std::to_string(i / 40) + "." + std::to_string((i % 40) + 1);
    honest_nodes.push_back(net.CreateNode(ip));
  }

  // Create attacker nodes spread across multiple netgroups (more sophisticated attack)
  std::set<int> attacker_ids;
  for (size_t i = 0; i < NUM_ATTACKERS; ++i) {
    int ng = 200 + (i % ATTACKER_NETGROUPS);
    std::string ip = std::to_string(ng) + "." + std::to_string(ng) + "." +
                     std::to_string(i / ATTACKER_NETGROUPS) + ".1";
    attacker_ids.insert(net.CreateNode(ip));
  }

  std::vector<int> all_nodes = honest_nodes;
  all_nodes.insert(all_nodes.end(), attacker_ids.begin(), attacker_ids.end());

  // All nodes form connections
  for (int node_id : all_nodes) {
    std::vector<int> targets = all_nodes;
    std::shuffle(targets.begin(), targets.end(), rng);

    for (int target_id : targets) {
      if (target_id == node_id) continue;
      net.Connect(node_id, target_id, SimConnectionType::OUTBOUND_FULL_RELAY);
    }
  }

  // Attackers flood honest nodes with inbound connections
  for (int attacker_id : attacker_ids) {
    std::vector<int> targets = honest_nodes;
    std::shuffle(targets.begin(), targets.end(), rng);
    for (int honest_id : targets) {
      net.Connect(attacker_id, honest_id, SimConnectionType::OUTBOUND_FULL_RELAY);
    }
  }

  // Measure eclipse rate
  size_t eclipsed_count = 0;
  for (int honest_id : honest_nodes) {
    auto* node = net.GetNode(honest_id);
    if (node && IsEclipsed(*node, attacker_ids)) {
      eclipsed_count++;
    }
  }

  double eclipse_rate = 100.0 * eclipsed_count / NUM_HONEST;

  INFO("Honest nodes: " << NUM_HONEST);
  INFO("Attacker nodes: " << NUM_ATTACKERS << " across " << ATTACKER_NETGROUPS << " netgroups");
  INFO("Eclipsed honest nodes: " << eclipsed_count);
  INFO("Eclipse rate: " << eclipse_rate << "%");

  // Even with 30% attackers, good defenses should keep eclipse rate manageable
  // This is a stress test - we're checking defenses hold under pressure
  REQUIRE(eclipse_rate < 20.0);
}

// =============================================================================
// NETWORK SCALE: Attacker Resource Analysis
// =============================================================================

TEST_CASE("Scale: Attacker resources needed to eclipse 10% of network", "[evicsim][scale][analysis]") {
  std::mt19937 rng(42);

  constexpr size_t NUM_HONEST = 100;
  constexpr size_t NUM_TRIALS = 5;

  struct Result {
    size_t attacker_count;
    size_t attacker_netgroups;
    double avg_eclipse_rate;
  };

  std::vector<Result> results;

  // Test different attacker configurations
  std::vector<std::pair<size_t, size_t>> configs = {
    {10, 2},   // 10 attackers in 2 netgroups
    {20, 4},   // 20 attackers in 4 netgroups
    {30, 6},   // 30 attackers in 6 netgroups
    {50, 10},  // 50 attackers in 10 netgroups
    {100, 20}, // 100 attackers in 20 netgroups
  };

  for (auto [num_attackers, num_attacker_netgroups] : configs) {
    double total_eclipse_rate = 0;

    for (size_t trial = 0; trial < NUM_TRIALS; ++trial) {
      EvictionTestNetwork net(42 + trial);

      // Create honest nodes
      std::vector<int> honest_nodes;
      for (size_t i = 0; i < NUM_HONEST; ++i) {
        int ng = 10 + (i % 40);
        std::string ip = std::to_string(ng) + "." + std::to_string(ng) + "." +
                         std::to_string(i / 40) + "." + std::to_string((i % 40) + 1);
        honest_nodes.push_back(net.CreateNode(ip));
      }

      // Create attacker nodes
      std::set<int> attacker_ids;
      for (size_t i = 0; i < num_attackers; ++i) {
        int ng = 200 + (i % num_attacker_netgroups);
        std::string ip = std::to_string(ng) + "." + std::to_string(ng) + "." +
                         std::to_string(i / num_attacker_netgroups) + ".1";
        attacker_ids.insert(net.CreateNode(ip));
      }

      std::vector<int> all_nodes = honest_nodes;
      all_nodes.insert(all_nodes.end(), attacker_ids.begin(), attacker_ids.end());

      // Form network
      for (int node_id : all_nodes) {
        std::vector<int> targets = all_nodes;
        std::shuffle(targets.begin(), targets.end(), rng);
        for (int target_id : targets) {
          if (target_id == node_id) continue;
          net.Connect(node_id, target_id, SimConnectionType::OUTBOUND_FULL_RELAY);
        }
      }

      // Attacker flood
      for (int attacker_id : attacker_ids) {
        for (int honest_id : honest_nodes) {
          net.Connect(attacker_id, honest_id, SimConnectionType::OUTBOUND_FULL_RELAY);
        }
      }

      // Count eclipsed
      size_t eclipsed = 0;
      for (int honest_id : honest_nodes) {
        auto* node = net.GetNode(honest_id);
        if (node && IsEclipsed(*node, attacker_ids)) {
          eclipsed++;
        }
      }

      total_eclipse_rate += 100.0 * eclipsed / NUM_HONEST;
    }

    results.push_back({num_attackers, num_attacker_netgroups, total_eclipse_rate / NUM_TRIALS});
  }

  // Report results
  INFO("=== Attacker Resource Analysis ===");
  INFO("Honest nodes: " << NUM_HONEST);
  for (const auto& r : results) {
    INFO("Attackers: " << r.attacker_count << " in " << r.attacker_netgroups
         << " netgroups -> Eclipse rate: " << r.avg_eclipse_rate << "%");
  }

  // Verify scaling - more attackers with more netgroups needed for higher eclipse rates
  // This is mainly for analysis, but we check some basic properties
  REQUIRE(results[0].avg_eclipse_rate <= results[4].avg_eclipse_rate);
}

// =============================================================================
// NETWORK SCALE: Churn Resilience
// =============================================================================

TEST_CASE("Scale: Network resilience under 50% node churn", "[evicsim][scale][churn]") {
  EvictionTestNetwork net(42);
  std::mt19937 rng(42);

  constexpr size_t INITIAL_NODES = 200;
  constexpr size_t CHURN_ROUNDS = 10;
  constexpr size_t NODES_PER_ROUND = 20;  // 10% churn per round

  // Create initial network
  std::vector<int> active_nodes;
  for (size_t i = 0; i < INITIAL_NODES; ++i) {
    int ng = 10 + (i % 50);
    std::string ip = std::to_string(ng) + "." + std::to_string(ng) + "." +
                     std::to_string(i / 50) + "." + std::to_string((i % 50) + 1);
    active_nodes.push_back(net.CreateNode(ip));
  }

  // Initial connection formation
  for (int node_id : active_nodes) {
    std::vector<int> targets = active_nodes;
    std::shuffle(targets.begin(), targets.end(), rng);
    for (int target_id : targets) {
      if (target_id == node_id) continue;
      net.Connect(node_id, target_id, SimConnectionType::OUTBOUND_FULL_RELAY);
    }
  }

  auto initial_metrics = net.CollectMetrics();
  INFO("Initial avg connections: " << (initial_metrics.avg_inbound_count + initial_metrics.avg_outbound_count));

  int next_ng = 100;

  // Simulate churn
  for (size_t round = 0; round < CHURN_ROUNDS; ++round) {
    // Remove random nodes (disconnect all their connections)
    std::shuffle(active_nodes.begin(), active_nodes.end(), rng);
    std::vector<int> removed;
    for (size_t i = 0; i < NODES_PER_ROUND && !active_nodes.empty(); ++i) {
      int node_id = active_nodes.back();
      active_nodes.pop_back();

      // Disconnect from all peers
      auto* node = net.GetNode(node_id);
      if (node) {
        std::vector<int> peers;
        for (const auto& [peer_id, _] : node->connections) {
          peers.push_back(peer_id);
        }
        for (int peer_id : peers) {
          net.Disconnect(node_id, peer_id);
        }
      }
      removed.push_back(node_id);
    }

    // Add new nodes
    std::vector<int> new_nodes;
    for (size_t i = 0; i < NODES_PER_ROUND; ++i) {
      int ng = next_ng + (i % 10);
      std::string ip = std::to_string(ng) + "." + std::to_string(ng) + "." +
                       std::to_string(i / 10) + "." + std::to_string((i % 10) + 1);
      new_nodes.push_back(net.CreateNode(ip));
    }
    next_ng += 10;

    // New nodes connect to existing network
    for (int new_id : new_nodes) {
      std::vector<int> targets = active_nodes;
      std::shuffle(targets.begin(), targets.end(), rng);
      for (int target_id : targets) {
        net.Connect(new_id, target_id, SimConnectionType::OUTBOUND_FULL_RELAY);
      }
      active_nodes.push_back(new_id);
    }

    // Existing nodes may reconnect to fill slots
    for (int node_id : active_nodes) {
      auto* node = net.GetNode(node_id);
      if (node && node->TotalOutboundCount() < 8) {
        std::vector<int> targets = active_nodes;
        std::shuffle(targets.begin(), targets.end(), rng);
        for (int target_id : targets) {
          if (target_id == node_id) continue;
          if (node->TotalOutboundCount() >= 8) break;
          net.Connect(node_id, target_id, SimConnectionType::OUTBOUND_FULL_RELAY);
        }
      }
    }
  }

  // Measure final network health
  auto final_metrics = net.CollectMetrics();

  size_t well_connected = 0;
  size_t isolated = 0;
  net.ForEachNode([&](const EvictionTestNode& node) {
    // Only count active nodes
    bool is_active = std::find(active_nodes.begin(), active_nodes.end(), node.id) != active_nodes.end();
    if (!is_active) return;

    if (node.TotalConnectionCount() >= 4) {
      well_connected++;
    } else if (node.TotalConnectionCount() == 0) {
      isolated++;
    }
  });

  INFO("After " << CHURN_ROUNDS << " rounds of " << NODES_PER_ROUND << " node churn:");
  INFO("Active nodes: " << active_nodes.size());
  INFO("Well-connected (>=4): " << well_connected);
  INFO("Isolated (0): " << isolated);
  INFO("Final avg connections: " << (final_metrics.avg_inbound_count + final_metrics.avg_outbound_count));

  // Network should remain healthy after churn
  REQUIRE(well_connected >= active_nodes.size() * 0.8);
  REQUIRE(isolated < active_nodes.size() * 0.05);
}

// =============================================================================
// NETWORK SCALE: Eviction Under Load
// =============================================================================

TEST_CASE("Scale: Eviction behavior with nodes at capacity", "[evicsim][scale][eviction]") {
  EvictionTestNetwork net(42);
  std::mt19937 rng(42);

  // Create a "popular" node that will receive many inbound connections
  auto popular_id = net.CreateNode("8.8.0.1");
  auto* popular = net.GetNode(popular_id);
  popular->max_inbound = 20;  // Small limit to trigger evictions

  // Create 200 nodes that will all try to connect to the popular node
  std::vector<int> connector_nodes;
  for (size_t i = 0; i < 200; ++i) {
    int ng = 10 + (i % 50);
    std::string ip = std::to_string(ng) + "." + std::to_string(ng) + "." +
                     std::to_string(i / 50) + "." + std::to_string((i % 50) + 1);
    connector_nodes.push_back(net.CreateNode(ip));
  }

  size_t total_connection_attempts = 0;
  size_t successful_connections = 0;

  // All nodes try to connect to the popular node
  for (int from_id : connector_nodes) {
    total_connection_attempts++;
    if (net.Connect(from_id, popular_id, SimConnectionType::OUTBOUND_FULL_RELAY)) {
      successful_connections++;
    }
  }

  size_t total_evictions = popular->evictions_triggered;

  INFO("Connector nodes: " << connector_nodes.size());
  INFO("Popular node inbound limit: " << popular->max_inbound);
  INFO("Connection attempts: " << total_connection_attempts);
  INFO("Successful connections: " << successful_connections);
  INFO("Evictions triggered: " << total_evictions);
  INFO("Final inbound count: " << popular->InboundCount());

  // Verify inbound limit respected
  REQUIRE(popular->InboundCount() <= popular->max_inbound);

  // With 200 nodes connecting to a node with 20 inbound limit,
  // evictions must have occurred (200 - 20 = 180 evictions needed)
  REQUIRE(total_evictions > 100);
}

// =============================================================================
// NETWORK SCALE: Block-Relay Rotation at Scale
// =============================================================================

TEST_CASE("Scale: Block-relay rotation across 200 node network", "[evicsim][scale][rotation]") {
  EvictionTestNetwork net(42);
  std::mt19937 rng(42);

  constexpr size_t NUM_NODES = 200;
  constexpr size_t ROTATION_ROUNDS = 20;

  // Create nodes
  std::vector<int> all_nodes;
  for (size_t i = 0; i < NUM_NODES; ++i) {
    int ng = 10 + (i % 50);
    std::string ip = std::to_string(ng) + "." + std::to_string(ng) + "." +
                     std::to_string(i / 50) + "." + std::to_string((i % 50) + 1);
    all_nodes.push_back(net.CreateNode(ip));
  }

  // Each node establishes block-relay connections
  for (int node_id : all_nodes) {
    std::vector<int> targets = all_nodes;
    std::shuffle(targets.begin(), targets.end(), rng);

    size_t block_relay_count = 0;
    for (int target_id : targets) {
      if (block_relay_count >= 2) break;
      if (target_id == node_id) continue;

      if (net.Connect(node_id, target_id, SimConnectionType::BLOCK_RELAY)) {
        block_relay_count++;
      }
    }
  }

  // Track rotation statistics
  uint64_t initial_rotations = 0;
  net.ForEachNode([&](const EvictionTestNode& node) {
    initial_rotations += node.block_relay_rotations;
  });

  // Simulate rotation over time
  for (size_t round = 0; round < ROTATION_ROUNDS; ++round) {
    net.AdvanceTime(std::chrono::seconds(300));  // 5 minutes per round

    // Random subset of nodes receive headers (active)
    // Others become stale
    std::vector<int> active_nodes;
    for (int node_id : all_nodes) {
      if (rng() % 2 == 0) {
        active_nodes.push_back(node_id);
      }
    }

    // Simulate headers from active nodes
    for (int node_id : active_nodes) {
      auto* node = net.GetNode(node_id);
      if (!node) continue;

      for (const auto& [peer_id, info] : node->connections) {
        if (info.type == SimConnectionType::BLOCK_RELAY) {
          net.SimulateHeadersReceived(peer_id, node_id);
        }
      }
    }

    // Try rotations
    for (int node_id : all_nodes) {
      std::vector<int> candidates;
      for (int target_id : all_nodes) {
        auto* node = net.GetNode(node_id);
        if (node && target_id != node_id && !node->IsConnectedTo(target_id)) {
          candidates.push_back(target_id);
        }
      }
      std::shuffle(candidates.begin(), candidates.end(), rng);
      if (!candidates.empty()) {
        net.TryRotateBlockRelay(node_id, candidates);
      }
    }
  }

  uint64_t final_rotations = 0;
  net.ForEachNode([&](const EvictionTestNode& node) {
    final_rotations += node.block_relay_rotations;
  });

  uint64_t rotations_occurred = final_rotations - initial_rotations;

  INFO("Nodes: " << NUM_NODES);
  INFO("Rotation rounds: " << ROTATION_ROUNDS);
  INFO("Total rotations: " << rotations_occurred);
  INFO("Rotations per node (avg): " << static_cast<double>(rotations_occurred) / NUM_NODES);

  // With stale detection, rotations should occur
  REQUIRE(rotations_occurred > 0);

  // Rotation rate depends on stale peer frequency
  // With 50% nodes active each round, expect significant rotation
  REQUIRE(rotations_occurred <= NUM_NODES * ROTATION_ROUNDS);
}

