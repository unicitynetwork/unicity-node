// Copyright (c) 2025 The Unicity Foundation
// Large-scale network simulation tests for address management
//
// These tests simulate networks with 100s-1000s of nodes to verify
// network-wide address propagation, eclipse resistance, and ADDR relay behavior.

#include "catch_amalgamated.hpp"
#include "addr_test_network.hpp"

#include <algorithm>
#include <random>
#include <set>

using namespace unicity;
using namespace unicity::test::addrsim;

namespace {

// Helper: Count how many nodes have a specific address in their AddrMan
size_t CountNodesWithAddress(const AddrTestNetwork& net, const std::string& addr_ip) {
  size_t count = 0;
  auto target = protocol::NetworkAddress::from_string(addr_ip, 9590);

  net.ForEachNode([&](const AddrTestNode& node) {
    auto addrs = node.addr_mgr->get_addresses(10000, 100);
    for (const auto& ta : addrs) {
      if (ta.address.ip == target.ip) {
        count++;
        break;
      }
    }
  });

  return count;
}

// Helper: Count addresses from a specific netgroup in a node's AddrMan
size_t CountAddressesFromNetgroup(const AddrTestNode& node, const std::string& netgroup_prefix) {
  size_t count = 0;
  auto addrs = node.addr_mgr->get_addresses(10000, 100);
  for (const auto& ta : addrs) {
    auto ip_opt = ta.address.to_string();
    if (ip_opt && ip_opt->find(netgroup_prefix) == 0) {
      count++;
    }
  }
  return count;
}

}  // namespace

// =============================================================================
// NETWORK SCALE: Address Propagation
// =============================================================================

TEST_CASE("Scale: Address propagates through 100 node network", "[addrsim][scale][propagation]") {
  AddrTestNetwork net(42);

  constexpr size_t NUM_NODES = 100;
  constexpr size_t AVG_CONNECTIONS = 8;

  // Create nodes across diverse netgroups
  for (size_t i = 0; i < NUM_NODES; ++i) {
    int ng = 10 + (i % 50);
    std::string ip = std::to_string(ng) + "." + std::to_string(ng) + "." +
                     std::to_string(i / 50) + "." + std::to_string((i % 50) + 1);
    net.CreateNode(ip);
  }

  // Create random topology
  net.CreateRandomTopology(AVG_CONNECTIONS);

  // Inject a fresh address into node 0
  std::string test_addr = "99.99.0.1";
  auto* node0 = net.GetNode(0);
  REQUIRE(node0 != nullptr);

  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string(test_addr, 9590);
  ta.timestamp = static_cast<uint32_t>(net.GetTime());

  // Deliver to node 0's peers (simulating node 0 announcing)
  for (int peer_id : node0->GetAllConnectedPeers()) {
    net.DeliverAddr(0, peer_id, {ta});
  }

  // Run simulation for propagation
  net.Run(50);

  // Check propagation
  size_t nodes_with_addr = CountNodesWithAddress(net, test_addr);
  double propagation_pct = 100.0 * nodes_with_addr / NUM_NODES;

  INFO("Nodes: " << NUM_NODES);
  INFO("Nodes with address: " << nodes_with_addr);
  INFO("Propagation: " << propagation_pct << "%");

  // Address should propagate to significant portion of network
  REQUIRE(propagation_pct > 30.0);
}

TEST_CASE("Scale: Address propagation in 500 node network", "[addrsim][scale][propagation]") {
  AddrTestNetwork net(123);

  constexpr size_t NUM_NODES = 500;
  constexpr size_t AVG_CONNECTIONS = 8;

  // Create nodes
  for (size_t i = 0; i < NUM_NODES; ++i) {
    int ng = 10 + (i % 100);
    std::string ip = std::to_string(ng) + "." + std::to_string(ng % 256) + "." +
                     std::to_string(i / 100) + "." + std::to_string((i % 100) + 1);
    net.CreateNode(ip);
  }

  net.CreateRandomTopology(AVG_CONNECTIONS);

  // Inject address at a random starting node
  std::string test_addr = "99.99.0.1";
  auto* start_node = net.GetNode(250);  // Middle node
  REQUIRE(start_node != nullptr);

  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string(test_addr, 9590);
  ta.timestamp = static_cast<uint32_t>(net.GetTime());

  // Initial broadcast
  for (int peer_id : start_node->GetAllConnectedPeers()) {
    net.DeliverAddr(250, peer_id, {ta});
  }

  // Run longer for larger network
  net.Run(100);

  size_t nodes_with_addr = CountNodesWithAddress(net, test_addr);
  double propagation_pct = 100.0 * nodes_with_addr / NUM_NODES;

  INFO("Nodes: " << NUM_NODES);
  INFO("Propagation: " << propagation_pct << "%");

  // Should reach significant portion even in larger network
  REQUIRE(propagation_pct > 20.0);
}

// =============================================================================
// NETWORK SCALE: Network-Wide Eclipse Resistance
// =============================================================================

TEST_CASE("Scale: Network resists coordinated address flooding", "[addrsim][scale][eclipse]") {
  AddrTestNetwork net(42);
  std::mt19937 rng(42);

  constexpr size_t NUM_HONEST = 100;
  constexpr size_t NUM_ATTACKER_ADDRS = 500;

  // Create honest nodes
  std::vector<int> honest_nodes;
  for (size_t i = 0; i < NUM_HONEST; ++i) {
    int ng = 10 + (i % 50);
    std::string ip = std::to_string(ng) + "." + std::to_string(ng) + "." +
                     std::to_string(i / 50) + "." + std::to_string((i % 50) + 1);
    honest_nodes.push_back(net.CreateNode(ip));
  }

  // Seed honest nodes with legitimate addresses first
  for (int honest_id : honest_nodes) {
    for (int i = 0; i < 100; ++i) {
      int ng = 10 + (rng() % 50);
      std::string ip = std::to_string(ng) + "." + std::to_string(ng) + "." +
                       std::to_string(rng() % 256) + "." + std::to_string((rng() % 254) + 1);
      net.InjectAddress(honest_id, ip);
    }
  }

  // Create attacker node (will inject malicious addresses)
  int attacker_id = net.CreateNode("66.66.0.1");

  // Connect attacker to all honest nodes
  for (int honest_id : honest_nodes) {
    net.Connect(attacker_id, honest_id);
  }

  // Honest nodes also connect to each other
  net.CreateRandomTopology(8);

  // Attacker floods network with addresses from single netgroup
  std::vector<protocol::TimestampedAddress> attack_addrs;
  for (size_t i = 0; i < NUM_ATTACKER_ADDRS; ++i) {
    protocol::TimestampedAddress ta;
    std::string ip = "44.44." + std::to_string(i / 256) + "." + std::to_string((i % 256) + 1);
    ta.address = protocol::NetworkAddress::from_string(ip, 9590);
    ta.timestamp = static_cast<uint32_t>(net.GetTime());
    attack_addrs.push_back(ta);
  }

  // Deliver attack addresses to all honest nodes
  for (int honest_id : honest_nodes) {
    // Deliver in batches (large ADDR messages aren't relayed)
    for (size_t i = 0; i < attack_addrs.size(); i += 10) {
      size_t end = std::min(i + 10, attack_addrs.size());
      std::vector<protocol::TimestampedAddress> batch(attack_addrs.begin() + i,
                                                       attack_addrs.begin() + end);
      net.DeliverAddr(attacker_id, honest_id, batch);
    }
  }

  // Let network process
  net.Run(20);

  // Check how dominated each node's table is by attacker addresses
  size_t max_attacker_addrs = 0;
  size_t total_attacker_addrs = 0;
  size_t nodes_over_50pct = 0;

  for (int honest_id : honest_nodes) {
    auto* node = net.GetNode(honest_id);
    size_t attacker_count = CountAddressesFromNetgroup(*node, "44.44.");
    size_t total = node->addr_mgr->size();

    max_attacker_addrs = std::max(max_attacker_addrs, attacker_count);
    total_attacker_addrs += attacker_count;

    if (total > 0 && attacker_count > total / 2) {
      nodes_over_50pct++;
    }
  }

  double avg_attacker_addrs = static_cast<double>(total_attacker_addrs) / NUM_HONEST;

  INFO("Attacker flooded: " << NUM_ATTACKER_ADDRS << " addresses");
  INFO("Max attacker addrs in any node: " << max_attacker_addrs);
  INFO("Avg attacker addrs per node: " << avg_attacker_addrs);
  INFO("Nodes with >50% attacker addrs: " << nodes_over_50pct);

  // Per-netgroup limits should prevent attacker from dominating
  // Attacker addresses all in 44.44.x.x, limited by per-group caps
  REQUIRE(nodes_over_50pct < NUM_HONEST / 2);
}

TEST_CASE("Scale: Diverse attacker addresses across netgroups", "[addrsim][scale][eclipse][diverse]") {
  AddrTestNetwork net(99);
  std::mt19937 rng(99);

  constexpr size_t NUM_HONEST = 50;
  constexpr size_t NUM_ATTACKER_NETGROUPS = 20;
  constexpr size_t ADDRS_PER_NETGROUP = 50;

  // Create honest nodes
  std::vector<int> honest_nodes;
  for (size_t i = 0; i < NUM_HONEST; ++i) {
    int ng = 10 + (i % 25);
    std::string ip = std::to_string(ng) + "." + std::to_string(ng) + "." +
                     std::to_string(i / 25) + "." + std::to_string((i % 25) + 1);
    honest_nodes.push_back(net.CreateNode(ip));
  }

  // Seed honest nodes with legitimate addresses first
  for (int honest_id : honest_nodes) {
    for (int i = 0; i < 100; ++i) {
      int ng = 10 + (rng() % 50);
      std::string ip = std::to_string(ng) + "." + std::to_string(ng) + "." +
                       std::to_string(rng() % 256) + "." + std::to_string((rng() % 254) + 1);
      net.InjectAddress(honest_id, ip);
    }
  }

  int attacker_id = net.CreateNode("66.66.0.1");

  // Connect attacker to all honest nodes
  for (int honest_id : honest_nodes) {
    net.Connect(attacker_id, honest_id);
  }

  // Attacker floods with addresses from DIVERSE netgroups (smarter attack)
  std::vector<protocol::TimestampedAddress> attack_addrs;
  for (size_t ng = 0; ng < NUM_ATTACKER_NETGROUPS; ++ng) {
    for (size_t i = 0; i < ADDRS_PER_NETGROUP; ++i) {
      protocol::TimestampedAddress ta;
      int first = 200 + ng;
      std::string ip = std::to_string(first) + "." + std::to_string(first) + "." +
                       std::to_string(i / 10) + "." + std::to_string((i % 10) + 1);
      ta.address = protocol::NetworkAddress::from_string(ip, 9590);
      ta.timestamp = static_cast<uint32_t>(net.GetTime());
      attack_addrs.push_back(ta);
    }
  }

  // Deliver to all honest nodes
  for (int honest_id : honest_nodes) {
    for (size_t i = 0; i < attack_addrs.size(); i += 10) {
      size_t end = std::min(i + 10, attack_addrs.size());
      std::vector<protocol::TimestampedAddress> batch(attack_addrs.begin() + i,
                                                       attack_addrs.begin() + end);
      net.DeliverAddr(attacker_id, honest_id, batch);
    }
  }

  net.Run(20);

  // With diverse attacker netgroups, they might have more success
  // But honest nodes should still have some honest addresses
  size_t nodes_fully_eclipsed = 0;

  for (int honest_id : honest_nodes) {
    auto* node = net.GetNode(honest_id);
    size_t attacker_count = 0;

    auto addrs = node->addr_mgr->get_addresses(10000, 100);
    for (const auto& ta : addrs) {
      auto ip_opt = ta.address.to_string();
      if (!ip_opt) continue;
      // Check if in attacker range (200-219)
      int first_octet = std::stoi(ip_opt->substr(0, ip_opt->find('.')));
      if (first_octet >= 200 && first_octet < 200 + (int)NUM_ATTACKER_NETGROUPS) {
        attacker_count++;
      }
    }

    if (attacker_count == addrs.size() && addrs.size() > 0) {
      nodes_fully_eclipsed++;
    }
  }

  double eclipse_rate = 100.0 * nodes_fully_eclipsed / NUM_HONEST;

  INFO("Attacker netgroups: " << NUM_ATTACKER_NETGROUPS);
  INFO("Total attacker addresses: " << attack_addrs.size());
  INFO("Fully eclipsed nodes: " << nodes_fully_eclipsed);
  INFO("Eclipse rate: " << eclipse_rate << "%");

  // Even with diverse attack, shouldn't eclipse majority
  REQUIRE(eclipse_rate < 50.0);
}

// =============================================================================
// NETWORK SCALE: GETADDR Behavior at Scale
// =============================================================================

TEST_CASE("Scale: GETADDR responses across 200 node network", "[addrsim][scale][getaddr]") {
  AddrTestNetwork net(42);

  constexpr size_t NUM_NODES = 200;

  // Create nodes
  std::vector<int> all_nodes;
  for (size_t i = 0; i < NUM_NODES; ++i) {
    int ng = 10 + (i % 50);
    std::string ip = std::to_string(ng) + "." + std::to_string(ng) + "." +
                     std::to_string(i / 50) + "." + std::to_string((i % 50) + 1);
    all_nodes.push_back(net.CreateNode(ip));
  }

  net.CreateRandomTopology(8);

  // Seed each node with some addresses
  std::mt19937 rng(42);
  for (int node_id : all_nodes) {
    // Add 50 random addresses to each node
    for (int i = 0; i < 50; ++i) {
      int ng = 10 + (rng() % 100);
      std::string ip = std::to_string(ng) + "." + std::to_string(ng) + "." +
                       std::to_string(rng() % 256) + "." + std::to_string((rng() % 254) + 1);
      net.InjectAddress(node_id, ip);
    }
  }

  // Each node sends GETADDR to one peer and collects response
  size_t total_responses = 0;
  size_t empty_responses = 0;
  size_t total_addrs_received = 0;

  for (int node_id : all_nodes) {
    auto* node = net.GetNode(node_id);
    auto peers = node->GetAllConnectedPeers();
    if (peers.empty()) continue;

    int peer_id = *peers.begin();
    auto response = net.DeliverGetAddr(node_id, peer_id);

    total_responses++;
    if (response.empty()) {
      empty_responses++;
    } else {
      total_addrs_received += response.size();
    }
  }

  double avg_response_size = total_responses > 0 ?
      static_cast<double>(total_addrs_received) / total_responses : 0;

  INFO("GETADDR requests: " << total_responses);
  INFO("Empty responses: " << empty_responses);
  INFO("Total addresses received: " << total_addrs_received);
  INFO("Avg response size: " << avg_response_size);

  // Most nodes should have addresses to share
  REQUIRE(empty_responses < total_responses / 2);
  REQUIRE(avg_response_size > 5.0);
}

// =============================================================================
// NETWORK SCALE: Network Health Under Churn
// =============================================================================

TEST_CASE("Scale: Address tables survive 50% node churn", "[addrsim][scale][churn]") {
  AddrTestNetwork net(42);
  std::mt19937 rng(42);

  constexpr size_t INITIAL_NODES = 100;
  constexpr size_t CHURN_ROUNDS = 5;
  constexpr size_t NODES_PER_ROUND = 10;

  // Create initial network
  std::vector<int> active_nodes;
  for (size_t i = 0; i < INITIAL_NODES; ++i) {
    int ng = 10 + (i % 50);
    std::string ip = std::to_string(ng) + "." + std::to_string(ng) + "." +
                     std::to_string(i / 50) + "." + std::to_string((i % 50) + 1);
    active_nodes.push_back(net.CreateNode(ip));
  }

  net.CreateRandomTopology(8);

  // Seed addresses
  for (int node_id : active_nodes) {
    for (int i = 0; i < 30; ++i) {
      int ng = 10 + (rng() % 50);
      std::string ip = std::to_string(ng) + "." + std::to_string(ng) + "." +
                       std::to_string(rng() % 256) + "." + std::to_string((rng() % 254) + 1);
      net.InjectAddress(node_id, ip);
    }
  }

  auto initial_metrics = net.CollectMetrics();
  INFO("Initial avg table size: " << initial_metrics.avg_total_size);

  int next_ng = 100;

  // Simulate churn
  for (size_t round = 0; round < CHURN_ROUNDS; ++round) {
    // Remove random nodes
    std::shuffle(active_nodes.begin(), active_nodes.end(), rng);
    for (size_t i = 0; i < NODES_PER_ROUND && !active_nodes.empty(); ++i) {
      int node_id = active_nodes.back();
      active_nodes.pop_back();

      // Disconnect from all peers
      auto* node = net.GetNode(node_id);
      if (node) {
        auto peers = node->GetAllConnectedPeers();
        for (int peer_id : peers) {
          net.Disconnect(node_id, peer_id);
        }
      }
    }

    // Add new nodes
    for (size_t i = 0; i < NODES_PER_ROUND; ++i) {
      int ng = next_ng + (i % 10);
      std::string ip = std::to_string(ng) + "." + std::to_string(ng) + "." +
                       std::to_string(i / 10) + "." + std::to_string((i % 10) + 1);
      int new_id = net.CreateNode(ip);
      active_nodes.push_back(new_id);

      // Connect to random existing nodes
      std::vector<int> targets = active_nodes;
      std::shuffle(targets.begin(), targets.end(), rng);
      for (size_t j = 0; j < 8 && j < targets.size(); ++j) {
        if (targets[j] != new_id) {
          net.Connect(new_id, targets[j]);
        }
      }

      // New node gets addresses via GETADDR
      auto* new_node = net.GetNode(new_id);
      for (int peer_id : new_node->GetAllConnectedPeers()) {
        auto addrs = net.DeliverGetAddr(new_id, peer_id);
        if (!addrs.empty()) {
          net.DeliverAddr(peer_id, new_id, addrs);
        }
        break;  // One GETADDR is enough
      }
    }

    next_ng += 10;
    net.Run(10);
  }

  // Check final network health
  size_t nodes_with_addresses = 0;
  double total_table_size = 0;

  for (int node_id : active_nodes) {
    auto* node = net.GetNode(node_id);
    if (node && node->addr_mgr->size() > 0) {
      nodes_with_addresses++;
      total_table_size += node->addr_mgr->size();
    }
  }

  double avg_table_size = active_nodes.empty() ? 0 :
      total_table_size / active_nodes.size();

  INFO("After " << CHURN_ROUNDS << " rounds of churn:");
  INFO("Active nodes: " << active_nodes.size());
  INFO("Nodes with addresses: " << nodes_with_addresses);
  INFO("Avg table size: " << avg_table_size);

  // Network should remain healthy
  REQUIRE(nodes_with_addresses >= active_nodes.size() * 0.7);
  REQUIRE(avg_table_size > 5.0);
}

// =============================================================================
// NETWORK SCALE: Traffic Analysis
// =============================================================================

TEST_CASE("Scale: ADDR relay traffic in 300 node network", "[addrsim][scale][traffic]") {
  AddrTestNetwork net(42);

  constexpr size_t NUM_NODES = 300;
  constexpr size_t NUM_TEST_ADDRS = 50;

  // Create network
  for (size_t i = 0; i < NUM_NODES; ++i) {
    int ng = 10 + (i % 75);
    std::string ip = std::to_string(ng) + "." + std::to_string(ng % 256) + "." +
                     std::to_string(i / 75) + "." + std::to_string((i % 75) + 1);
    net.CreateNode(ip);
  }

  net.CreateRandomTopology(8);

  // Inject addresses from a single source node
  std::vector<protocol::TimestampedAddress> test_addrs;
  for (size_t i = 0; i < NUM_TEST_ADDRS; ++i) {
    protocol::TimestampedAddress ta;
    std::string ip = "99.99." + std::to_string(i / 256) + "." + std::to_string((i % 256) + 1);
    ta.address = protocol::NetworkAddress::from_string(ip, 9590);
    ta.timestamp = static_cast<uint32_t>(net.GetTime());
    test_addrs.push_back(ta);
  }

  // Deliver from node 0 to its peers
  auto* node0 = net.GetNode(0);
  for (int peer_id : node0->GetAllConnectedPeers()) {
    // Small batches for relay
    for (size_t i = 0; i < test_addrs.size(); i += 5) {
      size_t end = std::min(i + 5, test_addrs.size());
      std::vector<protocol::TimestampedAddress> batch(test_addrs.begin() + i,
                                                       test_addrs.begin() + end);
      net.DeliverAddr(0, peer_id, batch);
    }
  }

  // Run simulation
  net.Run(100);

  auto metrics = net.CollectMetrics();

  INFO("Nodes: " << NUM_NODES);
  INFO("Test addresses injected: " << NUM_TEST_ADDRS);
  INFO("Total addresses received (network-wide): " << metrics.total_addrs_received);
  INFO("Total addresses relayed (network-wide): " << metrics.total_addrs_relayed);

  // Relay should happen but not explode (limited to 2 peers per address)
  // With 300 nodes and 8 connections each, relay amplification should be bounded
  REQUIRE(metrics.total_addrs_relayed > 0);
  REQUIRE(metrics.total_addrs_relayed < NUM_NODES * NUM_TEST_ADDRS * 10);  // Bounded amplification
}

// =============================================================================
// NETWORK SCALE: Large Network Stress Test
// =============================================================================

TEST_CASE("Scale: 1000 node network stress test", "[addrsim][scale][stress]") {
  AddrTestNetwork net(42);
  std::mt19937 rng(42);

  constexpr size_t NUM_NODES = 1000;

  // Create large network
  std::vector<int> all_nodes;
  for (size_t i = 0; i < NUM_NODES; ++i) {
    int ng = 10 + (i % 200);
    std::string ip = std::to_string(ng) + "." + std::to_string(ng % 256) + "." +
                     std::to_string((i / 200) % 256) + "." + std::to_string((i % 200) + 1);
    all_nodes.push_back(net.CreateNode(ip));
  }

  net.CreateRandomTopology(8);

  // Each node injects some addresses
  for (int node_id : all_nodes) {
    for (int i = 0; i < 20; ++i) {
      int ng = 10 + (rng() % 200);
      std::string ip = std::to_string(ng) + "." + std::to_string(ng % 256) + "." +
                       std::to_string(rng() % 256) + "." + std::to_string((rng() % 254) + 1);
      net.InjectAddress(node_id, ip);
    }
  }

  // Run simulation
  net.Run(50);

  // Collect metrics
  auto metrics = net.CollectMetrics();

  INFO("Nodes: " << NUM_NODES);
  INFO("Avg table size: " << metrics.avg_total_size);
  INFO("Avg TRIED: " << metrics.avg_tried_size);
  INFO("Avg NEW: " << metrics.avg_new_size);

  // All nodes should have some addresses
  size_t nodes_with_addrs = 0;
  net.ForEachNode([&](const AddrTestNode& node) {
    if (node.addr_mgr->size() > 0) {
      nodes_with_addrs++;
    }
  });

  INFO("Nodes with addresses: " << nodes_with_addrs);

  REQUIRE(nodes_with_addrs >= NUM_NODES * 0.95);
  REQUIRE(metrics.avg_total_size > 10.0);
}

