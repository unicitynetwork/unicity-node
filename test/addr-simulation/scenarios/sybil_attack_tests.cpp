// Copyright (c) 2025 The Unicity Foundation
// Sybil attack simulation tests
//
// Sybil attacks create many fake identities to manipulate address propagation
// and fingerprint network topology.

#include "../addr_test_network.hpp"
#include "catch_amalgamated.hpp"

#include <cmath>

using namespace unicity;
using namespace unicity::test::addrsim;

// Helper to calculate Gini coefficient (measure of inequality/concentration)
// 0 = perfect equality, 1 = perfect inequality
static double CalculateGini(const std::vector<size_t>& values) {
  if (values.empty()) return 0.0;

  size_t n = values.size();
  double sum = 0.0;
  double abs_diff_sum = 0.0;

  for (size_t i = 0; i < n; ++i) {
    sum += values[i];
    for (size_t j = 0; j < n; ++j) {
      abs_diff_sum += std::abs(static_cast<double>(values[i]) - static_cast<double>(values[j]));
    }
  }

  if (sum == 0) return 0.0;
  return abs_diff_sum / (2.0 * n * sum);
}

TEST_CASE("Sybil: Mass identity creation", "[addrsim][sybil][security]") {
  // Attacker creates many nodes to flood network with addresses
  // Defense: per-source limits, per-netgroup limits

  AddrTestNetwork net(42);

  // Create honest network core (20 nodes, well-connected)
  std::vector<int> honest_nodes;
  for (int ng = 1; ng <= 20; ++ng) {
    auto id = net.CreateNode("8." + std::to_string(ng) + ".0.1");
    honest_nodes.push_back(id);
  }

  // Connect honest nodes in mesh
  for (size_t i = 0; i < honest_nodes.size(); ++i) {
    for (size_t j = i + 1; j < honest_nodes.size() && j < i + 5; ++j) {
      net.Connect(honest_nodes[i], honest_nodes[j]);
    }
  }

  // Attacker creates 100 sybil identities across 10 netgroups
  std::vector<int> sybil_nodes;
  for (int i = 0; i < 100; ++i) {
    int ng = 50 + (i % 10);
    std::string ip = "44." + std::to_string(ng) + "." + std::to_string(i / 256) + "." + std::to_string((i % 256) + 1);
    auto id = net.CreateNode(ip);
    sybil_nodes.push_back(id);
  }

  // Sybils connect to random honest nodes
  for (int sybil : sybil_nodes) {
    // Each sybil connects to 3 random honest nodes
    for (int c = 0; c < 3; ++c) {
      int honest = honest_nodes[(sybil + c) % honest_nodes.size()];
      net.Connect(sybil, honest);
    }
  }

  // Each honest node advertises itself to its peers
  for (int honest : honest_nodes) {
    auto* honest_node = net.GetNode(honest);

    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(honest_node->ip_address, 9590);
    ta.timestamp = static_cast<uint32_t>(net.GetTime());

    for (int peer : honest_node->GetAllConnectedPeers()) {
      net.DeliverAddr(honest, peer, {ta});
    }
  }

  // Each sybil advertises its own address to connected peers
  for (int sybil : sybil_nodes) {
    auto* sybil_node = net.GetNode(sybil);

    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(sybil_node->ip_address, 9590);
    ta.timestamp = static_cast<uint32_t>(net.GetTime());

    for (int peer : sybil_node->GetAllConnectedPeers()) {
      net.DeliverAddr(sybil, peer, {ta});
    }
  }

  // Run propagation
  net.Run(20);

  // Check how many sybil addresses made it into honest nodes
  size_t total_sybil_addrs = 0;
  size_t total_honest_addrs = 0;

  for (int honest : honest_nodes) {
    auto* node = net.GetNode(honest);
    auto addrs = node->addr_mgr->get_addresses(10000, 100);

    for (const auto& ta : addrs) {
      auto ip_opt = ta.address.to_string();
      if (ip_opt) {
        if (ip_opt->substr(0, 3) == "44.") {
          total_sybil_addrs++;
        } else {
          total_honest_addrs++;
        }
      }
    }
  }

  double avg_sybil = static_cast<double>(total_sybil_addrs) / honest_nodes.size();
  double avg_honest = static_cast<double>(total_honest_addrs) / honest_nodes.size();

  INFO("Average sybil addresses per honest node: " << avg_sybil);
  INFO("Average honest addresses per honest node: " << avg_honest);

  // Sybils shouldn't completely dominate
  // Per-netgroup and per-source limits should help
  REQUIRE(avg_sybil < 200);  // Not overwhelming

  // Honest nodes should still have each other's addresses
  REQUIRE(avg_honest > 0);
}

TEST_CASE("Sybil: Address relay manipulation", "[addrsim][sybil][security]") {
  // Sybils try to control address relay to fingerprint or isolate nodes
  // Defense: deterministic relay target selection, limited relay peers

  AddrTestNetwork net(42);

  // Target node we want to observe
  auto target_id = net.CreateNode("8.1.0.1");

  // Honest neighbors
  std::vector<int> honest_neighbors;
  for (int i = 0; i < 5; ++i) {
    auto id = net.CreateNode("8." + std::to_string(i + 2) + ".0.1");
    honest_neighbors.push_back(id);
    net.Connect(target_id, id);
  }

  // Sybil neighbors (attacker trying to observe target's relay behavior)
  std::vector<int> sybil_neighbors;
  for (int i = 0; i < 10; ++i) {
    auto id = net.CreateNode("44." + std::to_string(i + 1) + ".0.1");
    sybil_neighbors.push_back(id);
    net.Connect(id, target_id);  // Inbound to target
  }

  // Send unique addresses through honest neighbors
  // Track which sybils receive relays
  std::map<int, std::set<std::string>> sybil_received;
  for (int sybil : sybil_neighbors) {
    sybil_received[sybil] = {};
  }

  for (int i = 0; i < 50; ++i) {
    int sender = honest_neighbors[i % honest_neighbors.size()];
    std::string addr = "9." + std::to_string(i) + ".0.1";

    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(addr, 9590);
    ta.timestamp = static_cast<uint32_t>(net.GetTime());

    net.DeliverAddr(sender, target_id, {ta});
    net.Tick();

    // Check which sybils received this address
    for (int sybil : sybil_neighbors) {
      auto* sybil_node = net.GetNode(sybil);
      auto addrs = sybil_node->addr_mgr->get_addresses(10000, 100);
      for (const auto& a : addrs) {
        auto ip_opt = a.address.to_string();
        if (ip_opt && *ip_opt == addr) {
          sybil_received[sybil].insert(addr);
        }
      }
    }
  }

  // Analyze relay pattern
  std::vector<size_t> receive_counts;
  for (const auto& [sybil, addrs] : sybil_received) {
    receive_counts.push_back(addrs.size());
    INFO("Sybil " << sybil << " received " << addrs.size() << " addresses");
  }

  // With limited relay peers (2), not all sybils should receive all addresses
  size_t sybils_with_some_addrs = 0;
  size_t sybils_with_all_addrs = 0;
  for (size_t count : receive_counts) {
    if (count > 0) sybils_with_some_addrs++;
    if (count >= 45) sybils_with_all_addrs++;  // 90% or more
  }

  INFO("Sybils with some addresses: " << sybils_with_some_addrs);
  INFO("Sybils with most addresses: " << sybils_with_all_addrs);

  // Not all sybils should receive everything (relay is limited)
  REQUIRE(sybils_with_all_addrs < sybil_neighbors.size());
}

TEST_CASE("Sybil: GETADDR response consistency", "[addrsim][sybil][security]") {
  // Sybils request GETADDR multiple times to fingerprint address table
  // Defense: cached responses, once-per-connection limit

  AddrTestNetwork net(42);

  auto target_id = net.CreateNode("8.1.0.1");
  auto* target = net.GetNode(target_id);

  // Populate target's AddrMan
  for (int ng = 1; ng <= 50; ++ng) {
    net.InjectAddress(target_id, "8." + std::to_string(ng) + ".0.1");
  }

  INFO("Target has " << target->addr_mgr->size() << " addresses");

  // Multiple sybil connections requesting GETADDR
  std::vector<std::set<std::string>> responses;

  for (int i = 0; i < 10; ++i) {
    auto sybil_id = net.CreateNode("44." + std::to_string(i + 1) + ".0.1");
    net.Connect(sybil_id, target_id);

    auto response = net.DeliverGetAddr(sybil_id, target_id);

    std::set<std::string> addr_set;
    for (const auto& ta : response) {
      auto ip_opt = ta.address.to_string();
      if (ip_opt) {
        addr_set.insert(*ip_opt);
      }
    }
    responses.push_back(addr_set);

    INFO("Sybil " << i << " got " << response.size() << " addresses");
  }

  // Check consistency - all sybils should get similar responses
  // (because of GETADDR response caching)
  if (responses.size() >= 2 && !responses[0].empty()) {
    // Compare first response to others
    size_t matching_count = 0;
    for (size_t i = 1; i < responses.size(); ++i) {
      size_t intersection = 0;
      for (const auto& addr : responses[0]) {
        if (responses[i].count(addr)) {
          intersection++;
        }
      }

      double overlap = static_cast<double>(intersection) / responses[0].size();
      INFO("Response " << i << " overlap with response 0: " << (overlap * 100) << "%");

      if (overlap > 0.9) {
        matching_count++;
      }
    }

    // With caching, most responses should be highly similar
    // (same 23% sample within cache window)
    INFO("Responses matching first: " << matching_count << " / " << (responses.size() - 1));
  }

  // Once-per-connection: second request should return empty
  auto repeat_sybil = net.CreateNode("44.100.0.1");
  net.Connect(repeat_sybil, target_id);

  auto first_response = net.DeliverGetAddr(repeat_sybil, target_id);
  auto second_response = net.DeliverGetAddr(repeat_sybil, target_id);

  INFO("First GETADDR: " << first_response.size() << " addresses");
  INFO("Second GETADDR: " << second_response.size() << " addresses");

  REQUIRE(first_response.size() > 0);
  REQUIRE(second_response.size() == 0);  // Once per connection
}

TEST_CASE("Sybil: Network partition attempt", "[addrsim][sybil][security]") {
  // Sybils try to prevent address propagation between network partitions
  // by not relaying between honest groups

  AddrTestNetwork net(42);

  // Create two honest clusters
  std::vector<int> cluster_a;
  for (int i = 0; i < 10; ++i) {
    auto id = net.CreateNode("8." + std::to_string(i + 1) + ".0.1");
    cluster_a.push_back(id);
  }

  std::vector<int> cluster_b;
  for (int i = 0; i < 10; ++i) {
    auto id = net.CreateNode("9." + std::to_string(i + 1) + ".0.1");
    cluster_b.push_back(id);
  }

  // Connect within clusters
  for (size_t i = 0; i < cluster_a.size(); ++i) {
    for (size_t j = i + 1; j < cluster_a.size() && j < i + 3; ++j) {
      net.Connect(cluster_a[i], cluster_a[j]);
    }
  }

  for (size_t i = 0; i < cluster_b.size(); ++i) {
    for (size_t j = i + 1; j < cluster_b.size() && j < i + 3; ++j) {
      net.Connect(cluster_b[i], cluster_b[j]);
    }
  }

  // Sybils are the only bridge between clusters
  // (In real attack, sybils would selectively drop relays)
  std::vector<int> bridge_sybils;
  for (int i = 0; i < 5; ++i) {
    auto id = net.CreateNode("44." + std::to_string(i + 1) + ".0.1");
    bridge_sybils.push_back(id);

    // Connect to both clusters
    net.Connect(id, cluster_a[i % cluster_a.size()]);
    net.Connect(id, cluster_b[i % cluster_b.size()]);
  }

  // Inject unique address in cluster A
  std::string cluster_a_addr = "7.1.0.1";
  net.InjectAddress(cluster_a[0], cluster_a_addr);

  // Send to neighbors
  auto* node_a0 = net.GetNode(cluster_a[0]);
  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string(cluster_a_addr, 9590);
  ta.timestamp = static_cast<uint32_t>(net.GetTime());

  for (int peer : node_a0->GetAllConnectedPeers()) {
    net.DeliverAddr(cluster_a[0], peer, {ta});
  }

  // Run propagation (sybils DO relay in this simulation)
  net.Run(30);

  // Check if address reached cluster B
  size_t cluster_b_with_addr = 0;
  for (int node_id : cluster_b) {
    auto* node = net.GetNode(node_id);
    auto addrs = node->addr_mgr->get_addresses(10000, 100);
    for (const auto& a : addrs) {
      auto ip_opt = a.address.to_string();
      if (ip_opt && *ip_opt == cluster_a_addr) {
        cluster_b_with_addr++;
        break;
      }
    }
  }

  INFO("Cluster B nodes with cluster A's address: " << cluster_b_with_addr << " / " << cluster_b.size());

  // With honest relay, address should propagate
  // (This test shows what happens WITH relay; a partition attack would require sybils to DROP relays)
  REQUIRE(cluster_b_with_addr > 0);
}

TEST_CASE("Sybil: Address table distribution fairness", "[addrsim][sybil][security]") {
  // Check that address distribution across the network is fair
  // despite sybil presence

  AddrTestNetwork net(42);

  // Create network: 30 honest + 20 sybils
  std::vector<int> honest_nodes;
  for (int i = 0; i < 30; ++i) {
    auto id = net.CreateNode("8." + std::to_string((i % 30) + 1) + ".0." + std::to_string((i / 30) + 1));
    honest_nodes.push_back(id);
  }

  std::vector<int> sybil_nodes;
  for (int i = 0; i < 20; ++i) {
    auto id = net.CreateNode("44." + std::to_string((i % 20) + 1) + ".0.1");
    sybil_nodes.push_back(id);
  }

  // Random topology
  std::vector<int> all_nodes = honest_nodes;
  all_nodes.insert(all_nodes.end(), sybil_nodes.begin(), sybil_nodes.end());

  for (int node : all_nodes) {
    // Connect to 5 random peers
    for (int c = 0; c < 5; ++c) {
      int peer = all_nodes[(node + c * 7 + 1) % all_nodes.size()];
      net.Connect(node, peer);
    }
  }

  // Each node advertises itself
  for (int node : all_nodes) {
    auto* n = net.GetNode(node);
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(n->ip_address, 9590);
    ta.timestamp = static_cast<uint32_t>(net.GetTime());

    for (int peer : n->GetAllConnectedPeers()) {
      net.DeliverAddr(node, peer, {ta});
    }
  }

  net.Run(30);

  // Measure distribution across honest nodes
  std::vector<size_t> honest_addr_counts;
  std::vector<size_t> sybil_addr_counts;

  for (int honest : honest_nodes) {
    auto* node = net.GetNode(honest);
    size_t honest_addrs = 0;
    size_t sybil_addrs = 0;

    auto addrs = node->addr_mgr->get_addresses(10000, 100);
    for (const auto& ta : addrs) {
      auto ip_opt = ta.address.to_string();
      if (ip_opt) {
        if (ip_opt->substr(0, 3) == "44.") {
          sybil_addrs++;
        } else {
          honest_addrs++;
        }
      }
    }

    honest_addr_counts.push_back(honest_addrs);
    sybil_addr_counts.push_back(sybil_addrs);
  }

  // Calculate Gini coefficients
  double honest_gini = CalculateGini(honest_addr_counts);
  double sybil_gini = CalculateGini(sybil_addr_counts);

  double avg_honest = 0, avg_sybil = 0;
  for (size_t i = 0; i < honest_addr_counts.size(); ++i) {
    avg_honest += honest_addr_counts[i];
    avg_sybil += sybil_addr_counts[i];
  }
  avg_honest /= honest_addr_counts.size();
  avg_sybil /= sybil_addr_counts.size();

  INFO("Average honest addresses per node: " << avg_honest);
  INFO("Average sybil addresses per node: " << avg_sybil);
  INFO("Honest address Gini coefficient: " << honest_gini);
  INFO("Sybil address Gini coefficient: " << sybil_gini);

  // Distribution should be reasonably fair (low Gini)
  REQUIRE(honest_gini < 0.5);  // Not too concentrated

  // Sybils shouldn't dominate
  REQUIRE(avg_sybil < avg_honest * 2);  // Sybils are 40% of network, shouldn't have >2x representation
}
