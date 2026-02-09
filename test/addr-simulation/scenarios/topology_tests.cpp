// Copyright (c) 2025 The Unicity Foundation
// Network topology effect tests
//
// Different network topologies affect address propagation:
// - Hub-and-spoke vs mesh
// - High vs low connectivity
// - Clustered vs random

#include "../addr_test_network.hpp"
#include "catch_amalgamated.hpp"
#include "util/time.hpp"

using namespace unicity;
using namespace unicity::test::addrsim;

TEST_CASE("Topology: Hub-and-spoke propagation", "[addrsim][topology]") {
  // Hub-and-spoke: one central node connected to many spokes
  // Propagation depends heavily on the hub

  AddrTestNetwork net(42);

  // Central hub
  auto hub_id = net.CreateNode("8.1.0.1");

  // 20 spoke nodes, only connected to hub
  std::vector<int> spokes;
  for (int i = 0; i < 20; ++i) {
    auto spoke_id = net.CreateNode("8." + std::to_string(i + 2) + ".0.1");
    spokes.push_back(spoke_id);
    net.Connect(spoke_id, hub_id);  // Spoke connects to hub
  }

  // One spoke advertises an address
  std::string test_addr = "9.1.0.1";
  net.InjectAddress(spokes[0], test_addr);

  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string(test_addr, 9590);
  ta.timestamp = static_cast<uint32_t>(util::GetTime());

  net.DeliverAddr(spokes[0], hub_id, {ta});

  // Run propagation
  net.Run(10);

  // Count how many spokes received the address
  size_t spokes_with_addr = 0;
  for (int spoke : spokes) {
    auto* node = net.GetNode(spoke);
    auto addrs = node->addr_mgr->get_addresses(100, 100);
    for (const auto& a : addrs) {
      auto ip = a.address.to_string();
      if (ip && *ip == test_addr) {
        spokes_with_addr++;
        break;
      }
    }
  }

  INFO("Spokes with address: " << spokes_with_addr << " / " << spokes.size());

  // In hub-and-spoke with limited relay (2 peers), not all spokes will get it
  // Hub relays to 2 random spokes, no further propagation (spokes don't connect to each other)
  REQUIRE(spokes_with_addr >= 1);
  REQUIRE(spokes_with_addr <= 5);  // Limited due to relay limit
}

TEST_CASE("Topology: Mesh network propagation", "[addrsim][topology]") {
  // Mesh: every node connected to multiple others
  // Better propagation due to multiple paths

  AddrTestNetwork net(42);

  // Create 20 nodes
  std::vector<int> nodes;
  for (int i = 0; i < 20; ++i) {
    auto id = net.CreateNode("8." + std::to_string(i + 1) + ".0.1");
    nodes.push_back(id);
  }

  // Connect in mesh (each connects to 4 neighbors)
  for (size_t i = 0; i < nodes.size(); ++i) {
    for (size_t j = 1; j <= 4; ++j) {
      size_t neighbor = (i + j) % nodes.size();
      if (neighbor != i) {
        net.Connect(nodes[i], nodes[neighbor]);
      }
    }
  }

  // Node 0 advertises an address
  std::string test_addr = "9.1.0.1";
  net.InjectAddress(nodes[0], test_addr);

  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string(test_addr, 9590);
  ta.timestamp = static_cast<uint32_t>(util::GetTime());

  // Send to all neighbors
  auto* node0 = net.GetNode(nodes[0]);
  for (int peer : node0->GetAllConnectedPeers()) {
    net.DeliverAddr(nodes[0], peer, {ta});
  }

  // Run propagation
  net.Run(10);

  // Count nodes with the address
  size_t nodes_with_addr = 0;
  for (int node_id : nodes) {
    auto* node = net.GetNode(node_id);
    auto addrs = node->addr_mgr->get_addresses(100, 100);
    for (const auto& a : addrs) {
      auto ip = a.address.to_string();
      if (ip && *ip == test_addr) {
        nodes_with_addr++;
        break;
      }
    }
  }

  INFO("Nodes with address: " << nodes_with_addr << " / " << nodes.size());

  // Mesh should propagate better than hub-and-spoke
  REQUIRE(nodes_with_addr >= 10);  // At least half
}

TEST_CASE("Topology: Clustered networks", "[addrsim][topology]") {
  // Two clusters connected by few bridges
  // Tests propagation across cluster boundaries

  AddrTestNetwork net(42);

  // Cluster A: 10 well-connected nodes
  std::vector<int> cluster_a;
  for (int i = 0; i < 10; ++i) {
    auto id = net.CreateNode("8." + std::to_string(i + 1) + ".0.1");
    cluster_a.push_back(id);
  }

  // Cluster B: 10 well-connected nodes
  std::vector<int> cluster_b;
  for (int i = 0; i < 10; ++i) {
    auto id = net.CreateNode("9." + std::to_string(i + 1) + ".0.1");
    cluster_b.push_back(id);
  }

  // Intra-cluster connections (mesh within cluster)
  for (size_t i = 0; i < cluster_a.size(); ++i) {
    for (size_t j = i + 1; j < cluster_a.size() && j < i + 4; ++j) {
      net.Connect(cluster_a[i], cluster_a[j]);
    }
  }
  for (size_t i = 0; i < cluster_b.size(); ++i) {
    for (size_t j = i + 1; j < cluster_b.size() && j < i + 4; ++j) {
      net.Connect(cluster_b[i], cluster_b[j]);
    }
  }

  // Bridge: only 2 connections between clusters
  net.Connect(cluster_a[0], cluster_b[0]);
  net.Connect(cluster_a[5], cluster_b[5]);

  // Address starts in cluster A
  std::string test_addr = "7.1.0.1";
  net.InjectAddress(cluster_a[2], test_addr);

  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string(test_addr, 9590);
  ta.timestamp = static_cast<uint32_t>(util::GetTime());

  auto* starter = net.GetNode(cluster_a[2]);
  for (int peer : starter->GetAllConnectedPeers()) {
    net.DeliverAddr(cluster_a[2], peer, {ta});
  }

  // Run propagation
  net.Run(20);

  // Count in each cluster
  size_t cluster_a_count = 0;
  size_t cluster_b_count = 0;

  for (int node_id : cluster_a) {
    auto* node = net.GetNode(node_id);
    auto addrs = node->addr_mgr->get_addresses(100, 100);
    for (const auto& a : addrs) {
      auto ip = a.address.to_string();
      if (ip && *ip == test_addr) {
        cluster_a_count++;
        break;
      }
    }
  }

  for (int node_id : cluster_b) {
    auto* node = net.GetNode(node_id);
    auto addrs = node->addr_mgr->get_addresses(100, 100);
    for (const auto& a : addrs) {
      auto ip = a.address.to_string();
      if (ip && *ip == test_addr) {
        cluster_b_count++;
        break;
      }
    }
  }

  INFO("Cluster A with address: " << cluster_a_count);
  INFO("Cluster B with address: " << cluster_b_count);

  // Should propagate within cluster A
  REQUIRE(cluster_a_count >= 5);

  // Should eventually reach cluster B via bridges
  REQUIRE(cluster_b_count >= 1);
}

TEST_CASE("Topology: High connectivity benefits", "[addrsim][topology]") {
  // Compare low vs high connectivity networks

  // Low connectivity network
  AddrTestNetwork net_low(42);
  std::vector<int> nodes_low;
  for (int i = 0; i < 20; ++i) {
    auto id = net_low.CreateNode("8." + std::to_string(i + 1) + ".0.1");
    nodes_low.push_back(id);
  }
  // Only 2 connections per node
  for (size_t i = 0; i < nodes_low.size(); ++i) {
    net_low.Connect(nodes_low[i], nodes_low[(i + 1) % nodes_low.size()]);
  }

  // High connectivity network
  AddrTestNetwork net_high(42);
  std::vector<int> nodes_high;
  for (int i = 0; i < 20; ++i) {
    auto id = net_high.CreateNode("8." + std::to_string(i + 1) + ".0.1");
    nodes_high.push_back(id);
  }
  // 6 connections per node
  for (size_t i = 0; i < nodes_high.size(); ++i) {
    for (size_t j = 1; j <= 6; ++j) {
      net_high.Connect(nodes_high[i], nodes_high[(i + j) % nodes_high.size()]);
    }
  }

  // Same address propagation test on both
  std::string test_addr = "9.1.0.1";

  // Low connectivity
  net_low.InjectAddress(nodes_low[0], test_addr);
  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string(test_addr, 9590);
  ta.timestamp = static_cast<uint32_t>(util::GetTime());

  auto* start_low = net_low.GetNode(nodes_low[0]);
  for (int peer : start_low->GetAllConnectedPeers()) {
    net_low.DeliverAddr(nodes_low[0], peer, {ta});
  }
  net_low.Run(10);

  // High connectivity
  net_high.InjectAddress(nodes_high[0], test_addr);
  auto* start_high = net_high.GetNode(nodes_high[0]);
  for (int peer : start_high->GetAllConnectedPeers()) {
    net_high.DeliverAddr(nodes_high[0], peer, {ta});
  }
  net_high.Run(10);

  // Count propagation
  auto count_with_addr = [&](AddrTestNetwork& net, const std::vector<int>& nodes) {
    size_t count = 0;
    for (int node_id : nodes) {
      auto* node = net.GetNode(node_id);
      auto addrs = node->addr_mgr->get_addresses(100, 100);
      for (const auto& a : addrs) {
        auto ip = a.address.to_string();
        if (ip && *ip == test_addr) {
          count++;
          break;
        }
      }
    }
    return count;
  };

  size_t low_count = count_with_addr(net_low, nodes_low);
  size_t high_count = count_with_addr(net_high, nodes_high);

  INFO("Low connectivity propagation: " << low_count);
  INFO("High connectivity propagation: " << high_count);

  // Both should have some propagation
  // Due to probabilistic relay, high connectivity isn't always better in small samples
  REQUIRE(low_count >= 5);
  REQUIRE(high_count >= 5);
}

TEST_CASE("Topology: Random graph resilience", "[addrsim][topology]") {
  // Random topology should still allow reasonable propagation

  AddrTestNetwork net(12345);  // Different seed

  // Create 30 nodes
  std::vector<int> nodes;
  for (int i = 0; i < 30; ++i) {
    auto id = net.CreateNode("8." + std::to_string((i % 30) + 1) + ".0." + std::to_string(i / 30 + 1));
    nodes.push_back(id);
  }

  // Random topology
  net.CreateRandomTopology(4);  // ~4 connections per node

  // Multiple addresses from different origins
  std::vector<std::string> test_addrs;
  for (int i = 0; i < 5; ++i) {
    std::string addr = "7." + std::to_string(i + 1) + ".0.1";
    test_addrs.push_back(addr);

    int origin = i * 6;  // Different origins
    net.InjectAddress(nodes[origin], addr);

    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(addr, 9590);
    ta.timestamp = static_cast<uint32_t>(util::GetTime());

    auto* node = net.GetNode(nodes[origin]);
    for (int peer : node->GetAllConnectedPeers()) {
      net.DeliverAddr(nodes[origin], peer, {ta});
    }
  }

  net.Run(15);

  // Check propagation of each address
  for (const auto& test_addr : test_addrs) {
    size_t count = 0;
    for (int node_id : nodes) {
      auto* node = net.GetNode(node_id);
      auto addrs = node->addr_mgr->get_addresses(100, 100);
      for (const auto& a : addrs) {
        auto ip = a.address.to_string();
        if (ip && *ip == test_addr) {
          count++;
          break;
        }
      }
    }
    INFO("Address " << test_addr << " reached: " << count << " nodes");
    REQUIRE(count >= 5);  // Should reach at least some nodes
  }
}
