// Copyright (c) 2025 The Unicity Foundation
// Basic address propagation tests

#include "../addr_test_network.hpp"
#include "catch_amalgamated.hpp"

using namespace unicity;
using namespace unicity::test::addrsim;

TEST_CASE("AddrSim: Basic node creation", "[addrsim][smoke]") {
  AddrTestNetwork net(42);  // Deterministic seed

  auto id1 = net.CreateNode("8.1.0.1");
  auto id2 = net.CreateNode("8.2.0.1");

  REQUIRE(net.NodeCount() == 2);
  REQUIRE(net.GetNode(id1)->ip_address == "8.1.0.1");
  REQUIRE(net.GetNode(id1)->netgroup == "8.1");
  REQUIRE(net.GetNode(id2)->netgroup == "8.2");
}

TEST_CASE("AddrSim: Connection management", "[addrsim][smoke]") {
  AddrTestNetwork net(42);

  auto a = net.CreateNode("8.1.0.1");
  auto b = net.CreateNode("8.2.0.1");
  auto c = net.CreateNode("8.3.0.1");

  REQUIRE(net.Connect(a, b));
  REQUIRE(net.Connect(a, c));

  auto* node_a = net.GetNode(a);
  auto* node_b = net.GetNode(b);

  REQUIRE(node_a->outbound_peers.count(b) == 1);
  REQUIRE(node_a->outbound_peers.count(c) == 1);
  REQUIRE(node_b->inbound_peers.count(a) == 1);

  // Can't connect twice
  REQUIRE_FALSE(net.Connect(a, b));

  // Disconnect
  net.Disconnect(a, b);
  REQUIRE_FALSE(node_a->IsConnectedTo(b));
  REQUIRE_FALSE(node_b->IsConnectedTo(a));
}

TEST_CASE("AddrSim: Address injection and retrieval", "[addrsim][smoke]") {
  AddrTestNetwork net(42);

  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Inject some addresses
  REQUIRE(net.InjectAddress(node_id, "9.1.0.1"));
  REQUIRE(net.InjectAddress(node_id, "9.2.0.1"));
  REQUIRE(net.InjectAddress(node_id, "9.3.0.1"));

  REQUIRE(node->addr_mgr->size() == 3);
  REQUIRE(node->addr_mgr->new_count() == 3);
  REQUIRE(node->addr_mgr->tried_count() == 0);
}

TEST_CASE("AddrSim: Simple propagation - 3 nodes in chain", "[addrsim][propagation]") {
  AddrTestNetwork net(42);

  // Create chain: A -> B -> C
  auto a = net.CreateNode("8.1.0.1");
  auto b = net.CreateNode("8.2.0.1");
  auto c = net.CreateNode("8.3.0.1");

  net.Connect(a, b);
  net.Connect(b, c);

  // Inject address at A
  std::string test_addr = "44.0.0.1";
  net.InjectAddress(a, test_addr);

  // Create ADDR message
  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string(test_addr, 9590);
  ta.timestamp = static_cast<uint32_t>(net.GetTime());

  // A sends to B
  net.DeliverAddr(a, b, {ta});

  // B should have it now
  auto* node_b = net.GetNode(b);
  REQUIRE(node_b->addr_mgr->size() >= 1);

  // Process tick (B relays to C)
  net.Tick();

  // C should have it now
  auto* node_c = net.GetNode(c);
  REQUIRE(node_c->addr_mgr->size() >= 1);

  // Check metrics
  auto metrics = net.CollectMetrics(test_addr);
  REQUIRE(metrics.nodes_with_address == 3);  // A (injected), B, C
  REQUIRE(metrics.propagation_pct == 100.0);
}

TEST_CASE("AddrSim: Propagation in random topology - 50 nodes", "[addrsim][propagation]") {
  AddrTestNetwork net(42);

  // Create 50 nodes in 10 different netgroups
  for (int ng = 0; ng < 10; ++ng) {
    std::string prefix = "8." + std::to_string(ng);
    net.CreateNodesInNetgroup(5, prefix);
  }
  REQUIRE(net.NodeCount() == 50);

  // Create random topology with ~4 connections per node
  net.CreateRandomTopology(4);

  // Inject address at node 0
  std::string test_addr = "44.99.99.1";
  net.InjectAddress(0, test_addr);

  // Create and send ADDR from node 0 to its peers
  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string(test_addr, 9590);
  ta.timestamp = static_cast<uint32_t>(net.GetTime());

  auto* node0 = net.GetNode(0);
  for (int peer_id : node0->GetAllConnectedPeers()) {
    net.DeliverAddr(0, peer_id, {ta});
  }

  // Run simulation for 10 ticks (enough for propagation)
  net.Run(10);

  // Check propagation
  auto metrics = net.CollectMetrics(test_addr);
  INFO("Nodes with address: " << metrics.nodes_with_address << " / " << net.NodeCount());
  INFO("Propagation: " << metrics.propagation_pct << "%");

  // Should reach most of the network (lower threshold due to realistic relay dedup)
  REQUIRE(metrics.propagation_pct >= 60.0);
}

TEST_CASE("AddrSim: GETADDR response caching (once per connection)", "[addrsim][getaddr]") {
  AddrTestNetwork net(42);

  auto a = net.CreateNode("8.1.0.1");
  auto b = net.CreateNode("8.2.0.1");

  net.Connect(a, b);

  // Populate B's AddrMan
  for (int i = 0; i < 100; ++i) {
    net.InjectAddress(b, "9.0." + std::to_string(i / 256) + "." + std::to_string((i % 256) + 1));
  }

  // First GETADDR should return addresses
  auto response1 = net.DeliverGetAddr(a, b);
  REQUIRE(response1.size() > 0);

  // Second GETADDR from same connection should return empty (once-per-connection)
  auto response2 = net.DeliverGetAddr(a, b);
  REQUIRE(response2.empty());

  // Stats
  auto* node_b = net.GetNode(b);
  REQUIRE(node_b->getaddr_requests == 1);  // Only first counted
}

TEST_CASE("AddrSim: Large message not relayed", "[addrsim][relay]") {
  AddrTestNetwork net(42);

  auto a = net.CreateNode("8.1.0.1");
  auto b = net.CreateNode("8.2.0.1");
  auto c = net.CreateNode("8.3.0.1");

  net.Connect(a, b);
  net.Connect(b, c);

  // Create large ADDR message (> 10 addresses)
  std::vector<protocol::TimestampedAddress> large_addrs;
  for (int i = 0; i < 50; ++i) {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(
        "44.0." + std::to_string(i / 256) + "." + std::to_string((i % 256) + 1), 9590);
    ta.timestamp = static_cast<uint32_t>(net.GetTime());
    large_addrs.push_back(ta);
  }

  // A sends large ADDR to B
  net.DeliverAddr(a, b, large_addrs);

  // B should NOT relay (message too large)
  auto* node_b = net.GetNode(b);
  REQUIRE(node_b->pending_relays.empty());

  // Process tick
  net.Tick();

  // C should NOT have received anything
  auto* node_c = net.GetNode(c);
  REQUIRE(node_c->addrs_received == 0);
}

TEST_CASE("AddrSim: Stale address not relayed", "[addrsim][relay]") {
  AddrTestNetwork net(42);

  auto a = net.CreateNode("8.1.0.1");
  auto b = net.CreateNode("8.2.0.1");
  auto c = net.CreateNode("8.3.0.1");

  net.Connect(a, b);
  net.Connect(b, c);

  // Create ADDR with old timestamp (> 10 min ago)
  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string("44.0.0.1", 9590);
  ta.timestamp = static_cast<uint32_t>(net.GetTime() - 700);  // 11+ minutes old

  // A sends to B
  net.DeliverAddr(a, b, {ta});

  // B should accept but NOT relay (too old)
  auto* node_b = net.GetNode(b);
  REQUIRE(node_b->addr_mgr->size() >= 1);  // Accepted
  REQUIRE(node_b->pending_relays.empty()); // Not relayed

  net.Tick();

  // C should not have it
  auto* node_c = net.GetNode(c);
  REQUIRE(node_c->addrs_received == 0);
}

TEST_CASE("AddrSim: No echo (don't relay back to sender)", "[addrsim][relay]") {
  AddrTestNetwork net(42);

  // Create triangle: A <-> B <-> C, but B only connected to A and C
  auto a = net.CreateNode("8.1.0.1");
  auto b = net.CreateNode("8.2.0.1");
  auto c = net.CreateNode("8.3.0.1");

  net.Connect(a, b);
  net.Connect(b, c);
  // A and C not directly connected

  // Create fresh ADDR
  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string("44.0.0.1", 9590);
  ta.timestamp = static_cast<uint32_t>(net.GetTime());

  // A sends to B
  net.DeliverAddr(a, b, {ta});

  // B should relay to C but NOT back to A
  auto* node_b = net.GetNode(b);
  REQUIRE(node_b->pending_relays.size() == 1);
  REQUIRE(node_b->pending_relays[0].target_id == c);  // Relayed to C, not A
}

TEST_CASE("AddrSim: 100 node network stress test", "[addrsim][stress]") {
  AddrTestNetwork net(12345);

  // Create 100 nodes across 20 netgroups
  for (int ng = 0; ng < 20; ++ng) {
    std::string prefix = "8." + std::to_string(ng);
    net.CreateNodesInNetgroup(5, prefix);
  }
  REQUIRE(net.NodeCount() == 100);

  // Random topology with 8 connections per node
  net.CreateRandomTopology(8);

  // Inject 10 different addresses at random nodes
  std::vector<std::string> test_addrs;
  for (int i = 0; i < 10; ++i) {
    std::string addr = "44.99." + std::to_string(i) + ".1";
    test_addrs.push_back(addr);
    net.InjectAddress(i * 10, addr);  // Inject at nodes 0, 10, 20, ...

    // Send to peers
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(addr, 9590);
    ta.timestamp = static_cast<uint32_t>(net.GetTime());

    auto* node = net.GetNode(i * 10);
    for (int peer_id : node->GetAllConnectedPeers()) {
      net.DeliverAddr(i * 10, peer_id, {ta});
    }
  }

  // Run simulation
  net.Run(20);

  // Check propagation of all addresses
  for (const auto& addr : test_addrs) {
    auto metrics = net.CollectMetrics(addr);
    INFO("Address " << addr << ": " << metrics.propagation_pct << "% coverage");
    REQUIRE(metrics.propagation_pct >= 60.0);  // Lower threshold due to realistic relay dedup
  }

  // Overall stats
  auto metrics = net.CollectMetrics();
  INFO("Avg TRIED size: " << metrics.avg_tried_size);
  INFO("Avg NEW size: " << metrics.avg_new_size);
  INFO("Total addrs received: " << metrics.total_addrs_received);
  INFO("Total addrs relayed: " << metrics.total_addrs_relayed);
}
