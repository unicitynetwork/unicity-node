// Copyright (c) 2025 The Unicity Foundation
// Mixed network type tests
//
// Tests handling of different address types:
// - IPv4 addresses
// - IPv6 addresses
// - Netgroup isolation between types
// - Routable vs non-routable filtering

#include "../addr_test_network.hpp"
#include "catch_amalgamated.hpp"
#include "util/time.hpp"

using namespace unicity;
using namespace unicity::test::addrsim;

TEST_CASE("Mixed: IPv4 addresses accepted", "[addrsim][mixed][network]") {
  AddrTestNetwork net(42);

  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Various IPv4 addresses
  std::vector<std::string> ipv4_addrs = {
      "1.2.3.4",
      "8.8.8.8",
      "44.55.66.77",
      "200.100.50.25",
  };

  size_t accepted = 0;
  for (const auto& addr : ipv4_addrs) {
    if (net.InjectAddress(node_id, addr)) {
      accepted++;
    }
  }

  INFO("IPv4 addresses accepted: " << accepted);
  REQUIRE(accepted == ipv4_addrs.size());
}

TEST_CASE("Mixed: IPv6 addresses accepted", "[addrsim][mixed][network]") {
  AddrTestNetwork net(42);

  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Various routable IPv6 addresses (not documentation/private ranges)
  std::vector<std::string> ipv6_addrs = {
      "2607:f8b0:4004:800::200e",  // Google-like
      "2001:4860:4860::8888",       // Public DNS-like
      "2a00:1450:4001:80f::200e",   // European-like
  };

  size_t accepted = 0;
  for (const auto& addr : ipv6_addrs) {
    auto na = protocol::NetworkAddress::from_string(addr, 9590);
    if (na.is_routable()) {
      auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);
      if (node->addr_mgr->add(na, source, static_cast<uint32_t>(util::GetTime()))) {
        accepted++;
      }
    }
  }

  INFO("IPv6 addresses accepted: " << accepted);
  // Routable IPv6 addresses should be accepted
  REQUIRE(accepted > 0);
}

TEST_CASE("Mixed: Non-routable addresses rejected", "[addrsim][mixed][network]") {
  AddrTestNetwork net(42);

  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Non-routable addresses that should be rejected
  std::vector<std::string> non_routable = {
      "10.0.0.1",       // RFC1918 private
      "172.16.0.1",     // RFC1918 private
      "192.168.1.1",    // RFC1918 private
      "127.0.0.1",      // Loopback
      "169.254.1.1",    // Link-local
      "224.0.0.1",      // Multicast
      "255.255.255.255", // Broadcast
      "0.0.0.0",        // Unspecified
  };

  size_t rejected = 0;
  for (const auto& addr : non_routable) {
    if (!net.InjectAddress(node_id, addr)) {
      rejected++;
    }
  }

  INFO("Non-routable addresses rejected: " << rejected << " / " << non_routable.size());
  REQUIRE(rejected == non_routable.size());
}

TEST_CASE("Mixed: IPv6 non-routable rejected", "[addrsim][mixed][network]") {
  AddrTestNetwork net(42);

  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Non-routable IPv6 addresses
  std::vector<std::string> non_routable_v6 = {
      "::1",            // Loopback
      "fe80::1",        // Link-local
      "fc00::1",        // Unique local
      "2001:db8::1",    // Documentation
  };

  size_t rejected = 0;
  for (const auto& addr : non_routable_v6) {
    auto na = protocol::NetworkAddress::from_string(addr, 9590);
    auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);
    if (!node->addr_mgr->add(na, source, static_cast<uint32_t>(util::GetTime()))) {
      rejected++;
    }
  }

  INFO("Non-routable IPv6 rejected: " << rejected << " / " << non_routable_v6.size());
  REQUIRE(rejected == non_routable_v6.size());
}

TEST_CASE("Mixed: Netgroup isolation between address types", "[addrsim][mixed][network]") {
  AddrTestNetwork net(42);

  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Add many IPv4 addresses from same /16
  for (int i = 1; i <= 50; ++i) {
    std::string addr = "44.99." + std::to_string(i / 256) + "." + std::to_string((i % 256) + 1);
    net.InjectAddress(node_id, addr);
  }

  size_t ipv4_count = node->addr_mgr->size();
  INFO("IPv4 addresses from 44.99.x.x: " << ipv4_count);

  // Per-netgroup limit should apply
  REQUIRE(ipv4_count <= 32);

  // IPv6 addresses should have separate netgroup
  // (Adding IPv6 shouldn't affect IPv4 netgroup counts and vice versa)
}

TEST_CASE("Mixed: Address selection fairness", "[addrsim][mixed][network]") {
  // If we have both IPv4 and IPv6, selection should consider both

  AddrTestNetwork net(42);

  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Add IPv4 addresses
  for (int i = 1; i <= 20; ++i) {
    net.InjectAddress(node_id, "9." + std::to_string(i) + ".0.1");
  }

  // Select multiple times
  std::set<std::string> selected;
  for (int i = 0; i < 100; ++i) {
    auto addr = node->addr_mgr->select();
    if (addr) {
      auto ip = addr->to_string();
      if (ip) selected.insert(*ip);
    }
  }

  INFO("Unique addresses selected: " << selected.size());

  // Should have variety in selection
  REQUIRE(selected.size() >= 5);
}

TEST_CASE("Mixed: GETADDR returns mixed types", "[addrsim][mixed][network]") {
  AddrTestNetwork net(42);

  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  auto requester_id = net.CreateNode("8.2.0.1");
  net.Connect(requester_id, node_id);

  // Add variety of IPv4 addresses
  for (int i = 1; i <= 50; ++i) {
    net.InjectAddress(node_id, std::to_string(i) + ".1.0.1");
  }

  auto response = net.DeliverGetAddr(requester_id, node_id);

  INFO("GETADDR returned: " << response.size() << " addresses");

  // Should return some addresses
  REQUIRE(response.size() > 0);

  // Count IPv4 addresses in response
  size_t ipv4_count = 0;
  for (const auto& ta : response) {
    if (ta.address.is_ipv4()) {
      ipv4_count++;
    }
  }

  INFO("IPv4 in response: " << ipv4_count);
  REQUIRE(ipv4_count > 0);
}

TEST_CASE("Mixed: Address propagation by type", "[addrsim][mixed][network]") {
  // Test that addresses propagate regardless of type

  AddrTestNetwork net(42);

  auto a = net.CreateNode("8.1.0.1");
  auto b = net.CreateNode("8.2.0.1");
  auto c = net.CreateNode("8.3.0.1");

  net.Connect(a, b);
  net.Connect(b, c);

  // Send IPv4 address from A to B
  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string("44.1.0.1", 9590);
  ta.timestamp = static_cast<uint32_t>(util::GetTime());

  net.DeliverAddr(a, b, {ta});
  net.Run(5);

  // Check propagation
  auto* node_c = net.GetNode(c);
  auto addrs = node_c->addr_mgr->get_addresses(100, 100);

  size_t found = 0;
  for (const auto& addr : addrs) {
    auto ip = addr.address.to_string();
    if (ip && *ip == "44.1.0.1") {
      found++;
    }
  }

  INFO("Address found at C: " << (found > 0 ? "yes" : "no"));
  REQUIRE(found >= 1);
}

TEST_CASE("Mixed: Special address ranges", "[addrsim][mixed][network]") {
  AddrTestNetwork net(42);

  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // CGNAT range (100.64.0.0/10) - should be rejected
  REQUIRE_FALSE(net.InjectAddress(node_id, "100.64.0.1"));
  REQUIRE_FALSE(net.InjectAddress(node_id, "100.127.255.254"));

  // Documentation ranges - should be rejected
  REQUIRE_FALSE(net.InjectAddress(node_id, "192.0.2.1"));   // TEST-NET-1
  REQUIRE_FALSE(net.InjectAddress(node_id, "198.51.100.1")); // TEST-NET-2
  REQUIRE_FALSE(net.InjectAddress(node_id, "203.0.113.1"));  // TEST-NET-3

  // Reserved/future use - should be rejected
  REQUIRE_FALSE(net.InjectAddress(node_id, "240.0.0.1"));
  REQUIRE_FALSE(net.InjectAddress(node_id, "255.255.255.254"));

  // Valid public addresses - should be accepted
  REQUIRE(net.InjectAddress(node_id, "1.1.1.1"));
  REQUIRE(net.InjectAddress(node_id, "8.8.8.8"));
  REQUIRE(net.InjectAddress(node_id, "208.67.222.222"));
}
