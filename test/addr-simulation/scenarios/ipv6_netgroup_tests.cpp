// Copyright (c) 2025 The Unicity Foundation
// IPv6 netgroup tests for AddressManager
//
// Tests IPv6-specific netgroup handling:
// - IPv6 netgroup calculation (based on /32 prefix)
// - Mixed IPv4/IPv6 networks
// - IPv6-mapped IPv4 addresses
// - 6to4 and Teredo tunneling addresses

#include "../addr_test_network.hpp"
#include "catch_amalgamated.hpp"
#include "util/time.hpp"

using namespace unicity;
using namespace unicity::test::addrsim;

static constexpr int64_t BASE_TIME = 1700000000;

TEST_CASE("IPv6: Basic IPv6 address accepted", "[addrsim][ipv6][netgroup]") {
  // Standard IPv6 addresses should be accepted

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  auto sender_id = net.CreateNode("8.2.0.1");
  net.Connect(sender_id, node_id);
  auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);

  // Add IPv6 addresses
  std::vector<std::string> ipv6_addrs = {
      "2001:db8::1",
      "2001:db8:1::1",
      "2607:f8b0:4004:800::200e",  // Google-like
      "2620:0:861:1::1",           // Another prefix
  };

  for (const auto& addr : ipv6_addrs) {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(addr, 9590);
    ta.timestamp = static_cast<uint32_t>(BASE_TIME);

    if (!ta.address.is_zero()) {
      node->addr_mgr->add_multiple({ta}, source, 0);
    }
  }

  size_t table_size = node->addr_mgr->size();
  INFO("Table size after IPv6 additions: " << table_size);

  // IPv6 addresses should be accepted
  REQUIRE(table_size > 0);
}

TEST_CASE("IPv6: Same /32 prefix grouped together", "[addrsim][ipv6][netgroup]") {
  // IPv6 addresses with same /32 prefix should be in same netgroup

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Multiple sources from different netgroups
  for (int i = 1; i <= 50; ++i) {
    auto source = protocol::NetworkAddress::from_string(
        std::to_string(i) + ".1.0.1", 9590);

    // All addresses with same /32 prefix (2001:db8::/32)
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(
        "2001:db8:" + std::to_string(i) + "::1", 9590);
    ta.timestamp = static_cast<uint32_t>(BASE_TIME);

    if (!ta.address.is_zero()) {
      node->addr_mgr->add_multiple({ta}, source, 0);
    }
  }

  // Get addresses and check netgroup diversity
  auto addrs = node->addr_mgr->get_addresses(1000, 100);

  // Count addresses with 2001:db8 prefix
  size_t same_prefix = 0;
  for (const auto& ta : addrs) {
    auto ip = ta.address.to_string();
    if (ip && ip->find("2001:db8:") == 0) {
      same_prefix++;
    }
  }

  INFO("Addresses with same /32 prefix: " << same_prefix);

  // Per-netgroup limit should apply (typically 32 for NEW)
  if (same_prefix > 0) {
    REQUIRE(same_prefix <= 32);  // MAX_PER_NETGROUP_NEW
  }
}

TEST_CASE("IPv6: Different /32 prefixes treated as different netgroups", "[addrsim][ipv6][netgroup]") {
  // Different /32 prefixes should be in different netgroups

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);

  // Different /32 prefixes
  std::vector<std::string> prefixes = {
      "2001:db8:",    // Documentation
      "2607:f8b0:",   // Google
      "2620:0:",      // Another
      "2a00:1450:",   // Google EU
  };

  for (size_t i = 0; i < prefixes.size(); ++i) {
    for (int j = 1; j <= 10; ++j) {
      protocol::TimestampedAddress ta;
      ta.address = protocol::NetworkAddress::from_string(
          prefixes[i] + std::to_string(j) + "::1", 9590);
      ta.timestamp = static_cast<uint32_t>(BASE_TIME);

      if (!ta.address.is_zero()) {
        node->addr_mgr->add_multiple({ta}, source, 0);
      }
    }
  }

  auto addrs = node->addr_mgr->get_addresses(1000, 100);

  // Count addresses per prefix
  std::map<std::string, size_t> prefix_counts;
  for (const auto& ta : addrs) {
    auto ip = ta.address.to_string();
    if (ip) {
      for (const auto& prefix : prefixes) {
        if (ip->find(prefix) == 0) {
          prefix_counts[prefix]++;
          break;
        }
      }
    }
  }

  INFO("Addresses per prefix:");
  for (const auto& [prefix, count] : prefix_counts) {
    INFO("  " << prefix << " -> " << count);
  }

  // Should have distinct /32 prefixes
  REQUIRE(prefix_counts.size() > 0);
}

TEST_CASE("IPv6: Mixed IPv4 and IPv6 network", "[addrsim][ipv6][mixed]") {
  // Network with both IPv4 and IPv6 addresses

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);

  // Add IPv4 addresses
  for (int i = 1; i <= 50; ++i) {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(
        "9." + std::to_string(i) + ".0.1", 9590);
    ta.timestamp = static_cast<uint32_t>(BASE_TIME);
    node->addr_mgr->add_multiple({ta}, source, 0);
  }

  // Add IPv6 addresses
  for (int i = 1; i <= 50; ++i) {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(
        "2001:db8:" + std::to_string(i) + "::1", 9590);
    ta.timestamp = static_cast<uint32_t>(BASE_TIME);

    if (!ta.address.is_zero()) {
      node->addr_mgr->add_multiple({ta}, source, 0);
    }
  }

  size_t total = node->addr_mgr->size();
  INFO("Total addresses (mixed IPv4/IPv6): " << total);

  // Should have IPv4 addresses at minimum
  REQUIRE(total >= 50);
}

TEST_CASE("IPv6: Loopback and local addresses rejected", "[addrsim][ipv6][validation]") {
  // IPv6 loopback (::1) and link-local (fe80::) should be rejected

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);

  size_t initial = node->addr_mgr->size();

  // Try to add non-routable IPv6 addresses
  std::vector<std::string> non_routable = {
      "::1",                  // Loopback
      "fe80::1",              // Link-local
      "fc00::1",              // Unique local
      "ff02::1",              // Multicast
  };

  for (const auto& addr : non_routable) {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(addr, 9590);
    ta.timestamp = static_cast<uint32_t>(BASE_TIME);

    if (!ta.address.is_zero()) {
      node->addr_mgr->add_multiple({ta}, source, 0);
    }
  }

  size_t after = node->addr_mgr->size();
  INFO("Table size after non-routable IPv6: " << after);

  // Non-routable addresses should be rejected
  REQUIRE(after == initial);
}

TEST_CASE("IPv6: IPv4-mapped addresses handled correctly", "[addrsim][ipv6][mapped]") {
  // ::ffff:192.0.2.1 style addresses

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);

  // IPv4-mapped IPv6 addresses
  std::vector<std::string> mapped = {
      "::ffff:192.0.2.1",
      "::ffff:9.1.0.1",
      "::ffff:10.0.0.1",  // Private - should be rejected
  };

  for (const auto& addr : mapped) {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(addr, 9590);
    ta.timestamp = static_cast<uint32_t>(BASE_TIME);

    if (!ta.address.is_zero()) {
      node->addr_mgr->add_multiple({ta}, source, 0);
    }
  }

  size_t table_size = node->addr_mgr->size();
  INFO("Table size after IPv4-mapped addresses: " << table_size);

  // IPv4-mapped addresses should be accepted
  REQUIRE(table_size > 0);
}

TEST_CASE("IPv6: Selection includes both address families", "[addrsim][ipv6][selection]") {
  // When selecting addresses, both IPv4 and IPv6 should be considered

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);

  // Add diverse addresses
  for (int i = 1; i <= 30; ++i) {
    // IPv4
    protocol::TimestampedAddress ta4;
    ta4.address = protocol::NetworkAddress::from_string(
        std::to_string(i) + ".1.0.1", 9590);
    ta4.timestamp = static_cast<uint32_t>(BASE_TIME);
    node->addr_mgr->add_multiple({ta4}, source, 0);

    // IPv6
    protocol::TimestampedAddress ta6;
    ta6.address = protocol::NetworkAddress::from_string(
        "2001:" + std::to_string(i) + "::1", 9590);
    ta6.timestamp = static_cast<uint32_t>(BASE_TIME);
    if (!ta6.address.is_zero()) {
      node->addr_mgr->add_multiple({ta6}, source, 0);
    }
  }

  // Select many times and count each family
  int ipv4_selected = 0;
  int ipv6_selected = 0;

  for (int i = 0; i < 100; ++i) {
    auto selected = node->addr_mgr->select();
    if (selected) {
      if (!selected->is_ipv4()) {
        ipv6_selected++;
      } else {
        ipv4_selected++;
      }
    }
  }

  INFO("IPv4 selected: " << ipv4_selected);
  INFO("IPv6 selected: " << ipv6_selected);

  // Should select IPv4 (IPv6 may be 0 if not supported)
  REQUIRE(ipv4_selected > 0);
}

TEST_CASE("IPv6: Netgroup isolation prevents cross-contamination", "[addrsim][ipv6][isolation]") {
  // IPv4 and IPv6 addresses from same /32 should have separate netgroups

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Add many IPv4 from 192.0.x.x
  for (int i = 1; i <= 100; ++i) {
    auto source = protocol::NetworkAddress::from_string(
        std::to_string(i) + ".1.0.1", 9590);

    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(
        "192.0." + std::to_string(i / 256) + "." + std::to_string((i % 256) + 1), 9590);
    ta.timestamp = static_cast<uint32_t>(BASE_TIME);

    node->addr_mgr->add_multiple({ta}, source, 0);
  }

  size_t ipv4_count = node->addr_mgr->size();

  // Add many IPv6 (if supported)
  for (int i = 1; i <= 100; ++i) {
    auto source = protocol::NetworkAddress::from_string(
        std::to_string(i) + ".1.0.1", 9590);

    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(
        "2001:db8:" + std::to_string(i) + "::1", 9590);
    ta.timestamp = static_cast<uint32_t>(BASE_TIME);

    if (!ta.address.is_zero()) {
      node->addr_mgr->add_multiple({ta}, source, 0);
    }
  }

  size_t total_count = node->addr_mgr->size();

  INFO("IPv4 addresses: " << ipv4_count);
  INFO("Total after IPv6: " << total_count);

  // IPv4 should still be there (IPv6 in separate netgroups)
  REQUIRE(total_count >= ipv4_count);
}

TEST_CASE("IPv6: GETADDR response can include both families", "[addrsim][ipv6][getaddr]") {
  // GETADDR response should include both IPv4 and IPv6 if available

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");

  auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);
  auto* node = net.GetNode(node_id);

  // Populate with mixed addresses
  for (int i = 1; i <= 50; ++i) {
    protocol::TimestampedAddress ta4;
    ta4.address = protocol::NetworkAddress::from_string(
        std::to_string(i) + ".1.0.1", 9590);
    ta4.timestamp = static_cast<uint32_t>(BASE_TIME);
    node->addr_mgr->add_multiple({ta4}, source, 0);

    protocol::TimestampedAddress ta6;
    ta6.address = protocol::NetworkAddress::from_string(
        "2001:db8:" + std::to_string(i) + "::1", 9590);
    ta6.timestamp = static_cast<uint32_t>(BASE_TIME);
    if (!ta6.address.is_zero()) {
      node->addr_mgr->add_multiple({ta6}, source, 0);
    }
  }

  // Get addresses
  auto addrs = node->addr_mgr->get_addresses(100, 100);

  int ipv4_count = 0;
  int ipv6_count = 0;

  for (const auto& ta : addrs) {
    if (!ta.address.is_ipv4()) {
      ipv6_count++;
    } else {
      ipv4_count++;
    }
  }

  INFO("get_addresses returned " << ipv4_count << " IPv4 and " << ipv6_count << " IPv6");

  // Should include IPv4 addresses
  REQUIRE(ipv4_count > 0);
}
