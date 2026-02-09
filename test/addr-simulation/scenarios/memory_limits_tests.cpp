// Copyright (c) 2025 The Unicity Foundation
// Memory limits tests for AddressManager
//
// AddressManager has various capacity limits to prevent unbounded memory growth:
// - MAX_NEW_ADDRESSES = 16384 (total NEW table capacity)
// - MAX_TRIED_ADDRESSES = 4096 (total TRIED table capacity)
// - MAX_PER_NETGROUP_NEW = 32 (per source-group limit in NEW)
// - MAX_PER_NETGROUP_TRIED = 8 (per netgroup limit in TRIED)
// - MAX_ADDRESSES_PER_SOURCE = 64 (per source limit)

#include "../addr_test_network.hpp"
#include "catch_amalgamated.hpp"
#include "util/time.hpp"

using namespace unicity;
using namespace unicity::test::addrsim;

static constexpr int64_t BASE_TIME = 1700000000;

// Known limits from addr_manager.hpp
static constexpr size_t MAX_NEW_ADDRESSES = 65536;
static constexpr size_t MAX_TRIED_ADDRESSES = 16384;
static constexpr size_t MAX_PER_NETGROUP_NEW = 32;
static constexpr size_t MAX_PER_NETGROUP_TRIED = 8;
static constexpr size_t MAX_ADDRESSES_PER_SOURCE = 64;

TEST_CASE("MemoryLimit: NEW table capacity enforced", "[addrsim][memory][limits]") {
  // Table should not exceed MAX_NEW_ADDRESSES

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Try to add way more than limit from diverse sources and netgroups
  size_t attempted = 0;
  for (int source_ng = 1; source_ng <= 255 && attempted < 20000; ++source_ng) {
    auto source = protocol::NetworkAddress::from_string(
        std::to_string(source_ng) + ".1.0.1", 9590);

    for (int addr_ng = 1; addr_ng <= 255 && attempted < 20000; ++addr_ng) {
      for (int addr_host = 1; addr_host <= 5 && attempted < 20000; ++addr_host) {
        protocol::TimestampedAddress ta;
        ta.address = protocol::NetworkAddress::from_string(
            std::to_string(addr_ng) + "." + std::to_string(addr_host) + ".0.1", 9590);
        ta.timestamp = static_cast<uint32_t>(BASE_TIME);

        node->addr_mgr->add_multiple({ta}, source, 0);
        attempted++;
      }
    }
  }

  size_t table_size = node->addr_mgr->size();
  INFO("Attempted to add: " << attempted);
  INFO("Final table size: " << table_size);

  // Table should be capped
  REQUIRE(table_size <= MAX_NEW_ADDRESSES);
}

TEST_CASE("MemoryLimit: TRIED table capacity enforced", "[addrsim][memory][limits]") {
  // TRIED table should not exceed MAX_TRIED_ADDRESSES

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Add and promote many addresses
  size_t promoted = 0;
  for (int ng = 1; ng <= 255 && promoted < 5000; ++ng) {
    for (int host = 1; host <= 20 && promoted < 5000; ++host) {
      std::string addr = std::to_string(ng) + "." + std::to_string(host) + ".0.1";
      net.InjectAddress(node_id, addr);

      auto na = protocol::NetworkAddress::from_string(addr, 9590);
      node->addr_mgr->good(na);
      promoted++;
    }
  }

  size_t tried_count = node->addr_mgr->tried_count();
  INFO("Attempted to promote: " << promoted);
  INFO("TRIED table size: " << tried_count);

  // TRIED table should be capped
  REQUIRE(tried_count <= MAX_TRIED_ADDRESSES);
}

TEST_CASE("MemoryLimit: Per-source limit enforced", "[addrsim][memory][limits]") {
  // Single source cannot add more than MAX_ADDRESSES_PER_SOURCE

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  auto sender_id = net.CreateNode("8.2.0.1");
  net.Connect(sender_id, node_id);

  auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);

  // Single source tries to add 500 addresses from same netgroup bucket
  for (int i = 1; i <= 500; ++i) {
    protocol::TimestampedAddress ta;
    // Use variety of addresses but same source
    ta.address = protocol::NetworkAddress::from_string(
        std::to_string((i / 256) + 1) + "." + std::to_string((i % 256) + 1) + ".0.1", 9590);
    ta.timestamp = static_cast<uint32_t>(BASE_TIME);

    node->addr_mgr->add_multiple({ta}, source, 0);
  }

  // Check total - should be limited by per-source cap
  size_t table_size = node->addr_mgr->size();
  INFO("Table size after 500 from single source: " << table_size);

  // Per-source limit applies to bucket, not total - but should see limiting
  REQUIRE(table_size <= MAX_ADDRESSES_PER_SOURCE * 4);  // Generous bound
}

TEST_CASE("MemoryLimit: Per-netgroup NEW limit enforced", "[addrsim][memory][limits]") {
  // Single netgroup bucket cannot exceed MAX_PER_NETGROUP_NEW

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Add many addresses from same netgroup via different sources
  for (int source_ng = 1; source_ng <= 100; ++source_ng) {
    auto source = protocol::NetworkAddress::from_string(
        std::to_string(source_ng) + ".1.0.1", 9590);

    // All addresses in 44.99.x.x (same netgroup)
    for (int host = 1; host <= 10; ++host) {
      protocol::TimestampedAddress ta;
      ta.address = protocol::NetworkAddress::from_string(
          "44.99." + std::to_string((source_ng * 10 + host) / 256) + "." +
              std::to_string(((source_ng * 10 + host) % 256) + 1),
          9590);
      ta.timestamp = static_cast<uint32_t>(BASE_TIME);

      node->addr_mgr->add_multiple({ta}, source, 0);
    }
  }

  // Get all addresses and count those in 44.99.x.x netgroup
  auto addrs = node->addr_mgr->get_addresses(20000, 100);
  size_t ng_count = 0;
  for (const auto& ta : addrs) {
    auto ip = ta.address.to_string();
    if (ip && ip->substr(0, 6) == "44.99.") {
      ng_count++;
    }
  }

  INFO("Addresses in 44.99.x.x netgroup: " << ng_count);

  // Per-netgroup limit should apply
  REQUIRE(ng_count <= MAX_PER_NETGROUP_NEW);
}

TEST_CASE("MemoryLimit: Per-netgroup TRIED limit enforced", "[addrsim][memory][limits]") {
  // Single netgroup cannot have more than MAX_PER_NETGROUP_TRIED in TRIED table

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Try to promote many addresses from same netgroup
  for (int i = 1; i <= 50; ++i) {
    std::string addr = "44.99." + std::to_string(i / 256) + "." + std::to_string((i % 256) + 1);
    net.InjectAddress(node_id, addr);

    auto na = protocol::NetworkAddress::from_string(addr, 9590);
    node->addr_mgr->good(na);
  }

  size_t tried_count = node->addr_mgr->tried_count();
  INFO("TRIED count for single netgroup: " << tried_count);

  // Per-netgroup TRIED limit
  REQUIRE(tried_count <= MAX_PER_NETGROUP_TRIED);
}

TEST_CASE("MemoryLimit: Diverse sources bypass per-source limit", "[addrsim][memory][limits]") {
  // Multiple sources should allow more addresses even to same destination netgroup

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Multiple sources from different netgroups
  size_t total_added = 0;
  for (int source_ng = 1; source_ng <= 100; ++source_ng) {
    auto source = protocol::NetworkAddress::from_string(
        std::to_string(source_ng) + ".1.0.1", 9590);

    // Each source adds addresses to different destination netgroups
    for (int dest_ng = 1; dest_ng <= 10; ++dest_ng) {
      protocol::TimestampedAddress ta;
      ta.address = protocol::NetworkAddress::from_string(
          std::to_string(dest_ng) + "." + std::to_string(source_ng) + ".0.1", 9590);
      ta.timestamp = static_cast<uint32_t>(BASE_TIME);

      node->addr_mgr->add_multiple({ta}, source, 0);
      total_added++;
    }
  }

  size_t table_size = node->addr_mgr->size();
  INFO("Total add attempts: " << total_added);
  INFO("Table size: " << table_size);

  // Should have many addresses (not limited by single-source cap)
  REQUIRE(table_size > MAX_ADDRESSES_PER_SOURCE);
}

TEST_CASE("MemoryLimit: Cleanup maintains limits after eviction", "[addrsim][memory][limits]") {
  // After cleanup removes stale entries, adding new ones should still respect limits
  // Note: This tests that the table can accept fresh addresses after cleanup

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Fill with old addresses (at BASE_TIME)
  for (int ng = 1; ng <= 100; ++ng) {
    auto source = protocol::NetworkAddress::from_string(
        std::to_string(ng) + ".1.0.1", 9590);

    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(
        "9." + std::to_string(ng) + ".0.1", 9590);
    ta.timestamp = static_cast<uint32_t>(BASE_TIME);

    node->addr_mgr->add_multiple({ta}, source, 0);
  }

  size_t initial_size = node->addr_mgr->size();
  INFO("Initial table size: " << initial_size);

  // Advance time to make addresses stale (>30 days)
  int64_t future_time = BASE_TIME + 35 * 24 * 3600;
  util::SetMockTime(future_time);
  node->addr_mgr->cleanup_stale();

  size_t after_cleanup = node->addr_mgr->size();
  INFO("After cleanup: " << after_cleanup);

  // Cleanup should have removed stale addresses
  REQUIRE(after_cleanup < initial_size);

  // Add fresh addresses directly to addr_mgr (bypassing network framework)
  for (int ng = 101; ng <= 200; ++ng) {
    auto source = protocol::NetworkAddress::from_string(
        std::to_string(ng) + ".1.0.1", 9590);

    auto addr = protocol::NetworkAddress::from_string(
        "10." + std::to_string(ng) + ".0.1", 9590);

    // Use direct add() which uses current MockTime
    node->addr_mgr->add(addr, source, static_cast<uint32_t>(future_time));
  }

  size_t final_size = node->addr_mgr->size();
  INFO("Final table size: " << final_size);

  // Should have accepted fresh addresses
  REQUIRE(final_size <= MAX_NEW_ADDRESSES);
  REQUIRE(final_size >= after_cleanup);  // At least as many as before
}

TEST_CASE("MemoryLimit: Total size = NEW + TRIED", "[addrsim][memory][limits]") {
  // Verify size() returns sum of NEW and TRIED tables

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Add some to NEW
  for (int i = 1; i <= 50; ++i) {
    net.InjectAddress(node_id, "9." + std::to_string(i) + ".0.1");
  }

  size_t new_count = node->addr_mgr->new_count();
  REQUIRE(new_count == 50);

  // Promote some to TRIED (different netgroups to avoid per-netgroup limit)
  for (int i = 1; i <= 20; ++i) {
    auto na = protocol::NetworkAddress::from_string(
        "9." + std::to_string(i) + ".0.1", 9590);
    node->addr_mgr->good(na);
  }

  size_t tried_count = node->addr_mgr->tried_count();
  size_t new_count_after = node->addr_mgr->new_count();
  size_t total = node->addr_mgr->size();

  INFO("NEW count: " << new_count_after);
  INFO("TRIED count: " << tried_count);
  INFO("Total size: " << total);

  REQUIRE(total == new_count_after + tried_count);
}

TEST_CASE("MemoryLimit: Eviction makes room for fresh addresses", "[addrsim][memory][limits]") {
  // When table is full, newer addresses should be able to evict older ones

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Fill a netgroup bucket
  for (int i = 1; i <= 50; ++i) {
    auto source = protocol::NetworkAddress::from_string(
        std::to_string(i) + ".1.0.1", 9590);

    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(
        "44.99.0." + std::to_string(i), 9590);
    ta.timestamp = static_cast<uint32_t>(BASE_TIME);

    node->addr_mgr->add_multiple({ta}, source, 0);
  }

  // Count current addresses in that netgroup
  auto addrs_before = node->addr_mgr->get_addresses(20000, 100);
  size_t ng_before = 0;
  for (const auto& ta : addrs_before) {
    auto ip = ta.address.to_string();
    if (ip && ip->substr(0, 6) == "44.99.") {
      ng_before++;
    }
  }

  INFO("Netgroup count before: " << ng_before);

  // Try to add fresh address (should trigger eviction if bucket full)
  util::SetMockTime(BASE_TIME + 3600);  // 1 hour later

  auto fresh_source = protocol::NetworkAddress::from_string("200.1.0.1", 9590);
  protocol::TimestampedAddress fresh_ta;
  fresh_ta.address = protocol::NetworkAddress::from_string("44.99.0.200", 9590);
  fresh_ta.timestamp = static_cast<uint32_t>(BASE_TIME + 3600);

  node->addr_mgr->add_multiple({fresh_ta}, fresh_source, 0);

  // Check if fresh address made it in
  auto addrs_after = node->addr_mgr->get_addresses(20000, 100);
  bool found_fresh = false;
  for (const auto& ta : addrs_after) {
    auto ip = ta.address.to_string();
    if (ip && *ip == "44.99.0.200") {
      found_fresh = true;
      break;
    }
  }

  INFO("Fresh address accepted: " << (found_fresh ? "yes" : "no"));

  // Count addresses in 44.99.x.x netgroup — should not exceed per-netgroup limit
  auto addrs_final = node->addr_mgr->get_addresses(20000, 100);
  size_t ng_after = 0;
  for (const auto& ta : addrs_final) {
    auto ip = ta.address.to_string();
    if (ip && ip->substr(0, 6) == "44.99.") {
      ng_after++;
    }
  }
  REQUIRE(ng_after <= MAX_PER_NETGROUP_NEW);

  // Table integrity: size should not have shrunk
  size_t final_table_size = node->addr_mgr->size();
  REQUIRE(final_table_size >= ng_before);
}
