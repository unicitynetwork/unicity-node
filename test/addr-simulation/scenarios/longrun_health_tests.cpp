// Copyright (c) 2025 The Unicity Foundation
// Long-running health tests
//
// Simulates extended operation periods to verify:
// - Address table health over time
// - Stale address cleanup
// - Diversity maintenance
// - No memory leaks or unbounded growth
//
// Uses MockTime to simulate time progression without waiting.

#include "../addr_test_network.hpp"
#include "catch_amalgamated.hpp"
#include "util/time.hpp"

using namespace unicity;
using namespace unicity::test::addrsim;

// Base time for mock time tests (arbitrary but stable)
static constexpr int64_t BASE_TIME = 1700000000;

TEST_CASE("LongRun: Stale address cleanup", "[addrsim][longrun][health]") {
  // Addresses older than 30 days should be cleaned up from NEW table
  // Use MockTime to control time precisely

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);

  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Inject fresh addresses (timestamp = BASE_TIME)
  for (int i = 1; i <= 5; ++i) {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(
        "9." + std::to_string(i) + ".0.1", 9590);
    ta.timestamp = static_cast<uint32_t>(BASE_TIME);

    auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);
    node->addr_mgr->add_multiple({ta}, source, 0);
  }

  size_t initial_count = node->addr_mgr->size();
  INFO("Initial addresses: " << initial_count);
  REQUIRE(initial_count == 5);

  // Advance mock time by 35 days (addresses become stale)
  util::SetMockTime(BASE_TIME + 35 * 24 * 3600);

  // Run cleanup - stale addresses should be removed
  node->addr_mgr->cleanup_stale();

  size_t after_cleanup = node->addr_mgr->size();
  INFO("After 35-day advance and cleanup: " << after_cleanup);

  // All addresses are now >30 days old and should be removed
  REQUIRE(after_cleanup < initial_count);
}

TEST_CASE("LongRun: Table size stability", "[addrsim][longrun][health]") {
  // With continuous churn, table size should remain stable

  AddrTestNetwork net(42);

  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  auto sender_id = net.CreateNode("8.2.0.1");
  net.Connect(sender_id, node_id);

  // Simulate weeks of address churn
  std::vector<size_t> size_history;
  uint32_t sim_time = static_cast<uint32_t>(util::GetTime());

  for (int week = 0; week < 4; ++week) {
    // Each week: receive new addresses, some become stale
    for (int day = 0; day < 7; ++day) {
      // Add 10 addresses per day from various netgroups
      for (int i = 0; i < 10; ++i) {
        int ng = (week * 70 + day * 10 + i) % 250 + 1;
        std::string addr = std::to_string(ng) + ".1.0.1";

        protocol::TimestampedAddress ta;
        ta.address = protocol::NetworkAddress::from_string(addr, 9590);
        ta.timestamp = sim_time;

        net.DeliverAddr(sender_id, node_id, {ta});
      }

      // Advance time 1 day
      sim_time += 24 * 3600;
    }

    // Weekly cleanup
    node->addr_mgr->cleanup_stale();

    size_history.push_back(node->addr_mgr->size());
    INFO("Week " << week << " table size: " << size_history.back());
  }

  // Size should be relatively stable (not growing unbounded)
  // Allow for some variance, but shouldn't explode
  size_t max_size = *std::max_element(size_history.begin(), size_history.end());
  size_t min_size = *std::min_element(size_history.begin(), size_history.end());

  INFO("Max size: " << max_size);
  INFO("Min size: " << min_size);

  // Table should stay within reasonable bounds
  REQUIRE(max_size <= 1000);  // Shouldn't grow huge
}

TEST_CASE("LongRun: Diversity maintenance", "[addrsim][longrun][health]") {
  // Over time, netgroup diversity should be maintained

  AddrTestNetwork net(42);

  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  auto sender_id = net.CreateNode("8.2.0.1");
  net.Connect(sender_id, node_id);

  // Initial diverse population
  for (int ng = 1; ng <= 50; ++ng) {
    std::string addr = "9." + std::to_string(ng) + ".0.1";
    net.InjectAddress(node_id, addr);
  }

  // Attacker tries to dominate with single netgroup over time
  uint32_t sim_time = static_cast<uint32_t>(util::GetTime());

  for (int day = 0; day < 14; ++day) {
    // Attacker sends 50 addresses per day from 44.99.x.x
    for (int i = 0; i < 50; ++i) {
      std::string addr = "44.99." + std::to_string((day * 50 + i) / 256) + "." +
                         std::to_string(((day * 50 + i) % 256) + 1);

      protocol::TimestampedAddress ta;
      ta.address = protocol::NetworkAddress::from_string(addr, 9590);
      ta.timestamp = sim_time;

      net.DeliverAddr(sender_id, node_id, {ta});
    }

    sim_time += 24 * 3600;
  }

  // Count netgroups
  std::set<std::string> netgroups;
  auto addrs = node->addr_mgr->get_addresses(10000, 100);

  for (const auto& ta : addrs) {
    std::string ng = ta.address.get_netgroup();
    if (!ng.empty()) netgroups.insert(ng);
  }

  INFO("Distinct netgroups in table: " << netgroups.size());

  // Should maintain diversity (not dominated by single netgroup)
  REQUIRE(netgroups.size() >= 10);
}

TEST_CASE("LongRun: TRIED table retention", "[addrsim][longrun][health]") {
  // TRIED addresses should be retained even if old
  // (unlike NEW which expires)

  AddrTestNetwork net(42);

  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Add addresses and mark good (moves to TRIED)
  for (int i = 1; i <= 10; ++i) {
    std::string addr = "9." + std::to_string(i) + ".0.1";
    net.InjectAddress(node_id, addr);
    auto na = protocol::NetworkAddress::from_string(addr, 9590);
    node->addr_mgr->good(na);
  }

  size_t tried_initial = node->addr_mgr->tried_count();
  INFO("Initial TRIED count: " << tried_initial);

  // Run cleanup (should NOT remove TRIED addresses)
  node->addr_mgr->cleanup_stale();

  size_t tried_after = node->addr_mgr->tried_count();
  INFO("TRIED count after cleanup: " << tried_after);

  // TRIED addresses should persist
  REQUIRE(tried_after == tried_initial);
}

TEST_CASE("LongRun: Address freshness propagation", "[addrsim][longrun][health]") {
  // When we see an address again with newer timestamp, update it

  AddrTestNetwork net(42);

  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  auto sender_id = net.CreateNode("8.2.0.1");
  net.Connect(sender_id, node_id);

  uint32_t base_time = static_cast<uint32_t>(util::GetTime());
  std::string test_addr = "9.1.0.1";

  // First: inject with older timestamp
  {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(test_addr, 9590);
    ta.timestamp = base_time - (10 * 24 * 3600);  // 10 days ago
    net.DeliverAddr(sender_id, node_id, {ta});
  }

  // Second: send same address with fresh timestamp
  {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(test_addr, 9590);
    ta.timestamp = base_time;  // Now
    net.DeliverAddr(sender_id, node_id, {ta});
  }

  // Check timestamp was updated
  auto addrs = node->addr_mgr->get_addresses(100, 100);
  for (const auto& ta : addrs) {
    auto ip = ta.address.to_string();
    if (ip && *ip == test_addr) {
      uint32_t age = base_time - ta.timestamp;
      INFO("Address age: " << age << " seconds");
      REQUIRE(age < 3600);  // Should be fresh, not 10 days old
    }
  }
}

TEST_CASE("LongRun: Periodic cleanup effectiveness", "[addrsim][longrun][health]") {
  // Simulate 60 days with periodic cleanup using MockTime

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);

  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  auto sender_id = net.CreateNode("8.2.0.1");
  net.Connect(sender_id, node_id);

  int64_t sim_time = BASE_TIME;

  // Simulate 60 days with daily address additions and cleanup
  size_t total_added = 0;
  for (int day = 0; day < 60; ++day) {
    util::SetMockTime(sim_time);

    // Add 5 addresses per day from various netgroups
    for (int i = 0; i < 5; ++i) {
      int ng = (day * 5 + i) % 200 + 1;
      std::string addr = std::to_string(ng) + ".1.0.1";

      protocol::TimestampedAddress ta;
      ta.address = protocol::NetworkAddress::from_string(addr, 9590);
      ta.timestamp = static_cast<uint32_t>(sim_time);

      net.DeliverAddr(sender_id, node_id, {ta});
      total_added++;
    }

    // Advance 1 day
    sim_time += 24 * 3600;

    // Daily cleanup
    node->addr_mgr->cleanup_stale();
  }

  INFO("Total addresses added over 60 days: " << total_added);
  INFO("Final table size: " << node->addr_mgr->size());

  // With 30-day expiry, table should contain roughly 30 days worth of addresses
  // But per-netgroup limits and eviction also apply
  REQUIRE(node->addr_mgr->size() > 0);
  REQUIRE(node->addr_mgr->size() <= 200);
}
