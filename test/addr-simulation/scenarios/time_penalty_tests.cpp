// Copyright (c) 2025 The Unicity Foundation
// Time penalty tests for ADDR messages
//
// Bitcoin Core applies a time penalty to timestamps in ADDR messages
// to prevent timestamp spoofing and improve privacy. This tests that behavior.
// The penalty is passed as a parameter to add_multiple().

#include "../addr_test_network.hpp"
#include "catch_amalgamated.hpp"
#include "util/time.hpp"

using namespace unicity;
using namespace unicity::test::addrsim;

static constexpr int64_t BASE_TIME = 1700000000;
static constexpr int64_t TWO_HOURS = 2 * 60 * 60;

TEST_CASE("TimePenalty: Penalty parameter reduces stored timestamp", "[addrsim][penalty]") {
  // When add_multiple is called with time_penalty > 0, stored timestamp
  // should be reduced by the penalty amount

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);

  // Send address with "current" timestamp and 2-hour penalty
  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string("9.1.0.1", 9590);
  ta.timestamp = static_cast<uint32_t>(BASE_TIME);

  // Apply 2-hour penalty directly via add_multiple
  node->addr_mgr->add_multiple({ta}, source, TWO_HOURS);

  // Check stored timestamp
  auto addrs = node->addr_mgr->get_addresses(100, 100);
  REQUIRE(addrs.size() == 1);

  // Stored timestamp should be penalized by 2 hours
  int64_t stored_ts = addrs[0].timestamp;
  int64_t expected = BASE_TIME - TWO_HOURS;

  INFO("Sent timestamp: " << BASE_TIME);
  INFO("Stored timestamp: " << stored_ts);
  INFO("Expected (with penalty): " << expected);

  // Must be reduced by at least the penalty amount
  REQUIRE(stored_ts <= expected);
}

TEST_CASE("TimePenalty: Zero penalty preserves timestamp", "[addrsim][penalty]") {
  // When add_multiple is called with time_penalty = 0, timestamp is preserved

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);

  // Send address with no penalty
  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string("9.1.0.1", 9590);
  ta.timestamp = static_cast<uint32_t>(BASE_TIME);

  node->addr_mgr->add_multiple({ta}, source, 0);  // No penalty

  auto addrs = node->addr_mgr->get_addresses(100, 100);
  REQUIRE(addrs.size() == 1);

  int64_t stored_ts = addrs[0].timestamp;

  INFO("Sent timestamp: " << BASE_TIME);
  INFO("Stored timestamp: " << stored_ts);

  // Should be same as sent (or clamped, but not penalized)
  REQUIRE(stored_ts >= BASE_TIME - 120);  // Allow small tolerance
}

TEST_CASE("TimePenalty: Larger penalty has larger effect", "[addrsim][penalty]") {
  // Larger penalties should reduce timestamp more

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);

  // Add address with 1-hour penalty
  protocol::TimestampedAddress ta1;
  ta1.address = protocol::NetworkAddress::from_string("9.1.0.1", 9590);
  ta1.timestamp = static_cast<uint32_t>(BASE_TIME);
  node->addr_mgr->add_multiple({ta1}, source, 3600);  // 1 hour

  // Add different address with 4-hour penalty
  protocol::TimestampedAddress ta2;
  ta2.address = protocol::NetworkAddress::from_string("9.2.0.1", 9590);
  ta2.timestamp = static_cast<uint32_t>(BASE_TIME);
  node->addr_mgr->add_multiple({ta2}, source, 4 * 3600);  // 4 hours

  auto addrs = node->addr_mgr->get_addresses(100, 100);
  REQUIRE(addrs.size() == 2);

  int64_t ts1 = 0, ts2 = 0;
  for (const auto& a : addrs) {
    auto ip = a.address.to_string();
    if (ip && *ip == "9.1.0.1") ts1 = a.timestamp;
    if (ip && *ip == "9.2.0.1") ts2 = a.timestamp;
  }

  INFO("1-hour penalty timestamp: " << ts1);
  INFO("4-hour penalty timestamp: " << ts2);

  // 4-hour penalty should result in older timestamp
  REQUIRE(ts2 < ts1);
}

TEST_CASE("TimePenalty: Fresher update replaces older timestamp", "[addrsim][penalty]") {
  // If we receive same address with fresher timestamp, it should update

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);
  std::string test_addr = "9.1.0.1";

  // First: send with old timestamp (10 days ago)
  {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(test_addr, 9590);
    ta.timestamp = static_cast<uint32_t>(BASE_TIME - 10 * 24 * 3600);
    node->addr_mgr->add_multiple({ta}, source, 0);
  }

  auto addrs1 = node->addr_mgr->get_addresses(100, 100);
  REQUIRE(addrs1.size() == 1);
  int64_t first_stored = addrs1[0].timestamp;

  // Second: send with fresh timestamp (but with 2-hour penalty)
  {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(test_addr, 9590);
    ta.timestamp = static_cast<uint32_t>(BASE_TIME);
    node->addr_mgr->add_multiple({ta}, source, TWO_HOURS);
  }

  auto addrs2 = node->addr_mgr->get_addresses(100, 100);
  REQUIRE(addrs2.size() == 1);
  int64_t second_stored = addrs2[0].timestamp;

  INFO("First stored timestamp: " << first_stored);
  INFO("Second stored timestamp: " << second_stored);

  // Second should be fresher (even with penalty, it's newer than 10-day-old)
  REQUIRE(second_stored > first_stored);
}

TEST_CASE("TimePenalty: Penalty with future timestamp", "[addrsim][penalty]") {
  // Future timestamps should be clamped, then penalty applied

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);

  // Send address with future timestamp (10 minutes ahead)
  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string("9.1.0.1", 9590);
  ta.timestamp = static_cast<uint32_t>(BASE_TIME + 600);  // 10 min future

  // Apply 2-hour penalty
  node->addr_mgr->add_multiple({ta}, source, TWO_HOURS);

  auto addrs = node->addr_mgr->get_addresses(100, 100);

  if (!addrs.empty()) {
    int64_t stored_ts = addrs[0].timestamp;
    INFO("Future timestamp: " << (BASE_TIME + 600));
    INFO("Stored timestamp: " << stored_ts);

    // Should not be in the future after clamping and penalty
    REQUIRE(stored_ts <= BASE_TIME);
  }
}

TEST_CASE("TimePenalty: Multiple addresses same penalty", "[addrsim][penalty]") {
  // When receiving multiple addresses, same penalty applies to all

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);

  // Send batch of addresses
  std::vector<protocol::TimestampedAddress> batch;
  for (int i = 1; i <= 5; ++i) {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(
        "9." + std::to_string(i) + ".0.1", 9590);
    ta.timestamp = static_cast<uint32_t>(BASE_TIME);
    batch.push_back(ta);
  }

  // Apply 1-hour penalty to all
  node->addr_mgr->add_multiple(batch, source, 3600);

  auto addrs = node->addr_mgr->get_addresses(100, 100);
  REQUIRE(addrs.size() == 5);

  // All should have similar penalized timestamps
  int64_t expected_max = BASE_TIME - 3600 + 60;  // 1 hour penalty with margin
  for (const auto& ta : addrs) {
    INFO("Address timestamp: " << ta.timestamp);
    REQUIRE(ta.timestamp <= expected_max);
  }
}

TEST_CASE("TimePenalty: Self-advertisement exempt from penalty", "[addrsim][penalty]") {
  // When we advertise our own address, no penalty should apply
  // (This tests the source=self case with 0 penalty)

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Add our own address directly (simulating self-advertisement)
  auto our_addr = protocol::NetworkAddress::from_string("8.1.0.1", 9590);

  protocol::TimestampedAddress ta;
  ta.address = our_addr;
  ta.timestamp = static_cast<uint32_t>(BASE_TIME);

  // Add with time_penalty=0 (self-advertisement path)
  node->addr_mgr->add_multiple({ta}, our_addr, 0);

  auto addrs = node->addr_mgr->get_addresses(100, 100);

  // Self-advertisement should be stored as-is (or close)
  for (const auto& a : addrs) {
    auto ip = a.address.to_string();
    if (ip && *ip == "8.1.0.1") {
      INFO("Self-address timestamp: " << a.timestamp);
      // Should be close to original (within tolerance for clamping)
      REQUIRE(a.timestamp >= BASE_TIME - 120);
    }
  }
}
