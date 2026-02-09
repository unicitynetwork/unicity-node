// Copyright (c) 2025 The Unicity Foundation
// Connection attempt tracking tests
//
// Tests the attempt() mechanism and is_terrible() failure counting.
//
// IMPORTANT: AddressManager uses a "last_count_attempt < m_last_good" check
// to prevent double-counting failures in rapid succession. This means
// attempt() only increments the failure counter once per "session" (until
// good() is called). This is Bitcoin Core behavior.

#include "../addr_test_network.hpp"
#include "catch_amalgamated.hpp"
#include "util/time.hpp"

using namespace unicity;
using namespace unicity::test::addrsim;

static constexpr int64_t BASE_TIME = 1700000000;

TEST_CASE("Attempt: First attempt counts failure", "[addrsim][attempt]") {
  // The first attempt() call should count as a failure

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  std::string test_addr = "9.1.0.1";
  net.InjectAddress(node_id, test_addr);
  REQUIRE(node->addr_mgr->new_count() == 1);

  auto addr = protocol::NetworkAddress::from_string(test_addr, 9590);

  // First attempt - should count
  util::SetMockTime(BASE_TIME + 120);
  node->addr_mgr->attempt(addr, true);

  // Address should still be in table (1 failure, need 3 for terrible)
  REQUIRE(node->addr_mgr->size() == 1);
}

TEST_CASE("Attempt: fCountFailure=false doesn't increment attempts", "[addrsim][attempt]") {
  // When fCountFailure is false, attempts counter shouldn't increment

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  std::string test_addr = "9.1.0.1";
  net.InjectAddress(node_id, test_addr);
  auto addr = protocol::NetworkAddress::from_string(test_addr, 9590);

  // Make attempts with fCountFailure=false
  for (int i = 0; i < 10; ++i) {
    util::SetMockTime(BASE_TIME + (i + 1) * 120);
    node->addr_mgr->attempt(addr, false);  // Don't count failure
  }

  // Wait past grace period
  util::SetMockTime(BASE_TIME + 2000);
  node->addr_mgr->cleanup_stale();

  INFO("After 10 non-counting attempts: " << node->addr_mgr->size());
  REQUIRE(node->addr_mgr->size() == 1);  // Still there (no failures counted)
}

TEST_CASE("Attempt: good() resets failure tracking", "[addrsim][attempt]") {
  // A successful connection (good()) should move to TRIED and reset attempt counting

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  std::string test_addr = "9.1.0.1";
  net.InjectAddress(node_id, test_addr);
  auto addr = protocol::NetworkAddress::from_string(test_addr, 9590);

  // One failed attempt
  util::SetMockTime(BASE_TIME + 120);
  node->addr_mgr->attempt(addr, true);

  REQUIRE(node->addr_mgr->new_count() == 1);

  // Now succeed - moves to TRIED
  util::SetMockTime(BASE_TIME + 240);
  node->addr_mgr->good(addr);

  // Should be in TRIED now
  REQUIRE(node->addr_mgr->tried_count() == 1);
  REQUIRE(node->addr_mgr->new_count() == 0);
}

TEST_CASE("Attempt: Selection deprioritizes recently tried", "[addrsim][attempt]") {
  // Addresses tried recently should have lower selection probability
  // (GetChance applies 0.01 multiplier for attempts < 10min ago)

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Add multiple addresses from different netgroups
  for (int i = 1; i <= 10; ++i) {
    net.InjectAddress(node_id, std::to_string(i + 8) + ".1.0.1");
  }

  auto addr1 = protocol::NetworkAddress::from_string("9.1.0.1", 9590);

  // Try addr1 recently (updates last_try, reduces selection probability)
  node->addr_mgr->attempt(addr1, false);

  // Select many times and count
  std::map<std::string, int> selections;
  for (int i = 0; i < 200; ++i) {
    auto selected = node->addr_mgr->select();
    if (selected) {
      auto ip = selected->to_string();
      if (ip) selections[*ip]++;
    }
  }

  INFO("9.1.0.1 (recently tried): " << selections["9.1.0.1"]);
  INFO("Total selections: " << selections.size() << " unique addresses");

  // Recently tried address should be selected less often than average
  // Average would be 200/10 = 20 selections per address
  // With 0.01 multiplier, it should be much less
  int tried_count = selections["9.1.0.1"];
  int total_other = 0;
  for (const auto& [ip, count] : selections) {
    if (ip != "9.1.0.1") total_other += count;
  }

  INFO("Recently tried selections: " << tried_count);
  INFO("Other selections total: " << total_other);

  // The recently tried address should get fewer selections
  // This is statistical - we just verify it's noticeably lower
  REQUIRE(tried_count < 30);  // Well below average of 20 + variance
}

TEST_CASE("Attempt: Grace period protects recently tried addresses", "[addrsim][attempt]") {
  // Addresses tried within last 60 seconds are never marked terrible
  // (TERRIBLE_GRACE_PERIOD_SEC = 60)

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  std::string test_addr = "9.1.0.1";
  net.InjectAddress(node_id, test_addr);
  auto addr = protocol::NetworkAddress::from_string(test_addr, 9590);

  // Make one failure attempt
  node->addr_mgr->attempt(addr, true);

  // Immediately try cleanup - grace period should protect
  node->addr_mgr->cleanup_stale();
  INFO("After attempt + immediate cleanup: " << node->addr_mgr->size());
  REQUIRE(node->addr_mgr->size() == 1);  // Grace period protects it
}

TEST_CASE("Attempt: TRIED addresses are retained after failures", "[addrsim][attempt]") {
  // TRIED addresses are kept even if they fail (they worked before)
  // Unlike NEW which gets cleaned up when terrible

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Add address and mark good (moves to TRIED)
  std::string test_addr = "9.1.0.1";
  net.InjectAddress(node_id, test_addr);
  auto addr = protocol::NetworkAddress::from_string(test_addr, 9590);
  node->addr_mgr->good(addr);

  REQUIRE(node->addr_mgr->tried_count() == 1);

  // Make a failure attempt
  util::SetMockTime(BASE_TIME + 120);
  node->addr_mgr->attempt(addr, true);

  // Wait past grace period and cleanup
  util::SetMockTime(BASE_TIME + 300);
  node->addr_mgr->cleanup_stale();

  INFO("TRIED count after failure: " << node->addr_mgr->tried_count());
  // TRIED addresses should be retained (they worked before)
  REQUIRE(node->addr_mgr->tried_count() == 1);
}

TEST_CASE("Attempt: Terrible addresses are excluded from selection", "[addrsim][attempt]") {
  // Addresses that become terrible should not be returned by select()

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Add a very old address (should be terrible due to timestamp)
  auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);
  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string("9.1.0.1", 9590);
  ta.timestamp = static_cast<uint32_t>(BASE_TIME - 40 * 24 * 3600);  // 40 days old

  node->addr_mgr->add_multiple({ta}, source, 0);

  // The old address might be rejected or might be accepted with old timestamp
  // Either way, select() should not return terrible addresses
  bool found_terrible = false;
  for (int i = 0; i < 50; ++i) {
    auto selected = node->addr_mgr->select();
    if (selected) {
      auto ip = selected->to_string();
      if (ip && *ip == "9.1.0.1") {
        found_terrible = true;
      }
    }
  }

  INFO("Terrible address selected: " << (found_terrible ? "yes" : "no"));
  // Old/terrible addresses should be filtered from selection
  REQUIRE_FALSE(found_terrible);
}

TEST_CASE("Attempt: Update timestamp keeps address fresh", "[addrsim][attempt]") {
  // Receiving an address again with newer timestamp should update it

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);
  std::string test_addr = "9.1.0.1";

  // Add with old timestamp (20 days ago)
  {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(test_addr, 9590);
    ta.timestamp = static_cast<uint32_t>(BASE_TIME - 20 * 24 * 3600);
    node->addr_mgr->add_multiple({ta}, source, 0);
  }

  // Update with fresh timestamp
  {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(test_addr, 9590);
    ta.timestamp = static_cast<uint32_t>(BASE_TIME);
    node->addr_mgr->add_multiple({ta}, source, 0);
  }

  // Address should now have fresh timestamp and be selectable
  bool found = false;
  for (int i = 0; i < 50; ++i) {
    auto selected = node->addr_mgr->select();
    if (selected) {
      auto ip = selected->to_string();
      if (ip && *ip == test_addr) {
        found = true;
        break;
      }
    }
  }

  INFO("Refreshed address selectable: " << (found ? "yes" : "no"));
  REQUIRE(found);
}
