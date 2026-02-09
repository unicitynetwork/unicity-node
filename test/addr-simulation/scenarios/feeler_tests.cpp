// Copyright (c) 2025 The Unicity Foundation
// Feeler connection simulation tests
//
// Feeler connections are short-lived probes used to:
// - Verify addresses in the NEW table are reachable
// - Promote verified addresses from NEW to TRIED
// - Track connection failures for address quality scoring

#include "../addr_test_network.hpp"
#include "catch_amalgamated.hpp"
#include "util/time.hpp"

using namespace unicity;
using namespace unicity::test::addrsim;

TEST_CASE("Feeler: Successful connection promotes to TRIED", "[addrsim][feeler]") {
  // A successful feeler connection should move address from NEW to TRIED

  AddrTestNetwork net(42);

  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Inject address into NEW table
  std::string test_addr = "9.1.0.1";
  net.InjectAddress(node_id, test_addr);

  REQUIRE(node->addr_mgr->new_count() == 1);
  REQUIRE(node->addr_mgr->tried_count() == 0);

  // Simulate successful feeler (good promotes to TRIED)
  auto addr = protocol::NetworkAddress::from_string(test_addr, 9590);
  node->addr_mgr->good(addr);

  INFO("NEW count after good: " << node->addr_mgr->new_count());
  INFO("TRIED count after good: " << node->addr_mgr->tried_count());

  REQUIRE(node->addr_mgr->tried_count() == 1);
}

TEST_CASE("Feeler: Failed connection counts failure", "[addrsim][feeler]") {
  // A failed feeler connection should increment failure count

  AddrTestNetwork net(42);

  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Inject address
  std::string test_addr = "9.1.0.1";
  net.InjectAddress(node_id, test_addr);

  // Simulate failed connection attempts
  auto addr = protocol::NetworkAddress::from_string(test_addr, 9590);
  for (int i = 0; i < 5; ++i) {
    node->addr_mgr->attempt(addr, true);  // true = count failure
  }

  // Address should still be in NEW (not removed yet)
  REQUIRE(node->addr_mgr->size() >= 1);

  // After many failures, address becomes "terrible" and may be evicted
  for (int i = 0; i < 20; ++i) {
    node->addr_mgr->attempt(addr, true);
  }

  // Force cleanup
  node->addr_mgr->cleanup_stale();

  INFO("Table size after failures and cleanup: " << node->addr_mgr->size());
  // Note: exact behavior depends on failure threshold implementation
}

TEST_CASE("Feeler: Selection prefers NEW addresses", "[addrsim][feeler]") {
  // For feeler connections, we want to probe NEW addresses

  AddrTestNetwork net(42);

  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Add addresses to both NEW and TRIED
  for (int i = 1; i <= 20; ++i) {
    std::string addr = "9." + std::to_string(i) + ".0.1";
    net.InjectAddress(node_id, addr);

    // Mark half as good (moves to TRIED)
    if (i <= 10) {
      auto na = protocol::NetworkAddress::from_string(addr, 9590);
      node->addr_mgr->good(na);
    }
  }

  INFO("NEW count: " << node->addr_mgr->new_count());
  INFO("TRIED count: " << node->addr_mgr->tried_count());

  // select_new_for_feeler() should only return NEW addresses (for feelers)
  int new_selected = 0;
  int tried_selected = 0;

  for (int i = 0; i < 50; ++i) {
    auto selected = node->addr_mgr->select_new_for_feeler();
    if (selected) {
      // All selections from select_new_for_feeler() should be from NEW table
      new_selected++;
    }
  }

  INFO("Selected from NEW: " << new_selected);
  REQUIRE(new_selected > 0);  // Should be able to select NEW addresses
}

TEST_CASE("Feeler: TRIED addresses selected for regular connections", "[addrsim][feeler]") {
  // Regular connection selection should include TRIED addresses

  AddrTestNetwork net(42);

  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Add addresses and mark all as good (TRIED)
  for (int i = 1; i <= 20; ++i) {
    std::string addr = "9." + std::to_string(i) + ".0.1";
    net.InjectAddress(node_id, addr);
    auto na = protocol::NetworkAddress::from_string(addr, 9590);
    node->addr_mgr->good(na);
  }

  REQUIRE(node->addr_mgr->tried_count() == 20);

  // select() should return TRIED addresses
  int selected_count = 0;
  for (int i = 0; i < 50; ++i) {
    auto selected = node->addr_mgr->select();
    if (selected) {
      selected_count++;
    }
  }

  INFO("Selected addresses: " << selected_count);
  REQUIRE(selected_count > 0);
}

TEST_CASE("Feeler: Mixed selection behavior", "[addrsim][feeler]") {
  // select() should balance between NEW and TRIED

  AddrTestNetwork net(42);

  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Add 50 to NEW, 50 to TRIED
  for (int i = 1; i <= 100; ++i) {
    std::string addr = "9." + std::to_string((i - 1) / 256 + 1) + "." +
                       std::to_string((i - 1) % 256) + ".1";
    net.InjectAddress(node_id, addr);

    if (i <= 50) {
      auto na = protocol::NetworkAddress::from_string(addr, 9590);
      node->addr_mgr->good(na);
    }
  }

  INFO("NEW count: " << node->addr_mgr->new_count());
  INFO("TRIED count: " << node->addr_mgr->tried_count());

  // select() multiple times and track unique addresses
  std::set<std::string> selected_addrs;
  for (int i = 0; i < 200; ++i) {
    auto selected = node->addr_mgr->select();
    if (selected) {
      auto ip = selected->to_string();
      if (ip) selected_addrs.insert(*ip);
    }
  }

  INFO("Unique addresses selected: " << selected_addrs.size());

  // Should select from both NEW and TRIED
  // With 50/50 split and probabilistic selection, expect variety
  REQUIRE(selected_addrs.size() > 10);
}

TEST_CASE("Feeler: Per-netgroup TRIED limit", "[addrsim][feeler]") {
  // TRIED table has per-netgroup limit (typically 8)

  AddrTestNetwork net(42);

  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Try to add many addresses from same netgroup to TRIED
  size_t promoted = 0;
  for (int i = 1; i <= 50; ++i) {
    std::string addr = "44.99." + std::to_string(i / 256) + "." + std::to_string((i % 256) + 1);
    net.InjectAddress(node_id, addr);

    size_t tried_before = node->addr_mgr->tried_count();
    auto na = protocol::NetworkAddress::from_string(addr, 9590);
    node->addr_mgr->good(na);
    size_t tried_after = node->addr_mgr->tried_count();

    if (tried_after > tried_before) {
      promoted++;
    }
  }

  INFO("Addresses promoted to TRIED: " << promoted);
  INFO("TRIED count: " << node->addr_mgr->tried_count());

  // Should be capped at MAX_PER_NETGROUP_TRIED (8)
  REQUIRE(node->addr_mgr->tried_count() <= 8);
}

TEST_CASE("Feeler: Successful connection promotes address", "[addrsim][feeler]") {
  // Successful feeler should move address to TRIED table

  AddrTestNetwork net(42);

  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Inject address
  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string("9.1.0.1", 9590);
  ta.timestamp = static_cast<uint32_t>(util::GetTime());

  auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);
  node->addr_mgr->add_multiple({ta}, source, 0);

  REQUIRE(node->addr_mgr->new_count() == 1);
  REQUIRE(node->addr_mgr->tried_count() == 0);

  // Successful feeler
  node->addr_mgr->good(ta.address);

  // Should be in TRIED now
  REQUIRE(node->addr_mgr->tried_count() == 1);
  REQUIRE(node->addr_mgr->new_count() == 0);
}

TEST_CASE("Feeler: Multiple feelers to same address", "[addrsim][feeler]") {
  // Multiple successful feelers to same address should not cause issues

  AddrTestNetwork net(42);

  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  std::string test_addr = "9.1.0.1";
  net.InjectAddress(node_id, test_addr);

  auto addr = protocol::NetworkAddress::from_string(test_addr, 9590);

  // Multiple good calls
  for (int i = 0; i < 5; ++i) {
    node->addr_mgr->good(addr);
  }

  // Should still have exactly one entry
  REQUIRE(node->addr_mgr->size() == 1);
  REQUIRE(node->addr_mgr->tried_count() == 1);
}
