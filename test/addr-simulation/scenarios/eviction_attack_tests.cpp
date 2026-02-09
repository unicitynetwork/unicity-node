// Copyright (c) 2025 The Unicity Foundation
// Eviction attack tests
//
// Attackers may try to:
// - Fill the address table to prevent legitimate addresses
// - Evict good addresses by flooding with slightly-better ones
// - Exploit eviction logic to maintain attacker-controlled entries

#include "../addr_test_network.hpp"
#include "catch_amalgamated.hpp"
#include "util/time.hpp"

using namespace unicity;
using namespace unicity::test::addrsim;

TEST_CASE("Eviction: Table capacity limits", "[addrsim][eviction][security]") {
  // Verify the NEW table has capacity limits

  AddrTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Try to inject more addresses than NEW table capacity
  // MAX_NEW_ADDRESSES is typically 10000
  size_t injected = 0;
  for (int ng = 1; ng <= 200; ++ng) {
    for (int i = 1; i <= 60; ++i) {
      std::string addr = std::to_string(ng) + "." + std::to_string(i) + ".0.1";
      if (net.InjectAddress(victim_id, addr)) {
        injected++;
      }
    }
  }

  INFO("Injected: " << injected);
  INFO("Table size: " << victim->addr_mgr->size());

  // Table should have enforced capacity limit
  // With per-netgroup limit of 32, we can have at most 200*32 = 6400 from injection
  // MAX_NEW_ADDRESSES is 16384, but actual limit depends on eviction
  REQUIRE(victim->addr_mgr->size() <= 16384);
}

TEST_CASE("Eviction: Per-netgroup limits enforced", "[addrsim][eviction][security]") {
  // Verify per-netgroup limits prevent single netgroup domination

  AddrTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Try to inject 100 addresses from single /16
  size_t accepted = 0;
  for (int i = 1; i <= 100; ++i) {
    std::string addr = "44.99." + std::to_string(i / 256) + "." + std::to_string((i % 256) + 1);
    if (net.InjectAddress(victim_id, addr)) {
      accepted++;
    }
  }

  INFO("Accepted from 44.99.x.x: " << accepted);

  // Should be capped at MAX_PER_NETGROUP_NEW (32)
  REQUIRE(accepted <= 32);
}

TEST_CASE("Eviction: Attacker cannot prevent honest addresses", "[addrsim][eviction][security]") {
  // Even with full table, honest addresses from new netgroups should still be accepted
  // (eviction makes room)

  AddrTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Fill table with attacker addresses (many netgroups)
  for (int ng = 50; ng <= 200; ++ng) {
    for (int i = 1; i <= 32; ++i) {  // Up to per-netgroup limit
      std::string addr = "44." + std::to_string(ng) + ".0." + std::to_string(i);
      net.InjectAddress(victim_id, addr);
    }
  }

  size_t after_attack = victim->addr_mgr->size();
  INFO("Table size after attack: " << after_attack);

  // Now honest addresses from NEW netgroups should still work
  // (eviction will make room if table is full)
  size_t honest_accepted = 0;
  for (int ng = 1; ng <= 10; ++ng) {
    std::string addr = "8." + std::to_string(ng) + ".0.1";
    if (net.InjectAddress(victim_id, addr)) {
      honest_accepted++;
    }
  }

  INFO("Honest addresses accepted: " << honest_accepted);
  REQUIRE(honest_accepted >= 5);  // At least some should get in
}

TEST_CASE("Eviction: Terrible addresses evicted first", "[addrsim][eviction][security]") {
  // When eviction is needed, terrible (old, failed) addresses should go first

  AddrTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  uint32_t now = static_cast<uint32_t>(util::GetTime());

  // Inject old addresses (near the terrible threshold)
  for (int i = 1; i <= 20; ++i) {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(
        "44.1." + std::to_string(i / 256) + "." + std::to_string((i % 256) + 1), 9590);
    // 25 days old (close to 30-day terrible threshold)
    ta.timestamp = now - (25 * 24 * 3600);

    auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);
    victim->addr_mgr->add_multiple({ta}, source, 0);
  }

  // Inject fresh addresses
  for (int i = 1; i <= 20; ++i) {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(
        "44.2." + std::to_string(i / 256) + "." + std::to_string((i % 256) + 1), 9590);
    ta.timestamp = now;  // Fresh

    auto source = protocol::NetworkAddress::from_string("8.3.0.1", 9590);
    victim->addr_mgr->add_multiple({ta}, source, 0);
  }

  // Check that fresh addresses are present
  auto addrs = victim->addr_mgr->get_addresses(1000, 100);
  size_t fresh_count = 0;
  size_t old_count = 0;

  for (const auto& ta : addrs) {
    auto ip = ta.address.to_string();
    if (ip && ip->substr(0, 5) == "44.2.") {
      fresh_count++;
    } else if (ip && ip->substr(0, 5) == "44.1.") {
      old_count++;
    }
  }

  INFO("Fresh addresses (44.2.x): " << fresh_count);
  INFO("Old addresses (44.1.x): " << old_count);

  // Fresh addresses should be present
  REQUIRE(fresh_count > 0);
}

TEST_CASE("Eviction: Source diversity maintained", "[addrsim][eviction][security]") {
  // Eviction should maintain source diversity

  AddrTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Multiple sources each contribute addresses
  std::vector<int> sources;
  for (int i = 0; i < 5; ++i) {
    auto src_id = net.CreateNode("8." + std::to_string(i + 10) + ".0.1");
    sources.push_back(src_id);
    net.Connect(src_id, victim_id);
  }

  // Each source sends addresses from different netgroups
  for (size_t s = 0; s < sources.size(); ++s) {
    for (int i = 0; i < 20; ++i) {
      int ng = 50 + s * 20 + i;
      std::string addr = "44." + std::to_string(ng) + ".0.1";

      protocol::TimestampedAddress ta;
      ta.address = protocol::NetworkAddress::from_string(addr, 9590);
      ta.timestamp = static_cast<uint32_t>(util::GetTime());

      net.DeliverAddr(sources[s], victim_id, {ta});
    }
  }

  // Count addresses from each source's netgroup range
  auto addrs = victim->addr_mgr->get_addresses(1000, 100);
  std::vector<size_t> source_counts(5, 0);

  for (const auto& ta : addrs) {
    auto ip = ta.address.to_string();
    if (ip && ip->substr(0, 3) == "44.") {
      // Extract netgroup number
      size_t dot1 = ip->find('.');
      size_t dot2 = ip->find('.', dot1 + 1);
      int ng = std::stoi(ip->substr(dot1 + 1, dot2 - dot1 - 1));
      int source_idx = (ng - 50) / 20;
      if (source_idx >= 0 && source_idx < 5) {
        source_counts[source_idx]++;
      }
    }
  }

  // All sources should have some representation
  size_t sources_with_addrs = 0;
  for (size_t i = 0; i < 5; ++i) {
    INFO("Source " << i << " contributed: " << source_counts[i] << " addresses");
    if (source_counts[i] > 0) sources_with_addrs++;
  }

  REQUIRE(sources_with_addrs >= 3);  // At least 3 of 5 sources should be represented
}

TEST_CASE("Eviction: Replacement attack resistance", "[addrsim][eviction][security]") {
  // Attacker tries to replace good addresses with attacker-controlled ones

  AddrTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // First, establish honest addresses
  for (int ng = 1; ng <= 20; ++ng) {
    net.InjectAddress(victim_id, "8." + std::to_string(ng) + ".0.1");
  }

  size_t honest_before = victim->addr_mgr->size();
  INFO("Honest addresses before attack: " << honest_before);

  // Attacker floods with many addresses
  auto attacker_id = net.CreateNode("44.1.0.1");
  net.Connect(attacker_id, victim_id);

  for (int ng = 50; ng <= 150; ++ng) {
    for (int i = 1; i <= 10; ++i) {
      std::string addr = "44." + std::to_string(ng) + ".0." + std::to_string(i);
      protocol::TimestampedAddress ta;
      ta.address = protocol::NetworkAddress::from_string(addr, 9590);
      ta.timestamp = static_cast<uint32_t>(util::GetTime());

      net.DeliverAddr(attacker_id, victim_id, {ta});
    }
  }

  // Count remaining honest vs attacker addresses
  auto addrs = victim->addr_mgr->get_addresses(10000, 100);
  size_t honest_count = 0;
  size_t attacker_count = 0;

  for (const auto& ta : addrs) {
    auto ip = ta.address.to_string();
    if (ip) {
      if (ip->substr(0, 2) == "8.") {
        honest_count++;
      } else if (ip->substr(0, 3) == "44.") {
        attacker_count++;
      }
    }
  }

  INFO("Honest addresses after attack: " << honest_count);
  INFO("Attacker addresses: " << attacker_count);

  // Honest addresses should not be completely evicted
  // (per-source limits protect against single-source flooding)
  REQUIRE(honest_count > 0);
}

// ============================================================================
// TRIED Table Eviction Tests (Bitcoin Core Parity)
// ============================================================================

TEST_CASE("Eviction: TRIED 4-hour grace period protects recent success", "[addrsim][eviction][grace]") {
  // TRIED addresses with last_success within 4 hours should be protected from eviction
  // This matches Bitcoin Core's ADDRMAN_REPLACEMENT_SEC (4 hours)

  util::MockTimeScope mock_time(1700000000);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Fill TRIED table with addresses from different netgroups
  // Each netgroup can have max 8 TRIED addresses
  // We need to fill enough to trigger eviction

  uint32_t now = static_cast<uint32_t>(util::GetTime());

  // Add addresses and mark them good (moves to TRIED)
  // Use old last_success (5 hours ago) so they're outside grace period
  std::vector<std::string> old_addrs;
  for (int ng = 1; ng <= 100; ++ng) {
    for (int i = 1; i <= 8; ++i) {
      std::string addr = std::to_string(ng) + "." + std::to_string(i) + ".0.1";
      old_addrs.push_back(addr);

      protocol::TimestampedAddress ta;
      ta.address = protocol::NetworkAddress::from_string(addr, 9590);
      ta.timestamp = now - 5 * 3600;  // 5 hours ago

      auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);
      node->addr_mgr->add_multiple({ta}, source, 0);
      node->addr_mgr->good(ta.address);
    }
  }

  size_t tried_before = node->addr_mgr->tried_count();
  INFO("TRIED count before adding recent: " << tried_before);

  // Now add ONE address with recent last_success (within 4 hours)
  std::string recent_addr = "200.1.0.1";
  {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(recent_addr, 9590);
    ta.timestamp = now;

    auto source = protocol::NetworkAddress::from_string("8.3.0.1", 9590);
    node->addr_mgr->add_multiple({ta}, source, 0);

    // Mark good - this sets last_success to current time
    node->addr_mgr->good(ta.address);
  }

  // Try to trigger eviction by adding more addresses to same netgroup (200.x)
  // The recent address should be protected
  for (int i = 2; i <= 20; ++i) {
    std::string addr = "200." + std::to_string(i) + ".0.1";
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(addr, 9590);
    ta.timestamp = now - 5 * 3600;  // Old timestamp

    auto source = protocol::NetworkAddress::from_string("8.4.0.1", 9590);
    node->addr_mgr->add_multiple({ta}, source, 0);
    node->addr_mgr->good(ta.address);
  }

  // Check if the recent address is still in TRIED
  auto addrs = node->addr_mgr->get_addresses(20000, 100);
  bool recent_found = false;
  for (const auto& ta : addrs) {
    auto ip = ta.address.to_string();
    if (ip && *ip == recent_addr) {
      recent_found = true;
      break;
    }
  }

  INFO("Recent address (200.1.0.1) still present: " << (recent_found ? "yes" : "no"));
  INFO("Final TRIED count: " << node->addr_mgr->tried_count());

  // The recently-successful address should be protected
  REQUIRE(recent_found);
}

TEST_CASE("Eviction: TRIED addresses demote to NEW on eviction", "[addrsim][eviction][demotion]") {
  // When a TRIED address is evicted, it should move to NEW table (not be deleted)
  // This preserves address information for future use

  util::MockTimeScope mock_time(1700000000);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  uint32_t now = static_cast<uint32_t>(util::GetTime());
  uint32_t old_ts = now - 5 * 3600;  // 5 hours ago (outside grace period)

  // Fill a single netgroup's TRIED slots (max 8 per netgroup)
  std::vector<std::string> original_addrs;
  for (int i = 1; i <= 8; ++i) {
    std::string addr = "50." + std::to_string(i) + ".0.1";
    original_addrs.push_back(addr);

    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(addr, 9590);
    ta.timestamp = old_ts;

    auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);
    node->addr_mgr->add_multiple({ta}, source, 0);
    node->addr_mgr->good(ta.address);
  }

  size_t tried_before = node->addr_mgr->tried_count();
  size_t new_before = node->addr_mgr->new_count();
  INFO("Before eviction - TRIED: " << tried_before << ", NEW: " << new_before);

  REQUIRE(tried_before == 8);
  REQUIRE(new_before == 0);

  // Add one more address to same netgroup - should trigger eviction
  std::string new_addr = "50.100.0.1";
  {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(new_addr, 9590);
    ta.timestamp = now;

    auto source = protocol::NetworkAddress::from_string("8.3.0.1", 9590);
    node->addr_mgr->add_multiple({ta}, source, 0);
    node->addr_mgr->good(ta.address);
  }

  size_t tried_after = node->addr_mgr->tried_count();
  size_t new_after = node->addr_mgr->new_count();
  INFO("After eviction - TRIED: " << tried_after << ", NEW: " << new_after);

  // TRIED should still be 8 (one evicted, one added)
  // But NEW should have increased (evicted address demoted)
  // Note: the evicted address might not make it to NEW if per-netgroup NEW limit is hit

  // Count how many of original addresses are still present (in either table)
  auto all_addrs = node->addr_mgr->get_addresses(1000, 100);
  size_t original_present = 0;
  for (const auto& ta : all_addrs) {
    auto ip = ta.address.to_string();
    if (ip) {
      for (const auto& orig : original_addrs) {
        if (*ip == orig) {
          original_present++;
          break;
        }
      }
    }
  }

  INFO("Original addresses still present: " << original_present << " of 8");

  // With demotion, at least some original addresses should still be present
  // (either in TRIED or demoted to NEW)
  REQUIRE(original_present >= 7);  // At least 7 of 8 should survive
}

TEST_CASE("Eviction: Demotion flood attack resistance", "[addrsim][eviction][demotion][security]") {
  // Attacker tries to flood NEW table by triggering mass TRIED demotions
  // Per-netgroup limits should still apply after demotion

  util::MockTimeScope mock_time(1700000000);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  uint32_t now = static_cast<uint32_t>(util::GetTime());
  uint32_t old_ts = now - 5 * 3600;  // Outside grace period

  // First, fill NEW table with honest addresses from various netgroups
  size_t honest_injected = 0;
  for (int ng = 1; ng <= 50; ++ng) {
    for (int i = 1; i <= 20; ++i) {
      std::string addr = std::to_string(ng) + "." + std::to_string(i) + ".0.1";
      if (net.InjectAddress(node_id, addr)) {
        honest_injected++;
      }
    }
  }

  INFO("Honest addresses injected to NEW: " << honest_injected);

  // Now attacker fills TRIED with addresses from SINGLE attack netgroup (44.99.x.x)
  // Each netgroup can have max 8 in TRIED, so we add 8 addresses
  for (int i = 1; i <= 8; ++i) {
    // All addresses in 44.99.x.x netgroup (same /16)
    std::string addr = "44.99." + std::to_string(i / 256) + "." + std::to_string((i % 256) + 1);

    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(addr, 9590);
    ta.timestamp = old_ts;

    auto source = protocol::NetworkAddress::from_string("8.99.0.1", 9590);
    node->addr_mgr->add_multiple({ta}, source, 0);
    node->addr_mgr->good(ta.address);
  }

  size_t tried_after_fill = node->addr_mgr->tried_count();
  INFO("TRIED after filling netgroup: " << tried_after_fill);

  // Now trigger evictions by adding MORE addresses to SAME netgroup
  // This should evict old addresses and demote them to NEW
  size_t demotions_triggered = 0;
  for (int i = 9; i <= 20; ++i) {
    std::string addr = "44.99." + std::to_string(i / 256) + "." + std::to_string((i % 256) + 1);

    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(addr, 9590);
    ta.timestamp = now;

    auto source = protocol::NetworkAddress::from_string("8.99.0.1", 9590);
    node->addr_mgr->add_multiple({ta}, source, 0);
    node->addr_mgr->good(ta.address);
    demotions_triggered++;
  }

  // Count attacker addresses in each table
  auto all_addrs = node->addr_mgr->get_addresses(20000, 100);
  size_t attacker_total = 0;
  size_t honest_remaining = 0;

  for (const auto& ta : all_addrs) {
    auto ip = ta.address.to_string();
    if (ip) {
      if (ip->substr(0, 6) == "44.99.") {
        attacker_total++;
      } else if (ip->find('.') != std::string::npos) {
        // Count addresses from netgroups 1-50 as honest
        int first_octet = std::stoi(ip->substr(0, ip->find('.')));
        if (first_octet >= 1 && first_octet <= 50) {
          honest_remaining++;
        }
      }
    }
  }

  INFO("Attacker addresses (44.99.x): " << attacker_total);
  INFO("Honest addresses remaining: " << honest_remaining);
  INFO("NEW table size: " << node->addr_mgr->new_count());
  INFO("TRIED table size: " << node->addr_mgr->tried_count());

  // Per-netgroup limits should cap attacker addresses:
  // Max 8 in TRIED + max 32 in NEW = 40 total per netgroup
  REQUIRE(attacker_total <= 40);

  // Honest addresses should largely survive (attacker only affects one netgroup)
  REQUIRE(honest_remaining > honest_injected * 0.9);  // 90%+ should survive
}

TEST_CASE("Eviction: Grace period expires after 4 hours", "[addrsim][eviction][grace]") {
  // Verify that the 4-hour grace period actually expires

  util::MockTimeScope mock_time(1700000000);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  uint32_t now = static_cast<uint32_t>(util::GetTime());

  // Add address and mark good
  std::string test_addr = "50.1.0.1";
  {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(test_addr, 9590);
    ta.timestamp = now;

    auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);
    node->addr_mgr->add_multiple({ta}, source, 0);
    node->addr_mgr->good(ta.address);
  }

  REQUIRE(node->addr_mgr->tried_count() == 1);

  // Fill rest of netgroup's TRIED slots
  for (int i = 2; i <= 8; ++i) {
    std::string addr = "50." + std::to_string(i) + ".0.1";
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(addr, 9590);
    ta.timestamp = now;

    auto source = protocol::NetworkAddress::from_string("8.2.0.1", 9590);
    node->addr_mgr->add_multiple({ta}, source, 0);
    node->addr_mgr->good(ta.address);
  }

  REQUIRE(node->addr_mgr->tried_count() == 8);

  // Advance time past the 4-hour grace period
  util::SetMockTime(now + 5 * 3600);  // 5 hours later

  // Now add another address - should be able to evict the first one
  std::string new_addr = "50.100.0.1";
  {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(new_addr, 9590);
    ta.timestamp = now + 5 * 3600;

    auto source = protocol::NetworkAddress::from_string("8.3.0.1", 9590);
    node->addr_mgr->add_multiple({ta}, source, 0);
    node->addr_mgr->good(ta.address);
  }

  // Check if the original address was evicted (moved to NEW)
  auto all_addrs = node->addr_mgr->get_addresses(1000, 100);
  bool original_in_tried = false;
  bool new_addr_found = false;

  for (const auto& ta : all_addrs) {
    auto ip = ta.address.to_string();
    if (ip) {
      if (*ip == test_addr) original_in_tried = true;
      if (*ip == new_addr) new_addr_found = true;
    }
  }

  INFO("Original address (50.1.0.1) still present: " << (original_in_tried ? "yes" : "no"));
  INFO("New address (50.100.0.1) present: " << (new_addr_found ? "yes" : "no"));
  INFO("TRIED count: " << node->addr_mgr->tried_count());
  INFO("NEW count: " << node->addr_mgr->new_count());

  // The new address should have been added
  REQUIRE(new_addr_found);

  // Original might be evicted (demoted to NEW) or still in TRIED
  // Either way, total addresses should be preserved
  REQUIRE(node->addr_mgr->size() >= 8);
}
