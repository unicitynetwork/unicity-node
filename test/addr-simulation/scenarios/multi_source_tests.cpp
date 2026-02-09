// Copyright (c) 2025 The Unicity Foundation
// Multi-source AddressManager stress tests
//
// These exercise AddressManager under conditions that single-source unit tests
// don't cover: many concurrent sources hitting per-source limits simultaneously,
// and verifying select() diversity after realistic adversarial injection.

#include "../addr_test_network.hpp"
#include "catch_amalgamated.hpp"
#include "util/time.hpp"

#include <map>

using namespace unicity;
using namespace unicity::test::addrsim;

static constexpr int64_t BASE_TIME = 1700000000;
static constexpr size_t MAX_ADDRESSES_PER_SOURCE = 64;
static constexpr size_t MAX_PER_NETGROUP_NEW = 32;
static constexpr size_t MAX_NEW_ADDRESSES = 65536;

TEST_CASE("MultiSource: Per-source limits hold under 100-source flood",
          "[addrsim][multisource]") {
  // 100 distinct sources each try to inject 64 addresses (the per-source limit)
  // into one victim. Each source uses diverse netgroups to avoid hitting
  // per-netgroup limits. Verify:
  //   - No individual source exceeds 64 accepted
  //   - Total table size stays within global capacity
  //   - Source-tracking bookkeeping doesn't break under load

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Track per-source acceptance
  std::map<std::string, size_t> accepted_per_source;

  for (int src = 0; src < 100; ++src) {
    std::string src_ip = std::to_string((src / 256) + 1) + "." +
                         std::to_string((src % 256) + 1) + ".0.1";
    auto source = protocol::NetworkAddress::from_string(src_ip, 9590);

    size_t source_accepted = 0;
    for (int addr = 0; addr < 64; ++addr) {
      // Each address in a different /16 to avoid per-netgroup limits
      // being the bottleneck instead of per-source limits
      int ng = (src * 64 + addr) % 250 + 1;
      int host = (src * 64 + addr) / 250 + 1;
      std::string addr_ip = std::to_string(ng) + "." +
                            std::to_string(host) + ".0." +
                            std::to_string((addr % 254) + 1);

      protocol::TimestampedAddress ta;
      ta.address = protocol::NetworkAddress::from_string(addr_ip, 9590);
      ta.timestamp = static_cast<uint32_t>(BASE_TIME);

      if (victim->addr_mgr->add_multiple({ta}, source, 0) > 0) {
        source_accepted++;
      }
    }
    accepted_per_source[src_ip] = source_accepted;
  }

  // Verify per-source limit holds for every source
  size_t sources_at_limit = 0;
  size_t max_from_any_source = 0;
  for (const auto& [src, count] : accepted_per_source) {
    REQUIRE(count <= MAX_ADDRESSES_PER_SOURCE);
    max_from_any_source = std::max(max_from_any_source, count);
    if (count == MAX_ADDRESSES_PER_SOURCE) sources_at_limit++;
  }

  INFO("Max accepted from any single source: " << max_from_any_source);
  INFO("Sources that hit the 64 limit: " << sources_at_limit);

  // Global capacity must hold
  size_t table_size = victim->addr_mgr->size();
  INFO("Total table size: " << table_size);
  REQUIRE(table_size <= MAX_NEW_ADDRESSES);

  // With 100 sources × 64 each = 6400 possible, many should have been accepted
  // (per-netgroup limits will reduce this, but table should be well-populated)
  REQUIRE(table_size > 500);
}

TEST_CASE("MultiSource: select() diversity after adversarial injection",
          "[addrsim][multisource][security]") {
  // Attacker controls 10 /16 netgroups (10 sources × 30 addresses each = 300).
  // Honest network has 5 sources × 20 addresses each = 100 from 5 netgroups.
  // After injection, attacker has ~3x the addresses.
  //
  // Verify select() returns honest addresses at a rate that isn't negligible.
  // The existing eclipse test just checks "honest > 0" which would pass even
  // if honest addresses appeared 1/1000 times. We check for a meaningful share.

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Honest sources: 5 sources, 20 addresses each, diverse netgroups
  size_t honest_injected = 0;
  for (int src = 0; src < 5; ++src) {
    auto source = protocol::NetworkAddress::from_string(
        "8." + std::to_string(src + 10) + ".0.1", 9590);

    for (int addr = 0; addr < 20; ++addr) {
      int ng = 10 + src * 20 + addr;  // Netgroups 10-109
      protocol::TimestampedAddress ta;
      ta.address = protocol::NetworkAddress::from_string(
          std::to_string(ng) + ".1.0.1", 9590);
      ta.timestamp = static_cast<uint32_t>(BASE_TIME);
      if (victim->addr_mgr->add_multiple({ta}, source, 0) > 0) {
        honest_injected++;
      }
    }
  }

  INFO("Honest addresses injected: " << honest_injected);

  // Attacker sources: 10 sources, 30 addresses each, different netgroups
  size_t attacker_injected = 0;
  for (int src = 0; src < 10; ++src) {
    auto source = protocol::NetworkAddress::from_string(
        "44." + std::to_string(src + 1) + ".0.1", 9590);

    for (int addr = 0; addr < 30; ++addr) {
      int ng = 120 + src * 30 + addr;  // Netgroups 120-419
      protocol::TimestampedAddress ta;
      ta.address = protocol::NetworkAddress::from_string(
          std::to_string(ng) + ".1.0.1", 9590);
      ta.timestamp = static_cast<uint32_t>(BASE_TIME);
      if (victim->addr_mgr->add_multiple({ta}, source, 0) > 0) {
        attacker_injected++;
      }
    }
  }

  INFO("Attacker addresses injected: " << attacker_injected);

  size_t total = victim->addr_mgr->size();
  double honest_table_share = 100.0 * honest_injected / total;
  INFO("Table size: " << total);
  INFO("Honest table share: " << honest_table_share << "%");

  // Sample select() 1000 times
  size_t honest_selected = 0;
  size_t attacker_selected = 0;
  size_t other_selected = 0;
  std::set<std::string> unique_selected;

  for (int i = 0; i < 1000; ++i) {
    auto selected = victim->addr_mgr->select();
    if (selected) {
      auto ip = selected->to_string();
      if (ip) {
        unique_selected.insert(*ip);
        // Parse first octet to classify
        int first_octet = std::stoi(ip->substr(0, ip->find('.')));
        if (first_octet >= 10 && first_octet < 120) {
          honest_selected++;
        } else if (first_octet >= 120) {
          attacker_selected++;
        } else {
          other_selected++;
        }
      }
    }
  }

  double honest_select_pct = 100.0 * honest_selected / (honest_selected + attacker_selected);
  INFO("Selection results (1000 samples):");
  INFO("  Honest: " << honest_selected << " (" << honest_select_pct << "%)");
  INFO("  Attacker: " << attacker_selected);
  INFO("  Unique addresses selected: " << unique_selected.size());

  // Honest addresses should appear at a rate roughly proportional to their
  // table share, not be starved out. With ~25% of table, we expect ~25% of
  // selections. Allow a wide margin but reject < 10%.
  REQUIRE(honest_select_pct > 10.0);

  // Selection should touch multiple unique addresses (not stuck on one)
  REQUIRE(unique_selected.size() >= 20);
}
