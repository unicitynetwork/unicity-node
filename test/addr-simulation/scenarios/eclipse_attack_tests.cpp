// Copyright (c) 2025 The Unicity Foundation
// Eclipse attack simulation tests
//
// Eclipse attacks attempt to isolate a victim node by filling its address table
// with attacker-controlled addresses, so all outbound connections go to the attacker.

#include "../addr_test_network.hpp"
#include "catch_amalgamated.hpp"
#include "util/time.hpp"

using namespace unicity;
using namespace unicity::test::addrsim;

// Helper to count addresses from a specific netgroup in a node's AddrMan
static size_t CountAddressesFromNetgroup(AddrTestNode* node, const std::string& netgroup_prefix) {
  auto addrs = node->addr_mgr->get_addresses(10000, 100);
  size_t count = 0;
  for (const auto& ta : addrs) {
    auto ip_opt = ta.address.to_string();
    if (ip_opt && ip_opt->substr(0, netgroup_prefix.size()) == netgroup_prefix) {
      count++;
    }
  }
  return count;
}

// Helper to get netgroup distribution in a node's AddrMan
static std::map<std::string, size_t> GetNetgroupDistribution(AddrTestNode* node) {
  std::map<std::string, size_t> dist;
  auto addrs = node->addr_mgr->get_addresses(10000, 100);
  for (const auto& ta : addrs) {
    std::string ng = ta.address.get_netgroup();
    if (!ng.empty()) {
      dist[ng]++;
    }
  }
  return dist;
}

TEST_CASE("Eclipse: Single netgroup flooding", "[addrsim][eclipse][security]") {
  // Attacker controls many nodes in a single /16 and floods victim with addresses
  // Defense: per-netgroup limits in AddrMan (MAX_PER_NETGROUP_NEW = 32)

  AddrTestNetwork net(42);

  // Create victim node
  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Create honest nodes in diverse netgroups
  std::vector<int> honest_nodes;
  for (int ng = 10; ng < 20; ++ng) {
    auto id = net.CreateNode("8." + std::to_string(ng) + ".0.1");
    honest_nodes.push_back(id);
    net.Connect(victim_id, id);
  }

  // Create attacker nodes all in same /16 (44.99.x.x)
  std::vector<int> attacker_nodes;
  for (int i = 0; i < 50; ++i) {
    auto id = net.CreateNode("44.99." + std::to_string(i / 256) + "." + std::to_string((i % 256) + 1));
    attacker_nodes.push_back(id);
    net.Connect(victim_id, id);
  }

  // Attacker floods victim with 1000 addresses from same /16
  for (int i = 0; i < 1000; ++i) {
    std::string attacker_addr = "44.99." + std::to_string((i / 256) % 256) + "." + std::to_string((i % 256) + 1);

    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(attacker_addr, 9590);
    ta.timestamp = static_cast<uint32_t>(net.GetTime());

    // Send from random attacker node
    int sender = attacker_nodes[i % attacker_nodes.size()];
    net.DeliverAddr(sender, victim_id, {ta});
  }

  // Also inject some honest addresses
  for (int ng = 20; ng < 30; ++ng) {
    for (int i = 0; i < 10; ++i) {
      std::string honest_addr = "8." + std::to_string(ng) + ".0." + std::to_string(i + 1);
      protocol::TimestampedAddress ta;
      ta.address = protocol::NetworkAddress::from_string(honest_addr, 9590);
      ta.timestamp = static_cast<uint32_t>(net.GetTime());

      int sender = honest_nodes[i % honest_nodes.size()];
      net.DeliverAddr(sender, victim_id, {ta});
    }
  }

  // Check victim's AddrMan
  size_t attacker_addrs = CountAddressesFromNetgroup(victim, "44.99");
  size_t total_addrs = victim->addr_mgr->size();

  INFO("Attacker addresses in victim's AddrMan: " << attacker_addrs);
  INFO("Total addresses in victim's AddrMan: " << total_addrs);
  INFO("Attacker percentage: " << (100.0 * attacker_addrs / std::max(total_addrs, size_t(1))) << "%");

  // Defense check: attacker should NOT dominate the address table
  // Per-netgroup limit should cap attacker addresses
  REQUIRE(attacker_addrs <= 40);  // MAX_PER_NETGROUP_NEW (32) + MAX_PER_NETGROUP_TRIED (8)

  // Honest addresses should still be present
  size_t honest_addrs = total_addrs - attacker_addrs;
  REQUIRE(honest_addrs > 0);
}

TEST_CASE("Eclipse: Multi-netgroup coordinated attack", "[addrsim][eclipse][security]") {
  // Attacker controls nodes across multiple /16s to bypass per-netgroup limits
  // This is harder to defend against - requires outbound connection diversity

  AddrTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Attacker controls 10 different /16 netgroups
  std::vector<std::string> attacker_netgroups;
  std::vector<int> attacker_nodes;
  for (int ng = 50; ng < 60; ++ng) {
    std::string prefix = "44." + std::to_string(ng);
    attacker_netgroups.push_back(prefix);

    // 5 nodes per netgroup
    for (int i = 0; i < 5; ++i) {
      auto id = net.CreateNode(prefix + ".0." + std::to_string(i + 1));
      attacker_nodes.push_back(id);
      net.Connect(victim_id, id);
    }
  }

  // Honest nodes in different netgroups
  std::vector<int> honest_nodes;
  for (int ng = 20; ng < 25; ++ng) {
    auto id = net.CreateNode("8." + std::to_string(ng) + ".0.1");
    honest_nodes.push_back(id);
    net.Connect(victim_id, id);
  }

  // Attacker floods from each netgroup
  for (const auto& ng_prefix : attacker_netgroups) {
    for (int i = 0; i < 100; ++i) {
      std::string addr = ng_prefix + "." + std::to_string(i / 256) + "." + std::to_string((i % 256) + 1);

      protocol::TimestampedAddress ta;
      ta.address = protocol::NetworkAddress::from_string(addr, 9590);
      ta.timestamp = static_cast<uint32_t>(net.GetTime());

      int sender = attacker_nodes[i % attacker_nodes.size()];
      net.DeliverAddr(sender, victim_id, {ta});
    }
  }

  // Honest addresses
  for (int ng = 30; ng < 40; ++ng) {
    for (int i = 0; i < 20; ++i) {
      std::string addr = "8." + std::to_string(ng) + ".0." + std::to_string(i + 1);
      protocol::TimestampedAddress ta;
      ta.address = protocol::NetworkAddress::from_string(addr, 9590);
      ta.timestamp = static_cast<uint32_t>(net.GetTime());

      int sender = honest_nodes[i % honest_nodes.size()];
      net.DeliverAddr(sender, victim_id, {ta});
    }
  }

  // Analyze distribution
  auto dist = GetNetgroupDistribution(victim);

  size_t attacker_total = 0;
  size_t honest_total = 0;
  size_t max_per_netgroup = 0;

  for (const auto& [ng, count] : dist) {
    max_per_netgroup = std::max(max_per_netgroup, count);

    // Check if this is an attacker netgroup (44.5x)
    if (ng.substr(0, 3) == "44.") {
      attacker_total += count;
    } else {
      honest_total += count;
    }
  }

  INFO("Attacker addresses: " << attacker_total);
  INFO("Honest addresses: " << honest_total);
  INFO("Max addresses per netgroup: " << max_per_netgroup);
  INFO("Number of netgroups: " << dist.size());

  // Even with multi-netgroup attack, per-netgroup limits apply
  REQUIRE(max_per_netgroup <= 40);  // MAX_PER_NETGROUP_NEW (32) + MAX_PER_NETGROUP_TRIED (8)

  // Victim should have addresses from multiple netgroups (diversity)
  REQUIRE(dist.size() >= 5);
}

TEST_CASE("Eclipse: Source-based flooding defense", "[addrsim][eclipse][security]") {
  // Attacker sends many addresses from single source
  // Defense: per-source limits (MAX_ADDRESSES_PER_SOURCE)

  AddrTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Single attacker node
  auto attacker_id = net.CreateNode("44.1.0.1");
  net.Connect(victim_id, attacker_id);

  // Attacker sends 500 addresses from diverse netgroups (to bypass per-netgroup limits)
  for (int i = 0; i < 500; ++i) {
    // Each address in different /16 to avoid netgroup limits
    std::string addr = "44." + std::to_string((i % 200) + 1) + ".0." + std::to_string((i / 200) + 1);

    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(addr, 9590);
    ta.timestamp = static_cast<uint32_t>(net.GetTime());

    net.DeliverAddr(attacker_id, victim_id, {ta});
  }

  size_t total_from_attacker = victim->addr_mgr->size();

  INFO("Addresses accepted from single source: " << total_from_attacker);

  // Per-source limit should prevent flooding
  // MAX_ADDRESSES_PER_SOURCE = 64
  REQUIRE(total_from_attacker <= 64);
}

TEST_CASE("Eclipse: Address table poisoning over time", "[addrsim][eclipse][security]") {
  // Attacker slowly poisons address table over multiple sessions
  // Simulates persistent attacker building up presence

  AddrTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Simulate multiple "sessions" where attacker connects and sends addresses
  for (int session = 0; session < 10; ++session) {
    // New attacker node each session (different source)
    auto attacker_id = net.CreateNode("44." + std::to_string(session + 1) + ".0.1");
    net.Connect(victim_id, attacker_id);

    // Send addresses across multiple netgroups
    for (int i = 0; i < 50; ++i) {
      int ng = 50 + (session * 5 + i) % 50;  // Spread across 50 netgroups
      std::string addr = "44." + std::to_string(ng) + ".0." + std::to_string(i + 1);

      protocol::TimestampedAddress ta;
      ta.address = protocol::NetworkAddress::from_string(addr, 9590);
      ta.timestamp = static_cast<uint32_t>(net.GetTime());

      net.DeliverAddr(attacker_id, victim_id, {ta});
    }

    net.Disconnect(victim_id, attacker_id);
    net.AdvanceTime(3600);  // 1 hour between sessions
  }

  // Also add some honest addresses
  auto honest_id = net.CreateNode("8.50.0.1");
  net.Connect(victim_id, honest_id);

  // Reset simulation time to real time before adding honest addresses
  // (otherwise timestamps appear far in future relative to AddressManager::now())
  net.SetTime(util::GetTime());

  for (int ng = 1; ng < 20; ++ng) {
    for (int i = 0; i < 10; ++i) {
      std::string addr = "8." + std::to_string(ng) + ".0." + std::to_string(i + 1);
      protocol::TimestampedAddress ta;
      ta.address = protocol::NetworkAddress::from_string(addr, 9590);
      ta.timestamp = static_cast<uint32_t>(net.GetTime());

      net.DeliverAddr(honest_id, victim_id, {ta});
    }
  }

  auto dist = GetNetgroupDistribution(victim);

  size_t attacker_netgroups = 0;
  size_t honest_netgroups = 0;

  for (const auto& [ng, count] : dist) {
    if (ng.substr(0, 3) == "44.") {
      attacker_netgroups++;
    } else {
      honest_netgroups++;
    }
  }

  INFO("Attacker netgroups represented: " << attacker_netgroups);
  INFO("Honest netgroups represented: " << honest_netgroups);
  INFO("Total addresses: " << victim->addr_mgr->size());

  // Even after persistent attack, honest addresses should remain
  REQUIRE(honest_netgroups >= 5);
}

TEST_CASE("Eclipse: Outbound connection simulation", "[addrsim][eclipse][security]") {
  // Simulate what happens when victim makes outbound connections
  // If attacker dominates AddrMan, most connections go to attacker

  AddrTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Seed victim's AddrMan with mix of honest and attacker addresses
  // Attacker has 70% of addresses across multiple netgroups

  // Attacker addresses (70 across 7 netgroups)
  for (int ng = 50; ng < 57; ++ng) {
    for (int i = 0; i < 10; ++i) {
      std::string addr = "44." + std::to_string(ng) + ".0." + std::to_string(i + 1);
      net.InjectAddress(victim_id, addr);
    }
  }

  // Honest addresses (30 across 3 netgroups)
  for (int ng = 10; ng < 13; ++ng) {
    for (int i = 0; i < 10; ++i) {
      std::string addr = "8." + std::to_string(ng) + ".0." + std::to_string(i + 1);
      net.InjectAddress(victim_id, addr);
    }
  }

  INFO("Total addresses seeded: " << victim->addr_mgr->size());

  // Simulate 100 address selections (like making outbound connections)
  size_t attacker_selected = 0;
  size_t honest_selected = 0;
  std::set<std::string> selected_netgroups;

  for (int i = 0; i < 100; ++i) {
    auto addr_opt = victim->addr_mgr->select();
    if (addr_opt) {
      auto ip_opt = addr_opt->to_string();
      if (ip_opt) {
        std::string ng = addr_opt->get_netgroup();
        selected_netgroups.insert(ng);

        if (ip_opt->substr(0, 3) == "44.") {
          attacker_selected++;
        } else {
          honest_selected++;
        }
      }
    }
  }

  INFO("Attacker addresses selected: " << attacker_selected << " / 100");
  INFO("Honest addresses selected: " << honest_selected << " / 100");
  INFO("Unique netgroups selected: " << selected_netgroups.size());

  // With probabilistic selection, attacker shouldn't get 100%
  // even if they have more addresses
  REQUIRE(honest_selected > 0);

  // Netgroup diversity should be maintained
  REQUIRE(selected_netgroups.size() >= 3);
}
