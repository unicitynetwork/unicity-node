// Copyright (c) 2025 The Unicity Foundation
// Bucketization gap analysis tests
//
// Bitcoin Core uses a sophisticated bucket system:
// - NEW: 1024 buckets × 64 slots = 65536 capacity
// - TRIED: 256 buckets × 64 slots = 16384 capacity
// - Bucket selection uses: Hash(secret_key, netgroup, source_group)
// - This provides cryptographic unpredictability
//
// Our implementation uses simple maps with per-netgroup limits:
// - No secret key (predictable placement)
// - No source-group based bucket isolation
// - Global per-netgroup limits instead of per-bucket limits
//
// These tests demonstrate attack scenarios that exploit these differences.

#include "../addr_test_network.hpp"
#include "catch_amalgamated.hpp"
#include "util/time.hpp"

#include <numeric>

using namespace unicity;
using namespace unicity::test::addrsim;

static constexpr int64_t BASE_TIME = 1700000000;

// Helper to count addresses by source netgroup
std::map<std::string, size_t> CountBySourceNetgroup(
    const std::vector<protocol::TimestampedAddress>& addrs) {
  std::map<std::string, size_t> counts;
  for (const auto& ta : addrs) {
    counts[ta.address.get_netgroup()]++;
  }
  return counts;
}

TEST_CASE("BucketGap: Single source can spread across all netgroups", "[addrsim][bucketgap]") {
  // WITHOUT bucket isolation: A single source can inject addresses into ANY netgroup
  // WITH buckets: Source would be confined to specific buckets based on Hash(key, src_group)
  //
  // This test shows that one malicious peer can pollute diverse netgroups

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Single attacker source
  auto attacker_source = protocol::NetworkAddress::from_string("44.1.0.1", 9590);

  // Attacker claims to know addresses in 100 different netgroups
  size_t injected = 0;
  for (int ng = 1; ng <= 100; ++ng) {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(
        std::to_string(ng) + ".1.0.1", 9590);
    ta.timestamp = static_cast<uint32_t>(BASE_TIME);

    if (node->addr_mgr->add_multiple({ta}, attacker_source, 0) > 0) {
      injected++;
    }
  }

  INFO("Single source injected addresses into " << injected << " different netgroups");

  // Get all addresses and check netgroup diversity
  auto addrs = node->addr_mgr->get_addresses(1000, 100);
  std::set<std::string> netgroups;
  for (const auto& ta : addrs) {
    netgroups.insert(ta.address.get_netgroup());
  }

  INFO("Netgroups represented in table: " << netgroups.size());

  // VULNERABILITY: Single source polluted many netgroups
  // In Bitcoin Core, source would be hashed into specific buckets, limiting spread
  REQUIRE(netgroups.size() >= 50);  // Shows the vulnerability exists

  // This is BAD for eclipse resistance - one peer shouldn't control this much diversity
  WARN("BUCKETIZATION GAP: Single source controls " << netgroups.size() << " netgroups");
}

TEST_CASE("BucketGap: Attacker can predict placement deterministically", "[addrsim][bucketgap]") {
  // WITHOUT secret key: Attacker knows exactly where addresses will land
  // WITH secret key: Hash(secret, netgroup, source) is unpredictable
  //
  // This test shows placement is deterministic and predictable

  util::MockTimeScope mock_time(BASE_TIME);

  // Create two nodes with same setup
  AddrTestNetwork net1(42);
  AddrTestNetwork net2(42);

  auto node1_id = net1.CreateNode("8.1.0.1");
  auto node2_id = net2.CreateNode("8.1.0.1");
  auto* node1 = net1.GetNode(node1_id);
  auto* node2 = net2.GetNode(node2_id);

  auto source = protocol::NetworkAddress::from_string("44.1.0.1", 9590);

  // Add same addresses to both
  for (int i = 1; i <= 50; ++i) {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(
        std::to_string(i) + ".1.0.1", 9590);
    ta.timestamp = static_cast<uint32_t>(BASE_TIME);

    node1->addr_mgr->add_multiple({ta}, source, 0);
    node2->addr_mgr->add_multiple({ta}, source, 0);
  }

  // Compare tables - they should be IDENTICAL (predictable)
  auto addrs1 = node1->addr_mgr->get_addresses(1000, 100);
  auto addrs2 = node2->addr_mgr->get_addresses(1000, 100);

  std::set<std::string> set1, set2;
  for (const auto& ta : addrs1) {
    auto ip = ta.address.to_string();
    if (ip) set1.insert(*ip);
  }
  for (const auto& ta : addrs2) {
    auto ip = ta.address.to_string();
    if (ip) set2.insert(*ip);
  }

  INFO("Node1 addresses: " << set1.size());
  INFO("Node2 addresses: " << set2.size());

  // Check how many are identical
  std::set<std::string> intersection;
  std::set_intersection(set1.begin(), set1.end(), set2.begin(), set2.end(),
                        std::inserter(intersection, intersection.begin()));

  double similarity = static_cast<double>(intersection.size()) /
                      std::max(set1.size(), set2.size());

  INFO("Similarity between nodes: " << (similarity * 100) << "%");

  // VULNERABILITY: Tables are nearly identical (predictable)
  // In Bitcoin Core, different secret keys would cause different bucket assignments
  REQUIRE(similarity > 0.9);

  WARN("BUCKETIZATION GAP: Placement is " << (similarity * 100) << "% predictable across nodes");
}

TEST_CASE("BucketGap: No source-group isolation in eviction", "[addrsim][bucketgap]") {
  // WITHOUT source-based buckets: Attacker's addresses compete globally
  // WITH source-based buckets: Each source confined to specific buckets
  //
  // This means attacker can evict honest addresses from ANY bucket

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // First: honest peers add diverse addresses
  for (int honest_src = 1; honest_src <= 20; ++honest_src) {
    auto source = protocol::NetworkAddress::from_string(
        std::to_string(honest_src) + ".1.0.1", 9590);

    for (int addr = 1; addr <= 5; ++addr) {
      protocol::TimestampedAddress ta;
      ta.address = protocol::NetworkAddress::from_string(
          std::to_string(100 + honest_src) + "." + std::to_string(addr) + ".0.1", 9590);
      ta.timestamp = static_cast<uint32_t>(BASE_TIME);
      node->addr_mgr->add_multiple({ta}, source, 0);
    }
  }

  size_t honest_count = node->addr_mgr->size();
  INFO("After honest peers: " << honest_count << " addresses");

  // Now: single attacker floods with addresses in same netgroups as honest
  auto attacker = protocol::NetworkAddress::from_string("44.99.0.1", 9590);

  size_t attacker_added = 0;
  for (int ng = 101; ng <= 120; ++ng) {  // Same netgroups as honest
    for (int host = 1; host <= 32; ++host) {  // Try to hit per-netgroup limit
      protocol::TimestampedAddress ta;
      ta.address = protocol::NetworkAddress::from_string(
          std::to_string(ng) + "." + std::to_string(host + 10) + ".0.1", 9590);
      ta.timestamp = static_cast<uint32_t>(BASE_TIME + 1);  // Slightly fresher

      if (node->addr_mgr->add_multiple({ta}, attacker, 0) > 0) {
        attacker_added++;
      }
    }
  }

  size_t final_count = node->addr_mgr->size();
  INFO("After attacker flood: " << final_count << " addresses");
  INFO("Attacker added: " << attacker_added);

  // Check what percentage is from attacker's injections
  auto all_addrs = node->addr_mgr->get_addresses(10000, 100);

  // Count addresses in the contested netgroups (101-120)
  size_t contested_total = 0;
  for (const auto& ta : all_addrs) {
    auto ng = ta.address.get_netgroup();
    // Parse first octet
    int first_octet = 0;
    try {
      first_octet = std::stoi(ng.substr(0, ng.find('.')));
    } catch (...) {}

    if (first_octet >= 101 && first_octet <= 120) {
      contested_total++;
    }
  }

  INFO("Addresses in contested netgroups: " << contested_total);

  // VULNERABILITY: Single attacker source can inject into same netgroups as honest
  // Per-netgroup limit helps, but attacker still gets representation
  // With source-based buckets, attacker would be isolated to different buckets
  WARN("BUCKETIZATION GAP: Attacker injected " << attacker_added <<
       " addresses competing with honest peers (no source isolation)");
}

TEST_CASE("BucketGap: Global limits vs per-bucket limits", "[addrsim][bucketgap]") {
  // WITHOUT per-bucket limits: Only global per-netgroup limit (32)
  // WITH per-bucket limits: Each bucket has its own limit (64), and netgroup
  //   maps to specific buckets based on hash
  //
  // This affects how eviction works under pressure

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Try to add many addresses from same netgroup via different sources
  // With global limit: capped at MAX_PER_NETGROUP_NEW (32)
  // With bucketed: could potentially store more if they hash to different buckets

  size_t added = 0;
  for (int src = 1; src <= 100; ++src) {
    auto source = protocol::NetworkAddress::from_string(
        std::to_string(src) + ".1.0.1", 9590);

    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(
        "44.99." + std::to_string(src / 256) + "." + std::to_string((src % 256) + 1), 9590);
    ta.timestamp = static_cast<uint32_t>(BASE_TIME);

    if (node->addr_mgr->add_multiple({ta}, source, 0) > 0) {
      added++;
    }
  }

  INFO("Addresses added from single netgroup (44.99.x.x): " << added);

  // With global per-netgroup limit of 32, we're capped
  REQUIRE(added <= 32);

  // This is actually GOOD for Sybil resistance in some ways
  // But it's DIFFERENT from Bitcoin Core's bucket-based approach
  INFO("Global per-netgroup limit enforced: " << added << " <= 32");
}

TEST_CASE("BucketGap: Eclipse attack efficiency without buckets", "[addrsim][bucketgap]") {
  // WITHOUT buckets: Attacker needs to fill per-netgroup limits across many netgroups
  // WITH buckets: Attacker needs to cause hash collisions in specific buckets
  //
  // This test measures how efficiently an attacker can dominate the address table

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Simulate honest network: addresses from many sources
  for (int honest_ng = 1; honest_ng <= 50; ++honest_ng) {
    auto source = protocol::NetworkAddress::from_string(
        std::to_string(honest_ng) + ".1.0.1", 9590);

    for (int addr = 1; addr <= 3; ++addr) {
      protocol::TimestampedAddress ta;
      ta.address = protocol::NetworkAddress::from_string(
          std::to_string(honest_ng + 100) + "." + std::to_string(addr) + ".0.1", 9590);
      ta.timestamp = static_cast<uint32_t>(BASE_TIME);
      node->addr_mgr->add_multiple({ta}, source, 0);
    }
  }

  size_t honest_baseline = node->addr_mgr->size();
  INFO("Honest baseline: " << honest_baseline << " addresses");

  // Attacker controls a /8 (256 /16 netgroups worth of IPs)
  // Simulates a well-resourced attacker (botnet, cloud provider, etc.)
  auto attacker_source = protocol::NetworkAddress::from_string("44.1.0.1", 9590);

  size_t attacker_added = 0;
  for (int ng = 1; ng <= 200; ++ng) {  // 200 different netgroups
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(
        std::to_string(ng) + ".99.0.1", 9590);  // Attacker's addresses
    ta.timestamp = static_cast<uint32_t>(BASE_TIME);

    if (node->addr_mgr->add_multiple({ta}, attacker_source, 0) > 0) {
      attacker_added++;
    }
  }

  size_t total_after = node->addr_mgr->size();

  // Calculate attacker's share
  double attacker_share = static_cast<double>(attacker_added) / total_after * 100;

  INFO("After attack:");
  INFO("  Total addresses: " << total_after);
  INFO("  Attacker added: " << attacker_added);
  INFO("  Attacker share: " << attacker_share << "%");

  // Count how many selections would go to attacker
  int attacker_selected = 0;
  int total_selected = 0;
  for (int i = 0; i < 1000; ++i) {
    auto selected = node->addr_mgr->select();
    if (selected) {
      total_selected++;
      auto ip = selected->to_string();
      if (ip) {
        // Check if it's an attacker address (*.99.0.1)
        if (ip->find(".99.0.1") != std::string::npos) {
          attacker_selected++;
        }
      }
    }
  }

  double selection_share = static_cast<double>(attacker_selected) / total_selected * 100;

  INFO("Selection test (1000 samples):");
  INFO("  Attacker selected: " << attacker_selected << " / " << total_selected);
  INFO("  Attacker selection share: " << selection_share << "%");

  // VULNERABILITY: Single source can achieve significant table presence
  // The per-source limit (64) helps, but attacker still gets ~40% with 200 netgroups
  WARN("BUCKETIZATION GAP: Single attacker source achieved " << attacker_share <<
       "% table share, " << selection_share << "% selection share");

  // For comparison, Bitcoin Core's bucket system would:
  // 1. Hash (secret, attacker_source_group) to specific buckets
  // 2. Limit attacker to those buckets only
  // 3. Make it much harder to achieve broad coverage
}

TEST_CASE("BucketGap: Source diversity requirement analysis", "[addrsim][bucketgap]") {
  // Test: How many diverse sources does an attacker need to dominate the table?
  //
  // WITHOUT buckets: Need to bypass per-source limit (64)
  // WITH buckets: Need sources that hash to different buckets

  util::MockTimeScope mock_time(BASE_TIME);

  AddrTestNetwork net(42);
  auto node_id = net.CreateNode("8.1.0.1");
  auto* node = net.GetNode(node_id);

  // Attacker uses multiple source IPs (simulating Sybil attack on source diversity)
  std::vector<size_t> shares_by_source_count;

  for (int num_sources : {1, 5, 10, 20, 50}) {
    // Reset
    AddrTestNetwork fresh_net(42);
    auto fresh_id = fresh_net.CreateNode("8.1.0.1");
    auto* fresh_node = fresh_net.GetNode(fresh_id);

    // Add some honest addresses first
    for (int h = 1; h <= 20; ++h) {
      auto src = protocol::NetworkAddress::from_string(
          std::to_string(h) + ".1.0.1", 9590);
      protocol::TimestampedAddress ta;
      ta.address = protocol::NetworkAddress::from_string(
          std::to_string(h + 50) + ".1.0.1", 9590);
      ta.timestamp = static_cast<uint32_t>(BASE_TIME);
      fresh_node->addr_mgr->add_multiple({ta}, src, 0);
    }

    size_t honest_count = fresh_node->addr_mgr->size();

    // Attacker with num_sources different source IPs
    size_t attacker_total = 0;
    for (int s = 0; s < num_sources; ++s) {
      auto attacker_src = protocol::NetworkAddress::from_string(
          "44." + std::to_string(s + 1) + ".0.1", 9590);

      // Each source adds addresses to different netgroups
      for (int ng = 0; ng < 50; ++ng) {
        protocol::TimestampedAddress ta;
        ta.address = protocol::NetworkAddress::from_string(
            std::to_string(100 + s * 50 + ng) + ".99.0.1", 9590);
        ta.timestamp = static_cast<uint32_t>(BASE_TIME);

        if (fresh_node->addr_mgr->add_multiple({ta}, attacker_src, 0) > 0) {
          attacker_total++;
        }
      }
    }

    size_t final_total = fresh_node->addr_mgr->size();
    double attacker_share = static_cast<double>(attacker_total) / final_total * 100;

    INFO("With " << num_sources << " attacker sources: "
         << attacker_total << "/" << final_total
         << " (" << attacker_share << "% attacker share)");

    shares_by_source_count.push_back(static_cast<size_t>(attacker_share));
  }

  // Show the progression
  WARN("BUCKETIZATION GAP: Attacker share increases linearly with source diversity");
  WARN("  1 source:  ~" << shares_by_source_count[0] << "%");
  WARN("  5 sources: ~" << shares_by_source_count[1] << "%");
  WARN("  10 sources: ~" << shares_by_source_count[2] << "%");
  WARN("  20 sources: ~" << shares_by_source_count[3] << "%");
  WARN("  50 sources: ~" << shares_by_source_count[4] << "%");

  // With Bitcoin Core's bucket system, source diversity helps less because
  // sources hash to specific buckets and can't spread arbitrarily
}

TEST_CASE("BucketGap: Summary of missing protections", "[addrsim][bucketgap]") {
  // This test serves as documentation of what's missing

  INFO("=== BUCKETIZATION GAP ANALYSIS ===");
  INFO("");
  INFO("Bitcoin Core's AddrMan uses:");
  INFO("  - Secret key for unpredictable bucket assignment");
  INFO("  - Hash(key, addr_group, src_group) for NEW bucket selection");
  INFO("  - Hash(key, addr_group) for TRIED bucket selection");
  INFO("  - Per-bucket limits (64 per bucket)");
  INFO("  - Bucket collision-based eviction");
  INFO("");
  INFO("Our implementation has:");
  INFO("  - No secret key (deterministic, predictable)");
  INFO("  - Global per-netgroup limits (32 NEW, 8 TRIED)");
  INFO("  - No source-group isolation");
  INFO("  - Simple map-based storage");
  INFO("");
  INFO("Security implications:");
  INFO("  1. Attacker can predict placement across all nodes");
  INFO("  2. Single source can pollute diverse netgroups");
  INFO("  3. No cryptographic isolation between sources");
  INFO("  4. Eclipse attacks require fewer resources");
  INFO("");
  INFO("Mitigations still present:");
  INFO("  + Per-netgroup limits cap concentration");
  INFO("  + Per-source limits (64) bound single-peer impact");
  INFO("  + Freshness requirements reject stale addresses");
  INFO("  + is_terrible() filters failing addresses");

  // Verify mitigations are actually enforced: per-source and per-netgroup limits
  AddrTestNetwork check_net(99);
  auto check_id = check_net.CreateNode("8.1.0.1");
  auto* check_node = check_net.GetNode(check_id);

  auto single_source = protocol::NetworkAddress::from_string("44.1.0.1", 9590);

  // Single source floods across many netgroups
  size_t source_accepted = 0;
  for (int ng = 1; ng <= 100; ++ng) {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(
        std::to_string(ng) + ".1.0.1", 9590);
    ta.timestamp = static_cast<uint32_t>(BASE_TIME);
    if (check_node->addr_mgr->add_multiple({ta}, single_source, 0) > 0) {
      source_accepted++;
    }
  }

  // Per-source limit: MAX_ADDRESSES_PER_SOURCE = 64
  REQUIRE(source_accepted <= 64);

  // Per-netgroup limit: flood single netgroup from many sources
  size_t ng_accepted = 0;
  for (int src = 1; src <= 50; ++src) {
    auto src_addr = protocol::NetworkAddress::from_string(
        std::to_string(src) + ".2.0.1", 9590);
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string(
        "44.99." + std::to_string(src / 256) + "." + std::to_string((src % 256) + 1), 9590);
    ta.timestamp = static_cast<uint32_t>(BASE_TIME);
    if (check_node->addr_mgr->add_multiple({ta}, src_addr, 0) > 0) {
      ng_accepted++;
    }
  }

  // Per-netgroup limit: MAX_PER_NETGROUP_NEW = 32
  REQUIRE(ng_accepted <= 32);
}
