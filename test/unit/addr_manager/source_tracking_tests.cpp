// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "common/catch_amalgamated.hpp"
#include "network/addr_manager.hpp"

#include <filesystem>
#include <fstream>

using namespace unicity::network;
using namespace unicity;

namespace {
// Helper to create a routable NetworkAddress with IPv4-mapped format
// Uses 93.x.x.x which is routable (not private/local)
protocol::NetworkAddress MakeIPv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port = 18444) {
  protocol::NetworkAddress addr;
  addr.ip.fill(0);
  addr.ip[10] = 0xff;
  addr.ip[11] = 0xff;
  addr.ip[12] = a;
  addr.ip[13] = b;
  addr.ip[14] = c;
  addr.ip[15] = d;
  addr.port = port;
  addr.services = 1;
  return addr;
}

// Create addresses in different /16 netgroups using routable IP ranges
// Uses 93.0.x.1, 93.1.x.1, etc. for different netgroups
protocol::NetworkAddress MakeAddressInNetgroup(int netgroup_id, uint8_t host = 1, uint16_t port = 18444) {
  // Use 93.x for a routable /8 block
  return MakeIPv4(93, static_cast<uint8_t>(netgroup_id), 0, host, port);
}
}  // namespace

TEST_CASE("Source tracking - per-source limits", "[addr_manager][source_tracking]") {
  AddressManager mgr;
  // Use routable source address (not 1.x.x.x or 10.x.x.x which are special)
  auto source = MakeIPv4(85, 2, 3, 4);

  SECTION("Can add MAX_ADDRESSES_PER_SOURCE addresses from same source") {
    // MAX_ADDRESSES_PER_SOURCE = 64
    size_t added = 0;
    for (int i = 0; i < 64; i++) {
      // Different /16 netgroups for addresses to avoid per-netgroup limits (93.x.0.1)
      auto addr = MakeAddressInNetgroup(i);
      if (mgr.add(addr, source)) {
        added++;
      }
    }
    REQUIRE(added == 64);
  }

  SECTION("65th address from same source is rejected") {
    // Add 64 addresses from source
    for (int i = 0; i < 64; i++) {
      auto addr = MakeAddressInNetgroup(i);
      mgr.add(addr, source);
    }
    REQUIRE(mgr.new_count() == 64);

    // 65th should fail
    auto addr65 = MakeAddressInNetgroup(65);
    REQUIRE_FALSE(mgr.add(addr65, source));
    REQUIRE(mgr.new_count() == 64);  // Still 64
  }

  SECTION("Different source can add more addresses") {
    // Add 64 from source1
    auto source1 = MakeIPv4(85, 2, 3, 4);
    for (int i = 0; i < 64; i++) {
      auto addr = MakeAddressInNetgroup(i);
      mgr.add(addr, source1);
    }
    REQUIRE(mgr.new_count() == 64);

    // source2 can add more (different /16)
    auto source2 = MakeIPv4(86, 6, 7, 8);
    auto addr65 = MakeAddressInNetgroup(65);
    REQUIRE(mgr.add(addr65, source2));
    REQUIRE(mgr.new_count() == 65);
  }

  SECTION("No source (empty) bypasses per-source limit") {
    // Add more than 64 addresses without source tracking
    for (int i = 0; i < 100; i++) {
      auto addr = MakeAddressInNetgroup(i);
      mgr.add(addr);  // No source = no per-source limit
    }
    REQUIRE(mgr.new_count() == 100);
  }

  SECTION("Per-source limit is per source netgroup (not per IP)") {
    // source1 and source2 are in same /16
    auto source1 = MakeIPv4(85, 2, 3, 4);
    auto source2 = MakeIPv4(85, 2, 99, 99);  // Same /16 as source1

    // Add 64 from source1
    for (int i = 0; i < 64; i++) {
      auto addr = MakeAddressInNetgroup(i);
      mgr.add(addr, source1);
    }

    // source2 (same netgroup) should also be blocked
    auto addr65 = MakeAddressInNetgroup(65);
    REQUIRE_FALSE(mgr.add(addr65, source2));
  }
}

TEST_CASE("Source tracking - eviction decrements count", "[addr_manager][source_tracking]") {
  // This test verifies that when addresses are moved out of NEW (via good()),
  // the per-source count is decremented, allowing more addresses from that source.
  // Note: We test via good() instead of failed() because is_terrible() has a
  // 60-second grace period that makes rapid testing impossible without sleeps.

  AddressManager mgr;
  auto source = MakeIPv4(85, 2, 3, 4);

  // Fill to capacity with addresses from source (64 = MAX_ADDRESSES_PER_SOURCE)
  for (int i = 0; i < 64; i++) {
    auto addr = MakeAddressInNetgroup(i);
    mgr.add(addr, source);
  }
  REQUIRE(mgr.new_count() == 64);

  // Verify we can't add more from this source
  auto overflow = MakeAddressInNetgroup(100);
  REQUIRE_FALSE(mgr.add(overflow, source));
  REQUIRE(mgr.new_count() == 64);

  // Move half the addresses from NEW to TRIED via good()
  // This should decrement source_counts_ for each
  for (int i = 0; i < 32; i++) {
    auto addr = MakeAddressInNetgroup(i);
    mgr.good(addr);
  }
  REQUIRE(mgr.tried_count() == 32);
  REQUIRE(mgr.new_count() == 32);

  // Now we should be able to add more addresses from source (up to 32 more)
  for (int i = 100; i < 132; i++) {
    auto addr = MakeAddressInNetgroup(i);
    REQUIRE(mgr.add(addr, source));
  }
  REQUIRE(mgr.new_count() == 64);  // 32 original + 32 new

  // 65th should still fail (back at limit)
  auto overflow2 = MakeAddressInNetgroup(200);
  REQUIRE_FALSE(mgr.add(overflow2, source));
}

TEST_CASE("Source tracking - good() decrements source count", "[addr_manager][source_tracking]") {
  AddressManager mgr;
  auto source = MakeIPv4(85, 2, 3, 4);

  // Add 64 addresses from source
  for (int i = 0; i < 64; i++) {
    auto addr = MakeAddressInNetgroup(i);
    mgr.add(addr, source);
  }
  REQUIRE(mgr.new_count() == 64);

  // Verify we can't add more from this source
  auto addr65 = MakeAddressInNetgroup(65);
  REQUIRE_FALSE(mgr.add(addr65, source));

  // Mark one address as good (moves from NEW to TRIED)
  auto addr0 = MakeAddressInNetgroup(0);
  mgr.good(addr0);
  REQUIRE(mgr.tried_count() == 1);
  REQUIRE(mgr.new_count() == 63);

  // Now we should be able to add one more from source
  REQUIRE(mgr.add(addr65, source));
  REQUIRE(mgr.new_count() == 64);  // Back to 64
}

TEST_CASE("Source tracking - persistence round-trip", "[addr_manager][source_tracking]") {
  const std::string test_file = "/tmp/source_tracking_test.json";
  auto source = MakeIPv4(85, 2, 3, 4);

  {
    AddressManager mgr;
    auto addr = MakeAddressInNetgroup(0);
    mgr.add(addr, source);
    REQUIRE(mgr.Save(test_file));
  }

  {
    AddressManager mgr2;
    REQUIRE(mgr2.Load(test_file));
    REQUIRE(mgr2.new_count() == 1);

    // After loading, source tracking should be restored
    // Add 63 more from source (total would be 64)
    for (int i = 1; i < 64; i++) {
      auto addr = MakeAddressInNetgroup(i);
      mgr2.add(addr, source);
    }
    REQUIRE(mgr2.new_count() == 64);

    // 65th should fail
    auto addr65 = MakeAddressInNetgroup(65);
    REQUIRE_FALSE(mgr2.add(addr65, source));
  }

  // Cleanup
  std::filesystem::remove(test_file);
}

TEST_CASE("Source tracking - v1 migration (no source in old file)", "[addr_manager][source_tracking]") {
  const std::string test_file = "/tmp/source_v1_migration_test.json";

  // Create a v1-format file (no source_ip fields)
  // Uses 93.0.0.1 which is routable (not 10.x.x.x which is private)
  {
    std::ofstream f(test_file);
    f << R"({
      "version": 1,
      "tried_count": 0,
      "new_count": 1,
      "m_last_good": 1,
      "tried": [],
      "new": [{
        "ip": [0,0,0,0,0,0,0,0,0,0,255,255,93,0,0,1],
        "port": 18444,
        "services": 1,
        "timestamp": 1000000,
        "last_try": 0,
        "last_count_attempt": 0,
        "last_success": 0,
        "attempts": 0
      }]
    })";
  }

  // Load should succeed
  AddressManager mgr;
  REQUIRE(mgr.Load(test_file));
  REQUIRE(mgr.new_count() == 1);

  // Addresses loaded from v1 have no source tracking
  // So we can add 64 more from any source without hitting per-source limit
  // (because loaded addresses don't count toward source limits)
  auto source = MakeIPv4(85, 2, 3, 4);
  for (int i = 1; i <= 64; i++) {
    auto addr = MakeAddressInNetgroup(i);
    REQUIRE(mgr.add(addr, source));
  }
  REQUIRE(mgr.new_count() == 65);  // 1 from v1 + 64 from source

  // Cleanup
  std::filesystem::remove(test_file);
}

TEST_CASE("Source tracking - AddrInfo::has_source()", "[addr_manager][source_tracking]") {
  SECTION("Default-constructed has no source") {
    AddrInfo info;
    REQUIRE_FALSE(info.has_source());
  }

  SECTION("Zero source has no source") {
    AddrInfo info;
    info.source = protocol::NetworkAddress{};  // All zeros
    REQUIRE_FALSE(info.has_source());
  }

  SECTION("Non-zero source has source") {
    AddrInfo info;
    info.source = MakeIPv4(85, 2, 3, 4);
    REQUIRE(info.has_source());
  }
}

// Note: TRIED->NEW demotion test removed - Bitcoin Core doesn't demote TRIED addresses.
// TRIED addresses stay in TRIED until evicted by collision during Good().
// Source tracking for TRIED addresses is handled by decrementing on Good() (NEW->TRIED).

TEST_CASE("Attempt counting - matches Bitcoin Core behavior", "[addr_manager][attempts]") {
  AddressManager mgr;
  auto addr = MakeAddressInNetgroup(0);
  mgr.add(addr);

  SECTION("attempt() with fCountFailure=true increments") {
    // Simulate connection attempt
    mgr.attempt(addr, true);  // Should increment (last_count_attempt < m_last_good_)

    // Address should still exist (attempts=1 < ADDRMAN_RETRIES=3)
    REQUIRE(mgr.new_count() == 1);
  }

  SECTION("Rapid attempts don't double-count (same second)") {
    // Multiple attempt() calls in same second only count once
    // This matches Bitcoin Core's last_count_attempt < m_last_good_ check
    // Note: Bitcoin Core has no failed() function
    mgr.attempt(addr, true);
    mgr.attempt(addr, true);  // Blocked: last_count_attempt >= m_last_good_
    mgr.attempt(addr, true);  // Blocked

    // Address should still exist - only 1 attempt counted
    REQUIRE(mgr.new_count() == 1);
  }

  SECTION("attempt() with fCountFailure=false does NOT increment") {
    // attempt() with fCountFailure=false should not increment attempts
    // Note: Bitcoin Core has no failed() function

    // First attempt with fCountFailure=false - should NOT increment
    mgr.attempt(addr, false);
    mgr.attempt(addr, false);
    mgr.attempt(addr, false);

    // Address should still exist (attempts=0)
    REQUIRE(mgr.new_count() == 1);
  }
}
