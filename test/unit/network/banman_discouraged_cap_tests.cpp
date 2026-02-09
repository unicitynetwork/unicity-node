// Copyright (c) 2025 The Unicity Foundation
// Unit tests for ConnectionManager discouragement cap functionality

#include "catch_amalgamated.hpp"
#include "network/ban_manager.hpp"
#include "network/connection_manager.hpp"
#include "network/addr_manager.hpp"
#include <asio.hpp>
#include <vector>
#include <string>

using namespace unicity::network;

// Test fixture
class DiscouragementTestFixture {
public:
    asio::io_context io_context;

    std::unique_ptr<ConnectionManager> CreateConnectionManager() {
        // Phase 2: ConnectionManager no longer requires AddressManager at construction
        // DiscoveryManager injection not needed for these ban-focused unit tests
        return std::make_unique<ConnectionManager>(io_context);
    }
};

TEST_CASE("ConnectionManager - Discouragement Cap", "[network][peermgr][ban][unit]") {
    DiscouragementTestFixture fixture;
    auto pm = fixture.CreateConnectionManager();

    SECTION("Can discourage up to MAX_DISCOURAGED addresses") {
        // Discourage MAX_DISCOURAGED addresses
        for (size_t i = 0; i < BanManager::MAX_DISCOURAGED; ++i) {
            std::string addr = "10.0." + std::to_string(i / 256) + "." + std::to_string(i % 256);
            pm->Discourage(addr);
        }

        // Verify first few are discouraged
        REQUIRE(pm->IsDiscouraged("10.0.0.0"));
        REQUIRE(pm->IsDiscouraged("10.0.0.1"));
        REQUIRE(pm->IsDiscouraged("10.0.0.100"));

        // Note: Current implementation may or may not enforce MAX_DISCOURAGED cap
        // This test documents behavior with large numbers of discouragements
    }

    SECTION("SweepDiscouraged is no-op (no expiry)") {
        // Discourage a few addresses
        pm->Discourage("192.168.1.1");
        pm->Discourage("192.168.1.2");
        pm->Discourage("192.168.1.3");

        REQUIRE(pm->IsDiscouraged("192.168.1.1"));
        REQUIRE(pm->IsDiscouraged("192.168.1.2"));
        REQUIRE(pm->IsDiscouraged("192.168.1.3"));

        // SweepDiscouraged is now a no-op (Core parity - no expiry)
        pm->SweepDiscouraged();

        // Still discouraged (entries persist until evicted by capacity)
        REQUIRE(pm->IsDiscouraged("192.168.1.1"));
        REQUIRE(pm->IsDiscouraged("192.168.1.2"));
        REQUIRE(pm->IsDiscouraged("192.168.1.3"));
    }

    SECTION("ClearDiscouraged removes all discouragements") {
        // Discourage many addresses
        for (int i = 0; i < 100; ++i) {
            std::string addr = "10.0.0." + std::to_string(i);
            pm->Discourage(addr);
        }

        REQUIRE(pm->IsDiscouraged("10.0.0.0"));
        REQUIRE(pm->IsDiscouraged("10.0.0.50"));
        REQUIRE(pm->IsDiscouraged("10.0.0.99"));

        // Clear all
        pm->ClearDiscouraged();

        // All should be cleared
        REQUIRE_FALSE(pm->IsDiscouraged("10.0.0.0"));
        REQUIRE_FALSE(pm->IsDiscouraged("10.0.0.50"));
        REQUIRE_FALSE(pm->IsDiscouraged("10.0.0.99"));
    }
}

TEST_CASE("ConnectionManager - Discouragement Eviction at Capacity", "[network][peermgr][ban][unit][eviction][.]") {
    // Tests the eviction path in BanManager::Discourage() when exceeding MAX_DISCOURAGED (50000)
    // Tagged [.] because filling 50K entries is slow (~5s)
    DiscouragementTestFixture fixture;
    auto pm = fixture.CreateConnectionManager();

    SECTION("Exceeding MAX_DISCOURAGED triggers eviction of oldest insertion") {
        // Fill to capacity
        for (size_t i = 0; i < BanManager::MAX_DISCOURAGED; ++i) {
            std::string addr = "10.0." + std::to_string(i / 256) + "." + std::to_string(i % 256);
            pm->Discourage(addr);
        }

        // Verify at capacity
        REQUIRE(pm->IsDiscouraged("10.0.0.0"));  // First entry
        REQUIRE(pm->IsDiscouraged("10.0.195.79")); // Last entry (50000 - 1 = 49999 = 195*256 + 79)

        // Add one more - this should trigger eviction of oldest insertion
        // Since all entries were added in sequence, the first one (10.0.0.0) is oldest
        pm->Discourage("192.168.1.1");

        // New entry should be discouraged
        REQUIRE(pm->IsDiscouraged("192.168.1.1"));

        // The first entry (10.0.0.0) should have been evicted as it was oldest
        REQUIRE_FALSE(pm->IsDiscouraged("10.0.0.0"));

        // Other entries should still be present
        REQUIRE(pm->IsDiscouraged("10.0.0.1"));  // Second entry still there
        REQUIRE(pm->IsDiscouraged("10.0.195.79")); // Last original entry still there
    }

    SECTION("Multiple insertions beyond capacity maintain cap") {
        // Fill to capacity
        for (size_t i = 0; i < BanManager::MAX_DISCOURAGED; ++i) {
            std::string addr = "10.0." + std::to_string(i / 256) + "." + std::to_string(i % 256);
            pm->Discourage(addr);
        }

        // Add 10 more entries
        for (int i = 0; i < 10; ++i) {
            std::string addr = "192.168.1." + std::to_string(i);
            pm->Discourage(addr);
        }

        // All new entries should be discouraged
        for (int i = 0; i < 10; ++i) {
            std::string addr = "192.168.1." + std::to_string(i);
            REQUIRE(pm->IsDiscouraged(addr));
        }

        // Verify that most original entries still exist (cap is maintained, not cleared)
        // Oldest entries (first 10 added) should be evicted
        int still_present = 0;
        for (size_t i = 0; i < BanManager::MAX_DISCOURAGED; i += 1000) {
            std::string addr = "10.0." + std::to_string(i / 256) + "." + std::to_string(i % 256);
            if (pm->IsDiscouraged(addr)) {
                still_present++;
            }
        }
        // Most sampled entries should still be present (only 10 evicted out of 50000)
        // Sampling every 1000 out of 50000 = 50 samples, 10 evicted = at least 40 present
        REQUIRE(still_present >= 40);
    }
}

TEST_CASE("ConnectionManager - Discouragement vs Bans", "[network][peermgr][ban][unit]") {
    DiscouragementTestFixture fixture;
    auto pm = fixture.CreateConnectionManager();

    SECTION("Discouraged and banned are independent") {
        // Discourage an address
        pm->Discourage("192.168.1.1");
        REQUIRE(pm->IsDiscouraged("192.168.1.1"));
        REQUIRE_FALSE(pm->IsBanned("192.168.1.1"));

        // Ban a different address
        pm->Ban("192.168.1.2", 3600);
        REQUIRE(pm->IsBanned("192.168.1.2"));
        REQUIRE_FALSE(pm->IsDiscouraged("192.168.1.2"));

        // Can have both on same address
        pm->Ban("192.168.1.3", 3600);
        pm->Discourage("192.168.1.3");
        REQUIRE(pm->IsBanned("192.168.1.3"));
        REQUIRE(pm->IsDiscouraged("192.168.1.3"));
    }

    SECTION("Clearing discouraged doesn't affect bans") {
        pm->Ban("192.168.1.1", 3600);
        pm->Discourage("192.168.1.1");

        REQUIRE(pm->IsBanned("192.168.1.1"));
        REQUIRE(pm->IsDiscouraged("192.168.1.1"));

        pm->ClearDiscouraged();

        // Ban persists, discouragement cleared
        REQUIRE(pm->IsBanned("192.168.1.1"));
        REQUIRE_FALSE(pm->IsDiscouraged("192.168.1.1"));
    }

    SECTION("Clearing bans doesn't affect discouragement") {
        pm->Ban("192.168.1.1", 3600);
        pm->Discourage("192.168.1.1");

        REQUIRE(pm->IsBanned("192.168.1.1"));
        REQUIRE(pm->IsDiscouraged("192.168.1.1"));

        pm->ClearBanned();

        // Discouragement persists, ban cleared
        REQUIRE_FALSE(pm->IsBanned("192.168.1.1"));
        REQUIRE(pm->IsDiscouraged("192.168.1.1"));
    }
}
