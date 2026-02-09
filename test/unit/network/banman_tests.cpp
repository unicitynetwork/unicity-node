// Copyright (c) 2025 The Unicity Foundation
// Unit tests for ConnectionManager ban functionality
// Focuses on persistence, expiration, and core operations

#include "catch_amalgamated.hpp"
#include "network/connection_manager.hpp"
#include "network/addr_manager.hpp"
#include <asio.hpp>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include "util/time.hpp"
#include <chrono>
#include <thread>

using namespace unicity::network;
using json = nlohmann::json;

// Test fixture to manage temporary directories and ConnectionManager dependencies
class BanTestFixture {
public:
    std::string test_dir;
    asio::io_context io_context;

    BanTestFixture() {
        // Create unique test directory
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        test_dir = "/tmp/peermgr_ban_test_" + std::to_string(now);
        std::filesystem::create_directory(test_dir);
    }

    ~BanTestFixture() {
        // Clean up test directory
        std::filesystem::remove_all(test_dir);
    }

    std::string GetBanlistPath() const {
        return test_dir + "/banlist.json";
    }

    // Helper to create a ConnectionManager for testing ban functionality
    std::unique_ptr<ConnectionManager> CreateConnectionManager(const std::string& datadir = "") {
        // Phase 2: ConnectionManager no longer requires AddressManager at construction
        auto pm = std::make_unique<ConnectionManager>(io_context);
        if (!datadir.empty()) {
            pm->LoadBans(datadir);
        }
        return pm;
    }
};

TEST_CASE("ConnectionManager - Basic Ban Operations", "[network][peermgr][ban][unit]") {
    BanTestFixture fixture;
    auto pm = fixture.CreateConnectionManager();

    SECTION("Ban and check") {
        REQUIRE_FALSE(pm->IsBanned("192.168.1.1"));

        pm->Ban("192.168.1.1", 3600);
        REQUIRE(pm->IsBanned("192.168.1.1"));

        // Different address not banned
        REQUIRE_FALSE(pm->IsBanned("192.168.1.2"));
    }

    SECTION("Unban") {
        pm->Ban("192.168.1.1", 3600);
        REQUIRE(pm->IsBanned("192.168.1.1"));

        pm->Unban("192.168.1.1");
        REQUIRE_FALSE(pm->IsBanned("192.168.1.1"));
    }

    SECTION("Get banned list") {
        pm->Ban("192.168.1.1", 3600);
        pm->Ban("192.168.1.2", 7200);

        auto banned = pm->GetBanned();
        REQUIRE(banned.size() == 2);
        REQUIRE(banned.find("192.168.1.1") != banned.end());
        REQUIRE(banned.find("192.168.1.2") != banned.end());
    }

    SECTION("Clear all bans") {
        pm->Ban("192.168.1.1", 3600);
        pm->Ban("192.168.1.2", 3600);
        pm->Ban("192.168.1.3", 3600);

        REQUIRE(pm->GetBanned().size() == 3);

        pm->ClearBanned();

        REQUIRE(pm->GetBanned().size() == 0);
        REQUIRE_FALSE(pm->IsBanned("192.168.1.1"));
        REQUIRE_FALSE(pm->IsBanned("192.168.1.2"));
        REQUIRE_FALSE(pm->IsBanned("192.168.1.3"));
    }
}

TEST_CASE("ConnectionManager - Discouragement", "[network][peermgr][ban][unit]") {
    BanTestFixture fixture;
    auto pm = fixture.CreateConnectionManager();

    SECTION("Discourage and check") {
        REQUIRE_FALSE(pm->IsDiscouraged("192.168.1.1"));

        pm->Discourage("192.168.1.1");
        REQUIRE(pm->IsDiscouraged("192.168.1.1"));

        // Different address not discouraged
        REQUIRE_FALSE(pm->IsDiscouraged("192.168.1.2"));
    }

    SECTION("Clear discouraged") {
        pm->Discourage("192.168.1.1");
        pm->Discourage("192.168.1.2");

        REQUIRE(pm->IsDiscouraged("192.168.1.1"));
        REQUIRE(pm->IsDiscouraged("192.168.1.2"));

        pm->ClearDiscouraged();

        REQUIRE_FALSE(pm->IsDiscouraged("192.168.1.1"));
        REQUIRE_FALSE(pm->IsDiscouraged("192.168.1.2"));
    }
}

TEST_CASE("ConnectionManager - Default Ban Time", "[network][peermgr][ban][unit]") {
    BanTestFixture fixture;
    auto pm = fixture.CreateConnectionManager();

    SECTION("ban_time_offset = 0 uses default 24h ban (matches Bitcoin Core)") {
        int64_t now = unicity::util::GetTime();
        pm->Ban("192.168.1.1", 0);  // 0 = use default (24h)
        REQUIRE(pm->IsBanned("192.168.1.1"));

        auto banned = pm->GetBanned();
        REQUIRE(banned.size() == 1);
        // Should be ~24h from now, not 0 (permanent)
        int64_t expected_ban_until = now + BanManager::DEFAULT_BAN_TIME_SEC;
        // Allow 5 seconds tolerance for timing
        REQUIRE(banned["192.168.1.1"].ban_until >= expected_ban_until - 5);
        REQUIRE(banned["192.168.1.1"].ban_until <= expected_ban_until + 5);
    }

    SECTION("ban_time_offset < 0 also uses default 24h ban") {
        int64_t now = unicity::util::GetTime();
        pm->Ban("192.168.1.1", -100);  // Negative = use default (24h)
        REQUIRE(pm->IsBanned("192.168.1.1"));

        auto banned = pm->GetBanned();
        int64_t expected_ban_until = now + BanManager::DEFAULT_BAN_TIME_SEC;
        REQUIRE(banned["192.168.1.1"].ban_until >= expected_ban_until - 5);
        REQUIRE(banned["192.168.1.1"].ban_until <= expected_ban_until + 5);
    }
}

TEST_CASE("ConnectionManager - Ban Expiration", "[network][peermgr][ban][unit]") {
    BanTestFixture fixture;
    auto pm = fixture.CreateConnectionManager();

    SECTION("Ban expires after time passes") {
        // Ban for 1 second
        pm->Ban("192.168.1.1", 1);
        REQUIRE(pm->IsBanned("192.168.1.1"));

        // Advance mock time by 2 seconds instead of sleeping
        {
            unicity::util::MockTimeScope mt(unicity::util::GetTime() + 2);
            // Sweep expired bans under advanced time
            pm->SweepBanned();
            // Should no longer be banned
            REQUIRE_FALSE(pm->IsBanned("192.168.1.1"));
        }
    }
}

TEST_CASE("ConnectionManager - Ban Persistence", "[network][peermgr][ban][persistence]") {
    BanTestFixture fixture;

    SECTION("Save and load bans") {
        {
            auto pm = fixture.CreateConnectionManager(fixture.test_dir);
            pm->Ban("192.168.1.1", 86400);  // 24h
            pm->Ban("192.168.1.2", 3600);   // 1h
            pm->Ban("192.168.1.3", 86400);  // 24h

            REQUIRE(pm->IsBanned("192.168.1.1"));
            REQUIRE(pm->IsBanned("192.168.1.2"));
            REQUIRE(pm->IsBanned("192.168.1.3"));

            // Save bans to disk
            REQUIRE(pm->SaveBans());
        }

        // Create new ConnectionManager and load bans
        {
            auto pm = fixture.CreateConnectionManager(fixture.test_dir);

            REQUIRE(pm->IsBanned("192.168.1.1"));
            REQUIRE(pm->IsBanned("192.168.1.2"));
            REQUIRE(pm->IsBanned("192.168.1.3"));

            auto bans = pm->GetBanned();
            REQUIRE(bans.size() == 3);
        }
    }

    SECTION("Unban persists correctly") {
        {
            auto pm = fixture.CreateConnectionManager(fixture.test_dir);
            pm->Ban("192.168.1.1", 86400);
            pm->Ban("192.168.1.2", 86400);
            pm->Ban("192.168.1.3", 86400);
            pm->Unban("192.168.1.2");

            REQUIRE(pm->IsBanned("192.168.1.1"));
            REQUIRE_FALSE(pm->IsBanned("192.168.1.2"));
            REQUIRE(pm->IsBanned("192.168.1.3"));

            REQUIRE(pm->SaveBans());
        }

        {
            auto pm = fixture.CreateConnectionManager(fixture.test_dir);

            REQUIRE(pm->IsBanned("192.168.1.1"));
            REQUIRE_FALSE(pm->IsBanned("192.168.1.2"));
            REQUIRE(pm->IsBanned("192.168.1.3"));
        }
    }
}

TEST_CASE("ConnectionManager - Ban Extension Logic (Core Parity)", "[network][peermgr][ban][unit]") {
    BanTestFixture fixture;
    auto pm = fixture.CreateConnectionManager();

    SECTION("Re-banning with longer duration extends the ban") {
        int64_t now = unicity::util::GetTime();

        // Initial ban for 1 hour
        pm->Ban("192.168.1.1", 3600);
        auto banned = pm->GetBanned();
        int64_t original_ban_until = banned["192.168.1.1"].ban_until;
        REQUIRE(original_ban_until >= now + 3600 - 5);
        REQUIRE(original_ban_until <= now + 3600 + 5);

        // Re-ban for 24 hours - should extend the ban
        pm->Ban("192.168.1.1", 86400);
        banned = pm->GetBanned();
        int64_t extended_ban_until = banned["192.168.1.1"].ban_until;

        // Ban should now be ~24 hours from now
        REQUIRE(extended_ban_until >= now + 86400 - 5);
        REQUIRE(extended_ban_until <= now + 86400 + 5);
        REQUIRE(extended_ban_until > original_ban_until);
    }

    SECTION("Re-banning with shorter duration does NOT shorten the ban (Core parity)") {
        int64_t now = unicity::util::GetTime();

        // Initial ban for 24 hours
        pm->Ban("192.168.1.1", 86400);
        auto banned = pm->GetBanned();
        int64_t original_ban_until = banned["192.168.1.1"].ban_until;
        REQUIRE(original_ban_until >= now + 86400 - 5);

        // Try to re-ban for only 1 hour - should NOT shorten
        pm->Ban("192.168.1.1", 3600);
        banned = pm->GetBanned();
        int64_t current_ban_until = banned["192.168.1.1"].ban_until;

        // Ban should still be ~24 hours (not shortened to 1 hour)
        REQUIRE(current_ban_until == original_ban_until);
    }

    SECTION("Re-banning with equal duration does not change the ban") {
        int64_t now = unicity::util::GetTime();

        // Initial ban for 1 hour
        pm->Ban("192.168.1.1", 3600);
        auto banned = pm->GetBanned();
        int64_t original_ban_until = banned["192.168.1.1"].ban_until;

        // Re-ban for same duration - should not change
        pm->Ban("192.168.1.1", 3600);
        banned = pm->GetBanned();
        int64_t current_ban_until = banned["192.168.1.1"].ban_until;

        // Allow small tolerance since time may have advanced slightly
        REQUIRE(current_ban_until >= original_ban_until);
        REQUIRE(current_ban_until <= original_ban_until + 2);
    }
}
