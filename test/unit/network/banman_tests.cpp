// Copyright (c) 2025 The Unicity Foundation
// Unit tests for ConnectionManager ban functionality
// Focuses on persistence, expiration, and core operations

#include "catch_amalgamated.hpp"
#include "network/peer_lifecycle_manager.hpp"
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
    std::unique_ptr<PeerLifecycleManager> CreatePeerLifecycleManager(const std::string& datadir = "") {
        // Phase 2: ConnectionManager no longer requires AddressManager at construction
        auto pm = std::make_unique<PeerLifecycleManager>(io_context);
        if (!datadir.empty()) {
            pm->LoadBans(datadir);
        }
        return pm;
    }
};

TEST_CASE("ConnectionManager - Basic Ban Operations", "[network][peermgr][ban][unit]") {
    BanTestFixture fixture;
    auto pm = fixture.CreatePeerLifecycleManager();

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
    auto pm = fixture.CreatePeerLifecycleManager();

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

TEST_CASE("ConnectionManager - Permanent Bans", "[network][peermgr][ban][unit]") {
    BanTestFixture fixture;
    auto pm = fixture.CreatePeerLifecycleManager();

    SECTION("Permanent ban (ban_time_offset = 0)") {
        pm->Ban("192.168.1.1", 0);  // 0 = permanent
        REQUIRE(pm->IsBanned("192.168.1.1"));

        auto banned = pm->GetBanned();
        REQUIRE(banned.size() == 1);
        REQUIRE(banned["192.168.1.1"].nBanUntil == 0);  // 0 means permanent
    }
}

TEST_CASE("ConnectionManager - Ban Expiration", "[network][peermgr][ban][unit]") {
    BanTestFixture fixture;
    auto pm = fixture.CreatePeerLifecycleManager();

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
            auto pm = fixture.CreatePeerLifecycleManager(fixture.test_dir);
            pm->Ban("192.168.1.1", 0);  // Permanent
            pm->Ban("192.168.1.2", 3600);
            pm->Ban("192.168.1.3", 0);  // Permanent

            REQUIRE(pm->IsBanned("192.168.1.1"));
            REQUIRE(pm->IsBanned("192.168.1.2"));
            REQUIRE(pm->IsBanned("192.168.1.3"));

            // Save bans to disk
            REQUIRE(pm->SaveBans());
        }

        // Create new ConnectionManager and load bans
        {
            auto pm = fixture.CreatePeerLifecycleManager(fixture.test_dir);

            REQUIRE(pm->IsBanned("192.168.1.1"));
            REQUIRE(pm->IsBanned("192.168.1.2"));
            REQUIRE(pm->IsBanned("192.168.1.3"));

            auto bans = pm->GetBanned();
            REQUIRE(bans.size() == 3);
        }
    }

    SECTION("Unban persists correctly") {
        {
            auto pm = fixture.CreatePeerLifecycleManager(fixture.test_dir);
            pm->Ban("192.168.1.1", 0);
            pm->Ban("192.168.1.2", 0);
            pm->Ban("192.168.1.3", 0);
            pm->Unban("192.168.1.2");

            REQUIRE(pm->IsBanned("192.168.1.1"));
            REQUIRE_FALSE(pm->IsBanned("192.168.1.2"));
            REQUIRE(pm->IsBanned("192.168.1.3"));

            REQUIRE(pm->SaveBans());
        }

        {
            auto pm = fixture.CreatePeerLifecycleManager(fixture.test_dir);

            REQUIRE(pm->IsBanned("192.168.1.1"));
            REQUIRE_FALSE(pm->IsBanned("192.168.1.2"));
            REQUIRE(pm->IsBanned("192.168.1.3"));
        }
    }
}

TEST_CASE("ConnectionManager - Whitelist (NoBan)", "[network][peermgr][ban][unit]") {
    BanTestFixture fixture;
    auto pm = fixture.CreatePeerLifecycleManager();

    SECTION("Whitelisted address can be banned (like Bitcoin Core)") {
        pm->AddToWhitelist("192.168.1.1");
        REQUIRE(pm->IsWhitelisted("192.168.1.1"));

        // Can ban whitelisted address (ban and whitelist are independent)
        pm->Ban("192.168.1.1", 3600);
        REQUIRE(pm->IsBanned("192.168.1.1"));

        // Both states coexist
        REQUIRE(pm->IsWhitelisted("192.168.1.1"));
        REQUIRE(pm->IsBanned("192.168.1.1"));

        // Note: Whitelist is checked at connection time, not ban time
        // This matches Bitcoin Core behavior where ban/whitelist are independent
    }

    SECTION("Remove from whitelist") {
        pm->AddToWhitelist("192.168.1.1");
        REQUIRE(pm->IsWhitelisted("192.168.1.1"));

        pm->RemoveFromWhitelist("192.168.1.1");
        REQUIRE_FALSE(pm->IsWhitelisted("192.168.1.1"));
    }
}
