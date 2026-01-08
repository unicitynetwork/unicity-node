// Copyright (c) 2025 The Unicity Foundation
// Unit tests for ConnectionManager whitelist (NoBan) functionality

#include "catch_amalgamated.hpp"
#include "network/peer_lifecycle_manager.hpp"
#include "network/addr_manager.hpp"
#include <asio.hpp>
#include <filesystem>
#include <thread>

using namespace unicity::network;

// Test fixture
class WhitelistTestFixture {
public:
    asio::io_context io_context;
    std::string test_dir;

    WhitelistTestFixture() {
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        test_dir = "/tmp/peermgr_whitelist_test_" + std::to_string(now);
        std::filesystem::create_directory(test_dir);
    }

    ~WhitelistTestFixture() {
        std::filesystem::remove_all(test_dir);
    }

    std::unique_ptr<PeerLifecycleManager> CreatePeerLifecycleManager(const std::string& datadir = "") {
        // Phase 2: ConnectionManager no longer requires AddressManager at construction
        auto pm = std::make_unique<PeerLifecycleManager>(io_context);
        if (!datadir.empty()) {
            pm->LoadBans(datadir);
        }
        return pm;
    }
};

TEST_CASE("ConnectionManager - Localhost not whitelisted by default", "[network][peermgr][whitelist][unit]") {
    WhitelistTestFixture fixture;
    auto pm = fixture.CreatePeerLifecycleManager();

    // By default, localhost is NOT whitelisted; banning should work
    pm->Ban("127.0.0.1", 3600);
    CHECK(pm->IsBanned("127.0.0.1"));

    // ::1 behaves the same
    pm->Ban("::1", 3600);
    CHECK(pm->IsBanned("::1"));
}

TEST_CASE("ConnectionManager - Whitelist operations", "[network][peermgr][whitelist][unit]") {
    WhitelistTestFixture fixture;
    auto pm = fixture.CreatePeerLifecycleManager();

    SECTION("Add to whitelist") {
        REQUIRE_FALSE(pm->IsWhitelisted("10.0.0.1"));

        pm->AddToWhitelist("10.0.0.1");
        REQUIRE(pm->IsWhitelisted("10.0.0.1"));

        // Different address not whitelisted
        REQUIRE_FALSE(pm->IsWhitelisted("10.0.0.2"));
    }

    SECTION("Remove from whitelist") {
        pm->AddToWhitelist("10.0.0.1");
        REQUIRE(pm->IsWhitelisted("10.0.0.1"));

        pm->RemoveFromWhitelist("10.0.0.1");
        REQUIRE_FALSE(pm->IsWhitelisted("10.0.0.1"));
    }
}

TEST_CASE("ConnectionManager - Whitelist interaction with bans", "[network][peermgr][whitelist][unit]") {
    WhitelistTestFixture fixture;
    auto pm = fixture.CreatePeerLifecycleManager();

    SECTION("Ban and whitelist are independent (can coexist)") {
        // Add to whitelist first
        pm->AddToWhitelist("10.0.0.1");
        REQUIRE(pm->IsWhitelisted("10.0.0.1"));

        // Can still ban (like Bitcoin Core)
        pm->Ban("10.0.0.1", 3600);
        REQUIRE(pm->IsBanned("10.0.0.1"));

        // Both states coexist
        REQUIRE(pm->IsWhitelisted("10.0.0.1"));
        REQUIRE(pm->IsBanned("10.0.0.1"));

        // Note: Whitelist is checked at connection time, not at ban time
        // This allows banning whitelisted addresses if needed
    }

    SECTION("Discourage and whitelist are independent") {
        pm->AddToWhitelist("10.0.0.1");
        REQUIRE(pm->IsWhitelisted("10.0.0.1"));

        pm->Discourage("10.0.0.1");
        REQUIRE(pm->IsDiscouraged("10.0.0.1"));

        // Both states coexist
        REQUIRE(pm->IsWhitelisted("10.0.0.1"));
        REQUIRE(pm->IsDiscouraged("10.0.0.1"));
    }

    SECTION("Whitelisting after ban preserves ban") {
        // Ban first
        pm->Ban("10.0.0.1", 3600);
        REQUIRE(pm->IsBanned("10.0.0.1"));

        // Whitelist doesn't remove the ban
        pm->AddToWhitelist("10.0.0.1");
        REQUIRE(pm->IsWhitelisted("10.0.0.1"));
        REQUIRE(pm->IsBanned("10.0.0.1"));
    }

    SECTION("Unbanning doesn't affect whitelist") {
        pm->AddToWhitelist("10.0.0.1");
        pm->Ban("10.0.0.1", 3600);

        REQUIRE(pm->IsWhitelisted("10.0.0.1"));
        REQUIRE(pm->IsBanned("10.0.0.1"));

        pm->Unban("10.0.0.1");

        REQUIRE(pm->IsWhitelisted("10.0.0.1"));
        REQUIRE_FALSE(pm->IsBanned("10.0.0.1"));
    }
}

TEST_CASE("ConnectionManager - Whitelist persistence", "[network][peermgr][whitelist][persistence]") {
    WhitelistTestFixture fixture;

    SECTION("Whitelist doesn't persist (in-memory only)") {
        {
            auto pm = fixture.CreatePeerLifecycleManager(fixture.test_dir);
            pm->AddToWhitelist("10.0.0.1");
            pm->Ban("10.0.0.2", 0);

            REQUIRE(pm->IsWhitelisted("10.0.0.1"));
            REQUIRE(pm->IsBanned("10.0.0.2"));

            pm->SaveBans();
        }

        // Create new ConnectionManager - whitelist should not persist
        {
            auto pm = fixture.CreatePeerLifecycleManager(fixture.test_dir);

            // Whitelist is not persisted (in-memory only)
            REQUIRE_FALSE(pm->IsWhitelisted("10.0.0.1"));

            // But bans are persisted
            REQUIRE(pm->IsBanned("10.0.0.2"));
        }
    }
}
