// Copyright (c) 2025 The Unicity Foundation
// ConnectionManager adversarial tests - tests edge cases, attack scenarios, and robustness

#include "catch_amalgamated.hpp"
#include "network/peer_lifecycle_manager.hpp"
#include "network/addr_manager.hpp"
#include <asio.hpp>
#include <string>
#include <spdlog/spdlog.h>

using namespace unicity::network;

// Test fixture
class AdversarialTestFixture {
public:
    asio::io_context io_context;

    AdversarialTestFixture() {
        // Disable verbose logging in tests to avoid log spam
        spdlog::set_level(spdlog::level::off);
    }

    ~AdversarialTestFixture() {
        // Restore default log level after test (off for tests)
        spdlog::set_level(spdlog::level::off);
    }

    std::unique_ptr<PeerLifecycleManager> CreatePeerLifecycleManager() {
        // Phase 2: PeerLifecycleManager no longer requires AddressManager at construction
        // PeerDiscoveryManager injection not needed for these ban-focused unit tests
        return std::make_unique<PeerLifecycleManager>(io_context);
    }
};

TEST_CASE("ConnectionManager Adversarial - Ban Evasion", "[adversarial][banman][critical]") {
    AdversarialTestFixture fixture;
    auto pm = fixture.CreatePeerLifecycleManager();

    SECTION("Different ports same IP") {
        // BanManager bans by IP only (ports are not part of ban system)
        pm->Ban("192.168.1.100", 3600);
        REQUIRE(pm->IsBanned("192.168.1.100"));

        // Port numbers are not part of the IP address format
        // Invalid IP addresses (like "192.168.1.100:8333") are rejected
    }

    SECTION("IPv4 vs IPv6 localhost") {
        pm->Ban("127.0.0.1", 3600);
        REQUIRE(pm->IsBanned("127.0.0.1"));

        // IPv6 localhost is a different address
        REQUIRE_FALSE(pm->IsBanned("::1"));
    }
}

TEST_CASE("ConnectionManager Adversarial - Ban List Limits", "[adversarial][banman][dos]") {
    AdversarialTestFixture fixture;
    auto pm = fixture.CreatePeerLifecycleManager();

    SECTION("Ban 100 different IPs (scaled down)") {
        // Test that we can ban a large number of addresses
        for (int i = 0; i < 100; i++) {
            pm->Ban("10.0.0." + std::to_string(i), 3600);
        }

        // Verify first and last are banned
        REQUIRE(pm->IsBanned("10.0.0.0"));
        REQUIRE(pm->IsBanned("10.0.0.99"));
        REQUIRE(pm->GetBanned().size() == 100);
    }

    SECTION("Discourage 100 different IPs") {
        // Test that we can discourage a large number of addresses
        for (int i = 0; i < 100; i++) {
            pm->Discourage("10.0.0." + std::to_string(i));
        }

        // Verify first and last are discouraged
        REQUIRE(pm->IsDiscouraged("10.0.0.0"));
        REQUIRE(pm->IsDiscouraged("10.0.0.99"));
    }
}

TEST_CASE("ConnectionManager Adversarial - Time Manipulation", "[adversarial][banman][timing]") {
    AdversarialTestFixture fixture;
    auto pm = fixture.CreatePeerLifecycleManager();

    SECTION("Permanent ban (offset = 0)") {
        pm->Ban("192.168.1.1", 0);
        REQUIRE(pm->IsBanned("192.168.1.1"));

        // Verify it's marked as permanent
        auto banned = pm->GetBanned();
        REQUIRE(banned["192.168.1.1"].nBanUntil == 0);
    }

    SECTION("Negative offset treated as permanent ban") {
        // Implementation treats offset <= 0 as permanent ban (same as offset = 0)
        pm->Ban("192.168.1.2", -100);

        // Should be permanently banned
        REQUIRE(pm->IsBanned("192.168.1.2"));

        // Verify it's marked as permanent (nBanUntil = 0)
        auto banned = pm->GetBanned();
        REQUIRE(banned["192.168.1.2"].nBanUntil == 0);
    }
}

TEST_CASE("ConnectionManager Adversarial - Edge Cases", "[adversarial][banman][edge]") {
    AdversarialTestFixture fixture;
    auto pm = fixture.CreatePeerLifecycleManager();

    SECTION("Empty address string") {
        // BanManager now validates IP addresses - empty string is invalid
        pm->Ban("", 3600);
        REQUIRE_FALSE(pm->IsBanned("")); // Empty string is rejected, not banned

        pm->Unban(""); // Should not crash
        REQUIRE_FALSE(pm->IsBanned(""));
    }

    SECTION("Very long address") {
        // BanManager now validates IP addresses - 1000-char string is invalid
        std::string long_addr(1000, 'A');
        pm->Ban(long_addr, 3600);
        REQUIRE_FALSE(pm->IsBanned(long_addr)); // Invalid address is rejected, not banned
    }

    SECTION("Special characters") {
        // BanManager now validates IP addresses - special chars make it invalid
        std::string special_addr = "192.168.1.1\n\t\r\"'\\";
        pm->Ban(special_addr, 3600);
        REQUIRE_FALSE(pm->IsBanned(special_addr)); // Invalid address is rejected, not banned
    }
}

TEST_CASE("ConnectionManager Adversarial - Duplicate Operations", "[adversarial][banman][idempotent]") {
    AdversarialTestFixture fixture;
    auto pm = fixture.CreatePeerLifecycleManager();

    SECTION("Ban same address twice") {
        pm->Ban("192.168.1.1", 3600);
        pm->Ban("192.168.1.1", 7200);

        REQUIRE(pm->IsBanned("192.168.1.1"));

        // Should still be only one entry
        REQUIRE(pm->GetBanned().size() == 1);
    }

    SECTION("Unban non-existent") {
        // Should not crash
        pm->Unban("192.168.1.1");
        REQUIRE_FALSE(pm->IsBanned("192.168.1.1"));
    }

    SECTION("Discourage twice") {
        pm->Discourage("192.168.1.1");
        pm->Discourage("192.168.1.1");

        REQUIRE(pm->IsDiscouraged("192.168.1.1"));
    }
}

TEST_CASE("ConnectionManager Adversarial - Ban vs Discourage", "[adversarial][banman][interaction]") {
    AdversarialTestFixture fixture;
    auto pm = fixture.CreatePeerLifecycleManager();

    SECTION("Ban AND discourage same address") {
        pm->Ban("192.168.1.1", 3600);
        pm->Discourage("192.168.1.1");

        // Both states can coexist
        REQUIRE(pm->IsBanned("192.168.1.1"));
        REQUIRE(pm->IsDiscouraged("192.168.1.1"));
    }

    SECTION("Unban discouraged address") {
        pm->Ban("192.168.1.1", 3600);
        pm->Discourage("192.168.1.1");
        pm->Unban("192.168.1.1");

        // Ban removed, discouragement persists
        REQUIRE_FALSE(pm->IsBanned("192.168.1.1"));
        REQUIRE(pm->IsDiscouraged("192.168.1.1"));
    }

    SECTION("Clear bans vs discouraged") {
        pm->Ban("192.168.1.1", 3600);
        pm->Discourage("192.168.1.1");
        pm->ClearBanned();

        // Only bans cleared
        REQUIRE_FALSE(pm->IsBanned("192.168.1.1"));
        REQUIRE(pm->IsDiscouraged("192.168.1.1"));
    }

    SECTION("Clear discouraged vs bans") {
        pm->Ban("192.168.1.1", 3600);
        pm->Discourage("192.168.1.1");
        pm->ClearDiscouraged();

        // Only discouragement cleared
        REQUIRE(pm->IsBanned("192.168.1.1"));
        REQUIRE_FALSE(pm->IsDiscouraged("192.168.1.1"));
    }
}

TEST_CASE("ConnectionManager Adversarial - Sweep Operation", "[adversarial][banman][sweep]") {
    AdversarialTestFixture fixture;
    auto pm = fixture.CreatePeerLifecycleManager();

    SECTION("Sweep removes only expired (no-crash)") {
        pm->Ban("192.168.1.1", 3600);
        pm->Ban("192.168.1.2", 3600);

        // Sweep should not crash and should not remove unexpired bans
        pm->SweepBanned();

        REQUIRE(pm->IsBanned("192.168.1.1"));
        REQUIRE(pm->IsBanned("192.168.1.2"));
    }
}

TEST_CASE("ConnectionManager Adversarial - IPv4-mapped IPv6 Ban Bypass", "[adversarial][banman][critical][normalization]") {
    // Tests that attacker cannot evade IPv4 ban by using IPv4-mapped IPv6 format
    // BanManager normalizes ::ffff:x.x.x.x to x.x.x.x before storage/lookup
    AdversarialTestFixture fixture;
    auto pm = fixture.CreatePeerLifecycleManager();

    SECTION("Ban IPv4, check IPv4-mapped IPv6 - bypass blocked") {
        pm->Ban("192.168.1.100", 3600);
        REQUIRE(pm->IsBanned("192.168.1.100"));

        // Attacker tries to connect using IPv4-mapped IPv6 format
        // Normalization should convert ::ffff:192.168.1.100 -> 192.168.1.100
        REQUIRE(pm->IsBanned("::ffff:192.168.1.100"));
    }

    SECTION("Ban IPv4-mapped IPv6, check IPv4 - bypass blocked") {
        pm->Ban("::ffff:10.0.0.1", 3600);

        // Should be normalized and stored as IPv4
        REQUIRE(pm->IsBanned("10.0.0.1"));
        REQUIRE(pm->IsBanned("::ffff:10.0.0.1"));
    }

    SECTION("Discourage IPv4, check IPv4-mapped IPv6 - bypass blocked") {
        pm->Discourage("172.16.0.1");
        REQUIRE(pm->IsDiscouraged("172.16.0.1"));
        REQUIRE(pm->IsDiscouraged("::ffff:172.16.0.1"));
    }

    SECTION("Whitelist IPv4, check IPv4-mapped IPv6 - consistent") {
        pm->AddToWhitelist("10.10.10.10");
        REQUIRE(pm->IsWhitelisted("10.10.10.10"));
        REQUIRE(pm->IsWhitelisted("::ffff:10.10.10.10"));
    }
}
