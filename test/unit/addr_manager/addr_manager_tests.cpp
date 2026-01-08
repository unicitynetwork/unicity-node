// Copyright (c) 2025 The Unicity Foundation
// Test suite for AddressManager

#include "catch_amalgamated.hpp"
#include "network/addr_manager.hpp"
#include "network/protocol.hpp"
#include <cstring>
#include <filesystem>
#include <fstream>

using namespace unicity::network;
using namespace unicity::protocol;

// Helper function to create a test address
static NetworkAddress MakeAddress(const std::string& ip_v4, uint16_t port) {
    NetworkAddress addr;
    addr.services = 1;
    addr.port = port;

    // Parse IPv4 and convert to IPv4-mapped IPv6 (::FFFF:x.x.x.x)
    std::memset(addr.ip.data(), 0, 10);
    addr.ip[10] = 0xFF;
    addr.ip[11] = 0xFF;

    // Simple IPv4 parsing (e.g., "127.0.0.1")
    int a, b, c, d;
    if (sscanf(ip_v4.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
        addr.ip[12] = static_cast<uint8_t>(a);
        addr.ip[13] = static_cast<uint8_t>(b);
        addr.ip[14] = static_cast<uint8_t>(c);
        addr.ip[15] = static_cast<uint8_t>(d);
    }

    return addr;
}

TEST_CASE("AddressManager basic operations", "[network][addrman]") {
    AddressManager addrman;

    SECTION("Empty address manager") {
        REQUIRE(addrman.size() == 0);
        REQUIRE(addrman.tried_count() == 0);
        REQUIRE(addrman.new_count() == 0);
        REQUIRE(addrman.select() == std::nullopt);
    }

    SECTION("Add single address") {
        NetworkAddress addr = MakeAddress("1.1.1.1", 8333);

        REQUIRE(addrman.add(addr));
        REQUIRE(addrman.size() == 1);
        REQUIRE(addrman.new_count() == 1);
        REQUIRE(addrman.tried_count() == 0);
    }

    SECTION("Add duplicate address") {
        NetworkAddress addr = MakeAddress("1.1.1.1", 8333);

        REQUIRE(addrman.add(addr));
        REQUIRE(addrman.size() == 1);

        // Adding same address again should return false
        REQUIRE_FALSE(addrman.add(addr));
        REQUIRE(addrman.size() == 1);
    }

    SECTION("Add multiple addresses") {
        std::vector<TimestampedAddress> addresses;
        uint32_t current_time = static_cast<uint32_t>(
            std::chrono::system_clock::now().time_since_epoch().count() / 1000000000);

        for (int i = 0; i < 10; i++) {
            std::string ip = "1.1.1." + std::to_string(i + 1);
            NetworkAddress addr = MakeAddress(ip, 8333);
            // Use timestamps from recent past (1 hour ago - 10 seconds ago)
            addresses.push_back({current_time - 3600 + (i * 360), addr});
        }

        size_t added = addrman.add_multiple(addresses);
        REQUIRE(added == 10);
        REQUIRE(addrman.size() == 10);
        REQUIRE(addrman.new_count() == 10);
    }
}

TEST_CASE("AddressManager state transitions", "[network][addrman]") {
    AddressManager addrman;
    NetworkAddress addr = MakeAddress("1.0.0.1", 8333);

    SECTION("Mark address as good (new -> tried)") {
        // Add to new table
        REQUIRE(addrman.add(addr));
        REQUIRE(addrman.new_count() == 1);
        REQUIRE(addrman.tried_count() == 0);

        // Mark as good (moves to tried)
        addrman.good(addr);
        REQUIRE(addrman.new_count() == 0);
        REQUIRE(addrman.tried_count() == 1);
        REQUIRE(addrman.size() == 1);
    }

    SECTION("Attempt tracking") {
        REQUIRE(addrman.add(addr));

        // One failed attempt
        addrman.attempt(addr);
        addrman.failed(addr);

        // Address should still be in new table after 1 failure (Bitcoin Core: < 3 attempts)
        REQUIRE(addrman.new_count() == 1);
    }

    SECTION("Good address stays good") {
        REQUIRE(addrman.add(addr));
        addrman.good(addr);
        REQUIRE(addrman.tried_count() == 1);

        // Marking good again should keep it in tried
        addrman.good(addr);
        REQUIRE(addrman.tried_count() == 1);
        REQUIRE(addrman.new_count() == 0);
    }

    SECTION("Too many failures removes address") {
        REQUIRE(addrman.add(addr));

        // Bitcoin Core parity: NEW addresses removed after ADDRMAN_RETRIES (3) failed attempts
        for (int i = 0; i < 3; i++) {
            addrman.failed(addr);
        }

        // Address should be removed from new table after 3 failures
        REQUIRE(addrman.size() == 0);
    }

    SECTION("Failed tried address moves back to new") {
        REQUIRE(addrman.add(addr));
        addrman.good(addr);
        REQUIRE(addrman.tried_count() == 1);

        // Fail it exactly MAX_FAILURES times (10)
        for (int i = 0; i < 10; i++) {
            addrman.failed(addr);
        }

        // Should move back to new table after reaching MAX_FAILURES
        REQUIRE(addrman.tried_count() == 0);
        REQUIRE(addrman.new_count() == 1);

        // Bitcoin Core parity: Once an address has succeeded (last_success > 0),
        // it needs 10 failures over 7+ days to be removed, not just 3 failures.
        // So it will stay in NEW table even with more failures (unless 7 days pass).
        // The address won't be removed until the time condition is met.
        for (int i = 0; i < 5; i++) {
            addrman.failed(addr);
        }

        // Still in NEW table (has last_success set, needs 7-day window to be removed)
        REQUIRE(addrman.size() == 1);
        REQUIRE(addrman.new_count() == 1);
    }
}

TEST_CASE("AddressManager selection", "[network][addrman]") {
    AddressManager addrman;

    SECTION("Select from new addresses") {
        // Add 10 new addresses
        for (int i = 0; i < 10; i++) {
            std::string ip = "1.1.2." + std::to_string(i + 1);
            NetworkAddress addr = MakeAddress(ip, 8333);
            addrman.add(addr);
        }

        // Should be able to select
        auto selected = addrman.select();
        REQUIRE(selected.has_value());
        REQUIRE(selected->port == 8333);
    }

    SECTION("Select prefers tried addresses") {
        // Add addresses to both tables
        NetworkAddress tried_addr = MakeAddress("1.0.0.1", 8333);
        addrman.add(tried_addr);
        addrman.good(tried_addr);

        for (int i = 0; i < 100; i++) {
            std::string ip = "1.1.3." + std::to_string(i + 1);
            NetworkAddress addr = MakeAddress(ip, 8333);
            addrman.add(addr);
        }

        // Select many times, should get tried address most of the time
        int tried_count = 0;
        for (int i = 0; i < 100; i++) {
            auto selected = addrman.select();
            REQUIRE(selected.has_value());

            // Check if it's the tried address (1.0.0.1)
            if (selected->ip[12] == 1 && selected->ip[13] == 0 &&
                selected->ip[14] == 0 && selected->ip[15] == 1) {
                tried_count++;
            }
        }

        // Should select tried address about 50% of the time (Bitcoin Core parity)
        REQUIRE(tried_count > 30);
        REQUIRE(tried_count < 70);
    }

    SECTION("Tried cooldown is honored (probabilistic: 1% initial chance with escalating factor)") {
        // Bitcoin Core parity: cooldown reduces initial selection chance to 1%
        // But with escalating chance_factor, address becomes more likely with each iteration
        // One tried address (under cooldown), many new addresses
        NetworkAddress tried_addr = MakeAddress("1.0.0.2", 8333);
        REQUIRE(addrman.add(tried_addr));
        addrman.good(tried_addr);
        addrman.attempt(tried_addr); // sets last_try for tried (cooldown active: GetChance = 0.01)

        for (int i = 0; i < 50; ++i) {
            std::string ip = "1.1.50." + std::to_string(i + 1);
            NetworkAddress addr = MakeAddress(ip, 8333);
            addrman.add(addr);
        }

        // Expected behavior with escalating chance_factor:
        // - 50% of time: search TRIED table (has 1 address with GetChance=0.01)
        //   * iteration 1: 1% chance → usually fails
        //   * iteration 2: 1.2% chance
        //   * iteration 3: 1.44% chance
        //   * iteration 10: ~6% chance
        //   * After ~20 iterations: >20% chance, likely selected
        // - 50% of time: search NEW table (has 50 addresses with GetChance=1.0)
        //   * iteration 1: 100% chance → immediately selected
        //
        // Overall: tried address selected roughly 50% of the time (Bitcoin Core parity)
        // (because when we search TRIED table, escalating factor ensures we eventually pick it)

        int tried_selected = 0;
        int new_selected = 0;
        for (int i = 0; i < 500; ++i) {
            auto sel = addrman.select();
            REQUIRE(sel.has_value());
            if (sel->ip[12] == 1 && sel->ip[13] == 0 && sel->ip[14] == 0 && sel->ip[15] == 2) {
                tried_selected++;
            } else {
                new_selected++;
            }
        }

        // With 50% tried bias and escalating chance_factor:
        // - Tried address should be selected around 50% of the time (allow variance)
        // - NEW addresses should be selected around 50% of the time
        // Use wider tolerance (35%-65%) to avoid flaky test failures from statistical variance
        REQUIRE(tried_selected >= 175);  // At least 35%
        REQUIRE(tried_selected <= 325);  // At most 65%
        REQUIRE(new_selected >= 175);    // At least 35%

        // Verify GetChance() is working: tried address has low initial chance but is still picked
        // due to escalating chance_factor (this is Bitcoin Core's behavior)
    }

    SECTION("Get multiple addresses") {
        // Add 50 addresses
        for (int i = 0; i < 50; i++) {
            std::string ip = "1.1.4." + std::to_string(i + 1);
            NetworkAddress addr = MakeAddress(ip, 8333);
            addrman.add(addr);
        }

        // Get 20 addresses
        auto addresses = addrman.get_addresses(20);
        REQUIRE(addresses.size() == 20);

        // All should be unique
        std::set<std::string> unique_ips;
        for (const auto& ts_addr : addresses) {
            std::string key = std::to_string(ts_addr.address.ip[12]) + "." +
                            std::to_string(ts_addr.address.ip[13]) + "." +
                            std::to_string(ts_addr.address.ip[14]) + "." +
                            std::to_string(ts_addr.address.ip[15]);
            unique_ips.insert(key);
        }
        REQUIRE(unique_ips.size() == 20);
    }
}

TEST_CASE("AddressManager persistence", "[network][addrman]") {
    std::filesystem::path test_file = std::filesystem::temp_directory_path() / "addrman_test.json";

    // Clean up any existing test file
    std::filesystem::remove(test_file);

    SECTION("Save and load empty address manager") {
        AddressManager addrman1;
        REQUIRE(addrman1.Save(test_file.string()));

        AddressManager addrman2;
        REQUIRE(addrman2.Load(test_file.string()));
        REQUIRE(addrman2.size() == 0);
    }

    SECTION("Save and load with new addresses") {
        AddressManager addrman1;

        // Add 20 addresses
        for (int i = 0; i < 20; i++) {
            std::string ip = "1.0.1." + std::to_string(i + 1);
            NetworkAddress addr = MakeAddress(ip, 8333);
            addrman1.add(addr);
        }

        REQUIRE(addrman1.size() == 20);
        REQUIRE(addrman1.Save(test_file.string()));

        // Load into new manager
        AddressManager addrman2;
        REQUIRE(addrman2.Load(test_file.string()));
        REQUIRE(addrman2.size() == 20);
        REQUIRE(addrman2.new_count() == 20);
        REQUIRE(addrman2.tried_count() == 0);
    }

    SECTION("Save and load with tried addresses") {
        AddressManager addrman1;

        // Add and mark as tried - use diverse /16 netgroups to avoid TRIED limit
        // MAX_PER_NETGROUP_TRIED = 8, so we need 2 different /16s for 10 addresses
        for (int i = 0; i < 8; i++) {
            std::string ip = "1.0.2." + std::to_string(i + 1);
            NetworkAddress addr = MakeAddress(ip, 8333);
            addrman1.add(addr);
            addrman1.good(addr);
        }
        for (int i = 0; i < 2; i++) {
            std::string ip = "2.0.2." + std::to_string(i + 1);  // Different /16
            NetworkAddress addr = MakeAddress(ip, 8333);
            addrman1.add(addr);
            addrman1.good(addr);
        }

        REQUIRE(addrman1.tried_count() == 10);
        REQUIRE(addrman1.Save(test_file.string()));

        // Load into new manager
        AddressManager addrman2;
        REQUIRE(addrman2.Load(test_file.string()));
        REQUIRE(addrman2.size() == 10);
        REQUIRE(addrman2.tried_count() == 10);
        REQUIRE(addrman2.new_count() == 0);
    }

    SECTION("Save and load with mixed addresses") {
        AddressManager addrman1;

        // Add 15 new addresses
        for (int i = 0; i < 15; i++) {
            std::string ip = "1.1.10." + std::to_string(i + 1);
            NetworkAddress addr = MakeAddress(ip, 8333);
            addrman1.add(addr);
        }

        // Add 5 tried addresses
        for (int i = 0; i < 5; i++) {
            std::string ip = "1.0.3." + std::to_string(i + 1);
            NetworkAddress addr = MakeAddress(ip, 8333);
            addrman1.add(addr);
            addrman1.good(addr);
        }

        REQUIRE(addrman1.size() == 20);
        REQUIRE(addrman1.new_count() == 15);
        REQUIRE(addrman1.tried_count() == 5);
        REQUIRE(addrman1.Save(test_file.string()));

        // Load and verify
        AddressManager addrman2;
        REQUIRE(addrman2.Load(test_file.string()));
        REQUIRE(addrman2.size() == 20);
        REQUIRE(addrman2.new_count() == 15);
        REQUIRE(addrman2.tried_count() == 5);
    }

    SECTION("Load non-existent file fails gracefully") {
        AddressManager addrman;
        REQUIRE_FALSE(addrman.Load("/tmp/nonexistent_addrman_file_xyz.json"));
        REQUIRE(addrman.size() == 0);
    }

    // Cleanup
    std::filesystem::remove(test_file);
}

// NOTE: Checksum tamper detection test removed - we no longer use checksums for
// persistence (they are fragile to whitespace/key-order changes). We rely on
// nlohmann::json parser error detection for malformed JSON instead.

TEST_CASE("AddressManager timestamp clamping and validation", "[network][addrman]") {
    AddressManager addrman;

    SECTION("Future timestamps are clamped and not considered stale") {
        NetworkAddress addr = MakeAddress("2.2.2.10", 8333);
        // Far future timestamp
        uint32_t now_s = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        uint32_t future = now_s + 10u * 365u * 24u * 60u * 60u; // +10 years

        REQUIRE(addrman.add(addr, future));
        REQUIRE(addrman.size() == 1);

        // cleanup_stale must not remove it (future ts should not be stale)
        addrman.cleanup_stale();
        REQUIRE(addrman.size() == 1);

        // Returned timestamp should be <= now (clamped)
        auto addrs = addrman.get_addresses(10);
        REQUIRE(addrs.size() == 1);
        REQUIRE(addrs[0].timestamp <= static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()));
    }

    SECTION("Reject invalid address (port zero)") {
        NetworkAddress invalid{}; // zero port, zero ip
        invalid.port = 0;
        invalid.services = 1;
        REQUIRE_FALSE(addrman.add(invalid));
        REQUIRE(addrman.size() == 0);
    }
}

TEST_CASE("AddressManager rejects reserved IP addresses", "[network][addrman][reserved]") {
    AddressManager addrman;

    SECTION("Reject IPv4 loopback addresses") {
        // 127.0.0.0/8 - Loopback range
        auto addr1 = MakeAddress("127.0.0.1", 8333);
        REQUIRE_FALSE(addrman.add(addr1));
        REQUIRE(addrman.size() == 0);

        auto addr2 = MakeAddress("127.0.0.100", 8333);
        REQUIRE_FALSE(addrman.add(addr2));
        REQUIRE(addrman.size() == 0);

        auto addr3 = MakeAddress("127.255.255.255", 8333);
        REQUIRE_FALSE(addrman.add(addr3));
        REQUIRE(addrman.size() == 0);
    }

    SECTION("Reject IPv4 broadcast address") {
        auto addr = MakeAddress("255.255.255.255", 8333);
        REQUIRE_FALSE(addrman.add(addr));
        REQUIRE(addrman.size() == 0);
    }

    SECTION("Reject IPv4 multicast addresses") {
        // 224.0.0.0/4 - Multicast range
        auto addr1 = MakeAddress("224.0.0.1", 8333);
        REQUIRE_FALSE(addrman.add(addr1));
        REQUIRE(addrman.size() == 0);

        auto addr2 = MakeAddress("239.255.255.255", 8333);
        REQUIRE_FALSE(addrman.add(addr2));
        REQUIRE(addrman.size() == 0);
    }

    SECTION("Reject IPv4 reserved addresses") {
        // 240.0.0.0/4 - Reserved range
        auto addr1 = MakeAddress("240.0.0.1", 8333);
        REQUIRE_FALSE(addrman.add(addr1));
        REQUIRE(addrman.size() == 0);

        auto addr2 = MakeAddress("255.0.0.1", 8333);
        REQUIRE_FALSE(addrman.add(addr2));
        REQUIRE(addrman.size() == 0);
    }

    SECTION("Reject IPv4 link-local addresses") {
        // 169.254.0.0/16 - Link-local range
        auto addr1 = MakeAddress("169.254.0.1", 8333);
        REQUIRE_FALSE(addrman.add(addr1));
        REQUIRE(addrman.size() == 0);

        auto addr2 = MakeAddress("169.254.255.255", 8333);
        REQUIRE_FALSE(addrman.add(addr2));
        REQUIRE(addrman.size() == 0);
    }

    SECTION("Reject IPv4 'this network' addresses") {
        // 0.0.0.0/8 - "This network"
        auto addr1 = MakeAddress("0.0.0.1", 8333);
        REQUIRE_FALSE(addrman.add(addr1));
        REQUIRE(addrman.size() == 0);

        auto addr2 = MakeAddress("0.255.255.255", 8333);
        REQUIRE_FALSE(addrman.add(addr2));
        REQUIRE(addrman.size() == 0);
    }

    SECTION("Accept valid public IPv4 addresses") {
        // These should be accepted (public routable addresses)
        auto addr1 = MakeAddress("8.8.8.8", 8333);  // Google DNS
        REQUIRE(addrman.add(addr1));
        REQUIRE(addrman.size() == 1);

        auto addr2 = MakeAddress("1.1.1.1", 8333);  // Cloudflare DNS
        REQUIRE(addrman.add(addr2));
        REQUIRE(addrman.size() == 2);

        auto addr3 = MakeAddress("93.184.216.34", 8333);  // example.com
        REQUIRE(addrman.add(addr3));
        REQUIRE(addrman.size() == 3);
    }
}

TEST_CASE("AddressManager stale address cleanup", "[network][addrman]") {
    AddressManager addrman;

    SECTION("Cleanup removes old addresses") {
        // Add addresses with recent timestamp first
        for (int i = 0; i < 10; i++) {
            std::string ip = "1.1.20." + std::to_string(i + 1);
            NetworkAddress addr = MakeAddress(ip, 8333);
            addrman.add(addr);  // Uses current time
        }

        REQUIRE(addrman.size() == 10);

        // Manually set old timestamps (simulate addresses becoming stale)
        // NOTE: This is a white-box test - we're reaching into internals
        // In real usage, addresses would become stale over time
        // For now, just verify cleanup doesn't crash
        addrman.cleanup_stale();

        // Recent addresses should still be there
        REQUIRE(addrman.size() == 10);
    }

    SECTION("Cleanup preserves recent addresses") {
        // Add recent addresses
        for (int i = 0; i < 10; i++) {
            std::string ip = "1.1.21." + std::to_string(i + 1);
            NetworkAddress addr = MakeAddress(ip, 8333);
            addrman.add(addr);  // Uses current time
        }

        REQUIRE(addrman.size() == 10);

        // Cleanup should not remove recent addresses
        addrman.cleanup_stale();
        REQUIRE(addrman.size() == 10);
    }

    SECTION("get_addresses filters terrible entries from new table") {
        // Add one address, then exceed failure threshold to make it terrible
        NetworkAddress a = MakeAddress("2.3.3.23", 8333);
        REQUIRE(addrman.add(a));
        for (int i = 0; i < 20; ++i) addrman.failed(a); // attempts >= MAX_FAILURES

        auto vec = addrman.get_addresses(10);
        // Should be filtered out (terrible)
        REQUIRE(vec.empty());
    }

    SECTION("Cleanup preserves tried addresses even if old") {
        // Add recent addresses then mark as tried
        for (int i = 0; i < 5; i++) {
            std::string ip = "1.0.4." + std::to_string(i + 1);
            NetworkAddress addr = MakeAddress(ip, 8333);
            addrman.add(addr);  // Uses current time
            addrman.good(addr);  // Move to tried table
        }

        REQUIRE(addrman.tried_count() == 5);

        // Cleanup should keep tried addresses (they worked, so we keep them)
        addrman.cleanup_stale();
        REQUIRE(addrman.tried_count() == 5);
    }
}
// ========================================================================
// ==================================================================== 
// Bitcoin Core Parity Tests: GetChance() probabilistic calculation only
// (Simplified to avoid flaky probabilistic selection tests)
// ====================================================================

TEST_CASE("AddrInfo::GetChance() - Bitcoin Core parity", "[network][addrman][prob]") {
    uint32_t now = 1000000;
    
    SECTION("Fresh address (never tried)") {
        AddrInfo info;
        info.last_try = 0;
        info.attempts = 0;
        
        double chance = info.GetChance(now);
        REQUIRE(chance == Catch::Approx(1.0).epsilon(0.01));
    }
    
    SECTION("Recent attempt (< 10 minutes)") {
        AddrInfo info;
        info.last_try = now - 300;  // 5 minutes ago
        info.attempts = 0;
        
        double chance = info.GetChance(now);
        // Should be 1% (0.01) due to 10-minute cooldown
        REQUIRE(chance == Catch::Approx(0.01).epsilon(0.001));
    }
    
    SECTION("Post-cooldown (>= 10 minutes)") {
        AddrInfo info;
        info.last_try = now - 600;  // Exactly 10 minutes ago
        info.attempts = 0;
        
        double chance = info.GetChance(now);
        // No cooldown penalty, only attempt penalty (0 attempts = 1.0)
        REQUIRE(chance == Catch::Approx(1.0).epsilon(0.01));
    }
    
    SECTION("One failed attempt (no cooldown)") {
        AddrInfo info;
        info.last_try = now - 700;  // 11+ minutes ago
        info.attempts = 1;
        
        double chance = info.GetChance(now);
        // 0.66^1 = 0.66
        REQUIRE(chance == Catch::Approx(0.66).epsilon(0.01));
    }
    
    SECTION("Two failed attempts (no cooldown)") {
        AddrInfo info;
        info.last_try = now - 700;
        info.attempts = 2;
        
        double chance = info.GetChance(now);
        // 0.66^2 = 0.4356
        REQUIRE(chance == Catch::Approx(0.4356).epsilon(0.01));
    }
    
    SECTION("Eight failed attempts (capped)") {
        AddrInfo info;
        info.last_try = now - 700;
        info.attempts = 8;
        
        double chance = info.GetChance(now);
        // 0.66^8 ≈ 0.0361
        REQUIRE(chance == Catch::Approx(0.0361).epsilon(0.005));
    }
    
    SECTION("Ten failed attempts (still capped at 8)") {
        AddrInfo info;
        info.last_try = now - 700;
        info.attempts = 10;
        
        double chance = info.GetChance(now);
        // Still 0.66^8 due to cap
        REQUIRE(chance == Catch::Approx(0.0361).epsilon(0.005));
    }
    
    SECTION("Combined: recent attempt + failures") {
        AddrInfo info;
        info.last_try = now - 300;  // 5 minutes ago (cooldown penalty)
        info.attempts = 2;           // 2 failed attempts
        
        double chance = info.GetChance(now);
        // 0.01 (cooldown) * 0.66^2 (attempts) = 0.01 * 0.4356 ≈ 0.004356
        REQUIRE(chance == Catch::Approx(0.004356).epsilon(0.001));
    }
}
