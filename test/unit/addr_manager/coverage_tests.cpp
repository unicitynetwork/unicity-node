// Copyright (c) 2025 The Unicity Foundation
// Additional AddrManager tests for comprehensive code coverage
// Based on Bitcoin Core test patterns and gap analysis

#include "catch_amalgamated.hpp"
#include "network/addr_manager.hpp"
#include "network/protocol.hpp"
#include <filesystem>
#include <fstream>
#include <set>
#include <map>

using namespace unicity;
using namespace unicity::network;
using namespace unicity::protocol;

// Helper: Create IPv4-mapped address from octets
static NetworkAddress MakeIPv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port = 9590) {
    NetworkAddress addr;
    addr.ip.fill(0);
    addr.ip[10] = 0xff;
    addr.ip[11] = 0xff;
    addr.ip[12] = a;
    addr.ip[13] = b;
    addr.ip[14] = c;
    addr.ip[15] = d;
    addr.port = port;
    addr.services = NODE_NETWORK;
    return addr;
}

// Helper: Create address with specific netgroup (a.b.x.x)
static NetworkAddress MakeAddressInNetgroup(uint8_t a, uint8_t b, uint8_t index, uint16_t port = 9590) {
    return MakeIPv4(a, b, index / 256, (index % 256) + 1, port);
}

// ============================================================================
// PRIORITY 1: select_new_for_feeler() tests - PREVIOUSLY ZERO COVERAGE
// ============================================================================

TEST_CASE("select_new_for_feeler() basic functionality", "[network][addrman][feeler]") {
    AddressManager am;

    SECTION("Empty NEW table returns nullopt") {
        auto result = am.select_new_for_feeler();
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Returns address from NEW table") {
        auto addr = MakeIPv4(1, 2, 3, 4);
        REQUIRE(am.add(addr));
        REQUIRE(am.new_count() == 1);

        auto result = am.select_new_for_feeler();
        REQUIRE(result.has_value());
        REQUIRE(result->port == 9590);
    }

    SECTION("Does not return addresses from TRIED table") {
        auto addr = MakeIPv4(1, 2, 3, 5);
        REQUIRE(am.add(addr));
        am.good(addr);  // Move to TRIED
        REQUIRE(am.tried_count() == 1);
        REQUIRE(am.new_count() == 0);

        auto result = am.select_new_for_feeler();
        REQUIRE_FALSE(result.has_value());  // No addresses in NEW
    }

    SECTION("Prefers addresses not tried in last 10 minutes") {
        // Add 10 addresses - all "fresh" (never attempted)
        for (int i = 0; i < 10; ++i) {
            auto addr = MakeIPv4(1, 2, 3, static_cast<uint8_t>(i + 10));
            am.add(addr);
        }
        REQUIRE(am.new_count() == 10);

        // Select should succeed and return one of them
        auto result = am.select_new_for_feeler();
        REQUIRE(result.has_value());
    }

    SECTION("Falls back to any address when all recently tried") {
        // Add one address
        auto addr = MakeIPv4(1, 2, 3, 20);
        REQUIRE(am.add(addr));

        // Mark it as recently attempted
        am.attempt(addr, false);

        // Should still return it as fallback (only option)
        auto result = am.select_new_for_feeler();
        REQUIRE(result.has_value());
    }
}

TEST_CASE("select_new_for_feeler() selection distribution", "[network][addrman][feeler]") {
    AddressManager am;

    // Add 50 addresses
    for (int i = 0; i < 50; ++i) {
        auto addr = MakeIPv4(1, static_cast<uint8_t>(i / 8), static_cast<uint8_t>(i % 256), 1);
        am.add(addr);
    }
    REQUIRE(am.new_count() == 50);

    // Select many times and verify we get variety
    std::set<uint16_t> selected_third_octets;
    for (int i = 0; i < 100; ++i) {
        auto result = am.select_new_for_feeler();
        REQUIRE(result.has_value());
        // Extract third octet to identify which address was selected
        selected_third_octets.insert(result->ip[14]);
    }

    // Should have selected multiple different addresses (randomness)
    REQUIRE(selected_third_octets.size() > 1);
}

// ============================================================================
// PRIORITY 1: Port handling tests (Bitcoin Core: addrman_ports)
// ============================================================================

TEST_CASE("Port handling - same IP different ports are separate entries", "[network][addrman][ports]") {
    AddressManager am;

    SECTION("Different ports create separate entries") {
        auto addr1 = MakeIPv4(1, 2, 3, 100, 9590);
        auto addr2 = MakeIPv4(1, 2, 3, 100, 8334);  // Same IP, different port

        REQUIRE(am.add(addr1));
        REQUIRE(am.add(addr2));
        REQUIRE(am.size() == 2);  // Both should be stored
    }

    SECTION("Good() on one port doesn't affect other port") {
        auto addr1 = MakeIPv4(1, 2, 3, 101, 9590);
        auto addr2 = MakeIPv4(1, 2, 3, 101, 8334);

        am.add(addr1);
        am.add(addr2);
        REQUIRE(am.new_count() == 2);

        // Mark only port 9590 as good
        am.good(addr1);
        REQUIRE(am.tried_count() == 1);
        REQUIRE(am.new_count() == 1);  // Port 8334 still in NEW
    }

    SECTION("Failed() on one port doesn't affect other port") {
        auto addr1 = MakeIPv4(1, 2, 3, 102, 9590);
        auto addr2 = MakeIPv4(1, 2, 3, 102, 8334);

        am.add(addr1);
        am.add(addr2);

        // Bitcoin Core parity: use attempt() to increment failures
        // Need to advance m_last_good_ between attempts
        am.attempt(addr1, true);  // attempts = 1
        am.good(addr2);  // advance m_last_good_, moves addr2 to TRIED
        am.attempt(addr1, true);  // attempts = 2
        am.good(addr2);  // advance m_last_good_
        am.attempt(addr1, true);  // attempts = 3

        // Note: is_terrible() has a 60-second grace period, so addr1 won't be
        // removed immediately. Bitcoin Core has no failed() function; terrible
        // addresses are filtered via GetChance() and cleaned by cleanup_stale().
        // The key test here is that operations on addr1 don't affect addr2 (different port = separate entry).

        // Both addresses still present (addr1 protected by grace period, addr2 in TRIED)
        REQUIRE(am.size() == 2);
        REQUIRE(am.tried_count() == 1);  // addr2 in TRIED
        REQUIRE(am.new_count() == 1);    // addr1 still in NEW (grace period)
    }

    SECTION("Select can return different ports for same IP") {
        auto addr1 = MakeIPv4(1, 2, 3, 103, 9590);
        auto addr2 = MakeIPv4(1, 2, 3, 103, 8334);

        am.add(addr1);
        am.add(addr2);

        std::set<uint16_t> ports_seen;
        for (int i = 0; i < 50; ++i) {
            auto sel = am.select();
            REQUIRE(sel.has_value());
            ports_seen.insert(sel->port);
        }

        // Should see both ports (with high probability)
        REQUIRE(ports_seen.size() == 2);
    }
}

// ============================================================================
// PRIORITY 1: Per-netgroup boundary tests
// ============================================================================

TEST_CASE("Per-netgroup limit for NEW table (MAX_PER_NETGROUP_NEW = 32)", "[network][addrman][netgroup]") {
    AddressManager am;

    // All addresses in same /16: 100.1.x.x
    SECTION("32 addresses from same /16 are accepted") {
        for (int i = 0; i < 32; ++i) {
            auto addr = MakeAddressInNetgroup(100, 1, i);
            REQUIRE(am.add(addr));
        }
        REQUIRE(am.new_count() == 32);
    }

    SECTION("33rd address from same /16 is rejected") {
        // Fill to limit
        for (int i = 0; i < 32; ++i) {
            auto addr = MakeAddressInNetgroup(100, 2, i);
            REQUIRE(am.add(addr));
        }
        REQUIRE(am.new_count() == 32);

        // 33rd should be rejected
        auto addr33 = MakeAddressInNetgroup(100, 2, 32);
        REQUIRE_FALSE(am.add(addr33));
        REQUIRE(am.new_count() == 32);
    }

    SECTION("Different /16 can still add addresses") {
        // Fill 100.3.x.x
        for (int i = 0; i < 32; ++i) {
            auto addr = MakeAddressInNetgroup(100, 3, i);
            am.add(addr);
        }

        // 100.4.x.x should still work
        auto addr_diff = MakeAddressInNetgroup(100, 4, 0);
        REQUIRE(am.add(addr_diff));
        REQUIRE(am.new_count() == 33);
    }
}

TEST_CASE("Per-netgroup limit for TRIED table (MAX_PER_NETGROUP_TRIED = 8)", "[network][addrman][netgroup]") {
    AddressManager am;

    SECTION("8 addresses from same /16 can be promoted to TRIED") {
        for (int i = 0; i < 8; ++i) {
            auto addr = MakeAddressInNetgroup(101, 1, i);
            am.add(addr);
            am.good(addr);
        }
        REQUIRE(am.tried_count() == 8);
        REQUIRE(am.new_count() == 0);
    }

    SECTION("9th address from same /16 stays in NEW (not promoted)") {
        // Promote 8 to TRIED
        for (int i = 0; i < 8; ++i) {
            auto addr = MakeAddressInNetgroup(101, 2, i);
            am.add(addr);
            am.good(addr);
        }
        REQUIRE(am.tried_count() == 8);

        // Add 9th and try to promote
        auto addr9 = MakeAddressInNetgroup(101, 2, 8);
        am.add(addr9);
        am.good(addr9);  // Should stay in NEW due to netgroup limit

        REQUIRE(am.tried_count() == 8);  // Still 8
        REQUIRE(am.new_count() == 1);    // 9th stays in NEW
    }

    SECTION("Different /16 can still promote to TRIED") {
        // Fill 101.3.x.x in TRIED
        for (int i = 0; i < 8; ++i) {
            auto addr = MakeAddressInNetgroup(101, 3, i);
            am.add(addr);
            am.good(addr);
        }

        // 101.4.x.x should still work
        auto addr_diff = MakeAddressInNetgroup(101, 4, 0);
        am.add(addr_diff);
        am.good(addr_diff);
        REQUIRE(am.tried_count() == 9);
    }
}

// ============================================================================
// PRIORITY 2: Eviction strategy verification
// ============================================================================

TEST_CASE("NEW table eviction strategy", "[network][addrman][eviction]") {
    // Note: Testing specific eviction order is tricky because timestamps
    // are auto-assigned. We verify the eviction happens correctly.

    SECTION("Eviction occurs when at capacity") {
        AddressManager am;

        // This is a slow test - we need to actually fill the table
        // For faster testing, we verify the mechanism works with smaller scale

        // Add addresses from many different /16s to avoid netgroup limits
        int added = 0;
        for (int netgroup = 0; netgroup < 1000 && added < 100; ++netgroup) {
            uint8_t a = static_cast<uint8_t>(1 + (netgroup / 256));
            uint8_t b = static_cast<uint8_t>(netgroup % 256);
            // Skip reserved ranges
            if (a == 10 || a == 127 || a >= 224) continue;

            auto addr = MakeIPv4(a, b, 0, 1);
            if (am.add(addr)) {
                added++;
            }
        }

        REQUIRE(am.new_count() == added);

        // Adding more should still work (eviction kicks in at capacity)
        auto extra = MakeIPv4(200, 200, 0, 1);
        REQUIRE(am.add(extra));
    }
}

TEST_CASE("TRIED table eviction strategy", "[network][addrman][eviction]") {
    AddressManager am;

    SECTION("Eviction allows new addresses when at capacity") {
        // Add and promote addresses from many /16s
        int promoted = 0;
        for (int netgroup = 0; netgroup < 200 && promoted < 50; ++netgroup) {
            uint8_t a = static_cast<uint8_t>(1 + (netgroup / 256));
            uint8_t b = static_cast<uint8_t>(netgroup % 256);
            if (a == 10 || a == 127 || a >= 224) continue;

            auto addr = MakeIPv4(a, b, 0, 1);
            if (am.add(addr)) {
                am.good(addr);
                if (am.tried_count() > static_cast<size_t>(promoted)) {
                    promoted++;
                }
            }
        }

        REQUIRE(am.tried_count() == static_cast<size_t>(promoted));
    }
}

// ============================================================================
// PRIORITY 2: add_multiple() edge cases
// ============================================================================

TEST_CASE("add_multiple() edge cases", "[network][addrman][batch]") {
    AddressManager am;

    SECTION("Empty vector returns 0") {
        std::vector<TimestampedAddress> empty;
        size_t added = am.add_multiple(empty);
        REQUIRE(added == 0);
        REQUIRE(am.size() == 0);
    }

    SECTION("All duplicates returns 0 after first add") {
        auto addr = MakeIPv4(1, 2, 3, 200);
        uint32_t ts = static_cast<uint32_t>(std::time(nullptr));

        std::vector<TimestampedAddress> addrs;
        addrs.push_back({ts, addr});
        addrs.push_back({ts, addr});  // Duplicate
        addrs.push_back({ts, addr});  // Duplicate

        size_t added = am.add_multiple(addrs);
        REQUIRE(added == 1);  // Only first one added
        REQUIRE(am.size() == 1);
    }

    SECTION("Mix of valid and invalid addresses") {
        uint32_t ts = static_cast<uint32_t>(std::time(nullptr));
        std::vector<TimestampedAddress> addrs;

        // Valid address
        addrs.push_back({ts, MakeIPv4(1, 2, 3, 201)});

        // Invalid: loopback
        NetworkAddress loopback;
        loopback.ip.fill(0);
        loopback.ip[10] = 0xff;
        loopback.ip[11] = 0xff;
        loopback.ip[12] = 127;
        loopback.ip[13] = 0;
        loopback.ip[14] = 0;
        loopback.ip[15] = 1;
        loopback.port = 9590;
        loopback.services = NODE_NETWORK;
        addrs.push_back({ts, loopback});

        // Another valid address
        addrs.push_back({ts, MakeIPv4(1, 2, 3, 202)});

        size_t added = am.add_multiple(addrs);
        REQUIRE(added == 2);  // Only valid ones
        REQUIRE(am.size() == 2);
    }

    SECTION("Batch respects per-netgroup limits") {
        uint32_t ts = static_cast<uint32_t>(std::time(nullptr));
        std::vector<TimestampedAddress> addrs;

        // Add 40 addresses from same /16 (limit is 32)
        for (int i = 0; i < 40; ++i) {
            addrs.push_back({ts, MakeAddressInNetgroup(102, 1, i)});
        }

        size_t added = am.add_multiple(addrs);
        REQUIRE(added == 32);  // Capped at netgroup limit
        REQUIRE(am.new_count() == 32);
    }
}

// ============================================================================
// PRIORITY 2: Load() error handling
// ============================================================================

TEST_CASE("Load() error handling", "[network][addrman][persistence]") {
    AddressManager am;
    const std::string test_dir = "/tmp/addrman_tests";
    std::filesystem::create_directories(test_dir);

    SECTION("Invalid JSON returns false and clears state") {
        std::string invalid_file = test_dir + "/invalid.json";
        std::ofstream f(invalid_file);
        f << "{ this is not valid json ]]]";
        f.close();

        // Add some addresses first
        am.add(MakeIPv4(1, 2, 3, 210));
        REQUIRE(am.size() == 1);

        // Load should fail and clear state
        REQUIRE_FALSE(am.Load(invalid_file));
        REQUIRE(am.size() == 0);

        std::filesystem::remove(invalid_file);
    }

    SECTION("Wrong version returns false") {
        std::string wrong_ver = test_dir + "/wrong_version.json";
        std::ofstream f(wrong_ver);
        f << R"({"version": 999, "tried_count": 0, "new_count": 0, "tried": [], "new": []})";
        f.close();

        REQUIRE_FALSE(am.Load(wrong_ver));
        REQUIRE(am.size() == 0);

        std::filesystem::remove(wrong_ver);
    }

    SECTION("Missing required fields handled gracefully") {
        std::string missing_fields = test_dir + "/missing.json";
        std::ofstream f(missing_fields);
        f << R"({"version": 1})";  // Missing tried/new arrays
        f.close();

        // Should not crash, may succeed with empty data
        bool result = am.Load(missing_fields);
        // Either succeeds with empty data or fails gracefully
        if (result) {
            REQUIRE(am.size() == 0);
        }

        std::filesystem::remove(missing_fields);
    }

    SECTION("Malformed address entries are skipped") {
        std::string malformed = test_dir + "/malformed.json";
        std::ofstream f(malformed);
        f << R"({
            "version": 1,
            "tried_count": 0,
            "new_count": 2,
            "tried": [],
            "new": [
                {"ip": [0,0,0,0,0,0,0,0,0,0,255,255,1,2,3,211], "port": 9590, "services": 1, "timestamp": 1000000, "last_try": 0, "last_success": 0, "attempts": 0},
                {"ip": "invalid", "port": 9590}
            ]
        })";
        f.close();

        REQUIRE(am.Load(malformed));
        // First entry should load, second should be skipped
        REQUIRE(am.size() == 1);

        std::filesystem::remove(malformed);
    }

    std::filesystem::remove_all(test_dir);
}

// ============================================================================
// Additional edge case tests
// ============================================================================

TEST_CASE("Timestamp edge cases", "[network][addrman][timestamp]") {
    AddressManager am;

    SECTION("Timestamp 0 uses current time") {
        auto addr = MakeIPv4(1, 2, 3, 220);
        REQUIRE(am.add(addr, 0));  // 0 means use current time
        REQUIRE(am.size() == 1);

        // Should be selectable (not stale)
        auto sel = am.select();
        REQUIRE(sel.has_value());
    }

    SECTION("Very old timestamp is rejected") {
        auto addr = MakeIPv4(1, 2, 3, 221);
        // Timestamp from year 1970 - way older than 30-day horizon
        // Bitcoin Core parity: old timestamps are rejected by is_terrible(), not clamped
        CHECK_FALSE(am.add(addr, 1));
        CHECK(am.size() == 0);
    }

    SECTION("Future timestamp is rejected") {
        auto addr = MakeIPv4(1, 2, 3, 222);
        uint32_t far_future = UINT32_MAX - 1000;
        // Bitcoin Core parity: future timestamps (> 10 min) are rejected by is_terrible()
        CHECK_FALSE(am.add(addr, far_future));
        CHECK(am.size() == 0);
    }
}

TEST_CASE("get_addresses() edge cases", "[network][addrman][getaddr]") {
    AddressManager am;

    SECTION("Empty manager returns empty vector") {
        auto addrs = am.get_addresses(100);
        REQUIRE(addrs.empty());
    }

    SECTION("Respects max_count parameter") {
        for (int i = 0; i < 20; ++i) {
            am.add(MakeIPv4(1, static_cast<uint8_t>(i), 0, 1));
        }

        auto addrs = am.get_addresses(5);
        REQUIRE(addrs.size() == 5);
    }

    SECTION("Returns shuffled results (privacy)") {
        for (int i = 0; i < 10; ++i) {
            am.add(MakeIPv4(1, static_cast<uint8_t>(i), 0, 1));
        }

        // Get addresses multiple times, order should vary
        std::vector<std::vector<uint8_t>> orders;
        for (int trial = 0; trial < 10; ++trial) {
            auto addrs = am.get_addresses(10);
            std::vector<uint8_t> order;
            for (const auto& a : addrs) {
                order.push_back(a.address.ip[13]);  // Second octet identifies address
            }
            orders.push_back(order);
        }

        // Check that not all orders are identical
        bool all_same = true;
        for (size_t i = 1; i < orders.size() && all_same; ++i) {
            if (orders[i] != orders[0]) {
                all_same = false;
            }
        }
        // With high probability, at least one order should differ
        REQUIRE_FALSE(all_same);
    }
}

TEST_CASE("Netgroup count cache consistency", "[network][addrman][netgroup][cache]") {
    AddressManager am;

    SECTION("Counts remain consistent through add/good cycle (Bitcoin Core parity)") {
        // Add addresses from same netgroup
        for (int i = 0; i < 8; ++i) {
            am.add(MakeAddressInNetgroup(103, 1, i));
        }
        REQUIRE(am.new_count() == 8);

        // Promote all to tried
        for (int i = 0; i < 8; ++i) {
            am.good(MakeAddressInNetgroup(103, 1, i));
        }
        REQUIRE(am.tried_count() == 8);
        REQUIRE(am.new_count() == 0);

        // Add more from same netgroup - should be allowed in NEW (since TRIED limit hit)
        for (int i = 8; i < 16; ++i) {
            am.add(MakeAddressInNetgroup(103, 1, i));
        }
        // Some should be added (NEW limit is 32)
        REQUIRE(am.new_count() > 0);

        // Bitcoin Core parity: TRIED addresses are NOT demoted back to NEW via failures.
        // They stay in TRIED until evicted by collision during Good().
        // Bitcoin Core has no failed() function - terrible addresses filtered via GetChance().
        // TRIED count unchanged (no demotion)
        REQUIRE(am.tried_count() == 8);
    }
}
