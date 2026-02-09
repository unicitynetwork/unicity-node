// Copyright (c) 2025 The Unicity Foundation
// Timestamp Clamping Adversarial Tests
//
// Tests for timestamp clamping boundary conditions and potential attack vectors.
// The AddressManager clamps timestamps to prevent:
// 1. Future timestamps (clamped to now)
// 2. Absurdly old timestamps (> 10 years, clamped to now)
// 3. Zero timestamps (use current time)
//
// Attack vectors tested:
// 1. Exact 10-year boundary exploitation
// 2. Far future timestamps (year 2100)
// 3. Using old timestamps to influence address selection priority
// 4. GETADDR response timestamp validation

#include "catch_amalgamated.hpp"
#include "network/addr_manager.hpp"
#include "network/protocol.hpp"
#include <chrono>
#include <cstring>

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

    int a, b, c, d;
    if (sscanf(ip_v4.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
        addr.ip[12] = static_cast<uint8_t>(a);
        addr.ip[13] = static_cast<uint8_t>(b);
        addr.ip[14] = static_cast<uint8_t>(c);
        addr.ip[15] = static_cast<uint8_t>(d);
    }

    return addr;
}

// Helper to get current Unix timestamp
static uint32_t now_timestamp() {
    return static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

// Constants matching addr_manager.cpp
static constexpr uint32_t ADDRMAN_HORIZON_DAYS = 30;
static constexpr uint32_t SECONDS_PER_DAY = 24 * 60 * 60;

// =============================================================================
// TEST 1: Timestamp boundary conditions (Bitcoin Core parity)
// =============================================================================
// Matching Bitcoin Core behavior:
// - Timestamps > 30 days old are rejected by is_terrible()
// - Timestamps > 10 min in future are rejected by is_terrible()
// - NO clamping of old timestamps to "now" (that was a bug creating a bypass)

TEST_CASE("Timestamp clamping: boundary conditions", "[network][addrman][timestamp][boundary]") {
    AddressManager addrman;
    uint32_t now = now_timestamp();

    SECTION("31 days old - rejected by is_terrible (> ADDRMAN_HORIZON)") {
        uint32_t days_31 = now - (31 * SECONDS_PER_DAY);

        auto addr = MakeAddress("93.184.216.34", 9590);
        bool added = addrman.add(addr, days_31);

        INFO("Timestamp: " << days_31 << " (31 days old)");
        CHECK_FALSE(added);  // Rejected by is_terrible
        CHECK(addrman.size() == 0);
    }

    SECTION("1 year old - rejected by is_terrible (> 30 days)") {
        uint32_t one_year = now - (365 * SECONDS_PER_DAY);

        auto addr = MakeAddress("93.184.216.35", 9590);
        bool added = addrman.add(addr, one_year);

        INFO("Timestamp: " << one_year << " (1 year old)");
        CHECK_FALSE(added);  // Rejected by is_terrible
        CHECK(addrman.size() == 0);
    }

    SECTION("11 years old - rejected by is_terrible (NO bypass via clamping)") {
        // Previously this would be clamped to "now" and accepted - that was a bug!
        // Now it's correctly rejected like any other old timestamp
        uint32_t eleven_years = now - (11u * 365u * SECONDS_PER_DAY);

        auto addr = MakeAddress("93.184.216.36", 9590);
        bool added = addrman.add(addr, eleven_years);

        INFO("Timestamp: " << eleven_years << " (11 years old)");
        CHECK_FALSE(added);  // Rejected by is_terrible - no bypass!
        CHECK(addrman.size() == 0);
    }

    SECTION("29 days old - accepted (within ADDRMAN_HORIZON)") {
        uint32_t days_29 = now - (29 * SECONDS_PER_DAY);

        auto addr = MakeAddress("93.184.216.37", 9590);
        REQUIRE(addrman.add(addr, days_29));
        REQUIRE(addrman.size() == 1);

        auto addrs = addrman.get_addresses(10);
        REQUIRE(addrs.size() == 1);

        // Timestamp preserved (not clamped)
        INFO("Original timestamp: " << days_29);
        INFO("Returned timestamp: " << addrs[0].timestamp);

        CHECK(addrs[0].timestamp >= days_29 - 5);
        CHECK(addrs[0].timestamp <= days_29 + 5);
    }
}

// =============================================================================
// TEST 2: Timestamp = 0 uses current time
// =============================================================================
// When timestamp is 0, the code should substitute current time.

TEST_CASE("Timestamp clamping: zero timestamp", "[network][addrman][timestamp][zero]") {
    AddressManager addrman;
    uint32_t now = now_timestamp();

    auto addr = MakeAddress("93.184.216.40", 9590);
    REQUIRE(addrman.add(addr, 0));  // timestamp = 0
    REQUIRE(addrman.size() == 1);

    auto addrs = addrman.get_addresses(10);
    REQUIRE(addrs.size() == 1);

    // Timestamp should be set to approximately current time
    INFO("Returned timestamp: " << addrs[0].timestamp);
    INFO("Now: " << now);

    uint32_t current = now_timestamp();
    CHECK(addrs[0].timestamp >= now - 5);
    CHECK(addrs[0].timestamp <= current + 5);
}

// =============================================================================
// TEST 3: Far future timestamp (Bitcoin Core parity)
// =============================================================================
// Future timestamps > 10 minutes are rejected by is_terrible().

TEST_CASE("Timestamp clamping: far future timestamp", "[network][addrman][timestamp][future]") {
    AddressManager addrman;
    uint32_t now = now_timestamp();

    SECTION("Year 2100 timestamp - rejected") {
        // Unix timestamp for Jan 1, 2100 (approximate)
        uint32_t year_2100 = 4102444800u;

        auto addr = MakeAddress("93.184.216.50", 9590);
        bool added = addrman.add(addr, year_2100);

        // Bitcoin Core parity: future timestamps > 10 min are rejected
        CHECK_FALSE(added);
        CHECK(addrman.size() == 0);
    }

    SECTION("5 minutes in the future - accepted") {
        // Within the 10-minute grace period
        uint32_t five_min_future = now + 300;

        auto addr = MakeAddress("93.184.216.51", 9590);
        REQUIRE(addrman.add(addr, five_min_future));
        REQUIRE(addrman.size() == 1);

        auto addrs = addrman.get_addresses(10);
        REQUIRE(addrs.size() == 1);

        // Timestamp preserved (within grace period)
        CHECK(addrs[0].timestamp >= five_min_future - 5);
    }

    SECTION("11 minutes in the future - rejected") {
        // Just over the 10-minute threshold
        uint32_t eleven_min_future = now + 660;

        auto addr = MakeAddress("93.184.216.52", 9590);
        bool added = addrman.add(addr, eleven_min_future);

        // Bitcoin Core parity: > 10 min future is terrible
        CHECK_FALSE(added);
        CHECK(addrman.size() == 0);
    }

    SECTION("UINT32_MAX timestamp - rejected") {
        uint32_t max_ts = UINT32_MAX;

        auto addr = MakeAddress("93.184.216.53", 9590);
        bool added = addrman.add(addr, max_ts);

        // Obviously > 10 min in future
        CHECK_FALSE(added);
        CHECK(addrman.size() == 0);
    }
}

// =============================================================================
// TEST 4: Attacker using old timestamps to influence selection
// =============================================================================
// All addresses with timestamps > 30 days are rejected by is_terrible().
// No bypass exists - old timestamps are consistently rejected.

TEST_CASE("Timestamp clamping: old timestamp selection influence", "[network][addrman][timestamp][selection]") {
    AddressManager addrman;
    uint32_t now = now_timestamp();

    // Recent timestamp (1 hour ago) - ACCEPTED
    auto addr_recent = MakeAddress("93.184.216.60", 9590);
    bool added_recent = addrman.add(addr_recent, now - 3600);
    CHECK(added_recent);

    // 20 days old - still within ADDRMAN_HORIZON (30 days) - ACCEPTED
    auto addr_20days = MakeAddress("93.184.216.61", 9590);
    bool added_20days = addrman.add(addr_20days, now - (20 * SECONDS_PER_DAY));
    CHECK(added_20days);

    // 1 year old - rejected by is_terrible (> 30 days) - REJECTED
    auto addr_1year = MakeAddress("93.184.216.62", 9590);
    bool added_1year = addrman.add(addr_1year, now - (365 * SECONDS_PER_DAY));
    CHECK_FALSE(added_1year);

    // 11 years old - ALSO rejected by is_terrible (no bypass!) - REJECTED
    auto addr_11years = MakeAddress("93.184.216.63", 9590);
    bool added_11years = addrman.add(addr_11years, now - (11u * 365u * SECONDS_PER_DAY));
    CHECK_FALSE(added_11years);  // No longer bypasses via clamping!

    // Should have 2 addresses (recent, 20days)
    CHECK(addrman.size() == 2);

    // Verify addresses are selectable
    auto addrs = addrman.get_addresses(10);
    INFO("Addresses returned: " << addrs.size());
    CHECK(addrs.size() == 2);
}

// =============================================================================
// TEST 5: GETADDR response only contains valid addresses
// =============================================================================
// Addresses with bad timestamps are rejected at add time, so GETADDR
// responses only contain addresses with valid timestamps.

TEST_CASE("Timestamp clamping: GETADDR response validation", "[network][addrman][timestamp][getaddr]") {
    AddressManager addrman;
    uint32_t now = now_timestamp();

    // Future timestamp (1 day) - should be REJECTED by is_terrible
    auto addr_future = MakeAddress("93.184.216.70", 9590);
    uint32_t future_ts = now + 86400;  // 1 day in future (> 10 min)
    bool added_future = addrman.add(addr_future, future_ts);
    CHECK_FALSE(added_future);  // Rejected by is_terrible (> 10 min future)

    // Very old timestamp (15 years) - should be REJECTED by is_terrible
    auto addr_old = MakeAddress("93.184.216.71", 9590);
    uint32_t old_ts = now - (15u * 365u * SECONDS_PER_DAY);  // 15 years ago
    bool added_old = addrman.add(addr_old, old_ts);
    CHECK_FALSE(added_old);  // Rejected by is_terrible (> 30 days)

    // Valid timestamps within range
    auto addr_recent = MakeAddress("93.184.216.72", 9590);
    REQUIRE(addrman.add(addr_recent, now - 3600));  // 1 hour ago

    auto addr_week = MakeAddress("93.184.216.73", 9590);
    REQUIRE(addrman.add(addr_week, now - (7 * SECONDS_PER_DAY)));  // 1 week ago

    // Get addresses (simulating GETADDR response)
    auto addrs = addrman.get_addresses(10);
    REQUIRE(addrs.size() == 2);

    uint32_t current = now_timestamp();

    for (const auto& ta : addrs) {
        auto str = ta.address.to_string();
        INFO("Address: " << (str ? *str : "unknown"));
        INFO("Timestamp: " << ta.timestamp);

        // ALL timestamps in GETADDR response must be within valid range
        CHECK(ta.timestamp <= current + 600);  // Not > 10 min in future
        CHECK(ta.timestamp >= now - (30 * SECONDS_PER_DAY));  // Not > 30 days old
    }
}

// =============================================================================
// TEST 6: Timestamp update on duplicate address
// =============================================================================
// When an address is re-added with a different timestamp, the newer
// timestamp should be used (if valid).

TEST_CASE("Timestamp clamping: update on duplicate", "[network][addrman][timestamp][update]") {
    AddressManager addrman;
    uint32_t now = now_timestamp();

    // Add address with old-ish timestamp (within 30-day horizon)
    auto addr = MakeAddress("93.184.216.80", 9590);
    uint32_t old_ts = now - (20 * SECONDS_PER_DAY);  // 20 days ago
    REQUIRE(addrman.add(addr, old_ts));

    auto addrs1 = addrman.get_addresses(10);
    REQUIRE(addrs1.size() == 1);
    uint32_t stored_ts1 = addrs1[0].timestamp;
    INFO("Initial timestamp: " << stored_ts1);

    // Re-add with newer timestamp
    uint32_t new_ts = now - 3600;  // 1 hour ago
    bool added = addrman.add(addr, new_ts);
    CHECK_FALSE(added);  // Duplicate, returns false

    auto addrs2 = addrman.get_addresses(10);
    REQUIRE(addrs2.size() == 1);
    uint32_t stored_ts2 = addrs2[0].timestamp;
    INFO("Updated timestamp: " << stored_ts2);

    // Timestamp should be updated to newer value
    CHECK(stored_ts2 >= stored_ts1);
}

// =============================================================================
// TEST 7: Edge cases and overflow safety
// =============================================================================
// Ensure edge cases are handled correctly.

TEST_CASE("Timestamp clamping: edge cases", "[network][addrman][timestamp][overflow]") {
    AddressManager addrman;

    SECTION("Very old timestamp (year 1970) is rejected") {
        // A timestamp of 1 is ~50 years ago, way beyond the 30-day horizon
        auto addr = MakeAddress("93.184.216.90", 9590);
        uint32_t small_ts = 1;  // Very old timestamp
        bool added = addrman.add(addr, small_ts);

        // Should be REJECTED by is_terrible (> 30 days old)
        CHECK_FALSE(added);
        CHECK(addrman.size() == 0);
    }

    SECTION("Timestamp 0 means use current time") {
        auto addr = MakeAddress("93.184.216.91", 9590);
        uint32_t epoch = 0;
        REQUIRE(addrman.add(addr, epoch));  // 0 means use current time
        REQUIRE(addrman.size() == 1);

        auto addrs = addrman.get_addresses(10);
        REQUIRE(addrs.size() == 1);

        // Timestamp 0 is treated as "use current time"
        uint32_t now = now_timestamp();
        CHECK(addrs[0].timestamp >= now - 10);
    }
}
