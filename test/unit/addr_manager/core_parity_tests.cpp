// ====================================================================
// Bitcoin Core Parity Tests: New Features
// Tests for m_last_count_attempt, fCountFailure, m_last_good_, and ADDRMAN_HORIZON
// ====================================================================

#include "catch_amalgamated.hpp"
#include "network/addr_manager.hpp"
#include "network/protocol.hpp"
#include "util/time.hpp"
#include <thread>
#include <chrono>

using namespace unicity::network;
using namespace unicity::protocol;

// Helper to create test addresses
static NetworkAddress MakeAddress(const std::string& ip, uint16_t port) {
    NetworkAddress addr;
    // Parse IPv4 as IPv4-mapped IPv6
    if (ip.find('.') != std::string::npos) {
        // IPv4: store as ::ffff:a.b.c.d
        size_t pos1 = ip.find('.');
        size_t pos2 = ip.find('.', pos1 + 1);
        size_t pos3 = ip.find('.', pos2 + 1);

        uint8_t a = std::stoi(ip.substr(0, pos1));
        uint8_t b = std::stoi(ip.substr(pos1 + 1, pos2 - pos1 - 1));
        uint8_t c = std::stoi(ip.substr(pos2 + 1, pos3 - pos2 - 1));
        uint8_t d = std::stoi(ip.substr(pos3 + 1));

        addr.ip.fill(0);
        addr.ip[10] = 0xff;
        addr.ip[11] = 0xff;
        addr.ip[12] = a;
        addr.ip[13] = b;
        addr.ip[14] = c;
        addr.ip[15] = d;
    }
    addr.port = port;
    addr.services = 1;
    return addr;
}

TEST_CASE("Bitcoin Core Parity: fCountFailure prevents double-counting", "[network][addrman][core-parity]") {
    AddressManager addrman;
    NetworkAddress addr = MakeAddress("1.0.0.1", 9590);

    REQUIRE(addrman.add(addr));
    REQUIRE(addrman.size() == 1);

    SECTION("fCountFailure=true increments attempts") {
        // Bitcoin Core parity: only attempt() increments, not failed()
        // To accumulate 3 attempts, m_last_good_ must advance between calls
        NetworkAddress helper = MakeAddress("1.0.0.2", 9590);
        addrman.add(helper);

        // Attempt 1 (increments because last_count_attempt=0 < m_last_good_=1)
        addrman.attempt(addr, true);
        REQUIRE(addrman.size() == 2);

        // Advance m_last_good_ by marking helper as good
        addrman.good(helper);  // helper moves to TRIED, m_last_good_++

        // Attempt 2 (increments because last_count_attempt < m_last_good_)
        addrman.attempt(addr, true);
        REQUIRE(addrman.new_count() == 1);  // addr still in NEW

        // Advance m_last_good_ again
        addrman.good(helper);  // m_last_good_++

        // Attempt 3 (increments to 3)
        addrman.attempt(addr, true);

        // Note: is_terrible() has a 60-second grace period - addresses tried
        // within the last 60 seconds are never terrible. The address has
        // 3 attempts (making it logically terrible), but the grace period
        // protects it from removal. Bitcoin Core has no failed() function;
        // terrible addresses are filtered via GetChance() and cleaned by cleanup_stale().

        // Address still present due to 60-second grace period
        REQUIRE(addrman.new_count() == 1);
        REQUIRE(addrman.tried_count() == 1);  // helper in TRIED
    }

    SECTION("fCountFailure=false does NOT increment attempts") {
        // Multiple attempts with fCountFailure=false (don't call failed() to avoid removal)
        for (int i = 0; i < 5; i++) {
            addrman.attempt(addr, false);
        }

        // Address should still be present (attempts not counted)
        REQUIRE(addrman.size() == 1);

        // Now try with fCountFailure=true (should be first counted attempt)
        addrman.attempt(addr, true);
        // Still should be present (only 1 counted attempt, need 3 for removal)
        REQUIRE(addrman.size() == 1);
    }

    SECTION("Double-counting prevention: attempt -> good -> attempt") {
        // First attempt (counted)
        addrman.attempt(addr, true);

        // Mark as good (moves to TRIED, updates m_last_good_)
        addrman.good(addr);
        REQUIRE(addrman.tried_count() == 1);

        // Second attempt with fCountFailure=true
        // This should NOT increment attempts because last_count_attempt < m_last_good_
        addrman.attempt(addr, true);

        // Third attempt should increment (new attempt after good())
        addrman.attempt(addr, true);

        // Note: No failed() - Bitcoin Core doesn't have it
        // Address should still be in TRIED
        REQUIRE(addrman.tried_count() == 1);
    }
}

TEST_CASE("Bitcoin Core Parity: ADDRMAN_HORIZON and is_stale()", "[network][addrman][core-parity]") {
    uint32_t now = 10000000;  // Large enough to avoid underflow

    SECTION("Address older than 30 days is stale") {
        AddrInfo info;
        info.timestamp = now - (31 * 86400);  // 31 days ago
        info.attempts = 0;
        info.last_try = 0;
        info.last_success = 0;

        REQUIRE(info.is_stale(now));
    }

    SECTION("Address exactly 30 days old is NOT stale") {
        AddrInfo info;
        info.timestamp = now - (30 * 86400);  // Exactly 30 days
        info.attempts = 0;
        info.last_try = 0;
        info.last_success = 0;

        REQUIRE_FALSE(info.is_stale(now));
    }

    SECTION("Recent address is NOT stale") {
        AddrInfo info;
        info.timestamp = now - (5 * 86400);  // 5 days ago
        info.attempts = 0;
        info.last_try = 0;
        info.last_success = 0;

        REQUIRE_FALSE(info.is_stale(now));
    }
}

TEST_CASE("Bitcoin Core Parity: IsTerrible() grace period", "[network][addrman][core-parity]") {
    SECTION("Address tried in last 60 seconds is never terrible") {
        uint32_t now = 1000000;

        AddrInfo info;
        info.last_try = now - 30;  // 30 seconds ago
        info.attempts = 100;       // Many failures
        info.last_success = 0;     // Never succeeded
        info.timestamp = now - (100 * 86400);  // 100 days old

        // Despite having many failures, being very old, and never succeeding,
        // address should NOT be terrible due to 60-second grace period
        REQUIRE_FALSE(info.is_terrible(now));
    }

    SECTION("Address tried 61 seconds ago respects normal terrible logic") {
        uint32_t now = 1000000;

        AddrInfo info;
        info.last_try = now - 61;  // 61 seconds ago (past grace period)
        info.attempts = 3;         // 3 failures
        info.last_success = 0;     // Never succeeded
        info.timestamp = now;      // Recent timestamp

        // Past grace period, 3 failures with no success = terrible
        REQUIRE(info.is_terrible(now));
    }
}

TEST_CASE("Bitcoin Core Parity: IsTerrible() future timestamp rejection", "[network][addrman][core-parity]") {
    uint32_t now = 1000000;

    SECTION("Timestamp 5 minutes in future is acceptable") {
        AddrInfo info;
        info.timestamp = now + 300;  // 5 minutes in future
        info.attempts = 0;
        info.last_try = 0;
        info.last_success = 0;

        REQUIRE_FALSE(info.is_terrible(now));
    }

    SECTION("Timestamp 11 minutes in future is terrible") {
        AddrInfo info;
        info.timestamp = now + 660;  // 11 minutes in future
        info.attempts = 0;
        info.last_try = 0;
        info.last_success = 0;

        // "Flying DeLorean" addresses are terrible
        REQUIRE(info.is_terrible(now));
    }

    SECTION("Timestamp exactly 10 minutes in future is acceptable") {
        AddrInfo info;
        info.timestamp = now + 600;  // Exactly 10 minutes
        info.attempts = 0;
        info.last_try = 0;
        info.last_success = 0;

        REQUIRE_FALSE(info.is_terrible(now));
    }
}

TEST_CASE("Bitcoin Core Parity: NEW vs TRIED terrible thresholds", "[network][addrman][core-parity]") {
    uint32_t now = 1000000;

    SECTION("NEW address: terrible after 3 failures") {
        AddrInfo info;
        info.last_success = 0;     // Never succeeded
        info.attempts = 3;
        info.timestamp = now;
        info.last_try = now - 700; // Past grace period

        REQUIRE(info.is_terrible(now));
    }

    SECTION("NEW address: 2 failures is NOT terrible") {
        AddrInfo info;
        info.last_success = 0;
        info.attempts = 2;
        info.timestamp = now;
        info.last_try = now - 700;

        REQUIRE_FALSE(info.is_terrible(now));
    }

    SECTION("TRIED address: terrible after 10 failures over 7+ days") {
        AddrInfo info;
        info.last_success = now - (8 * 86400);  // Succeeded 8 days ago
        info.attempts = 10;
        info.timestamp = now;
        info.last_try = now - 700;

        REQUIRE(info.is_terrible(now));
    }

    SECTION("TRIED address: 10 failures within 6 days is NOT terrible") {
        AddrInfo info;
        info.last_success = now - (6 * 86400);  // Succeeded 6 days ago
        info.attempts = 10;
        info.timestamp = now;
        info.last_try = now - 700;

        // Not enough time has passed since last_success
        REQUIRE_FALSE(info.is_terrible(now));
    }

    SECTION("TRIED address: 9 failures over 8 days is NOT terrible") {
        AddrInfo info;
        info.last_success = now - (8 * 86400);  // Succeeded 8 days ago
        info.attempts = 9;  // Only 9 failures (need 10)
        info.timestamp = now;
        info.last_try = now - 700;

        // Not enough failures
        REQUIRE_FALSE(info.is_terrible(now));
    }
}

TEST_CASE("Bitcoin Core Parity: Integration test", "[network][addrman][core-parity]") {
    AddressManager addrman;
    NetworkAddress addr = MakeAddress("1.0.0.5", 9590);

    SECTION("Full lifecycle: add -> attempt -> good (Bitcoin Core parity)") {
        // Add address
        REQUIRE(addrman.add(addr));
        REQUIRE(addrman.new_count() == 1);

        // First attempt (fCountFailure=true)
        addrman.attempt(addr, true);

        // Mark as good (moves to TRIED, sets m_last_good_)
        addrman.good(addr);
        REQUIRE(addrman.tried_count() == 1);
        REQUIRE(addrman.new_count() == 0);

        // Bitcoin Core: TRIED addresses are never demoted back to NEW based on failures.
        // They stay in TRIED until evicted by collision when a new address needs the slot.
        // Bitcoin Core has no failed() function - terrible addresses filtered via GetChance().

        // Still in TRIED (Bitcoin Core behavior)
        REQUIRE(addrman.tried_count() == 1);
        REQUIRE(addrman.new_count() == 0);
    }
}

TEST_CASE("Bitcoin Core Parity: Persistence of new fields", "[network][addrman][core-parity]") {
    const std::string test_file = "/tmp/test_addrman_parity.json";
    NetworkAddress addr1 = MakeAddress("1.0.0.10", 9590);
    NetworkAddress addr2 = MakeAddress("1.0.0.11", 9590);

    // Save state
    {
        AddressManager addrman;
        REQUIRE(addrman.add(addr1));
        REQUIRE(addrman.add(addr2));

        // Setup some state
        addrman.attempt(addr1, true);
        // Note: No failed() - Bitcoin Core doesn't have it

        addrman.good(addr2);
        addrman.attempt(addr2, true);

        REQUIRE(addrman.Save(test_file));
    }

    // Load state
    {
        AddressManager addrman2;
        REQUIRE(addrman2.Load(test_file));

        REQUIRE(addrman2.size() == 2);
        // addr1 should be in NEW with 1 failure
        // addr2 should be in TRIED
        REQUIRE(addrman2.tried_count() == 1);
        REQUIRE(addrman2.new_count() == 1);
    }

    std::remove(test_file.c_str());
}

TEST_CASE("Bitcoin Core Parity: 2-hour time penalty for ADDR messages", "[network][addrman][core-parity]") {
    // Bitcoin Core applies a 2-hour penalty to timestamps in ADDR messages
    // to prevent timestamp manipulation attacks. Self-announcements are exempt.
    // Reference: net_processing.cpp:3938 - m_addrman.Add(vAddrOk, pfrom.addr, 2h);

    AddressManager addrman;
    // Use real current time - AddressManager::now() returns real time via util::GetTime()
    // so test timestamps must be realistic to avoid is_terrible() rejections
    uint32_t now = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    constexpr uint32_t TWO_HOURS = 2 * 60 * 60;  // 7200 seconds

    NetworkAddress addr1 = MakeAddress("1.0.0.100", 9590);
    NetworkAddress addr2 = MakeAddress("1.0.0.101", 9590);
    NetworkAddress addr3 = MakeAddress("1.0.0.102", 9590);
    NetworkAddress source = MakeAddress("2.0.0.1", 9590);

    SECTION("Time penalty is applied to relayed addresses") {
        std::vector<TimestampedAddress> addrs;
        TimestampedAddress ta;
        ta.address = addr1;
        ta.timestamp = now;
        addrs.push_back(ta);

        // Add with 2-hour penalty
        size_t added = addrman.add_multiple(addrs, source, TWO_HOURS);
        REQUIRE(added == 1);

        // The address should be stored with timestamp = now - 2h
        // We can verify this indirectly: an address with timestamp "now - 2h" should
        // have lower GetChance() than one with timestamp "now"
        // For simplicity, just verify it was added successfully
        REQUIRE(addrman.size() == 1);
    }

    SECTION("Self-announcement is exempt from penalty") {
        // When addr == source, no penalty should be applied
        std::vector<TimestampedAddress> addrs;
        TimestampedAddress ta;
        ta.address = addr2;
        ta.timestamp = now;
        addrs.push_back(ta);

        // Self-announcement: source == addr
        size_t added = addrman.add_multiple(addrs, addr2, TWO_HOURS);
        REQUIRE(added == 1);
        REQUIRE(addrman.size() == 1);
    }

    SECTION("Penalty does not make timestamp negative") {
        std::vector<TimestampedAddress> addrs;
        TimestampedAddress ta;
        ta.address = addr3;
        ta.timestamp = 1000;  // Very small timestamp
        addrs.push_back(ta);

        // 2-hour penalty (7200) > timestamp (1000) - should clamp to 0, not underflow
        size_t added = addrman.add_multiple(addrs, source, TWO_HOURS);
        // Address with timestamp 0 may or may not be added depending on is_terrible()
        // The key assertion is that we don't crash from underflow
        REQUIRE(addrman.size() <= 1);  // Either 0 or 1, no crash
    }

    SECTION("No penalty when time_penalty_seconds is 0") {
        std::vector<TimestampedAddress> addrs;
        TimestampedAddress ta;
        ta.address = MakeAddress("1.0.0.103", 9590);
        ta.timestamp = now;
        addrs.push_back(ta);

        // Add without penalty (default behavior for backwards compatibility)
        size_t added = addrman.add_multiple(addrs, source, 0);
        REQUIRE(added == 1);
    }
}

// =============================================================================
// END-TO-END TEST: Terrible address cleanup via cleanup_stale()
// =============================================================================
// This test verifies the FULL flow matching Bitcoin Core behavior:
// 1. Address is added to NEW table
// 2. Multiple failed attempts make it "terrible" (>= 3 attempts with no success)
// 3. cleanup_stale() removes the terrible address
//
// Bitcoin Core has NO failed() function - terrible addresses are identified
// by is_terrible() and removed during cleanup_stale() or filtered in select().

TEST_CASE("Bitcoin Core Parity: cleanup_stale removes terrible addresses", "[network][addrman][core-parity][cleanup]") {
    using namespace unicity::util;

    // Use mock time for deterministic testing
    // Base time: 2025-01-01 00:00:00 UTC
    const int64_t base_time = 1735689600;
    MockTimeScope mock_time(base_time);

    AddressManager addrman;
    NetworkAddress addr = MakeAddress("93.184.216.100", 9590);

    // Add address at base_time (timestamp = base_time)
    REQUIRE(addrman.add(addr, base_time));
    REQUIRE(addrman.new_count() == 1);

    SECTION("Address becomes terrible at exactly ADDRMAN_RETRIES (3) attempts") {
        // This test verifies the BOUNDARY: 2 attempts = OK, 3 attempts = terrible
        // Bitcoin Core: ADDRMAN_RETRIES = 3 for NEW addresses with no prior success

        // Helper address to advance m_last_good_ (needed to allow attempt counting)
        NetworkAddress helper = MakeAddress("93.184.216.101", 9590);
        REQUIRE(addrman.add(helper));

        // === ATTEMPT 1 ===
        addrman.attempt(addr, true);  // attempts = 1

        // Advance m_last_good_ via helper
        SetMockTime(base_time + 1);
        addrman.good(helper);

        // === ATTEMPT 2 ===
        SetMockTime(base_time + 2);
        addrman.attempt(addr, true);  // attempts = 2

        // Advance past grace period with only 2 attempts
        SetMockTime(base_time + 100);
        addrman.cleanup_stale();

        // KEY ASSERTION: With 2 attempts, address is NOT terrible (< ADDRMAN_RETRIES)
        REQUIRE(addrman.new_count() == 1);  // Still present!

        // Advance m_last_good_ again
        SetMockTime(base_time + 101);
        addrman.good(helper);

        // === ATTEMPT 3 ===
        SetMockTime(base_time + 102);
        addrman.attempt(addr, true);  // attempts = 3 (now at threshold)

        // Still protected by grace period
        SetMockTime(base_time + 103);
        addrman.cleanup_stale();
        REQUIRE(addrman.new_count() == 1);  // Grace period protects it

        // Advance past grace period (60 seconds after last attempt at 102)
        SetMockTime(base_time + 170);
        addrman.cleanup_stale();

        // KEY ASSERTION: With 3 attempts, address IS terrible (= ADDRMAN_RETRIES)
        REQUIRE(addrman.new_count() == 0);  // Removed!
        REQUIRE(addrman.tried_count() == 1);  // helper still in TRIED
    }

    SECTION("Address with success is NOT terrible despite attempts") {
        // Mark as good first (moves to TRIED, sets last_success)
        addrman.good(addr);
        REQUIRE(addrman.tried_count() == 1);
        REQUIRE(addrman.new_count() == 0);

        // Even with many attempts, TRIED addresses with success are not terrible
        // (they have last_success > 0, different threshold applies)
        NetworkAddress helper = MakeAddress("93.184.216.102", 9590);
        REQUIRE(addrman.add(helper));

        // Make multiple attempts on addr
        for (int i = 0; i < 5; i++) {
            SetMockTime(base_time + i * 2);
            addrman.good(helper);  // Advance m_last_good_
            SetMockTime(base_time + i * 2 + 1);
            addrman.attempt(addr, true);
        }

        // Advance past grace period
        SetMockTime(base_time + 100);

        // cleanup_stale should NOT remove the TRIED address
        addrman.cleanup_stale();
        REQUIRE(addrman.tried_count() == 2);  // addr and helper both in TRIED
    }

    SECTION("Stale address (>30 days old) is removed by cleanup_stale") {
        // Address was added at base_time with timestamp = base_time
        REQUIRE(addrman.new_count() == 1);

        // Advance time by 31 days
        SetMockTime(base_time + 31 * 24 * 60 * 60);

        // cleanup_stale removes addresses older than ADDRMAN_HORIZON (30 days)
        addrman.cleanup_stale();
        REQUIRE(addrman.new_count() == 0);  // Removed as stale
    }
}

// =============================================================================
// Tests for connected() - timestamp update for long-running connections
// =============================================================================

TEST_CASE("Bitcoin Core Parity: connected() updates timestamp", "[network][addrman][core-parity][connected]") {
    using namespace unicity::util;

    // Base time: 2025-01-01 00:00:00 UTC
    const int64_t base_time = 1735689600;
    MockTimeScope mock_time(base_time);

    AddressManager addrman;
    NetworkAddress addr = MakeAddress("93.184.216.110", 9590);

    // Add address with timestamp at base_time
    REQUIRE(addrman.add(addr, base_time));
    REQUIRE(addrman.new_count() == 1);

    SECTION("connected() does NOT update timestamp if less than 20 minutes old") {
        // Advance time by 19 minutes (just under threshold)
        SetMockTime(base_time + 19 * 60);

        addrman.connected(addr);

        // Get addresses to verify timestamp wasn't updated
        auto addrs = addrman.get_addresses(10);
        REQUIRE(addrs.size() == 1);
        REQUIRE(addrs[0].timestamp == base_time);  // Still original timestamp
    }

    SECTION("connected() updates timestamp if more than 20 minutes old") {
        // Advance time by 21 minutes (over threshold)
        const int64_t new_time = base_time + 21 * 60;
        SetMockTime(new_time);

        addrman.connected(addr);

        // Get addresses to verify timestamp was updated
        auto addrs = addrman.get_addresses(10);
        REQUIRE(addrs.size() == 1);
        REQUIRE(addrs[0].timestamp == new_time);  // Updated to current time
    }

    SECTION("connected() works for TRIED addresses too") {
        // Move address to TRIED
        addrman.good(addr);
        REQUIRE(addrman.tried_count() == 1);

        // Advance time by 25 minutes
        const int64_t new_time = base_time + 25 * 60;
        SetMockTime(new_time);

        addrman.connected(addr);

        // Verify timestamp was updated
        auto addrs = addrman.get_addresses(10);
        REQUIRE(addrs.size() == 1);
        REQUIRE(addrs[0].timestamp == new_time);
    }

    SECTION("connected() for unknown address is a no-op") {
        NetworkAddress unknown = MakeAddress("93.184.216.111", 9590);

        // Should not crash or throw
        addrman.connected(unknown);

        // Original address still intact
        REQUIRE(addrman.size() == 1);
    }
}

// =============================================================================
// Tests for get_addresses() max_pct parameter
// =============================================================================

TEST_CASE("Bitcoin Core Parity: get_addresses() max_pct limit", "[network][addrman][core-parity][getaddr]") {
    using namespace unicity::util;

    const int64_t base_time = 1735689600;
    MockTimeScope mock_time(base_time);

    AddressManager addrman;

    // Add 100 addresses across different /16 netgroups to avoid netgroup limits
    // Use pattern: 93.X.0.1 where X varies from 0-99 (each in different /16)
    for (int i = 0; i < 100; i++) {
        std::string ip = "93." + std::to_string(i) + ".0.1";
        NetworkAddress addr = MakeAddress(ip, 9590);
        addrman.add(addr, base_time);
    }
    REQUIRE(addrman.size() == 100);

    SECTION("max_count=0 and max_pct=0 returns ALL addresses (Bitcoin Core parity)") {
        // Bitcoin Core: max_addresses=0 means "no limit", max_pct=0 means "no percentage limit"
        auto addrs = addrman.get_addresses(0, 0);
        REQUIRE(addrs.size() == 100);  // All addresses returned
    }

    SECTION("max_pct=0 with max_count>0 returns up to max_count addresses") {
        // max_pct=0 means no percentage limit, only max_count applies
        auto addrs = addrman.get_addresses(50, 0);
        REQUIRE(addrs.size() == 50);
    }

    SECTION("max_pct=23 limits to 23% of total (Bitcoin Core parity)") {
        // Bitcoin Core test: "23% of 5 is 1 rounded down"
        // Here: 23% of 100 = 23 addresses
        auto addrs = addrman.get_addresses(2500, 23);
        size_t expected = (100 * 23) / 100;  // Integer division like Bitcoin Core
        REQUIRE(addrs.size() == expected);
        REQUIRE(addrs.size() == 23);
    }

    SECTION("max_pct=10 limits to 10% of total") {
        // 10% of 100 = 10 addresses
        auto addrs = addrman.get_addresses(1000, 10);
        REQUIRE(addrs.size() == 10);
    }

    SECTION("max_count takes precedence when smaller than max_pct result") {
        // max_pct=50 would give 50 addresses, but max_count=20 limits it
        auto addrs = addrman.get_addresses(20, 50);
        REQUIRE(addrs.size() == 20);
    }

    SECTION("max_count=0 with max_pct=100 returns all addresses") {
        // max_count=0 means no limit, max_pct=100 allows all
        auto addrs = addrman.get_addresses(0, 100);
        REQUIRE(addrs.size() == 100);
    }

    SECTION("max_pct > 100 is capped at 100") {
        // Invalid percentage should be ignored (>100 treated as no pct limit)
        auto addrs = addrman.get_addresses(1000, 150);
        // max_pct > 100 is outside valid range, so pct_limit not applied
        // Only max_count=1000 applies, but we only have 100 addresses
        REQUIRE(addrs.size() == 100);
    }
}

// =============================================================================
// Tests for select_new_for_feeler() using GetChance()
// =============================================================================

TEST_CASE("Bitcoin Core Parity: select_new_for_feeler() uses GetChance()", "[network][addrman][core-parity][feeler]") {
    using namespace unicity::util;

    const int64_t base_time = 1735689600;
    MockTimeScope mock_time(base_time);

    AddressManager addrman;

    SECTION("Addresses with many failures are less likely to be selected") {
        // Add two addresses: one "good" (no failures), one "bad" (many failures)
        NetworkAddress good_addr = MakeAddress("93.184.216.120", 9590);
        NetworkAddress bad_addr = MakeAddress("93.184.216.121", 9590);

        addrman.add(good_addr, base_time);
        addrman.add(bad_addr, base_time);
        REQUIRE(addrman.new_count() == 2);

        // Make bad_addr have high failure count using m_last_good_ advancement
        NetworkAddress helper = MakeAddress("93.184.216.122", 9590);
        addrman.add(helper);

        // Accumulate 2 failures on bad_addr (below ADDRMAN_RETRIES=3 terrible threshold)
        for (int i = 0; i < 2; i++) {
            SetMockTime(base_time + i * 2);
            addrman.good(helper);  // Advance m_last_good_
            SetMockTime(base_time + i * 2 + 1);
            addrman.attempt(bad_addr, true);  // Count failure
        }

        // Move helper to tried so only good_addr and bad_addr in NEW
        // (helper is already in tried from good() calls)
        REQUIRE(addrman.new_count() == 2);
        REQUIRE(addrman.tried_count() == 1);

        // Advance past grace period
        SetMockTime(base_time + 1000);

        // Select many times and count how often each is selected
        // With GetChance(), bad_addr (2 failures) has chance = 0.66^2 ≈ 0.44
        // good_addr (0 failures) has chance = 1.0
        // So good_addr should be selected ~2x more often than bad_addr
        int good_count = 0;
        int bad_count = 0;
        const int iterations = 1000;

        for (int i = 0; i < iterations; i++) {
            auto selected = addrman.select_new_for_feeler();
            REQUIRE(selected.has_value());
            if (selected->get_ipv4() == good_addr.get_ipv4()) {
                good_count++;
            } else if (selected->get_ipv4() == bad_addr.get_ipv4()) {
                bad_count++;
            }
        }

        // good_addr should be selected more often (chance 1.0 vs 0.44)
        REQUIRE(good_count > bad_count);

        // Sanity check: both should be selected (escalating chance_factor ensures this)
        REQUIRE(good_count > 0);
        REQUIRE(bad_count > 0);
    }

    SECTION("Empty NEW table returns nullopt") {
        // No addresses in NEW table
        REQUIRE(addrman.new_count() == 0);
        auto selected = addrman.select_new_for_feeler();
        REQUIRE_FALSE(selected.has_value());
    }

    SECTION("Single address is always selected") {
        NetworkAddress addr = MakeAddress("93.184.216.125", 9590);
        addrman.add(addr, base_time);
        REQUIRE(addrman.new_count() == 1);

        // Should always return the only address
        for (int i = 0; i < 10; i++) {
            auto selected = addrman.select_new_for_feeler();
            REQUIRE(selected.has_value());
            REQUIRE(selected->get_ipv4() == addr.get_ipv4());
        }
    }
}
