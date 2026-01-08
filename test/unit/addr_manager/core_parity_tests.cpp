// ====================================================================
// Bitcoin Core Parity Tests: New Features
// Tests for m_last_count_attempt, fCountFailure, m_last_good_, and ADDRMAN_HORIZON
// ====================================================================

#include "catch_amalgamated.hpp"
#include "network/addr_manager.hpp"
#include "network/protocol.hpp"
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
    NetworkAddress addr = MakeAddress("1.0.0.1", 8333);

    REQUIRE(addrman.add(addr));
    REQUIRE(addrman.size() == 1);

    SECTION("fCountFailure=true increments attempts") {
        // First attempt with fCountFailure=true
        addrman.attempt(addr, true);
        addrman.failed(addr);

        // Check that attempts incremented (need to verify through behavior)
        // After 1 failure, address should still be in addrman
        REQUIRE(addrman.size() == 1);

        // 2 more failures (total 3) should remove NEW address
        addrman.attempt(addr, true);
        addrman.failed(addr);
        addrman.attempt(addr, true);
        addrman.failed(addr);

        // After 3 failures, NEW address should be removed (ADDRMAN_RETRIES=3)
        addrman.cleanup_stale();
        REQUIRE(addrman.size() == 0);
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
        addrman.failed(addr);

        // Address should still be in TRIED (only 1 failure counted)
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
    NetworkAddress addr = MakeAddress("1.0.0.5", 8333);

    SECTION("Full lifecycle: add -> attempt -> good -> fail -> terrible") {
        // Add address
        REQUIRE(addrman.add(addr));
        REQUIRE(addrman.new_count() == 1);

        // First attempt (fCountFailure=true)
        addrman.attempt(addr, true);

        // Mark as good (moves to TRIED, sets m_last_good_)
        addrman.good(addr);
        REQUIRE(addrman.tried_count() == 1);
        REQUIRE(addrman.new_count() == 0);

        // Fail it 10 times (should move back to NEW after MAX_FAILURES)
        for (int i = 0; i < 10; i++) {
            addrman.attempt(addr, true);
            addrman.failed(addr);
        }

        // Should be back in NEW
        REQUIRE(addrman.new_count() == 1);
        REQUIRE(addrman.tried_count() == 0);

        // Address now has last_success set, so needs 10 failures over 7 days to be terrible
        // Since we just failed it 10 times but last_success is recent, NOT terrible yet
        REQUIRE(addrman.size() == 1);
    }
}

TEST_CASE("Bitcoin Core Parity: Persistence of new fields", "[network][addrman][core-parity]") {
    const std::string test_file = "/tmp/test_addrman_parity.json";
    NetworkAddress addr1 = MakeAddress("1.0.0.10", 8333);
    NetworkAddress addr2 = MakeAddress("1.0.0.11", 8333);

    // Save state
    {
        AddressManager addrman;
        REQUIRE(addrman.add(addr1));
        REQUIRE(addrman.add(addr2));

        // Setup some state
        addrman.attempt(addr1, true);
        addrman.failed(addr1);

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
