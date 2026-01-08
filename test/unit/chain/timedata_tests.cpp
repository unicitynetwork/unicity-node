// Copyright (c) 2025 The Unicity Foundation
// Unit tests for chain/timedata.cpp - Network-adjusted time
//
// Tests are organized into sections:
// 1. Initial State - Default offset
// 2. Median Filter - CMedianFilter behavior
// 3. Peer Updates - How offset changes with peer samples
// 4. Time Limits - DEFAULT_MAX_TIME_ADJUSTMENT cap
// 5. Security - Outlier resistance, duplicate rejection, eclipse attacks
// 6. Accumulation - Gradual peer addition behavior

#include "catch_amalgamated.hpp"
#include "chain/timedata.hpp"
#include "network/protocol.hpp"
#include "util/time.hpp"
#include <ctime>

using namespace unicity::chain;
using namespace unicity::protocol;

// =============================================================================
// Test Helpers
// =============================================================================

static void AddPeers(const std::vector<int64_t>& offsets) {
    for (size_t i = 0; i < offsets.size(); i++) {
        NetworkAddress addr = NetworkAddress::from_string(
            "192.168.1." + std::to_string(i), 8333, NODE_NETWORK);
        AddTimeData(addr, offsets[i]);
    }
}

static NetworkAddress A(uint32_t v4) {
    return NetworkAddress::from_ipv4(NODE_NETWORK, v4, 9590);
}

// =============================================================================
// Section 1: Initial State
// =============================================================================

TEST_CASE("TimeData - Initial state", "[timedata]") {
    TestOnlyResetTimeData();
    REQUIRE(GetTimeOffset() == 0);
}

// =============================================================================
// Section 2: Median Filter
// =============================================================================

TEST_CASE("TimeData - CMedianFilter basic", "[timedata]") {
    CMedianFilter<int> filter(5, 0);

    REQUIRE(filter.size() == 1);
    REQUIRE(filter.median() == 0);

    filter.input(10);
    REQUIRE(filter.size() == 2);
    REQUIRE(filter.median() == 5);

    filter.input(20);
    REQUIRE(filter.size() == 3);
    REQUIRE(filter.median() == 10);

    filter.input(5);
    REQUIRE(filter.size() == 4);
    REQUIRE(filter.median() == 7);

    filter.input(15);
    REQUIRE(filter.size() == 5);
    REQUIRE(filter.median() == 10);
}

TEST_CASE("TimeData - CMedianFilter rolling window", "[timedata]") {
    CMedianFilter<int> filter(3, 0);

    filter.input(10);
    filter.input(20);
    REQUIRE(filter.size() == 3);
    REQUIRE(filter.median() == 10);

    filter.input(30);
    REQUIRE(filter.size() == 3);
    REQUIRE(filter.median() == 20);

    filter.input(5);
    REQUIRE(filter.size() == 3);
    REQUIRE(filter.median() == 20);
}

// =============================================================================
// Section 3: Peer Updates
// =============================================================================

TEST_CASE("TimeData - Need 4 peers to get first update", "[timedata]") {
    TestOnlyResetTimeData();

    AddPeers({10, 20, 15, 12});
    REQUIRE(GetTimeOffset() == 12);
}

TEST_CASE("TimeData - 5 peers = 6 total (even), no update from previous", "[timedata]") {
    TestOnlyResetTimeData();

    AddPeers({10, 20, 15, 12});
    REQUIRE(GetTimeOffset() == 12);

    NetworkAddress addr_extra = NetworkAddress::from_string("192.168.1.100", 8333, NODE_NETWORK);
    AddTimeData(addr_extra, 18);

    REQUIRE(GetTimeOffset() == 12);
}

TEST_CASE("TimeData - 6 peers = 7 total (odd), updates", "[timedata]") {
    TestOnlyResetTimeData();

    AddPeers({10, 20, 15, 12, 18, 25});
    REQUIRE(GetTimeOffset() == 15);
}

TEST_CASE("TimeData - Negative offsets", "[timedata]") {
    TestOnlyResetTimeData();

    AddPeers({-30, -20, -25, -22});
    REQUIRE(GetTimeOffset() == -22);
}

TEST_CASE("TimeData - Mixed positive and negative", "[timedata]") {
    TestOnlyResetTimeData();

    AddPeers({-10, 5, -3, 8});
    REQUIRE(GetTimeOffset() == 0);
}

TEST_CASE("TimeData - 8 peers (9 total, odd)", "[timedata]") {
    TestOnlyResetTimeData();

    AddPeers({10, 24, 14, 20, 12, 22, 16, 18});
    REQUIRE(GetTimeOffset() == 16);
}

TEST_CASE("TimeData - Zero offsets (perfect sync)", "[timedata]") {
    TestOnlyResetTimeData();

    AddPeers({0, 0, 0, 0});
    REQUIRE(GetTimeOffset() == 0);
}

TEST_CASE("TimeData - Small variations around zero", "[timedata]") {
    TestOnlyResetTimeData();

    AddPeers({-2, -1, 1, 2});
    REQUIRE(GetTimeOffset() == 0);
}

// =============================================================================
// Section 4: Time Limits
// =============================================================================

TEST_CASE("TimeData - Small offsets well within cap are applied", "[timedata]") {
    TestOnlyResetTimeData();

    AddPeers({30, 30, 30, 30});
    REQUIRE(GetTimeOffset() == 30);
}

TEST_CASE("TimeData - Small negative offsets well within cap are applied", "[timedata]") {
    TestOnlyResetTimeData();

    AddPeers({-30, -30, -30, -30});
    REQUIRE(GetTimeOffset() == -30);
}

TEST_CASE("TimeData - Exactly at +1 minute boundary", "[timedata]") {
    TestOnlyResetTimeData();

    int64_t max_adj = DEFAULT_MAX_TIME_ADJUSTMENT;
    AddPeers({max_adj, max_adj, max_adj, max_adj});
    REQUIRE(GetTimeOffset() == max_adj);
}

TEST_CASE("TimeData - Exactly at -1 minute boundary", "[timedata]") {
    TestOnlyResetTimeData();

    int64_t max_adj = DEFAULT_MAX_TIME_ADJUSTMENT;
    AddPeers({-max_adj, -max_adj, -max_adj, -max_adj});
    REQUIRE(GetTimeOffset() == -max_adj);
}

TEST_CASE("TimeData - One second over limit", "[timedata]") {
    TestOnlyResetTimeData();

    int64_t over_limit = DEFAULT_MAX_TIME_ADJUSTMENT + 1;
    AddPeers({over_limit, over_limit, over_limit, over_limit});
    REQUIRE(GetTimeOffset() == 0);
}

TEST_CASE("TimeData - Offsets near limit", "[timedata]") {
    TestOnlyResetTimeData();

    AddPeers({50, 40, 55, 45});
    REQUIRE(GetTimeOffset() == 45);
}

// =============================================================================
// Section 5: Security
// =============================================================================

TEST_CASE("TimeData - Duplicate peer addresses ignored", "[timedata]") {
    TestOnlyResetTimeData();

    NetworkAddress addr1 = NetworkAddress::from_string("192.168.1.1", 8333, NODE_NETWORK);
    NetworkAddress addr2 = NetworkAddress::from_string("192.168.1.2", 8333, NODE_NETWORK);
    NetworkAddress addr3 = NetworkAddress::from_string("192.168.1.3", 8333, NODE_NETWORK);
    NetworkAddress addr4 = NetworkAddress::from_string("192.168.1.4", 8333, NODE_NETWORK);

    AddTimeData(addr1, 10);
    AddTimeData(addr1, 50);  // Ignored
    AddTimeData(addr1, 100); // Ignored
    AddTimeData(addr2, 20);
    AddTimeData(addr3, 15);
    AddTimeData(addr4, 12);

    REQUIRE(GetTimeOffset() == 12);
}

TEST_CASE("TimeData - Outlier resistance", "[timedata]") {
    TestOnlyResetTimeData();

    AddPeers({10, 12, 11, 3000});
    REQUIRE(GetTimeOffset() == 11);
}

TEST_CASE("TimeData - Eclipse attack with majority", "[timedata]") {
    TestOnlyResetTimeData();

    AddPeers({5000, 5000, 5000, 10});
    REQUIRE(GetTimeOffset() == 0);
}

TEST_CASE("TimeData - duplicate source ignored and size cap", "[timedata][add]") {
    TestOnlyResetTimeData();

    auto addr = A(0x0A0A0A0A);
    AddTimeData(addr, 5);
    AddTimeData(addr, 1000); // duplicate source ignored

    AddTimeData(A(0x0B0B0B0B), 5);
    AddTimeData(A(0x0C0C0C0C), 5);
    AddTimeData(A(0x0D0D0D0D), 5);
    AddTimeData(A(0x0E0E0E0E), 5);

    REQUIRE(GetTimeOffset() == 5);
}

// =============================================================================
// Section 6: Accumulation
// =============================================================================

TEST_CASE("TimeData - Gradual accumulation", "[timedata]") {
    TestOnlyResetTimeData();

    NetworkAddress peer1 = NetworkAddress::from_string("10.0.0.1", 8333, NODE_NETWORK);
    AddTimeData(peer1, 10);
    REQUIRE(GetTimeOffset() == 0);

    NetworkAddress peer2 = NetworkAddress::from_string("10.0.0.2", 8333, NODE_NETWORK);
    AddTimeData(peer2, 20);
    REQUIRE(GetTimeOffset() == 0);

    NetworkAddress peer3 = NetworkAddress::from_string("10.0.0.3", 8333, NODE_NETWORK);
    AddTimeData(peer3, 15);
    REQUIRE(GetTimeOffset() == 0);

    NetworkAddress peer4 = NetworkAddress::from_string("10.0.0.4", 8333, NODE_NETWORK);
    AddTimeData(peer4, 12);
    REQUIRE(GetTimeOffset() == 12);

    NetworkAddress peer5 = NetworkAddress::from_string("10.0.0.5", 8333, NODE_NETWORK);
    AddTimeData(peer5, 18);
    REQUIRE(GetTimeOffset() == 12);

    NetworkAddress peer6 = NetworkAddress::from_string("10.0.0.6", 8333, NODE_NETWORK);
    AddTimeData(peer6, 14);
    REQUIRE(GetTimeOffset() == 14);
}

TEST_CASE("TimeData - Reset functionality", "[timedata]") {
    TestOnlyResetTimeData();

    AddPeers({10, 20, 15, 12});
    REQUIRE(GetTimeOffset() == 12);

    TestOnlyResetTimeData();
    REQUIRE(GetTimeOffset() == 0);

    AddPeers({50, 55, 52, 48});
    REQUIRE(GetTimeOffset() == 50);
}

TEST_CASE("TimeData - median update and limits", "[timedata][add]") {
    TestOnlyResetTimeData();

    AddTimeData(A(0x01010101), 10);
    AddTimeData(A(0x02020202), 20);
    AddTimeData(A(0x03030303), 30);
    AddTimeData(A(0x04040404), 40);
    AddTimeData(A(0x05050505), 50);

    REQUIRE(GetTimeOffset() == 20);

    AddTimeData(A(0x06060606), 60);
    REQUIRE(GetTimeOffset() == 30);

    int64_t too_far = DEFAULT_MAX_TIME_ADJUSTMENT + 600;
    AddTimeData(A(0x07070707), too_far);
    REQUIRE(GetTimeOffset() == 30);
}
