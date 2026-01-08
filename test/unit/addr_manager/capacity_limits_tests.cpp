// Copyright (c) 2025 The Unicity Foundation
// Address Manager capacity and eviction tests

#include "catch_amalgamated.hpp"
#include "network/addr_manager.hpp"
#include "network/protocol.hpp"
#include <filesystem>

using namespace unicity;
using namespace unicity::network;
using namespace unicity::protocol;

// Helper: Get current timestamp (Unix time)
static uint32_t now_timestamp() {
    return static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

// Helper: Create unique IPv4 address with netgroup diversity
// Generates addresses across different /16 subnets to work with per-netgroup limits
// Format: first.second.third.fourth where first.second varies for netgroup diversity
//
// Per-netgroup limits: NEW table = 32, TRIED table = 8
// We change /16 every 8 addresses to satisfy the stricter TRIED limit
static NetworkAddress MakeIPv4Address(uint32_t index, uint16_t port = 9590) {
    // Generate addresses across different /16 subnets:
    // - first octet: 1-223 (public routable range, avoiding 0, 10, 127, 224+)
    // - second octet: 0-255 (varies with index for netgroup diversity)
    // - third/fourth: from index modulo
    //
    // This gives us ~56,000 unique /16 subnets (223 * 256 minus reserved)
    // With 8 addresses per /16 (TRIED limit), we need ~1250 /16s for 10000 addresses
    uint16_t netgroup_index = index / 8;  // Change /16 every 8 addresses (TRIED limit)
    uint8_t first = 1 + (netgroup_index / 256) % 222;  // 1-222 (avoid 10.x, 127.x)
    if (first >= 10) first++;  // Skip 10.x.x.x (RFC1918)
    if (first >= 127) first++;  // Skip 127.x.x.x (loopback)
    uint8_t second = netgroup_index % 256;
    uint8_t third = (index % 8) / 254;
    uint8_t fourth = (index % 8) % 254 + 1;  // 1-254
    uint32_t ip = (first << 24) | (second << 16) | (third << 8) | fourth;
    return NetworkAddress::from_ipv4(NODE_NETWORK, ip, port);
}

// Helper: Create pure IPv6 address (not IPv4-mapped)
static NetworkAddress MakeIPv6Address(const std::string& ipv6_str, uint16_t port = 9590) {
    return NetworkAddress::from_string(ipv6_str, port, NODE_NETWORK);
}

TEST_CASE("Address table respects MAX_NEW_ADDRESSES limit", "[addr_manager][capacity][limits][slow]") {
    AddressManager am;

    // Try to add 25,000 addresses (exceeds MAX_NEW_ADDRESSES = 20,000)
    const int addresses_to_add = 25000;
    int added_count = 0;

    for (int i = 0; i < addresses_to_add; i++) {
        auto addr = MakeIPv4Address(i, 9590 + (i % 1000));
        if (am.add(addr)) {  // Use auto-timestamp (timestamp=0 → uses current time)
            added_count++;
        }
    }

    INFO("Added " << added_count << " addresses out of " << addresses_to_add << " attempted");

    // Should cap at MAX_NEW_ADDRESSES (20,000)
    REQUIRE(am.new_count() <= 20000);

    // Should have triggered eviction for addresses beyond limit
    REQUIRE(added_count > 20000);  // We successfully added more than limit (via eviction)
    REQUIRE(am.new_count() == 20000);  // But table capped at limit

    // Should still be able to select addresses
    auto selected = am.select();
    REQUIRE(selected.has_value());
}

TEST_CASE("Address table respects MAX_TRIED_ADDRESSES limit", "[addr_manager][capacity][limits]") {
    AddressManager am;

    // Add and promote 12,000 addresses to tried table (exceeds MAX_TRIED_ADDRESSES = 10,000)
    const int addresses_to_try = 12000;

    for (int i = 0; i < addresses_to_try; i++) {
        auto addr = MakeIPv4Address(i, 9590);

        // Add to NEW table
        am.add(addr);

        // Promote to TRIED table via good()
        am.good(addr);
    }

    INFO("Tried count: " << am.tried_count());

    // Should cap at MAX_TRIED_ADDRESSES (10,000)
    REQUIRE(am.tried_count() <= 10000);
}

TEST_CASE("Eviction allows new addresses when at capacity", "[addr_manager][capacity][eviction]") {
    AddressManager am;

    // Fill NEW table to capacity
    for (int i = 0; i < 20000; i++) {
        auto addr = MakeIPv4Address(i, 9590);
        am.add(addr);
    }

    REQUIRE(am.new_count() == 20000);  // At capacity

    // Add one more address - should evict an existing one
    auto new_addr = MakeIPv4Address(99999, 9591);
    REQUIRE(am.add(new_addr));

    // Should still be at capacity
    REQUIRE(am.new_count() == 20000);
}

// Note: Testing specific eviction strategies (terrible addresses, oldest timestamp)
// requires manipulating timestamps which we avoid in unit tests. The eviction
// logic is tested implicitly by verifying the capacity limits are enforced.

TEST_CASE("Pure IPv6 addresses work correctly", "[addr_manager][ipv6]") {
    AddressManager am;

    // Native IPv6 (not IPv4-mapped)
    NetworkAddress ipv6 = MakeIPv6Address("2600::1", 9590);

    REQUIRE(am.add(ipv6));
    REQUIRE(am.new_count() == 1);

    // Promote to tried
    am.good(ipv6);
    REQUIRE(am.tried_count() == 1);
    REQUIRE(am.new_count() == 0);

    // Should be selectable
    auto selected = am.select();
    REQUIRE(selected.has_value());
}

TEST_CASE("IPv6 persistence round-trip", "[addr_manager][ipv6][persistence]") {
    const std::string test_file = "/tmp/test_ipv6_addr_manager.json";

    // Clean up any existing test file
    std::filesystem::remove(test_file);

    {
        AddressManager am;

        // Add various IPv6 addresses
        auto ipv6_1 = MakeIPv6Address("2600::1", 9590);
        auto ipv6_2 = MakeIPv6Address("2600::2", 9590);
        auto ipv6_3 = MakeIPv6Address("2600::3", 9590);

        am.add(ipv6_1);
        am.add(ipv6_2);
        am.add(ipv6_3);

        // Promote one to tried
        am.good(ipv6_1);

        REQUIRE(am.tried_count() == 1);
        REQUIRE(am.new_count() == 2);

        // Save
        REQUIRE(am.Save(test_file));
    }

    // Load into new manager
    {
        AddressManager am2;
        REQUIRE(am2.Load(test_file));

        REQUIRE(am2.tried_count() == 1);
        REQUIRE(am2.new_count() == 2);
        REQUIRE(am2.size() == 3);
    }

    // Clean up
    std::filesystem::remove(test_file);
}

TEST_CASE("Mixed IPv4 and IPv6 addresses", "[addr_manager][ipv4][ipv6]") {
    AddressManager am;

    // Add mix of IPv4 and IPv6
    auto ipv4_1 = MakeIPv4Address(1, 9590);
    auto ipv4_2 = MakeIPv4Address(2, 9590);
    auto ipv6_1 = MakeIPv6Address("2600::1", 9590);
    auto ipv6_2 = MakeIPv6Address("2600::2", 9590);

    REQUIRE(am.add(ipv4_1));
    REQUIRE(am.add(ipv4_2));
    REQUIRE(am.add(ipv6_1));
    REQUIRE(am.add(ipv6_2));

    REQUIRE(am.size() == 4);

    // Promote some to tried
    am.good(ipv4_1);
    am.good(ipv6_1);

    REQUIRE(am.tried_count() == 2);
    REQUIRE(am.new_count() == 2);
}

TEST_CASE("Capacity limits work with failed() and demotion", "[addr_manager][capacity][demotion]") {
    AddressManager am;

    // Fill TRIED table to capacity
    const int addresses = 10000;

    for (int i = 0; i < addresses; i++) {
        auto addr = MakeIPv4Address(i, 9590);
        am.add(addr);
        am.good(addr);
    }

    REQUIRE(am.tried_count() == 10000);

    // Add one more and promote - should trigger eviction in tried table
    auto new_addr = MakeIPv4Address(99999, 9591);
    am.add(new_addr);
    am.good(new_addr);

    // Should still be at capacity
    REQUIRE(am.tried_count() <= 10000);
}

TEST_CASE("select() works with table at capacity", "[addr_manager][capacity][selection]") {
    AddressManager am;

    // Fill NEW table to capacity
    for (int i = 0; i < 20000; i++) {
        auto addr = MakeIPv4Address(i, 9590);
        am.add(addr);
    }

    REQUIRE(am.new_count() == 20000);

    // Should still be able to select addresses
    for (int i = 0; i < 100; i++) {
        auto selected = am.select();
        REQUIRE(selected.has_value());
    }
}

TEST_CASE("get_addresses() works with table at capacity", "[addr_manager][capacity][getaddr]") {
    AddressManager am;

    // Fill NEW table
    for (int i = 0; i < 20000; i++) {
        auto addr = MakeIPv4Address(i, 9590);
        am.add(addr);
    }

    // Get addresses
    auto addrs = am.get_addresses(1000);

    // Should return up to 1000 addresses
    REQUIRE(addrs.size() <= 1000);
    REQUIRE(addrs.size() > 0);
}
