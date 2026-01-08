#include "catch_amalgamated.hpp"
#include "network/addr_manager.hpp"
#include "network/protocol.hpp"
#include <sys/stat.h>

using namespace unicity;
using namespace unicity::network;
using namespace unicity::protocol;

TEST_CASE("IPv4-compatible addresses are normalized to IPv4-mapped", "[network][addr][normalization]") {
    AddressManager am;

    // Create IPv4-compatible address: ::93.184.216.34 (example.com)
    NetworkAddress ipv4_compat;
    for (int i = 0; i < 16; ++i) ipv4_compat.ip[i] = 0;
    ipv4_compat.ip[12] = 93;
    ipv4_compat.ip[13] = 184;
    ipv4_compat.ip[14] = 216;
    ipv4_compat.ip[15] = 34;
    ipv4_compat.port = 9590;
    ipv4_compat.services = NODE_NETWORK;

    // Create the same address in IPv4-mapped format: ::ffff:93.184.216.34
    NetworkAddress ipv4_mapped;
    for (int i = 0; i < 10; ++i) ipv4_mapped.ip[i] = 0;
    ipv4_mapped.ip[10] = 0xff;
    ipv4_mapped.ip[11] = 0xff;
    ipv4_mapped.ip[12] = 93;
    ipv4_mapped.ip[13] = 184;
    ipv4_mapped.ip[14] = 216;
    ipv4_mapped.ip[15] = 34;
    ipv4_mapped.port = 9590;
    ipv4_mapped.services = NODE_NETWORK;

    // Add IPv4-compatible address
    REQUIRE(am.add(ipv4_compat));
    REQUIRE(am.size() == 1);

    // Try to add IPv4-mapped version of same address - should be duplicate
    REQUIRE_FALSE(am.add(ipv4_mapped));
    REQUIRE(am.size() == 1);  // Still only 1 address
}

TEST_CASE("failed() works with IPv4-compatible addresses after normalization", "[network][addr][normalization]") {
    AddressManager am;

    // Create IPv4-compatible address: ::93.184.216.34
    NetworkAddress addr;
    for (int i = 0; i < 16; ++i) addr.ip[i] = 0;
    addr.ip[12] = 93;
    addr.ip[13] = 184;
    addr.ip[14] = 216;
    addr.ip[15] = 34;
    addr.port = 9590;
    addr.services = NODE_NETWORK;

    // Add and verify
    REQUIRE(am.add(addr));
    REQUIRE(am.size() == 1);
    REQUIRE(am.new_count() == 1);

    // Call failed() with the same IPv4-compatible address (un-normalized)
    for (int i = 0; i < 20; ++i) {
        am.failed(addr);
    }

    // Cleanup should remove it (it's terrible now)
    am.cleanup_stale();
    REQUIRE(am.size() == 0);
}

TEST_CASE("good() works with IPv4-compatible addresses after normalization", "[network][addr][normalization]") {
    AddressManager am;

    // Create IPv4-compatible address: ::93.184.216.34
    NetworkAddress addr;
    for (int i = 0; i < 16; ++i) addr.ip[i] = 0;
    addr.ip[12] = 93;
    addr.ip[13] = 184;
    addr.ip[14] = 216;
    addr.ip[15] = 34;
    addr.port = 9590;
    addr.services = NODE_NETWORK;

    // Add to new table
    REQUIRE(am.add(addr));
    REQUIRE(am.new_count() == 1);
    REQUIRE(am.tried_count() == 0);

    // Call good() with the same IPv4-compatible address (un-normalized)
    am.good(addr);

    // Should have moved to tried table
    REQUIRE(am.new_count() == 0);
    REQUIRE(am.tried_count() == 1);
}

TEST_CASE("attempt() works with IPv4-compatible addresses after normalization", "[network][addr][normalization]") {
    AddressManager am;

    // Create IPv4-compatible address: ::93.184.216.34
    NetworkAddress addr;
    for (int i = 0; i < 16; ++i) addr.ip[i] = 0;
    addr.ip[12] = 93;
    addr.ip[13] = 184;
    addr.ip[14] = 216;
    addr.ip[15] = 34;
    addr.port = 9590;
    addr.services = NODE_NETWORK;

    // Add to new table
    REQUIRE(am.add(addr));

    // Call attempt() with the same IPv4-compatible address (un-normalized)
    // Should not throw or fail to find the address
    REQUIRE_NOTHROW(am.attempt(addr, true));
}

TEST_CASE("Multiple IPv4-compatible addresses with different IPs don't collide", "[network][addr][normalization]") {
    AddressManager am;

    // Create two different IPv4-compatible addresses
    // First: ::93.184.216.34 (example.com)
    NetworkAddress addr1;
    for (int i = 0; i < 16; ++i) addr1.ip[i] = 0;
    addr1.ip[12] = 93;
    addr1.ip[13] = 184;
    addr1.ip[14] = 216;
    addr1.ip[15] = 34;
    addr1.port = 9590;
    addr1.services = NODE_NETWORK;

    // Second: ::8.8.8.8 (Google DNS)
    NetworkAddress addr2;
    for (int i = 0; i < 16; ++i) addr2.ip[i] = 0;
    addr2.ip[12] = 8;
    addr2.ip[13] = 8;
    addr2.ip[14] = 8;
    addr2.ip[15] = 8;
    addr2.port = 9590;
    addr2.services = NODE_NETWORK;

    // Both should be added successfully
    REQUIRE(am.add(addr1));
    REQUIRE(am.add(addr2));
    REQUIRE(am.size() == 2);

    // Failed on addr1 should only affect addr1
    for (int i = 0; i < 20; ++i) {
        am.failed(addr1);
    }

    am.cleanup_stale();
    REQUIRE(am.size() == 1);  // Only addr2 remains
}

TEST_CASE("IPv4-mapped addresses are not re-normalized", "[network][addr][normalization]") {
    AddressManager am;

    // Create already-normalized IPv4-mapped address: ::ffff:1.1.1.1
    NetworkAddress addr;
    for (int i = 0; i < 10; ++i) addr.ip[i] = 0;
    addr.ip[10] = 0xff;
    addr.ip[11] = 0xff;
    addr.ip[12] = 1;
    addr.ip[13] = 1;
    addr.ip[14] = 1;
    addr.ip[15] = 1;
    addr.port = 9590;
    addr.services = NODE_NETWORK;

    // Should be added successfully
    REQUIRE(am.add(addr));
    REQUIRE(am.size() == 1);

    // Adding again should be duplicate
    REQUIRE_FALSE(am.add(addr));
    REQUIRE(am.size() == 1);
}

TEST_CASE("Pure IPv6 addresses are not affected by normalization", "[network][addr][normalization]") {
    AddressManager am;

    // Create a pure IPv6 address (not IPv4-compatible or IPv4-mapped)
    NetworkAddress addr;
    addr.ip[0] = 0x20;  // 2000::/3 (global unicast)
    addr.ip[1] = 0x01;
    for (int i = 2; i < 16; ++i) addr.ip[i] = static_cast<uint8_t>(i);
    addr.port = 9590;
    addr.services = NODE_NETWORK;

    REQUIRE(am.add(addr));
    REQUIRE(am.size() == 1);

    // Should work with all operations
    REQUIRE_NOTHROW(am.attempt(addr, true));
    REQUIRE_NOTHROW(am.good(addr));
    REQUIRE(am.tried_count() == 1);
}

TEST_CASE("File permissions are 0600 for peers.json", "[network][addr][security]") {
    AddressManager am;

    // Add some addresses
    NetworkAddress addr;
    for (int i = 0; i < 16; ++i) addr.ip[i] = 0;
    addr.ip[15] = 10;
    addr.port = 9590;
    addr.services = NODE_NETWORK;
    am.add(addr);

    // Save to temp file
    const std::string temp_file = "/tmp/test_peers_permissions.json";
    REQUIRE(am.Save(temp_file));

    // Check file permissions
    struct stat st;
    REQUIRE(stat(temp_file.c_str(), &st) == 0);

    // Extract permission bits (last 9 bits)
    mode_t perms = st.st_mode & 0777;

    // Should be 0600 (owner read/write only)
    REQUIRE(perms == 0600);

    // Cleanup
    std::remove(temp_file.c_str());
}

TEST_CASE("Incremental vector updates maintain consistency", "[network][addr][performance]") {
    AddressManager am;

    // Use routable IPs: 93.184.216.34 and 8.8.8.8
    NetworkAddress addr1;
    for (int i = 0; i < 16; ++i) addr1.ip[i] = 0;
    addr1.ip[10] = 0xff;
    addr1.ip[11] = 0xff;
    addr1.ip[12] = 93;
    addr1.ip[13] = 184;
    addr1.ip[14] = 216;
    addr1.ip[15] = 34;
    addr1.port = 9590;
    addr1.services = NODE_NETWORK;

    NetworkAddress addr2;
    for (int i = 0; i < 16; ++i) addr2.ip[i] = 0;
    addr2.ip[10] = 0xff;
    addr2.ip[11] = 0xff;
    addr2.ip[12] = 8;
    addr2.ip[13] = 8;
    addr2.ip[14] = 8;
    addr2.ip[15] = 8;
    addr2.port = 9590;
    addr2.services = NODE_NETWORK;

    // Add two addresses to new table
    REQUIRE(am.add(addr1));
    REQUIRE(am.add(addr2));
    REQUIRE(am.new_count() == 2);
    REQUIRE(am.tried_count() == 0);

    // Move addr1 to tried (tests incremental update in good())
    am.good(addr1);
    REQUIRE(am.new_count() == 1);
    REQUIRE(am.tried_count() == 1);

    // Verify selection still works (tests vectors are in sync)
    auto selected = am.select();
    REQUIRE(selected.has_value());

    // Fail addr1 many times to demote back to new (tests incremental update in failed())
    for (int i = 0; i < 15; ++i) {
        am.failed(addr1);
    }
    REQUIRE(am.new_count() == 2);
    REQUIRE(am.tried_count() == 0);

    // Selection should still work
    selected = am.select();
    REQUIRE(selected.has_value());
}

TEST_CASE("Exception safety in Load() with rebuild_key_vectors()", "[network][addr][exception]") {
    AddressManager am1;

    // Add routable address: 93.184.216.34
    NetworkAddress addr;
    for (int i = 0; i < 16; ++i) addr.ip[i] = 0;
    addr.ip[10] = 0xff;
    addr.ip[11] = 0xff;
    addr.ip[12] = 93;
    addr.ip[13] = 184;
    addr.ip[14] = 216;
    addr.ip[15] = 34;
    addr.port = 9590;
    addr.services = NODE_NETWORK;
    am1.add(addr);

    // Save
    const std::string temp_file = "/tmp/test_addr_load.json";
    REQUIRE(am1.Save(temp_file));

    // Load into new manager
    AddressManager am2;
    REQUIRE(am2.Load(temp_file));

    // Should have same size
    REQUIRE(am2.size() == am1.size());

    // Should be able to select (vectors are properly rebuilt)
    auto selected = am2.select();
    REQUIRE(selected.has_value());

    // Cleanup
    std::remove(temp_file.c_str());
}

TEST_CASE("Failure counting state persists across Save/Load", "[network][addr][persistence]") {
    AddressManager am1;

    // Create routable address: 93.184.216.34
    NetworkAddress addr;
    for (int i = 0; i < 16; ++i) addr.ip[i] = 0;
    addr.ip[10] = 0xff;
    addr.ip[11] = 0xff;
    addr.ip[12] = 93;
    addr.ip[13] = 184;
    addr.ip[14] = 216;
    addr.ip[15] = 34;
    addr.port = 9590;
    addr.services = NODE_NETWORK;

    // Add address and mark as good (moves to tried table)
    REQUIRE(am1.add(addr));
    am1.good(addr);
    REQUIRE(am1.tried_count() == 1);

    // Simulate some failures (but not enough to demote)
    for (int i = 0; i < 5; ++i) {
        am1.failed(addr);
    }

    // Save to file
    const std::string temp_file = "/tmp/test_addr_failure_persist.json";
    REQUIRE(am1.Save(temp_file));

    // Load into new manager
    AddressManager am2;
    REQUIRE(am2.Load(temp_file));

    // Verify basic state
    REQUIRE(am2.size() == 1);
    REQUIRE(am2.tried_count() == 1);

    // Verify failure counting state by checking that more failures lead to demotion
    // If attempts weren't persisted, we'd need 10 more failures
    // Since it was persisted (5 already counted), we only need 5 more to reach threshold of 10
    for (int i = 0; i < 5; ++i) {
        am2.failed(addr);
    }

    // Should now be demoted to new table (5 persisted + 5 new = 10 total >= TRIED_DEMOTION_THRESHOLD)
    REQUIRE(am2.tried_count() == 0);
    REQUIRE(am2.new_count() == 1);

    // Cleanup
    std::remove(temp_file.c_str());
}

TEST_CASE("m_last_good_ persists across Save/Load", "[network][addr][persistence]") {
    AddressManager am1;

    // Create and add two routable addresses
    NetworkAddress addr1, addr2;
    for (int i = 0; i < 16; ++i) {
        addr1.ip[i] = 0;
        addr2.ip[i] = 0;
    }
    // addr1: 93.184.216.34
    addr1.ip[10] = 0xff;
    addr1.ip[11] = 0xff;
    addr1.ip[12] = 93;
    addr1.ip[13] = 184;
    addr1.ip[14] = 216;
    addr1.ip[15] = 34;
    // addr2: 8.8.8.8
    addr2.ip[10] = 0xff;
    addr2.ip[11] = 0xff;
    addr2.ip[12] = 8;
    addr2.ip[13] = 8;
    addr2.ip[14] = 8;
    addr2.ip[15] = 8;
    addr1.port = 9590;
    addr2.port = 9590;
    addr1.services = NODE_NETWORK;
    addr2.services = NODE_NETWORK;

    REQUIRE(am1.add(addr1));
    REQUIRE(am1.add(addr2));

    // Mark addr1 as good (updates m_last_good_)
    am1.good(addr1);

    // Now attempt addr2 with fCountFailure=true
    // This should count because last_count_attempt (0) < m_last_good_ (current_time)
    am1.attempt(addr2, true);

    // Save
    const std::string temp_file = "/tmp/test_addr_m_last_good.json";
    REQUIRE(am1.Save(temp_file));

    // Load into new manager
    AddressManager am2;
    REQUIRE(am2.Load(temp_file));

    // Verify m_last_good_ was restored by checking that subsequent attempts
    // are handled correctly (this is hard to test directly, but we verify
    // the state was saved and loaded without error)
    REQUIRE(am2.size() == 2);

    // Cleanup
    std::remove(temp_file.c_str());
}
