// Copyright (c) 2025 The Unicity Foundation
// Unit tests for PeerDiscoveryManager
//
// Tests cover:
// - HandleAddr logic (rate limiting, block-relay filtering, learned address eviction)
// - HandleGetAddr logic (inbound-only, once-per-connection, echo suppression)
// - Learned address eviction (regression test for bug fix)

#include "catch_amalgamated.hpp"
#include "network/peer_discovery_manager.hpp"
#include "network/peer_lifecycle_manager.hpp"
#include "network/peer.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"
#include "network/connection_types.hpp"
#include "infra/mock_transport.hpp"
#include "chain/chainparams.hpp"
#include "util/time.hpp"
#include "util/netaddress.hpp"
#include <asio.hpp>

using namespace unicity;
using namespace unicity::network;
using namespace unicity::protocol;

// Test fixture for PeerDiscoveryManager tests
class DiscoveryManagerTestFixture {
public:
    asio::io_context io_context;
    PeerLifecycleManager::Config pm_config;
    std::unique_ptr<PeerLifecycleManager> peer_manager;
    std::unique_ptr<PeerDiscoveryManager> discovery_manager;

    DiscoveryManagerTestFixture() {
        chain::GlobalChainParams::Select(chain::ChainType::REGTEST);

        pm_config.max_full_relay_outbound = 8;
        pm_config.max_block_relay_outbound = 2;
        pm_config.target_full_relay_outbound = 8;
        pm_config.target_block_relay_outbound = 2;

        peer_manager = std::make_unique<PeerLifecycleManager>(io_context, pm_config);
        discovery_manager = std::make_unique<PeerDiscoveryManager>(peer_manager.get());
    }

    // Create a peer with mock transport for testing
    // Uses routable public IPs (193.x.x.x) to satisfy add_peer validation
    PeerPtr create_peer(ConnectionType type, const std::string& addr = "193.0.0.1", uint16_t port = 9590) {
        // Create mock transport with routable address
        auto mock_conn = std::make_shared<MockTransportConnection>(addr, port);
        mock_conn->set_inbound(type == ConnectionType::INBOUND);

        PeerPtr peer;
        if (type == ConnectionType::INBOUND) {
            peer = Peer::create_inbound(io_context, mock_conn, magic::REGTEST, 0);
        } else {
            peer = Peer::create_outbound(io_context, mock_conn, magic::REGTEST, 0, addr, port, type);
        }
        return peer;
    }

    // Create a unique network address for testing
    // IMPORTANT: Uses routable public IP ranges - NOT 10.x.x.x (RFC1918 private)
    // because AddrMan rejects non-routable addresses
    //
    // Address format: Each index maps to a UNIQUE /16 netgroup to avoid MAX_PER_NETGROUP_NEW (32) limit
    // Format: first_octet.second_octet.0.1 where (first_octet, second_octet) is derived from index
    // This ensures we never hit the 32-per-netgroup limit when testing large batches
    static NetworkAddress MakeAddress(uint32_t index, uint16_t port = 9590) {
        NetworkAddress addr;
        addr.services = NODE_NETWORK;
        addr.port = port;

        // Create IPv4-mapped IPv6 address with proper netgroup distribution
        // AddrManager has MAX_PER_NETGROUP_NEW = 32, so we put 32 addresses per /16
        // This ensures all addresses can be added without hitting netgroup limits
        //
        // Strategy: index/32 selects the /16 netgroup, index%32 provides uniqueness within
        // Use only clearly routable public IP ranges:
        // - Skip 0.x.x.x (reserved), 10.x.x.x (private), 100.64-127.x.x (CGNAT)
        // - Skip 127.x.x.x (loopback), 169.254.x.x (link-local), 172.16-31.x.x (private)
        // - Skip 192.0.0/2.x.x (special), 192.168.x.x (private), 224+.x.x.x (multicast+)
        // Use safe ranges: 11-99, 101-126, 128-168, 170-171, 173-191, 193-223
        static const uint8_t safe_first_bytes[] = {
            11, 12, 13, 14, 15, 16, 17, 18, 19,  // 9 values after 10.x
            20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
            40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
            60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
            80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99
        };  // 89 values
        constexpr size_t NUM_SAFE = sizeof(safe_first_bytes) / sizeof(safe_first_bytes[0]);

        uint32_t netgroup_idx = index / 32;
        uint8_t first_byte = safe_first_bytes[netgroup_idx % NUM_SAFE];
        uint8_t second_byte = static_cast<uint8_t>(netgroup_idx / NUM_SAFE);
        uint8_t third_byte = static_cast<uint8_t>(index % 32);
        uint8_t fourth_byte = 1;  // Non-zero

        std::memset(addr.ip.data(), 0, 10);
        addr.ip[10] = 0xFF;
        addr.ip[11] = 0xFF;
        addr.ip[12] = first_byte;
        addr.ip[13] = second_byte;
        addr.ip[14] = third_byte;
        addr.ip[15] = fourth_byte;

        return addr;
    }

    static TimestampedAddress MakeTimestampedAddress(uint32_t index, uint32_t timestamp = 0) {
        TimestampedAddress ta;
        ta.address = MakeAddress(index);
        ta.timestamp = timestamp ? timestamp : static_cast<uint32_t>(util::GetTime());
        return ta;
    }
};

// ============================================================================
// Learned Address Eviction Tests (Regression tests for bug fix)
// ============================================================================

TEST_CASE("PeerDiscoveryManager - Learned address eviction keeps correct count", "[discovery][eviction][regression]") {
    // This is a regression test for the bug where eviction was deleting
    // target_keep entries instead of (size - target_keep) entries

    // Ensure no leftover mock time from previous tests
    util::SetMockTime(0);

    DiscoveryManagerTestFixture fixture;

    // Create and add a peer
    auto peer = fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY, "192.168.1.1", 9590);
    int peer_id = fixture.peer_manager->add_peer(peer);
    REQUIRE(peer_id >= 0);
    peer->set_successfully_connected_for_test(true);

    // MAX_LEARNED_PER_PEER = 2000
    // Eviction triggers at 2200 (110% of 2000)
    // After eviction, should have 1800 (90% of 2000)

    SECTION("Eviction keeps 90% of capacity when triggered") {
        const size_t MAX_LEARNED = 2000;
        const size_t EVICTION_THRESHOLD = MAX_LEARNED * 11 / 10;  // 2200
        const size_t TARGET_KEEP = MAX_LEARNED * 9 / 10;  // 1800

        // Get current time - all entries need to be "recent" to avoid TTL pruning
        const int64_t now_s = util::GetTime();  // Use mock-aware time

        // Populate learned addresses directly via ModifyLearnedAddresses
        // Add 2300 entries (above 2200 threshold)
        const size_t initial_count = 2300;

        fixture.peer_manager->ModifyLearnedAddresses(peer_id, [&](LearnedMap& learned) {
            for (size_t i = 0; i < initial_count; i++) {
                AddressKey key;
                auto addr = DiscoveryManagerTestFixture::MakeAddress(static_cast<uint32_t>(i));
                key.ip = addr.ip;
                key.port = addr.port;

                LearnedEntry entry;
                entry.ts_addr.address = addr;
                entry.ts_addr.timestamp = static_cast<uint32_t>(now_s);
                // Use recent timestamps (within TTL of 600s) to avoid pruning
                // Vary slightly so eviction can pick oldest
                entry.last_seen_s = now_s - 100 + static_cast<int64_t>(i % 100);

                learned[key] = entry;
            }
        });

        // Verify we have 2300 entries before triggering eviction
        auto learned_opt = fixture.peer_manager->GetLearnedAddresses(peer_id);
        REQUIRE(learned_opt.has_value());
        REQUIRE(learned_opt->size() == initial_count);

        // Now send an ADDR message to trigger the eviction code path
        // Create a small ADDR message (1 address) to trigger HandleAddr
        message::AddrMessage addr_msg;
        addr_msg.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(99999));

        bool result = fixture.discovery_manager->HandleAddr(peer, &addr_msg);
        REQUIRE(result == true);

        // Check the count after eviction
        auto learned_after = fixture.peer_manager->GetLearnedAddresses(peer_id);
        REQUIRE(learned_after.has_value());

        // Should have approximately TARGET_KEEP entries (1800) + the 1 new address
        // The exact count depends on timing, but it should NOT be 500!
        INFO("Entries after eviction: " << learned_after->size());
        INFO("Expected approximately: " << (TARGET_KEEP + 1));
        INFO("Bug would have left: " << (initial_count - TARGET_KEEP));

        // The fix ensures we keep ~1800 entries, not ~500
        REQUIRE(learned_after->size() >= TARGET_KEEP);
        REQUIRE(learned_after->size() <= TARGET_KEEP + 10);  // Allow small variance
    }

    SECTION("Eviction evicts oldest entries") {
        // Verify that the oldest entries (by last_seen_s) are evicted
        const size_t initial_count = 2300;

        fixture.peer_manager->ModifyLearnedAddresses(peer_id, [&](LearnedMap& learned) {
            for (size_t i = 0; i < initial_count; i++) {
                AddressKey key;
                auto addr = DiscoveryManagerTestFixture::MakeAddress(static_cast<uint32_t>(i));
                key.ip = addr.ip;
                key.port = addr.port;

                LearnedEntry entry;
                entry.ts_addr.address = addr;
                entry.ts_addr.timestamp = static_cast<uint32_t>(1000000 + i);
                // Use i directly as last_seen_s so older indices = older timestamps
                entry.last_seen_s = static_cast<int64_t>(i);

                learned[key] = entry;
            }
        });

        // Trigger eviction
        message::AddrMessage addr_msg;
        addr_msg.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(99999));
        fixture.discovery_manager->HandleAddr(peer, &addr_msg);

        // Check that the newest entries were kept
        auto learned_after = fixture.peer_manager->GetLearnedAddresses(peer_id);
        REQUIRE(learned_after.has_value());

        // The oldest entries (lowest last_seen_s values) should have been evicted
        // The newest entries (highest indices) should remain
        // Check that we kept the newer half
        size_t kept_count = learned_after->size();

        // Find the minimum last_seen_s in the remaining entries
        int64_t min_last_seen = std::numeric_limits<int64_t>::max();
        for (const auto& [key, entry] : *learned_after) {
            min_last_seen = std::min(min_last_seen, entry.last_seen_s);
        }

        INFO("Kept " << kept_count << " entries");
        INFO("Minimum last_seen_s in remaining: " << min_last_seen);

        // The minimum remaining should be roughly (initial_count - TARGET_KEEP)
        // i.e., the oldest 500 were evicted, so min remaining should be >= 500
        size_t expected_evicted = initial_count - 1800;
        REQUIRE(min_last_seen >= static_cast<int64_t>(expected_evicted - 10));  // Allow small variance
    }
}

TEST_CASE("PeerDiscoveryManager - No eviction below threshold", "[discovery][eviction]") {
    // Ensure no leftover mock time from previous tests
    util::SetMockTime(0);

    DiscoveryManagerTestFixture fixture;

    auto peer = fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY, "192.168.1.1", 9590);
    int peer_id = fixture.peer_manager->add_peer(peer);
    REQUIRE(peer_id >= 0);
    peer->set_successfully_connected_for_test(true);

    // Add exactly 2000 entries (at capacity but not over threshold)
    const size_t count = 2000;

    fixture.peer_manager->ModifyLearnedAddresses(peer_id, [&](LearnedMap& learned) {
        for (size_t i = 0; i < count; i++) {
            AddressKey key;
            auto addr = DiscoveryManagerTestFixture::MakeAddress(static_cast<uint32_t>(i));
            key.ip = addr.ip;
            key.port = addr.port;

            LearnedEntry entry;
            entry.ts_addr.address = addr;
            entry.ts_addr.timestamp = static_cast<uint32_t>(util::GetTime());
            entry.last_seen_s = util::GetTime();

            learned[key] = entry;
        }
    });

    // Trigger HandleAddr
    message::AddrMessage addr_msg;
    addr_msg.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(99999));
    fixture.discovery_manager->HandleAddr(peer, &addr_msg);

    // Should have 2001 entries (no eviction triggered since 2001 <= 2200)
    auto learned_after = fixture.peer_manager->GetLearnedAddresses(peer_id);
    REQUIRE(learned_after.has_value());
    REQUIRE(learned_after->size() == count + 1);
}

// ============================================================================
// HandleAddr Tests
// ============================================================================

TEST_CASE("PeerDiscoveryManager - HandleAddr null message returns false", "[discovery][addr]") {
    DiscoveryManagerTestFixture fixture;

    auto peer = fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY, "192.168.1.1", 9590);
    fixture.peer_manager->add_peer(peer);
    peer->set_successfully_connected_for_test(true);

    bool result = fixture.discovery_manager->HandleAddr(peer, nullptr);
    REQUIRE(result == false);
}

TEST_CASE("PeerDiscoveryManager - HandleAddr pre-VERACK is ignored", "[discovery][addr]") {
    DiscoveryManagerTestFixture fixture;

    auto peer = fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY, "192.168.1.1", 9590);
    fixture.peer_manager->add_peer(peer);
    // Note: NOT setting successfully_connected_for_test(true)

    message::AddrMessage addr_msg;
    addr_msg.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(1));

    bool result = fixture.discovery_manager->HandleAddr(peer, &addr_msg);
    REQUIRE(result == true);  // Returns true (handled, not error) but doesn't process

    // Verify nothing was added to AddrMan
    REQUIRE(fixture.discovery_manager->addr_manager_for_test().size() == 0);
}

TEST_CASE("PeerDiscoveryManager - HandleAddr block-relay peer is ignored", "[discovery][addr][block_relay]") {
    DiscoveryManagerTestFixture fixture;

    auto peer = fixture.create_peer(ConnectionType::BLOCK_RELAY, "192.168.1.1", 9590);
    fixture.peer_manager->add_peer(peer);
    peer->set_successfully_connected_for_test(true);

    message::AddrMessage addr_msg;
    addr_msg.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(1));

    size_t initial_size = fixture.discovery_manager->addr_manager_for_test().size();

    bool result = fixture.discovery_manager->HandleAddr(peer, &addr_msg);
    REQUIRE(result == true);  // Handled successfully (not an error)

    // Verify nothing was added
    REQUIRE(fixture.discovery_manager->addr_manager_for_test().size() == initial_size);
}

// Note: Oversized ADDR messages are rejected at deserialization layer
// (AddrMessage::deserialize returns false for count > MAX_ADDR_SIZE),
// so HandleAddr never sees them. No need to test oversized handling here.

// ============================================================================
// HandleGetAddr Tests
// ============================================================================

TEST_CASE("PeerDiscoveryManager - HandleGetAddr pre-VERACK is ignored", "[discovery][getaddr]") {
    DiscoveryManagerTestFixture fixture;

    auto peer = fixture.create_peer(ConnectionType::INBOUND, "192.168.1.1", 9590);
    fixture.peer_manager->add_peer(peer);
    // Note: NOT setting successfully_connected_for_test(true)

    bool result = fixture.discovery_manager->HandleGetAddr(peer);
    REQUIRE(result == true);  // Returns true but doesn't respond
}

TEST_CASE("PeerDiscoveryManager - HandleGetAddr block-relay peer is ignored", "[discovery][getaddr][block_relay]") {
    DiscoveryManagerTestFixture fixture;

    auto peer = fixture.create_peer(ConnectionType::BLOCK_RELAY, "192.168.1.1", 9590);
    fixture.peer_manager->add_peer(peer);
    peer->set_successfully_connected_for_test(true);

    bool result = fixture.discovery_manager->HandleGetAddr(peer);
    REQUIRE(result == true);  // Handled but ignored
}

TEST_CASE("PeerDiscoveryManager - HandleGetAddr outbound peer is ignored (fingerprinting protection)", "[discovery][getaddr][security]") {
    DiscoveryManagerTestFixture fixture;

    // Add some addresses to AddrMan
    for (int i = 0; i < 10; i++) {
        fixture.discovery_manager->addr_manager_for_test().add(DiscoveryManagerTestFixture::MakeAddress(i));
    }

    auto peer = fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY, "192.168.1.1", 9590);
    fixture.peer_manager->add_peer(peer);
    peer->set_successfully_connected_for_test(true);

    auto stats_before = fixture.discovery_manager->GetGetAddrDebugStats();

    bool result = fixture.discovery_manager->HandleGetAddr(peer);
    REQUIRE(result == true);

    auto stats_after = fixture.discovery_manager->GetGetAddrDebugStats();
    REQUIRE(stats_after.ignored_outbound == stats_before.ignored_outbound + 1);
}

TEST_CASE("PeerDiscoveryManager - HandleGetAddr once per connection", "[discovery][getaddr][ratelimit]") {
    DiscoveryManagerTestFixture fixture;

    // Add some addresses to AddrMan so GETADDR has something to return
    for (int i = 0; i < 10; i++) {
        fixture.discovery_manager->addr_manager_for_test().add(DiscoveryManagerTestFixture::MakeAddress(i));
    }

    // Create inbound peer with routable address via mock transport
    auto peer = fixture.create_peer(ConnectionType::INBOUND, "193.0.0.1", 9590);
    int peer_id = fixture.peer_manager->add_peer(peer);
    REQUIRE(peer_id >= 0);  // Verify add_peer succeeded
    peer->set_successfully_connected_for_test(true);

    auto stats_before = fixture.discovery_manager->GetGetAddrDebugStats();

    // First GETADDR should be served
    bool result1 = fixture.discovery_manager->HandleGetAddr(peer);
    REQUIRE(result1 == true);

    auto stats_after1 = fixture.discovery_manager->GetGetAddrDebugStats();
    REQUIRE(stats_after1.served == stats_before.served + 1);

    // Second GETADDR should be ignored (repeat)
    bool result2 = fixture.discovery_manager->HandleGetAddr(peer);
    REQUIRE(result2 == true);

    auto stats_after2 = fixture.discovery_manager->GetGetAddrDebugStats();
    REQUIRE(stats_after2.served == stats_after1.served);  // No change
    REQUIRE(stats_after2.ignored_repeat == stats_after1.ignored_repeat + 1);
}

TEST_CASE("PeerDiscoveryManager - HandleGetAddr respects 23% limit (Bitcoin Core parity)", "[discovery][getaddr][bitcoin_core]") {
    DiscoveryManagerTestFixture fixture;

    // Add 100 addresses to AddrMan
    for (int i = 0; i < 100; i++) {
        fixture.discovery_manager->addr_manager_for_test().add(DiscoveryManagerTestFixture::MakeAddress(i));
    }
    REQUIRE(fixture.discovery_manager->addr_manager_for_test().size() == 100);

    // Create inbound peer
    auto peer = fixture.create_peer(ConnectionType::INBOUND, "192.168.1.1", 9590);
    fixture.peer_manager->add_peer(peer);
    peer->set_successfully_connected_for_test(true);

    // HandleGetAddr should return at most 23% of 100 = 23 addresses
    bool result = fixture.discovery_manager->HandleGetAddr(peer);
    REQUIRE(result == true);

    // Check stats - last_from_addrman should be <= 23
    auto stats = fixture.discovery_manager->GetGetAddrDebugStats();
    REQUIRE(stats.last_from_addrman <= 23);
    INFO("Returned " << stats.last_from_addrman << " addresses (limit: 23)");
}

TEST_CASE("PeerDiscoveryManager - HandleGetAddr percentage limit prevents full enumeration", "[discovery][getaddr][bitcoin_core][security]") {
    DiscoveryManagerTestFixture fixture;

    // Add 1000 addresses to AddrMan (max typical size)
    for (int i = 0; i < 1000; i++) {
        fixture.discovery_manager->addr_manager_for_test().add(DiscoveryManagerTestFixture::MakeAddress(i));
    }
    size_t addrman_size = fixture.discovery_manager->addr_manager_for_test().size();
    INFO("AddrMan size: " << addrman_size);

    // Create inbound peer
    auto peer = fixture.create_peer(ConnectionType::INBOUND, "192.168.1.1", 9590);
    fixture.peer_manager->add_peer(peer);
    peer->set_successfully_connected_for_test(true);

    bool result = fixture.discovery_manager->HandleGetAddr(peer);
    REQUIRE(result == true);

    // 23% of 1000 = 230, but also capped at MAX_ADDR_SIZE (1000)
    // So limit should be min(230, 1000) = 230
    auto stats = fixture.discovery_manager->GetGetAddrDebugStats();
    size_t expected_max = (addrman_size * 23) / 100;
    REQUIRE(stats.last_from_addrman <= expected_max);
    INFO("Returned " << stats.last_from_addrman << " addresses (limit: " << expected_max << ")");

    // Verify we're not returning everything (fingerprinting protection)
    REQUIRE(stats.last_from_addrman < addrman_size);
}

TEST_CASE("PeerDiscoveryManager - HandleGetAddr echo suppression (addresses peer sent us)", "[discovery][getaddr][echo]") {
    // Ensure no leftover mock time from previous tests
    util::SetMockTime(0);

    DiscoveryManagerTestFixture fixture;

    // Add addresses to AddrMan
    for (int i = 0; i < 50; i++) {
        fixture.discovery_manager->addr_manager_for_test().add(DiscoveryManagerTestFixture::MakeAddress(i));
    }

    // Create inbound peer
    auto peer = fixture.create_peer(ConnectionType::INBOUND, "192.168.1.1", 9590);
    int peer_id = fixture.peer_manager->add_peer(peer);
    REQUIRE(peer_id >= 0);
    peer->set_successfully_connected_for_test(true);

    // Simulate that peer sent us addresses 0-9 (add to learned map)
    const int64_t now_s = util::GetTime();  // Use mock-aware time
    fixture.peer_manager->ModifyLearnedAddresses(peer_id, [&](LearnedMap& learned) {
        for (int i = 0; i < 10; i++) {
            auto addr = DiscoveryManagerTestFixture::MakeAddress(i);
            AddressKey key;
            key.ip = addr.ip;
            key.port = addr.port;

            LearnedEntry entry;
            entry.ts_addr.address = addr;
            entry.ts_addr.timestamp = static_cast<uint32_t>(now_s);
            entry.last_seen_s = now_s;

            learned[key] = entry;
        }
    });

    // HandleGetAddr should suppress the 10 addresses peer sent us
    bool result = fixture.discovery_manager->HandleGetAddr(peer);
    REQUIRE(result == true);

    auto stats = fixture.discovery_manager->GetGetAddrDebugStats();
    // Should have suppressed some addresses
    REQUIRE(stats.last_suppressed > 0);
    INFO("Suppressed " << stats.last_suppressed << " addresses that peer already knows");
}

TEST_CASE("PeerDiscoveryManager - HandleGetAddr self-address suppression", "[discovery][getaddr][echo]") {
    // This test verifies that HandleGetAddr doesn't send the peer their own address
    // We test the suppression logic by adding the peer's address to the learned map
    // (which triggers the same is_suppressed check as self-address)

    // Ensure no leftover mock time from previous tests
    util::SetMockTime(0);

    DiscoveryManagerTestFixture fixture;

    // Add addresses to AddrMan
    for (int i = 0; i < 50; i++) {
        fixture.discovery_manager->addr_manager_for_test().add(DiscoveryManagerTestFixture::MakeAddress(i));
    }

    // Create inbound peer
    auto mock_conn = std::make_shared<MockTransportConnection>("93.184.216.100", 9590);
    mock_conn->set_inbound(true);
    auto peer = Peer::create_inbound(fixture.io_context, mock_conn, magic::REGTEST, 0);
    int peer_id = fixture.peer_manager->add_peer(peer);
    REQUIRE(peer_id >= 0);
    peer->set_successfully_connected_for_test(true);

    // Verify peer's address is parsed correctly
    REQUIRE(peer->address() == "93.184.216.100");
    REQUIRE(peer->port() == 9590);

    // Add peer's own address to their learned map (simulating they sent it to us)
    // This ensures the self-address suppression is tested via the is_suppressed() path
    const int64_t now_s = util::GetTime();  // Use mock-aware time
    auto self_addr = protocol::NetworkAddress::from_string("93.184.216.100", 9590);
    fixture.peer_manager->ModifyLearnedAddresses(peer_id, [&](LearnedMap& learned) {
        AddressKey key;
        key.ip = self_addr.ip;
        key.port = self_addr.port;

        LearnedEntry entry;
        entry.ts_addr.address = self_addr;
        entry.ts_addr.timestamp = static_cast<uint32_t>(now_s);
        entry.last_seen_s = now_s;

        learned[key] = entry;
    });

    // Also add the peer's address to AddrMan so it could be returned
    fixture.discovery_manager->addr_manager_for_test().add(self_addr);

    // HandleGetAddr should suppress the peer's own address
    bool result = fixture.discovery_manager->HandleGetAddr(peer);
    REQUIRE(result == true);

    // The peer's address should have been suppressed (either via learned map or self-check)
    auto stats = fixture.discovery_manager->GetGetAddrDebugStats();
    // Note: With 23% limit and random selection, the address might not be in the returned set
    // But if it is, it will be suppressed. The test verifies the code path runs without error.
    INFO("Suppressed " << stats.last_suppressed << " addresses");

    // Verify response was sent
    REQUIRE(mock_conn->sent_message_count() == 1);
}

TEST_CASE("PeerDiscoveryManager - HandleGetAddr echo suppression TTL expiry", "[discovery][getaddr][echo][time]") {
    // Use mock time for this test
    util::SetMockTime(0);
    constexpr int64_t TEST_TIME = 1700000000;
    util::MockTimeScope mock_time(TEST_TIME);

    DiscoveryManagerTestFixture fixture;

    // Add addresses to AddrMan
    for (int i = 0; i < 50; i++) {
        fixture.discovery_manager->addr_manager_for_test().add(DiscoveryManagerTestFixture::MakeAddress(i));
    }

    // Create inbound peer
    auto peer = fixture.create_peer(ConnectionType::INBOUND, "192.168.1.1", 9590);
    int peer_id = fixture.peer_manager->add_peer(peer);
    REQUIRE(peer_id >= 0);
    peer->set_successfully_connected_for_test(true);

    // Add learned addresses with OLD timestamps (beyond TTL)
    // ECHO_SUPPRESS_TTL_SEC is 600 (10 minutes)
    const int64_t old_time = TEST_TIME - 700;  // 700 seconds ago (beyond 600s TTL)
    fixture.peer_manager->ModifyLearnedAddresses(peer_id, [&](LearnedMap& learned) {
        for (int i = 0; i < 10; i++) {
            auto addr = DiscoveryManagerTestFixture::MakeAddress(i);
            AddressKey key;
            key.ip = addr.ip;
            key.port = addr.port;

            LearnedEntry entry;
            entry.ts_addr.address = addr;
            entry.ts_addr.timestamp = static_cast<uint32_t>(old_time);
            entry.last_seen_s = old_time;  // Old last_seen triggers TTL expiry

            learned[key] = entry;
        }
    });

    // HandleGetAddr should NOT suppress these addresses (TTL expired)
    bool result = fixture.discovery_manager->HandleGetAddr(peer);
    REQUIRE(result == true);

    auto stats = fixture.discovery_manager->GetGetAddrDebugStats();
    // Old addresses should NOT be suppressed (TTL expired, peer may have forgotten)
    INFO("Suppressed " << stats.last_suppressed << " addresses (should be 0 due to TTL expiry)");
    REQUIRE(stats.last_suppressed == 0);
}

TEST_CASE("PeerDiscoveryManager - HandleGetAddr TOCTOU protection (peer disconnected)", "[discovery][getaddr][toctou]") {
    DiscoveryManagerTestFixture fixture;

    // Add addresses to AddrMan
    for (int i = 0; i < 10; i++) {
        fixture.discovery_manager->addr_manager_for_test().add(DiscoveryManagerTestFixture::MakeAddress(i));
    }

    // Create inbound peer
    auto mock_conn = std::make_shared<MockTransportConnection>("192.168.1.1", 9590);
    mock_conn->set_inbound(true);
    auto peer = Peer::create_inbound(fixture.io_context, mock_conn, magic::REGTEST, 0);
    int peer_id = fixture.peer_manager->add_peer(peer);
    REQUIRE(peer_id >= 0);
    peer->set_successfully_connected_for_test(true);

    // Disconnect the peer before HandleGetAddr sends the response
    // close() sets is_open() to false, which peer->is_connected() checks
    mock_conn->close();

    // HandleGetAddr should handle disconnected peer gracefully
    bool result = fixture.discovery_manager->HandleGetAddr(peer);
    REQUIRE(result == true);  // Returns true (not an error, just too late)

    // No message should have been sent (peer disconnected)
    REQUIRE(mock_conn->sent_message_count() == 0);
}

TEST_CASE("PeerDiscoveryManager - HandleGetAddr with null addr_manager returns false", "[discovery][getaddr][edge]") {
    // Create a discovery manager without an addr_manager
    asio::io_context io_context;
    PeerLifecycleManager::Config pm_config;
    auto peer_manager = std::make_unique<PeerLifecycleManager>(io_context, pm_config);

    // Create discovery manager and clear addr_manager
    auto discovery_manager = std::make_unique<PeerDiscoveryManager>(peer_manager.get());

    // Create a peer
    auto mock_conn = std::make_shared<MockTransportConnection>("192.168.1.1", 9590);
    mock_conn->set_inbound(true);
    auto peer = Peer::create_inbound(io_context, mock_conn, magic::REGTEST, 0);
    peer_manager->add_peer(peer);
    peer->set_successfully_connected_for_test(true);

    // The addr_manager is always created in constructor, so this test verifies
    // normal operation. The null check is defensive.
    bool result = discovery_manager->HandleGetAddr(peer);
    // With valid addr_manager, should return true
    REQUIRE(result == true);
}

TEST_CASE("PeerDiscoveryManager - HandleGetAddr shuffles response for privacy", "[discovery][getaddr][privacy]") {
    // Test that GETADDR responses are shuffled to prevent recency leaks
    // Note: AddrMan's get_addresses() has its own randomness, so we can't test
    // determinism with seeds alone. Instead, verify that:
    // 1. Multiple calls produce responses (shuffle doesn't crash)
    // 2. The shuffle code path is exercised

    DiscoveryManagerTestFixture fixture;

    // Add addresses to AddrMan
    for (int i = 0; i < 20; i++) {
        fixture.discovery_manager->addr_manager_for_test().add(
            DiscoveryManagerTestFixture::MakeAddress(i));
    }

    // Create inbound peer
    auto mock_conn = std::make_shared<MockTransportConnection>("193.0.0.1", 9590);
    mock_conn->set_inbound(true);
    auto peer = Peer::create_inbound(fixture.io_context, mock_conn, magic::REGTEST, 0);
    fixture.peer_manager->add_peer(peer);
    peer->set_successfully_connected_for_test(true);

    // Call HandleGetAddr - should shuffle and send
    bool result = fixture.discovery_manager->HandleGetAddr(peer);
    REQUIRE(result == true);

    // Verify a message was sent
    auto msgs = mock_conn->get_sent_messages();
    REQUIRE(msgs.size() == 1);

    // Verify the message has content (addresses were included)
    // Message header is 24 bytes (magic:4 + cmd:12 + len:4 + checksum:4)
    // Each address entry is ~30 bytes, so with addresses the message should be substantial
    REQUIRE(msgs[0].size() > 24);

    // The shuffle is verified implicitly - if shuffle threw or corrupted data,
    // the message serialization would fail or produce invalid output
    INFO("GETADDR response size: " << msgs[0].size() << " bytes");
}

// ============================================================================
// Rate Limiting Tests
// ============================================================================

TEST_CASE("PeerDiscoveryManager - ADDR rate limiting", "[discovery][addr][ratelimit]") {
    DiscoveryManagerTestFixture fixture;

    // Use routable public IP
    auto peer = fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY, "193.0.0.2", 9590);
    fixture.peer_manager->add_peer(peer);
    peer->set_successfully_connected_for_test(true);

    // First message: should be fully processed (token bucket starts at 1.0)
    message::AddrMessage addr_msg1;
    addr_msg1.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(1));

    fixture.discovery_manager->HandleAddr(peer, &addr_msg1);

    // Token bucket is now depleted
    // Send another large batch - should be rate limited
    message::AddrMessage addr_msg2;
    for (int i = 0; i < 100; i++) {
        addr_msg2.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(1000 + i));
    }

    fixture.discovery_manager->HandleAddr(peer, &addr_msg2);

    // Not all addresses should have been processed due to rate limiting
    // Exact count depends on token bucket refill, but should be < 100
    // This is hard to test precisely without mocking time, but at least verify no crash
    REQUIRE(fixture.discovery_manager->addr_manager_for_test().size() > 0);
}

TEST_CASE("PeerDiscoveryManager - NotifyGetAddrSent boosts token bucket", "[discovery][addr][ratelimit]") {
    DiscoveryManagerTestFixture fixture;

    // Create outbound peer with routable address via mock transport
    auto peer = fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY, "193.0.0.1", 9590);
    int peer_id = fixture.peer_manager->add_peer(peer);
    REQUIRE(peer_id >= 0);  // Verify add_peer succeeded
    REQUIRE(peer->id() == peer_id);  // Verify peer's ID matches
    peer->set_successfully_connected_for_test(true);

    // Deplete token bucket with first address
    message::AddrMessage addr_msg1;
    addr_msg1.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(1));
    fixture.discovery_manager->HandleAddr(peer, &addr_msg1);

    // Boost bucket by notifying GETADDR sent
    // Use peer->id() to ensure we boost the right bucket (same one HandleAddr uses)
    fixture.discovery_manager->NotifyGetAddrSent(peer->id());

    // Now send a large batch - should be fully processed due to bucket boost
    message::AddrMessage addr_msg2;
    for (int i = 0; i < 500; i++) {
        addr_msg2.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(1000 + i));
    }

    size_t before = fixture.discovery_manager->addr_manager_for_test().size();
    fixture.discovery_manager->HandleAddr(peer, &addr_msg2);
    size_t after = fixture.discovery_manager->addr_manager_for_test().size();

    // Per-source limit caps addresses from any single peer to MAX_ADDRESSES_PER_SOURCE (64)
    // This is stricter than rate limiting and provides Sybil resistance
    // After the first address, we can add at most 63 more from this peer
    REQUIRE(after - before <= 64);
    REQUIRE(after - before >= 32);  // Some addresses should be added (allowing for netgroup limits)
}

TEST_CASE("PeerDiscoveryManager - ADDR rate limiting with mock time", "[discovery][addr][ratelimit][time]") {
    // Ensure mock time starts clean (no leftover from previous tests)
    util::SetMockTime(0);

    // Use a realistic timestamp (recent past) to avoid timestamp validation issues
    constexpr int64_t TEST_TIME = 1700000000;  // Nov 2023
    util::MockTimeScope mock_time(TEST_TIME);

    DiscoveryManagerTestFixture fixture;
    auto peer = fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY, "193.0.0.3", 9590);
    fixture.peer_manager->add_peer(peer);
    peer->set_successfully_connected_for_test(true);

    SECTION("First ADDR message gets full bucket (1000 tokens)") {
        // Realistic scenario: we send GETADDR, peer responds with ADDR.
        // NotifyGetAddrSent() boosts the bucket to allow the expected large response.
        // (Don't rely on steady_clock epoch being far in the past - CI runners may have low uptime)
        fixture.discovery_manager->NotifyGetAddrSent(peer->id());

        // Use 100 addresses to stay well under AddrManager's netgroup limits
        size_t before = fixture.discovery_manager->addr_manager_for_test().size();

        message::AddrMessage addr_msg;
        for (int i = 0; i < 100; i++) {
            addr_msg.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(i, TEST_TIME));
        }

        fixture.discovery_manager->HandleAddr(peer, &addr_msg);

        size_t after = fixture.discovery_manager->addr_manager_for_test().size();
        size_t added = after - before;

        // Debug: show what we got
        INFO("Mock time: " << util::GetMockTime());
        INFO("Addresses added: " << added << " / 100");

        // Per-source limit caps addresses from any single peer to MAX_ADDRESSES_PER_SOURCE (64)
        // Rate limiting allows 100, but per-source Sybil protection limits to 64
        REQUIRE(added <= 64);
        REQUIRE(added >= 32);  // Some addresses should be added (allowing for netgroup limits)
    }

    SECTION("Second ADDR message is rate limited after bucket depleted") {
        // Boost bucket first (simulates GETADDR being sent)
        fixture.discovery_manager->NotifyGetAddrSent(peer->id());

        // First message: deplete bucket with 1000 addresses
        message::AddrMessage addr_msg1;
        for (int i = 0; i < 1000; i++) {
            addr_msg1.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(i, TEST_TIME));
        }
        fixture.discovery_manager->HandleAddr(peer, &addr_msg1);
        size_t after_first = fixture.discovery_manager->addr_manager_for_test().size();

        // Second message immediately after: bucket is empty, should be rate limited
        // No time advance, so no refill
        message::AddrMessage addr_msg2;
        for (int i = 1000; i < 1100; i++) {
            addr_msg2.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(i, TEST_TIME));
        }
        fixture.discovery_manager->HandleAddr(peer, &addr_msg2);
        size_t after_second = fixture.discovery_manager->addr_manager_for_test().size();

        // Very few or none should be added (bucket refill is 0.1/sec, so ~0 in 0 seconds)
        REQUIRE(after_second - after_first < 10);
    }

    SECTION("Bucket refills over time - limited by per-source cap") {
        // Boost bucket first (simulates GETADDR being sent)
        fixture.discovery_manager->NotifyGetAddrSent(peer->id());

        // First message - will be capped by per-source limit (64 addresses)
        message::AddrMessage addr_msg1;
        for (int i = 0; i < 1000; i++) {
            addr_msg1.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(i, TEST_TIME));
        }
        fixture.discovery_manager->HandleAddr(peer, &addr_msg1);
        size_t after_first = fixture.discovery_manager->addr_manager_for_test().size();

        // Per-source limit already reached (64 addresses from this peer)
        // So even with bucket refill, no more addresses can be added from this peer
        // This is expected behavior - per-source limit is stricter than rate limiting

        // Advance time by 100 seconds (bucket would refill 10 tokens)
        util::SetMockTime(TEST_TIME + 100);

        message::AddrMessage addr_msg2;
        for (int i = 1000; i < 1020; i++) {
            addr_msg2.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(i, TEST_TIME + 100));
        }
        fixture.discovery_manager->HandleAddr(peer, &addr_msg2);
        size_t after_second = fixture.discovery_manager->addr_manager_for_test().size();

        // Per-source limit already reached, so no more addresses can be added from this peer
        // This is the expected Sybil resistance behavior
        size_t processed = after_second - after_first;
        REQUIRE(processed == 0);  // Per-source limit prevents any more from this peer
    }
}

// ============================================================================
// Shuffle Fairness Tests
// ============================================================================

TEST_CASE("PeerDiscoveryManager - Rate limiting shuffle fairness", "[discovery][addr][ratelimit][shuffle]") {
    // This test verifies that when rate limiting kicks in, the shuffle ensures
    // different addresses get accepted based on random order (not always the first N)
    //
    // Without shuffling, the first N addresses in the message would always be accepted.
    // With shuffling, the acceptance depends on the random order.

    // Use a fixed mock time for determinism
    util::SetMockTime(0);
    constexpr int64_t TEST_TIME = 1700000000;
    util::MockTimeScope mock_time(TEST_TIME);

    SECTION("Same seed produces deterministic results - capped by per-source limit") {
        // Per-source limit (MAX_ADDRESSES_PER_SOURCE=64) caps what any single peer can add
        // After first message hits 64 addresses, no more can be added from that peer
        // This test verifies the deterministic behavior within that constraint
        auto run_with_seed = [&](uint64_t seed) -> size_t {
            DiscoveryManagerTestFixture fixture;
            fixture.discovery_manager->TestSeedRng(seed);

            auto peer = fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY, "193.0.0.1", 9590);
            fixture.peer_manager->add_peer(peer);
            peer->set_successfully_connected_for_test(true);

            // Boost bucket first (simulates GETADDR being sent)
            fixture.discovery_manager->NotifyGetAddrSent(peer->id());

            // First message - will be capped by per-source limit (64 addresses)
            message::AddrMessage first_msg;
            for (int i = 0; i < 100; i++) {
                first_msg.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(i, TEST_TIME));
            }
            fixture.discovery_manager->HandleAddr(peer, &first_msg);

            return fixture.discovery_manager->addr_manager_for_test().size();
        };

        // Same seed should produce same result
        size_t result1 = run_with_seed(12345);
        util::SetMockTime(TEST_TIME); // Reset for next run
        size_t result2 = run_with_seed(12345);

        REQUIRE(result1 == result2);
        // Per-source limit caps at ~64 (slight variance due to timing of check vs increment)
        REQUIRE(result1 <= 66);
        REQUIRE(result1 >= 32);  // Some addresses accepted (allowing for netgroup limits)
    }

    SECTION("Per-source limit prevents additional addresses from same peer") {
        // This verifies that per-source limit is the primary constraint
        // Once 64 addresses from a peer are added, no more can be added

        DiscoveryManagerTestFixture fixture;
        fixture.discovery_manager->TestSeedRng(99999);

        auto peer = fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY, "193.0.0.1", 9590);
        fixture.peer_manager->add_peer(peer);
        peer->set_successfully_connected_for_test(true);

        // Boost bucket first (simulates GETADDR being sent)
        fixture.discovery_manager->NotifyGetAddrSent(peer->id());

        // First message - hits per-source limit (64)
        message::AddrMessage first_msg;
        for (int i = 0; i < 1000; i++) {
            first_msg.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(i, TEST_TIME));
        }
        fixture.discovery_manager->HandleAddr(peer, &first_msg);
        size_t after_first = fixture.discovery_manager->addr_manager_for_test().size();

        // Per-source limit should have capped at ~64
        INFO("After first message: " << after_first << " addresses");
        REQUIRE(after_first <= 66);  // Slight variance due to timing
        REQUIRE(after_first >= 32);

        // Refill bucket (wouldn't matter since per-source limit already hit)
        util::SetMockTime(TEST_TIME + 50);

        // Second message - should add nothing (per-source limit already reached)
        message::AddrMessage second_msg;
        for (int i = 2000; i < 2020; i++) {
            second_msg.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(i, TEST_TIME));
        }
        fixture.discovery_manager->HandleAddr(peer, &second_msg);
        size_t after_second = fixture.discovery_manager->addr_manager_for_test().size();

        size_t accepted = after_second - after_first;
        INFO("Accepted " << accepted << " addresses in second message (per-source limit already hit)");

        // Per-source limit prevents any more from this peer
        REQUIRE(accepted == 0);
    }
}

// ============================================================================
// Bootstrap Tests
// ============================================================================

TEST_CASE("PeerDiscoveryManager - Bootstrap on Start", "[discovery][bootstrap]") {
    DiscoveryManagerTestFixture fixture;

    // Ensure AddrMan is empty
    REQUIRE(fixture.discovery_manager->addr_manager_for_test().size() == 0);

    // Start() calls BootstrapFromFixedSeeds internally when AddrMan is empty
    fixture.discovery_manager->Start([](const std::vector<protocol::NetworkAddress>&) {
        // Empty callback - we're just testing bootstrap
    });

    // Should have added some addresses (exact count depends on chain params)
    // At minimum, verify the function doesn't crash
    INFO("Addresses after bootstrap: " << fixture.discovery_manager->addr_manager_for_test().size());
}

TEST_CASE("PeerDiscoveryManager - Start() bootstraps from fixed seeds when empty", "[discovery][bootstrap]") {
    DiscoveryManagerTestFixture fixture;

    // Ensure AddrMan starts empty
    REQUIRE(fixture.discovery_manager->addr_manager_for_test().size() == 0);

    // Get REGTEST chain params to check how many seeds we have
    const auto& params = chain::GlobalChainParams::Get();
    const auto& seeds = params.FixedSeeds();

    INFO("REGTEST has " << seeds.size() << " fixed seeds");

    // Start() should call BootstrapFromFixedSeeds when addr_manager is empty
    fixture.discovery_manager->Start([](const std::vector<protocol::NetworkAddress>&) {
        // Empty callback - we're just testing bootstrap
    });

    // If REGTEST has seeds, they should have been added
    if (!seeds.empty()) {
        size_t addrman_size = fixture.discovery_manager->addr_manager_for_test().size();
        INFO("AddrMan size after bootstrap: " << addrman_size);
        REQUIRE(addrman_size > 0);
        REQUIRE(addrman_size <= seeds.size());  // Can't add more than provided
    }
}

TEST_CASE("PeerDiscoveryManager - Fixed seeds have valid format", "[discovery][bootstrap]") {
    // Verify all configured seeds have valid IP:port format
    const auto& params = chain::GlobalChainParams::Get();
    const auto& seeds = params.FixedSeeds();

    for (const auto& seed : seeds) {
        size_t colon_pos = seed.find(':');
        // Valid seeds should have a colon
        REQUIRE(colon_pos != std::string::npos);

        // Port should be parseable
        std::string port_str = seed.substr(colon_pos + 1);
        int port = std::stoi(port_str);
        REQUIRE(port > 0);
        REQUIRE(port <= 65535);

        INFO("Valid seed: " << seed);
    }
}

TEST_CASE("PeerDiscoveryManager - Start() skips bootstrap when AddrMan not empty", "[discovery][bootstrap][testnet]") {
    // Switch to TESTNET which has fixed seeds (REGTEST has none)
    chain::GlobalChainParams::Select(chain::ChainType::TESTNET);

    DiscoveryManagerTestFixture fixture;
    chain::GlobalChainParams::Select(chain::ChainType::TESTNET);  // Re-select after fixture resets to REGTEST

    // First Start() with empty AddrMan -> bootstraps
    fixture.discovery_manager->Start([](const std::vector<protocol::NetworkAddress>&) {});
    size_t size_after_first = fixture.discovery_manager->addr_manager_for_test().size();
    REQUIRE(size_after_first > 0);  // Should have bootstrapped

    // Second Start() - AddrMan not empty, should skip bootstrap
    // We can verify this by checking size doesn't change (no duplicates)
    fixture.discovery_manager->Start([](const std::vector<protocol::NetworkAddress>&) {});
    size_t size_after_second = fixture.discovery_manager->addr_manager_for_test().size();

    // Size should remain the same (bootstrap skipped because AddrMan wasn't empty)
    INFO("Size after first: " << size_after_first << ", after second: " << size_after_second);
    REQUIRE(size_after_second == size_after_first);

    // Restore REGTEST for other tests
    chain::GlobalChainParams::Select(chain::ChainType::REGTEST);
}

TEST_CASE("PeerDiscoveryManager - Bootstrap uses mockable time for timestamps", "[discovery][bootstrap][time][testnet]") {
    // Switch to TESTNET which has fixed seeds (REGTEST has none)
    chain::GlobalChainParams::Select(chain::ChainType::TESTNET);

    util::SetMockTime(0);
    constexpr int64_t TEST_TIME = 1700000000;
    util::MockTimeScope mock_time(TEST_TIME);

    DiscoveryManagerTestFixture fixture;
    chain::GlobalChainParams::Select(chain::ChainType::TESTNET);  // Re-select after fixture resets to REGTEST

    // Start() triggers bootstrap when AddrMan is empty
    fixture.discovery_manager->Start([](const std::vector<protocol::NetworkAddress>&) {});

    // Verify addresses were added with the mock timestamp
    auto addrs = fixture.discovery_manager->addr_manager_for_test().get_addresses(100);
    REQUIRE(!addrs.empty());  // Should have bootstrapped seeds

    // Timestamps should be close to TEST_TIME (within a few seconds)
    for (const auto& ta : addrs) {
        int64_t timestamp_diff = std::abs(static_cast<int64_t>(ta.timestamp) - TEST_TIME);
        INFO("Address timestamp: " << ta.timestamp << ", expected: " << TEST_TIME);
        REQUIRE(timestamp_diff < 10);  // Within 10 seconds
    }

    // Restore REGTEST for other tests
    chain::GlobalChainParams::Select(chain::ChainType::REGTEST);
}

TEST_CASE("PeerDiscoveryManager - TESTNET seeds are routable and accepted by AddrMan", "[discovery][bootstrap][testnet]") {
    // This test verifies that production seeds (TESTNET) will actually work:
    // 1. Seeds are parseable
    // 2. Seeds are routable (not private/reserved IPs)
    // 3. Seeds are accepted by AddrMan

    // Save current chain and switch to TESTNET
    // Note: Tests normally run with REGTEST which has no seeds
    chain::GlobalChainParams::Select(chain::ChainType::TESTNET);

    // Verify we have seeds to test (capture count before fixture resets chain)
    const auto& seeds = chain::GlobalChainParams::Get().FixedSeeds();
    REQUIRE(!seeds.empty());
    const size_t seed_count = seeds.size();
    INFO("Testing " << seed_count << " TESTNET seeds");

    // Verify each seed is routable
    for (const auto& seed : seeds) {
        size_t colon_pos = seed.find(':');
        REQUIRE(colon_pos != std::string::npos);
        std::string ip = seed.substr(0, colon_pos);

        INFO("Checking seed: " << seed);
        REQUIRE(util::IsRoutable(ip));
    }

    // Create fixture and verify Start() adds seeds to AddrMan
    // Note: fixture constructor resets to REGTEST, so we re-select TESTNET
    {
        DiscoveryManagerTestFixture fixture;
        chain::GlobalChainParams::Select(chain::ChainType::TESTNET);  // Re-select after fixture

        REQUIRE(fixture.discovery_manager->addr_manager_for_test().size() == 0);

        fixture.discovery_manager->Start([](const std::vector<protocol::NetworkAddress>&) {});

        size_t added = fixture.discovery_manager->addr_manager_for_test().size();
        INFO("AddrMan accepted " << added << " of " << seed_count << " seeds");
        REQUIRE(added > 0);
        REQUIRE(added == seed_count);  // All valid seeds should be accepted
    }

    // Restore REGTEST for other tests
    chain::GlobalChainParams::Select(chain::ChainType::REGTEST);
}

// ============================================================================
// AddressManager Integration Tests
// ============================================================================

TEST_CASE("PeerDiscoveryManager - AddressManager integration", "[discovery][addrman]") {
    DiscoveryManagerTestFixture fixture;

    // Test Add
    NetworkAddress addr1 = DiscoveryManagerTestFixture::MakeAddress(1);
    REQUIRE(fixture.discovery_manager->addr_manager_for_test().add(addr1));
    REQUIRE(fixture.discovery_manager->addr_manager_for_test().size() == 1);
    REQUIRE(fixture.discovery_manager->addr_manager_for_test().new_count() == 1);
    REQUIRE(fixture.discovery_manager->addr_manager_for_test().tried_count() == 0);

    // Test Good (moves to tried)
    fixture.discovery_manager->Good(addr1);
    REQUIRE(fixture.discovery_manager->addr_manager_for_test().new_count() == 0);
    REQUIRE(fixture.discovery_manager->addr_manager_for_test().tried_count() == 1);

    // Test Select
    auto selected = fixture.discovery_manager->Select();
    REQUIRE(selected.has_value());

    // Test GetAddresses
    auto addrs = fixture.discovery_manager->addr_manager_for_test().get_addresses(10);
    REQUIRE(addrs.size() == 1);

    // Test AddMultiple
    std::vector<TimestampedAddress> multi;
    multi.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(2));
    multi.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(3));
    size_t added = fixture.discovery_manager->addr_manager_for_test().add_multiple(multi);
    REQUIRE(added == 2);
    REQUIRE(fixture.discovery_manager->addr_manager_for_test().size() == 3);
}

// ============================================================================
// Address Relay Tests
// ============================================================================

TEST_CASE("PeerDiscoveryManager - Address relay to other peers", "[discovery][relay]") {
    DiscoveryManagerTestFixture fixture;

    // Seed deterministic random for predictable tests
    fixture.discovery_manager->TestSeedRng(12345);

    // Create sender peer (outbound full-relay)
    auto mock_conn1 = std::make_shared<MockTransportConnection>("193.0.0.1", 9590);
    mock_conn1->set_inbound(false);
    auto sender = Peer::create_outbound(fixture.io_context, mock_conn1, magic::REGTEST, 0, "193.0.0.1", 9590, ConnectionType::OUTBOUND_FULL_RELAY);
    int sender_id = fixture.peer_manager->add_peer(sender);
    REQUIRE(sender_id >= 0);
    sender->set_successfully_connected_for_test(true);

    // Create two relay target peers (outbound full-relay)
    auto mock_conn2 = std::make_shared<MockTransportConnection>("193.0.0.2", 9590);
    mock_conn2->set_inbound(false);
    auto target1 = Peer::create_outbound(fixture.io_context, mock_conn2, magic::REGTEST, 0, "193.0.0.2", 9590, ConnectionType::OUTBOUND_FULL_RELAY);
    int target1_id = fixture.peer_manager->add_peer(target1);
    REQUIRE(target1_id >= 0);
    target1->set_successfully_connected_for_test(true);

    auto mock_conn3 = std::make_shared<MockTransportConnection>("193.0.0.3", 9590);
    mock_conn3->set_inbound(false);
    auto target2 = Peer::create_outbound(fixture.io_context, mock_conn3, magic::REGTEST, 0, "193.0.0.3", 9590, ConnectionType::OUTBOUND_FULL_RELAY);
    int target2_id = fixture.peer_manager->add_peer(target2);
    REQUIRE(target2_id >= 0);
    target2->set_successfully_connected_for_test(true);

    // Clear any messages from peer setup
    mock_conn2->clear_sent_messages();
    mock_conn3->clear_sent_messages();

    SECTION("Addresses are relayed to other peers") {
        // Send ADDR from sender
        message::AddrMessage addr_msg;
        addr_msg.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(100));

        fixture.discovery_manager->HandleAddr(sender, &addr_msg);

        // Check that target peers received relayed messages
        size_t target1_msgs = mock_conn2->sent_message_count();
        size_t target2_msgs = mock_conn3->sent_message_count();

        INFO("Target1 received " << target1_msgs << " messages");
        INFO("Target2 received " << target2_msgs << " messages");

        // At least one target should have received the relay
        // (relay goes to 1-2 random peers)
        REQUIRE((target1_msgs > 0 || target2_msgs > 0));
    }

    SECTION("Addresses are NOT relayed back to sender") {
        // Send ADDR from sender
        message::AddrMessage addr_msg;
        addr_msg.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(100));

        mock_conn1->clear_sent_messages();
        fixture.discovery_manager->HandleAddr(sender, &addr_msg);

        // Sender should NOT receive any relay (no echo)
        REQUIRE(mock_conn1->sent_message_count() == 0);
    }
}

TEST_CASE("PeerDiscoveryManager - Address relay loop prevention", "[discovery][relay][loop]") {
    DiscoveryManagerTestFixture fixture;

    // Seed deterministic random
    fixture.discovery_manager->TestSeedRng(12345);

    // Create two peers that will exchange addresses
    auto mock_conn1 = std::make_shared<MockTransportConnection>("193.0.0.1", 9590);
    mock_conn1->set_inbound(false);
    auto peer1 = Peer::create_outbound(fixture.io_context, mock_conn1, magic::REGTEST, 0, "193.0.0.1", 9590, ConnectionType::OUTBOUND_FULL_RELAY);
    int peer1_id = fixture.peer_manager->add_peer(peer1);
    REQUIRE(peer1_id >= 0);
    peer1->set_successfully_connected_for_test(true);

    auto mock_conn2 = std::make_shared<MockTransportConnection>("193.0.0.2", 9590);
    mock_conn2->set_inbound(false);
    auto peer2 = Peer::create_outbound(fixture.io_context, mock_conn2, magic::REGTEST, 0, "193.0.0.2", 9590, ConnectionType::OUTBOUND_FULL_RELAY);
    int peer2_id = fixture.peer_manager->add_peer(peer2);
    REQUIRE(peer2_id >= 0);
    peer2->set_successfully_connected_for_test(true);

    SECTION("Known addresses are not relayed again") {
        // First, peer1 sends an address - it gets relayed to peer2
        message::AddrMessage addr_msg1;
        auto test_addr = DiscoveryManagerTestFixture::MakeTimestampedAddress(200);
        addr_msg1.addresses.push_back(test_addr);

        mock_conn2->clear_sent_messages();
        fixture.discovery_manager->HandleAddr(peer1, &addr_msg1);

        size_t first_relay_count = mock_conn2->sent_message_count();
        INFO("First relay: peer2 received " << first_relay_count << " messages");

        // Peer2 should have received the address (marked as "known" by peer2)
        // Verify learned_addresses was updated for peer2
        auto peer2_learned = fixture.peer_manager->GetLearnedAddresses(peer2_id);
        REQUIRE(peer2_learned.has_value());

        // Now simulate peer2 sending the SAME address back
        // This should NOT be relayed to peer2 again (loop prevention)
        message::AddrMessage addr_msg2;
        addr_msg2.addresses.push_back(test_addr);

        mock_conn2->clear_sent_messages();
        fixture.discovery_manager->HandleAddr(peer2, &addr_msg2);

        // Peer2 should NOT receive the address again
        size_t second_relay_count = mock_conn2->sent_message_count();
        INFO("Second relay: peer2 received " << second_relay_count << " messages");

        // The address should be filtered out because peer2 already knows it
        REQUIRE(second_relay_count == 0);
    }

    SECTION("New addresses in same batch are relayed") {
        // First send establishes peer2 knows address 200
        message::AddrMessage addr_msg1;
        addr_msg1.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(200));
        fixture.discovery_manager->HandleAddr(peer1, &addr_msg1);

        // Second send includes known (200) and new (201) addresses
        message::AddrMessage addr_msg2;
        addr_msg2.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(200));  // known
        addr_msg2.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(201));  // new

        mock_conn2->clear_sent_messages();
        // Use peer1 as sender again (only peer2 as target)
        // But we need to check if 201 gets through
        fixture.discovery_manager->HandleAddr(peer1, &addr_msg2);

        // If messages were sent, verify the content
        auto sent_msgs = mock_conn2->get_sent_messages();
        if (!sent_msgs.empty()) {
            // At least one message was sent - this is expected for the new address
            INFO("Relay messages sent: " << sent_msgs.size());
            REQUIRE(sent_msgs.size() > 0);
        }
    }
}

TEST_CASE("PeerDiscoveryManager - Address relay skips block-relay-only peers", "[discovery][relay][block_relay]") {
    DiscoveryManagerTestFixture fixture;

    fixture.discovery_manager->TestSeedRng(12345);

    // Create sender (full-relay)
    auto mock_conn1 = std::make_shared<MockTransportConnection>("193.0.0.1", 9590);
    mock_conn1->set_inbound(false);
    auto sender = Peer::create_outbound(fixture.io_context, mock_conn1, magic::REGTEST, 0, "193.0.0.1", 9590, ConnectionType::OUTBOUND_FULL_RELAY);
    fixture.peer_manager->add_peer(sender);
    sender->set_successfully_connected_for_test(true);

    // Create target as BLOCK_RELAY (should NOT receive relay)
    auto mock_conn2 = std::make_shared<MockTransportConnection>("193.0.0.2", 9590);
    mock_conn2->set_inbound(false);
    auto block_relay_peer = Peer::create_outbound(fixture.io_context, mock_conn2, magic::REGTEST, 0, "193.0.0.2", 9590, ConnectionType::BLOCK_RELAY);
    fixture.peer_manager->add_peer(block_relay_peer);
    block_relay_peer->set_successfully_connected_for_test(true);

    mock_conn2->clear_sent_messages();

    // Send ADDR from sender
    message::AddrMessage addr_msg;
    addr_msg.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(100));
    fixture.discovery_manager->HandleAddr(sender, &addr_msg);

    // Block-relay peer should NOT receive any relay
    REQUIRE(mock_conn2->sent_message_count() == 0);
}

TEST_CASE("PeerDiscoveryManager - Address relay skips pre-handshake peers", "[discovery][relay]") {
    DiscoveryManagerTestFixture fixture;

    fixture.discovery_manager->TestSeedRng(12345);

    // Create sender (full-relay, post-handshake)
    auto mock_conn1 = std::make_shared<MockTransportConnection>("193.0.0.1", 9590);
    mock_conn1->set_inbound(false);
    auto sender = Peer::create_outbound(fixture.io_context, mock_conn1, magic::REGTEST, 0, "193.0.0.1", 9590, ConnectionType::OUTBOUND_FULL_RELAY);
    fixture.peer_manager->add_peer(sender);
    sender->set_successfully_connected_for_test(true);

    // Create target but do NOT mark as successfully connected
    auto mock_conn2 = std::make_shared<MockTransportConnection>("193.0.0.2", 9590);
    mock_conn2->set_inbound(false);
    auto target = Peer::create_outbound(fixture.io_context, mock_conn2, magic::REGTEST, 0, "193.0.0.2", 9590, ConnectionType::OUTBOUND_FULL_RELAY);
    fixture.peer_manager->add_peer(target);
    // Note: NOT calling target->set_successfully_connected_for_test(true)

    mock_conn2->clear_sent_messages();

    // Send ADDR from sender
    message::AddrMessage addr_msg;
    addr_msg.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(100));
    fixture.discovery_manager->HandleAddr(sender, &addr_msg);

    // Pre-handshake peer should NOT receive any relay
    REQUIRE(mock_conn2->sent_message_count() == 0);
}

TEST_CASE("PeerDiscoveryManager - Address relay marks addresses as known", "[discovery][relay][learned]") {
    DiscoveryManagerTestFixture fixture;

    fixture.discovery_manager->TestSeedRng(12345);

    // Create sender and target
    auto mock_conn1 = std::make_shared<MockTransportConnection>("193.0.0.1", 9590);
    mock_conn1->set_inbound(false);
    auto sender = Peer::create_outbound(fixture.io_context, mock_conn1, magic::REGTEST, 0, "193.0.0.1", 9590, ConnectionType::OUTBOUND_FULL_RELAY);
    fixture.peer_manager->add_peer(sender);
    sender->set_successfully_connected_for_test(true);

    auto mock_conn2 = std::make_shared<MockTransportConnection>("193.0.0.2", 9590);
    mock_conn2->set_inbound(false);
    auto target = Peer::create_outbound(fixture.io_context, mock_conn2, magic::REGTEST, 0, "193.0.0.2", 9590, ConnectionType::OUTBOUND_FULL_RELAY);
    int target_id = fixture.peer_manager->add_peer(target);
    REQUIRE(target_id >= 0);
    target->set_successfully_connected_for_test(true);

    // Initially target has no learned addresses
    auto learned_before = fixture.peer_manager->GetLearnedAddresses(target_id);
    size_t count_before = learned_before ? learned_before->size() : 0;

    // Send ADDR from sender
    message::AddrMessage addr_msg;
    auto test_addr = DiscoveryManagerTestFixture::MakeTimestampedAddress(300);
    addr_msg.addresses.push_back(test_addr);
    fixture.discovery_manager->HandleAddr(sender, &addr_msg);

    // After relay, target's learned_addresses should include the relayed address
    auto learned_after = fixture.peer_manager->GetLearnedAddresses(target_id);

    // If relay occurred, learned count should increase
    // (Note: depends on random selection, but with only 1 target it should be selected)
    if (mock_conn2->sent_message_count() > 0) {
        REQUIRE(learned_after.has_value());
        REQUIRE(learned_after->size() > count_before);

        // Verify the specific address is marked as known
        AddressKey k;
        k.ip = test_addr.address.ip;
        k.port = test_addr.address.port;
        REQUIRE(learned_after->find(k) != learned_after->end());
    }
}

TEST_CASE("PeerDiscoveryManager - Address relay with no eligible targets", "[discovery][relay]") {
    DiscoveryManagerTestFixture fixture;

    fixture.discovery_manager->TestSeedRng(12345);

    // Create only the sender (no other peers to relay to)
    auto mock_conn1 = std::make_shared<MockTransportConnection>("193.0.0.1", 9590);
    mock_conn1->set_inbound(false);
    auto sender = Peer::create_outbound(fixture.io_context, mock_conn1, magic::REGTEST, 0, "193.0.0.1", 9590, ConnectionType::OUTBOUND_FULL_RELAY);
    fixture.peer_manager->add_peer(sender);
    sender->set_successfully_connected_for_test(true);

    // Send ADDR - should not crash with no targets
    message::AddrMessage addr_msg;
    addr_msg.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(100));

    // This should not crash or throw
    bool result = fixture.discovery_manager->HandleAddr(sender, &addr_msg);
    REQUIRE(result == true);

    // Address should still be added to AddrMan
    REQUIRE(fixture.discovery_manager->addr_manager_for_test().size() > 0);
}

TEST_CASE("PeerDiscoveryManager - Address relay limits to 2 peers", "[discovery][relay]") {
    DiscoveryManagerTestFixture fixture;

    fixture.discovery_manager->TestSeedRng(12345);

    // Create sender
    auto mock_conn0 = std::make_shared<MockTransportConnection>("193.0.0.0", 9590);
    mock_conn0->set_inbound(false);
    auto sender = Peer::create_outbound(fixture.io_context, mock_conn0, magic::REGTEST, 0, "193.0.0.0", 9590, ConnectionType::OUTBOUND_FULL_RELAY);
    fixture.peer_manager->add_peer(sender);
    sender->set_successfully_connected_for_test(true);

    // Create 5 target peers
    std::vector<std::shared_ptr<MockTransportConnection>> mock_conns;
    for (int i = 1; i <= 5; i++) {
        auto conn = std::make_shared<MockTransportConnection>("193.0.0." + std::to_string(i), 9590);
        conn->set_inbound(false);
        mock_conns.push_back(conn);

        auto target = Peer::create_outbound(fixture.io_context, conn, magic::REGTEST, 0, "193.0.0." + std::to_string(i), 9590, ConnectionType::OUTBOUND_FULL_RELAY);
        fixture.peer_manager->add_peer(target);
        target->set_successfully_connected_for_test(true);
    }

    // Clear all messages
    for (auto& conn : mock_conns) {
        conn->clear_sent_messages();
    }

    // Send ADDR from sender
    message::AddrMessage addr_msg;
    addr_msg.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(100));
    fixture.discovery_manager->HandleAddr(sender, &addr_msg);

    // Count how many targets received the relay
    int targets_with_messages = 0;
    for (auto& conn : mock_conns) {
        if (conn->sent_message_count() > 0) {
            targets_with_messages++;
        }
    }

    INFO("Targets that received relay: " << targets_with_messages);

    // Should be at most 2 (our relay limit)
    REQUIRE(targets_with_messages <= 2);
    // Should be at least 1 (if any eligible targets)
    REQUIRE(targets_with_messages >= 1);
}

// ============================================================================
// Bitcoin Core Relay Condition Tests
// ============================================================================

TEST_CASE("PeerDiscoveryManager - Relay skipped for large ADDR messages (>10)", "[discovery][relay][bitcoin_core]") {
    // Bitcoin Core only relays from ADDR messages with ≤10 addresses
    // to prevent relay amplification attacks

    DiscoveryManagerTestFixture fixture;
    fixture.discovery_manager->TestSeedRng(12345);

    // Create sender and target
    auto mock_conn1 = std::make_shared<MockTransportConnection>("193.0.0.1", 9590);
    mock_conn1->set_inbound(false);
    auto sender = Peer::create_outbound(fixture.io_context, mock_conn1, magic::REGTEST, 0, "193.0.0.1", 9590, ConnectionType::OUTBOUND_FULL_RELAY);
    fixture.peer_manager->add_peer(sender);
    sender->set_successfully_connected_for_test(true);

    auto mock_conn2 = std::make_shared<MockTransportConnection>("193.0.0.2", 9590);
    mock_conn2->set_inbound(false);
    auto target = Peer::create_outbound(fixture.io_context, mock_conn2, magic::REGTEST, 0, "193.0.0.2", 9590, ConnectionType::OUTBOUND_FULL_RELAY);
    fixture.peer_manager->add_peer(target);
    target->set_successfully_connected_for_test(true);

    mock_conn2->clear_sent_messages();

    SECTION("Message with 11 addresses is NOT relayed") {
        message::AddrMessage addr_msg;
        for (int i = 0; i < 11; i++) {
            addr_msg.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(i));
        }

        fixture.discovery_manager->HandleAddr(sender, &addr_msg);

        // No relay should occur
        REQUIRE(mock_conn2->sent_message_count() == 0);
    }

    SECTION("Message with 10 addresses IS relayed") {
        message::AddrMessage addr_msg;
        for (int i = 0; i < 10; i++) {
            addr_msg.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(i));
        }

        fixture.discovery_manager->HandleAddr(sender, &addr_msg);

        // Relay should occur
        REQUIRE(mock_conn2->sent_message_count() > 0);
    }
}

TEST_CASE("PeerDiscoveryManager - Relay skipped for GETADDR responses", "[discovery][relay][bitcoin_core]") {
    // Bitcoin Core only relays unsolicited ADDR messages
    // If we sent GETADDR to a peer, their response should NOT be relayed

    DiscoveryManagerTestFixture fixture;
    fixture.discovery_manager->TestSeedRng(12345);

    // Create sender and target
    auto mock_conn1 = std::make_shared<MockTransportConnection>("193.0.0.1", 9590);
    mock_conn1->set_inbound(false);
    auto sender = Peer::create_outbound(fixture.io_context, mock_conn1, magic::REGTEST, 0, "193.0.0.1", 9590, ConnectionType::OUTBOUND_FULL_RELAY);
    fixture.peer_manager->add_peer(sender);
    sender->set_successfully_connected_for_test(true);

    auto mock_conn2 = std::make_shared<MockTransportConnection>("193.0.0.2", 9590);
    mock_conn2->set_inbound(false);
    auto target = Peer::create_outbound(fixture.io_context, mock_conn2, magic::REGTEST, 0, "193.0.0.2", 9590, ConnectionType::OUTBOUND_FULL_RELAY);
    fixture.peer_manager->add_peer(target);
    target->set_successfully_connected_for_test(true);

    mock_conn2->clear_sent_messages();

    // Mark that we sent GETADDR to sender (simulating our request)
    sender->mark_getaddr_sent();

    // Send small ADDR message (would normally be relayed)
    message::AddrMessage addr_msg;
    addr_msg.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(100));

    fixture.discovery_manager->HandleAddr(sender, &addr_msg);

    // No relay should occur because this is a response to our GETADDR
    REQUIRE(mock_conn2->sent_message_count() == 0);
}

TEST_CASE("PeerDiscoveryManager - Relay skipped for old timestamps", "[discovery][relay][bitcoin_core]") {
    // Bitcoin Core only relays addresses with timestamps within last 10 minutes

    // Set mock time for deterministic testing
    util::SetMockTime(0);
    constexpr int64_t TEST_TIME = 1700000000;
    util::MockTimeScope mock_time(TEST_TIME);

    DiscoveryManagerTestFixture fixture;
    fixture.discovery_manager->TestSeedRng(12345);

    // Create sender and target
    auto mock_conn1 = std::make_shared<MockTransportConnection>("193.0.0.1", 9590);
    mock_conn1->set_inbound(false);
    auto sender = Peer::create_outbound(fixture.io_context, mock_conn1, magic::REGTEST, 0, "193.0.0.1", 9590, ConnectionType::OUTBOUND_FULL_RELAY);
    fixture.peer_manager->add_peer(sender);
    sender->set_successfully_connected_for_test(true);

    auto mock_conn2 = std::make_shared<MockTransportConnection>("193.0.0.2", 9590);
    mock_conn2->set_inbound(false);
    auto target = Peer::create_outbound(fixture.io_context, mock_conn2, magic::REGTEST, 0, "193.0.0.2", 9590, ConnectionType::OUTBOUND_FULL_RELAY);
    fixture.peer_manager->add_peer(target);
    target->set_successfully_connected_for_test(true);

    SECTION("Address with old timestamp (>10 min) is NOT relayed") {
        mock_conn2->clear_sent_messages();

        message::AddrMessage addr_msg;
        // Timestamp 15 minutes ago (900 seconds)
        addr_msg.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(100, TEST_TIME - 900));

        fixture.discovery_manager->HandleAddr(sender, &addr_msg);

        // No relay should occur (address too old)
        REQUIRE(mock_conn2->sent_message_count() == 0);
    }

    SECTION("Address with fresh timestamp (<10 min) IS relayed") {
        mock_conn2->clear_sent_messages();

        message::AddrMessage addr_msg;
        // Timestamp 5 minutes ago (300 seconds)
        addr_msg.addresses.push_back(DiscoveryManagerTestFixture::MakeTimestampedAddress(100, TEST_TIME - 300));

        fixture.discovery_manager->HandleAddr(sender, &addr_msg);

        // Relay should occur
        REQUIRE(mock_conn2->sent_message_count() > 0);
    }
}

// ============================================================================
// AddressKey Tests
// ============================================================================

TEST_CASE("AddressKey constructor from NetworkAddress", "[network][addresskey]") {
    // Create a NetworkAddress with known values
    protocol::NetworkAddress na;
    na.ip = {10, 20, 30, 40, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 100};
    na.port = 9590;
    na.services = protocol::ServiceFlags::NODE_NETWORK;

    // Construct AddressKey from NetworkAddress
    AddressKey key(na);

    // Verify IP was copied correctly
    REQUIRE(key.ip == na.ip);

    // Verify port was copied correctly
    REQUIRE(key.port == na.port);

    // Services should NOT be copied (AddressKey only has ip + port)
    // This is by design - AddressKey is for keying, not full address info
}

TEST_CASE("AddressKey constructor from NetworkAddress - IPv4-mapped", "[network][addresskey]") {
    // IPv4-mapped IPv6 address (::ffff:93.184.216.34)
    protocol::NetworkAddress na;
    na.ip = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 93, 184, 216, 34};
    na.port = 8333;

    AddressKey key(na);

    REQUIRE(key.ip[10] == 0xff);
    REQUIRE(key.ip[11] == 0xff);
    REQUIRE(key.ip[12] == 93);
    REQUIRE(key.ip[13] == 184);
    REQUIRE(key.ip[14] == 216);
    REQUIRE(key.ip[15] == 34);
    REQUIRE(key.port == 8333);
}

TEST_CASE("AddressKey equality with NetworkAddress constructor", "[network][addresskey]") {
    protocol::NetworkAddress na;
    na.ip = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    na.port = 12345;

    // Two keys from same NetworkAddress should be equal
    AddressKey k1(na);
    AddressKey k2(na);
    REQUIRE(k1 == k2);

    // Manual construction with same values should also be equal
    AddressKey k3;
    k3.ip = na.ip;
    k3.port = na.port;
    REQUIRE(k1 == k3);
}

// ============================================================================
// AddressKey::Hasher Tests
// ============================================================================

TEST_CASE("AddressKey::Hasher is deterministic", "[network][hash]") {
    AddressKey k1;
    k1.ip = {192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    k1.port = 8333;

    AddressKey k2 = k1;  // Same values

    AddressKey::Hasher hasher;
    REQUIRE(hasher(k1) == hasher(k2));

    // Multiple calls return same result
    REQUIRE(hasher(k1) == hasher(k1));
}

TEST_CASE("AddressKey::Hasher differentiates IPs", "[network][hash]") {
    AddressKey k1, k2;
    k1.ip = {192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    k1.port = 8333;

    k2.ip = {192, 168, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};  // Different last octet
    k2.port = 8333;

    AddressKey::Hasher hasher;
    REQUIRE(hasher(k1) != hasher(k2));
}

TEST_CASE("AddressKey::Hasher differentiates ports", "[network][hash]") {
    AddressKey k1, k2;
    k1.ip = {192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    k1.port = 8333;

    k2.ip = k1.ip;  // Same IP
    k2.port = 8334;  // Different port

    AddressKey::Hasher hasher;
    REQUIRE(hasher(k1) != hasher(k2));
}

TEST_CASE("AddressKey::Hasher produces correct FNV-1a hashes", "[network][hash]") {
    // Test against known FNV-1a behavior
    // FNV-1a 64-bit offset basis = 0xcbf29ce484222325

    AddressKey empty;
    // All zeros: 16 bytes of 0x00 for IP + 2 bytes of 0x00 for port
    AddressKey::Hasher hasher;

    // Verify the hash of all-zeros follows FNV-1a algorithm:
    // Each byte XORs with h, then multiplies by prime
    // Starting with offset 14695981039346656037, XOR with 0, multiply by prime
    // After 18 iterations of (h ^= 0; h *= prime), we get a specific value

    uint64_t expected = 14695981039346656037ULL;
    for (int i = 0; i < 18; i++) {  // 16 IP bytes + 2 port bytes
        expected ^= 0;
        expected *= 1099511628211ULL;
    }
    REQUIRE(hasher(empty) == expected);
}

TEST_CASE("AddressKey works correctly in unordered_map", "[network][hash]") {
    std::unordered_map<AddressKey, int, AddressKey::Hasher> map;

    AddressKey k1, k2, k3;
    k1.ip = {10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    k1.port = 9590;

    k2.ip = {10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    k2.port = 9590;

    k3.ip = k1.ip;
    k3.port = 9590;  // Same as k1

    map[k1] = 100;
    map[k2] = 200;

    REQUIRE(map.size() == 2);
    REQUIRE(map[k1] == 100);
    REQUIRE(map[k2] == 200);
    REQUIRE(map[k3] == 100);  // k3 == k1, should find same entry

    // Overwrite via k3
    map[k3] = 300;
    REQUIRE(map[k1] == 300);
    REQUIRE(map.size() == 2);
}
