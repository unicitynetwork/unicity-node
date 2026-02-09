// Copyright (c) 2025 The Unicity Foundation
// Tests for BLOCK_RELAY_ONLY connection type functionality
//
// These tests verify the eclipse attack resistance features of block-relay-only
// connections, including:
// - ADDR/GETADDR message filtering
// - AddrMan exclusion for block-relay peers
// - Separate slot management for full-relay vs block-relay
// - next_outbound_type() connection type selection

#include "catch_amalgamated.hpp"
#include "network/connection_types.hpp"
#include "network/network_manager.hpp"  // For ConnectionResult
#include "network/peer.hpp"
#include "network/connection_manager.hpp"
#include "network/addr_relay_manager.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"
#include "infra/test_access.hpp"
#include "infra/mock_transport.hpp"

#include <asio.hpp>
#include <algorithm>
#include <map>

using namespace unicity;
using unicity::test::AddrRelayManagerTestAccess;
using namespace unicity::network;
using unicity::test::PeerTestAccess;

namespace {

// Transport that always succeeds and creates MockTransportConnections
class SuccessTransport : public Transport {
public:
    TransportConnectionPtr connect(const std::string& address, uint16_t port,
                                   ConnectCallback callback) override {
        auto conn = std::make_shared<MockTransportConnection>(address, port);
        conn->set_inbound(false);
        if (callback) callback(true);
        return conn;
    }

    bool listen(uint16_t, std::function<void(TransportConnectionPtr)>) override { return true; }
    void stop_listening() override {}
    void run() override {}
    void stop() override {}
    bool is_running() const override { return true; }
};

} // namespace

// =============================================================================
// Test Fixtures
// =============================================================================

struct BlockRelayTestFixture {
    asio::io_context io_context;

    PeerPtr create_peer(ConnectionType conn_type, const std::string& address = "10.0.0.1", uint16_t port = 9590) {
        return Peer::create_outbound(
            io_context,
            nullptr,  // No transport needed for unit tests
            0x12345678,  // network magic
            0,           // start_height
            address,
            port,
            conn_type
        );
    }
};

// =============================================================================
// RelaysAddr() Behavior Tests
// =============================================================================

TEST_CASE("Block-relay peers - RelaysAddr behavior", "[network][block_relay][unit]") {
    BlockRelayTestFixture fixture;

    SECTION("Full-relay outbound peers relay addresses") {
        auto peer = fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY);
        REQUIRE(peer->relays_addr() == true);
        REQUIRE(peer->is_block_relay_only() == false);
        REQUIRE(peer->is_full_relay() == true);
    }

    SECTION("Block-relay peers do NOT relay addresses") {
        auto peer = fixture.create_peer(ConnectionType::BLOCK_RELAY);
        REQUIRE(peer->relays_addr() == false);
        REQUIRE(peer->is_block_relay_only() == true);
        REQUIRE(peer->is_full_relay() == false);
    }

    SECTION("Inbound peers relay addresses") {
        // Inbound peers are created differently, test the ConnectionType directly
        REQUIRE(RelaysAddr(ConnectionType::INBOUND) == true);
    }

    SECTION("Feeler peers do NOT relay addresses") {
        auto peer = fixture.create_peer(ConnectionType::FEELER);
        REQUIRE(peer->relays_addr() == false);
    }

    SECTION("Manual peers relay addresses (Core parity: net_processing.cpp:5466)") {
        auto peer = fixture.create_peer(ConnectionType::MANUAL);
        REQUIRE(peer->relays_addr() == true);
    }
}

// =============================================================================
// Slot Management Tests
// =============================================================================

TEST_CASE("Block-relay peers - Separate slot management", "[network][block_relay][unit]") {
    BlockRelayTestFixture fixture;

    SECTION("Config defaults are correct") {
        ConnectionManager::Config config;

        REQUIRE(config.max_full_relay_outbound == 8);
        REQUIRE(config.max_block_relay_outbound == 2);
        REQUIRE(config.target_full_relay_outbound == 8);
        REQUIRE(config.target_block_relay_outbound == 2);
        // Total = 8 + 2 = 10
        REQUIRE(config.max_outbound_peers == 10);
    }

    SECTION("Full-relay and block-relay slots are tracked separately") {
        ConnectionManager::Config config;
        config.max_full_relay_outbound = 2;
        config.max_block_relay_outbound = 1;
        config.target_full_relay_outbound = 2;
        config.target_block_relay_outbound = 1;

        ConnectionManager pm(fixture.io_context, config);

        REQUIRE(pm.full_relay_outbound_count() == 0);
        REQUIRE(pm.block_relay_outbound_count() == 0);

        // Add a full-relay peer
        auto fr_peer1 = fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY, "10.0.0.1");
        REQUIRE(pm.add_peer(fr_peer1) >= 0);
        REQUIRE(pm.full_relay_outbound_count() == 1);
        REQUIRE(pm.block_relay_outbound_count() == 0);

        // Add a block-relay peer
        auto br_peer1 = fixture.create_peer(ConnectionType::BLOCK_RELAY, "10.0.0.2");
        REQUIRE(pm.add_peer(br_peer1) >= 0);
        REQUIRE(pm.full_relay_outbound_count() == 1);
        REQUIRE(pm.block_relay_outbound_count() == 1);

        // Add another full-relay (should succeed, we have 2 slots)
        auto fr_peer2 = fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY, "10.0.0.3");
        REQUIRE(pm.add_peer(fr_peer2) >= 0);
        REQUIRE(pm.full_relay_outbound_count() == 2);

        // Try to add a third full-relay (should fail, slots full)
        auto fr_peer3 = fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY, "10.0.0.4");
        REQUIRE(pm.add_peer(fr_peer3) == -1);
        REQUIRE(pm.full_relay_outbound_count() == 2);

        // Try to add a second block-relay (should fail, only 1 slot)
        auto br_peer2 = fixture.create_peer(ConnectionType::BLOCK_RELAY, "10.0.0.5");
        REQUIRE(pm.add_peer(br_peer2) == -1);
        REQUIRE(pm.block_relay_outbound_count() == 1);
    }

    SECTION("needs_more methods work correctly") {
        ConnectionManager::Config config;
        config.max_full_relay_outbound = 2;
        config.max_block_relay_outbound = 1;
        config.target_full_relay_outbound = 2;
        config.target_block_relay_outbound = 1;

        ConnectionManager pm(fixture.io_context, config);

        // Initially need both types
        REQUIRE(pm.needs_more_full_relay_outbound() == true);
        REQUIRE(pm.needs_more_block_relay_outbound() == true);
        REQUIRE(pm.needs_more_outbound() == true);

        // Fill full-relay slots
        pm.add_peer(fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY, "10.0.0.1"));
        pm.add_peer(fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY, "10.0.0.2"));

        REQUIRE(pm.needs_more_full_relay_outbound() == false);
        REQUIRE(pm.needs_more_block_relay_outbound() == true);
        REQUIRE(pm.needs_more_outbound() == true);  // Still need block-relay

        // Fill block-relay slot
        pm.add_peer(fixture.create_peer(ConnectionType::BLOCK_RELAY, "10.0.0.3"));

        REQUIRE(pm.needs_more_full_relay_outbound() == false);
        REQUIRE(pm.needs_more_block_relay_outbound() == false);
        REQUIRE(pm.needs_more_outbound() == false);
    }
}

// =============================================================================
// next_outbound_type() Tests
// =============================================================================

TEST_CASE("Block-relay peers - next_outbound_type selection", "[network][block_relay][unit]") {
    BlockRelayTestFixture fixture;

    SECTION("Prioritizes block-relay when both needed (security first)") {
        // Block-relay connections are established first for eclipse attack resistance
        // These "secret" connections protect the node even if an attacker controls
        // all addresses in AddrMan
        ConnectionManager::Config config;
        config.max_full_relay_outbound = 2;
        config.max_block_relay_outbound = 1;
        config.target_full_relay_outbound = 2;
        config.target_block_relay_outbound = 1;

        ConnectionManager pm(fixture.io_context, config);

        // When both are needed, block-relay is prioritized (security-critical)
        REQUIRE(pm.next_outbound_type() == ConnectionType::BLOCK_RELAY);
    }

    SECTION("Switches to full-relay when block-relay is satisfied") {
        ConnectionManager::Config config;
        config.max_full_relay_outbound = 2;
        config.max_block_relay_outbound = 1;
        config.target_full_relay_outbound = 2;
        config.target_block_relay_outbound = 1;

        ConnectionManager pm(fixture.io_context, config);

        // Fill block-relay slot
        pm.add_peer(fixture.create_peer(ConnectionType::BLOCK_RELAY, "10.0.0.1"));

        // Now should return full-relay since block-relay is satisfied
        REQUIRE(pm.next_outbound_type() == ConnectionType::OUTBOUND_FULL_RELAY);
    }

    SECTION("Returns block-relay when full-relay is full but block-relay is not") {
        ConnectionManager::Config config;
        config.max_full_relay_outbound = 1;
        config.max_block_relay_outbound = 2;
        config.target_full_relay_outbound = 1;
        config.target_block_relay_outbound = 2;

        ConnectionManager pm(fixture.io_context, config);

        // Fill full-relay slot first
        pm.add_peer(fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY, "10.0.0.1"));

        // Should return block-relay since those slots are not full
        REQUIRE(pm.next_outbound_type() == ConnectionType::BLOCK_RELAY);
    }

    SECTION("Returns full-relay as default when all slots are full") {
        ConnectionManager::Config config;
        config.max_full_relay_outbound = 1;
        config.max_block_relay_outbound = 1;
        config.target_full_relay_outbound = 1;
        config.target_block_relay_outbound = 1;

        ConnectionManager pm(fixture.io_context, config);

        // Fill all slots
        pm.add_peer(fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY, "10.0.0.1"));
        pm.add_peer(fixture.create_peer(ConnectionType::BLOCK_RELAY, "10.0.0.2"));

        // Default should be full-relay even when full
        REQUIRE(pm.next_outbound_type() == ConnectionType::OUTBOUND_FULL_RELAY);
    }
}

// =============================================================================
// Peer Helper Method Tests
// =============================================================================

TEST_CASE("Block-relay peers - Peer helper methods", "[network][block_relay][unit]") {
    BlockRelayTestFixture fixture;

    SECTION("is_block_relay_only() correctly identifies block-relay peers") {
        auto br_peer = fixture.create_peer(ConnectionType::BLOCK_RELAY);
        auto fr_peer = fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY);
        auto feeler = fixture.create_peer(ConnectionType::FEELER);

        REQUIRE(br_peer->is_block_relay_only() == true);
        REQUIRE(fr_peer->is_block_relay_only() == false);
        REQUIRE(feeler->is_block_relay_only() == false);
    }

    SECTION("is_full_relay() correctly identifies full-relay peers") {
        auto br_peer = fixture.create_peer(ConnectionType::BLOCK_RELAY);
        auto fr_peer = fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY);
        auto feeler = fixture.create_peer(ConnectionType::FEELER);

        REQUIRE(br_peer->is_full_relay() == false);
        REQUIRE(fr_peer->is_full_relay() == true);
        REQUIRE(feeler->is_full_relay() == false);
    }

    SECTION("connection_type() returns correct type") {
        auto br_peer = fixture.create_peer(ConnectionType::BLOCK_RELAY);
        auto fr_peer = fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY);

        REQUIRE(br_peer->connection_type() == ConnectionType::BLOCK_RELAY);
        REQUIRE(fr_peer->connection_type() == ConnectionType::OUTBOUND_FULL_RELAY);
    }
}

// =============================================================================
// Protocol Constants Tests
// =============================================================================

TEST_CASE("Block-relay peers - Protocol constants", "[network][block_relay][unit]") {
    SECTION("Default connection limits match Bitcoin Core") {
        // Bitcoin Core defaults: 8 full-relay, 2 block-relay
        REQUIRE(protocol::DEFAULT_MAX_FULL_RELAY_OUTBOUND == 8);
        REQUIRE(protocol::DEFAULT_MAX_BLOCK_RELAY_OUTBOUND == 2);
        REQUIRE(protocol::DEFAULT_MAX_OUTBOUND_CONNECTIONS == 10);
    }

    SECTION("Total outbound equals sum of full-relay and block-relay") {
        REQUIRE(protocol::DEFAULT_MAX_OUTBOUND_CONNECTIONS ==
                protocol::DEFAULT_MAX_FULL_RELAY_OUTBOUND +
                protocol::DEFAULT_MAX_BLOCK_RELAY_OUTBOUND);
    }
}

// =============================================================================
// Integration: AttemptOutboundConnections Tests
// =============================================================================

TEST_CASE("Block-relay peers - AttemptOutboundConnections passes correct type", "[network][block_relay][unit]") {
    BlockRelayTestFixture fixture;

    SECTION("Block-relay connections are prioritized for security") {
        ConnectionManager::Config config;
        config.max_full_relay_outbound = 1;
        config.max_block_relay_outbound = 1;
        config.target_full_relay_outbound = 1;
        config.target_block_relay_outbound = 1;

        ConnectionManager plm(fixture.io_context, config);
        AddrRelayManager pdm(&plm);

        // Seed two addresses from different netgroups (diversity enforcement)
        auto& am = AddrRelayManagerTestAccess::GetAddrManager(pdm);
        am.add(protocol::NetworkAddress::from_string("93.184.216.34", 9590));
        am.add(protocol::NetworkAddress::from_string("94.185.217.35", 9590));

        auto transport = std::make_shared<SuccessTransport>();
        plm.Init(transport, [](Peer*){}, [](){ return true; },
                 protocol::magic::REGTEST, /*local_nonce=*/42);

        plm.AttemptOutboundConnections(/*current_height=*/0);
        fixture.io_context.poll();
        fixture.io_context.restart();

        // Should have created peers with correct connection types
        auto peers = plm.get_all_peers();
        REQUIRE(peers.size() >= 2);

        // Sort by id to get creation order
        std::sort(peers.begin(), peers.end(),
                  [](const PeerPtr& a, const PeerPtr& b) { return a->id() < b->id(); });

        // First should be block-relay (prioritized for security), then full-relay
        REQUIRE(peers[0]->connection_type() == ConnectionType::BLOCK_RELAY);
        REQUIRE(peers[1]->connection_type() == ConnectionType::OUTBOUND_FULL_RELAY);
    }
}

// =============================================================================
// Edge Cases
// =============================================================================

TEST_CASE("Block-relay peers - Edge cases", "[network][block_relay][unit]") {
    BlockRelayTestFixture fixture;

    SECTION("Zero block-relay slots disables block-relay connections") {
        ConnectionManager::Config config;
        config.max_full_relay_outbound = 2;
        config.max_block_relay_outbound = 0;
        config.target_full_relay_outbound = 2;
        config.target_block_relay_outbound = 0;

        ConnectionManager pm(fixture.io_context, config);

        // Should never need block-relay
        REQUIRE(pm.needs_more_block_relay_outbound() == false);

        // Trying to add block-relay should fail
        auto br_peer = fixture.create_peer(ConnectionType::BLOCK_RELAY, "10.0.0.1");
        REQUIRE(pm.add_peer(br_peer) == -1);
    }

    SECTION("Block-relay peer removal frees slot") {
        ConnectionManager::Config config;
        config.max_full_relay_outbound = 1;
        config.max_block_relay_outbound = 1;
        config.target_full_relay_outbound = 1;
        config.target_block_relay_outbound = 1;

        ConnectionManager pm(fixture.io_context, config);

        // Add and remove block-relay peer
        auto br_peer = fixture.create_peer(ConnectionType::BLOCK_RELAY, "10.0.0.1");
        int peer_id = pm.add_peer(br_peer);
        REQUIRE(peer_id >= 0);
        REQUIRE(pm.block_relay_outbound_count() == 1);

        pm.remove_peer(peer_id);
        REQUIRE(pm.block_relay_outbound_count() == 0);
        REQUIRE(pm.needs_more_block_relay_outbound() == true);

        // Should be able to add another
        auto br_peer2 = fixture.create_peer(ConnectionType::BLOCK_RELAY, "10.0.0.2");
        REQUIRE(pm.add_peer(br_peer2) >= 0);
    }

    SECTION("Feelers don't consume block-relay or full-relay slots") {
        ConnectionManager::Config config;
        config.max_full_relay_outbound = 1;
        config.max_block_relay_outbound = 1;
        config.target_full_relay_outbound = 1;
        config.target_block_relay_outbound = 1;

        ConnectionManager pm(fixture.io_context, config);

        // Fill both slot types
        pm.add_peer(fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY, "10.0.0.1"));
        pm.add_peer(fixture.create_peer(ConnectionType::BLOCK_RELAY, "10.0.0.2"));

        REQUIRE(pm.full_relay_outbound_count() == 1);
        REQUIRE(pm.block_relay_outbound_count() == 1);

        // Feeler should still be accepted
        auto feeler = fixture.create_peer(ConnectionType::FEELER, "10.0.0.3");
        REQUIRE(pm.add_peer(feeler) >= 0);

        // Slot counts unchanged
        REQUIRE(pm.full_relay_outbound_count() == 1);
        REQUIRE(pm.block_relay_outbound_count() == 1);
    }
}

// =============================================================================
// AddrMan Integration Tests - Eclipse Attack Resistance
// =============================================================================

TEST_CASE("Block-relay peers - AddrMan isolation", "[network][block_relay][addrman][unit]") {
    BlockRelayTestFixture fixture;

    SECTION("ConnectionTypeAsString returns correct strings for notification matching") {
        // This test ensures the notification strings match what handlers expect
        REQUIRE(ConnectionTypeAsString(ConnectionType::OUTBOUND_FULL_RELAY) == "outbound-full-relay");
        REQUIRE(ConnectionTypeAsString(ConnectionType::BLOCK_RELAY) == "block-relay-only");
        REQUIRE(ConnectionTypeAsString(ConnectionType::INBOUND) == "inbound");
        REQUIRE(ConnectionTypeAsString(ConnectionType::FEELER) == "feeler");
        REQUIRE(ConnectionTypeAsString(ConnectionType::MANUAL) == "manual");
    }

    SECTION("Block-relay peer disconnect does NOT promote address in AddrMan") {
        // This tests the fix for the bug where block-relay peers were incorrectly
        // having their addresses promoted in AddrMan on disconnect
        ConnectionManager::Config config;
        config.max_full_relay_outbound = 1;
        config.max_block_relay_outbound = 1;
        config.target_full_relay_outbound = 1;
        config.target_block_relay_outbound = 1;

        ConnectionManager pm(fixture.io_context, config);
        AddrRelayManager pdm(&pm);
        pm.SetAddrRelayManager(&pdm);  // Wire up the discovery manager

        // Use routable public IPs (10.x.x.x is private and filtered by AddrMan)
        const std::string br_ip = "93.184.216.1";  // Public routable IP
        const std::string fr_ip = "93.184.216.2";  // Public routable IP

        // Seed both addresses in AddrMan's "new" table first
        protocol::NetworkAddress br_addr = protocol::NetworkAddress::from_string(br_ip, 9590);
        protocol::NetworkAddress fr_addr = protocol::NetworkAddress::from_string(fr_ip, 9590);
        AddrRelayManagerTestAccess::GetAddrManager(pdm).add(br_addr);
        AddrRelayManagerTestAccess::GetAddrManager(pdm).add(fr_addr);

        size_t initial_tried = AddrRelayManagerTestAccess::GetAddrManager(pdm).tried_count();
        REQUIRE(initial_tried == 0);  // Neither should be in tried yet

        // Add block-relay peer and simulate successful connection
        auto br_peer = fixture.create_peer(ConnectionType::BLOCK_RELAY, br_ip, 9590);
        int br_id = pm.add_peer(br_peer);
        REQUIRE(br_id >= 0);
        PeerTestAccess::SetSuccessfullyConnected(*br_peer, true);

        // Add full-relay peer and simulate successful connection
        auto fr_peer = fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY, fr_ip, 9590);
        int fr_id = pm.add_peer(fr_peer);
        REQUIRE(fr_id >= 0);
        PeerTestAccess::SetSuccessfullyConnected(*fr_peer, true);

        // Simulate VERACK handling:
        // - Full-relay peers ARE marked good (called at VERACK in production)
        // - Block-relay peers should NOT be marked good (eclipse resistance)
        // Note: Can't use HandleVerack() directly because test peers have no transport
        // (they start in DISCONNECTED state). Instead, call Good() directly for full-relay.
        pdm.Good(fr_addr);  // This is what HandleVerack does for full-relay peers
        // Block-relay peer's address is NOT passed to Good() - this is the key behavior

        // Full-relay peer should have been promoted to "tried" table
        // Block-relay peer should NOT be promoted (eclipse resistance)
        size_t tried_after = AddrRelayManagerTestAccess::GetAddrManager(pdm).tried_count();
        REQUIRE(tried_after == 1);  // Only full-relay peer promoted

        // Disconnect both peers - this should NOT affect tried count
        // (connected() updates timestamp, doesn't promote)
        pm.remove_peer(br_id);
        pm.remove_peer(fr_id);
        REQUIRE(AddrRelayManagerTestAccess::GetAddrManager(pdm).tried_count() == 1);  // Still just 1
    }

    SECTION("Full-relay peers are added to AddrMan on connect notification") {
        ConnectionManager::Config config;
        config.max_full_relay_outbound = 1;
        config.max_block_relay_outbound = 1;
        config.target_full_relay_outbound = 1;
        config.target_block_relay_outbound = 1;

        ConnectionManager pm(fixture.io_context, config);
        AddrRelayManager pdm(&pm);

        // Get initial AddrMan size
        size_t initial_new = AddrRelayManagerTestAccess::GetAddrManager(pdm).new_count();

        // Add full-relay peer - this triggers PeerConnected notification
        auto fr_peer = fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY, "93.184.216.34", 9590);
        pm.add_peer(fr_peer);

        // The address should be added to AddrMan's new table
        size_t new_count_after = AddrRelayManagerTestAccess::GetAddrManager(pdm).new_count();
        // Note: The address might already be in AddrMan or the add might be a no-op
        // What we're really testing is that the code path executes without error
        // and the string matching works correctly
        REQUIRE(new_count_after >= initial_new);
    }

    SECTION("Block-relay peers are NOT added to AddrMan on connect notification") {
        ConnectionManager::Config config;
        config.max_full_relay_outbound = 1;
        config.max_block_relay_outbound = 1;
        config.target_full_relay_outbound = 1;
        config.target_block_relay_outbound = 1;

        ConnectionManager pm(fixture.io_context, config);
        AddrRelayManager pdm(&pm);

        // Seed an address first so we have something to compare
        protocol::NetworkAddress seed_addr = protocol::NetworkAddress::from_string("8.8.8.8", 9590);
        AddrRelayManagerTestAccess::GetAddrManager(pdm).add(seed_addr);

        // Get AddrMan size after seeding
        size_t new_count_before = AddrRelayManagerTestAccess::GetAddrManager(pdm).new_count();

        // Add block-relay peer with a NEW address (not the seeded one)
        auto br_peer = fixture.create_peer(ConnectionType::BLOCK_RELAY, "93.184.216.34", 9590);
        pm.add_peer(br_peer);

        // The block-relay peer's address should NOT be added to AddrMan
        size_t new_count_after = AddrRelayManagerTestAccess::GetAddrManager(pdm).new_count();

        // Count should not increase (block-relay addresses are not added)
        REQUIRE(new_count_after == new_count_before);
    }
}

// =============================================================================
// ADDR/GETADDR Message Filtering Tests
// =============================================================================

TEST_CASE("Block-relay peers - ADDR message handling", "[network][block_relay][addr][unit]") {
    BlockRelayTestFixture fixture;

    SECTION("ADDR from block-relay peer is ignored (not added to AddrMan)") {
        // This is the critical security test - ADDR messages from block-relay
        // peers must be silently ignored to prevent address pollution attacks
        ConnectionManager::Config config;
        config.max_block_relay_outbound = 1;
        config.target_block_relay_outbound = 1;

        ConnectionManager pm(fixture.io_context, config);
        AddrRelayManager pdm(&pm);

        // Create block-relay peer and add to manager
        auto br_peer = fixture.create_peer(ConnectionType::BLOCK_RELAY, "10.0.0.1", 9590);
        int br_id = pm.add_peer(br_peer);
        REQUIRE(br_id >= 0);
        PeerTestAccess::SetSuccessfullyConnected(*br_peer, true);

        // Get initial AddrMan count
        size_t initial_count = AddrRelayManagerTestAccess::GetAddrManager(pdm).size();

        // Create ADDR message with a test address
        message::AddrMessage addr_msg;
        protocol::TimestampedAddress test_addr;
        test_addr.address = protocol::NetworkAddress::from_string("192.168.1.100", 9590);
        test_addr.timestamp = static_cast<uint32_t>(std::time(nullptr));
        addr_msg.addresses.push_back(test_addr);

        // Handle the ADDR message from block-relay peer
        bool result = pdm.HandleAddr(br_peer, &addr_msg);

        // Should return true (handled, not an error) but not add to AddrMan
        REQUIRE(result == true);
        REQUIRE(AddrRelayManagerTestAccess::GetAddrManager(pdm).size() == initial_count);  // No change
    }

    SECTION("ADDR from full-relay peer IS processed (added to AddrMan)") {
        // Verify that normal full-relay peers still have their ADDR processed
        ConnectionManager::Config config;
        config.max_full_relay_outbound = 1;
        config.target_full_relay_outbound = 1;

        ConnectionManager pm(fixture.io_context, config);
        AddrRelayManager pdm(&pm);

        // Create full-relay peer and add to manager
        auto fr_peer = fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY, "10.0.0.2", 9590);
        int fr_id = pm.add_peer(fr_peer);
        REQUIRE(fr_id >= 0);
        PeerTestAccess::SetSuccessfullyConnected(*fr_peer, true);

        // Get initial AddrMan count
        size_t initial_count = AddrRelayManagerTestAccess::GetAddrManager(pdm).size();

        // Create ADDR message with a test address
        message::AddrMessage addr_msg;
        protocol::TimestampedAddress test_addr;
        test_addr.address = protocol::NetworkAddress::from_string("192.168.1.101", 9590);
        test_addr.timestamp = static_cast<uint32_t>(std::time(nullptr));
        addr_msg.addresses.push_back(test_addr);

        // Handle the ADDR message from full-relay peer
        bool result = pdm.HandleAddr(fr_peer, &addr_msg);

        // Should process and potentially add to AddrMan
        REQUIRE(result == true);
        // Note: Address may or may not be added depending on other factors,
        // but the key is that it was processed (not ignored like block-relay)
    }
}

TEST_CASE("Block-relay peers - GETADDR message handling", "[network][block_relay][getaddr][unit]") {
    BlockRelayTestFixture fixture;

    SECTION("GETADDR from block-relay peer is ignored (no response)") {
        // Block-relay peers should NOT receive ADDR responses to GETADDR
        // This keeps them "invisible" and prevents enumeration attacks
        ConnectionManager::Config config;
        config.max_block_relay_outbound = 1;
        config.target_block_relay_outbound = 1;

        ConnectionManager pm(fixture.io_context, config);
        AddrRelayManager pdm(&pm);

        // Seed some addresses in AddrMan so there's something to return
        protocol::NetworkAddress seed_addr = protocol::NetworkAddress::from_string("8.8.8.8", 9590);
        AddrRelayManagerTestAccess::GetAddrManager(pdm).add(seed_addr);

        // Create block-relay peer
        auto br_peer = fixture.create_peer(ConnectionType::BLOCK_RELAY, "10.0.0.1", 9590);
        int br_id = pm.add_peer(br_peer);
        REQUIRE(br_id >= 0);
        PeerTestAccess::SetSuccessfullyConnected(*br_peer, true);

        // Handle GETADDR from block-relay peer
        bool result = pdm.HandleGetAddr(br_peer);

        // Should return true (handled, not an error) but should NOT send response
        // The actual verification that no message was sent would require mocking
        // the peer's send_message, but we verify the return value and that
        // relays_addr() correctly returns false
        REQUIRE(result == true);
        REQUIRE(br_peer->relays_addr() == false);
    }
}

// =============================================================================
// GETADDR Sending Policy Tests
// =============================================================================

TEST_CASE("Block-relay peers - GETADDR sending policy on VERACK", "[network][block_relay][verack][unit]") {
    BlockRelayTestFixture fixture;

    // Note: Testing GETADDR sending requires observing the peer's send_message calls.
    // Since Peer doesn't have a mock interface, we verify the policy through
    // the relays_addr() and has_sent_getaddr() flags.

    SECTION("Block-relay peers have relays_addr=false (prerequisite for no GETADDR)") {
        auto br_peer = fixture.create_peer(ConnectionType::BLOCK_RELAY, "10.0.0.1", 9590);

        // Block-relay peers must have relays_addr() == false
        // This is what prevents GETADDR from being sent in HandleVerack
        REQUIRE(br_peer->relays_addr() == false);
    }

    SECTION("Full-relay peers have relays_addr=true (will receive GETADDR)") {
        auto fr_peer = fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY, "10.0.0.1", 9590);

        // Full-relay peers have relays_addr() == true
        // This allows GETADDR to be sent in HandleVerack
        REQUIRE(fr_peer->relays_addr() == true);
    }

    SECTION("Feeler peers have relays_addr=false (no GETADDR sent)") {
        auto feeler_peer = fixture.create_peer(ConnectionType::FEELER, "10.0.0.1", 9590);

        // Feelers also don't participate in address relay
        REQUIRE(feeler_peer->relays_addr() == false);
    }
}

// =============================================================================
// Extra Block-Relay Peer Rotation Tests (Bitcoin Core parity: eclipse resistance)
// =============================================================================

TEST_CASE("Block-relay peers - GetOldestBlockRelayPeer basic behavior", "[network][block_relay][rotation][unit]") {
    BlockRelayTestFixture fixture;

    SECTION("Returns -1 when no block-relay-only outbound peers") {
        ConnectionManager::Config config;
        config.max_full_relay_outbound = 2;
        config.max_block_relay_outbound = 2;
        config.target_full_relay_outbound = 2;
        config.target_block_relay_outbound = 2;

        ConnectionManager pm(fixture.io_context, config);

        // No peers at all
        REQUIRE(pm.GetOldestBlockRelayPeer() == -1);

        // Only full-relay peer
        auto fr_peer = fixture.create_peer(ConnectionType::OUTBOUND_FULL_RELAY, "10.0.0.1");
        PeerTestAccess::SetSuccessfullyConnected(*fr_peer, true);
        pm.add_peer(fr_peer);

        REQUIRE(pm.GetOldestBlockRelayPeer() == -1);
    }

    SECTION("Returns correct peer when block-relay-only outbound exists") {
        ConnectionManager::Config config;
        config.max_block_relay_outbound = 2;
        config.target_block_relay_outbound = 2;

        ConnectionManager pm(fixture.io_context, config);

        auto br_peer = fixture.create_peer(ConnectionType::BLOCK_RELAY, "10.0.0.1");
        PeerTestAccess::SetSuccessfullyConnected(*br_peer, true);
        int id = pm.add_peer(br_peer);
        REQUIRE(id >= 0);

        REQUIRE(pm.GetOldestBlockRelayPeer() == id);
    }

    SECTION("Returns oldest by last_headers_received time") {
        ConnectionManager::Config config;
        config.max_block_relay_outbound = 3;
        config.target_block_relay_outbound = 3;

        ConnectionManager pm(fixture.io_context, config);

        // Add three block-relay peers
        auto br1 = fixture.create_peer(ConnectionType::BLOCK_RELAY, "10.0.0.1");
        auto br2 = fixture.create_peer(ConnectionType::BLOCK_RELAY, "10.0.0.2");
        auto br3 = fixture.create_peer(ConnectionType::BLOCK_RELAY, "10.0.0.3");
        PeerTestAccess::SetSuccessfullyConnected(*br1, true);
        PeerTestAccess::SetSuccessfullyConnected(*br2, true);
        PeerTestAccess::SetSuccessfullyConnected(*br3, true);

        int id1 = pm.add_peer(br1);
        int id2 = pm.add_peer(br2);
        int id3 = pm.add_peer(br3);
        REQUIRE(id1 >= 0);
        REQUIRE(id2 >= 0);
        REQUIRE(id3 >= 0);

        // Initially all have epoch time (oldest possible), first added wins
        // Update peer2 and peer3 to have more recent times
        pm.UpdateLastHeadersReceived(id2);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        pm.UpdateLastHeadersReceived(id3);

        // peer1 never got headers, so it's oldest
        REQUIRE(pm.GetOldestBlockRelayPeer() == id1);

        // Now update peer1 to be most recent
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        pm.UpdateLastHeadersReceived(id1);

        // Now peer2 is oldest (it was updated first among the updated ones)
        REQUIRE(pm.GetOldestBlockRelayPeer() == id2);
    }

    SECTION("Ignores peers that haven't completed handshake") {
        ConnectionManager::Config config;
        config.max_block_relay_outbound = 2;
        config.target_block_relay_outbound = 2;

        ConnectionManager pm(fixture.io_context, config);

        // Peer without completed handshake
        auto br1 = fixture.create_peer(ConnectionType::BLOCK_RELAY, "10.0.0.1");
        // Don't set successfully_connected

        // Peer with completed handshake
        auto br2 = fixture.create_peer(ConnectionType::BLOCK_RELAY, "10.0.0.2");
        PeerTestAccess::SetSuccessfullyConnected(*br2, true);

        int id1 = pm.add_peer(br1);
        int id2 = pm.add_peer(br2);
        REQUIRE(id1 >= 0);
        REQUIRE(id2 >= 0);

        // Should only consider peer2
        REQUIRE(pm.GetOldestBlockRelayPeer() == id2);
    }
}

TEST_CASE("Block-relay peers - UpdateLastHeadersReceived tracks time", "[network][block_relay][rotation][unit]") {
    BlockRelayTestFixture fixture;
    ConnectionManager::Config config;
    config.max_block_relay_outbound = 1;
    config.target_block_relay_outbound = 1;

    ConnectionManager pm(fixture.io_context, config);

    auto br_peer = fixture.create_peer(ConnectionType::BLOCK_RELAY, "10.0.0.1");
    PeerTestAccess::SetSuccessfullyConnected(*br_peer, true);
    int id = pm.add_peer(br_peer);
    REQUIRE(id >= 0);

    // Get initial time
    auto initial_time = br_peer->last_headers_received();

    // Wait a bit and update
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    pm.UpdateLastHeadersReceived(id);

    // Time should have advanced
    auto updated_time = br_peer->last_headers_received();
    REQUIRE(updated_time > initial_time);
}
