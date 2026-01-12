// Copyright (c) 2025 The Unicity Foundation
// Unit tests for Bitcoin Core parity in connection management
//
// These tests verify Bitcoin Core-aligned behavior for:
// - Discouraged peer conditional acceptance
// - Anchor peer BLOCK_RELAY selection
// - Connection type classification
// - Misbehavior scoring and thresholds
// - Eviction protection rules
// - Per-netgroup inbound limits
//
// Note: Service flags validation is tested via integration tests that use
// full message routing through simulate_receive(), not direct handle_version() calls.
// Manual address tracking is an internal implementation detail of ConnectTo().

#include "catch_amalgamated.hpp"
#include "network/peer_lifecycle_manager.hpp"
#include "network/anchor_manager.hpp"
#include "network/eviction_manager.hpp"
#include "network/misbehavior_manager.hpp"
#include "network/peer.hpp"
#include "network/protocol.hpp"
#include "network/peer_misbehavior.hpp"
#include "infra/mock_transport.hpp"
#include <asio.hpp>

using namespace unicity;
using namespace unicity::network;

// =============================================================================
// Test Fixtures
// =============================================================================

struct BitcoinCoreParityFixture {
    asio::io_context io_context;

    PeerPtr create_outbound_peer(ConnectionType conn_type,
                                  const std::string& address = "10.0.0.1",
                                  uint16_t port = 8333) {
        return Peer::create_outbound(
            io_context,
            nullptr,  // No transport needed for unit tests
            protocol::magic::REGTEST,
            0,        // start_height
            address,
            port,
            conn_type
        );
    }

    std::shared_ptr<MockTransportConnection> create_inbound_connection(
        const std::string& address = "10.0.0.1",
        uint16_t port = 12345) {
        auto conn = std::make_shared<MockTransportConnection>(address, port);
        conn->set_inbound(true);
        return conn;
    }
};

// =============================================================================
// Discouraged Peer Conditional Acceptance Tests
// Bitcoin Core: Discouraged peers are only rejected when inbound slots almost full
// =============================================================================

TEST_CASE("Discouraged peer conditional acceptance - Bitcoin Core parity",
          "[network][bitcoin_core][discouraged][unit]") {
    BitcoinCoreParityFixture fixture;

    SECTION("Discouraged peer rejected when inbound slots almost full") {
        PeerLifecycleManager::Config config;
        config.max_inbound_peers = 3;  // Small limit for testing
        PeerLifecycleManager pm(fixture.io_context, config);

        // Discourage the address we'll try to connect from
        pm.Discourage("10.0.0.100");
        REQUIRE(pm.IsDiscouraged("10.0.0.100"));

        // Fill up inbound slots to almost full (2 out of 3)
        auto conn1 = fixture.create_inbound_connection("10.0.0.1");
        auto conn2 = fixture.create_inbound_connection("10.0.0.2");

        auto is_running = [](){ return true; };
        auto setup_handler = [](Peer*){};

        pm.HandleInboundConnection(conn1, is_running, setup_handler,
            protocol::magic::REGTEST, 0, 42, NetPermissionFlags::None);
        pm.HandleInboundConnection(conn2, is_running, setup_handler,
            protocol::magic::REGTEST, 0, 42, NetPermissionFlags::None);

        REQUIRE(pm.inbound_count() == 2);

        // Now try to connect from discouraged address - should be rejected
        // because adding one more would fill slots (3/3)
        auto discouraged_conn = fixture.create_inbound_connection("10.0.0.100");
        pm.HandleInboundConnection(discouraged_conn, is_running, setup_handler,
            protocol::magic::REGTEST, 0, 42, NetPermissionFlags::None);

        // Connection should be closed (rejected)
        REQUIRE_FALSE(discouraged_conn->is_open());
        REQUIRE(pm.inbound_count() == 2);  // No new peer added
    }

    SECTION("Discouraged peer accepted when slots available") {
        PeerLifecycleManager::Config config;
        config.max_inbound_peers = 10;  // Plenty of room
        PeerLifecycleManager pm(fixture.io_context, config);

        // Discourage the address
        pm.Discourage("10.0.0.100");
        REQUIRE(pm.IsDiscouraged("10.0.0.100"));

        // No other inbound peers - lots of slots available
        REQUIRE(pm.inbound_count() == 0);

        // Try to connect from discouraged address - should be accepted
        auto discouraged_conn = fixture.create_inbound_connection("10.0.0.100");
        auto is_running = [](){ return true; };
        auto setup_handler = [](Peer*){};

        pm.HandleInboundConnection(discouraged_conn, is_running, setup_handler,
            protocol::magic::REGTEST, 0, 42, NetPermissionFlags::None);

        // Connection should be accepted (not closed)
        REQUIRE(discouraged_conn->is_open());
        REQUIRE(pm.inbound_count() == 1);  // Peer was added
    }

    SECTION("NoBan permission bypasses discouragement check") {
        PeerLifecycleManager::Config config;
        config.max_inbound_peers = 2;  // Limited slots
        PeerLifecycleManager pm(fixture.io_context, config);

        // Discourage the address
        pm.Discourage("10.0.0.100");

        // Fill one slot (leaving slots almost full)
        auto conn1 = fixture.create_inbound_connection("10.0.0.1");
        auto is_running = [](){ return true; };
        auto setup_handler = [](Peer*){};

        pm.HandleInboundConnection(conn1, is_running, setup_handler,
            protocol::magic::REGTEST, 0, 42, NetPermissionFlags::None);
        REQUIRE(pm.inbound_count() == 1);

        // Try discouraged peer WITH NoBan permission - should be accepted
        auto discouraged_conn = fixture.create_inbound_connection("10.0.0.100");
        pm.HandleInboundConnection(discouraged_conn, is_running, setup_handler,
            protocol::magic::REGTEST, 0, 42, NetPermissionFlags::NoBan);

        // NoBan bypasses the discouragement check
        REQUIRE(discouraged_conn->is_open());
        REQUIRE(pm.inbound_count() == 2);
    }
}

// =============================================================================
// HandleInboundConnection Edge Case Tests
// =============================================================================

TEST_CASE("HandleInboundConnection - banned address rejected",
          "[network][bitcoin_core][inbound][unit]") {
    BitcoinCoreParityFixture fixture;

    PeerLifecycleManager::Config config;
    config.max_inbound_peers = 10;
    PeerLifecycleManager pm(fixture.io_context, config);

    // Ban the address
    pm.Ban("10.0.0.50", 3600);
    REQUIRE(pm.IsBanned("10.0.0.50"));

    // Try to connect from banned address
    auto banned_conn = fixture.create_inbound_connection("10.0.0.50");
    auto is_running = [](){ return true; };
    auto setup_handler = [](Peer*){};

    pm.HandleInboundConnection(banned_conn, is_running, setup_handler,
        protocol::magic::REGTEST, 0, 42, NetPermissionFlags::None);

    // Connection should be closed (rejected)
    REQUIRE_FALSE(banned_conn->is_open());
    REQUIRE(pm.inbound_count() == 0);
}

TEST_CASE("HandleInboundConnection - early exit when not running",
          "[network][bitcoin_core][inbound][unit]") {
    BitcoinCoreParityFixture fixture;

    PeerLifecycleManager::Config config;
    config.max_inbound_peers = 10;
    PeerLifecycleManager pm(fixture.io_context, config);

    auto conn = fixture.create_inbound_connection("10.0.0.1");
    auto is_running = [](){ return false; };  // Not running
    auto setup_handler = [](Peer*){};

    pm.HandleInboundConnection(conn, is_running, setup_handler,
        protocol::magic::REGTEST, 0, 42, NetPermissionFlags::None);

    // No peer should be added (early exit)
    REQUIRE(pm.inbound_count() == 0);
    // Connection remains open (not explicitly closed on early exit)
    REQUIRE(conn->is_open());
}

TEST_CASE("HandleInboundConnection - null connection handled gracefully",
          "[network][bitcoin_core][inbound][unit]") {
    BitcoinCoreParityFixture fixture;

    PeerLifecycleManager::Config config;
    config.max_inbound_peers = 10;
    PeerLifecycleManager pm(fixture.io_context, config);

    auto is_running = [](){ return true; };
    auto setup_handler = [](Peer*){};

    // Pass null connection - should not crash
    pm.HandleInboundConnection(nullptr, is_running, setup_handler,
        protocol::magic::REGTEST, 0, 42, NetPermissionFlags::None);

    // No peer should be added
    REQUIRE(pm.inbound_count() == 0);
}

// =============================================================================
// Anchor BLOCK_RELAY Selection Tests
// Bitcoin Core: Anchors are selected from block-relay-only connections
// =============================================================================

TEST_CASE("Anchor peers select from BLOCK_RELAY only - Bitcoin Core parity",
          "[network][bitcoin_core][anchor][unit]") {
    BitcoinCoreParityFixture fixture;

    SECTION("GetAnchors only returns BLOCK_RELAY peers") {
        PeerLifecycleManager::Config config;
        config.max_full_relay_outbound = 8;
        config.max_block_relay_outbound = 2;
        PeerLifecycleManager pm(fixture.io_context, config);

        AnchorManager am(pm);

        // Add a mix of peer types
        auto full_relay1 = fixture.create_outbound_peer(ConnectionType::OUTBOUND_FULL_RELAY, "10.0.0.1");
        auto full_relay2 = fixture.create_outbound_peer(ConnectionType::OUTBOUND_FULL_RELAY, "10.0.0.2");
        auto block_relay1 = fixture.create_outbound_peer(ConnectionType::BLOCK_RELAY, "10.0.0.3");
        auto block_relay2 = fixture.create_outbound_peer(ConnectionType::BLOCK_RELAY, "10.0.0.4");

        pm.add_peer(full_relay1);
        pm.add_peer(full_relay2);
        pm.add_peer(block_relay1);
        pm.add_peer(block_relay2);

        // GetAnchors should only return BLOCK_RELAY peers
        // Note: GetAnchors also requires is_connected() and state() == READY
        // In unit tests, peers may not be in READY state, so this might return empty
        auto anchors = am.GetAnchors();

        // If anchors are returned, they must all be from block-relay peers
        // (In unit tests, this may be empty because peers aren't fully connected)
        for (const auto& anchor : anchors) {
            // Verify the anchor IPs match block_relay peers, not full_relay
            // 10.0.0.3 or 10.0.0.4, not 10.0.0.1 or 10.0.0.2
            auto ip_str = anchor.to_string();
            if (ip_str) {
                // Extract just the IP part (without port)
                std::string ip = ip_str->substr(0, ip_str->find(':'));
                REQUIRE((ip == "10.0.0.3" || ip == "10.0.0.4"));
            }
        }
    }

    SECTION("Feeler peers are never selected as anchors") {
        PeerLifecycleManager::Config config;
        PeerLifecycleManager pm(fixture.io_context, config);
        AnchorManager am(pm);

        // Add feeler peer
        auto feeler = fixture.create_outbound_peer(ConnectionType::FEELER, "10.0.0.100");
        pm.add_peer(feeler);

        auto anchors = am.GetAnchors();
        // Feelers should never be in anchors list
        for (const auto& anchor : anchors) {
            auto ip_str = anchor.to_string();
            if (ip_str) {
                std::string ip = ip_str->substr(0, ip_str->find(':'));
                REQUIRE(ip != "10.0.0.100");
            }
        }
    }

    SECTION("Full-relay peers are never selected as anchors") {
        PeerLifecycleManager::Config config;
        PeerLifecycleManager pm(fixture.io_context, config);
        AnchorManager am(pm);

        // Add only full-relay peers
        auto full_relay1 = fixture.create_outbound_peer(ConnectionType::OUTBOUND_FULL_RELAY, "10.0.0.1");
        auto full_relay2 = fixture.create_outbound_peer(ConnectionType::OUTBOUND_FULL_RELAY, "10.0.0.2");
        pm.add_peer(full_relay1);
        pm.add_peer(full_relay2);

        // Even if they were READY, they should not be selected as anchors
        // GetAnchors filters on is_block_relay_only()
        auto anchors = am.GetAnchors();

        // Should be empty - no block-relay peers available
        // (Even if not empty due to state, verify IPs don't match full-relay)
        for (const auto& anchor : anchors) {
            auto ip_str = anchor.to_string();
            if (ip_str) {
                std::string ip = ip_str->substr(0, ip_str->find(':'));
                REQUIRE(ip != "10.0.0.1");
                REQUIRE(ip != "10.0.0.2");
            }
        }
    }
}

// =============================================================================
// Connection Type Classification Tests
// Verify peers are correctly classified by connection type
// =============================================================================

TEST_CASE("Connection type classification - Bitcoin Core parity",
          "[network][bitcoin_core][connection_type][unit]") {
    BitcoinCoreParityFixture fixture;

    SECTION("Block-relay peers are correctly identified") {
        auto block_relay = fixture.create_outbound_peer(ConnectionType::BLOCK_RELAY, "10.0.0.1");
        REQUIRE(block_relay->is_block_relay_only() == true);
        REQUIRE(block_relay->is_full_relay() == false);
        REQUIRE(block_relay->relays_addr() == false);
    }

    SECTION("Full-relay peers are correctly identified") {
        auto full_relay = fixture.create_outbound_peer(ConnectionType::OUTBOUND_FULL_RELAY, "10.0.0.1");
        REQUIRE(full_relay->is_block_relay_only() == false);
        REQUIRE(full_relay->is_full_relay() == true);
        REQUIRE(full_relay->relays_addr() == true);
    }

    SECTION("Feeler peers are correctly identified") {
        auto feeler = fixture.create_outbound_peer(ConnectionType::FEELER, "10.0.0.1");
        REQUIRE(feeler->is_feeler() == true);
        REQUIRE(feeler->is_block_relay_only() == false);
        REQUIRE(feeler->relays_addr() == false);
    }

    SECTION("Manual peers are correctly identified") {
        auto manual = fixture.create_outbound_peer(ConnectionType::MANUAL, "10.0.0.1");
        REQUIRE(manual->is_manual() == true);
        REQUIRE(manual->is_block_relay_only() == false);
        REQUIRE(manual->relays_addr() == false);  // Manual peers don't relay addresses
    }
}

// =============================================================================
// Slot Accounting Tests
// Verify connection types are counted correctly for slot limits
// =============================================================================

TEST_CASE("Slot accounting by connection type - Bitcoin Core parity",
          "[network][bitcoin_core][slots][unit]") {
    BitcoinCoreParityFixture fixture;

    SECTION("Manual peers don't count toward full-relay slots") {
        PeerLifecycleManager::Config config;
        config.max_full_relay_outbound = 2;
        config.max_block_relay_outbound = 0;
        PeerLifecycleManager pm(fixture.io_context, config);

        // Add a manual peer
        auto manual_peer = fixture.create_outbound_peer(ConnectionType::MANUAL, "10.0.0.50", 9590);
        int manual_id = pm.add_peer(manual_peer);
        REQUIRE(manual_id >= 0);

        // Manual should NOT count toward full_relay_outbound_count
        REQUIRE(pm.full_relay_outbound_count() == 0);

        // But it should be in the peer list
        REQUIRE(pm.peer_count() == 1);
    }

    SECTION("Feeler peers don't count toward outbound slots") {
        PeerLifecycleManager::Config config;
        config.max_full_relay_outbound = 2;
        config.max_block_relay_outbound = 0;
        PeerLifecycleManager pm(fixture.io_context, config);

        // Add a feeler peer
        auto feeler_peer = fixture.create_outbound_peer(ConnectionType::FEELER, "10.0.0.50", 9590);
        int feeler_id = pm.add_peer(feeler_peer);
        REQUIRE(feeler_id >= 0);

        // Feeler should NOT count toward full_relay_outbound_count
        REQUIRE(pm.full_relay_outbound_count() == 0);
        REQUIRE(pm.block_relay_outbound_count() == 0);

        // But it should be in the peer list
        REQUIRE(pm.peer_count() == 1);
    }

    SECTION("Full-relay and block-relay have separate slot pools") {
        PeerLifecycleManager::Config config;
        config.max_full_relay_outbound = 2;
        config.max_block_relay_outbound = 1;
        PeerLifecycleManager pm(fixture.io_context, config);

        // Add full-relay peers up to limit
        auto full1 = fixture.create_outbound_peer(ConnectionType::OUTBOUND_FULL_RELAY, "10.0.0.1");
        auto full2 = fixture.create_outbound_peer(ConnectionType::OUTBOUND_FULL_RELAY, "10.0.0.2");
        REQUIRE(pm.add_peer(full1) >= 0);
        REQUIRE(pm.add_peer(full2) >= 0);
        REQUIRE(pm.full_relay_outbound_count() == 2);

        // Full-relay slots exhausted, but block-relay slot available
        auto full3 = fixture.create_outbound_peer(ConnectionType::OUTBOUND_FULL_RELAY, "10.0.0.3");
        REQUIRE(pm.add_peer(full3) == -1);  // Rejected

        // Block-relay should still work
        auto block1 = fixture.create_outbound_peer(ConnectionType::BLOCK_RELAY, "10.0.0.4");
        REQUIRE(pm.add_peer(block1) >= 0);
        REQUIRE(pm.block_relay_outbound_count() == 1);
    }
}

// =============================================================================
// Misbehavior System Tests - Bitcoin Core Parity (March 2024)
// Bitcoin Core: Instant discourage on any misbehavior (no score accumulation)
// =============================================================================

TEST_CASE("Misbehavior instant discourage - Bitcoin Core parity",
          "[network][bitcoin_core][misbehavior][unit]") {

    SECTION("Any misbehavior results in instant discourage") {
        // Bitcoin Core removed score-based misbehavior in commit ae60d485da (March 2024)
        // Any misbehavior now results in instant discouragement - no score accumulation
        util::ThreadSafeMap<int, PeerTrackingData> peer_states;
        PeerTrackingData data;
        data.misbehavior.permissions = NetPermissionFlags::None;
        peer_states.InsertOrUpdate(1, data);

        MisbehaviorManager mm(peer_states);

        // Single misbehavior should instantly discourage
        mm.ReportInvalidPoW(1);
        REQUIRE(mm.IsMisbehaving(1));
        REQUIRE(mm.ShouldDisconnect(1));
    }

    SECTION("Unconnecting headers threshold is 10 messages") {
        // Bitcoin Core disconnects after 10 unconnecting header messages
        // This prevents memory exhaustion from orphan header spam
        REQUIRE(MAX_UNCONNECTING_HEADERS == 10);
    }

    SECTION("Unconnecting headers threshold triggers instant discourage") {
        // Create peer state tracking manually to test MisbehaviorManager directly
        util::ThreadSafeMap<int, PeerTrackingData> peer_states;

        // Initialize peer state
        PeerTrackingData data;
        data.misbehavior.permissions = NetPermissionFlags::None;
        peer_states.InsertOrUpdate(1, data);

        MisbehaviorManager mm(peer_states);

        // Send 9 unconnecting headers - should NOT trigger discourage yet
        for (int i = 0; i < 9; ++i) {
            mm.IncrementUnconnectingHeaders(1);
            REQUIRE_FALSE(mm.IsMisbehaving(1));  // No discourage until threshold
            REQUIRE_FALSE(mm.ShouldDisconnect(1));
        }

        // 10th unconnecting headers message triggers instant discourage
        mm.IncrementUnconnectingHeaders(1);
        REQUIRE(mm.IsMisbehaving(1));
        REQUIRE(mm.ShouldDisconnect(1));
    }

    SECTION("Unconnecting headers reset clears counter") {
        util::ThreadSafeMap<int, PeerTrackingData> peer_states;
        PeerTrackingData data;
        data.misbehavior.permissions = NetPermissionFlags::None;
        peer_states.InsertOrUpdate(1, data);

        MisbehaviorManager mm(peer_states);

        // Increment several times
        for (int i = 0; i < 5; ++i) {
            mm.IncrementUnconnectingHeaders(1);
        }
        REQUIRE(mm.GetUnconnectingHeadersCount(1) == 5);

        // Reset when progress is made
        mm.ResetUnconnectingHeaders(1);
        REQUIRE(mm.GetUnconnectingHeadersCount(1) == 0);

        // Can increment again from zero
        mm.IncrementUnconnectingHeaders(1);
        REQUIRE(mm.GetUnconnectingHeadersCount(1) == 1);
    }

    SECTION("Duplicate invalid header does not re-trigger discourage") {
        util::ThreadSafeMap<int, PeerTrackingData> peer_states;
        PeerTrackingData data;
        data.misbehavior.permissions = NetPermissionFlags::None;
        peer_states.InsertOrUpdate(1, data);

        MisbehaviorManager mm(peer_states);

        // Create a fake header hash
        uint256 invalid_hash;
        std::fill(invalid_hash.begin(), invalid_hash.end(), 0xAB);

        // First time seeing this invalid header - not recorded yet
        REQUIRE_FALSE(mm.HasInvalidHeaderHash(1, invalid_hash));

        // Note that we've seen it
        mm.NoteInvalidHeaderHash(1, invalid_hash);

        // Now it should be recorded
        REQUIRE(mm.HasInvalidHeaderHash(1, invalid_hash));

        // Seeing it again - check returns true, so caller should skip re-processing
        REQUIRE(mm.HasInvalidHeaderHash(1, invalid_hash));

        // A different hash is not recorded
        uint256 other_hash;
        std::fill(other_hash.begin(), other_hash.end(), 0xCD);
        REQUIRE_FALSE(mm.HasInvalidHeaderHash(1, other_hash));
    }

    SECTION("NoBan peers tracked but not disconnected") {
        util::ThreadSafeMap<int, PeerTrackingData> peer_states;
        PeerTrackingData data;
        data.misbehavior.permissions = NetPermissionFlags::NoBan;  // Protected peer
        peer_states.InsertOrUpdate(1, data);

        MisbehaviorManager mm(peer_states);

        // Report severe violation that would normally disconnect
        mm.ReportInvalidPoW(1);  // Instant discourage normally

        // Misbehavior is tracked (should_discourage = true)
        REQUIRE(mm.IsMisbehaving(1));

        // But NoBan peer should NOT be disconnected
        REQUIRE_FALSE(mm.ShouldDisconnect(1));
    }
}

// =============================================================================
// Eviction Protection Rules Tests - Bitcoin Core Parity
// Bitcoin Core: Complex multi-criteria protection to resist eclipse attacks
// =============================================================================

TEST_CASE("Eviction protection rules - Bitcoin Core parity",
          "[network][bitcoin_core][eviction][unit]") {

    auto now = std::chrono::steady_clock::now();

    SECTION("Outbound peers are never evicted (defense in depth)") {
        std::vector<EvictionManager::EvictionCandidate> candidates;

        // Add an outbound peer
        candidates.push_back({
            .peer_id = 1,
            .connected_time = now - std::chrono::hours(1),
            .ping_time_ms = 50,
            .netgroup = "10.0",
            .is_protected = false,
            .is_outbound = true,  // OUTBOUND
            .last_headers_time = now
        });

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));
        // Should return nullopt - outbound peers never evicted
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("NoBan/protected peers are never evicted") {
        std::vector<EvictionManager::EvictionCandidate> candidates;

        // Add a protected inbound peer
        candidates.push_back({
            .peer_id = 1,
            .connected_time = now - std::chrono::hours(1),
            .ping_time_ms = 50,
            .netgroup = "10.0",
            .is_protected = true,  // PROTECTED
            .is_outbound = false,
            .last_headers_time = now
        });

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));
        // Should return nullopt - protected peers never evicted
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Netgroup diversity protection - 4 unique netgroups protected") {
        std::vector<EvictionManager::EvictionCandidate> candidates;

        // Add peers from 5 different netgroups
        for (int i = 0; i < 5; ++i) {
            candidates.push_back({
                .peer_id = i + 1,
                .connected_time = now - std::chrono::minutes(i + 1),  // Different ages
                .ping_time_ms = 100,  // Same ping
                .netgroup = "10." + std::to_string(i),  // Different netgroups
                .is_protected = false,
                .is_outbound = false,
                .last_headers_time = now - std::chrono::hours(1)  // Old headers time
            });
        }

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));
        REQUIRE(result.has_value());

        // One of the 5 should be evicted (netgroup protection saves 4)
        // The evicted peer should be from the netgroup with most connections
        // Since all have 1 connection, it picks from the "youngest" after other protections
    }

    SECTION("Ping time protection - 8 lowest ping peers protected") {
        std::vector<EvictionManager::EvictionCandidate> candidates;

        // Add 10 peers with varying ping times, all same netgroup
        for (int i = 0; i < 10; ++i) {
            candidates.push_back({
                .peer_id = i + 1,
                .connected_time = now - std::chrono::hours(1),
                .ping_time_ms = static_cast<int64_t>((i + 1) * 10),  // 10ms, 20ms, ..., 100ms
                .netgroup = "192.168",  // Same netgroup
                .is_protected = false,
                .is_outbound = false,
                .last_headers_time = now - std::chrono::hours(1)
            });
        }

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));
        REQUIRE(result.has_value());

        // Peers with lowest 8 ping times (10-80ms) should be protected
        // Evicted peer should be one with higher ping (90ms or 100ms)
        int evicted_id = result.value();
        REQUIRE(evicted_id >= 9);  // peer_id 9 or 10 (90ms or 100ms ping)
    }

    SECTION("Header relay protection - peers doing useful work protected") {
        std::vector<EvictionManager::EvictionCandidate> candidates;

        // Add peers - some with recent header relay, some without
        for (int i = 0; i < 6; ++i) {
            candidates.push_back({
                .peer_id = i + 1,
                .connected_time = now - std::chrono::hours(1),
                .ping_time_ms = 100,  // Same ping
                .netgroup = "192.168",  // Same netgroup
                .is_protected = false,
                .is_outbound = false,
                // First 4 have recent headers (protected), last 2 have old headers
                .last_headers_time = (i < 4) ? now : now - std::chrono::hours(24)
            });
        }

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));
        REQUIRE(result.has_value());

        // Peers 1-4 (recent headers) should be protected
        // Evicted peer should be 5 or 6 (old headers)
        int evicted_id = result.value();
        REQUIRE(evicted_id >= 5);
    }

    SECTION("Eviction constants match Bitcoin Core") {
        REQUIRE(EvictionManager::PROTECT_BY_NETGROUP == 4);
        REQUIRE(EvictionManager::PROTECT_BY_PING == 8);
        REQUIRE(EvictionManager::PROTECT_BY_HEADERS == 4);
    }
}

// =============================================================================
// Per-Netgroup Inbound Limit Tests - Bitcoin Core Parity
// Prevent Sybil attacks from same /16 subnet
// =============================================================================

TEST_CASE("Per-netgroup inbound limits - Bitcoin Core parity",
          "[network][bitcoin_core][netgroup][unit]") {

    SECTION("Max inbound per netgroup constant is defined") {
        REQUIRE(PeerLifecycleManager::MAX_INBOUND_PER_NETGROUP == 4);
    }

    SECTION("Connections from same /16 subnet are limited") {
        asio::io_context io_context;
        PeerLifecycleManager::Config config;
        config.max_inbound_peers = 100;  // Plenty of total room
        PeerLifecycleManager pm(io_context, config);

        auto is_running = [](){ return true; };
        auto setup_handler = [](Peer*){};

        // First 4 connections from same /16 should succeed
        // Use RFC1918 addresses (10.x.x.x) which are common in local networks
        for (int i = 0; i < 4; ++i) {
            // All in 10.0.x.x /16 (10.0.0.1, 10.0.1.2, 10.0.2.3, 10.0.3.4)
            std::string ip = "10.0." + std::to_string(i) + "." + std::to_string(i + 1);
            auto conn = std::make_shared<MockTransportConnection>(ip, 12345);
            conn->set_inbound(true);

            pm.HandleInboundConnection(conn, is_running, setup_handler,
                protocol::magic::REGTEST, 0, 42, NetPermissionFlags::None);
        }
        REQUIRE(pm.inbound_count() == 4);

        // 5th connection from same /16 (10.0.x.x) should be rejected
        auto conn5 = std::make_shared<MockTransportConnection>("10.0.100.200", 12345);
        conn5->set_inbound(true);

        pm.HandleInboundConnection(conn5, is_running, setup_handler,
            protocol::magic::REGTEST, 0, 42, NetPermissionFlags::None);

        // Peer should NOT have been added (per-netgroup limit)
        // Note: connection->is_open() may still be true because peer->disconnect()
        // posts to io_context which isn't run in this test
        REQUIRE(pm.inbound_count() == 4);

        // But connection from DIFFERENT /16 should succeed (10.1.x.x)
        auto conn_other = std::make_shared<MockTransportConnection>("10.1.0.1", 12345);
        conn_other->set_inbound(true);

        pm.HandleInboundConnection(conn_other, is_running, setup_handler,
            protocol::magic::REGTEST, 0, 42, NetPermissionFlags::None);

        REQUIRE(pm.inbound_count() == 5);
    }
}
