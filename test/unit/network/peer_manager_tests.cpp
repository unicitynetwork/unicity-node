// Copyright (c) 2025 The Unicity Foundation
// Unit tests for network/peer_manager.cpp - Peer lifecycle and DoS protection
//
// These tests verify:
// - Connection limits (inbound/outbound)
// - Misbehavior score tracking
// - Discouragement thresholds
// - Permission flags (NoBan, Manual)
// - Unconnecting headers tracking
// - Peer lifecycle (add/remove)

#include "catch_amalgamated.hpp"
#include "network/peer_lifecycle_manager.hpp"
#include "network/peer_discovery_manager.hpp"
#include "network/peer.hpp"
#include "network/addr_manager.hpp"
#include "network/connection_types.hpp"
#include "util/time.hpp"
#include "util/uint.hpp"
#include <asio.hpp>

using namespace unicity::network;
using namespace unicity::protocol;

// Helper to create a minimal mock peer for testing
// Note: We don't need full peer functionality, just a valid PeerPtr
class TestPeerFixture {
public:
    asio::io_context io_context;

    TestPeerFixture() {
    }

    // Create a simple outbound peer for testing
    // Note: We won't actually start/connect these peers in unit tests
    PeerPtr create_test_peer(const std::string& address = "127.0.0.1", uint16_t port = 8333) {
        // For unit testing, we just need a valid PeerPtr
        // We use create_outbound with nullptr transport since we won't actually connect
        auto peer = Peer::create_outbound(
            io_context,
            nullptr,  // No actual transport needed for these tests
            0x12345678,  // network magic
            0,           // start_height
            address,
            port
        );
        return peer;
    }
};

TEST_CASE("ConnectionManager - Construction", "[network][peer_manager][unit]") {
    TestPeerFixture fixture;

    PeerLifecycleManager::Config config;
    config.max_full_relay_outbound = 8;
    config.max_block_relay_outbound = 0;  // Disable block-relay for simplicity
    config.max_inbound_peers = 125;

    PeerLifecycleManager pm(fixture.io_context, config);

    REQUIRE(pm.peer_count() == 0);
    REQUIRE(pm.outbound_count() == 0);
    REQUIRE(pm.inbound_count() == 0);
}

TEST_CASE("ConnectionManager - Connection Limits", "[network][peer_manager][unit]") {
    TestPeerFixture fixture;

    PeerLifecycleManager::Config config;
    config.max_full_relay_outbound = 2;
    config.max_block_relay_outbound = 0;  // Disable block-relay for this test
    config.max_inbound_peers = 3;
    config.target_full_relay_outbound = 2;
    config.target_block_relay_outbound = 0;

    PeerLifecycleManager pm(fixture.io_context, config);

    SECTION("Needs more outbound when empty") {
        REQUIRE(pm.needs_more_outbound());
    }

    SECTION("Can accept inbound when empty") {
        REQUIRE(pm.can_accept_inbound());
    }

    SECTION("Track peer counts correctly") {
        REQUIRE(pm.peer_count() == 0);
        REQUIRE(pm.outbound_count() == 0);
        REQUIRE(pm.inbound_count() == 0);
    }
}

TEST_CASE("ConnectionManager - Instant Discourage", "[network][peer_manager][unit]") {
    // Bitcoin Core (March 2024+): Any misbehavior = instant discourage
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    auto peer = fixture.create_test_peer();
    int peer_id = pm.add_peer(peer);
    REQUIRE(peer_id >= 0);

    SECTION("Initial state is not misbehaving") {
        REQUIRE_FALSE(pm.IsMisbehaving(peer_id));
        REQUIRE_FALSE(pm.ShouldDisconnect(peer_id));
    }

    SECTION("Low work headers triggers instant discourage") {
        pm.ReportLowWorkHeaders(peer_id);
        REQUIRE(pm.IsMisbehaving(peer_id));
        REQUIRE(pm.ShouldDisconnect(peer_id));
    }

    SECTION("Non-continuous headers triggers instant discourage") {
        pm.ReportNonContinuousHeaders(peer_id);
        REQUIRE(pm.IsMisbehaving(peer_id));
        REQUIRE(pm.ShouldDisconnect(peer_id));
    }

    SECTION("Oversized message triggers instant discourage") {
        pm.ReportOversizedMessage(peer_id);
        REQUIRE(pm.IsMisbehaving(peer_id));
        REQUIRE(pm.ShouldDisconnect(peer_id));
    }

    SECTION("Invalid PoW triggers instant discourage") {
        pm.ReportInvalidPoW(peer_id);
        REQUIRE(pm.IsMisbehaving(peer_id));
        REQUIRE(pm.ShouldDisconnect(peer_id));
    }

    SECTION("Invalid header triggers instant discourage") {
        pm.ReportInvalidHeader(peer_id, "test reason");
        REQUIRE(pm.IsMisbehaving(peer_id));
        REQUIRE(pm.ShouldDisconnect(peer_id));
    }

    SECTION("Too many orphans triggers instant discourage") {
        pm.ReportTooManyOrphans(peer_id);
        REQUIRE(pm.IsMisbehaving(peer_id));
        REQUIRE(pm.ShouldDisconnect(peer_id));
    }
}

TEST_CASE("ConnectionManager - Permission Flags", "[network][peer_manager][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    SECTION("NoBan permission prevents disconnection") {
        auto peer = fixture.create_test_peer();
        int peer_id = pm.add_peer(peer, NetPermissionFlags::NoBan, "127.0.0.1");
        REQUIRE(peer_id >= 0);

        // Even with severe misbehavior, NoBan peer should not be disconnected
        pm.ReportInvalidPoW(peer_id);

        // Misbehavior is tracked
        REQUIRE(pm.IsMisbehaving(peer_id));

        // But NoBan should NOT disconnect
        REQUIRE_FALSE(pm.ShouldDisconnect(peer_id));
    }

    SECTION("Manual permission") {
        auto peer = fixture.create_test_peer();
        int peer_id = pm.add_peer(peer, NetPermissionFlags::Manual);
        REQUIRE(peer_id >= 0);

        // Manual connections can still be disconnected for misbehavior
        pm.ReportInvalidPoW(peer_id);
        REQUIRE(pm.ShouldDisconnect(peer_id));
    }

    SECTION("Combined permissions") {
        auto peer = fixture.create_test_peer();
        int peer_id = pm.add_peer(peer,
                                   NetPermissionFlags::NoBan | NetPermissionFlags::Manual);
        REQUIRE(peer_id >= 0);

        // NoBan should still protect even with Manual flag
        pm.ReportInvalidPoW(peer_id);
        REQUIRE_FALSE(pm.ShouldDisconnect(peer_id));
    }
}

TEST_CASE("ConnectionManager - Unconnecting Headers Tracking", "[network][peer_manager][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    auto peer = fixture.create_test_peer();
    int peer_id = pm.add_peer(peer);
    REQUIRE(peer_id >= 0);

    SECTION("Track unconnecting headers messages") {
        // Increment up to threshold - 1 (should not trigger discourage yet)
        for (int i = 0; i < MAX_UNCONNECTING_HEADERS - 1; i++) {
            pm.IncrementUnconnectingHeaders(peer_id);
            REQUIRE_FALSE(pm.IsMisbehaving(peer_id));
        }

        // 10th increment triggers instant discourage
        pm.IncrementUnconnectingHeaders(peer_id);
        REQUIRE(pm.IsMisbehaving(peer_id));
        REQUIRE(pm.ShouldDisconnect(peer_id));
    }

    SECTION("Reset unconnecting headers") {
        // Increment a few times
        for (int i = 0; i < 5; i++) {
            pm.IncrementUnconnectingHeaders(peer_id);
        }

        // Reset
        pm.ResetUnconnectingHeaders(peer_id);

        // Now we should be able to increment again without penalty (up to MAX-1)
        for (int i = 0; i < MAX_UNCONNECTING_HEADERS - 1; i++) {
            pm.IncrementUnconnectingHeaders(peer_id);
        }

        // Should not have discouraged yet (count is MAX-1)
        REQUIRE_FALSE(pm.ShouldDisconnect(peer_id));
    }
}

TEST_CASE("ConnectionManager - Peer Lifecycle", "[network][peer_manager][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    SECTION("Add and retrieve peer") {
        auto peer = fixture.create_test_peer();
        int peer_id = pm.add_peer(peer);

        REQUIRE(peer_id >= 0);
        REQUIRE(pm.peer_count() == 1);

        auto retrieved = pm.get_peer(peer_id);
        REQUIRE(retrieved != nullptr);
        REQUIRE(retrieved == peer);
    }

    SECTION("Add multiple peers") {
        auto peer1 = fixture.create_test_peer("192.168.1.1", 8333);
        auto peer2 = fixture.create_test_peer("192.168.1.2", 8333);
        auto peer3 = fixture.create_test_peer("192.168.1.3", 8333);

        int id1 = pm.add_peer(peer1);
        int id2 = pm.add_peer(peer2);
        int id3 = pm.add_peer(peer3);

        REQUIRE(id1 != id2);
        REQUIRE(id2 != id3);
        REQUIRE(id1 != id3);

        REQUIRE(pm.peer_count() == 3);
    }

    SECTION("Remove peer") {
        auto peer = fixture.create_test_peer();
        int peer_id = pm.add_peer(peer);

        REQUIRE(pm.peer_count() == 1);

        pm.remove_peer(peer_id);

        REQUIRE(pm.peer_count() == 0);
        REQUIRE(pm.get_peer(peer_id) == nullptr);
    }

    SECTION("Remove non-existent peer") {
        // Should not crash
        pm.remove_peer(999);
        REQUIRE(pm.peer_count() == 0);
    }
}

TEST_CASE("ConnectionManager - Get Peer by ID", "[network][peer_manager][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    SECTION("Get existing peer") {
        auto peer = fixture.create_test_peer();
        int peer_id = pm.add_peer(peer);

        auto retrieved = pm.get_peer(peer_id);
        REQUIRE(retrieved != nullptr);
        REQUIRE(retrieved == peer);
    }

    SECTION("Get non-existent peer") {
        auto retrieved = pm.get_peer(999);
        REQUIRE(retrieved == nullptr);
    }

    SECTION("Get peer after removal") {
        auto peer = fixture.create_test_peer();
        int peer_id = pm.add_peer(peer);

        pm.remove_peer(peer_id);

        auto retrieved = pm.get_peer(peer_id);
        REQUIRE(retrieved == nullptr);
    }
}

TEST_CASE("ConnectionManager - Peer Count Tracking", "[network][peer_manager][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    SECTION("Empty manager") {
        REQUIRE(pm.peer_count() == 0);
        REQUIRE(pm.outbound_count() == 0);
        REQUIRE(pm.inbound_count() == 0);
    }

    SECTION("Count after adding peers") {
        auto peer1 = fixture.create_test_peer();
        auto peer2 = fixture.create_test_peer();

        pm.add_peer(peer1);
        pm.add_peer(peer2);

        REQUIRE(pm.peer_count() == 2);
    }

    SECTION("Count after removing peer") {
        auto peer1 = fixture.create_test_peer();
        auto peer2 = fixture.create_test_peer();

        int id1 = pm.add_peer(peer1);
        pm.add_peer(peer2);

        REQUIRE(pm.peer_count() == 2);

        pm.remove_peer(id1);

        REQUIRE(pm.peer_count() == 1);
    }
}

TEST_CASE("ConnectionManager - Disconnect All", "[network][peer_manager][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    // Add several peers
    auto peer1 = fixture.create_test_peer();
    auto peer2 = fixture.create_test_peer();
    auto peer3 = fixture.create_test_peer();

    pm.add_peer(peer1);
    pm.add_peer(peer2);
    pm.add_peer(peer3);

    REQUIRE(pm.peer_count() == 3);

    // Disconnect all
    pm.disconnect_all();

    // Note: disconnect_all() calls disconnect() and remove_peer() for each peer
    // After processing, peer count should be 0
    REQUIRE(pm.peer_count() == 0);
}

TEST_CASE("ConnectionManager - Misbehavior for Invalid Peer ID", "[network][peer_manager][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    SECTION("Report misbehavior for non-existent peer") {
        // Should not crash
        pm.ReportInvalidPoW(999);
        pm.ReportLowWorkHeaders(999);
        pm.IncrementUnconnectingHeaders(999);
    }

    SECTION("Query misbehavior for non-existent peer") {
        // Should return safe defaults
        REQUIRE_FALSE(pm.IsMisbehaving(999));
        REQUIRE_FALSE(pm.ShouldDisconnect(999));
    }
}

TEST_CASE("ConnectionManager - HasPermission Utility", "[network][peer_manager][unit]") {
    SECTION("None has no permissions") {
        REQUIRE_FALSE(HasPermission(NetPermissionFlags::None, NetPermissionFlags::NoBan));
        REQUIRE_FALSE(HasPermission(NetPermissionFlags::None, NetPermissionFlags::Manual));
    }

    SECTION("NoBan flag") {
        auto flags = NetPermissionFlags::NoBan;
        REQUIRE(HasPermission(flags, NetPermissionFlags::NoBan));
        REQUIRE_FALSE(HasPermission(flags, NetPermissionFlags::Manual));
    }

    SECTION("Manual flag") {
        auto flags = NetPermissionFlags::Manual;
        REQUIRE(HasPermission(flags, NetPermissionFlags::Manual));
        REQUIRE_FALSE(HasPermission(flags, NetPermissionFlags::NoBan));
    }

    SECTION("Combined flags") {
        auto flags = NetPermissionFlags::NoBan | NetPermissionFlags::Manual;
        REQUIRE(HasPermission(flags, NetPermissionFlags::NoBan));
        REQUIRE(HasPermission(flags, NetPermissionFlags::Manual));
    }
}

TEST_CASE("ConnectionManager - Permission Flag Operations", "[network][peer_manager][unit]") {
    SECTION("OR operation") {
        auto combined = NetPermissionFlags::NoBan | NetPermissionFlags::Manual;
        REQUIRE(HasPermission(combined, NetPermissionFlags::NoBan));
        REQUIRE(HasPermission(combined, NetPermissionFlags::Manual));
    }

    SECTION("AND operation") {
        auto flags = NetPermissionFlags::NoBan | NetPermissionFlags::Manual;
        auto result = flags & NetPermissionFlags::NoBan;
        REQUIRE(result == NetPermissionFlags::NoBan);
    }
}

TEST_CASE("ConnectionManager - Misbehavior Constants", "[network][peer_manager][unit]") {
    SECTION("Unconnecting headers threshold") {
        // MAX_UNCONNECTING_HEADERS is the only threshold-based constant
        // All other misbehavior results in instant discourage
        REQUIRE(MAX_UNCONNECTING_HEADERS == 10);
    }

    SECTION("Instant discourage design") {
        // Bitcoin Core (March 2024+): Any misbehavior = instant discourage
        // No more score accumulation - should_discourage is a boolean
        INFO("Modern Core: instant discourage, no score accumulation");
        CHECK(true);  // Document the design
    }
}

TEST_CASE("ConnectionManager - Feeler connections do not consume outbound slots", "[network][peer_manager][unit][feeler]") {
    TestPeerFixture fixture;

    PeerLifecycleManager::Config config;
    config.max_full_relay_outbound = 2;
    config.max_block_relay_outbound = 0;  // Disable block-relay for this test
    config.max_inbound_peers = 125;
    config.target_full_relay_outbound = 2;
    config.target_block_relay_outbound = 0;

    PeerLifecycleManager pm(fixture.io_context, config);

    // Fill outbound full-relay slots
    auto p1 = Peer::create_outbound(fixture.io_context, nullptr, 0x12345678, 0, "10.0.0.1", 8333, ConnectionType::OUTBOUND_FULL_RELAY);
    auto p2 = Peer::create_outbound(fixture.io_context, nullptr, 0x12345678, 0, "10.0.0.2", 8333, ConnectionType::OUTBOUND_FULL_RELAY);
    int id1 = pm.add_peer(p1);
    int id2 = pm.add_peer(p2);
    REQUIRE(id1 >= 0);
    REQUIRE(id2 >= 0);
    REQUIRE(pm.outbound_count() == 2);

    // Attempt to add another full-relay outbound: should fail
    auto p3 = Peer::create_outbound(fixture.io_context, nullptr, 0x12345678, 0, "10.0.0.3", 8333, ConnectionType::OUTBOUND_FULL_RELAY);
    int id3 = pm.add_peer(p3);
    REQUIRE(id3 == -1);
    REQUIRE(pm.outbound_count() == 2);

    // Now add a feeler: should be accepted and not consume outbound_count
    auto pf = Peer::create_outbound(fixture.io_context, nullptr, 0x12345678, 0, "10.0.0.4", 8333, ConnectionType::FEELER);
    int idf = pm.add_peer(pf);
    REQUIRE(idf >= 0);

    // Outbound count remains at full-relay capacity, but total peer count increased
    REQUIRE(pm.outbound_count() == 2);
    REQUIRE(pm.peer_count() == 3);
}

TEST_CASE("ConnectionManager - Feeler lifetime is enforced", "[network][peer_manager][unit][feeler]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    // Add a feeler and artificially age it beyond lifetime
    auto feeler = Peer::create_outbound(fixture.io_context, nullptr, 0x12345678, 0, "10.0.0.11", 8333, ConnectionType::FEELER);
    int fid = pm.add_peer(feeler);
    REQUIRE(fid >= 0);

    // Backdate creation time by 5 minutes (use mockable time for consistency)
    pm.TestOnlySetPeerCreatedAt(fid, unicity::util::GetSteadyTime() - std::chrono::minutes(5));

    // Trigger periodic processing to enforce lifetime
    pm.process_periodic();

    // Feeler should be removed
    REQUIRE(pm.get_peer(fid) == nullptr);
}

TEST_CASE("ConnectionManager - disconnect_all removes all peers", "[network][peer_manager][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    auto p = fixture.create_test_peer("127.0.0.5", 8333);
    int id = pm.add_peer(p);
    REQUIRE(id >= 0);
    REQUIRE(pm.peer_count() == 1);

    pm.disconnect_all();
    REQUIRE(pm.peer_count() == 0);
}

TEST_CASE("ConnectionManager - Concurrent add_peer yields unique IDs", "[network][peer_manager][unit][concurrency]") {
    TestPeerFixture fixture;
    PeerLifecycleManager::Config cfg;
    cfg.max_full_relay_outbound = 10000;
    cfg.target_full_relay_outbound = 10000;
    cfg.max_block_relay_outbound = 0;
    cfg.target_block_relay_outbound = 0;
    PeerLifecycleManager pm(fixture.io_context, cfg);

    const int threads = 8;
    const int per_thread = 50;
    std::vector<std::thread> ts;
    std::mutex m;
    std::vector<int> ids;
    ts.reserve(threads);

    for (int t = 0; t < threads; ++t) {
        ts.emplace_back([&]{
            for (int i = 0; i < per_thread; ++i) {
                auto peer = fixture.create_test_peer("192.0.2." + std::to_string((i%200)+1), 8333);
                int id = pm.add_peer(peer);
                std::lock_guard<std::mutex> g(m);
                ids.push_back(id);
            }
        });
    }
    for (auto &th : ts) th.join();

    // All IDs should be non-negative and unique
    REQUIRE(ids.size() == static_cast<size_t>(threads * per_thread));
    std::set<int> uniq(ids.begin(), ids.end());
    REQUIRE(uniq.size() == ids.size());
    REQUIRE(pm.peer_count() == ids.size());
}

TEST_CASE("ConnectionManager - Config Defaults", "[network][peer_manager][unit]") {
    PeerLifecycleManager::Config config;

    // Total outbound = full-relay (8) + block-relay (2) = 10
    REQUIRE(config.max_full_relay_outbound == 8);
    REQUIRE(config.max_block_relay_outbound == 2);
    REQUIRE(config.max_outbound_peers == 10);
    REQUIRE(config.max_inbound_peers == 125);
    REQUIRE(config.target_full_relay_outbound == 8);
    REQUIRE(config.target_block_relay_outbound == 2);
}

TEST_CASE("ConnectionManager - Multiple Misbehavior Reports", "[network][peer_manager][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    auto peer1 = fixture.create_test_peer("192.168.1.1", 8333);
    auto peer2 = fixture.create_test_peer("192.168.1.2", 8333);

    int id1 = pm.add_peer(peer1);
    int id2 = pm.add_peer(peer2);

    SECTION("Independent misbehavior tracking") {
        pm.ReportLowWorkHeaders(id1);
        pm.ReportNonContinuousHeaders(id2);

        // With instant discourage, any misbehavior triggers disconnect
        REQUIRE(pm.IsMisbehaving(id1));
        REQUIRE(pm.IsMisbehaving(id2));
    }

    SECTION("Both peers should disconnect after misbehavior") {
        pm.ReportInvalidPoW(id1);
        pm.ReportLowWorkHeaders(id2);

        // With instant discourage, both peers should disconnect
        REQUIRE(pm.ShouldDisconnect(id1));
        REQUIRE(pm.ShouldDisconnect(id2));
    }
}

TEST_CASE("ConnectionManager - Duplicate invalid header tracking is per-peer", "[network][peer_manager][unit][duplicates]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    auto peerA = fixture.create_test_peer("10.0.0.1", 8333);
    auto peerB = fixture.create_test_peer("10.0.0.2", 8333);
    int idA = pm.add_peer(peerA);
    int idB = pm.add_peer(peerB);

    // Synthetic header hash
    uint256 h; // default zero; flip a byte to create non-null
    h.begin()[0] = 0x42;

    // Before noting, HasInvalidHeaderHash should be false for both peers
    REQUIRE_FALSE(pm.HasInvalidHeaderHash(idA, h));
    REQUIRE_FALSE(pm.HasInvalidHeaderHash(idB, h));

    // First invalid report for peerA (instant discourage) and record the hash
    pm.ReportInvalidHeader(idA, "bad-diffbits");
    pm.NoteInvalidHeaderHash(idA, h);
    REQUIRE(pm.IsMisbehaving(idA));

    // Simulate duplicate from same peer: guard prevents redundant processing
    // (HeaderSyncManager checks HasInvalidHeaderHash before calling Report...)
    REQUIRE(pm.HasInvalidHeaderHash(idA, h));
    // Should still be misbehaving (latched state)
    REQUIRE(pm.IsMisbehaving(idA));

    // Other peer has no record of this hash
    REQUIRE_FALSE(pm.HasInvalidHeaderHash(idB, h));
}

// =============================================================================
// remove_peer() Tests - Verifying address handling, mark_addr_good, discourage
// =============================================================================

TEST_CASE("remove_peer - misbehaving peer gets discouraged", "[network][peer_manager][remove_peer]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    auto peer = fixture.create_test_peer("93.184.216.34", 8333);
    int peer_id = pm.add_peer(peer);
    REQUIRE(peer_id >= 0);

    // Report misbehavior
    pm.ReportInvalidPoW(peer_id);
    REQUIRE(pm.IsMisbehaving(peer_id));

    pm.remove_peer(peer_id);

    // Verify peer was discouraged (check via IsDiscouraged)
    CHECK(pm.IsDiscouraged("93.184.216.34"));
}

TEST_CASE("remove_peer - failure metrics for failed outbound", "[network][peer_manager][remove_peer][metrics]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    // Get baseline metrics
    uint64_t baseline = pm.GetOutboundFailures();

    // Create outbound peer that fails to connect (successfully_connected=false)
    auto peer = Peer::create_outbound(
        fixture.io_context, nullptr, 0x12345678, 0,
        "93.184.216.34", 8333, ConnectionType::OUTBOUND_FULL_RELAY
    );
    // Don't set successfully_connected - simulates failed handshake

    int peer_id = pm.add_peer(peer);
    REQUIRE(peer_id >= 0);

    pm.remove_peer(peer_id);

    // Check failure metric incremented
    CHECK(pm.GetOutboundFailures() == baseline + 1);
}

TEST_CASE("remove_peer - failure metrics for failed feeler", "[network][peer_manager][remove_peer][metrics]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    uint64_t baseline = pm.GetFeelerFailures();

    // Create feeler that fails to connect
    auto peer = Peer::create_outbound(
        fixture.io_context, nullptr, 0x12345678, 0,
        "93.184.216.34", 8333, ConnectionType::FEELER
    );
    // Don't set successfully_connected

    int peer_id = pm.add_peer(peer);
    REQUIRE(peer_id >= 0);

    pm.remove_peer(peer_id);

    CHECK(pm.GetFeelerFailures() == baseline + 1);
}

TEST_CASE("remove_peer - successful outbound increments success metrics", "[network][peer_manager][remove_peer][metrics]") {
    // Note: Success metrics are incremented in HandleVerack, not remove_peer
    // This test verifies failure metrics are NOT incremented for successful peers
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    uint64_t baseline_failures = pm.GetOutboundFailures();

    auto peer = Peer::create_outbound(
        fixture.io_context, nullptr, 0x12345678, 0,
        "93.184.216.34", 8333, ConnectionType::OUTBOUND_FULL_RELAY
    );
    peer->set_successfully_connected_for_test(true);  // Simulates completed handshake

    int peer_id = pm.add_peer(peer);
    REQUIRE(peer_id >= 0);

    pm.remove_peer(peer_id);

    // Failure metric should NOT increment for successful connection
    CHECK(pm.GetOutboundFailures() == baseline_failures);
}

TEST_CASE("remove_peer - block-relay peer failure increments correct metric", "[network][peer_manager][remove_peer][metrics]") {
    TestPeerFixture fixture;
    PeerLifecycleManager::Config config;
    config.max_block_relay_outbound = 2;
    config.target_block_relay_outbound = 2;
    PeerLifecycleManager pm(fixture.io_context, config);

    uint64_t baseline = pm.GetOutboundFailures();

    // Create block-relay peer that fails handshake
    auto peer = Peer::create_outbound(
        fixture.io_context, nullptr, 0x12345678, 0,
        "93.184.216.34", 8333, ConnectionType::BLOCK_RELAY
    );
    // Don't set successfully_connected

    int peer_id = pm.add_peer(peer);
    REQUIRE(peer_id >= 0);

    pm.remove_peer(peer_id);

    // Block-relay failures count as outbound failures
    CHECK(pm.GetOutboundFailures() == baseline + 1);
}

// =============================================================================
// find_peer_by_address() Tests
// =============================================================================

TEST_CASE("find_peer_by_address - exact address:port match", "[network][peer_manager][find_peer]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    auto peer = Peer::create_outbound(
        fixture.io_context, nullptr, 0x12345678, 0,
        "93.184.216.34", 8333, ConnectionType::OUTBOUND_FULL_RELAY
    );
    int peer_id = pm.add_peer(peer);
    REQUIRE(peer_id >= 0);

    // Exact match should find the peer
    CHECK(pm.find_peer_by_address("93.184.216.34", 8333) == peer_id);
}

TEST_CASE("find_peer_by_address - address only (port=0)", "[network][peer_manager][find_peer]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    auto peer = Peer::create_outbound(
        fixture.io_context, nullptr, 0x12345678, 0,
        "93.184.216.34", 8333, ConnectionType::OUTBOUND_FULL_RELAY
    );
    int peer_id = pm.add_peer(peer);
    REQUIRE(peer_id >= 0);

    // port=0 should match any port
    CHECK(pm.find_peer_by_address("93.184.216.34", 0) == peer_id);
}

TEST_CASE("find_peer_by_address - wrong port returns -1", "[network][peer_manager][find_peer]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    auto peer = Peer::create_outbound(
        fixture.io_context, nullptr, 0x12345678, 0,
        "93.184.216.34", 8333, ConnectionType::OUTBOUND_FULL_RELAY
    );
    int peer_id = pm.add_peer(peer);
    REQUIRE(peer_id >= 0);

    // Wrong port should not find the peer
    CHECK(pm.find_peer_by_address("93.184.216.34", 9999) == -1);
}

TEST_CASE("find_peer_by_address - non-existent address returns -1", "[network][peer_manager][find_peer]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    auto peer = Peer::create_outbound(
        fixture.io_context, nullptr, 0x12345678, 0,
        "93.184.216.34", 8333, ConnectionType::OUTBOUND_FULL_RELAY
    );
    pm.add_peer(peer);

    // Different address should not be found
    CHECK(pm.find_peer_by_address("1.2.3.4", 0) == -1);
    CHECK(pm.find_peer_by_address("1.2.3.4", 8333) == -1);
}

TEST_CASE("find_peer_by_address - invalid address returns -1", "[network][peer_manager][find_peer]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    auto peer = Peer::create_outbound(
        fixture.io_context, nullptr, 0x12345678, 0,
        "93.184.216.34", 8333, ConnectionType::OUTBOUND_FULL_RELAY
    );
    pm.add_peer(peer);

    // Invalid addresses should return -1
    CHECK(pm.find_peer_by_address("not-an-ip", 0) == -1);
    CHECK(pm.find_peer_by_address("", 0) == -1);
    CHECK(pm.find_peer_by_address("999.999.999.999", 0) == -1);
}

TEST_CASE("find_peer_by_address - multiple peers same IP different ports", "[network][peer_manager][find_peer]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    // Add two peers with same IP but different ports
    auto peer1 = Peer::create_outbound(
        fixture.io_context, nullptr, 0x12345678, 0,
        "93.184.216.34", 8333, ConnectionType::OUTBOUND_FULL_RELAY
    );
    auto peer2 = Peer::create_outbound(
        fixture.io_context, nullptr, 0x12345678, 0,
        "93.184.216.34", 9999, ConnectionType::OUTBOUND_FULL_RELAY
    );

    int id1 = pm.add_peer(peer1);
    int id2 = pm.add_peer(peer2);
    REQUIRE(id1 >= 0);
    REQUIRE(id2 >= 0);
    REQUIRE(id1 != id2);

    // Exact port match should find correct peer
    CHECK(pm.find_peer_by_address("93.184.216.34", 8333) == id1);
    CHECK(pm.find_peer_by_address("93.184.216.34", 9999) == id2);

    // port=0 should find one of them (first match)
    int found = pm.find_peer_by_address("93.184.216.34", 0);
    CHECK((found == id1 || found == id2));
}

TEST_CASE("find_peer_by_address - empty peer list returns -1", "[network][peer_manager][find_peer]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    // No peers added
    CHECK(pm.find_peer_by_address("93.184.216.34", 0) == -1);
    CHECK(pm.find_peer_by_address("93.184.216.34", 8333) == -1);
}

TEST_CASE("find_peer_by_address - finds peer after removal of others", "[network][peer_manager][find_peer]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    auto peer1 = Peer::create_outbound(
        fixture.io_context, nullptr, 0x12345678, 0,
        "1.1.1.1", 8333, ConnectionType::OUTBOUND_FULL_RELAY
    );
    auto peer2 = Peer::create_outbound(
        fixture.io_context, nullptr, 0x12345678, 0,
        "2.2.2.2", 8333, ConnectionType::OUTBOUND_FULL_RELAY
    );

    int id1 = pm.add_peer(peer1);
    int id2 = pm.add_peer(peer2);
    REQUIRE(id1 >= 0);
    REQUIRE(id2 >= 0);

    // Remove first peer
    pm.remove_peer(id1);

    // First peer should not be found
    CHECK(pm.find_peer_by_address("1.1.1.1", 0) == -1);

    // Second peer should still be found
    CHECK(pm.find_peer_by_address("2.2.2.2", 0) == id2);
}

// === CheckIncomingNonce Tests ===

TEST_CASE("CheckIncomingNonce - rejects self-connection (nonce == local_nonce)", "[network][peer_manager][nonce][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager::Config cfg;
    PeerLifecycleManager pm(fixture.io_context, cfg);

    uint64_t local_nonce = 0x1234567890ABCDEF;

    // Incoming nonce matches local nonce - self-connection
    CHECK_FALSE(pm.CheckIncomingNonce(local_nonce, local_nonce));

    // Different nonce should be accepted (no peers yet)
    CHECK(pm.CheckIncomingNonce(0xDEADBEEF, local_nonce));
}

TEST_CASE("CheckIncomingNonce - rejects nonce collision with existing peer", "[network][peer_manager][nonce][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager::Config cfg;
    PeerLifecycleManager pm(fixture.io_context, cfg);

    uint64_t local_nonce = 0x1111111111111111;
    uint64_t peer_remote_nonce = 0x2222222222222222;

    // Create a peer with a known remote nonce
    auto peer = Peer::create_outbound(
        fixture.io_context, nullptr, 0x12345678, 0,
        "1.2.3.4", 8333, ConnectionType::OUTBOUND_FULL_RELAY
    );
    peer->set_successfully_connected_for_test(true);
    peer->set_peer_nonce_for_test(peer_remote_nonce);

    int id = pm.add_peer(peer);
    REQUIRE(id >= 0);

    // Incoming nonce matches existing peer's remote nonce - collision
    CHECK_FALSE(pm.CheckIncomingNonce(peer_remote_nonce, local_nonce));

    // Different nonce should be accepted
    CHECK(pm.CheckIncomingNonce(0x3333333333333333, local_nonce));
}

TEST_CASE("CheckIncomingNonce - skips peers without completed handshake", "[network][peer_manager][nonce][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager::Config cfg;
    PeerLifecycleManager pm(fixture.io_context, cfg);

    uint64_t local_nonce = 0x1111111111111111;
    uint64_t peer_remote_nonce = 0x2222222222222222;

    // Create a peer that hasn't completed handshake
    auto peer = Peer::create_outbound(
        fixture.io_context, nullptr, 0x12345678, 0,
        "1.2.3.4", 8333, ConnectionType::OUTBOUND_FULL_RELAY
    );
    // Don't set successfully_connected - defaults to false
    peer->set_peer_nonce_for_test(peer_remote_nonce);

    int id = pm.add_peer(peer);
    REQUIRE(id >= 0);

    // Peer hasn't completed handshake, so its nonce should NOT be checked
    // Even though incoming nonce matches peer's nonce, it should be accepted
    CHECK(pm.CheckIncomingNonce(peer_remote_nonce, local_nonce));
}

TEST_CASE("CheckIncomingNonce - accepts unique nonce with multiple peers", "[network][peer_manager][nonce][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager::Config cfg;
    PeerLifecycleManager pm(fixture.io_context, cfg);

    uint64_t local_nonce = 0x1111111111111111;

    // Create multiple peers with different nonces
    for (int i = 0; i < 5; ++i) {
        auto peer = Peer::create_outbound(
            fixture.io_context, nullptr, 0x12345678, 0,
            "10.0.0." + std::to_string(i + 1), 8333, ConnectionType::OUTBOUND_FULL_RELAY
        );
        peer->set_successfully_connected_for_test(true);
        peer->set_peer_nonce_for_test(0x1000 + i);  // Nonces: 0x1000, 0x1001, 0x1002, 0x1003, 0x1004
        pm.add_peer(peer);
    }

    // Unique nonce should be accepted
    CHECK(pm.CheckIncomingNonce(0x9999, local_nonce));

    // But collision with any existing peer should be rejected
    CHECK_FALSE(pm.CheckIncomingNonce(0x1000, local_nonce));
    CHECK_FALSE(pm.CheckIncomingNonce(0x1002, local_nonce));
    CHECK_FALSE(pm.CheckIncomingNonce(0x1004, local_nonce));
}

TEST_CASE("CheckIncomingNonce - checks all peers regardless of direction", "[network][peer_manager][nonce][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager::Config cfg;
    PeerLifecycleManager pm(fixture.io_context, cfg);

    uint64_t local_nonce = 0x1111111111111111;

    // Create two peers with different nonces
    auto peer1 = Peer::create_outbound(
        fixture.io_context, nullptr, 0x12345678, 0,
        "1.1.1.1", 8333, ConnectionType::OUTBOUND_FULL_RELAY
    );
    peer1->set_successfully_connected_for_test(true);
    peer1->set_peer_nonce_for_test(0xAAAA);
    pm.add_peer(peer1);

    auto peer2 = Peer::create_outbound(
        fixture.io_context, nullptr, 0x12345678, 0,
        "2.2.2.2", 8333, ConnectionType::OUTBOUND_FULL_RELAY
    );
    peer2->set_successfully_connected_for_test(true);
    peer2->set_peer_nonce_for_test(0xBBBB);
    pm.add_peer(peer2);

    // Both nonces should cause rejection (Bitcoin Core checks ALL peers)
    CHECK_FALSE(pm.CheckIncomingNonce(0xAAAA, local_nonce));
    CHECK_FALSE(pm.CheckIncomingNonce(0xBBBB, local_nonce));

    // Unique nonce should be accepted
    CHECK(pm.CheckIncomingNonce(0xCCCC, local_nonce));
}

// =============================================================================
// HandleVerack Tests
// =============================================================================

TEST_CASE("HandleVerack - returns true for null peer", "[network][peer_manager][verack][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager::Config config;
    PeerLifecycleManager pm(fixture.io_context, config);

    // Null peer should return true (no error, just ignored)
    CHECK(pm.HandleVerack(nullptr));
}

TEST_CASE("HandleVerack - returns true for disconnected peer", "[network][peer_manager][verack][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager::Config config;
    PeerLifecycleManager pm(fixture.io_context, config);

    auto peer = Peer::create_outbound(
        fixture.io_context, nullptr, 0x12345678, 0,
        "10.0.0.1", 8333, ConnectionType::OUTBOUND_FULL_RELAY
    );
    // Peer created with nullptr transport starts DISCONNECTED
    CHECK(peer->state() == PeerConnectionState::DISCONNECTED);

    // Disconnected peer should return true (no error, just ignored)
    CHECK(pm.HandleVerack(peer));
}

TEST_CASE("HandleVerack - GETADDR sent for full-relay outbound peer", "[network][peer_manager][verack][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager::Config config;
    PeerLifecycleManager pm(fixture.io_context, config);

    auto peer = Peer::create_outbound(
        fixture.io_context, nullptr, 0x12345678, 0,
        "10.0.0.1", 8333, ConnectionType::OUTBOUND_FULL_RELAY
    );
    peer->set_state_for_test(PeerConnectionState::READY);
    peer->set_successfully_connected_for_test(true);
    pm.add_peer(peer);

    CHECK_FALSE(peer->has_sent_getaddr());

    // HandleVerack should mark getaddr as sent for full-relay outbound
    pm.HandleVerack(peer);

    CHECK(peer->has_sent_getaddr());
}

TEST_CASE("HandleVerack - GETADDR NOT sent for block-relay peer", "[network][peer_manager][verack][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager::Config config;
    PeerLifecycleManager pm(fixture.io_context, config);

    auto peer = Peer::create_outbound(
        fixture.io_context, nullptr, 0x12345678, 0,
        "10.0.0.1", 8333, ConnectionType::BLOCK_RELAY
    );
    peer->set_state_for_test(PeerConnectionState::READY);
    peer->set_successfully_connected_for_test(true);
    pm.add_peer(peer);

    CHECK_FALSE(peer->has_sent_getaddr());

    // HandleVerack should NOT send getaddr to block-relay peers
    pm.HandleVerack(peer);

    CHECK_FALSE(peer->has_sent_getaddr());
}

TEST_CASE("HandleVerack - GETADDR NOT sent for inbound peer", "[network][peer_manager][verack][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager::Config config;
    PeerLifecycleManager pm(fixture.io_context, config);

    auto peer = Peer::create_inbound(
        fixture.io_context, nullptr, 0x12345678, 0
    );
    peer->set_state_for_test(PeerConnectionState::READY);
    peer->set_successfully_connected_for_test(true);
    pm.add_peer(peer);

    CHECK_FALSE(peer->has_sent_getaddr());

    // HandleVerack should NOT send getaddr to inbound peers
    pm.HandleVerack(peer);

    CHECK_FALSE(peer->has_sent_getaddr());
}

TEST_CASE("HandleVerack - GETADDR NOT sent twice", "[network][peer_manager][verack][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager::Config config;
    PeerLifecycleManager pm(fixture.io_context, config);

    auto peer = Peer::create_outbound(
        fixture.io_context, nullptr, 0x12345678, 0,
        "10.0.0.1", 8333, ConnectionType::OUTBOUND_FULL_RELAY
    );
    peer->set_state_for_test(PeerConnectionState::READY);
    peer->set_successfully_connected_for_test(true);
    pm.add_peer(peer);

    // First HandleVerack marks getaddr sent
    pm.HandleVerack(peer);
    CHECK(peer->has_sent_getaddr());

    // Manually reset state for second call test
    // (In practice this wouldn't happen, but tests the guard)
    // The peer already has getaddr_sent = true, so calling again shouldn't try to send
    pm.HandleVerack(peer);

    // Still marked as sent (no crash, no duplicate)
    CHECK(peer->has_sent_getaddr());
}

TEST_CASE("HandleVerack - metrics incremented for outbound success", "[network][peer_manager][verack][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager::Config config;
    PeerLifecycleManager pm(fixture.io_context, config);

    auto peer = Peer::create_outbound(
        fixture.io_context, nullptr, 0x12345678, 0,
        "10.0.0.1", 8333, ConnectionType::OUTBOUND_FULL_RELAY
    );
    peer->set_state_for_test(PeerConnectionState::READY);
    peer->set_successfully_connected_for_test(true);
    pm.add_peer(peer);

    uint64_t before = pm.GetOutboundSuccesses();
    pm.HandleVerack(peer);
    uint64_t after = pm.GetOutboundSuccesses();

    CHECK(after == before + 1);
}

TEST_CASE("HandleVerack - metrics incremented for feeler success", "[network][peer_manager][verack][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager::Config config;
    PeerLifecycleManager pm(fixture.io_context, config);

    auto peer = Peer::create_outbound(
        fixture.io_context, nullptr, 0x12345678, 0,
        "10.0.0.1", 8333, ConnectionType::FEELER
    );
    peer->set_state_for_test(PeerConnectionState::READY);
    peer->set_successfully_connected_for_test(true);
    pm.add_peer(peer);

    uint64_t before = pm.GetFeelerSuccesses();
    pm.HandleVerack(peer);
    uint64_t after = pm.GetFeelerSuccesses();

    CHECK(after == before + 1);
}

TEST_CASE("HandleVerack - Good() called for block-relay peer (Bitcoin Core parity)", "[network][peer_manager][verack][unit]") {
    // This test verifies the fix: block-relay peers SHOULD have Good() called
    // to move their addresses from NEW to TRIED table (prevents eviction)
    TestPeerFixture fixture;
    PeerLifecycleManager::Config config;
    PeerLifecycleManager pm(fixture.io_context, config);

    // Create discovery manager and wire it up
    PeerDiscoveryManager discovery(&pm);

    // Add address to NEW table first (Good() only promotes addresses already in addrman)
    // Use routable IP (not 10.x.x.x private)
    NetworkAddress addr;
    addr.services = NODE_NETWORK;
    addr.port = 8333;
    addr.ip.fill(0);
    addr.ip[10] = 0xFF; addr.ip[11] = 0xFF;  // IPv4-mapped
    addr.ip[12] = 193; addr.ip[13] = 0; addr.ip[14] = 0; addr.ip[15] = 1;  // 193.0.0.1

    discovery.addr_manager_for_test().add(addr);
    CHECK(discovery.addr_manager_for_test().new_count() == 1);
    CHECK(discovery.addr_manager_for_test().tried_count() == 0);

    // Create block-relay peer for the same address
    auto peer = Peer::create_outbound(
        fixture.io_context, nullptr, magic::REGTEST, 0,
        "193.0.0.1", 8333, ConnectionType::BLOCK_RELAY
    );
    peer->set_state_for_test(PeerConnectionState::READY);
    peer->set_successfully_connected_for_test(true);
    pm.add_peer(peer);

    // HandleVerack should call Good() for block-relay peer
    pm.HandleVerack(peer);

    // Address should have moved from NEW to TRIED
    CHECK(discovery.addr_manager_for_test().new_count() == 0);
    CHECK(discovery.addr_manager_for_test().tried_count() == 1);
}

TEST_CASE("HandleVerack - Good() called for full-relay peer", "[network][peer_manager][verack][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager::Config config;
    PeerLifecycleManager pm(fixture.io_context, config);

    // Create discovery manager and wire it up
    PeerDiscoveryManager discovery(&pm);

    // Add address to NEW table
    NetworkAddress addr;
    addr.services = NODE_NETWORK;
    addr.port = 8333;
    addr.ip.fill(0);
    addr.ip[10] = 0xFF; addr.ip[11] = 0xFF;
    addr.ip[12] = 194; addr.ip[13] = 0; addr.ip[14] = 0; addr.ip[15] = 1;  // 194.0.0.1

    discovery.addr_manager_for_test().add(addr);
    CHECK(discovery.addr_manager_for_test().new_count() == 1);
    CHECK(discovery.addr_manager_for_test().tried_count() == 0);

    // Create full-relay peer
    auto peer = Peer::create_outbound(
        fixture.io_context, nullptr, magic::REGTEST, 0,
        "194.0.0.1", 8333, ConnectionType::OUTBOUND_FULL_RELAY
    );
    peer->set_state_for_test(PeerConnectionState::READY);
    peer->set_successfully_connected_for_test(true);
    pm.add_peer(peer);

    pm.HandleVerack(peer);

    // Address should have moved from NEW to TRIED
    CHECK(discovery.addr_manager_for_test().new_count() == 0);
    CHECK(discovery.addr_manager_for_test().tried_count() == 1);
}

TEST_CASE("HandleVerack - Good() NOT called for inbound peer", "[network][peer_manager][verack][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager::Config config;
    PeerLifecycleManager pm(fixture.io_context, config);

    // Create discovery manager and wire it up
    PeerDiscoveryManager discovery(&pm);

    // Add address to NEW table
    NetworkAddress addr;
    addr.services = NODE_NETWORK;
    addr.port = 8333;
    addr.ip.fill(0);
    addr.ip[10] = 0xFF; addr.ip[11] = 0xFF;
    addr.ip[12] = 195; addr.ip[13] = 0; addr.ip[14] = 0; addr.ip[15] = 1;  // 195.0.0.1

    discovery.addr_manager_for_test().add(addr);
    CHECK(discovery.addr_manager_for_test().new_count() == 1);

    // Create inbound peer
    auto peer = Peer::create_inbound(
        fixture.io_context, nullptr, magic::REGTEST, 0
    );
    peer->set_state_for_test(PeerConnectionState::READY);
    peer->set_successfully_connected_for_test(true);
    pm.add_peer(peer);

    pm.HandleVerack(peer);

    // Address should still be in NEW (Good() not called for inbound)
    CHECK(discovery.addr_manager_for_test().new_count() == 1);
    CHECK(discovery.addr_manager_for_test().tried_count() == 0);
}

// ============================================================================
// Tests for get_inbound_peers()
// ============================================================================

TEST_CASE("get_inbound_peers - returns empty vector when no peers", "[network][peer_manager][inbound][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    auto inbound = pm.get_inbound_peers();
    CHECK(inbound.empty());
}

TEST_CASE("get_inbound_peers - returns only inbound peers", "[network][peer_manager][inbound][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    // Add outbound peer (with valid address)
    auto outbound = Peer::create_outbound(
        fixture.io_context, nullptr, magic::REGTEST, 0,
        "10.0.0.1", 8333, ConnectionType::OUTBOUND_FULL_RELAY
    );
    pm.add_peer(outbound, NetPermissionFlags::None, "10.0.0.1");

    // Add inbound peer (must provide valid address since transport is nullptr)
    auto inbound1 = Peer::create_inbound(
        fixture.io_context, nullptr, magic::REGTEST, 0
    );
    pm.add_peer(inbound1, NetPermissionFlags::None, "10.0.0.2");

    // Add another inbound peer
    auto inbound2 = Peer::create_inbound(
        fixture.io_context, nullptr, magic::REGTEST, 0
    );
    pm.add_peer(inbound2, NetPermissionFlags::None, "10.0.0.3");

    auto result = pm.get_inbound_peers();
    CHECK(result.size() == 2);

    // Verify all returned peers are inbound
    for (const auto& peer : result) {
        CHECK(peer->is_inbound());
    }
}

TEST_CASE("get_inbound_peers - sorted by peer ID", "[network][peer_manager][inbound][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    // Add multiple inbound peers (use different /16 netgroups to avoid per-netgroup limit)
    std::vector<int> ids;
    for (int i = 0; i < 5; ++i) {
        auto peer = Peer::create_inbound(
            fixture.io_context, nullptr, magic::REGTEST, 0
        );
        // Use different /16 netgroups: 10.0.x.1, 10.1.x.1, 10.2.x.1, etc.
        std::string addr = "10." + std::to_string(i) + ".0.1";
        int id = pm.add_peer(peer, NetPermissionFlags::None, addr);
        REQUIRE(id >= 0);  // Ensure peer was added
        ids.push_back(id);
    }

    auto result = pm.get_inbound_peers();
    REQUIRE(result.size() == 5);

    // Verify sorted by ID
    for (size_t i = 1; i < result.size(); ++i) {
        CHECK(result[i-1]->id() < result[i]->id());
    }
}

// ============================================================================
// Tests for discouraged peer rejection
// ============================================================================

TEST_CASE("add_peer - rejects discouraged outbound address", "[network][peer_manager][discourage][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    // Discourage an address
    pm.Discourage("10.0.0.99");

    // Try to add outbound peer to discouraged address
    auto peer = Peer::create_outbound(
        fixture.io_context, nullptr, magic::REGTEST, 0,
        "10.0.0.99", 8333, ConnectionType::OUTBOUND_FULL_RELAY
    );

    int id = pm.add_peer(peer, NetPermissionFlags::None, "10.0.0.99");
    CHECK(id == -1);  // Should be rejected
    CHECK(pm.peer_count() == 0);
}

TEST_CASE("add_peer - accepts inbound from discouraged address", "[network][peer_manager][discourage][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    // Discourage an address
    pm.Discourage("10.0.0.99");

    // Inbound peers from discouraged addresses ARE accepted
    // (they can connect to us, we just won't connect to them)
    auto peer = Peer::create_inbound(
        fixture.io_context, nullptr, magic::REGTEST, 0
    );

    int id = pm.add_peer(peer, NetPermissionFlags::None, "10.0.0.99");
    CHECK(id >= 0);  // Should be accepted
    CHECK(pm.peer_count() == 1);
}

// ============================================================================
// Tests for pending connection count functions
// ============================================================================

TEST_CASE("pending connection counts - initial state is zero", "[network][peer_manager][pending][unit]") {
    TestPeerFixture fixture;
    PeerLifecycleManager pm(fixture.io_context);

    CHECK(pm.pending_full_relay_count() == 0);
    CHECK(pm.pending_block_relay_count() == 0);
}

// ============================================================================
// Tests for inbound peer limit and eviction
// ============================================================================

TEST_CASE("add_peer - respects inbound limit", "[network][peer_manager][limits][unit]") {
    TestPeerFixture fixture;

    PeerLifecycleManager::Config config;
    config.max_inbound_peers = 2;  // Very low limit for testing

    PeerLifecycleManager pm(fixture.io_context, config);

    // Add peers up to limit (must provide valid addresses)
    auto peer1 = Peer::create_inbound(fixture.io_context, nullptr, magic::REGTEST, 0);
    auto peer2 = Peer::create_inbound(fixture.io_context, nullptr, magic::REGTEST, 0);

    CHECK(pm.add_peer(peer1, NetPermissionFlags::None, "10.0.0.1") >= 0);
    CHECK(pm.add_peer(peer2, NetPermissionFlags::None, "10.0.0.2") >= 0);
    CHECK(pm.inbound_count() == 2);
    CHECK(pm.can_accept_inbound() == false);
}
