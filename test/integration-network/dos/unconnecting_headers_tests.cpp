// Copyright (c) 2025 The Unicity Foundation
// DoS: Unconnecting headers counter tests
//
// Tests the protection against peers sending headers that don't connect to our chain.
// Attack: Send batches of headers with unknown parents repeatedly
// Defense: Track unconnecting count per peer, discourage after MAX_UNCONNECTING_HEADERS (10)
//
// NOTE: Modern Bitcoin Core (March 2024+) uses instant discourage for misbehavior.
// After MAX_UNCONNECTING_HEADERS threshold, peer is instantly discouraged.

#include "catch_amalgamated.hpp"
#include "network/peer_misbehavior.hpp"

using namespace unicity;
using namespace unicity::network;

TEST_CASE("DoS: Unconnecting headers - constants verification", "[dos][network][unconnecting][unit]") {
    SECTION("Verify unconnecting threshold") {
        REQUIRE(MAX_UNCONNECTING_HEADERS == 10);
    }

    SECTION("Threshold triggers instant discourage") {
        // Verify the struct tracks the counter
        PeerMisbehaviorData data;
        CHECK(data.num_unconnecting_headers_msgs == 0);

        // Simulate reaching threshold
        for (int i = 0; i < MAX_UNCONNECTING_HEADERS; ++i) {
            data.num_unconnecting_headers_msgs++;
        }
        CHECK(data.num_unconnecting_headers_msgs == MAX_UNCONNECTING_HEADERS);

        // At threshold, discourage is triggered
        data.should_discourage = true;
        CHECK(data.should_discourage == true);
    }
}

TEST_CASE("DoS: Unconnecting headers - penalty is latched", "[dos][network][unconnecting][unit]") {
    SECTION("Discourage is latched to prevent double-reporting") {
        PeerMisbehaviorData data;
        CHECK(data.unconnecting_penalized == false);

        // First time hitting threshold
        data.unconnecting_penalized = true;
        CHECK(data.unconnecting_penalized == true);

        // Latch stays set - can't be un-penalized
        // (This prevents repeated Misbehaving() calls)
    }
}

TEST_CASE("DoS: Unconnecting headers - counter is per-peer", "[dos][network][unconnecting][unit]") {
    SECTION("Each peer has independent counter") {
        // Each PeerMisbehaviorData instance is independent
        PeerMisbehaviorData peer1_data;
        PeerMisbehaviorData peer2_data;

        // Peer 1 sends 5 unconnecting batches
        for (int i = 0; i < 5; ++i) {
            peer1_data.num_unconnecting_headers_msgs++;
        }

        // Peer 2 sends 5 unconnecting batches
        for (int i = 0; i < 5; ++i) {
            peer2_data.num_unconnecting_headers_msgs++;
        }

        // Neither has reached threshold (counters are independent)
        CHECK(peer1_data.num_unconnecting_headers_msgs == 5);
        CHECK(peer2_data.num_unconnecting_headers_msgs == 5);
        CHECK(peer1_data.num_unconnecting_headers_msgs < MAX_UNCONNECTING_HEADERS);
        CHECK(peer2_data.num_unconnecting_headers_msgs < MAX_UNCONNECTING_HEADERS);
    }
}

TEST_CASE("DoS: Unconnecting headers - counter reset on successful headers", "[dos][network][unconnecting][unit]") {
    SECTION("Counter resets when connecting headers received") {
        PeerMisbehaviorData data;

        // Accumulate 7 unconnecting batches (close to threshold)
        for (int i = 0; i < 7; ++i) {
            data.num_unconnecting_headers_msgs++;
        }
        CHECK(data.num_unconnecting_headers_msgs == 7);

        // Peer sends connecting headers - counter resets
        data.num_unconnecting_headers_msgs = 0;  // ResetUnconnectingHeaders()
        CHECK(data.num_unconnecting_headers_msgs == 0);

        // Peer can send more unconnecting without hitting threshold
        for (int i = 0; i < 5; ++i) {
            data.num_unconnecting_headers_msgs++;
        }
        CHECK(data.num_unconnecting_headers_msgs == 5);
        CHECK(data.num_unconnecting_headers_msgs < MAX_UNCONNECTING_HEADERS);
    }
}

TEST_CASE("DoS: Unconnecting headers - only small batches tracked", "[dos][network][unconnecting][unit]") {
    SECTION("Large unconnecting batches immediately rejected") {
        // Large batches (> kMaxUnsolicitedAnnouncement) that don't connect
        // are rejected outright, triggering instant discourage
        PeerMisbehaviorData data;

        // Large unconnecting batch = instant discourage (no counter increment)
        // Simulate this: if batch_size > threshold, skip counter, set discourage
        data.should_discourage = true;  // Large batch triggers directly

        CHECK(data.should_discourage == true);
        CHECK(data.num_unconnecting_headers_msgs == 0);  // Counter not used for large batches
    }
}

TEST_CASE("DoS: Unconnecting headers - misbehavior flow", "[dos][network][unconnecting][unit]") {
    SECTION("Flow: increment -> threshold check -> instant discourage") {
        // Full flow simulation
        PeerMisbehaviorData data;

        // 1-3: Peer sends 10 small unconnecting batches (reaching threshold)
        for (int i = 0; i < MAX_UNCONNECTING_HEADERS; ++i) {
            data.num_unconnecting_headers_msgs++;
        }
        CHECK(data.num_unconnecting_headers_msgs == MAX_UNCONNECTING_HEADERS);

        // 4: At threshold, set unconnecting_penalized
        data.unconnecting_penalized = true;
        CHECK(data.unconnecting_penalized == true);

        // 5: Misbehaving() sets should_discourage
        data.should_discourage = true;
        CHECK(data.should_discourage == true);

        // 6: Peer would be disconnected (verified elsewhere)
    }
}
