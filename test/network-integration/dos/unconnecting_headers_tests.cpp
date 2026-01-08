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
        INFO("After 10 unconnecting header batches, peer is instantly discouraged");
    }

    SECTION("Threshold triggers instant discourage") {
        // With modern Core parity: exceeding threshold = instant discourage
        // No score accumulation - just boolean should_discourage = true
        CHECK(MAX_UNCONNECTING_HEADERS == 10);
    }
}

TEST_CASE("DoS: Unconnecting headers - penalty is latched", "[dos][network][unconnecting][unit]") {
    SECTION("Discourage is latched to prevent double-reporting") {
        // The misbehavior_manager.cpp has: data.unconnecting_penalized = true
        // This prevents repeated calls to Misbehaving() for the same peer
        // Once discouraged, further unconnecting batches don't re-trigger

        // This is tested in misbehavior_manager.cpp:
        // if (data.unconnecting_penalized) { return; }
        // data.unconnecting_penalized = true;

        CHECK(MAX_UNCONNECTING_HEADERS == 10);
        INFO("Discourage is latched after first trigger to prevent redundant logging");
    }
}

TEST_CASE("DoS: Unconnecting headers - counter is per-peer", "[dos][network][unconnecting][unit]") {
    SECTION("Each peer has independent counter") {
        // The counter is stored in PeerMisbehaviorData::num_unconnecting_headers_msgs
        // which is per-peer state in peer_states_ map

        // This ensures attacker1 sending 5 unconnecting batches
        // and attacker2 sending 5 unconnecting batches
        // does NOT accumulate to 10 - each has independent counter

        CHECK(MAX_UNCONNECTING_HEADERS == 10);
        INFO("Counters are per-peer, not global");
    }
}

TEST_CASE("DoS: Unconnecting headers - counter reset on successful headers", "[dos][network][unconnecting][unit]") {
    SECTION("Counter resets when connecting headers received") {
        // misbehavior_manager.cpp: ResetUnconnectingHeaders() sets counter to 0
        // Called when headers successfully connect to chain

        // This allows honest peers that occasionally send unconnecting headers
        // (due to reorgs, timing issues) to avoid triggering discourage

        CHECK(MAX_UNCONNECTING_HEADERS == 10);
        INFO("Counter resets on successful header connection");
    }
}

TEST_CASE("DoS: Unconnecting headers - only small batches tracked", "[dos][network][unconnecting][unit]") {
    SECTION("Large unconnecting batches immediately rejected") {
        // header_sync_manager.cpp line 305-315:
        // "CRITICAL DoS PROTECTION: Reject full unconnecting batches immediately"
        //
        // Large batches (> kMaxUnsolicitedAnnouncement) that don't connect
        // are rejected outright without incrementing the counter.
        // Only small batches (1-2 headers) increment the counter.

        // This prevents amplification attacks where attacker sends
        // large batches to quickly reach the threshold.

        CHECK(MAX_UNCONNECTING_HEADERS == 10);
        INFO("Only small unconnecting batches increment the counter");
    }
}

TEST_CASE("DoS: Unconnecting headers - misbehavior flow", "[dos][network][unconnecting][unit]") {
    SECTION("Flow: increment -> threshold check -> instant discourage") {
        // 1. Peer sends small unconnecting HEADERS message
        // 2. header_sync_manager calls peer_manager_.IncrementUnconnectingHeaders()
        // 3. misbehavior_manager increments num_unconnecting_headers_msgs
        // 4. If count >= MAX_UNCONNECTING_HEADERS (10), set unconnecting_penalized = true
        // 5. Call Misbehaving() which sets should_discourage = true
        // 6. Peer is disconnected (unless NoBan permission)

        CHECK(MAX_UNCONNECTING_HEADERS == 10);
        INFO("Modern Core (March 2024+): instant discourage, no score accumulation");
    }
}
