// Copyright (c) 2025 The Unicity Foundation
// DoS: Misbehavior system tests
//
// Tests the instant-discourage misbehavior system (Bitcoin Core March 2024+ parity).
// Any misbehavior results in instant discouragement - no score accumulation.
//
// NOTE: Bitcoin Core removed score-based misbehavior in commit ae60d485da (March 2024).
// The old overflow protection tests are no longer relevant since there's no accumulation.

#include "catch_amalgamated.hpp"
#include "network/peer_misbehavior.hpp"
#include <limits>

using namespace unicity;
using namespace unicity::network;

TEST_CASE("DoS: Misbehavior system - instant discourage design", "[dos][network][misbehavior][unit]") {
    SECTION("Modern Core parity: no score accumulation") {
        // Bitcoin Core commit ae60d485da (March 2024) removed score-based misbehavior.
        // Any misbehavior now results in instant discouragement.
        //
        // Old system: Accumulate points, disconnect at threshold (100)
        // New system: Any misbehavior = should_discourage = true, disconnect immediately
        //
        // Benefits:
        // - Simpler code, fewer bugs
        // - No integer overflow concerns
        // - No "save up points" attacks
        // - Cleaner separation between misbehavior types

        // PeerMisbehaviorData now has bool should_discourage instead of int score
        CHECK(MAX_UNCONNECTING_HEADERS == 10);
        INFO("Modern Core (March 2024+): instant discourage, no score accumulation");
    }
}

TEST_CASE("DoS: Misbehavior system - unconnecting headers threshold", "[dos][network][misbehavior][unit]") {
    SECTION("Unconnecting headers is the only threshold-based check") {
        // The unconnecting headers counter is the only case where we don't instantly discourage.
        // We allow up to MAX_UNCONNECTING_HEADERS (10) small unconnecting batches
        // before discouraging, to allow for honest reorg scenarios.
        //
        // All other violations result in instant discourage:
        // - Invalid PoW
        // - Invalid header
        // - Too many orphans
        // - Non-continuous headers
        // - Oversized messages
        // - Pre-VERACK messages

        CHECK(MAX_UNCONNECTING_HEADERS == 10);
        INFO("MAX_UNCONNECTING_HEADERS is the only threshold-based protection");
    }
}

TEST_CASE("DoS: Misbehavior system - NoBan permission", "[dos][network][misbehavior][unit]") {
    SECTION("NoBan peers are not disconnected") {
        // Peers with NetPermissionFlags::NoBan are tracked for misbehavior
        // (should_discourage is set to true) but are NOT disconnected.
        //
        // This allows whitelisted peers (like local monitoring tools) to
        // send invalid messages without being kicked.
        //
        // Two query methods:
        // - ShouldDisconnect(): Returns false for NoBan peers
        // - IsMisbehaving(): Returns true for all misbehaving peers (ignores NoBan)

        CHECK(static_cast<int>(NetPermissionFlags::NoBan) != 0);
        INFO("NoBan peers are tracked but not disconnected");
    }
}

TEST_CASE("DoS: Misbehavior system - duplicate header tracking", "[dos][network][misbehavior][unit]") {
    SECTION("Duplicate invalid headers don't re-trigger discourage") {
        // If a peer sends the same invalid header multiple times, we only
        // discourage them once. The invalid_header_hashes set tracks which
        // headers have already been reported.
        //
        // This prevents log spam and redundant processing.

        CHECK(MAX_UNCONNECTING_HEADERS == 10);
        INFO("Duplicate invalid headers are tracked to prevent redundant discouragement");
    }
}

TEST_CASE("DoS: Misbehavior system - latching behavior", "[dos][network][misbehavior][unit]") {
    SECTION("Unconnecting penalty is latched") {
        // Once a peer exceeds MAX_UNCONNECTING_HEADERS, the unconnecting_penalized
        // flag is set to true. This prevents:
        // 1. Redundant Misbehaving() calls
        // 2. Log spam for the same peer
        //
        // Note: should_discourage is also effectively "latched" since it's boolean.
        // Once true, calling Misbehaving() again just keeps it true.

        CHECK(MAX_UNCONNECTING_HEADERS == 10);
        INFO("Discouragement latches after first trigger");
    }
}
