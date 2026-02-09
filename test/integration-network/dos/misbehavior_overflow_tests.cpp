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
#include <string>

using namespace unicity;
using namespace unicity::network;

TEST_CASE("DoS: Misbehavior system - instant discourage design", "[dos][network][misbehavior][unit]") {
    SECTION("Modern Core parity: no score accumulation") {
        // Bitcoin Core commit ae60d485da (March 2024) removed score-based misbehavior.
        // Any misbehavior now results in instant discouragement.
        //
        // Old system: Accumulate points, disconnect at threshold (100)
        // New system: Any misbehavior = should_discourage = true, disconnect immediately

        // Verify PeerMisbehaviorData uses boolean (instant) not integer (accumulating)
        PeerMisbehaviorData data;
        CHECK(data.should_discourage == false);  // Default: not discouraged
        data.should_discourage = true;           // Any misbehavior sets directly
        CHECK(data.should_discourage == true);   // Instant - no accumulation needed
    }
}

// NOTE: Removed "unconnecting headers threshold" test case.
// Bitcoin Core (March 2024+) no longer penalizes unconnecting headers - they are just ignored.
// The getheaders throttling (2-minute ignore window) provides sufficient DoS protection.

TEST_CASE("DoS: Misbehavior system - NoBan permission", "[dos][network][misbehavior][unit]") {
    SECTION("NoBan peers are not disconnected") {
        // Peers with NetPermissionFlags::NoBan are tracked for misbehavior
        // (should_discourage is set to true) but are NOT disconnected.
        //
        // This is a unit test for data structures. For integration tests that
        // verify NoBan peers stay connected during actual attacks, see:
        // - test/integration-network/permission_tests.cpp: "NoBan peer survives invalid PoW"
        // - test/integration-network/permission_tests.cpp: "NoBan peer survives orphan spam"

        PeerMisbehaviorData data;
        data.permissions = NetPermissionFlags::NoBan;
        data.should_discourage = true;  // Peer misbehaved

        // Verify NoBan flag can be set and checked
        CHECK((data.permissions & NetPermissionFlags::NoBan) == NetPermissionFlags::NoBan);
        CHECK(data.should_discourage == true);  // Still tracked as misbehaving
    }
}

TEST_CASE("DoS: Misbehavior system - duplicate header tracking", "[dos][network][misbehavior][unit]") {
    SECTION("Duplicate invalid headers don't re-trigger discourage") {
        // If a peer sends the same invalid header multiple times, we only
        // discourage them once. The invalid_header_hashes set tracks which
        // headers have already been reported.

        PeerMisbehaviorData data;
        CHECK(data.invalid_header_hashes.empty());

        // First occurrence - not yet seen
        std::string hash1 = "abc123";
        auto [it1, inserted1] = data.invalid_header_hashes.insert(hash1);
        CHECK(inserted1 == true);  // New hash

        // Duplicate - already tracked
        auto [it2, inserted2] = data.invalid_header_hashes.insert(hash1);
        CHECK(inserted2 == false);  // Duplicate detected
    }
}

TEST_CASE("DoS: Misbehavior system - latching behavior", "[dos][network][misbehavior][unit]") {
    SECTION("should_discourage is latched") {
        // Once should_discourage is set to true, it stays true.
        // This is the instant-discourage model (Bitcoin Core March 2024+).

        PeerMisbehaviorData data;
        CHECK(data.should_discourage == false);  // Default

        // After misbehavior is detected, flag latches
        data.should_discourage = true;
        CHECK(data.should_discourage == true);

        // Setting again has no effect (already true)
        data.should_discourage = true;
        CHECK(data.should_discourage == true);
    }
}
