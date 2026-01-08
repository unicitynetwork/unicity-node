// Copyright (c) 2025 The Unicity Foundation
// Time-based eviction tests for orphan header management
// Tests precise timeout verification and time-based cleanup

#include "catch_amalgamated.hpp"
#include "chain/validation.hpp"
#include "common/test_chainstate_manager.hpp"
#include "chain/chainparams.hpp"
#include "chain/block.hpp"
#include "util/sha256.hpp"
#include "util/time.hpp"
#include <memory>

using namespace unicity;
using namespace unicity::test;
using namespace unicity::chain;
using unicity::validation::ValidationState;

// Helper to create test header
static CBlockHeader CreateTestHeader(const uint256& prevHash, uint32_t nTime, uint32_t nNonce = 12345) {
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock = prevHash;
    header.minerAddress.SetNull();
    header.nTime = nTime;
    header.nBits = 0x207fffff;  // RegTest difficulty
    header.nNonce = nNonce;
    header.hashRandomX.SetNull();
    return header;
}

// Helper to create a random hash
static uint256 RandomHash(int seed = 0) {
    uint256 hash;
    for (int i = 0; i < 32; i++) {
        *(hash.begin() + i) = (rand() + seed) % 256;
    }
    return hash;
}

// =============================================================================
// TEST 5: Verify Expiry Timeout
// =============================================================================
// Security Goal: Verify orphans evicted ONLY after exact timeout
// Attack Scenario: Attacker keeps orphans in pool to consume memory
// Expected: Eviction happens precisely at timeout boundary
TEST_CASE("Time Eviction - Verify Expiry Timeout", "[orphan][time][critical]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    // Get timeout value for RegTest
    int64_t timeout = params->GetConsensus().nOrphanHeaderExpireTime;
    REQUIRE(timeout == 12 * 60);  // RegTest: 12 minutes (720 seconds)

    SECTION("Orphan NOT evicted before timeout") {
        // Set base time
        int64_t base_time = 1234567890;
        util::SetMockTime(base_time);

        // Add orphan at T=0
        uint256 unknownParent = RandomHash(1);
        CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890, 1000);
        bool added = chainstate.AddOrphanHeader(orphan, /*peer_id=*/1);
        REQUIRE(added);
        REQUIRE(chainstate.GetOrphanHeaderCount() == 1);

        // Advance time to just before timeout (T + timeout - 1)
        util::SetMockTime(base_time + timeout - 1);

        // Call eviction
        size_t evicted = chainstate.EvictOrphanHeaders();

        // Orphan should NOT be evicted yet
        REQUIRE(evicted == 0);
        REQUIRE(chainstate.GetOrphanHeaderCount() == 1);

        // Cleanup
        util::SetMockTime(0);
    }

    SECTION("Orphan IS evicted after timeout") {
        // Set base time
        int64_t base_time = 1234567890;
        util::SetMockTime(base_time);

        // Add orphan at T=0
        uint256 unknownParent = RandomHash(2);
        CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890, 2000);
        bool added = chainstate.AddOrphanHeader(orphan, /*peer_id=*/1);
        REQUIRE(added);
        REQUIRE(chainstate.GetOrphanHeaderCount() == 1);

        // Advance time past timeout (T + timeout + 1)
        util::SetMockTime(base_time + timeout + 1);

        // Call eviction
        size_t evicted = chainstate.EvictOrphanHeaders();

        // Orphan should be evicted
        REQUIRE(evicted == 1);
        REQUIRE(chainstate.GetOrphanHeaderCount() == 0);

        // Cleanup
        util::SetMockTime(0);
    }

    SECTION("Exact boundary test - evicted at timeout + 0") {
        // Set base time
        int64_t base_time = 1234567890;
        util::SetMockTime(base_time);

        // Add orphan
        uint256 unknownParent = RandomHash(3);
        CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890, 3000);
        chainstate.AddOrphanHeader(orphan, /*peer_id=*/1);

        // Advance to EXACTLY timeout
        util::SetMockTime(base_time + timeout);

        // At exactly timeout, orphan should NOT be evicted (uses > not >=)
        size_t evicted = chainstate.EvictOrphanHeaders();
        REQUIRE(evicted == 0);

        // One second later, should be evicted
        util::SetMockTime(base_time + timeout + 1);
        evicted = chainstate.EvictOrphanHeaders();
        REQUIRE(evicted == 1);

        // Cleanup
        util::SetMockTime(0);
    }
}

// =============================================================================
// TEST 6: Partial Time Eviction
// =============================================================================
// Security Goal: Verify only expired orphans are evicted, not all orphans
// Attack Scenario: Attacker adds orphans at different times
// Expected: Only orphans past timeout are removed
TEST_CASE("Time Eviction - Partial Eviction", "[orphan][time][critical]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    int64_t timeout = params->GetConsensus().nOrphanHeaderExpireTime;

    SECTION("Add 10 orphans at different times, verify only expired ones evicted") {
        int64_t base_time = 1234567890;
        util::SetMockTime(base_time);

        // Add 10 orphans at different times (T, T+60, T+120, ..., T+540)
        for (int i = 0; i < 10; ++i) {
            util::SetMockTime(base_time + i * 60);  // Every 60 seconds

            uint256 unknownParent = RandomHash(100 + i);
            CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890 + i, 1000 + i);
            chainstate.AddOrphanHeader(orphan, /*peer_id=*/1);
        }

        REQUIRE(chainstate.GetOrphanHeaderCount() == 10);

        // Advance time to base_time + timeout + 300
        // This means:
        // - First orphan added at T=0, now age = timeout + 300 (EXPIRED)
        // - Second orphan added at T=60, now age = timeout + 240 (EXPIRED)
        // - Third orphan added at T=120, now age = timeout + 180 (EXPIRED)
        // - Fourth orphan added at T=180, now age = timeout + 120 (EXPIRED)
        // - Fifth orphan added at T=240, now age = timeout + 60 (EXPIRED)
        // - Sixth orphan added at T=300, now age = timeout + 0 (NOT EXPIRED, needs > timeout)
        // - Remaining 4 orphans: NOT EXPIRED

        util::SetMockTime(base_time + timeout + 300);

        size_t evicted = chainstate.EvictOrphanHeaders();

        // First 5 orphans should be evicted (ages: timeout+300, +240, +180, +120, +60)
        REQUIRE(evicted == 5);
        REQUIRE(chainstate.GetOrphanHeaderCount() == 5);

        // Cleanup
        util::SetMockTime(0);
    }

    SECTION("Verify remaining orphans are correct ones") {
        int64_t base_time = 2000000000;
        util::SetMockTime(base_time);

        // Add 5 orphans
        for (int i = 0; i < 5; ++i) {
            util::SetMockTime(base_time + i * 100);

            uint256 unknownParent = RandomHash(200 + i);
            CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890 + i, 2000 + i);
            chainstate.AddOrphanHeader(orphan, /*peer_id=*/1);
        }

        // Advance time to expire first 3 orphans
        util::SetMockTime(base_time + timeout + 250);

        size_t evicted = chainstate.EvictOrphanHeaders();
        REQUIRE(evicted == 3);
        REQUIRE(chainstate.GetOrphanHeaderCount() == 2);

        // Add more time to expire remaining orphans
        util::SetMockTime(base_time + timeout + 500);

        evicted = chainstate.EvictOrphanHeaders();
        REQUIRE(evicted == 2);
        REQUIRE(chainstate.GetOrphanHeaderCount() == 0);

        // Cleanup
        util::SetMockTime(0);
    }
}

// =============================================================================
// TEST 7: Chain-Specific Timeouts
// =============================================================================
// Security Goal: Verify correct timeout per chain type
// Attack Scenario: Timeout misconfiguration allows memory exhaustion
// Expected: Mainnet: 6h, TestNet: 12m, RegTest: 12m
TEST_CASE("Time Eviction - Chain-Specific Timeouts", "[orphan][time][critical]") {
    SECTION("MainNet timeout: 6 hours (21600 seconds)") {
        auto params = ChainParams::CreateMainNet();
        TestChainstateManager chainstate(*params);
        chainstate.Initialize(params->GenesisBlock());

        int64_t timeout = params->GetConsensus().nOrphanHeaderExpireTime;
        REQUIRE(timeout == 6 * 60 * 60);  // 6 hours

        int64_t base_time = 1234567890;
        util::SetMockTime(base_time);

        // Add orphan
        uint256 unknownParent = RandomHash(300);
        CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890, 3000);
        chainstate.AddOrphanHeader(orphan, /*peer_id=*/1);

        // Not evicted before 6 hours
        util::SetMockTime(base_time + timeout - 1);
        REQUIRE(chainstate.EvictOrphanHeaders() == 0);

        // Evicted after 6 hours
        util::SetMockTime(base_time + timeout + 1);
        REQUIRE(chainstate.EvictOrphanHeaders() == 1);

        util::SetMockTime(0);
    }

    SECTION("TestNet timeout: 6 hours (21600 seconds)") {
        auto params = ChainParams::CreateTestNet();
        TestChainstateManager chainstate(*params);
        chainstate.Initialize(params->GenesisBlock());

        int64_t timeout = params->GetConsensus().nOrphanHeaderExpireTime;
        REQUIRE(timeout == 6 * 60 * 60);  // 6 hours

        int64_t base_time = 1234567890;
        util::SetMockTime(base_time);

        // Add orphan
        uint256 unknownParent = RandomHash(400);
        CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890, 4000);
        chainstate.AddOrphanHeader(orphan, /*peer_id=*/1);

        // Not evicted before 6 hours
        util::SetMockTime(base_time + timeout - 1);
        REQUIRE(chainstate.EvictOrphanHeaders() == 0);

        // Evicted after 6 hours
        util::SetMockTime(base_time + timeout + 1);
        REQUIRE(chainstate.EvictOrphanHeaders() == 1);

        util::SetMockTime(0);
    }

    SECTION("RegTest timeout: 12 minutes (720 seconds)") {
        auto params = ChainParams::CreateRegTest();
        TestChainstateManager chainstate(*params);
        chainstate.Initialize(params->GenesisBlock());

        int64_t timeout = params->GetConsensus().nOrphanHeaderExpireTime;
        REQUIRE(timeout == 12 * 60);  // 12 minutes

        int64_t base_time = 1234567890;
        util::SetMockTime(base_time);

        // Add orphan
        uint256 unknownParent = RandomHash(500);
        CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890, 5000);
        chainstate.AddOrphanHeader(orphan, /*peer_id=*/1);

        // Not evicted before 12 minutes
        util::SetMockTime(base_time + timeout - 1);
        REQUIRE(chainstate.EvictOrphanHeaders() == 0);

        // Evicted after 12 minutes
        util::SetMockTime(base_time + timeout + 1);
        REQUIRE(chainstate.EvictOrphanHeaders() == 1);

        util::SetMockTime(0);
    }
}

// =============================================================================
// TEST 8: Eviction During Active Use
// =============================================================================
// Security Goal: Verify eviction doesn't break concurrent operations
// Attack Scenario: Eviction triggered while adding/processing orphans
// Expected: Expired orphans removed, new orphans added, processing continues
TEST_CASE("Time Eviction - Eviction During Active Use", "[orphan][time][critical]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    int64_t timeout = params->GetConsensus().nOrphanHeaderExpireTime;

    SECTION("Evict expired orphans while adding new orphans") {
        int64_t base_time = 1234567890;
        util::SetMockTime(base_time);

        // Add 50 old orphans
        for (int i = 0; i < 50; ++i) {
            uint256 unknownParent = RandomHash(600 + i);
            CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890 + i, 6000 + i);
            chainstate.AddOrphanHeader(orphan, /*peer_id=*/1);
        }

        REQUIRE(chainstate.GetOrphanHeaderCount() == 50);

        // Advance time to expire all old orphans
        util::SetMockTime(base_time + timeout + 100);

        // Evict expired orphans
        size_t evicted = chainstate.EvictOrphanHeaders();
        REQUIRE(evicted == 50);
        REQUIRE(chainstate.GetOrphanHeaderCount() == 0);

        // Add new orphans (should succeed)
        for (int i = 0; i < 30; ++i) {
            uint256 unknownParent = RandomHash(700 + i);
            CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890 + i, 7000 + i);
            chainstate.AddOrphanHeader(orphan, /*peer_id=*/2);
        }

        REQUIRE(chainstate.GetOrphanHeaderCount() == 30);

        // Cleanup
        util::SetMockTime(0);
    }

    SECTION("Mixed expiry: some expired, some fresh") {
        int64_t base_time = 2000000000;
        util::SetMockTime(base_time);

        // Add 30 old orphans
        for (int i = 0; i < 30; ++i) {
            uint256 unknownParent = RandomHash(800 + i);
            CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890 + i, 8000 + i);
            chainstate.AddOrphanHeader(orphan, /*peer_id=*/1);
        }

        // Advance time to half-expired
        util::SetMockTime(base_time + timeout / 2);

        // Add 30 new orphans (these will NOT be expired)
        for (int i = 0; i < 30; ++i) {
            uint256 unknownParent = RandomHash(900 + i);
            CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890 + i, 9000 + i);
            chainstate.AddOrphanHeader(orphan, /*peer_id=*/2);
        }

        REQUIRE(chainstate.GetOrphanHeaderCount() == 60);

        // Advance time to expire first batch
        util::SetMockTime(base_time + timeout + 100);

        // Evict expired orphans (only first 30)
        size_t evicted = chainstate.EvictOrphanHeaders();
        REQUIRE(evicted == 30);
        REQUIRE(chainstate.GetOrphanHeaderCount() == 30);

        // Advance time to expire second batch
        util::SetMockTime(base_time + timeout + timeout / 2 + 100);

        // Evict remaining
        evicted = chainstate.EvictOrphanHeaders();
        REQUIRE(evicted == 30);
        REQUIRE(chainstate.GetOrphanHeaderCount() == 0);

        // Cleanup
        util::SetMockTime(0);
    }

    SECTION("Process orphans while evicting expired ones") {
        const auto& genesis = params->GenesisBlock();
        int64_t base_time = 3000000000;
        util::SetMockTime(base_time);

        // Add parent block
        CBlockHeader parent = CreateTestHeader(genesis.GetHash(), genesis.nTime + 120, 1000);
        ValidationState state;
        chain::CBlockIndex* parent_idx = chainstate.AcceptBlockHeader(parent, state);
        REQUIRE(parent_idx != nullptr);
        chainstate.TryAddBlockIndexCandidate(parent_idx);

        uint256 parent_hash = parent.GetHash();

        // Add 10 old orphans (will expire)
        for (int i = 0; i < 10; ++i) {
            uint256 unknownParent = RandomHash(1000 + i);
            CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890 + i, 10000 + i);
            chainstate.AddOrphanHeader(orphan, /*peer_id=*/1);
        }

        REQUIRE(chainstate.GetOrphanHeaderCount() == 10);

        // Advance time forward (to avoid expiring the new orphans we're about to add)
        util::SetMockTime(base_time + timeout / 2);

        // Add 10 orphans that reference the parent (will NOT expire)
        for (int i = 0; i < 10; ++i) {
            CBlockHeader orphan = CreateTestHeader(parent_hash, genesis.nTime + 240 + i * 60, 11000 + i);
            chainstate.AddOrphanHeader(orphan, /*peer_id=*/2);
        }

        REQUIRE(chainstate.GetOrphanHeaderCount() == 20);

        // Advance time to expire first batch only
        util::SetMockTime(base_time + timeout + 100);

        // Evict expired orphans (only the first 10)
        size_t evicted = chainstate.EvictOrphanHeaders();
        REQUIRE(evicted == 10);

        // Remaining orphans should be the ones waiting for parent
        REQUIRE(chainstate.GetOrphanHeaderCount() == 10);

        // Cleanup
        util::SetMockTime(0);
    }
}
