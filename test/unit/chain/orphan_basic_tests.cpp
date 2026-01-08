// Copyright (c) 2025 The Unicity Foundation
// Test suite for orphan header basic functionality

#include "catch_amalgamated.hpp"
#include "chain/validation.hpp"
#include "common/test_chainstate_manager.hpp"
#include "chain/chainparams.hpp"
#include "chain/block.hpp"
#include "util/sha256.hpp"
#include <memory>

using namespace unicity;
using namespace unicity::test;
using namespace unicity::chain;
using unicity::validation::ValidationState;

// Helper function to create test header
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
static uint256 RandomHash() {
    uint256 hash;
    for (int i = 0; i < 32; i++) {
        *(hash.begin() + i) = rand() % 256;
    }
    return hash;
}

TEST_CASE("Orphan Headers - Basic Detection", "[orphan][basic]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);

    SECTION("Initialize with genesis") {
        REQUIRE(chainstate.Initialize(params->GenesisBlock()));
        REQUIRE(chainstate.GetChainHeight() == 0);
    }

    SECTION("Detect orphan when parent missing") {
        chainstate.Initialize(params->GenesisBlock());

        // Create header with unknown parent
        uint256 unknownParent = RandomHash();
        CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890);

        // Add as orphan via orphan pool API (no Accept on missing parent)
        bool added = chainstate.AddOrphanHeader(orphan, /*peer_id=*/1);
        REQUIRE(added);
        REQUIRE(chainstate.GetOrphanHeaderCount() == 1);
        REQUIRE(chainstate.LookupBlockIndex(orphan.GetHash()) == nullptr);
    }

    SECTION("Accept non-orphan when parent exists") {
        chainstate.Initialize(params->GenesisBlock());
        const auto& genesis = params->GenesisBlock();

        // Create header extending genesis (parent exists)
        CBlockHeader valid = CreateTestHeader(genesis.GetHash(), genesis.nTime + 120);

        ValidationState state;
        chain::CBlockIndex* result = chainstate.AcceptBlockHeader(valid, state);

        // Should succeed
        REQUIRE(result != nullptr);
        REQUIRE(state.IsValid());
        REQUIRE(chainstate.GetOrphanHeaderCount() == 0);  // Not orphaned
    }

    SECTION("Check orphan not added to block index") {
        chainstate.Initialize(params->GenesisBlock());

        uint256 unknownParent = RandomHash();
        CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890);
        uint256 orphanHash = orphan.GetHash();

        // Add to orphan pool (not block index)
        bool added = chainstate.AddOrphanHeader(orphan, /*peer_id=*/1);
        REQUIRE(added);

        // Orphan should be in orphan pool, NOT in block index
        REQUIRE(chainstate.LookupBlockIndex(orphanHash) == nullptr);
        REQUIRE(chainstate.GetOrphanHeaderCount() == 1);
    }

    SECTION("Genesis block not cached as orphan") {
        chainstate.Initialize(params->GenesisBlock());
        const auto& genesis = params->GenesisBlock();

        // Try to re-add genesis
        ValidationState state;
        chain::CBlockIndex* result = chainstate.AcceptBlockHeader(genesis, state);

        // Should return existing genesis (duplicate detection at line 48 of chainstate_manager.cpp)
        // and NOT be cached as orphan
        REQUIRE(result != nullptr);  // Returns existing pindex
        REQUIRE(state.IsValid());     // Not an error, just a duplicate
        REQUIRE(chainstate.GetOrphanHeaderCount() == 0);
    }
}

TEST_CASE("Orphan Headers - Orphan Processing", "[orphan][basic]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);

    SECTION("Process single orphan when parent arrives") {
        chainstate.Initialize(params->GenesisBlock());
        const auto& genesis = params->GenesisBlock();

        // Step 1: Create and send child header (orphan, parent unknown)
        CBlockHeader parentHeader = CreateTestHeader(genesis.GetHash(), genesis.nTime + 120, 1000);
        uint256 parentHash = parentHeader.GetHash();

        CBlockHeader childHeader = CreateTestHeader(parentHash, genesis.nTime + 240, 1001);

        // Send child first (becomes orphan)
        ValidationState childState; // unused now
        bool added = chainstate.AddOrphanHeader(childHeader, /*peer_id=*/1);
        REQUIRE(added);
        REQUIRE(chainstate.GetOrphanHeaderCount() == 1);

        // Step 2: Send parent (should trigger child processing)
        ValidationState parentState;
        chain::CBlockIndex* parentResult = chainstate.AcceptBlockHeader(parentHeader, parentState);

        // Parent accepted
        REQUIRE(parentResult != nullptr);
        REQUIRE(parentState.IsValid());

        // Orphan should be automatically processed and removed from pool
        REQUIRE(chainstate.GetOrphanHeaderCount() == 0);

        // Child should now be in block index
        REQUIRE(chainstate.LookupBlockIndex(childHeader.GetHash()) != nullptr);
    }

    SECTION("Process linear orphan chain") {
        chainstate.Initialize(params->GenesisBlock());
        const auto& genesis = params->GenesisBlock();

        // Create chain: Genesis -> A -> B -> C
        CBlockHeader headerA = CreateTestHeader(genesis.GetHash(), genesis.nTime + 120, 1000);
        uint256 hashA = headerA.GetHash();

        CBlockHeader headerB = CreateTestHeader(hashA, genesis.nTime + 240, 1001);
        uint256 hashB = headerB.GetHash();

        CBlockHeader headerC = CreateTestHeader(hashB, genesis.nTime + 360, 1002);

        // Send in reverse: C, B, A (all become orphans except A)
        ValidationState state;

        // Send C (orphan - parent B missing)
        REQUIRE(chainstate.AddOrphanHeader(headerC, /*peer_id=*/1));
        REQUIRE(chainstate.GetOrphanHeaderCount() == 1);

        // Send B (orphan - parent A missing)
        REQUIRE(chainstate.AddOrphanHeader(headerB, /*peer_id=*/1));
        REQUIRE(chainstate.GetOrphanHeaderCount() == 2);

        // Send A (parent = genesis, exists!)
        chainstate.AcceptBlockHeader(headerA, state);

        // All orphans should cascade: A accepted -> triggers B -> B triggers C
        REQUIRE(chainstate.GetOrphanHeaderCount() == 0);
        REQUIRE(chainstate.LookupBlockIndex(hashA) != nullptr);
        REQUIRE(chainstate.LookupBlockIndex(hashB) != nullptr);
        REQUIRE(chainstate.LookupBlockIndex(headerC.GetHash()) != nullptr);
    }

    SECTION("Process branching orphan chain") {
        chainstate.Initialize(params->GenesisBlock());
        const auto& genesis = params->GenesisBlock();

        // Create tree:
        //     Genesis -> A -> B
        //                  \-> C
        //                  \-> D
        CBlockHeader headerA = CreateTestHeader(genesis.GetHash(), genesis.nTime + 120, 1000);
        uint256 hashA = headerA.GetHash();

        CBlockHeader headerB = CreateTestHeader(hashA, genesis.nTime + 240, 1001);
        CBlockHeader headerC = CreateTestHeader(hashA, genesis.nTime + 240, 1002);
        CBlockHeader headerD = CreateTestHeader(hashA, genesis.nTime + 240, 1003);

        ValidationState state;

        // Send B, C, D (all orphaned - parent A missing)
        REQUIRE(chainstate.AddOrphanHeader(headerB, /*peer_id=*/1));
        REQUIRE(chainstate.AddOrphanHeader(headerC, /*peer_id=*/1));
        REQUIRE(chainstate.AddOrphanHeader(headerD, /*peer_id=*/1));
        REQUIRE(chainstate.GetOrphanHeaderCount() == 3);

        // Send parent A (should trigger all 3 children)
        chainstate.AcceptBlockHeader(headerA, state);

        // All 3 children should be processed
        REQUIRE(chainstate.GetOrphanHeaderCount() == 0);
        REQUIRE(chainstate.LookupBlockIndex(headerA.GetHash()) != nullptr);
        REQUIRE(chainstate.LookupBlockIndex(headerB.GetHash()) != nullptr);
        REQUIRE(chainstate.LookupBlockIndex(headerC.GetHash()) != nullptr);
        REQUIRE(chainstate.LookupBlockIndex(headerD.GetHash()) != nullptr);
    }

    SECTION("Deep orphan chain (20 levels)") {
        chainstate.Initialize(params->GenesisBlock());
        const auto& genesis = params->GenesisBlock();

        const int DEPTH = 20;
        std::vector<CBlockHeader> headers;
        uint256 prevHash = genesis.GetHash();
        uint32_t baseTime = genesis.nTime;

        // Build chain of headers
        for (int i = 0; i < DEPTH; i++) {
            CBlockHeader h = CreateTestHeader(prevHash, baseTime + (i + 1) * 120, 1000 + i);
            headers.push_back(h);
            prevHash = h.GetHash();
        }

        ValidationState state;

        // Send in REVERSE order (all become orphans)
        for (int i = DEPTH - 1; i >= 1; i--) {
            REQUIRE(chainstate.AddOrphanHeader(headers[i], /*peer_id=*/1));
        }
        REQUIRE(chainstate.GetOrphanHeaderCount() == DEPTH - 1);

        // Send the first header (extends genesis)
        // Should trigger cascade processing of all orphans
        chainstate.AcceptBlockHeader(headers[0], state);

        REQUIRE(chainstate.GetOrphanHeaderCount() == 0);

        // All should be in block index
        for (const auto& h : headers) {
            REQUIRE(chainstate.LookupBlockIndex(h.GetHash()) != nullptr);
        }
    }
}

TEST_CASE("Orphan Headers - Duplicate Detection", "[orphan][basic]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);

    SECTION("Same orphan sent twice is ignored") {
        chainstate.Initialize(params->GenesisBlock());

        uint256 unknownParent = RandomHash();
        CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890);

        ValidationState state1, state2;

        // Send once
        REQUIRE(chainstate.AddOrphanHeader(orphan, /*peer_id=*/1));
        REQUIRE(chainstate.GetOrphanHeaderCount() == 1);

        // Send again (duplicate)
        REQUIRE(chainstate.AddOrphanHeader(orphan, /*peer_id=*/1));

        // Should not add duplicate
        REQUIRE(chainstate.GetOrphanHeaderCount() == 1);
    }

    SECTION("Same orphan from different peers") {
        chainstate.Initialize(params->GenesisBlock());

        uint256 unknownParent = RandomHash();
        CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890);

        ValidationState state1, state2;

        // Peer 1 sends it
        REQUIRE(chainstate.AddOrphanHeader(orphan, /*peer_id=*/1));
        REQUIRE(chainstate.GetOrphanHeaderCount() == 1);

        // Peer 2 sends same header
        REQUIRE(chainstate.AddOrphanHeader(orphan, /*peer_id=*/2));

        // Only stored once
        REQUIRE(chainstate.GetOrphanHeaderCount() == 1);
    }

    SECTION("Orphan not re-added after processing") {
        chainstate.Initialize(params->GenesisBlock());
        const auto& genesis = params->GenesisBlock();

        // Create parent and child
        CBlockHeader parent = CreateTestHeader(genesis.GetHash(), genesis.nTime + 120, 1000);
        uint256 parentHash = parent.GetHash();

        CBlockHeader child = CreateTestHeader(parentHash, genesis.nTime + 240, 1001);

        ValidationState state;

        // Add as orphan
        REQUIRE(chainstate.AddOrphanHeader(child, /*peer_id=*/1));
        REQUIRE(chainstate.GetOrphanHeaderCount() == 1);

        // Parent arrives, child processed
        chainstate.AcceptBlockHeader(parent, state);
        REQUIRE(chainstate.GetOrphanHeaderCount() == 0);
        REQUIRE(chainstate.LookupBlockIndex(child.GetHash()) != nullptr);

        // Try to add same header again via Accept (should be duplicate and not re-add)
        chainstate.AcceptBlockHeader(child, state);

        // Should recognize as duplicate, NOT re-add to orphan pool
        REQUIRE(chainstate.GetOrphanHeaderCount() == 0);
    }
}

TEST_CASE("Orphan Headers - Empty State", "[orphan][basic]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);

    SECTION("Fresh chainstate has no orphans") {
        chainstate.Initialize(params->GenesisBlock());
        REQUIRE(chainstate.GetOrphanHeaderCount() == 0);
    }

    SECTION("Orphan count accurate after additions") {
        chainstate.Initialize(params->GenesisBlock());

        ValidationState state;

        // Add 5 orphans
        for (int i = 0; i < 5; i++) {
            uint256 unknownParent = RandomHash();
            CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890 + i, 1000 + i);
            REQUIRE(chainstate.AddOrphanHeader(orphan, /*peer_id=*/1));
        }

        REQUIRE(chainstate.GetOrphanHeaderCount() == 5);
    }
}
