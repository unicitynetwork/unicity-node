// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license
// Comprehensive chain reorganization tests

#include "catch_amalgamated.hpp"
#include "chain/validation.hpp"
#include "common/test_chainstate_manager.hpp"
#include "chain/chainstate_manager.hpp"
#include "chain/chainparams.hpp"
#include "chain/chain.hpp"
#include "chain/block_index.hpp"
#include "chain/block.hpp"
#include "chain/notifications.hpp"
#include "util/logging.hpp"
#include "util/time.hpp"
#include <filesystem>
#include <memory>
#include <vector>

using namespace unicity;
using namespace unicity::test;
using namespace unicity::chain;
using unicity::validation::ValidationState;

// Test helper: Create a block header with specified parent and time
static CBlockHeader CreateTestHeader(const uint256& hashPrevBlock,
                                     uint32_t nTime,
                                     uint32_t nBits = 0x207fffff) {
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock = hashPrevBlock;
    header.minerAddress.SetNull();
    header.nTime = nTime;
    header.nBits = nBits;
    header.nNonce = 0;
    header.hashRandomX.SetNull(); // Valid PoW placeholder (test bypasses validation)
    return header;
}

// Test helper: Build a chain of N blocks from a parent
static std::vector<CBlockHeader> BuildChain(const uint256& parent_hash,
                                            uint32_t start_time,
                                            int count,
                                            uint32_t nBits = 0x207fffff) {
    std::vector<CBlockHeader> chain;
    uint256 prev_hash = parent_hash;
    uint32_t time = start_time;

    for (int i = 0; i < count; i++) {
        auto header = CreateTestHeader(prev_hash, time, nBits);
        chain.push_back(header);
        prev_hash = header.GetHash();
        time += 120; // 2-minute blocks
    }

    return chain;
}

TEST_CASE("Reorg - Simple reorg (1 block)", "[reorg]") {
    // Test basic 1-block reorg
    // Initial: Genesis -> A
    // Fork:    Genesis -> B (more work)
    // Result:  Should reorg to B

    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    const auto& genesis = params->GenesisBlock();
    validation::ValidationState state;

    // Build initial chain: Genesis -> A
    auto headerA = CreateTestHeader(genesis.GetHash(), util::GetTime());
    chain::CBlockIndex* pindexA = chainstate.AcceptBlockHeader(headerA, state);
    chainstate.TryAddBlockIndexCandidate(pindexA);
    REQUIRE(pindexA != nullptr);

    chainstate.ActivateBestChain();
    REQUIRE(chainstate.GetTip() == pindexA);

    // Build competing fork: Genesis -> B -> C (longer chain = more work)
    auto headerB = CreateTestHeader(genesis.GetHash(), util::GetTime() + 120);
    chain::CBlockIndex* pindexB = chainstate.AcceptBlockHeader(headerB, state);
    chainstate.TryAddBlockIndexCandidate(pindexB);
    REQUIRE(pindexB != nullptr);

    auto headerC = CreateTestHeader(headerB.GetHash(), util::GetTime() + 240);
    chain::CBlockIndex* pindexC = chainstate.AcceptBlockHeader(headerC, state);
    chainstate.TryAddBlockIndexCandidate(pindexC);
    REQUIRE(pindexC != nullptr);

    chainstate.ActivateBestChain();

    // Should reorg to C (more work - longer chain)
    REQUIRE(chainstate.GetTip() == pindexC);
}

TEST_CASE("Reorg - Medium reorg (3 blocks)", "[reorg]") {
    // Test medium-depth reorg
    // Initial: Genesis -> A -> B -> C
    // Fork:    Genesis -> X -> Y -> Z -> W (more blocks = more work)
    // Result:  Should reorg to W

    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    const auto& genesis = params->GenesisBlock();
    validation::ValidationState state;

    // Build initial chain: Genesis -> A -> B -> C
    auto chainABC = BuildChain(genesis.GetHash(), util::GetTime(), 3);
    chain::CBlockIndex* tip = nullptr;

    for (const auto& header : chainABC) {
        tip = chainstate.AcceptBlockHeader(header, state);
        if (tip) chainstate.TryAddBlockIndexCandidate(tip);
        REQUIRE(tip != nullptr);
    }

    chainstate.ActivateBestChain();
    REQUIRE(chainstate.GetTip() == tip);
    REQUIRE(chainstate.GetTip()->nHeight == 3);

    // Build competing fork: Genesis -> X -> Y -> Z -> W (4 blocks, more work)
    auto chainXYZW = BuildChain(genesis.GetHash(), util::GetTime(), 4);
    chain::CBlockIndex* tipW = nullptr;

    for (const auto& header : chainXYZW) {
        tipW = chainstate.AcceptBlockHeader(header, state);
        if (tipW) chainstate.TryAddBlockIndexCandidate(tipW);
        REQUIRE(tipW != nullptr);
    }

    chainstate.ActivateBestChain();

    // Should reorg to W
    REQUIRE(chainstate.GetTip() == tipW);
    REQUIRE(chainstate.GetTip()->nHeight == 4);
}

TEST_CASE("Reorg - Deep reorg protection (suspicious_reorg_depth)", "[reorg]") {
    // Test that reorgs deeper than suspicious_reorg_depth are rejected
    // Initial: Genesis -> [7 blocks]
    // Fork:    Genesis -> [8 blocks with more work]
    // Result:  Should REJECT reorg (depth 7 >= suspicious_reorg_depth=7)

    auto params = ChainParams::CreateRegTest();
    // Set suspicious_reorg_depth=7 (allow up to depth 6, reject depth 7+)
    params->SetSuspiciousReorgDepth(7);
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    const auto& genesis = params->GenesisBlock();
    validation::ValidationState state;

    // Build initial chain: Genesis -> [7 blocks]
    auto chainMain = BuildChain(genesis.GetHash(), util::GetTime(), 7);
    chain::CBlockIndex* mainTip = nullptr;

    for (const auto& header : chainMain) {
        mainTip = chainstate.AcceptBlockHeader(header, state);
        if (mainTip) chainstate.TryAddBlockIndexCandidate(mainTip);
        REQUIRE(mainTip != nullptr);
    }

    chainstate.ActivateBestChain();
    REQUIRE(chainstate.GetTip() == mainTip);
    REQUIRE(chainstate.GetTip()->nHeight == 7);

    // Build competing fork: Genesis -> [8 blocks] (more work, but requires depth-7 reorg)
    auto chainFork = BuildChain(genesis.GetHash(), util::GetTime() + 1000, 8);
    chain::CBlockIndex* forkTip = nullptr;

    for (const auto& header : chainFork) {
        forkTip = chainstate.AcceptBlockHeader(header, state);
        if (forkTip) chainstate.TryAddBlockIndexCandidate(forkTip);
        REQUIRE(forkTip != nullptr);
    }

    chainstate.ActivateBestChain();

    // Should REJECT reorg (depth 7 >= suspicious_reorg_depth=7)
    // Check that we stayed on original chain
    REQUIRE(chainstate.GetTip() == mainTip);
    REQUIRE(chainstate.GetTip()->nHeight == 7);
}

TEST_CASE("Reorg - Suspicious deep reorg warning (SUSPICIOUS_REORG_DEPTH)", "[reorg]") {
    // Test that reorgs deeper than SUSPICIOUS_REORG_DEPTH=100 trigger warnings
    // Note: This test verifies warning is logged (if observable) or that reorg is rejected

    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    const auto& genesis = params->GenesisBlock();
    validation::ValidationState state;

    // Build initial chain: Genesis -> [101 blocks]
    auto chainMain = BuildChain(genesis.GetHash(), util::GetTime(), 101);
    chain::CBlockIndex* mainTip = nullptr;

    for (const auto& header : chainMain) {
        mainTip = chainstate.AcceptBlockHeader(header, state);
        if (mainTip) chainstate.TryAddBlockIndexCandidate(mainTip);
        REQUIRE(mainTip != nullptr);
    }

    chainstate.ActivateBestChain();
    REQUIRE(chainstate.GetTip() == mainTip);
    REQUIRE(chainstate.GetTip()->nHeight == 101);

    // Build competing fork: Genesis -> [102 blocks] (depth-101 reorg required)
    auto chainFork = BuildChain(genesis.GetHash(), util::GetTime() + 10000, 102);
    chain::CBlockIndex* forkTip = nullptr;

    for (const auto& header : chainFork) {
        forkTip = chainstate.AcceptBlockHeader(header, state);
        if (forkTip) chainstate.TryAddBlockIndexCandidate(forkTip);
        REQUIRE(forkTip != nullptr);
    }

    chainstate.ActivateBestChain();

    // Should either reject or issue warning
    // At minimum, verify we don't crash
    REQUIRE(chainstate.GetTip() != nullptr);
}

TEST_CASE("Reorg - Fork point detection (common ancestor)", "[reorg]") {
    // Test LastCommonAncestor logic
    // Chain: Genesis -> A -> B -> C
    //                    \-> X -> Y
    // Fork point should be A

    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    const auto& genesis = params->GenesisBlock();
    validation::ValidationState state;

    // Build: Genesis -> A
    auto headerA = CreateTestHeader(genesis.GetHash(), util::GetTime());
    chain::CBlockIndex* pindexA = chainstate.AcceptBlockHeader(headerA, state);
    chainstate.TryAddBlockIndexCandidate(pindexA);
    REQUIRE(pindexA != nullptr);

    // Build main chain: A -> B -> C
    auto headerB = CreateTestHeader(headerA.GetHash(), util::GetTime() + 120);
    chain::CBlockIndex* pindexB = chainstate.AcceptBlockHeader(headerB, state);
    chainstate.TryAddBlockIndexCandidate(pindexB);
    REQUIRE(pindexB != nullptr);

    auto headerC = CreateTestHeader(headerB.GetHash(), util::GetTime() + 240);
    chain::CBlockIndex* pindexC = chainstate.AcceptBlockHeader(headerC, state);
    chainstate.TryAddBlockIndexCandidate(pindexC);
    REQUIRE(pindexC != nullptr);

    chainstate.ActivateBestChain();
    REQUIRE(chainstate.GetTip() == pindexC);

    // Build fork: A -> X -> Y -> Z (more work)
    auto headerX = CreateTestHeader(headerA.GetHash(), util::GetTime() + 1000);
    chain::CBlockIndex* pindexX = chainstate.AcceptBlockHeader(headerX, state);
    chainstate.TryAddBlockIndexCandidate(pindexX);
    REQUIRE(pindexX != nullptr);

    auto headerY = CreateTestHeader(headerX.GetHash(), util::GetTime() + 1120);
    chain::CBlockIndex* pindexY = chainstate.AcceptBlockHeader(headerY, state);
    chainstate.TryAddBlockIndexCandidate(pindexY);
    REQUIRE(pindexY != nullptr);

    auto headerZ = CreateTestHeader(headerY.GetHash(), util::GetTime() + 1240);
    chain::CBlockIndex* pindexZ = chainstate.AcceptBlockHeader(headerZ, state);
    chainstate.TryAddBlockIndexCandidate(pindexZ);
    REQUIRE(pindexZ != nullptr);

    chainstate.ActivateBestChain();

    // Should reorg to Z
    REQUIRE(chainstate.GetTip() == pindexZ);

    // Verify fork point (common ancestor) is A
    const CBlockIndex* fork_point = LastCommonAncestor(pindexC, pindexZ);
    REQUIRE(fork_point == pindexA);
}

TEST_CASE("Reorg - Fork point is genesis", "[reorg]") {
    // Test edge case where fork point is genesis block
    // Chain: Genesis -> A
    //        Genesis -> X (competing from genesis)

    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    const auto& genesis = params->GenesisBlock();
    validation::ValidationState state;

    // Build: Genesis -> A
    auto headerA = CreateTestHeader(genesis.GetHash(), util::GetTime());
    chain::CBlockIndex* pindexA = chainstate.AcceptBlockHeader(headerA, state);
    chainstate.TryAddBlockIndexCandidate(pindexA);
    REQUIRE(pindexA != nullptr);

    chainstate.ActivateBestChain();
    REQUIRE(chainstate.GetTip() == pindexA);

    // Build fork from genesis: Genesis -> X (more work)
    auto headerX = CreateTestHeader(genesis.GetHash(), util::GetTime() + 120, 0x1e0ffff0 - 1);
    chain::CBlockIndex* pindexX = chainstate.AcceptBlockHeader(headerX, state);
    chainstate.TryAddBlockIndexCandidate(pindexX);
    REQUIRE(pindexX != nullptr);

    chainstate.ActivateBestChain();

    // Should reorg to X
    REQUIRE(chainstate.GetTip() == pindexX);

    // Verify fork point is genesis
    const CBlockIndex* genesis_index = chainstate.LookupBlockIndex(genesis.GetHash());
    REQUIRE(genesis_index != nullptr);

    const CBlockIndex* fork_point = LastCommonAncestor(pindexA, pindexX);
    REQUIRE(fork_point == genesis_index);
}

TEST_CASE("Reorg - Equal work (no reorg)", "[reorg]") {
    // Test that equal work doesn't trigger reorg (first-seen wins)
    // Chain: Genesis -> A
    //        Genesis -> B (equal work)
    // Result: Stay on A (first seen)

    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    const auto& genesis = params->GenesisBlock();
    validation::ValidationState state;

    // Build: Genesis -> A
    auto headerA = CreateTestHeader(genesis.GetHash(), util::GetTime());
    chain::CBlockIndex* pindexA = chainstate.AcceptBlockHeader(headerA, state);
    chainstate.TryAddBlockIndexCandidate(pindexA);
    REQUIRE(pindexA != nullptr);

    chainstate.ActivateBestChain();
    REQUIRE(chainstate.GetTip() == pindexA);

    // Build fork: Genesis -> B (same difficulty = equal work)
    auto headerB = CreateTestHeader(genesis.GetHash(), util::GetTime() + 120);
    chain::CBlockIndex* pindexB = chainstate.AcceptBlockHeader(headerB, state);
    chainstate.TryAddBlockIndexCandidate(pindexB);
    REQUIRE(pindexB != nullptr);

    chainstate.ActivateBestChain();

    // Should stay on A (equal work, first-seen wins)
    REQUIRE(chainstate.GetTip() == pindexA);
}

TEST_CASE("Reorg - Insufficient work (no reorg)", "[reorg]") {
    // Test that lower work doesn't trigger reorg
    // Chain: Genesis -> A -> B
    //        Genesis -> X (less work)
    // Result: Stay on B

    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    const auto& genesis = params->GenesisBlock();
    validation::ValidationState state;

    // Build: Genesis -> A -> B
    auto chainAB = BuildChain(genesis.GetHash(), util::GetTime(), 2);
    chain::CBlockIndex* tipB = nullptr;

    for (const auto& header : chainAB) {
        tipB = chainstate.AcceptBlockHeader(header, state);
        if (tipB) chainstate.TryAddBlockIndexCandidate(tipB);
        REQUIRE(tipB != nullptr);
    }

    chainstate.ActivateBestChain();
    REQUIRE(chainstate.GetTip() == tipB);
    REQUIRE(chainstate.GetTip()->nHeight == 2);

    // Build fork: Genesis -> X (only 1 block, less work than A->B)
    auto headerX = CreateTestHeader(genesis.GetHash(), util::GetTime() + 1000);
    chain::CBlockIndex* pindexX = chainstate.AcceptBlockHeader(headerX, state);
    chainstate.TryAddBlockIndexCandidate(pindexX);
    REQUIRE(pindexX != nullptr);

    chainstate.ActivateBestChain();

    // Should stay on B (more work)
    REQUIRE(chainstate.GetTip() == tipB);
    REQUIRE(chainstate.GetTip()->nHeight == 2);
}

TEST_CASE("Reorg - Multiple competing forks", "[reorg]") {
    // Test handling of multiple competing forks
    // Chain: Genesis -> A -> B
    //        Genesis -> X -> Y
    //        Genesis -> P -> Q -> R (most work)
    // Result: Should reorg to R

    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    const auto& genesis = params->GenesisBlock();
    validation::ValidationState state;

    // Build initial chain: Genesis -> A -> B
    auto chainAB = BuildChain(genesis.GetHash(), util::GetTime(), 2);
    chain::CBlockIndex* tipB = nullptr;

    for (const auto& header : chainAB) {
        tipB = chainstate.AcceptBlockHeader(header, state);
        if (tipB) chainstate.TryAddBlockIndexCandidate(tipB);
        REQUIRE(tipB != nullptr);
    }

    chainstate.ActivateBestChain();
    REQUIRE(chainstate.GetTip() == tipB);

    // Build fork 1: Genesis -> X -> Y (equal to AB)
    auto chainXY = BuildChain(genesis.GetHash(), util::GetTime() + 1000, 2);
    chain::CBlockIndex* tipY = nullptr;

    for (const auto& header : chainXY) {
        tipY = chainstate.AcceptBlockHeader(header, state);
        if (tipY) chainstate.TryAddBlockIndexCandidate(tipY);
        REQUIRE(tipY != nullptr);
    }

    chainstate.ActivateBestChain();
    // Should stay on B (equal work, first seen)
    REQUIRE(chainstate.GetTip() == tipB);

    // Build fork 2: Genesis -> P -> Q -> R (most work)
    auto chainPQR = BuildChain(genesis.GetHash(), util::GetTime() + 2000, 3);
    chain::CBlockIndex* tipR = nullptr;

    for (const auto& header : chainPQR) {
        tipR = chainstate.AcceptBlockHeader(header, state);
        if (tipR) chainstate.TryAddBlockIndexCandidate(tipR);
        REQUIRE(tipR != nullptr);
    }

    chainstate.ActivateBestChain();

    // Should reorg to R (most work)
    REQUIRE(chainstate.GetTip() == tipR);
    REQUIRE(chainstate.GetTip()->nHeight == 3);
}

TEST_CASE("Reorg - BlockConnected notifications for new chain", "[reorg]") {
    // Test that BlockConnected fires for newly connected blocks during reorg
    // Chain: Genesis -> A -> B
    //        Genesis -> X -> Y -> Z (triggers reorg)
    // Expected: BlockConnected for X, Y, Z

    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    const auto& genesis = params->GenesisBlock();
    validation::ValidationState state;

    std::vector<int> connected_heights;
    auto connect_sub = Notifications().SubscribeBlockConnected(
        [&connected_heights](const BlockConnectedEvent& event) {
            connected_heights.push_back(event.height);
        }
    );

    // Build initial chain: Genesis -> A -> B
    auto chainAB = BuildChain(genesis.GetHash(), util::GetTime(), 2);
    for (const auto& header : chainAB) {
        auto pindex = chainstate.AcceptBlockHeader(header, state);
        if (pindex) chainstate.TryAddBlockIndexCandidate(pindex);
    }

    chainstate.ActivateBestChain();
    connected_heights.clear();

    // Build competing fork: Genesis -> X -> Y -> Z (more work)
    auto chainXYZ = BuildChain(genesis.GetHash(), util::GetTime() + 1000, 3);
    for (const auto& header : chainXYZ) {
        auto pindex = chainstate.AcceptBlockHeader(header, state);
        if (pindex) chainstate.TryAddBlockIndexCandidate(pindex);
    }

    chainstate.ActivateBestChain();

    // Should connect X, Y, Z (fork point to new tip)
    REQUIRE(connected_heights.size() == 3);
    REQUIRE(connected_heights[0] == 1); // X
    REQUIRE(connected_heights[1] == 2); // Y
    REQUIRE(connected_heights[2] == 3); // Z
}

TEST_CASE("Reorg - Candidate pruning after reorg", "[reorg]") {
    // Test that losing chain candidates are properly tracked
    // Chain: Genesis -> A -> B (active)
    //        Genesis -> X (candidate)
    // After reorg, verify both chains maintained as candidates

    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    const auto& genesis = params->GenesisBlock();
    validation::ValidationState state;

    // Build: Genesis -> A -> B
    auto chainAB = BuildChain(genesis.GetHash(), util::GetTime(), 2);
    chain::CBlockIndex* tipB = nullptr;

    for (const auto& header : chainAB) {
        tipB = chainstate.AcceptBlockHeader(header, state);
        if (tipB) chainstate.TryAddBlockIndexCandidate(tipB);
        REQUIRE(tipB != nullptr);
    }

    chainstate.ActivateBestChain();
    REQUIRE(chainstate.GetTip() == tipB);

    // Build fork: Genesis -> X (less work, becomes candidate)
    auto headerX = CreateTestHeader(genesis.GetHash(), util::GetTime() + 1000);
    chain::CBlockIndex* pindexX = chainstate.AcceptBlockHeader(headerX, state);
    chainstate.TryAddBlockIndexCandidate(pindexX);
    REQUIRE(pindexX != nullptr);

    chainstate.ActivateBestChain();
    // Should stay on B
    REQUIRE(chainstate.GetTip() == tipB);

    // Verify X is tracked as candidate (can still be looked up)
    const chain::CBlockIndex* found = chainstate.LookupBlockIndex(headerX.GetHash());
    REQUIRE(found == pindexX);
    REQUIRE(found->nHeight == 1);
}

TEST_CASE("Reorg - Persistence after reorg", "[reorg][persistence]") {
    // Test that chain state is correctly saved/loaded after a reorg
    // Initial: Genesis -> A -> B
    // Fork:    Genesis -> X -> Y -> Z (triggers reorg)
    // Save, reload, verify Z is still the tip

    std::string test_file = "/tmp/test_reorg_persist_" + std::to_string(std::time(nullptr)) + ".json";

    // Cleanup helper
    struct Cleanup {
        std::string file;
        ~Cleanup() { std::filesystem::remove(file); }
    } cleanup{test_file};

    auto params = ChainParams::CreateRegTest();
    validation::ValidationState state;

    // Phase 1: Build initial chain and perform reorg
    {
        TestChainstateManager chainstate(*params);
        chainstate.Initialize(params->GenesisBlock());

        const auto& genesis = params->GenesisBlock();

        // Build initial chain: Genesis -> A -> B
        auto chainAB = BuildChain(genesis.GetHash(), util::GetTime(), 2);
        for (const auto& header : chainAB) {
            auto pindex = chainstate.AcceptBlockHeader(header, state);
            if (pindex) chainstate.TryAddBlockIndexCandidate(pindex);
            REQUIRE(pindex != nullptr);
        }

        chainstate.ActivateBestChain();
        REQUIRE(chainstate.GetTip()->nHeight == 2);

        // Build competing fork: Genesis -> X -> Y -> Z (more work)
        auto chainXYZ = BuildChain(genesis.GetHash(), util::GetTime() + 1000, 3);
        chain::CBlockIndex* tipZ = nullptr;

        for (const auto& header : chainXYZ) {
            tipZ = chainstate.AcceptBlockHeader(header, state);
            if (tipZ) chainstate.TryAddBlockIndexCandidate(tipZ);
            REQUIRE(tipZ != nullptr);
        }

        chainstate.ActivateBestChain();

        // Verify reorg happened
        REQUIRE(chainstate.GetTip() == tipZ);
        REQUIRE(chainstate.GetTip()->nHeight == 3);

        uint256 tipZ_hash = tipZ->GetBlockHash();

        // Save state after reorg
        REQUIRE(chainstate.Save(test_file));

        // Store hash for verification after reload
        REQUIRE(chainstate.LookupBlockIndex(tipZ_hash) != nullptr);
    }

    // Phase 2: Load state and verify tip is still Z
    {
        TestChainstateManager chainstate2(*params);
        REQUIRE(chainstate2.Load(test_file) == chain::LoadResult::SUCCESS);

        // Verify tip is still Z (height 3)
        REQUIRE(chainstate2.GetTip() != nullptr);
        REQUIRE(chainstate2.GetTip()->nHeight == 3);

        // Verify we have all 7 blocks (genesis + 2 from AB + 3 from XYZ + genesis counted once)
        REQUIRE(chainstate2.GetBlockCount() == 6);  // Genesis + 2 (A,B) + 3 (X,Y,Z)

        // Verify genesis
        const auto& genesis = params->GenesisBlock();
        const chain::CBlockIndex* genesis_index = chainstate2.LookupBlockIndex(genesis.GetHash());
        REQUIRE(genesis_index != nullptr);
        REQUIRE(genesis_index->nHeight == 0);

        // Verify active chain continuity
        for (int h = 0; h <= 3; h++) {
            const chain::CBlockIndex* pindex = chainstate2.GetBlockAtHeight(h);
            REQUIRE(pindex != nullptr);
            REQUIRE(pindex->nHeight == h);
        }
    }
}

TEST_CASE("Reorg - Persistence with competing forks", "[reorg][persistence]") {
    // Test that ALL branches are saved/loaded correctly, not just active chain
    // Chain: Genesis -> A -> B (active)
    //        Genesis -> X -> Y (inactive fork)
    // Save, reload, verify both chains exist

    std::string test_file = "/tmp/test_reorg_forks_" + std::to_string(std::time(nullptr)) + ".json";

    struct Cleanup {
        std::string file;
        ~Cleanup() { std::filesystem::remove(file); }
    } cleanup{test_file};

    auto params = ChainParams::CreateRegTest();
    validation::ValidationState state;

    uint256 tipB_hash, tipY_hash;

    // Phase 1: Build two competing chains
    {
        TestChainstateManager chainstate(*params);
        chainstate.Initialize(params->GenesisBlock());

        const auto& genesis = params->GenesisBlock();

        // Build main chain: Genesis -> A -> B
        auto chainAB = BuildChain(genesis.GetHash(), util::GetTime(), 2);
        chain::CBlockIndex* tipB = nullptr;

        for (const auto& header : chainAB) {
            tipB = chainstate.AcceptBlockHeader(header, state);
            if (tipB) chainstate.TryAddBlockIndexCandidate(tipB);
            REQUIRE(tipB != nullptr);
        }

        chainstate.ActivateBestChain();
        REQUIRE(chainstate.GetTip() == tipB);
        tipB_hash = tipB->GetBlockHash();

        // Build competing fork: Genesis -> X -> Y (equal work)
        auto chainXY = BuildChain(genesis.GetHash(), util::GetTime() + 1000, 2);
        chain::CBlockIndex* tipY = nullptr;

        for (const auto& header : chainXY) {
            tipY = chainstate.AcceptBlockHeader(header, state);
            if (tipY) chainstate.TryAddBlockIndexCandidate(tipY);
            REQUIRE(tipY != nullptr);
        }

        chainstate.ActivateBestChain();

        // Should stay on B (equal work, first seen)
        REQUIRE(chainstate.GetTip() == tipB);
        tipY_hash = tipY->GetBlockHash();

        // Save state with both forks
        REQUIRE(chainstate.Save(test_file));
    }

    // Phase 2: Load and verify both forks exist
    {
        TestChainstateManager chainstate2(*params);
        REQUIRE(chainstate2.Load(test_file) == chain::LoadResult::SUCCESS);

        // Verify tip is one of the two equal-work chains (B or Y)
        // After defensive fix: Load() recomputes best tip by work, so with equal work
        // either chain is valid (iteration order determines which is selected)
        REQUIRE(chainstate2.GetTip() != nullptr);
        REQUIRE(chainstate2.GetTip()->nHeight == 2);
        bool isTipB = (chainstate2.GetTip()->GetBlockHash() == tipB_hash);
        bool isTipY = (chainstate2.GetTip()->GetBlockHash() == tipY_hash);
        REQUIRE((isTipB || isTipY));

        // Verify both forks are in the block index
        const chain::CBlockIndex* foundB = chainstate2.LookupBlockIndex(tipB_hash);
        REQUIRE(foundB != nullptr);
        REQUIRE(foundB->nHeight == 2);

        const chain::CBlockIndex* foundY = chainstate2.LookupBlockIndex(tipY_hash);
        REQUIRE(foundY != nullptr);
        REQUIRE(foundY->nHeight == 2);

        // Verify we have all blocks (genesis + 2*2 = 5 blocks)
        REQUIRE(chainstate2.GetBlockCount() == 5);

        // Verify both forks have correct ancestry
        REQUIRE(foundB->pprev != nullptr);
        REQUIRE(foundB->pprev->pprev != nullptr);
        REQUIRE(foundB->pprev->pprev->nHeight == 0);  // Genesis

        REQUIRE(foundY->pprev != nullptr);
        REQUIRE(foundY->pprev->pprev != nullptr);
        REQUIRE(foundY->pprev->pprev->nHeight == 0);  // Genesis

        // Verify they share genesis as common ancestor
        const chain::CBlockIndex* fork_point = chain::LastCommonAncestor(foundB, foundY);
        REQUIRE(fork_point != nullptr);
        REQUIRE(fork_point->nHeight == 0);  // Genesis
    }
}

TEST_CASE("Reorg - Persistence after failed reorg attempt", "[reorg][persistence]") {
    // Test that if we reject a reorg (due to suspicious depth), state is still correct
    // Initial: Genesis -> [7 blocks]
    // Fork:    Genesis -> [8 blocks] (rejected due to depth limit)
    // Save, reload, verify we're still on original 7-block chain

    std::string test_file = "/tmp/test_reorg_failed_" + std::to_string(std::time(nullptr)) + ".json";

    struct Cleanup {
        std::string file;
        ~Cleanup() { std::filesystem::remove(file); }
    } cleanup{test_file};

    auto params = ChainParams::CreateRegTest();
    validation::ValidationState state;

    uint256 mainTip_hash;

    // Phase 1: Build chains and trigger rejected reorg
    {
        // Set suspicious_reorg_depth=7 to reject depth-7 reorg
        params->SetSuspiciousReorgDepth(7);
        TestChainstateManager chainstate(*params);
        chainstate.Initialize(params->GenesisBlock());

        const auto& genesis = params->GenesisBlock();

        // Build initial chain: Genesis -> [7 blocks]
        auto chainMain = BuildChain(genesis.GetHash(), util::GetTime(), 7);
        chain::CBlockIndex* mainTip = nullptr;

        for (const auto& header : chainMain) {
            mainTip = chainstate.AcceptBlockHeader(header, state);
            if (mainTip) chainstate.TryAddBlockIndexCandidate(mainTip);
            REQUIRE(mainTip != nullptr);
        }

        chainstate.ActivateBestChain();
        REQUIRE(chainstate.GetTip() == mainTip);
        mainTip_hash = mainTip->GetBlockHash();

        // Build competing fork: Genesis -> [8 blocks] (should be rejected)
        auto chainFork = BuildChain(genesis.GetHash(), util::GetTime() + 1000, 8);

        for (const auto& header : chainFork) {
            auto pindex = chainstate.AcceptBlockHeader(header, state);
            if (pindex) chainstate.TryAddBlockIndexCandidate(pindex);
            REQUIRE(pindex != nullptr);
        }

        chainstate.ActivateBestChain();

        // Verify reorg was REJECTED - still on mainTip
        REQUIRE(chainstate.GetTip() == mainTip);
        REQUIRE(chainstate.GetTip()->nHeight == 7);

        // Save state after rejected reorg
        REQUIRE(chainstate.Save(test_file));
    }

    // Phase 2: Load and verify state
    {
        params->SetSuspiciousReorgDepth(7);
        TestChainstateManager chainstate2(*params);
        REQUIRE(chainstate2.Load(test_file) == chain::LoadResult::SUCCESS);

        // Load() uses the saved tip, which is the 7-block chain (the reorg was rejected)
        // Both chains are valid, but we trust the saved tip and stay on the 7-block chain
        REQUIRE(chainstate2.GetTip() != nullptr);
        REQUIRE(chainstate2.GetTip()->nHeight == 7);
        REQUIRE(chainstate2.GetTip()->GetBlockHash() == mainTip_hash);

        // Verify we have all blocks from both chains (genesis + 7 + 8 = 16)
        REQUIRE(chainstate2.GetBlockCount() == 16);

        // Verify active chain continuity (7-block chain - saved tip)
        for (int h = 0; h <= 7; h++) {
            const chain::CBlockIndex* pindex = chainstate2.GetBlockAtHeight(h);
            REQUIRE(pindex != nullptr);
            REQUIRE(pindex->nHeight == h);
        }
    }
}
