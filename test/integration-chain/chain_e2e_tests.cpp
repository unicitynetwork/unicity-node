// End-to-End Chain State Verification Tests
//
// These tests verify FINAL OBSERVABLE BEHAVIOR, not intermediate state.
// Every test checks GetChainHeight() and GetBestBlockHash() to ensure
// chain operations actually result in correct tip advancement.

#include "catch_amalgamated.hpp"
#include "common/test_chainstate_manager.hpp"
#include "chain/validation.hpp"
#include "chain/chainparams.hpp"
#include "chain/block.hpp"

using namespace unicity;
using namespace unicity::test;
using namespace unicity::chain;
using unicity::validation::ValidationState;

namespace {

CBlockHeader CreateTestHeader(const uint256& prevHash, uint32_t nTime, uint32_t nNonce = 12345) {
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock = prevHash;
    header.minerAddress.SetNull();
    header.nTime = nTime;
    header.nBits = 0x207fffff;
    header.nNonce = nNonce;
    header.hashRandomX.SetNull();
    return header;
}

// Helper to build a chain of headers
std::vector<CBlockHeader> BuildHeaderChain(const uint256& startHash, uint32_t startTime,
                                            size_t count, uint32_t nonceStart = 1000) {
    std::vector<CBlockHeader> headers;
    headers.reserve(count);

    uint256 prevHash = startHash;
    for (size_t i = 0; i < count; i++) {
        CBlockHeader h = CreateTestHeader(prevHash, startTime + 120 * (i + 1), nonceStart + i);
        prevHash = h.GetHash();
        headers.push_back(h);
    }
    return headers;
}

// Helper to accept headers and add to candidates
bool AcceptHeadersToChain(TestChainstateManager& chainstate,
                          const std::vector<CBlockHeader>& headers) {
    for (const auto& header : headers) {
        ValidationState st;
        chain::CBlockIndex* pindex = chainstate.AcceptBlockHeader(header, st);
        if (!pindex) return false;
        chainstate.TryAddBlockIndexCandidate(pindex);
    }
    return true;
}

} // anonymous namespace

TEST_CASE("E2E: Header chain advances tip correctly", "[e2e][chain][critical]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());
    chainstate.SetBypassPOWValidation(true);
    const auto& genesis = params->GenesisBlock();

    SECTION("Single header advances tip by 1") {
        REQUIRE(chainstate.GetChainHeight() == 0);

        CBlockHeader h1 = CreateTestHeader(genesis.GetHash(), genesis.nTime + 120, 1000);

        ValidationState st;
        chain::CBlockIndex* pindex = chainstate.AcceptBlockHeader(h1, st);
        REQUIRE(pindex != nullptr);
        chainstate.TryAddBlockIndexCandidate(pindex);

        REQUIRE(chainstate.ActivateBestChain(nullptr));

        // E2E verification: chain height advanced
        REQUIRE(chainstate.GetChainHeight() == 1);
        // E2E verification: tip is correct block
        REQUIRE(chainstate.GetTip()->GetBlockHash() == h1.GetHash());
    }

    SECTION("Chain of 10 headers advances tip to height 10") {
        REQUIRE(chainstate.GetChainHeight() == 0);

        auto headers = BuildHeaderChain(genesis.GetHash(), genesis.nTime, 10);
        REQUIRE(AcceptHeadersToChain(chainstate, headers));
        REQUIRE(chainstate.ActivateBestChain(nullptr));

        // E2E verification: full chain height
        REQUIRE(chainstate.GetChainHeight() == 10);
        // E2E verification: tip is last header
        REQUIRE(chainstate.GetTip()->GetBlockHash() == headers.back().GetHash());
    }

    SECTION("Chain of 100 headers advances tip to height 100") {
        REQUIRE(chainstate.GetChainHeight() == 0);

        auto headers = BuildHeaderChain(genesis.GetHash(), genesis.nTime, 100);
        REQUIRE(AcceptHeadersToChain(chainstate, headers));
        REQUIRE(chainstate.ActivateBestChain(nullptr));

        // E2E verification: full chain height
        REQUIRE(chainstate.GetChainHeight() == 100);
        // E2E verification: tip is last header
        REQUIRE(chainstate.GetTip()->GetBlockHash() == headers.back().GetHash());
    }

    SECTION("Headers in batches result in correct final height") {
        REQUIRE(chainstate.GetChainHeight() == 0);

        // Batch 1: first 5 headers
        auto batch1 = BuildHeaderChain(genesis.GetHash(), genesis.nTime, 5, 1000);
        REQUIRE(AcceptHeadersToChain(chainstate, batch1));
        REQUIRE(chainstate.ActivateBestChain(nullptr));
        REQUIRE(chainstate.GetChainHeight() == 5);

        // Batch 2: next 5 headers
        auto batch2 = BuildHeaderChain(batch1.back().GetHash(), genesis.nTime + 600, 5, 2000);
        REQUIRE(AcceptHeadersToChain(chainstate, batch2));
        REQUIRE(chainstate.ActivateBestChain(nullptr));

        // E2E verification: combined height
        REQUIRE(chainstate.GetChainHeight() == 10);
        REQUIRE(chainstate.GetTip()->GetBlockHash() == batch2.back().GetHash());
    }
}

TEST_CASE("E2E: Reorg results in correct final chain", "[e2e][chain][reorg][critical]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());
    chainstate.SetBypassPOWValidation(true);
    const auto& genesis = params->GenesisBlock();

    SECTION("Longer chain wins reorg") {
        // Build initial chain: genesis -> A -> B -> C (height 3)
        auto chainA = BuildHeaderChain(genesis.GetHash(), genesis.nTime, 3, 1000);
        REQUIRE(AcceptHeadersToChain(chainstate, chainA));
        REQUIRE(chainstate.ActivateBestChain(nullptr));

        REQUIRE(chainstate.GetChainHeight() == 3);
        uint256 oldTip = chainstate.GetTip()->GetBlockHash();
        REQUIRE(oldTip == chainA.back().GetHash());

        // Build competing chain: genesis -> A' -> B' -> C' -> D' (height 4)
        auto chainB = BuildHeaderChain(genesis.GetHash(), genesis.nTime, 4, 2000);
        REQUIRE(AcceptHeadersToChain(chainstate, chainB));
        REQUIRE(chainstate.ActivateBestChain(nullptr));

        // E2E verification: longer chain wins
        REQUIRE(chainstate.GetChainHeight() == 4);
        REQUIRE(chainstate.GetTip()->GetBlockHash() == chainB.back().GetHash());
        // E2E verification: old tip is NOT the current tip
        REQUIRE(chainstate.GetTip()->GetBlockHash() != oldTip);
    }

    SECTION("Same-length chain does NOT cause reorg (first-seen wins)") {
        // Build initial chain: height 3
        auto chainA = BuildHeaderChain(genesis.GetHash(), genesis.nTime, 3, 1000);
        REQUIRE(AcceptHeadersToChain(chainstate, chainA));
        REQUIRE(chainstate.ActivateBestChain(nullptr));

        uint256 originalTip = chainstate.GetTip()->GetBlockHash();
        REQUIRE(chainstate.GetChainHeight() == 3);

        // Build competing chain: also height 3 (different blocks)
        auto chainB = BuildHeaderChain(genesis.GetHash(), genesis.nTime, 3, 2000);
        REQUIRE(AcceptHeadersToChain(chainstate, chainB));
        REQUIRE(chainstate.ActivateBestChain(nullptr));

        // E2E verification: original chain retained (first-seen wins for same height)
        REQUIRE(chainstate.GetChainHeight() == 3);
        REQUIRE(chainstate.GetTip()->GetBlockHash() == originalTip);
    }

    SECTION("Deep reorg replaces entire chain") {
        // Build initial chain: height 10
        auto chainA = BuildHeaderChain(genesis.GetHash(), genesis.nTime, 10, 1000);
        REQUIRE(AcceptHeadersToChain(chainstate, chainA));
        REQUIRE(chainstate.ActivateBestChain(nullptr));
        REQUIRE(chainstate.GetChainHeight() == 10);

        // Build competing chain: height 15 (completely different from genesis)
        auto chainB = BuildHeaderChain(genesis.GetHash(), genesis.nTime, 15, 2000);
        REQUIRE(AcceptHeadersToChain(chainstate, chainB));
        REQUIRE(chainstate.ActivateBestChain(nullptr));

        // E2E verification: new chain is active
        REQUIRE(chainstate.GetChainHeight() == 15);
        REQUIRE(chainstate.GetTip()->GetBlockHash() == chainB.back().GetHash());

        // E2E verification: verify chain structure by walking back
        const chain::CBlockIndex* tip = chainstate.LookupBlockIndex(chainB.back().GetHash());
        REQUIRE(tip != nullptr);
        REQUIRE(tip->nHeight == 15);

        // Walk back and verify all blocks are from chainB
        const chain::CBlockIndex* current = tip;
        for (int i = 14; i >= 0; i--) {
            REQUIRE(current->pprev != nullptr);
            current = current->pprev;
            REQUIRE(current->nHeight == i);
            if (i > 0) {
                REQUIRE(current->GetBlockHash() == chainB[i-1].GetHash());
            }
        }
        // Should end at genesis
        REQUIRE(current->GetBlockHash() == genesis.GetHash());
    }

    SECTION("Partial reorg at fork point") {
        // Build common prefix: genesis -> A -> B (height 2)
        auto common = BuildHeaderChain(genesis.GetHash(), genesis.nTime, 2, 1000);
        REQUIRE(AcceptHeadersToChain(chainstate, common));
        REQUIRE(chainstate.ActivateBestChain(nullptr));
        REQUIRE(chainstate.GetChainHeight() == 2);

        // Extend with chain1: B -> C1 -> D1 (height 4)
        auto chain1 = BuildHeaderChain(common.back().GetHash(), genesis.nTime + 240, 2, 3000);
        REQUIRE(AcceptHeadersToChain(chainstate, chain1));
        REQUIRE(chainstate.ActivateBestChain(nullptr));
        REQUIRE(chainstate.GetChainHeight() == 4);
        uint256 chain1Tip = chainstate.GetTip()->GetBlockHash();

        // Competing fork from B: B -> C2 -> D2 -> E2 (height 5)
        auto chain2 = BuildHeaderChain(common.back().GetHash(), genesis.nTime + 240, 3, 4000);
        REQUIRE(AcceptHeadersToChain(chainstate, chain2));
        REQUIRE(chainstate.ActivateBestChain(nullptr));

        // E2E verification: longer fork wins
        REQUIRE(chainstate.GetChainHeight() == 5);
        REQUIRE(chainstate.GetTip()->GetBlockHash() == chain2.back().GetHash());
        REQUIRE(chainstate.GetTip()->GetBlockHash() != chain1Tip);

        // E2E verification: common prefix is still in chain
        REQUIRE(chainstate.LookupBlockIndex(common[0].GetHash()) != nullptr);
        REQUIRE(chainstate.LookupBlockIndex(common[1].GetHash()) != nullptr);
    }
}

TEST_CASE("E2E: Chain walk from tip to genesis is valid", "[e2e][chain][structure]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());
    chainstate.SetBypassPOWValidation(true);
    const auto& genesis = params->GenesisBlock();

    SECTION("50-block chain has valid structure") {
        const int CHAIN_LENGTH = 50;
        auto headers = BuildHeaderChain(genesis.GetHash(), genesis.nTime, CHAIN_LENGTH);
        REQUIRE(AcceptHeadersToChain(chainstate, headers));
        REQUIRE(chainstate.ActivateBestChain(nullptr));

        REQUIRE(chainstate.GetChainHeight() == CHAIN_LENGTH);

        // Walk from tip to genesis, verify structure
        const chain::CBlockIndex* current = chainstate.LookupBlockIndex(chainstate.GetTip()->GetBlockHash());
        REQUIRE(current != nullptr);

        int expectedHeight = CHAIN_LENGTH;
        while (current != nullptr) {
            // Verify height is correct
            REQUIRE(current->nHeight == expectedHeight);

            // Verify hash matches (except genesis)
            if (expectedHeight > 0) {
                REQUIRE(current->GetBlockHash() == headers[expectedHeight - 1].GetHash());
            } else {
                REQUIRE(current->GetBlockHash() == genesis.GetHash());
            }

            // Verify pprev relationship
            if (expectedHeight > 0) {
                REQUIRE(current->pprev != nullptr);
                REQUIRE(current->pprev->nHeight == expectedHeight - 1);
            }

            current = current->pprev;
            expectedHeight--;
        }

        // Should have walked exactly to before genesis
        REQUIRE(expectedHeight == -1);
    }
}

TEST_CASE("E2E: Multiple competing forks resolve correctly", "[e2e][chain][fork]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());
    chainstate.SetBypassPOWValidation(true);
    const auto& genesis = params->GenesisBlock();

    SECTION("Three competing forks - longest wins") {
        // Fork 1: height 5
        auto fork1 = BuildHeaderChain(genesis.GetHash(), genesis.nTime, 5, 1000);
        REQUIRE(AcceptHeadersToChain(chainstate, fork1));
        REQUIRE(chainstate.ActivateBestChain(nullptr));
        REQUIRE(chainstate.GetChainHeight() == 5);

        // Fork 2: height 7 (should become tip)
        auto fork2 = BuildHeaderChain(genesis.GetHash(), genesis.nTime, 7, 2000);
        REQUIRE(AcceptHeadersToChain(chainstate, fork2));
        REQUIRE(chainstate.ActivateBestChain(nullptr));
        REQUIRE(chainstate.GetChainHeight() == 7);
        REQUIRE(chainstate.GetTip()->GetBlockHash() == fork2.back().GetHash());

        // Fork 3: height 6 (should NOT become tip)
        auto fork3 = BuildHeaderChain(genesis.GetHash(), genesis.nTime, 6, 3000);
        REQUIRE(AcceptHeadersToChain(chainstate, fork3));
        REQUIRE(chainstate.ActivateBestChain(nullptr));

        // E2E verification: fork2 (longest) is still tip
        REQUIRE(chainstate.GetChainHeight() == 7);
        REQUIRE(chainstate.GetTip()->GetBlockHash() == fork2.back().GetHash());
    }

    SECTION("Fork extension makes shorter fork win") {
        // Initial: fork1 at height 5, fork2 at height 3
        auto fork1 = BuildHeaderChain(genesis.GetHash(), genesis.nTime, 5, 1000);
        auto fork2 = BuildHeaderChain(genesis.GetHash(), genesis.nTime, 3, 2000);

        REQUIRE(AcceptHeadersToChain(chainstate, fork1));
        REQUIRE(AcceptHeadersToChain(chainstate, fork2));
        REQUIRE(chainstate.ActivateBestChain(nullptr));

        REQUIRE(chainstate.GetChainHeight() == 5);
        REQUIRE(chainstate.GetTip()->GetBlockHash() == fork1.back().GetHash());

        // Extend fork2 to height 7
        auto fork2_ext = BuildHeaderChain(fork2.back().GetHash(), genesis.nTime + 360, 4, 3000);
        REQUIRE(AcceptHeadersToChain(chainstate, fork2_ext));
        REQUIRE(chainstate.ActivateBestChain(nullptr));

        // E2E verification: extended fork2 is now tip
        REQUIRE(chainstate.GetChainHeight() == 7);
        REQUIRE(chainstate.GetTip()->GetBlockHash() == fork2_ext.back().GetHash());
    }
}

// Note: Test "E2E: Headers received out of order still result in correct chain"
// was removed because orphan pool infrastructure was removed. Out-of-order headers
// are now discarded and trigger GETHEADERS requests to fill the gap.
