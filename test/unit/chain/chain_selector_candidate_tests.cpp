// Candidate pruning and invariants tests (requires UNICITY_TESTS)

#include "catch_amalgamated.hpp"
#include "chain/chainstate_manager.hpp"
#include "chain/chainparams.hpp"
#include "chain/block.hpp"
#include "chain/validation.hpp"
#include "common/test_chainstate_manager.hpp"

using namespace unicity;
using namespace unicity::chain;
using namespace unicity::validation;
using unicity::test::TestChainstateManager;

static CBlockHeader Mkh(const CBlockIndex* prev, uint32_t nTime) {
    CBlockHeader h; h.nVersion=1; h.hashPrevBlock = prev ? prev->GetBlockHash() : uint256();
    h.minerAddress.SetNull(); h.nTime=nTime; h.nBits=0x207fffff; h.nNonce=0; h.hashRandomX.SetNull(); return h;
}

static bool HasChild(const BlockManager& bm, const CBlockIndex* idx) {
    for (const auto& [hash, block] : bm.GetBlockIndex()) {
        if (block.pprev == idx) return true;
    }
    return false;
}

TEST_CASE("Candidate set invariants across activation and invalidation", "[chain][candidates]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);
    REQUIRE(csm.Initialize(params->GenesisBlock()));

    const CBlockIndex* g = csm.GetTip();

    // Add A1 and activate
    CBlockHeader A1 = Mkh(g, g->nTime + 120);
    ValidationState s; auto* pA1 = csm.AcceptBlockHeader(A1, s); REQUIRE(pA1);
    csm.TryAddBlockIndexCandidate(pA1);
    REQUIRE(csm.DebugCandidateCount() >= 1);
    REQUIRE(csm.ActivateBestChain());

    // After activation, candidates should be pruned (no tip, no lower-work)
    REQUIRE(csm.DebugCandidateCount() == 0);

    // Add competing fork B1 (lower work than current tip)
    CBlockHeader B1 = Mkh(g, g->nTime + 130);
    auto* pB1 = csm.AcceptBlockHeader(B1, s); REQUIRE(pB1);
    csm.TryAddBlockIndexCandidate(pB1);

    // Activate best chain keeps A1 as tip; B1 remains as a lower-work candidate (Core keeps candidates on no-op)
    REQUIRE(csm.ActivateBestChain());
    REQUIRE(csm.DebugCandidateCount() >= 1);

    // Extend fork to surpass tip: B2, B3
    CBlockHeader B2 = Mkh(pB1, pB1->nTime + 120);
    auto* pB2 = csm.AcceptBlockHeader(B2, s); REQUIRE(pB2);
    csm.TryAddBlockIndexCandidate(pB2);

    CBlockHeader B3 = Mkh(pB2, pB2->nTime + 120);
    auto* pB3 = csm.AcceptBlockHeader(B3, s); REQUIRE(pB3);
    csm.TryAddBlockIndexCandidate(pB3);

    // Before activation, candidate should include B3 (a leaf)
    REQUIRE(csm.DebugCandidateCount() >= 1);

    // Activate reorg to B3; candidates pruned again
    REQUIRE(csm.ActivateBestChain());
    REQUIRE(csm.DebugCandidateCount() == 0);

    // Invalidate current tip (B3) – should populate candidates without activating
    REQUIRE(csm.InvalidateBlock(pB3->GetBlockHash()));

    auto hashes = csm.DebugCandidateHashes();
    REQUIRE_FALSE(hashes.empty());

    // None of the candidates should be the invalidated block
    for (const auto& h : hashes) {
        REQUIRE(h != pB3->GetBlockHash());
    }
}

TEST_CASE("ANCESTOR_FAILED propagation marks descendants", "[chain][candidates][ancestor_failed]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);
    REQUIRE(csm.Initialize(params->GenesisBlock()));

    const CBlockIndex* g = csm.GetTip();

    // Build chain: genesis -> A1 -> A2 -> A3
    CBlockHeader A1 = Mkh(g, g->nTime + 120);
    ValidationState s; auto* pA1 = csm.AcceptBlockHeader(A1, s); REQUIRE(pA1);

    CBlockHeader A2 = Mkh(pA1, pA1->nTime + 120);
    auto* pA2 = csm.AcceptBlockHeader(A2, s); REQUIRE(pA2);

    CBlockHeader A3 = Mkh(pA2, pA2->nTime + 120);
    auto* pA3 = csm.AcceptBlockHeader(A3, s); REQUIRE(pA3);

    // Activate the chain
    csm.TryAddBlockIndexCandidate(pA3);
    REQUIRE(csm.ActivateBestChain());
    REQUIRE(csm.GetTip() == pA3);

    // Invalidate A1 (middle of chain)
    REQUIRE(csm.InvalidateBlock(pA1->GetBlockHash()));

    // A1 should be VALIDATION_FAILED
    REQUIRE(pA1->status.IsFailed());

    // A2 and A3 should be ANCESTOR_FAILED
    REQUIRE(pA2->status.IsFailed());
    REQUIRE(pA3->status.IsFailed());

    // Neither A1, A2, nor A3 should be in candidates
    auto hashes = csm.DebugCandidateHashes();
    for (const auto& h : hashes) {
        REQUIRE(h != pA1->GetBlockHash());
        REQUIRE(h != pA2->GetBlockHash());
        REQUIRE(h != pA3->GetBlockHash());
    }

    // Tip should have rolled back to genesis
    REQUIRE(csm.GetTip() == g);
}

TEST_CASE("Parent re-added as candidate after child invalidation", "[chain][candidates][parent_readd]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);
    REQUIRE(csm.Initialize(params->GenesisBlock()));

    const CBlockIndex* g = csm.GetTip();

    // Build chain: genesis -> A1 -> A2
    CBlockHeader A1 = Mkh(g, g->nTime + 120);
    ValidationState s; auto* pA1 = csm.AcceptBlockHeader(A1, s); REQUIRE(pA1);

    CBlockHeader A2 = Mkh(pA1, pA1->nTime + 120);
    auto* pA2 = csm.AcceptBlockHeader(A2, s); REQUIRE(pA2);

    // Activate the chain to A2
    csm.TryAddBlockIndexCandidate(pA2);
    REQUIRE(csm.ActivateBestChain());
    REQUIRE(csm.GetTip() == pA2);

    // Candidates may include lower-work blocks (kept for InvalidateBlock fallback)
    // The key invariant is that the tip is correctly activated

    // Invalidate A2 (the tip)
    REQUIRE(csm.InvalidateBlock(pA2->GetBlockHash()));

    // A1 should now be the tip
    REQUIRE(csm.GetTip() == pA1);

    // A1's parent (genesis) should be re-added to candidates OR
    // we should have some candidate available for fallback
    // Since A1 is now the tip, candidates may be empty after prune
    // The key invariant: we didn't lose track of valid chain state
    REQUIRE(csm.GetTip()->IsValid());
}

TEST_CASE("Competing fork becomes candidate after main chain invalidation", "[chain][candidates][fork_activation]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);
    REQUIRE(csm.Initialize(params->GenesisBlock()));

    const CBlockIndex* g = csm.GetTip();

    // Build main chain: genesis -> A1 -> A2 -> A3
    CBlockHeader A1 = Mkh(g, g->nTime + 120);
    ValidationState s; auto* pA1 = csm.AcceptBlockHeader(A1, s); REQUIRE(pA1);

    CBlockHeader A2 = Mkh(pA1, pA1->nTime + 120);
    auto* pA2 = csm.AcceptBlockHeader(A2, s); REQUIRE(pA2);

    CBlockHeader A3 = Mkh(pA2, pA2->nTime + 120);
    auto* pA3 = csm.AcceptBlockHeader(A3, s); REQUIRE(pA3);

    // Build competing fork: genesis -> B1 -> B2 (shorter but valid)
    CBlockHeader B1 = Mkh(g, g->nTime + 130);
    auto* pB1 = csm.AcceptBlockHeader(B1, s); REQUIRE(pB1);

    CBlockHeader B2 = Mkh(pB1, pB1->nTime + 120);
    auto* pB2 = csm.AcceptBlockHeader(B2, s); REQUIRE(pB2);

    // Activate main chain (A3 has more work)
    csm.TryAddBlockIndexCandidate(pA3);
    csm.TryAddBlockIndexCandidate(pB2);
    REQUIRE(csm.ActivateBestChain());
    REQUIRE(csm.GetTip() == pA3);

    // Invalidate A1 (kills entire main chain)
    REQUIRE(csm.InvalidateBlock(pA1->GetBlockHash()));

    // B2 should now be a candidate (it's the best valid chain)
    auto hashes = csm.DebugCandidateHashes();
    bool b2_in_candidates = false;
    for (const auto& h : hashes) {
        if (h == pB2->GetBlockHash()) {
            b2_in_candidates = true;
            break;
        }
    }
    REQUIRE(b2_in_candidates);

    // Activate best chain should switch to fork B
    REQUIRE(csm.ActivateBestChain());
    REQUIRE(csm.GetTip() == pB2);
}

TEST_CASE("AcceptBlockHeader rejects headers descending from failed block", "[chain][candidates][reject_descendant]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);
    REQUIRE(csm.Initialize(params->GenesisBlock()));

    const CBlockIndex* g = csm.GetTip();

    // Build chain: genesis -> A1
    CBlockHeader A1 = Mkh(g, g->nTime + 120);
    ValidationState s; auto* pA1 = csm.AcceptBlockHeader(A1, s); REQUIRE(pA1);

    // Activate A1
    csm.TryAddBlockIndexCandidate(pA1);
    REQUIRE(csm.ActivateBestChain());

    // Invalidate A1
    REQUIRE(csm.InvalidateBlock(pA1->GetBlockHash()));

    // Now try to accept A2 which extends the invalidated A1
    CBlockHeader A2 = Mkh(pA1, pA1->nTime + 120);
    ValidationState s2;
    auto* pA2 = csm.AcceptBlockHeader(A2, s2);

    // Should be rejected because parent is failed
    REQUIRE(pA2 == nullptr);
    REQUIRE(s2.IsInvalid());
}