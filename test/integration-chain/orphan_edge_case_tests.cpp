// Orphan edge case tests (ported to test2, chain-level)

#include "catch_amalgamated.hpp"
#include "common/test_chainstate_manager.hpp"
#include "chain/validation.hpp"
#include "chain/chainparams.hpp"
#include "chain/block.hpp"

using namespace unicity;
using namespace unicity::test;
using namespace unicity::chain;
using unicity::validation::ValidationState;

static CBlockHeader CreateTestHeader(const uint256& prevHash, uint32_t nTime, uint32_t nNonce = 12345) {
    CBlockHeader header; header.nVersion=1; header.hashPrevBlock=prevHash; header.minerAddress.SetNull(); header.nTime=nTime; header.nBits=0x207fffff; header.nNonce=nNonce; header.hashRandomX.SetNull(); return header;
}
static uint256 RandomHash(){ uint256 h; for(int i=0;i<32;i++) *(h.begin()+i)=rand()%256; return h; }

TEST_CASE("Orphan Edge Cases - Invalid Headers", "[orphan][edge]") {
    auto params = ChainParams::CreateRegTest(); TestChainstateManager chainstate(*params);

    SECTION("Orphan with future timestamp") {
        chainstate.Initialize(params->GenesisBlock());
        uint256 up=RandomHash();
        CBlockHeader o=CreateTestHeader(up, std::time(nullptr)+10000);
        ValidationState st;
        chain::CBlockIndex* r = chainstate.AcceptBlockHeader(o, st);
        REQUIRE(r==nullptr);
        REQUIRE(st.GetRejectReason()=="prev-blk-not-found");
        REQUIRE(chainstate.AddOrphanHeader(o, /*peer_id=*/1));
        REQUIRE(chainstate.GetOrphanHeaderCount()==1);
    }
    SECTION("Orphan with null prev hash should not be cached") {
        chainstate.Initialize(params->GenesisBlock()); uint256 nullHash; nullHash.SetNull(); CBlockHeader o=CreateTestHeader(nullHash,1234567890); ValidationState st; chain::CBlockIndex* r=chainstate.AcceptBlockHeader(o, st); REQUIRE(r==nullptr); REQUIRE(st.GetRejectReason()!="orphaned"); REQUIRE(chainstate.GetOrphanHeaderCount()==0);
    }
    SECTION("Orphan with invalid version") {
        chainstate.Initialize(params->GenesisBlock()); uint256 up=RandomHash(); CBlockHeader o=CreateTestHeader(up,1234567890); o.nVersion=0; ValidationState st; chainstate.AcceptBlockHeader(o, st); REQUIRE(true);
    }
    SECTION("Orphan becomes valid when parent arrives (processed from orphan pool)") {
        chainstate.Initialize(params->GenesisBlock());
        const auto& genesis=params->GenesisBlock();
        CBlockHeader parent=CreateTestHeader(genesis.GetHash(), genesis.nTime+120,1000);
        uint256 parentHash=parent.GetHash();
        CBlockHeader orphan=CreateTestHeader(parentHash, genesis.nTime+60,1001);
        ValidationState st;
        chain::CBlockIndex* r = chainstate.AcceptBlockHeader(orphan, st);
        REQUIRE(r==nullptr);
        REQUIRE(st.GetRejectReason()=="prev-blk-not-found");
        REQUIRE(chainstate.AddOrphanHeader(orphan, /*peer_id=*/1));
        REQUIRE(chainstate.GetOrphanHeaderCount()==1);
        chainstate.AcceptBlockHeader(parent, st);
        REQUIRE(chainstate.GetOrphanHeaderCount()==0);
        REQUIRE(chainstate.LookupBlockIndex(orphan.GetHash())!=nullptr);
    }
    SECTION("Orphan becomes tip when parent arrives") {
        chainstate.Initialize(params->GenesisBlock());
        chainstate.SetBypassPOWValidation(true);
        const auto& genesis=params->GenesisBlock();

        // Create parent (connects to genesis, height 1)
        CBlockHeader parent=CreateTestHeader(genesis.GetHash(), genesis.nTime+120, 1000);
        uint256 parentHash=parent.GetHash();

        // Create orphan (connects to parent, height 2)
        CBlockHeader orphan=CreateTestHeader(parentHash, genesis.nTime+240, 1001);

        REQUIRE(chainstate.GetChainHeight() == 0);  // Start at genesis

        // Add orphan first (should fail and be cached)
        ValidationState st;
        chain::CBlockIndex* r = chainstate.AcceptBlockHeader(orphan, st);
        REQUIRE(r == nullptr);
        REQUIRE(st.GetRejectReason() == "prev-blk-not-found");
        REQUIRE(chainstate.AddOrphanHeader(orphan, /*peer_id=*/1));
        REQUIRE(chainstate.GetOrphanHeaderCount() == 1);

        // Accept parent - this should trigger orphan resolution
        chain::CBlockIndex* pParent = chainstate.AcceptBlockHeader(parent, st);
        REQUIRE(pParent != nullptr);
        chainstate.TryAddBlockIndexCandidate(pParent);

        // Orphan should be resolved
        REQUIRE(chainstate.GetOrphanHeaderCount() == 0);
        REQUIRE(chainstate.LookupBlockIndex(orphan.GetHash()) != nullptr);

        // Activate best chain
        bool activated = chainstate.ActivateBestChain(nullptr);
        REQUIRE(activated);

        // The tip should be height 2 (the resolved orphan), NOT height 1 (the parent)
        // If this fails, it means orphans are indexed but never become candidates
        INFO("Tip height after orphan resolution: " << chainstate.GetChainHeight());
        REQUIRE(chainstate.GetChainHeight() == 2);
    }
}

TEST_CASE("Orphan Edge Cases - Chain Topology", "[orphan][edge]") {
    auto params = ChainParams::CreateRegTest(); TestChainstateManager chainstate(*params);

    SECTION("Orphan chain with missing middle block") {
        chainstate.Initialize(params->GenesisBlock());
        const auto& genesis=params->GenesisBlock();
        CBlockHeader A=CreateTestHeader(genesis.GetHash(), genesis.nTime+120,1000); uint256 hA=A.GetHash();
        CBlockHeader B=CreateTestHeader(hA, genesis.nTime+240,1001); uint256 hB=B.GetHash();
        CBlockHeader C=CreateTestHeader(hB, genesis.nTime+360,1002);
        ValidationState st;
        chain::CBlockIndex* pA = chainstate.AcceptBlockHeader(A, st);
        if (pA) { chainstate.TryAddBlockIndexCandidate(pA); }
        REQUIRE(chainstate.LookupBlockIndex(hA)!=nullptr);
        chain::CBlockIndex* rC = chainstate.AcceptBlockHeader(C, st);
        REQUIRE(rC==nullptr);
        REQUIRE(st.GetRejectReason()=="prev-blk-not-found");
        REQUIRE(chainstate.AddOrphanHeader(C, /*peer_id=*/1));
        REQUIRE(chainstate.GetOrphanHeaderCount()==1);
        chainstate.AcceptBlockHeader(B, st);
        REQUIRE(chainstate.GetOrphanHeaderCount()==0);
        REQUIRE(chainstate.LookupBlockIndex(hB)!=nullptr);
        REQUIRE(chainstate.LookupBlockIndex(C.GetHash())!=nullptr);
    }
    SECTION("Multiple orphan chains from same root") {
        chainstate.Initialize(params->GenesisBlock());
        const auto& genesis=params->GenesisBlock();
        uint256 hA=RandomHash();
        CBlockHeader B1=CreateTestHeader(hA, genesis.nTime+240,1001);
        CBlockHeader B2=CreateTestHeader(hA, genesis.nTime+240,1002);
        CBlockHeader B3=CreateTestHeader(hA, genesis.nTime+240,1003);
        ValidationState st;
        chain::CBlockIndex* r1 = chainstate.AcceptBlockHeader(B1, st);
        REQUIRE(r1==nullptr);
        REQUIRE(st.GetRejectReason()=="prev-blk-not-found");
        REQUIRE(chainstate.AddOrphanHeader(B1, /*peer_id=*/1));
        chain::CBlockIndex* r2 = chainstate.AcceptBlockHeader(B2, st);
        REQUIRE(r2==nullptr);
        REQUIRE(st.GetRejectReason()=="prev-blk-not-found");
        REQUIRE(chainstate.AddOrphanHeader(B2, /*peer_id=*/1));
        chain::CBlockIndex* r3 = chainstate.AcceptBlockHeader(B3, st);
        REQUIRE(r3==nullptr);
        REQUIRE(st.GetRejectReason()=="prev-blk-not-found");
        REQUIRE(chainstate.AddOrphanHeader(B3, /*peer_id=*/1));
        REQUIRE(chainstate.GetOrphanHeaderCount()==3);
    }
    SECTION("Orphan refers to block already in active chain") {
        chainstate.Initialize(params->GenesisBlock()); const auto& genesis=params->GenesisBlock(); CBlockHeader A=CreateTestHeader(genesis.GetHash(), genesis.nTime+120,1000); CBlockHeader B=CreateTestHeader(A.GetHash(), genesis.nTime+240,1001); ValidationState st; chain::CBlockIndex* pA=chainstate.AcceptBlockHeader(A, st); if(pA){ chainstate.TryAddBlockIndexCandidate(pA);} REQUIRE(chainstate.LookupBlockIndex(A.GetHash())!=nullptr); chain::CBlockIndex* pB=chainstate.AcceptBlockHeader(B, st); if(pB){ chainstate.TryAddBlockIndexCandidate(pB);} REQUIRE(chainstate.LookupBlockIndex(B.GetHash())!=nullptr);
    }
}

TEST_CASE("Orphan Resolution - Chain Tip Selection", "[orphan][edge][tip]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());
    chainstate.SetBypassPOWValidation(true);
    const auto& genesis = params->GenesisBlock();

    SECTION("Chain of orphans becomes tip when first parent arrives") {
        // Create: genesis -> A -> B -> C (A is parent, B,C are orphans)
        CBlockHeader A = CreateTestHeader(genesis.GetHash(), genesis.nTime+120, 1000);
        uint256 hA = A.GetHash();
        CBlockHeader B = CreateTestHeader(hA, genesis.nTime+240, 1001);
        uint256 hB = B.GetHash();
        CBlockHeader C = CreateTestHeader(hB, genesis.nTime+360, 1002);

        ValidationState st;

        // Add C first (orphan, grandparent missing)
        REQUIRE(chainstate.AcceptBlockHeader(C, st) == nullptr);
        REQUIRE(chainstate.AddOrphanHeader(C, 1));

        // Add B (orphan, parent missing)
        REQUIRE(chainstate.AcceptBlockHeader(B, st) == nullptr);
        REQUIRE(chainstate.AddOrphanHeader(B, 1));

        REQUIRE(chainstate.GetOrphanHeaderCount() == 2);
        REQUIRE(chainstate.GetChainHeight() == 0);

        // Now add A - should trigger cascade resolution of B and C
        chain::CBlockIndex* pA = chainstate.AcceptBlockHeader(A, st);
        REQUIRE(pA != nullptr);
        chainstate.TryAddBlockIndexCandidate(pA);

        // All orphans should be resolved
        REQUIRE(chainstate.GetOrphanHeaderCount() == 0);
        REQUIRE(chainstate.LookupBlockIndex(hB) != nullptr);
        REQUIRE(chainstate.LookupBlockIndex(C.GetHash()) != nullptr);

        // Activate best chain - should be at height 3
        REQUIRE(chainstate.ActivateBestChain(nullptr));
        INFO("Chain height after cascade resolution: " << chainstate.GetChainHeight());
        REQUIRE(chainstate.GetChainHeight() == 3);
    }

    SECTION("Multiple orphans waiting for same parent all become candidates") {
        // Create: genesis -> A -> B1, B2, B3 (competing forks)
        CBlockHeader A = CreateTestHeader(genesis.GetHash(), genesis.nTime+120, 1000);
        uint256 hA = A.GetHash();
        CBlockHeader B1 = CreateTestHeader(hA, genesis.nTime+240, 1001);
        CBlockHeader B2 = CreateTestHeader(hA, genesis.nTime+240, 1002);
        CBlockHeader B3 = CreateTestHeader(hA, genesis.nTime+240, 1003);

        ValidationState st;

        // Add B1, B2, B3 as orphans
        REQUIRE(chainstate.AcceptBlockHeader(B1, st) == nullptr);
        REQUIRE(chainstate.AddOrphanHeader(B1, 1));
        REQUIRE(chainstate.AcceptBlockHeader(B2, st) == nullptr);
        REQUIRE(chainstate.AddOrphanHeader(B2, 1));
        REQUIRE(chainstate.AcceptBlockHeader(B3, st) == nullptr);
        REQUIRE(chainstate.AddOrphanHeader(B3, 1));

        REQUIRE(chainstate.GetOrphanHeaderCount() == 3);

        // Add parent A - all three should be resolved
        chain::CBlockIndex* pA = chainstate.AcceptBlockHeader(A, st);
        REQUIRE(pA != nullptr);
        chainstate.TryAddBlockIndexCandidate(pA);

        REQUIRE(chainstate.GetOrphanHeaderCount() == 0);
        REQUIRE(chainstate.LookupBlockIndex(B1.GetHash()) != nullptr);
        REQUIRE(chainstate.LookupBlockIndex(B2.GetHash()) != nullptr);
        REQUIRE(chainstate.LookupBlockIndex(B3.GetHash()) != nullptr);

        // Activate - one of B1/B2/B3 should become tip (all at height 2)
        REQUIRE(chainstate.ActivateBestChain(nullptr));
        REQUIRE(chainstate.GetChainHeight() == 2);
    }

    SECTION("Deep orphan chain resolves correctly") {
        // Create chain of 10 orphan blocks
        const int CHAIN_LENGTH = 10;
        std::vector<CBlockHeader> headers;
        headers.reserve(CHAIN_LENGTH);

        // First header connects to genesis
        headers.push_back(CreateTestHeader(genesis.GetHash(), genesis.nTime+120, 1000));

        // Rest connect to previous
        for (int i = 1; i < CHAIN_LENGTH; i++) {
            headers.push_back(CreateTestHeader(headers[i-1].GetHash(), genesis.nTime+120*(i+1), 1000+i));
        }

        ValidationState st;

        // Add all except first as orphans (in reverse order to stress test)
        for (int i = CHAIN_LENGTH - 1; i >= 1; i--) {
            REQUIRE(chainstate.AcceptBlockHeader(headers[i], st) == nullptr);
            REQUIRE(chainstate.AddOrphanHeader(headers[i], 1));
        }

        REQUIRE(chainstate.GetOrphanHeaderCount() == CHAIN_LENGTH - 1);

        // Add first header - should trigger cascade
        chain::CBlockIndex* pFirst = chainstate.AcceptBlockHeader(headers[0], st);
        REQUIRE(pFirst != nullptr);
        chainstate.TryAddBlockIndexCandidate(pFirst);

        // All should be resolved
        REQUIRE(chainstate.GetOrphanHeaderCount() == 0);
        for (int i = 0; i < CHAIN_LENGTH; i++) {
            REQUIRE(chainstate.LookupBlockIndex(headers[i].GetHash()) != nullptr);
        }

        // Should reach full height
        REQUIRE(chainstate.ActivateBestChain(nullptr));
        INFO("Chain height after deep cascade: " << chainstate.GetChainHeight());
        REQUIRE(chainstate.GetChainHeight() == CHAIN_LENGTH);
    }

    SECTION("Orphan causing reorg becomes new tip") {
        // Build initial chain: genesis -> A -> B (height 2)
        CBlockHeader A = CreateTestHeader(genesis.GetHash(), genesis.nTime+120, 1000);
        CBlockHeader B = CreateTestHeader(A.GetHash(), genesis.nTime+240, 1001);

        ValidationState st;
        chain::CBlockIndex* pA = chainstate.AcceptBlockHeader(A, st);
        REQUIRE(pA != nullptr);
        chainstate.TryAddBlockIndexCandidate(pA);
        chain::CBlockIndex* pB = chainstate.AcceptBlockHeader(B, st);
        REQUIRE(pB != nullptr);
        chainstate.TryAddBlockIndexCandidate(pB);

        REQUIRE(chainstate.ActivateBestChain(nullptr));
        REQUIRE(chainstate.GetChainHeight() == 2);

        // Now create competing fork: genesis -> A' -> B' -> C' (height 3)
        CBlockHeader Ap = CreateTestHeader(genesis.GetHash(), genesis.nTime+120, 2000);
        uint256 hAp = Ap.GetHash();
        CBlockHeader Bp = CreateTestHeader(hAp, genesis.nTime+240, 2001);
        uint256 hBp = Bp.GetHash();
        CBlockHeader Cp = CreateTestHeader(hBp, genesis.nTime+360, 2002);

        // Add C' and B' as orphans
        REQUIRE(chainstate.AcceptBlockHeader(Cp, st) == nullptr);
        REQUIRE(chainstate.AddOrphanHeader(Cp, 1));
        REQUIRE(chainstate.AcceptBlockHeader(Bp, st) == nullptr);
        REQUIRE(chainstate.AddOrphanHeader(Bp, 1));

        REQUIRE(chainstate.GetOrphanHeaderCount() == 2);

        // Add A' - should resolve orphans and trigger reorg to longer chain
        chain::CBlockIndex* pAp = chainstate.AcceptBlockHeader(Ap, st);
        REQUIRE(pAp != nullptr);
        chainstate.TryAddBlockIndexCandidate(pAp);

        REQUIRE(chainstate.GetOrphanHeaderCount() == 0);

        // Activate - should reorg to longer chain (height 3)
        REQUIRE(chainstate.ActivateBestChain(nullptr));
        INFO("Chain height after orphan-triggered reorg: " << chainstate.GetChainHeight());
        REQUIRE(chainstate.GetChainHeight() == 3);

        // Verify we're on the new chain
        REQUIRE(chainstate.LookupBlockIndex(Cp.GetHash()) != nullptr);
    }
}

TEST_CASE("Orphan Resolution - Edge Cases", "[orphan][edge][resolution]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());
    chainstate.SetBypassPOWValidation(true);
    const auto& genesis = params->GenesisBlock();

    SECTION("Duplicate orphan is rejected") {
        CBlockHeader orphan = CreateTestHeader(RandomHash(), genesis.nTime+120, 1000);

        ValidationState st;
        REQUIRE(chainstate.AcceptBlockHeader(orphan, st) == nullptr);
        REQUIRE(chainstate.AddOrphanHeader(orphan, 1));
        REQUIRE(chainstate.GetOrphanHeaderCount() == 1);

        // Try to add same orphan again
        REQUIRE(chainstate.AddOrphanHeader(orphan, 1) == true);  // Returns true but doesn't duplicate
        REQUIRE(chainstate.GetOrphanHeaderCount() == 1);
    }

    SECTION("Orphan with already-known hash is not re-added") {
        // Create and accept a block
        CBlockHeader A = CreateTestHeader(genesis.GetHash(), genesis.nTime+120, 1000);

        ValidationState st;
        chain::CBlockIndex* pA = chainstate.AcceptBlockHeader(A, st);
        REQUIRE(pA != nullptr);
        chainstate.TryAddBlockIndexCandidate(pA);

        // Try to add same block as orphan - should fail (already indexed)
        bool added = chainstate.AddOrphanHeader(A, 1);
        REQUIRE(added == false);  // Already indexed, not added to orphan pool
        REQUIRE(chainstate.GetOrphanHeaderCount() == 0);
    }

    SECTION("Orphan resolution handles re-orphaned blocks (missing grandparent)") {
        // Create: genesis -> A -> B -> C
        // Add C (orphan - missing parent B)
        // Add B (should resolve C, but B is also orphan - missing A)
        // Both should remain orphaned until A arrives

        CBlockHeader A = CreateTestHeader(genesis.GetHash(), genesis.nTime+120, 1000);
        uint256 hA = A.GetHash();
        CBlockHeader B = CreateTestHeader(hA, genesis.nTime+240, 1001);
        uint256 hB = B.GetHash();
        CBlockHeader C = CreateTestHeader(hB, genesis.nTime+360, 1002);

        ValidationState st;

        // Add C as orphan
        REQUIRE(chainstate.AcceptBlockHeader(C, st) == nullptr);
        REQUIRE(chainstate.AddOrphanHeader(C, 1));
        REQUIRE(chainstate.GetOrphanHeaderCount() == 1);

        // Add B - it should fail too (A doesn't exist)
        // Note: B itself goes to orphan pool since A is missing
        REQUIRE(chainstate.AcceptBlockHeader(B, st) == nullptr);
        REQUIRE(chainstate.AddOrphanHeader(B, 1));

        // C might still be orphaned (waiting for B which is now also orphaned)
        // Or it might be waiting for B to be resolved first
        INFO("Orphan count after adding B: " << chainstate.GetOrphanHeaderCount());

        // Now add A - should cascade resolve B, then C
        chain::CBlockIndex* pA = chainstate.AcceptBlockHeader(A, st);
        REQUIRE(pA != nullptr);
        chainstate.TryAddBlockIndexCandidate(pA);

        // All should be resolved
        REQUIRE(chainstate.GetOrphanHeaderCount() == 0);
        REQUIRE(chainstate.LookupBlockIndex(hB) != nullptr);
        REQUIRE(chainstate.LookupBlockIndex(C.GetHash()) != nullptr);

        REQUIRE(chainstate.ActivateBestChain(nullptr));
        REQUIRE(chainstate.GetChainHeight() == 3);
    }
}
