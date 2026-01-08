// Chain-level invalidateblock tests (ported to test2)

#include <catch_amalgamated.hpp>
#include "common/test_chainstate_manager.hpp"
#include "chain/validation.hpp"
#include "chain/chainparams.hpp"
#include "chain/block.hpp"
#include "util/time.hpp"

using namespace unicity;
using namespace unicity::validation;
using namespace unicity::chain;
using namespace unicity::test;

class InvalidateBlockChainFixture2 {
public:
    InvalidateBlockChainFixture2() : params(ChainParams::CreateRegTest()), chainstate(*params) {
        CBlockHeader genesis = params->GenesisBlock();
        chainstate.Initialize(genesis);
        genesis_hash = genesis.GetHash();
    }
    uint256 MineBlock() {
        auto* tip = chainstate.GetTip(); REQUIRE(tip != nullptr);
        CBlockHeader header; header.nVersion=1; header.hashPrevBlock=tip->GetBlockHash(); header.minerAddress=uint160(); header.nTime=tip->nTime+120; header.nBits=0x207fffff; header.nNonce=tip->nHeight+1;
        header.hashRandomX.SetNull(); ValidationState st; REQUIRE(chainstate.ProcessNewBlockHeader(header, st)); return header.GetHash();
    }
    const CBlockIndex* Get(const uint256& h){ return chainstate.LookupBlockIndex(h); }
    std::unique_ptr<ChainParams> params; TestChainstateManager chainstate; uint256 genesis_hash;
};

TEST_CASE("InvalidateBlock (chain) - Basic invalidation", "[invalidateblock][chain]") {
    InvalidateBlockChainFixture2 fx; uint256 b1=fx.MineBlock(); uint256 b2=fx.MineBlock(); uint256 b3=fx.MineBlock(); auto* tip=fx.chainstate.GetTip(); REQUIRE(tip); CHECK(tip->nHeight==3); CHECK(tip->GetBlockHash()==b3);
    bool ok=fx.chainstate.InvalidateBlock(b2); REQUIRE(ok); auto* b2i=fx.Get(b2); REQUIRE(b2i); CHECK(b2i->status.failure == BlockStatus::VALIDATION_FAILED); auto* b3i=fx.Get(b3); REQUIRE(b3i); CHECK(b3i->status.failure == BlockStatus::ANCESTOR_FAILED); auto* b1i=fx.Get(b1); REQUIRE(b1i); CHECK(b1i->IsValid()); tip=fx.chainstate.GetTip(); REQUIRE(tip); CHECK(tip->nHeight==1); CHECK(tip->GetBlockHash()==b1);
}

TEST_CASE("InvalidateBlock (chain) - Invalidate genesis", "[invalidateblock][chain]") {
    InvalidateBlockChainFixture2 fx; bool ok=fx.chainstate.InvalidateBlock(fx.genesis_hash); CHECK(!ok); auto* g=fx.Get(fx.genesis_hash); REQUIRE(g); CHECK(g->IsValid()); CHECK(fx.chainstate.GetTip()==g);
}

TEST_CASE("InvalidateBlock (chain) - Fork switching after invalidation", "[invalidateblock][chain]") {
    // Build: genesis -> A1 -> A2 -> A3 -> A4 (active, height 4)
    //                \-> B1 -> B2 -> B3 (fork, height 3, less work)
    // After invalidating A1, fork B becomes best chain
    InvalidateBlockChainFixture2 fx;

    // Main chain (4 blocks)
    uint256 a1 = fx.MineBlock();
    uint256 a2 = fx.MineBlock();
    uint256 a3 = fx.MineBlock();
    uint256 a4 = fx.MineBlock();
    REQUIRE(fx.chainstate.GetTip()->nHeight == 4);

    // Build shorter competing fork from genesis (3 blocks, less work)
    CBlockHeader b1;
    b1.nVersion = 1;
    b1.hashPrevBlock = fx.genesis_hash;
    b1.minerAddress = uint160();
    b1.nTime = fx.chainstate.GetTip()->nTime + 1000;
    b1.nBits = 0x207fffff;
    b1.nNonce = 9999;
    b1.hashRandomX.SetNull();
    ValidationState st;
    REQUIRE(fx.chainstate.ProcessNewBlockHeader(b1, st));

    CBlockHeader b2;
    b2.nVersion = 1;
    b2.hashPrevBlock = b1.GetHash();
    b2.minerAddress = uint160();
    b2.nTime = b1.nTime + 120;
    b2.nBits = 0x207fffff;
    b2.nNonce = 10000;
    b2.hashRandomX.SetNull();
    REQUIRE(fx.chainstate.ProcessNewBlockHeader(b2, st));

    CBlockHeader b3;
    b3.nVersion = 1;
    b3.hashPrevBlock = b2.GetHash();
    b3.minerAddress = uint160();
    b3.nTime = b2.nTime + 120;
    b3.nBits = 0x207fffff;
    b3.nNonce = 10001;
    b3.hashRandomX.SetNull();
    REQUIRE(fx.chainstate.ProcessNewBlockHeader(b3, st));

    // Main chain still active (more work: 4 blocks vs 3)
    REQUIRE(fx.chainstate.GetTip()->GetBlockHash() == a4);
    REQUIRE(fx.chainstate.GetTip()->nHeight == 4);

    // Invalidate A1 - main chain becomes invalid
    REQUIRE(fx.chainstate.InvalidateBlock(a1));

    // A1, A2, A3, A4 should be failed
    REQUIRE(fx.Get(a1)->status.IsFailed());
    REQUIRE(fx.Get(a2)->status.IsFailed());
    REQUIRE(fx.Get(a3)->status.IsFailed());
    REQUIRE(fx.Get(a4)->status.IsFailed());

    // After ActivateBestChain, tip should be on fork B (now the best valid chain)
    REQUIRE(fx.chainstate.ActivateBestChain());
    REQUIRE(fx.chainstate.GetTip()->GetBlockHash() == b3.GetHash());
    REQUIRE(fx.chainstate.GetTip()->nHeight == 3);
}

TEST_CASE("InvalidateBlock (chain) - Invalidate tip directly", "[invalidateblock][chain]") {
    InvalidateBlockChainFixture2 fx;
    uint256 b1 = fx.MineBlock();
    uint256 b2 = fx.MineBlock();
    uint256 b3 = fx.MineBlock();

    REQUIRE(fx.chainstate.GetTip()->GetBlockHash() == b3);

    // Invalidate the tip itself
    REQUIRE(fx.chainstate.InvalidateBlock(b3));

    // Tip should rewind to b2
    REQUIRE(fx.chainstate.GetTip()->GetBlockHash() == b2);
    REQUIRE(fx.Get(b3)->status.IsFailed());
    REQUIRE(fx.Get(b2)->IsValid());
}

TEST_CASE("InvalidateBlock (chain) - Invalidate non-active chain block", "[invalidateblock][chain]") {
    InvalidateBlockChainFixture2 fx;

    // Main chain: genesis -> A1 -> A2
    uint256 a1 = fx.MineBlock();
    uint256 a2 = fx.MineBlock();

    // Fork: genesis -> B1
    CBlockHeader b1;
    b1.nVersion = 1;
    b1.hashPrevBlock = fx.genesis_hash;
    b1.minerAddress = uint160();
    b1.nTime = fx.chainstate.GetTip()->nTime + 500;
    b1.nBits = 0x207fffff;
    b1.nNonce = 8888;
    b1.hashRandomX.SetNull();
    ValidationState st;
    REQUIRE(fx.chainstate.ProcessNewBlockHeader(b1, st));

    // Main chain still active (more work)
    REQUIRE(fx.chainstate.GetTip()->GetBlockHash() == a2);

    // Invalidate B1 (not on active chain)
    REQUIRE(fx.chainstate.InvalidateBlock(b1.GetHash()));

    // Main chain unchanged
    REQUIRE(fx.chainstate.GetTip()->GetBlockHash() == a2);
    REQUIRE(fx.Get(b1.GetHash())->status.IsFailed());
    REQUIRE(fx.Get(a1)->IsValid());
    REQUIRE(fx.Get(a2)->IsValid());
}

TEST_CASE("InvalidateBlock (chain) - Invalidate with no competing forks", "[invalidateblock][chain]") {
    InvalidateBlockChainFixture2 fx;
    uint256 b1 = fx.MineBlock();
    uint256 b2 = fx.MineBlock();
    uint256 b3 = fx.MineBlock();

    // Invalidate b2 - no fork available, tip should be b1
    REQUIRE(fx.chainstate.InvalidateBlock(b2));
    REQUIRE(fx.chainstate.GetTip()->GetBlockHash() == b1);
    REQUIRE(fx.chainstate.GetTip()->nHeight == 1);

    // ActivateBestChain should not change anything (no better candidate)
    REQUIRE(fx.chainstate.ActivateBestChain());
    REQUIRE(fx.chainstate.GetTip()->GetBlockHash() == b1);
}

TEST_CASE("InvalidateBlock (chain) - Deep invalidation", "[invalidateblock][chain]") {
    InvalidateBlockChainFixture2 fx;

    // Build chain of 20 blocks
    std::vector<uint256> blocks;
    for (int i = 0; i < 20; i++) {
        blocks.push_back(fx.MineBlock());
    }
    REQUIRE(fx.chainstate.GetTip()->nHeight == 20);

    // Invalidate block at height 5
    REQUIRE(fx.chainstate.InvalidateBlock(blocks[4]));

    // Tip should be at height 4
    REQUIRE(fx.chainstate.GetTip()->nHeight == 4);

    // Blocks 5-20 should be failed
    for (int i = 4; i < 20; i++) {
        auto* idx = fx.Get(blocks[i]);
        REQUIRE(idx->status.IsFailed());
    }

    // Blocks 1-4 should be valid
    for (int i = 0; i < 4; i++) {
        auto* idx = fx.Get(blocks[i]);
        REQUIRE(idx->IsValid());
    }
}

TEST_CASE("InvalidateBlock (chain) - Invalidate unknown block", "[invalidateblock][chain]") {
    InvalidateBlockChainFixture2 fx;
    fx.MineBlock();

    uint256 fake_hash;
    fake_hash.SetHex("0000000000000000000000000000000000000000000000000000000000001234");

    REQUIRE_FALSE(fx.chainstate.InvalidateBlock(fake_hash));
    REQUIRE(fx.chainstate.GetTip()->nHeight == 1);
}

TEST_CASE("InvalidateBlock (chain) - Multiple forks, best fork wins", "[invalidateblock][chain]") {
    // Main: genesis -> A1 -> A2 -> A3 -> A4 (active, height 4)
    // Fork B: genesis -> B1 (height 1, least work)
    // Fork C: genesis -> C1 -> C2 (height 2, middle work)
    // After invalidating A1, fork C wins (most work among valid chains)
    InvalidateBlockChainFixture2 fx;

    // Main chain (4 blocks)
    uint256 a1 = fx.MineBlock();
    uint256 a2 = fx.MineBlock();
    uint256 a3 = fx.MineBlock();
    uint256 a4 = fx.MineBlock();
    REQUIRE(fx.chainstate.GetTip()->nHeight == 4);

    // Fork B: genesis -> B1 (height 1)
    CBlockHeader b1;
    b1.nVersion = 1;
    b1.hashPrevBlock = fx.genesis_hash;
    b1.minerAddress = uint160();
    b1.nTime = fx.chainstate.GetTip()->nTime + 500;
    b1.nBits = 0x207fffff;
    b1.nNonce = 7777;
    b1.hashRandomX.SetNull();
    ValidationState st;
    REQUIRE(fx.chainstate.ProcessNewBlockHeader(b1, st));

    // Fork C: genesis -> C1 -> C2 (height 2)
    CBlockHeader c1;
    c1.nVersion = 1;
    c1.hashPrevBlock = fx.genesis_hash;
    c1.minerAddress = uint160();
    c1.nTime = fx.chainstate.GetTip()->nTime + 1000;
    c1.nBits = 0x207fffff;
    c1.nNonce = 6666;
    c1.hashRandomX.SetNull();
    REQUIRE(fx.chainstate.ProcessNewBlockHeader(c1, st));

    CBlockHeader c2;
    c2.nVersion = 1;
    c2.hashPrevBlock = c1.GetHash();
    c2.minerAddress = uint160();
    c2.nTime = c1.nTime + 120;
    c2.nBits = 0x207fffff;
    c2.nNonce = 6667;
    c2.hashRandomX.SetNull();
    REQUIRE(fx.chainstate.ProcessNewBlockHeader(c2, st));

    // Main chain still active (most work)
    REQUIRE(fx.chainstate.GetTip()->GetBlockHash() == a4);

    // Invalidate A1 - should switch to fork C (most work among valid), not B
    REQUIRE(fx.chainstate.InvalidateBlock(a1));
    REQUIRE(fx.chainstate.ActivateBestChain());

    REQUIRE(fx.chainstate.GetTip()->GetBlockHash() == c2.GetHash());
    REQUIRE(fx.chainstate.GetTip()->nHeight == 2);

    // B1 should still be valid (not a descendant of A1)
    REQUIRE(fx.Get(b1.GetHash())->IsValid());
}
