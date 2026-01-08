// Copyright (c) 2025 The Unicity Foundation
// Test suite for chain classes (CBlockIndex, CChain, BlockManager)

#include "catch_amalgamated.hpp"
#include "chain/block_index.hpp"
#include "chain/chain.hpp"
#include "chain/block_manager.hpp"
#include "chain/block.hpp"

using namespace unicity::chain;

TEST_CASE("BlockManager basic operations", "[chain]") {
    BlockManager manager;

    // Create a simple genesis block
    CBlockHeader genesis;
    genesis.nVersion = 1;
    genesis.hashPrevBlock.SetNull();
    genesis.minerAddress.SetNull();
    genesis.nTime = 1231006505; // 
    genesis.nBits = 0x1d00ffff;
    genesis.nNonce = 2083236893;
    genesis.hashRandomX.SetNull();

    SECTION("Initialize with genesis") {
        REQUIRE(manager.Initialize(genesis));
        REQUIRE(manager.GetBlockCount() == 1);
        REQUIRE(manager.GetTip() != nullptr);
        REQUIRE(manager.GetTip()->nHeight == 0);
    }

    SECTION("Add multiple blocks") {
        REQUIRE(manager.Initialize(genesis));

        // Add block 1
        CBlockHeader block1;
        block1.nVersion = 1;
        block1.hashPrevBlock = genesis.GetHash();
        block1.minerAddress.SetNull();
        block1.nTime = genesis.nTime + 600;
        block1.nBits = genesis.nBits;
        block1.nNonce = 123456;
        block1.hashRandomX.SetNull();

        CBlockIndex* pindex1 = manager.AddToBlockIndex(block1);
        REQUIRE(pindex1 != nullptr);
        REQUIRE(pindex1->nHeight == 1);
        REQUIRE(pindex1->pprev != nullptr);
        REQUIRE(pindex1->pprev->nHeight == 0);

        // Add block 2
        CBlockHeader block2;
        block2.nVersion = 1;
        block2.hashPrevBlock = block1.GetHash();
        block2.minerAddress.SetNull();
        block2.nTime = block1.nTime + 600;
        block2.nBits = block1.nBits;
        block2.nNonce = 789012;
        block2.hashRandomX.SetNull();

        CBlockIndex* pindex2 = manager.AddToBlockIndex(block2);
        REQUIRE(pindex2 != nullptr);
        REQUIRE(pindex2->nHeight == 2);
        REQUIRE(pindex2->pprev == pindex1);

        REQUIRE(manager.GetBlockCount() == 3);
    }
}

TEST_CASE("CChain operations", "[chain]") {
    BlockManager manager;

    // Genesis
    CBlockHeader genesis;
    genesis.nVersion = 1;
    genesis.hashPrevBlock.SetNull();
    genesis.nTime = 1231006505;
    genesis.nBits = 0x1d00ffff;
    genesis.nNonce = 2083236893;

    manager.Initialize(genesis);

    // Add 10 blocks
    CBlockHeader prev = genesis;
    for (int i = 1; i <= 10; i++) {
        CBlockHeader block;
        block.nVersion = 1;
        block.hashPrevBlock = prev.GetHash();
        block.nTime = prev.nTime + 600;
        block.nBits = prev.nBits;
        block.nNonce = i;

        CBlockIndex* pindex = manager.AddToBlockIndex(block);
        REQUIRE(pindex != nullptr);

        // Update active chain
        manager.SetActiveTip(*pindex);

        prev = block;
    }

    const CChain& chain = manager.ActiveChain();

    SECTION("Chain height") {
        REQUIRE(chain.Height() == 10);
    }

    SECTION("Access by height") {
        REQUIRE(chain[0] != nullptr);
        REQUIRE(chain[0]->nHeight == 0);
        REQUIRE(chain[5] != nullptr);
        REQUIRE(chain[5]->nHeight == 5);
        REQUIRE(chain[10] != nullptr);
        REQUIRE(chain[10]->nHeight == 10);
        REQUIRE(chain[11] == nullptr); // Out of bounds
    }

    SECTION("Genesis and Tip") {
        REQUIRE(chain.Genesis() != nullptr);
        REQUIRE(chain.Genesis()->nHeight == 0);
        REQUIRE(chain.Tip() != nullptr);
        REQUIRE(chain.Tip()->nHeight == 10);
    }

    SECTION("Contains") {
        REQUIRE(chain.Contains(chain[5]));
        REQUIRE(chain.Contains(chain[0]));
        REQUIRE(chain.Contains(chain[10]));
    }

    SECTION("Next") {
        REQUIRE(chain.Next(chain[5]) == chain[6]);
        REQUIRE(chain.Next(chain[9]) == chain[10]);
        REQUIRE(chain.Next(chain[10]) == nullptr); // Tip has no next
    }

    SECTION("GetLocator") {
        CBlockLocator locator = chain.GetLocator();
        REQUIRE(!locator.IsNull());
        REQUIRE(locator.vHave.size() > 0);
        // First entry should be tip
        REQUIRE(locator.vHave[0] == chain.Tip()->GetBlockHash());
    }
}

TEST_CASE("CBlockIndex ancestry", "[chain]") {
    BlockManager manager;

    // Genesis
    CBlockHeader genesis;
    genesis.nVersion = 1;
    genesis.nTime = 1231006505;
    genesis.nBits = 0x1d00ffff;

    manager.Initialize(genesis);

    // Add 100 blocks
    CBlockHeader prev = genesis;
    CBlockIndex* tip = nullptr;
    for (int i = 1; i <= 100; i++) {
        CBlockHeader block;
        block.nVersion = 1;
        block.hashPrevBlock = prev.GetHash();
        block.nTime = prev.nTime + 600;
        block.nBits = prev.nBits;
        block.nNonce = i;

        tip = manager.AddToBlockIndex(block);
        prev = block;
    }

    REQUIRE(tip != nullptr);
    REQUIRE(tip->nHeight == 100);

    SECTION("GetAncestor") {
        // Get ancestor at various heights
        const CBlockIndex* anc50 = tip->GetAncestor(50);
        REQUIRE(anc50 != nullptr);
        REQUIRE(anc50->nHeight == 50);

        const CBlockIndex* anc0 = tip->GetAncestor(0);
        REQUIRE(anc0 != nullptr);
        REQUIRE(anc0->nHeight == 0);

        const CBlockIndex* anc100 = tip->GetAncestor(100);
        REQUIRE(anc100 == tip);

        // Out of range
        REQUIRE(tip->GetAncestor(101) == nullptr);
        REQUIRE(tip->GetAncestor(-1) == nullptr);
    }

    SECTION("Median Time Past") {
        // MTP should be median of last 11 blocks
        int64_t mtp = tip->GetMedianTimePast();
        REQUIRE(mtp > 0);
        // MTP should be less than tip time
        REQUIRE(mtp <= tip->GetBlockTime());
    }
}

TEST_CASE("CChain::SetTip edge cases", "[chain][settip]") {
    BlockManager manager;

    // Genesis
    CBlockHeader genesis;
    genesis.nVersion = 1;
    genesis.hashPrevBlock.SetNull();
    genesis.nTime = 1231006505;
    genesis.nBits = 0x1d00ffff;
    genesis.nNonce = 2083236893;

    manager.Initialize(genesis);
    CBlockIndex* genesis_index = manager.GetTip();

    SECTION("SetTip to genesis") {
        manager.SetActiveTip(*genesis_index);
        REQUIRE(manager.ActiveChain().Height() == 0);
        REQUIRE(manager.ActiveChain().Tip() == genesis_index);
        REQUIRE(manager.ActiveChain().Genesis() == genesis_index);
        REQUIRE(manager.ActiveChain()[0] == genesis_index);
    }

    SECTION("SetTip forward and backward") {
        // Build chain: genesis -> A -> B -> C
        CBlockHeader blockA_header;
        blockA_header.nVersion = 1;
        blockA_header.hashPrevBlock = genesis.GetHash();
        blockA_header.nTime = genesis.nTime + 600;
        blockA_header.nBits = genesis.nBits;
        blockA_header.nNonce = 1;
        CBlockIndex* blockA = manager.AddToBlockIndex(blockA_header);

        CBlockHeader blockB_header;
        blockB_header.nVersion = 1;
        blockB_header.hashPrevBlock = blockA_header.GetHash();
        blockB_header.nTime = blockA_header.nTime + 600;
        blockB_header.nBits = blockA_header.nBits;
        blockB_header.nNonce = 2;
        CBlockIndex* blockB = manager.AddToBlockIndex(blockB_header);

        CBlockHeader blockC_header;
        blockC_header.nVersion = 1;
        blockC_header.hashPrevBlock = blockB_header.GetHash();
        blockC_header.nTime = blockB_header.nTime + 600;
        blockC_header.nBits = blockB_header.nBits;
        blockC_header.nNonce = 3;
        CBlockIndex* blockC = manager.AddToBlockIndex(blockC_header);

        // Set tip to C (height 3)
        manager.SetActiveTip(*blockC);
        REQUIRE(manager.ActiveChain().Height() == 3);
        REQUIRE(manager.ActiveChain().Tip() == blockC);
        REQUIRE(manager.ActiveChain()[0] == genesis_index);
        REQUIRE(manager.ActiveChain()[1] == blockA);
        REQUIRE(manager.ActiveChain()[2] == blockB);
        REQUIRE(manager.ActiveChain()[3] == blockC);

        // Disconnect to B (simulating DisconnectTip)
        manager.SetActiveTip(*blockB);
        REQUIRE(manager.ActiveChain().Height() == 2);
        REQUIRE(manager.ActiveChain().Tip() == blockB);
        REQUIRE(manager.ActiveChain()[0] == genesis_index);
        REQUIRE(manager.ActiveChain()[1] == blockA);
        REQUIRE(manager.ActiveChain()[2] == blockB);
        REQUIRE(manager.ActiveChain()[3] == nullptr); // Out of bounds now

        // Disconnect to A
        manager.SetActiveTip(*blockA);
        REQUIRE(manager.ActiveChain().Height() == 1);
        REQUIRE(manager.ActiveChain().Tip() == blockA);
        REQUIRE(manager.ActiveChain()[0] == genesis_index);
        REQUIRE(manager.ActiveChain()[1] == blockA);
        REQUIRE(manager.ActiveChain()[2] == nullptr);

        // Disconnect to genesis
        manager.SetActiveTip(*genesis_index);
        REQUIRE(manager.ActiveChain().Height() == 0);
        REQUIRE(manager.ActiveChain().Tip() == genesis_index);
        REQUIRE(manager.ActiveChain()[0] == genesis_index);
        REQUIRE(manager.ActiveChain()[1] == nullptr);

        // Reconnect forward to C (simulating ConnectTip)
        manager.SetActiveTip(*blockA);
        REQUIRE(manager.ActiveChain().Height() == 1);

        manager.SetActiveTip(*blockB);
        REQUIRE(manager.ActiveChain().Height() == 2);

        manager.SetActiveTip(*blockC);
        REQUIRE(manager.ActiveChain().Height() == 3);
        REQUIRE(manager.ActiveChain().Tip() == blockC);
    }

    SECTION("SetTip with reorg (different chain)") {
        // Build main chain: genesis -> A -> B -> C
        CBlockHeader blockA_header;
        blockA_header.nVersion = 1;
        blockA_header.hashPrevBlock = genesis.GetHash();
        blockA_header.nTime = genesis.nTime + 600;
        blockA_header.nBits = genesis.nBits;
        blockA_header.nNonce = 1;
        CBlockIndex* blockA = manager.AddToBlockIndex(blockA_header);

        CBlockHeader blockB_header;
        blockB_header.nVersion = 1;
        blockB_header.hashPrevBlock = blockA_header.GetHash();
        blockB_header.nTime = blockA_header.nTime + 600;
        blockB_header.nBits = blockA_header.nBits;
        blockB_header.nNonce = 2;
        CBlockIndex* blockB = manager.AddToBlockIndex(blockB_header);

        CBlockHeader blockC_header;
        blockC_header.nVersion = 1;
        blockC_header.hashPrevBlock = blockB_header.GetHash();
        blockC_header.nTime = blockB_header.nTime + 600;
        blockB_header.nBits = blockB_header.nBits;
        blockC_header.nNonce = 3;
        CBlockIndex* blockC = manager.AddToBlockIndex(blockC_header);

        // Build fork chain: genesis -> A -> X -> Y
        CBlockHeader blockX_header;
        blockX_header.nVersion = 1;
        blockX_header.hashPrevBlock = blockA_header.GetHash();
        blockX_header.nTime = blockA_header.nTime + 600;
        blockX_header.nBits = blockA_header.nBits;
        blockX_header.nNonce = 100;  // Different nonce
        CBlockIndex* blockX = manager.AddToBlockIndex(blockX_header);

        CBlockHeader blockY_header;
        blockY_header.nVersion = 1;
        blockY_header.hashPrevBlock = blockX_header.GetHash();
        blockY_header.nTime = blockX_header.nTime + 600;
        blockY_header.nBits = blockX_header.nBits;
        blockY_header.nNonce = 101;
        CBlockIndex* blockY = manager.AddToBlockIndex(blockY_header);

        // Start with main chain active (genesis -> A -> B -> C)
        manager.SetActiveTip(*blockC);
        REQUIRE(manager.ActiveChain().Height() == 3);
        REQUIRE(manager.ActiveChain().Tip() == blockC);

        // Reorg to fork chain (genesis -> A -> X -> Y)
        // This simulates: DisconnectTip(C), DisconnectTip(B), ConnectTip(X), ConnectTip(Y)
        manager.SetActiveTip(*blockY);
        REQUIRE(manager.ActiveChain().Height() == 3);
        REQUIRE(manager.ActiveChain().Tip() == blockY);
        REQUIRE(manager.ActiveChain()[0] == genesis_index);
        REQUIRE(manager.ActiveChain()[1] == blockA);
        REQUIRE(manager.ActiveChain()[2] == blockX);  // NOT blockB!
        REQUIRE(manager.ActiveChain()[3] == blockY);  // NOT blockC!

        // Verify old chain blocks are NOT in active chain
        REQUIRE(!manager.ActiveChain().Contains(blockB));
        REQUIRE(!manager.ActiveChain().Contains(blockC));

        // Verify new chain blocks ARE in active chain
        REQUIRE(manager.ActiveChain().Contains(blockX));
        REQUIRE(manager.ActiveChain().Contains(blockY));
    }

    SECTION("SetTip repeatedly (idempotent)") {
        // Build chain
        CBlockHeader block1_header;
        block1_header.nVersion = 1;
        block1_header.hashPrevBlock = genesis.GetHash();
        block1_header.nTime = genesis.nTime + 600;
        block1_header.nBits = genesis.nBits;
        block1_header.nNonce = 1;
        CBlockIndex* block1 = manager.AddToBlockIndex(block1_header);

        // Set tip multiple times to same block
        manager.SetActiveTip(*block1);
        REQUIRE(manager.ActiveChain().Height() == 1);

        manager.SetActiveTip(*block1);
        REQUIRE(manager.ActiveChain().Height() == 1);

        manager.SetActiveTip(*block1);
        REQUIRE(manager.ActiveChain().Height() == 1);

        // Chain should still be correct
        REQUIRE(manager.ActiveChain().Tip() == block1);
        REQUIRE(manager.ActiveChain()[0] == genesis_index);
        REQUIRE(manager.ActiveChain()[1] == block1);
    }
}

// =============================================================================
// Section: Edge Cases for chain.cpp coverage
// =============================================================================

TEST_CASE("LocatorEntries with null index", "[chain][locator]") {
    // Test that LocatorEntries handles null index gracefully
    std::vector<uint256> entries = LocatorEntries(nullptr);
    REQUIRE(entries.empty());
}

TEST_CASE("GetLocator free function", "[chain][locator]") {
    BlockManager manager;

    // Genesis
    CBlockHeader genesis;
    genesis.nVersion = 1;
    genesis.hashPrevBlock.SetNull();
    genesis.nTime = 1231006505;
    genesis.nBits = 0x1d00ffff;
    genesis.nNonce = 2083236893;

    manager.Initialize(genesis);
    CBlockIndex* genesis_index = manager.GetTip();

    // Add a few blocks
    CBlockHeader prev = genesis;
    CBlockIndex* tip = genesis_index;
    for (int i = 1; i <= 5; i++) {
        CBlockHeader block;
        block.nVersion = 1;
        block.hashPrevBlock = prev.GetHash();
        block.nTime = prev.nTime + 600;
        block.nBits = prev.nBits;
        block.nNonce = i;

        tip = manager.AddToBlockIndex(block);
        prev = block;
    }

    // Test free function GetLocator
    CBlockLocator locator = GetLocator(tip);
    REQUIRE(!locator.IsNull());
    REQUIRE(locator.vHave.size() > 0);
    REQUIRE(locator.vHave[0] == tip->GetBlockHash());

    // Test with genesis
    CBlockLocator genesis_locator = GetLocator(genesis_index);
    REQUIRE(!genesis_locator.IsNull());
    REQUIRE(genesis_locator.vHave.size() == 1);
    REQUIRE(genesis_locator.vHave[0] == genesis_index->GetBlockHash());

    // Test with null
    CBlockLocator null_locator = GetLocator(nullptr);
    REQUIRE(null_locator.IsNull());
}

TEST_CASE("CChain::FindFork edge cases", "[chain][findfork]") {
    BlockManager manager;

    // Genesis
    CBlockHeader genesis;
    genesis.nVersion = 1;
    genesis.hashPrevBlock.SetNull();
    genesis.nTime = 1231006505;
    genesis.nBits = 0x1d00ffff;
    genesis.nNonce = 2083236893;

    manager.Initialize(genesis);
    CBlockIndex* genesis_index = manager.GetTip();

    // Build main chain: genesis -> A -> B -> C
    CBlockHeader blockA_header;
    blockA_header.nVersion = 1;
    blockA_header.hashPrevBlock = genesis.GetHash();
    blockA_header.nTime = genesis.nTime + 600;
    blockA_header.nBits = genesis.nBits;
    blockA_header.nNonce = 1;
    CBlockIndex* blockA = manager.AddToBlockIndex(blockA_header);

    CBlockHeader blockB_header;
    blockB_header.nVersion = 1;
    blockB_header.hashPrevBlock = blockA_header.GetHash();
    blockB_header.nTime = blockA_header.nTime + 600;
    blockB_header.nBits = blockA_header.nBits;
    blockB_header.nNonce = 2;
    CBlockIndex* blockB = manager.AddToBlockIndex(blockB_header);

    CBlockHeader blockC_header;
    blockC_header.nVersion = 1;
    blockC_header.hashPrevBlock = blockB_header.GetHash();
    blockC_header.nTime = blockB_header.nTime + 600;
    blockC_header.nBits = blockB_header.nBits;
    blockC_header.nNonce = 3;
    CBlockIndex* blockC = manager.AddToBlockIndex(blockC_header);

    // Set active chain to C
    manager.SetActiveTip(*blockC);
    const CChain& chain = manager.ActiveChain();

    SECTION("FindFork with null pindex") {
        // Should return nullptr
        const CBlockIndex* fork = chain.FindFork(nullptr);
        REQUIRE(fork == nullptr);
    }

    SECTION("FindFork with block in chain") {
        // FindFork with a block that's in the chain should return that block
        const CBlockIndex* fork = chain.FindFork(blockB);
        REQUIRE(fork == blockB);
    }

    SECTION("FindFork with tip") {
        const CBlockIndex* fork = chain.FindFork(blockC);
        REQUIRE(fork == blockC);
    }

    SECTION("FindFork with genesis") {
        const CBlockIndex* fork = chain.FindFork(genesis_index);
        REQUIRE(fork == genesis_index);
    }
}

TEST_CASE("CChain::FindFork with disconnected chain", "[chain][findfork]") {
    // Test FindFork when the pindex is not connected to the active chain
    // This tests line 105 where FindFork returns null

    BlockManager manager1;
    BlockManager manager2;

    // Genesis for chain 1
    CBlockHeader genesis1;
    genesis1.nVersion = 1;
    genesis1.hashPrevBlock.SetNull();
    genesis1.nTime = 1231006505;
    genesis1.nBits = 0x1d00ffff;
    genesis1.nNonce = 1;

    // Different genesis for chain 2
    CBlockHeader genesis2;
    genesis2.nVersion = 1;
    genesis2.hashPrevBlock.SetNull();
    genesis2.nTime = 1231006505;
    genesis2.nBits = 0x1d00ffff;
    genesis2.nNonce = 2;  // Different nonce = different hash

    manager1.Initialize(genesis1);
    manager2.Initialize(genesis2);

    // Build chain on manager1
    CBlockHeader block1_header;
    block1_header.nVersion = 1;
    block1_header.hashPrevBlock = genesis1.GetHash();
    block1_header.nTime = genesis1.nTime + 600;
    block1_header.nBits = genesis1.nBits;
    block1_header.nNonce = 100;
    CBlockIndex* block1 = manager1.AddToBlockIndex(block1_header);
    manager1.SetActiveTip(*block1);

    // Build chain on manager2
    CBlockHeader block2_header;
    block2_header.nVersion = 1;
    block2_header.hashPrevBlock = genesis2.GetHash();
    block2_header.nTime = genesis2.nTime + 600;
    block2_header.nBits = genesis2.nBits;
    block2_header.nNonce = 200;
    CBlockIndex* block2 = manager2.AddToBlockIndex(block2_header);
    manager2.SetActiveTip(*block2);

    // Try to find fork between chain1 and a block from chain2
    // They have different genesis blocks, so there's no fork point
    const CChain& chain1 = manager1.ActiveChain();
    const CBlockIndex* fork = chain1.FindFork(block2);

    // Should return nullptr because block2 is not connected to chain1's genesis
    REQUIRE(fork == nullptr);
}
