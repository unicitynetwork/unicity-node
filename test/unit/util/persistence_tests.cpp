// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "catch_amalgamated.hpp"
#include "chain/block_manager.hpp"
#include "chain/chainparams.hpp"
#include "chain/block.hpp"
#include <filesystem>
#include <cstdio>

using namespace unicity::chain;

TEST_CASE("BlockManager persistence", "[persistence][chain]") {
    // Setup: Create temp file path
    std::string test_file = "/tmp/test_headers_" + std::to_string(std::time(nullptr)) + ".json";

    // Cleanup: Remove test file at end
    struct Cleanup {
        std::string file;
        ~Cleanup() {
            std::filesystem::remove(file);
        }
    } cleanup{test_file};

    SECTION("Save and load empty BlockManager") {
        BlockManager bm1;

        // Initialize with genesis
        GlobalChainParams::Select(ChainType::REGTEST);
        const auto& params = GlobalChainParams::Get();
        CBlockHeader genesis = params.GenesisBlock();

        REQUIRE(bm1.Initialize(genesis));
        REQUIRE(bm1.GetBlockCount() == 1);

        // Save
        REQUIRE(bm1.Save(test_file));
        REQUIRE(std::filesystem::exists(test_file));

        // Load into new BlockManager
        BlockManager bm2;
        REQUIRE(bm2.Load(test_file, genesis.GetHash()) == LoadResult::SUCCESS);
        REQUIRE(bm2.GetBlockCount() == 1);

        // Verify tip
        REQUIRE(bm2.GetTip() != nullptr);
        REQUIRE(bm2.GetTip()->nHeight == 0);
        REQUIRE(bm2.GetTip()->GetBlockHash() == genesis.GetHash());
    }

    SECTION("Save and load chain with multiple blocks") {
        BlockManager bm1;

        // Initialize with genesis
        GlobalChainParams::Select(ChainType::REGTEST);
        const auto& params = GlobalChainParams::Get();
        CBlockHeader genesis = params.GenesisBlock();

        REQUIRE(bm1.Initialize(genesis));

        // Add 10 more blocks
        CBlockHeader prev_header = genesis;
        for (int i = 1; i <= 10; ++i) {
            CBlockHeader header;
            header.nVersion = 1;
            header.hashPrevBlock = prev_header.GetHash();
            header.minerAddress.SetHex("0000000000000000000000000000000000000001");
            header.nTime = genesis.nTime + i * 600;  // 10 minutes apart
            header.nBits = genesis.nBits;
            header.nNonce = i;
            header.hashRandomX.SetHex("0000000000000000000000000000000000000000000000000000000000000001");

            CBlockIndex* pindex = bm1.AddToBlockIndex(header);
            REQUIRE(pindex != nullptr);
            REQUIRE(pindex->nHeight == i);

            // Update active chain tip
            bm1.SetActiveTip(*pindex);

            prev_header = header;
        }

        REQUIRE(bm1.GetBlockCount() == 11);  // Genesis + 10 blocks
        REQUIRE(bm1.GetTip()->nHeight == 10);

        uint256 tip_hash = bm1.GetTip()->GetBlockHash();

        // Save
        REQUIRE(bm1.Save(test_file));

        // Load into new BlockManager
        BlockManager bm2;
        REQUIRE(bm2.Load(test_file, genesis.GetHash()) == LoadResult::SUCCESS);

        // Verify block count
        REQUIRE(bm2.GetBlockCount() == 11);

        // Verify tip
        REQUIRE(bm2.GetTip() != nullptr);
        REQUIRE(bm2.GetTip()->nHeight == 10);
        REQUIRE(bm2.GetTip()->GetBlockHash() == tip_hash);

        // Verify genesis
        REQUIRE(bm2.ActiveChain().Genesis() != nullptr);
        REQUIRE(bm2.ActiveChain().Genesis()->nHeight == 0);
        REQUIRE(bm2.ActiveChain().Genesis()->GetBlockHash() == genesis.GetHash());

        // Verify chain continuity
        for (int h = 0; h <= 10; ++h) {
            CBlockIndex* pindex = bm2.ActiveChain()[h];
            REQUIRE(pindex != nullptr);
            REQUIRE(pindex->nHeight == h);

            if (h > 0) {
                REQUIRE(pindex->pprev != nullptr);
                REQUIRE(pindex->pprev->nHeight == h - 1);
            }
        }

        // Verify lookups work
        CBlockIndex* block5 = bm2.ActiveChain()[5];
        REQUIRE(block5 != nullptr);
        uint256 block5_hash = block5->GetBlockHash();

        CBlockIndex* found = bm2.LookupBlockIndex(block5_hash);
        REQUIRE(found != nullptr);
        REQUIRE(found == block5);
        REQUIRE(found->nHeight == 5);
    }

    SECTION("Load non-existent file returns FILE_NOT_FOUND") {
        GlobalChainParams::Select(ChainType::REGTEST);
        const auto& params = GlobalChainParams::Get();
        CBlockHeader genesis = params.GenesisBlock();

        BlockManager bm;
        REQUIRE(bm.Load("/tmp/nonexistent_file_12345678.json", genesis.GetHash()) == LoadResult::FILE_NOT_FOUND);
    }

    SECTION("Chainwork is preserved") {
        BlockManager bm1;

        // Initialize with genesis
        GlobalChainParams::Select(ChainType::REGTEST);
        const auto& params = GlobalChainParams::Get();
        CBlockHeader genesis = params.GenesisBlock();

        REQUIRE(bm1.Initialize(genesis));

        // Add one block
        CBlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock = genesis.GetHash();
        header.minerAddress.SetHex("0000000000000000000000000000000000000001");
        header.nTime = genesis.nTime + 600;
        header.nBits = genesis.nBits;
        header.nNonce = 1;
        header.hashRandomX.SetHex("0000000000000000000000000000000000000000000000000000000000000001");

        CBlockIndex* pindex = bm1.AddToBlockIndex(header);
        REQUIRE(pindex != nullptr);
        bm1.SetActiveTip(*pindex);

        arith_uint256 original_work = pindex->nChainWork;
        REQUIRE(original_work > 0);

        // Save and load
        REQUIRE(bm1.Save(test_file));

        BlockManager bm2;
        REQUIRE(bm2.Load(test_file, genesis.GetHash()) == LoadResult::SUCCESS);

        // Verify chainwork preserved
        CBlockIndex* loaded = bm2.GetTip();
        REQUIRE(loaded != nullptr);
        REQUIRE(loaded->nChainWork == original_work);
    }
}
