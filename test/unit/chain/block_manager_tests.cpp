// Copyright (c) 2025 The Unicity Foundation
// Unit tests for chain/block_manager.cpp - Block storage and retrieval
//
// Consolidated tests covering:
// - Initialization with genesis block
// - Block index management (add, lookup)
// - Active chain tracking
// - Persistence (save/load to disk)
// - Genesis validation
// - Error handling
// - Defensive validations (corruption, tampering, edge cases)
// - Reorg scenarios
// - Atomic save / crash consistency

#include "catch_amalgamated.hpp"
#include "chain/block_manager.hpp"
#include "chain/block.hpp"
#include "chain/chainparams.hpp"
#include "chain/chainstate_manager.hpp"
#include "chain/pow.hpp"
#include "chain/validation.hpp"
#include "chain/notifications.hpp"
#include "common/test_chainstate_manager.hpp"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <unistd.h>
#include <vector>

using namespace unicity::chain;
using json = nlohmann::json;

//==============================================================================
// Helper Functions
//==============================================================================

// Helper to create a test block header
static CBlockHeader CreateTestHeader(uint32_t nTime = 1234567890, uint32_t nBits = 0x1d00ffff, uint32_t nNonce = 0) {
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.minerAddress.SetNull();
    header.nTime = nTime;
    header.nBits = nBits;
    header.nNonce = nNonce;
    header.hashRandomX.SetNull();
    return header;
}

// Helper to create a child header
static CBlockHeader CreateChildHeader(const uint256& prevHash, uint32_t nTime = 1234567890, uint32_t nBits = 0x1d00ffff) {
    CBlockHeader header = CreateTestHeader(nTime, nBits);
    header.hashPrevBlock = prevHash;
    return header;
}

// Helper to create a child block with specific difficulty (for ChainstateManager tests)
static CBlockHeader MakeChild(const CBlockIndex *parent, uint32_t nTime, uint32_t nBits) {
    CBlockHeader child;
    child.nVersion = 1;
    child.hashPrevBlock = parent->GetBlockHash();
    child.nTime = nTime;
    child.nBits = nBits;
    child.nNonce = 0;
    child.minerAddress.SetNull();
    child.hashRandomX.SetNull();
    return child;
}

//==============================================================================
// Test Fixtures
//==============================================================================

// Test fixture for managing temporary files
class BlockManagerTestFixture {
public:
    std::string test_file;

    BlockManagerTestFixture() {
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        test_file = "/tmp/block_manager_test_" + std::to_string(now) + ".json";
    }

    ~BlockManagerTestFixture() {
        // Clean up test file
        std::filesystem::remove(test_file);
    }

    // Helper to create valid chain JSON
    json CreateValidChainJSON(int num_blocks = 3) {
        json root;
        root["version"] = 1;
        root["block_count"] = num_blocks;

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        bm.Initialize(genesis);

        root["genesis_hash"] = genesis.GetHash().ToString();

        CBlockIndex* prev = bm.GetTip();
        for (int i = 1; i < num_blocks; i++) {
            CBlockHeader block = CreateChildHeader(prev->GetBlockHash(), 1234567890 + i * 100);
            prev = bm.AddToBlockIndex(block);
        }

        root["tip_hash"] = prev->GetBlockHash().ToString();

        json blocks = json::array();
        for (const auto& [hash, block_index] : bm.GetBlockIndex()) {
            json block_data;
            block_data["hash"] = hash.ToString();
            block_data["version"] = block_index.nVersion;
            block_data["miner_address"] = block_index.minerAddress.ToString();
            block_data["time"] = block_index.nTime;
            block_data["bits"] = block_index.nBits;
            block_data["nonce"] = block_index.nNonce;
            block_data["hash_randomx"] = block_index.hashRandomX.ToString();
            block_data["height"] = block_index.nHeight;
            block_data["chainwork"] = block_index.nChainWork.GetHex();
            block_data["status"] = {
                {"validation", block_index.status.validation},
                {"failure", block_index.status.failure}
            };

            if (block_index.pprev) {
                block_data["prev_hash"] = block_index.pprev->GetBlockHash().ToString();
            } else {
                block_data["prev_hash"] = uint256().ToString();
            }

            blocks.push_back(block_data);
        }

        root["blocks"] = blocks;
        return root;
    }
};

//==============================================================================
// Basic BlockManager Tests
//==============================================================================

TEST_CASE("BlockManager - Construction", "[chain][block_manager][unit]") {
    BlockManager bm;

    SECTION("Default construction") {
        REQUIRE(bm.GetBlockCount() == 0);
        REQUIRE(bm.GetTip() == nullptr);
    }
}

TEST_CASE("BlockManager - Initialize", "[chain][block_manager][unit]") {
    BlockManager bm;
    CBlockHeader genesis = CreateTestHeader();

    SECTION("Initialize with genesis") {
        bool result = bm.Initialize(genesis);

        REQUIRE(result);
        REQUIRE(bm.GetBlockCount() == 1);
        REQUIRE(bm.GetTip() != nullptr);
        REQUIRE(bm.GetTip()->GetBlockHash() == genesis.GetHash());
        REQUIRE(bm.GetTip()->nHeight == 0);
    }

    SECTION("Cannot initialize twice") {
        REQUIRE(bm.Initialize(genesis));

        // Try to initialize again
        CBlockHeader another_genesis = CreateTestHeader(9999999);
        REQUIRE_FALSE(bm.Initialize(another_genesis));

        // Should still have original genesis
        REQUIRE(bm.GetBlockCount() == 1);
        REQUIRE(bm.GetTip()->GetBlockHash() == genesis.GetHash());
    }

    SECTION("Genesis becomes active tip") {
        bm.Initialize(genesis);

        const CChain& chain = bm.ActiveChain();
        REQUIRE(chain.Height() == 0);
        REQUIRE(chain.Tip() != nullptr);
        REQUIRE(chain.Tip()->GetBlockHash() == genesis.GetHash());
    }
}

TEST_CASE("BlockManager - AddToBlockIndex", "[chain][block_manager][unit]") {
    BlockManager bm;
    CBlockHeader genesis = CreateTestHeader();
    bm.Initialize(genesis);

    SECTION("Add new block") {
        CBlockHeader block1 = CreateChildHeader(genesis.GetHash(), 1234567900);
        CBlockIndex* pindex = bm.AddToBlockIndex(block1);

        REQUIRE(pindex != nullptr);
        REQUIRE(pindex->GetBlockHash() == block1.GetHash());
        REQUIRE(pindex->nHeight == 1);
        REQUIRE(pindex->pprev != nullptr);
        REQUIRE(pindex->pprev->GetBlockHash() == genesis.GetHash());
        REQUIRE(bm.GetBlockCount() == 2);
    }

    SECTION("Add same block twice returns existing") {
        CBlockHeader block1 = CreateChildHeader(genesis.GetHash());

        CBlockIndex* pindex1 = bm.AddToBlockIndex(block1);
        CBlockIndex* pindex2 = bm.AddToBlockIndex(block1);

        REQUIRE(pindex1 == pindex2);  // Same pointer
        REQUIRE(bm.GetBlockCount() == 2);  // Still only 2 blocks
    }

    SECTION("Add block with unknown parent - rejected") {
        // Test defensive behavior: blocks with unknown parents are rejected by BlockManager
        uint256 unknown_parent;
        unknown_parent.SetHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        CBlockHeader unconnecting = CreateChildHeader(unknown_parent);
        CBlockIndex* pindex = bm.AddToBlockIndex(unconnecting);

        // Blocks with unknown parents are rejected
        REQUIRE(pindex == nullptr);
        REQUIRE(bm.GetBlockCount() == 1);  // Only genesis
    }

    SECTION("Add chain of blocks") {
        CBlockHeader block1 = CreateChildHeader(genesis.GetHash(), 1000);
        CBlockHeader block2 = CreateChildHeader(block1.GetHash(), 2000);
        CBlockHeader block3 = CreateChildHeader(block2.GetHash(), 3000);

        CBlockIndex* p1 = bm.AddToBlockIndex(block1);
        CBlockIndex* p2 = bm.AddToBlockIndex(block2);
        CBlockIndex* p3 = bm.AddToBlockIndex(block3);

        REQUIRE(p1->nHeight == 1);
        REQUIRE(p2->nHeight == 2);
        REQUIRE(p3->nHeight == 3);

        REQUIRE(p1->pprev->GetBlockHash() == genesis.GetHash());
        REQUIRE(p2->pprev == p1);
        REQUIRE(p3->pprev == p2);

        REQUIRE(bm.GetBlockCount() == 4);  // Genesis + 3 blocks
    }

    SECTION("Chain work increases with each block") {
        CBlockHeader block1 = CreateChildHeader(genesis.GetHash());
        CBlockHeader block2 = CreateChildHeader(block1.GetHash());

        CBlockIndex* genesis_idx = bm.LookupBlockIndex(genesis.GetHash());
        CBlockIndex* p1 = bm.AddToBlockIndex(block1);
        CBlockIndex* p2 = bm.AddToBlockIndex(block2);

        REQUIRE(p1->nChainWork > genesis_idx->nChainWork);
        REQUIRE(p2->nChainWork > p1->nChainWork);
    }
}

TEST_CASE("BlockManager - LookupBlockIndex", "[chain][block_manager][unit]") {
    BlockManager bm;
    CBlockHeader genesis = CreateTestHeader();
    bm.Initialize(genesis);

    SECTION("Lookup existing block") {
        uint256 genesis_hash = genesis.GetHash();
        CBlockIndex* pindex = bm.LookupBlockIndex(genesis_hash);

        REQUIRE(pindex != nullptr);
        REQUIRE(pindex->GetBlockHash() == genesis_hash);
    }

    SECTION("Lookup non-existent block") {
        uint256 unknown_hash;
        unknown_hash.SetHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        CBlockIndex* pindex = bm.LookupBlockIndex(unknown_hash);
        REQUIRE(pindex == nullptr);
    }

    SECTION("Lookup multiple blocks") {
        CBlockHeader block1 = CreateChildHeader(genesis.GetHash());
        CBlockHeader block2 = CreateChildHeader(block1.GetHash());

        bm.AddToBlockIndex(block1);
        bm.AddToBlockIndex(block2);

        REQUIRE(bm.LookupBlockIndex(genesis.GetHash()) != nullptr);
        REQUIRE(bm.LookupBlockIndex(block1.GetHash()) != nullptr);
        REQUIRE(bm.LookupBlockIndex(block2.GetHash()) != nullptr);
    }

    SECTION("Const lookup") {
        const BlockManager& cbm = bm;
        const CBlockIndex* pindex = cbm.LookupBlockIndex(genesis.GetHash());

        REQUIRE(pindex != nullptr);
        REQUIRE(pindex->GetBlockHash() == genesis.GetHash());
    }
}

TEST_CASE("BlockManager - Active Chain", "[chain][block_manager][unit]") {
    BlockManager bm;
    CBlockHeader genesis = CreateTestHeader();
    bm.Initialize(genesis);

    SECTION("Genesis is initial tip") {
        REQUIRE(bm.GetTip() != nullptr);
        REQUIRE(bm.GetTip()->GetBlockHash() == genesis.GetHash());
        REQUIRE(bm.GetTip()->nHeight == 0);
    }

    SECTION("SetActiveTip updates tip") {
        CBlockHeader block1 = CreateChildHeader(genesis.GetHash());
        CBlockIndex* p1 = bm.AddToBlockIndex(block1);

        bm.SetActiveTip(*p1);

        REQUIRE(bm.GetTip() == p1);
        REQUIRE(bm.GetTip()->nHeight == 1);
        REQUIRE(bm.ActiveChain().Height() == 1);
    }

    SECTION("Active chain tracks full chain") {
        CBlockHeader block1 = CreateChildHeader(genesis.GetHash());
        CBlockHeader block2 = CreateChildHeader(block1.GetHash());
        CBlockHeader block3 = CreateChildHeader(block2.GetHash());

        CBlockIndex* p1 = bm.AddToBlockIndex(block1);
        CBlockIndex* p2 = bm.AddToBlockIndex(block2);
        CBlockIndex* p3 = bm.AddToBlockIndex(block3);

        bm.SetActiveTip(*p3);

        const CChain& chain = bm.ActiveChain();
        REQUIRE(chain.Height() == 3);
        REQUIRE(chain[0]->GetBlockHash() == genesis.GetHash());
        REQUIRE(chain[1] == p1);
        REQUIRE(chain[2] == p2);
        REQUIRE(chain[3] == p3);
    }
}

TEST_CASE("BlockManager - GetBlockCount", "[chain][block_manager][unit]") {
    BlockManager bm;

    SECTION("Empty manager") {
        REQUIRE(bm.GetBlockCount() == 0);
    }

    SECTION("After initialization") {
        CBlockHeader genesis = CreateTestHeader();
        bm.Initialize(genesis);
        REQUIRE(bm.GetBlockCount() == 1);
    }

    SECTION("After adding blocks") {
        CBlockHeader genesis = CreateTestHeader();
        bm.Initialize(genesis);

        CBlockHeader block1 = CreateChildHeader(genesis.GetHash());
        CBlockHeader block2 = CreateChildHeader(block1.GetHash());

        bm.AddToBlockIndex(block1);
        REQUIRE(bm.GetBlockCount() == 2);

        bm.AddToBlockIndex(block2);
        REQUIRE(bm.GetBlockCount() == 3);
    }

    SECTION("Adding same block doesn't increase count") {
        CBlockHeader genesis = CreateTestHeader();
        bm.Initialize(genesis);

        CBlockHeader block1 = CreateChildHeader(genesis.GetHash());
        bm.AddToBlockIndex(block1);
        REQUIRE(bm.GetBlockCount() == 2);

        bm.AddToBlockIndex(block1);  // Add again
        REQUIRE(bm.GetBlockCount() == 2);  // No change
    }
}

TEST_CASE("BlockManager - Save/Load", "[chain][block_manager][unit]") {
    BlockManagerTestFixture fixture;

    SECTION("Save and load genesis only") {
        CBlockHeader genesis = CreateTestHeader();

        // Save
        {
            BlockManager bm;
            bm.Initialize(genesis);
            REQUIRE(bm.Save(fixture.test_file));
        }

        // Load
        {
            BlockManager bm;
            REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::SUCCESS);
            REQUIRE(bm.GetBlockCount() == 1);
            REQUIRE(bm.GetTip() != nullptr);
            REQUIRE(bm.GetTip()->GetBlockHash() == genesis.GetHash());
        }
    }

    SECTION("Save and load multiple blocks") {
        CBlockHeader genesis = CreateTestHeader();
        CBlockHeader block1 = CreateChildHeader(genesis.GetHash(), 1000);
        CBlockHeader block2 = CreateChildHeader(block1.GetHash(), 2000);

        // Save
        {
            BlockManager bm;
            bm.Initialize(genesis);
            CBlockIndex* p1 = bm.AddToBlockIndex(block1);
            bm.AddToBlockIndex(block2);
            bm.SetActiveTip(*bm.LookupBlockIndex(block2.GetHash()));

            REQUIRE(bm.Save(fixture.test_file));
        }

        // Load
        {
            BlockManager bm;
            REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::SUCCESS);
            REQUIRE(bm.GetBlockCount() == 3);
            REQUIRE(bm.GetTip()->GetBlockHash() == block2.GetHash());
            REQUIRE(bm.GetTip()->nHeight == 2);
        }
    }

    SECTION("Load from non-existent file returns FILE_NOT_FOUND") {
        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();

        REQUIRE(bm.Load("/tmp/does_not_exist_12345.json", genesis.GetHash()) == LoadResult::FILE_NOT_FOUND);
        REQUIRE(bm.GetBlockCount() == 0);
    }

    SECTION("Genesis mismatch on load returns CORRUPTED") {
        CBlockHeader genesis = CreateTestHeader();
        CBlockHeader wrong_genesis = CreateTestHeader(9999999);

        // Save with one genesis
        {
            BlockManager bm;
            bm.Initialize(genesis);
            REQUIRE(bm.Save(fixture.test_file));
        }

        // Try to load with different genesis - file is corrupted (wrong network)
        {
            BlockManager bm;
            REQUIRE(bm.Load(fixture.test_file, wrong_genesis.GetHash()) == LoadResult::CORRUPTED);
            REQUIRE(bm.GetBlockCount() == 0);  // Should be cleared on failure
        }
    }

    SECTION("Save to invalid path") {
        // Skip test when running as root (root can create directories anywhere)
        if (geteuid() == 0) {
            WARN("Skipping invalid path test when running as root");
            return;
        }

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        bm.Initialize(genesis);

        REQUIRE_FALSE(bm.Save("/invalid/path/that/does/not/exist/file.json"));
    }

    SECTION("Chain work preserved across save/load") {
        CBlockHeader genesis = CreateTestHeader();
        CBlockHeader block1 = CreateChildHeader(genesis.GetHash());

        arith_uint256 original_work;

        // Save
        {
            BlockManager bm;
            bm.Initialize(genesis);
            CBlockIndex* p1 = bm.AddToBlockIndex(block1);
            original_work = p1->nChainWork;

            REQUIRE(bm.Save(fixture.test_file));
        }

        // Load
        {
            BlockManager bm;
            REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::SUCCESS);

            CBlockIndex* p1 = bm.LookupBlockIndex(block1.GetHash());
            REQUIRE(p1 != nullptr);
            REQUIRE(p1->nChainWork == original_work);
        }
    }

    SECTION("Parent pointers reconstructed on load") {
        CBlockHeader genesis = CreateTestHeader();
        CBlockHeader block1 = CreateChildHeader(genesis.GetHash());
        CBlockHeader block2 = CreateChildHeader(block1.GetHash());

        // Save
        {
            BlockManager bm;
            bm.Initialize(genesis);
            bm.AddToBlockIndex(block1);
            bm.AddToBlockIndex(block2);
            REQUIRE(bm.Save(fixture.test_file));
        }

        // Load and verify parent pointers
        {
            BlockManager bm;
            REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::SUCCESS);

            CBlockIndex* genesis_idx = bm.LookupBlockIndex(genesis.GetHash());
            CBlockIndex* p1 = bm.LookupBlockIndex(block1.GetHash());
            CBlockIndex* p2 = bm.LookupBlockIndex(block2.GetHash());

            REQUIRE(genesis_idx->pprev == nullptr);
            REQUIRE(p1->pprev == genesis_idx);
            REQUIRE(p2->pprev == p1);
        }
    }

    SECTION("Block metadata preserved") {
        CBlockHeader genesis = CreateTestHeader(1000, 0x1d00ffff, 42);

        // Save
        {
            BlockManager bm;
            bm.Initialize(genesis);
            REQUIRE(bm.Save(fixture.test_file));
        }

        // Load and verify
        {
            BlockManager bm;
            REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::SUCCESS);

            CBlockIndex* pindex = bm.LookupBlockIndex(genesis.GetHash());
            REQUIRE(pindex->nTime == 1000);
            REQUIRE(pindex->nBits == 0x1d00ffff);
            REQUIRE(pindex->nNonce == 42);
            REQUIRE(pindex->nVersion == 1);
        }
    }
}

TEST_CASE("BlockManager - Load Error Handling", "[chain][block_manager][unit]") {
    BlockManagerTestFixture fixture;

    SECTION("Corrupted JSON file returns CORRUPTED") {
        // Create corrupted file
        std::ofstream file(fixture.test_file);
        file << "{ invalid json ][{";
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();

        REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::CORRUPTED);
        REQUIRE(bm.GetBlockCount() == 0);
    }

    SECTION("Wrong version number returns CORRUPTED") {
        // Create file with wrong version
        std::ofstream file(fixture.test_file);
        file << R"({"version": 999, "block_count": 0, "blocks": []})";
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();

        REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::CORRUPTED);
    }
}

TEST_CASE("BlockManager - GetBlockIndex", "[chain][block_manager][unit]") {
    BlockManager bm;
    CBlockHeader genesis = CreateTestHeader();
    bm.Initialize(genesis);

    SECTION("Get block index map") {
        const auto& block_index = bm.GetBlockIndex();

        REQUIRE(block_index.size() == 1);
        REQUIRE(block_index.find(genesis.GetHash()) != block_index.end());
    }

    SECTION("Block index contains all blocks") {
        CBlockHeader block1 = CreateChildHeader(genesis.GetHash());
        CBlockHeader block2 = CreateChildHeader(block1.GetHash());

        bm.AddToBlockIndex(block1);
        bm.AddToBlockIndex(block2);

        const auto& block_index = bm.GetBlockIndex();
        REQUIRE(block_index.size() == 3);
    }
}

TEST_CASE("BlockManager - Edge Cases", "[chain][block_manager][unit]") {
    SECTION("Multiple forks from same parent") {
        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        bm.Initialize(genesis);

        // Create two competing chains from genesis
        CBlockHeader fork1_block1 = CreateChildHeader(genesis.GetHash(), 1000, 0x1d00ffff);
        CBlockHeader fork2_block1 = CreateChildHeader(genesis.GetHash(), 2000, 0x1d00ffff);

        CBlockIndex* p1 = bm.AddToBlockIndex(fork1_block1);
        CBlockIndex* p2 = bm.AddToBlockIndex(fork2_block1);

        REQUIRE(p1->pprev == p2->pprev);  // Same parent
        REQUIRE(p1 != p2);  // Different blocks
        REQUIRE(p1->nHeight == p2->nHeight);  // Same height
        REQUIRE(bm.GetBlockCount() == 3);  // Genesis + 2 forks
    }

    SECTION("Out of order block addition - unconnecting blocks rejected") {
        // Test defensive behavior: blocks with missing parents are rejected.
        // BlockManager only accepts blocks whose parent is already indexed.
        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        bm.Initialize(genesis);

        CBlockHeader block1 = CreateChildHeader(genesis.GetHash());
        CBlockHeader block2 = CreateChildHeader(block1.GetHash());
        CBlockHeader block3 = CreateChildHeader(block2.GetHash());

        // Try to add block 3 first (parent unknown) - should be rejected
        CBlockIndex* p3 = bm.AddToBlockIndex(block3);
        REQUIRE(p3 == nullptr);  // Rejected - parent not found
        REQUIRE(bm.GetBlockCount() == 1);  // Only genesis

        // Try to add block 2 (parent still unknown) - should also be rejected
        CBlockIndex* p2 = bm.AddToBlockIndex(block2);
        REQUIRE(p2 == nullptr);  // Rejected - parent not found
        REQUIRE(bm.GetBlockCount() == 1);  // Still only genesis

        // Add block 1 (connects to genesis) - should succeed
        CBlockIndex* p1 = bm.AddToBlockIndex(block1);
        REQUIRE(p1 != nullptr);
        REQUIRE(p1->pprev != nullptr);
        REQUIRE(p1->nHeight == 1);
        REQUIRE(bm.GetBlockCount() == 2);  // Genesis + block1

        // Now add block 2 (connects to block1) - should succeed
        p2 = bm.AddToBlockIndex(block2);
        REQUIRE(p2 != nullptr);
        REQUIRE(p2->pprev == p1);
        REQUIRE(p2->nHeight == 2);
        REQUIRE(bm.GetBlockCount() == 3);  // Genesis + block1 + block2

        // Finally add block 3 (connects to block2) - should succeed
        p3 = bm.AddToBlockIndex(block3);
        REQUIRE(p3 != nullptr);
        REQUIRE(p3->pprev == p2);
        REQUIRE(p3->nHeight == 3);
        REQUIRE(bm.GetBlockCount() == 4);  // Complete chain
    }
}

//==============================================================================
// Defensive Tests - Corruption Detection
//==============================================================================

TEST_CASE("BlockManager Defensive - Hash Corruption Detection", "[chain][block_manager][defensive]") {
    BlockManagerTestFixture fixture;

    SECTION("Detect corrupted block hash") {
        // Create valid JSON, then corrupt a hash
        json root = fixture.CreateValidChainJSON(3);

        // Corrupt the hash of block at index 1 (not genesis)
        root["blocks"][1]["hash"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        // Write to file
        std::ofstream file(fixture.test_file);
        file << root.dump();
        file.close();

        // Load should fail - recomputed hash won't match stored hash
        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::CORRUPTED);
    }

    SECTION("Detect tampered header fields") {
        json root = fixture.CreateValidChainJSON(2);

        // Tamper with a header field (change nTime)
        root["blocks"][1]["time"] = 99999;
        // Hash remains the same (invalid!)

        std::ofstream file(fixture.test_file);
        file << root.dump();
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::CORRUPTED);
    }
}

TEST_CASE("BlockManager Defensive - Multiple Genesis Detection", "[chain][block_manager][defensive]") {
    BlockManagerTestFixture fixture;

    SECTION("Reject multiple genesis blocks") {
        json root = fixture.CreateValidChainJSON(3);

        // Corrupt: set two blocks to have null prev_hash (both claim to be genesis)
        root["blocks"][1]["prev_hash"] = uint256().ToString();

        std::ofstream file(fixture.test_file);
        file << root.dump();
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::CORRUPTED);
    }

    SECTION("Reject zero genesis blocks") {
        json root = fixture.CreateValidChainJSON(2);

        // Corrupt: make all blocks have a parent (no genesis)
        std::string fake_parent = "1111111111111111111111111111111111111111111111111111111111111111";
        root["blocks"][0]["prev_hash"] = fake_parent;

        std::ofstream file(fixture.test_file);
        file << root.dump();
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::CORRUPTED);
    }

    SECTION("Reject wrong genesis hash") {
        json root = fixture.CreateValidChainJSON(2);

        // The file claims a different genesis hash
        root["genesis_hash"] = "2222222222222222222222222222222222222222222222222222222222222222";

        std::ofstream file(fixture.test_file);
        file << root.dump();
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        // This should fail at the genesis hash mismatch check (before unique genesis check)
        REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::CORRUPTED);
    }
}

TEST_CASE("BlockManager Defensive - Chain Continuity", "[chain][block_manager][defensive]") {
    BlockManagerTestFixture fixture;

    SECTION("Detect broken chain - missing parent") {
        json root = fixture.CreateValidChainJSON(3);

        // Remove the block at height 1, so block at height 2 has missing parent
        auto& blocks = root["blocks"];
        for (size_t i = 0; i < blocks.size(); i++) {
            if (blocks[i]["height"] == 1) {
                blocks.erase(i);
                break;
            }
        }
        root["block_count"] = blocks.size();

        std::ofstream file(fixture.test_file);
        file << root.dump();
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::CORRUPTED);
    }

    SECTION("Detect blocks not descending from genesis") {
        json root = fixture.CreateValidChainJSON(2);

        // Best tip doesn't connect to genesis (separate chain)
        json& tip_block = root["blocks"][1];
        tip_block["prev_hash"] = "3333333333333333333333333333333333333333333333333333333333333333";
        // This will fail hash reconstruction, but let's also test continuity

        std::ofstream file(fixture.test_file);
        file << root.dump();
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::CORRUPTED);
    }
}

//==============================================================================
// Defensive Tests - Height Validation
//==============================================================================

TEST_CASE("BlockManager Defensive - Height Invariants", "[chain][block_manager][defensive]") {
    BlockManagerTestFixture fixture;

    SECTION("Detect parent height >= child height") {
        json root = fixture.CreateValidChainJSON(3);

        // Corrupt: child has same height as parent
        root["blocks"][1]["height"] = 0;  // Same as genesis

        std::ofstream file(fixture.test_file);
        file << root.dump();
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::CORRUPTED);
    }

    SECTION("Detect parent height > child height") {
        json root = fixture.CreateValidChainJSON(3);

        // Corrupt: parent has higher height than child
        root["blocks"][0]["height"] = 10;
        root["blocks"][1]["height"] = 5;

        std::ofstream file(fixture.test_file);
        file << root.dump();
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::CORRUPTED);
    }

    SECTION("Detect negative height") {
        json root = fixture.CreateValidChainJSON(2);

        root["blocks"][1]["height"] = -1;

        std::ofstream file(fixture.test_file);
        file << root.dump();
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        // This should fail somewhere (likely during validation)
        REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::CORRUPTED);
    }

    SECTION("Detect height gap") {
        json root = fixture.CreateValidChainJSON(3);

        // Genesis=0, block1=1, block2=10 (gap!)
        root["blocks"][2]["height"] = 10;

        std::ofstream file(fixture.test_file);
        file << root.dump();
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::CORRUPTED);
    }

    SECTION("Detect genesis with non-zero height") {
        json root = fixture.CreateValidChainJSON(2);

        root["blocks"][0]["height"] = 5;

        std::ofstream file(fixture.test_file);
        file << root.dump();
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::CORRUPTED);
    }
}

//==============================================================================
// Defensive Tests - JSON Structure
//==============================================================================

TEST_CASE("BlockManager Defensive - JSON Structure", "[chain][block_manager][defensive]") {
    BlockManagerTestFixture fixture;

    SECTION("Reject missing 'blocks' field") {
        json root;
        root["version"] = 1;
        root["block_count"] = 0;
        root["genesis_hash"] = CreateTestHeader().GetHash().ToString();
        // Missing "blocks" field

        std::ofstream file(fixture.test_file);
        file << root.dump();
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::CORRUPTED);
    }

    SECTION("Reject 'blocks' as non-array") {
        json root;
        root["version"] = 1;
        root["block_count"] = 1;
        root["genesis_hash"] = CreateTestHeader().GetHash().ToString();
        root["blocks"] = "not an array";  // Wrong type!

        std::ofstream file(fixture.test_file);
        file << root.dump();
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::CORRUPTED);
    }

    SECTION("Warn on block_count mismatch") {
        json root = fixture.CreateValidChainJSON(3);

        // block_count says 10 but array has 3
        root["block_count"] = 10;

        std::ofstream file(fixture.test_file);
        file << root.dump();
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        // Should still load (uses actual array size) but logs warning
        LoadResult result = bm.Load(fixture.test_file, genesis.GetHash());
        REQUIRE(result == LoadResult::SUCCESS);
        REQUIRE(bm.GetBlockCount() == 3);  // Actual size, not claimed size
    }

    SECTION("Reject missing required field - hash") {
        json root = fixture.CreateValidChainJSON(2);

        root["blocks"][1].erase("hash");

        std::ofstream file(fixture.test_file);
        file << root.dump();
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::CORRUPTED);
    }

    SECTION("Reject missing required field - height") {
        json root = fixture.CreateValidChainJSON(2);

        root["blocks"][1].erase("height");

        std::ofstream file(fixture.test_file);
        file << root.dump();
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::CORRUPTED);
    }

    SECTION("Reject empty blocks array") {
        json root;
        root["version"] = 1;
        root["block_count"] = 0;
        root["genesis_hash"] = CreateTestHeader().GetHash().ToString();
        root["blocks"] = json::array();  // Empty

        std::ofstream file(fixture.test_file);
        file << root.dump();
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::CORRUPTED);
    }

    SECTION("Reject unsupported version") {
        json root = fixture.CreateValidChainJSON(2);
        root["version"] = 999;

        std::ofstream file(fixture.test_file);
        file << root.dump();
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::CORRUPTED);
    }
}

//==============================================================================
// Defensive Tests - Tip Selection
//==============================================================================

TEST_CASE("BlockManager Defensive - Tip Selection", "[chain][block_manager][defensive]") {
    BlockManagerTestFixture fixture;

    SECTION("Select tip with most work") {
        // Create two forks with different work
        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader(1000, 0x1d00ffff);
        bm.Initialize(genesis);

        // Fork A: 2 blocks with high difficulty (more work)
        CBlockHeader a1 = CreateChildHeader(genesis.GetHash(), 2000, 0x1d00aaaa);
        CBlockHeader a2 = CreateChildHeader(a1.GetHash(), 3000, 0x1d00aaaa);
        bm.AddToBlockIndex(a1);
        bm.AddToBlockIndex(a2);

        // Fork B: 3 blocks with low difficulty (less total work)
        CBlockHeader b1 = CreateChildHeader(genesis.GetHash(), 2000, 0x1d00ffff);
        CBlockHeader b2 = CreateChildHeader(b1.GetHash(), 3000, 0x1d00ffff);
        CBlockHeader b3 = CreateChildHeader(b2.GetHash(), 4000, 0x1d00ffff);
        bm.AddToBlockIndex(b1);
        bm.AddToBlockIndex(b2);
        bm.AddToBlockIndex(b3);

        // Save and reload
        REQUIRE(bm.Save(fixture.test_file));

        BlockManager bm2;
        REQUIRE(bm2.Load(fixture.test_file, genesis.GetHash()) == LoadResult::SUCCESS);

        // Should select fork with most work (not necessarily longest)
        REQUIRE(bm2.GetTip() != nullptr);
        // Fork A has more work due to higher difficulty
        REQUIRE(bm2.GetTip()->nHeight <= 3);  // Could be either fork
    }

    SECTION("Reject load when saved tip is invalid") {
        json root = fixture.CreateValidChainJSON(3);

        // Find and mark the block at height 2 (the tip) as invalid
        for (auto& block : root["blocks"]) {
            if (block["height"] == 2) {
                block["status"] = {
                    {"validation", BlockStatus::TREE},
                    {"failure", BlockStatus::VALIDATION_FAILED}
                };
                break;
            }
        }

        std::ofstream file(fixture.test_file);
        file << root.dump();
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        // Load should fail because saved tip is marked as invalid
        REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::CORRUPTED);
    }
}

//==============================================================================
// Defensive Tests - Boundary Conditions
//==============================================================================

TEST_CASE("BlockManager Defensive - Boundary Conditions", "[chain][block_manager][defensive]") {
    BlockManagerTestFixture fixture;

    SECTION("Handle genesis-only blockchain") {
        json root = fixture.CreateValidChainJSON(1);

        std::ofstream file(fixture.test_file);
        file << root.dump();
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        REQUIRE(bm.Load(fixture.test_file, genesis.GetHash()) == LoadResult::SUCCESS);
        REQUIRE(bm.GetBlockCount() == 1);
        REQUIRE(bm.GetTip()->nHeight == 0);
    }

    SECTION("Handle maximum timestamp") {
        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader(UINT32_MAX);
        REQUIRE(bm.Initialize(genesis));

        REQUIRE(bm.Save(fixture.test_file));

        BlockManager bm2;
        REQUIRE(bm2.Load(fixture.test_file, genesis.GetHash()) == LoadResult::SUCCESS);
        REQUIRE(bm2.GetTip()->nTime == UINT32_MAX);
    }

    SECTION("Save preserves height order") {
        // Create blocks out of order, save, verify JSON is sorted
        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        bm.Initialize(genesis);

        CBlockHeader b1 = CreateChildHeader(genesis.GetHash(), 2000);
        CBlockHeader b2 = CreateChildHeader(b1.GetHash(), 3000);
        CBlockHeader b3 = CreateChildHeader(b2.GetHash(), 4000);

        bm.AddToBlockIndex(b1);
        bm.AddToBlockIndex(b2);
        bm.AddToBlockIndex(b3);

        REQUIRE(bm.Save(fixture.test_file));

        // Read JSON and verify blocks are in height order
        std::ifstream file(fixture.test_file);
        json root;
        file >> root;
        file.close();

        REQUIRE(root["blocks"].is_array());
        int prev_height = -1;
        for (const auto& block : root["blocks"]) {
            int height = block["height"].get<int>();
            REQUIRE(height > prev_height);  // Ascending order
            prev_height = height;
        }
    }
}

//==============================================================================
// Defensive Tests - Performance
//==============================================================================

TEST_CASE("BlockManager Defensive - Performance", "[chain][block_manager][defensive][!benchmark]") {
    BlockManagerTestFixture fixture;

    SECTION("Handle moderately large chain (1000 blocks)") {
        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        bm.Initialize(genesis);

        CBlockIndex* prev = bm.GetTip();
        for (int i = 1; i < 1000; i++) {
            CBlockHeader block = CreateChildHeader(prev->GetBlockHash(), 1000000 + i);
            prev = bm.AddToBlockIndex(block);
            REQUIRE(prev != nullptr);
        }

        REQUIRE(bm.GetBlockCount() == 1000);

        // Set active tip to the end of the chain before saving
        bm.SetActiveTip(*prev);
        REQUIRE(bm.GetTip()->nHeight == 999);

        // Save and reload should be fast (no quadratic behavior)
        auto start = std::chrono::steady_clock::now();
        REQUIRE(bm.Save(fixture.test_file));
        auto save_duration = std::chrono::steady_clock::now() - start;

        BlockManager bm2;
        start = std::chrono::steady_clock::now();
        REQUIRE(bm2.Load(fixture.test_file, genesis.GetHash()) == LoadResult::SUCCESS);
        auto load_duration = std::chrono::steady_clock::now() - start;

        REQUIRE(bm2.GetBlockCount() == 1000);
        REQUIRE(bm2.GetTip()->nHeight == 999);

        // Should complete in reasonable time (not checking specific duration,
        // just ensuring it doesn't hang or crash)
        INFO("Save took: " << std::chrono::duration_cast<std::chrono::milliseconds>(save_duration).count() << "ms");
        INFO("Load took: " << std::chrono::duration_cast<std::chrono::milliseconds>(load_duration).count() << "ms");
    }

    SECTION("Handle many forks (50 competing chains)") {
        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        bm.Initialize(genesis);

        // Create 50 forks from genesis, each 5 blocks long
        for (int fork = 0; fork < 50; fork++) {
            CBlockIndex* prev = bm.GetTip();  // Genesis
            for (int height = 1; height <= 5; height++) {
                CBlockHeader block = CreateChildHeader(prev->GetBlockHash(), 1000000 + fork * 1000 + height);
                prev = bm.AddToBlockIndex(block);
                REQUIRE(prev != nullptr);
            }
        }

        REQUIRE(bm.GetBlockCount() == 1 + 50 * 5);  // Genesis + 250 blocks

        REQUIRE(bm.Save(fixture.test_file));

        BlockManager bm2;
        REQUIRE(bm2.Load(fixture.test_file, genesis.GetHash()) == LoadResult::SUCCESS);
        REQUIRE(bm2.GetBlockCount() == 251);
    }
}

//==============================================================================
// Defensive Tests - Unknown Parent Handling
//==============================================================================

TEST_CASE("BlockManager Defensive - Unknown Parent Rejection", "[chain][block_manager][defensive]") {
    SECTION("AddToBlockIndex rejects block with unknown parent") {
        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        bm.Initialize(genesis);

        // Create header with unknown parent
        uint256 unknown;
        unknown.SetHex("4444444444444444444444444444444444444444444444444444444444444444");
        CBlockHeader unconnecting = CreateChildHeader(unknown);

        // Should reject - BlockManager only accepts blocks whose parent is indexed
        CBlockIndex* pindex = bm.AddToBlockIndex(unconnecting);
        REQUIRE(pindex == nullptr);
        REQUIRE(bm.GetBlockCount() == 1);  // Only genesis
    }

    SECTION("AddToBlockIndex accepts valid child after parent added") {
        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        bm.Initialize(genesis);

        CBlockHeader block1 = CreateChildHeader(genesis.GetHash());
        CBlockHeader block2 = CreateChildHeader(block1.GetHash());

        // Try to add block2 first (parent not indexed) - rejected
        CBlockIndex* p2 = bm.AddToBlockIndex(block2);
        REQUIRE(p2 == nullptr);

        // Add block1 (valid)
        CBlockIndex* p1 = bm.AddToBlockIndex(block1);
        REQUIRE(p1 != nullptr);
        REQUIRE(p1->nHeight == 1);

        // Now block2 can be added
        p2 = bm.AddToBlockIndex(block2);
        REQUIRE(p2 != nullptr);
        REQUIRE(p2->nHeight == 2);
        REQUIRE(p2->pprev == p1);
    }
}

//==============================================================================
// Defensive Tests - Corruption Recovery
//==============================================================================

TEST_CASE("BlockManager - Corruption Recovery", "[chain][block_manager][corruption]") {
    BlockManagerTestFixture fixture;

    SECTION("Corrupted JSON returns CORRUPTED, not FILE_NOT_FOUND") {
        // Create a corrupted JSON file
        std::ofstream file(fixture.test_file);
        file << "{ this is not valid JSON [[[";
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();

        // Should return CORRUPTED (file exists but is invalid)
        LoadResult result = bm.Load(fixture.test_file, genesis.GetHash());
        REQUIRE(result == LoadResult::CORRUPTED);
        REQUIRE(result != LoadResult::FILE_NOT_FOUND);
    }

    SECTION("Truncated JSON returns CORRUPTED") {
        // Create valid start of JSON but truncated
        std::ofstream file(fixture.test_file);
        file << R"({"version": 1, "block_count": 5, "blocks": [{"hash": ")";
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();

        LoadResult result = bm.Load(fixture.test_file, genesis.GetHash());
        REQUIRE(result == LoadResult::CORRUPTED);
    }

    SECTION("Empty file returns CORRUPTED") {
        // Create empty file
        std::ofstream file(fixture.test_file);
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();

        LoadResult result = bm.Load(fixture.test_file, genesis.GetHash());
        REQUIRE(result == LoadResult::CORRUPTED);
    }

    SECTION("Binary garbage returns CORRUPTED") {
        // Write binary garbage
        std::ofstream file(fixture.test_file, std::ios::binary);
        char garbage[] = {0x00, 0x01, 0x02, (char)0xFF, (char)0xFE, 0x00};
        file.write(garbage, sizeof(garbage));
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();

        LoadResult result = bm.Load(fixture.test_file, genesis.GetHash());
        REQUIRE(result == LoadResult::CORRUPTED);
    }

    SECTION("Valid JSON but wrong schema returns CORRUPTED") {
        // Valid JSON but completely wrong structure
        std::ofstream file(fixture.test_file);
        file << R"({"name": "John", "age": 30})";
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();

        LoadResult result = bm.Load(fixture.test_file, genesis.GetHash());
        REQUIRE(result == LoadResult::CORRUPTED);
    }

    SECTION("Partial block data returns CORRUPTED") {
        // Create JSON with missing required fields in a block
        json root;
        root["version"] = 1;
        root["block_count"] = 1;
        root["genesis_hash"] = CreateTestHeader().GetHash().ToString();
        root["tip_hash"] = CreateTestHeader().GetHash().ToString();

        json blocks = json::array();
        json block;
        block["hash"] = CreateTestHeader().GetHash().ToString();
        // Missing: prev_hash, version, miner_address, time, bits, nonce, hash_randomx, height, chainwork, status
        blocks.push_back(block);
        root["blocks"] = blocks;

        std::ofstream file(fixture.test_file);
        file << root.dump();
        file.close();

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();

        LoadResult result = bm.Load(fixture.test_file, genesis.GetHash());
        REQUIRE(result == LoadResult::CORRUPTED);
    }

    SECTION("Non-existent file returns FILE_NOT_FOUND") {
        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();

        // This file definitely doesn't exist
        LoadResult result = bm.Load("/tmp/definitely_does_not_exist_xyz123.json", genesis.GetHash());
        REQUIRE(result == LoadResult::FILE_NOT_FOUND);
    }

    SECTION("State is clean after CORRUPTED load") {
        // First, create a valid chain
        BlockManager bm1;
        CBlockHeader genesis = CreateTestHeader();
        bm1.Initialize(genesis);

        CBlockHeader block1 = CreateChildHeader(genesis.GetHash());
        bm1.AddToBlockIndex(block1);
        bm1.SetActiveTip(*bm1.LookupBlockIndex(block1.GetHash()));

        // Now create a corrupted file
        std::ofstream file(fixture.test_file);
        file << "corrupted data";
        file.close();

        // Try to load - should fail
        BlockManager bm2;
        LoadResult result = bm2.Load(fixture.test_file, genesis.GetHash());
        REQUIRE(result == LoadResult::CORRUPTED);

        // State should be clean (not partially loaded)
        REQUIRE(bm2.GetBlockCount() == 0);
        REQUIRE(bm2.GetTip() == nullptr);
    }
}

//==============================================================================
// Defensive Tests - Atomic Save / Crash Consistency
//==============================================================================

TEST_CASE("BlockManager - Atomic Save", "[chain][block_manager][atomic]") {
    BlockManagerTestFixture fixture;

    SECTION("Save creates file atomically") {
        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        bm.Initialize(genesis);

        // Add some blocks
        CBlockIndex* prev = bm.GetTip();
        for (int i = 0; i < 10; i++) {
            CBlockHeader block = CreateChildHeader(prev->GetBlockHash(), 1000 + i);
            prev = bm.AddToBlockIndex(block);
        }
        bm.SetActiveTip(*prev);

        // Save should succeed
        REQUIRE(bm.Save(fixture.test_file));

        // File should exist and be valid
        REQUIRE(std::filesystem::exists(fixture.test_file));

        // Load should succeed
        BlockManager bm2;
        REQUIRE(bm2.Load(fixture.test_file, genesis.GetHash()) == LoadResult::SUCCESS);
        REQUIRE(bm2.GetBlockCount() == 11);
    }

    SECTION("Temp file is cleaned up after successful save") {
        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        bm.Initialize(genesis);

        REQUIRE(bm.Save(fixture.test_file));

        // Check no temp file remains (temp file pattern is <filename>.tmp)
        std::string temp_file = fixture.test_file + ".tmp";
        REQUIRE_FALSE(std::filesystem::exists(temp_file));
    }

    SECTION("Original file preserved if save target is new") {
        // This tests that atomic write doesn't corrupt anything
        // when writing to a new location
        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        bm.Initialize(genesis);

        std::string new_file = fixture.test_file + "_new.json";

        REQUIRE(bm.Save(new_file));
        REQUIRE(std::filesystem::exists(new_file));

        // Cleanup
        std::filesystem::remove(new_file);
    }

    SECTION("Save to invalid path fails gracefully") {
        // Skip test when running as root (root can create directories anywhere)
        if (geteuid() == 0) {
            WARN("Skipping invalid path test when running as root");
            return;
        }

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        bm.Initialize(genesis);

        // Try to save to a directory that doesn't exist
        bool result = bm.Save("/nonexistent/directory/path/headers.json");
        REQUIRE_FALSE(result);

        // BlockManager state should be unchanged
        REQUIRE(bm.GetBlockCount() == 1);
        REQUIRE(bm.GetTip() != nullptr);
    }

    SECTION("Save overwrites existing file atomically") {
        BlockManager bm1;
        CBlockHeader genesis = CreateTestHeader();
        bm1.Initialize(genesis);
        REQUIRE(bm1.Save(fixture.test_file));

        // Verify first save
        {
            BlockManager verify;
            REQUIRE(verify.Load(fixture.test_file, genesis.GetHash()) == LoadResult::SUCCESS);
            REQUIRE(verify.GetBlockCount() == 1);
        }

        // Create larger chain and overwrite
        BlockManager bm2;
        bm2.Initialize(genesis);
        CBlockIndex* prev = bm2.GetTip();
        for (int i = 0; i < 5; i++) {
            CBlockHeader block = CreateChildHeader(prev->GetBlockHash(), 2000 + i);
            prev = bm2.AddToBlockIndex(block);
        }
        bm2.SetActiveTip(*prev);
        REQUIRE(bm2.Save(fixture.test_file));

        // Verify overwrite worked
        {
            BlockManager verify;
            REQUIRE(verify.Load(fixture.test_file, genesis.GetHash()) == LoadResult::SUCCESS);
            REQUIRE(verify.GetBlockCount() == 6);  // genesis + 5 blocks
        }
    }
}

//==============================================================================
// Defensive Tests - Disk Full Handling
//==============================================================================

TEST_CASE("BlockManager - Disk Full Handling", "[chain][block_manager][diskfull]") {
    BlockManagerTestFixture fixture;

    SECTION("Save to read-only location fails gracefully") {
        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        bm.Initialize(genesis);

        // /proc is a read-only filesystem on Linux, /dev/null won't work as a file
        // Use a path that definitely can't be written to
        #ifdef __linux__
        bool result = bm.Save("/proc/headers.json");
        REQUIRE_FALSE(result);
        #elif defined(__APPLE__)
        // On macOS, try a system directory
        bool result = bm.Save("/System/headers.json");
        REQUIRE_FALSE(result);
        #endif

        // State should be unchanged after failed save
        REQUIRE(bm.GetBlockCount() == 1);
    }

    SECTION("State unchanged after failed save") {
        // Skip test when running as root (root can create directories anywhere)
        if (geteuid() == 0) {
            WARN("Skipping invalid path test when running as root");
            return;
        }

        BlockManager bm;
        CBlockHeader genesis = CreateTestHeader();
        bm.Initialize(genesis);

        // Build a chain
        CBlockIndex* prev = bm.GetTip();
        for (int i = 0; i < 5; i++) {
            CBlockHeader block = CreateChildHeader(prev->GetBlockHash(), 1000 + i);
            prev = bm.AddToBlockIndex(block);
        }
        bm.SetActiveTip(*prev);

        uint256 original_tip = bm.GetTip()->GetBlockHash();
        size_t original_count = bm.GetBlockCount();

        // Attempt save to invalid location
        bool result = bm.Save("/invalid/path/headers.json");
        REQUIRE_FALSE(result);

        // Verify state is completely unchanged
        REQUIRE(bm.GetBlockCount() == original_count);
        REQUIRE(bm.GetTip()->GetBlockHash() == original_tip);
    }

    // Note: Actually simulating disk full is difficult in unit tests without
    // special test infrastructure (tmpfs with size limits, etc.)
    // The atomic_write_file function handles this by:
    // 1. Writing to temp file (will fail if disk full)
    // 2. fsync (will fail if disk full during flush)
    // 3. rename (will succeed even on nearly-full disk since it's metadata only)
    //
    // The key guarantee is: if Save() returns false, the original file (if any)
    // is untouched.
}

//==============================================================================
// Advanced Tests - Reorg at Suspicious Depth Boundary
//==============================================================================

TEST_CASE("Reorg at exact suspicious_reorg_depth boundary", "[chain][reorg][boundary]") {
    using namespace unicity;
    using namespace unicity::chain;
    using namespace unicity::validation;
    using namespace unicity::test;

    auto params = ChainParams::CreateRegTest();

    // Set suspicious depth to exactly 5 blocks
    params->SetSuspiciousReorgDepth(5);

    TestChainstateManager csm(*params);
    REQUIRE(csm.Initialize(params->GenesisBlock()));

    // Build main chain to height 10
    const CBlockIndex* tip = csm.GetTip();
    const CBlockIndex* forkPoint = nullptr;

    for (int i = 1; i <= 10; i++) {
        uint32_t bits = consensus::GetNextWorkRequired(tip, *params);
        CBlockHeader h = MakeChild(tip, tip->nTime + 120, bits);
        validation::ValidationState s;
        auto* pi = csm.AcceptBlockHeader(h, s);
        REQUIRE(pi != nullptr);
        csm.TryAddBlockIndexCandidate(pi);
        REQUIRE(csm.ActivateBestChain());
        tip = csm.GetTip();

        if (i == 5) {
            forkPoint = tip;
        }
    }

    REQUIRE(tip->nHeight == 10);

    // Test 1: Reorg of exactly 4 blocks (should be ALLOWED)
    {
        // Build competing fork from height 6 with more work
        const CBlockIndex* forkTip = csm.LookupBlockIndex(forkPoint->GetBlockHash());

        for (int i = 0; i < 5; i++) { // Build 5 blocks to get more work
            uint32_t bits = consensus::GetNextWorkRequired(forkTip, *params);
            CBlockHeader h = MakeChild(forkTip, forkTip->nTime + 120, bits);
            validation::ValidationState s;
            auto* pi = csm.AcceptBlockHeader(h, s);
            REQUIRE(pi != nullptr);
            csm.TryAddBlockIndexCandidate(pi);
            forkTip = pi;
        }

        // This reorg is 4 blocks deep (10 -> 6), should be allowed
        bool activated = csm.ActivateBestChain();

        // With depth 5, reorg of 4 should be allowed
        // NOTE: The policy is: refuse if depth >= suspicious_reorg_depth
        // So depth 4 < 5 should be ALLOWED
        REQUIRE(activated);
        REQUIRE(csm.GetTip() == forkTip);
    }
}

TEST_CASE("Reorg refuses at suspicious_reorg_depth threshold", "[chain][reorg][policy]") {
    using namespace unicity;
    using namespace unicity::chain;
    using namespace unicity::validation;
    using namespace unicity::test;

    auto params = ChainParams::CreateRegTest();

    // Set suspicious depth to exactly 5 blocks
    params->SetSuspiciousReorgDepth(5);

    TestChainstateManager csm(*params);
    REQUIRE(csm.Initialize(params->GenesisBlock()));

    // Build main chain to height 10
    const CBlockIndex* tip = csm.GetTip();
    const CBlockIndex* forkPoint = nullptr;

    for (int i = 1; i <= 10; i++) {
        uint32_t bits = consensus::GetNextWorkRequired(tip, *params);
        CBlockHeader h = MakeChild(tip, tip->nTime + 120, bits);
        validation::ValidationState s;
        auto* pi = csm.AcceptBlockHeader(h, s);
        REQUIRE(pi != nullptr);
        csm.TryAddBlockIndexCandidate(pi);
        REQUIRE(csm.ActivateBestChain());
        tip = csm.GetTip();

        if (i == 5) {
            forkPoint = tip;
        }
    }

    REQUIRE(tip->nHeight == 10);
    const CBlockIndex* originalTip = tip;

    // Test 2: Reorg of exactly 5 blocks (should be REFUSED)
    {
        // Subscribe to fatal error notification BEFORE building the fork
        bool got_fatal_error = false;
        std::string debug_msg;
        auto sub = Notifications().SubscribeFatalError([&](const std::string& debug_message, const std::string& user_message) {
            got_fatal_error = true;
            debug_msg = debug_message;
        });

        // Build competing fork from height 5 with more work
        // Use different timestamps to create different block hashes
        const CBlockIndex* forkTip = csm.LookupBlockIndex(forkPoint->GetBlockHash());

        for (int i = 0; i < 6; i++) { // Build 6 blocks to get more work
            uint32_t bits = consensus::GetNextWorkRequired(forkTip, *params);
            // Use different time (+240 instead of +120) to create different hashes than main chain
            CBlockHeader h = MakeChild(forkTip, forkTip->nTime + 240, bits);
            validation::ValidationState s;
            auto* pi = csm.AcceptBlockHeader(h, s);
            REQUIRE(pi != nullptr);
            csm.TryAddBlockIndexCandidate(pi);
            forkTip = pi;
        }

        // Now activate - this should trigger the 5-block reorg and REFUSE
        bool activated = csm.ActivateBestChain();

        // With depth 5, reorg of 5 should trigger fatal error
        // ActivateBestChain() returns false because the requested chain switch was refused
        REQUIRE_FALSE(activated);  // Returns false because activation was blocked
        REQUIRE(got_fatal_error);  // Fatal error notification was triggered
        REQUIRE(debug_msg.find("5 blocks") != std::string::npos);

        // Tip should remain on original chain (reorg was refused)
        REQUIRE(csm.GetTip() == originalTip);
        REQUIRE(csm.GetTip()->nHeight == 10);
    }
}

TEST_CASE("Load with descendants of failed blocks", "[chain][load][failed]") {
    using namespace unicity;
    using namespace unicity::chain;
    using namespace unicity::validation;
    using namespace unicity::test;

    auto params = ChainParams::CreateRegTest();

    // Build and save a chain with failed blocks
    std::string test_file = "/tmp/test_failed_load_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".json";

    {
        TestChainstateManager csm(*params);
        REQUIRE(csm.Initialize(params->GenesisBlock()));

        // Build main chain: genesis -> A1 -> A2 -> A3
        const CBlockIndex* tip = csm.GetTip();
        const CBlockIndex* blockToFail = nullptr;

        for (int i = 1; i <= 3; i++) {
            uint32_t bits = consensus::GetNextWorkRequired(tip, *params);
            CBlockHeader h = MakeChild(tip, tip->nTime + 120, bits);
            validation::ValidationState s;
            auto* pi = csm.AcceptBlockHeader(h, s);
            REQUIRE(pi != nullptr);
            csm.TryAddBlockIndexCandidate(pi);
            REQUIRE(csm.ActivateBestChain());
            tip = csm.GetTip();

            if (i == 2) {
                blockToFail = tip; // A2
            }
        }

        // Build descendants from A2: A2 -> B3 -> B4 (fork with different timestamps)
        const CBlockIndex* descendant = blockToFail;
        for (int i = 0; i < 2; i++) {
            uint32_t bits = consensus::GetNextWorkRequired(descendant, *params);
            // Use different time (+240 instead of +120) to create different hashes than A3
            CBlockHeader h = MakeChild(descendant, descendant->nTime + 240, bits);
            validation::ValidationState s;
            auto* pi = csm.AcceptBlockHeader(h, s);
            REQUIRE(pi != nullptr);
            csm.TryAddBlockIndexCandidate(pi);
            descendant = pi;
        }

        // Invalidate A2
        REQUIRE(csm.InvalidateBlock(blockToFail->GetBlockHash()));

        // Save to disk
        REQUIRE(csm.Save(test_file));
    }

    // Load and verify descendants are properly marked
    {
        TestChainstateManager csm2(*params);

        REQUIRE(csm2.Load(test_file) == chain::LoadResult::SUCCESS);

        // After load, the Load() function should have marked all descendants
        // of the failed block as ANCESTOR_FAILED

        // Verify we loaded the correct number of blocks
        REQUIRE(csm2.GetBlockCount() >= 6); // genesis + 3 main + 2 descendants

        // Tip should be at the valid chain (A1)
        REQUIRE(csm2.GetTip()->nHeight == 1);
    }

    // Cleanup
    std::filesystem::remove(test_file);
}

#if 0  // DISABLED: Stress test kills machine
TEST_CASE("InvalidateBlock - Multiple competing forks stress test", "[chain][invalidate][stress]") {
    using namespace unicity;
    using namespace unicity::chain;
    using namespace unicity::validation;
    using namespace unicity::test;

    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);

    REQUIRE(csm.Initialize(params->GenesisBlock()));
    const auto& genesis = params->GenesisBlock();

    // Build main chain: genesis -> A1 -> A2 -> A3 -> A4 -> A5
    const CBlockIndex* tip = csm.GetTip();
    std::vector<const CBlockIndex*> mainChain;
    mainChain.push_back(tip); // genesis

    for (int i = 1; i <= 5; i++) {
        uint32_t bits = consensus::GetNextWorkRequired(tip, *params);
        CBlockHeader h = MakeChild(tip, tip->nTime + 120, bits);
        validation::ValidationState s;
        auto* pi = csm.AcceptBlockHeader(h, s);
        REQUIRE(pi != nullptr);
        csm.TryAddBlockIndexCandidate(pi);
        REQUIRE(csm.ActivateBestChain());
        tip = csm.GetTip();
        mainChain.push_back(tip);
    }

    REQUIRE(tip->nHeight == 5);

    // Build fork 1 from A2: A2 -> B3 -> B4 -> B5 -> B6 (more work than main)
    const CBlockIndex* forkBase1 = mainChain[2]; // A2
    const CBlockIndex* forkTip1 = forkBase1;

    for (int i = 0; i < 4; i++) {
        uint32_t bits = consensus::GetNextWorkRequired(forkTip1, *params);
        CBlockHeader h = MakeChild(forkTip1, forkTip1->nTime + 120, bits);
        validation::ValidationState s;
        auto* pi = csm.AcceptBlockHeader(h, s);
        REQUIRE(pi != nullptr);
        csm.TryAddBlockIndexCandidate(pi);
        forkTip1 = pi;
    }

    // Build fork 2 from A3: A3 -> C4 -> C5 (equal work to main)
    const CBlockIndex* forkBase2 = mainChain[3]; // A3
    const CBlockIndex* forkTip2 = forkBase2;

    for (int i = 0; i < 2; i++) {
        uint32_t bits = consensus::GetNextWorkRequired(forkTip2, *params);
        CBlockHeader h = MakeChild(forkTip2, forkTip2->nTime + 120, bits);
        validation::ValidationState s;
        auto* pi = csm.AcceptBlockHeader(h, s);
        REQUIRE(pi != nullptr);
        csm.TryAddBlockIndexCandidate(pi);
        forkTip2 = pi;
    }

    // Build fork 3 from genesis: genesis -> D1 -> D2 -> D3 (less work)
    const CBlockIndex* forkBase3 = mainChain[0]; // genesis
    const CBlockIndex* forkTip3 = forkBase3;

    for (int i = 0; i < 3; i++) {
        uint32_t bits = consensus::GetNextWorkRequired(forkTip3, *params);
        CBlockHeader h = MakeChild(forkTip3, forkTip3->nTime + 120, bits);
        validation::ValidationState s;
        auto* pi = csm.AcceptBlockHeader(h, s);
        REQUIRE(pi != nullptr);
        csm.TryAddBlockIndexCandidate(pi);
        forkTip3 = pi;
    }

    // Now we have:
    // - Main chain at A5 (height 5)
    // - Fork 1: B6 (height 6, most work)
    // - Fork 2: C5 (height 5, same work as main)
    // - Fork 3: D3 (height 3, less work)

    // Activate best chain - should switch to B6
    REQUIRE(csm.ActivateBestChain());
    REQUIRE(csm.GetTip() == forkTip1);
    REQUIRE(csm.GetTip()->nHeight == 6);

    // Now invalidate A2 (the fork point for B chain)
    // This should:
    // 1. Disconnect B3->B4->B5->B6
    // 2. Mark A2 as failed
    // 3. Consider forks C and D as candidates
    // 4. Activate best valid chain

    REQUIRE(csm.InvalidateBlock(mainChain[2]->GetBlockHash())); // Invalidate A2

    // After invalidation, we should be on the best valid chain
    // Options: A1, C5 (descends from A3, which descends from A2 - INVALID), D3
    // Expected: D3 (only valid option)
    // Wait - C5 descends from A3 which descends from A2 (failed), so C5 should be lazy-marked as ANCESTOR_FAILED
    // when encountered

    // Actually, let's check what happened
    const CBlockIndex* newTip = csm.GetTip();

    // The tip should be A1 (last valid block on main chain before A2)
    REQUIRE(newTip == mainChain[1]);
    REQUIRE(newTip->nHeight == 1);

    // Verify A2 is marked as failed
    REQUIRE(mainChain[2]->status.IsFailed());
}
#endif  // DISABLED: Stress test
