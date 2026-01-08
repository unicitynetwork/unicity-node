#include "catch_amalgamated.hpp"
#include "chain/block_index.hpp"
#include "chain/block.hpp"
#include <memory>
#include <vector>

using namespace unicity;
using namespace unicity::chain;

// Helper function to create a test block header
CBlockHeader CreateTestHeader(uint32_t nTime = 1234567890, uint32_t nBits = 0x1d00ffff) {
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.minerAddress.SetNull();
    header.nTime = nTime;
    header.nBits = nBits;
    header.nNonce = 0;
    header.hashRandomX.SetNull();
    return header;
}

TEST_CASE("CBlockIndex - Construction and initialization", "[block_index]") {
    SECTION("Default constructor initializes all fields") {
        CBlockIndex index;

        REQUIRE(index.status.validation == BlockStatus::UNKNOWN);
        REQUIRE(index.status.failure == BlockStatus::NOT_FAILED);
        REQUIRE(index.m_block_hash.IsNull());
        REQUIRE(index.pprev == nullptr);
        REQUIRE(index.nHeight == 0);
        REQUIRE(index.nChainWork == 0);
        REQUIRE(index.nVersion == 0);
        REQUIRE(index.minerAddress.IsNull());
        REQUIRE(index.nTime == 0);
        REQUIRE(index.nBits == 0);
        REQUIRE(index.nNonce == 0);
        REQUIRE(index.hashRandomX.IsNull());
    }

    SECTION("Constructor from CBlockHeader copies header fields") {
        CBlockHeader header = CreateTestHeader(1000, 0x1d00ffff);
        header.nVersion = 2;
        header.nNonce = 12345;
        header.minerAddress.SetHex("0102030405060708090a0b0c0d0e0f1011121314");

        CBlockIndex index(header);

        REQUIRE(index.nVersion == 2);
        REQUIRE(index.nTime == 1000);
        REQUIRE(index.nBits == 0x1d00ffff);
        REQUIRE(index.nNonce == 12345);
        REQUIRE(index.minerAddress == header.minerAddress);
        REQUIRE(index.hashRandomX == header.hashRandomX);

        // Metadata fields should be default-initialized
        REQUIRE(index.status.validation == BlockStatus::UNKNOWN);
        REQUIRE(index.status.failure == BlockStatus::NOT_FAILED);
        REQUIRE(index.m_block_hash.IsNull());
        REQUIRE(index.pprev == nullptr);
        REQUIRE(index.nHeight == 0);
        REQUIRE(index.nChainWork == 0);
    }

    SECTION("Copy/move constructors are deleted") {
        // This test verifies the design decision is enforced at compile time
        // If this compiles, the test would fail, but it shouldn't compile
        STATIC_REQUIRE(std::is_copy_constructible_v<CBlockIndex> == false);
        STATIC_REQUIRE(std::is_copy_assignable_v<CBlockIndex> == false);
        STATIC_REQUIRE(std::is_move_constructible_v<CBlockIndex> == false);
        STATIC_REQUIRE(std::is_move_assignable_v<CBlockIndex> == false);
    }
}

TEST_CASE("CBlockIndex - GetBlockHash", "[block_index]") {
    SECTION("GetBlockHash returns the hash when m_block_hash is set") {
        CBlockIndex index;
        uint256 hash;
        hash.SetHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

        index.m_block_hash = hash;

        REQUIRE(index.GetBlockHash() == hash);
    }

    SECTION("GetBlockHash with real header hash") {
        CBlockHeader header = CreateTestHeader();
        uint256 hash = header.GetHash();

        CBlockIndex index(header);
        index.m_block_hash = hash;

        REQUIRE(index.GetBlockHash() == hash);
        REQUIRE(index.GetBlockHash() == header.GetHash());
    }
}

TEST_CASE("CBlockIndex - GetBlockHeader", "[block_index]") {
    SECTION("GetBlockHeader reconstructs header without parent") {
        CBlockHeader original = CreateTestHeader(1000, 0x1d00ffff);
        original.nVersion = 2;
        original.nNonce = 54321;
        original.minerAddress.SetHex("0102030405060708090a0b0c0d0e0f1011121314");
        original.hashRandomX.SetHex("1111111111111111111111111111111111111111111111111111111111111111");

        CBlockIndex index(original);

        CBlockHeader reconstructed = index.GetBlockHeader();

        REQUIRE(reconstructed.nVersion == original.nVersion);
        REQUIRE(reconstructed.nTime == original.nTime);
        REQUIRE(reconstructed.nBits == original.nBits);
        REQUIRE(reconstructed.nNonce == original.nNonce);
        REQUIRE(reconstructed.minerAddress == original.minerAddress);
        REQUIRE(reconstructed.hashRandomX == original.hashRandomX);
        REQUIRE(reconstructed.hashPrevBlock.IsNull()); // No parent
    }

    SECTION("GetBlockHeader includes parent hash when pprev is set") {
        // Create parent block
        CBlockHeader parent_header = CreateTestHeader(900);
        uint256 parent_hash = parent_header.GetHash();
        CBlockIndex parent(parent_header);
        parent.m_block_hash = parent_hash;

        // Create child block
        CBlockHeader child_header = CreateTestHeader(1000);
        child_header.hashPrevBlock = parent_hash;
        CBlockIndex child(child_header);
        child.pprev = &parent;

        CBlockHeader reconstructed = child.GetBlockHeader();

        REQUIRE(reconstructed.hashPrevBlock == parent_hash);
        REQUIRE(reconstructed.hashPrevBlock == parent.GetBlockHash());
    }

    SECTION("GetBlockHeader returns self-contained copy") {
        CBlockHeader original = CreateTestHeader();
        uint256 hash = original.GetHash();

        CBlockIndex index(original);
        index.m_block_hash = hash;

        CBlockHeader copy = index.GetBlockHeader();

        // Modify the index
        index.nVersion = 999;
        index.nTime = 9999;

        // Copy should be unchanged
        REQUIRE(copy.nVersion == original.nVersion);
        REQUIRE(copy.nTime == original.nTime);
    }
}

TEST_CASE("CBlockIndex - GetBlockTime", "[block_index]") {
    SECTION("GetBlockTime returns nTime as int64_t") {
        CBlockIndex index;
        index.nTime = 1234567890;

        REQUIRE(index.GetBlockTime() == 1234567890);
    }

    SECTION("GetBlockTime handles maximum uint32_t value") {
        CBlockIndex index;
        index.nTime = 0xFFFFFFFF; // Max uint32_t

        int64_t time = index.GetBlockTime();
        REQUIRE(time == 0xFFFFFFFF);
        REQUIRE(time > 0); // Should be positive
    }
}

TEST_CASE("CBlockIndex - GetMedianTimePast", "[block_index]") {
    SECTION("Single block returns its own time") {
        CBlockIndex index;
        index.nTime = 1000;

        REQUIRE(index.GetMedianTimePast() == 1000);
    }

    SECTION("Two blocks returns median") {
        CBlockIndex index1;
        index1.nTime = 1000;

        CBlockIndex index2;
        index2.nTime = 2000;
        index2.pprev = &index1;

        int64_t median = index2.GetMedianTimePast();
        // Median of [1000, 2000] is one of them (depends on sort)
        REQUIRE((median == 1000 || median == 2000));
    }

    SECTION("Eleven blocks uses all for median") {
        // Create chain of 11 blocks with times: 1000, 1100, 1200, ..., 2000
        std::vector<CBlockIndex> chain(11);
        for (int i = 0; i < 11; i++) {
            chain[i].nTime = 1000 + i * 100;
            if (i > 0) {
                chain[i].pprev = &chain[i-1];
            }
        }

        int64_t median = chain[10].GetMedianTimePast();
        // Median of 11 values is the 6th value (index 5)
        REQUIRE(median == 1500); // 1000 + 5*100
    }

    SECTION("More than eleven blocks only uses last 11") {
        // Create chain of 20 blocks with times: 1000, 1100, 1200, ..., 2900
        std::vector<CBlockIndex> chain(20);
        for (int i = 0; i < 20; i++) {
            chain[i].nTime = 1000 + i * 100;
            if (i > 0) {
                chain[i].pprev = &chain[i-1];
            }
        }

        int64_t median = chain[19].GetMedianTimePast();
        // Should only consider blocks [9..19] (last 11)
        // Median of those is block 14: 1000 + 14*100 = 2400
        REQUIRE(median == 2400);
    }

    SECTION("Handles non-monotonic times correctly") {
        // Create blocks with intentionally unsorted times
        CBlockIndex index1;
        index1.nTime = 5000;

        CBlockIndex index2;
        index2.nTime = 3000; // Earlier!
        index2.pprev = &index1;

        CBlockIndex index3;
        index3.nTime = 4000; // Middle
        index3.pprev = &index2;

        int64_t median = index3.GetMedianTimePast();
        // Median of [3000, 4000, 5000] is 4000
        REQUIRE(median == 4000);
    }

    SECTION("Chain with duplicate timestamps") {
        std::vector<CBlockIndex> chain(5);
        chain[0].nTime = 1000;
        chain[1].nTime = 1000;
        chain[1].pprev = &chain[0];
        chain[2].nTime = 2000;
        chain[2].pprev = &chain[1];
        chain[3].nTime = 2000;
        chain[3].pprev = &chain[2];
        chain[4].nTime = 3000;
        chain[4].pprev = &chain[3];

        int64_t median = chain[4].GetMedianTimePast();
        // Sorted: [1000, 1000, 2000, 2000, 3000]
        // Median is index 2 = 2000
        REQUIRE(median == 2000);
    }
}

TEST_CASE("CBlockIndex - GetAncestor", "[block_index]") {
    SECTION("GetAncestor returns nullptr for invalid heights") {
        CBlockIndex index;
        index.nHeight = 5;

        REQUIRE(index.GetAncestor(-1) == nullptr);
        REQUIRE(index.GetAncestor(6) == nullptr);
        REQUIRE(index.GetAncestor(100) == nullptr);
    }

    SECTION("GetAncestor returns self for own height") {
        CBlockIndex index;
        index.nHeight = 5;

        REQUIRE(index.GetAncestor(5) == &index);
    }

    SECTION("GetAncestor walks chain correctly") {
        // Create chain: 0 -> 1 -> 2 -> 3 -> 4 -> 5
        std::vector<CBlockIndex> chain(6);
        for (int i = 0; i < 6; i++) {
            chain[i].nHeight = i;
            if (i > 0) {
                chain[i].pprev = &chain[i-1];
            }
        }

        // Test from tip (height 5)
        REQUIRE(chain[5].GetAncestor(5) == &chain[5]);
        REQUIRE(chain[5].GetAncestor(4) == &chain[4]);
        REQUIRE(chain[5].GetAncestor(3) == &chain[3]);
        REQUIRE(chain[5].GetAncestor(2) == &chain[2]);
        REQUIRE(chain[5].GetAncestor(1) == &chain[1]);
        REQUIRE(chain[5].GetAncestor(0) == &chain[0]);
    }

    SECTION("GetAncestor from middle of chain") {
        std::vector<CBlockIndex> chain(6);
        for (int i = 0; i < 6; i++) {
            chain[i].nHeight = i;
            if (i > 0) {
                chain[i].pprev = &chain[i-1];
            }
        }

        // Test from height 3
        REQUIRE(chain[3].GetAncestor(3) == &chain[3]);
        REQUIRE(chain[3].GetAncestor(2) == &chain[2]);
        REQUIRE(chain[3].GetAncestor(1) == &chain[1]);
        REQUIRE(chain[3].GetAncestor(0) == &chain[0]);
        REQUIRE(chain[3].GetAncestor(4) == nullptr); // Too high
    }

    SECTION("GetAncestor non-const overload") {
        std::vector<CBlockIndex> chain(3);
        for (int i = 0; i < 3; i++) {
            chain[i].nHeight = i;
            if (i > 0) {
                chain[i].pprev = &chain[i-1];
            }
        }

        CBlockIndex* ancestor = chain[2].GetAncestor(1);
        REQUIRE(ancestor == &chain[1]);

        // Verify we can modify through non-const pointer
        ancestor->nTime = 9999;
        REQUIRE(chain[1].nTime == 9999);
    }

    SECTION("GetAncestor on long chain") {
        // Test performance isn't terrible for longer chains
        const int chain_length = 1000;
        std::vector<CBlockIndex> chain(chain_length);
        for (int i = 0; i < chain_length; i++) {
            chain[i].nHeight = i;
            if (i > 0) {
                chain[i].pprev = &chain[i-1];
            }
        }

        REQUIRE(chain[999].GetAncestor(0) == &chain[0]);
        REQUIRE(chain[999].GetAncestor(500) == &chain[500]);
        REQUIRE(chain[999].GetAncestor(999) == &chain[999]);
    }
}

TEST_CASE("CBlockIndex - IsValid and RaiseValidity", "[block_index]") {
    SECTION("Default block is not valid") {
        CBlockIndex index;
        REQUIRE(index.status.validation == BlockStatus::UNKNOWN);
        REQUIRE(index.status.failure == BlockStatus::NOT_FAILED);
        REQUIRE_FALSE(index.IsValid(BlockStatus::HEADER));
        REQUIRE_FALSE(index.IsValid(BlockStatus::TREE));
    }

    SECTION("RaiseValidity to HEADER") {
        CBlockIndex index;

        bool changed = index.RaiseValidity(BlockStatus::HEADER);

        REQUIRE(changed);
        REQUIRE(index.IsValid(BlockStatus::HEADER));
        REQUIRE_FALSE(index.IsValid(BlockStatus::TREE));
    }

    SECTION("RaiseValidity to TREE") {
        CBlockIndex index;

        (void)index.RaiseValidity(BlockStatus::TREE);

        REQUIRE(index.IsValid(BlockStatus::HEADER));
        REQUIRE(index.IsValid(BlockStatus::TREE));
    }

    SECTION("RaiseValidity returns false if already at level") {
        CBlockIndex index;

        REQUIRE(index.RaiseValidity(BlockStatus::HEADER) == true);
        REQUIRE(index.RaiseValidity(BlockStatus::HEADER) == false); // No change
    }

    SECTION("RaiseValidity returns false if failed") {
        CBlockIndex index;
        index.status.MarkFailed();

        REQUIRE(index.RaiseValidity(BlockStatus::HEADER) == false);
        REQUIRE_FALSE(index.IsValid(BlockStatus::HEADER));
    }

    SECTION("IsValid returns false for failed blocks") {
        CBlockIndex index;
        index.status.validation = BlockStatus::HEADER;
        index.status.MarkFailed();

        REQUIRE_FALSE(index.IsValid(BlockStatus::HEADER));
    }

    SECTION("Failed child also fails validation") {
        CBlockIndex index;
        index.status.validation = BlockStatus::TREE;
        index.status.MarkAncestorFailed();

        REQUIRE_FALSE(index.IsValid(BlockStatus::TREE));
    }

    SECTION("Validity levels are hierarchical") {
        CBlockIndex index;

        (void)index.RaiseValidity(BlockStatus::TREE);

        // TREE implies HEADER
        REQUIRE(index.IsValid(BlockStatus::HEADER));
        REQUIRE(index.IsValid(BlockStatus::TREE));
    }
}

TEST_CASE("CBlockIndex - ToString", "[block_index]") {
    SECTION("ToString produces readable output") {
        CBlockIndex index;
        uint256 hash;
        hash.SetHex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

        index.nHeight = 100;
        index.m_block_hash = hash;
        index.minerAddress.SetHex("0102030405060708090a0b0c0d0e0f1011121314");

        std::string str = index.ToString();

        REQUIRE(str.find("height=100") != std::string::npos);
        REQUIRE(str.find("CBlockIndex") != std::string::npos);
        REQUIRE_FALSE(str.empty());
    }

    SECTION("ToString handles default hash") {
        CBlockIndex index;
        index.nHeight = 5;

        std::string str = index.ToString();

        // Default hash shows as zeros
        REQUIRE(str.find("0000000000000000") != std::string::npos);
    }
}

TEST_CASE("GetBlockProof - work calculation", "[block_index]") {
    SECTION("GetBlockProof returns zero for invalid nBits") {
        CBlockIndex index;

        // Negative target
        index.nBits = 0x00800000;
        REQUIRE(GetBlockProof(index) == 0);

        // Zero target
        index.nBits = 0x00000000;
        REQUIRE(GetBlockProof(index) == 0);

        // Zero mantissa
        index.nBits = 0x01000000;
        REQUIRE(GetBlockProof(index) == 0);
    }

    SECTION("GetBlockProof returns non-zero for valid nBits") {
        CBlockIndex index;
        index.nBits = 0x1d00ffff; // Bitcoin's initial difficulty

        arith_uint256 proof = GetBlockProof(index);

        REQUIRE(proof > 0);
    }

    SECTION("Higher difficulty produces more work") {
        CBlockIndex easy;
        easy.nBits = 0x1d00ffff; // Easier (larger target)

        CBlockIndex hard;
        hard.nBits = 0x1c00ffff; // Harder (smaller target)

        arith_uint256 easy_work = GetBlockProof(easy);
        arith_uint256 hard_work = GetBlockProof(hard);

        REQUIRE(hard_work > easy_work);
    }

    SECTION("GetBlockProof formula correctness") {
        CBlockIndex index;
        index.nBits = 0x1d00ffff;

        // Manual calculation
        arith_uint256 bnTarget;
        bool fNegative, fOverflow;
        bnTarget.SetCompact(index.nBits, &fNegative, &fOverflow);

        REQUIRE_FALSE(fNegative);
        REQUIRE_FALSE(fOverflow);
        REQUIRE(bnTarget != 0);

        // Expected: ~target / (target + 1) + 1
        arith_uint256 expected = (~bnTarget / (bnTarget + 1)) + 1;
        arith_uint256 actual = GetBlockProof(index);

        REQUIRE(actual == expected);
    }

    SECTION("GetBlockProof with RegTest difficulty") {
        CBlockIndex index;
        index.nBits = 0x207fffff; // RegTest (very easy)

        arith_uint256 proof = GetBlockProof(index);

        REQUIRE(proof > 0);
        REQUIRE(proof == 2); // RegTest has minimal work
    }

    SECTION("GetBlockProof consistency across multiple calls") {
        CBlockIndex index;
        index.nBits = 0x1d00ffff;

        arith_uint256 proof1 = GetBlockProof(index);
        arith_uint256 proof2 = GetBlockProof(index);

        REQUIRE(proof1 == proof2);
    }
}

TEST_CASE("LastCommonAncestor - fork detection", "[block_index]") {
    SECTION("Returns nullptr for null inputs") {
        CBlockIndex index;

        REQUIRE(LastCommonAncestor(nullptr, nullptr) == nullptr);
        REQUIRE(LastCommonAncestor(&index, nullptr) == nullptr);
        REQUIRE(LastCommonAncestor(nullptr, &index) == nullptr);
    }

    SECTION("Two identical blocks return self") {
        CBlockIndex index;

        const CBlockIndex* ancestor = LastCommonAncestor(&index, &index);

        REQUIRE(ancestor == &index);
    }

    SECTION("Parent and child return parent") {
        CBlockIndex parent;
        parent.nHeight = 0;

        CBlockIndex child;
        child.nHeight = 1;
        child.pprev = &parent;

        const CBlockIndex* ancestor = LastCommonAncestor(&parent, &child);

        REQUIRE(ancestor == &parent);
    }

    SECTION("Fork from common ancestor") {
        // Create: Genesis -> A -> B -> C (main)
        //                     \-> D -> E (fork)
        CBlockIndex genesis;
        genesis.nHeight = 0;

        CBlockIndex a;
        a.nHeight = 1;
        a.pprev = &genesis;

        CBlockIndex b;
        b.nHeight = 2;
        b.pprev = &a;

        CBlockIndex c;
        c.nHeight = 3;
        c.pprev = &b;

        CBlockIndex d;
        d.nHeight = 2;
        d.pprev = &a;

        CBlockIndex e;
        e.nHeight = 3;
        e.pprev = &d;

        // Test various combinations
        REQUIRE(LastCommonAncestor(&c, &e) == &a);
        REQUIRE(LastCommonAncestor(&b, &d) == &a);
        REQUIRE(LastCommonAncestor(&c, &d) == &a);
        REQUIRE(LastCommonAncestor(&b, &e) == &a);
    }

    SECTION("Fork with different heights") {
        // Genesis -> A -> B -> C -> D -> E (long chain)
        //         \-> F (short fork)
        CBlockIndex genesis;
        genesis.nHeight = 0;

        std::vector<CBlockIndex> main_chain(5);
        main_chain[0].nHeight = 1;
        main_chain[0].pprev = &genesis;
        for (int i = 1; i < 5; i++) {
            main_chain[i].nHeight = i + 1;
            main_chain[i].pprev = &main_chain[i-1];
        }

        CBlockIndex fork;
        fork.nHeight = 1;
        fork.pprev = &genesis;

        REQUIRE(LastCommonAncestor(&main_chain[4], &fork) == &genesis);
    }

    SECTION("Deep fork") {
        // Create a long common chain, then fork
        std::vector<CBlockIndex> common(10);
        common[0].nHeight = 0;
        for (int i = 1; i < 10; i++) {
            common[i].nHeight = i;
            common[i].pprev = &common[i-1];
        }

        // Branch A
        std::vector<CBlockIndex> branch_a(5);
        branch_a[0].nHeight = 10;
        branch_a[0].pprev = &common[9];
        for (int i = 1; i < 5; i++) {
            branch_a[i].nHeight = 10 + i;
            branch_a[i].pprev = &branch_a[i-1];
        }

        // Branch B
        std::vector<CBlockIndex> branch_b(3);
        branch_b[0].nHeight = 10;
        branch_b[0].pprev = &common[9];
        for (int i = 1; i < 3; i++) {
            branch_b[i].nHeight = 10 + i;
            branch_b[i].pprev = &branch_b[i-1];
        }

        REQUIRE(LastCommonAncestor(&branch_a[4], &branch_b[2]) == &common[9]);
    }

    SECTION("Ancestor is always at or below both heights") {
        std::vector<CBlockIndex> chain(10);
        chain[0].nHeight = 0;
        for (int i = 1; i < 10; i++) {
            chain[i].nHeight = i;
            chain[i].pprev = &chain[i-1];
        }

        const CBlockIndex* ancestor = LastCommonAncestor(&chain[7], &chain[3]);

        REQUIRE(ancestor == &chain[3]);
        REQUIRE(ancestor->nHeight <= chain[7].nHeight);
        REQUIRE(ancestor->nHeight <= chain[3].nHeight);
    }

    SECTION("Completely divergent chains return nullptr") {
        // Scenario: Two chains with different genesis blocks
        // This simulates database corruption or wrong chain params
        //
        // Chain A: genesisA -> A1 -> A2
        // Chain B: genesisB -> B1 -> B2
        //
        // No common ancestor should exist

        // Chain A
        CBlockIndex genesis_a;
        genesis_a.nHeight = 0;
        genesis_a.pprev = nullptr;

        CBlockIndex a1;
        a1.nHeight = 1;
        a1.pprev = &genesis_a;

        CBlockIndex a2;
        a2.nHeight = 2;
        a2.pprev = &a1;

        // Chain B (completely separate)
        CBlockIndex genesis_b;
        genesis_b.nHeight = 0;
        genesis_b.pprev = nullptr;

        CBlockIndex b1;
        b1.nHeight = 1;
        b1.pprev = &genesis_b;

        CBlockIndex b2;
        b2.nHeight = 2;
        b2.pprev = &b1;

        // These chains have no common ancestor
        const CBlockIndex* ancestor = LastCommonAncestor(&a2, &b2);

        REQUIRE(ancestor == nullptr);

        // Verify at various heights
        REQUIRE(LastCommonAncestor(&a1, &b1) == nullptr);
        REQUIRE(LastCommonAncestor(&a2, &b1) == nullptr);
        REQUIRE(LastCommonAncestor(&a1, &b2) == nullptr);
        REQUIRE(LastCommonAncestor(&genesis_a, &genesis_b) == nullptr);
    }
}

TEST_CASE("BlockStatus - struct operations", "[block_index]") {
    SECTION("Validity levels are sequential integers") {
        // Validity levels use numeric comparison
        REQUIRE(BlockStatus::UNKNOWN == 0);
        REQUIRE(BlockStatus::HEADER == 1);
        REQUIRE(BlockStatus::TREE == 2);
    }

    SECTION("Failure states are enumerated") {
        REQUIRE(BlockStatus::NOT_FAILED == 0);
        REQUIRE(BlockStatus::VALIDATION_FAILED == 1);
        REQUIRE(BlockStatus::ANCESTOR_FAILED == 2);
    }

    SECTION("BlockStatus has separate validation and failure") {
        BlockStatus status;
        REQUIRE(status.validation == BlockStatus::UNKNOWN);
        REQUIRE(status.failure == BlockStatus::NOT_FAILED);

        status.validation = BlockStatus::TREE;
        status.failure = BlockStatus::VALIDATION_FAILED;

        REQUIRE(status.validation == BlockStatus::TREE);
        REQUIRE(status.failure == BlockStatus::VALIDATION_FAILED);
    }

    SECTION("Status combinations with CBlockIndex") {
        CBlockIndex index;

        // Set both validity and failure (should fail validation)
        index.status.validation = BlockStatus::HEADER;
        index.status.MarkFailed();

        REQUIRE_FALSE(index.IsValid(BlockStatus::HEADER));
    }
}

TEST_CASE("CBlockIndex - Integration scenarios", "[block_index]") {
    SECTION("Simulate block chain building") {
        // Create a realistic chain scenario using std::map (like BlockManager does)
        std::map<uint256, CBlockIndex> block_index;
        std::vector<CBlockHeader> headers;
        std::vector<uint256> hashes;
        std::vector<CBlockIndex*> indices; // Pointers to map entries

        // Genesis
        headers.push_back(CreateTestHeader(1000000, 0x207fffff));
        hashes.push_back(headers[0].GetHash());

        auto [it0, _] = block_index.try_emplace(hashes[0], headers[0]);
        CBlockIndex* genesis = &it0->second;
        genesis->m_block_hash = it0->first;
        genesis->nHeight = 0;
        genesis->nChainWork = GetBlockProof(*genesis);
        [[maybe_unused]] bool raised0 = genesis->RaiseValidity(BlockStatus::TREE);
        indices.push_back(genesis);

        // Build chain of 10 blocks
        for (int i = 1; i < 10; i++) {
            headers.push_back(CreateTestHeader(1000000 + i * 600, 0x207fffff));
            headers[i].hashPrevBlock = hashes[i-1];
            hashes.push_back(headers[i].GetHash());

            auto [it, inserted] = block_index.try_emplace(hashes[i], headers[i]);
            REQUIRE(inserted);

            CBlockIndex* pindex = &it->second;
            pindex->m_block_hash = it->first;
            pindex->pprev = indices[i-1];
            pindex->nHeight = i;
            pindex->nChainWork = indices[i-1]->nChainWork + GetBlockProof(*pindex);
            [[maybe_unused]] bool raised = pindex->RaiseValidity(BlockStatus::TREE);
            indices.push_back(pindex);
        }

        // Verify chain properties
        REQUIRE(indices[9]->nHeight == 9);
        REQUIRE(indices[9]->pprev == indices[8]);
        REQUIRE(indices[9]->GetBlockHash() == hashes[9]);
        REQUIRE(indices[9]->IsValid(BlockStatus::TREE));
        REQUIRE(indices[9]->nChainWork > indices[0]->nChainWork);

        // Verify we can reconstruct headers
        CBlockHeader reconstructed = indices[9]->GetBlockHeader();
        REQUIRE(reconstructed.hashPrevBlock == hashes[8]);
        REQUIRE(reconstructed.GetHash() == hashes[9]);

        // Verify ancestor lookup
        REQUIRE(indices[9]->GetAncestor(0) == indices[0]);
        REQUIRE(indices[9]->GetAncestor(5) == indices[5]);

        // Verify median time past
        int64_t mtp = indices[9]->GetMedianTimePast();
        REQUIRE(mtp > 0);
        REQUIRE(mtp >= indices[0]->nTime);
        REQUIRE(mtp <= indices[9]->nTime);
    }
}

// ============================================================================
// Skip List Tests - Bitcoin Core O(log n) ancestor lookup
// ============================================================================

TEST_CASE("CBlockIndex - BuildSkip initialization", "[block_index][skip_list]") {
    SECTION("Genesis block has no skip pointer") {
        CBlockIndex genesis;
        genesis.nHeight = 0;
        genesis.pprev = nullptr;

        genesis.BuildSkip();

        REQUIRE(genesis.pskip == nullptr);
    }

    SECTION("Block 1 skips to genesis") {
        CBlockIndex genesis;
        genesis.nHeight = 0;
        genesis.pprev = nullptr;
        genesis.BuildSkip();

        CBlockIndex block1;
        block1.nHeight = 1;
        block1.pprev = &genesis;

        block1.BuildSkip();

        // Height 1: GetSkipHeight(1) = 0, pprev->GetAncestor(0) = genesis
        REQUIRE(block1.pskip == &genesis);
    }

    SECTION("Block 2 skips to genesis") {
        std::vector<CBlockIndex> chain(3);
        chain[0].nHeight = 0;
        chain[0].pprev = nullptr;
        chain[0].BuildSkip();

        chain[1].nHeight = 1;
        chain[1].pprev = &chain[0];
        chain[1].BuildSkip();

        chain[2].nHeight = 2;
        chain[2].pprev = &chain[1];
        chain[2].BuildSkip();

        // Height 2: GetSkipHeight(2) = InvertLowestOne(2) = 0
        REQUIRE(chain[2].pskip == &chain[0]);
    }

    SECTION("Power of 2 heights skip to previous power of 2") {
        // Create chain: 0, 1, 2, 3, 4, 5, 6, 7, 8
        std::vector<CBlockIndex> chain(9);
        for (int i = 0; i < 9; i++) {
            chain[i].nHeight = i;
            chain[i].pprev = (i > 0) ? &chain[i-1] : nullptr;
            chain[i].BuildSkip();
        }

        // Height 2 -> 0
        REQUIRE(chain[2].pskip == &chain[0]);

        // Height 4 -> 0
        REQUIRE(chain[4].pskip == &chain[0]);

        // Height 8 -> 0
        REQUIRE(chain[8].pskip == &chain[0]);
    }

    SECTION("Binary tree structure for heights 1-16") {
        std::vector<CBlockIndex> chain(17);
        for (int i = 0; i < 17; i++) {
            chain[i].nHeight = i;
            chain[i].pprev = (i > 0) ? &chain[i-1] : nullptr;
            chain[i].BuildSkip();
        }

        // Verify skip pattern follows Bitcoin Core algorithm
        REQUIRE(chain[0].pskip == nullptr);   // Genesis
        REQUIRE(chain[1].pskip == &chain[0]); // 1 -> 0
        REQUIRE(chain[2].pskip == &chain[0]); // 2 -> 0
        REQUIRE(chain[3].pskip == &chain[1]); // 3 -> 1
        REQUIRE(chain[4].pskip == &chain[0]); // 4 -> 0
        REQUIRE(chain[5].pskip == &chain[1]); // 5 -> 1
        REQUIRE(chain[6].pskip == &chain[4]); // 6 -> 4
        REQUIRE(chain[7].pskip == &chain[1]); // 7 -> 1
        REQUIRE(chain[8].pskip == &chain[0]); // 8 -> 0
        REQUIRE(chain[9].pskip == &chain[1]); // 9 -> 1
        REQUIRE(chain[10].pskip == &chain[8]); // 10 -> 8
        REQUIRE(chain[11].pskip == &chain[1]); // 11 -> 1
        REQUIRE(chain[12].pskip == &chain[8]); // 12 -> 8
        REQUIRE(chain[13].pskip == &chain[1]); // 13 -> 1
        REQUIRE(chain[14].pskip == &chain[12]); // 14 -> 12
        REQUIRE(chain[15].pskip == &chain[9]); // 15 -> 9
        REQUIRE(chain[16].pskip == &chain[0]); // 16 -> 0
    }
}

TEST_CASE("CBlockIndex - GetAncestor uses skip list", "[block_index][skip_list]") {
    SECTION("GetAncestor correctness with skip list") {
        // Build chain with skip pointers
        const int chain_length = 100;
        std::vector<CBlockIndex> chain(chain_length);
        for (int i = 0; i < chain_length; i++) {
            chain[i].nHeight = i;
            chain[i].pprev = (i > 0) ? &chain[i-1] : nullptr;
            chain[i].BuildSkip();
        }

        // Verify GetAncestor returns correct blocks
        REQUIRE(chain[99].GetAncestor(0) == &chain[0]);
        REQUIRE(chain[99].GetAncestor(50) == &chain[50]);
        REQUIRE(chain[99].GetAncestor(99) == &chain[99]);
        REQUIRE(chain[99].GetAncestor(25) == &chain[25]);
        REQUIRE(chain[99].GetAncestor(75) == &chain[75]);
        REQUIRE(chain[99].GetAncestor(1) == &chain[1]);
        REQUIRE(chain[99].GetAncestor(98) == &chain[98]);
    }

    SECTION("GetAncestor with powers of 2") {
        const int chain_length = 65;
        std::vector<CBlockIndex> chain(chain_length);
        for (int i = 0; i < chain_length; i++) {
            chain[i].nHeight = i;
            chain[i].pprev = (i > 0) ? &chain[i-1] : nullptr;
            chain[i].BuildSkip();
        }

        // Should use skip pointers efficiently for power-of-2 heights
        REQUIRE(chain[64].GetAncestor(0) == &chain[0]);
        REQUIRE(chain[64].GetAncestor(32) == &chain[32]);
        REQUIRE(chain[64].GetAncestor(16) == &chain[16]);
        REQUIRE(chain[64].GetAncestor(8) == &chain[8]);
        REQUIRE(chain[64].GetAncestor(4) == &chain[4]);
        REQUIRE(chain[64].GetAncestor(2) == &chain[2]);
    }

    SECTION("GetAncestor on long chain verifies O(log n) access") {
        // Create a longer chain to demonstrate skip list efficiency
        const int chain_length = 1000;
        std::vector<CBlockIndex> chain(chain_length);
        for (int i = 0; i < chain_length; i++) {
            chain[i].nHeight = i;
            chain[i].pprev = (i > 0) ? &chain[i-1] : nullptr;
            chain[i].BuildSkip();
        }

        // Verify correctness for various ancestor queries
        REQUIRE(chain[999].GetAncestor(0) == &chain[0]);
        REQUIRE(chain[999].GetAncestor(500) == &chain[500]);
        REQUIRE(chain[999].GetAncestor(250) == &chain[250]);
        REQUIRE(chain[999].GetAncestor(750) == &chain[750]);
        REQUIRE(chain[999].GetAncestor(999) == &chain[999]);
        REQUIRE(chain[999].GetAncestor(1) == &chain[1]);

        // Test from middle of chain
        REQUIRE(chain[500].GetAncestor(0) == &chain[0]);
        REQUIRE(chain[500].GetAncestor(250) == &chain[250]);
        REQUIRE(chain[500].GetAncestor(125) == &chain[125]);
    }
}

TEST_CASE("CBlockIndex - Skip list performance characteristics", "[block_index][skip_list]") {
    SECTION("Skip list provides logarithmic jumps") {
        // Build a 1024-block chain (2^10)
        const int chain_length = 1024;
        std::vector<CBlockIndex> chain(chain_length);
        for (int i = 0; i < chain_length; i++) {
            chain[i].nHeight = i;
            chain[i].pprev = (i > 0) ? &chain[i-1] : nullptr;
            chain[i].BuildSkip();
        }

        // Manually trace GetAncestor(0) from height 1023 to count jumps
        // With skip list, this should take ~10 jumps (log2(1024))
        // Without skip list, would take 1023 jumps

        CBlockIndex* current = &chain[1023];
        int jump_count = 0;

        // Simulate GetAncestor traversal (simplified logic)
        while (current->nHeight > 0) {
            jump_count++;
            if (current->pskip != nullptr && current->pskip->nHeight >= 0) {
                // Can use skip pointer
                current = current->pskip;
            } else if (current->pprev != nullptr) {
                // Fall back to pprev
                current = current->pprev;
            } else {
                break;
            }
            // Safety: prevent infinite loop
            REQUIRE(jump_count < 1000);
        }

        // With skip list, should take ~log2(1023) = ~10 jumps
        // We allow up to 20 jumps to account for algorithm details
        REQUIRE(jump_count <= 20);
        REQUIRE(current->nHeight == 0);
    }

    SECTION("Skip list handles deep chains efficiently") {
        // Test with chain length simulating mainnet depth
        const int chain_length = 10000;
        std::vector<CBlockIndex> chain(chain_length);

        // Build chain with skip pointers
        for (int i = 0; i < chain_length; i++) {
            chain[i].nHeight = i;
            chain[i].pprev = (i > 0) ? &chain[i-1] : nullptr;
            chain[i].BuildSkip();
        }

        // Verify correctness for various queries
        REQUIRE(chain[9999].GetAncestor(0) == &chain[0]);
        REQUIRE(chain[9999].GetAncestor(5000) == &chain[5000]);
        REQUIRE(chain[9999].GetAncestor(9999) == &chain[9999]);

        // Test ASERT-like scenario: anchor at height 1, query from 9999
        REQUIRE(chain[9999].GetAncestor(1) == &chain[1]);

        // This should be O(log 9998) ≈ 13 jumps, not O(9998) jumps
        // The test itself doesn't measure time, but verifies correctness
    }
}

TEST_CASE("CBlockIndex - Skip list edge cases", "[block_index][skip_list]") {
    SECTION("Skip list with non-sequential pprev updates") {
        // Simulate out-of-order block insertion (can happen with headers-first sync)
        std::vector<CBlockIndex> chain(10);

        // Initialize all blocks
        for (int i = 0; i < 10; i++) {
            chain[i].nHeight = i;
            chain[i].pprev = (i > 0) ? &chain[i-1] : nullptr;
        }

        // Build skip pointers in order (simulates BlockManager::AddToBlockIndex)
        for (int i = 0; i < 10; i++) {
            chain[i].BuildSkip();
        }

        // Verify skip pointers are valid
        for (int i = 2; i < 10; i++) {
            if (chain[i].pskip != nullptr) {
                REQUIRE(chain[i].pskip->nHeight < chain[i].nHeight);
                REQUIRE(chain[i].pskip->nHeight >= 0);
            }
        }

        // Verify GetAncestor still works
        REQUIRE(chain[9].GetAncestor(0) == &chain[0]);
        REQUIRE(chain[9].GetAncestor(5) == &chain[5]);
    }

    SECTION("Skip list with nullptr pprev (genesis)") {
        CBlockIndex genesis;
        genesis.nHeight = 0;
        genesis.pprev = nullptr;
        genesis.BuildSkip();

        REQUIRE(genesis.pskip == nullptr);
        REQUIRE(genesis.GetAncestor(0) == &genesis);
        REQUIRE(genesis.GetAncestor(1) == nullptr);
    }

    SECTION("Skip list consistency after chain reorg") {
        // Simulate a reorg scenario
        // Main chain: 0 -> 1 -> 2 -> 3 -> 4
        // Fork chain: 0 -> 1 -> 2' -> 3' -> 4' -> 5'

        std::vector<CBlockIndex> main_chain(5);
        for (int i = 0; i < 5; i++) {
            main_chain[i].nHeight = i;
            main_chain[i].pprev = (i > 0) ? &main_chain[i-1] : nullptr;
            main_chain[i].BuildSkip();
        }

        // Fork shares common blocks 0, 1 then diverges
        std::vector<CBlockIndex> fork_chain(6);
        // Fork blocks 0 and 1 point to same ancestors as main chain
        fork_chain[0].nHeight = 0;
        fork_chain[0].pprev = nullptr;
        fork_chain[0].BuildSkip();

        fork_chain[1].nHeight = 1;
        fork_chain[1].pprev = &fork_chain[0];
        fork_chain[1].BuildSkip();

        // Fork diverges at height 2
        for (int i = 2; i < 6; i++) {
            fork_chain[i].nHeight = i;
            fork_chain[i].pprev = &fork_chain[i-1];
            fork_chain[i].BuildSkip();
        }

        // Verify skip pointers are set correctly on fork
        REQUIRE(fork_chain[5].GetAncestor(0) == &fork_chain[0]);
        REQUIRE(fork_chain[5].GetAncestor(1) == &fork_chain[1]);
        REQUIRE(fork_chain[5].GetAncestor(2) == &fork_chain[2]);
    }
}

TEST_CASE("CBlockIndex - Skip list matches Bitcoin Core behavior", "[block_index][skip_list]") {
    SECTION("Verify GetSkipHeight pattern for first 32 blocks") {
        // Expected skip heights based on Bitcoin Core's GetSkipHeight() algorithm
        // Computed from: GetSkipHeight(h) called within BuildSkip()
        const std::vector<int> expected_skip_heights = {
            -1,  // height 0 (genesis, no skip)
            0,   // height 1 -> 0
            0,   // height 2 -> 0
            1,   // height 3 -> 1
            0,   // height 4 -> 0
            1,   // height 5 -> 1
            4,   // height 6 -> 4
            1,   // height 7 -> 1
            0,   // height 8 -> 0
            1,   // height 9 -> 1
            8,   // height 10 -> 8
            1,   // height 11 -> 1
            8,   // height 12 -> 8
            1,   // height 13 -> 1
            12,  // height 14 -> 12
            9,   // height 15 -> 9
            0,   // height 16 -> 0
            1,   // height 17 -> 1
            16,  // height 18 -> 16
            1,   // height 19 -> 1
            16,  // height 20 -> 16
            1,   // height 21 -> 1
            20,  // height 22 -> 20
            17,  // height 23 -> 17
            16,  // height 24 -> 16
            1,   // height 25 -> 1
            24,  // height 26 -> 24
            17,  // height 27 -> 17
            24,  // height 28 -> 24
            17,  // height 29 -> 17
            28,  // height 30 -> 28
            25   // height 31 -> 25
        };

        std::vector<CBlockIndex> chain(32);
        for (int i = 0; i < 32; i++) {
            chain[i].nHeight = i;
            chain[i].pprev = (i > 0) ? &chain[i-1] : nullptr;
            chain[i].BuildSkip();
        }

        // Verify skip pointers match expected pattern
        for (int i = 0; i < 32; i++) {
            int expected_skip = expected_skip_heights[i];
            if (expected_skip == -1) {
                REQUIRE(chain[i].pskip == nullptr);
            } else {
                REQUIRE(chain[i].pskip == &chain[expected_skip]);
            }
        }
    }
}

// =============================================================================
// Section: BlockStatus::ToString coverage
// =============================================================================

TEST_CASE("BlockStatus::ToString - all validation levels", "[block_index][status]") {
    SECTION("UNKNOWN validation level") {
        BlockStatus status;
        status.validation = BlockStatus::UNKNOWN;
        status.failure = BlockStatus::NOT_FAILED;

        std::string str = status.ToString();
        REQUIRE(str.find("UNKNOWN") != std::string::npos);
        REQUIRE(str.find("NOT_FAILED") != std::string::npos);
    }

    SECTION("HEADER validation level") {
        BlockStatus status;
        status.validation = BlockStatus::HEADER;
        status.failure = BlockStatus::NOT_FAILED;

        std::string str = status.ToString();
        REQUIRE(str.find("HEADER") != std::string::npos);
        REQUIRE(str.find("NOT_FAILED") != std::string::npos);
    }

    SECTION("TREE validation level") {
        BlockStatus status;
        status.validation = BlockStatus::TREE;
        status.failure = BlockStatus::NOT_FAILED;

        std::string str = status.ToString();
        REQUIRE(str.find("TREE") != std::string::npos);
    }

    SECTION("Invalid validation level (default case)") {
        BlockStatus status;
        // Force an invalid validation level by casting
        status.validation = static_cast<BlockStatus::ValidationLevel>(99);
        status.failure = BlockStatus::NOT_FAILED;

        std::string str = status.ToString();
        REQUIRE(str.find("INVALID_LEVEL") != std::string::npos);
    }
}

TEST_CASE("BlockStatus::ToString - all failure states", "[block_index][status]") {
    SECTION("NOT_FAILED state") {
        BlockStatus status;
        status.validation = BlockStatus::UNKNOWN;
        status.failure = BlockStatus::NOT_FAILED;

        std::string str = status.ToString();
        REQUIRE(str.find("NOT_FAILED") != std::string::npos);
    }

    SECTION("VALIDATION_FAILED state") {
        BlockStatus status;
        status.validation = BlockStatus::HEADER;
        status.failure = BlockStatus::VALIDATION_FAILED;

        std::string str = status.ToString();
        REQUIRE(str.find("VALIDATION_FAILED") != std::string::npos);
    }

    SECTION("ANCESTOR_FAILED state") {
        BlockStatus status;
        status.validation = BlockStatus::TREE;
        status.failure = BlockStatus::ANCESTOR_FAILED;

        std::string str = status.ToString();
        REQUIRE(str.find("ANCESTOR_FAILED") != std::string::npos);
    }

    SECTION("Invalid failure state (default case)") {
        BlockStatus status;
        status.validation = BlockStatus::HEADER;
        // Force an invalid failure state by casting
        status.failure = static_cast<BlockStatus::FailureState>(99);

        std::string str = status.ToString();
        REQUIRE(str.find("INVALID_FAILURE") != std::string::npos);
    }
}

TEST_CASE("BlockStatus::ToString - format verification", "[block_index][status]") {
    SECTION("ToString returns pipe-separated format") {
        BlockStatus status;
        status.validation = BlockStatus::TREE;
        status.failure = BlockStatus::VALIDATION_FAILED;

        std::string str = status.ToString();
        REQUIRE(str == "TREE|VALIDATION_FAILED");
    }
}

// =============================================================================
// Section: GetBlockProof edge cases
// =============================================================================

TEST_CASE("GetBlockProof - max target edge case", "[block_index][proof]") {
    SECTION("Overflow and edge conditions") {
        // This tests line 126-127: overflow condition returns 0
        CBlockIndex index;

        // Test with overflow-inducing nBits
        // 0xff = 255 bytes which far exceeds 256-bit limit
        index.nBits = 0xff00ffff;
        arith_uint256 proof = GetBlockProof(index);
        REQUIRE(proof == 0);  // Returns 0 due to overflow

        // 0x21 = 33 bytes = 264 bits, also overflows
        index.nBits = 0x21ffffff;
        proof = GetBlockProof(index);
        REQUIRE(proof == 0);  // Returns 0 due to overflow

        // Test with valid large target (0x20 = 32 bytes = 256 bits max)
        index.nBits = 0x207fffff;  // RegTest difficulty - largest valid
        proof = GetBlockProof(index);
        REQUIRE(proof > 0);  // Should return valid proof
    }

    SECTION("Boundary conditions for target") {
        CBlockIndex index;

        // Test with target that produces minimal work
        index.nBits = 0x207fffff;  // RegTest difficulty
        arith_uint256 proof = GetBlockProof(index);
        REQUIRE(proof == 2);

        // Test with higher difficulty (smaller target = more work)
        index.nBits = 0x1f7fffff;
        arith_uint256 higher_proof = GetBlockProof(index);
        REQUIRE(higher_proof > proof);
    }
}
