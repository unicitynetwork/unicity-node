// Copyright (c) 2025 The Unicity Foundation
// Unit tests for chain/chainstate_manager.cpp - Main chain state coordinator
//
// Tests are organized into sections:
// 1. Basic Operations - Construction, initialization, header acceptance
// 2. Orphan Management - Orphan caching, processing, eviction
// 3. Chain Activation - Extending chain, reorgs, best chain selection
// 4. Persistence - Save/Load, round-trip, hardening
// 5. Query API - LookupBlockIndex, GetLocator, IsOnActiveChain, etc.
// 6. IBD Detection - IsInitialBlockDownload latch behavior
// 7. InvalidateBlock - Manual block invalidation
// 8. Contextual Validation - Difficulty, timestamps, network expiration
// 9. Security - PoW skip guard, divergent chain detection
// 10. Edge Cases - Thread safety, error conditions
// 11. ActiveTipCandidates - Candidate hash set operations
// 12. GetChainTips - Chain tip enumeration and status

#include "catch_amalgamated.hpp"
#include "chain/chainstate_manager.hpp"
#include "chain/active_tip_candidates.hpp"
#include "chain/block_manager.hpp"
#include "chain/chainparams.hpp"
#include "chain/block.hpp"
#include "chain/block_index.hpp"
#include "chain/chain.hpp"
#include "chain/pow.hpp"
#include "chain/randomx_pow.hpp"
#include "chain/validation.hpp"
#include "chain/notifications.hpp"
#include "util/time.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>
#include <atomic>

using namespace unicity;
using namespace unicity::validation;
using namespace unicity::chain;

// =============================================================================
// Test Helpers
// =============================================================================

// Test subclass that bypasses expensive PoW validation with controllable results
class TestChainstateManager : public ChainstateManager {
public:
    explicit TestChainstateManager(const ChainParams& params)
        : ChainstateManager(params), bypass_pow_validation_(true) {
        if (params.GetChainType() == ChainType::REGTEST) {
            TestSetSkipPoWChecks(true);
        }
    }

    // Control validation bypass
    void SetBypassPoW(bool bypass) {
        bypass_pow_validation_ = bypass;
        if (GetParams().GetChainType() == ChainType::REGTEST) {
            TestSetSkipPoWChecks(bypass);
        }
    }
    void SetBypassContextualValidation(bool bypass) { bypass_contextual_ = bypass; }

    // Control test outcomes (only when bypass is enabled)
    void SetPoWCheckResult(bool result) { pow_check_result_ = result; }
    void SetBlockHeaderCheckResult(bool result) { block_header_check_result_ = result; }
    void SetContextualCheckResult(bool result) { contextual_check_result_ = result; }

protected:
    bool CheckProofOfWork(const CBlockHeader& header, crypto::POWVerifyMode mode) const override {
        if (bypass_pow_validation_) {
            return pow_check_result_;
        }
        return ChainstateManager::CheckProofOfWork(header, mode);
    }

    bool CheckBlockHeaderWrapper(const CBlockHeader& header, ValidationState& state) const override {
        if (bypass_pow_validation_) {
            if (!block_header_check_result_) {
                state.Invalid("test-failure", "block header check failed (test)");
                return false;
            }
            return true;
        }
        return ChainstateManager::CheckBlockHeaderWrapper(header, state);
    }

    bool ContextualCheckBlockHeaderWrapper(const CBlockHeader& header,
                                           const CBlockIndex* pindexPrev,
                                           int64_t adjusted_time,
                                           ValidationState& state) const override {
        if (bypass_contextual_) {
            if (!contextual_check_result_) {
                state.Invalid("test-failure", "contextual check failed (test)");
                return false;
            }
            return true;
        }
        return ChainstateManager::ContextualCheckBlockHeaderWrapper(header, pindexPrev, adjusted_time, state);
    }

private:
    bool bypass_pow_validation_{true};
    bool bypass_contextual_{true};
    bool pow_check_result_{true};
    bool block_header_check_result_{true};
    bool contextual_check_result_{true};
};

// Helper: Create a block header
static CBlockHeader CreateTestHeader(uint32_t nTime = 1234567890, uint32_t nBits = 0x1d00ffff) {
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

// Helper: Create a child header
static CBlockHeader CreateChildHeader(const uint256& prevHash, uint32_t nTime = 1234567890) {
    CBlockHeader header = CreateTestHeader(nTime);
    header.hashPrevBlock = prevHash;
    return header;
}

// Helper: Make a child header from CBlockIndex
static CBlockHeader MakeChild(const CBlockIndex* prev, uint32_t nTime, uint32_t nBits = 0x207fffff) {
    CBlockHeader h;
    h.nVersion = 1;
    h.hashPrevBlock = prev ? prev->GetBlockHash() : uint256();
    h.minerAddress.SetNull();
    h.nTime = nTime;
    h.nBits = nBits;
    h.nNonce = 0;
    h.hashRandomX.SetNull();
    return h;
}

// Helper: Mine a valid child header (expensive - uses RandomX)
static CBlockHeader MineChild(const CBlockIndex* prev, const ChainParams& params, uint32_t nTime) {
    CBlockHeader h;
    h.nVersion = 1;
    h.hashPrevBlock = prev ? prev->GetBlockHash() : uint256();
    h.minerAddress.SetNull();
    h.nTime = nTime;
    h.nBits = consensus::GetNextWorkRequired(prev, params);
    h.nNonce = 0;
    h.hashRandomX.SetNull();

    uint256 out_hash;
    int iter = 0;
    while (!consensus::CheckProofOfWork(h, h.nBits, params, crypto::POWVerifyMode::MINING, &out_hash)) {
        h.nNonce++;
        iter++;
        REQUIRE(iter < 500000);
    }
    h.hashRandomX = out_hash;
    return h;
}

// Test fixture for temp files
class ChainstateManagerTestFixture {
public:
    std::string test_file;

    ChainstateManagerTestFixture() {
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        test_file = "/tmp/chainstate_test_" + std::to_string(now) + ".json";
    }

    ~ChainstateManagerTestFixture() {
        std::filesystem::remove(test_file);
    }
};

// =============================================================================
// Section 1: Basic Operations
// =============================================================================

TEST_CASE("ChainstateManager - Construction", "[chain][chainstate_manager][unit]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);

    SECTION("Default construction") {
        REQUIRE(csm.GetTip() == nullptr);
        REQUIRE(csm.GetBlockCount() == 0);
        REQUIRE(csm.GetChainHeight() == -1);
    }
}

TEST_CASE("ChainstateManager - Initialize", "[chain][chainstate_manager][unit]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);

    SECTION("Initialize with genesis") {
        CBlockHeader genesis = CreateTestHeader();
        REQUIRE(csm.Initialize(genesis));

        REQUIRE(csm.GetTip() != nullptr);
        REQUIRE(csm.GetTip()->GetBlockHash() == genesis.GetHash());
        REQUIRE(csm.GetBlockCount() == 1);
        REQUIRE(csm.GetChainHeight() == 0);
    }

    SECTION("Cannot initialize twice") {
        CBlockHeader genesis = CreateTestHeader();
        REQUIRE(csm.Initialize(genesis));

        CBlockHeader another = CreateTestHeader(9999999);
        REQUIRE_FALSE(csm.Initialize(another));
    }
}

TEST_CASE("ChainstateManager - AcceptBlockHeader Basic", "[chain][chainstate_manager][unit]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);

    CBlockHeader genesis = CreateTestHeader();
    csm.Initialize(genesis);

    SECTION("Accept valid block") {
        CBlockHeader block1 = CreateChildHeader(genesis.GetHash(), 1234567900);
        ValidationState state;

        CBlockIndex* pindex = csm.AcceptBlockHeader(block1, state);
        REQUIRE(pindex != nullptr);
        REQUIRE(pindex->GetBlockHash() == block1.GetHash());
        REQUIRE(pindex->nHeight == 1);
        REQUIRE(state.IsValid());
    }

    SECTION("Reject duplicate block") {
        CBlockHeader block1 = CreateChildHeader(genesis.GetHash(), 1234567900);
        ValidationState state1;

        CBlockIndex* pindex1 = csm.AcceptBlockHeader(block1, state1);
        REQUIRE(pindex1 != nullptr);

        ValidationState state2;
        CBlockIndex* pindex2 = csm.AcceptBlockHeader(block1, state2);
        REQUIRE(pindex2 == pindex1);  // Returns existing index
    }

    SECTION("Reject genesis via AcceptBlockHeader") {
        CBlockHeader fake_genesis = CreateTestHeader(9999999);
        ValidationState state;

        CBlockIndex* pindex = csm.AcceptBlockHeader(fake_genesis, state);
        REQUIRE(pindex == nullptr);
        REQUIRE_FALSE(state.IsValid());
        REQUIRE(state.GetRejectReason() == "bad-genesis");
    }

    SECTION("Reject block with failed PoW commitment") {
        csm.SetPoWCheckResult(false);

        CBlockHeader block1 = CreateChildHeader(genesis.GetHash(), 1234567900);
        ValidationState state;

        CBlockIndex* pindex = csm.AcceptBlockHeader(block1, state);
        REQUIRE(pindex == nullptr);
        REQUIRE_FALSE(state.IsValid());
        REQUIRE(state.GetRejectReason() == "high-hash");
    }

    SECTION("Reject block with failed header check") {
        csm.SetBlockHeaderCheckResult(false);

        CBlockHeader block1 = CreateChildHeader(genesis.GetHash(), 1234567900);
        ValidationState state;

        CBlockIndex* pindex = csm.AcceptBlockHeader(block1, state);
        REQUIRE(pindex == nullptr);
        REQUIRE_FALSE(state.IsValid());
        REQUIRE(state.GetRejectReason() == "test-failure");
    }

    SECTION("Reject block with failed contextual check") {
        csm.SetContextualCheckResult(false);

        CBlockHeader block1 = CreateChildHeader(genesis.GetHash(), 1234567900);
        ValidationState state;

        CBlockIndex* pindex = csm.AcceptBlockHeader(block1, state);
        REQUIRE(pindex == nullptr);
        REQUIRE_FALSE(state.IsValid());
        REQUIRE(state.GetRejectReason() == "test-failure");
    }
}

TEST_CASE("ChainstateManager - ProcessNewBlockHeader", "[chain][chainstate_manager][unit]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);

    CBlockHeader genesis = CreateTestHeader();
    csm.Initialize(genesis);

    SECTION("Process valid block") {
        CBlockHeader block1 = CreateChildHeader(genesis.GetHash(), 1234567900);
        ValidationState state;

        REQUIRE(csm.ProcessNewBlockHeader(block1, state));
        REQUIRE(state.IsValid());
        REQUIRE(csm.GetTip()->GetBlockHash() == block1.GetHash());
        REQUIRE(csm.GetChainHeight() == 1);
    }

    SECTION("Process invalid block") {
        csm.SetPoWCheckResult(false);

        CBlockHeader block1 = CreateChildHeader(genesis.GetHash(), 1234567900);
        ValidationState state;

        REQUIRE_FALSE(csm.ProcessNewBlockHeader(block1, state));
        REQUIRE_FALSE(state.IsValid());
        REQUIRE(csm.GetTip()->GetBlockHash() == genesis.GetHash());
    }
}

// =============================================================================
// Section 2: Orphan Management
// =============================================================================

TEST_CASE("ChainstateManager - Orphan Headers", "[chain][chainstate_manager][unit]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);

    CBlockHeader genesis = CreateTestHeader();
    csm.Initialize(genesis);

    SECTION("Orphan header cached when parent missing") {
        uint256 missing_parent;
        missing_parent.SetNull();
        memset((void*)missing_parent.data(), 0xaa, 32);

        CBlockHeader block2 = CreateChildHeader(missing_parent, 1234567900);
        ValidationState state;

        CBlockIndex* pindex = csm.AcceptBlockHeader(block2, state);
        REQUIRE(pindex == nullptr);
        REQUIRE_FALSE(state.IsValid());
        REQUIRE(state.GetRejectReason() == "prev-blk-not-found");
        REQUIRE(csm.AddOrphanHeader(block2, 1));
        REQUIRE(csm.GetOrphanHeaderCount() == 1);
    }

    SECTION("Orphan processed when parent arrives") {
        CBlockHeader block1 = CreateChildHeader(genesis.GetHash(), 1234567900);
        CBlockHeader block2 = CreateChildHeader(block1.GetHash(), 1234567910);

        ValidationState state1;
        REQUIRE(csm.AddOrphanHeader(block2, 1));
        REQUIRE(csm.GetOrphanHeaderCount() == 1);

        ValidationState state2;
        CBlockIndex* pindex1 = csm.AcceptBlockHeader(block1, state2);
        REQUIRE(pindex1 != nullptr);

        REQUIRE(csm.GetOrphanHeaderCount() == 0);
        REQUIRE(csm.GetBlockCount() == 3);
    }

    SECTION("Per-peer orphan limit") {
        for (int i = 0; i < 51; i++) {
            uint256 missing_parent;
            missing_parent.SetNull();
            memset((void*)missing_parent.data(), 0xaa + i, 32);

            CBlockHeader orphan = CreateChildHeader(missing_parent, 1234567900 + i);
            ValidationState state;
            (void)csm.AddOrphanHeader(orphan, 1);
        }

        REQUIRE(csm.GetOrphanHeaderCount() <= 50);
    }

    SECTION("Multiple orphans from different peers") {
        uint256 missing1, missing2;
        missing1.SetNull();
        memset((void*)missing1.data(), 0xaa, 32);
        missing2.SetNull();
        memset((void*)missing2.data(), 0xbb, 32);

        CBlockHeader orphan1 = CreateChildHeader(missing1, 1000);
        CBlockHeader orphan2 = CreateChildHeader(missing2, 2000);

        ValidationState state1, state2;
        csm.AcceptBlockHeader(orphan1, state1);
        REQUIRE(csm.AddOrphanHeader(orphan1, 1));
        csm.AcceptBlockHeader(orphan2, state2);
        REQUIRE(csm.AddOrphanHeader(orphan2, 2));

        REQUIRE(csm.GetOrphanHeaderCount() == 2);
    }
}

// Custom params with tiny orphan expire time for eviction test
class OrphanExpireParams : public ChainParams {
public:
    OrphanExpireParams() {
        chainType = ChainType::REGTEST;
        consensus.powLimit = uint256S("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetSpacing = 2*60;
        consensus.nRandomXEpochDuration = 365ULL * 24 * 60 * 60 * 100;
        consensus.nASERTHalfLife = 60*60;
        consensus.nASERTAnchorHeight = 1;
        consensus.nMinimumChainWork = uint256S("0x0");
        consensus.nNetworkExpirationInterval = 0;
        consensus.nNetworkExpirationGracePeriod = 0;
        consensus.nOrphanHeaderExpireTime = 1;
        consensus.nSuspiciousReorgDepth = 100;
        consensus.nAntiDosWorkBufferBlocks = 144;
        nDefaultPort = 29590;
        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1);
        consensus.hashGenesisBlock = genesis.GetHash();
    }
};

TEST_CASE("Orphan headers time-based eviction", "[chain][chainstate_manager][orphan][dos]") {
    auto params = std::make_unique<OrphanExpireParams>();
    TestChainstateManager csm(*params);

    REQUIRE(csm.Initialize(params->GenesisBlock()));

    uint256 unknown;
    unknown.SetNull();
    memset((void*)unknown.data(), 0xaa, 32);
    CBlockHeader orphan = MakeChild(nullptr, params->GenesisBlock().nTime + 100);
    orphan.hashPrevBlock = unknown;

    ValidationState st;
    CBlockIndex* r = csm.AcceptBlockHeader(orphan, st);
    REQUIRE(r == nullptr);
    REQUIRE(csm.AddOrphanHeader(orphan, 1));
    REQUIRE(csm.GetOrphanHeaderCount() == 1);

    int64_t base = util::GetTime();
    util::SetMockTime(base + params->GetConsensus().nOrphanHeaderExpireTime + 2);

    size_t evicted = csm.EvictOrphanHeaders();
    util::SetMockTime(0);
    REQUIRE(evicted >= 1);
    REQUIRE(csm.GetOrphanHeaderCount() == 0);
}

// =============================================================================
// Section 3: Chain Activation
// =============================================================================

TEST_CASE("ChainstateManager - Chain Activation", "[chain][chainstate_manager][unit]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);

    CBlockHeader genesis = CreateTestHeader();
    csm.Initialize(genesis);

    SECTION("Extend main chain") {
        CBlockHeader block1 = CreateChildHeader(genesis.GetHash(), 1234567900);
        ValidationState state1;
        csm.ProcessNewBlockHeader(block1, state1);

        CBlockHeader block2 = CreateChildHeader(block1.GetHash(), 1234567910);
        ValidationState state2;
        csm.ProcessNewBlockHeader(block2, state2);

        REQUIRE(csm.GetChainHeight() == 2);
        REQUIRE(csm.GetTip()->GetBlockHash() == block2.GetHash());
    }

    SECTION("No reorg to chain with less work") {
        CBlockHeader blockA1 = CreateChildHeader(genesis.GetHash(), 1000);
        ValidationState stateA1;
        csm.ProcessNewBlockHeader(blockA1, stateA1);

        CBlockHeader blockA2 = CreateChildHeader(blockA1.GetHash(), 2000);
        ValidationState stateA2;
        csm.ProcessNewBlockHeader(blockA2, stateA2);

        REQUIRE(csm.GetChainHeight() == 2);

        CBlockHeader blockB1 = CreateChildHeader(genesis.GetHash(), 3000);
        ValidationState stateB1;
        csm.ProcessNewBlockHeader(blockB1, stateB1);

        REQUIRE(csm.GetTip()->GetBlockHash() == blockA2.GetHash());
    }
}

TEST_CASE("ChainstateManager - Reorg", "[chain][chainstate_manager][unit]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);

    CBlockHeader genesis = CreateTestHeader();
    csm.Initialize(genesis);

    SECTION("Simple reorg to longer chain") {
        CBlockHeader blockA1 = CreateChildHeader(genesis.GetHash(), 1000);
        ValidationState stateA1;
        csm.ProcessNewBlockHeader(blockA1, stateA1);

        CBlockHeader blockB1 = CreateChildHeader(genesis.GetHash(), 2000);
        ValidationState stateB1;
        csm.ProcessNewBlockHeader(blockB1, stateB1);

        CBlockHeader blockB2 = CreateChildHeader(blockB1.GetHash(), 3000);
        ValidationState stateB2;
        csm.ProcessNewBlockHeader(blockB2, stateB2);

        REQUIRE(csm.GetTip()->GetBlockHash() == blockB2.GetHash());
        REQUIRE(csm.GetChainHeight() == 2);
    }

    SECTION("Deep reorg rejected") {
        auto params_limited = ChainParams::CreateRegTest();
        params_limited->SetSuspiciousReorgDepth(2);
        TestChainstateManager csm_limited(*params_limited);
        csm_limited.Initialize(genesis);

        CBlockHeader blockA1 = CreateChildHeader(genesis.GetHash(), 1000);
        ValidationState stateA1;
        csm_limited.ProcessNewBlockHeader(blockA1, stateA1);

        CBlockHeader blockA2 = CreateChildHeader(blockA1.GetHash(), 2000);
        ValidationState stateA2;
        csm_limited.ProcessNewBlockHeader(blockA2, stateA2);

        CBlockHeader blockB1 = CreateChildHeader(genesis.GetHash(), 3000);
        ValidationState stateB1;
        csm_limited.ProcessNewBlockHeader(blockB1, stateB1);

        CBlockHeader blockB2 = CreateChildHeader(blockB1.GetHash(), 4000);
        ValidationState stateB2;
        csm_limited.ProcessNewBlockHeader(blockB2, stateB2);

        CBlockHeader blockB3 = CreateChildHeader(blockB2.GetHash(), 5000);
        ValidationState stateB3;
        csm_limited.ProcessNewBlockHeader(blockB3, stateB3);

        REQUIRE(csm_limited.GetTip()->GetBlockHash() == blockA2.GetHash());
    }
}

// =============================================================================
// Section 4: Persistence
// =============================================================================

TEST_CASE("ChainstateManager - Persistence", "[chain][chainstate_manager][unit]") {
    ChainstateManagerTestFixture fixture;
    auto params = ChainParams::CreateRegTest();

    SECTION("Save") {
        CBlockHeader genesis = CreateTestHeader();

        TestChainstateManager csm1(*params);
        csm1.Initialize(genesis);

        CBlockHeader block1 = CreateChildHeader(genesis.GetHash(), 1000);
        ValidationState state1;
        csm1.ProcessNewBlockHeader(block1, state1);

        CBlockHeader block2 = CreateChildHeader(block1.GetHash(), 2000);
        ValidationState state2;
        csm1.ProcessNewBlockHeader(block2, state2);

        REQUIRE(csm1.GetChainHeight() == 2);
        REQUIRE(csm1.Save(fixture.test_file));
        REQUIRE(std::filesystem::exists(fixture.test_file));
    }
}

TEST_CASE("Chainstate Load round-trip reconstructs candidates", "[chain][chainstate_manager][persistence]") {
    auto params = ChainParams::CreateRegTest();

    TestChainstateManager csm1(*params);
    csm1.Initialize(params->GenesisBlock());

    const CBlockIndex* g = csm1.GetTip();
    CBlockHeader A1 = MakeChild(g, g->nTime + 120);
    ValidationState s;
    auto* pA1 = csm1.AcceptBlockHeader(A1, s);
    REQUIRE(pA1);
    csm1.TryAddBlockIndexCandidate(pA1);
    REQUIRE(csm1.ActivateBestChain());

    CBlockHeader A2 = MakeChild(pA1, pA1->nTime + 120);
    auto* pA2 = csm1.AcceptBlockHeader(A2, s);
    REQUIRE(pA2);
    csm1.TryAddBlockIndexCandidate(pA2);
    REQUIRE(csm1.ActivateBestChain());

    CBlockHeader B1 = MakeChild(g, g->nTime + 130);
    auto* pB1 = csm1.AcceptBlockHeader(B1, s);
    REQUIRE(pB1);
    csm1.TryAddBlockIndexCandidate(pB1);

    CBlockHeader B2 = MakeChild(pB1, pB1->nTime + 120);
    auto* pB2 = csm1.AcceptBlockHeader(B2, s);
    REQUIRE(pB2);
    csm1.TryAddBlockIndexCandidate(pB2);

    CBlockHeader B3 = MakeChild(pB2, pB2->nTime + 120);
    auto* pB3 = csm1.AcceptBlockHeader(B3, s);
    REQUIRE(pB3);
    csm1.TryAddBlockIndexCandidate(pB3);

    REQUIRE(csm1.ActivateBestChain());
    REQUIRE(csm1.GetTip()->GetBlockHash() == pB3->GetBlockHash());

    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    std::string path = "/tmp/chainstate_load_rt_" + std::to_string(now) + ".json";
    REQUIRE(csm1.Save(path));

    TestChainstateManager csm2(*params);
    REQUIRE(csm2.Load(path) == chain::LoadResult::SUCCESS);
    REQUIRE(csm2.ActivateBestChain());

    REQUIRE(csm2.GetTip() != nullptr);
    REQUIRE(csm2.GetTip()->nHeight == 3);
    REQUIRE(csm2.GetTip()->GetBlockHash() == pB3->GetBlockHash());

    std::filesystem::remove(path);
}

TEST_CASE("Chainstate Load hardening: recompute ignores tampered chainwork", "[chain][chainstate_manager][persistence][hardening]") {
    crypto::InitRandomX();

    auto params = ChainParams::CreateRegTest();

    ChainstateManager csm(*params);
    REQUIRE(csm.Initialize(params->GenesisBlock()));

    const CBlockIndex* tip = csm.GetTip();
    REQUIRE(tip != nullptr);

    for (int i = 1; i <= 4; ++i) {
        CBlockHeader h = MineChild(tip, *params, static_cast<uint32_t>(tip->nTime + 120));
        ValidationState st;
        REQUIRE(csm.ProcessNewBlockHeader(h, st));
        REQUIRE(st.IsValid());
        tip = csm.GetTip();
        REQUIRE(tip != nullptr);
        REQUIRE(tip->nHeight == i);
    }

    const uint256 orig_tip_hash = csm.GetTip()->GetBlockHash();
    const arith_uint256 orig_tip_work = csm.GetTip()->nChainWork;

    const std::filesystem::path tmp_path = std::filesystem::temp_directory_path() / "chainstate_load_hardening.json";
    REQUIRE(csm.Save(tmp_path.string()));

    {
        std::ifstream in(tmp_path);
        REQUIRE(in.is_open());
        nlohmann::json root;
        in >> root;
        in.close();

        REQUIRE(root.contains("blocks"));
        REQUIRE(root["blocks"].is_array());
        for (auto& blk : root["blocks"]) {
            blk["chainwork"] = "0x0";
        }

        std::ofstream out(tmp_path);
        REQUIRE(out.is_open());
        out << root.dump(2);
        out.close();
    }

    ChainstateManager csm2(*params);
    REQUIRE(csm2.Load(tmp_path.string(), true) == chain::LoadResult::SUCCESS);
    REQUIRE(csm2.ActivateBestChain(nullptr));

    const CBlockIndex* tip2 = csm2.GetTip();
    REQUIRE(tip2 != nullptr);
    REQUIRE(tip2->GetBlockHash() == orig_tip_hash);
    REQUIRE(tip2->nChainWork == orig_tip_work);

    std::filesystem::remove(tmp_path);
}

TEST_CASE("Chainstate Load: trust mode marks all blocks valid", "[chain][chainstate_manager][persistence]") {
    crypto::InitRandomX();

    auto params = ChainParams::CreateRegTest();

    ChainstateManager csm(*params);
    REQUIRE(csm.Initialize(params->GenesisBlock()));

    const CBlockIndex* tip = csm.GetTip();
    for (int i = 1; i <= 3; ++i) {
        CBlockHeader h = MineChild(tip, *params, static_cast<uint32_t>(tip->nTime + 120));
        ValidationState st;
        REQUIRE(csm.ProcessNewBlockHeader(h, st));
        tip = csm.GetTip();
    }

    const uint256 tip_hash = tip->GetBlockHash();
    const std::filesystem::path tmp_path = std::filesystem::temp_directory_path() / "trust_mode_test.json";
    REQUIRE(csm.Save(tmp_path.string()));

    ChainstateManager csm2(*params);
    REQUIRE(csm2.Load(tmp_path.string(), false) == chain::LoadResult::SUCCESS);
    csm2.ActivateBestChain(nullptr);

    REQUIRE(csm2.GetTip()->GetBlockHash() == tip_hash);
    REQUIRE(csm2.GetTip()->nHeight == 3);
    REQUIRE(csm2.GetTip()->IsValid(chain::BlockStatus::TREE));

    for (int h = 0; h <= 3; ++h) {
        const CBlockIndex* block = csm2.GetBlockAtHeight(h);
        REQUIRE(block != nullptr);
        REQUIRE(block->IsValid(chain::BlockStatus::TREE));
        REQUIRE_FALSE(block->status.IsFailed());
    }

    std::filesystem::remove(tmp_path);
}

TEST_CASE("Chainstate Load: round-trip preserves fork structure", "[chain][chainstate_manager][persistence]") {
    crypto::InitRandomX();

    auto params = ChainParams::CreateRegTest();

    ChainstateManager csm(*params);
    REQUIRE(csm.Initialize(params->GenesisBlock()));

    const CBlockIndex* genesis = csm.GetTip();

    CBlockHeader A1 = MineChild(genesis, *params, static_cast<uint32_t>(genesis->nTime + 120));
    ValidationState st;
    REQUIRE(csm.ProcessNewBlockHeader(A1, st));
    const CBlockIndex* pA1 = csm.GetTip();

    CBlockHeader A2 = MineChild(pA1, *params, static_cast<uint32_t>(pA1->nTime + 120));
    REQUIRE(csm.ProcessNewBlockHeader(A2, st));

    CBlockHeader B1 = MineChild(genesis, *params, static_cast<uint32_t>(genesis->nTime + 130));
    REQUIRE(csm.ProcessNewBlockHeader(B1, st));

    REQUIRE(csm.GetBlockCount() == 4);
    REQUIRE(csm.GetChainHeight() == 2);

    const std::filesystem::path tmp_path = std::filesystem::temp_directory_path() / "fork_roundtrip_test.json";
    REQUIRE(csm.Save(tmp_path.string()));

    ChainstateManager csm2(*params);
    REQUIRE(csm2.Load(tmp_path.string(), true) == chain::LoadResult::SUCCESS);
    csm2.ActivateBestChain(nullptr);

    REQUIRE(csm2.GetBlockCount() == 4);
    REQUIRE(csm2.GetChainHeight() == 2);
    REQUIRE(csm2.GetTip()->GetBlockHash() == A2.GetHash());

    const CBlockIndex* pB1 = csm2.LookupBlockIndex(B1.GetHash());
    REQUIRE(pB1 != nullptr);
    REQUIRE_FALSE(csm2.IsOnActiveChain(pB1));
    REQUIRE(pB1->IsValid(chain::BlockStatus::TREE));

    std::filesystem::remove(tmp_path);
}

TEST_CASE("Chainstate Load: revalidate fails on corrupted block", "[chain][chainstate_manager][persistence][hardening]") {
    crypto::InitRandomX();

    auto params = ChainParams::CreateRegTest();

    ChainstateManager csm(*params);
    REQUIRE(csm.Initialize(params->GenesisBlock()));

    const CBlockIndex* tip = csm.GetTip();

    CBlockHeader hdrA = MineChild(tip, *params, static_cast<uint32_t>(tip->nTime + 120));
    ValidationState st;
    REQUIRE(csm.ProcessNewBlockHeader(hdrA, st));
    tip = csm.GetTip();
    REQUIRE(tip->nHeight == 1);

    CBlockHeader hdrB = MineChild(tip, *params, static_cast<uint32_t>(tip->nTime + 120));
    REQUIRE(csm.ProcessNewBlockHeader(hdrB, st));
    tip = csm.GetTip();
    REQUIRE(tip->nHeight == 2);

    const std::filesystem::path tmp_path = std::filesystem::temp_directory_path() / "ancestor_failure_test.json";
    REQUIRE(csm.Save(tmp_path.string()));

    uint256 new_A_hash;
    uint256 new_B_hash;
    {
        std::ifstream in(tmp_path);
        nlohmann::json root;
        in >> root;
        in.close();

        for (auto& blk : root["blocks"]) {
            if (blk["height"] == 1) {
                CBlockHeader h;
                h.nVersion = blk["version"].get<int32_t>();
                h.hashPrevBlock.SetHex(blk["prev_hash"].get<std::string>());
                h.minerAddress.SetHex(blk["miner_address"].get<std::string>());
                h.nTime = blk["time"].get<uint32_t>();
                h.nBits = blk["bits"].get<uint32_t>();
                h.nNonce = blk["nonce"].get<uint32_t>();
                h.hashRandomX.SetNull();

                new_A_hash = h.GetHash();
                blk["hash_randomx"] = h.hashRandomX.ToString();
                blk["hash"] = new_A_hash.ToString();
                break;
            }
        }

        for (auto& blk : root["blocks"]) {
            if (blk["height"] == 2) {
                CBlockHeader h;
                h.nVersion = blk["version"].get<int32_t>();
                h.hashPrevBlock = new_A_hash;
                h.minerAddress.SetHex(blk["miner_address"].get<std::string>());
                h.nTime = blk["time"].get<uint32_t>();
                h.nBits = blk["bits"].get<uint32_t>();
                h.nNonce = blk["nonce"].get<uint32_t>();
                h.hashRandomX.SetHex(blk["hash_randomx"].get<std::string>());

                new_B_hash = h.GetHash();
                blk["prev_hash"] = new_A_hash.ToString();
                blk["hash"] = new_B_hash.ToString();
                break;
            }
        }

        root["tip_hash"] = new_B_hash.ToString();

        std::ofstream out(tmp_path);
        out << root.dump(2);
    }

    ChainstateManager csm2(*params);
    REQUIRE(csm2.Load(tmp_path.string(), true) == chain::LoadResult::CORRUPTED);

    std::filesystem::remove(tmp_path);
}

// =============================================================================
// Section 5: Query API
// =============================================================================

TEST_CASE("ChainstateManager - LookupBlockIndex", "[chain][chainstate_manager][unit]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);

    CBlockHeader genesis = CreateTestHeader();
    csm.Initialize(genesis);

    SECTION("Lookup existing block") {
        CBlockHeader block1 = CreateChildHeader(genesis.GetHash(), 1000);
        ValidationState state;
        csm.ProcessNewBlockHeader(block1, state);

        const CBlockIndex* pindex = csm.LookupBlockIndex(block1.GetHash());
        REQUIRE(pindex != nullptr);
        REQUIRE(pindex->GetBlockHash() == block1.GetHash());
    }

    SECTION("Lookup non-existing block") {
        uint256 fake_hash;
        fake_hash.SetNull();
        memset((void*)fake_hash.data(), 0xff, 32);

        const CBlockIndex* pindex = csm.LookupBlockIndex(fake_hash);
        REQUIRE(pindex == nullptr);
    }
}

TEST_CASE("ChainstateManager - GetLocator", "[chain][chainstate_manager][unit]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);

    CBlockHeader genesis = CreateTestHeader();
    csm.Initialize(genesis);

    SECTION("Locator for tip") {
        CBlockHeader block1 = CreateChildHeader(genesis.GetHash(), 1000);
        ValidationState state1;
        csm.ProcessNewBlockHeader(block1, state1);

        CBlockLocator locator = csm.GetLocator();
        REQUIRE(!locator.vHave.empty());
        REQUIRE(locator.vHave[0] == block1.GetHash());
    }

    SECTION("Locator for specific block") {
        CBlockHeader block1 = CreateChildHeader(genesis.GetHash(), 1000);
        ValidationState state1;
        csm.ProcessNewBlockHeader(block1, state1);

        CBlockHeader block2 = CreateChildHeader(block1.GetHash(), 2000);
        ValidationState state2;
        csm.ProcessNewBlockHeader(block2, state2);

        const CBlockIndex* pindex1 = csm.LookupBlockIndex(block1.GetHash());
        CBlockLocator locator = csm.GetLocator(pindex1);

        REQUIRE(!locator.vHave.empty());
        REQUIRE(locator.vHave[0] == block1.GetHash());
    }
}

TEST_CASE("GetLocator structure: step-back pattern and genesis inclusion", "[chain][chainstate_manager][locator]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);
    csm.Initialize(params->GenesisBlock());

    const CBlockIndex* tip = csm.GetTip();
    ValidationState st;
    for (int i = 0; i < 25; i++) {
        CBlockHeader h = MakeChild(tip, tip->nTime + 120);
        auto* p = csm.AcceptBlockHeader(h, st);
        REQUIRE(p);
        csm.TryAddBlockIndexCandidate(p);
        REQUIRE(csm.ActivateBestChain());
        tip = csm.GetTip();
    }
    REQUIRE(tip->nHeight == 25);

    CBlockLocator loc = csm.GetLocator();
    REQUIRE(!loc.vHave.empty());
    REQUIRE(loc.vHave[0] == tip->GetBlockHash());

    size_t checkN = std::min<size_t>(11, loc.vHave.size());
    for (size_t i = 1; i < checkN; i++) {
        const CBlockIndex* prev = csm.LookupBlockIndex(loc.vHave[i-1]);
        REQUIRE(prev);
        const CBlockIndex* cur = csm.LookupBlockIndex(loc.vHave[i]);
        REQUIRE(cur);
        REQUIRE(cur->nHeight == prev->nHeight - 1);
    }

    bool hasGenesis = false;
    for (auto& h : loc.vHave) {
        if (h == params->GenesisBlock().GetHash()) {
            hasGenesis = true;
            break;
        }
    }
    REQUIRE(hasGenesis);
}

TEST_CASE("ChainstateManager - IsOnActiveChain", "[chain][chainstate_manager][unit]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);

    CBlockHeader genesis = CreateTestHeader();
    csm.Initialize(genesis);

    SECTION("Genesis is on active chain") {
        REQUIRE(csm.IsOnActiveChain(csm.GetTip()));
    }

    SECTION("Active block is on active chain") {
        CBlockHeader block1 = CreateChildHeader(genesis.GetHash(), 1000);
        ValidationState state;
        csm.ProcessNewBlockHeader(block1, state);

        const CBlockIndex* pindex = csm.LookupBlockIndex(block1.GetHash());
        REQUIRE(csm.IsOnActiveChain(pindex));
    }

    SECTION("Orphaned block not on active chain") {
        CBlockHeader blockA1 = CreateChildHeader(genesis.GetHash(), 1000);
        ValidationState stateA1;
        csm.ProcessNewBlockHeader(blockA1, stateA1);

        CBlockHeader blockB1 = CreateChildHeader(genesis.GetHash(), 2000);
        ValidationState stateB1;
        csm.ProcessNewBlockHeader(blockB1, stateB1);

        const CBlockIndex* pindexA1 = csm.LookupBlockIndex(blockA1.GetHash());
        REQUIRE(csm.IsOnActiveChain(pindexA1));

        const CBlockIndex* pindexB1 = csm.LookupBlockIndex(blockB1.GetHash());
        REQUIRE_FALSE(csm.IsOnActiveChain(pindexB1));
    }

    SECTION("Null pointer check") {
        REQUIRE_FALSE(csm.IsOnActiveChain(nullptr));
    }
}

TEST_CASE("ChainstateManager - GetBlockAtHeight", "[chain][chainstate_manager][unit]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);

    CBlockHeader genesis = CreateTestHeader();
    csm.Initialize(genesis);

    SECTION("Get genesis at height 0") {
        const CBlockIndex* pindex = csm.GetBlockAtHeight(0);
        REQUIRE(pindex != nullptr);
        REQUIRE(pindex->GetBlockHash() == genesis.GetHash());
    }

    SECTION("Get block at valid height") {
        CBlockHeader block1 = CreateChildHeader(genesis.GetHash(), 1000);
        ValidationState state;
        csm.ProcessNewBlockHeader(block1, state);

        const CBlockIndex* pindex = csm.GetBlockAtHeight(1);
        REQUIRE(pindex != nullptr);
        REQUIRE(pindex->GetBlockHash() == block1.GetHash());
    }

    SECTION("Get block at invalid height") {
        REQUIRE(csm.GetBlockAtHeight(-1) == nullptr);
        REQUIRE(csm.GetBlockAtHeight(999) == nullptr);
    }
}

TEST_CASE("ChainstateManager - GetBlockCount/GetChainHeight", "[chain][chainstate_manager][unit]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);

    SECTION("Empty chain") {
        REQUIRE(csm.GetBlockCount() == 0);
        REQUIRE(csm.GetChainHeight() == -1);
    }

    SECTION("With genesis") {
        CBlockHeader genesis = CreateTestHeader();
        csm.Initialize(genesis);

        REQUIRE(csm.GetBlockCount() == 1);
        REQUIRE(csm.GetChainHeight() == 0);
    }

    SECTION("With multiple blocks") {
        CBlockHeader genesis = CreateTestHeader();
        csm.Initialize(genesis);

        CBlockHeader block1 = CreateChildHeader(genesis.GetHash(), 1000);
        ValidationState state1;
        csm.ProcessNewBlockHeader(block1, state1);

        CBlockHeader block2 = CreateChildHeader(block1.GetHash(), 2000);
        ValidationState state2;
        csm.ProcessNewBlockHeader(block2, state2);

        REQUIRE(csm.GetBlockCount() == 3);
        REQUIRE(csm.GetChainHeight() == 2);
    }
}

TEST_CASE("CChain::FindFork returns correct fork point", "[chain][findfork]") {
    BlockManager bm;

    CBlockHeader g;
    g.nVersion = 1;
    g.hashPrevBlock.SetNull();
    g.minerAddress.SetNull();
    g.nTime = 1000;
    g.nBits = 0x207fffff;
    g.nNonce = 0;
    REQUIRE(bm.Initialize(g));

    CBlockHeader prev = g;
    CBlockIndex* lastA = nullptr;
    for (int i = 1; i <= 5; i++) {
        CBlockHeader h = MakeChild((i == 1 ? bm.GetTip() : lastA), (i == 1 ? g.nTime : lastA->nTime) + 120);
        lastA = bm.AddToBlockIndex(h);
        REQUIRE(lastA);
        bm.SetActiveTip(*lastA);
    }
    REQUIRE(bm.ActiveChain().Tip() == lastA);

    CBlockIndex* lastB = bm.LookupBlockIndex(g.GetHash());
    for (int i = 1; i <= 6; i++) {
        CBlockHeader h = MakeChild((i == 1 ? bm.LookupBlockIndex(g.GetHash()) : lastB), (i == 1 ? g.nTime : lastB->nTime) + 90);
        lastB = bm.AddToBlockIndex(h);
        REQUIRE(lastB);
    }

    const CChain& chain = bm.ActiveChain();

    const CBlockIndex* fork = chain.FindFork(lastB);
    REQUIRE(fork != nullptr);
    REQUIRE(fork->GetBlockHash() == g.GetHash());

    REQUIRE(chain.FindFork(lastA) == lastA);
}

// =============================================================================
// Section 6: IBD Detection
// =============================================================================

TEST_CASE("ChainstateManager - IsInitialBlockDownload", "[chain][chainstate_manager][ibd][unit]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);

    SECTION("IBD when no tip") {
        REQUIRE(csm.IsInitialBlockDownload());
    }

    SECTION("IBD at genesis height 0") {
        CBlockHeader genesis = CreateTestHeader();
        csm.Initialize(genesis);
        REQUIRE(csm.IsInitialBlockDownload());
    }

    SECTION("IBD with old tip timestamp") {
        CBlockHeader genesis = CreateTestHeader(1000000);
        csm.Initialize(genesis);

        CBlockHeader block1 = CreateChildHeader(genesis.GetHash(), 1000100);
        ValidationState state;
        csm.ProcessNewBlockHeader(block1, state);

        REQUIRE(csm.IsInitialBlockDownload());
    }

    SECTION("IBD check is thread-safe") {
        CBlockHeader genesis = CreateTestHeader();
        csm.Initialize(genesis);

        std::vector<std::thread> threads;
        std::atomic<int> ibd_true_count{0};
        std::atomic<int> ibd_false_count{0};

        for (int i = 0; i < 10; ++i) {
            threads.emplace_back([&]() {
                for (int j = 0; j < 100; ++j) {
                    if (csm.IsInitialBlockDownload()) {
                        ibd_true_count++;
                    } else {
                        ibd_false_count++;
                    }
                }
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        REQUIRE((ibd_true_count + ibd_false_count) == 1000);
    }

    SECTION("IBD returns consistent result on repeated calls") {
        CBlockHeader genesis = CreateTestHeader();
        csm.Initialize(genesis);

        bool first_result = csm.IsInitialBlockDownload();

        for (int i = 0; i < 10; ++i) {
            REQUIRE(csm.IsInitialBlockDownload() == first_result);
        }
    }
}

TEST_CASE("IsInitialBlockDownload latch behavior", "[chain][chainstate_manager][ibd]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);

    SECTION("Empty and genesis-only return IBD true") {
        REQUIRE(csm.IsInitialBlockDownload());
        REQUIRE(csm.Initialize(params->GenesisBlock()));
        REQUIRE(csm.IsInitialBlockDownload());
    }

    SECTION("Height>0 recent tip clears IBD and latches") {
        csm.SetBypassContextualValidation(false);
        REQUIRE(csm.Initialize(params->GenesisBlock()));
        const CBlockIndex* tip = csm.GetTip();
        uint32_t bits = consensus::GetNextWorkRequired(tip, *params);
        uint32_t nowt = static_cast<uint32_t>(util::GetTime());
        CBlockHeader h = MakeChild(tip, nowt, bits);
        ValidationState s;
        auto* pi = csm.AcceptBlockHeader(h, s);
        REQUIRE(pi != nullptr);
        csm.TryAddBlockIndexCandidate(pi);
        REQUIRE(csm.ActivateBestChain());

        REQUIRE_FALSE(csm.IsInitialBlockDownload());
        REQUIRE_FALSE(csm.IsInitialBlockDownload());
    }
}

// =============================================================================
// Section 7: InvalidateBlock
// =============================================================================

TEST_CASE("ChainstateManager - InvalidateBlock", "[chain][chainstate_manager][unit]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);

    CBlockHeader genesis = CreateTestHeader();
    csm.Initialize(genesis);

    SECTION("Cannot invalidate genesis") {
        REQUIRE_FALSE(csm.InvalidateBlock(genesis.GetHash()));
    }

    SECTION("Cannot invalidate unknown block") {
        uint256 fake_hash;
        fake_hash.SetNull();
        memset((void*)fake_hash.data(), 0xff, 32);

        REQUIRE_FALSE(csm.InvalidateBlock(fake_hash));
    }

    SECTION("Invalidate block on main chain") {
        CBlockHeader block1 = CreateChildHeader(genesis.GetHash(), 1000);
        ValidationState state1;
        csm.ProcessNewBlockHeader(block1, state1);

        CBlockHeader block2 = CreateChildHeader(block1.GetHash(), 2000);
        ValidationState state2;
        csm.ProcessNewBlockHeader(block2, state2);

        REQUIRE(csm.GetChainHeight() == 2);
        REQUIRE(csm.InvalidateBlock(block2.GetHash()));

        REQUIRE(csm.GetTip()->GetBlockHash() == block1.GetHash());
        REQUIRE(csm.GetChainHeight() == 1);
    }

    SECTION("Invalidate block not on main chain") {
        CBlockHeader blockA1 = CreateChildHeader(genesis.GetHash(), 1000);
        ValidationState stateA1;
        csm.ProcessNewBlockHeader(blockA1, stateA1);

        CBlockHeader blockB1 = CreateChildHeader(genesis.GetHash(), 2000);
        ValidationState stateB1;
        csm.ProcessNewBlockHeader(blockB1, stateB1);

        REQUIRE(csm.InvalidateBlock(blockB1.GetHash()));
        REQUIRE(csm.GetTip()->GetBlockHash() == blockA1.GetHash());

        const CBlockIndex* pindexB1 = csm.LookupBlockIndex(blockB1.GetHash());
        REQUIRE(pindexB1->status.IsFailed());
    }
}

TEST_CASE("ChainstateManager - Duplicate invalid re-announce", "[chain][chainstate_manager][unit]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);

    CBlockHeader genesis = CreateTestHeader();
    csm.Initialize(genesis);

    CBlockHeader block1 = CreateChildHeader(genesis.GetHash(), 1234567900);
    {
        ValidationState st;
        CBlockIndex* p1 = csm.AcceptBlockHeader(block1, st);
        REQUIRE(p1 != nullptr);
        REQUIRE(st.IsValid());
    }

    REQUIRE(csm.InvalidateBlock(block1.GetHash()));

    ValidationState st2;
    CBlockIndex* p2 = csm.AcceptBlockHeader(block1, st2);
    REQUIRE(p2 == nullptr);
    REQUIRE_FALSE(st2.IsValid());
    REQUIRE(st2.GetRejectReason() == "duplicate");
}

TEST_CASE("ChainstateManager - Descendant of invalid is rejected", "[chain][chainstate_manager][unit]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);

    CBlockHeader genesis = CreateTestHeader();
    csm.Initialize(genesis);

    CBlockHeader A1 = CreateChildHeader(genesis.GetHash(), 1000);
    CBlockHeader A2 = CreateChildHeader(A1.GetHash(), 2000);

    {
        ValidationState s1;
        REQUIRE(csm.AcceptBlockHeader(A1, s1) != nullptr);
        ValidationState s2;
        REQUIRE(csm.AcceptBlockHeader(A2, s2) != nullptr);
    }

    REQUIRE(csm.InvalidateBlock(A1.GetHash()));

    CBlockHeader A3 = CreateChildHeader(A2.GetHash(), 3000);
    ValidationState s3;
    CBlockIndex* p3 = csm.AcceptBlockHeader(A3, s3);

    REQUIRE(p3 == nullptr);
    REQUIRE_FALSE(s3.IsValid());
    REQUIRE(s3.GetRejectReason() == "bad-prevblk");
}

// =============================================================================
// Section 8: Contextual Validation
// =============================================================================

TEST_CASE("Contextual - bad difficulty is rejected", "[chain][chainstate_manager][validation][contextual]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);
    csm.SetBypassContextualValidation(false);

    REQUIRE(csm.Initialize(params->GenesisBlock()));
    const CBlockIndex* tip = csm.GetTip();
    REQUIRE(tip != nullptr);

    uint32_t expected = consensus::GetNextWorkRequired(tip, *params);

    CBlockHeader bad = MakeChild(tip, tip->nTime + 120, expected ^ 1);

    ValidationState st;
    CBlockIndex* p = csm.AcceptBlockHeader(bad, st);
    REQUIRE(p == nullptr);
    REQUIRE_FALSE(st.IsValid());
    REQUIRE(st.GetRejectReason() == "bad-diffbits");
}

TEST_CASE("Contextual - timestamp constraints (MTP and future)", "[chain][chainstate_manager][validation][contextual]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);
    csm.SetBypassContextualValidation(false);

    REQUIRE(csm.Initialize(params->GenesisBlock()));
    const CBlockIndex* tip = csm.GetTip();
    REQUIRE(tip != nullptr);

    uint32_t bitsA = consensus::GetNextWorkRequired(tip, *params);
    CBlockHeader A = MakeChild(tip, tip->nTime + 120, bitsA);
    {
        ValidationState s;
        auto* pa = csm.AcceptBlockHeader(A, s);
        REQUIRE(pa != nullptr);
        csm.TryAddBlockIndexCandidate(pa);
        REQUIRE(csm.ActivateBestChain());
    }

    const CBlockIndex* tipA = csm.GetTip();
    REQUIRE(tipA != nullptr);

    SECTION("time-too-old vs median time past") {
        uint32_t bitsB = consensus::GetNextWorkRequired(tipA, *params);
        CBlockHeader B = MakeChild(tipA, tipA->nTime, bitsB);
        ValidationState s;
        auto* pb = csm.AcceptBlockHeader(B, s);
        REQUIRE(pb == nullptr);
        REQUIRE_FALSE(s.IsValid());
        REQUIRE(s.GetRejectReason() == "time-too-old");
    }

    SECTION("time-too-new vs adjusted time") {
        uint32_t bitsB = consensus::GetNextWorkRequired(tipA, *params);
        uint32_t future = static_cast<uint32_t>(util::GetTime() + MAX_FUTURE_BLOCK_TIME + 1000);
        CBlockHeader B = MakeChild(tipA, future, bitsB);
        ValidationState s;
        auto* pb = csm.AcceptBlockHeader(B, s);
        REQUIRE(pb == nullptr);
        REQUIRE_FALSE(s.IsValid());
        REQUIRE(s.GetRejectReason() == "time-too-new");
    }
}

// Test-only params with tiny expiration height
class SmallExpireParams : public ChainParams {
public:
    SmallExpireParams() {
        chainType = ChainType::REGTEST;
        consensus.powLimit = uint256S("0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetSpacing = 2 * 60;
        consensus.nRandomXEpochDuration = 365ULL * 24 * 60 * 60 * 100;
        consensus.nASERTHalfLife = 60 * 60;
        consensus.nASERTAnchorHeight = 1;
        consensus.nMinimumChainWork = uint256S("0x0");
        consensus.nNetworkExpirationInterval = 3;
        consensus.nNetworkExpirationGracePeriod = 1;
        consensus.nOrphanHeaderExpireTime = 12 * 60;
        consensus.nSuspiciousReorgDepth = 100;
        consensus.nAntiDosWorkBufferBlocks = 144;
        nDefaultPort = 29590;
        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1);
        consensus.hashGenesisBlock = genesis.GetHash();
    }
};

TEST_CASE("Network expiration triggers reject + notification", "[chain][chainstate_manager][validation][timebomb]") {
    auto params = std::make_unique<SmallExpireParams>();
    TestChainstateManager csm(*params);
    csm.SetBypassContextualValidation(false);

    REQUIRE(csm.Initialize(params->GenesisBlock()));

    bool got_notify = false;
    std::string debug_msg;
    std::string user_msg;
    auto sub = Notifications().SubscribeFatalError([&](const std::string& debug_message, const std::string& user_message) {
        got_notify = true;
        debug_msg = debug_message;
        user_msg = user_message;
    });

    const CBlockIndex* tip = csm.GetTip();
    for (int i = 0; i < 2; i++) {
        uint32_t bits = consensus::GetNextWorkRequired(tip, *params);
        CBlockHeader h = MakeChild(tip, tip->nTime + 120, bits);
        ValidationState s;
        auto* pi = csm.AcceptBlockHeader(h, s);
        REQUIRE(pi != nullptr);
        csm.TryAddBlockIndexCandidate(pi);
        REQUIRE(csm.ActivateBestChain());
        tip = csm.GetTip();
    }
    REQUIRE(tip->nHeight == 2);

    uint32_t bits = consensus::GetNextWorkRequired(tip, *params);
    CBlockHeader expH = MakeChild(tip, tip->nTime + 120, bits);
    ValidationState s;
    auto* r = csm.AcceptBlockHeader(expH, s);
    REQUIRE(r != nullptr);
    REQUIRE(s.IsValid());

    csm.TryAddBlockIndexCandidate(r);
    REQUIRE_FALSE(csm.ActivateBestChain());

    REQUIRE(got_notify);
    REQUIRE(debug_msg.find("expiration block 3") != std::string::npos);
    REQUIRE(user_msg.find("update") != std::string::npos);
    REQUIRE(csm.GetTip()->nHeight == 3);
}

TEST_CASE("ChainstateManager - CheckHeadersPoW", "[chain][chainstate_manager][unit]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);

    SECTION("All headers pass") {
        std::vector<CBlockHeader> headers;
        headers.push_back(CreateTestHeader(1000));
        headers.push_back(CreateTestHeader(2000));

        REQUIRE(csm.CheckHeadersPoW(headers));
    }

    SECTION("Headers with null hashRandomX fail when validation enabled") {
        csm.SetBypassPoW(false);

        std::vector<CBlockHeader> headers;
        headers.push_back(CreateTestHeader(1000));
        headers.push_back(CreateTestHeader(2000));

        REQUIRE_FALSE(csm.CheckHeadersPoW(headers));
    }

    SECTION("Empty list") {
        std::vector<CBlockHeader> headers;
        REQUIRE(csm.CheckHeadersPoW(headers));
    }

    SECTION("Large batch all pass") {
        std::vector<CBlockHeader> headers;
        for (int i = 0; i < 100; ++i) {
            headers.push_back(CreateTestHeader(1000 + i));
        }
        REQUIRE(csm.CheckHeadersPoW(headers));
    }
}

// =============================================================================
// Section 9: Security
// =============================================================================

TEST_CASE("TestSetSkipPoWChecks - Network type guard", "[chain][chainstate_manager][security][pow]") {
    SECTION("Allows PoW skip in REGTEST mode") {
        auto params = ChainParams::CreateRegTest();
        TestChainstateManager csm(*params);
        REQUIRE(csm.Initialize(params->GenesisBlock()));

        REQUIRE_NOTHROW(csm.TestSetSkipPoWChecks(true));
        REQUIRE(csm.TestGetSkipPoWChecks() == true);

        REQUIRE_NOTHROW(csm.TestSetSkipPoWChecks(false));
        REQUIRE(csm.TestGetSkipPoWChecks() == false);
    }

    SECTION("Rejects PoW skip in MAINNET mode") {
        auto params = ChainParams::CreateMainNet();
        ChainstateManager csm(*params);
        REQUIRE(csm.Initialize(params->GenesisBlock()));

        REQUIRE_THROWS_AS(csm.TestSetSkipPoWChecks(true), std::runtime_error);
        REQUIRE(csm.TestGetSkipPoWChecks() == false);
    }

    SECTION("Rejects PoW skip in TESTNET mode") {
        auto params = ChainParams::CreateTestNet();
        ChainstateManager csm(*params);
        REQUIRE(csm.Initialize(params->GenesisBlock()));

        REQUIRE_THROWS_AS(csm.TestSetSkipPoWChecks(true), std::runtime_error);
        REQUIRE(csm.TestGetSkipPoWChecks() == false);
    }

    SECTION("Exception contains descriptive message") {
        auto params = ChainParams::CreateMainNet();
        ChainstateManager csm(*params);
        REQUIRE(csm.Initialize(params->GenesisBlock()));

        try {
            csm.TestSetSkipPoWChecks(true);
            FAIL("Expected exception was not thrown");
        } catch (const std::runtime_error& e) {
            std::string msg = e.what();
            REQUIRE(msg.find("regtest") != std::string::npos);
            REQUIRE(msg.find("PoW") != std::string::npos);
        }
    }
}

TEST_CASE("ChainstateManager - No common ancestor triggers fatal error", "[chain][chainstate_manager][security][fatal]") {
    crypto::InitRandomX();
    GlobalChainParams::Select(ChainType::REGTEST);

    SECTION("Simulated divergent chain scenario") {
        CBlockIndex genesis_a;
        genesis_a.nHeight = 0;
        genesis_a.pprev = nullptr;

        CBlockIndex a1;
        a1.nHeight = 1;
        a1.pprev = &genesis_a;

        CBlockIndex genesis_b;
        genesis_b.nHeight = 0;
        genesis_b.pprev = nullptr;

        CBlockIndex b1;
        b1.nHeight = 1;
        b1.pprev = &genesis_b;

        const CBlockIndex* lca = LastCommonAncestor(&a1, &b1);
        REQUIRE(lca == nullptr);
    }
}

TEST_CASE("LastCommonAncestor - Divergent chain edge cases", "[chain][block_index][security]") {
    SECTION("Different height chains with no common ancestor") {
        std::vector<CBlockIndex> chain_a(6);
        chain_a[0].nHeight = 0;
        chain_a[0].pprev = nullptr;

        for (int i = 1; i < 6; i++) {
            chain_a[i].nHeight = i;
            chain_a[i].pprev = &chain_a[i-1];
        }

        std::vector<CBlockIndex> chain_b(2);
        chain_b[0].nHeight = 0;
        chain_b[0].pprev = nullptr;

        chain_b[1].nHeight = 1;
        chain_b[1].pprev = &chain_b[0];

        REQUIRE(LastCommonAncestor(&chain_a[5], &chain_b[1]) == nullptr);
        REQUIRE(LastCommonAncestor(&chain_a[1], &chain_b[1]) == nullptr);
        REQUIRE(LastCommonAncestor(&chain_a[0], &chain_b[0]) == nullptr);
    }

    SECTION("Equal height chains with no common ancestor") {
        std::vector<CBlockIndex> chain_a(4);
        chain_a[0].nHeight = 0;
        chain_a[0].pprev = nullptr;

        for (int i = 1; i < 4; i++) {
            chain_a[i].nHeight = i;
            chain_a[i].pprev = &chain_a[i-1];
        }

        std::vector<CBlockIndex> chain_b(4);
        chain_b[0].nHeight = 0;
        chain_b[0].pprev = nullptr;

        for (int i = 1; i < 4; i++) {
            chain_b[i].nHeight = i;
            chain_b[i].pprev = &chain_b[i-1];
        }

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                const CBlockIndex* lca = LastCommonAncestor(&chain_a[i], &chain_b[j]);
                REQUIRE(lca == nullptr);
            }
        }
    }

    SECTION("Very long divergent chains") {
        std::vector<CBlockIndex> chain_a(100);
        chain_a[0].nHeight = 0;
        chain_a[0].pprev = nullptr;

        for (int i = 1; i < 100; i++) {
            chain_a[i].nHeight = i;
            chain_a[i].pprev = &chain_a[i-1];
        }

        std::vector<CBlockIndex> chain_b(100);
        chain_b[0].nHeight = 0;
        chain_b[0].pprev = nullptr;

        for (int i = 1; i < 100; i++) {
            chain_b[i].nHeight = i;
            chain_b[i].pprev = &chain_b[i-1];
        }

        const CBlockIndex* lca = LastCommonAncestor(&chain_a[99], &chain_b[99]);
        REQUIRE(lca == nullptr);
    }
}

TEST_CASE("LastCommonAncestor - Performance verification", "[chain][block_index][performance]") {
    SECTION("O(min(h1, h2)) performance for divergent chains") {
        std::vector<CBlockIndex> chain_a(1000);
        chain_a[0].nHeight = 0;
        chain_a[0].pprev = nullptr;

        for (int i = 1; i < 1000; i++) {
            chain_a[i].nHeight = i;
            chain_a[i].pprev = &chain_a[i-1];
        }

        std::vector<CBlockIndex> chain_b(500);
        chain_b[0].nHeight = 0;
        chain_b[0].pprev = nullptr;

        for (int i = 1; i < 500; i++) {
            chain_b[i].nHeight = i;
            chain_b[i].pprev = &chain_b[i-1];
        }

        auto start = std::chrono::high_resolution_clock::now();
        const CBlockIndex* lca = LastCommonAncestor(&chain_a[999], &chain_b[499]);
        auto end = std::chrono::high_resolution_clock::now();

        REQUIRE(lca == nullptr);

        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        REQUIRE(duration.count() < 1000);
    }
}

// =============================================================================
// Section 11: ActiveTipCandidates
// =============================================================================

// Helper to create test hashes for ActiveTipCandidates tests
static uint256 MakeCandidateHash(int n) {
    uint256 hash;
    hash.SetNull();
    uint8_t* data = hash.data();
    data[0] = static_cast<uint8_t>(n & 0xFF);
    data[1] = static_cast<uint8_t>((n >> 8) & 0xFF);
    return hash;
}

TEST_CASE("ActiveTipCandidates - Construction", "[chain][active_tip_candidates][unit]") {
    ActiveTipCandidates selector;

    REQUIRE(selector.Size() == 0);
    REQUIRE(selector.All().empty());
}

TEST_CASE("ActiveTipCandidates - Add", "[chain][active_tip_candidates][unit]") {
    ActiveTipCandidates selector;

    SECTION("Add single hash") {
        uint256 hash1 = MakeCandidateHash(1);
        selector.Add(hash1);

        REQUIRE(selector.Size() == 1);
        REQUIRE(selector.Contains(hash1));
    }

    SECTION("Add multiple hashes") {
        uint256 hash1 = MakeCandidateHash(1);
        uint256 hash2 = MakeCandidateHash(2);
        uint256 hash3 = MakeCandidateHash(3);

        selector.Add(hash1);
        selector.Add(hash2);
        selector.Add(hash3);

        REQUIRE(selector.Size() == 3);
        REQUIRE(selector.Contains(hash1));
        REQUIRE(selector.Contains(hash2));
        REQUIRE(selector.Contains(hash3));
    }

    SECTION("Duplicate add is idempotent") {
        uint256 hash1 = MakeCandidateHash(1);

        selector.Add(hash1);
        selector.Add(hash1);

        REQUIRE(selector.Size() == 1);
    }
}

TEST_CASE("ActiveTipCandidates - Remove", "[chain][active_tip_candidates][unit]") {
    ActiveTipCandidates selector;

    SECTION("Remove existing hash") {
        uint256 hash1 = MakeCandidateHash(1);
        selector.Add(hash1);
        REQUIRE(selector.Size() == 1);

        selector.Remove(hash1);
        REQUIRE(selector.Size() == 0);
        REQUIRE(!selector.Contains(hash1));
    }

    SECTION("Remove non-existent hash is no-op") {
        uint256 hash1 = MakeCandidateHash(1);

        selector.Remove(hash1);
        REQUIRE(selector.Size() == 0);
    }

    SECTION("Remove one of multiple") {
        uint256 hash1 = MakeCandidateHash(1);
        uint256 hash2 = MakeCandidateHash(2);
        uint256 hash3 = MakeCandidateHash(3);

        selector.Add(hash1);
        selector.Add(hash2);
        selector.Add(hash3);
        REQUIRE(selector.Size() == 3);

        selector.Remove(hash2);
        REQUIRE(selector.Size() == 2);
        REQUIRE(selector.Contains(hash1));
        REQUIRE(!selector.Contains(hash2));
        REQUIRE(selector.Contains(hash3));
    }
}

TEST_CASE("ActiveTipCandidates - Clear", "[chain][active_tip_candidates][unit]") {
    ActiveTipCandidates selector;

    SECTION("Clear empty set") {
        selector.Clear();
        REQUIRE(selector.Size() == 0);
    }

    SECTION("Clear populated set") {
        selector.Add(MakeCandidateHash(1));
        selector.Add(MakeCandidateHash(2));
        selector.Add(MakeCandidateHash(3));
        REQUIRE(selector.Size() == 3);

        selector.Clear();
        REQUIRE(selector.Size() == 0);
        REQUIRE(selector.All().empty());
    }
}

TEST_CASE("ActiveTipCandidates - Contains", "[chain][active_tip_candidates][unit]") {
    ActiveTipCandidates selector;

    uint256 hash1 = MakeCandidateHash(1);
    uint256 hash2 = MakeCandidateHash(2);

    REQUIRE(!selector.Contains(hash1));
    REQUIRE(!selector.Contains(hash2));

    selector.Add(hash1);

    REQUIRE(selector.Contains(hash1));
    REQUIRE(!selector.Contains(hash2));
}

TEST_CASE("ActiveTipCandidates - All", "[chain][active_tip_candidates][unit]") {
    ActiveTipCandidates selector;

    SECTION("Empty set returns empty collection") {
        const auto& all = selector.All();
        REQUIRE(all.empty());
    }

    SECTION("Returns all added hashes") {
        uint256 hash1 = MakeCandidateHash(1);
        uint256 hash2 = MakeCandidateHash(2);
        uint256 hash3 = MakeCandidateHash(3);

        selector.Add(hash1);
        selector.Add(hash2);
        selector.Add(hash3);

        const auto& all = selector.All();
        REQUIRE(all.size() == 3);
        REQUIRE(all.count(hash1) == 1);
        REQUIRE(all.count(hash2) == 1);
        REQUIRE(all.count(hash3) == 1);
    }
}

TEST_CASE("ActiveTipCandidates - Edge Cases", "[chain][active_tip_candidates][unit]") {
    ActiveTipCandidates selector;

    SECTION("Null hash can be added") {
        uint256 null_hash;
        null_hash.SetNull();

        selector.Add(null_hash);
        REQUIRE(selector.Size() == 1);
        REQUIRE(selector.Contains(null_hash));
    }

    SECTION("Clear then re-add works") {
        uint256 hash1 = MakeCandidateHash(1);

        selector.Add(hash1);
        selector.Clear();
        selector.Add(hash1);

        REQUIRE(selector.Size() == 1);
        REQUIRE(selector.Contains(hash1));
    }

    SECTION("Iteration after modification") {
        selector.Add(MakeCandidateHash(1));
        selector.Add(MakeCandidateHash(2));
        selector.Add(MakeCandidateHash(3));

        std::vector<uint256> to_remove;
        for (const auto& hash : selector.All()) {
            to_remove.push_back(hash);
        }

        for (const auto& hash : to_remove) {
            selector.Remove(hash);
        }

        REQUIRE(selector.Size() == 0);
    }
}

// =============================================================================
// Section 12: GetChainTips
// =============================================================================

// Test subclass for GetChainTips that bypasses PoW validation
class TestChainstateManagerForTips : public ChainstateManager {
public:
  explicit TestChainstateManagerForTips(const ChainParams& params) : ChainstateManager(params) {}

protected:
  bool CheckProofOfWork(const CBlockHeader& /*header*/, crypto::POWVerifyMode /*mode*/) const override { return true; }

  bool CheckBlockHeaderWrapper(const CBlockHeader& /*header*/, ValidationState& /*state*/) const override {
    return true;
  }

  bool ContextualCheckBlockHeaderWrapper(const CBlockHeader& /*header*/, const CBlockIndex* /*pindexPrev*/,
                                         int64_t /*adjusted_time*/, ValidationState& /*state*/) const override {
    return true;
  }
};

// Helper: Create a block header for GetChainTips tests
static CBlockHeader CreateTipsTestHeader(uint32_t nTime = 1234567890, uint32_t nBits = 0x1d00ffff) {
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

// Helper: Create a child header with unique hash
static CBlockHeader CreateTipsChildHeader(const uint256& prevHash, uint32_t nTime, uint32_t nNonce = 0) {
  CBlockHeader header = CreateTipsTestHeader(nTime);
  header.hashPrevBlock = prevHash;
  header.nNonce = nNonce;
  return header;
}

TEST_CASE("GetChainTips - Empty chain", "[chain][getchaintips][unit]") {
  auto params = ChainParams::CreateRegTest();
  TestChainstateManagerForTips csm(*params);

  auto tips = csm.GetChainTips();
  REQUIRE(tips.empty());
}

TEST_CASE("GetChainTips - Genesis only", "[chain][getchaintips][unit]") {
  auto params = ChainParams::CreateRegTest();
  TestChainstateManagerForTips csm(*params);

  CBlockHeader genesis = CreateTipsTestHeader();
  REQUIRE(csm.Initialize(genesis));

  auto tips = csm.GetChainTips();
  REQUIRE(tips.size() == 1);
  REQUIRE(tips[0].height == 0);
  REQUIRE(tips[0].hash == genesis.GetHash());
  REQUIRE(tips[0].branchlen == 0);
  REQUIRE(tips[0].status == ChainstateManager::ChainTip::Status::ACTIVE);
}

TEST_CASE("GetChainTips - Linear chain", "[chain][getchaintips][unit]") {
  auto params = ChainParams::CreateRegTest();
  TestChainstateManagerForTips csm(*params);

  CBlockHeader genesis = CreateTipsTestHeader(1000);
  REQUIRE(csm.Initialize(genesis));

  CBlockHeader block1 = CreateTipsChildHeader(genesis.GetHash(), 1001);
  ValidationState state1;
  REQUIRE(csm.ProcessNewBlockHeader(block1, state1));

  CBlockHeader block2 = CreateTipsChildHeader(block1.GetHash(), 1002);
  ValidationState state2;
  REQUIRE(csm.ProcessNewBlockHeader(block2, state2));

  CBlockHeader block3 = CreateTipsChildHeader(block2.GetHash(), 1003);
  ValidationState state3;
  REQUIRE(csm.ProcessNewBlockHeader(block3, state3));

  auto tips = csm.GetChainTips();
  REQUIRE(tips.size() == 1);
  REQUIRE(tips[0].height == 3);
  REQUIRE(tips[0].hash == block3.GetHash());
  REQUIRE(tips[0].branchlen == 0);
  REQUIRE(tips[0].status == ChainstateManager::ChainTip::Status::ACTIVE);
}

TEST_CASE("GetChainTips - Simple fork", "[chain][getchaintips][unit]") {
  auto params = ChainParams::CreateRegTest();
  TestChainstateManagerForTips csm(*params);

  CBlockHeader genesis = CreateTipsTestHeader(1000);
  REQUIRE(csm.Initialize(genesis));

  CBlockHeader block1 = CreateTipsChildHeader(genesis.GetHash(), 1001);
  ValidationState state1;
  REQUIRE(csm.ProcessNewBlockHeader(block1, state1));

  CBlockHeader block2 = CreateTipsChildHeader(block1.GetHash(), 1002, 1);
  ValidationState state2;
  REQUIRE(csm.ProcessNewBlockHeader(block2, state2));

  CBlockHeader fork1 = CreateTipsChildHeader(block1.GetHash(), 1002, 2);
  ValidationState state_fork;
  REQUIRE(csm.ProcessNewBlockHeader(fork1, state_fork));

  auto tips = csm.GetChainTips();
  REQUIRE(tips.size() == 2);

  std::sort(tips.begin(), tips.end(), [](const auto& a, const auto& b) {
    return static_cast<int>(a.status) < static_cast<int>(b.status);
  });

  REQUIRE(tips[0].status == ChainstateManager::ChainTip::Status::ACTIVE);
  REQUIRE(tips[0].height == 2);
  REQUIRE(tips[0].branchlen == 0);
  REQUIRE(tips[0].hash == block2.GetHash());

  REQUIRE(tips[1].status == ChainstateManager::ChainTip::Status::VALID_FORK);
  REQUIRE(tips[1].height == 2);
  REQUIRE(tips[1].branchlen == 1);
  REQUIRE(tips[1].hash == fork1.GetHash());
}

TEST_CASE("GetChainTips - Longer fork", "[chain][getchaintips][unit]") {
  auto params = ChainParams::CreateRegTest();
  TestChainstateManagerForTips csm(*params);

  CBlockHeader genesis = CreateTipsTestHeader(1000);
  REQUIRE(csm.Initialize(genesis));

  CBlockHeader block1 = CreateTipsChildHeader(genesis.GetHash(), 1001);
  ValidationState state1;
  REQUIRE(csm.ProcessNewBlockHeader(block1, state1));

  CBlockHeader block2 = CreateTipsChildHeader(block1.GetHash(), 1002, 1);
  ValidationState state2;
  REQUIRE(csm.ProcessNewBlockHeader(block2, state2));

  CBlockHeader block3 = CreateTipsChildHeader(block2.GetHash(), 1003, 1);
  ValidationState state3;
  REQUIRE(csm.ProcessNewBlockHeader(block3, state3));

  CBlockHeader fork1 = CreateTipsChildHeader(block1.GetHash(), 1002, 2);
  ValidationState state_f1;
  REQUIRE(csm.ProcessNewBlockHeader(fork1, state_f1));

  CBlockHeader fork2 = CreateTipsChildHeader(fork1.GetHash(), 1003, 2);
  ValidationState state_f2;
  REQUIRE(csm.ProcessNewBlockHeader(fork2, state_f2));

  auto tips = csm.GetChainTips();
  REQUIRE(tips.size() == 2);

  const ChainstateManager::ChainTip* fork_tip = nullptr;
  const ChainstateManager::ChainTip* active_tip = nullptr;
  for (const auto& tip : tips) {
    if (tip.status == ChainstateManager::ChainTip::Status::ACTIVE) {
      active_tip = &tip;
    } else if (tip.status == ChainstateManager::ChainTip::Status::VALID_FORK) {
      fork_tip = &tip;
    }
  }

  REQUIRE(active_tip != nullptr);
  REQUIRE(fork_tip != nullptr);

  REQUIRE(active_tip->height == 3);
  REQUIRE(active_tip->branchlen == 0);

  REQUIRE(fork_tip->height == 3);
  REQUIRE(fork_tip->branchlen == 2);
  REQUIRE(fork_tip->hash == fork2.GetHash());
}

TEST_CASE("GetChainTips - Multiple forks", "[chain][getchaintips][unit]") {
  auto params = ChainParams::CreateRegTest();
  TestChainstateManagerForTips csm(*params);

  CBlockHeader genesis = CreateTipsTestHeader(1000);
  REQUIRE(csm.Initialize(genesis));

  CBlockHeader block1 = CreateTipsChildHeader(genesis.GetHash(), 1001, 1);
  ValidationState state1;
  REQUIRE(csm.ProcessNewBlockHeader(block1, state1));

  CBlockHeader block2 = CreateTipsChildHeader(block1.GetHash(), 1002, 1);
  ValidationState state2;
  REQUIRE(csm.ProcessNewBlockHeader(block2, state2));

  CBlockHeader forkA1 = CreateTipsChildHeader(genesis.GetHash(), 1001, 2);
  ValidationState state_a;
  REQUIRE(csm.ProcessNewBlockHeader(forkA1, state_a));

  CBlockHeader forkB1 = CreateTipsChildHeader(genesis.GetHash(), 1001, 3);
  ValidationState state_b;
  REQUIRE(csm.ProcessNewBlockHeader(forkB1, state_b));

  auto tips = csm.GetChainTips();
  REQUIRE(tips.size() == 3);

  int active_count = 0;
  int fork_count = 0;
  for (const auto& tip : tips) {
    if (tip.status == ChainstateManager::ChainTip::Status::ACTIVE) {
      active_count++;
      REQUIRE(tip.height == 2);
      REQUIRE(tip.branchlen == 0);
    } else if (tip.status == ChainstateManager::ChainTip::Status::VALID_FORK) {
      fork_count++;
      REQUIRE(tip.height == 1);
      REQUIRE(tip.branchlen == 1);
    }
  }

  REQUIRE(active_count == 1);
  REQUIRE(fork_count == 2);
}

TEST_CASE("GetChainTips - Invalid block", "[chain][getchaintips][unit]") {
  auto params = ChainParams::CreateRegTest();
  TestChainstateManagerForTips csm(*params);

  CBlockHeader genesis = CreateTipsTestHeader(1000);
  REQUIRE(csm.Initialize(genesis));

  CBlockHeader block1 = CreateTipsChildHeader(genesis.GetHash(), 1001);
  ValidationState state1;
  REQUIRE(csm.ProcessNewBlockHeader(block1, state1));

  CBlockHeader block2 = CreateTipsChildHeader(block1.GetHash(), 1002, 1);
  ValidationState state2;
  REQUIRE(csm.ProcessNewBlockHeader(block2, state2));

  CBlockHeader fork1 = CreateTipsChildHeader(block1.GetHash(), 1002, 2);
  ValidationState state_f1;
  REQUIRE(csm.ProcessNewBlockHeader(fork1, state_f1));

  CBlockHeader fork2 = CreateTipsChildHeader(fork1.GetHash(), 1003, 2);
  ValidationState state_f2;
  REQUIRE(csm.ProcessNewBlockHeader(fork2, state_f2));

  REQUIRE(csm.InvalidateBlock(block2.GetHash()));

  auto tips = csm.GetChainTips();

  REQUIRE(tips.size() >= 2);

  const ChainstateManager::ChainTip* invalid_tip = nullptr;
  const ChainstateManager::ChainTip* active_tip = nullptr;
  for (const auto& tip : tips) {
    if (tip.status == ChainstateManager::ChainTip::Status::INVALID) {
      invalid_tip = &tip;
    } else if (tip.status == ChainstateManager::ChainTip::Status::ACTIVE) {
      active_tip = &tip;
    }
  }

  REQUIRE(invalid_tip != nullptr);
  REQUIRE(invalid_tip->hash == block2.GetHash());

  REQUIRE(active_tip != nullptr);
  REQUIRE(active_tip->hash == fork2.GetHash());
}
