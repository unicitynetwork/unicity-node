// Copyright (c) 2025 The Unicity Foundation
// Unit tests for chain/miner.cpp
//
// Tests are organized into sections:
// 1. Mining Address - Set/get address, persistence, formats
// 2. Initial State - Default values
// 3. Start/Stop - Mining lifecycle, idempotency
// 4. Block Template - Template creation, regeneration

#include "catch_amalgamated.hpp"
#include "chain/miner.hpp"
#include "chain/token_manager.hpp"
#include "chain/trust_base_manager.hpp"
#include "chain/chainparams.hpp"
#include "chain/chainstate_manager.hpp"
#include "chain/block.hpp"
#include "chain/validation.hpp"
#include "common/test_chainstate_manager.hpp"
#include "common/mock_bft_client.hpp"
#include "util/uint.hpp"
#include "util/hash.hpp"
#include <memory>

using namespace unicity;
using namespace unicity::chain;
using namespace unicity::mining;
using namespace unicity::validation;
using namespace unicity::test;

// =============================================================================
// Test Fixtures
// =============================================================================

class MinerTestFixture {
public:
    MinerTestFixture() {
        GlobalChainParams::Select(ChainType::REGTEST);
        params = &GlobalChainParams::Get();

        test_dir = std::filesystem::temp_directory_path() / "unicity_miner_test_XXXXXX";
        char dir_template[256];
        std::strncpy(dir_template, test_dir.string().c_str(), sizeof(dir_template));
        if (mkdtemp(dir_template)) {
            test_dir = dir_template;
        }

        tbm = std::make_unique<LocalTrustBaseManager>(test_dir, std::make_shared<MockBFTClient>());
        chainstate = std::make_unique<ChainstateManager>(*params, *tbm);

        token_manager = std::make_unique<TokenManager>(test_dir, *chainstate);        miner = std::make_unique<CPUMiner>(*params, *chainstate, *tbm, *token_manager);
    }

    ~MinerTestFixture() {
        if (miner && miner->IsMining()) {
            miner->Stop();
        }
        if (!test_dir.empty() && std::filesystem::exists(test_dir)) {
            std::filesystem::remove_all(test_dir);
        }
    }

    const ChainParams* params;
    std::unique_ptr<ChainstateManager> chainstate;
    std::unique_ptr<TrustBaseManager> tbm;
    std::unique_ptr<TokenManager> token_manager;
    std::unique_ptr<CPUMiner> miner;
    std::filesystem::path test_dir;
};

// =============================================================================
// Section 1: Initial State
// =============================================================================

TEST_CASE("CPUMiner - Initial state", "[miner]") {
    MinerTestFixture fixture;

    SECTION("Miner starts in stopped state") {
        REQUIRE(!fixture.miner->IsMining());
    }

    SECTION("Initial stats are zero") {
        REQUIRE(fixture.miner->GetTotalHashes() == 0);
        REQUIRE(fixture.miner->GetBlocksFound() == 0);
        REQUIRE(fixture.miner->GetHashrate() == 0.0);
    }

}

// =============================================================================
// Section 2: Start/Stop
// =============================================================================

TEST_CASE("CPUMiner - Start/Stop and idempotency", "[miner]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);
    REQUIRE(csm.Initialize(params->GenesisBlock()));

    std::filesystem::path test_dir = std::filesystem::temp_directory_path() / "unicity_miner_test_XXXXXX";
    char dir_template[256];
    std::strncpy(dir_template, test_dir.string().c_str(), sizeof(dir_template));

    LocalTrustBaseManager tbm(test_dir, std::make_shared<MockBFTClient>());
    TokenManager token_manager(test_dir, csm);
    CPUMiner miner(*params, csm, tbm, token_manager);

    SECTION("Start spawns worker and Stop joins") {
        REQUIRE(miner.Start(/*target_height=*/-1));
        REQUIRE(miner.IsMining());
        miner.Stop();
        REQUIRE_FALSE(miner.IsMining());
    }

    SECTION("Double Start prevented and double Stop safe") {
        REQUIRE(miner.Start());
        REQUIRE_FALSE(miner.Start());
        miner.Stop();
        miner.Stop();
        REQUIRE_FALSE(miner.IsMining());
    }
    
    if (std::filesystem::exists(test_dir)) {
        std::filesystem::remove_all(test_dir);
    }
}

// =============================================================================
// Section 3: Block Template
// =============================================================================

TEST_CASE("CPUMiner - DebugCreateBlockTemplate and DebugShouldRegenerateTemplate", "[miner]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);
    REQUIRE(csm.Initialize(params->GenesisBlock()));

    std::filesystem::path test_dir = std::filesystem::temp_directory_path() / "unicity_miner_test_XXXXXX";
    char dir_template[256];
    std::strncpy(dir_template, test_dir.string().c_str(), sizeof(dir_template));
    if (mkdtemp(dir_template)) {
        test_dir = dir_template;
    }

    LocalTrustBaseManager tbm(test_dir, std::make_shared<MockBFTClient>());
    TokenManager token_manager(test_dir, csm);
    CPUMiner miner(*params, csm, tbm, token_manager);

    SECTION("Template reflects tip and MTP constraint") {
        auto tmpl1 = miner.DebugCreateBlockTemplate();
        REQUIRE(tmpl1.nHeight == 1);
        REQUIRE(tmpl1.hashPrevBlock == params->GenesisBlock().GetHash());
        REQUIRE(tmpl1.header.nTime > static_cast<uint32_t>(params->GenesisBlock().nTime));

        CBlockHeader h;
        h.nVersion = 1;
        h.hashPrevBlock = params->GenesisBlock().GetHash();
        
        uint256 token_id;
        token_id.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
        uint256 token_hash = Hash(std::span<const uint8_t>(token_id.begin(), token_id.size()));
        uint256 leaf_0 = token_hash;
        uint256 leaf_1 = uint256::ZERO;
        h.payloadRoot = CBlockHeader::ComputePayloadRoot(leaf_0, leaf_1);
        h.vPayload.assign(token_hash.begin(), token_hash.end());

        h.nTime = tmpl1.header.nTime + 120;
        h.nBits = tmpl1.nBits;
        h.nNonce = 0;
        h.hashRandomX.SetNull();

        ValidationState st;
        REQUIRE(csm.ProcessNewBlockHeader(h, st));

        auto tmpl2 = miner.DebugCreateBlockTemplate();
        REQUIRE(tmpl2.nHeight == 2);
        REQUIRE(tmpl2.hashPrevBlock == h.GetHash());
    }

    SECTION("InvalidateTemplate triggers one-shot regeneration request") {
        auto tmpl = miner.DebugCreateBlockTemplate();
        REQUIRE_FALSE(miner.DebugShouldRegenerateTemplate(tmpl.hashPrevBlock));
        miner.InvalidateTemplate();
        REQUIRE(miner.DebugShouldRegenerateTemplate(tmpl.hashPrevBlock));
        REQUIRE_FALSE(miner.DebugShouldRegenerateTemplate(tmpl.hashPrevBlock));
    }
    
    if (std::filesystem::exists(test_dir)) {
        std::filesystem::remove_all(test_dir);
    }
}
