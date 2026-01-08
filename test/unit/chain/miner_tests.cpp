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
#include "chain/chainparams.hpp"
#include "chain/chainstate_manager.hpp"
#include "chain/block.hpp"
#include "chain/validation.hpp"
#include "common/test_chainstate_manager.hpp"
#include "util/uint.hpp"
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
        chainstate = std::make_unique<ChainstateManager>(*params);
        miner = std::make_unique<CPUMiner>(*params, *chainstate);
    }

    ~MinerTestFixture() {
        if (miner && miner->IsMining()) {
            miner->Stop();
        }
    }

    const ChainParams* params;
    std::unique_ptr<ChainstateManager> chainstate;
    std::unique_ptr<CPUMiner> miner;
};

// =============================================================================
// Section 1: Mining Address
// =============================================================================

TEST_CASE("CPUMiner - Mining address management", "[miner]") {
    MinerTestFixture fixture;

    SECTION("Default mining address is null (zero)") {
        uint160 default_addr = fixture.miner->GetMiningAddress();
        REQUIRE(default_addr.IsNull());
        REQUIRE(default_addr == uint160());
    }

    SECTION("SetMiningAddress stores the address") {
        uint160 test_addr;
        test_addr.SetHex("1234567890abcdef1234567890abcdef12345678");

        fixture.miner->SetMiningAddress(test_addr);

        uint160 retrieved = fixture.miner->GetMiningAddress();
        REQUIRE(retrieved == test_addr);
        REQUIRE(retrieved.GetHex() == "1234567890abcdef1234567890abcdef12345678");
    }

    SECTION("Mining address persists across multiple set/get calls") {
        uint160 addr1;
        addr1.SetHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        fixture.miner->SetMiningAddress(addr1);
        REQUIRE(fixture.miner->GetMiningAddress() == addr1);
        REQUIRE(fixture.miner->GetMiningAddress() == addr1);

        uint160 addr2;
        addr2.SetHex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        fixture.miner->SetMiningAddress(addr2);

        REQUIRE(fixture.miner->GetMiningAddress() == addr2);
        REQUIRE(fixture.miner->GetMiningAddress() != addr1);
    }

    SECTION("Can set address to null (zero)") {
        uint160 test_addr;
        test_addr.SetHex("1234567890abcdef1234567890abcdef12345678");
        fixture.miner->SetMiningAddress(test_addr);
        REQUIRE(!fixture.miner->GetMiningAddress().IsNull());

        uint160 null_addr;
        null_addr.SetNull();
        fixture.miner->SetMiningAddress(null_addr);

        REQUIRE(fixture.miner->GetMiningAddress().IsNull());
    }

    SECTION("Different address formats are preserved correctly") {
        uint160 zeros;
        zeros.SetHex("0000000000000000000000000000000000000000");
        fixture.miner->SetMiningAddress(zeros);
        REQUIRE(fixture.miner->GetMiningAddress() == zeros);

        uint160 ones;
        ones.SetHex("ffffffffffffffffffffffffffffffffffffffff");
        fixture.miner->SetMiningAddress(ones);
        REQUIRE(fixture.miner->GetMiningAddress() == ones);

        uint160 mixed;
        mixed.SetHex("0123456789abcdef0123456789abcdef01234567");
        fixture.miner->SetMiningAddress(mixed);
        REQUIRE(fixture.miner->GetMiningAddress() == mixed);
    }
}

TEST_CASE("CPUMiner - Address validation scenarios", "[miner]") {
    MinerTestFixture fixture;

    SECTION("Valid 40-character hex address") {
        uint160 addr;
        addr.SetHex("1234567890abcdef1234567890abcdef12345678");

        fixture.miner->SetMiningAddress(addr);
        REQUIRE(fixture.miner->GetMiningAddress().GetHex() == "1234567890abcdef1234567890abcdef12345678");
    }

    SECTION("Address with uppercase hex characters") {
        uint160 addr;
        addr.SetHex("1234567890ABCDEF1234567890ABCDEF12345678");

        fixture.miner->SetMiningAddress(addr);
        REQUIRE(fixture.miner->GetMiningAddress().GetHex() == "1234567890abcdef1234567890abcdef12345678");
    }

    SECTION("Address with mixed case") {
        uint160 addr;
        addr.SetHex("1234567890AbCdEf1234567890aBcDeF12345678");

        fixture.miner->SetMiningAddress(addr);
        REQUIRE(fixture.miner->GetMiningAddress().GetHex() == "1234567890abcdef1234567890abcdef12345678");
    }
}

TEST_CASE("CPUMiner - Mining address sticky behavior", "[miner]") {
    MinerTestFixture fixture;

    SECTION("Address persists without explicit reset") {
        uint160 addr1;
        addr1.SetHex("1111111111111111111111111111111111111111");
        fixture.miner->SetMiningAddress(addr1);

        REQUIRE(fixture.miner->GetMiningAddress() == addr1);
        REQUIRE(fixture.miner->GetMiningAddress() == addr1);
        REQUIRE(fixture.miner->GetMiningAddress() == addr1);
    }

    SECTION("Address changes only when explicitly set") {
        uint160 addr1;
        addr1.SetHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        uint160 addr2;
        addr2.SetHex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

        fixture.miner->SetMiningAddress(addr1);
        REQUIRE(fixture.miner->GetMiningAddress() == addr1);

        REQUIRE(fixture.miner->GetMiningAddress() == addr1);

        fixture.miner->SetMiningAddress(addr2);
        REQUIRE(fixture.miner->GetMiningAddress() == addr2);
        REQUIRE(fixture.miner->GetMiningAddress() != addr1);
    }

    SECTION("Address survives across mining operations") {
        uint160 test_addr;
        test_addr.SetHex("9999999999999999999999999999999999999999");

        fixture.miner->SetMiningAddress(test_addr);
        REQUIRE(fixture.miner->GetMiningAddress() == test_addr);

        REQUIRE(fixture.miner->GetMiningAddress() == test_addr);

        bool is_mining = fixture.miner->IsMining();
        REQUIRE(!is_mining);
        REQUIRE(fixture.miner->GetMiningAddress() == test_addr);
    }
}

TEST_CASE("CPUMiner - Address format edge cases", "[miner]") {
    MinerTestFixture fixture;

    SECTION("Leading zeros preserved in address") {
        uint160 addr;
        addr.SetHex("0000000000000000000000000000000012345678");

        fixture.miner->SetMiningAddress(addr);

        std::string hex = fixture.miner->GetMiningAddress().GetHex();
        REQUIRE(hex == "0000000000000000000000000000000012345678");
        REQUIRE(hex.length() == 40);
    }

    SECTION("Trailing zeros preserved in address") {
        uint160 addr;
        addr.SetHex("1234567800000000000000000000000000000000");

        fixture.miner->SetMiningAddress(addr);

        std::string hex = fixture.miner->GetMiningAddress().GetHex();
        REQUIRE(hex == "1234567800000000000000000000000000000000");
        REQUIRE(hex.length() == 40);
    }

    SECTION("All zeros is a valid address") {
        uint160 addr;
        addr.SetHex("0000000000000000000000000000000000000000");

        fixture.miner->SetMiningAddress(addr);

        REQUIRE(fixture.miner->GetMiningAddress().IsNull());
        REQUIRE(fixture.miner->GetMiningAddress().GetHex() == "0000000000000000000000000000000000000000");
    }

    SECTION("Maximum value address (all F's)") {
        uint160 addr;
        addr.SetHex("ffffffffffffffffffffffffffffffffffffffff");

        fixture.miner->SetMiningAddress(addr);

        REQUIRE(fixture.miner->GetMiningAddress().GetHex() == "ffffffffffffffffffffffffffffffffffffffff");
    }
}

// =============================================================================
// Section 2: Initial State
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

    SECTION("Initial address is null") {
        REQUIRE(fixture.miner->GetMiningAddress().IsNull());
    }
}

// =============================================================================
// Section 3: Start/Stop
// =============================================================================

TEST_CASE("CPUMiner - Start/Stop and idempotency", "[miner]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);
    REQUIRE(csm.Initialize(params->GenesisBlock()));

    mining::CPUMiner miner(*params, csm);

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
}

// =============================================================================
// Section 4: Block Template
// =============================================================================

TEST_CASE("CPUMiner - DebugCreateBlockTemplate and DebugShouldRegenerateTemplate", "[miner]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);
    REQUIRE(csm.Initialize(params->GenesisBlock()));

    mining::CPUMiner miner(*params, csm);

    SECTION("Template reflects tip and MTP constraint") {
        auto tmpl1 = miner.DebugCreateBlockTemplate();
        REQUIRE(tmpl1.nHeight == 1);
        REQUIRE(tmpl1.hashPrevBlock == params->GenesisBlock().GetHash());
        REQUIRE(tmpl1.header.nTime > static_cast<uint32_t>(params->GenesisBlock().nTime));

        CBlockHeader h;
        h.nVersion = 1;
        h.hashPrevBlock = params->GenesisBlock().GetHash();
        h.minerAddress = uint160();
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
}
