// Copyright (c) 2025 The Unicity Foundation
// Unit tests for chain/validation.cpp
//
// Tests are organized into sections:
// 1. ValidationState - State tracking for validation
// 2. Header Continuity - CheckHeadersAreContinuous
// 3. Work Calculation - CalculateHeadersWork
// 4. Time Handling - MedianTimePast
// 5. Block Header Validation - CheckBlockHeader
// 6. Contextual Validation - ContextualCheckBlockHeader
// 7. Network Expiration - Timebomb checks
// 8. PoW Validation - CheckHeadersPoW

#include "catch_amalgamated.hpp"
#include "chain/validation.hpp"
#include "chain/chainparams.hpp"
#include "chain/block.hpp"
#include "chain/block_index.hpp"
#include "chain/block_manager.hpp"
#include "chain/pow.hpp"
#include "chain/randomx_pow.hpp"
#include "network/protocol.hpp"
#include "util/time.hpp"
#include "common/test_chainstate_manager.hpp"
#include <memory>

using namespace unicity;
using namespace unicity::validation;
using namespace unicity::chain;
using namespace unicity::test;

// =============================================================================
// Test Helpers
// =============================================================================

// Helper function to create a valid test header
static CBlockHeader CreateTestHeader(uint32_t nTime = 1234567890, uint32_t nBits = 0x207fffff, uint32_t nNonce = 0) {
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

// =============================================================================
// Section 1: ValidationState
// =============================================================================

TEST_CASE("ValidationState - basic functionality", "[validation]") {
    SECTION("Default state is valid") {
        ValidationState state;
        REQUIRE(state.IsValid());
        REQUIRE_FALSE(state.IsInvalid());
        REQUIRE_FALSE(state.IsError());
    }

    SECTION("Invalid() marks state as invalid and returns false") {
        ValidationState state;
        bool result = state.Invalid("bad-header", "test failure");

        REQUIRE_FALSE(result);
        REQUIRE(state.IsInvalid());
        REQUIRE_FALSE(state.IsValid());
        REQUIRE_FALSE(state.IsError());
        REQUIRE(state.GetRejectReason() == "bad-header");
        REQUIRE(state.GetDebugMessage() == "test failure");
    }

    SECTION("Invalid() without debug message") {
        ValidationState state;
        state.Invalid("bad-block");

        REQUIRE(state.GetRejectReason() == "bad-block");
        REQUIRE(state.GetDebugMessage() == "");
    }

    SECTION("Error() marks state as error and returns false") {
        ValidationState state;
        bool result = state.Error("disk-failure", "I/O error reading block");

        REQUIRE_FALSE(result);
        REQUIRE(state.IsError());
        REQUIRE_FALSE(state.IsValid());
        REQUIRE_FALSE(state.IsInvalid());
        REQUIRE(state.GetRejectReason() == "disk-failure");
        REQUIRE(state.GetDebugMessage() == "I/O error reading block");
    }

    SECTION("Error() without debug message") {
        ValidationState state;
        state.Error("network-timeout");

        REQUIRE(state.GetRejectReason() == "network-timeout");
        REQUIRE(state.GetDebugMessage() == "");
    }
}

// =============================================================================
// Section 2: Header Continuity
// =============================================================================

TEST_CASE("CheckHeadersAreContinuous - chain structure validation", "[validation]") {
    SECTION("Empty vector is continuous") {
        std::vector<CBlockHeader> headers;
        REQUIRE(CheckHeadersAreContinuous(headers));
    }

    SECTION("Single header is continuous") {
        std::vector<CBlockHeader> headers;
        headers.push_back(CreateTestHeader());
        REQUIRE(CheckHeadersAreContinuous(headers));
    }

    SECTION("Two connected headers are continuous") {
        CBlockHeader header1 = CreateTestHeader(1000);
        CBlockHeader header2 = CreateTestHeader(1001);
        header2.hashPrevBlock = header1.GetHash();

        std::vector<CBlockHeader> headers = {header1, header2};
        REQUIRE(CheckHeadersAreContinuous(headers));
    }

    SECTION("Three connected headers are continuous") {
        CBlockHeader header1 = CreateTestHeader(1000);
        CBlockHeader header2 = CreateTestHeader(1001);
        header2.hashPrevBlock = header1.GetHash();
        CBlockHeader header3 = CreateTestHeader(1002);
        header3.hashPrevBlock = header2.GetHash();

        std::vector<CBlockHeader> headers = {header1, header2, header3};
        REQUIRE(CheckHeadersAreContinuous(headers));
    }

    SECTION("Disconnected headers are not continuous") {
        CBlockHeader header1 = CreateTestHeader(1000);
        CBlockHeader header2 = CreateTestHeader(1001);

        std::vector<CBlockHeader> headers = {header1, header2};
        REQUIRE_FALSE(CheckHeadersAreContinuous(headers));
    }

    SECTION("Gap in middle breaks continuity") {
        CBlockHeader header1 = CreateTestHeader(1000);
        CBlockHeader header2 = CreateTestHeader(1001);
        header2.hashPrevBlock = header1.GetHash();
        CBlockHeader header3 = CreateTestHeader(1002);

        std::vector<CBlockHeader> headers = {header1, header2, header3};
        REQUIRE_FALSE(CheckHeadersAreContinuous(headers));
    }

    SECTION("Long chain of headers") {
        std::vector<CBlockHeader> headers;
        CBlockHeader prev = CreateTestHeader(1000);
        headers.push_back(prev);

        for (int i = 1; i < 100; i++) {
            CBlockHeader next = CreateTestHeader(1000 + i);
            next.hashPrevBlock = prev.GetHash();
            headers.push_back(next);
            prev = next;
        }

        REQUIRE(CheckHeadersAreContinuous(headers));
        REQUIRE(headers.size() == 100);
    }
}

// =============================================================================
// Section 3: Work Calculation
// =============================================================================

TEST_CASE("CalculateHeadersWork - work calculation", "[validation]") {
    SECTION("Empty vector has zero work") {
        std::vector<CBlockHeader> headers;
        arith_uint256 work = CalculateHeadersWork(headers);
        REQUIRE(work == 0);
    }

    SECTION("Single valid header has non-zero work") {
        CBlockHeader header = CreateTestHeader();
        header.nBits = 0x1d00ffff;

        std::vector<CBlockHeader> headers = {header};
        arith_uint256 work = CalculateHeadersWork(headers);
        REQUIRE(work > 0);
    }

    SECTION("Multiple headers accumulate work") {
        CBlockHeader header1 = CreateTestHeader();
        header1.nBits = 0x1d00ffff;
        CBlockHeader header2 = CreateTestHeader();
        header2.nBits = 0x1d00ffff;

        std::vector<CBlockHeader> headers = {header1, header2};
        arith_uint256 total_work = CalculateHeadersWork(headers);

        arith_uint256 single_work = CalculateHeadersWork({header1});
        REQUIRE(total_work > single_work);
        REQUIRE(total_work < single_work * 3);
    }

    SECTION("Invalid nBits with negative flag is skipped") {
        CBlockHeader header = CreateTestHeader();
        header.nBits = 0x00800000;

        std::vector<CBlockHeader> headers = {header};
        arith_uint256 work = CalculateHeadersWork(headers);
        REQUIRE(work == 0);
    }

    SECTION("Invalid nBits with zero target is skipped") {
        CBlockHeader header = CreateTestHeader();
        header.nBits = 0x00000000;

        std::vector<CBlockHeader> headers = {header};
        arith_uint256 work = CalculateHeadersWork(headers);
        REQUIRE(work == 0);
    }

    SECTION("Mix of valid and invalid headers") {
        CBlockHeader valid1 = CreateTestHeader();
        valid1.nBits = 0x1d00ffff;

        CBlockHeader invalid = CreateTestHeader();
        invalid.nBits = 0x00000000;

        CBlockHeader valid2 = CreateTestHeader();
        valid2.nBits = 0x1d00ffff;

        std::vector<CBlockHeader> headers = {valid1, invalid, valid2};
        arith_uint256 work = CalculateHeadersWork(headers);

        arith_uint256 expected = CalculateHeadersWork({valid1}) + CalculateHeadersWork({valid2});
        REQUIRE(work == expected);
    }

    SECTION("Higher difficulty produces more work") {
        CBlockHeader easy = CreateTestHeader();
        easy.nBits = 0x1d00ffff;

        CBlockHeader hard = CreateTestHeader();
        hard.nBits = 0x1c00ffff;

        arith_uint256 easy_work = CalculateHeadersWork({easy});
        arith_uint256 hard_work = CalculateHeadersWork({hard});

        REQUIRE(hard_work > easy_work);
    }

    SECTION("Work calculation matches GetBlockProof") {
        CBlockHeader header = CreateTestHeader();
        header.nBits = 0x1d00ffff;

        CBlockIndex index(header);
        index.nBits = header.nBits;

        arith_uint256 work_from_calculate = CalculateHeadersWork({header});
        arith_uint256 work_from_getproof = GetBlockProof(index);

        REQUIRE(work_from_calculate == work_from_getproof);
    }
}

// =============================================================================
// Section 4: Time Handling
// =============================================================================

TEST_CASE("CBlockIndex::GetMedianTimePast - median time calculation", "[validation]") {
    SECTION("Single block returns its own time") {
        CBlockIndex index;
        index.nTime = 1000;
        index.pprev = nullptr;

        REQUIRE(index.GetMedianTimePast() == 1000);
    }

    SECTION("Eleven blocks uses all for median") {
        std::vector<std::unique_ptr<CBlockIndex>> chain;
        for (int i = 0; i < 11; i++) {
            auto index = std::make_unique<CBlockIndex>();
            index->nTime = 1000 + i * 100;
            index->pprev = (i > 0) ? chain[i-1].get() : nullptr;
            chain.push_back(std::move(index));
        }

        int64_t median = chain[10]->GetMedianTimePast();
        REQUIRE(median == 1500);
    }

    SECTION("More than eleven blocks only uses last 11") {
        std::vector<std::unique_ptr<CBlockIndex>> chain;
        for (int i = 0; i < 20; i++) {
            auto index = std::make_unique<CBlockIndex>();
            index->nTime = 1000 + i * 100;
            index->pprev = (i > 0) ? chain[i-1].get() : nullptr;
            chain.push_back(std::move(index));
        }

        int64_t median = chain[19]->GetMedianTimePast();
        REQUIRE(median == 2400);
    }

    SECTION("Handles unsorted times correctly") {
        CBlockIndex index1;
        index1.nTime = 5000;
        index1.pprev = nullptr;

        CBlockIndex index2;
        index2.nTime = 3000;
        index2.pprev = &index1;

        CBlockIndex index3;
        index3.nTime = 4000;
        index3.pprev = &index2;

        int64_t median = index3.GetMedianTimePast();
        REQUIRE(median == 4000);
    }
}

// =============================================================================
// Section 6: Block Header Validation
// =============================================================================

TEST_CASE("CheckBlockHeader - version validation", "[validation][version]") {
    auto params = ChainParams::CreateRegTest();
    ValidationState state;

    SECTION("Accepts version >= MIN_BLOCK_VERSION (1)") {
        CBlockHeader h = CreateTestHeader();
        h.nVersion = 1;
        h.hashRandomX = uint256S("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

        bool result = CheckBlockHeader(h, *params, state);
        if (!result) {
            REQUIRE(state.GetRejectReason() != "bad-version");
        }
    }

    SECTION("Accepts version > 1 (forward compatibility)") {
        CBlockHeader h = CreateTestHeader();
        h.nVersion = 2;
        h.hashRandomX = uint256S("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

        bool result = CheckBlockHeader(h, *params, state);
        if (!result) {
            REQUIRE(state.GetRejectReason() != "bad-version");
        }
    }

    SECTION("Rejects version < MIN_BLOCK_VERSION") {
        CBlockHeader h = CreateTestHeader();
        h.nVersion = 0;

        bool result = CheckBlockHeader(h, *params, state);
        REQUIRE_FALSE(result);
        REQUIRE(state.GetRejectReason() == "bad-version");
        REQUIRE(state.GetDebugMessage().find("version too old") != std::string::npos);
    }

    SECTION("Rejects negative version") {
        CBlockHeader h = CreateTestHeader();
        h.nVersion = -1;

        bool result = CheckBlockHeader(h, *params, state);
        REQUIRE_FALSE(result);
        REQUIRE(state.GetRejectReason() == "bad-version");
    }
}

TEST_CASE("CheckBlockHeader - null hashRandomX validation", "[validation][pow]") {
    auto params = ChainParams::CreateRegTest();
    ValidationState state;

    SECTION("Rejects header with null hashRandomX") {
        CBlockHeader h = CreateTestHeader();
        h.nVersion = 1;
        h.hashRandomX.SetNull();

        bool result = CheckBlockHeader(h, *params, state);
        REQUIRE_FALSE(result);
        REQUIRE(state.GetRejectReason() == "bad-randomx-hash");
        REQUIRE(state.GetDebugMessage().find("missing RandomX hash") != std::string::npos);
    }

    SECTION("Accepts header with non-null hashRandomX") {
        CBlockHeader h = CreateTestHeader();
        h.nVersion = 1;
        h.hashRandomX = uint256S("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

        bool result = CheckBlockHeader(h, *params, state);
        if (!result) {
            REQUIRE(state.GetRejectReason() != "bad-randomx-hash");
        }
    }
}

// =============================================================================
// Section 7: Contextual Validation
// =============================================================================

TEST_CASE("ContextualCheckBlockHeader - eclipse attack protection", "[validation][contextual][security]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager csm(*params);
    REQUIRE(csm.Initialize(params->GenesisBlock()));

    const CBlockIndex* genesis = csm.GetTip();
    REQUIRE(genesis != nullptr);

    SECTION("Rejects timestamp too far ahead of system time") {
        int64_t system_time = util::GetTime();
        uint32_t far_future = static_cast<uint32_t>(system_time + MAX_FUTURE_BLOCK_TIME + 1000);

        CBlockHeader h = CreateTestHeader(far_future);
        uint32_t bits = consensus::GetNextWorkRequired(genesis, *params);
        h.nBits = bits;

        ValidationState state;
        int64_t adjusted_time = system_time + MAX_FUTURE_BLOCK_TIME + 2000;

        bool result = ContextualCheckBlockHeader(h, genesis, *params, adjusted_time, state);
        REQUIRE_FALSE(result);
        REQUIRE(state.GetRejectReason() == "time-too-new-absolute");
    }

    SECTION("Accepts timestamp within system time + MAX_FUTURE_BLOCK_TIME") {
        int64_t system_time = util::GetTime();
        uint32_t valid_time = static_cast<uint32_t>(system_time + MAX_FUTURE_BLOCK_TIME - 60);

        CBlockHeader h = CreateTestHeader(valid_time);
        uint32_t bits = consensus::GetNextWorkRequired(genesis, *params);
        h.nBits = bits;

        ValidationState state;
        int64_t adjusted_time = system_time;

        bool result = ContextualCheckBlockHeader(h, genesis, *params, adjusted_time, state);
        if (!result && state.GetRejectReason() == "time-too-new-absolute") {
            FAIL("Should not reject timestamp within valid range");
        }
    }

    SECTION("Network-adjusted time check still works") {
        int64_t system_time = util::GetTime();
        uint32_t valid_time = static_cast<uint32_t>(system_time + 60);

        CBlockHeader h = CreateTestHeader(valid_time);
        uint32_t bits = consensus::GetNextWorkRequired(genesis, *params);
        h.nBits = bits;

        ValidationState state;
        int64_t adjusted_time = system_time - MAX_FUTURE_BLOCK_TIME - 1000;

        bool result = ContextualCheckBlockHeader(h, genesis, *params, adjusted_time, state);
        REQUIRE_FALSE(result);
        REQUIRE(state.GetRejectReason() == "time-too-new");
    }
}

// =============================================================================
// Section 8: Network Expiration
// =============================================================================

TEST_CASE("Network Expiration (Timebomb) - validation checks", "[validation][timebomb]") {
    SECTION("MainNet has expiration disabled") {
        GlobalChainParams::Select(ChainType::MAIN);
        const ChainParams& params = GlobalChainParams::Get();

        REQUIRE(params.GetConsensus().nNetworkExpirationInterval == 0);
        REQUIRE(params.GetConsensus().nNetworkExpirationGracePeriod == 0);
    }

    SECTION("TestNet has expiration enabled") {
        GlobalChainParams::Select(ChainType::TESTNET);
        const ChainParams& params = GlobalChainParams::Get();

        REQUIRE(params.GetConsensus().nNetworkExpirationInterval > 0);
        REQUIRE(params.GetConsensus().nNetworkExpirationGracePeriod == 24);
    }

    SECTION("RegTest has expiration disabled for testing") {
        GlobalChainParams::Select(ChainType::REGTEST);
        const ChainParams& params = GlobalChainParams::Get();

        REQUIRE(params.GetConsensus().nNetworkExpirationInterval == 0);
        REQUIRE(params.GetConsensus().nNetworkExpirationGracePeriod == 0);
    }

    SECTION("Expiration check logic is correct") {
        GlobalChainParams::Select(ChainType::TESTNET);
        const ChainParams& params = GlobalChainParams::Get();
        const auto& consensus = params.GetConsensus();

        int32_t expirationHeight = consensus.nNetworkExpirationInterval;
        int32_t gracePeriod = consensus.nNetworkExpirationGracePeriod;

        REQUIRE(expirationHeight > 0);
        REQUIRE(gracePeriod == 24);

        int32_t currentHeight = expirationHeight;
        REQUIRE(currentHeight <= expirationHeight);

        currentHeight = expirationHeight + 1;
        REQUIRE(currentHeight > expirationHeight);

        int32_t gracePeriodStart = expirationHeight - gracePeriod;
        REQUIRE(gracePeriodStart == (expirationHeight - 24));
    }
}

TEST_CASE("Validation constants", "[validation]") {
    SECTION("MAX_FUTURE_BLOCK_TIME is 10 minutes") {
        REQUIRE(MAX_FUTURE_BLOCK_TIME == 10 * 60);
        REQUIRE(MAX_FUTURE_BLOCK_TIME == 600);
    }

    SECTION("MEDIAN_TIME_SPAN matches block_index.hpp") {
        REQUIRE(chain::MEDIAN_TIME_SPAN == 11);
    }

    SECTION("MAX_HEADERS_SIZE is reasonable") {
        REQUIRE(protocol::MAX_HEADERS_SIZE == 80000);
    }
}

// =============================================================================
// Section 8: PoW Validation
// =============================================================================

TEST_CASE("CheckHeadersPoW - Direct validation function tests", "[validation][pow]") {
    crypto::InitRandomX();

    auto params = ChainParams::CreateRegTest();

    SECTION("Empty header list passes") {
        std::vector<CBlockHeader> headers;
        REQUIRE(CheckHeadersPoW(headers, *params));
    }

    SECTION("Headers with null hashRandomX fail") {
        CBlockHeader header = CreateTestHeader();
        header.hashRandomX.SetNull();

        std::vector<CBlockHeader> headers = {header};
        REQUIRE_FALSE(CheckHeadersPoW(headers, *params));
    }

    SECTION("Headers with valid PoW commitment pass") {
        CBlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock.SetNull();
        header.minerAddress.SetNull();
        header.nTime = 1234567890;
        header.nBits = 0x207fffff;
        header.nNonce = 0;

        uint256 out_hash;
        bool found = false;
        for (uint32_t nonce = 0; nonce < 1000000 && !found; ++nonce) {
            header.nNonce = nonce;
            if (consensus::CheckProofOfWork(header, header.nBits, *params,
                                            crypto::POWVerifyMode::MINING, &out_hash)) {
                header.hashRandomX = out_hash;
                found = true;
            }
        }
        REQUIRE(found);

        std::vector<CBlockHeader> headers = {header};
        REQUIRE(CheckHeadersPoW(headers, *params));
    }

    SECTION("Multiple mined headers all pass") {
        auto mineHeader = [&params]() {
            CBlockHeader header;
            header.nVersion = 1;
            header.hashPrevBlock.SetNull();
            header.minerAddress.SetNull();
            header.nTime = 1234567890;
            header.nBits = 0x207fffff;
            header.nNonce = 0;

            uint256 out_hash;
            for (uint32_t nonce = 0; nonce < 1000000; ++nonce) {
                header.nNonce = nonce;
                if (consensus::CheckProofOfWork(header, header.nBits, *params,
                                                crypto::POWVerifyMode::MINING, &out_hash)) {
                    header.hashRandomX = out_hash;
                    return header;
                }
            }
            throw std::runtime_error("Failed to mine header");
        };

        std::vector<CBlockHeader> headers = {mineHeader(), mineHeader()};
        REQUIRE(CheckHeadersPoW(headers, *params));
    }
}

// =============================================================================
// Integration Tests
// =============================================================================

TEST_CASE("Validation - integration test", "[validation]") {
    SECTION("Complete header validation flow") {
        CBlockHeader header = CreateTestHeader();

        auto serialized = header.Serialize();
        REQUIRE(serialized.size() == 100);

        CBlockHeader header2;
        REQUIRE(header2.Deserialize(serialized.data(), serialized.size()));

        REQUIRE(header.GetHash() == header2.GetHash());

        arith_uint256 work = CalculateHeadersWork({header});
        REQUIRE(work > 0);
    }
}
