#include "catch_amalgamated.hpp"
#include "chain/block.hpp"
#include "util/endian.hpp"
#include <array>
#include <cstdint>
#include <random>
#include <vector>
#include <algorithm>

TEST_CASE("CBlockHeader fuzz: random 100-byte round-trip preserves bytes", "[block][serialize][fuzz]") {
    std::mt19937 rng(0xC01DBA5Eu);
    std::uniform_int_distribution<int> dist(0, 255);

    for (int iter = 0; iter < 64; ++iter) {
        std::vector<uint8_t> bytes(CBlockHeader::HEADER_SIZE);
        for (auto &b : bytes) b = static_cast<uint8_t>(dist(rng));

        CBlockHeader h;
        REQUIRE(h.Deserialize(bytes.data(), bytes.size()));

        auto out = h.Serialize();
        REQUIRE(out.size() == bytes.size());
        REQUIRE(std::equal(out.begin(), out.end(), bytes.begin()));

        // Hash should be deterministic
        REQUIRE(h.GetHash() == h.GetHash());
    }
}

TEST_CASE("CBlockHeader deserialization strict size checks (truncated/oversized)", "[block][serialize]") {
    // All sizes below HEADER_SIZE must be rejected
    for (size_t sz = 0; sz < CBlockHeader::HEADER_SIZE; ++sz) {
        std::vector<uint8_t> v(sz, 0xAA);
        CBlockHeader h;
        REQUIRE_FALSE(h.Deserialize(v.data(), v.size()));
    }

    // Exact size is accepted
    {
        std::vector<uint8_t> v(CBlockHeader::HEADER_SIZE, 0);
        CBlockHeader h;
        REQUIRE(h.Deserialize(v.data(), v.size()));
    }

    // Oversized buffers must be rejected regardless of content
    const size_t oversizes[] = {101, 128, 256, 1000};
    for (size_t sz : oversizes) {
        std::vector<uint8_t> v(sz, 0xBB);
        CBlockHeader h;
        REQUIRE_FALSE(h.Deserialize(v.data(), v.size()));
    }
}

static CBlockHeader MakeBaselineHeader() {
    CBlockHeader base;
    base.nVersion = 0x11223344;
    base.nTime    = 0x55667788;
    base.nBits    = 0x1d00ffff;
    base.nNonce   = 0xA1B2C3D4;
    for (int i = 0; i < 32; ++i) {
        base.hashPrevBlock.begin()[i] = static_cast<uint8_t>(i);
        base.hashRandomX.begin()[i]   = static_cast<uint8_t>(255 - i);
    }
    for (int i = 0; i < 20; ++i) {
        base.minerAddress.begin()[i] = static_cast<uint8_t>(0xAA + i);
    }
    return base;
}

TEST_CASE("CBlockHeader corrupted-field cases flip single byte in each field", "[block][serialize][corruption]") {
    const CBlockHeader base = MakeBaselineHeader();
    const auto baseline_bytes = base.Serialize();
    const uint256 base_hash = base.GetHash();

    // Helper to mutate a single byte and assert expected field changed
    auto mutate_and_check = [&](size_t offset, const char* name, auto check_field_changed) {
        std::vector<uint8_t> mutated(baseline_bytes.begin(), baseline_bytes.end());
        mutated[offset] ^= 0x01; // flip lowest bit to ensure change

        CBlockHeader h2;
        REQUIRE(h2.Deserialize(mutated.data(), mutated.size()));

        // Field-specific assertions provided by caller
        check_field_changed(h2);

        // Re-serialize must exactly equal mutated bytes
        auto out = h2.Serialize();
        REQUIRE(std::equal(out.begin(), out.end(), mutated.begin()));

        // Hash should almost certainly change
        REQUIRE(h2.GetHash() != base_hash);
    };

    // nVersion
    mutate_and_check(CBlockHeader::OFF_VERSION, "nVersion", [&](const CBlockHeader& h2){
        REQUIRE(h2.nVersion != base.nVersion);
    });

    // hashPrevBlock (first byte)
    mutate_and_check(CBlockHeader::OFF_PREV, "hashPrevBlock", [&](const CBlockHeader& h2){
        REQUIRE(h2.hashPrevBlock != base.hashPrevBlock);
    });

    // minerAddress (first byte)
    mutate_and_check(CBlockHeader::OFF_MINER, "minerAddress", [&](const CBlockHeader& h2){
        REQUIRE(h2.minerAddress != base.minerAddress);
    });

    // nTime
    mutate_and_check(CBlockHeader::OFF_TIME, "nTime", [&](const CBlockHeader& h2){
        REQUIRE(h2.nTime != base.nTime);
    });

    // nBits
    mutate_and_check(CBlockHeader::OFF_BITS, "nBits", [&](const CBlockHeader& h2){
        REQUIRE(h2.nBits != base.nBits);
    });

    // nNonce
    mutate_and_check(CBlockHeader::OFF_NONCE, "nNonce", [&](const CBlockHeader& h2){
        REQUIRE(h2.nNonce != base.nNonce);
    });

    // hashRandomX (first byte)
    mutate_and_check(CBlockHeader::OFF_RANDOMX, "hashRandomX", [&](const CBlockHeader& h2){
        REQUIRE(h2.hashRandomX != base.hashRandomX);
    });
}

TEST_CASE("CBlockHeader extreme/invalid scalar values (nVersion/nBits) round-trip", "[block][serialize][edge]") {
    // Test a set of edge-case values that are semantically invalid for consensus
    // but must serialize/deserialize exactly without crashing or altering bytes.
    const int32_t versions[] = {0, -1, std::numeric_limits<int32_t>::min(), std::numeric_limits<int32_t>::max(), 1};
    const uint32_t bits_values[] = {
        0x00000000u, // zero mantissa
        0x01000000u, // minimal exponent with zero mantissa
        0xFF7FFFFFu, // large exponent (likely overflow if used)
        0x207FFFFFu, // regtest-like easy target
        0x1D00FFFFu  // bitcoin-style pow limit
    };

    for (int32_t ver : versions) {
        for (uint32_t bits : bits_values) {
            CBlockHeader h;
            h.nVersion = ver;
            h.nTime = 0x01020304u;
            h.nBits = bits;
            h.nNonce = 0xAABBCCDDu;
            h.hashPrevBlock.SetNull();
            h.minerAddress.SetNull();
            h.hashRandomX.SetNull();

            auto bytes = h.Serialize();
            REQUIRE(bytes.size() == CBlockHeader::HEADER_SIZE);

            CBlockHeader h2;
            REQUIRE(h2.Deserialize(bytes.data(), bytes.size()));

            // Exact value preservation
            REQUIRE(h2.nVersion == ver);
            REQUIRE(h2.nTime == 0x01020304u);
            REQUIRE(h2.nBits == bits);
            REQUIRE(h2.nNonce == 0xAABBCCDDu);

            // Hash deterministic
            REQUIRE(h2.GetHash() == h2.GetHash());
        }
    }
}
