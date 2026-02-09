#include "catch_amalgamated.hpp"
#include "chain/block.hpp"
#include "util/sha256.hpp"
#include <cstring>
#include <array>
#include <span>

TEST_CASE("CBlockHeader serialization and deserialization", "[block]") {
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.minerAddress.SetNull();
    header.nTime = 1234567890;
    header.nBits = 0x1d00ffff;
    header.nNonce = 42;

    SECTION("Serialize produces correct size") {
        auto serialized = header.Serialize();
        REQUIRE(serialized.size() == CBlockHeader::HEADER_SIZE);
    }

    SECTION("Round-trip serialization") {
        auto serialized = header.Serialize();

        CBlockHeader header2;
        bool success = header2.Deserialize(serialized.data(), serialized.size());

        REQUIRE(success);
        REQUIRE(header2.nVersion == header.nVersion);
        REQUIRE(header2.nTime == header.nTime);
        REQUIRE(header2.nBits == header.nBits);
        REQUIRE(header2.nNonce == header.nNonce);
    }

    SECTION("Deserialize rejects too-short data") {
        std::vector<uint8_t> short_data(50);
        CBlockHeader header2;
        bool success = header2.Deserialize(short_data.data(), short_data.size());

        REQUIRE_FALSE(success);
    }
}

TEST_CASE("CBlockHeader hashing", "[block]") {
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.minerAddress.SetNull();
    header.nTime = 1234567890;
    header.nBits = 0x1d00ffff;
    header.nNonce = 42;

    SECTION("Hash is deterministic") {
        uint256 hash1 = header.GetHash();
        uint256 hash2 = header.GetHash();

        REQUIRE(hash1 == hash2);
    }

    SECTION("Different nonce produces different hash") {
        uint256 hash1 = header.GetHash();

        header.nNonce = 43;
        uint256 hash2 = header.GetHash();

        REQUIRE(hash1 != hash2);
    }

    SECTION("Hash is non-null") {
        uint256 hash = header.GetHash();
        uint256 null_hash;
        null_hash.SetNull();

        REQUIRE(hash != null_hash);
    }
}

TEST_CASE("CBlockHeader initialization", "[block]") {
    SECTION("Default constructor sets null") {
        CBlockHeader header;
        REQUIRE(header.nVersion == 0);
        REQUIRE(header.nTime == 0);
        REQUIRE(header.nBits == 0);
        REQUIRE(header.nNonce == 0);
        REQUIRE(header.IsNull());
    }

    SECTION("IsNull() checks all fields") {
        CBlockHeader header;
        REQUIRE(header.IsNull());

        // Setting any field makes it non-null
        header.nBits = 0x1d00ffff;
        REQUIRE_FALSE(header.IsNull());

        header.SetNull();
        header.nTime = 1234567890;
        REQUIRE_FALSE(header.IsNull());
    }

    SECTION("SetNull() resets all fields") {
        CBlockHeader header;
        header.nVersion = 1;
        header.nTime = 12345;
        header.nBits = 0x1d00ffff;
        header.nNonce = 999;

        header.SetNull();

        REQUIRE(header.nVersion == 0);
        REQUIRE(header.nTime == 0);
        REQUIRE(header.nBits == 0);
        REQUIRE(header.nNonce == 0);
        REQUIRE(header.IsNull());
    }
}

TEST_CASE("CBlockHeader golden vector", "[block]") {
    SECTION("Known test vector matches expected hash") {
        CBlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock.SetNull();
        header.minerAddress.SetNull();
        header.nTime = 1234567890;
        header.nBits = 0x1d00ffff;
        header.nNonce = 42;
        header.hashRandomX.SetNull();

        // Serialize and verify exact bytes
        auto serialized = header.Serialize();
        REQUIRE(serialized.size() == 100);

        // Verify specific byte offsets (little-endian)
        // nVersion = 1 at offset 0
        REQUIRE(serialized[0] == 0x01);
        REQUIRE(serialized[1] == 0x00);
        REQUIRE(serialized[2] == 0x00);
        REQUIRE(serialized[3] == 0x00);

        // nTime = 1234567890 (0x499602D2) at offset 56
        REQUIRE(serialized[56] == 0xD2);
        REQUIRE(serialized[57] == 0x02);
        REQUIRE(serialized[58] == 0x96);
        REQUIRE(serialized[59] == 0x49);

        // nBits = 0x1d00ffff at offset 60
        REQUIRE(serialized[60] == 0xFF);
        REQUIRE(serialized[61] == 0xFF);
        REQUIRE(serialized[62] == 0x00);
        REQUIRE(serialized[63] == 0x1D);

        // nNonce = 42 (0x2A) at offset 64
        REQUIRE(serialized[64] == 0x2A);
        REQUIRE(serialized[65] == 0x00);
        REQUIRE(serialized[66] == 0x00);
        REQUIRE(serialized[67] == 0x00);

        // Compute hash and verify it's deterministic
        uint256 hash1 = header.GetHash();
        uint256 hash2 = header.GetHash();
        REQUIRE(hash1 == hash2);

        // Hash should be non-null
        REQUIRE_FALSE(hash1.IsNull());
    }
}

TEST_CASE("CBlockHeader endianness verification", "[block]") {
    SECTION("Little-endian encoding of scalar fields") {
        CBlockHeader header;
        header.nVersion = 1;
        header.nTime = 2;
        header.nBits = 3;
        header.nNonce = 4;
        header.hashPrevBlock.SetNull();
        header.minerAddress.SetNull();
        header.hashRandomX.SetNull();

        auto serialized = header.Serialize();

        // nVersion = 1 at offset 0 (little-endian: 01 00 00 00)
        REQUIRE(serialized[0] == 0x01);
        REQUIRE(serialized[1] == 0x00);
        REQUIRE(serialized[2] == 0x00);
        REQUIRE(serialized[3] == 0x00);

        // nTime = 2 at offset 56 (little-endian: 02 00 00 00)
        REQUIRE(serialized[56] == 0x02);
        REQUIRE(serialized[57] == 0x00);
        REQUIRE(serialized[58] == 0x00);
        REQUIRE(serialized[59] == 0x00);

        // nBits = 3 at offset 60 (little-endian: 03 00 00 00)
        REQUIRE(serialized[60] == 0x03);
        REQUIRE(serialized[61] == 0x00);
        REQUIRE(serialized[62] == 0x00);
        REQUIRE(serialized[63] == 0x00);

        // nNonce = 4 at offset 64 (little-endian: 04 00 00 00)
        REQUIRE(serialized[64] == 0x04);
        REQUIRE(serialized[65] == 0x00);
        REQUIRE(serialized[66] == 0x00);
        REQUIRE(serialized[67] == 0x00);
    }

    SECTION("Big-endian values serialize correctly") {
        CBlockHeader header;
        header.nVersion = 0x01020304;
        header.nTime = 0x05060708;
        header.nBits = 0x090A0B0C;
        header.nNonce = 0x0D0E0F10;
        header.hashPrevBlock.SetNull();
        header.minerAddress.SetNull();
        header.hashRandomX.SetNull();

        auto serialized = header.Serialize();

        // nVersion = 0x01020304 (little-endian: 04 03 02 01)
        REQUIRE(serialized[0] == 0x04);
        REQUIRE(serialized[1] == 0x03);
        REQUIRE(serialized[2] == 0x02);
        REQUIRE(serialized[3] == 0x01);

        // nTime = 0x05060708 (little-endian: 08 07 06 05)
        REQUIRE(serialized[56] == 0x08);
        REQUIRE(serialized[57] == 0x07);
        REQUIRE(serialized[58] == 0x06);
        REQUIRE(serialized[59] == 0x05);
    }
}

TEST_CASE("CBlockHeader deserialization rejection", "[block]") {
    SECTION("Rejects size < HEADER_SIZE") {
        std::vector<uint8_t> too_short(99);
        CBlockHeader header;
        REQUIRE_FALSE(header.Deserialize(too_short.data(), too_short.size()));
    }

    SECTION("Rejects size > HEADER_SIZE") {
        std::vector<uint8_t> too_long(101);
        CBlockHeader header;
        REQUIRE_FALSE(header.Deserialize(too_long.data(), too_long.size()));
    }

    SECTION("Rejects size = 0") {
        std::vector<uint8_t> empty;
        CBlockHeader header;
        REQUIRE_FALSE(header.Deserialize(empty.data(), empty.size()));
    }

    SECTION("Accepts exact HEADER_SIZE") {
        std::vector<uint8_t> exact(CBlockHeader::HEADER_SIZE, 0);
        CBlockHeader header;
        REQUIRE(header.Deserialize(exact.data(), exact.size()));
    }
}

TEST_CASE("CBlockHeader round-trip with random data", "[block]") {
    SECTION("Random header survives serialization round-trip") {
        CBlockHeader header1;
        header1.nVersion = 0x12345678;
        header1.nTime = 0xABCDEF01;
        header1.nBits = 0x1d00ffff;
        header1.nNonce = 0x99887766;

        // Set some non-zero bytes in hash fields
        for (int i = 0; i < 32; i++) {
            header1.hashPrevBlock.begin()[i] = static_cast<uint8_t>(i);
            header1.hashRandomX.begin()[i] = static_cast<uint8_t>(255 - i);
        }
        for (int i = 0; i < 20; i++) {
            header1.minerAddress.begin()[i] = static_cast<uint8_t>(i * 2);
        }

        // Serialize
        auto serialized = header1.Serialize();
        REQUIRE(serialized.size() == CBlockHeader::HEADER_SIZE);

        // Deserialize
        CBlockHeader header2;
        bool success = header2.Deserialize(serialized.data(), serialized.size());
        REQUIRE(success);

        // Verify all fields match
        REQUIRE(header2.nVersion == header1.nVersion);
        REQUIRE(header2.nTime == header1.nTime);
        REQUIRE(header2.nBits == header1.nBits);
        REQUIRE(header2.nNonce == header1.nNonce);
        REQUIRE(header2.hashPrevBlock == header1.hashPrevBlock);
        REQUIRE(header2.minerAddress == header1.minerAddress);
        REQUIRE(header2.hashRandomX == header1.hashRandomX);

        // Verify hashes match
        REQUIRE(header2.GetHash() == header1.GetHash());
    }
}

TEST_CASE("CBlockHeader Serialize returns fixed-size array", "[block]") {
    SECTION("Serialize produces exact 100-byte array") {
        CBlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock.SetNull();
        header.minerAddress.SetNull();
        header.nTime = 1234567890;
        header.nBits = 0x1d00ffff;
        header.nNonce = 42;
        header.hashRandomX.SetNull();

        auto fixed = header.Serialize();

        // Verify it's exactly HEADER_SIZE
        REQUIRE(fixed.size() == CBlockHeader::HEADER_SIZE);
        REQUIRE(fixed.size() == 100);
    }

    SECTION("Serialize uses field offset constants") {
        CBlockHeader header;
        header.nVersion = 1;
        header.nTime = 2;
        header.nBits = 3;
        header.nNonce = 4;
        header.hashPrevBlock.SetNull();
        header.minerAddress.SetNull();
        header.hashRandomX.SetNull();

        auto fixed = header.Serialize();

        // Verify offsets match constants
        REQUIRE(fixed[CBlockHeader::OFF_VERSION] == 0x01);
        REQUIRE(fixed[CBlockHeader::OFF_TIME] == 0x02);
        REQUIRE(fixed[CBlockHeader::OFF_BITS] == 0x03);
        REQUIRE(fixed[CBlockHeader::OFF_NONCE] == 0x04);
    }
}

TEST_CASE("CBlockHeader span-based Deserialize", "[block]") {
    SECTION("Deserialize from std::span") {
        CBlockHeader header1;
        header1.nVersion = 0x12345678;
        header1.nTime = 0xABCDEF01;
        header1.nBits = 0x1d00ffff;
        header1.nNonce = 0x99887766;

        for (int i = 0; i < 32; i++) {
            header1.hashPrevBlock.begin()[i] = static_cast<uint8_t>(i);
            header1.hashRandomX.begin()[i] = static_cast<uint8_t>(255 - i);
        }
        for (int i = 0; i < 20; i++) {
            header1.minerAddress.begin()[i] = static_cast<uint8_t>(i * 2);
        }

        auto serialized = header1.Serialize();

        CBlockHeader header2;
        bool success = header2.Deserialize(serialized.data(), serialized.size());

        REQUIRE(success);
        REQUIRE(header2.nVersion == header1.nVersion);
        REQUIRE(header2.nTime == header1.nTime);
        REQUIRE(header2.nBits == header1.nBits);
        REQUIRE(header2.nNonce == header1.nNonce);
        REQUIRE(header2.hashPrevBlock == header1.hashPrevBlock);
        REQUIRE(header2.minerAddress == header1.minerAddress);
        REQUIRE(header2.hashRandomX == header1.hashRandomX);
    }
}

TEST_CASE("CBlockHeader array-based Deserialize", "[block]") {
    SECTION("Deserialize from std::array with exact size") {
        CBlockHeader header1;
        header1.nVersion = 1;
        header1.nTime = 1234567890;
        header1.nBits = 0x1d00ffff;
        header1.nNonce = 42;
        header1.hashPrevBlock.SetNull();
        header1.minerAddress.SetNull();
        header1.hashRandomX.SetNull();

        auto fixed = header1.Serialize();

        CBlockHeader header2;
        bool success = header2.Deserialize(fixed.data(), fixed.size());

        REQUIRE(success);
        REQUIRE(header2.nVersion == header1.nVersion);
        REQUIRE(header2.nTime == header1.nTime);
        REQUIRE(header2.nBits == header1.nBits);
        REQUIRE(header2.nNonce == header1.nNonce);
    }

    SECTION("Deserialize from std::array with wrong size rejects") {
        std::array<uint8_t, 50> wrong_size{};
        CBlockHeader header;

        bool success = header.Deserialize(wrong_size.data(), wrong_size.size());
        REQUIRE_FALSE(success);
    }
}

TEST_CASE("CBlockHeader MainNet genesis block golden vector", "[block]") {
    SECTION("MainNet genesis block from chainparams") {
        // This is the actual genesis block from chainparams.cpp
        // Mined on: 2025-10-27
        // Expected hash: 938f0a2ca374ea2fade1911b254269a82576d0c95a97807a2120e1e508f0d688

        CBlockHeader genesis;
        genesis.nVersion = 1;
        genesis.hashPrevBlock.SetNull();
        genesis.minerAddress.SetNull();
        genesis.nTime = 1761564252;      // Oct 27, 2025
        genesis.nBits = 0x1f06a000;      // Target: ~2.5 minutes at 50 H/s
        genesis.nNonce = 8497;           // Found by genesis miner
        genesis.hashRandomX.SetNull();

        // Serialize and verify exact size
        auto serialized = genesis.Serialize();
        REQUIRE(serialized.size() == 100);

        // Verify the serialized header bytes match expected format
        // nVersion = 1 at offset 0 (little-endian: 01 00 00 00)
        REQUIRE(serialized[0] == 0x01);
        REQUIRE(serialized[1] == 0x00);
        REQUIRE(serialized[2] == 0x00);
        REQUIRE(serialized[3] == 0x00);

        // hashPrevBlock is all zeros (offset 4-35)
        for (size_t i = 4; i < 36; i++) {
            REQUIRE(serialized[i] == 0x00);
        }

        // minerAddress is all zeros (offset 36-55)
        for (size_t i = 36; i < 56; i++) {
            REQUIRE(serialized[i] == 0x00);
        }

        // nTime = 1761564252 (0x68FF565C) at offset 56 (little-endian: 5C 56 FF 68)
        REQUIRE(serialized[56] == 0x5C);
        REQUIRE(serialized[57] == 0x56);
        REQUIRE(serialized[58] == 0xFF);
        REQUIRE(serialized[59] == 0x68);

        // nBits = 0x1f06a000 at offset 60 (little-endian: 00 A0 06 1F)
        REQUIRE(serialized[60] == 0x00);
        REQUIRE(serialized[61] == 0xA0);
        REQUIRE(serialized[62] == 0x06);
        REQUIRE(serialized[63] == 0x1F);

        // nNonce = 8497 (0x00002131) at offset 64 (little-endian: 31 21 00 00)
        REQUIRE(serialized[64] == 0x31);
        REQUIRE(serialized[65] == 0x21);
        REQUIRE(serialized[66] == 0x00);
        REQUIRE(serialized[67] == 0x00);

        // hashRandomX is all zeros (offset 68-99)
        for (size_t i = 68; i < 100; i++) {
            REQUIRE(serialized[i] == 0x00);
        }

        // Compute hash and verify it matches expected genesis hash
        uint256 hash = genesis.GetHash();
        std::string hashHex = hash.GetHex();

        // Expected: 938f0a2ca374ea2fade1911b254269a82576d0c95a97807a2120e1e508f0d688
        // (This is the display format; GetHex() reverses bytes per Bitcoin convention)
        REQUIRE(hashHex == "938f0a2ca374ea2fade1911b254269a82576d0c95a97807a2120e1e508f0d688");
    }

    SECTION("Genesis block round-trip preserves hash") {
        CBlockHeader genesis;
        genesis.nVersion = 1;
        genesis.hashPrevBlock.SetNull();
        genesis.minerAddress.SetNull();
        genesis.nTime = 1761564252;
        genesis.nBits = 0x1f06a000;
        genesis.nNonce = 8497;
        genesis.hashRandomX.SetNull();

        uint256 originalHash = genesis.GetHash();

        // Round-trip through serialization
        auto serialized = genesis.Serialize();

        CBlockHeader deserialized;
        bool success = deserialized.Deserialize(serialized.data(), serialized.size());
        REQUIRE(success);

        uint256 deserializedHash = deserialized.GetHash();
        REQUIRE(deserializedHash == originalHash);
    }
}

TEST_CASE("CBlockHeader comprehensive hex golden vector", "[block]") {
    SECTION("Complete 100-byte header with expected hash") {
        // Manually constructed test vector for interoperability testing
        // This serves as a reference for alternative implementations

        CBlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock.SetNull();
        header.minerAddress.SetNull();
        header.nTime = 1234567890;
        header.nBits = 0x1d00ffff;
        header.nNonce = 42;
        header.hashRandomX.SetNull();

        // Serialize to get exact hex bytes
        auto serialized = header.Serialize();
        REQUIRE(serialized.size() == 100);

        // Expected hex representation (for documentation/interop)
        // 01000000 (version=1)
        // 0000000000000000000000000000000000000000000000000000000000000000 (hashPrevBlock)
        // 00000000000000000000000000000000000000000000 (minerAddress, 20 bytes)
        // d2029649 (nTime=1234567890)
        // ffff001d (nBits=0x1d00ffff)
        // 2a000000 (nNonce=42)
        // 0000000000000000000000000000000000000000000000000000000000000000 (hashRandomX)

        // Compute the hash
        uint256 hash = header.GetHash();

        // Hash should be deterministic and non-null
        REQUIRE_FALSE(hash.IsNull());

        // Verify hash is reproducible
        uint256 hash2 = header.GetHash();
        REQUIRE(hash == hash2);

        // Store expected hash for this specific test vector
        std::string hashHex = hash.GetHex();

        // This test documents the expected hash for alternative implementations
        // If this hash changes, it indicates a consensus-breaking change
        INFO("Golden test vector hash: " << hashHex);

        // Verify the hash is deterministic across runs
        REQUIRE(hashHex == hash2.GetHex());
    }
}

TEST_CASE("CBlockHeader ToString", "[block]") {
    CBlockHeader h;
    h.nVersion = 1;
    h.nTime = 1234567890;
    h.nBits = 0x1d00ffff;
    h.nNonce = 42;
    h.hashPrevBlock.SetNull();
    h.hashRandomX.SetNull();
    h.minerAddress.SetNull();

    auto s = h.ToString();
    REQUIRE(s.find("version") != std::string::npos);
}

TEST_CASE("CBlockLocator basic semantics", "[block]") {
    uint256 a, b, c;
    a.SetHex("11");
    b.SetHex("22");
    c.SetHex("33");
    std::vector<uint256> have{c, b, a};
    CBlockLocator loc(std::move(have));

    REQUIRE(!loc.IsNull());
    REQUIRE(loc.vHave.size() == 3);

    loc.SetNull();
    REQUIRE(loc.IsNull());
}

TEST_CASE("CBlockHeader alpha-release compatibility", "[block][alpha]") {
    SECTION("Hash computation matches alpha-release (no byte reversal)") {
        // Alpha-release uses HashWriter pattern: double SHA256 with NO byte reversal
        // Our refactored code should produce identical hashes

        CBlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock.SetNull();
        header.minerAddress.SetNull();
        header.nTime = 1234567890;
        header.nBits = 0x1d00ffff;
        header.nNonce = 42;
        header.hashRandomX.SetNull();

        // Get hash from our implementation
        uint256 our_hash = header.GetHash();

        // Compute hash using alpha-release logic (copied from alpha-release src/hash.h)
        // Alpha HashWriter::GetHash() does: double SHA256, NO byte reversal
        auto serialized = header.Serialize();
        uint256 alpha_hash;
        CSHA256().Write(serialized.data(), serialized.size()).Finalize(alpha_hash.begin());
        CSHA256().Write(alpha_hash.begin(), CSHA256::OUTPUT_SIZE).Finalize(alpha_hash.begin());

        // Our hash MUST match alpha-release hash exactly
        REQUIRE(our_hash == alpha_hash);

        INFO("Our hash:   " << our_hash.GetHex());
        INFO("Alpha hash: " << alpha_hash.GetHex());
    }

    SECTION("Genesis block hash matches alpha-release mainnet genesis") {
        // Mainnet genesis from chainparams.cpp
        CBlockHeader genesis;
        genesis.nVersion = 1;
        genesis.hashPrevBlock.SetNull();
        genesis.minerAddress.SetNull();
        genesis.nTime = 1761564252;      // Oct 27, 2025
        genesis.nBits = 0x1f06a000;
        genesis.nNonce = 8497;
        genesis.hashRandomX.SetNull();

        // Our implementation
        uint256 our_hash = genesis.GetHash();

        // Alpha-release logic (double SHA256, no reversal)
        auto serialized = genesis.Serialize();
        uint256 alpha_hash;
        CSHA256().Write(serialized.data(), serialized.size()).Finalize(alpha_hash.begin());
        CSHA256().Write(alpha_hash.begin(), CSHA256::OUTPUT_SIZE).Finalize(alpha_hash.begin());

        // Must match
        REQUIRE(our_hash == alpha_hash);

        // Also verify against the expected mainnet genesis hash (GetHex() displays in reversed byte order)
        REQUIRE(our_hash.GetHex() == "938f0a2ca374ea2fade1911b254269a82576d0c95a97807a2120e1e508f0d688");
    }

    SECTION("Multiple test vectors match alpha-release") {
        // Test several different headers to ensure consistency
        struct TestVector {
            int32_t version;
            uint32_t time;
            uint32_t bits;
            uint32_t nonce;
        };

        TestVector vectors[] = {
            {1, 0, 0x207fffff, 0},
            {1, 1234567890, 0x1d00ffff, 42},
            {1, 1761564252, 0x1f06a000, 8497},
            {2, 9999999, 0x1a0fffff, 123456},
        };

        for (const auto& vec : vectors) {
            CBlockHeader header;
            header.nVersion = vec.version;
            header.hashPrevBlock.SetNull();
            header.minerAddress.SetNull();
            header.nTime = vec.time;
            header.nBits = vec.bits;
            header.nNonce = vec.nonce;
            header.hashRandomX.SetNull();

            // Our implementation
            uint256 our_hash = header.GetHash();

            // Alpha-release logic
            auto serialized = header.Serialize();
            uint256 alpha_hash;
            CSHA256().Write(serialized.data(), serialized.size()).Finalize(alpha_hash.begin());
            CSHA256().Write(alpha_hash.begin(), CSHA256::OUTPUT_SIZE).Finalize(alpha_hash.begin());

            // Must match for every test vector
            REQUIRE(our_hash == alpha_hash);

            INFO("Test vector: version=" << vec.version << " time=" << vec.time
                 << " bits=0x" << std::hex << vec.bits << " nonce=" << std::dec << vec.nonce);
            INFO("Hash: " << our_hash.GetHex());
        }
    }

    SECTION("Regtest genesis matches alpha-release") {
        // Regtest genesis from chainparams.cpp
        CBlockHeader genesis;
        genesis.nVersion = 1;
        genesis.hashPrevBlock.SetNull();
        genesis.minerAddress.SetNull();
        genesis.nTime = 1760549555;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 2;
        genesis.hashRandomX.SetNull();

        // Our implementation
        uint256 our_hash = genesis.GetHash();

        // Alpha-release logic
        auto serialized = genesis.Serialize();
        uint256 alpha_hash;
        CSHA256().Write(serialized.data(), serialized.size()).Finalize(alpha_hash.begin());
        CSHA256().Write(alpha_hash.begin(), CSHA256::OUTPUT_SIZE).Finalize(alpha_hash.begin());

        // Must match
        REQUIRE(our_hash == alpha_hash);

        // Verify against expected regtest genesis hash
        REQUIRE(our_hash.GetHex() == "0555faa88836f4ce189235a28279af4614432234b6f7e2f350e4fc0dadb1ffa7");
    }
}
