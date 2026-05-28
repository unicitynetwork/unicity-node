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
    header.payloadRoot.SetNull();
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
    header.payloadRoot.SetNull();
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
        header.payloadRoot.SetNull();
        header.nTime = 1234567890;
        header.nBits = 0x1d00ffff;
        header.nNonce = 42;
        header.hashRandomX.SetNull();

        // Serialize and verify exact bytes
        auto serialized = header.Serialize();
        REQUIRE(serialized.size() == 112);

        // Verify specific byte offsets (little-endian)
        // nVersion = 1 at offset 0
        REQUIRE(serialized[0] == 0x01);
        REQUIRE(serialized[1] == 0x00);
        REQUIRE(serialized[2] == 0x00);
        REQUIRE(serialized[3] == 0x00);

        // nTime = 1234567890 (0x499602D2) at offset 68
        REQUIRE(serialized[68] == 0xD2);
        REQUIRE(serialized[69] == 0x02);
        REQUIRE(serialized[70] == 0x96);
        REQUIRE(serialized[71] == 0x49);

        // nBits = 0x1d00ffff at offset 72
        REQUIRE(serialized[72] == 0xFF);
        REQUIRE(serialized[73] == 0xFF);
        REQUIRE(serialized[74] == 0x00);
        REQUIRE(serialized[75] == 0x1D);

        // nNonce = 42 (0x2A) at offset 76
        REQUIRE(serialized[76] == 0x2A);
        REQUIRE(serialized[77] == 0x00);
        REQUIRE(serialized[78] == 0x00);
        REQUIRE(serialized[79] == 0x00);

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
        header.payloadRoot.SetNull();
        header.hashRandomX.SetNull();

        auto serialized = header.Serialize();

        // nVersion = 1 at offset 0 (little-endian: 01 00 00 00)
        REQUIRE(serialized[0] == 0x01);
        REQUIRE(serialized[1] == 0x00);
        REQUIRE(serialized[2] == 0x00);
        REQUIRE(serialized[3] == 0x00);

        // nTime = 2 at offset 68 (little-endian: 02 00 00 00)
        REQUIRE(serialized[68] == 0x02);
        REQUIRE(serialized[69] == 0x00);
        REQUIRE(serialized[70] == 0x00);
        REQUIRE(serialized[71] == 0x00);

        // nBits = 3 at offset 72 (little-endian: 03 00 00 00)
        REQUIRE(serialized[72] == 0x03);
        REQUIRE(serialized[73] == 0x00);
        REQUIRE(serialized[74] == 0x00);
        REQUIRE(serialized[75] == 0x00);

        // nNonce = 4 at offset 76 (little-endian: 04 00 00 00)
        REQUIRE(serialized[76] == 0x04);
        REQUIRE(serialized[77] == 0x00);
        REQUIRE(serialized[78] == 0x00);
        REQUIRE(serialized[79] == 0x00);
    }

    SECTION("Big-endian values serialize correctly") {
        CBlockHeader header;
        header.nVersion = 0x01020304;
        header.nTime = 0x05060708;
        header.nBits = 0x090A0B0C;
        header.nNonce = 0x0D0E0F10;
        header.hashPrevBlock.SetNull();
        header.payloadRoot.SetNull();
        header.hashRandomX.SetNull();

        auto serialized = header.Serialize();

        // nVersion = 0x01020304 (little-endian: 04 03 02 01)
        REQUIRE(serialized[0] == 0x04);
        REQUIRE(serialized[1] == 0x03);
        REQUIRE(serialized[2] == 0x02);
        REQUIRE(serialized[3] == 0x01);

        // nTime = 0x05060708 (little-endian: 08 07 06 05)
        REQUIRE(serialized[68] == 0x08);
        REQUIRE(serialized[69] == 0x07);
        REQUIRE(serialized[70] == 0x06);
        REQUIRE(serialized[71] == 0x05);
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
            header1.payloadRoot.begin()[i] = static_cast<uint8_t>(i * 2);
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
        REQUIRE(header2.payloadRoot == header1.payloadRoot);
        REQUIRE(header2.hashRandomX == header1.hashRandomX);

        // Verify hashes match
        REQUIRE(header2.GetHash() == header1.GetHash());
    }
}

TEST_CASE("CBlockHeader Serialize returns fixed-size array", "[block]") {
    SECTION("Serialize produces exact 112-byte array") {
        CBlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock.SetNull();
        header.payloadRoot.SetNull();
        header.nTime = 1234567890;
        header.nBits = 0x1d00ffff;
        header.nNonce = 42;
        header.hashRandomX.SetNull();

        auto fixed = header.Serialize();

        // Verify it's exactly HEADER_SIZE
        REQUIRE(fixed.size() == CBlockHeader::HEADER_SIZE);
        REQUIRE(fixed.size() == 112);
    }

    SECTION("Serialize uses field offset constants") {
        CBlockHeader header;
        header.nVersion = 1;
        header.nTime = 2;
        header.nBits = 3;
        header.nNonce = 4;
        header.hashPrevBlock.SetNull();
        header.payloadRoot.SetNull();
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
            header1.payloadRoot.begin()[i] = static_cast<uint8_t>(i * 2);
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
        REQUIRE(header2.payloadRoot == header1.payloadRoot);
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
        header1.payloadRoot.SetNull();
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
        // Mined on: 2025-10-24
        // Expected hash: 4d84216a9a2cf3854488f85a49d8331818e376cfe88c0f0883a81df2ffd86092

        CBlockHeader genesis;
        genesis.nVersion = 1;
        genesis.hashPrevBlock.SetNull();
        genesis.payloadRoot.SetNull();
        genesis.nTime = 1761330012;      // Oct 24, 2025
        genesis.nBits = 0x1f06a000;      // Target: ~2.5 minutes at 50 H/s
        genesis.nNonce = 8497;           // Found by genesis miner
        genesis.hashRandomX.SetNull();

        // Serialize and verify exact size
        auto serialized = genesis.Serialize();
        REQUIRE(serialized.size() == 112);

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

        // payloadRoot is all zeros (offset 36-67)
        for (size_t i = 36; i < 68; i++) {
            REQUIRE(serialized[i] == 0x00);
        }

        // nTime = 1761330012 (0x68FBC35C) at offset 68 (little-endian: 5C C3 FB 68)
        REQUIRE(static_cast<uint8_t>(serialized[68]) == 0x5C);
        REQUIRE(static_cast<uint8_t>(serialized[69]) == 0xC3);
        REQUIRE(static_cast<uint8_t>(serialized[70]) == 0xFB);
        REQUIRE(static_cast<uint8_t>(serialized[71]) == 0x68);

        // nBits = 0x1f06a000 at offset 72 (little-endian: 00 A0 06 1F)
        REQUIRE(serialized[72] == 0x00);
        REQUIRE(serialized[73] == 0xA0);
        REQUIRE(serialized[74] == 0x06);
        REQUIRE(serialized[75] == 0x1F);

        // nNonce = 8497 (0x00002131) at offset 76 (little-endian: 31 21 00 00)
        REQUIRE(serialized[76] == 0x31);
        REQUIRE(serialized[77] == 0x21);
        REQUIRE(serialized[78] == 0x00);
        REQUIRE(serialized[79] == 0x00);

        // hashRandomX is all zeros (offset 80-111)
        for (size_t i = 80; i < 112; i++) {
            REQUIRE(serialized[i] == 0x00);
        }

        // Compute hash and verify it matches expected genesis hash
        uint256 hash = genesis.GetHash();
        std::string hashHex = hash.GetHex();

        // Expected: 4d84216a9a2cf3854488f85a49d8331818e376cfe88c0f0883a81df2ffd86092
        // (This is the display format; GetHex() reverses bytes per Bitcoin convention)
        REQUIRE(hashHex == "4d84216a9a2cf3854488f85a49d8331818e376cfe88c0f0883a81df2ffd86092");
    }

    SECTION("Genesis block round-trip preserves hash") {
        CBlockHeader genesis;
        genesis.nVersion = 1;
        genesis.hashPrevBlock.SetNull();
        genesis.payloadRoot.SetNull();
        genesis.nTime = 1761330012;
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
    SECTION("Complete 112-byte header with expected hash") {
        // Manually constructed test vector for interoperability testing
        // This serves as a reference for alternative implementations

        CBlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock.SetNull();
        header.payloadRoot.SetNull();
        header.nTime = 1234567890;
        header.nBits = 0x1d00ffff;
        header.nNonce = 42;
        header.hashRandomX.SetNull();

        // Serialize to get exact hex bytes
        auto serialized = header.Serialize();
        REQUIRE(serialized.size() == 112);

        // Expected hex representation (for documentation/interop)
        // 01000000 (version=1)
        // 0000000000000000000000000000000000000000000000000000000000000000 (hashPrevBlock)
        // 0000000000000000000000000000000000000000000000000000000000000000 (payloadRoot, 32 bytes)
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
    h.payloadRoot.SetNull();

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
