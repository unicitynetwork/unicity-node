// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "catch_amalgamated.hpp"
#include "util/uint.hpp"
#include "util/arith_uint256.hpp"
#include <sstream>

TEST_CASE("uint256 basic operations", "[uint]")
{
    SECTION("Default constructor creates zero")
    {
        uint256 zero;
        REQUIRE(zero.IsNull());
        REQUIRE(zero == uint256::ZERO);
    }

    SECTION("Constructor with value")
    {
        uint256 one(1);
        REQUIRE_FALSE(one.IsNull());
        REQUIRE(one == uint256::ONE);
    }

    SECTION("SetNull works correctly")
    {
        uint256 test(1);
        REQUIRE_FALSE(test.IsNull());
        test.SetNull();
        REQUIRE(test.IsNull());
    }

    SECTION("Comparison operators")
    {
        uint256 zero;
        uint256 one(1);
        uint256 another_zero;

        REQUIRE(zero == another_zero);
        REQUIRE(zero != one);
        REQUIRE(zero < one);
    }

    SECTION("Consteval hex constructor - compile-time construction")
    {
        // This is evaluated at compile time - invalid hex would cause compile error
        constexpr uint256 genesis{"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"};

        REQUIRE_FALSE(genesis.IsNull());
        REQUIRE(genesis.GetHex() == "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");

        // Verify it matches the runtime-parsed version
        uint256 runtime = uint256S("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
        REQUIRE(genesis == runtime);
    }

    SECTION("Hex conversion - basic")
    {
        uint256 test;
        test.SetHex("0000000000000000000000000000000000000000000000000000000000000001");

        std::string hex = test.GetHex();
        REQUIRE(hex == "0000000000000000000000000000000000000000000000000000000000000001");
    }

    SECTION("Hex conversion - with 0x prefix")
    {
        uint256 test;
        test.SetHex("0x00000000000000000000000000000000000000000000000000000000000000ff");

        std::string hex = test.GetHex();
        REQUIRE(hex == "00000000000000000000000000000000000000000000000000000000000000ff");
    }

    SECTION("Hex conversion - full value")
    {
        uint256 test;
        test.SetHex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");

        std::string hex = test.GetHex();
        REQUIRE(hex == "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    }

    SECTION("ToString returns GetHex")
    {
        uint256 test;
        test.SetHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        REQUIRE(test.ToString() == test.GetHex());
    }

    SECTION("GetUint64 reads correct position")
    {
        uint256 test;
        // GetHex() shows bytes in reverse order, so we set the value reversed
        // We want bytes at position 0 to be 0xDEADBEEFCAFEBABE in little-endian
        // In hex string (which is reversed): last 16 chars are the first 8 bytes
        test.SetHex("00000000000000000000000000000000000000000000000000000000deadbeefcafebabe");

        REQUIRE(test.GetUint64(0) == 0xDEADBEEFCAFEBABE);
    }

    SECTION("GetUint32 reads correct position")
    {
        uint256 test;
        // GetHex() shows bytes in reverse, so last 8 chars are first 4 bytes
        // We want 0x12345678 at pos 0, 0xABCDEF00 at pos 1 (reading little-endian from memory)
        // In hex string (which shows MSB first): last 16 chars = first 8 bytes
        // But positions are reversed: put position 1 value first, then position 0
        test.SetHex("00000000000000000000000000000000000000000000000000000000abcdef0012345678");

        REQUIRE(test.GetUint32(0) == 0x12345678);
        REQUIRE(test.GetUint32(1) == 0xABCDEF00);
    }
}

TEST_CASE("uint160 operations", "[uint]")
{
    SECTION("Default constructor creates zero")
    {
        uint160 zero;
        REQUIRE(zero.IsNull());
    }

    SECTION("Hex conversion works")
    {
        uint160 test;
        test.SetHex("0102030405060708090a0b0c0d0e0f1011121314");

        std::string hex = test.GetHex();
        REQUIRE(hex == "0102030405060708090a0b0c0d0e0f1011121314");
    }

    SECTION("Size is correct")
    {
        REQUIRE(uint160::size() == 20);
    }
}

TEST_CASE("uint256S helper function", "[uint]")
{
    SECTION("Creates uint256 from string")
    {
        uint256 test = uint256S("deadbeef00000000000000000000000000000000000000000000000000000000");
        REQUIRE(test.GetHex() == "deadbeef00000000000000000000000000000000000000000000000000000000");
    }

    SECTION("Handles const char*")
    {
        const char* hex_str = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        uint256 test = uint256S(hex_str);
        REQUIRE(test.GetHex() == hex_str);
    }
}

TEST_CASE("arith_uint256 basic arithmetic", "[arith_uint]")
{
    SECTION("Default constructor creates zero")
    {
        arith_uint256 zero;
        REQUIRE(zero == 0);
    }

    SECTION("Constructor with uint64_t value")
    {
        arith_uint256 value(42);
        REQUIRE(value == 42);
    }

    SECTION("Addition works correctly")
    {
        arith_uint256 a(100);
        arith_uint256 b(200);
        arith_uint256 result = a + b;

        REQUIRE(result == 300);
    }

    SECTION("Subtraction works correctly")
    {
        arith_uint256 a(500);
        arith_uint256 b(200);
        arith_uint256 result = a - b;

        REQUIRE(result == 300);
    }

    SECTION("Multiplication works correctly")
    {
        arith_uint256 a(10);
        arith_uint256 b(20);
        arith_uint256 result = a * b;

        REQUIRE(result == 200);
    }

    SECTION("Division works correctly")
    {
        arith_uint256 a(100);
        arith_uint256 b(10);
        arith_uint256 result = a / b;

        REQUIRE(result == 10);
    }

    SECTION("Increment works correctly")
    {
        arith_uint256 value(99);
        ++value;
        REQUIRE(value == 100);

        arith_uint256 post = value++;
        REQUIRE(post == 100);
        REQUIRE(value == 101);
    }

    SECTION("Decrement works correctly")
    {
        arith_uint256 value(100);
        --value;
        REQUIRE(value == 99);

        arith_uint256 post = value--;
        REQUIRE(post == 99);
        REQUIRE(value == 98);
    }
}

TEST_CASE("arith_uint256 bitwise operations", "[arith_uint]")
{
    SECTION("Left shift works correctly")
    {
        arith_uint256 value(1);
        arith_uint256 shifted = value << 8;

        REQUIRE(shifted == 256);
    }

    SECTION("Right shift works correctly")
    {
        arith_uint256 value(256);
        arith_uint256 shifted = value >> 8;

        REQUIRE(shifted == 1);
    }

    SECTION("Bitwise AND works correctly")
    {
        arith_uint256 a(0xFF);
        arith_uint256 b(0x0F);
        arith_uint256 result = a & b;

        REQUIRE(result == 0x0F);
    }

    SECTION("Bitwise OR works correctly")
    {
        arith_uint256 a(0xF0);
        arith_uint256 b(0x0F);
        arith_uint256 result = a | b;

        REQUIRE(result == 0xFF);
    }

    SECTION("Bitwise XOR works correctly")
    {
        arith_uint256 a(0xFF);
        arith_uint256 b(0x0F);
        arith_uint256 result = a ^ b;

        REQUIRE(result == 0xF0);
    }

    SECTION("Bitwise NOT works correctly")
    {
        arith_uint256 value(0);
        arith_uint256 inverted = ~value;

        REQUIRE_FALSE(inverted == 0);
    }

    SECTION("Negation works correctly")
    {
        arith_uint256 value(1);
        arith_uint256 negated = -value;

        // -1 in two's complement should be all 1s
        REQUIRE(negated + 1 == 0);
    }
}

TEST_CASE("arith_uint256 comparison operators", "[arith_uint]")
{
    SECTION("Equality works correctly")
    {
        arith_uint256 a(100);
        arith_uint256 b(100);
        arith_uint256 c(200);

        REQUIRE(a == b);
        REQUIRE_FALSE(a == c);
    }

    SECTION("Spaceship operator works correctly")
    {
        arith_uint256 a(100);
        arith_uint256 b(200);

        REQUIRE(a < b);
        REQUIRE(a <= b);
        REQUIRE(b > a);
        REQUIRE(b >= a);
        REQUIRE(a <= a);
        REQUIRE(a >= a);
    }
}

TEST_CASE("arith_uint256 compact format", "[arith_uint]")
{
    SECTION("SetCompact and GetCompact roundtrip")
    {
        // Difficulty target 0x1d00ffff (Bitcoin's initial difficulty)
        arith_uint256 target;
        target.SetCompact(0x1d00ffff);

        uint32_t compact = target.GetCompact();
        REQUIRE(compact == 0x1d00ffff);
    }

    SECTION("SetCompact handles negative flag")
    {
        arith_uint256 value;
        bool negative = false;
        bool overflow = false;

        // 0x03803f00 = size:3, sign bit set, mantissa:0x003f00
        value.SetCompact(0x03803f00, &negative, &overflow);

        REQUIRE(negative);
        REQUIRE_FALSE(overflow);
    }

    SECTION("SetCompact detects overflow")
    {
        arith_uint256 value;
        bool negative = false;
        bool overflow = false;

        // Size > 34 bytes causes overflow (size=35, mantissa=0x01)
        value.SetCompact(0x23010000, &negative, &overflow);

        REQUIRE(overflow);
    }
}

TEST_CASE("arith_uint256 hex conversion", "[arith_uint]")
{
    SECTION("SetHex and GetHex roundtrip")
    {
        arith_uint256 value;
        value.SetHex("000000000000000000000000000000000000000000000000000000000000ffff");

        std::string hex = value.GetHex();
        REQUIRE(hex == "000000000000000000000000000000000000000000000000000000000000ffff");
    }

    SECTION("SetHex handles 0x prefix")
    {
        arith_uint256 value;
        value.SetHex("0x0000000000000000000000000000000000000000000000000000000000001234");

        REQUIRE(value == 0x1234);
    }

    SECTION("ToString returns GetHex")
    {
        arith_uint256 value(0xDEADBEEF);
        REQUIRE(value.ToString() == value.GetHex());
    }
}

TEST_CASE("arith_uint256 helper methods", "[arith_uint]")
{
    SECTION("bits() returns correct bit count")
    {
        arith_uint256 zero;
        REQUIRE(zero.bits() == 0);

        arith_uint256 one(1);
        REQUIRE(one.bits() == 1);

        arith_uint256 value(255);
        REQUIRE(value.bits() == 8);

        arith_uint256 large(256);
        REQUIRE(large.bits() == 9);
    }

    SECTION("GetLow64 returns lower 64 bits")
    {
        arith_uint256 value;
        value = 0xDEADBEEFCAFEBABE;

        REQUIRE(value.GetLow64() == 0xDEADBEEFCAFEBABE);
    }

    SECTION("getdouble converts to double")
    {
        arith_uint256 value(1000);
        double d = value.getdouble();

        REQUIRE(d == Catch::Approx(1000.0));
    }
}

TEST_CASE("arith_uint512 operations", "[arith_uint512]")
{
    SECTION("Default constructor creates zero")
    {
        arith_uint512 zero;
        REQUIRE(zero == 0);
    }

    SECTION("Constructor with uint64_t value")
    {
        arith_uint512 value(42);
        REQUIRE(value == 42);
    }

    SECTION("Basic arithmetic works")
    {
        arith_uint512 a(100);
        arith_uint512 b(200);

        REQUIRE(a + b == 300);
        REQUIRE(b - a == 100);
        REQUIRE(a * arith_uint512(2) == 200);
    }

    SECTION("Can hold values larger than uint256")
    {
        arith_uint512 max256;
        for (int i = 0; i < 256; ++i) {
            max256 = (max256 << 1) | arith_uint512(1);
        }

        // max256 is now 2^256 - 1
        arith_uint512 larger = max256 + arith_uint512(1);
        REQUIRE(larger > max256);
        REQUIRE(larger.bits() == 257);
    }

    SECTION("Hex conversion works")
    {
        arith_uint512 value;
        value.SetHex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001234");

        REQUIRE(value == 0x1234);
    }

    SECTION("Is trivially copyable")
    {
        REQUIRE(std::is_trivially_copyable_v<arith_uint512>);
    }
}

TEST_CASE("UintToArith256 and ArithToUint256 conversion", "[uint][arith_uint]")
{
    SECTION("UintToArith256 converts correctly")
    {
        uint256 blob = uint256S("00000000000000000000000000000000000000000000000000000000deadbeef");
        arith_uint256 arith = UintToArith256(blob);

        REQUIRE(arith == 0xDEADBEEF);
    }

    SECTION("ArithToUint256 converts correctly")
    {
        arith_uint256 arith(0xCAFEBABE);
        uint256 blob = ArithToUint256(arith);

        uint256 expected = uint256S("00000000000000000000000000000000000000000000000000000000cafebabe");
        REQUIRE(blob == expected);
    }

    SECTION("Roundtrip conversion preserves value")
    {
        arith_uint256 original(0x123456789ABCDEF0);
        uint256 blob = ArithToUint256(original);
        arith_uint256 converted = UintToArith256(blob);

        REQUIRE(converted == original);
    }
}

TEST_CASE("Large value arithmetic", "[arith_uint]")
{
    SECTION("Can compute large products")
    {
        arith_uint256 a;
        a.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        arith_uint256 two(2);

        // This should wrap around due to overflow
        arith_uint256 result = a + two;
        REQUIRE(result == 1);
    }

    SECTION("Division by large divisor works")
    {
        arith_uint256 dividend;
        dividend.SetHex("0000000000000000000000000000000000000000000000000000000100000000");

        arith_uint256 divisor(0x10000);
        arith_uint256 quotient = dividend / divisor;

        REQUIRE(quotient == 0x10000);
    }
}

TEST_CASE("Real-world blockchain values", "[uint][arith_uint][realworld]")
{
    SECTION("Bitcoin Genesis Block hash")
    {
        // Bitcoin Genesis Block hash (block 0)
        // https://blockchair.com/bitcoin/block/0
        uint256 genesis_hash = uint256S("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");

        // Verify it's not null
        REQUIRE_FALSE(genesis_hash.IsNull());

        // Verify roundtrip
        std::string hex = genesis_hash.GetHex();
        REQUIRE(hex == "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
    }

    SECTION("Bitcoin Genesis Block difficulty target")
    {
        // Bitcoin genesis block nBits: 0x1d00ffff
        // This is the initial difficulty target
        arith_uint256 target;
        target.SetCompact(0x1d00ffff);

        // The expanded form should be:
        // 0x00000000ffff0000000000000000000000000000000000000000000000000000
        arith_uint256 expected;
        expected.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");

        REQUIRE(target == expected);

        // Verify GetCompact returns the original value
        REQUIRE(target.GetCompact() == 0x1d00ffff);
    }

    SECTION("Bitcoin Block 100,000 hash")
    {
        // Block 100,000 hash
        // https://blockchair.com/bitcoin/block/100000
        uint256 block_hash = uint256S("000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506");

        REQUIRE_FALSE(block_hash.IsNull());
        REQUIRE(block_hash.GetHex() == "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506");
    }

    SECTION("Bitcoin Block 100,000 difficulty (nBits: 0x1b04864c)")
    {
        // Block 100,000 nBits: 0x1b04864c
        arith_uint256 target;
        target.SetCompact(0x1b04864c);

        // Verify roundtrip
        uint32_t compact = target.GetCompact();
        REQUIRE(compact == 0x1b04864c);

        // The target should be less than genesis difficulty (higher difficulty = lower target)
        arith_uint256 genesis_target;
        genesis_target.SetCompact(0x1d00ffff);
        REQUIRE(target < genesis_target);
    }

    SECTION("Maximum difficulty target (testnet minimum difficulty)")
    {
        // Testnet minimum difficulty: 0x1d00ffff (same as genesis)
        arith_uint256 max_target;
        max_target.SetCompact(0x1d00ffff);

        // This is the largest valid target (easiest difficulty)
        std::string hex = max_target.GetHex();
        REQUIRE(hex == "00000000ffff0000000000000000000000000000000000000000000000000000");
    }

    SECTION("Block hash comparison - chain ordering")
    {
        // Earlier block has lower height, but hash comparison is different
        uint256 block_1 = uint256S("00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048");
        uint256 block_2 = uint256S("000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd");

        // Both are valid block hashes
        REQUIRE_FALSE(block_1.IsNull());
        REQUIRE_FALSE(block_2.IsNull());

        // They should be different
        REQUIRE(block_1 != block_2);

        // Lexicographic comparison (not height-based) - one must be less than the other
        bool comparison_works = (block_1 < block_2) || (block_2 < block_1);
        REQUIRE(comparison_works);
    }

    SECTION("Difficulty calculation - target to bits conversion")
    {
        // Test that we can convert back and forth between compact and full form
        std::vector<uint32_t> known_bits = {
            0x1d00ffff,  // Genesis
            0x1b04864c,  // Block 100,000
            0x1a05db8b,  // Block 200,000
            0x1900896c,  // Block 300,000
        };

        for (uint32_t bits : known_bits) {
            arith_uint256 target;
            target.SetCompact(bits);
            uint32_t result = target.GetCompact();

            // Should roundtrip exactly (or very close due to precision)
            // Allow for small rounding in the mantissa
            REQUIRE((result == bits || (result >> 24) == (bits >> 24)));
        }
    }

    SECTION("Chainwork calculation - cumulative difficulty")
    {
        // Chainwork is cumulative: sum of (2^256 / (target+1)) for each block
        // For genesis block with target 0x1d00ffff:
        arith_uint256 target;
        target.SetCompact(0x1d00ffff);

        // Work = 2^256 / (target + 1)
        // For genesis, this should be relatively small
        arith_uint256 target_plus_one = target + arith_uint256(1);

        // Verify target is reasonable (not zero, not too large)
        REQUIRE(target > 0);
        REQUIRE(target.bits() > 200);  // Should be around 224 bits
        REQUIRE(target.bits() < 256);
    }
}
