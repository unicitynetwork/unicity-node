// Copyright (c) 2016-present The Bitcoin Core developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license.

#include "catch_amalgamated.hpp"
#include "util/siphash.hpp"

#include <cstdint>

using namespace unicity::util;

/*
   SipHash-2-4 output with
   k = 00 01 02 ...
   and
   in = (empty string)
   in = 00 (1 byte)
   in = 00 01 (2 bytes)
   in = 00 01 02 (3 bytes)
   ...
   in = 00 01 02 ... 3e (63 bytes)

   from: https://131002.net/siphash/siphash24.c
*/
static const uint64_t siphash_2_4_testvec[] = {
    0x726fdb47dd0e0e31, 0x74f839c593dc67fd, 0x0d6c8009d9a94f5a, 0x85676696d7fb7e2d,
    0xcf2794e0277187b7, 0x18765564cd99a68d, 0xcbc9466e58fee3ce, 0xab0200f58b01d137,
    0x93f5f5799a932462, 0x9e0082df0ba9e4b0, 0x7a5dbbc594ddb9f3, 0xf4b32f46226bada7,
    0x751e8fbc860ee5fb, 0x14ea5627c0843d90, 0xf723ca908e7af2ee, 0xa129ca6149be45e5,
    0x3f2acc7f57c29bdb, 0x699ae9f52cbe4794, 0x4bc1b3f0968dd39c, 0xbb6dc91da77961bd,
    0xbed65cf21aa2ee98, 0xd0f2cbb02e3b67c7, 0x93536795e3a33e88, 0xa80c038ccd5ccec8,
    0xb8ad50c6f649af94, 0xbce192de8a85b8ea, 0x17d835b85bbb15f3, 0x2f2e6163076bcfad,
    0xde4daaaca71dc9a5, 0xa6a2506687956571, 0xad87a3535c49ef28, 0x32d892fad841c342,
    0x7127512f72f27cce, 0xa7f32346f95978e3, 0x12e0b01abb051238, 0x15e034d40fa197ae,
    0x314dffbe0815a3b4, 0x027990f029623981, 0xcadcd4e59ef40c4d, 0x9abfd8766a33735c,
    0x0e3ea96b5304a7d0, 0xad0c42d6fc585992, 0x187306c89bc215a9, 0xd4a60abcf3792b95,
    0xf935451de4f21df2, 0xa9538f0419755787, 0xdb9acddff56ca510, 0xd06c98cd5c0975eb,
    0xe612a3cb9ecba951, 0xc766e62cfcadaf96, 0xee64435a9752fe72, 0xa192d576b245165a,
    0x0a8787bf8ecb74b2, 0x81b3e73d20b49b6f, 0x7fa8220ba3b2ecea, 0x245731c13ca42499,
    0xb78dbfaf3a8d83bd, 0xea1ad565322a1a0b, 0x60e61c23a3795013, 0x6606d7e446282b93,
    0x6ca4ecb15c5f91e1, 0x9f626da15c9625f3, 0xe51b38608ef25f57, 0x958a324ceb064572
};

TEST_CASE("SipHash-2-4 official test vectors - byte at a time", "[siphash][crypto]") {
    // Test key from spec: k = 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
    // As little-endian 64-bit values: k0 = 0x0706050403020100, k1 = 0x0F0E0D0C0B0A0908
    SipHasher hasher(0x0706050403020100ULL, 0x0F0E0D0C0B0A0908ULL);

    // Check test vectors from spec, one byte at a time
    for (uint8_t x = 0; x < std::size(siphash_2_4_testvec); ++x) {
        REQUIRE(hasher.Finalize() == siphash_2_4_testvec[x]);
        hasher.Write(&x, 1);
    }
}

TEST_CASE("SipHash-2-4 official test vectors - 8 bytes at a time", "[siphash][crypto]") {
    // Test key from spec
    SipHasher hasher(0x0706050403020100ULL, 0x0F0E0D0C0B0A0908ULL);

    // Check test vectors from spec, eight bytes at a time
    for (uint8_t x = 0; x < std::size(siphash_2_4_testvec); x += 8) {
        REQUIRE(hasher.Finalize() == siphash_2_4_testvec[x]);
        uint64_t val = uint64_t(x) | (uint64_t(x+1) << 8) | (uint64_t(x+2) << 16) | (uint64_t(x+3) << 24) |
                       (uint64_t(x+4) << 32) | (uint64_t(x+5) << 40) | (uint64_t(x+6) << 48) | (uint64_t(x+7) << 56);
        hasher.Write(val);
    }
}

TEST_CASE("SipHash-2-4 incremental writes match Core test", "[siphash][crypto]") {
    // This matches Bitcoin Core's hash_tests.cpp siphash test case
    SipHasher hasher(0x0706050403020100ULL, 0x0F0E0D0C0B0A0908ULL);
    REQUIRE(hasher.Finalize() == 0x726fdb47dd0e0e31ULL);

    static const uint8_t t0[1] = {0};
    hasher.Write(t0, 1);
    REQUIRE(hasher.Finalize() == 0x74f839c593dc67fdULL);

    static const uint8_t t1[7] = {1,2,3,4,5,6,7};
    hasher.Write(t1, 7);
    REQUIRE(hasher.Finalize() == 0x93f5f5799a932462ULL);

    hasher.Write(0x0F0E0D0C0B0A0908ULL);
    REQUIRE(hasher.Finalize() == 0x3f2acc7f57c29bdbULL);

    static const uint8_t t2[2] = {16,17};
    hasher.Write(t2, 2);
    REQUIRE(hasher.Finalize() == 0x4bc1b3f0968dd39cULL);

    static const uint8_t t3[9] = {18,19,20,21,22,23,24,25,26};
    hasher.Write(t3, 9);
    REQUIRE(hasher.Finalize() == 0x2f2e6163076bcfadULL);

    static const uint8_t t4[5] = {27,28,29,30,31};
    hasher.Write(t4, 5);
    REQUIRE(hasher.Finalize() == 0x7127512f72f27cceULL);

    hasher.Write(0x2726252423222120ULL);
    REQUIRE(hasher.Finalize() == 0x0e3ea96b5304a7d0ULL);

    hasher.Write(0x2F2E2D2C2B2A2928ULL);
    REQUIRE(hasher.Finalize() == 0xe612a3cb9ecba951ULL);
}

TEST_CASE("SipHash-2-4 empty input", "[siphash][crypto]") {
    SipHasher hasher(0x0706050403020100ULL, 0x0F0E0D0C0B0A0908ULL);
    REQUIRE(hasher.Finalize() == 0x726fdb47dd0e0e31ULL);
}

TEST_CASE("SipHash-2-4 zero keys", "[siphash][crypto]") {
    // Test with zero keys (used for address hashing)
    SipHasher hasher(0, 0);
    uint64_t result = hasher.Finalize();
    // Just verify it produces a consistent result (not checking specific value)

    SipHasher hasher2(0, 0);
    REQUIRE(hasher2.Finalize() == result);
}

TEST_CASE("SipHash-2-4 different keys produce different results", "[siphash][crypto]") {
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

    SipHasher hasher1(0x0706050403020100ULL, 0x0F0E0D0C0B0A0908ULL);
    hasher1.Write(data, sizeof(data));
    uint64_t result1 = hasher1.Finalize();

    SipHasher hasher2(0x1716151413121110ULL, 0x1F1E1D1C1B1A1918ULL);
    hasher2.Write(data, sizeof(data));
    uint64_t result2 = hasher2.Finalize();

    REQUIRE(result1 != result2);
}

TEST_CASE("SipHash-2-4 copy preserves state", "[siphash][crypto]") {
    SipHasher hasher1(0x0706050403020100ULL, 0x0F0E0D0C0B0A0908ULL);
    hasher1.Write(0x0102030405060708ULL);

    // Copy the hasher
    SipHasher hasher2 = hasher1;

    // Both should produce same result
    REQUIRE(hasher1.Finalize() == hasher2.Finalize());

    // Continue writing to copy - should diverge
    hasher2.Write(0x0910111213141516ULL);
    REQUIRE(hasher1.Finalize() != hasher2.Finalize());
}
