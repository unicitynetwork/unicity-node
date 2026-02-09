// Copyright (c) 2016-present The Bitcoin Core developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license.

#ifndef UNICITY_UTIL_SIPHASH_HPP
#define UNICITY_UTIL_SIPHASH_HPP

#include <array>
#include <cstdint>
#include <cstddef>

namespace unicity {
namespace util {

// SipHash-2-4 implementation for deterministic, unpredictable hashing.
// Used for ADDR relay peer selection to prevent amplification attacks.
//
// Ported from Bitcoin Core's src/crypto/siphash.cpp

class SipHasher {
public:
    // Construct with 128-bit key (k0, k1)
    SipHasher(uint64_t k0, uint64_t k1);

    // Hash a 64-bit integer (little-endian interpretation of 8 bytes).
    // Can only be used when a multiple of 8 bytes have been written.
    SipHasher& Write(uint64_t data);

    // Hash arbitrary bytes
    SipHasher& Write(const uint8_t* data, size_t len);

    // Compute the 64-bit SipHash-2-4. Object remains untouched (const).
    uint64_t Finalize() const;

private:
    // Internal state constants
    static constexpr uint64_t C0{0x736f6d6570736575ULL};
    static constexpr uint64_t C1{0x646f72616e646f6dULL};
    static constexpr uint64_t C2{0x6c7967656e657261ULL};
    static constexpr uint64_t C3{0x7465646279746573ULL};

    std::array<uint64_t, 4> v_;
    uint64_t tmp_{0};
    uint8_t count_{0};  // Only low 8 bits of input size matter
};

}  // namespace util
}  // namespace unicity

#endif  // UNICITY_UTIL_SIPHASH_HPP
