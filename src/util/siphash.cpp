// Copyright (c) 2016-present The Bitcoin Core developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license.

#include "util/siphash.hpp"

#include <bit>
#include <cassert>

namespace unicity {
namespace util {

namespace {

inline uint64_t rotl64(uint64_t x, int b) {
    return std::rotl(x, b);
}

}  // namespace

#define SIPROUND do { \
    v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; \
    v0 = rotl64(v0, 32); \
    v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2; \
    v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0; \
    v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; \
    v2 = rotl64(v2, 32); \
} while (0)

SipHasher::SipHasher(uint64_t k0, uint64_t k1)
    : v_{C0 ^ k0, C1 ^ k1, C2 ^ k0, C3 ^ k1} {}

SipHasher& SipHasher::Write(uint64_t data) {
    uint64_t v0 = v_[0], v1 = v_[1], v2 = v_[2], v3 = v_[3];

    assert(count_ % 8 == 0);

    v3 ^= data;
    SIPROUND;
    SIPROUND;
    v0 ^= data;

    v_[0] = v0;
    v_[1] = v1;
    v_[2] = v2;
    v_[3] = v3;

    count_ += 8;
    return *this;
}

SipHasher& SipHasher::Write(const uint8_t* data, size_t len) {
    uint64_t v0 = v_[0], v1 = v_[1], v2 = v_[2], v3 = v_[3];
    uint64_t t = tmp_;
    uint8_t c = count_;

    for (size_t i = 0; i < len; ++i) {
        t |= static_cast<uint64_t>(data[i]) << (8 * (c % 8));
        c++;
        if ((c & 7) == 0) {
            v3 ^= t;
            SIPROUND;
            SIPROUND;
            v0 ^= t;
            t = 0;
        }
    }

    v_[0] = v0;
    v_[1] = v1;
    v_[2] = v2;
    v_[3] = v3;
    count_ = c;
    tmp_ = t;

    return *this;
}

uint64_t SipHasher::Finalize() const {
    uint64_t v0 = v_[0], v1 = v_[1], v2 = v_[2], v3 = v_[3];

    uint64_t t = tmp_ | (static_cast<uint64_t>(count_) << 56);

    v3 ^= t;
    SIPROUND;
    SIPROUND;
    v0 ^= t;
    v2 ^= 0xFF;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

#undef SIPROUND

}  // namespace util
}  // namespace unicity
