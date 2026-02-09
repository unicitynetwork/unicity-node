// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include "network/protocol.hpp"
#include "util/siphash.hpp"

#include <array>
#include <cstdint>
#include <random>
#include <unordered_map>

namespace unicity {
namespace network {

// Forward declarations
struct LearnedEntry;

// AddressKey for binary IP:port keying
struct AddressKey {
  std::array<uint8_t, 16> ip{};
  uint16_t port{0};

  // Default constructor
  AddressKey() = default;

  // Construct from NetworkAddress
  explicit AddressKey(const protocol::NetworkAddress& a) : ip(a.ip), port(a.port) {}

  struct Hasher {
    size_t operator()(const AddressKey& k) const noexcept {
      // SipHash-2-4 with per-process random key (HashDoS resistant)
      static const auto [k0, k1] = [] {
        std::random_device rd;
        return std::pair{(uint64_t(rd()) << 32) | rd(), (uint64_t(rd()) << 32) | rd()};
      }();
      return util::SipHasher(k0, k1)
          .Write(k.ip.data(), k.ip.size())
          .Write(reinterpret_cast<const uint8_t*>(&k.port), 2)
          .Finalize();
    }
  };

  bool operator==(const AddressKey& o) const noexcept { return port == o.port && ip == o.ip; }
};

// Learned address entry for echo suppression
struct LearnedEntry {
  protocol::TimestampedAddress ts_addr{};
  int64_t last_seen_s{0};
};

using LearnedMap = std::unordered_map<AddressKey, LearnedEntry, AddressKey::Hasher>;

}  // namespace network
}  // namespace unicity
