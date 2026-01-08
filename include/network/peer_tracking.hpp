#pragma once

#include "network/peer.hpp"
#include "network/peer_misbehavior.hpp"
#include "util/time.hpp"
#include "util/uint.hpp"

#include <array>
#include <chrono>
#include <deque>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

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
      // FNV-1a 64-bit (offset basis and prime from spec)
      uint64_t h = 14695981039346656037ULL;  // 0xcbf29ce484222325
      for (auto b : k.ip) {
        h ^= b;
        h *= 1099511628211ULL;  // 0x100000001b3
      }
      h ^= static_cast<uint8_t>(k.port >> 8);
      h *= 1099511628211ULL;
      h ^= static_cast<uint8_t>(k.port & 0xFF);
      h *= 1099511628211ULL;
      return static_cast<size_t>(h);
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

// PeerTrackingData - Consolidated per-peer state
struct PeerTrackingData {
  PeerPtr peer;

  // For feeler lifetime enforcement
  std::chrono::steady_clock::time_point created_at;

  // Managed by MisbehaviorManager
  PeerMisbehaviorData misbehavior;

  // Block hashes queued for INV announcement to this peer
  std::vector<uint256> blocks_for_inv_relay;
  uint256 last_announced_block;
  int64_t last_announce_time_s{0};

  // For eviction protection (peers sending headers get protection)
  std::chrono::steady_clock::time_point last_headers_received{};

  // Address discovery state
  bool getaddr_replied{false};   // Once-per-connection GETADDR policy
  LearnedMap learned_addresses;  // Echo suppression

  PeerTrackingData() = default;
  explicit PeerTrackingData(PeerPtr p, std::chrono::steady_clock::time_point created = util::GetSteadyTime())
      : peer(std::move(p)), created_at(created) {}
};

}  // namespace network
}  // namespace unicity
