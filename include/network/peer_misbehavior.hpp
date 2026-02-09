// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include <cstdint>
#include <string>
#include <unordered_set>

namespace unicity {
namespace network {

// Permission flags for peer connections
enum class NetPermissionFlags : uint32_t {
  None = 0,
  // Manual connection (not subject to connection limits)
  Manual = (1U << 1),
  // Can't be banned/disconnected/discouraged for misbehavior
  // Note: NoBan includes Download permission (1U << 6)
  NoBan = (1U << 4) | (1U << 6),
  // Allow getheaders during IBD when chain has insufficient work
  Download = (1U << 6),
  // Can send us unlimited amounts of addrs (bypasses ADDR rate limiting)
  Addr = (1U << 7),
};

inline NetPermissionFlags operator|(NetPermissionFlags a, NetPermissionFlags b) {
  return static_cast<NetPermissionFlags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline NetPermissionFlags operator&(NetPermissionFlags a, NetPermissionFlags b) {
  return static_cast<NetPermissionFlags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline bool HasPermission(NetPermissionFlags flags, NetPermissionFlags check) {
  return (flags & check) == check && static_cast<uint32_t>(check) != 0;
}

// Peer misbehavior tracking data
struct PeerMisbehaviorData {
  bool should_discourage{false};       // One-shot flag: cleared after processing 
  uint32_t misbehavior_count{0};       // Lifetime count: never cleared (for diagnostics/testing)
  NetPermissionFlags permissions{NetPermissionFlags::None};
  std::string address;
  // Track duplicates of invalid headers reported by this peer to avoid double-reporting
  std::unordered_set<std::string> invalid_header_hashes;
};

}  // namespace network
}  // namespace unicity
