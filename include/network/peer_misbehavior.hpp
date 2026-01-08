#pragma once

#include <cstdint>
#include <string>
#include <unordered_set>

namespace unicity {
namespace network {

// Permission flags for peer connections
enum class NetPermissionFlags : uint32_t {
  None = 0,
  // Allow getheaders during IBD when chain has insufficient work
  Download = (1U << 6),
  // Can't be banned/disconnected/discouraged for misbehavior
  // Note: NoBan includes Download permission
  NoBan = (1U << 4) | Download,
  // Manual connection (not subject to connection limits)
  Manual = (1U << 1),
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
  bool should_discourage{false};
  int num_unconnecting_headers_msgs{0};
  bool unconnecting_penalized{false};
  NetPermissionFlags permissions{NetPermissionFlags::None};
  std::string address;
  // Track duplicates of invalid headers reported by this peer to avoid double-reporting
  std::unordered_set<std::string> invalid_header_hashes;
};

// Maximum unconnecting headers messages before penalty
static constexpr int MAX_UNCONNECTING_HEADERS = 10;

}  // namespace network
}  // namespace unicity
