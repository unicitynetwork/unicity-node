// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license.

#ifndef UNICITY_NETWORK_EVICTION_MANAGER_HPP
#define UNICITY_NETWORK_EVICTION_MANAGER_HPP

#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace unicity {
namespace network {

/**
 * EvictionManager - Peer eviction selection algorithm
 *
 * Protection rules (in order):
 * 1. Remove outbound peers (never evict outbound connections)
 * 2. Remove NoBan/protected peers
 * 3. Protect 4 peers by netgroup diversity
 * 4. Protect 8 peers with lowest ping time
 * 5. Protect 4 peers that most recently sent us valid headers
 * 6. Protect 50% of remaining peers by longest uptime
 * 7. From remaining: select from netgroup with most connections
 * 8. Within that netgroup: evict youngest (most recently connected)
 *
 * This class is stateless - all state is passed via EvictionCandidate vector.
 *
 * NOTE: This manager handles INBOUND slot exhaustion. For OUTBOUND peer rotation
 * (feeler logic), see HeaderSyncManager.
 */
class EvictionManager {
public:
  struct EvictionCandidate {
    int peer_id;
    std::chrono::steady_clock::time_point connected_time;
    int64_t ping_time_ms;  // -1 if unknown
    std::string netgroup;  // e.g., "192.168" for /16
    bool is_protected;     // NoBan or other protection flag
    bool is_outbound;      // Outbound peers are never evicted (defense in depth)

    // Header relay tracking - peers that do useful work get protected
    std::chrono::steady_clock::time_point last_headers_time;  // Last valid headers received

    // Eviction priority - discouraged peers are evicted first (after protection phases)
    bool prefer_evict{false};
  };

  // Select a peer to evict from the given candidates (all peers inbound and outbound).
  // Outbound peers will be filtered internally as defense-in-depth.
  // Returns peer_id to evict, or nullopt if no suitable candidate.
  static std::optional<int> SelectNodeToEvict(std::vector<EvictionCandidate> candidates);

  // Configuration constants (adapted from Bitcoin Core for header-only chain)
  static constexpr size_t PROTECT_BY_NETGROUP = 4;
  static constexpr size_t PROTECT_BY_PING = 8;
  static constexpr size_t PROTECT_BY_HEADERS = 4;  // Peers that relay headers (useful work)
};

}  // namespace network
}  // namespace unicity

#endif  // UNICITY_NETWORK_EVICTION_MANAGER_HPP
