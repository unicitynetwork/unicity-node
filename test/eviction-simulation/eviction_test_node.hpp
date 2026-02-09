// Copyright (c) 2025 The Unicity Foundation
// Lightweight node stub for eviction simulation
//
// This is a minimal representation of a node focused on connection state,
// enabling large-scale statistical analysis of eviction behavior
// (protection phases, netgroup diversity, prefer_evict handling).

#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <set>
#include <string>

namespace unicity {
namespace test {
namespace evicsim {

// Connection type enum (mirrors network::ConnectionType)
enum class SimConnectionType {
  INBOUND,
  OUTBOUND_FULL_RELAY,
  BLOCK_RELAY,
  FEELER,
  MANUAL
};

// Per-connection metadata
struct ConnectionInfo {
  int peer_id;
  SimConnectionType type;
  std::chrono::steady_clock::time_point connected_at;
  std::chrono::steady_clock::time_point last_headers_received;
  std::string netgroup;  // Peer's /16 netgroup
  bool is_block_relay_only{false};

  // Ping tracking (for PROTECT_BY_PING eviction phase)
  // -1 means no ping response yet
  int64_t ping_time_ms{-1};

  // NoBan protection flag (Manual/NoBan peers cannot be evicted)
  bool is_protected{false};

  // Prefer eviction flag (for discouraged peers)
  // Set to true for misbehaving peers that should be evicted first
  bool prefer_evict{false};
};

// Lightweight node for eviction simulation
// Contains only connection management state - no networking, no chain
struct EvictionTestNode {
  int id{-1};
  std::string ip_address;  // Node's own IP
  std::string netgroup;    // Node's /16 netgroup

  // Slot configuration (matches ConnectionManager::Config defaults)
  size_t max_inbound{125};
  size_t max_full_relay_outbound{8};
  size_t max_block_relay_outbound{2};

  // Active connections (peer_id -> connection info)
  std::map<int, ConnectionInfo> connections;

  // Stats
  uint64_t connections_attempted{0};
  uint64_t connections_accepted{0};
  uint64_t connections_rejected{0};
  uint64_t evictions_triggered{0};
  uint64_t block_relay_rotations{0};

  EvictionTestNode() = default;

  explicit EvictionTestNode(int node_id, const std::string& ip)
      : id(node_id), ip_address(ip) {
    // Extract netgroup from IP (assumes IPv4 format "a.b.c.d")
    auto first_dot = ip.find('.');
    auto second_dot = ip.find('.', first_dot + 1);
    if (first_dot != std::string::npos && second_dot != std::string::npos) {
      netgroup = ip.substr(0, second_dot);
    }
  }

  // === Connection Queries ===

  bool IsConnectedTo(int peer_id) const { return connections.count(peer_id) > 0; }

  size_t InboundCount() const {
    size_t count = 0;
    for (const auto& [_, info] : connections) {
      if (info.type == SimConnectionType::INBOUND) count++;
    }
    return count;
  }

  size_t OutboundFullRelayCount() const {
    size_t count = 0;
    for (const auto& [_, info] : connections) {
      if (info.type == SimConnectionType::OUTBOUND_FULL_RELAY) count++;
    }
    return count;
  }

  size_t BlockRelayCount() const {
    size_t count = 0;
    for (const auto& [_, info] : connections) {
      if (info.type == SimConnectionType::BLOCK_RELAY) count++;
    }
    return count;
  }

  size_t TotalOutboundCount() const { return OutboundFullRelayCount() + BlockRelayCount(); }

  size_t TotalConnectionCount() const { return connections.size(); }

  // Get all connected peer IDs
  std::set<int> GetConnectedPeerIds() const {
    std::set<int> ids;
    for (const auto& [peer_id, _] : connections) {
      ids.insert(peer_id);
    }
    return ids;
  }

  // Get netgroup distribution of connections
  std::map<std::string, size_t> GetNetgroupDistribution() const {
    std::map<std::string, size_t> dist;
    for (const auto& [_, info] : connections) {
      dist[info.netgroup]++;
    }
    return dist;
  }

  // Get largest netgroup among connections
  std::string GetLargestNetgroup() const {
    std::string largest;
    size_t max_count = 0;
    auto dist = GetNetgroupDistribution();
    for (const auto& [ng, count] : dist) {
      if (count > max_count) {
        max_count = count;
        largest = ng;
      }
    }
    return largest;
  }

  // === Slot Checks ===

  bool CanAcceptInbound() const { return InboundCount() < max_inbound; }

  bool NeedsMoreFullRelayOutbound() const { return OutboundFullRelayCount() < max_full_relay_outbound; }

  bool NeedsMoreBlockRelayOutbound() const { return BlockRelayCount() < max_block_relay_outbound; }

  bool NeedsMoreOutbound() const { return NeedsMoreFullRelayOutbound() || NeedsMoreBlockRelayOutbound(); }

  // === Block-Relay Rotation Support ===

  // Get oldest block-relay peer by last_headers_received time
  // Returns -1 if no block-relay peers exist
  int GetOldestBlockRelayPeer() const {
    int oldest_id = -1;
    auto oldest_time = std::chrono::steady_clock::time_point::max();

    for (const auto& [peer_id, info] : connections) {
      if (info.type == SimConnectionType::BLOCK_RELAY) {
        if (info.last_headers_received < oldest_time) {
          oldest_time = info.last_headers_received;
          oldest_id = peer_id;
        }
      }
    }
    return oldest_id;
  }

  // Update last_headers_received for a peer
  void UpdateLastHeadersReceived(int peer_id, std::chrono::steady_clock::time_point time) {
    auto it = connections.find(peer_id);
    if (it != connections.end()) {
      it->second.last_headers_received = time;
    }
  }

  // Update ping time for a peer
  void UpdatePingTime(int peer_id, int64_t ping_ms) {
    auto it = connections.find(peer_id);
    if (it != connections.end()) {
      it->second.ping_time_ms = ping_ms;
    }
  }

  // Mark a peer as protected (NoBan - cannot be evicted)
  void SetProtected(int peer_id, bool protected_flag) {
    auto it = connections.find(peer_id);
    if (it != connections.end()) {
      it->second.is_protected = protected_flag;
    }
  }

  // Mark a peer for preferential eviction (e.g., misbehaving)
  void SetPreferEvict(int peer_id, bool prefer) {
    auto it = connections.find(peer_id);
    if (it != connections.end()) {
      it->second.prefer_evict = prefer;
    }
  }

  // Get last headers received time for a peer (for rotation logic)
  std::chrono::steady_clock::time_point GetLastHeadersReceived(int peer_id) const {
    auto it = connections.find(peer_id);
    if (it != connections.end()) {
      return it->second.last_headers_received;
    }
    return std::chrono::steady_clock::time_point{};
  }
};

}  // namespace evicsim
}  // namespace test
}  // namespace unicity
