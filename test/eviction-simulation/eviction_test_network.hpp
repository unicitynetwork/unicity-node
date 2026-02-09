// Copyright (c) 2025 The Unicity Foundation
// Virtual network for eviction simulation
//
// Provides a lightweight simulation environment for testing eviction behavior
// at scale. Uses the REAL EvictionManager for eviction decisions, ensuring
// tests reflect actual production behavior.

#pragma once

#include "eviction_test_node.hpp"
#include "network/eviction_manager.hpp"  // REAL production eviction code

#include <algorithm>
#include <functional>
#include <map>
#include <random>
#include <set>
#include <string>
#include <vector>

namespace unicity {
namespace test {
namespace evicsim {

// Configuration for the simulated network
struct NetworkConfig {
  // Connection limits (defaults)
  size_t max_inbound{125};
  size_t max_full_relay_outbound{8};
  size_t max_block_relay_outbound{2};

  // Eviction protection (from EvictionManager)
  size_t protect_by_netgroup{4};  // Protect N peers from diverse netgroups
  size_t protect_by_ping{8};      // Protect N peers with best ping
  size_t protect_by_headers{4};   // Protect N peers with recent header relay
  double protect_by_uptime_pct{0.5};  // Protect 50% by connection age

  // Outbound diversity
  bool enforce_netgroup_diversity{true};  // 1 outbound per netgroup
};

// Virtual network for eviction simulation
class EvictionTestNetwork {
 public:
  explicit EvictionTestNetwork(uint64_t seed = 0)
      : rng_(seed == 0 ? std::random_device{}() : seed),
        current_time_(std::chrono::steady_clock::now()) {}

  // === Node Management ===

  // Create a node with specified IP
  int CreateNode(const std::string& ip) {
    int id = next_node_id_++;
    nodes_.emplace(id, EvictionTestNode(id, ip));

    // Apply config
    auto& node = nodes_.at(id);
    node.max_inbound = config_.max_inbound;
    node.max_full_relay_outbound = config_.max_full_relay_outbound;
    node.max_block_relay_outbound = config_.max_block_relay_outbound;

    return id;
  }

  // Create N nodes with IPs in specified /16 netgroup
  std::vector<int> CreateNodesInNetgroup(size_t count, const std::string& netgroup_prefix) {
    std::vector<int> ids;
    ids.reserve(count);
    for (size_t i = 0; i < count; ++i) {
      int third = (i / 256) % 256;
      int fourth = (i % 256) + 1;
      std::string ip = netgroup_prefix + "." + std::to_string(third) + "." + std::to_string(fourth);
      ids.push_back(CreateNode(ip));
    }
    return ids;
  }

  // Get node by ID
  EvictionTestNode* GetNode(int id) {
    auto it = nodes_.find(id);
    return it != nodes_.end() ? &it->second : nullptr;
  }

  const EvictionTestNode* GetNode(int id) const {
    auto it = nodes_.find(id);
    return it != nodes_.end() ? &it->second : nullptr;
  }

  size_t NodeCount() const { return nodes_.size(); }

  // Iterate all nodes
  template <typename Func>
  void ForEachNode(Func&& fn) {
    for (auto& [id, node] : nodes_) {
      fn(node);
    }
  }

  template <typename Func>
  void ForEachNode(Func&& fn) const {
    for (const auto& [id, node] : nodes_) {
      fn(node);
    }
  }

  // === Connection Management ===

  // Attempt connection from src to dst
  // Returns true if connection established
  bool Connect(int from_id, int to_id, SimConnectionType type = SimConnectionType::OUTBOUND_FULL_RELAY) {
    auto* from_node = GetNode(from_id);
    auto* to_node = GetNode(to_id);
    if (!from_node || !to_node) return false;
    if (from_id == to_id) return false;
    if (from_node->IsConnectedTo(to_id)) return false;

    from_node->connections_attempted++;

    // Check outbound slots on initiator
    if (type == SimConnectionType::OUTBOUND_FULL_RELAY) {
      if (!from_node->NeedsMoreFullRelayOutbound()) {
        from_node->connections_rejected++;
        return false;
      }
    } else if (type == SimConnectionType::BLOCK_RELAY) {
      if (!from_node->NeedsMoreBlockRelayOutbound()) {
        from_node->connections_rejected++;
        return false;
      }
    }

    // Check inbound slots on receiver (unless type is MANUAL)
    if (type != SimConnectionType::MANUAL && !to_node->CanAcceptInbound()) {
      // Try eviction
      if (!TryEvictInbound(to_id)) {
        from_node->connections_rejected++;
        return false;
      }
    }

    // Check netgroup diversity for outbound
    if (config_.enforce_netgroup_diversity &&
        (type == SimConnectionType::OUTBOUND_FULL_RELAY || type == SimConnectionType::BLOCK_RELAY)) {
      // Check if we already have an outbound to this netgroup
      for (const auto& [peer_id, info] : from_node->connections) {
        if ((info.type == SimConnectionType::OUTBOUND_FULL_RELAY ||
             info.type == SimConnectionType::BLOCK_RELAY) &&
            info.netgroup == to_node->netgroup) {
          from_node->connections_rejected++;
          return false;  // Already have outbound to this netgroup
        }
      }
    }

    // Create connection
    ConnectionInfo from_info;
    from_info.peer_id = to_id;
    from_info.type = type;
    from_info.connected_at = current_time_;
    from_info.last_headers_received = current_time_;
    from_info.netgroup = to_node->netgroup;
    from_info.is_block_relay_only = (type == SimConnectionType::BLOCK_RELAY);
    from_info.is_protected = (type == SimConnectionType::MANUAL);
    from_node->connections[to_id] = from_info;

    // Create reverse connection (inbound on receiver)
    ConnectionInfo to_info;
    to_info.peer_id = from_id;
    to_info.type = SimConnectionType::INBOUND;
    to_info.connected_at = current_time_;
    to_info.last_headers_received = current_time_;
    to_info.netgroup = from_node->netgroup;
    to_info.is_block_relay_only = false;
    to_node->connections[from_id] = to_info;

    from_node->connections_accepted++;
    to_node->connections_accepted++;

    return true;
  }

  // Disconnect two nodes
  void Disconnect(int a_id, int b_id) {
    auto* a = GetNode(a_id);
    auto* b = GetNode(b_id);
    if (a) a->connections.erase(b_id);
    if (b) b->connections.erase(a_id);
  }

  // === Eviction ===

  // Try to evict an inbound peer to make room for new connection
  // Uses the REAL EvictionManager::SelectNodeToEvict() for production-accurate behavior
  bool TryEvictInbound(int node_id) {
    auto* node = GetNode(node_id);
    if (!node) return false;

    // Build EvictionCandidate list from our connection info
    // This uses the REAL production EvictionCandidate struct
    std::vector<network::EvictionManager::EvictionCandidate> candidates;

    for (const auto& [peer_id, info] : node->connections) {
      network::EvictionManager::EvictionCandidate candidate;
      candidate.peer_id = peer_id;
      candidate.connected_time = info.connected_at;
      candidate.ping_time_ms = info.ping_time_ms;
      candidate.netgroup = info.netgroup;
      candidate.is_protected = info.is_protected;
      candidate.is_outbound = (info.type != SimConnectionType::INBOUND);
      candidate.last_headers_time = info.last_headers_received;
      candidate.prefer_evict = info.prefer_evict;

      candidates.push_back(candidate);
    }

    if (candidates.empty()) return false;

    // Call the REAL production eviction algorithm
    auto result = network::EvictionManager::SelectNodeToEvict(std::move(candidates));

    if (!result.has_value()) {
      return false;  // No one to evict (all protected)
    }

    int evict_id = *result;
    Disconnect(node_id, evict_id);
    node->evictions_triggered++;
    return true;
  }

  // === Block-Relay Rotation ===

  // Simulate headers received from a peer
  // This also triggers rotation check if the peer is a block-relay peer
  // and has newer headers than the oldest block-relay peer
  void SimulateHeadersReceived(int node_id, int peer_id) {
    auto* node = GetNode(node_id);
    if (node) {
      node->UpdateLastHeadersReceived(peer_id, current_time_);
    }
  }

  // Simulate ping response from a peer
  void SimulatePingResponse(int node_id, int peer_id, int64_t ping_ms) {
    auto* node = GetNode(node_id);
    if (node) {
      node->UpdatePingTime(peer_id, ping_ms);
    }
  }

  // Mark a peer as protected (NoBan - immune to eviction)
  void MarkProtected(int node_id, int peer_id) {
    auto* node = GetNode(node_id);
    if (node) {
      node->SetProtected(peer_id, true);
    }
  }

  // Mark a peer as prefer_evict (misbehaving)
  void MarkPreferEvict(int node_id, int peer_id) {
    auto* node = GetNode(node_id);
    if (node) {
      node->SetPreferEvict(peer_id, true);
    }
  }

  // Try to rotate block-relay peers (evict oldest, connect new)
  // This simulates the rotation that happens when a block-relay peer
  // sends headers newer than the oldest block-relay peer's last headers
  // Returns true if rotation occurred
  bool TryRotateBlockRelay(int node_id, const std::vector<int>& available_targets) {
    auto* node = GetNode(node_id);
    if (!node) return false;

    // Need at least max block-relay connections before rotation makes sense
    if (node->BlockRelayCount() < node->max_block_relay_outbound) return false;

    int oldest = node->GetOldestBlockRelayPeer();
    if (oldest < 0) return false;

    // Get oldest peer's last headers time
    auto oldest_headers_time = node->GetLastHeadersReceived(oldest);
    auto* oldest_peer = GetNode(oldest);
    if (!oldest_peer) return false;

    for (int target_id : available_targets) {
      auto* target = GetNode(target_id);
      if (!target) continue;
      if (target->netgroup == oldest_peer->netgroup) continue;  // Same netgroup, skip
      if (node->IsConnectedTo(target_id)) continue;              // Already connected

      // Evict oldest and connect new
      Disconnect(node_id, oldest);
      if (Connect(node_id, target_id, SimConnectionType::BLOCK_RELAY)) {
        node->block_relay_rotations++;
        return true;
      }
    }

    return false;
  }

  // Check if rotation should happen based on header receipt
  // Call this when a block-relay peer sends headers to check if the
  // oldest peer should be rotated out
  // Returns the ID of the peer that should be evicted, or -1 if no rotation needed
  int CheckRotationNeeded(int node_id, int sending_peer_id) {
    auto* node = GetNode(node_id);
    if (!node) return -1;

    // Only block-relay peers trigger rotation
    auto conn_it = node->connections.find(sending_peer_id);
    if (conn_it == node->connections.end()) return -1;
    if (conn_it->second.type != SimConnectionType::BLOCK_RELAY) return -1;

    // Need full set of block-relay connections
    if (node->BlockRelayCount() < node->max_block_relay_outbound) return -1;

    int oldest = node->GetOldestBlockRelayPeer();
    if (oldest < 0 || oldest == sending_peer_id) return -1;

    // Check if sending peer's headers are newer than oldest's
    auto sending_time = node->GetLastHeadersReceived(sending_peer_id);
    auto oldest_time = node->GetLastHeadersReceived(oldest);

    if (sending_time > oldest_time) {
      return oldest;  // Oldest should be rotated out
    }

    return -1;
  }

  // === Time Control ===

  void AdvanceTime(std::chrono::seconds seconds) { current_time_ += seconds; }

  void Tick(int64_t advance_seconds = 1) { AdvanceTime(std::chrono::seconds(advance_seconds)); }

  void Run(size_t num_ticks, int64_t seconds_per_tick = 1) {
    for (size_t i = 0; i < num_ticks; ++i) {
      Tick(seconds_per_tick);
    }
  }

  std::chrono::steady_clock::time_point GetTime() const { return current_time_; }

  // === Metrics ===

  struct Metrics {
    // Connection metrics
    double avg_inbound_count{0.0};
    double avg_outbound_count{0.0};
    double avg_block_relay_count{0.0};

    // Netgroup diversity
    double avg_netgroup_diversity{0.0};      // Unique netgroups / total connections
    double avg_largest_netgroup_ratio{0.0};  // Largest netgroup / total connections

    // Eclipse analysis
    size_t total_eclipsed_nodes{0};  // Nodes where attacker has >50% connections

    // Rotation metrics
    uint64_t total_rotations{0};
  };

  Metrics CollectMetrics(const std::set<int>& attacker_node_ids = {}) const {
    Metrics m;
    if (nodes_.empty()) return m;

    for (const auto& [id, node] : nodes_) {
      // Skip attacker nodes in metrics
      if (attacker_node_ids.count(id)) continue;

      m.avg_inbound_count += node.InboundCount();
      m.avg_outbound_count += node.TotalOutboundCount();
      m.avg_block_relay_count += node.BlockRelayCount();

      // Netgroup diversity
      auto dist = node.GetNetgroupDistribution();
      size_t total = node.TotalConnectionCount();
      if (total > 0) {
        m.avg_netgroup_diversity += static_cast<double>(dist.size()) / total;

        size_t largest = 0;
        for (const auto& [_, count] : dist) {
          largest = std::max(largest, count);
        }
        m.avg_largest_netgroup_ratio += static_cast<double>(largest) / total;
      }

      // Eclipse detection
      if (!attacker_node_ids.empty() && total > 0) {
        size_t attacker_connections = 0;
        for (const auto& [peer_id, _] : node.connections) {
          if (attacker_node_ids.count(peer_id)) {
            attacker_connections++;
          }
        }
        if (attacker_connections > total / 2) {
          m.total_eclipsed_nodes++;
        }
      }

      m.total_rotations += node.block_relay_rotations;
    }

    size_t honest_count = nodes_.size() - attacker_node_ids.size();
    if (honest_count > 0) {
      m.avg_inbound_count /= honest_count;
      m.avg_outbound_count /= honest_count;
      m.avg_block_relay_count /= honest_count;
      m.avg_netgroup_diversity /= honest_count;
      m.avg_largest_netgroup_ratio /= honest_count;
    }

    return m;
  }

  // === Config ===

  NetworkConfig& Config() { return config_; }
  const NetworkConfig& Config() const { return config_; }

 private:
  std::map<int, EvictionTestNode> nodes_;
  int next_node_id_{0};
  std::chrono::steady_clock::time_point current_time_;
  std::mt19937 rng_;
  NetworkConfig config_;
};

}  // namespace evicsim
}  // namespace test
}  // namespace unicity
