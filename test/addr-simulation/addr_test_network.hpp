// Copyright (c) 2025 The Unicity Foundation
// Virtual network for address management simulation

#pragma once

#include "addr_test_node.hpp"
#include "network/addr_manager.hpp"
#include "network/protocol.hpp"
#include "util/time.hpp"

#include <algorithm>
#include <functional>
#include <map>
#include <random>
#include <set>
#include <string>
#include <vector>

namespace unicity {
namespace test {
namespace addrsim {

// Configuration for the simulated network
struct NetworkConfig {
  // ADDR relay settings (matching Bitcoin Core / Unicity defaults)
  size_t max_addr_relay_peers{2};        // Relay to N peers per address
  size_t max_addr_per_message{10};       // Small messages only relayed
  int64_t relay_freshness_sec{600};      // Only relay addrs < 10 min old

  // GETADDR settings
  size_t max_getaddr_response{1000};     // Max addresses in GETADDR response
  size_t getaddr_pct_limit{23};          // Return max 23% of AddrMan

  // Timing
  int64_t addr_relay_delay_ms{0};        // Trickle delay (0 = instant for testing)
};

// Virtual network for address simulation
class AddrTestNetwork {
public:
  explicit AddrTestNetwork(uint64_t seed = 0)
      : rng_(seed == 0 ? std::random_device{}() : seed) {
    // Initialize mock time from real time (required because AddressManager::now() uses real time)
    current_time_ = util::GetTime();
  }

  // === Node Management ===

  // Create a node with specified IP
  int CreateNode(const std::string& ip) {
    int id = next_node_id_++;
    nodes_.emplace(id, AddrTestNode(id, ip));
    return id;
  }

  // Create N nodes with IPs in specified /16 netgroup
  // Returns vector of node IDs
  std::vector<int> CreateNodesInNetgroup(size_t count, const std::string& netgroup_prefix) {
    std::vector<int> ids;
    ids.reserve(count);
    for (size_t i = 0; i < count; ++i) {
      // Generate IP: netgroup_prefix.X.Y where X,Y vary
      int third = (i / 256) % 256;
      int fourth = (i % 256) + 1;  // Avoid .0
      std::string ip = netgroup_prefix + "." + std::to_string(third) + "." + std::to_string(fourth);
      ids.push_back(CreateNode(ip));
    }
    return ids;
  }

  // Get node by ID (returns nullptr if not found)
  AddrTestNode* GetNode(int id) {
    auto it = nodes_.find(id);
    return it != nodes_.end() ? &it->second : nullptr;
  }

  const AddrTestNode* GetNode(int id) const {
    auto it = nodes_.find(id);
    return it != nodes_.end() ? &it->second : nullptr;
  }

  size_t NodeCount() const { return nodes_.size(); }

  // Iterate all nodes
  template<typename Func>
  void ForEachNode(Func&& fn) {
    for (auto& [id, node] : nodes_) {
      fn(node);
    }
  }

  template<typename Func>
  void ForEachNode(Func&& fn) const {
    for (const auto& [id, node] : nodes_) {
      fn(node);
    }
  }

  // === Connection Management ===

  // Connect node A to node B (A's outbound, B's inbound)
  bool Connect(int from_id, int to_id) {
    auto* from_node = GetNode(from_id);
    auto* to_node = GetNode(to_id);
    if (!from_node || !to_node) return false;
    if (from_id == to_id) return false;  // No self-connections
    if (from_node->IsConnectedTo(to_id)) return false;  // Already connected

    from_node->outbound_peers.insert(to_id);
    to_node->inbound_peers.insert(from_id);
    return true;
  }

  // Disconnect two nodes
  void Disconnect(int a_id, int b_id) {
    auto* a = GetNode(a_id);
    auto* b = GetNode(b_id);
    if (!a || !b) return;

    a->outbound_peers.erase(b_id);
    a->inbound_peers.erase(b_id);
    b->outbound_peers.erase(a_id);
    b->inbound_peers.erase(a_id);
  }

  // Create random topology: each node connects to avg_connections random peers
  void CreateRandomTopology(size_t avg_connections) {
    std::vector<int> node_ids;
    for (const auto& [id, _] : nodes_) {
      node_ids.push_back(id);
    }

    for (int from_id : node_ids) {
      // Shuffle and pick first N as outbound peers
      std::shuffle(node_ids.begin(), node_ids.end(), rng_);
      size_t connections_made = 0;
      for (int to_id : node_ids) {
        if (connections_made >= avg_connections) break;
        if (Connect(from_id, to_id)) {
          connections_made++;
        }
      }
    }
  }

  // === Message Delivery ===

  // Inject an address into a node's AddrMan (simulates learning from external source)
  bool InjectAddress(int node_id, const std::string& addr_ip, uint16_t port = 9590) {
    auto* node = GetNode(node_id);
    if (!node) return false;

    auto na = protocol::NetworkAddress::from_string(addr_ip, port);
    // add(addr, source, timestamp)
    return node->addr_mgr->add(na, {}, static_cast<uint32_t>(current_time_));
  }

  // Deliver ADDR message from src to dst
  // Returns number of addresses accepted
  size_t DeliverAddr(int src_id, int dst_id,
                     const std::vector<protocol::TimestampedAddress>& addrs) {
    auto* src = GetNode(src_id);
    auto* dst = GetNode(dst_id);
    if (!src || !dst) return 0;
    if (!dst->IsConnectedTo(src_id)) return 0;  // Must be connected

    // Get source address for AddrMan
    auto source = protocol::NetworkAddress::from_string(src->ip_address, 9590);

    // Add to destination's AddrMan
    size_t added = dst->addr_mgr->add_multiple(addrs, source, 0);
    dst->addrs_received += addrs.size();

    // Relay logic: small fresh messages get relayed ONLY if new (to prevent exponential relay explosion)
    if (added > 0 && addrs.size() <= config_.max_addr_per_message) {
      std::vector<protocol::TimestampedAddress> to_relay;
      for (const auto& ta : addrs) {
        int64_t age = current_time_ - static_cast<int64_t>(ta.timestamp);
        if (age >= 0 && age <= config_.relay_freshness_sec) {
          to_relay.push_back(ta);
        }
      }

      if (!to_relay.empty()) {
        // Select relay targets (exclude source)
        auto peers = dst->GetAllConnectedPeers();
        peers.erase(src_id);  // Don't echo back

        std::vector<int> peer_vec(peers.begin(), peers.end());
        std::shuffle(peer_vec.begin(), peer_vec.end(), rng_);

        size_t relay_count = std::min(config_.max_addr_relay_peers, peer_vec.size());
        for (size_t i = 0; i < relay_count; ++i) {
          dst->pending_relays.push_back({peer_vec[i], to_relay});
          dst->addrs_relayed += to_relay.size();
        }
      }
    }

    return added;
  }

  // Deliver GETADDR request and return response
  std::vector<protocol::TimestampedAddress> DeliverGetAddr(int src_id, int dst_id) {
    auto* src = GetNode(src_id);
    auto* dst = GetNode(dst_id);
    if (!src || !dst) return {};
    if (!dst->IsConnectedTo(src_id)) return {};

    // Once per connection
    if (dst->getaddr_replied_to.count(src_id)) {
      return {};
    }
    dst->getaddr_replied_to.insert(src_id);
    dst->getaddr_requests++;

    // Get addresses from AddrMan
    auto addrs = dst->addr_mgr->get_addresses(
        config_.max_getaddr_response,
        config_.getaddr_pct_limit);

    dst->getaddr_responses++;
    return addrs;
  }

  // === Simulation Control ===

  // Process one tick: deliver pending relays, advance time
  void Tick(int64_t advance_seconds = 1) {
    // Collect all pending relays (process in random order for fairness)
    std::vector<std::tuple<int, int, std::vector<protocol::TimestampedAddress>>> to_deliver;

    for (auto& [id, node] : nodes_) {
      for (auto& relay : node.pending_relays) {
        to_deliver.emplace_back(id, relay.target_id, std::move(relay.addrs));
      }
      node.pending_relays.clear();
    }

    std::shuffle(to_deliver.begin(), to_deliver.end(), rng_);

    for (auto& [src, dst, addrs] : to_deliver) {
      DeliverAddr(src, dst, addrs);
    }

    current_time_ += advance_seconds;
  }

  // Run simulation for N ticks
  void Run(size_t num_ticks, int64_t seconds_per_tick = 1) {
    for (size_t i = 0; i < num_ticks; ++i) {
      Tick(seconds_per_tick);
    }
  }

  // === Time Control ===

  int64_t GetTime() const { return current_time_; }
  void SetTime(int64_t t) { current_time_ = t; }
  void AdvanceTime(int64_t seconds) { current_time_ += seconds; }

  // === Metrics ===

  struct Metrics {
    // Propagation
    size_t nodes_with_address{0};        // How many nodes have the target address
    double propagation_pct{0.0};         // % of nodes reached

    // Table health
    double avg_tried_size{0.0};
    double avg_new_size{0.0};
    double avg_total_size{0.0};

    // Netgroup diversity (in TRIED tables)
    std::map<std::string, size_t> netgroup_distribution;  // Aggregate across all nodes
    size_t max_per_netgroup{0};

    // Traffic
    uint64_t total_addrs_received{0};
    uint64_t total_addrs_relayed{0};
  };

  // Collect metrics, optionally checking for specific address
  Metrics CollectMetrics(const std::string& target_addr_ip = "") const {
    Metrics m;
    protocol::NetworkAddress target_na;
    bool check_target = !target_addr_ip.empty();
    if (check_target) {
      target_na = protocol::NetworkAddress::from_string(target_addr_ip, 9590);
    }

    for (const auto& [id, node] : nodes_) {
      // Check if node has target address
      if (check_target) {
        auto addrs = node.addr_mgr->get_addresses(10000, 100);
        for (const auto& ta : addrs) {
          if (ta.address.ip == target_na.ip) {
            m.nodes_with_address++;
            break;
          }
        }
      }

      // Table sizes
      m.avg_tried_size += node.addr_mgr->tried_count();
      m.avg_new_size += node.addr_mgr->new_count();
      m.avg_total_size += node.addr_mgr->size();

      // Traffic
      m.total_addrs_received += node.addrs_received;
      m.total_addrs_relayed += node.addrs_relayed;
    }

    size_t n = nodes_.size();
    if (n > 0) {
      m.avg_tried_size /= n;
      m.avg_new_size /= n;
      m.avg_total_size /= n;
      if (check_target) {
        m.propagation_pct = 100.0 * m.nodes_with_address / n;
      }
    }

    return m;
  }

  // Access config
  NetworkConfig& Config() { return config_; }
  const NetworkConfig& Config() const { return config_; }

private:
  std::map<int, AddrTestNode> nodes_;
  int next_node_id_{0};
  int64_t current_time_;
  std::mt19937 rng_;
  NetworkConfig config_;
};

}  // namespace addrsim
}  // namespace test
}  // namespace unicity
