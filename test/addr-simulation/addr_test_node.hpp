// Copyright (c) 2025 The Unicity Foundation
// Lightweight node stub for address management simulation

#pragma once

#include "network/addr_manager.hpp"
#include "network/protocol.hpp"

#include <memory>
#include <set>
#include <string>
#include <vector>

namespace unicity {
namespace test {
namespace addrsim {

// Lightweight node for address simulation
// Contains only address management components - no networking, no chain
struct AddrTestNode {
  int id{-1};
  std::string ip_address;                            // Node's own IP (for self-announcement)
  std::string netgroup;                              // Node's /16 netgroup
  std::unique_ptr<network::AddressManager> addr_mgr; // Address table
  std::set<int> outbound_peers;                      // Outbound connections (we initiated)
  std::set<int> inbound_peers;                       // Inbound connections (they initiated)

  // GETADDR state (once per connection)
  std::set<int> getaddr_replied_to;

  // Pending ADDR relay (queued for next tick)
  struct PendingRelay {
    int target_id;
    std::vector<protocol::TimestampedAddress> addrs;
  };
  std::vector<PendingRelay> pending_relays;

  // Stats
  uint64_t addrs_received{0};
  uint64_t addrs_relayed{0};
  uint64_t getaddr_requests{0};
  uint64_t getaddr_responses{0};

  AddrTestNode() : addr_mgr(std::make_unique<network::AddressManager>()) {}

  explicit AddrTestNode(int node_id, const std::string& ip)
      : id(node_id),
        ip_address(ip),
        addr_mgr(std::make_unique<network::AddressManager>()) {
    // Extract netgroup from IP (assumes IPv4 format "a.b.c.d")
    auto first_dot = ip.find('.');
    auto second_dot = ip.find('.', first_dot + 1);
    if (first_dot != std::string::npos && second_dot != std::string::npos) {
      netgroup = ip.substr(0, second_dot);
    }
  }

  // Check if we're connected to a peer (either direction)
  bool IsConnectedTo(int peer_id) const {
    return outbound_peers.count(peer_id) > 0 || inbound_peers.count(peer_id) > 0;
  }

  // Get all connected peer IDs
  std::set<int> GetAllConnectedPeers() const {
    std::set<int> all = outbound_peers;
    all.insert(inbound_peers.begin(), inbound_peers.end());
    return all;
  }

  size_t ConnectionCount() const {
    return outbound_peers.size() + inbound_peers.size();
  }
};

}  // namespace addrsim
}  // namespace test
}  // namespace unicity
