// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

/*
 PeerDiscoveryInterface — abstract interface for peer discovery operations

 Methods fall into two categories:
 1. Event notifications: OnPeerConnected, OnPeerDisconnected
 2. Address operations: Select, Attempt, Good, etc.
*/

#include "network/connection_types.hpp"
#include "network/protocol.hpp"

#include <optional>
#include <string>

namespace unicity {
namespace network {

class PeerDiscoveryInterface {
public:
  virtual ~PeerDiscoveryInterface() = default;

  // === Event Notifications ===
  // Called by ConnectionManager when peer lifecycle changes

  virtual void OnPeerConnected(int peer_id, const std::string& address, uint16_t port,
                               ConnectionType connection_type) = 0;


  virtual void OnPeerDisconnected(int peer_id, const std::string& address, uint16_t port,
                                  bool mark_addr_good, bool mark_addr_connected) = 0;

  // === Address Operations ===
  // Used by ConnectionManager for connection management

  // Select an address for outbound connection (from TRIED or NEW tables)
  virtual std::optional<protocol::NetworkAddress> Select() = 0;

  // Select an address from NEW table for feeler connection
  virtual std::optional<protocol::NetworkAddress> SelectNewForFeeler() = 0;

  // Mark address as connection attempt
  // count_failures: if true, increment failure counter
  virtual void Attempt(const protocol::NetworkAddress& addr, bool count_failures = true) = 0;

  // Mark address as successfully connected (NEW -> TRIED promotion)
  virtual void Good(const protocol::NetworkAddress& addr) = 0;

  // Boost ADDR rate limit after sending GETADDR (allows peer to respond)
  virtual void NotifyGetAddrSent(int peer_id) = 0;
};

}  // namespace network
}  // namespace unicity
