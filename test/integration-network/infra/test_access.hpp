// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

// Friend classes for accessing internal state in tests.
// This pattern keeps test-only methods out of production headers
// while allowing tests to manipulate internal state when needed.

#include "network/peer.hpp"
#include "network/network_manager.hpp"
#include "network/real_transport.hpp"
#include "network/connection_manager.hpp"
#include "network/header_sync_manager.hpp"
#include "network/addr_relay_manager.hpp"
#include "network/addr_manager.hpp"
#include "network/anchor_manager.hpp"
#include "network/message_dispatcher.hpp"
#include "chain/chainstate_manager.hpp"

#include <chrono>

namespace unicity {
namespace test {

// Friend class for accessing Peer internals in tests
class PeerTestAccess {
public:
  static void SetState(network::Peer& p, network::PeerConnectionState state) { p.state_ = state; }

  static void SetSuccessfullyConnected(network::Peer& p, bool value) { p.successfully_connected_ = value; }

  static void SetPeerNonce(network::Peer& p, uint64_t nonce) { p.peer_nonce_ = nonce; }

  static void SetVersion(network::Peer& p, int32_t version) { p.peer_version_ = version; }

  static void SetPingTime(network::Peer& p, std::chrono::milliseconds ms) {
    p.stats_.ping_time_ms.store(ms, std::memory_order_relaxed);
  }

  // Static timeout overrides (affect all Peer instances)
  static void SetTimeouts(std::chrono::milliseconds handshake_ms, std::chrono::milliseconds inactivity_ms);
  static void ResetTimeouts();
};

// Friend class for accessing NetworkManager internals in tests
class NetworkManagerTestAccess {
public:
  // Access internal managers for test diagnostics
  static network::MessageDispatcher& GetDispatcher(network::NetworkManager& nm) {
    return *nm.message_dispatcher_;
  }

  static network::AddrRelayManager& GetDiscoveryManager(network::NetworkManager& nm) {
    return *nm.addr_relay_mgr_;
  }

  static network::HeaderSyncManager& GetHeaderSync(network::NetworkManager& nm) {
    return *nm.header_sync_manager_;
  }

  // Trigger internal methods for testing
  static void CheckInitialSync(network::NetworkManager& nm) {
    nm.check_initial_sync();
  }

  static void ProcessHeaderSyncTimers(network::NetworkManager& nm) {
    nm.header_sync_manager_->ProcessTimers();
  }

  static void TriggerSelfAdvertisement(network::NetworkManager& nm);

  static void AttemptFeelerConnection(network::NetworkManager& nm);

  static void AttemptExtraBlockRelayConnection(network::NetworkManager& nm) {
    nm.attempt_extra_block_relay_connection();
  }

  // Set default inbound permissions
  static void SetDefaultInboundPermissions(network::NetworkManager& nm, network::NetPermissionFlags flags) {
    nm.default_inbound_permissions_ = flags;
  }

  // NAT / local address test access
  static void SetLocalAddr(network::NetworkManager& nm, const protocol::NetworkAddress& addr);
  static void ClearLocalAddr(network::NetworkManager& nm);
  static std::optional<protocol::NetworkAddress> GetLocalAddr(network::NetworkManager& nm);
  static bool HasLocalAddr(network::NetworkManager& nm);
  static void ResetNextLocalAddrSend(network::NetworkManager& nm);
};

// Friend class for accessing AddrRelayManager internals in tests
class AddrRelayManagerTestAccess {
public:
  // Access internal managers
  static network::AddressManager& GetAddrManager(network::AddrRelayManager& pdm) {
    return *pdm.addr_manager_;
  }

  static network::AnchorManager& GetAnchorManager(network::AddrRelayManager& pdm) {
    return *pdm.anchor_manager_;
  }

  // RNG seeding for deterministic tests
  static void SeedRng(network::AddrRelayManager& pdm, uint64_t seed) {
    pdm.rng_.seed(seed);
  }

  static void SeedAddrRelay(network::AddrRelayManager& pdm, uint64_t seed0, uint64_t seed1) {
    pdm.addr_relay_seed0_ = seed0;
    pdm.addr_relay_seed1_ = seed1;
  }

  // GETADDR cache access
  static size_t GetCachedAddrCount(network::AddrRelayManager& pdm) {
    return pdm.addr_response_cache_.addresses.size();
  }

  static void ClearAddrCache(network::AddrRelayManager& pdm) {
    pdm.addr_response_cache_.addresses.clear();
    pdm.addr_response_cache_.expiration = std::chrono::steady_clock::time_point{};
  }

  // Deterministic relay target selection
  static std::vector<network::PeerPtr> SelectAddrRelayTargets(
      network::AddrRelayManager& pdm,
      const protocol::NetworkAddress& addr,
      const std::vector<network::PeerPtr>& candidates) {
    return pdm.SelectAddrRelayTargets(addr, candidates);
  }

  // Pending relay count
  static size_t GetPendingAddrRelayCount(network::AddrRelayManager& pdm);

  // HandleAddr call count
  static uint64_t GetHandleAddrCallCount(network::AddrRelayManager& pdm) {
    return pdm.stats_handleaddr_calls_.load(std::memory_order_relaxed);
  }
};

// Friend class for accessing ConnectionManager internals in tests
class ConnectionManagerTestAccess {
public:
  // Set peer created_at timestamp for testing eviction
  static void SetPeerCreatedAt(network::ConnectionManager& pm, int peer_id, std::chrono::steady_clock::time_point tp);

  // Clear pending outbound connections
  static void ClearPendingOutbound(network::ConnectionManager& pm) {
    pm.pending_outbound_.clear();
  }
};

// Friend class for accessing HeaderSyncManager internals in tests
class HeaderSyncManagerTestAccess {
public:
  static int GetProtectedOutboundCount(network::HeaderSyncManager& hsm) {
    return hsm.protected_outbound_count_;
  }

  static void SetProtectedOutboundCount(network::HeaderSyncManager& hsm, int count) {
    hsm.protected_outbound_count_ = count;
  }

  // Override continuation threshold for testing (defaults to MAX_HEADERS_SIZE)
  static void SetContinuationThreshold(network::HeaderSyncManager& hsm, size_t threshold) {
    hsm.continuation_threshold_ = threshold;
  }

  static size_t GetContinuationThreshold(network::HeaderSyncManager& hsm) {
    return hsm.continuation_threshold_;
  }
};

// Friend class for accessing RealTransportConnection internals in tests
class RealTransportTestAccess {
public:
  // Static timeout overrides
  static void SetConnectTimeout(std::chrono::milliseconds timeout_ms) {
    network::RealTransportConnection::connect_timeout_override_ms_.store(timeout_ms, std::memory_order_relaxed);
  }

  static void ResetConnectTimeout() {
    network::RealTransportConnection::connect_timeout_override_ms_.store(std::chrono::milliseconds{0}, std::memory_order_relaxed);
  }

  // Static send queue limit override
  static void SetSendQueueLimit(size_t bytes) {
    network::RealTransportConnection::send_queue_limit_override_bytes_.store(bytes, std::memory_order_relaxed);
  }

  static void ResetSendQueueLimit() {
    network::RealTransportConnection::send_queue_limit_override_bytes_.store(0, std::memory_order_relaxed);
  }
};

}  // namespace test
}  // namespace unicity
