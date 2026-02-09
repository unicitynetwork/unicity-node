// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

/*
 AddrRelayManager — peer discovery coordinator

 Purpose
 - Own and coordinate AddressManager (peer address database) and AnchorManager (eclipse resistance)
 - Handle peer discovery protocol messages (ADDR/GETADDR)
 - Provide unified interface for address management and anchor persistence
 - Consolidate discovery-related components under one manager

 Key responsibilities
 1. Own AddressManager and AnchorManager
 2. Handle ADDR/GETADDR protocol messages
 3. Implement echo suppression (don't send addresses back to source)
 4. Provide forwarding methods for address operations
 5. Provide forwarding methods for anchor operations
*/

#include "network/connection_types.hpp"
#include "network/message.hpp"
#include "network/peer.hpp"
#include "network/peer_discovery_interface.hpp"
#include "network/peer_tracking.hpp"
#include "network/protocol.hpp"

#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <vector>

namespace unicity {

// Forward declaration for test access
namespace test {
class AddrRelayManagerTestAccess;
}  // namespace test

// Forward declarations for chain types
namespace chain {
class ChainParams;
}

namespace network {

// Forward declarations
class AddressManager;
class AnchorManager;
class ConnectionManager;


class AddrRelayManager : public PeerDiscoveryInterface {
public:
  explicit AddrRelayManager(ConnectionManager* connman, const std::string& datadir = "");
  ~AddrRelayManager();

  // Non-copyable
  AddrRelayManager(const AddrRelayManager&) = delete;
  AddrRelayManager& operator=(const AddrRelayManager&) = delete;

  using ConnectToAnchorsCallback = std::function<void(const std::vector<protocol::NetworkAddress>&)>;

  // Load anchors and bootstrap from fixed seeds if needed
  void Start(ConnectToAnchorsCallback connect_anchors);

  // === Protocol Message Handlers ===

  bool HandleAddr(PeerPtr peer, message::AddrMessage* msg);
  bool HandleGetAddr(PeerPtr peer);

  // Boost peer's ADDR rate limit bucket after we send GETADDR
  void NotifyGetAddrSent(int peer_id) override;

  // === Peer Lifecycle Callbacks (called by ConnectionManager) ===

  // OnPeerConnected: Called when a peer handshake completes (post-VERACK).
  // - Adds OUTBOUND_FULL_RELAY peers to AddressManager (so we can remember they are good nodes).
  // - Ignores BLOCK_RELAY (privacy/eclipse protection) and INBOUND (unverified source).
  void OnPeerConnected(int peer_id,
                       const std::string& address,
                       uint16_t port,
                       ConnectionType connection_type) override;
  
  // OnPeerDisconnected: Handles AddressManager updates upon disconnection.
  // - mark_addr_good: If true, calls good(). Used for short-lived "Feeler" connections that successfully handshook.
  //   Effect: Moves address from New (unverified) -> Tried (verified) table.
  // - mark_addr_connected: If true, calls connected(). Used for long-lived outbound peers.
  //   Effect: Updates "last seen" timestamp in Tried table to keep address fresh.
  void OnPeerDisconnected(int peer_id,
                          const std::string& address,
                          uint16_t port,
                          bool mark_addr_good,
                          bool mark_addr_connected) override;

  // === AddressManager Forwarding Methods ===

  // Attempt: Records a connection attempt to an address.
  // - Updates "last try" timestamp (preventing rapid retries).
  // - count_failures: If true (default), increments failure count.
  //   Set to false if *we* might be offline, to avoid penalizing good peers.
  void Attempt(const protocol::NetworkAddress& addr, bool count_failures = true) override;

  // Good: Records a successful connection/handshake.
  // - Promotes address from New (unverified) -> Tried (verified) table.
  // - Resets failure count to 0.
  // - Updates timestamp to keep address fresh in our database.
  void Good(const protocol::NetworkAddress& addr) override;

  // Select: Picks an address for a regular outbound connection.
  // - Weighted towards "Tried" (verified) addresses for higher connection success rate.
  // - Used when we need a long-lived peer.
  std::optional<protocol::NetworkAddress> Select() override;

  // SelectNewForFeeler: Picks an address specifically for a "Feeler" connection.
  // - Weighted towards "New" (unverified) addresses to test if they are online.
  // - If successful, "Good()" will be called to promote it to "Tried".
  std::optional<protocol::NetworkAddress> SelectNewForFeeler() override;

  size_t Size() const;
  size_t TriedCount() const;
  size_t NewCount() const;

  bool SaveAddresses(const std::string& filepath);
  bool LoadAddresses(const std::string& filepath);

  // Low-level access for RPC diagnostics (getrawaddrman)
  AddressManager& addr_manager() { return *addr_manager_; }
  const AddressManager& addr_manager() const { return *addr_manager_; }

  // === AnchorManager Forwarding Methods ===

  std::vector<protocol::NetworkAddress> GetAnchors() const;
  bool SaveAnchors(const std::string& filepath);
  std::vector<protocol::NetworkAddress> LoadAnchors(const std::string& filepath);

  // === Test/Diagnostic Methods ===

  // Add a peer address directly to AddrMan (for testing/RPC)
  bool AddPeerAddress(const std::string& address, uint16_t port);

  struct GetAddrDebugStats {
    uint64_t total{0};
    uint64_t served{0};
    uint64_t ignored_outbound{0};
    uint64_t ignored_prehandshake{0};
    uint64_t ignored_repeat{0};
    size_t last_from_addrman{0};
    size_t last_suppressed{0};
  };
  GetAddrDebugStats GetGetAddrDebugStats() const;

private:
  // Test access - allows test code to manipulate internal state
  friend class test::AddrRelayManagerTestAccess;

  std::string datadir_;
  ConnectionManager* connman_;
  std::unique_ptr<AddressManager> addr_manager_;
  std::unique_ptr<AnchorManager> anchor_manager_;

  // How long we remember that a peer knows an address (to avoid sending it back).
  static constexpr int64_t ECHO_SUPPRESS_TTL_SEC = 600;

  // Maximum number of addresses we track per peer for deduplication.
  // If a peer sends us >2000 unique addresses in 10 mins, we start evicting old ones.
  static constexpr size_t MAX_LEARNED_PER_PEER = 2000;

  // Eviction Hysteresis:
  // When learned addresses > 2200 (1.1 * 2000), we evict down to 1800 (0.9 * 2000).
  // This prevents constant re-balancing at the threshold.
  static constexpr double EVICTION_TRIGGER_RATIO = 1.1;
  static constexpr double EVICTION_TARGET_RATIO = 0.9;

  static constexpr int64_t ADDR_TRICKLE_MEAN_MS = 30000;  // Mean delay before relay (Poisson)

  // All peers within the cache window get the same 23% sample of AddrMan
  // Cache expires after 21-27 hours (21h base + 0-6h random jitter)
  static constexpr auto ADDR_RESPONSE_CACHE_BASE = std::chrono::hours(21);
  static constexpr auto ADDR_RESPONSE_CACHE_JITTER = std::chrono::hours(6);

  // ADDR protocol constants
  static constexpr int64_t ADDR_TIME_PENALTY_SEC = 2 * 60 * 60;  // 2 hours - prevents timestamp manipulation
  static constexpr int64_t RELAY_FRESHNESS_SEC = 600;            // 10 minutes - only relay fresh addresses
  static constexpr size_t MAX_PCT_ADDR_TO_SEND = 23;             // Max % of AddrMan to send in GETADDR response

  static constexpr int64_t TIMESTAMP_FUTURE_LIMIT_SEC = 600;             // 10 minutes - max clock skew allowed
  static constexpr int64_t TIMESTAMP_PENALTY_DAYS = 5;                   // Penalty for suspicious timestamps

  // Deterministic relay target rotation interval (matches Core's ROTATE_ADDR_RELAY_DEST_INTERVAL)
  static constexpr int64_t ROTATE_ADDR_RELAY_DEST_INTERVAL_SEC = 24 * 60 * 60;  // 24 hours

  // Anti-Reconnaissance Cache
  // - To prevent mapping our topology by spamming GETADDR,
  //   we cache the response and serve the *same* subset of peers to everyone for ~24h.
  // - This limits an attacker to learning only ~23% of our peers per day.
  struct CachedAddrResponse {
    std::vector<protocol::TimestampedAddress> addresses;
    std::chrono::steady_clock::time_point expiration{};
  };
  CachedAddrResponse addr_response_cache_;

  // Deterministic ADDR relay peer selection
  // - We select 2 peers to relay an address to, based on: SipHash(Randomizer | Address | TimeBucket | PeerID).
  // - This ensures that for a given time window (24h), we always relay the same address to the same peers.
  // - Prevents an attacker from easily mapping propagation paths by just reconnecting.
  // - RANDOMIZER_ID is a domain separator for the SipHash function.
  static constexpr uint64_t RANDOMIZER_ID_ADDRESS_RELAY = 0x3cac0035b5866b90ULL;

  // Number of peers each address is relayed to (Core: ADDR_RELAY_TO_DESTINATIONS)
  static constexpr size_t ADDR_RELAY_TO_DESTINATIONS = 2;

  // 128-bit secret key for the SipHash function (initialized on startup).
  uint64_t addr_relay_seed0_{0};
  uint64_t addr_relay_seed1_{0};

  // Select relay targets deterministically based on address hash and time bucket
  std::vector<PeerPtr> SelectAddrRelayTargets(
      const protocol::NetworkAddress& addr,
      const std::vector<PeerPtr>& candidates);

  std::atomic<uint64_t> stats_handleaddr_calls_{0};  // For testing: count HandleAddr invocations
  std::atomic<uint64_t> stats_getaddr_total_{0};
  std::atomic<uint64_t> stats_getaddr_served_{0};
  std::atomic<uint64_t> stats_getaddr_ignored_outbound_{0};
  std::atomic<uint64_t> stats_getaddr_ignored_prehandshake_{0};
  std::atomic<uint64_t> stats_getaddr_ignored_repeat_{0};
  std::atomic<size_t> last_resp_from_addrman_{0};
  std::atomic<size_t> last_resp_suppressed_{0};

  // Random number generator for:
  // - Address list shuffling (HandleGetAddr)
  // - Adding jitter to cache expiration
  // - Generating Poisson delays for address relay (trickling)
  std::mt19937 rng_;

  // Per-peer ADDR Message Rate Limiting
  // - Implements a token bucket filter to prevent ADDR spam from malicious peers.
  // - Each peer has its own token bucket.
  // - Rate: 0.1 tokens/sec (1 address processed every 10 seconds).
  // - Burst: Up to 1000 addresses (MAX_ADDR_SIZE) allowed instantly if accumulated.
  // - Excessive addresses are dropped/ignored.
  struct AddrRateLimitState {
    double token_bucket{1.0};
    std::chrono::steady_clock::time_point last_update{};
    uint64_t addr_processed{0};
    uint64_t addr_rate_limited{0};
  };
  std::unordered_map<int, AddrRateLimitState> addr_rate_limit_;
  static constexpr double MAX_ADDR_RATE_PER_SECOND = 0.1;
  static constexpr double MAX_ADDR_PROCESSING_TOKEN_BUCKET = protocol::MAX_ADDR_SIZE;

  // Max addresses queued per peer for relay 
  static constexpr size_t MAX_ADDR_TO_SEND = 1000;

  void BootstrapFromFixedSeeds(const chain::ChainParams& params);

  // Addresses queue up per-peer and are sent in batches when timer fires
  struct PeerAddrSendState {
    std::vector<protocol::TimestampedAddress> addrs_to_send;
    std::chrono::steady_clock::time_point next_send_time{};
  };
  std::unordered_map<int, PeerAddrSendState> peer_addr_send_state_;

public:
  // Process pending ADDR relays (called periodically from NetworkManager)
  void ProcessPendingAddrRelays();
};

}  // namespace network
}  // namespace unicity
