// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

/*
 ConnectionManager — unified peer lifecycle and misbehavior tracking

 Purpose
 - Maintain a registry of active peer connections (both inbound and outbound)
 - Enforce connection limits (max_inbound, max_outbound)
 - Track misbehavior scores and apply DoS protection policies
 - Coordinate with AddressManager for connection lifecycle updates (good/failed)
 - Provide connection/eviction logic for connection management

 Key responsibilities
 1. Peer lifecycle: add, remove, lookup by ID or address
 2. Connection policy: limit enforcement, feeler connections, eviction
 3. Misbehavior tracking: score accumulation, thresholds, disconnect decisions
 4. Permission system: NoBan and Manual flags to protect certain connections
 5. Integration: notifies AddrRelayManager and HeaderSyncManager directly
 6. Address lifecycle: reports connection outcomes to AddrRelayManager

 Misbehavior system
 - Any misbehavior results in instant discouragement (no score accumulation)
 - Permission flags can prevent banning (NoBan) or mark manual connections
 - Duplicate-invalid tracking: avoid double-penalizing the same invalid header

 Violations (all result in instant discouragement)
   - Invalid proof of work
   - Invalid header (checkpoints, difficulty, structure)
   - Non-continuous headers sequence
   - Oversized messages
   - Pre-VERACK protocol messages

 Note: Unconnecting headers (unknown parent) trigger GETHEADERS but no penalty.

 Connection limits
 - max_full_relay_outbound: default 8 (full address relay)
 - max_block_relay_outbound: default 2 (eclipse resistance, no address relay)
 - max_inbound_peers: default 125

 Feeler connections
 - Short-lived test connections to validate addresses in the "new" table
 - Normal disconnect: after VERSION in Peer::handle_version()
 - Address marked good in remove_peer() on successful disconnect (NEW→TRIED promotion)
 - FEELER_MAX_LIFETIME_SEC = 120: safety net timeout for stuck handshakes (2x handshake timeout)
 - Marked as feeler via PeerPtr flags, tracked for cleanup in process_periodic()

 Public API design
 - Report* methods: external code (HeaderSync, message handlers) reports violations
   • ReportInvalidPoW, ReportInvalidHeader, ReportLowWorkHeaders, etc.
   • Each marks the peer for discouragement (instant, no score accumulation)
 - Query methods: ShouldDisconnect() for testing/debugging
 - NO direct penalty manipulation from external code


 Threading
 - Peer registry (peer_states_) is a ThreadSafeMap with internal locking
 - mutex_ protects pending_outbound_ and manual_addresses_ (accessed by RPC threads)
 - Shutdown() sets flag to prevent notifications during destruction
 - Calls AddrRelayManager and HeaderSyncManager directly on peer disconnect

 Differences from Bitcoin Core
 - Simpler permission model: only NoBan and Manual flags (no BloomFilter, etc.)
 - /16 subnet netgroups only, no ASN-based grouping (no NetGroupManager)
 - Misbehavior data stored separately from Peer objects for cleaner separation
 - Feeler connections explicitly tracked and aged out (no implicit heuristics)
 - Inbound eviction: delegated to EvictionManager with multi-phase protection:
   • Protect 8 peers by lowest ping, 4 by recent header relay, 50% by uptime
   • Evict from netgroup with most connections (network diversity preservation)

 Notes
 - find_peer_by_address() requires exact IP:port match if port != 0
 - evict_inbound_peer() delegates to EvictionManager for candidate selection
 - process_periodic() should be called regularly (e.g., every 10 seconds) to
   handle feeler cleanup and connection maintenance
*/

#include "network/addr_manager.hpp"
#include "network/ban_manager.hpp"
#include "network/misbehavior_manager.hpp"
#include "network/peer.hpp"
#include "network/peer_discovery_interface.hpp"
#include "network/peer_misbehavior.hpp"  // For PeerMisbehaviorData, NetPermissionFlags, etc.
#include "network/peer_tracking.hpp"
#include "util/threadsafe_containers.hpp"

#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <unordered_set>

namespace unicity {

// Forward declaration for test access
namespace test {
class ConnectionManagerTestAccess;
}  // namespace test

namespace network {

// Forward declarations
class HeaderSyncManager;
class Transport;
enum class ConnectionResult;  // From network_manager.hpp

class ConnectionManager {
public:
  struct Config {
    // Full-relay outbound: connections with full address relay
    size_t max_full_relay_outbound;     // Max full-relay outbound connections (default: 8)
    size_t target_full_relay_outbound;  // Target full-relay outbound connections (default: 8)

    // Block-relay-only outbound: eclipse attack resistance, no address relay
    size_t max_block_relay_outbound;     // Max block-relay-only connections (default: 2)
    size_t target_block_relay_outbound;  // Target block-relay-only connections (default: 2)

    // Legacy: total outbound (full-relay + block-relay, excludes manual/feeler)
    size_t max_outbound_peers;     // Max total outbound (sum of full + block-relay)
    size_t max_inbound_peers;      // Max inbound connections
    size_t target_outbound_peers;  // Try to maintain this many total outbound

    Config()
        : max_full_relay_outbound(protocol::DEFAULT_MAX_FULL_RELAY_OUTBOUND),
          target_full_relay_outbound(protocol::DEFAULT_MAX_FULL_RELAY_OUTBOUND),
          max_block_relay_outbound(protocol::DEFAULT_MAX_BLOCK_RELAY_OUTBOUND),
          target_block_relay_outbound(protocol::DEFAULT_MAX_BLOCK_RELAY_OUTBOUND),
          max_outbound_peers(protocol::DEFAULT_MAX_OUTBOUND_CONNECTIONS),
          max_inbound_peers(protocol::DEFAULT_MAX_INBOUND_CONNECTIONS),
          target_outbound_peers(protocol::DEFAULT_MAX_OUTBOUND_CONNECTIONS) {}
  };

  explicit ConnectionManager(asio::io_context& io_context,
                             const Config& config = Config{},
                             const std::string& datadir = "");

  // Max lifetime for a feeler connection before forced removal
  static constexpr int FEELER_MAX_LIFETIME_SEC = 120;

  ~ConnectionManager();

  // Set AddrRelayManager (must be called after construction to enable address tracking)
  void SetAddrRelayManager(PeerDiscoveryInterface* addr_relay_mgr);

  // Set HeaderSyncManager (must be called after construction to enable sync peer tracking)
  void SetHeaderSyncManager(HeaderSyncManager* sync_mgr);

  // Shutdown: disable callbacks and mark as shutting down 
  void Shutdown();

  // Add a peer (with optional permissions)
  // Allocates peer ID internally and adds to manager
  // Returns the assigned peer_id on success, -1 on failure
  // prefer_evict: mark discouraged inbound peers for eviction priority
  // bypass_slot_limit: allow exceeding configured slot limits (extra block-relay rotation)
  int add_peer(PeerPtr peer,
               NetPermissionFlags permissions = NetPermissionFlags::None,
               const std::string& address = "",
               bool prefer_evict = false,
               bool bypass_slot_limit = false);

  // Remove a peer by ID (idempotent - safe to call multiple times with same ID)
  void remove_peer(int peer_id);

  // Get a peer by ID
  PeerPtr get_peer(int peer_id);

  // Find peer ID by address:port. Returns -1 if not found.
  // Contract: if port != 0, requires exact address:port match
  int find_peer_by_address(const std::string& address, uint16_t port);

  // Get all active peers
  std::vector<PeerPtr> get_all_peers();

  // Get outbound peers only
  std::vector<PeerPtr> get_outbound_peers();

  // Get inbound peers only
  std::vector<PeerPtr> get_inbound_peers();

  // Get count of active peers
  size_t peer_count() const;
  size_t outbound_count() const;  // Total outbound (full-relay + block-relay, excludes feeler/manual)
  size_t inbound_count() const;

  // Separate outbound counts by type
  size_t full_relay_outbound_count() const;   // Full-relay outbound connections
  size_t block_relay_outbound_count() const;  // Block-relay-only outbound connections
  size_t pending_full_relay_count() const;    // Pending full-relay connections (in-flight)
  size_t pending_block_relay_count() const;   // Pending block-relay connections (in-flight)

  // Metrics accessors (single-threaded network - direct read)
  uint64_t GetOutboundAttempts() const { return metrics_outbound_attempts_; }
  uint64_t GetOutboundSuccesses() const { return metrics_outbound_successes_; }
  uint64_t GetOutboundFailures() const { return metrics_outbound_failures_; }
  uint64_t GetFeelerAttempts() const { return metrics_feeler_attempts_; }
  uint64_t GetFeelerSuccesses() const { return metrics_feeler_successes_; }
  uint64_t GetFeelerFailures() const { return metrics_feeler_failures_; }

  // Check if we need more outbound connections
  bool needs_more_outbound() const;              // Either full-relay or block-relay slots available
  bool needs_more_full_relay_outbound() const;   // Full-relay slots below target
  bool needs_more_block_relay_outbound() const;  // Block-relay slots below target

  // Returns which type of outbound connection to make next
  // Priority: block-relay if slots available (security), then full-relay
  ConnectionType next_outbound_type() const;

  // Check if we can accept more inbound connections
  bool can_accept_inbound() const;

  // Try to evict a peer to make room for a new inbound connection
  // Returns true if a peer was evicted
  bool evict_inbound_peer();

  // Disconnect and remove all peers
  void disconnect_all();

  // Process periodic tasks (cleanup, connection maintenance)
  void process_periodic();

  // === Misbehavior Tracking (delegated to MisbehaviorManager) ===
  // Public API for reporting protocol violations
  void ReportInvalidPoW(int peer_id);
  void ReportOversizedMessage(int peer_id);
  void ReportNonContinuousHeaders(int peer_id);
  void ReportLowWorkHeaders(int peer_id);
  void ReportInvalidHeader(int peer_id, const std::string& reason);
  void ReportPreVerackMessage(int peer_id);

  // Duplicate-invalid tracking
  void NoteInvalidHeaderHash(int peer_id, const uint256& hash);
  bool HasInvalidHeaderHash(int peer_id, const uint256& hash) const;

  // Query misbehavior state (for testing/debugging)
  bool ShouldDisconnect(int peer_id) const;
  bool IsMisbehaving(int peer_id) const;  // Ignores NoBan - for testing NoBan peers

  // Get peer permissions (for protocol logic, e.g., Download flag)
  NetPermissionFlags GetPeerPermissions(int peer_id) const;

  // === Ban Management (delegated to BanManager) ===
  // Two-tier system:
  // 1. Manual bans: Persistent, stored on disk, permanent or timed
  // 2. Discouragement: Temporary, in-memory, for misbehavior

  // Persistent ban management
  void Ban(const std::string& address, int64_t ban_time_offset = 0);
  void Unban(const std::string& address);
  bool IsBanned(const std::string& address) const;
  std::map<std::string, BanManager::BanEntry> GetBanned() const;
  void ClearBanned();
  void SweepBanned();

  // Temporary discouragement (misbehavior)
  void Discourage(const std::string& address);
  bool IsDiscouraged(const std::string& address) const;
  void ClearDiscouraged();
  void SweepDiscouraged();

  // Persistence
  bool LoadBans(const std::string& datadir);
  bool SaveBans();

  // === PeerTrackingData Accessors (for AddrRelay, etc.) ===

  // Address discovery state accessors
  bool HasRepliedToGetAddr(int peer_id) const;
  void MarkGetAddrReplied(int peer_id);
  void AddLearnedAddress(int peer_id, const AddressKey& key, const LearnedEntry& entry);
  std::optional<LearnedMap> GetLearnedAddresses(int peer_id) const;
  void ClearLearnedAddresses(int peer_id);

  // Header relay tracking (for eviction protection - peers that do useful work)
  void UpdateLastHeadersReceived(int peer_id);

  // Get count of "extra" block-relay peers (above target).
  // Returns 0 if at or below target, positive if we have extra temporary peers.
  // Used for extra block-relay peer rotation
  size_t GetExtraBlockRelayCount() const;

  // Get oldest block-relay-only outbound peer by last_headers_received time
  // Returns peer_id, or -1 if no block-relay-only outbound peers exist
  int GetOldestBlockRelayPeer() const;

  // In-place modification of learned addresses
  template <typename Func>
  void ModifyLearnedAddresses(int peer_id, Func&& modifier) {
    peer_states_.Modify(peer_id, [&](PeerPtr& peer) { modifier(peer->learned_addresses()); });
  }

  // === Initialization ===

  // Initialize stable connection parameters (must be called before any connection methods)
  // These values are constant for the lifetime of the manager.
  void Init(std::shared_ptr<Transport> transport,
            std::function<void(Peer*)> setup_message_handler,
            std::function<bool()> is_running,
            uint32_t network_magic,
            uint64_t local_nonce);

  // === Connection Management ===

  // Attempt to establish new outbound connections
  // Coordinates address selection, duplicate checking, and connection attempts
  // Automatically fills block-relay-only slots first (security priority), then full-relay slots
  void AttemptOutboundConnections(int32_t current_height);

  // Attempt a feeler connection to validate addresses in the "new" table
  // Feeler connections are short-lived test connections that disconnect after handshake
  void AttemptFeelerConnection(int32_t current_height);

  // Connect to anchor peers
  // Anchors are the last 2-3 outbound peers from the previous session
  void ConnectToAnchors(const std::vector<protocol::NetworkAddress>& anchors, int32_t current_height);

  // Check if incoming nonce collides with our local nonce or any existing peer's remote nonce
  // Detect self-connection and duplicate connections
  bool CheckIncomingNonce(uint64_t nonce);

  // Connect to a peer address (main outbound connection logic)
  // Performs all checks (banned, discouraged, already connected, slot availability)
  // and initiates async transport connection.
  // bypass_slot_limit: allows extra block-relay connections beyond the configured max
  //   (used for periodic block-relay rotation)
  ConnectionResult ConnectTo(const protocol::NetworkAddress& addr,
                             NetPermissionFlags permissions,
                             int32_t chain_height,
                             ConnectionType conn_type = ConnectionType::OUTBOUND_FULL_RELAY,
                             bool bypass_slot_limit = false);

  // Handle an inbound connection
  // Processes incoming connections, validates against bans/limits, creates peer
  void HandleInboundConnection(TransportConnectionPtr connection,
                               int32_t current_height,
                               NetPermissionFlags permissions = NetPermissionFlags::None);

  // === Protocol Message Handlers ===

  // Handle VERACK message - mark outbound peers as successful in address manager
  bool HandleVerack(PeerPtr peer);

private:
  // Test access
  friend class test::ConnectionManagerTestAccess;

  asio::io_context& io_context_;
  PeerDiscoveryInterface* addr_relay_mgr_{nullptr};  // Injected after construction
  HeaderSyncManager* header_sync_manager_{nullptr};     // Injected after construction
  Config config_;

  // Stable connection parameters (set once via Init(), constant thereafter)
  std::shared_ptr<Transport> transport_;
  std::function<void(Peer*)> setup_message_handler_;
  std::function<bool()> is_running_;
  uint32_t network_magic_{0};
  uint64_t local_nonce_{0};

  // Protects concurrent access to manual_addresses_, pending_outbound_, and other non-atomic shared state
  // Required because RPC threads (addnode, etc.) access these members concurrently with the reactor thread
  mutable std::recursive_mutex mutex_;

  // === Peer Registry ===
  // Maps peer ID to Peer object (all per-peer state is now consolidated in Peer)
  util::ThreadSafeMap<int, PeerPtr> peer_states_;

  // Get next available peer ID
  // Monotonic 32-bit counter; IDs are only allocated after connection succeeds
  // (we do not recycle IDs within a process lifetime)
  std::atomic<int> next_peer_id_{1};

  // Track in-flight outbound connection attempts to avoid duplicate concurrent dials
  // Maps address -> connection type to enable per-type limit checking
  std::unordered_map<AddressKey, ConnectionType, AddressKey::Hasher> pending_outbound_;

  // Track manually-added addresses (via addnode RPC) 
  std::unordered_set<AddressKey, AddressKey::Hasher> manual_addresses_;

  // === Lightweight connection metrics (for observability) ===
  // Atomic to allow lock-free reading from RPC threads
  std::atomic<uint64_t> metrics_outbound_attempts_{0};
  std::atomic<uint64_t> metrics_outbound_successes_{0};
  std::atomic<uint64_t> metrics_outbound_failures_{0};
  std::atomic<uint64_t> metrics_feeler_attempts_{0};
  std::atomic<uint64_t> metrics_feeler_successes_{0};
  std::atomic<uint64_t> metrics_feeler_failures_{0};

  // Shutdown flag to guard callbacks during destruction
  std::atomic<bool> shutting_down_{false};
  // In-progress bulk shutdown (disconnect_all); reject add_peer while true
  std::atomic<bool> stopping_all_{false};
  // === Ban Management (delegated to BanManager) ===
  std::unique_ptr<BanManager> ban_manager_;

  // === Misbehavior Management (delegated to MisbehaviorManager) ===
  std::unique_ptr<MisbehaviorManager> misbehavior_manager_;
};

}  // namespace network
}  // namespace unicity
