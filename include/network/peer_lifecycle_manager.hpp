#pragma once

/*
 PeerLifecycleManager — unified peer lifecycle and misbehavior tracking

 Purpose
 - Maintain a registry of active peer connections (both inbound and outbound)
 - Enforce connection limits (max_inbound, max_outbound, per-netgroup limits)
 - Track misbehavior scores and apply DoS protection policies
 - Coordinate with AddressManager for connection lifecycle updates (good/failed)
 - Provide peer discovery/eviction logic for connection management

 Key responsibilities
 1. Peer lifecycle: add, remove, lookup by ID or address
 2. Connection policy: limit enforcement, feeler connections, eviction
 3. Misbehavior tracking: score accumulation, thresholds, disconnect decisions
 4. Permission system: NoBan and Manual flags to protect certain connections
 5. Integration: notifies PeerDiscoveryManager and HeaderSyncManager directly
 6. Address lifecycle: reports connection outcomes to DiscoveryManager

 Misbehavior system
 - Any misbehavior results in instant discouragement (no score accumulation)
 - Permission flags can prevent banning (NoBan) or mark manual connections
 - Duplicate-invalid tracking: avoid double-penalizing the same invalid header
 - Unconnecting headers: progressive tracking with max threshold before penalty

 Violations (all result in instant discouragement)
   - Invalid proof of work
   - Invalid header (checkpoints, difficulty, structure)
   - Too many unconnecting headers (after MAX_UNCONNECTING_HEADERS threshold)
   - Too many orphan headers
   - Non-continuous headers sequence
   - Oversized messages
   - Pre-VERACK protocol messages

 Connection limits
 - max_outbound_peers: default 8 (protocol::DEFAULT_MAX_OUTBOUND_CONNECTIONS)
 - max_inbound_peers: default 125 (protocol::DEFAULT_MAX_INBOUND_CONNECTIONS)
 - target_outbound_peers: attempt to maintain this many outbound connections
 - MAX_INBOUND_PER_NETGROUP = 4: max inbound connections from same /16 subnet

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
 - Increment/Reset UnconnectingHeaders: track non-connectable header sequences
 - Query methods: ShouldDisconnect() for testing/debugging
 - NO direct penalty manipulation from external code


 Threading
 - All public methods are thread-safe (protected by mutex_)
 - Shutdown() sets flag to prevent notifications during destruction
 - Calls PeerDiscoveryManager and HeaderSyncManager directly on peer disconnect

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
 - TestOnlySetPeerCreatedAt() is for unit tests to simulate feeler aging
 - process_periodic() should be called regularly (e.g., every 10 seconds) to
   handle feeler cleanup and connection maintenance
*/

#include "network/addr_manager.hpp"
#include "network/ban_manager.hpp"
#include "network/misbehavior_manager.hpp"
#include "network/peer.hpp"
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
namespace network {

// Forward declarations
class PeerDiscoveryManager;
class HeaderSyncManager;
class Transport;
enum class ConnectionResult;  // From network_manager.hpp

class PeerLifecycleManager {
public:
  struct Config {
    // Full-relay outbound: connections with full address/transaction relay
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

  explicit PeerLifecycleManager(asio::io_context& io_context, const Config& config = Config{},
                                const std::string& datadir = "");

  // Max lifetime for a feeler connection before forced removal
  static constexpr int FEELER_MAX_LIFETIME_SEC = 120;

  ~PeerLifecycleManager();

  // Set PeerDiscoveryManager (must be called after construction to enable address tracking)
  void SetDiscoveryManager(PeerDiscoveryManager* disc_mgr);

  // Set HeaderSyncManager (must be called after construction to enable sync peer tracking)
  void SetHeaderSyncManager(HeaderSyncManager* sync_mgr);

  // Shutdown: disable callbacks and mark as shutting down 
  void Shutdown();

  // Add a peer (with optional permissions)
  // Allocates peer ID internally and adds to manager
  // Returns the assigned peer_id on success, -1 on failure
  int add_peer(PeerPtr peer, NetPermissionFlags permissions = NetPermissionFlags::None,
               const std::string& address = "");

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

  // Per-netgroup inbound limit
  static constexpr int MAX_INBOUND_PER_NETGROUP = 4;

  // Try to evict a peer to make room for a new inbound connection
  // Returns true if a peer was evicted
  bool evict_inbound_peer();

  // Disconnect and remove all peers
  void disconnect_all();

  // Process periodic tasks (cleanup, connection maintenance)
  void process_periodic();

  // Test-only: set a peer's creation time (used to simulate feeler aging)
  // This method is intentionally public but should only be used in tests
  void TestOnlySetPeerCreatedAt(int peer_id, std::chrono::steady_clock::time_point tp);

  // === Misbehavior Tracking (delegated to MisbehaviorManager) ===
  // Public API for reporting protocol violations

  // Track unconnecting headers from a peer
  void IncrementUnconnectingHeaders(int peer_id);
  void ResetUnconnectingHeaders(int peer_id);
  int GetUnconnectingHeadersCount(int peer_id) const;

  // Report specific protocol violations (used by message handlers)
  void ReportInvalidPoW(int peer_id);
  void ReportOversizedMessage(int peer_id);
  void ReportNonContinuousHeaders(int peer_id);
  void ReportLowWorkHeaders(int peer_id);
  void ReportInvalidHeader(int peer_id, const std::string& reason);
  void ReportTooManyOrphans(int peer_id);
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
  std::map<std::string, BanManager::CBanEntry> GetBanned() const;
  void ClearBanned();
  void SweepBanned();

  // Temporary discouragement (misbehavior)
  void Discourage(const std::string& address);
  bool IsDiscouraged(const std::string& address) const;
  void ClearDiscouraged();
  void SweepDiscouraged();

  // Whitelist (NoBan) support
  void AddToWhitelist(const std::string& address);
  void RemoveFromWhitelist(const std::string& address);
  bool IsWhitelisted(const std::string& address) const;

  // Persistence
  bool LoadBans(const std::string& datadir);
  bool SaveBans();

  // === PeerTrackingData Accessors (for BlockRelayManager, AddrRelay) ===
  // Thread-safe accessors for consolidated per-peer state

  // Block relay state accessors
  // Atomic getter for last announcement (hash + timestamp)
  // Returns pair of (hash, timestamp) or nullopt if peer not found
  // This prevents race conditions when checking TTL in block relay
  std::optional<std::pair<uint256, int64_t>> GetLastAnnouncement(int peer_id) const;
  void SetLastAnnouncedBlock(int peer_id, const uint256& hash, int64_t time_s);

  // Block announcement queue operations
  std::vector<uint256> GetBlocksForInvRelay(int peer_id) const;
  void AddBlockForInvRelay(int peer_id, const uint256& hash);  // Adds with dedup check
  void RemoveBlockForInvRelay(int peer_id, const uint256& hash);
  std::vector<uint256> MoveBlocksForInvRelay(int peer_id);  // Move and clear
  void ClearBlocksForInvRelay(int peer_id);

  // Address discovery state accessors
  bool HasRepliedToGetAddr(int peer_id) const;
  void MarkGetAddrReplied(int peer_id);
  void AddLearnedAddress(int peer_id, const AddressKey& key, const LearnedEntry& entry);
  std::optional<LearnedMap> GetLearnedAddresses(int peer_id) const;
  void ClearLearnedAddresses(int peer_id);

  // Header relay tracking (for eviction protection - peers that do useful work)
  void UpdateLastHeadersReceived(int peer_id);
  // In-place modification of learned addresses (for efficient bulk updates)
  template <typename Func>
  void ModifyLearnedAddresses(int peer_id, Func&& modifier) {
    peer_states_.Modify(peer_id, [&](PeerTrackingData& state) { modifier(state.learned_addresses); });
  }

  // === Connection Management ===

  // Callback types for AttemptOutboundConnections
  // ConnectCallback takes address and connection type (OUTBOUND_FULL_RELAY or BLOCK_RELAY)
  using ConnectCallback = std::function<ConnectionResult(const protocol::NetworkAddress&, ConnectionType)>;
  using IsRunningCallback = std::function<bool()>;

  // Attempt to establish new outbound connections
  // Coordinates address selection, duplicate checking, and connection attempts
  // Automatically fills block-relay-only slots first (security priority), then full-relay slots
  void AttemptOutboundConnections(IsRunningCallback is_running, ConnectCallback connect_fn);

  // Callback types for AttemptFeelerConnection
  using SetupMessageHandlerCallback = std::function<void(Peer*)>;
  using GetTransportCallback = std::function<std::shared_ptr<Transport>()>;


  // Attempt a feeler connection to validate addresses in the "new" table
  // Feeler connections are short-lived test connections that disconnect after handshake
  void AttemptFeelerConnection(IsRunningCallback is_running, GetTransportCallback get_transport,
                               SetupMessageHandlerCallback setup_handler, uint32_t network_magic,
                               int32_t current_height, uint64_t local_nonce);

  // Connect to anchor peers
  // Anchors are the last 2-3 outbound peers from the previous session
  void ConnectToAnchors(const std::vector<protocol::NetworkAddress>& anchors, ConnectCallback connect_fn);

  // Check if incoming nonce collides with our local nonce or any existing peer's remote nonce
  // Detect self-connection and duplicate connections
  bool CheckIncomingNonce(uint64_t nonce, uint64_t local_nonce);

  // Callbacks for ConnectTo method
  using OnGoodCallback = std::function<void(const protocol::NetworkAddress&)>;
  using OnAttemptCallback = std::function<void(const protocol::NetworkAddress&)>;

  // Connect to a peer address (main outbound connection logic)
  // Performs all checks (banned, discouraged, already connected, slot availability)
  // and initiates async transport connection.
  ConnectionResult ConnectTo(const protocol::NetworkAddress& addr, NetPermissionFlags permissions,
                             std::shared_ptr<Transport> transport, OnGoodCallback on_good, OnAttemptCallback on_attempt,
                             SetupMessageHandlerCallback setup_message_handler, uint32_t network_magic,
                             int32_t chain_height, uint64_t local_nonce,
                             ConnectionType conn_type = ConnectionType::OUTBOUND_FULL_RELAY);

  // Handle an inbound connection
  // Processes incoming connections, validates against bans/limits, creates peer
  void HandleInboundConnection(TransportConnectionPtr connection, IsRunningCallback is_running,
                               SetupMessageHandlerCallback setup_handler, uint32_t network_magic,
                               int32_t current_height, uint64_t local_nonce,
                               NetPermissionFlags permissions = NetPermissionFlags::None);

  // === Protocol Message Handlers ===

  // Handle VERACK message - mark outbound peers as successful in address manager
  bool HandleVerack(PeerPtr peer);

private:
  asio::io_context& io_context_;
  PeerDiscoveryManager* discovery_manager_{nullptr};  // Injected after construction
  HeaderSyncManager* header_sync_manager_{nullptr};   // Injected after construction
  Config config_;

  // === State Consolidation ===
  // Unified per-peer state (replaces old peers_, peer_misbehavior_, peer_created_at_ maps)
  util::ThreadSafeMap<int, PeerTrackingData> peer_states_;

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
  uint64_t metrics_outbound_attempts_{0};
  uint64_t metrics_outbound_successes_{0};
  uint64_t metrics_outbound_failures_{0};
  uint64_t metrics_feeler_attempts_{0};
  uint64_t metrics_feeler_successes_{0};
  uint64_t metrics_feeler_failures_{0};

  // Shutdown flag to guard callbacks during destruction
  bool shutting_down_{false};
  // In-progress bulk shutdown (disconnect_all); reject add_peer while true
  bool stopping_all_{false};
  // === Ban Management (delegated to BanManager) ===
  std::unique_ptr<BanManager> ban_manager_;

  // === Misbehavior Management (delegated to MisbehaviorManager) ===
  std::unique_ptr<MisbehaviorManager> misbehavior_manager_;
};

}  // namespace network
}  // namespace unicity
