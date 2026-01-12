#pragma once

#include "network/peer.hpp"
#include "network/peer_lifecycle_manager.hpp"
#include "network/protocol.hpp"
#include "network/transport.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <stddef.h>
#include <stdint.h>

// Forward declarations
class uint256;

namespace unicity {

namespace chain {
class ChainParams;
}

namespace message {
class GetHeadersMessage;
class HeadersMessage;
class InvMessage;
class Message;
}  // namespace message

namespace validation {
class ChainstateManager;
}

namespace network {

// Connection result codes
enum class ConnectionResult {
  Success,
  NotRunning,
  AddressBanned,
  AddressDiscouraged,
  AlreadyConnected,
  NoSlotsAvailable,
  TransportFailed
};

// Forward declarations
class AddressManager;
class AnchorManager;
class BlockRelayManager;
class PeerDiscoveryManager;
class HeaderSyncManager;
class MessageDispatcher;
class NATManager;

// Default configuration constants
static constexpr std::chrono::seconds DEFAULT_CONNECT_INTERVAL{5};
static constexpr std::chrono::seconds DEFAULT_MAINTENANCE_INTERVAL{30};
static constexpr double DEFAULT_FEELER_MAX_DELAY_MULTIPLIER{3.0};
static constexpr size_t DEFAULT_MAX_OUTBOUND_CONNECTIONS{8};

// NetworkManager - Top-level coordinator for all networking (inspired by Bitcoin's CConnman)
// Manages io_context, coordinates managers (PeerLifecycleManager, PeerDiscoveryManager,
// HeaderSyncManager, BlockRelayManager), handles connections, routes messages
//
//   Single-threaded networking reactor:
// - NetworkManager is NOT thread-safe for Config::io_threads > 1
// - All timer/handler operations assume serialized execution
// - Config::io_threads MUST be 1 in production (0 = external io_context for tests)
// - Application layer (validation, mining, RPC) may be multi-threaded
class NetworkManager {
public:
  struct Config {
    uint32_t network_magic;  // Network magic bytes 
    uint16_t listen_port;    // Port to listen on (0 = don't listen)
    bool listen_enabled;     // Enable inbound connections
    bool enable_nat;         // Enable UPnP NAT traversal
    size_t io_threads;       // Number of IO threads — MUST be 1 in production (0 = external io_context for tests)
    std::string datadir;     // Data directory

    std::chrono::seconds connect_interval;      // Time between connection attempts
    std::chrono::seconds maintenance_interval;  // Time between maintenance tasks
    double feeler_max_delay_multiplier;         // Cap feeler delay at this multiple of FEELER_INTERVAL (≤ 0 = no cap)
    size_t max_outbound_connections;  // Maximum number of outbound connections (0 = disable automatic outbound)

    // Test-only: Override for deterministic nonce (production uses random)
    std::optional<uint64_t> test_nonce;

    Config()
        : network_magic(0), listen_port(0), listen_enabled(true), enable_nat(true), io_threads(1), datadir(""),
          connect_interval(DEFAULT_CONNECT_INTERVAL), maintenance_interval(DEFAULT_MAINTENANCE_INTERVAL),
          feeler_max_delay_multiplier(DEFAULT_FEELER_MAX_DELAY_MULTIPLIER),
          max_outbound_connections(DEFAULT_MAX_OUTBOUND_CONNECTIONS), test_nonce(std::nullopt) {}
  };

  // Construct NetworkManager with chainstate manager reference, network config,
  // optional transport (nullptr = create TCP transport), and optional external io_context (nullptr = create owned).
  explicit NetworkManager(validation::ChainstateManager& chainstate_manager, const Config& config = Config{},
                          std::shared_ptr<Transport> transport = nullptr,
                          std::shared_ptr<asio::io_context> external_io_context = nullptr);
  ~NetworkManager();

  // Lifecycle
  bool start();

  /**
   * Stop NetworkManager and clean up all resources
   *
   * - This method may block for several seconds if timer handlers are slow
   * - stop() waits for all io_context threads to complete their work
   * - If a timer handler is blocked (e.g., waiting on I/O, locks, or network),
   *   stop() will wait for it to complete before returning
   * - Calling stop() from a destructor means the destructor may block
   * - Safe to call multiple times (idempotent)
   *
   * Thread-safety: Multiple threads may call stop() concurrently (serialized internally)
   */
  void stop();

  bool is_running() const { return running_; }

  // Component access
  PeerLifecycleManager& peer_manager();
  PeerDiscoveryManager& discovery_manager();

  // Manual connection management
  ConnectionResult connect_to(const protocol::NetworkAddress& addr,
                              NetPermissionFlags permissions = NetPermissionFlags::None,
                              ConnectionType conn_type = ConnectionType::OUTBOUND_FULL_RELAY);
  bool disconnect_from(int peer_id);  // Returns true if peer existed and was disconnected

  // Block relay
  void relay_block(const uint256& block_hash);

  // Periodic tip announcements (public for testing/simulation)
  void announce_tip_to_peers();

  // Announce tip to a single peer (called when peer becomes READY)
  void announce_tip_to_peer(const Peer* peer);

  // Flush pending block announcements from all peers' queues
  void flush_block_announcements();

  // Self-connection prevention
  uint64_t get_local_nonce() const { return local_nonce_; }

  // Test-only hook: trigger initial sync selection (normally run via timers)
  // This method is intentionally public but should only be used in tests
  void test_hook_check_initial_sync();

  // Test-only hook: trigger headers sync timeout processing (stall detection)
  // This method is intentionally public but should only be used in tests
  void test_hook_header_sync_process_timers();

  // Test-only: Set default permissions for inbound connections
  // This method is intentionally public but should only be used in tests
  void set_default_inbound_permissions(NetPermissionFlags flags) { default_inbound_permissions_ = flags; }

  // Test-only: Manually trigger a feeler connection attempt
  // This method is intentionally public but should only be used in tests
  void attempt_feeler_connection();

  // Test-only: Access dispatcher for diagnostics
  // This method is intentionally public but should only be used in tests
  MessageDispatcher& dispatcher_for_test() { return *message_dispatcher_; }

  // Test-only: Access discovery manager for diagnostics
  // This method is intentionally public but should only be used in tests
  PeerDiscoveryManager& discovery_manager_for_test() { return *discovery_manager_; }

  // Test-only: Access sync managers for diagnostics
  // These methods are intentionally public but should only be used in tests
  HeaderSyncManager& header_sync_for_test() { return *header_sync_manager_; }
  BlockRelayManager& block_relay_for_test() { return *block_relay_manager_; }

  // Connection stats
  size_t active_peer_count() const;
  size_t outbound_peer_count() const;
  size_t inbound_peer_count() const;

  // Anchors
  std::vector<protocol::NetworkAddress> GetAnchors() const;
  bool SaveAnchors(const std::string& filepath);
  bool LoadAnchors(const std::string& filepath);

private:
  Config config_;
  std::atomic<bool> running_{false};
  mutable std::mutex start_stop_mutex_;  // Protects start/stop from race conditions
  std::condition_variable stop_cv_;      // Signals when stop() has fully completed
  bool fully_stopped_{true};             // true when all threads have been joined (guarded by start_stop_mutex_)

  // Self-connection prevention: unique nonce for this node
  uint64_t local_nonce_;

  // Test-only: Default permissions for inbound connections
  NetPermissionFlags default_inbound_permissions_{NetPermissionFlags::None};

  // IO context (shared ownership ensures it outlives all async operations)
  std::shared_ptr<asio::io_context> io_context_;  // Either external (shared) or owned
  bool external_io_context_;                      // true if io_context was provided externally (don't spawn threads)
  std::unique_ptr<asio::executor_work_guard<asio::io_context::executor_type>> work_guard_;
  std::vector<std::thread> io_threads_;

  // Transport layer (either real TCP or simulated for testing)
  std::shared_ptr<Transport> transport_;

  // Components
  std::unique_ptr<PeerLifecycleManager> peer_manager_;       // Peer connection lifecycle management
  std::unique_ptr<PeerDiscoveryManager> discovery_manager_;  // Peer discovery (owns AddressManager + AnchorManager)
  std::unique_ptr<HeaderSyncManager> header_sync_manager_;   // Header synchronization
  std::unique_ptr<BlockRelayManager> block_relay_manager_;   // Block relay and announcements

  // Supporting infrastructure
  validation::ChainstateManager& chainstate_manager_;      // Reference to Application's ChainstateManager
  std::unique_ptr<MessageDispatcher> message_dispatcher_;  // Message routing infrastructure
  std::unique_ptr<NATManager> nat_manager_;                // Utility component

  // Periodic tasks
  std::unique_ptr<asio::steady_timer> connect_timer_;
  std::unique_ptr<asio::steady_timer> maintenance_timer_;
  std::unique_ptr<asio::steady_timer> feeler_timer_;
  std::unique_ptr<asio::steady_timer> sendmessages_timer_;
  static constexpr std::chrono::minutes FEELER_INTERVAL{2};
  static constexpr std::chrono::seconds SENDMESSAGES_INTERVAL{1};  // Flush announcements every 1s

  // Tip announcement tracking (for periodic re-announcements)
  int64_t last_tip_announcement_time_{0};  // Last time we announced (mockable time)

  // Self-advertisement: our routable address for network discovery
  mutable std::mutex local_addr_mutex_;
  std::optional<protocol::NetworkAddress> local_addr_;  // Our advertised address (if known)
  int64_t last_local_addr_send_{0};                     // Last time we sent self-advertisement (mockable time)
  static constexpr std::chrono::hours LOCAL_ADDR_BROADCAST_INTERVAL{24};

  // Self-advertisement methods
  void maybe_send_local_addr();        // Called periodically, sends our address to full-relay peers
  void update_local_addr_from_upnp();  // Learn address from NATManager
  void set_local_addr_from_peer_feedback(const std::string& ip);  // Learn from VERSION addr_recv

  // Feeler connection RNG (avoids thread_local to prevent leaks on dlclose)
  mutable std::mutex feeler_rng_mutex_;
  std::mt19937 feeler_rng_;

  // Connection management
  void schedule_next_connection_attempt();
  void schedule_next_feeler();

  // Maintenance
  void run_maintenance();
  void schedule_next_maintenance();

  // Bitcoin-like SendMessages loop (flushes block announcements)
  void run_sendmessages();
  void schedule_next_sendmessages();

  // Initial sync
  void check_initial_sync();

  // Message handling
  void setup_peer_message_handler(Peer* peer);
  void handle_message(PeerPtr peer, std::unique_ptr<message::Message> msg);
};

}  // namespace network
}  // namespace unicity
