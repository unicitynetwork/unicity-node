// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "network/network_manager.hpp"

#include "chain/block_manager.hpp"
#include "chain/chainparams.hpp"
#include "chain/chainstate_manager.hpp"
#include "chain/validation.hpp"
#include "network/addr_manager.hpp"
#include "network/anchor_manager.hpp"
#include "network/block_relay_manager.hpp"
#include "network/connection_types.hpp"
#include "network/header_sync_manager.hpp"
#include "network/message.hpp"
#include "network/message_dispatcher.hpp"
#include "network/nat_manager.hpp"
#include "network/peer_discovery_manager.hpp"
#include "network/real_transport.hpp"
#include "util/logging.hpp"
#include "util/netaddress.hpp"
#include "util/time.hpp"

#include <algorithm>
#include <filesystem>
#include <functional>
#include <optional>
#include <random>
#include <utility>

#include <asio/executor_work_guard.hpp>
#include <asio/post.hpp>

namespace unicity {
namespace network {

// Helper to generate random nonce (non-blocking, deterministic seed for tests)
// Called once at startup (not thread_local, not repeated)
static uint64_t generate_nonce(const NetworkManager::Config& config) {
  // Test override for determinism
  if (config.test_nonce) {
    return *config.test_nonce;
  }

  // Production: high-quality random nonce generated once
  // static random_device prevents fd-exhaustion on OSes where random_device opens /dev/urandom each call
  static std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint64_t> dis;
  return dis(gen);
}

NetworkManager::NetworkManager(validation::ChainstateManager& chainstate_manager, const Config& config,
                               std::shared_ptr<Transport> transport,
                               std::shared_ptr<asio::io_context> external_io_context)
    : config_(config), local_nonce_(generate_nonce(config)),
      // Shared ownership of io_context ensures it outlives all async operations and timers
      // IMPORTANT: Must be initialized before transport_ since RealTransport needs io_context
      io_context_(external_io_context ? external_io_context : std::make_shared<asio::io_context>()),
      external_io_context_(external_io_context != nullptr),  // Track if context was provided externally
      // Initialize transport in member init list to avoid half-formed state
      // If transport is null, create default RealTransport with our io_context
      // This ensures transport_ is always valid if constructor succeeds
      transport_(transport ? transport : std::make_shared<RealTransport>(*io_context_)),
      chainstate_manager_(chainstate_manager) {
  // SECURITY: Validate required config (fail fast on misconfiguration)
  if (config_.network_magic == 0) {
    throw std::invalid_argument(
        "NetworkManager::Config::network_magic must be set to chain-specific value (mainnet/testnet/regtest)");
  }

  feeler_rng_.seed(std::random_device{}());

  // transport_ is now guaranteed to be non-null at this point
  // If RealTransport construction threw, we never reach here and destructor won't call transport_->stop()

  LOG_NET_TRACE("NetworkManager initialized (local nonce: {}, external_io_context: {})", local_nonce_,
                external_io_context_ ? "yes" : "no");

  // Set process-wide nonce for all peers (self-connection detection)
  // In test mode, each node gets unique nonce via set_local_nonce() calls
  // In production, all peers share process-wide nonce for reliable self-connect detection
  if (!config.test_nonce.has_value()) {
    Peer::set_process_nonce(local_nonce_);
  }

  // Create components in dependency order (3-manager architecture)
  // PeerLifecycleManager
  PeerLifecycleManager::Config peer_config;
  peer_config.max_outbound_peers = config_.max_outbound_connections;
  peer_config.target_outbound_peers = config_.max_outbound_connections;
  peer_manager_ = std::make_unique<PeerLifecycleManager>(*io_context_, peer_config, config_.datadir);

  // PeerDiscoveryManager (owns AddressManager + AnchorManager, injects itself into PeerLifecycleManager)
  discovery_manager_ = std::make_unique<PeerDiscoveryManager>(peer_manager_.get(), config_.datadir);

  // HeaderSyncManager (header synchronization)
  header_sync_manager_ = std::make_unique<HeaderSyncManager>(chainstate_manager, *peer_manager_);
  peer_manager_->SetHeaderSyncManager(header_sync_manager_.get());

  // BlockRelayManager (block announcements and relay, needs HeaderSyncManager reference)
  block_relay_manager_ = std::make_unique<BlockRelayManager>(chainstate_manager, *peer_manager_, *header_sync_manager_);

  // Create NAT manager if enabled
  if (config_.enable_nat) {
    nat_manager_ = std::make_unique<NATManager>();
  }

  // MessageDispatcher (handler registry pattern)
  message_dispatcher_ = std::make_unique<MessageDispatcher>();

  // === Register Message Handlers with MessageDispatcher ===

  // VERACK - Connection lifecycle (no message payload)
  message_dispatcher_->RegisterHandler(protocol::commands::VERACK, [this](PeerPtr peer, ::unicity::message::Message*) {
    return peer_manager_->HandleVerack(peer);
  });

  // ADDR - Address discovery
  message_dispatcher_->RegisterHandler(protocol::commands::ADDR, [this](PeerPtr peer,
                                                                        ::unicity::message::Message* msg) {
    auto* addr_msg = dynamic_cast<message::AddrMessage*>(msg);
    if (!addr_msg) {
      LOG_NET_ERROR("MessageDispatcher: bad payload type for ADDR from peer {}", peer ? peer->id() : -1);
      return false;
    }
    return discovery_manager_->HandleAddr(peer, addr_msg);
  });

  // GETADDR - Address discovery (no message payload)
  message_dispatcher_->RegisterHandler(protocol::commands::GETADDR, [this](PeerPtr peer, ::unicity::message::Message*) {
    return discovery_manager_->HandleGetAddr(peer);
  });

  // INV - Block relay
  message_dispatcher_->RegisterHandler(protocol::commands::INV, [this](PeerPtr peer, ::unicity::message::Message* msg) {
    auto* inv_msg = dynamic_cast<message::InvMessage*>(msg);
    if (!inv_msg) {
      LOG_NET_ERROR("MessageDispatcher: bad payload type for INV from peer {}", peer ? peer->id() : -1);
      return false;
    }
    // Gate INV on post-VERACK
    // Sending protocol messages before handshake is a DoS vector - disconnect immediately
    if (!peer || !peer->successfully_connected()) {
      LOG_NET_WARN_RL("Peer {} sent INV before completing handshake, disconnecting", peer ? peer->id() : -1);
      if (peer) {
        peer->disconnect();
      }
      return false;  // Disconnect
    }
    return block_relay_manager_->HandleInvMessage(peer, inv_msg);
  });

  // HEADERS - Header sync
  message_dispatcher_->RegisterHandler(protocol::commands::HEADERS, [this](PeerPtr peer,
                                                                           ::unicity::message::Message* msg) {
    auto* headers_msg = dynamic_cast<message::HeadersMessage*>(msg);
    if (!headers_msg) {
      LOG_NET_ERROR("MessageDispatcher: bad payload type for HEADERS from peer {}", peer ? peer->id() : -1);
      return false;
    }
    // Gate HEADERS on post-VERACK
    // Sending protocol messages before handshake is a DoS vector - disconnect immediately
    if (!peer || !peer->successfully_connected()) {
      LOG_NET_WARN_RL("Peer {} sent HEADERS before completing handshake, disconnecting", peer ? peer->id() : -1);
      if (peer) {
        peer->disconnect();
      }
      return false;  // Disconnect
    }
    return header_sync_manager_->HandleHeadersMessage(peer, headers_msg);
  });

  // GETHEADERS - Header sync
  message_dispatcher_->RegisterHandler(protocol::commands::GETHEADERS, [this](PeerPtr peer,
                                                                              ::unicity::message::Message* msg) {
    auto* getheaders_msg = dynamic_cast<message::GetHeadersMessage*>(msg);
    if (!getheaders_msg) {
      LOG_NET_ERROR("MessageDispatcher: bad payload type for GETHEADERS from peer {}", peer ? peer->id() : -1);
      return false;
    }
    // Gate GETHEADERS on post-VERACK
    // Sending protocol messages before handshake is a DoS vector - disconnect immediately
    if (!peer || !peer->successfully_connected()) {
      LOG_NET_WARN_RL("Peer {} sent GETHEADERS before completing handshake, disconnecting", peer ? peer->id() : -1);
      if (peer) {
        peer->disconnect();
      }
      return false;  // Disconnect
    }
    return header_sync_manager_->HandleGetHeadersMessage(peer, getheaders_msg);
  });

  LOG_NET_INFO("Registered {} message handlers with MessageDispatcher",
               message_dispatcher_->GetRegisteredCommands().size());
}

NetworkManager::~NetworkManager() {
  try {
    stop();
  } catch (...) {
  }
}

PeerLifecycleManager& NetworkManager::peer_manager() {
  return *peer_manager_;
}

PeerDiscoveryManager& NetworkManager::discovery_manager() {
  return *discovery_manager_;
}

bool NetworkManager::start() {
  // Fast path: check without lock
  if (running_.load(std::memory_order_acquire)) {
    return false;
  }

  // Acquire lock for initialization
  std::unique_lock<std::mutex> lock(start_stop_mutex_);

  // Wait for any pending stop() to fully complete (thread joins, etc.)
  // This prevents starting while threads from a previous instance are still cleaning up
  stop_cv_.wait(lock, [this]() { return fully_stopped_; });

  // Double-check after acquiring lock and waiting (another thread may have started)
  if (running_.load(std::memory_order_acquire)) {
    return false;
  }

  running_.store(true, std::memory_order_release);
  fully_stopped_ = false;  // Mark that we're now running (threads will be spawned)

  // Start transport
  transport_->run();

  // Create work guard and timers only if we own the io_context
  // When using external io_context (tests), the external code controls event processing
  // IMPORTANT: Check external_io_context_ flag to prevent spawning threads on external
  // io_contexts (which would cause data races)
  if (config_.io_threads > 0 && !external_io_context_) {
    // Create work guard to keep io_context running (for timers)
    work_guard_ = std::make_unique<asio::executor_work_guard<asio::io_context::executor_type>>(
        asio::make_work_guard(*io_context_));

    // Setup timers
    connect_timer_ = std::make_unique<asio::steady_timer>(*io_context_);
    maintenance_timer_ = std::make_unique<asio::steady_timer>(*io_context_);
    feeler_timer_ = std::make_unique<asio::steady_timer>(*io_context_);
    sendmessages_timer_ = std::make_unique<asio::steady_timer>(*io_context_);

    // Start IO threads (only for owned io_context)
    for (size_t i = 0; i < config_.io_threads; ++i) {
      io_threads_.emplace_back([this]() { io_context_->run(); });
    }
  }

  // Start listening if enabled (via transport)
  if (config_.listen_enabled && config_.listen_port > 0) {
    bool success = transport_->listen(config_.listen_port, [this](TransportConnectionPtr connection) {
      // Delegate to PeerLifecycleManager
      peer_manager_->HandleInboundConnection(
          connection, [this]() { return running_.load(std::memory_order_acquire); },
          [this](Peer* peer) { setup_peer_message_handler(peer); }, config_.network_magic,
          chainstate_manager_.GetChainHeight(), local_nonce_, default_inbound_permissions_);
    });

    if (success) {
      // Start NAT traversal if enabled
      if (nat_manager_ && nat_manager_->Start(config_.listen_port)) {
        LOG_NET_TRACE("UPnP NAT traversal enabled - external {}:{}", nat_manager_->GetExternalIP(),
                      nat_manager_->GetExternalPort());
      }
    } else {
      LOG_NET_ERROR("Failed to start listener on port {}", config_.listen_port);
      // Fail fast if we can't bind to the configured port
      // This prevents silent degradation and catches multi-instance issues
      running_.store(false, std::memory_order_release);

      // Clean up threads that were started earlier
      // Without this cleanup, destructors will call std::terminate() on joinable threads

      // Stop transport threads
      transport_->stop();

      // Stop io_context and join io_threads_ that may have been created
      if (work_guard_) {
        work_guard_.reset();
      }
      io_context_->stop();
      for (auto& thread : io_threads_) {
        if (thread.joinable()) {
          thread.join();
        }
      }
      io_threads_.clear();

      return false;
    }
  }

  // Start discovery services (loads anchors, bootstraps if needed)
  discovery_manager_->Start([this](const std::vector<protocol::NetworkAddress>& anchors) {
    peer_manager_->ConnectToAnchors(anchors,
                                    [this](const protocol::NetworkAddress& addr, ConnectionType /*conn_type*/) {
                                      // Anchor connections use NoBan permission; conn_type ignored since anchors are
                                      // always full-relay
                                      return connect_to(addr, NetPermissionFlags::NoBan);
                                    });
  });

  // Schedule periodic tasks (only if we own the io_context threads)
  // When using external io_context (tests), the external code controls event processing
  if (config_.io_threads > 0) {
    schedule_next_connection_attempt();
    schedule_next_maintenance();
    schedule_next_feeler();
    schedule_next_sendmessages();
  }

  return true;
}

void NetworkManager::stop() {
  // Fast path: check without lock
  if (!running_.load(std::memory_order_acquire)) {
    return;
  }

  // Acquire lock for shutdown
  std::unique_lock<std::mutex> lock(start_stop_mutex_);

  // Double-check after acquiring lock (another thread may have stopped)
  if (!running_.load(std::memory_order_acquire)) {
    return;
  }

  // Set running_ = false FIRST to prevent new operations (handle_message checks this)
  running_.store(false, std::memory_order_release);

  // Cancel timers to prevent new connections/operations from starting
  // Note: This doesn't stop io_context, just cancels pending timer callbacks
  if (connect_timer_) {
    connect_timer_->cancel();
  }
  if (maintenance_timer_) {
    maintenance_timer_->cancel();
  }
  if (feeler_timer_) {
    feeler_timer_->cancel();
  }
  if (sendmessages_timer_) {
    sendmessages_timer_->cancel();
  }

  // Save anchors while peers are still connected (need their addresses)
  // CRITICAL: Must not throw (stop() called from destructors)
  // Don't log here - this is called from destructor, logger may be shut down
  if (!config_.datadir.empty()) {
    try {
      std::string anchors_path = config_.datadir + "/anchors.json";
      SaveAnchors(anchors_path);
    } catch (const std::exception& e) {
      // Don't propagate exceptions from stop() - can be called from destructors
      // Don't log either - logger may be shut down
    } catch (...) {
      // Silently swallow exceptions during shutdown
    }
  }

  // CRITICAL SHUTDOWN SEQUENCE
  // 1. Disconnect all peers BEFORE stopping io_context
  //    - Allows disconnect callbacks to run properly
  //    - Ensures clean TCP shutdown (FIN packets sent)
  //    - Prevents half-open sockets
  peer_manager_->Shutdown();  // Disable callbacks first to prevent UAF
  peer_manager_->disconnect_all();

  // 2. Stop transport BEFORE io_context
  //    - Stops accepting new connections
  //    - Closes listening sockets cleanly
  if (transport_) {
    transport_->stop();
  }

  // 3. Stop NAT traversal
  if (nat_manager_) {
    nat_manager_->Stop();
  }

  // 4. NOW stop io_context (after all cleanup is done)
  //    - All sockets are closed
  //    - All callbacks have run
  //    - Safe to stop event loop
  io_context_->stop();

  // 5. Reset work guard (allows io_context threads to exit)
  //    Only reset if we created it (i.e., we own the io_context)
  if (work_guard_) {
    work_guard_.reset();
  }

  // Join all threads (should return quickly now that io_context is stopped)
  for (auto& thread : io_threads_) {
    if (thread.joinable()) {
      thread.join();
    }
  }
  io_threads_.clear();

  // Reset io_context for potential restart
  io_context_->restart();

  // Mark as fully stopped and signal any waiting start() calls
  // This must be done while holding the lock to prevent TOCTOU races
  fully_stopped_ = true;
  stop_cv_.notify_all();
}

ConnectionResult NetworkManager::connect_to(const protocol::NetworkAddress& addr, NetPermissionFlags permissions,
                                            ConnectionType conn_type) {
  if (!running_.load(std::memory_order_acquire)) {
    return ConnectionResult::NotRunning;
  }

  // Delegate to PeerLifecycleManager (handles all connection logic)
  return peer_manager_->ConnectTo(
      addr, permissions, transport_, [this](const protocol::NetworkAddress&) { /* defer Good() until post-VERACK */ },
      [this](const protocol::NetworkAddress& a) { discovery_manager_->Attempt(a); },
      [this](Peer* peer) { setup_peer_message_handler(peer); }, config_.network_magic,
      chainstate_manager_.GetChainHeight(), local_nonce_, conn_type);
}

bool NetworkManager::disconnect_from(int peer_id) {
  auto peer = peer_manager_->get_peer(peer_id);
  if (!peer) {
    return false;
  }
  peer_manager_->remove_peer(peer_id);
  return true;
}

size_t NetworkManager::active_peer_count() const {
  return peer_manager_->peer_count();
}

size_t NetworkManager::outbound_peer_count() const {
  return peer_manager_->outbound_count();
}

size_t NetworkManager::inbound_peer_count() const {
  return peer_manager_->inbound_count();
}

void NetworkManager::schedule_next_connection_attempt() {
  if (!running_.load(std::memory_order_acquire)) {
    return;
  }

  connect_timer_->expires_after(config_.connect_interval);
  connect_timer_->async_wait([this](const asio::error_code& ec) {
    if (!ec && running_.load(std::memory_order_acquire)) {
      // Skip automatic outbound connections if max_outbound_connections is 0
      if (config_.max_outbound_connections > 0) {
        // Delegate to PeerLifecycleManager with callbacks for running check and connection
        // The callback receives connection type (OUTBOUND_FULL_RELAY or BLOCK_RELAY) to use
        peer_manager_->AttemptOutboundConnections([this]() { return running_.load(std::memory_order_acquire); },
                                                  [this](const protocol::NetworkAddress& addr,
                                                         ConnectionType conn_type) {
                                                    return connect_to(addr, NetPermissionFlags::None, conn_type);
                                                  });
      }
      schedule_next_connection_attempt();
    }
  });
}

void NetworkManager::run_maintenance() {
  if (!running_.load(std::memory_order_acquire)) {
    return;
  }

  // Run periodic cleanup
  peer_manager_->process_periodic();

  // Headers sync timeouts and maintenance
  header_sync_manager_->ProcessTimers();

  // Sweep expired bans and discouraged entries
  peer_manager_->SweepBanned();
  peer_manager_->SweepDiscouraged();

  // Process pending ADDR relays 
  discovery_manager_->ProcessPendingAddrRelays();

  // Periodically announce our tip to peers
  block_relay_manager_->AnnounceTipToAllPeers();

  // Check if we need to start initial sync
  check_initial_sync();
}

void NetworkManager::schedule_next_maintenance() {
  if (!running_.load(std::memory_order_acquire)) {
    return;
  }

  maintenance_timer_->expires_after(config_.maintenance_interval);
  maintenance_timer_->async_wait([this](const asio::error_code& ec) {
    if (!ec && running_.load(std::memory_order_acquire)) {
      run_maintenance();
      schedule_next_maintenance();
    }
  });
}

void NetworkManager::run_sendmessages() {
  if (!running_.load(std::memory_order_acquire)) {
    return;
  }

  // Check for initial sync opportunities
  header_sync_manager_->CheckInitialSync();

  // Flush queued block announcement
  block_relay_manager_->FlushBlockAnnouncements();

  // Self-advertisement: periodically send our address to peers
  // This allows other nodes to discover us and connect inbound
  maybe_send_local_addr();
}

void NetworkManager::schedule_next_sendmessages() {
  if (!running_.load(std::memory_order_acquire)) {
    return;
  }

  sendmessages_timer_->expires_after(SENDMESSAGES_INTERVAL);
  sendmessages_timer_->async_wait([this](const asio::error_code& ec) {
    if (!ec && running_.load(std::memory_order_acquire)) {
      run_sendmessages();
      schedule_next_sendmessages();
    }
  });
}

// Test/diagnostic methods (accessible only via friend class SimulatedNode)
void NetworkManager::test_hook_check_initial_sync() {
  // Expose initial sync trigger for tests when io_threads==0
  check_initial_sync();
}

void NetworkManager::test_hook_header_sync_process_timers() {
  // Expose header sync stall/timeout processing for tests (io_threads==0)
  header_sync_manager_->ProcessTimers();
}

void NetworkManager::attempt_feeler_connection() {
  // Test-only wrapper: Delegate to PeerLifecycleManager
  peer_manager_->AttemptFeelerConnection([this]() { return running_.load(std::memory_order_acquire); },
                                         [this]() { return transport_; },
                                         [this](Peer* peer) { setup_peer_message_handler(peer); },
                                         config_.network_magic, chainstate_manager_.GetChainHeight(), local_nonce_);
}

void NetworkManager::schedule_next_feeler() {
  if (!running_.load(std::memory_order_acquire) || !feeler_timer_) {
    return;
  }

  // Exponential/Poisson scheduling around mean FEELER_INTERVAL
  // Use member RNG instead of thread_local to avoid leaks on dlclose
  double delay_s;
  {
    std::lock_guard<std::mutex> lock(feeler_rng_mutex_);
    std::exponential_distribution<double> exp(
        1.0 / std::chrono::duration_cast<std::chrono::seconds>(FEELER_INTERVAL).count());
    delay_s = exp(feeler_rng_);
  }

  // Cap delay if configured (prevents pathological long delays in tests)
  // If feeler_max_delay_multiplier ≤ 0, no cap is applied
  if (config_.feeler_max_delay_multiplier > 0.0) {
    double max_delay = config_.feeler_max_delay_multiplier * FEELER_INTERVAL.count();
    delay_s = std::min(max_delay, delay_s);
  }

  auto delay = std::chrono::seconds(std::max(1, static_cast<int>(delay_s)));

  feeler_timer_->expires_after(delay);

  feeler_timer_->async_wait([this](const asio::error_code& ec) {
    if (!ec && running_.load(std::memory_order_acquire)) {
      // Delegate to PeerLifecycleManager with callbacks
      peer_manager_->AttemptFeelerConnection([this]() { return running_.load(std::memory_order_acquire); },
                                             [this]() { return transport_; },
                                             [this](Peer* peer) { setup_peer_message_handler(peer); },
                                             config_.network_magic, chainstate_manager_.GetChainHeight(), local_nonce_);
      schedule_next_feeler();
    }
  });
}

void NetworkManager::check_initial_sync() {
  // Delegate to HeaderSyncManager
  header_sync_manager_->CheckInitialSync();
}

void NetworkManager::setup_peer_message_handler(Peer* peer) {
  peer->set_message_handler(
      [this](PeerPtr peer, std::unique_ptr<message::Message> msg) { return handle_message(peer, std::move(msg)); });

  // Set VERACK completion handler
  // Announce our tip immediately when peer becomes READY
  peer->set_verack_complete_handler([this](PeerPtr peer) { announce_tip_to_peer(peer.get()); });

  // Set local address learned handler )
  // When inbound peers tell us what IP they see us as, use it for self-advertisement
  peer->set_local_addr_learned_handler([this](const std::string& ip) { set_local_addr_from_peer_feedback(ip); });
}

void NetworkManager::handle_message(PeerPtr peer, std::unique_ptr<message::Message> msg) {
  // Early exit if shutting down (prevents processing messages during teardown)
  if (!running_.load(std::memory_order_acquire)) {
    return;
  }

  // Detect self-connections in VERSION handler
  if (msg->command() == protocol::commands::VERSION) {
    const auto* version_msg = dynamic_cast<const message::VersionMessage*>(msg.get());
    if (!version_msg) {
      LOG_NET_ERROR("VERSION message cast failed for peer {}", peer->id());
      return;
    }

    // Check if their nonce collides with our local nonce or any existing peer's remote nonce
    // This detects: self-connections, duplicate connections, and accidental nonce collisions
    if (!peer_manager_->CheckIncomingNonce(version_msg->nonce, local_nonce_)) {
      // Nonce collision detected! Either self-connection or duplicate connection
      LOG_NET_INFO("Nonce collision detected for peer {}, disconnecting", peer->address());
      int peer_id = peer->id();

      // Re-check running_ before operations that interact with manager state
      if (!running_.load(std::memory_order_acquire)) {
        return;
      }

      peer->disconnect();
      peer_manager_->remove_peer(peer_id);
      return;  // Don't route the message
    }
  }

  // Re-check running_ before dispatching (which may trigger more manager interactions)
  if (!running_.load(std::memory_order_acquire)) {
    return;
  }

  // Route via MessageDispatcher (handler registry pattern)
  if (message_dispatcher_) {
    message_dispatcher_->Dispatch(peer, msg->command(), msg.get());
  }
}

// Anchors implementation for eclipse attack resistance (delegated to AnchorManager)
std::vector<protocol::NetworkAddress> NetworkManager::GetAnchors() const {
  return discovery_manager_->GetAnchors();
}

bool NetworkManager::SaveAnchors(const std::string& filepath) {
  return discovery_manager_->SaveAnchors(filepath);
}

bool NetworkManager::LoadAnchors(const std::string& filepath) {
  // Load anchors and delegate connection logic to PeerLifecycleManager
  // CRITICAL: Must not throw (called during startup)
  try {
    auto anchor_addrs = discovery_manager_->LoadAnchors(filepath);
    if (!anchor_addrs.empty()) {
      peer_manager_->ConnectToAnchors(anchor_addrs,
                                      [this](const protocol::NetworkAddress& addr, ConnectionType /*conn_type*/) {
                                        // NoBan: anchors are trusted peers from previous session, don't disconnect for
                                        // misbehavior. Note: conn_type (BLOCK_RELAY) is ignored; anchors connect as
                                        // OUTBOUND_FULL_RELAY.
                                        return connect_to(addr, NetPermissionFlags::NoBan);
                                      });
      return true;
    }
    return false;
  } catch (const std::exception& e) {
    // TODO Don't propagate exceptions from LoadAnchors - corrupted file is not fatal
    LOG_NET_ERROR("Failed to load anchors from {}: {}", filepath, e.what());
    return false;  // Continue with empty anchors
  } catch (...) {
    LOG_NET_ERROR("Unknown exception while loading anchors from {}", filepath);
    return false;  // Continue with empty anchors
  }
}

void NetworkManager::announce_tip_to_peers() {
  block_relay_manager_->AnnounceTipToAllPeers();
}

void NetworkManager::announce_tip_to_peer(const Peer* peer) {
  block_relay_manager_->AnnounceTipToPeer(peer);
}

void NetworkManager::flush_block_announcements() {
  block_relay_manager_->FlushBlockAnnouncements();
}

void NetworkManager::relay_block(const uint256& block_hash) {
  block_relay_manager_->RelayBlock(block_hash);
}

// ============================================================================
// Self-advertisement
// ============================================================================

void NetworkManager::update_local_addr_from_upnp() {
  if (!nat_manager_ || !nat_manager_->IsPortMapped()) {
    return;
  }

  std::string external_ip = nat_manager_->GetExternalIP();
  if (external_ip.empty()) {
    return;
  }

  std::lock_guard<std::mutex> lock(local_addr_mutex_);

  // Only update if we don't have an address yet (UPnP is authoritative)
  if (local_addr_.has_value()) {
    return;  // Already have an address, don't overwrite
  }

  try {
    local_addr_ = protocol::NetworkAddress::from_string(external_ip, config_.listen_port, protocol::NODE_NETWORK);
    LOG_NET_INFO("Learned local address from UPnP: {}:{}", external_ip, config_.listen_port);
  } catch (const std::exception& e) {
    LOG_NET_WARN("Failed to parse UPnP address {}: {}", external_ip, e.what());
  }
}

void NetworkManager::set_local_addr_from_peer_feedback(const std::string& ip) {
  if (ip.empty()) {
    return;
  }

  std::lock_guard<std::mutex> lock(local_addr_mutex_);

  // Only use peer feedback if we don't already have an address
  if (local_addr_.has_value()) {
    return;
  }

  try {
    protocol::NetworkAddress addr = protocol::NetworkAddress::from_string(ip, config_.listen_port,
                                                                          protocol::NODE_NETWORK);

    // Validate it's a routable address (not private/loopback)
    auto addr_str = addr.to_string();
    if (!addr_str.has_value()) {
      return;
    }

    if (!util::IsRoutable(ip)) {
      LOG_NET_TRACE("Ignoring non-routable peer feedback address: {}", ip);
      return;
    }

    local_addr_ = addr;
    LOG_NET_INFO("Learned local address from peer feedback: {}:{}", ip, config_.listen_port);
  } catch (const std::exception& e) {
    LOG_NET_WARN("Failed to parse peer feedback address {}: {}", ip, e.what());
  }
}

void NetworkManager::maybe_send_local_addr() {
  // Gate on listening enabled
  if (!config_.listen_enabled || config_.listen_port == 0) {
    LOG_NET_DEBUG("maybe_send_local_addr: skipping - listening not enabled");
    return;
  }

  // NOTE: We intentionally do NOT gate on IBD here.
  //
  // Check if we have a local address to advertise
  std::optional<protocol::NetworkAddress> addr_to_send;
  {
    std::lock_guard<std::mutex> lock(local_addr_mutex_);
    addr_to_send = local_addr_;
  }

  // Try UPnP discovery if we still don't have an address
  if (!addr_to_send.has_value()) {
    update_local_addr_from_upnp();
    std::lock_guard<std::mutex> lock(local_addr_mutex_);
    addr_to_send = local_addr_;
  }

  if (!addr_to_send.has_value()) {
    // No address to advertise yet
    LOG_NET_DEBUG("maybe_send_local_addr: skipping - no local address learned yet");
    return;
  }

  // Check if enough time has passed since last advertisement
  int64_t now = util::GetTime();
  if (last_local_addr_send_ > 0) {
    int64_t elapsed = now - last_local_addr_send_;
    int64_t interval_sec = std::chrono::duration_cast<std::chrono::seconds>(LOCAL_ADDR_BROADCAST_INTERVAL).count();
    if (elapsed < interval_sec) {
      return;  // Not time yet
    }
  }

  // Build ADDR message with our address
  auto addr_msg = std::make_unique<message::AddrMessage>();
  protocol::TimestampedAddress ts_addr;
  ts_addr.timestamp = static_cast<uint32_t>(now);
  ts_addr.address = *addr_to_send;
  addr_msg->addresses.push_back(ts_addr);

  // Send to all full-relay peers (not block-relay-only)
  auto peers = peer_manager_->get_all_peers();
  size_t sent_count = 0;
  for (const auto& peer : peers) {
    if (!peer || !peer->successfully_connected()) {
      continue;
    }
    // Only send to peers that relay addresses (not block-relay-only)
    if (!peer->relays_addr()) {
      continue;
    }

    // Clone the message for each peer
    auto msg_copy = std::make_unique<message::AddrMessage>();
    msg_copy->addresses = addr_msg->addresses;
    peer->send_message(std::move(msg_copy));
    sent_count++;
  }

  if (sent_count > 0) {
    last_local_addr_send_ = now;
    auto addr_str = addr_to_send->to_string();
    LOG_NET_INFO("Self-advertisement: sent local address {} to {} peers", addr_str.value_or("unknown"), sent_count);
  }
}

}  // namespace network
}  // namespace unicity
