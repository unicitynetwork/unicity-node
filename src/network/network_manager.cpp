// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "network/network_manager.hpp"

#include "chain/block_manager.hpp"
#include "chain/chainparams.hpp"
#include "chain/chainstate_manager.hpp"
#include "chain/validation.hpp"
#include "network/addr_manager.hpp"
#include "network/anchor_manager.hpp"
#include "network/connection_types.hpp"
#include "network/header_sync_manager.hpp"
#include "network/message.hpp"
#include "network/message_dispatcher.hpp"
#include "network/nat_manager.hpp"
#include "network/addr_relay_manager.hpp"
#include "network/real_transport.hpp"
#include "util/logging.hpp"
#include "util/netaddress.hpp"
#include "util/time.hpp"

#include <algorithm>
#include <functional>
#include <optional>
#include <random>
#include <utility>

#include <asio/executor_work_guard.hpp>

namespace unicity {
namespace network {

// Helper to generate random nonce (non-blocking, deterministic seed for tests)
// Called once at startup (not thread_local, not repeated)
static uint64_t generate_nonce(const NetworkManager::Config& config) {
  // Test override for determinism
  if (config.test_nonce) {
    return *config.test_nonce;
  }

  static std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint64_t> dis;
  return dis(gen);
}

NetworkManager::NetworkManager(
    validation::ChainstateManager& chainstate_manager,
    const Config& config,
    std::shared_ptr<Transport> transport,
    std::shared_ptr<asio::io_context> external_io_context)
    : config_(config)
    , local_nonce_(generate_nonce(config))
    , io_context_(external_io_context ? external_io_context : std::make_shared<asio::io_context>())
    , external_io_context_(external_io_context != nullptr)
    , transport_(transport ? transport : std::make_shared<RealTransport>(*io_context_))
    , chainstate_manager_(chainstate_manager)
{
  if (config_.network_magic == 0) {
    throw std::invalid_argument(
        "NetworkManager::Config::network_magic must be set to chain-specific value (mainnet/testnet/regtest)");
  }

  feeler_rng_.seed(std::random_device{}());

  LOG_NET_TRACE("NetworkManager initialized (local nonce: {}, external_io_context: {})", local_nonce_,
                external_io_context_ ? "yes" : "no");

  // Set process-wide nonce for all peers (self-connection detection)
  // In test mode, each node gets unique nonce via set_local_nonce() calls
  // In production, all peers share process-wide nonce 
  if (!config.test_nonce.has_value()) {
    Peer::set_process_nonce(local_nonce_);
  }

  // Create components in dependency order (3-manager architecture)
  // ConnectionManager
  ConnectionManager::Config peer_config;
  peer_config.max_outbound_peers = config_.max_outbound_connections;
  peer_config.target_outbound_peers = config_.max_outbound_connections;
  peer_config.max_inbound_peers = config_.max_inbound_connections;
  peer_manager_ = std::make_unique<ConnectionManager>(*io_context_, peer_config, config_.datadir);

  // AddrRelayManager (owns AddressManager + AnchorManager, injects itself into ConnectionManager)
  addr_relay_mgr_ = std::make_unique<AddrRelayManager>(peer_manager_.get(), config_.datadir);

  // HeaderSyncManager (header synchronization)
  header_sync_manager_ = std::make_unique<HeaderSyncManager>(chainstate_manager, *peer_manager_);
  peer_manager_->SetHeaderSyncManager(header_sync_manager_.get());

  // Initialize stable connection parameters
  peer_manager_->Init(
      transport_,
      [this](Peer* peer) { setup_peer_message_handler(peer); },
      [this]() { return running_.load(std::memory_order_acquire) && network_active_.load(std::memory_order_acquire); },
      config_.network_magic,
      local_nonce_);


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
    return addr_relay_mgr_->HandleAddr(peer, addr_msg);
  });

  // GETADDR - Address discovery (no message payload)
  message_dispatcher_->RegisterHandler(protocol::commands::GETADDR, [this](PeerPtr peer, ::unicity::message::Message*) {
    return addr_relay_mgr_->HandleGetAddr(peer);
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
      LOG_NET_WARN_RL("peer {} sent headers before completing handshake, disconnecting", peer ? peer->id() : -1);
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
      LOG_NET_WARN_RL("peer {} sent getheaders before completing handshake, disconnecting", peer ? peer->id() : -1);
      if (peer) {
        peer->disconnect();
      }
      return false;  // Disconnect
    }
    return header_sync_manager_->HandleGetHeadersMessage(peer, getheaders_msg);
  });

  LOG_NET_INFO("registered {} message handlers with MessageDispatcher",
               message_dispatcher_->GetRegisteredCommands().size());
}

NetworkManager::~NetworkManager() {
  try {
    stop();
  } catch (...) {
  }
}

ConnectionManager& NetworkManager::peer_manager() {
  return *peer_manager_;
}

AddrRelayManager& NetworkManager::discovery_manager() {
  return *addr_relay_mgr_;
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
  if (config_.io_threads > 0 && !external_io_context_) {
    // Create work guard to keep io_context running (for timers)
    work_guard_ = std::make_unique<asio::executor_work_guard<asio::io_context::executor_type>>(
        asio::make_work_guard(*io_context_));

    // Setup timers
    connect_timer_ = std::make_unique<asio::steady_timer>(*io_context_);
    maintenance_timer_ = std::make_unique<asio::steady_timer>(*io_context_);
    feeler_timer_ = std::make_unique<asio::steady_timer>(*io_context_);
    sendmessages_timer_ = std::make_unique<asio::steady_timer>(*io_context_);
    extra_block_relay_timer_ = std::make_unique<asio::steady_timer>(*io_context_);

    // Start IO threads (only for owned io_context)
    for (size_t i = 0; i < config_.io_threads; ++i) {
      io_threads_.emplace_back([this]() { io_context_->run(); });
    }
  }

  // Start listening if enabled (via transport)
  if (config_.listen_enabled && config_.listen_port > 0) {
    bool success = transport_->listen(config_.listen_port, [this](TransportConnectionPtr connection) {
      // Delegate to ConnectionManager
      peer_manager_->HandleInboundConnection(
          connection, chainstate_manager_.GetChainHeight(), default_inbound_permissions_);
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

      // Restore fully_stopped_ so a subsequent start() won't deadlock
      fully_stopped_ = true;
      stop_cv_.notify_all();

      return false;
    }
  }

  // Start discovery services (loads anchors, bootstraps if needed)
  addr_relay_mgr_->Start([this](const std::vector<protocol::NetworkAddress>& anchors) {
    peer_manager_->ConnectToAnchors(anchors, chainstate_manager_.GetChainHeight());
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
  if (extra_block_relay_timer_) {
    extra_block_relay_timer_->cancel();
  }

  // Save anchors while peers are still connected (need their addresses)
  if (!config_.datadir.empty()) {
    try {
      std::string anchors_path = config_.datadir + "/anchors.json";
      SaveAnchors(anchors_path);
    } catch (const std::exception& e) {
    } catch (...) {
    }
  }

  // HUTDOWN SEQUENCE
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
  fully_stopped_ = true;
  stop_cv_.notify_all();
}

ConnectionResult NetworkManager::connect_to(const protocol::NetworkAddress& addr,
                                            NetPermissionFlags permissions,
                                            ConnectionType conn_type,
                                            bool bypass_slot_limit) {
  if (!running_.load(std::memory_order_acquire)) {
    return ConnectionResult::NotRunning;
  }

  // Network activity disabled (setnetworkactive false)
  if (!network_active_.load(std::memory_order_acquire)) {
    return ConnectionResult::NotRunning;
  }

  // Delegate to ConnectionManager (handles all connection logic)
  return peer_manager_->ConnectTo(addr, permissions, chainstate_manager_.GetChainHeight(), conn_type, bypass_slot_limit);
}

bool NetworkManager::disconnect_from(int peer_id) {
  if (!peer_manager_->get_peer(peer_id)) {
    return false;
  }
  asio::post(*io_context_, [this, peer_id]() {
    peer_manager_->remove_peer(peer_id);
  });
  return true;
}

void NetworkManager::SetNetworkActive(bool active) {
  if (network_active_.load(std::memory_order_acquire) == active) {
    return;  // No change
  }

  LOG_INFO("SetNetworkActive: {}", active ? "enabling" : "disabling");
  network_active_.store(active, std::memory_order_release);

  if (!active) {
    auto peers = peer_manager_->get_all_peers();
    for (const auto& peer : peers) {
      if (peer) {
        int id = peer->id();
        LOG_DEBUG("SetNetworkActive: disconnecting peer {}", id);
        asio::post(*io_context_, [this, id]() {
          peer_manager_->remove_peer(id);
        });
      }
    }
  }
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

std::optional<protocol::NetworkAddress> NetworkManager::get_local_address() const {
  std::lock_guard<std::mutex> lock(local_addr_mutex_);
  return local_addr_;
}

void NetworkManager::schedule_next_connection_attempt() {
  if (!running_.load(std::memory_order_acquire)) {
    return;
  }

  connect_timer_->expires_after(config_.connect_interval);
  connect_timer_->async_wait([this](const asio::error_code& ec) {
    if (!ec && running_.load(std::memory_order_acquire)) {
      if (config_.max_outbound_connections > 0) {
        peer_manager_->AttemptOutboundConnections(chainstate_manager_.GetChainHeight());
      }
      schedule_next_connection_attempt();
    }
  });
}

void NetworkManager::run_maintenance() {
  if (!running_.load(std::memory_order_acquire)) {
    return;
  }

  peer_manager_->process_periodic();
  header_sync_manager_->ProcessTimers();
  peer_manager_->SweepBanned();
  peer_manager_->SweepDiscouraged();

  check_initial_sync();

  // Enable extra block-relay peer rotation once IBD completes.
  // Periodically verifies our chain tip from fresh block-relay-only peers.
  if (!extra_block_relay_started_ && !chainstate_manager_.IsInitialBlockDownload()) {
    StartExtraBlockRelayPeers();
  }
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

  check_initial_sync();
  addr_relay_mgr_->ProcessPendingAddrRelays();

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
    double max_delay = config_.feeler_max_delay_multiplier *
                       std::chrono::duration_cast<std::chrono::seconds>(FEELER_INTERVAL).count();
    delay_s = std::min(max_delay, delay_s);
  }

  auto delay = std::chrono::seconds(std::max(1, static_cast<int>(delay_s)));

  feeler_timer_->expires_after(delay);

  feeler_timer_->async_wait([this](const asio::error_code& ec) {
    if (!ec && running_.load(std::memory_order_acquire)) {
      peer_manager_->AttemptFeelerConnection(chainstate_manager_.GetChainHeight());
      schedule_next_feeler();
    }
  });
}

void NetworkManager::schedule_next_extra_block_relay() {
  if (!running_.load(std::memory_order_acquire) || !extra_block_relay_timer_) {
    return;
  }

  if (!extra_block_relay_started_) {
    return;
  }

  // Exponential distribution around 5 minute mean
  double delay_s;
  {
    std::lock_guard<std::mutex> lock(feeler_rng_mutex_);
    std::exponential_distribution<double> exp(
        1.0 / std::chrono::duration_cast<std::chrono::seconds>(EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL).count());
    delay_s = exp(feeler_rng_);
  }

  // Cap at 3x interval to prevent pathological delays
  double max_delay = 3.0 *
                     std::chrono::duration_cast<std::chrono::seconds>(EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL).count();
  delay_s = std::min(max_delay, delay_s);

  auto delay = std::chrono::seconds(std::max(1, static_cast<int>(delay_s)));

  extra_block_relay_timer_->expires_after(delay);

  extra_block_relay_timer_->async_wait([this](const asio::error_code& ec) {
    if (!ec && running_.load(std::memory_order_acquire)) {
      attempt_extra_block_relay_connection();
      schedule_next_extra_block_relay();
    }
  });
}

void NetworkManager::attempt_extra_block_relay_connection() {
  if (!running_.load(std::memory_order_acquire) || !network_active_.load(std::memory_order_acquire)) {
    return;
  }

  // Get address from AddrMan for block-relay connection
  auto addr_opt = addr_relay_mgr_->Select();
  if (!addr_opt) {
    LOG_NET_TRACE("extra block-relay: no address available");
    return;
  }

  LOG_NET_DEBUG("attempting extra block-relay connection to {}", addr_opt->to_string().value_or("unknown"));

  // Connect as block-relay-only (bypass slot limit for rotation)
  auto result = connect_to(*addr_opt, NetPermissionFlags::None, ConnectionType::BLOCK_RELAY,
                           /*bypass_slot_limit=*/true);

  if (result != ConnectionResult::Success) {
    LOG_NET_TRACE("extra block-relay connection failed: {}", static_cast<int>(result));
  }
  // Eviction decision happens after headers sync in HeaderSyncManager
}

void NetworkManager::StartExtraBlockRelayPeers() {
  LOG_NET_DEBUG("enabling extra block-relay-only peers");
  extra_block_relay_started_ = true;
  schedule_next_extra_block_relay();
}

void NetworkManager::check_initial_sync() {
  header_sync_manager_->CheckInitialSync();
}

void NetworkManager::setup_peer_message_handler(Peer* peer) {
  peer->set_message_handler(
      [this](PeerPtr peer, std::unique_ptr<message::Message> msg) { return handle_message(peer, std::move(msg)); });

  // When inbound peers tell us what IP they see us as, use it for self-advertisement
  peer->set_local_addr_learned_handler([this](const std::string& ip) { set_local_addr_from_peer_feedback(ip); });
}

void NetworkManager::handle_message(PeerPtr peer, std::unique_ptr<message::Message> msg) {
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
    if (!peer_manager_->CheckIncomingNonce(version_msg->nonce)) {
      // Nonce collision detected! Either self-connection or duplicate connection
      // (CheckIncomingNonce already logs the details)
      int peer_id = peer->id();

      // Re-check running_ before operations that interact with manager state
      if (!running_.load(std::memory_order_acquire)) {
        return;
      }

      peer->disconnect();
      peer_manager_->remove_peer(peer_id);
      return; 
    }
  }

  // Re-check running_ before dispatching (which may trigger more manager interactions)
  if (!running_.load(std::memory_order_acquire)) {
    return;
  }

  message_dispatcher_->Dispatch(peer, msg->command(), msg.get());
}

std::vector<protocol::NetworkAddress> NetworkManager::GetAnchors() const {
  return addr_relay_mgr_->GetAnchors();
}

bool NetworkManager::SaveAnchors(const std::string& filepath) {
  return addr_relay_mgr_->SaveAnchors(filepath);
}

bool NetworkManager::LoadAnchors(const std::string& filepath) {
  // Load anchors and delegate connection logic to ConnectionManager
  try {
    auto anchor_addrs = addr_relay_mgr_->LoadAnchors(filepath);
    if (!anchor_addrs.empty()) {
      peer_manager_->ConnectToAnchors(anchor_addrs, chainstate_manager_.GetChainHeight());
      return true;
    }
    return false;
  } catch (const std::exception& e) {
    LOG_NET_ERROR("Failed to load anchors from {}: {}", filepath, e.what());
    return false;  // Corrupted file is not fatal - continue with empty anchors
  } catch (...) {
    LOG_NET_ERROR("Unknown exception while loading anchors from {}", filepath);
    return false;  // Continue with empty anchors
  }
}

void NetworkManager::announce_block(const uint256& block_hash) {
  // Dispatch to io_context thread to avoid data races on Peer::connection_.
  // This method may be called from the miner or RPC thread (via ChainTip notifications),
  // but peer state must only be accessed from the io_context thread.
  // asio::dispatch runs immediately if already on the io_context thread.
  asio::dispatch(*io_context_, [this, block_hash]() {
    const chain::CBlockIndex* pindex = chainstate_manager_.LookupBlockIndex(block_hash);
    if (!pindex) {
      LOG_NET_WARN("announce_block: block {} not found in index", block_hash.GetHex());
      return;
    }

    CBlockHeader header = pindex->GetBlockHeader();
    auto all_peers = peer_manager_->get_all_peers();
    size_t sent_count = 0;

    for (const auto& peer : all_peers) {
      if (!peer || !peer->is_connected() || peer->state() != PeerConnectionState::READY)
        continue;
      auto msg = std::make_unique<message::HeadersMessage>();
      msg->headers.push_back(header);
      peer->send_message(std::move(msg));
      sent_count++;
    }

    LOG_NET_DEBUG("announced block {} via HEADERS to {} peers", block_hash.GetHex(), sent_count);
  });
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

  if (local_addr_.has_value()) {
    return;  
  }

  try {
    local_addr_ = protocol::NetworkAddress::from_string(external_ip, config_.listen_port, protocol::NODE_NETWORK);
    LOG_NET_INFO("learned local address from UPnP: {}:{}", external_ip, config_.listen_port);
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
      LOG_NET_TRACE("ignoring non-routable peer feedback address: {}", ip);
      return;
    }

    local_addr_ = addr;
    LOG_NET_INFO("learned local address from peer feedback: {}:{}", ip, config_.listen_port);
  } catch (const std::exception& e) {
    LOG_NET_WARN("Failed to parse peer feedback address {}: {}", ip, e.what());
  }
}

void NetworkManager::maybe_send_local_addr() {
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

  // Check if it's time to send (exponential distribution)
  auto now_steady = util::GetSteadyTime();
  if (next_local_addr_send_ != std::chrono::steady_clock::time_point{} &&
      now_steady < next_local_addr_send_) {
    return;  
  }

  // Build ADDR message with our address
  auto addr_msg = std::make_unique<message::AddrMessage>();
  protocol::TimestampedAddress ts_addr;
  ts_addr.timestamp = static_cast<uint32_t>(util::GetTime());
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
    // Schedule next send using exponential distribution
    int64_t delay_sec;
    {
      std::lock_guard<std::mutex> lock(feeler_rng_mutex_);
      std::exponential_distribution<double> exp_dist(1.0 / AVG_LOCAL_ADDR_BROADCAST_INTERVAL_SEC);
      delay_sec = static_cast<int64_t>(exp_dist(feeler_rng_));
    }
    next_local_addr_send_ = now_steady + std::chrono::seconds(delay_sec);

    auto addr_str = addr_to_send->to_string();
    LOG_NET_INFO("self-advertisement: sent local address {} to {} peers (next in {}h)",
                 addr_str.value_or("unknown"), sent_count, delay_sec / 3600);
  }
}

}  // namespace network
}  // namespace unicity
