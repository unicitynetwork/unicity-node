// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "network/peer.hpp"

#include "chain/timedata.hpp"
#include "util/hash.hpp"
#include "util/logging.hpp"
#include "util/time.hpp"

#include <random>

#include <asio/ip/address.hpp>
#include <asio/ip/address_v6.hpp>

namespace unicity {
namespace network {

// Generate random nonce for ping messages
static uint64_t generate_ping_nonce() {
  static std::random_device rd;
  static std::mt19937_64 gen(rd());
  static std::uniform_int_distribution<uint64_t> dis;
  return dis(gen);
}

// Initialize process-wide nonce (set by NetworkManager at startup)
std::atomic<uint64_t> Peer::process_nonce_{0};

// Test-only timeout overrides (0ms = disabled)
std::atomic<std::chrono::milliseconds> Peer::handshake_timeout_override_ms_{std::chrono::milliseconds{0}};
std::atomic<std::chrono::milliseconds> Peer::inactivity_timeout_override_ms_{std::chrono::milliseconds{0}};

// Peer implementation
Peer::Peer(PrivateTag, asio::io_context& io_context, TransportConnectionPtr connection, uint32_t network_magic,
           bool is_inbound, int32_t start_height, const std::string& target_address, uint16_t target_port,
           ConnectionType conn_type)
    : io_context_(io_context), connection_(connection), handshake_timer_(io_context), ping_timer_(io_context),
      inactivity_timer_(io_context), network_magic_(network_magic), is_inbound_(is_inbound),
      connection_type_(conn_type), id_(-1),
      local_nonce_(process_nonce_.load() != 0 ? process_nonce_.load() : generate_ping_nonce()),
      local_start_height_(start_height), target_address_(target_address), target_port_(target_port),
      state_(connection && connection->is_open()
                 ? PeerConnectionState::CONNECTED
                 : (connection ? PeerConnectionState::CONNECTING : PeerConnectionState::DISCONNECTED)),
      last_unknown_reset_(util::GetSteadyTime()) {}

Peer::~Peer() {
  try {
    // Correct lifecycle: disconnect() is called -> callbacks cleared -> connection closed
    // Then later: destructor runs on already-cleaned-up object
    if (state_ != PeerConnectionState::DISCONNECTED) {
      LOG_NET_ERROR("CRITICAL: Peer destructor called without prior disconnect() - "
                    "peer={}, state={}, address={}. This indicates a lifecycle bug. "
                    "disconnect() must be called while shared_ptr is alive.",
                    id_, static_cast<int>(state_), address());
    }

    // Prevent UB if disconnect() was not called (bug logged above)
    cancel_all_timers();
  } catch (...) {
  }
}

// Factory methods enforce shared_ptr ownership (required by enable_shared_from_this)
PeerPtr Peer::create_outbound(asio::io_context& io_context, TransportConnectionPtr connection, uint32_t network_magic,
                              int32_t start_height, const std::string& target_address, uint16_t target_port,
                              ConnectionType conn_type) {
  return std::make_shared<Peer>(PrivateTag{}, io_context, connection, network_magic, false, start_height,
                                target_address, target_port, conn_type);
}

PeerPtr Peer::create_inbound(asio::io_context& io_context, TransportConnectionPtr connection, uint32_t network_magic,
                             int32_t start_height) {
  std::string addr = connection ? connection->remote_address() : "";
  uint16_t remote_port = connection ? connection->remote_port() : 0;
  return std::make_shared<Peer>(PrivateTag{}, io_context, connection, network_magic, true, start_height, addr,
                                remote_port, ConnectionType::INBOUND);
}

void Peer::start() {
  // Guard against double-start or restart after disconnect
  if (started_.exchange(true)) {
    if (state_ == PeerConnectionState::DISCONNECTED || state_ == PeerConnectionState::DISCONNECTING) {
      LOG_NET_ERROR("Peer {} restart attempted; Peer objects are single-use", id_);
    }
    return;
  }

  if (state_ != PeerConnectionState::CONNECTING && state_ != PeerConnectionState::CONNECTED) {
    return;
  }

  // Outbound connection flow:
  //   1. create_outbound() creates peer in CONNECTING state
  //   2. Transport layer initiates async TCP connect
  //   3. On TCP success, transport calls its connect callback
  //   4. Connect callback calls peer->start() (we are here)
  //   5. This block transitions CONNECTING -> CONNECTED
  //   6. Then we proceed to P2P handshake (VERSION/VERACK)
  // Inbound peers skip this - they're created in CONNECTED state (socket already accepted)
  if (state_ == PeerConnectionState::CONNECTING) {
    if (!connection_ || !connection_->is_open()) {
      LOG_NET_ERROR("Cannot start peer - connection not open");
      return;
    }
    state_ = PeerConnectionState::CONNECTED;
  }

  // Initialize connection timestamps for RPC reporting and inactivity detection.
  // GetSteadyTime() returns a time_point (absolute moment in time).
  // time_since_epoch() converts to duration (elapsed time since clock's reference point).
  // We store durations rather than time_points because atomic<duration> is simpler.
  auto now_tp = util::GetSteadyTime();
  auto now_secs = std::chrono::duration_cast<std::chrono::seconds>(now_tp.time_since_epoch());
  stats_.connected_time.store(now_secs, std::memory_order_relaxed);
  stats_.last_send.store(now_secs, std::memory_order_relaxed);
  stats_.last_recv.store(now_secs, std::memory_order_relaxed);

  // Millisecond precision for test-only inactivity timeout (allows sub-second timeouts in tests)
  auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now_tp.time_since_epoch());
  last_activity_ms_.store(now_ms, std::memory_order_relaxed);

  // Capture shared_ptr in callbacks to prevent use-after-free during callback execution
  PeerPtr self = shared_from_this();
  connection_->set_receive_callback([self](const std::vector<uint8_t>& data) { self->on_transport_receive(data); });
  connection_->set_disconnect_callback([self]() { self->on_transport_disconnect(); });

  connection_->start();

  // Outbound: we initiated, so we send VERSION first
  // Inbound: they initiated, so we wait for their VERSION
  if (!is_inbound_) {
    send_version();
  }
  start_handshake_timeout();
}

void Peer::disconnect() {
  // SECURITY: Thread-safe disconnect() via io_context serialization
  // If called from external thread (RPC, background tasks), post to io_context
  // If already on io_context thread (timers, callbacks), execute directly
  // This serializes all disconnect operations on the single-threaded networking reactor
  if (io_context_.get_executor().running_in_this_thread()) {
    // Already on io_context thread - safe to execute directly
    do_disconnect();
  } else {
    // External thread - post to io_context for serialization
    auto self = shared_from_this();
    asio::post(io_context_, [self]() { self->do_disconnect(); });
  }
}

void Peer::do_disconnect() {
  // Simple state check - no atomics needed, we're on single-threaded io_context
  if (state_ == PeerConnectionState::DISCONNECTED || state_ == PeerConnectionState::DISCONNECTING) {
    return;
  }

  state_ = PeerConnectionState::DISCONNECTING;
  LOG_NET_DEBUG("disconnecting peer={}", id_);

  // Cancel all timers first
  cancel_all_timers();

  if (connection_) {
    // SECURITY: Clear callbacks BEFORE closing connection to prevent use-after-free
    // If we close first, pending async operations might invoke callbacks during/after
    // this object's destruction. Clear callbacks while shared_ptr is still alive.
    connection_->set_receive_callback({});
    connection_->set_disconnect_callback({});

    // Now safe to close and release connection
    connection_->close();
    connection_.reset();
  }

  // Update state and invoke final disconnect callback
  on_disconnect();
}

void Peer::post_disconnect() {
  // SECURITY: Post disconnect() to io_context to prevent use-after-free
  // By posting, we defer disconnect until after the current call finishes.
  auto self = shared_from_this();
  asio::post(io_context_, [self]() { self->disconnect(); });
}

void Peer::send_message(std::unique_ptr<message::Message> msg) {
  std::string command = msg->command();

  if (state_ == PeerConnectionState::DISCONNECTED || state_ == PeerConnectionState::DISCONNECTING) {
    return;
  }

  // Fast-fail before doing work if transport is already closed
  if (!connection_ || !connection_->is_open()) {
    post_disconnect();
    return;
  }

  auto payload = msg->serialize();

  // Create message header with checksum
  protocol::MessageHeader header(network_magic_, msg->command(), static_cast<uint32_t>(payload.size()));
  uint256 hash = Hash(payload);
  std::memcpy(header.checksum.data(), hash.begin(), 4);

  auto header_bytes = ::unicity::message::serialize_header(header);

  std::vector<uint8_t> full_message;
  full_message.reserve(header_bytes.size() + payload.size());
  full_message.insert(full_message.end(), header_bytes.begin(), header_bytes.end());
  full_message.insert(full_message.end(), payload.begin(), payload.end());

  bool send_result = connection_ && connection_->send(full_message);

  if (send_result) {
    stats_.messages_sent.fetch_add(1, std::memory_order_relaxed);
    stats_.bytes_sent.fetch_add(full_message.size(), std::memory_order_relaxed);
    auto now_tp = util::GetSteadyTime();
    auto now = std::chrono::duration_cast<std::chrono::seconds>(now_tp.time_since_epoch());
    stats_.last_send.store(now, std::memory_order_relaxed);
    last_activity_ms_.store(std::chrono::duration_cast<std::chrono::milliseconds>(now_tp.time_since_epoch()),
                            std::memory_order_relaxed);
  } else {
    LOG_NET_ERROR("Failed to send {} to {}", command, address());
    post_disconnect();
  }
}

void Peer::set_message_handler(MessageHandler handler) {
  message_handler_ = std::move(handler);
}

void Peer::set_verack_complete_handler(VerackCompleteHandler handler) {
  verack_complete_handler_ = std::move(handler);
}

void Peer::set_local_addr_learned_handler(LocalAddrLearnedHandler handler) {
  local_addr_learned_handler_ = std::move(handler);
}

std::string Peer::address() const {
  if (connection_)
    return connection_->remote_address();
  if (!target_address_.empty())
    return target_address_;
  return "unknown";
}

uint16_t Peer::port() const {
  if (connection_)
    return connection_->remote_port();
  if (target_port_ != 0)
    return target_port_;
  return 0;
}

// Private methods

void Peer::on_connected() {
  state_ = PeerConnectionState::CONNECTED;
}

void Peer::on_disconnect() {
  state_ = PeerConnectionState::DISCONNECTED;
}

void Peer::on_transport_receive(const std::vector<uint8_t>& data) {
  // SECURITY: Check incoming chunk size FIRST before any allocation
  // This prevents a single oversized chunk from bypassing flood protection
  if (data.size() > protocol::DEFAULT_RECV_FLOOD_SIZE) {
    LOG_NET_WARN_RL("Oversized chunk received ({} bytes, limit: {} bytes), "
                    "disconnecting from {}",
                    data.size(), protocol::DEFAULT_RECV_FLOOD_SIZE, address());
    post_disconnect();
    return;
  }

  // Enforce DEFAULT_RECV_FLOOD_SIZE to prevent unbounded receive buffer DoS
  // Check total buffer size (including already processed data)
  // Defense-in-depth: verify invariant that offset <= size (should always hold)
  if (recv_buffer_offset_ > recv_buffer_.size()) {
    LOG_NET_ERROR("Buffer invariant violation: offset {} > size {}, disconnecting {}", recv_buffer_offset_,
                  recv_buffer_.size(), address());
    post_disconnect();
    return;
  }
  size_t usable_bytes = recv_buffer_.size() - recv_buffer_offset_;
  if (usable_bytes + data.size() > protocol::DEFAULT_RECV_FLOOD_SIZE) {
    LOG_NET_WARN_RL("Receive buffer overflow (usable: {} bytes, incoming: {} "
                    "bytes, limit: {} bytes), disconnecting from {}",
                    usable_bytes, data.size(), protocol::DEFAULT_RECV_FLOOD_SIZE, address());
    post_disconnect();
    return;
  }

  // Compact buffer if offset has grown large (over half the buffer)
  // This prevents unbounded memory growth while keeping O(1) amortized cost
  if (recv_buffer_offset_ > 0 && recv_buffer_offset_ >= recv_buffer_.size() / 2) {
    recv_buffer_.erase(recv_buffer_.begin(), recv_buffer_.begin() + recv_buffer_offset_);
    recv_buffer_offset_ = 0;

    // SECURITY: Shrink capacity if buffer is empty or very small to prevent
    // permanent memory waste after processing large messages
    // Example: 5MB burst → buffer grows to 5MB → consumed → shrink to 0
    // This prevents each peer from wasting up to 5MB indefinitely
    // With 125 inbound peers, this saves up to 625MB memory
    if (recv_buffer_.empty() || recv_buffer_.size() < 1024) {
      recv_buffer_.shrink_to_fit();
    }
  }

  // Accumulate received data into buffer
  // Reserve space to avoid multiple reallocations
  recv_buffer_.reserve(recv_buffer_.size() + data.size());
  recv_buffer_.insert(recv_buffer_.end(), data.begin(), data.end());

  // Update stats
  stats_.bytes_received.fetch_add(data.size(), std::memory_order_relaxed);
  auto now_tp = util::GetSteadyTime();
  auto now = std::chrono::duration_cast<std::chrono::seconds>(now_tp.time_since_epoch());
  stats_.last_recv.store(now, std::memory_order_relaxed);
  last_activity_ms_.store(std::chrono::duration_cast<std::chrono::milliseconds>(now_tp.time_since_epoch()),
                          std::memory_order_relaxed);

  // Try to process complete messages
  process_received_data();
}

void Peer::on_transport_disconnect() {
  // SECURITY: Remote close path - must break reference cycle to prevent leak
  // Reference cycle: Peer → connection_ → callbacks → Peer (via captured shared_ptr)
  //
  // Transport already closed connection, but we must:
  // 1. Clear callbacks to break cycle (callbacks capture shared_ptr)
  // 2. Release connection_ to decrement refcount
  // 3. Cancel timers and mark disconnected
  if (state_ != PeerConnectionState::DISCONNECTED) {
    cancel_all_timers();

    // Break reference cycle: clear callbacks and release connection
    if (connection_) {
      connection_->set_receive_callback({});
      connection_->set_disconnect_callback({});
      connection_.reset();
    }

    on_disconnect();
  }
}

void Peer::send_version() {
  // Precondition: must have a connection to send VERSION
  assert(connection_ && "send_version called without connection");
  if (!connection_) {
    LOG_NET_ERROR("send_version called without connection");
    return;
  }

  auto version_msg = std::make_unique<::unicity::message::VersionMessage>();
  version_msg->version = protocol::PROTOCOL_VERSION;
  version_msg->services = protocol::NODE_NETWORK;
  version_msg->timestamp = util::GetTime();

  // addr_recv: The network address of the remote peer
  std::string peer_addr = connection_->remote_address();
  uint16_t peer_port = connection_->remote_port();
  version_msg->addr_recv = protocol::NetworkAddress::from_string(peer_addr, peer_port);
  std::string them_addr = peer_addr + ":" + std::to_string(peer_port);

  // addr_from: Our address as seen by the peer
  // Peers discover our real address from the connection itself (what IP they see).
  version_msg->addr_from = protocol::NetworkAddress();

  // Use our local nonce for self-connection prevention
  version_msg->nonce = local_nonce_;
  version_msg->user_agent = protocol::GetUserAgent();
  version_msg->start_height = local_start_height_;

  LOG_NET_DEBUG("send version message: version {}, blocks={}, them={}, peer={}", protocol::PROTOCOL_VERSION,
                local_start_height_, them_addr, id_);

  send_message(std::move(version_msg));
  state_ = PeerConnectionState::VERSION_SENT;
}

void Peer::handle_version(const message::VersionMessage& msg) {
  // Ignore duplicate VERSION messages 
  if (peer_version_ != 0) {
    LOG_NET_DEBUG("redundant version message from peer={}", id_);
    return;
  }

  // Reject obsolete protocol versions
  if (msg.version < static_cast<int32_t>(protocol::MIN_PROTOCOL_VERSION)) {
    LOG_NET_DEBUG("peer={} using obsolete version {}; disconnecting", id_, msg.version);
    post_disconnect();
    return;
  }

  peer_version_ = msg.version;
  peer_services_ = msg.services;

  // Validate service flags for outbound connections
  // Outbound peers (that we initiated) MUST advertise NODE_NETWORK to be useful for sync
  // Inbound peers (they connected to us) are not required to serve us data - accept any
  // Feelers are just testing liveness, not for sync - no service requirements
  if (!is_inbound_ && !is_feeler()) {
    if ((peer_services_ & protocol::NODE_NETWORK) == 0) {
      LOG_NET_DEBUG("peer={} missing required NODE_NETWORK service flag (services={}); disconnecting", id_,
                    peer_services_);
      post_disconnect();
      return;
    }
  }
  peer_start_height_ = msg.start_height;
  peer_user_agent_ = msg.user_agent;
  peer_nonce_ = msg.nonce;

  // Sanitize user_agent before logging to prevent:
  // 1. Log spam (attacker sends 4MB user_agent → 4MB log line)
  // 2. Control char injection (ANSI codes, format strings)
  // 3. Null byte injection (truncates logs)
  std::string sanitized_ua = peer_user_agent_;

  // Cap size to 256 chars
  if (sanitized_ua.size() > protocol::MAX_SUBVERSION_LENGTH) {
    sanitized_ua.resize(protocol::MAX_SUBVERSION_LENGTH);
    sanitized_ua += "...[truncated]";
  }

  // Remove control characters (except tab)
  sanitized_ua.erase(std::remove_if(sanitized_ua.begin(), sanitized_ua.end(),
                                    [](unsigned char c) { return c < 32 && c != '\t'; }),
                     sanitized_ua.end());

  // Replace null bytes with spaces (prevent log truncation)
  std::replace(sanitized_ua.begin(), sanitized_ua.end(), '\0', ' ');

  LOG_NET_DEBUG("receive version message: {}: version {}, blocks={}, peer={}", sanitized_ua, msg.version,
                msg.start_height, id_);

  // SECURITY: Self-connection detection
  // Checks nonce for BOTH inbound and outbound connections to prevent:
  // - Wasting connection slots
  // - Resource exhaustion from connecting to ourselves
  // - Potential protocol confusion
  //
  // Defense-in-depth: This is a FAST self-connection check at Peer level.
  // NetworkManager also performs COMPREHENSIVE nonce checking including:
  //   1. Self-connection (same check as here)
  //   2. Duplicate connection detection (checks against ALL existing peers' nonces)
  // This layered approach provides:
  //   - Early rejection at Peer level (no NetworkManager overhead)
  //   - Peer works standalone (e.g., in unit tests without NetworkManager)
  //   - NetworkManager catches duplicate connections that Peer can't detect
  if (peer_nonce_ == local_nonce_) {
    LOG_NET_WARN_RL("self connection detected, disconnecting peer={}", id_);
    post_disconnect();
    return;
  }

  // SECURITY: Clamp negative timestamps to prevent overflow
  // After clamping, both values are non-negative, making overflow impossible
  int64_t nTime = msg.timestamp;
  if (nTime < 0) {
    nTime = 0;
  }

  int64_t now = util::GetTime();
  int64_t time_offset = nTime - now;

  // Only sample time from outbound peers (reduces skew risk)
  if (!is_inbound_) {
    protocol::NetworkAddress net_addr = protocol::NetworkAddress::from_string(address(), port(),
                                                                              protocol::NODE_NETWORK);
    chain::AddTimeData(net_addr, time_offset);
  }

  // Local address discovery from peer feedback
  // Both inbound and outbound peers tell us what IP they see us as via addr_recv.
  // - Inbound: peer connected to our listen port, addr_recv has our public IP:port
  // - Outbound: peer sees our outgoing connection IP (same as listen IP for public servers)
  // This enables self-advertisement for nodes that only make outbound connections.
  if (local_addr_learned_handler_) {
    auto our_addr_str = msg.addr_recv.to_string();
    if (our_addr_str.has_value()) {
      // Extract just the IP (strip port) since we know our own listen port
      std::string ip = *our_addr_str;
      auto colon_pos = ip.rfind(':');
      if (colon_pos != std::string::npos) {
        ip.resize(colon_pos);
      }
      local_addr_learned_handler_(ip);
    }
  }

  // FEELER connections: disconnect immediately after receiving VERSION
  // Address is proven reachable as soon as we get a valid VERSION response.
  // Note: We do NOT set successfully_connected_ here - that flag is for full handshake
  // completion (VERACK). Feeler success is determined by receiving VERSION, which
  // is checked via peer_version() > 0 in remove_peer().
  if (is_feeler()) {
    LOG_NET_DEBUG("feeler connection completed peer={}; disconnecting", id_);
    post_disconnect();
    return;
  }

  // Inbound handshake: Send our VERSION response, then send VERACK
  // Order matters: VERSION must be sent before VERACK to avoid protocol violations
  if (is_inbound_ && state_ == PeerConnectionState::CONNECTED) {
    send_version();
  }

  // Send VERACK
  send_message(std::make_unique<::unicity::message::VerackMessage>());
}

void Peer::handle_verack() {
  // Reject duplicate VERACK messages
  if (successfully_connected_) {
    LOG_NET_WARN_RL("Duplicate VERACK from peer {}, ignoring", address());
    return;
  }

  // Mark handshake complete before any early returns so upper layers can act
  state_ = PeerConnectionState::READY;
  successfully_connected_ = true;
  handshake_timer_.cancel();

  // Start ping timer and inactivity timeout
  schedule_ping();
  start_inactivity_timeout();

  // Announce tip immediately after handshake completes
  // This allows newly connected peers to discover our chain tip without waiting
  // for the periodic announcement timer
  if (verack_complete_handler_) {
    verack_complete_handler_(shared_from_this());
  }

  std::string conn_dir = is_inbound_ ? "inbound" : "outbound";
  std::string conn_subtype = is_block_relay_only() ? "block-relay-only" : (is_feeler() ? "feeler" : "full-relay");
  LOG_NET_INFO("New {} {} peer connected: version: {}, blocks={}, peer={}", conn_dir, conn_subtype, peer_version_,
               peer_start_height_, id_);
}

void Peer::process_received_data() {
  // Process as many complete messages as we have in the buffer
  // Uses read offset to avoid O(n²) erase-from-front
  if (recv_buffer_offset_ > recv_buffer_.size()) {
    LOG_NET_ERROR("process_received_data: invariant violation offset {} > size {}", recv_buffer_offset_,
                  recv_buffer_.size());
    post_disconnect();
    return;
  }
  while (recv_buffer_.size() - recv_buffer_offset_ >= protocol::MESSAGE_HEADER_SIZE) {
    const uint8_t* read_ptr = recv_buffer_.data() + recv_buffer_offset_;
    size_t available = recv_buffer_.size() - recv_buffer_offset_;

    // Try to parse header
    protocol::MessageHeader header;
    if (!::unicity::message::deserialize_header(read_ptr, protocol::MESSAGE_HEADER_SIZE, header)) {
      LOG_NET_DEBUG("Header error: Unable to deserialize, peer={}", id_);
      post_disconnect();
      return;
    }

    // Validate magic
    if (header.magic != network_magic_) {
      LOG_NET_DEBUG("Header error: Wrong MessageStart {:08x} received, peer={}", header.magic, id_);
      post_disconnect();
      return;
    }

    // Validate payload size (already checked in deserialize_header)
    if (header.length > protocol::MAX_PROTOCOL_MESSAGE_LENGTH) {
      LOG_NET_DEBUG("Header error: Size too large ({}, {} bytes), peer={}", header.get_command(), header.length, id_);
      post_disconnect();
      return;
    }

    // Check if we have the complete message (header + payload)
    size_t total_message_size = protocol::MESSAGE_HEADER_SIZE + header.length;
    if (available < total_message_size) {
      // Don't have complete message yet, wait for more data
      return;
    }

    // Extract payload (avoid copy by passing pointer and size to deserializer)
    const uint8_t* payload_ptr = read_ptr + protocol::MESSAGE_HEADER_SIZE;
    std::vector<uint8_t> payload(payload_ptr, payload_ptr + header.length);

    // Verify checksum
    uint256 hash = Hash(payload);
    if (std::memcmp(header.checksum.data(), hash.begin(), 4) != 0) {
      LOG_NET_DEBUG("Header error: Wrong checksum ({}, {} bytes), peer={}", header.get_command(), header.length, id_);
      post_disconnect();
      return;
    }

    // Process the complete message
    process_message(header, payload);

    // Advance read offset instead of erasing (O(1) instead of O(n))
    recv_buffer_offset_ += total_message_size;
  }
}

void Peer::process_message(const protocol::MessageHeader& header, const std::vector<uint8_t>& payload) {
  stats_.messages_received.fetch_add(1, std::memory_order_relaxed);

  std::string command = header.get_command();

  LOG_NET_TRACE("Received {} from {} (payload size: {} bytes, peer_version: {})", command, address(), payload.size(),
                peer_version_);

  // Enforce VERSION must be first message
  if (peer_version_ == 0 && command != protocol::commands::VERSION) {
    LOG_NET_DEBUG("non-version message before version handshake. Message \"{}\" from peer={}", command, id_);
    post_disconnect();
    return;
  }

  // Create message object
  auto msg = ::unicity::message::create_message(command);
  if (!msg) {
    // Unknown command - ignore with rate limiting
    // This provides forward compatibility (new protocol versions can add commands)
    // while protecting against DoS via excessive unknown command spam

    auto now = util::GetSteadyTime();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_unknown_reset_).count();

    if (elapsed > 60) {
      // Reset counter every 60 seconds
      unknown_command_count_.store(0, std::memory_order_relaxed);
      last_unknown_reset_ = now;
    }

    int count = unknown_command_count_.fetch_add(1, std::memory_order_relaxed) + 1;

    // Log unknown commands (rate-limited to prevent spam)
    LOG_NET_WARN_RL("unknown message type: {} peer={} (count: {}/60s)", command, id_, count);

    // Disconnect if excessive unknown commands (likely attack or broken client)
    if (count > static_cast<int>(protocol::MAX_UNKNOWN_COMMANDS_PER_MINUTE)) {
      LOG_NET_ERROR_RL("excessive unknown commands from peer={} ({}/60s), "
                       "disconnecting (possible attack)",
                       id_, count);
      post_disconnect();
    }
    return;
  }

  // SECURITY: Validate zero-length payloads for KNOWN commands
  // Only VERACK and GETADDR are allowed to have empty payloads
  // PING/PONG must include 8-byte nonce
  // All other known messages (VERSION, ADDR, INV, GETHEADERS, HEADERS) must have data
  // Unknown commands are not checked here (handled above with rate limiting)
  if (payload.size() == 0) {
    if (command != protocol::commands::VERACK && command != protocol::commands::GETADDR) {
      LOG_NET_ERROR("unexpected zero-length payload for known message {} peer={}", command, id_);
      post_disconnect();
      return;
    }
  }

  // Deserialize
  if (!msg->deserialize(payload.data(), payload.size())) {
    LOG_NET_ERROR("failed to deserialize message: {} - disconnecting (protocol violation) peer={}", command, id_);
    // Malformed messages indicate protocol violation or malicious peer
    post_disconnect();
    return;
  }

  // Handle protocol messages internally
  if (command == protocol::commands::VERSION) {
    handle_version(static_cast<const message::VersionMessage&>(*msg));
    // Also notify handler for duplicate detection
    if (message_handler_) {
      message_handler_(shared_from_this(), std::move(msg));
    }
  } else if (command == protocol::commands::VERACK) {
    handle_verack();
    // Also notify handler so NetworkManager knows peer is ready
    if (message_handler_) {
      message_handler_(shared_from_this(), std::move(msg));
    }
  } else if (command == protocol::commands::PING) {
    // Only respond to PING after handshake is complete
    if (!successfully_connected_) {
      LOG_NET_DEBUG("Received PING before handshake complete from peer={}, ignoring", id_);
      return;
    }
    auto& ping = static_cast<const ::unicity::message::PingMessage&>(*msg);
    auto pong = std::make_unique<::unicity::message::PongMessage>(ping.nonce);
    send_message(std::move(pong));
    // PING/PONG handled internally only
  } else if (command == protocol::commands::PONG) {
    // Only process PONG after handshake is complete
    if (!successfully_connected_) {
      LOG_NET_DEBUG("Received PONG before handshake complete from peer={}, ignoring", id_);
      return;
    }
    handle_pong(static_cast<const message::PongMessage&>(*msg));
    // PING/PONG handled internally only
  } else {
    // Only process non-handshake messages after handshake is complete
    if (!successfully_connected_) {
      LOG_NET_DEBUG("Received {} before handshake complete from peer={}, ignoring", command, id_);
      return;
    }
    // Pass to handler
    if (message_handler_) {
      message_handler_(shared_from_this(), std::move(msg));
    }
  }
}

void Peer::SetTimeoutsForTest(std::chrono::milliseconds handshake_ms, std::chrono::milliseconds inactivity_ms) {
  handshake_timeout_override_ms_.store(handshake_ms, std::memory_order_relaxed);
  inactivity_timeout_override_ms_.store(inactivity_ms, std::memory_order_relaxed);
}

void Peer::ResetTimeoutsForTest() {
  handshake_timeout_override_ms_.store(std::chrono::milliseconds{0}, std::memory_order_relaxed);
  inactivity_timeout_override_ms_.store(std::chrono::milliseconds{0}, std::memory_order_relaxed);
}

void Peer::schedule_ping() {
  auto self = shared_from_this();
  ping_timer_.expires_after(std::chrono::seconds(protocol::PING_INTERVAL_SEC));
  ping_timer_.async_wait([self](const asio::error_code& ec) {
    if (!ec) {
      // Check if disconnected BEFORE accessing any members
      if (self->state_ == PeerConnectionState::DISCONNECTED || self->state_ == PeerConnectionState::DISCONNECTING) {
        return;
      }

      // Check if peer timed out (no PONG to previous PING)
      if (self->last_ping_nonce_ != 0) {
        // We sent a ping but haven't received PONG yet
        auto now = util::GetSteadyTime();
        auto ping_age = std::chrono::duration_cast<std::chrono::seconds>(now - self->ping_sent_time_);

        if (ping_age.count() > protocol::PING_TIMEOUT_SEC) {
          LOG_NET_DEBUG("ping timeout: {} seconds, peer={}", ping_age.count(), self->id_);
          self->disconnect();
          return;
        }
        // Still waiting for PONG, don't send another PING
        // (prevents overwriting last_ping_nonce_ and losing track of outstanding PING)
      } else {
        // No outstanding PING, safe to send a new one
        self->send_ping();
      }
      self->schedule_ping();
    }
  });
}

void Peer::send_ping() {
  last_ping_nonce_ = generate_ping_nonce();
  ping_sent_time_ = util::GetSteadyTime();

  auto ping = std::make_unique<::unicity::message::PingMessage>(last_ping_nonce_);
  send_message(std::move(ping));
}

void Peer::handle_pong(const message::PongMessage& msg) {
  if (msg.nonce == last_ping_nonce_) {
    auto now = util::GetSteadyTime();
    auto ping_time = std::chrono::duration_cast<std::chrono::milliseconds>(now - ping_sent_time_);
    stats_.ping_time_ms.store(ping_time, std::memory_order_relaxed);
    LOG_NET_TRACE("Ping time for {}: {}ms", address(), ping_time.count());

    // Clear nonce to indicate we received the PONG
    last_ping_nonce_ = 0;
  }
}

void Peer::start_handshake_timeout() {
  auto self = shared_from_this();
  {
    auto ov = handshake_timeout_override_ms_.load(std::memory_order_relaxed);
    if (ov.count() > 0) {
      handshake_timer_.expires_after(ov);
    } else {
      handshake_timer_.expires_after(std::chrono::seconds(protocol::VERSION_HANDSHAKE_TIMEOUT_SEC));
    }
  }
  handshake_timer_.async_wait([self](const asio::error_code& ec) {
    if (!ec) {
      // SECURITY: Check if disconnected BEFORE accessing any members
      if (self->state_ == PeerConnectionState::DISCONNECTED || self->state_ == PeerConnectionState::DISCONNECTING) {
        return;
      }

      if (self->state_ != PeerConnectionState::READY) {
        LOG_NET_DEBUG("version handshake timeout peer={}", self->id_);
        self->disconnect();
      }
    }
  });
}

void Peer::start_inactivity_timeout() {
  auto self = shared_from_this();
  // Check every 60 seconds instead of waiting the full timeout
  // This allows us to properly track activity and disconnect promptly
  auto ov = inactivity_timeout_override_ms_.load(std::memory_order_relaxed);
  if (ov.count() > 0) {
    inactivity_timer_.expires_after(ov);
  } else {
    constexpr int CHECK_INTERVAL_SEC = 60;
    inactivity_timer_.expires_after(std::chrono::seconds(CHECK_INTERVAL_SEC));
  }
  inactivity_timer_.async_wait([self](const asio::error_code& ec) {
    if (!ec) {
      // Check if disconnected BEFORE accessing any members
      if (self->state_ == PeerConnectionState::DISCONNECTED || self->state_ == PeerConnectionState::DISCONNECTING) {
        return;
      }

      // Load atomic durations
      auto now_duration = std::chrono::duration_cast<std::chrono::seconds>(util::GetSteadyTime().time_since_epoch());
      auto last_send = self->stats_.last_send.load(std::memory_order_relaxed);
      auto last_recv = self->stats_.last_recv.load(std::memory_order_relaxed);
      auto last_activity = std::max(last_send, last_recv);
      auto idle_time = now_duration - last_activity;

      auto ov = inactivity_timeout_override_ms_.load(std::memory_order_relaxed);
      if (ov.count() > 0) {
        // Millisecond-precision override path (used by tests for fast timeouts)
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(util::GetSteadyTime().time_since_epoch());
        auto last_ms = self->last_activity_ms_.load(std::memory_order_relaxed);
        auto idle_ms = now_ms - last_ms;
        if (idle_ms >= ov) {
          LOG_NET_WARN("Inactivity timeout (override)");
          self->disconnect();
          return;
        } else {
          self->start_inactivity_timeout();
          return;
        }
      }
      if (idle_time.count() > protocol::INACTIVITY_TIMEOUT_SEC) {
        if (last_send.count() == 0 && last_recv.count() == 0) {
          LOG_NET_DEBUG("socket no message in first {} seconds, {} {} peer={}", protocol::INACTIVITY_TIMEOUT_SEC,
                        last_recv.count() != 0 ? 1 : 0, last_send.count() != 0 ? 1 : 0, self->id_);
        } else if ((now_duration - last_send).count() > protocol::INACTIVITY_TIMEOUT_SEC) {
          LOG_NET_DEBUG("socket sending timeout: {}s peer={}", (now_duration - last_send).count(), self->id_);
        } else if ((now_duration - last_recv).count() > protocol::INACTIVITY_TIMEOUT_SEC) {
          LOG_NET_DEBUG("socket receive timeout: {}s peer={}", (now_duration - last_recv).count(), self->id_);
        } else {
          LOG_NET_WARN("Inactivity timeout (idle {}s)", idle_time.count());
        }
        self->disconnect();
      } else {
        // Still active, reschedule check
        self->start_inactivity_timeout();
      }
    }
  });
}

void Peer::cancel_all_timers() {
  handshake_timer_.cancel();
  ping_timer_.cancel();
  inactivity_timer_.cancel();
}

}  // namespace network
}  // namespace unicity
