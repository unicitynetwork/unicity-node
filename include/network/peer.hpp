// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include "network/connection_types.hpp"
#include "network/message.hpp"
#include "network/protocol.hpp"
#include "network/transport.hpp"

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>

#include <asio.hpp>

namespace unicity {
namespace network {

// Forward declarations
class Peer;
using PeerPtr = std::shared_ptr<Peer>;

// Peer connection states
enum class PeerConnectionState {
  DISCONNECTED,  // Not connected
  CONNECTING,    // TCP connection in progress
  CONNECTED,     // TCP connected, handshake not started
  VERSION_SENT,  // Sent VERSION message
  READY,         // Received VERACK, fully connected and ready
  DISCONNECTING  // Shutting down
};

// Peer connection statistics
struct PeerStats {
  std::atomic<uint64_t> bytes_sent{0};
  std::atomic<uint64_t> bytes_received{0};
  std::atomic<uint64_t> messages_sent{0};
  std::atomic<uint64_t> messages_received{0};
  std::atomic<std::chrono::seconds> connected_time{std::chrono::seconds{0}};
  std::atomic<std::chrono::seconds> last_send{std::chrono::seconds{0}};
  std::atomic<std::chrono::seconds> last_recv{std::chrono::seconds{0}};
  std::atomic<std::chrono::milliseconds> ping_time_ms{std::chrono::milliseconds{-1}};  // -1 means not measured yet
};

// Message handler callback type (ownership of message transfers to handler)
using MessageHandler = std::function<void(PeerPtr peer, std::unique_ptr<message::Message> msg)>;

// VERACK completion callback (called when peer transitions to READY state)
using VerackCompleteHandler = std::function<void(PeerPtr peer)>;

// Local address discovery callback (called when inbound peer tells us our address in VERSION)
// inbound peers tell us what IP they see us as in VERSION.addr_recv
// This helps nodes behind NAT discover their external address for self-advertisement.
using LocalAddrLearnedHandler = std::function<void(const std::string& ip)>;

// Peer class - Represents a single peer connection
// Handles async TCP connection, protocol handshake (VERSION/VERACK),
// message framing/parsing, send/receive queuing, ping/pong keepalive, lifecycle
// management
//
// Peer is single-use. start() may be called exactly once for the
// lifetime of a Peer instance. After disconnect(), a Peer must NOT be restarted;
// higher layers should create a new Peer instance for any subsequent connection.
//
// Threading Model:
// - All Peer I/O operations run on NetworkManager's single io_context thread
//   (no strand/locks needed for state_, recv_buffer_, etc.)
// - PeerStats members are atomic because they're accessed from multiple threads:
//   * Updated by io_context thread during send/receive operations
//   * Read by RPC server thread for monitoring/metrics (see RPCServer::handle_getpeerinfo)
// - NetworkManager must run with Config::io_threads = 1 (enforced at runtime)
class Peer : public std::enable_shared_from_this<Peer> {
private:
  // Passkey idiom: allows make_shared while preventing direct construction
  struct PrivateTag {};

public:
  // Create outbound peer (we initiate connection)
  static PeerPtr create_outbound(asio::io_context& io_context, TransportConnectionPtr connection,
                                 uint32_t network_magic, int32_t start_height, const std::string& target_address = "",
                                 uint16_t target_port = 0,
                                 ConnectionType conn_type = ConnectionType::OUTBOUND_FULL_RELAY);

  // Create inbound peer (they connected to us)
  static PeerPtr create_inbound(asio::io_context& io_context, TransportConnectionPtr connection, uint32_t network_magic,
                                int32_t start_height);

  ~Peer();

  // Disable copying
  Peer(const Peer&) = delete;
  Peer& operator=(const Peer&) = delete;

  // Start peer connection (outbound: initiates connection, inbound: starts
  // receiving messages)
  void start();

  void disconnect();
  void send_message(std::unique_ptr<message::Message> msg);
  void set_message_handler(MessageHandler handler);
  void set_verack_complete_handler(VerackCompleteHandler handler);
  void set_local_addr_learned_handler(LocalAddrLearnedHandler handler);

  // Test-only: override timeouts to keep tests fast
  // Pass 0ms to clear an override (use defaults).
  static void SetTimeoutsForTest(std::chrono::milliseconds handshake_ms, std::chrono::milliseconds inactivity_ms);
  static void ResetTimeoutsForTest();
  // Test-only: mark peer as having completed handshake
  void set_successfully_connected_for_test(bool value) { successfully_connected_ = value; }
  // Test-only: set connection state (peers created with nullptr transport start DISCONNECTED)
  void set_state_for_test(PeerConnectionState state) { state_ = state; }
  // Test-only: set peer's remote nonce (normally set when VERSION received)
  void set_peer_nonce_for_test(uint64_t nonce) { peer_nonce_ = nonce; }
  // Test-only: set ping time (for deterministic eviction testing)
  void set_ping_time_for_test(std::chrono::milliseconds ms) {
    stats_.ping_time_ms.store(ms, std::memory_order_relaxed);
  }

  // Setters (called by ConnectionManager)
  void set_id(int id) { id_ = id; }
  // Test-only: override per-peer nonce to simulate self-connection scenarios
  void set_local_nonce(uint64_t nonce) { local_nonce_ = nonce; }

  // Process-wide nonce for self-connection detection
  // Set once at startup, shared by all peers for reliable self-connect detection
  static void set_process_nonce(uint64_t nonce) { process_nonce_ = nonce; }
  static uint64_t get_process_nonce() { return process_nonce_; }

  // Getters
  PeerConnectionState state() const { return state_; }
  bool is_connected() const {
    return state_ != PeerConnectionState::DISCONNECTED && state_ != PeerConnectionState::DISCONNECTING;
  }
  bool successfully_connected() const { return successfully_connected_; }  // Handshake complete

  const PeerStats& stats() const { return stats_; }
  std::string address() const;
  uint16_t port() const;

  const std::string& target_address() const { return target_address_; }
  uint16_t target_port() const { return target_port_; }
  uint64_t get_local_nonce() const { return local_nonce_; }

  bool is_inbound() const { return is_inbound_; }
  ConnectionType connection_type() const { return connection_type_; }
  bool is_feeler() const { return connection_type_ == ConnectionType::FEELER; }
  bool is_manual() const { return connection_type_ == ConnectionType::MANUAL; }
  bool is_block_relay_only() const { return connection_type_ == ConnectionType::BLOCK_RELAY; }
  bool is_full_relay() const { return connection_type_ == ConnectionType::OUTBOUND_FULL_RELAY; }

  // Returns true if this peer participates in address relay (ADDR/GETADDR)
  // Block-relay-only, manual, and feeler connections do NOT relay addresses
  bool relays_addr() const { return RelaysAddr(connection_type_); }

  int id() const { return id_; }

  // Peer information from VERSION message
  int32_t version() const { return peer_version_; }
  uint64_t services() const { return peer_services_; }
  int32_t start_height() const { return peer_start_height_; }
  const std::string& user_agent() const { return peer_user_agent_; }
  uint64_t peer_nonce() const { return peer_nonce_; }

  // Header sync state
  bool sync_started() const { return sync_started_; }
  void set_sync_started(bool started) { sync_started_ = started; }

  // Discovery state
  bool has_sent_getaddr() const { return getaddr_sent_; }
  void mark_getaddr_sent() { getaddr_sent_ = true; }

  // Public constructor for make_shared, but requires PrivateTag (passkey idiom)
  // DO NOT call directly - use create_outbound() or create_inbound() factory functions
  Peer(PrivateTag, asio::io_context& io_context, TransportConnectionPtr connection, uint32_t network_magic,
       bool is_inbound, int32_t start_height, const std::string& target_address = "", uint16_t target_port = 0,
       ConnectionType conn_type = ConnectionType::OUTBOUND_FULL_RELAY);

private:
  // Connection management
  // Disconnect flow: disconnect() or on_transport_disconnect() -> do_disconnect() -> on_disconnect()
  // - disconnect(): public API, callable from any thread (posts to io_context if not already on it)
  // - do_disconnect(): actual disconnect logic (cancel timers, close socket), runs on io_context thread
  // - on_disconnect(): cleanup callback after disconnect completes
  // - on_transport_disconnect(): transport layer detected connection closed
  void do_disconnect();
  void on_connected();
  void on_disconnect();
  void on_transport_receive(const std::vector<uint8_t>& data);
  void on_transport_disconnect();

  // Handshake
  void send_version();
  void handle_version(const ::unicity::message::VersionMessage& msg);
  void handle_verack();

  // Message I/O
  void process_received_data();  // Uses recv_buffer_ with offset pattern
  void process_message(const protocol::MessageHeader& header, const std::vector<uint8_t>& payload);

  // Ping/Pong
  void schedule_ping();
  void send_ping();
  void handle_pong(const ::unicity::message::PongMessage& msg);

  // Timeouts
  void start_handshake_timeout();
  void start_inactivity_timeout();
  void cancel_all_timers();

  // Post disconnect to io_context
  void post_disconnect();

  // Member variables
  asio::io_context& io_context_;
  TransportConnectionPtr connection_;
  asio::steady_timer handshake_timer_;
  asio::steady_timer ping_timer_;
  asio::steady_timer inactivity_timer_;

  uint32_t network_magic_;
  bool is_inbound_;
  ConnectionType connection_type_;  // Connection type (INBOUND, OUTBOUND_FULL_RELAY, FEELER, etc.)
  int id_;                          // Set by ConnectionManager when peer is added

  // Self-connection prevention: per-peer copy of process_nonce_ (exists for test overrides via set_local_nonce)
  uint64_t local_nonce_;
  int32_t local_start_height_;  // Our blockchain height at connection time

  // Stored peer address
  // For outbound: target address we're connecting to (passed to create_outbound)
  // For inbound: runtime address from accepted socket (set in create_inbound)
  // Used for duplicate prevention and peer lookup (see ConnectionManager::find_peer_by_address)
  std::string target_address_;
  uint16_t target_port_{0};

  PeerConnectionState state_;
  PeerStats stats_;
  MessageHandler message_handler_;
  VerackCompleteHandler verack_complete_handler_;
  LocalAddrLearnedHandler local_addr_learned_handler_;
  bool successfully_connected_{false};  // Set to true after VERACK received

  // Millisecond-precision last activity (used for test inactivity timeouts)
  std::atomic<std::chrono::milliseconds> last_activity_ms_{std::chrono::milliseconds{0}};
  bool sync_started_{false};  // Whether we've started headers sync with this peer
  bool getaddr_sent_{false};  // Whether we've sent GETADDR to this peer (discovery)

  // Ensures start() executes exactly once (Peer objects are single-use)
  std::atomic<bool> started_{false};

  // Peer info from VERSION
  int32_t peer_version_ = 0;
  uint64_t peer_services_ = 0;
  int32_t peer_start_height_ = 0;
  std::string peer_user_agent_;
  uint64_t peer_nonce_ = 0;  // Peer's nonce from their VERSION message

  // Receive buffer (accumulates data until complete message received)
  // Uses read offset pattern to avoid O(n²) erase-from-front
  std::vector<uint8_t> recv_buffer_;
  size_t recv_buffer_offset_ = 0;  // Read position in recv_buffer_

  // Ping tracking
  uint64_t last_ping_nonce_ = 0;
  std::chrono::steady_clock::time_point ping_sent_time_;

  // Rate limiting for unknown commands to prevent log spam DoS
  std::atomic<int> unknown_command_count_{0};
  std::chrono::steady_clock::time_point last_unknown_reset_{};

  // Process-wide nonce for self-connection detection (set once at startup)
  static std::atomic<uint64_t> process_nonce_;

  // Test-only timeout overrides (0ms = disabled)
  static std::atomic<std::chrono::milliseconds> handshake_timeout_override_ms_;
  static std::atomic<std::chrono::milliseconds> inactivity_timeout_override_ms_;

public:
};

}  // namespace network
}  // namespace unicity
