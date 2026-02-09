// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include "network/transport.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <queue>

#include <asio.hpp>
#include <asio/any_io_executor.hpp>
#include <asio/strand.hpp>

namespace unicity {

// Forward declaration for test access
namespace test {
class RealTransportTestAccess;
}  // namespace test

namespace network {

// RealTransportConnection - TCP socket implementation of TransportConnection
// Wraps asio::ip::tcp::socket and provides the abstract interface.
class RealTransportConnection : public TransportConnection,
                                public std::enable_shared_from_this<RealTransportConnection> {
public:
  // Create outbound connection (will connect to remote)
  static TransportConnectionPtr create_outbound(asio::io_context& io_context, const std::string& address, uint16_t port,
                                                ConnectCallback callback);

  // Create inbound connection (already connected socket)
  static TransportConnectionPtr create_inbound(asio::io_context& io_context, asio::ip::tcp::socket socket);

  ~RealTransportConnection() override;

  // Non-copyable, non-movable (connections are not reusable)
  RealTransportConnection(const RealTransportConnection&) = delete;
  RealTransportConnection& operator=(const RealTransportConnection&) = delete;
  RealTransportConnection(RealTransportConnection&&) = delete;
  RealTransportConnection& operator=(RealTransportConnection&&) = delete;

  // TransportConnection interface
  void start() override;
  bool send(const std::vector<uint8_t>& data) override;
  void close() override;
  bool is_open() const override;
  std::string remote_address() const override;
  uint16_t remote_port() const override;
  bool is_inbound() const override { return is_inbound_; }
  void set_receive_callback(ReceiveCallback callback) override;
  void set_disconnect_callback(DisconnectCallback callback) override;

private:
  // Test access - allows test code to manipulate internal state
  friend class test::RealTransportTestAccess;
  RealTransportConnection(asio::io_context& io_context, bool is_inbound);

  void do_connect(const std::string& address, uint16_t port, ConnectCallback callback);

  // Strand-serialized internals (must be called on strand_)
  void start_read_impl();
  void do_write_impl();
  void close_impl();

  // Helper to deliver disconnect callback exactly once (must be called on strand)
  void deliver_disconnect_once();

  // Compute connect timeout (override if set, else default)
  std::chrono::milliseconds connect_timeout_ms() const;

  asio::io_context& io_context_;
  asio::ip::tcp::socket socket_;
  asio::strand<asio::any_io_executor> strand_;
  bool is_inbound_;
  uint64_t id_;
  static std::atomic<uint64_t> next_id_;

  // Callbacks (accessed only on strand_)
  ReceiveCallback receive_callback_;
  DisconnectCallback disconnect_callback_;
  // Flag to ensure disconnect callback is only delivered once
  bool disconnect_delivered_{false};

  // Send queue (accessed only on strand_)
  std::queue<std::shared_ptr<std::vector<uint8_t>>> send_queue_;
  size_t send_queue_bytes_ = 0;  // Total bytes in send queue (for DoS protection)
  // NOTE: writing_ is atomic because send() may check it from a non-strand thread
  // before dispatching the lambda onto the strand. By the time the lambda runs,
  // writing_ could have changed. Using atomic prevents data races.
  std::atomic<bool> writing_{false};

  // Receive buffer size for per-read allocations.
  static constexpr size_t RECV_BUFFER_SIZE = 256 * 1024;  // 256 KB

  // Connect timeout and state
  // NOTE: connect_timer_ is a unique_ptr so that its destructor can be explicitly
  // controlled. When the object is destroyed inside the io_context thread (common
  // during shutdown), the timer destructor must not try to access scheduler state
  // that may have been destroyed. We move it to a local variable in close_impl()
  // so it gets destroyed after the io_context has been stopped.
  std::unique_ptr<asio::steady_timer> connect_timer_;
  // CRITICAL: connect_done_ must be atomic because it's checked from multiple
  // async handlers (timeout, resolve, connect) which may execute concurrently
  // on different io_context threads.
  std::atomic<bool> connect_done_{false};
  std::shared_ptr<asio::ip::tcp::resolver> resolver_;
  static constexpr std::chrono::milliseconds DEFAULT_CONNECT_TIMEOUT{std::chrono::seconds(10)};

  static std::atomic<std::chrono::milliseconds> connect_timeout_override_ms_;
  // Test-only override for send queue limit (0 = disabled)
  static std::atomic<size_t> send_queue_limit_override_bytes_;

  // Connection state
  std::atomic<bool> open_{false};
  std::string remote_addr_;
  uint16_t remote_port_ = 0;
};

// RealTransport - asio implementation of Transport
// Uses an external io_context provided at construction time.
// The caller is responsible for running the io_context (e.g., via io_context.run()).
// This design unifies all networking onto a single io_context, eliminating
// potential data races from multiple io_contexts running on separate threads.
class RealTransport : public Transport, public std::enable_shared_from_this<RealTransport> {
public:
  // Create transport using external io_context.
  // The io_context must outlive this RealTransport instance.
  // The caller is responsible for running the io_context.
  explicit RealTransport(asio::io_context& io_context);
  ~RealTransport() override;

  // Transport interface
  TransportConnectionPtr connect(const std::string& address, uint16_t port, ConnectCallback callback) override;

  bool listen(uint16_t port, std::function<void(TransportConnectionPtr)> accept_callback) override;

  void stop_listening() override;

  // run() is a no-op - caller is responsible for running io_context
  void run() override {}

  // stop() cancels pending operations but does not stop the io_context
  void stop() override;

  bool is_running() const override { return running_; }

  // Access to io_context (for timers, etc.)
  asio::io_context& io_context() { return io_context_; }

  // Test/diagnostic: return bound listening port (0 if not listening)
  uint16_t listening_port() const;

private:
  void start_accept();
  void handle_accept(const asio::error_code& ec, asio::ip::tcp::socket socket);

  // Reference to external io_context (must outlive this object)
  asio::io_context& io_context_;
  std::atomic<bool> running_{true};  // Always "running" since io_context is external

  // Acceptor for inbound connections
  std::unique_ptr<asio::ip::tcp::acceptor> acceptor_;
  std::function<void(TransportConnectionPtr)> accept_callback_;
  uint16_t last_listen_port_{0};
};

}  // namespace network
}  // namespace unicity
