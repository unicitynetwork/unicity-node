// Copyright (c) 2025 The Unicity Foundation
// Real transport implementation using asio TCP sockets

#include "network/real_transport.hpp"

#include "network/protocol.hpp"
#include "util/logging.hpp"

#include <cassert>

namespace unicity {
namespace network {

// ============================================================================
// RealTransportConnection
// ============================================================================

std::atomic<uint64_t> RealTransportConnection::next_id_{1};

std::atomic<std::chrono::milliseconds> RealTransportConnection::connect_timeout_override_ms_{
    std::chrono::milliseconds{0}};
std::atomic<size_t> RealTransportConnection::send_queue_limit_override_bytes_{0};

TransportConnectionPtr RealTransportConnection::create_outbound(
    asio::io_context& io_context,
    const std::string& address,
    uint16_t port,
    ConnectCallback callback)
{
  auto conn = std::shared_ptr<RealTransportConnection>(new RealTransportConnection(io_context, false));
  // Defer do_connect onto the strand so shared_from_this() is safe and the
  // object lifetime is extended regardless of factory return-value usage.
  asio::post(conn->strand_, [conn, address, port, callback]() mutable {
    conn->do_connect(address, port, std::move(callback));
  });
  return conn;
}

TransportConnectionPtr RealTransportConnection::create_inbound(
    asio::io_context& io_context,
    asio::ip::tcp::socket socket)
{
  auto conn = std::shared_ptr<RealTransportConnection>(new RealTransportConnection(io_context, true));
  conn->socket_ = std::move(socket);
  conn->open_ = true;

  // Get remote endpoint
  try {
    auto remote_ep = conn->socket_.remote_endpoint();
    conn->remote_addr_ = remote_ep.address().to_string();
    conn->remote_port_ = remote_ep.port();
  } catch (const std::exception& e) {
    LOG_NET_TRACE("failed to get remote endpoint: {}", e.what());
  }

  return conn;
}

RealTransportConnection::RealTransportConnection(asio::io_context& io_context, bool is_inbound)
    : io_context_(io_context)
    , socket_(io_context)
    , strand_(io_context.get_executor())
    , is_inbound_(is_inbound)
    , id_(next_id_++)
    , connect_timer_(std::make_unique<asio::steady_timer>(io_context))
{
}

RealTransportConnection::~RealTransportConnection() {}

void RealTransportConnection::do_connect(const std::string& address, uint16_t port, ConnectCallback callback) {
  remote_addr_ = address;
  remote_port_ = port;
  connect_done_ = false;

  // Start connect timeout timer
  auto timeout = connect_timeout_ms();
  if (timeout.count() > 0 && connect_timer_) {
    connect_timer_->expires_after(timeout);

    auto timeout_handler = [this, self = shared_from_this(), callback](const asio::error_code& ec) mutable {
      if (ec == asio::error::operation_aborted || connect_done_) {
        return;
      }
      LOG_NET_DEBUG("connect timeout to {}:{}", remote_addr_, remote_port_);
      connect_done_ = true;
      asio::error_code ignored;
      if (resolver_)
        resolver_->cancel();
      socket_.cancel(ignored);
      socket_.close(ignored);
      if (callback) {
        try {
          callback(false);
        } catch (...) {
        }
      }
    };

    connect_timer_->async_wait(asio::bind_executor(strand_, timeout_handler));
  }

  // Resolve address (store resolver_ to allow cancellation)
  resolver_ = std::make_shared<asio::ip::tcp::resolver>(io_context_);

  auto resolve_handler = [this, self = shared_from_this(), callback](
      const asio::error_code& ec, asio::ip::tcp::resolver::results_type results) mutable {
    if (connect_done_)
      return;

    if (ec) {
      LOG_NET_TRACE("failed to resolve {}: {}", remote_addr_, ec.message());
      connect_done_ = true;
      if (connect_timer_)
        (void)connect_timer_->cancel();
      if (callback) {
        try {
          callback(false);
        } catch (...) {
        }
      }
      return;
    }

    auto connect_handler = [this, self, callback](const asio::error_code& ec, const asio::ip::tcp::endpoint&) {
      if (connect_done_)
        return;

      if (ec) {
        LOG_NET_TRACE("failed to connect to {}:{}: {}", remote_addr_, remote_port_, ec.message());
        connect_done_ = true;
        if (connect_timer_)
          (void)connect_timer_->cancel();
        if (callback) {
          try {
            callback(false);
          } catch (...) {
          }
        }
        return;
      }

      open_ = true;

      // Set useful TCP options (best-effort)
      try {
        asio::error_code opt_ec;
        socket_.set_option(asio::ip::tcp::no_delay(true), opt_ec);
        socket_.set_option(asio::socket_base::keep_alive(true), opt_ec);
      } catch (...) {
      }

      // Canonicalize remote address/port from the actual socket endpoint
      try {
        auto ep = socket_.remote_endpoint();
        remote_addr_ = ep.address().to_string();
        remote_port_ = ep.port();
      } catch (const std::exception& e) {
        LOG_NET_TRACE("failed to get remote endpoint after connect: {}", e.what());
      } catch (...) {
        LOG_NET_TRACE("unknown exception getting remote endpoint after connect");
      }

      connect_done_ = true;
      if (connect_timer_)
        (void)connect_timer_->cancel();
      if (callback) {
        try {
          callback(true);
        } catch (...) {
        }
      }
    };

    asio::async_connect(socket_, results, asio::bind_executor(strand_, connect_handler));
  };

  resolver_->async_resolve(address, std::to_string(port), asio::bind_executor(strand_, resolve_handler));
}

void RealTransportConnection::start() {
  asio::dispatch(strand_, [self = shared_from_this()]() {
    if (!self->open_)
      return;
    self->start_read_impl();
  });
}

void RealTransportConnection::start_read_impl() {
  if (!open_)
    return;

  assert(strand_.running_in_this_thread());

  // Allocate a fresh buffer per read to avoid any possibility of scribbling on a
  // shared member buffer if future refactors accidentally post two reads.
  auto buf = std::make_shared<std::vector<uint8_t>>(RECV_BUFFER_SIZE);

  auto read_handler = [this, self = shared_from_this(), buf](const asio::error_code& ec, size_t bytes_transferred) {
    // Early exit if connection has been closed meanwhile. Do not reschedule.
    if (!open_) {
      deliver_disconnect_once();
      close_impl();
      return;
    }

    if (ec) {
      if (ec != asio::error::eof && ec != asio::error::operation_aborted) {
        LOG_NET_TRACE("read error from {}:{}: {}", remote_addr_, remote_port_, ec.message());
      }
      deliver_disconnect_once();
      close_impl();
      return;
    }

    if (bytes_transferred > 0) {
      ReceiveCallback saved_receive_cb = receive_callback_;
      if (saved_receive_cb) {
        std::vector<uint8_t> data(buf->begin(), buf->begin() + bytes_transferred);
        try {
          saved_receive_cb(data);
        } catch (const std::exception& e) {
          LOG_NET_TRACE("exception in receive callback from {}:{}: {}", remote_addr_, remote_port_, e.what());
        } catch (...) {
          LOG_NET_TRACE("unknown exception in receive callback from {}:{}", remote_addr_, remote_port_);
        }
      }

      // If the receive callback closed the connection, do not reschedule
      if (!open_) {
        return;
      }
    }

    // Continue reading
    start_read_impl();
  };

  socket_.async_read_some(asio::buffer(*buf), asio::bind_executor(strand_, read_handler));
}

// NOTE on semantics:
// - This method returns false only if the connection is already closed at
//   call time.
// - Queue overflow is enforced on the strand; if the send queue limit would
//   be exceeded, the connection is closed and the disconnect callback is
//   delivered. In that case, a prior `true` return value simply indicated an
//   accepted send attempt, not a guarantee of enqueue or write.
// - Higher layers (Peer) must treat `true` as fire-and-forget and rely on the
//   disconnect callback for final failure in overflow scenarios.
bool RealTransportConnection::send(const std::vector<uint8_t>& data) {
  if (!open_)
    return false;  // fast path
  // CRITICAL: Copy data BEFORE posting to strand to avoid race where caller
  // destroys the buffer immediately after send() returns but before the lambda
  // executes on the strand. The copy at (data.begin(), data.end()) would read
  // from freed memory.
  auto payload = std::make_shared<std::vector<uint8_t>>(data.begin(), data.end());
  asio::dispatch(strand_, [this, self = shared_from_this(), payload]() {
    if (!open_)
      return;

    // DoS Protection: Enforce send queue size limit (prevent slow-reading peer from exhausting memory)
    size_t limit = send_queue_limit_override_bytes_.load(std::memory_order_relaxed);
    if (limit == 0)
      limit = protocol::DEFAULT_SEND_QUEUE_SIZE;
    if (send_queue_bytes_ + payload->size() > limit) {
      LOG_NET_WARN_RL("Send queue overflow (current: {} bytes, incoming: {} bytes, limit: {} bytes), disconnecting "
                      "slow-reading peer {}:{}",
                      send_queue_bytes_, payload->size(), limit, remote_addr_, remote_port_);
      // IMPORTANT: Don't set open_=false here; let close_impl() do the exchange.
      // If we set it to false before calling close_impl(), the exchange(false) at
      // line 375 will see it's already false and early-return without cleanup.
      deliver_disconnect_once();
      close_impl();
      return;
    }

    send_queue_.push(payload);
    send_queue_bytes_ += payload->size();

    if (!writing_.exchange(true, std::memory_order_acquire)) {
      // We just transitioned from false to true, so we should initiate write.
      // We are already on the strand; avoid extra post to reduce wakeups.
      do_write_impl();
    }
  });
  return true;
}

void RealTransportConnection::do_write_impl() {
  if (!open_)
    return;

  assert(strand_.running_in_this_thread());

  if (send_queue_.empty()) {
    writing_.store(false, std::memory_order_release);
    return;
  }

  auto data_ptr = send_queue_.front();

  auto write_handler = [this, self = shared_from_this(), data_ptr](
      const asio::error_code& ec, size_t /*bytes_transferred*/) {
    if (!open_) {
      return;
    }

    if (ec) {
      LOG_NET_TRACE("write error to {}:{}: {}", remote_addr_, remote_port_, ec.message());
      deliver_disconnect_once();
      close_impl();
      return;
    }

    size_t sent_bytes = data_ptr->size();
    send_queue_.pop();
    send_queue_bytes_ -= sent_bytes;

    if (!send_queue_.empty()) {
      do_write_impl();
    } else {
      writing_.store(false, std::memory_order_release);
    }
  };

  asio::async_write(socket_, asio::buffer(*data_ptr), asio::bind_executor(strand_, write_handler));
}

void RealTransportConnection::deliver_disconnect_once() {
  assert(strand_.running_in_this_thread());

  if (disconnect_delivered_) {
    return;  // Already delivered
  }
  disconnect_delivered_ = true;

  // Move callback to local to clear member before invoking
  DisconnectCallback saved_disconnect_cb = std::move(disconnect_callback_);
  if (saved_disconnect_cb) {
    // Post to io_context (not strand) to avoid re-entering strand
    asio::post(io_context_, [cb = std::move(saved_disconnect_cb)]() {
      try {
        cb();
      } catch (...) { /* swallow */
      }
    });
  }
}

void RealTransportConnection::close() {
  asio::dispatch(strand_, [this, self = shared_from_this()]() { close_impl(); });
}

void RealTransportConnection::close_impl() {
  assert(strand_.running_in_this_thread());

  if (!open_.exchange(false)) {
    return;  // Already closed
  }

  // CRITICAL: Move callbacks to locals BEFORE canceling socket to prevent lost events.
  // If we clear callbacks first, then cancel the socket, any final events (EOF, etc.)
  // delivered between clearing and canceling would be lost because receive_callback_
  // would already be empty. By moving to locals first, we preserve the callbacks
  // until after cancellation.
  //
  // NOTE: disconnect_callback_ may already be empty if deliver_disconnect_once() was
  // called from an error path before close_impl().
  // cppcheck-suppress unreadVariable ; RAII lifetime extension - kept alive until scope exit
  ReceiveCallback saved_receive_cb = std::move(receive_callback_);
  // cppcheck-suppress unreadVariable ; RAII lifetime extension - kept alive until scope exit
  DisconnectCallback saved_disconnect_cb = std::move(disconnect_callback_);

  // CRITICAL: Cancel outstanding I/O operations before destroying member state.
  // Any lambda captured with [self = shared_from_this()] will keep the object alive
  // until the completion handler runs. If we destroy member state (e.g., callbacks,
  // send_queue_) while those handlers are queued in io_context, they'll access
  // destroyed memory when they eventually run.
  //
  // Solution: Move socket to a local variable and cancel it. This forces all
  // pending async operations (async_read_some, async_write, async_connect, etc.)
  // to complete with operation_aborted. The completion handlers will then run
  // with ec == operation_aborted, exit early, and the last shared_ptr (inside
  // the handler lambda) will be released safely.
  {
    asio::ip::tcp::socket socket_to_cancel(std::move(socket_));
    asio::error_code cancel_ec;
    socket_to_cancel.cancel(cancel_ec);
    // socket_to_cancel is destroyed here (in valid-but-unspecified state)
  }
  // socket_ is now in moved-from state; avoid further operations on it

  // Clear the member callbacks (they were already moved to locals above)
  receive_callback_ = {};
  disconnect_callback_ = {};

  // saved_receive_cb and saved_disconnect_cb go out of scope here, which is safe
  // because we've already canceled all I/O operations above.

  // CRITICAL: Move the timer to a local variable so its destructor runs here,
  // not in the RealTransportConnection destructor. If the destructor runs on the
  // io_context thread (common during shutdown), the timer destructor may try to
  // access scheduler state that has already been destroyed → segfault inside boost.
  // By moving it to a local variable, its destruction is delayed until after
  // io_context.stop() is called.
  {
    auto timer_to_destroy = std::move(connect_timer_);
    if (timer_to_destroy) {
      (void)timer_to_destroy->cancel();
      // timer_to_destroy destroyed here, but io_context is still running
      // so the boost internals are still valid
    }
  }
  // connect_timer_ is now nullptr; safe to destroy later

  // Release resolver to break potential cycles and allow cancellation
  resolver_.reset();

  // CRITICAL: Move send queue to a local variable and destroy it OUTSIDE the strand.
  // If the queue contains huge vectors, their destructors could block the strand
  // for an unbounded time. By posting the queue to io_context (not strand), we
  // allow the strand to continue servicing other connections while the queue is
  // destroyed in the background.
  std::queue<std::shared_ptr<std::vector<uint8_t>>> queue_to_destroy;
  std::swap(send_queue_, queue_to_destroy);
  send_queue_bytes_ = 0;
  writing_.store(false, std::memory_order_release);

  // Post queue destruction to io_context (not strand) to avoid blocking strand
  if (!queue_to_destroy.empty()) {
    asio::post(io_context_, [queue = std::move(queue_to_destroy)]() mutable {
      // queue destroyed here, outside the strand
      (void)queue;  // Explicit no-op; just let it go out of scope
    });
  }
}

bool RealTransportConnection::is_open() const {
  return open_;
}

std::chrono::milliseconds RealTransportConnection::connect_timeout_ms() const {
  auto ms = connect_timeout_override_ms_.load(std::memory_order_relaxed);
  if (ms.count() > 0)
    return ms;
  return DEFAULT_CONNECT_TIMEOUT;
}

std::string RealTransportConnection::remote_address() const {
  return remote_addr_;
}

uint16_t RealTransportConnection::remote_port() const {
  return remote_port_;
}

void RealTransportConnection::set_receive_callback(ReceiveCallback callback) {
  asio::dispatch(strand_, [this, self = shared_from_this(), cb = std::move(callback)]() mutable {
    receive_callback_ = std::move(cb);
  });
}

void RealTransportConnection::set_disconnect_callback(DisconnectCallback callback) {
  asio::dispatch(strand_, [this, self = shared_from_this(), cb = std::move(callback)]() mutable {
    disconnect_callback_ = std::move(cb);
  });
}

// ============================================================================
// RealTransport
// ============================================================================

RealTransport::RealTransport(asio::io_context& io_context) : io_context_(io_context) {}

RealTransport::~RealTransport() {
  stop();
}

TransportConnectionPtr RealTransport::connect(const std::string& address, uint16_t port, ConnectCallback callback) {
  return RealTransportConnection::create_outbound(io_context_, address, port, callback);
}

bool RealTransport::listen(uint16_t port, std::function<void(TransportConnectionPtr)> accept_callback) {
  if (acceptor_) {
    LOG_NET_TRACE("already listening");
    return false;
  }

  accept_callback_ = accept_callback;

  try {
    using tcp = asio::ip::tcp;
    acceptor_ = std::make_unique<tcp::acceptor>(io_context_);

    // Try dual-stack (IPv6 with v6_only=false); fall back to IPv4-only on failure
    try {
      acceptor_->open(tcp::v6());
      acceptor_->set_option(asio::ip::v6_only(false));
      acceptor_->set_option(tcp::acceptor::reuse_address(true));
      acceptor_->bind(tcp::endpoint(tcp::v6(), port));
      acceptor_->listen(asio::socket_base::max_listen_connections);
    } catch (const std::exception&) {
      asio::error_code ec;
      acceptor_->close(ec);
      acceptor_->open(tcp::v4());
      acceptor_->set_option(tcp::acceptor::reuse_address(true));
      acceptor_->bind(tcp::endpoint(tcp::v4(), port));
      acceptor_->listen(asio::socket_base::max_listen_connections);
    }

    // Record the actual bound port (handles ephemeral port 0)
    {
      asio::error_code ec;
      auto ep = acceptor_->local_endpoint(ec);
      last_listen_port_ = ec ? 0 : ep.port();
    }

    LOG_NET_INFO("listening on port {}", last_listen_port_ ? last_listen_port_ : port);
    start_accept();
    return true;

  } catch (const std::exception& e) {
    LOG_NET_ERROR("failed to listen on port {}: {}", port, e.what());
    // Ensure a failed attempt does not leave a half-initialized acceptor_
    if (acceptor_) {
      asio::error_code ec;
      acceptor_->close(ec);
      acceptor_.reset();
    }
    return false;
  }
}

void RealTransport::start_accept() {
  if (!acceptor_)
    return;

  // Do not use shared_from_this() here; RealTransport can be stack-allocated in tests.
  // We rely on stop_listening()/stop() to cancel pending accepts before destruction.
  acceptor_->async_accept(
      [this](const asio::error_code& ec, asio::ip::tcp::socket socket) { handle_accept(ec, std::move(socket)); });
}

void RealTransport::handle_accept(const asio::error_code& ec, asio::ip::tcp::socket socket) {
  if (ec) {
    if (ec != asio::error::operation_aborted) {
      LOG_NET_TRACE("accept error: {}", ec.message());
      // Continue accepting despite error
      start_accept();
    }
    return;
  }

  // Set useful TCP options on the accepted socket (best-effort)
  // NOTE: Wrap in try-catch because older boost versions may throw instead
  // of using error_code overload.
  try {
    asio::error_code opt_ec;
    socket.set_option(asio::ip::tcp::no_delay(true), opt_ec);
    socket.set_option(asio::socket_base::keep_alive(true), opt_ec);
  } catch (...) {
    // Ignore errors setting socket options; they're best-effort
  }

  // Get remote address for logging (before moving socket)
  std::string remote_addr;
  try {
    auto remote_ep = socket.remote_endpoint();
    remote_addr = remote_ep.address().to_string() + ":" + std::to_string(remote_ep.port());
  } catch (...) {
    remote_addr = "unknown";
  }

  LOG_NET_DEBUG("connection from {} accepted", remote_addr);

  // Create inbound connection
  auto conn = RealTransportConnection::create_inbound(io_context_, std::move(socket));

  // Notify callback (wrap in try-catch to ensure accept loop continues)
  if (accept_callback_) {
    try {
      accept_callback_(conn);
    } catch (const std::exception& e) {
      LOG_NET_TRACE("exception in accept callback: {}", e.what());
    } catch (...) {
      LOG_NET_TRACE("unknown exception in accept callback");
    }
  }

  // Continue accepting
  start_accept();
}

void RealTransport::stop_listening() {
  if (acceptor_) {
    asio::error_code ec;
    acceptor_->close(ec);
    acceptor_.reset();
  }
  last_listen_port_ = 0;

  // IMPORTANT: Clear the accept callback to break reference cycles.
  // The callback may contain bound shared_ptrs to user objects or lambdas
  // that capture "this" or other references. If the user destroys the transport
  // before explicitly calling stop_listening(), these captured references would
  // stay alive and potentially prevent application shutdown.
  // By clearing the callback, we release any captured references.
  accept_callback_ = {};
}

uint16_t RealTransport::listening_port() const {
  return last_listen_port_;
}

void RealTransport::stop() {
  running_.store(false);
  stop_listening();
}

}  // namespace network
}  // namespace unicity
