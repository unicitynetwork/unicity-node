// Copyright (c) 2025 The Unicity Foundation
// DoS: Timeout enforcement tests using RealTransport + Peer
//
// These tests verify timeout-based DoS defenses work with the full stack:
// - Handshake timeout (60s default, shortened for tests)
// - Inactivity timeout (1200s default, shortened for tests)
// - Ping timeout (1200s default)
//
// Uses real TCP sockets via RealTransport + actual Peer objects.

#include "catch_amalgamated.hpp"
#include "network/real_transport.hpp"
#include "network/peer.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"
#include "util/hash.hpp"
#include "chain/chainparams.hpp"
#include "infra/test_access.hpp"

#include <asio/executor_work_guard.hpp>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <chrono>

using namespace unicity;
using namespace unicity::network;
using unicity::test::PeerTestAccess;

namespace {

static struct TestSetup {
    TestSetup() { chain::GlobalChainParams::Select(chain::ChainType::REGTEST); }
} test_setup_timeout_dos;

// RAII guard for timeout overrides
struct TimeoutGuard {
    TimeoutGuard(std::chrono::milliseconds hs, std::chrono::milliseconds idle) {
        PeerTestAccess::SetTimeouts(hs, idle);
    }
    ~TimeoutGuard() { PeerTestAccess::ResetTimeouts(); }
};

class TestIoContext {
public:
    TestIoContext()
        : io_context_(),
          work_guard_(asio::make_work_guard(io_context_)),
          thread_([this]() { io_context_.run(); }) {}

    ~TestIoContext() {
        work_guard_.reset();
        io_context_.stop();
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    asio::io_context& get() { return io_context_; }

private:
    asio::io_context io_context_;
    asio::executor_work_guard<asio::io_context::executor_type> work_guard_;
    std::thread thread_;
};

static uint16_t pick_listen_port(RealTransport& t,
                                 std::function<void(TransportConnectionPtr)> accept_cb,
                                 uint16_t start = 44000,
                                 uint16_t end = 44100) {
    for (uint16_t p = start; p < end; ++p) {
        if (t.listen(p, accept_cb)) return p;
    }
    if (t.listen(0, accept_cb)) {
        return t.listening_port();
    }
    return 0;
}

std::vector<uint8_t> build_raw_message(const std::string& command,
                                        const std::vector<uint8_t>& payload) {
    protocol::MessageHeader header(protocol::magic::REGTEST, command,
                                   static_cast<uint32_t>(payload.size()));
    uint256 hash = Hash(payload);
    std::memcpy(header.checksum.data(), hash.begin(), 4);
    auto header_bytes = message::serialize_header(header);

    std::vector<uint8_t> full;
    full.reserve(header_bytes.size() + payload.size());
    full.insert(full.end(), header_bytes.begin(), header_bytes.end());
    full.insert(full.end(), payload.begin(), payload.end());
    return full;
}

} // anonymous namespace

// =============================================================================
// HANDSHAKE TIMEOUT TESTS
// =============================================================================

TEST_CASE("DoS: Handshake timeout - peer disconnects if no VERSION/VERACK", "[dos][network][timeout][handshake]") {
    // Short timeout for test (100ms)
    TimeoutGuard guard(std::chrono::milliseconds(100), std::chrono::milliseconds(0));

    TestIoContext io;
    RealTransport transport(io.get());

    std::mutex m;
    std::condition_variable cv;
    std::atomic<bool> peer_created{false};
    std::atomic<bool> peer_disconnected{false};
    PeerPtr victim_peer;

    auto accept_cb = [&](TransportConnectionPtr conn) {
        // Create a Peer that expects handshake
        victim_peer = Peer::create_inbound(io.get(), conn, protocol::magic::REGTEST, 1);
        victim_peer->start();
        peer_created = true;
        cv.notify_all();
    };

    uint16_t port = pick_listen_port(transport, accept_cb);
    if (port == 0) {
        WARN("Skipping: unable to bind listening port");
        return;
    }

    // Connect but don't send VERSION
    RealTransport attacker_transport(io.get());
    auto attacker_conn = attacker_transport.connect("127.0.0.1", port, [](bool) {});
    REQUIRE(attacker_conn);

    // Wait for peer to be created
    {
        std::unique_lock<std::mutex> lk(m);
        cv.wait_for(lk, std::chrono::seconds(2), [&] { return peer_created.load(); });
    }
    REQUIRE(peer_created);

    // Sleep past handshake timeout
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Peer should have disconnected due to handshake timeout
    CHECK(victim_peer->state() == PeerConnectionState::DISCONNECTED);

    attacker_conn->close();
    transport.stop();
    attacker_transport.stop();
}

TEST_CASE("DoS: Handshake timeout - successful handshake prevents disconnect", "[dos][network][timeout][handshake]") {
    TimeoutGuard guard(std::chrono::milliseconds(500), std::chrono::milliseconds(0));

    TestIoContext io;
    RealTransport transport(io.get());

    std::mutex m;
    std::condition_variable cv;
    std::atomic<bool> peer_created{false};
    PeerPtr victim_peer;

    auto accept_cb = [&](TransportConnectionPtr conn) {
        victim_peer = Peer::create_inbound(io.get(), conn, protocol::magic::REGTEST, 1);
        victim_peer->start();
        peer_created = true;
        cv.notify_all();
    };

    uint16_t port = pick_listen_port(transport, accept_cb);
    if (port == 0) {
        WARN("Skipping: unable to bind listening port");
        return;
    }

    RealTransport attacker_transport(io.get());
    std::atomic<bool> connected{false};
    auto attacker_conn = attacker_transport.connect("127.0.0.1", port, [&](bool ok) {
        connected = ok;
        cv.notify_all();
    });
    REQUIRE(attacker_conn);

    {
        std::unique_lock<std::mutex> lk(m);
        cv.wait_for(lk, std::chrono::seconds(2), [&] { return peer_created && connected; });
    }
    REQUIRE(peer_created);
    REQUIRE(connected);

    // Send VERSION message
    message::VersionMessage ver;
    ver.version = protocol::PROTOCOL_VERSION;
    ver.services = protocol::NODE_NETWORK;
    ver.timestamp = 12345;
    ver.nonce = 67890;
    ver.user_agent = "/test/";
    ver.start_height = 0;
    auto ver_msg = build_raw_message(protocol::commands::VERSION, ver.serialize());
    (void)attacker_conn->send(ver_msg);

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Send VERACK
    auto verack_msg = build_raw_message(protocol::commands::VERACK, {});
    (void)attacker_conn->send(verack_msg);

    // Sleep past what would be timeout
    std::this_thread::sleep_for(std::chrono::milliseconds(600));

    // Peer should still be connected (handshake completed)
    // Note: May be READY or still connecting depending on timing
    CHECK(victim_peer->state() != PeerConnectionState::DISCONNECTED);

    attacker_conn->close();
    transport.stop();
    attacker_transport.stop();
}

// =============================================================================
// INACTIVITY TIMEOUT TESTS
// =============================================================================

TEST_CASE("DoS: Inactivity timeout - peer disconnects after idle", "[dos][network][timeout][inactivity]") {
    // Short inactivity timeout for test (150ms)
    TimeoutGuard guard(std::chrono::milliseconds(0), std::chrono::milliseconds(150));

    TestIoContext io;
    RealTransport transport(io.get());

    std::mutex m;
    std::condition_variable cv;
    std::atomic<bool> peer_created{false};
    PeerPtr victim_peer;

    auto accept_cb = [&](TransportConnectionPtr conn) {
        victim_peer = Peer::create_inbound(io.get(), conn, protocol::magic::REGTEST, 1);
        victim_peer->start();
        peer_created = true;
        cv.notify_all();
    };

    uint16_t port = pick_listen_port(transport, accept_cb);
    if (port == 0) {
        WARN("Skipping: unable to bind listening port");
        return;
    }

    RealTransport attacker_transport(io.get());
    std::atomic<bool> connected{false};
    auto attacker_conn = attacker_transport.connect("127.0.0.1", port, [&](bool ok) {
        connected = ok;
        cv.notify_all();
    });
    REQUIRE(attacker_conn);

    {
        std::unique_lock<std::mutex> lk(m);
        cv.wait_for(lk, std::chrono::seconds(2), [&] { return peer_created && connected; });
    }
    REQUIRE(peer_created);
    REQUIRE(connected);

    // Complete handshake
    message::VersionMessage ver;
    ver.version = protocol::PROTOCOL_VERSION;
    ver.services = protocol::NODE_NETWORK;
    ver.timestamp = 12345;
    ver.nonce = 67890;
    ver.user_agent = "/test/";
    ver.start_height = 0;
    (void)attacker_conn->send(build_raw_message(protocol::commands::VERSION, ver.serialize()));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    (void)attacker_conn->send(build_raw_message(protocol::commands::VERACK, {}));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Now go idle - no more messages
    std::this_thread::sleep_for(std::chrono::milliseconds(400));

    // Peer should have disconnected due to inactivity
    CHECK(victim_peer->state() == PeerConnectionState::DISCONNECTED);

    attacker_conn->close();
    transport.stop();
    attacker_transport.stop();
}

TEST_CASE("DoS: Inactivity timeout - activity prevents disconnect", "[dos][network][timeout][inactivity]") {
    TimeoutGuard guard(std::chrono::milliseconds(0), std::chrono::milliseconds(300));

    TestIoContext io;
    RealTransport transport(io.get());

    std::mutex m;
    std::condition_variable cv;
    std::atomic<bool> peer_created{false};
    PeerPtr victim_peer;

    auto accept_cb = [&](TransportConnectionPtr conn) {
        victim_peer = Peer::create_inbound(io.get(), conn, protocol::magic::REGTEST, 1);
        victim_peer->start();
        peer_created = true;
        cv.notify_all();
    };

    uint16_t port = pick_listen_port(transport, accept_cb);
    if (port == 0) {
        WARN("Skipping: unable to bind listening port");
        return;
    }

    RealTransport attacker_transport(io.get());
    std::atomic<bool> connected{false};
    auto attacker_conn = attacker_transport.connect("127.0.0.1", port, [&](bool ok) {
        connected = ok;
        cv.notify_all();
    });
    REQUIRE(attacker_conn);

    {
        std::unique_lock<std::mutex> lk(m);
        cv.wait_for(lk, std::chrono::seconds(2), [&] { return peer_created && connected; });
    }
    REQUIRE(peer_created);
    REQUIRE(connected);

    // Complete handshake
    message::VersionMessage ver;
    ver.version = protocol::PROTOCOL_VERSION;
    ver.services = protocol::NODE_NETWORK;
    ver.timestamp = 12345;
    ver.nonce = 67890;
    ver.user_agent = "/test/";
    ver.start_height = 0;
    (void)attacker_conn->send(build_raw_message(protocol::commands::VERSION, ver.serialize()));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    (void)attacker_conn->send(build_raw_message(protocol::commands::VERACK, {}));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Keep activity: send PINGs periodically
    for (int i = 0; i < 5; ++i) {
        message::PingMessage ping(static_cast<uint64_t>(i));
        (void)attacker_conn->send(build_raw_message(protocol::commands::PING, ping.serialize()));
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // Sleep a bit less than timeout
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Peer should still be connected (activity resets timer)
    CHECK(victim_peer->is_connected());

    attacker_conn->close();
    transport.stop();
    attacker_transport.stop();
}

// Note: Unknown command rate limit test moved to unknown_command_rate_limit_tests.cpp
// to consolidate all unknown command tests in one file.
