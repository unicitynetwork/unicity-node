// Peer regression tests - Bug fix validation (ported to test2)

#include "catch_amalgamated.hpp"
#include "network/peer.hpp"
#include "network/transport.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"
#include "util/hash.hpp"
#include "infra/mock_transport.hpp"
#include <asio.hpp>
#include <memory>
#include <vector>
#include <mutex>
#include <thread>
#include <chrono>
#include <atomic>

using namespace unicity;
using namespace unicity::network;

// =============================================================================
// HELPERS
// =============================================================================

static std::vector<uint8_t> create_test_message(
    uint32_t magic,
    const std::string& command,
    const std::vector<uint8_t>& payload)
{
    protocol::MessageHeader header(magic, command, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(header.checksum.data(), hash.begin(), 4);
    auto header_bytes = message::serialize_header(header);

    std::vector<uint8_t> full_message;
    full_message.insert(full_message.end(), header_bytes.begin(), header_bytes.end());
    full_message.insert(full_message.end(), payload.begin(), payload.end());
    return full_message;
}

static std::vector<uint8_t> create_version_message(uint32_t magic, uint64_t nonce, int32_t version = protocol::PROTOCOL_VERSION) {
    message::VersionMessage msg;
    msg.version = version;
    msg.services = protocol::NODE_NETWORK;
    msg.timestamp = 1234567890;
    msg.nonce = nonce;
    msg.user_agent = "/Test:1.0.0/";
    msg.start_height = 0;
    auto payload = msg.serialize();
    return create_test_message(magic, protocol::commands::VERSION, payload);
}

static std::vector<uint8_t> create_verack_message(uint32_t magic) {
    message::VerackMessage msg;
    auto payload = msg.serialize();
    return create_test_message(magic, protocol::commands::VERACK, payload);
}

static std::vector<uint8_t> create_ping_message(uint32_t magic, uint64_t nonce) {
    message::PingMessage msg(nonce);
    auto payload = msg.serialize();
    return create_test_message(magic, protocol::commands::PING, payload);
}

// =============================================================================
// DISCONNECT REGRESSION TESTS
// =============================================================================

TEST_CASE("Peer - DisconnectRaceCondition", "[peer][disconnect][regression]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    auto version_msg = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version_msg);
    io_context.poll();

    auto verack_msg = create_verack_message(magic);
    mock_conn->simulate_receive(verack_msg);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::READY);

    peer->disconnect();
    io_context.poll();

    CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    CHECK_FALSE(peer->is_connected());

    peer->disconnect();
    peer->disconnect();
    CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
}

// =============================================================================
// STATISTICS REGRESSION TESTS
// =============================================================================

TEST_CASE("Peer - StatsInitialization", "[peer][stats][regression]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);

    peer->start();
    io_context.poll();

    const auto& stats = peer->stats();

    // Load atomic durations
    auto connected_time = stats.connected_time.load(std::memory_order_relaxed);
    CHECK(connected_time.count() > 0);

    auto last_send = stats.last_send.load(std::memory_order_relaxed);
    auto last_recv = stats.last_recv.load(std::memory_order_relaxed);
    CHECK(last_send >= connected_time);
    CHECK(last_recv >= connected_time);

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch());
    auto idle_time = now - last_recv;

    CHECK(idle_time.count() < 1);
}

TEST_CASE("Peer - MessageCounters", "[peer][stats][regression]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    auto version_msg = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version_msg);
    io_context.poll();

    auto verack_msg = create_verack_message(magic);
    mock_conn->simulate_receive(verack_msg);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::READY);

    const auto& stats = peer->stats();

    // Load atomic values before sending messages
    uint64_t msgs_recv_before = stats.messages_received.load(std::memory_order_relaxed);
    uint64_t msgs_sent_before = stats.messages_sent.load(std::memory_order_relaxed);
    uint64_t bytes_recv_before = stats.bytes_received.load(std::memory_order_relaxed);
    uint64_t bytes_sent_before = stats.bytes_sent.load(std::memory_order_relaxed);

    for (int i = 0; i < 5; i++) {
        auto ping = create_ping_message(magic, 2000 + i);
        mock_conn->simulate_receive(ping);
        io_context.poll();
    }

    // Load atomic values after sending messages
    uint64_t msgs_recv_after = stats.messages_received.load(std::memory_order_relaxed);
    uint64_t msgs_sent_after = stats.messages_sent.load(std::memory_order_relaxed);
    uint64_t bytes_recv_after = stats.bytes_received.load(std::memory_order_relaxed);
    uint64_t bytes_sent_after = stats.bytes_sent.load(std::memory_order_relaxed);

    CHECK(msgs_recv_after > msgs_recv_before);
    CHECK(msgs_sent_after > msgs_sent_before);
    CHECK(bytes_recv_after > bytes_recv_before);
    CHECK(bytes_sent_after > bytes_sent_before);
}

// =============================================================================
// THREADING REGRESSION TESTS
// =============================================================================

TEST_CASE("Peer - StateThreadSafety", "[peer][threading][regression]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    std::atomic<bool> stop{false};
    std::atomic<int> read_count{0};
    std::vector<std::thread> readers;

    for (int i = 0; i < 4; i++) {
        readers.emplace_back([&]() {
            while (!stop) {
                auto state = peer->state();
                (void)state;
                read_count++;
                std::this_thread::yield();
            }
        });
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    peer->disconnect();
    io_context.poll();

    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    stop = true;

    for (auto& t : readers) {
        t.join();
    }

    CHECK(read_count > 0);
    CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
}

// =============================================================================
// PROTOCOL REGRESSION TESTS
// =============================================================================

TEST_CASE("Peer - FeelerConnectionLifecycle", "[peer][feeler][regression]") {
    // Feelers disconnect immediately after receiving VERSION (Bitcoin Core parity)
    // The address is proven reachable as soon as we get a valid VERSION response.
    // No VERACK is needed or sent.
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0,
                                      "127.0.0.1", 9590, ConnectionType::FEELER);

    CHECK(peer->is_feeler());
    CHECK_FALSE(peer->successfully_connected());

    peer->start();
    io_context.poll();

    // Receive VERSION - feeler should disconnect immediately (Core parity)
    auto version_msg = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version_msg);
    io_context.poll();

    // Feeler disconnects after VERSION, not after VERACK
    CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    CHECK_FALSE(peer->is_connected());
    // Feelers do NOT set successfully_connected (that's for full handshake/VERACK)
    // Feeler success is determined by version() > 0 (received VERSION)
    CHECK_FALSE(peer->successfully_connected());
    CHECK(peer->version() > 0);
}

TEST_CASE("Peer - ObsoleteProtocolVersion", "[peer][security][regression]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    auto version_msg = create_version_message(magic, 54321, 0);
    mock_conn->simulate_receive(version_msg);
    io_context.poll();

    CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    CHECK(peer->version() == 0);
}

TEST_CASE("Peer - ReceiveBufferOptimization", "[peer][performance][regression]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    auto version_msg = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version_msg);
    io_context.poll();

    auto verack_msg = create_verack_message(magic);
    mock_conn->simulate_receive(verack_msg);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::READY);

    for (int i = 0; i < 10; i++) {
        auto ping = create_ping_message(magic, 1000 + i);
        mock_conn->simulate_receive(ping);
        io_context.poll();
    }

    CHECK(peer->is_connected());
    CHECK(peer->stats().messages_received >= 12);
}