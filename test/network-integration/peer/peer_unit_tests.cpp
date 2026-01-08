// Peer unit tests for network/peer.cpp (ported to test2)

#include "catch_amalgamated.hpp"
#include "network/peer.hpp"
#include "network/transport.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"
#include "util/hash.hpp"
#include <asio.hpp>
#include <memory>
#include <vector>
#include <deque>
#include <mutex>
#include <thread>

using namespace unicity;
using namespace unicity::network;

// =============================================================================
// MOCK TRANSPORT
// =============================================================================

#include "infra/mock_transport.hpp"

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

static std::vector<uint8_t> create_version_message(uint32_t magic, uint64_t nonce) {
    message::VersionMessage msg;
    msg.version = protocol::PROTOCOL_VERSION;
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

static std::vector<uint8_t> create_pong_message(uint32_t magic, uint64_t nonce) {
    message::PongMessage msg(nonce);
    auto payload = msg.serialize();
    return create_test_message(magic, protocol::commands::PONG, payload);
}

// =============================================================================
// PEER STATE MACHINE TESTS
// =============================================================================

TEST_CASE("Peer - OutboundHandshake", "[peer][handshake]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    mock_conn->set_inbound(false);

    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);

    SECTION("Initial state") {
        CHECK(peer->state() == PeerConnectionState::CONNECTED);
        CHECK_FALSE(peer->successfully_connected());
        CHECK(peer->is_connected());
        CHECK_FALSE(peer->is_inbound());
    }

    SECTION("Sends VERSION on start") {
        peer->start();
        io_context.poll();
        CHECK(mock_conn->sent_message_count() >= 1);
        CHECK(peer->state() == PeerConnectionState::VERSION_SENT);
    }

    SECTION("Complete handshake") {
        bool message_received = false;
        peer->set_message_handler([&](PeerPtr p, std::unique_ptr<message::Message> msg) {
            message_received = true;
        });
        peer->start();
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::VERSION_SENT);
        auto version_msg = create_version_message(magic, 54321);
        mock_conn->simulate_receive(version_msg);
        io_context.poll();
        CHECK(mock_conn->sent_message_count() >= 2);
        auto verack_msg = create_verack_message(magic);
        mock_conn->simulate_receive(verack_msg);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::READY);
        CHECK(peer->successfully_connected());
        CHECK(message_received);
    }
}

TEST_CASE("Peer - InboundHandshake", "[peer][handshake]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    mock_conn->set_inbound(true);

    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);

    SECTION("Waits for VERSION") {
        peer->start();
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::CONNECTED);
    }

    SECTION("Complete inbound handshake") {
        peer->start();
        io_context.poll();
        auto version_msg = create_version_message(magic, 54321);
        mock_conn->simulate_receive(version_msg);
        io_context.poll();
        CHECK(mock_conn->sent_message_count() >= 2);
        auto verack_msg = create_verack_message(magic);
        mock_conn->simulate_receive(verack_msg);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::READY);
        CHECK(peer->successfully_connected());
    }
}

TEST_CASE("Peer - SelfConnectionPrevention", "[peer][handshake][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    mock_conn->set_inbound(true);

    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    auto version_msg = create_version_message(magic, peer->get_local_nonce());
    mock_conn->simulate_receive(version_msg);
    io_context.poll();
    CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
}

// =============================================================================
// MESSAGE HANDLING TESTS
// =============================================================================

TEST_CASE("Peer - SendMessage", "[peer][messages]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();

    const uint32_t magic = protocol::magic::REGTEST;
    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);

    SECTION("Send PING message") {
        auto ping = std::make_unique<message::PingMessage>(99999);
        peer->send_message(std::move(ping));
        io_context.poll();
        CHECK(mock_conn->sent_message_count() == 1);
        auto sent = mock_conn->get_sent_messages()[0];
        CHECK(sent.size() >= protocol::MESSAGE_HEADER_SIZE);
    }

    SECTION("Cannot send when disconnected") {
        peer->disconnect();
        io_context.poll();
        size_t before = mock_conn->sent_message_count();
        auto ping = std::make_unique<message::PingMessage>(99999);
        peer->send_message(std::move(ping));
        CHECK(mock_conn->sent_message_count() == before);
    }
}

TEST_CASE("Peer - ReceiveMessage", "[peer][messages]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();

    const uint32_t magic = protocol::magic::REGTEST;
    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);

    std::string received_command;
    peer->set_message_handler([&](PeerPtr p, std::unique_ptr<message::Message> msg) {
        received_command = msg->command();
    });

    peer->start();
    io_context.poll();

    auto version_msg = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version_msg);
    io_context.poll();

    auto verack_msg = create_verack_message(magic);
    mock_conn->simulate_receive(verack_msg);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::READY);
    mock_conn->clear_sent_messages();

    SECTION("Receive PING and auto-respond with PONG") {
        received_command.clear();
        auto ping_msg = create_ping_message(magic, 77777);
        mock_conn->simulate_receive(ping_msg);
        io_context.poll();
        CHECK(mock_conn->sent_message_count() == 1);
        CHECK(received_command.empty());
    }
}

TEST_CASE("Peer - InvalidMessageHandling", "[peer][messages][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();

    const uint32_t magic = protocol::magic::REGTEST;
    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    SECTION("Wrong magic bytes") {
        auto ping_msg = create_ping_message(0xDEADBEEF, 12345);
        mock_conn->simulate_receive(ping_msg);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }

    SECTION("Message too large") {
        protocol::MessageHeader header(magic, protocol::commands::PING,
                                      protocol::MAX_PROTOCOL_MESSAGE_LENGTH + 1);
        header.checksum.fill(0);
        auto header_bytes = message::serialize_header(header);
        mock_conn->simulate_receive(header_bytes);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }

    SECTION("Checksum mismatch") {
        message::PingMessage ping(12345);
        auto payload = ping.serialize();
        protocol::MessageHeader header(magic, protocol::commands::PING,
                                      static_cast<uint32_t>(payload.size()));
        header.checksum.fill(0xFF);
        auto header_bytes = message::serialize_header(header);
        std::vector<uint8_t> full_message;
        full_message.insert(full_message.end(), header_bytes.begin(), header_bytes.end());
        full_message.insert(full_message.end(), payload.begin(), payload.end());
        mock_conn->simulate_receive(full_message);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }
}

// =============================================================================
// TIMEOUT TESTS (documentation only)
// =============================================================================

TEST_CASE("Peer - HandshakeTimeout", "[.][timeout]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    auto peer = Peer::create_outbound(io_context, mock_conn,
                                      protocol::magic::REGTEST, 0);
    peer->start();
    auto work = asio::make_work_guard(io_context);
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start <
           std::chrono::seconds(protocol::VERSION_HANDSHAKE_TIMEOUT_SEC + 1)) {
        io_context.poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
}

TEST_CASE("Peer - InactivityTimeout", "[peer][timeout]") {
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
}

// =============================================================================
// BUFFER MANAGEMENT / SECURITY TESTS
// =============================================================================

TEST_CASE("Peer - ReceiveBufferFloodProtection", "[peer][security][dos]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    auto peer = Peer::create_outbound(io_context, mock_conn,
                                      protocol::magic::REGTEST, 0);
    peer->start();
    io_context.poll();
    std::vector<uint8_t> huge_data(protocol::DEFAULT_RECV_FLOOD_SIZE + 1, 0xAA);
    mock_conn->simulate_receive(huge_data);
    io_context.poll();
    CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
}

TEST_CASE("Peer - UserAgentLengthValidation", "[peer][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;
    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();
    message::VersionMessage msg;
    msg.version = protocol::PROTOCOL_VERSION;
    msg.services = protocol::NODE_NETWORK;
    msg.timestamp = 1234567890;
    msg.nonce = 54321;
    msg.user_agent = std::string(protocol::MAX_SUBVERSION_LENGTH + 1, 'X');
    msg.start_height = 0;
    auto payload = msg.serialize();
    auto full_msg = create_test_message(magic, protocol::commands::VERSION, payload);
    mock_conn->simulate_receive(full_msg);
    io_context.poll();
    CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
}

// =============================================================================
// STATISTICS TESTS
// =============================================================================

TEST_CASE("Peer - Statistics", "[peer][stats]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;
    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);

    SECTION("Tracks messages sent") {
        peer->start();
        io_context.poll();
        size_t initial = peer->stats().messages_sent;
        auto ping = std::make_unique<message::PingMessage>(12345);
        peer->send_message(std::move(ping));
        io_context.poll();
        CHECK(peer->stats().messages_sent == initial + 1);
        CHECK(peer->stats().bytes_sent > 0);
    }

    SECTION("Tracks messages received") {
        peer->set_message_handler([](PeerPtr p, std::unique_ptr<message::Message> msg) {
        });
        peer->start();
        io_context.poll();
        auto version_msg = create_version_message(magic, 54321);
        mock_conn->simulate_receive(version_msg);
        io_context.poll();
        auto verack_msg = create_verack_message(magic);
        mock_conn->simulate_receive(verack_msg);
        io_context.poll();
        size_t initial = peer->stats().messages_received;
        auto ping_msg = create_ping_message(magic, 99999);
        mock_conn->simulate_receive(ping_msg);
        io_context.poll();
        CHECK(peer->stats().messages_received > initial);
        CHECK(peer->stats().bytes_received > 0);
    }
}

// =============================================================================
// PING/PONG TESTS
// =============================================================================

TEST_CASE("Peer - PingPong", "[peer][ping]") {
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
    mock_conn->clear_sent_messages();
    uint64_t ping_nonce = 777777;
    auto ping_msg = create_ping_message(magic, ping_nonce);
    mock_conn->simulate_receive(ping_msg);
    io_context.poll();
    CHECK(mock_conn->sent_message_count() == 1);
    auto pong_data = mock_conn->get_sent_messages()[0];
    CHECK(pong_data.size() >= protocol::MESSAGE_HEADER_SIZE);
}

// =============================================================================
// DISCONNECT TESTS
// =============================================================================

TEST_CASE("Peer - DisconnectCleanup", "[peer][disconnect]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    auto peer = Peer::create_outbound(io_context, mock_conn,
                                      protocol::magic::REGTEST, 0);
    peer->start();
    io_context.poll();
    REQUIRE(peer->is_connected());
    peer->disconnect();
    io_context.poll();
    CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    CHECK_FALSE(peer->is_connected());
    peer->disconnect();
    peer->disconnect();
}

TEST_CASE("Peer - PeerInfo", "[peer][info]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;
    const uint64_t peer_nonce = 54321;
    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();
    CHECK(peer->version() == 0);
    CHECK(peer->user_agent().empty());
    CHECK(peer->start_height() == 0);
    message::VersionMessage version_msg;
    version_msg.version = protocol::PROTOCOL_VERSION;
    version_msg.services = protocol::NODE_NETWORK;
    version_msg.timestamp = 1234567890;
    version_msg.nonce = peer_nonce;
    version_msg.user_agent = "/TestPeer:2.0.0/";
    version_msg.start_height = 100;
    auto payload = version_msg.serialize();
    auto full_msg = create_test_message(magic, protocol::commands::VERSION, payload);
    mock_conn->simulate_receive(full_msg);
    io_context.poll();
    CHECK(peer->version() == protocol::PROTOCOL_VERSION);
    CHECK(peer->services() == protocol::NODE_NETWORK);
    CHECK(peer->user_agent() == "/TestPeer:2.0.0/");
    CHECK(peer->start_height() == 100);
    CHECK(peer->peer_nonce() == peer_nonce);
}

// =============================================================================
// PROTOCOL SECURITY TESTS
// =============================================================================

TEST_CASE("Peer - DuplicateVersionRejection", "[peer][security][critical]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;
    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();
    auto version1 = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version1);
    io_context.poll();
    CHECK(peer->version() == protocol::PROTOCOL_VERSION);
    CHECK(peer->user_agent() == "/Test:1.0.0/");
    CHECK(peer->peer_nonce() == 54321);
    message::VersionMessage msg2;
    msg2.version = 99999;
    msg2.services = protocol::NODE_NETWORK;
    msg2.timestamp = 9999999999;
    msg2.nonce = 11111;
    msg2.user_agent = "/Attacker:6.6.6/";
    msg2.start_height = 999;
    auto payload2 = msg2.serialize();
    auto version2 = create_test_message(magic, protocol::commands::VERSION, payload2);
    mock_conn->simulate_receive(version2);
    io_context.poll();
    CHECK(peer->version() == protocol::PROTOCOL_VERSION);
    CHECK(peer->user_agent() == "/Test:1.0.0/");
    CHECK(peer->peer_nonce() == 54321);
    CHECK(peer->is_connected());
}

TEST_CASE("Peer - MessageBeforeVersionRejected", "[peer][security][critical]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;
    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();
    REQUIRE(peer->state() == PeerConnectionState::CONNECTED);
    REQUIRE(peer->version() == 0);
    SECTION("PING before VERSION disconnects") {
        auto ping_msg = create_ping_message(magic, 99999);
        mock_conn->simulate_receive(ping_msg);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }
    SECTION("VERACK before VERSION disconnects") {
        // Track initial message count (inbound peer sends nothing initially, should be 0)
        size_t initial_count = mock_conn->sent_message_count();

        auto verack_msg = create_verack_message(magic);
        mock_conn->simulate_receive(verack_msg);
        io_context.poll();

        // SECURITY: Peer must disconnect AND send no response messages
        // Premature VERACK (before sending/receiving VERSION) is invalid protocol state
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);

        // Assert no egress: peer must not send any messages in response to invalid VERACK
        CHECK(mock_conn->sent_message_count() == initial_count);
    }
    SECTION("PONG before VERSION disconnects") {
        auto pong_msg = create_pong_message(magic, 12345);
        mock_conn->simulate_receive(pong_msg);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }
}

TEST_CASE("Peer - DuplicateVerackRejection", "[peer][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;
    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();
    auto version_msg = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version_msg);
    io_context.poll();
    auto verack1 = create_verack_message(magic);
    mock_conn->simulate_receive(verack1);
    io_context.poll();
    CHECK(peer->state() == PeerConnectionState::READY);
    CHECK(peer->successfully_connected());
    auto verack2 = create_verack_message(magic);
    mock_conn->simulate_receive(verack2);
    io_context.poll();
    CHECK(peer->state() == PeerConnectionState::READY);
    CHECK(peer->successfully_connected());
    CHECK(peer->is_connected());
}

TEST_CASE("Peer - VersionMustBeFirstMessage", "[peer][security][critical]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;
    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();
    auto version1 = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version1);
    io_context.poll();
    REQUIRE(peer->version() != 0);
    auto verack = create_verack_message(magic);
    mock_conn->simulate_receive(verack);
    io_context.poll();
    CHECK(peer->state() == PeerConnectionState::READY);
    auto version2 = create_version_message(magic, 99999);
    mock_conn->simulate_receive(version2);
    io_context.poll();
    CHECK(peer->peer_nonce() == 54321);
    CHECK(peer->state() == PeerConnectionState::READY);
}

// =============================================================================
// NODE_NETWORK SERVICE FLAG TESTS
// =============================================================================

static std::vector<uint8_t> create_version_message_with_services(
    uint32_t magic, uint64_t nonce, uint64_t services) {
    message::VersionMessage msg;
    msg.version = protocol::PROTOCOL_VERSION;
    msg.services = services;
    msg.timestamp = 1234567890;
    msg.nonce = nonce;
    msg.user_agent = "/Test:1.0.0/";
    msg.start_height = 0;
    auto payload = msg.serialize();
    return create_test_message(magic, protocol::commands::VERSION, payload);
}

TEST_CASE("Peer - OutboundRejectsNoNodeNetwork", "[peer][security][services]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    mock_conn->set_inbound(false);
    const uint32_t magic = protocol::magic::REGTEST;

    // Create outbound peer (we initiated connection)
    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Peer responds with VERSION but NO NODE_NETWORK flag (services=0)
    auto version_msg = create_version_message_with_services(magic, 54321, 0);
    mock_conn->simulate_receive(version_msg);
    io_context.poll();

    // Outbound peers MUST have NODE_NETWORK - should disconnect
    CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
}

TEST_CASE("Peer - InboundAcceptsNoNodeNetwork", "[peer][security][services]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    mock_conn->set_inbound(true);
    const uint32_t magic = protocol::magic::REGTEST;

    // Create inbound peer (they connected to us)
    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Peer sends VERSION with NO NODE_NETWORK flag (services=0)
    auto version_msg = create_version_message_with_services(magic, 54321, 0);
    mock_conn->simulate_receive(version_msg);
    io_context.poll();

    // Inbound peers don't require NODE_NETWORK - should accept
    CHECK(peer->is_connected());

    // Complete handshake
    auto verack_msg = create_verack_message(magic);
    mock_conn->simulate_receive(verack_msg);
    io_context.poll();

    CHECK(peer->state() == PeerConnectionState::READY);
}

TEST_CASE("Peer - FeelerAcceptsNoNodeNetwork", "[peer][security][services]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    mock_conn->set_inbound(false);
    const uint32_t magic = protocol::magic::REGTEST;

    // Create feeler connection (outbound but just testing liveness)
    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0,
                                      "127.0.0.1", 9590, ConnectionType::FEELER);
    CHECK(peer->is_feeler());
    peer->start();
    io_context.poll();

    // Peer responds with VERSION but NO NODE_NETWORK flag
    auto version_msg = create_version_message_with_services(magic, 54321, 0);
    mock_conn->simulate_receive(version_msg);
    io_context.poll();

    // Feelers don't require NODE_NETWORK - should NOT disconnect due to missing services
    // Instead, feelers disconnect normally after receiving VERSION (address verified reachable)
    // Key: version() > 0 means we received VERSION (feeler success), not rejected for service flags
    // Note: successfully_connected() is false for feelers (that's for full VERACK handshake)
    CHECK_FALSE(peer->successfully_connected());
    CHECK(peer->version() > 0);
    // Feelers always disconnect after VERSION processing (Core parity)
    CHECK_FALSE(peer->is_connected());
}

// =============================================================================
// UNKNOWN COMMAND RATE LIMITING TESTS
// =============================================================================

static std::vector<uint8_t> create_unknown_command_message(uint32_t magic, const std::string& cmd) {
    std::vector<uint8_t> payload = {0x01, 0x02, 0x03, 0x04};  // Arbitrary payload
    return create_test_message(magic, cmd, payload);
}

TEST_CASE("Peer - UnknownCommandRateLimiting", "[peer][security][dos]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Complete handshake first
    auto version_msg = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version_msg);
    io_context.poll();

    auto verack_msg = create_verack_message(magic);
    mock_conn->simulate_receive(verack_msg);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::READY);

    // Send many unknown commands - should eventually disconnect
    // MAX_UNKNOWN_COMMANDS_PER_MINUTE is defined in protocol.hpp
    for (size_t i = 0; i <= protocol::MAX_UNKNOWN_COMMANDS_PER_MINUTE + 1; i++) {
        if (peer->state() == PeerConnectionState::DISCONNECTED) break;
        auto unknown_msg = create_unknown_command_message(magic, "unknowncmd");
        mock_conn->simulate_receive(unknown_msg);
        io_context.poll();
    }

    CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
}

TEST_CASE("Peer - UnknownCommandAcceptedUnderLimit", "[peer][security][dos]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Complete handshake first
    auto version_msg = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version_msg);
    io_context.poll();

    auto verack_msg = create_verack_message(magic);
    mock_conn->simulate_receive(verack_msg);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::READY);

    // Send a few unknown commands - should stay connected
    for (int i = 0; i < 3; i++) {
        auto unknown_msg = create_unknown_command_message(magic, "testcmd");
        mock_conn->simulate_receive(unknown_msg);
        io_context.poll();
    }

    CHECK(peer->state() == PeerConnectionState::READY);
    CHECK(peer->is_connected());
}

// =============================================================================
// PARTIAL MESSAGE (SPLIT TCP) TESTS
// =============================================================================

TEST_CASE("Peer - PartialMessageReceive", "[peer][messages][tcp]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Create a complete VERSION message
    auto full_version = create_version_message(magic, 54321);

    // Split it into multiple chunks to simulate TCP fragmentation
    size_t mid = full_version.size() / 2;
    std::vector<uint8_t> chunk1(full_version.begin(), full_version.begin() + mid);
    std::vector<uint8_t> chunk2(full_version.begin() + mid, full_version.end());

    // Send first chunk - should buffer, no state change yet
    mock_conn->simulate_receive(chunk1);
    io_context.poll();
    CHECK(peer->state() == PeerConnectionState::VERSION_SENT);

    // Send second chunk - now complete message should be processed
    mock_conn->simulate_receive(chunk2);
    io_context.poll();

    // VERSION should now be processed
    CHECK(peer->version() == protocol::PROTOCOL_VERSION);
}

TEST_CASE("Peer - HeaderOnlyThenPayload", "[peer][messages][tcp]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Create a complete VERSION message
    auto full_version = create_version_message(magic, 54321);

    // Split at exactly the header boundary
    std::vector<uint8_t> header_only(full_version.begin(),
                                      full_version.begin() + protocol::MESSAGE_HEADER_SIZE);
    std::vector<uint8_t> payload_only(full_version.begin() + protocol::MESSAGE_HEADER_SIZE,
                                       full_version.end());

    // Send header only - should wait for payload
    mock_conn->simulate_receive(header_only);
    io_context.poll();
    CHECK(peer->state() == PeerConnectionState::VERSION_SENT);

    // Send payload - now should process
    mock_conn->simulate_receive(payload_only);
    io_context.poll();

    CHECK(peer->version() == protocol::PROTOCOL_VERSION);
}

// =============================================================================
// PONG NONCE MISMATCH TESTS
// =============================================================================

TEST_CASE("Peer - PongNonceMismatch", "[peer][ping]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Complete handshake
    auto version_msg = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version_msg);
    io_context.poll();

    auto verack_msg = create_verack_message(magic);
    mock_conn->simulate_receive(verack_msg);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::READY);

    // Get initial ping time (should be 0 or default)
    auto initial_ping = peer->stats().ping_time_ms.load();

    // Send a PONG with wrong nonce (we never sent a PING with this nonce)
    auto pong_msg = create_pong_message(magic, 99999999);
    mock_conn->simulate_receive(pong_msg);
    io_context.poll();

    // Peer should still be connected (mismatched PONG is ignored, not error)
    CHECK(peer->state() == PeerConnectionState::READY);

    // Ping time should NOT be updated (PONG was ignored)
    auto final_ping = peer->stats().ping_time_ms.load();
    CHECK(final_ping == initial_ping);
}

// =============================================================================
// BLOCK-RELAY-ONLY CONNECTION TESTS
// =============================================================================

TEST_CASE("Peer - BlockRelayOnlyConnection", "[peer][connection-type]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    mock_conn->set_inbound(false);
    const uint32_t magic = protocol::magic::REGTEST;

    // Create block-relay-only connection
    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0,
                                      "127.0.0.1", 9590, ConnectionType::BLOCK_RELAY);

    CHECK(peer->is_block_relay_only());
    CHECK_FALSE(peer->is_feeler());
    CHECK_FALSE(peer->is_inbound());

    peer->start();
    io_context.poll();

    // Complete handshake
    auto version_msg = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version_msg);
    io_context.poll();

    auto verack_msg = create_verack_message(magic);
    mock_conn->simulate_receive(verack_msg);
    io_context.poll();

    // Should complete handshake normally (unlike feelers which disconnect)
    CHECK(peer->state() == PeerConnectionState::READY);
    CHECK(peer->successfully_connected());
    CHECK(peer->is_block_relay_only());
}

// =============================================================================
// FEELER CONNECTION TESTS
// =============================================================================

TEST_CASE("Peer - FeelerDisconnectsAfterVersion", "[peer][feeler]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    mock_conn->set_inbound(false);
    const uint32_t magic = protocol::magic::REGTEST;

    // Create feeler connection
    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0,
                                      "127.0.0.1", 9590, ConnectionType::FEELER);
    CHECK(peer->is_feeler());

    peer->start();
    io_context.poll();

    // Receive VERSION from peer - feeler should disconnect immediately
    // Bitcoin Core: Feelers disconnect after VERSION, not after VERACK
    // The address is proven reachable as soon as we get a valid VERSION response
    auto version_msg = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version_msg);
    io_context.poll();

    // Feelers disconnect immediately after receiving VERSION (Core parity)
    CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    // Feelers do NOT set successfully_connected (that's for full handshake/VERACK)
    // Feeler success is determined by version() > 0 (received VERSION)
    CHECK_FALSE(peer->successfully_connected());
    CHECK(peer->version() > 0);
}

// =============================================================================
// CALLBACK TESTS
// =============================================================================

TEST_CASE("Peer - VerackCompleteHandlerCalled", "[peer][callback]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);

    bool handler_called = false;
    PeerPtr received_peer = nullptr;
    peer->set_verack_complete_handler([&](PeerPtr p) {
        handler_called = true;
        received_peer = p;
    });

    peer->start();
    io_context.poll();

    // Complete handshake
    auto version_msg = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version_msg);
    io_context.poll();

    auto verack_msg = create_verack_message(magic);
    mock_conn->simulate_receive(verack_msg);
    io_context.poll();

    CHECK(handler_called);
    CHECK(received_peer.get() == peer.get());
}

TEST_CASE("Peer - LocalAddrLearnedHandlerCalled", "[peer][callback]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);

    bool handler_called = false;
    std::string learned_ip;
    peer->set_local_addr_learned_handler([&](const std::string& ip) {
        handler_called = true;
        learned_ip = ip;
    });

    peer->start();
    io_context.poll();

    // Create VERSION with addr_recv containing our "external" address
    message::VersionMessage version_msg;
    version_msg.version = protocol::PROTOCOL_VERSION;
    version_msg.services = protocol::NODE_NETWORK;
    version_msg.timestamp = 1234567890;
    version_msg.nonce = 54321;
    version_msg.user_agent = "/Test:1.0.0/";
    version_msg.start_height = 0;
    // addr_recv is what the peer sees us as
    version_msg.addr_recv = protocol::NetworkAddress::from_string("203.0.113.50", 9590);

    auto payload = version_msg.serialize();
    auto full_msg = create_test_message(magic, protocol::commands::VERSION, payload);
    mock_conn->simulate_receive(full_msg);
    io_context.poll();

    CHECK(handler_called);
    CHECK(learned_ip == "203.0.113.50");
}

// =============================================================================
// PROTOCOL VERSION TESTS
// =============================================================================

TEST_CASE("Peer - ObsoleteProtocolVersionRejection", "[peer][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Create VERSION with version below MIN_PROTOCOL_VERSION
    message::VersionMessage version_msg;
    version_msg.version = protocol::MIN_PROTOCOL_VERSION - 1;  // Too old
    version_msg.services = protocol::NODE_NETWORK;
    version_msg.timestamp = 1234567890;
    version_msg.nonce = 54321;
    version_msg.user_agent = "/OldClient:0.1.0/";
    version_msg.start_height = 0;

    auto payload = version_msg.serialize();
    auto full_msg = create_test_message(magic, protocol::commands::VERSION, payload);
    mock_conn->simulate_receive(full_msg);
    io_context.poll();

    // Should disconnect due to obsolete protocol version
    CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
}

// =============================================================================
// MULTIPLE MESSAGES IN SINGLE PACKET TESTS
// =============================================================================

TEST_CASE("Peer - MultipleMessagesInSinglePacket", "[peer][messages][tcp]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Create VERSION + VERACK concatenated together (simulating TCP coalescing)
    auto version_msg = create_version_message(magic, 54321);
    auto verack_msg = create_verack_message(magic);

    std::vector<uint8_t> combined;
    combined.insert(combined.end(), version_msg.begin(), version_msg.end());
    combined.insert(combined.end(), verack_msg.begin(), verack_msg.end());

    // Send both messages in a single receive
    mock_conn->simulate_receive(combined);
    io_context.poll();

    // Both messages should be processed
    CHECK(peer->version() == protocol::PROTOCOL_VERSION);
    CHECK(peer->state() == PeerConnectionState::READY);
    CHECK(peer->successfully_connected());
}

// =============================================================================
// ADDR RELAY FLAG TESTS
// =============================================================================

TEST_CASE("Peer - AddrRelayFlags", "[peer][connection-type]") {
    asio::io_context io_context;
    const uint32_t magic = protocol::magic::REGTEST;

    SECTION("Full relay peers relay addresses") {
        auto mock_conn = std::make_shared<MockTransportConnection>();
        auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0,
                                          "127.0.0.1", 9590, ConnectionType::OUTBOUND_FULL_RELAY);
        CHECK(peer->relays_addr());
    }

    SECTION("Block-relay-only peers do NOT relay addresses") {
        auto mock_conn = std::make_shared<MockTransportConnection>();
        auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0,
                                          "127.0.0.1", 9590, ConnectionType::BLOCK_RELAY);
        CHECK_FALSE(peer->relays_addr());
    }

    SECTION("Feeler peers do NOT relay addresses") {
        auto mock_conn = std::make_shared<MockTransportConnection>();
        auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0,
                                          "127.0.0.1", 9590, ConnectionType::FEELER);
        CHECK_FALSE(peer->relays_addr());
    }

    SECTION("Manual peers do NOT relay addresses") {
        auto mock_conn = std::make_shared<MockTransportConnection>();
        auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0,
                                          "127.0.0.1", 9590, ConnectionType::MANUAL);
        CHECK_FALSE(peer->relays_addr());
    }

    SECTION("Inbound peers relay addresses") {
        auto mock_conn = std::make_shared<MockTransportConnection>();
        mock_conn->set_inbound(true);
        auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
        CHECK(peer->relays_addr());
    }
}

// =============================================================================
// SYNC STATE TESTS
// =============================================================================

TEST_CASE("Peer - SyncStartedFlag", "[peer][sync]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);

    // Initially false
    CHECK_FALSE(peer->sync_started());

    // Can be set
    peer->set_sync_started(true);
    CHECK(peer->sync_started());

    // Can be cleared
    peer->set_sync_started(false);
    CHECK_FALSE(peer->sync_started());
}

TEST_CASE("Peer - GetaddrSentFlag", "[peer][discovery]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);

    // Initially false
    CHECK_FALSE(peer->has_sent_getaddr());

    // Can be marked
    peer->mark_getaddr_sent();
    CHECK(peer->has_sent_getaddr());

    // Idempotent
    peer->mark_getaddr_sent();
    CHECK(peer->has_sent_getaddr());
}

// =============================================================================
// START() GUARD TESTS
// =============================================================================

TEST_CASE("Peer - StartOnlyOnce", "[peer][lifecycle]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);

    // First start works
    peer->start();
    io_context.poll();
    CHECK(peer->state() == PeerConnectionState::VERSION_SENT);

    size_t messages_after_first_start = mock_conn->sent_message_count();

    // Second start should be ignored (no additional VERSION sent)
    peer->start();
    io_context.poll();

    // Should not have sent another VERSION
    CHECK(mock_conn->sent_message_count() == messages_after_first_start);
}
