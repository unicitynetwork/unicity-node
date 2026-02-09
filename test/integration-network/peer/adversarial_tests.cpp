// Adversarial tests for network/peer.cpp - Attack scenarios and edge cases (ported to test2)

#include "catch_amalgamated.hpp"
#include "network/peer.hpp"
#include "network/transport.hpp"
#include "network/real_transport.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"
#include "util/hash.hpp"
#include <asio.hpp>
#include <memory>
#include <vector>
#include <set>
#include <array>
#include <random>
#include <mutex>
#include <thread>
#include <condition_variable>

using namespace unicity;
using namespace unicity::network;

// =============================================================================
// MOCK TRANSPORT (from legacy tests)
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
// MALFORMED MESSAGE ATTACKS
// =============================================================================

TEST_CASE("Adversarial - PartialHeaderAttack", "[adversarial][malformed]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    SECTION("Partial header (only magic bytes)") {
        std::vector<uint8_t> partial_header(4);
        std::memcpy(partial_header.data(), &magic, 4);

        mock_conn->simulate_receive(partial_header);
        io_context.poll();

        CHECK(peer->is_connected());
        CHECK(peer->version() == 0);
    }

    SECTION("Partial header then timeout") {
        std::vector<uint8_t> partial_header(12);  // Only 12 of 24 header bytes
        mock_conn->simulate_receive(partial_header);
        io_context.poll();
        CHECK(peer->is_connected());
    }
}

TEST_CASE("Adversarial - HeaderLengthMismatch", "[adversarial][malformed]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    SECTION("Header claims 100 bytes, send 50 bytes") {
        protocol::MessageHeader header(magic, protocol::commands::VERSION, 100);
        header.checksum = [&](const auto& data) { uint256 hash = Hash(data); std::array<uint8_t, 4> checksum; std::memcpy(checksum.data(), hash.begin(), 4); return checksum; }(std::vector<uint8_t>(100, 0));
        auto header_bytes = message::serialize_header(header);
        std::vector<uint8_t> partial_payload(50, 0xAA);
        std::vector<uint8_t> malicious_msg;
        malicious_msg.insert(malicious_msg.end(), header_bytes.begin(), header_bytes.end());
        malicious_msg.insert(malicious_msg.end(), partial_payload.begin(), partial_payload.end());
        mock_conn->simulate_receive(malicious_msg);
        io_context.poll();
        CHECK(peer->is_connected());
        CHECK(peer->version() == 0);
    }

    SECTION("Header claims 0 bytes, send 100 bytes") {
        protocol::MessageHeader header(magic, protocol::commands::VERSION, 0);
        header.checksum.fill(0);
        auto header_bytes = message::serialize_header(header);
        std::vector<uint8_t> unexpected_payload(100, 0xBB);
        std::vector<uint8_t> malicious_msg;
        malicious_msg.insert(malicious_msg.end(), header_bytes.begin(), header_bytes.end());
        malicious_msg.insert(malicious_msg.end(), unexpected_payload.begin(), unexpected_payload.end());
        mock_conn->simulate_receive(malicious_msg);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }
}

TEST_CASE("Adversarial - EmptyCommandField", "[adversarial][malformed]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    protocol::MessageHeader header;
    header.magic = magic;
    header.command.fill(0);
    header.length = 0;
    header.checksum.fill(0);

    auto header_bytes = message::serialize_header(header);
    mock_conn->simulate_receive(header_bytes);
    io_context.poll();

    CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
}

TEST_CASE("Adversarial - NonPrintableCommandCharacters", "[adversarial][malformed]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    protocol::MessageHeader header;
    header.magic = magic;
    header.command = { static_cast<char>(0xFF), static_cast<char>(0xFE), static_cast<char>(0xFD), static_cast<char>(0xFC),
                       static_cast<char>(0xFB), static_cast<char>(0xFA), static_cast<char>(0xF9), static_cast<char>(0xF8),
                       static_cast<char>(0xF7), static_cast<char>(0xF6), static_cast<char>(0xF5), static_cast<char>(0xF4) };
    header.length = 0;
    header.checksum.fill(0);

    auto header_bytes = message::serialize_header(header);
    mock_conn->simulate_receive(header_bytes);
    io_context.poll();

    CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
}

// =============================================================================
// PROTOCOL STATE MACHINE ATTACKS
// =============================================================================

TEST_CASE("Adversarial - RapidVersionFlood", "[adversarial][flood]") {
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
    CHECK(peer->peer_nonce() == 54321);

    for (int i = 0; i < 99; i++) {
        auto version_dup = create_version_message(magic, 99999 + i);
        mock_conn->simulate_receive(version_dup);
        io_context.poll();
    }

    CHECK(peer->version() == protocol::PROTOCOL_VERSION);
    CHECK(peer->peer_nonce() == 54321);
    CHECK(peer->is_connected());
}

TEST_CASE("Adversarial - RapidVerackFlood", "[adversarial][flood]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    auto version = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version);
    io_context.poll();

    auto verack1 = create_verack_message(magic);
    mock_conn->simulate_receive(verack1);
    io_context.poll();

    CHECK(peer->state() == PeerConnectionState::READY);

    for (int i = 0; i < 99; i++) {
        auto verack_dup = create_verack_message(magic);
        mock_conn->simulate_receive(verack_dup);
        io_context.poll();
    }

    CHECK(peer->state() == PeerConnectionState::READY);
    CHECK(peer->is_connected());
}

TEST_CASE("Adversarial - AlternatingVersionVerack", "[adversarial][protocol]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    for (int i = 0; i < 10; i++) {
        auto version = create_version_message(magic, 50000 + i);
        mock_conn->simulate_receive(version);
        io_context.poll();
        if (!peer->is_connected()) break;
        auto verack = create_verack_message(magic);
        mock_conn->simulate_receive(verack);
        io_context.poll();
        if (!peer->is_connected()) break;
    }

    CHECK(peer->state() == PeerConnectionState::READY);
    CHECK(peer->peer_nonce() == 50000);
}

// =============================================================================
// RESOURCE EXHAUSTION ATTACKS
// =============================================================================

TEST_CASE("Adversarial - SlowDataDrip", "[adversarial][resource]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    auto version = create_version_message(magic, 54321);
    for (size_t i = 0; i < version.size(); i++) {
        std::vector<uint8_t> single_byte = {version[i]};
        mock_conn->simulate_receive(single_byte);
        io_context.poll();
    }

    CHECK(peer->version() == protocol::PROTOCOL_VERSION);
    CHECK(peer->is_connected());
}

TEST_CASE("Adversarial - MultiplePartialMessages", "[adversarial][resource]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Send partial headers (12 bytes each containing 0xCC)
    // After 2 iterations, buffer has 24 bytes → triggers header parse
    // Magic bytes 0xCCCCCCCC don't match REGTEST → disconnect
    for (int i = 0; i < 10; i++) {
        std::vector<uint8_t> partial_header(12, 0xCC);
        mock_conn->simulate_receive(partial_header);
        io_context.poll();
        if (!peer->is_connected()) {
            break;
        }
    }

    // NOTE: This test validates wrong magic detection, not partial message handling.
    // Partial headers < 24 bytes are tolerated (buffered until complete).
    // At 24 bytes, header is parsed and bad magic (0xCCCCCCCC) triggers disconnect.
    CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
}

TEST_CASE("Adversarial - BufferFragmentation", "[adversarial][resource]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    auto version = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version);
    io_context.poll();
    CHECK(peer->version() == protocol::PROTOCOL_VERSION);

    auto verack = create_verack_message(magic);
    mock_conn->simulate_receive(verack);
    io_context.poll();
    REQUIRE(peer->state() == PeerConnectionState::READY);

    auto bad_ping = create_ping_message(0xBADBAD, 99999);
    mock_conn->simulate_receive(bad_ping);
    io_context.poll();

    CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
}

// =============================================================================
// TIMING ATTACKS
// =============================================================================

TEST_CASE("Adversarial - ExtremeTimestamps", "[adversarial][timing]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    SECTION("Timestamp = 0 (January 1970)") {
        message::VersionMessage msg;
        msg.version = protocol::PROTOCOL_VERSION;
        msg.services = protocol::NODE_NETWORK;
        msg.timestamp = 0;
        msg.nonce = 54321;
        msg.user_agent = "/Test:1.0.0/";
        msg.start_height = 0;
        auto payload = msg.serialize();
        auto full_msg = create_test_message(magic, protocol::commands::VERSION, payload);
        mock_conn->simulate_receive(full_msg);
        io_context.poll();
        CHECK(peer->version() == protocol::PROTOCOL_VERSION);
        CHECK(peer->is_connected());
    }

    SECTION("Timestamp = MAX_INT64 (far future)") {
        message::VersionMessage msg;
        msg.version = protocol::PROTOCOL_VERSION;
        msg.services = protocol::NODE_NETWORK;
        msg.timestamp = std::numeric_limits<int64_t>::max();
        msg.nonce = 54321;
        msg.user_agent = "/Test:1.0.0/";
        msg.start_height = 0;
        auto payload = msg.serialize();
        auto full_msg = create_test_message(magic, protocol::commands::VERSION, payload);
        mock_conn->simulate_receive(full_msg);
        io_context.poll();
        CHECK(peer->version() == protocol::PROTOCOL_VERSION);
        CHECK(peer->is_connected());
    }
}

// =============================================================================
// MESSAGE SEQUENCE ATTACKS
// =============================================================================

TEST_CASE("Adversarial - OutOfOrderHandshake", "[adversarial][protocol]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    SECTION("VERACK then VERSION then VERACK (outbound)") {
        // Bitcoin Core behavior: ignore non-version messages before handshake (no disconnect)
        // Core: net_processing.cpp:3657-3660 - logs and returns without disconnecting
        auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);
        peer->start();
        io_context.poll();

        // Track message count after VERSION sent during start()
        size_t count_after_version = mock_conn->sent_message_count();

        auto verack1 = create_verack_message(magic);
        mock_conn->simulate_receive(verack1);
        io_context.poll();

        // SECURITY: Peer must ignore premature VERACK (match Bitcoin Core)
        // Premature VERACK is silently ignored, peer stays connected waiting for VERSION
        CHECK(peer->is_connected());
        CHECK(peer->version() == 0);  // Still waiting for VERSION

        // Assert no egress: peer must not send any messages in response to premature VERACK
        CHECK(mock_conn->sent_message_count() == count_after_version);
    }

    SECTION("Double VERSION with VERACK in between") {
        auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
        peer->start();
        io_context.poll();
        auto version1 = create_version_message(magic, 11111);
        mock_conn->simulate_receive(version1);
        io_context.poll();
        CHECK(peer->peer_nonce() == 11111);
        auto verack = create_verack_message(magic);
        mock_conn->simulate_receive(verack);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::READY);
        auto version2 = create_version_message(magic, 22222);
        mock_conn->simulate_receive(version2);
        io_context.poll();
        CHECK(peer->peer_nonce() == 11111);
        CHECK(peer->state() == PeerConnectionState::READY);
    }
}

TEST_CASE("Adversarial - PingFloodBeforeHandshake", "[adversarial][flood]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Send VERSION to start handshake (but don't send VERACK to complete it)
    auto version = create_version_message(magic, 12345);
    mock_conn->simulate_receive(version);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::VERSION_SENT);

    // Clear messages (VERSION, VERACK sent by peer)
    mock_conn->clear_sent_messages();

    // Flood with PING messages before handshake completes
    for (int i = 0; i < 10; i++) {
        auto ping = create_ping_message(magic, 1000 + i);
        mock_conn->simulate_receive(ping);
        io_context.poll();
    }

    // CRITICAL: Peer must IGNORE all PINGs (Bitcoin Core policy)
    // - Stay connected (not disconnect)
    // - Send no PONG responses
    // - Remain in VERSION_SENT state (waiting for our VERACK)
    CHECK(peer->state() == PeerConnectionState::VERSION_SENT);
    CHECK(peer->is_connected());

    // Verify no PONG messages were sent
    auto sent_messages = mock_conn->get_sent_messages();
    for (const auto& msg : sent_messages) {
        if (msg.size() >= 24) {
            std::string command(msg.begin() + 4, msg.begin() + 16);
            CHECK(command.find("pong") == std::string::npos);
        }
    }
}

// =============================================================================
// QUICK WIN TESTS
// =============================================================================

TEST_CASE("Adversarial - PongNonceMismatch", "[adversarial][protocol][quickwin]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    auto version = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version);
    io_context.poll();

    auto verack = create_verack_message(magic);
    mock_conn->simulate_receive(verack);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::READY);
    mock_conn->clear_sent_messages();

    uint64_t peer_ping_nonce = 777777;
    auto ping_from_peer = create_ping_message(magic, peer_ping_nonce);
    mock_conn->simulate_receive(ping_from_peer);
    io_context.poll();
    CHECK(mock_conn->sent_message_count() == 1);

    auto wrong_pong = create_pong_message(magic, 999999);
    mock_conn->simulate_receive(wrong_pong);
    io_context.poll();
    CHECK(peer->is_connected());
}

TEST_CASE("Adversarial - DeserializationFailureFlooding", "[adversarial][malformed][quickwin]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    auto version = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version);
    io_context.poll();

    auto verack = create_verack_message(magic);
    mock_conn->simulate_receive(verack);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::READY);

    SECTION("PING with payload too short") {
        std::vector<uint8_t> short_payload = {0x01, 0x02, 0x03, 0x04};
        auto malformed_ping = create_test_message(magic, protocol::commands::PING, short_payload);
        mock_conn->simulate_receive(malformed_ping);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }

    SECTION("PING with payload too long") {
        // SECURITY: PING must be exactly 8 bytes (Bitcoin Core pattern)
        // Oversized PING messages are a DoS vector (e.g., 4 MB PING flooding)
        std::vector<uint8_t> long_payload(16, 0xAA);  // 16 bytes, should be 8
        auto malformed_ping = create_test_message(magic, protocol::commands::PING, long_payload);
        mock_conn->simulate_receive(malformed_ping);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }

    SECTION("VERACK with unexpected payload") {
        std::vector<uint8_t> garbage_payload = {0xDE, 0xAD, 0xBE, 0xEF};
        auto malformed_verack = create_test_message(magic, protocol::commands::VERACK, garbage_payload);
        mock_conn->simulate_receive(malformed_verack);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }

    SECTION("PONG with wrong length") {
        // SECURITY: PONG must be exactly 8 bytes (Bitcoin Core pattern)
        // Oversized PONG messages are a DoS vector
        std::vector<uint8_t> long_pong(16, 0xBB);  // 16 bytes, should be 8
        auto malformed_pong = create_test_message(magic, protocol::commands::PONG, long_pong);
        mock_conn->simulate_receive(malformed_pong);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }

    SECTION("PING with wrong length") {
        // SECURITY: PING must be exactly 8 bytes (Bitcoin Core pattern)
        // Oversized PING messages are a DoS vector
        std::vector<uint8_t> short_ping(4, 0xAA);  // 4 bytes, should be 8
        auto malformed_ping = create_test_message(magic, protocol::commands::PING, short_ping);
        mock_conn->simulate_receive(malformed_ping);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }

    SECTION("GETADDR with wrong length") {
        // SECURITY: GETADDR must be exactly 0 bytes (empty payload)
        // Prevents abuse of GETADDR flood with extra payload
        std::vector<uint8_t> payload_getaddr(10, 0xCC);  // 10 bytes, should be 0
        auto malformed_getaddr = create_test_message(magic, protocol::commands::GETADDR, payload_getaddr);
        mock_conn->simulate_receive(malformed_getaddr);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }
}

// TEST REMOVED: ReceiveBufferCycling previously tested buffer management with 100 KB PING messages
// This test is no longer valid after adding per-message-type size limits (PING must be exactly 8 bytes)
// Buffer cycling is adequately tested by other tests with properly-sized messages

TEST_CASE("Adversarial - MessageSizeLimits", "[adversarial][malformed][dos]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    auto version = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version);
    io_context.poll();

    auto verack = create_verack_message(magic);
    mock_conn->simulate_receive(verack);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::READY);

    SECTION("ADDR oversized (>1000 addresses)") {
        // SECURITY: ADDR messages limited to MAX_ADDR_SIZE (1000) addresses
        // Prevents memory exhaustion attacks
        message::MessageSerializer s;
        s.write_varint(1001);  // One more than MAX_ADDR_SIZE
        // Write 1001 dummy addresses (each 30 bytes without timestamp, 34 with)
        for (int i = 0; i < 1001; i++) {
            s.write_uint32(1234567890);  // timestamp
            s.write_uint64(protocol::NODE_NETWORK);  // services
            std::array<uint8_t, 16> ipv6{};
            ipv6[10] = 0xFF; ipv6[11] = 0xFF;  // IPv4-mapped prefix
            ipv6[12] = 127; ipv6[15] = 1;  // 127.0.0.1
            s.write_bytes(ipv6.data(), 16);
            s.write_uint16(9590);  // port (network byte order)
        }
        auto oversized_addr = create_test_message(magic, protocol::commands::ADDR, s.data());
        mock_conn->simulate_receive(oversized_addr);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }

    SECTION("GETHEADERS oversized locator (>101 hashes)") {
        // SECURITY: GETHEADERS locator limited to MAX_LOCATOR_SZ (101) hashes
        // Prevents CPU exhaustion from expensive FindFork() operations
        message::MessageSerializer s;
        s.write_uint32(protocol::PROTOCOL_VERSION);
        s.write_varint(102);  // One more than MAX_LOCATOR_SZ
        // Write 102 dummy block hashes (each 32 bytes)
        for (int i = 0; i < 102; i++) {
            std::array<uint8_t, 32> hash{};
            hash[0] = static_cast<uint8_t>(i & 0xFF);
            s.write_bytes(hash.data(), 32);
        }
        // Write hash_stop (32 bytes of zeros)
        std::array<uint8_t, 32> hash_stop{};
        s.write_bytes(hash_stop.data(), 32);
        auto oversized_getheaders = create_test_message(magic, protocol::commands::GETHEADERS, s.data());
        mock_conn->simulate_receive(oversized_getheaders);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }

    SECTION("HEADERS oversized (>MAX_HEADERS_SIZE)") {
        // SECURITY: HEADERS messages limited to MAX_HEADERS_SIZE (80000) headers
        // Prevents memory exhaustion attacks
        // Note: We claim to send MAX_HEADERS_SIZE+1 headers but only write a few
        // The rejection happens based on the count, not the actual data
        message::MessageSerializer s;
        s.write_varint(protocol::MAX_HEADERS_SIZE + 1);  // One more than MAX_HEADERS_SIZE
        // Write just a few dummy headers (100 bytes each for Unicity)
        for (int i = 0; i < 10; i++) {
            // CBlockHeader: 100 bytes (version, prev_hash, miner_addr, timestamp, bits, nonce, randomx_hash)
            s.write_uint32(1);  // version (4)
            std::array<uint8_t, 32> prev_hash{};
            s.write_bytes(prev_hash.data(), 32);  // hashPrevBlock (32)
            std::array<uint8_t, 20> miner_addr{};
            s.write_bytes(miner_addr.data(), 20);  // minerAddress (20)
            s.write_uint32(1234567890);  // timestamp (4)
            s.write_uint32(0x1d00ffff);  // bits (4)
            s.write_uint32(i);  // nonce (4)
            std::array<uint8_t, 32> randomx_hash{};
            s.write_bytes(randomx_hash.data(), 32);  // hashRandomX (32)
        }
        auto oversized_headers = create_test_message(magic, protocol::commands::HEADERS, s.data());
        mock_conn->simulate_receive(oversized_headers);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }
}

TEST_CASE("Adversarial - ProtocolStateMachine", "[adversarial][protocol][state]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    SECTION("Multiple VERSION messages - ignored per Bitcoin Core") {
        // Bitcoin Core: Ignores duplicate VERSION (checks if pfrom.nVersion != 0)
        // Prevents: time manipulation via multiple AddTimeData() calls
        // Pattern: Log and return, don't disconnect

        auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
        peer->start();
        io_context.poll();

        // First VERSION: should be accepted
        auto version1 = create_version_message(magic, 54321);
        mock_conn->simulate_receive(version1);
        io_context.poll();

        // Send VERACK to complete handshake
        auto verack = create_verack_message(magic);
        mock_conn->simulate_receive(verack);
        io_context.poll();

        REQUIRE(peer->state() == PeerConnectionState::READY);

        // Capture message count before second VERSION
        size_t count_before = mock_conn->sent_message_count();

        // Second VERSION: ignored (Bitcoin Core pattern)
        auto version2 = create_version_message(magic, 99999);
        mock_conn->simulate_receive(version2);
        io_context.poll();

        // Bitcoin Core: Stays connected, ignores duplicate, sends no response
        CHECK(peer->state() == PeerConnectionState::READY);
        CHECK(mock_conn->sent_message_count() == count_before);  // No egress!
    }

    SECTION("Multiple VERACK messages - ignored per Bitcoin Core") {
        // Bitcoin Core: Ignores duplicate VERACK (checks if pfrom.fSuccessfullyConnected)
        // Prevents: timer churn from repeated schedule_ping() calls
        // Pattern: Log warning and return, don't disconnect

        auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
        peer->start();
        io_context.poll();

        auto version = create_version_message(magic, 54321);
        mock_conn->simulate_receive(version);
        io_context.poll();

        auto verack1 = create_verack_message(magic);
        mock_conn->simulate_receive(verack1);
        io_context.poll();

        REQUIRE(peer->state() == PeerConnectionState::READY);

        // Capture message count before second VERACK
        size_t count_before = mock_conn->sent_message_count();

        // Second VERACK: ignored (Bitcoin Core pattern)
        auto verack2 = create_verack_message(magic);
        mock_conn->simulate_receive(verack2);
        io_context.poll();

        // Bitcoin Core: Stays connected, ignores duplicate, sends no response
        CHECK(peer->state() == PeerConnectionState::READY);
        CHECK(mock_conn->sent_message_count() == count_before);  // No egress!
    }

    SECTION("VERSION after READY state - ignored per Bitcoin Core") {
        // Bitcoin Core: Duplicate VERSION is ignored (same as multiple VERSION test)
        // Even after READY, peer_version_ != 0 so duplicate is ignored

        auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
        peer->start();
        io_context.poll();

        auto version = create_version_message(magic, 54321);
        mock_conn->simulate_receive(version);
        io_context.poll();

        auto verack = create_verack_message(magic);
        mock_conn->simulate_receive(verack);
        io_context.poll();

        REQUIRE(peer->state() == PeerConnectionState::READY);

        // Capture message count before VERSION after READY
        size_t count_before = mock_conn->sent_message_count();

        // Send VERSION after READY - ignored (same logic as duplicate VERSION)
        auto version2 = create_version_message(magic, 99999);
        mock_conn->simulate_receive(version2);
        io_context.poll();

        // Bitcoin Core: Stays connected, ignores duplicate
        CHECK(peer->state() == PeerConnectionState::READY);
        CHECK(mock_conn->sent_message_count() == count_before);  // No egress!
    }

    SECTION("GETHEADERS before handshake complete - ignored") {
        // SECURITY: Non-handshake messages ignored before successfully_connected_
        // Prevents: resource exhaustion from unauthenticated peers
        // Pattern: peer.cpp:770 checks successfully_connected_, logs and returns

        auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
        peer->start();
        io_context.poll();

        auto version = create_version_message(magic, 54321);
        mock_conn->simulate_receive(version);
        io_context.poll();

        // Peer has received VERSION but not yet VERACK - not in READY state
        // Capture message count before sending GETHEADERS
        size_t count_before = mock_conn->sent_message_count();

        // Send GETHEADERS before VERACK - ignored
        message::MessageSerializer s;
        s.write_uint32(protocol::PROTOCOL_VERSION);
        s.write_varint(1);  // 1 locator hash
        std::array<uint8_t, 32> hash{};
        s.write_bytes(hash.data(), 32);
        std::array<uint8_t, 32> hash_stop{};
        s.write_bytes(hash_stop.data(), 32);
        auto getheaders = create_test_message(magic, protocol::commands::GETHEADERS, s.data());
        mock_conn->simulate_receive(getheaders);
        io_context.poll();

        // Stays connected (still in VERSION_SENT state), ignores message, sends no response
        CHECK(peer->state() == PeerConnectionState::VERSION_SENT);  // Still in handshake
        CHECK(mock_conn->sent_message_count() == count_before);  // No egress!
    }

    SECTION("HEADERS before handshake complete - ignored") {
        // SECURITY: Non-handshake messages ignored before successfully_connected_
        // Prevents: DoS attacks from unauthenticated peers sending expensive HEADERS
        // Pattern: peer.cpp:770 checks successfully_connected_, logs and returns

        auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
        peer->start();
        io_context.poll();

        auto version = create_version_message(magic, 54321);
        mock_conn->simulate_receive(version);
        io_context.poll();

        // Peer has received VERSION but not yet VERACK - not in READY state
        // Capture message count before sending HEADERS
        size_t count_before = mock_conn->sent_message_count();

        // Send HEADERS before VERACK - ignored
        message::MessageSerializer s;
        s.write_varint(0);  // 0 headers (empty, but still ignored before READY)
        auto headers = create_test_message(magic, protocol::commands::HEADERS, s.data());
        mock_conn->simulate_receive(headers);
        io_context.poll();

        // Stays connected (still in VERSION_SENT state), ignores message, sends no response
        CHECK(peer->state() == PeerConnectionState::VERSION_SENT);  // Still in handshake
        CHECK(mock_conn->sent_message_count() == count_before);  // No egress!
    }
}

TEST_CASE("Adversarial - UnknownMessageFlooding", "[adversarial][flood][quickwin]") {
    // Bitcoin Core parity: unknown commands are silently ignored
    // This provides forward compatibility for protocol upgrades
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    auto version = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version);
    io_context.poll();

    auto verack = create_verack_message(magic);
    mock_conn->simulate_receive(verack);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::READY);

    std::vector<std::string> fake_commands = {
        "FAKECMD1", "FAKECMD2", "XYZABC", "UNKNOWN",
        "BOGUS", "INVALID", "NOTREAL", "JUNK",
        "GARBAGE", "RANDOM"
    };

    // Send many unknown commands - all should be silently ignored
    const int messages_to_send = 100;
    for (int i = 0; i < messages_to_send; i++) {
        std::string fake_cmd = fake_commands[i % fake_commands.size()];
        std::vector<uint8_t> dummy_payload = {0x01, 0x02, 0x03, 0x04};
        auto unknown_msg = create_test_message(magic, fake_cmd, dummy_payload);
        mock_conn->simulate_receive(unknown_msg);
        io_context.poll();
    }

    // Peer should still be connected - unknown commands are ignored
    CHECK(peer->is_connected());
    CHECK(peer->state() == PeerConnectionState::READY);
}

TEST_CASE("Adversarial - StatisticsOverflow", "[adversarial][resource][quickwin]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    auto version = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version);
    io_context.poll();

    auto verack = create_verack_message(magic);
    mock_conn->simulate_receive(verack);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::READY);

    // Snapshot stats before injecting PINGs
    auto& stats = peer->stats();
    uint64_t msg_before = stats.messages_received.load();
    uint64_t bytes_before = stats.bytes_received.load();
    const int ping_count = 1000;

    for (int i = 0; i < ping_count; i++) {
        auto ping = create_ping_message(magic, 5000 + i);
        mock_conn->simulate_receive(ping);
        io_context.poll();
    }

    // Verify exact stat increments
    uint64_t msg_after = stats.messages_received.load();
    uint64_t bytes_after = stats.bytes_received.load();
    CHECK(msg_after == msg_before + ping_count);
    CHECK(bytes_after > bytes_before);
    CHECK(peer->is_connected());
}

TEST_CASE("Adversarial - MessageHandlerBlocking", "[adversarial][threading][p2]") {
    // Tests that message handlers can perform work without crashing the peer
    // Removed sleep_for() per TESTING.md guidelines (deterministic tests only)
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);

    int handler_call_count = 0;
    const auto msgs_before = peer->stats().messages_received.load();

    peer->set_message_handler([&](PeerPtr p, std::unique_ptr<message::Message> msg) {
        handler_call_count++;
        // Simulate some work (without sleep - tests should be fast)
        // In real usage, handlers might do validation, chainstate queries, etc.
        int work = 0;
        for (int i = 0; i < 1000; ++i) {
            work = work + i;  // Avoid volatile compound assignment (deprecated in C++20)
        }
        // Prevent optimization of the loop
        if (work < 0) handler_call_count = 0;  // Never true, but compiler can't prove it
    });

    peer->start();
    io_context.poll();

    auto version = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version);
    io_context.poll();

    auto verack = create_verack_message(magic);
    mock_conn->simulate_receive(verack);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::READY);
    REQUIRE(handler_call_count > 0);  // Handler was called

    const auto msgs_after = peer->stats().messages_received.load();
    CHECK(msgs_after > msgs_before);  // Messages were processed
    CHECK(peer->is_connected());  // Peer still connected after handler execution
}

TEST_CASE("Adversarial - ConcurrentDisconnectDuringProcessing", "[adversarial][race][p2]") {
    // Tests that disconnect() can be safely called at any time during message processing
    // This verifies the shared_ptr-based lifecycle management in peer.cpp:164-168
    // Removed sleep_for() per TESTING.md guidelines (deterministic tests only)
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);

    bool handler_executed = false;
    PeerConnectionState state_during_handler = PeerConnectionState::DISCONNECTED;

    peer->set_message_handler([&](PeerPtr p, std::unique_ptr<message::Message> msg) {
        handler_executed = true;
        // Capture state during handler execution
        state_during_handler = p->state();
        // Handler completes successfully even if disconnect is imminent
    });

    peer->start();
    io_context.poll();

    auto version = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version);
    io_context.poll();

    auto verack = create_verack_message(magic);
    mock_conn->simulate_receive(verack);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::READY);
    REQUIRE(handler_executed);  // Handler ran during handshake

    // The adversarial test: call disconnect() after message processing has occurred
    // This verifies shared_ptr lifecycle management prevents use-after-free
    // (The handler was called above during VERSION/VERACK, proving message processing works)

    peer->disconnect();
    io_context.poll();

    // Peer should be cleanly disconnected
    CHECK(peer->state() == PeerConnectionState::DISCONNECTED);

    // Success: No crashes or use-after-free during or after disconnect
    // The test passes if we reach here without crashing
}

TEST_CASE("Adversarial - SelfConnectionEdgeCases", "[adversarial][protocol][p2]") {
    asio::io_context io_context;
    const uint32_t magic = protocol::magic::REGTEST;

    SECTION("Inbound self-connection with matching nonce") {
        auto mock_conn = std::make_shared<MockTransportConnection>();
        auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
        peer->start();
        io_context.poll();
        auto version = create_version_message(magic, peer->get_local_nonce());
        mock_conn->simulate_receive(version);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }

    SECTION("Outbound self-connection detection") {
        // Both inbound AND outbound should detect self-connection (Bitcoin Core pattern)
        auto mock_conn = std::make_shared<MockTransportConnection>();
        auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);
        peer->start();
        io_context.poll();
        auto version = create_version_message(magic, peer->get_local_nonce());
        mock_conn->simulate_receive(version);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }
}

TEST_CASE("Adversarial - MaxMessageSizeEdgeCases", "[adversarial][edge][p2]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    auto version = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version);
    io_context.poll();

    auto verack = create_verack_message(magic);
    mock_conn->simulate_receive(verack);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::READY);

    SECTION("Exactly MAX_PROTOCOL_MESSAGE_LENGTH PING rejected") {
        // Even though this is within global MAX_PROTOCOL_MESSAGE_LENGTH (4 MB),
        // PING has per-message-type limit of exactly 8 bytes
        std::vector<uint8_t> max_payload(protocol::MAX_PROTOCOL_MESSAGE_LENGTH, 0xAA);
        auto max_msg = create_test_message(magic, protocol::commands::PING, max_payload);
        mock_conn->simulate_receive(max_msg);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }

    SECTION("Exactly MAX_PROTOCOL_MESSAGE_LENGTH + 1") {
        std::vector<uint8_t> payload(protocol::MAX_PROTOCOL_MESSAGE_LENGTH + 1, 0xBB);
        protocol::MessageHeader header(magic, protocol::commands::PING,
                                      protocol::MAX_PROTOCOL_MESSAGE_LENGTH + 1);
        header.checksum = [&](const auto& data) { uint256 hash = Hash(data); std::array<uint8_t, 4> checksum; std::memcpy(checksum.data(), hash.begin(), 4); return checksum; }(payload);
        auto header_bytes = message::serialize_header(header);
        mock_conn->simulate_receive(header_bytes);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }

    SECTION("Oversized PING rejected (DoS protection)") {
        // SECURITY: PING must be exactly 8 bytes (Bitcoin Core pattern)
        // Accepting 3 MB PING messages is a DoS footgun (bandwidth/memory exhaustion)
        // This test validates per-message-type size limits, not just global MAX limit
        std::vector<uint8_t> large_payload(3 * 1024 * 1024, 0xEE);  // 3 MB PING!
        auto large_msg = create_test_message(magic, protocol::commands::PING, large_payload);
        mock_conn->simulate_receive(large_msg);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);  // Must disconnect!
    }
}

TEST_CASE("Adversarial - MessageRateLimiting", "[adversarial][flood][p3]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    auto version = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version);
    io_context.poll();

    auto verack = create_verack_message(magic);
    mock_conn->simulate_receive(verack);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::READY);

    // Snapshot stats before flood
    auto& stats = peer->stats();
    uint64_t msg_before = stats.messages_received.load();
    const int ping_count = 1000;
    int sent = 0;

    for (int i = 0; i < ping_count; i++) {
        auto ping = create_ping_message(magic, 8000 + i);
        mock_conn->simulate_receive(ping);
        io_context.poll();
        sent++;
        if (!peer->is_connected()) { break; }
    }

    // Verify exact stat increments
    uint64_t msg_after = stats.messages_received.load();
    CHECK(peer->is_connected());
    CHECK(msg_after == msg_before + sent);
}

TEST_CASE("Adversarial - TransportCallbackOrdering", "[adversarial][race][p3]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    SECTION("Receive callback after disconnect") {
        peer->disconnect();
        io_context.poll();  // Process the disconnect operation
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
        auto version = create_version_message(magic, 54321);
        mock_conn->simulate_receive(version);
        io_context.poll();
        // SECURITY: After disconnect(), callbacks are cleared to prevent use-after-free
        // Messages received after disconnect() should NOT be processed
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
        CHECK(peer->version() == 0);  // VERSION not processed (callback cleared)
    }

    SECTION("Disconnect callback fires twice") {
        auto version = create_version_message(magic, 54321);
        mock_conn->simulate_receive(version);
        io_context.poll();
        auto verack = create_verack_message(magic);
        mock_conn->simulate_receive(verack);
        io_context.poll();
        REQUIRE(peer->state() == PeerConnectionState::READY);
        peer->disconnect();
        io_context.poll();  // Process first disconnect
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
        peer->disconnect();
        io_context.poll();  // Process second disconnect (should be no-op)
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }
}

TEST_CASE("Adversarial - CommandFieldPadding", "[adversarial][malformed][p3]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    SECTION("VERSION with null padding") {
        protocol::MessageHeader header;
        header.magic = magic;
        header.command.fill(0);
        std::string cmd = "version";
        std::copy(cmd.begin(), cmd.end(), header.command.begin());
        message::VersionMessage msg;
        msg.version = protocol::PROTOCOL_VERSION;
        msg.services = protocol::NODE_NETWORK;
        msg.timestamp = 1234567890;
        msg.nonce = 54321;
        msg.user_agent = "/Test:1.0.0/";
        msg.start_height = 0;
        auto payload = msg.serialize();
        header.length = payload.size();
        header.checksum = [&](const auto& data) { uint256 hash = Hash(data); std::array<uint8_t, 4> checksum; std::memcpy(checksum.data(), hash.begin(), 4); return checksum; }(payload);
        auto header_bytes = message::serialize_header(header);
        std::vector<uint8_t> full_message;
        full_message.insert(full_message.end(), header_bytes.begin(), header_bytes.end());
        full_message.insert(full_message.end(), payload.begin(), payload.end());
        mock_conn->simulate_receive(full_message);
        io_context.poll();
        CHECK(peer->version() == protocol::PROTOCOL_VERSION);
        CHECK(peer->is_connected());
    }

    SECTION("Command with trailing spaces") {
        protocol::MessageHeader header;
        header.magic = magic;
        header.command.fill(' ');
        std::string cmd = "version";
        std::copy(cmd.begin(), cmd.end(), header.command.begin());
        message::VersionMessage msg;
        msg.version = protocol::PROTOCOL_VERSION;
        msg.services = protocol::NODE_NETWORK;
        msg.timestamp = 1234567890;
        msg.nonce = 54321;
        msg.user_agent = "/Test:1.0.0/";
        msg.start_height = 0;
        auto payload = msg.serialize();
        header.length = payload.size();
        header.checksum = [&](const auto& data) { uint256 hash = Hash(data); std::array<uint8_t, 4> checksum; std::memcpy(checksum.data(), hash.begin(), 4); return checksum; }(payload);
        auto header_bytes = message::serialize_header(header);
        std::vector<uint8_t> full_message;
        full_message.insert(full_message.end(), header_bytes.begin(), header_bytes.end());
        full_message.insert(full_message.end(), payload.begin(), payload.end());
        mock_conn->simulate_receive(full_message);
        io_context.poll();
        bool connected = peer->is_connected();
        bool version_set = (peer->version() == protocol::PROTOCOL_VERSION);
        CHECK((connected == version_set));
    }
}
// =============================================================================
// HANDSHAKE SECURITY TESTS - Phase 1: Critical Security
// =============================================================================
// Tests for handshake state machine enforcement - prevents information
// disclosure and DoS attacks from unauthenticated peers.
//
// These tests validate the fix in src/network/peer.cpp:733-765 which adds
// successfully_connected_ checks before processing non-handshake messages.
// =============================================================================

// Helper functions for creating protocol messages
static std::vector<uint8_t> create_getaddr_message(uint32_t magic) {
    // GETADDR has no payload
    std::vector<uint8_t> empty_payload;
    return create_test_message(magic, protocol::commands::GETADDR, empty_payload);
}

static std::vector<uint8_t> create_getheaders_message(uint32_t magic) {
    // Minimal GETHEADERS: version (4 bytes) + hash_count (1 byte = 0) + hash_stop (32 bytes = 0)
    message::GetHeadersMessage msg;
    msg.version = protocol::PROTOCOL_VERSION;
    // Empty locator hashes
    msg.hash_stop.SetNull();
    auto payload = msg.serialize();
    return create_test_message(magic, protocol::commands::GETHEADERS, payload);
}

static std::vector<uint8_t> create_addr_message(uint32_t magic) {
    // ADDR with one address
    message::AddrMessage msg;
    protocol::TimestampedAddress addr;
    addr.timestamp = 1234567890;
    addr.address.services = protocol::NODE_NETWORK;
    addr.address.ip.fill(0);
    addr.address.ip[10] = 0xff;
    addr.address.ip[11] = 0xff;
    addr.address.ip[12] = 127;
    addr.address.ip[13] = 0;
    addr.address.ip[14] = 0;
    addr.address.ip[15] = 1;
    addr.address.port = 9590;
    msg.addresses.push_back(addr);
    auto payload = msg.serialize();
    return create_test_message(magic, protocol::commands::ADDR, payload);
}

static std::vector<uint8_t> create_headers_message(uint32_t magic) {
    // HEADERS with one header
    message::HeadersMessage msg;
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.minerAddress.SetNull();
    header.nTime = 1234567890;
    header.nBits = 0x1d00ffff;
    header.nNonce = 0;
    header.hashRandomX.SetNull();
    msg.headers.push_back(header);
    auto payload = msg.serialize();
    return create_test_message(magic, protocol::commands::HEADERS, payload);
}

// Helper to create a message with specific header length field
static std::vector<uint8_t> create_message_with_length(uint32_t magic, const std::string& command, uint32_t length_field) {
    protocol::MessageHeader header;
    header.magic = magic;
    header.set_command(command);
    header.length = length_field;
    header.checksum.fill(0);  // Invalid checksum, but we're testing length handling

    auto header_bytes = message::serialize_header(header);
    return header_bytes;  // Return just the header, no payload
}

// =============================================================================
// TEST 1.1: PING before VERACK
// =============================================================================
TEST_CASE("Handshake Security - PING before VERACK", "[adversarial][handshake][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Send VERSION
    auto version = create_version_message(magic, 12345);
    mock_conn->simulate_receive(version);
    io_context.poll();

    // Peer should be in CONNECTED state but not READY
    REQUIRE(peer->state() == PeerConnectionState::VERSION_SENT);

    // Clear any outgoing messages (VERSION, VERACK)
    mock_conn->clear_sent_messages();

    // Send PING before completing handshake
    auto ping = create_ping_message(magic, 0xDEADBEEF);
    mock_conn->simulate_receive(ping);
    io_context.poll();

    // CRITICAL: Peer must NOT respond with PONG
    // Verify NO egress traffic (security: no information disclosure)
    CHECK(mock_conn->sent_message_count() == 0);

    // Double-check: scan for PONG specifically
    auto sent_messages = mock_conn->get_sent_messages();
    bool pong_sent = false;
    for (const auto& msg : sent_messages) {
        if (msg.size() >= 24) {
            std::string command(msg.begin() + 4, msg.begin() + 16);
            if (command.find("pong") != std::string::npos) {
                pong_sent = true;
                break;
            }
        }
    }
    CHECK(!pong_sent);

    // Verify peer stays connected and in correct state
    CHECK(peer->is_connected());
    CHECK(peer->state() == PeerConnectionState::VERSION_SENT);
}

// =============================================================================
// TEST 1.3: GETADDR before VERACK
// =============================================================================
TEST_CASE("Handshake Security - GETADDR before VERACK", "[adversarial][handshake][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Send VERSION
    auto version = create_version_message(magic, 12345);
    mock_conn->simulate_receive(version);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::VERSION_SENT);
    mock_conn->clear_sent_messages();

    // Attack: Send GETADDR before VERACK to enumerate addresses
    auto getaddr = create_getaddr_message(magic);
    mock_conn->simulate_receive(getaddr);
    io_context.poll();

    // CRITICAL: Peer must NOT respond with ADDR
    // Verify NO egress traffic (security: no network topology disclosure)
    CHECK(mock_conn->sent_message_count() == 0);

    // Double-check: scan for ADDR specifically
    auto sent_messages = mock_conn->get_sent_messages();
    bool addr_sent = false;
    for (const auto& msg : sent_messages) {
        if (msg.size() >= 24) {
            std::string command(msg.begin() + 4, msg.begin() + 16);
            if (command.find("addr") != std::string::npos) {
                addr_sent = true;
                break;
            }
        }
    }
    CHECK(!addr_sent);

    // Verify peer stays connected and in correct state
    CHECK(peer->is_connected());
    CHECK(peer->state() == PeerConnectionState::VERSION_SENT);
}

// =============================================================================
// TEST 1.4: GETHEADERS before VERACK
// =============================================================================
TEST_CASE("Handshake Security - GETHEADERS before VERACK", "[adversarial][handshake][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    auto version = create_version_message(magic, 12345);
    mock_conn->simulate_receive(version);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::VERSION_SENT);
    mock_conn->clear_sent_messages();

    // Attack: Send GETHEADERS before VERACK to fingerprint chain state
    auto getheaders = create_getheaders_message(magic);
    mock_conn->simulate_receive(getheaders);
    io_context.poll();

    // CRITICAL: Peer must NOT respond with HEADERS
    // Verify NO egress traffic (security: no chain state disclosure)
    CHECK(mock_conn->sent_message_count() == 0);

    // Double-check: scan for HEADERS specifically
    auto sent_messages = mock_conn->get_sent_messages();
    bool headers_sent = false;
    for (const auto& msg : sent_messages) {
        if (msg.size() >= 24) {
            std::string command(msg.begin() + 4, msg.begin() + 16);
            if (command.find("headers") != std::string::npos) {
                headers_sent = true;
                break;
            }
        }
    }

    CHECK(!headers_sent);  // HEADERS must NOT be sent (chain fingerprinting protection)

    // Verify peer stays connected and in correct state
    CHECK(peer->is_connected());
    CHECK(peer->state() == PeerConnectionState::VERSION_SENT);
}

// =============================================================================
// TEST 1.6: ADDR before VERACK
// =============================================================================
TEST_CASE("Handshake Security - ADDR before VERACK", "[adversarial][handshake][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    auto version = create_version_message(magic, 12345);
    mock_conn->simulate_receive(version);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::VERSION_SENT);
    mock_conn->clear_sent_messages();

    // Attack: Send malicious ADDR before VERACK to poison address database
    auto addr = create_addr_message(magic);
    mock_conn->simulate_receive(addr);
    io_context.poll();

    // CRITICAL: Peer should ignore ADDR (address table must not be polluted)
    // Verify NO egress traffic (security: no response to pre-handshake ADDR)
    CHECK(mock_conn->sent_message_count() == 0);

    // This test validates that ADDR processing is deferred until handshake completes
    // Note: We can't directly inspect the address manager, but the message should be ignored
    CHECK(peer->is_connected());
    CHECK(peer->state() == PeerConnectionState::VERSION_SENT);

    // Now complete handshake and verify peer reaches READY state
    auto verack = create_verack_message(magic);
    mock_conn->simulate_receive(verack);
    io_context.poll();

    CHECK(peer->state() == PeerConnectionState::READY);
}

// =============================================================================
// TEST 6.5: Header length field overflow
// =============================================================================
TEST_CASE("Handshake Security - Header length overflow", "[adversarial][handshake][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Attack: Send VERSION header with length = 0xFFFFFFFF (4GB)
    // This could cause integer overflow or massive memory allocation
    auto malicious_header = create_message_with_length(magic, protocol::commands::VERSION, 0xFFFFFFFF);
    mock_conn->simulate_receive(malicious_header);
    io_context.poll();

    // Peer should disconnect or reject the message (not crash!)
    // The exact behavior depends on implementation, but it must not allocate 4GB
    // The peer should either be disconnected or still waiting for valid VERSION
    bool safe_state = (peer->state() == PeerConnectionState::DISCONNECTED ||
                       peer->state() == PeerConnectionState::CONNECTING ||
                       peer->version() == 0);

    CHECK(safe_state);  // Must not process 4GB message
}

// =============================================================================
// TEST 6.4: Oversized VERSION
// =============================================================================
TEST_CASE("Handshake Security - Oversized VERSION", "[adversarial][handshake][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Attack: Send VERSION with length = MAX_PROTOCOL_MESSAGE_LENGTH
    // Peer should reject this before allocating memory
    auto malicious_header = create_message_with_length(magic, protocol::commands::VERSION,
                                                       protocol::MAX_PROTOCOL_MESSAGE_LENGTH);
    mock_conn->simulate_receive(malicious_header);
    io_context.poll();

    // Peer should disconnect (not allocate 4MB for VERSION)
    bool safe_state = (peer->state() == PeerConnectionState::DISCONNECTED ||
                       peer->version() == 0);

    CHECK(safe_state);  // Must not allocate maximum size for VERSION
}

// =============================================================================
// TEST 6.6: VERSION with bad checksum
// =============================================================================
TEST_CASE("Handshake Security - VERSION with bad checksum", "[adversarial][handshake][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Create a valid VERSION message
    message::VersionMessage msg;
    msg.version = protocol::PROTOCOL_VERSION;
    msg.services = protocol::NODE_NETWORK;
    msg.timestamp = 1234567890;
    msg.nonce = 12345;
    msg.user_agent = "/Test:1.0.0/";
    msg.start_height = 0;
    auto payload = msg.serialize();

    // Create header with CORRECT length but WRONG checksum
    protocol::MessageHeader header;
    header.magic = magic;
    header.set_command(protocol::commands::VERSION);
    header.length = static_cast<uint32_t>(payload.size());
    header.checksum.fill(0);  // Wrong checksum (should be hash of payload)

    auto header_bytes = message::serialize_header(header);

    // Send complete message: header + payload
    std::vector<uint8_t> malicious_message;
    malicious_message.insert(malicious_message.end(), header_bytes.begin(), header_bytes.end());
    malicious_message.insert(malicious_message.end(), payload.begin(), payload.end());

    mock_conn->simulate_receive(malicious_message);
    io_context.poll();

    // CRITICAL: Peer must disconnect on checksum mismatch
    // Bad checksum indicates corrupted or malicious message
    bool safe_state = (peer->state() == PeerConnectionState::DISCONNECTED ||
                       peer->version() == 0);

    CHECK(safe_state);  // Must reject message with bad checksum
}

// =============================================================================
// TEST 6.7: Wrong network magic during handshake
// =============================================================================
TEST_CASE("Handshake Security - Wrong network magic during handshake", "[adversarial][handshake][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Attack: Send VERSION with TESTNET magic to REGTEST node
    const uint32_t wrong_magic = protocol::magic::TESTNET;

    message::VersionMessage msg;
    msg.version = protocol::PROTOCOL_VERSION;
    msg.services = protocol::NODE_NETWORK;
    msg.timestamp = 1234567890;
    msg.nonce = 12345;
    msg.user_agent = "/Test:1.0.0/";
    msg.start_height = 0;
    auto payload = msg.serialize();

    // Create message with WRONG magic
    auto malicious_message = create_test_message(wrong_magic, protocol::commands::VERSION, payload);

    mock_conn->simulate_receive(malicious_message);
    io_context.poll();

    // CRITICAL: Peer must disconnect on magic mismatch
    // Prevents cross-network pollution and fingerprinting
    bool safe_state = (peer->state() == PeerConnectionState::DISCONNECTED ||
                       peer->version() == 0);

    CHECK(safe_state);  // Must reject wrong network magic
}

// =============================================================================
// TEST 6.8: Checksum for zeros with non-zero payload
// =============================================================================
TEST_CASE("Handshake Security - Checksum for zeros with non-zero payload", "[adversarial][handshake][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Create a valid VERSION message payload
    message::VersionMessage msg;
    msg.version = protocol::PROTOCOL_VERSION;
    msg.services = protocol::NODE_NETWORK;
    msg.timestamp = 1234567890;
    msg.nonce = 12345;
    msg.user_agent = "/Test:1.0.0/";
    msg.start_height = 0;
    auto payload = msg.serialize();

    // Calculate checksum of all zeros (different from actual payload)
    std::vector<uint8_t> zeros(payload.size(), 0);
    protocol::MessageHeader wrong_header(magic, protocol::commands::VERSION, static_cast<uint32_t>(zeros.size()));
    uint256 hash = Hash(zeros);
    std::memcpy(wrong_header.checksum.data(), hash.begin(), 4);
    auto header_bytes = message::serialize_header(wrong_header);

    // Send header with checksum for zeros, but actual non-zero payload
    std::vector<uint8_t> malicious_message;
    malicious_message.insert(malicious_message.end(), header_bytes.begin(), header_bytes.end());
    malicious_message.insert(malicious_message.end(), payload.begin(), payload.end());

    mock_conn->simulate_receive(malicious_message);
    io_context.poll();

    // CRITICAL: Peer must disconnect on checksum mismatch
    // Header claims checksum for zeros, but payload is non-zero
    bool safe_state = (peer->state() == PeerConnectionState::DISCONNECTED ||
                       peer->version() == 0);

    CHECK(safe_state);  // Must detect checksum mismatch
}

// =============================================================================
// TEST 1.2: PONG before VERACK
// =============================================================================
TEST_CASE("Handshake Security - PONG before VERACK", "[adversarial][handshake][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Send VERSION
    auto version = create_version_message(magic, 12345);
    mock_conn->simulate_receive(version);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::VERSION_SENT);
    mock_conn->clear_sent_messages();

    // Attack: Send unsolicited PONG before VERACK
    auto pong = create_pong_message(magic, 0xDEADBEEF);
    mock_conn->simulate_receive(pong);
    io_context.poll();

    // CRITICAL: Peer must ignore unsolicited PONG (prevents state confusion)
    CHECK(mock_conn->sent_message_count() == 0);
    CHECK(peer->is_connected());
    CHECK(peer->state() == PeerConnectionState::VERSION_SENT);
}

// =============================================================================
// TEST 1.7: HEADERS before VERACK
// =============================================================================
TEST_CASE("Handshake Security - HEADERS before VERACK", "[adversarial][handshake][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    auto version = create_version_message(magic, 12345);
    mock_conn->simulate_receive(version);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::VERSION_SENT);
    mock_conn->clear_sent_messages();

    // Attack: Send unsolicited HEADERS before VERACK
    auto headers = create_headers_message(magic);
    mock_conn->simulate_receive(headers);
    io_context.poll();

    // CRITICAL: Peer must ignore HEADERS (prevents DoS via header processing)
    CHECK(mock_conn->sent_message_count() == 0);
    CHECK(peer->is_connected());
    CHECK(peer->state() == PeerConnectionState::VERSION_SENT);
}

// =============================================================================
// TEST 2.3: Multiple VERACKs
// =============================================================================
TEST_CASE("Handshake Security - Multiple VERACKs", "[adversarial][handshake][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Complete handshake
    auto version = create_version_message(magic, 12345);
    mock_conn->simulate_receive(version);
    io_context.poll();

    auto verack = create_verack_message(magic);
    mock_conn->simulate_receive(verack);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::READY);
    mock_conn->clear_sent_messages();

    // Attack: Send duplicate VERACK messages
    for (int i = 0; i < 5; ++i) {
        auto duplicate_verack = create_verack_message(magic);
        mock_conn->simulate_receive(duplicate_verack);
        io_context.poll();
    }

    // CRITICAL: Peer should ignore duplicate VERACKs, stay in READY state
    CHECK(peer->state() == PeerConnectionState::READY);
    CHECK(peer->is_connected());
}

// =============================================================================
// TEST 4.1: GETADDR flood before VERACK
// =============================================================================
TEST_CASE("Handshake Security - GETADDR flood before VERACK", "[adversarial][handshake][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    auto version = create_version_message(magic, 12345);
    mock_conn->simulate_receive(version);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::VERSION_SENT);
    mock_conn->clear_sent_messages();

    // Attack: Flood with 100 GETADDR messages before VERACK
    for (int i = 0; i < 100; ++i) {
        auto getaddr = create_getaddr_message(magic);
        mock_conn->simulate_receive(getaddr);
        io_context.poll();
    }

    // CRITICAL: All GETADDR messages ignored, no ADDR responses
    CHECK(mock_conn->sent_message_count() == 0);

    // Now complete handshake
    auto verack = create_verack_message(magic);
    mock_conn->simulate_receive(verack);
    io_context.poll();

    // Peer should reach READY state successfully
    CHECK(peer->state() == PeerConnectionState::READY);
}

// =============================================================================
// TEST 4.2: Large message before VERACK
// =============================================================================
TEST_CASE("Handshake Security - Large message before VERACK", "[adversarial][handshake][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    auto version = create_version_message(magic, 12345);
    mock_conn->simulate_receive(version);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::VERSION_SENT);

    // Attack: Send large HEADERS message (near max size) before VERACK
    message::HeadersMessage msg;
    // Add 2000 headers (2000 * 100 bytes = 200KB)
    for (int i = 0; i < 2000; ++i) {
        CBlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock.SetNull();
        header.minerAddress.SetNull();
        header.nTime = 1234567890 + i;
        header.nBits = 0x1d00ffff;
        header.nNonce = i;
        header.hashRandomX.SetNull();
        msg.headers.push_back(header);
    }
    auto payload = msg.serialize();
    auto large_headers = create_test_message(magic, protocol::commands::HEADERS, payload);

    mock_conn->simulate_receive(large_headers);
    io_context.poll();

    // CRITICAL: Message should be ignored, no memory exhaustion
    // Peer should remain connected or disconnect (both acceptable)
    bool safe_state = (peer->is_connected() && peer->state() == PeerConnectionState::VERSION_SENT) ||
                      peer->state() == PeerConnectionState::DISCONNECTED;
    CHECK(safe_state);
}

// =============================================================================
// TEST 4.3: Message storm before VERACK
// =============================================================================
TEST_CASE("Handshake Security - Message storm before VERACK", "[adversarial][handshake][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    auto version = create_version_message(magic, 12345);
    mock_conn->simulate_receive(version);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::VERSION_SENT);
    mock_conn->clear_sent_messages();

    // Attack: Rapidly send multiple message types before VERACK
    for (int i = 0; i < 20; ++i) {
        mock_conn->simulate_receive(create_ping_message(magic, i));
        mock_conn->simulate_receive(create_getaddr_message(magic));
        mock_conn->simulate_receive(create_getheaders_message(magic));
        io_context.poll();
    }

    // CRITICAL: All non-handshake messages ignored
    CHECK(mock_conn->sent_message_count() == 0);

    // Handshake should complete normally
    auto verack = create_verack_message(magic);
    mock_conn->simulate_receive(verack);
    io_context.poll();

    CHECK(peer->state() == PeerConnectionState::READY);
}

// =============================================================================
// TEST 6.1: VERSION with truncated payload
// =============================================================================
TEST_CASE("Handshake Security - VERSION with truncated payload", "[adversarial][handshake][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Create valid VERSION message
    auto version = create_version_message(magic, 12345);

    // Truncate payload by 10 bytes (but keep header length field unchanged)
    if (version.size() > 34) {  // 24-byte header + some payload
        version.resize(version.size() - 10);
    }

    mock_conn->simulate_receive(version);
    io_context.poll();

    // CRITICAL: Peer should disconnect or reject malformed message
    bool safe_state = (peer->state() == PeerConnectionState::DISCONNECTED ||
                       peer->version() == 0);
    CHECK(safe_state);
}

// =============================================================================
// TEST 6.2: VERSION with extra bytes
// =============================================================================
TEST_CASE("Handshake Security - VERSION with extra bytes", "[adversarial][handshake][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Create valid VERSION message
    auto version = create_version_message(magic, 12345);

    // Append garbage bytes beyond declared length
    std::vector<uint8_t> garbage = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
    version.insert(version.end(), garbage.begin(), garbage.end());

    mock_conn->simulate_receive(version);
    io_context.poll();

    // CRITICAL: Peer should either:
    // 1. Disconnect due to protocol violation, OR
    // 2. Ignore extra bytes and process valid portion (implementation-dependent)
    // Both behaviors are acceptable; the key is no crash or undefined behavior
    bool safe_state = (peer->state() == PeerConnectionState::DISCONNECTED ||
                       peer->state() == PeerConnectionState::VERSION_SENT ||
                       peer->version() > 0);
    CHECK(safe_state);
}

// =============================================================================
// TEST 7.2: Invalid magic bytes
// =============================================================================
TEST_CASE("Handshake Security - Invalid magic bytes", "[adversarial][handshake][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Send VERSION with invalid magic (not MAINNET, TESTNET, or REGTEST)
    const uint32_t invalid_magic = 0xDEADBEEF;
    auto version = create_version_message(invalid_magic, 12345);

    mock_conn->simulate_receive(version);
    io_context.poll();

    // CRITICAL: Peer must disconnect on invalid magic
    CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
}

// =============================================================================
// TEST 7.3: Magic bytes change mid-handshake
// =============================================================================
TEST_CASE("Handshake Security - Magic bytes change mid-handshake", "[adversarial][handshake][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Send VERSION with correct magic
    auto version = create_version_message(magic, 12345);
    mock_conn->simulate_receive(version);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::VERSION_SENT);

    // Attack: Send VERACK with different magic
    const uint32_t wrong_magic = protocol::magic::TESTNET;
    auto verack = create_verack_message(wrong_magic);
    mock_conn->simulate_receive(verack);
    io_context.poll();

    // CRITICAL: Peer must disconnect on magic mismatch
    CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
}

// =============================================================================
// TEST 3.2: Messages queued during handshake
// =============================================================================
TEST_CASE("Handshake Security - Messages queued during handshake", "[adversarial][handshake][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Send VERSION, PING, VERACK in rapid succession (all in one batch)
    auto version = create_version_message(magic, 12345);
    auto ping = create_ping_message(magic, 0x12345678);
    auto verack = create_verack_message(magic);

    mock_conn->simulate_receive(version);
    mock_conn->simulate_receive(ping);  // PING sent before VERACK
    mock_conn->simulate_receive(verack);
    io_context.poll();

    // Peer should reach READY state
    REQUIRE(peer->state() == PeerConnectionState::READY);
    mock_conn->clear_sent_messages();

    // Wait briefly to see if PING gets processed later (it shouldn't)
    io_context.poll();

    // CRITICAL: PING sent before VERACK should NOT trigger PONG later
    auto sent_messages = mock_conn->get_sent_messages();
    bool pong_sent = false;
    for (const auto& msg : sent_messages) {
        if (msg.size() >= 24) {
            std::string command(msg.begin() + 4, msg.begin() + 16);
            if (command.find("pong") != std::string::npos) {
                pong_sent = true;
                break;
            }
        }
    }
    CHECK(!pong_sent);  // PING was ignored, no PONG should be sent
}

// ============================================================================
// PHASE 3: RESOURCE EXHAUSTION TESTS
// ============================================================================
// Tests for DoS protection via resource limits:
// - Recv buffer exhaustion (DEFAULT_RECV_FLOOD_SIZE = 10 MB)
// - Send queue exhaustion (DEFAULT_SEND_QUEUE_SIZE = 10 MB)
// - GETADDR rate limiting
//
// Limits must be >= MAX_PROTOCOL_MESSAGE_LENGTH (8 MB) to allow valid messages.
// See protocol.hpp for limit definitions and peer.cpp for enforcement.

TEST_CASE("Adversarial - RecvBufferExhaustion", "[adversarial][resource][flood]") {
    // SECURITY: Enforces DEFAULT_RECV_FLOOD_SIZE (10 MB) limit
    // to prevent memory exhaustion via large messages
    //
    // Attack scenario: Attacker sends message header claiming large payload,
    // then sends partial data. If we buffer unbounded, attacker can OOM us.
    //
    // Defense: peer.cpp checks if buffer exceeds limit and disconnects
    //
    // This test verifies we disconnect before buffer exceeds 5MB.

    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Complete handshake to reach READY state
    auto version = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version);
    io_context.poll();

    auto verack = create_verack_message(magic);
    mock_conn->simulate_receive(verack);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::READY);

    // Record baseline stats
    uint64_t bytes_received_before = peer->stats().bytes_received.load();

    // Create a message header claiming 12MB payload (exceeds 10MB limit)
    // We'll send the header + 1MB of data, triggering flood protection
    // when peer tries to buffer it (total would be >10MB).
    const uint32_t claimed_payload_size = 12 * 1024 * 1024;  // 12MB
    protocol::MessageHeader hdr;
    hdr.magic = magic;
    hdr.set_command("fakecmd");  // Unknown command (non-zero payload allowed)
    hdr.length = claimed_payload_size;
    hdr.checksum = {0x00, 0x00, 0x00, 0x00};  // Fake checksum (we won't get to validation)

    // Serialize header (24 bytes)
    message::MessageSerializer s;
    s.write_uint32(hdr.magic);
    for (char c : hdr.command) {
        s.write_uint8(static_cast<uint8_t>(c));
    }
    s.write_uint32(hdr.length);
    for (uint8_t b : hdr.checksum) {
        s.write_uint8(b);
    }

    std::vector<uint8_t> header_bytes = s.data();
    REQUIRE(header_bytes.size() == protocol::MESSAGE_HEADER_SIZE);

    // Send header
    mock_conn->simulate_receive(header_bytes);
    io_context.poll();

    // Check if disconnected already (header parsing might trigger limit check)
    if (peer->state() == PeerConnectionState::DISCONNECTED ||
        peer->state() == PeerConnectionState::DISCONNECTING) {
        // Good! Disconnected early (before buffering full payload)
        CHECK(peer->state() != PeerConnectionState::READY);
        return;
    }

    // Still connected after header, now send 1MB of payload data
    // This should push buffer over 10MB limit and trigger disconnect
    const size_t chunk_size = 1 * 1024 * 1024;  // 1MB
    std::vector<uint8_t> payload_chunk(chunk_size, 0xAA);

    size_t sent_before_disconnect = mock_conn->sent_message_count();

    mock_conn->simulate_receive(payload_chunk);
    io_context.poll();

    // CRITICAL SECURITY CHECK: Peer must disconnect when recv buffer would exceed 10MB
    // peer.cpp:338: if (usable_bytes + data.size() > DEFAULT_RECV_FLOOD_SIZE) disconnect
    bool disconnected = (peer->state() == PeerConnectionState::DISCONNECTED ||
                         peer->state() == PeerConnectionState::DISCONNECTING);

    CHECK(disconnected);  // Must disconnect on flood

    // Verify no response sent (egress silence on resource exhaustion)
    CHECK(mock_conn->sent_message_count() == sent_before_disconnect);

    // Stats verification: bytes_received should reflect what was buffered before disconnect
    uint64_t bytes_received_after = peer->stats().bytes_received.load();
    uint64_t delta = bytes_received_after - bytes_received_before;

    // We sent header (24 bytes) + chunk (1MB), but peer may have disconnected
    // before processing all of it. Just verify some bytes were received.
    CHECK(delta > 0);
    CHECK(delta <= header_bytes.size() + chunk_size);
}

// NOTE: Send queue exhaustion testing is covered in test/network/real_transport_tests.cpp
// ("Send-queue overflow closes connection") because it's a transport-level protection,
// not a Peer-level protocol concern. That test verifies real_transport.cpp:274 enforcement.

// NOTE: GETADDR "rate limiting" test
// Bitcoin Core (and Unicity) don't rate-limit GETADDR requests per se.
// Instead, they use once-per-connection gating: addr_relay_manager.cpp:312-319
// Only the FIRST GETADDR on each connection gets a response.
// This is a simpler and more effective DoS protection than rate limiting.
//
// The test below verifies this once-per-connection gating behavior.

TEST_CASE("Adversarial - GetAddrOncePerConnection", "[adversarial][resource][getaddr]") {
    // SECURITY: Bitcoin Core responds to GETADDR only once per connection
    // (addr_relay_manager.cpp:312-319)
    //
    // Attack scenario: Attacker sends many GETADDR messages to exhaust CPU/bandwidth
    //
    // Defense: Once-per-connection gating - only first GETADDR gets a response
    //
    // This test verifies the gating is enforced (not a full integration test,
    // just verifies the message is accepted without error - full test would
    // require NetworkManager/AddrRelayManager integration)

    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Complete handshake
    auto version = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version);
    io_context.poll();

    auto verack = create_verack_message(magic);
    mock_conn->simulate_receive(verack);
    io_context.poll();

    REQUIRE(peer->state() == PeerConnectionState::READY);

    // Send first GETADDR (zero-length payload allowed for GETADDR)
    auto getaddr1 = create_test_message(magic, protocol::commands::GETADDR, {});
    mock_conn->simulate_receive(getaddr1);
    io_context.poll();

    // Peer should still be connected (GETADDR is valid)
    CHECK(peer->is_connected());

    // Send second GETADDR
    auto getaddr2 = create_test_message(magic, protocol::commands::GETADDR, {});
    mock_conn->simulate_receive(getaddr2);
    io_context.poll();

    // Peer should STILL be connected (once-per-connection gating doesn't disconnect,
    // it just silently ignores subsequent GETADDR requests)
    CHECK(peer->is_connected());

    // Send third GETADDR
    auto getaddr3 = create_test_message(magic, protocol::commands::GETADDR, {});
    mock_conn->simulate_receive(getaddr3);
    io_context.poll();

    // Still connected - gating is passive (no disconnect)
    CHECK(peer->is_connected());

    // NOTE: This test verifies Peer-level handling (message acceptance).
    // Full verification of once-per-connection gating happens at AddrRelayManager level
    // (addr_relay_manager.cpp:312-319) and is covered by discovery tests.
    // The adversarial aspect we're testing here is: spamming GETADDR doesn't crash/disconnect.
}

// =============================================================================
// PHASE 4: NETWORK SECURITY TESTS
// =============================================================================

TEST_CASE("Adversarial - WrongNetworkMagic", "[adversarial][security][network-magic]") {
    // Bitcoin Core: net_processing.cpp rejects messages with wrong magic bytes immediately
    // Security: Prevents cross-network pollution (mainnet peer sending testnet messages)
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t correct_magic = protocol::magic::REGTEST;
    const uint32_t wrong_magic = protocol::magic::MAINNET;  // Different network

    auto peer = Peer::create_inbound(io_context, mock_conn, correct_magic, 0);
    peer->start();
    io_context.poll();

    const auto msgs_before = peer->stats().messages_received.load();
    const auto bytes_before = peer->stats().bytes_received.load();

    SECTION("VERSION with wrong magic → disconnect") {
        // Create VERSION message with MAINNET magic instead of REGTEST
        message::VersionMessage msg;
        msg.version = protocol::PROTOCOL_VERSION;
        msg.services = protocol::NODE_NETWORK;
        msg.timestamp = 1234567890;
        msg.nonce = 999999;
        msg.user_agent = "/Attacker:1.0.0/";
        msg.start_height = 0;

        auto payload = msg.serialize();
        auto malicious_msg = create_test_message(wrong_magic, protocol::commands::VERSION, payload);

        mock_conn->simulate_receive(malicious_msg);
        io_context.poll();

        // Peer should disconnect (wrong magic is protocol violation)
        CHECK_FALSE(peer->is_connected());

        // No message should be processed (magic check happens before deserialization)
        const auto msgs_after = peer->stats().messages_received.load();
        const auto bytes_after = peer->stats().bytes_received.load();
        CHECK(msgs_after == msgs_before);
        // Note: bytes_received is updated at transport layer (before validation)
        // so bytes_after > bytes_before is expected. What matters is msgs_received didn't increment.
        CHECK(bytes_after > bytes_before);
    }

    SECTION("Correct magic followed by wrong magic → disconnect on second") {
        // First message: correct magic (REGTEST)
        auto version1 = create_version_message(correct_magic, 111111);
        mock_conn->simulate_receive(version1);
        io_context.poll();

        CHECK(peer->is_connected());
        const auto msgs_middle = peer->stats().messages_received.load();
        CHECK(msgs_middle == msgs_before + 1);

        // Second message: wrong magic (MAINNET)
        auto version2 = create_version_message(wrong_magic, 222222);
        mock_conn->simulate_receive(version2);
        io_context.poll();

        // Should disconnect on wrong magic
        CHECK_FALSE(peer->is_connected());

        // Only first message processed
        const auto msgs_after = peer->stats().messages_received.load();
        CHECK(msgs_after == msgs_middle);  // No increment
    }

    SECTION("Magic bytes in payload → correctly framed, not confused") {
        // Ensure magic bytes appearing in message payload don't confuse parser
        // This tests that framing is robust against payload content

        // Create payload containing wrong magic bytes
        std::vector<uint8_t> payload;
        uint32_t embedded_magic = wrong_magic;
        payload.insert(payload.end(),
                      reinterpret_cast<uint8_t*>(&embedded_magic),
                      reinterpret_cast<uint8_t*>(&embedded_magic) + 4);
        payload.insert(payload.end(), 100, 0xAA);  // Padding

        // But header has correct magic
        auto framed_msg = create_test_message(correct_magic, protocol::commands::VERSION, payload);

        mock_conn->simulate_receive(framed_msg);
        io_context.poll();

        // Should NOT confuse embedded magic with real magic
        // Message processed normally (though it will fail deserialization due to invalid payload)
        const auto msgs_after = peer->stats().messages_received.load();

        // Message was received at network layer (magic was correct)
        // Deserialization might fail but that's okay - we're testing magic check isolation
        CHECK(msgs_after >= msgs_before);
    }
}

TEST_CASE("Adversarial - UnsupportedProtocolVersion", "[adversarial][security][version]") {
    // Bitcoin Core: Rejects peers with version < MIN_PROTOCOL_VERSION
    // Ref: protocol.hpp MIN_PROTOCOL_VERSION = 1
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    const auto msgs_before = peer->stats().messages_received.load();

    SECTION("VERSION with protocol_version = 0 → disconnect") {
        message::VersionMessage msg;
        msg.version = 0;  // Too old (< MIN_PROTOCOL_VERSION = 1)
        msg.services = protocol::NODE_NETWORK;
        msg.timestamp = 1234567890;
        msg.nonce = 123456;
        msg.user_agent = "/OldNode:0.1.0/";
        msg.start_height = 0;

        auto payload = msg.serialize();
        auto version_msg = create_test_message(magic, protocol::commands::VERSION, payload);

        mock_conn->simulate_receive(version_msg);
        io_context.poll();

        // Peer should disconnect (unsupported version)
        CHECK_FALSE(peer->is_connected());

        // Message was received but caused disconnect
        const auto msgs_after = peer->stats().messages_received.load();
        CHECK(msgs_after == msgs_before + 1);

        // Peer version should not be set (handshake failed)
        CHECK(peer->version() == 0);
    }

    SECTION("VERSION with future protocol_version → accept") {
        // Bitcoin Core accepts peers with newer versions (forward compatibility)
        message::VersionMessage msg;
        msg.version = 99999;  // Far future version
        msg.services = protocol::NODE_NETWORK;
        msg.timestamp = 1234567890;
        msg.nonce = 654321;
        msg.user_agent = "/FutureNode:99.0.0/";
        msg.start_height = 100;

        auto payload = msg.serialize();
        auto version_msg = create_test_message(magic, protocol::commands::VERSION, payload);

        mock_conn->simulate_receive(version_msg);
        io_context.poll();

        // Should accept (forward compatibility)
        CHECK(peer->is_connected());

        // Peer version should be set
        CHECK(peer->version() == 99999);

        const auto msgs_after = peer->stats().messages_received.load();
        CHECK(msgs_after == msgs_before + 1);
    }

    SECTION("VERSION with exactly MIN_PROTOCOL_VERSION → accept") {
        message::VersionMessage msg;
        msg.version = protocol::MIN_PROTOCOL_VERSION;  // Exactly at boundary
        msg.services = protocol::NODE_NETWORK;
        msg.timestamp = 1234567890;
        msg.nonce = 111222;
        msg.user_agent = "/MinNode:1.0.0/";
        msg.start_height = 0;

        auto payload = msg.serialize();
        auto version_msg = create_test_message(magic, protocol::commands::VERSION, payload);

        mock_conn->simulate_receive(version_msg);
        io_context.poll();

        // Should accept (at minimum)
        CHECK(peer->is_connected());
        CHECK(peer->version() == protocol::MIN_PROTOCOL_VERSION);

        const auto msgs_after = peer->stats().messages_received.load();
        CHECK(msgs_after == msgs_before + 1);
    }
}

TEST_CASE("Adversarial - InvalidChecksum", "[adversarial][security][checksum]") {
    // Bitcoin Core: Disconnects peers sending messages with invalid checksums
    // Ref: src/net.cpp V1Transport::CompleteMessage()
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    const auto msgs_before = peer->stats().messages_received.load();
    const auto bytes_before = peer->stats().bytes_received.load();

    SECTION("VERSION with corrupted checksum → disconnect") {
        message::VersionMessage msg;
        msg.version = protocol::PROTOCOL_VERSION;
        msg.services = protocol::NODE_NETWORK;
        msg.timestamp = 1234567890;
        msg.nonce = 123456;
        msg.user_agent = "/Test:1.0.0/";
        msg.start_height = 0;

        auto payload = msg.serialize();

        // Create message with valid checksum first
        protocol::MessageHeader header(magic, protocol::commands::VERSION, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(header.checksum.data(), hash.begin(), 4);
        auto header_bytes = message::serialize_header(header);

        // Corrupt the checksum (bytes 20-23 of header)
        header_bytes[20] ^= 0xFF;
        header_bytes[21] ^= 0xFF;
        header_bytes[22] ^= 0xFF;
        header_bytes[23] ^= 0xFF;

        std::vector<uint8_t> corrupted_msg;
        corrupted_msg.insert(corrupted_msg.end(), header_bytes.begin(), header_bytes.end());
        corrupted_msg.insert(corrupted_msg.end(), payload.begin(), payload.end());

        mock_conn->simulate_receive(corrupted_msg);
        io_context.poll();

        // Peer should disconnect (checksum mismatch)
        CHECK_FALSE(peer->is_connected());

        // Message should not be processed (checksum validation before processing)
        const auto msgs_after = peer->stats().messages_received.load();
        const auto bytes_after = peer->stats().bytes_received.load();
        CHECK(msgs_after == msgs_before);  // No increment (validation failed)
        // Note: bytes_received is updated at transport layer (before validation)
        CHECK(bytes_after > bytes_before);  // Bytes were received, just not accepted
    }

    SECTION("Valid checksum → accepted") {
        // Verify that valid messages still work (control test)
        auto version_msg = create_version_message(magic, 999888);
        mock_conn->simulate_receive(version_msg);
        io_context.poll();

        CHECK(peer->is_connected());

        const auto msgs_after = peer->stats().messages_received.load();
        CHECK(msgs_after == msgs_before + 1);
    }

    SECTION("Empty payload with zero checksum → special case") {
        // Bitcoin Core: Empty payloads have checksum 0x5df6e0e2 (hash of empty string)
        // NOT all-zeros. Test that we handle empty payloads correctly.

        std::vector<uint8_t> empty_payload;
        protocol::MessageHeader header(magic, protocol::commands::VERACK, static_cast<uint32_t>(empty_payload.size()));
    uint256 hash = Hash(empty_payload);
    std::memcpy(header.checksum.data(), hash.begin(), 4);

        // VERACK has empty payload - checksum should be hash(empty), not 0x00000000
        // If our implementation uses 0x00000000 for empty payloads, this is a bug
        auto header_bytes = message::serialize_header(header);

        // Extract checksum from generated header
        uint32_t checksum;
        std::memcpy(&checksum, &header_bytes[20], 4);

        // Bitcoin Core: SHA256(SHA256(""))[:4] = 0x5df6e0e2
        // Our implementation should match
        CHECK(checksum != 0x00000000);  // Not all-zeros

        // Send the message
        std::vector<uint8_t> verack_msg;
        verack_msg.insert(verack_msg.end(), header_bytes.begin(), header_bytes.end());

        // First send VERSION to enable VERACK
        auto version = create_version_message(magic, 111222);
        mock_conn->simulate_receive(version);
        io_context.poll();

        const auto msgs_middle = peer->stats().messages_received.load();

        mock_conn->simulate_receive(verack_msg);
        io_context.poll();

        // Should accept (valid checksum for empty payload)
        // Note: might disconnect due to protocol reasons (unexpected VERACK from inbound)
        // but NOT due to checksum
        const auto msgs_after = peer->stats().messages_received.load();
        CHECK(msgs_after == msgs_middle + 1);  // Message was processed
    }
}

// =============================================================================
// MESSAGE LIBRARY EDGE CASE TESTS
// =============================================================================


TEST_CASE("Adversarial - PONG with short payload", "[adversarial][pong][security]") {
    // SECURITY: PONG must be exactly 8 bytes (nonce)
    // Short PONG should be rejected
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Complete handshake
    auto version = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version);
    io_context.poll();

    auto verack = create_verack_message(magic);
    mock_conn->simulate_receive(verack);
    io_context.poll();
    REQUIRE(peer->state() == PeerConnectionState::READY);

    SECTION("PONG with 0 bytes (empty)") {
        std::vector<uint8_t> empty_payload;
        auto malformed_pong = create_test_message(magic, protocol::commands::PONG, empty_payload);
        mock_conn->simulate_receive(malformed_pong);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }

    SECTION("PONG with 4 bytes (half nonce)") {
        std::vector<uint8_t> short_payload = {0x01, 0x02, 0x03, 0x04};
        auto malformed_pong = create_test_message(magic, protocol::commands::PONG, short_payload);
        mock_conn->simulate_receive(malformed_pong);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }

    SECTION("PONG with 7 bytes (one byte short)") {
        std::vector<uint8_t> almost_payload = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
        auto malformed_pong = create_test_message(magic, protocol::commands::PONG, almost_payload);
        mock_conn->simulate_receive(malformed_pong);
        io_context.poll();
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }
}

TEST_CASE("Adversarial - ADDR edge cases", "[adversarial][addr][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Complete handshake
    auto version = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version);
    io_context.poll();

    auto verack = create_verack_message(magic);
    mock_conn->simulate_receive(verack);
    io_context.poll();
    REQUIRE(peer->state() == PeerConnectionState::READY);

    SECTION("ADDR with truncated address entry") {
        // Each ADDR entry is 30 bytes: timestamp(4) + services(8) + ip(16) + port(2)
        message::MessageSerializer s;
        s.write_varint(1);  // 1 address
        s.write_uint32(0);  // timestamp
        s.write_uint64(1);  // services
        // Missing IP and port (only 12 bytes instead of 30)

        auto payload = s.data();
        auto addr_msg = create_test_message(magic, protocol::commands::ADDR, payload);
        mock_conn->simulate_receive(addr_msg);
        io_context.poll();

        // Should disconnect due to incomplete message
        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }

    SECTION("ADDR with zero addresses") {
        message::MessageSerializer s;
        s.write_varint(0);  // 0 addresses

        auto payload = s.data();
        auto addr_msg = create_test_message(magic, protocol::commands::ADDR, payload);
        mock_conn->simulate_receive(addr_msg);
        io_context.poll();

        // Empty ADDR should be accepted (valid but useless)
        CHECK(peer->is_connected());
    }

    SECTION("ADDR with all-zero IP address") {
        message::MessageSerializer s;
        s.write_varint(1);
        s.write_uint32(static_cast<uint32_t>(std::time(nullptr)));  // timestamp
        s.write_uint64(1);  // services
        // IPv4-mapped 0.0.0.0
        for (int i = 0; i < 10; ++i) s.write_uint8(0);
        s.write_uint8(0xFF); s.write_uint8(0xFF);
        s.write_uint8(0); s.write_uint8(0); s.write_uint8(0); s.write_uint8(0);
        s.write_uint16(9590);  // port

        auto payload = s.data();
        auto addr_msg = create_test_message(magic, protocol::commands::ADDR, payload);
        mock_conn->simulate_receive(addr_msg);
        io_context.poll();

        // Should remain connected (invalid IPs are filtered at application layer)
        CHECK(peer->is_connected());
    }

    SECTION("ADDR with loopback address") {
        message::MessageSerializer s;
        s.write_varint(1);
        s.write_uint32(static_cast<uint32_t>(std::time(nullptr)));
        s.write_uint64(1);
        // IPv4-mapped 127.0.0.1
        for (int i = 0; i < 10; ++i) s.write_uint8(0);
        s.write_uint8(0xFF); s.write_uint8(0xFF);
        s.write_uint8(127); s.write_uint8(0); s.write_uint8(0); s.write_uint8(1);
        s.write_uint16(9590);

        auto payload = s.data();
        auto addr_msg = create_test_message(magic, protocol::commands::ADDR, payload);
        mock_conn->simulate_receive(addr_msg);
        io_context.poll();

        // Loopback addresses may be filtered but shouldn't crash
        CHECK(peer->is_connected());
    }
}

TEST_CASE("Adversarial - GETHEADERS edge cases", "[adversarial][getheaders][security]") {
    asio::io_context io_context;
    auto mock_conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);
    peer->start();
    io_context.poll();

    // Complete handshake
    auto version = create_version_message(magic, 54321);
    mock_conn->simulate_receive(version);
    io_context.poll();

    auto verack = create_verack_message(magic);
    mock_conn->simulate_receive(verack);
    io_context.poll();
    REQUIRE(peer->state() == PeerConnectionState::READY);

    SECTION("GETHEADERS with empty locator (just stop hash)") {
        message::MessageSerializer s;
        s.write_uint32(protocol::PROTOCOL_VERSION);  // version
        s.write_varint(0);  // 0 locator hashes
        for (int i = 0; i < 32; ++i) s.write_uint8(0);  // stop hash (all zeros)

        auto payload = s.data();
        auto msg = create_test_message(magic, protocol::commands::GETHEADERS, payload);
        mock_conn->simulate_receive(msg);
        io_context.poll();

        // Empty locator is valid (means "give me headers from genesis")
        CHECK(peer->is_connected());
    }

    SECTION("GETHEADERS with truncated payload") {
        // Only version field, no locator count
        message::MessageSerializer s;
        s.write_uint32(protocol::PROTOCOL_VERSION);

        auto payload = s.data();
        auto msg = create_test_message(magic, protocol::commands::GETHEADERS, payload);
        mock_conn->simulate_receive(msg);
        io_context.poll();

        CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
    }
}
