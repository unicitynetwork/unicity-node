// Copyright (c) 2025 The Unicity Foundation
// Self-advertisement tests (Bitcoin Core parity)
// Tests for local address learning and periodic self-advertisement
//
// Tests cover:
// - LocalAddrLearnedHandler callback on both inbound and outbound peers
// - Private IP filtering in set_local_addr_from_peer_feedback()
// - ADDR message sent to full-relay peers only
// - Self-advertisement gating conditions (IBD, listen enabled)

#include "catch_amalgamated.hpp"
#include "network/peer.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"
#include "infra/mock_transport.hpp"
#include "util/hash.hpp"
#include "util/time.hpp"
#include <asio.hpp>

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

// Create VERSION message with specific addr_recv (what sender thinks receiver's address is)
static std::vector<uint8_t> create_version_message_with_addr_recv(
    uint32_t magic,
    uint64_t nonce,
    const std::string& addr_recv_ip,
    uint16_t addr_recv_port)
{
    message::VersionMessage msg;
    msg.version = protocol::PROTOCOL_VERSION;
    msg.services = protocol::NODE_NETWORK;
    msg.timestamp = util::GetTime();
    msg.nonce = nonce;
    msg.user_agent = "/Test:1.0.0/";
    msg.start_height = 0;
    msg.addr_recv = protocol::NetworkAddress::from_string(addr_recv_ip, addr_recv_port);
    msg.addr_from = protocol::NetworkAddress();  // Empty, like Bitcoin Core
    auto payload = msg.serialize();
    return create_test_message(magic, protocol::commands::VERSION, payload);
}

// =============================================================================
// PEER LOCAL ADDRESS LEARNING TESTS
// =============================================================================

TEST_CASE("Peer - LocalAddrLearnedHandler called for inbound peers", "[peer][self-advertisement]") {
    asio::io_context io_context;
    const uint32_t magic = protocol::magic::REGTEST;

    // Create inbound peer (they connected to us)
    auto mock_conn = std::make_shared<MockTransportConnection>("192.168.1.100", 12345);
    mock_conn->set_inbound(true);

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);

    // Track callback invocations
    std::string learned_ip;
    int callback_count = 0;

    peer->set_local_addr_learned_handler([&](const std::string& ip) {
        learned_ip = ip;
        callback_count++;
    });

    peer->start();
    io_context.poll();

    SECTION("Learns IP from VERSION addr_recv on inbound connection") {
        // Simulate receiving VERSION from inbound peer with our external IP
        const std::string our_external_ip = "203.0.113.50";
        const uint16_t our_port = protocol::ports::REGTEST;

        auto version_msg = create_version_message_with_addr_recv(
            magic, 0x1234567890ABCDEF, our_external_ip, our_port);
        mock_conn->simulate_receive(version_msg);
        io_context.poll();

        CHECK(callback_count == 1);
        CHECK(learned_ip == our_external_ip);
    }

    SECTION("Callback receives IP even for private addresses") {
        // Peer sends private IP - callback IS called (filtering is in NetworkManager)
        auto version_msg = create_version_message_with_addr_recv(
            magic, 0x1234567890ABCDEF, "192.168.1.50", protocol::ports::REGTEST);
        mock_conn->simulate_receive(version_msg);
        io_context.poll();

        // Callback is called - Peer extracts IP, NetworkManager decides whether to use it
        CHECK(callback_count == 1);
        CHECK(learned_ip == "192.168.1.50");
    }

    SECTION("Learns different external IP") {
        // Test with different routable IP
        const std::string external_ip = "198.51.100.25";

        auto version_msg = create_version_message_with_addr_recv(
            magic, 0xABCDEF1234567890, external_ip, protocol::ports::REGTEST);
        mock_conn->simulate_receive(version_msg);
        io_context.poll();

        CHECK(callback_count == 1);
        CHECK(learned_ip == external_ip);
    }
}

TEST_CASE("Peer - LocalAddrLearnedHandler called for outbound peers", "[peer][self-advertisement]") {
    asio::io_context io_context;
    const uint32_t magic = protocol::magic::REGTEST;

    // Create outbound peer (we connected to them)
    auto mock_conn = std::make_shared<MockTransportConnection>("192.168.1.100", 9590);
    mock_conn->set_inbound(false);

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);

    // Track callback invocations
    std::string learned_ip;
    int callback_count = 0;

    peer->set_local_addr_learned_handler([&](const std::string& ip) {
        learned_ip = ip;
        callback_count++;
    });

    peer->start();
    io_context.poll();

    // Simulate receiving VERSION from outbound peer
    auto version_msg = create_version_message_with_addr_recv(
        magic, 0x1234567890ABCDEF, "203.0.113.50", protocol::ports::REGTEST);
    mock_conn->simulate_receive(version_msg);
    io_context.poll();

    // Callback IS called for outbound peers (Bitcoin Core parity)
    // Bitcoin Core: SetAddrLocal() called for all peers (net_processing.cpp:3492)
    // GetLocalAddrForPeer() uses GetAddrLocal() from both peer types (net.cpp:249-262)
    // This enables self-advertisement for nodes that only make outbound connections.
    CHECK(callback_count == 1);
    CHECK(learned_ip == "203.0.113.50");
}

TEST_CASE("Peer - LocalAddrLearnedHandler not set does not crash", "[peer][self-advertisement][edge]") {
    asio::io_context io_context;
    const uint32_t magic = protocol::magic::REGTEST;

    auto mock_conn = std::make_shared<MockTransportConnection>("192.168.1.100", 12345);
    mock_conn->set_inbound(true);

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);

    // Deliberately NOT setting local_addr_learned_handler

    peer->start();
    io_context.poll();

    // Receive VERSION - should not crash even without handler
    auto version_msg = create_version_message_with_addr_recv(
        magic, 0x1234567890ABCDEF, "203.0.113.50", protocol::ports::REGTEST);

    REQUIRE_NOTHROW(mock_conn->simulate_receive(version_msg));
    io_context.poll();
}

TEST_CASE("Peer - LocalAddrLearnedHandler with zero addr_recv", "[peer][self-advertisement][edge]") {
    asio::io_context io_context;
    const uint32_t magic = protocol::magic::REGTEST;

    auto mock_conn = std::make_shared<MockTransportConnection>("192.168.1.100", 12345);
    mock_conn->set_inbound(true);

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);

    std::string learned_ip;
    int callback_count = 0;

    peer->set_local_addr_learned_handler([&](const std::string& ip) {
        learned_ip = ip;
        callback_count++;
    });

    peer->start();
    io_context.poll();

    // Create VERSION with all-zero addr_recv
    message::VersionMessage msg;
    msg.version = protocol::PROTOCOL_VERSION;
    msg.services = protocol::NODE_NETWORK;
    msg.timestamp = util::GetTime();
    msg.nonce = 0x1234567890ABCDEF;
    msg.user_agent = "/Test:1.0.0/";
    msg.start_height = 0;
    msg.addr_recv = protocol::NetworkAddress();  // All zeros
    msg.addr_from = protocol::NetworkAddress();

    auto payload = msg.serialize();
    auto version_msg = create_test_message(magic, protocol::commands::VERSION, payload);

    // Should not crash
    REQUIRE_NOTHROW(mock_conn->simulate_receive(version_msg));
    io_context.poll();

    // Callback may be called with "0.0.0.0" or similar, which NetworkManager will filter
}

TEST_CASE("Peer - LocalAddrLearnedHandler extracts IP without port", "[peer][self-advertisement]") {
    asio::io_context io_context;
    const uint32_t magic = protocol::magic::REGTEST;

    auto mock_conn = std::make_shared<MockTransportConnection>("192.168.1.100", 12345);
    mock_conn->set_inbound(true);

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);

    std::string learned_ip;

    peer->set_local_addr_learned_handler([&](const std::string& ip) {
        learned_ip = ip;
    });

    peer->start();
    io_context.poll();

    // Test that the callback receives just the IP, not IP:port
    auto version_msg = create_version_message_with_addr_recv(
        magic, 0x1234567890ABCDEF, "203.0.113.50", 29590);  // Non-standard port
    mock_conn->simulate_receive(version_msg);
    io_context.poll();

    // Should be just the IP, no port suffix
    CHECK(learned_ip == "203.0.113.50");
    CHECK(learned_ip.find(':') == std::string::npos);
}

// =============================================================================
// IPv6 ADDRESS LEARNING TESTS
// =============================================================================

TEST_CASE("Peer - LocalAddrLearnedHandler with IPv6 addresses", "[peer][self-advertisement][ipv6]") {
    asio::io_context io_context;
    const uint32_t magic = protocol::magic::REGTEST;

    auto mock_conn = std::make_shared<MockTransportConnection>("192.168.1.100", 12345);
    mock_conn->set_inbound(true);

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);

    std::string learned_ip;
    int callback_count = 0;

    peer->set_local_addr_learned_handler([&](const std::string& ip) {
        learned_ip = ip;
        callback_count++;
    });

    peer->start();
    io_context.poll();

    SECTION("Learns full IPv6 address correctly") {
        // Standard global unicast IPv6 address
        const std::string ipv6_addr = "2001:db8::1";

        auto version_msg = create_version_message_with_addr_recv(
            magic, 0x1234567890ABCDEF, ipv6_addr, protocol::ports::REGTEST);
        mock_conn->simulate_receive(version_msg);
        io_context.poll();

        CHECK(callback_count == 1);
        CHECK(learned_ip == ipv6_addr);
    }

    SECTION("Learns IPv6 address with multiple colons") {
        // IPv6 address with multiple segments (tests that colons aren't stripped)
        const std::string ipv6_addr = "2001:db8:85a3::8a2e:370:7334";

        auto version_msg = create_version_message_with_addr_recv(
            magic, 0x1234567890ABCDEF, ipv6_addr, protocol::ports::REGTEST);
        mock_conn->simulate_receive(version_msg);
        io_context.poll();

        CHECK(callback_count == 1);
        CHECK(learned_ip == ipv6_addr);
    }

    SECTION("Learns fully expanded IPv6 address") {
        // Fully expanded IPv6 address
        const std::string ipv6_addr = "2001:0db8:0000:0000:0000:0000:0000:0001";

        auto version_msg = create_version_message_with_addr_recv(
            magic, 0x1234567890ABCDEF, ipv6_addr, protocol::ports::REGTEST);
        mock_conn->simulate_receive(version_msg);
        io_context.poll();

        CHECK(callback_count == 1);
        // ASIO normalizes to compressed form
        CHECK((learned_ip == ipv6_addr || learned_ip == "2001:db8::1"));
    }

    SECTION("Learns IPv6 address ending in hex digits") {
        // IPv6 ending with hex that could be confused with port
        const std::string ipv6_addr = "2001:db8::abcd";

        auto version_msg = create_version_message_with_addr_recv(
            magic, 0x1234567890ABCDEF, ipv6_addr, protocol::ports::REGTEST);
        mock_conn->simulate_receive(version_msg);
        io_context.poll();

        CHECK(callback_count == 1);
        CHECK(learned_ip == ipv6_addr);
    }

    SECTION("Learns IPv6 loopback (filtering is done by NetworkManager)") {
        // Loopback - Peer passes it through, NetworkManager filters
        const std::string ipv6_loopback = "::1";

        auto version_msg = create_version_message_with_addr_recv(
            magic, 0x1234567890ABCDEF, ipv6_loopback, protocol::ports::REGTEST);
        mock_conn->simulate_receive(version_msg);
        io_context.poll();

        CHECK(callback_count == 1);
        CHECK(learned_ip == ipv6_loopback);
    }

    SECTION("Learns IPv6 link-local address") {
        // Link-local address - Peer passes it through, NetworkManager filters
        const std::string ipv6_linklocal = "fe80::1";

        auto version_msg = create_version_message_with_addr_recv(
            magic, 0x1234567890ABCDEF, ipv6_linklocal, protocol::ports::REGTEST);
        mock_conn->simulate_receive(version_msg);
        io_context.poll();

        CHECK(callback_count == 1);
        CHECK(learned_ip == ipv6_linklocal);
    }
}

TEST_CASE("Peer - LocalAddrLearnedHandler IPv6 outbound", "[peer][self-advertisement][ipv6]") {
    asio::io_context io_context;
    const uint32_t magic = protocol::magic::REGTEST;

    // Outbound connection to an IPv6 peer
    auto mock_conn = std::make_shared<MockTransportConnection>("2001:db8::100", 9590);
    mock_conn->set_inbound(false);

    auto peer = Peer::create_outbound(io_context, mock_conn, magic, 0);

    std::string learned_ip;
    int callback_count = 0;

    peer->set_local_addr_learned_handler([&](const std::string& ip) {
        learned_ip = ip;
        callback_count++;
    });

    peer->start();
    io_context.poll();

    // Peer tells us our IPv6 address
    const std::string our_ipv6 = "2001:db8::50";
    auto version_msg = create_version_message_with_addr_recv(
        magic, 0x1234567890ABCDEF, our_ipv6, protocol::ports::REGTEST);
    mock_conn->simulate_receive(version_msg);
    io_context.poll();

    CHECK(callback_count == 1);
    CHECK(learned_ip == our_ipv6);
}

TEST_CASE("Peer - IPv4-mapped IPv6 addresses", "[peer][self-advertisement][ipv6]") {
    asio::io_context io_context;
    const uint32_t magic = protocol::magic::REGTEST;

    auto mock_conn = std::make_shared<MockTransportConnection>("192.168.1.100", 12345);
    mock_conn->set_inbound(true);

    auto peer = Peer::create_inbound(io_context, mock_conn, magic, 0);

    std::string learned_ip;

    peer->set_local_addr_learned_handler([&](const std::string& ip) {
        learned_ip = ip;
    });

    peer->start();
    io_context.poll();

    // IPv4-mapped IPv6 address - NetworkAddress::to_string() normalizes to IPv4
    // The wire format stores as IPv4-mapped, but to_string() returns pure IPv4
    const std::string ipv4_addr = "203.0.113.50";
    auto version_msg = create_version_message_with_addr_recv(
        magic, 0x1234567890ABCDEF, ipv4_addr, protocol::ports::REGTEST);
    mock_conn->simulate_receive(version_msg);
    io_context.poll();

    // Should get back pure IPv4, not ::ffff:203.0.113.50
    CHECK(learned_ip == ipv4_addr);
    CHECK(learned_ip.find("::ffff:") == std::string::npos);
}

// =============================================================================
// SELF-ADVERTISEMENT INTEGRATION TESTS
// =============================================================================

// These tests require SimulatedNetwork infrastructure
// See test/network/addr/self_advertisement_integration_tests.cpp for full integration tests
