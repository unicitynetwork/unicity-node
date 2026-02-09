// Copyright (c) 2025 The Unicity Foundation
// Node Simulator - Test utility for P2P protocol testing
//
// This tool connects to a node and sends custom P2P messages to test
// protocol behavior and DoS protection mechanisms. It should ONLY be used for testing on private networks.

#include <asio.hpp>
#include <iostream>
#include <vector>
#include <cstring>
#include <thread>
#include <chrono>
#include <cstdint>
#include <algorithm>
#include <random>

#include "network/protocol.hpp"
#include "network/message.hpp"
#include "chain/block.hpp"
#include "util/hash.hpp"

using namespace unicity;

class NodeSimulator {
public:
    NodeSimulator(asio::io_context& io_context, const std::string& host, uint16_t port)
        : socket_(io_context), host_(host), port_(port)
    {
    }

    bool connect() {
        try {
            asio::ip::tcp::resolver resolver(socket_.get_executor());
            auto endpoints = resolver.resolve(host_, std::to_string(port_));
            asio::connect(socket_, endpoints);
            std::cout << "✓ Connected to " << host_ << ":" << port_ << std::endl;
            return true;
        } catch (const std::exception& e) {
            std::cerr << "✗ Connection failed: " << e.what() << std::endl;
            return false;
        }
    }

    // Returns true if message was fully sent, false if connection was closed during send
    // (connection close during send is expected for some adversarial tests)
    bool send_raw_message(const std::string& command, const std::vector<uint8_t>& payload) {
        protocol::MessageHeader header(protocol::magic::REGTEST, command, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(header.checksum.data(), hash.begin(), 4);
        auto header_bytes = message::serialize_header(header);

        std::vector<uint8_t> full_message;
        full_message.insert(full_message.end(), header_bytes.begin(), header_bytes.end());
        full_message.insert(full_message.end(), payload.begin(), payload.end());

        try {
            asio::write(socket_, asio::buffer(full_message));
            std::cout << "→ Sent " << command << " (" << payload.size() << " bytes)" << std::endl;
            return true;
        } catch (const asio::system_error& e) {
            // Connection closed during write - expected for large adversarial messages
            // where the node rejects based on declared size in header
            std::cout << "→ Sent " << command << " header, connection closed during payload" << std::endl;
            std::cout << "  (This is expected - node rejected oversized message)" << std::endl;
            return false;
        }
    }

    void send_version() {
        message::VersionMessage msg;
        msg.version = protocol::PROTOCOL_VERSION;
        msg.services = protocol::NODE_NETWORK;
        msg.timestamp = std::time(nullptr);
        msg.addr_recv = protocol::NetworkAddress();
        msg.addr_from = protocol::NetworkAddress();
        // Use random nonce to avoid collision disconnects on repeated runs
        std::mt19937_64 rng(static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));
        msg.nonce = rng();
        msg.user_agent = "/NodeSimulator:0.1.0/";
        msg.start_height = 0;

        auto payload = msg.serialize();
        send_raw_message(protocol::commands::VERSION, payload);
    }

    void send_verack() {
        message::VerackMessage msg;
        auto payload = msg.serialize();
        send_raw_message(protocol::commands::VERACK, payload);
    }

    // Helper: send header then drip payload in chunks (slow-loris)
    void send_chunked(const std::string& command,
                      const std::vector<uint8_t>& payload,
                      size_t chunk_size,
                      int delay_ms,
                      size_t max_bytes_to_send,
                      bool close_early) {
        protocol::MessageHeader header(protocol::magic::REGTEST, command, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(header.checksum.data(), hash.begin(), 4);
        auto header_bytes = message::serialize_header(header);
        // Send header
        asio::write(socket_, asio::buffer(header_bytes));
        // Drip payload
        size_t sent = 0;
        while (sent < payload.size() && sent < max_bytes_to_send) {
            size_t n = std::min(chunk_size, payload.size() - sent);
            asio::write(socket_, asio::buffer(payload.data() + sent, n));
            sent += n;
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
        }
        if (close_early) {
            // Close socket to simulate truncation/timeout end
            try { socket_.shutdown(asio::ip::tcp::socket::shutdown_both); } catch (...) {}
            try { socket_.close(); } catch (...) {}
        }
        std::cout << "→ Slow-loris sent " << sent << " / " << payload.size() << " bytes of payload" << std::endl;
    }

    // Attack: Send headers with invalid PoW
    void test_invalid_pow(const uint256& prev_hash) {
        std::cout << "\n=== TEST: Invalid PoW ===" << std::endl;

        CBlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock = prev_hash;
        header.minerAddress.SetNull();
        header.nTime = std::time(nullptr);
        header.nBits = 0x00000001;  // Impossible difficulty
        header.nNonce = 0;
        header.hashRandomX.SetNull();

        std::vector<CBlockHeader> headers = {header};
        message::HeadersMessage msg;
        msg.headers = headers;
        auto payload = msg.serialize();
        send_raw_message(protocol::commands::HEADERS, payload);

        std::cout << "Expected: Peer should be disconnected immediately (score=100)" << std::endl;
    }

    // Attack: Send oversized headers message
    void test_oversized_headers() {
        std::cout << "\n=== TEST: Oversized Headers ===" << std::endl;

        // Create more than MAX_HEADERS_SIZE headers
        // Use MAX_HEADERS_SIZE + 100 headers - just over the limit
        // Note: With MAX_HEADERS_SIZE=80000, this creates a large message (~8MB)
        std::vector<CBlockHeader> headers;

        // Use a valid-looking RandomX hash for regtest
        uint256 dummyRandomXHash;
        dummyRandomXHash.SetHex("0000000000000000000000000000000000000000000000000000000000000000");

        CBlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock.SetNull();
        header.minerAddress.SetNull();
        header.nTime = std::time(nullptr);
        header.nBits = 0x207fffff;
        header.nNonce = 0;
        header.hashRandomX = dummyRandomXHash;  // Non-null for commitment check

        // Send MAX_HEADERS_SIZE + 100 headers (just over the limit)
        const size_t count = protocol::MAX_HEADERS_SIZE + 100;
        for (size_t i = 0; i < count; i++) {
            headers.push_back(header);
        }

        message::HeadersMessage msg;
        msg.headers = headers;
        auto payload = msg.serialize();
        send_raw_message(protocol::commands::HEADERS, payload);

        std::cout << "Expected: Misbehavior +20 (oversized-headers)" << std::endl;
    }

    // Attack: Send non-continuous headers
    void test_non_continuous_headers(const uint256& prev_hash) {
        std::cout << "\n=== TEST: Non-Continuous Headers ===" << std::endl;

        // Create headers that don't connect
        // Use a very small dummy RandomX hash that will pass regtest commitment check
        // For regtest (0x207fffff = max target), commitment must be < target
        // Use all zeros which will definitely pass
        uint256 dummyRandomXHash;
        dummyRandomXHash.SetHex("0000000000000000000000000000000000000000000000000000000000000000");

        CBlockHeader header1;
        header1.nVersion = 1;
        header1.hashPrevBlock = prev_hash;
        header1.minerAddress.SetNull();
        header1.nTime = std::time(nullptr);
        header1.nBits = 0x207fffff;
        header1.nNonce = 1;
        header1.hashRandomX = dummyRandomXHash;  // Valid-looking (non-null) RandomX hash

        CBlockHeader header2;
        header2.nVersion = 1;
        header2.hashPrevBlock.SetNull();  // Wrong! Doesn't connect to header1
        header2.minerAddress.SetNull();
        header2.nTime = std::time(nullptr);
        header2.nBits = 0x207fffff;
        header2.nNonce = 2;
        header2.hashRandomX = dummyRandomXHash;  // Valid-looking (non-null) RandomX hash

        std::vector<CBlockHeader> headers = {header1, header2};
        message::HeadersMessage msg;
        msg.headers = headers;
        auto payload = msg.serialize();
        send_raw_message(protocol::commands::HEADERS, payload);

        std::cout << "Expected: Misbehavior +20 (non-continuous-headers)" << std::endl;
    }

    // Attack: Bad magic in message header
    void test_bad_magic() {
        std::cout << "\n=== TEST: Bad Magic ===" << std::endl;
        // Small dummy payload
        std::vector<uint8_t> payload = {0x00};
        protocol::MessageHeader hdr(protocol::magic::REGTEST, protocol::commands::HEADERS, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(hdr.checksum.data(), hash.begin(), 4);
        auto hdr_bytes = message::serialize_header(hdr);
        // Overwrite first 4 bytes (magic)
        uint8_t bad[4] = {0xDE, 0xAD, 0xBE, 0xEF};
        std::copy(bad, bad + 4, hdr_bytes.begin());
        std::vector<uint8_t> full; full.reserve(hdr_bytes.size() + payload.size());
        full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());
        asio::write(socket_, asio::buffer(full));
        std::cout << "Expected: Immediate disconnect due to bad magic" << std::endl;
    }

    // Attack: Bad checksum in header
    void test_bad_checksum() {
        std::cout << "\n=== TEST: Bad Checksum ===" << std::endl;
        std::vector<uint8_t> payload = {0x00};
        protocol::MessageHeader hdr(protocol::magic::REGTEST, protocol::commands::HEADERS, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(hdr.checksum.data(), hash.begin(), 4);
        auto hdr_bytes = message::serialize_header(hdr);
        // Flip one byte in checksum (offset 20..23: checksum)
        if (hdr_bytes.size() >= 24) {
            hdr_bytes[20] ^= 0xFF;
        }
        std::vector<uint8_t> full; full.reserve(hdr_bytes.size() + payload.size());
        full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());
        asio::write(socket_, asio::buffer(full));
        std::cout << "Expected: Disconnect due to checksum mismatch" << std::endl;
    }

    // Attack: Declared length larger than actual payload (then close)
    void test_bad_length() {
        std::cout << "\n=== TEST: Bad Length (len > actual) ===" << std::endl;
        std::vector<uint8_t> payload(64, 0x00);
        protocol::MessageHeader hdr(protocol::magic::REGTEST, protocol::commands::HEADERS, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(hdr.checksum.data(), hash.begin(), 4);
        auto hdr_bytes = message::serialize_header(hdr);
        // Increase little-endian length at bytes 16..19
        if (hdr_bytes.size() >= 24) {
            uint32_t len = hdr_bytes[16] | (hdr_bytes[17] << 8) | (hdr_bytes[18] << 16) | (hdr_bytes[19] << 24);
            uint32_t bumped = len + 100;
            hdr_bytes[16] = (uint8_t)(bumped & 0xFF);
            hdr_bytes[17] = (uint8_t)((bumped >> 8) & 0xFF);
            hdr_bytes[18] = (uint8_t)((bumped >> 16) & 0xFF);
            hdr_bytes[19] = (uint8_t)((bumped >> 24) & 0xFF);
        }
        std::vector<uint8_t> full; full.reserve(hdr_bytes.size() + payload.size());
        full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());
        // Send header + actual payload only, then close (truncation vs declared)
        asio::write(socket_, asio::buffer(full));
        try { socket_.shutdown(asio::ip::tcp::socket::shutdown_both); } catch (...) {}
        try { socket_.close(); } catch (...) {}
        std::cout << "Sent bad-length message and closed; node should handle EOF cleanly" << std::endl;
    }

    // Attack: Truncated payload (header length correct, but close early)
    void test_truncation() {
        std::cout << "\n=== TEST: Truncation ===" << std::endl;
        // Build a payload (e.g., 512 bytes) and send half
        std::vector<uint8_t> payload(512, 0x00);
        protocol::MessageHeader hdr(protocol::magic::REGTEST, protocol::commands::HEADERS, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(hdr.checksum.data(), hash.begin(), 4);
        auto hdr_bytes = message::serialize_header(hdr);
        asio::write(socket_, asio::buffer(hdr_bytes));
        size_t half = payload.size() / 2;
        asio::write(socket_, asio::buffer(payload.data(), half));
        try { socket_.shutdown(asio::ip::tcp::socket::shutdown_both); } catch (...) {}
        try { socket_.close(); } catch (...) {}
        std::cout << "Sent half payload then closed" << std::endl;
    }

    // Attack: Empty command field
    void test_empty_command() {
        std::cout << "\n=== TEST: Empty Command ===" << std::endl;
        std::cout << "Sending message with empty command field..." << std::endl;

        std::vector<uint8_t> payload = {0x00};
        // Build header manually with empty command
        std::vector<uint8_t> hdr_bytes(protocol::MESSAGE_HEADER_SIZE);
        // Magic (regtest)
        uint32_t magic = protocol::magic::REGTEST;
        std::memcpy(hdr_bytes.data(), &magic, 4);
        // Command - all zeros (empty)
        std::memset(hdr_bytes.data() + 4, 0, 12);
        // Length
        uint32_t len = static_cast<uint32_t>(payload.size());
        std::memcpy(hdr_bytes.data() + 16, &len, 4);
        // Checksum
        uint256 hash = Hash(payload);
        std::memcpy(hdr_bytes.data() + 20, hash.begin(), 4);

        std::vector<uint8_t> full;
        full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());
        asio::write(socket_, asio::buffer(full));

        std::cout << "Expected: Node should handle gracefully (unknown command)" << std::endl;
    }

    // Attack: Declared length < actual payload
    void test_length_less_than_actual() {
        std::cout << "\n=== TEST: Length Less Than Actual ===" << std::endl;
        std::cout << "Sending message with declared length < actual payload..." << std::endl;

        // Build a 100-byte payload but declare only 10 bytes
        std::vector<uint8_t> payload(100, 0x41);  // 'A' bytes
        std::vector<uint8_t> hdr_bytes(protocol::MESSAGE_HEADER_SIZE);

        uint32_t magic = protocol::magic::REGTEST;
        std::memcpy(hdr_bytes.data(), &magic, 4);
        // Command: "headers"
        const char* cmd = "headers";
        std::memset(hdr_bytes.data() + 4, 0, 12);
        std::memcpy(hdr_bytes.data() + 4, cmd, strlen(cmd));
        // Declare only 10 bytes (less than actual 100)
        uint32_t len = 10;
        std::memcpy(hdr_bytes.data() + 16, &len, 4);
        // Checksum of the DECLARED portion only
        std::vector<uint8_t> declared_payload(payload.begin(), payload.begin() + 10);
        uint256 hash = Hash(declared_payload);
        std::memcpy(hdr_bytes.data() + 20, hash.begin(), 4);

        std::vector<uint8_t> full;
        full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());  // Send full 100 bytes
        asio::write(socket_, asio::buffer(full));

        std::cout << "Expected: Node reads declared length, extra bytes interpreted as next message" << std::endl;
    }

    // Attack: Declared length exceeds MAX_PROTOCOL_MESSAGE_LENGTH
    void test_length_exceeds_max() {
        std::cout << "\n=== TEST: Length Exceeds Max ===" << std::endl;
        std::cout << "Sending message with length > MAX_PROTOCOL_MESSAGE_LENGTH (8MB)..." << std::endl;

        std::vector<uint8_t> payload = {0x00};
        std::vector<uint8_t> hdr_bytes(protocol::MESSAGE_HEADER_SIZE);

        uint32_t magic = protocol::magic::REGTEST;
        std::memcpy(hdr_bytes.data(), &magic, 4);
        const char* cmd = "headers";
        std::memset(hdr_bytes.data() + 4, 0, 12);
        std::memcpy(hdr_bytes.data() + 4, cmd, strlen(cmd));
        // Declare 16MB (exceeds 8MB limit)
        uint32_t len = 16 * 1024 * 1024;
        std::memcpy(hdr_bytes.data() + 16, &len, 4);
        uint256 hash = Hash(payload);
        std::memcpy(hdr_bytes.data() + 20, hash.begin(), 4);

        // Just send header, don't bother with payload
        asio::write(socket_, asio::buffer(hdr_bytes));

        std::cout << "Expected: Node should reject oversized message immediately" << std::endl;
    }

    // Attack: Spam with repeated non-continuous headers
    void test_spam_non_continuous(const uint256& prev_hash, int count) {
        std::cout << "\n=== TEST: Spam Non-Continuous Headers (" << count << " times) ===" << std::endl;

        for (int i = 0; i < count; i++) {
            test_non_continuous_headers(prev_hash);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        std::cout << "Expected: After 5 violations (5*20=100), peer should be disconnected" << std::endl;
    }

    // ========== Phase 1: Protocol Handshake Attacks ==========

    // Attack: Send protocol message before handshake (no VERSION/VERACK)
    void test_pre_handshake_headers() {
        std::cout << "\n=== TEST: Pre-Handshake Headers ===" << std::endl;
        std::cout << "Sending HEADERS without completing handshake..." << std::endl;

        // Create a simple headers message
        CBlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock.SetNull();
        header.minerAddress.SetNull();
        header.nTime = std::time(nullptr);
        header.nBits = 0x207fffff;
        header.nNonce = 0;
        header.hashRandomX.SetNull();

        std::vector<CBlockHeader> headers = {header};
        message::HeadersMessage msg;
        msg.headers = headers;
        auto payload = msg.serialize();
        send_raw_message(protocol::commands::HEADERS, payload);

        std::cout << "Expected: Node should reject/disconnect (pre-VERACK message)" << std::endl;
    }

    // Attack: Send GETHEADERS before handshake
    void test_pre_handshake_getheaders() {
        std::cout << "\n=== TEST: Pre-Handshake GetHeaders ===" << std::endl;
        std::cout << "Sending GETHEADERS without completing handshake..." << std::endl;

        message::GetHeadersMessage msg;
        msg.version = protocol::PROTOCOL_VERSION;
        msg.block_locator_hashes = {};  // Empty locator
        msg.hash_stop.SetNull();
        auto payload = msg.serialize();
        send_raw_message(protocol::commands::GETHEADERS, payload);

        std::cout << "Expected: Node should reject/disconnect (pre-VERACK message)" << std::endl;
    }

    // Attack: Send INV before handshake
    void test_pre_handshake_inv() {
        std::cout << "\n=== TEST: Pre-Handshake INV ===" << std::endl;
        std::cout << "Sending INV without completing handshake..." << std::endl;

        // Create a simple INV message with one block hash
        std::vector<uint8_t> payload;
        // Count (varint) = 1
        payload.push_back(0x01);
        // Type = MSG_BLOCK (2)
        payload.push_back(0x02);
        payload.push_back(0x00);
        payload.push_back(0x00);
        payload.push_back(0x00);
        // 32-byte hash (zeros)
        for (int i = 0; i < 32; i++) payload.push_back(0x00);

        send_raw_message("inv", payload);

        std::cout << "Expected: Node should reject/disconnect (pre-VERACK message)" << std::endl;
    }

    // Attack: Send VERACK without first receiving VERSION
    void test_verack_without_version() {
        std::cout << "\n=== TEST: VERACK Without VERSION ===" << std::endl;
        std::cout << "Sending VERACK without sending VERSION first..." << std::endl;

        message::VerackMessage msg;
        auto payload = msg.serialize();
        send_raw_message(protocol::commands::VERACK, payload);

        std::cout << "Expected: Node should reject/disconnect" << std::endl;
    }

    // Attack: Send GETDATA before handshake
    void test_pre_handshake_getdata() {
        std::cout << "\n=== TEST: Pre-Handshake GETDATA ===" << std::endl;
        std::cout << "Sending GETDATA without completing handshake..." << std::endl;

        // Create a simple GETDATA message
        std::vector<uint8_t> payload;
        // Count = 1
        payload.push_back(0x01);
        // Type = MSG_BLOCK (2)
        uint32_t type = 2;
        payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&type), reinterpret_cast<uint8_t*>(&type) + 4);
        // 32-byte hash (zeros)
        for (int i = 0; i < 32; i++) payload.push_back(0x00);

        send_raw_message("getdata", payload);

        std::cout << "Expected: Node should reject/disconnect (pre-VERACK message)" << std::endl;
    }

    // Attack: Send multiple VERACK messages
    void test_multi_verack() {
        std::cout << "\n=== TEST: Multiple VERACK ===" << std::endl;
        std::cout << "Sending VERACK twice after handshake..." << std::endl;

        message::VerackMessage msg;
        auto payload = msg.serialize();
        send_raw_message(protocol::commands::VERACK, payload);
        send_raw_message(protocol::commands::VERACK, payload);

        std::cout << "Expected: Node should handle gracefully or disconnect" << std::endl;
    }

    // Attack: Send partial/incomplete VERSION message
    void test_partial_version() {
        std::cout << "\n=== TEST: Partial VERSION ===" << std::endl;
        std::cout << "Sending incomplete VERSION message then closing..." << std::endl;

        // Build a partial VERSION - just first 20 bytes of what should be ~100 bytes
        std::vector<uint8_t> partial_payload(20, 0x00);
        // Set version field
        int32_t version = protocol::PROTOCOL_VERSION;
        std::memcpy(partial_payload.data(), &version, 4);

        // Build header with correct length for full message but only send partial
        protocol::MessageHeader hdr(protocol::magic::REGTEST, protocol::commands::VERSION, 100);  // Claim 100 bytes
        uint256 hash = Hash(partial_payload);
        std::memcpy(hdr.checksum.data(), hash.begin(), 4);
        auto hdr_bytes = message::serialize_header(hdr);

        // Send header + partial payload
        try {
            asio::write(socket_, asio::buffer(hdr_bytes));
            asio::write(socket_, asio::buffer(partial_payload));
        } catch (const std::exception& e) {
            std::cout << "  Write failed (expected for truncated message): " << e.what() << std::endl;
        }

        // Close connection
        try { socket_.shutdown(asio::ip::tcp::socket::shutdown_both); } catch (...) {}
        try { socket_.close(); } catch (...) {}

        std::cout << "Expected: Node should handle truncation gracefully" << std::endl;
    }

    // Attack: Command with null bytes embedded
    void test_command_null_bytes() {
        std::cout << "\n=== TEST: Command With Null Bytes ===" << std::endl;
        std::cout << "Sending message with null bytes in command field..." << std::endl;

        std::vector<uint8_t> payload = {0x00};
        std::vector<uint8_t> hdr_bytes(protocol::MESSAGE_HEADER_SIZE);

        uint32_t magic = protocol::magic::REGTEST;
        std::memcpy(hdr_bytes.data(), &magic, 4);
        // Command: "ver\x00sion\x00\x00\x00\x00" - null byte in middle
        const char cmd[] = "ver\x00sion";
        std::memset(hdr_bytes.data() + 4, 0, 12);
        std::memcpy(hdr_bytes.data() + 4, cmd, 8);
        // Length
        uint32_t len = static_cast<uint32_t>(payload.size());
        std::memcpy(hdr_bytes.data() + 16, &len, 4);
        // Checksum
        uint256 hash = Hash(payload);
        std::memcpy(hdr_bytes.data() + 20, hash.begin(), 4);

        std::vector<uint8_t> full;
        full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());
        try {
            asio::write(socket_, asio::buffer(full));
        } catch (const std::exception& e) {
            std::cout << "  Write failed: " << e.what() << std::endl;
        }

        std::cout << "Expected: Node should treat as unknown command" << std::endl;
    }

    // Attack: Command with non-ASCII characters
    void test_command_non_ascii() {
        std::cout << "\n=== TEST: Command With Non-ASCII ===" << std::endl;
        std::cout << "Sending message with binary/non-ASCII command..." << std::endl;

        std::vector<uint8_t> payload = {0x00};
        std::vector<uint8_t> hdr_bytes(protocol::MESSAGE_HEADER_SIZE);

        uint32_t magic = protocol::magic::REGTEST;
        std::memcpy(hdr_bytes.data(), &magic, 4);
        // Command: binary garbage
        uint8_t bad_cmd[12] = {0xFF, 0xFE, 0x80, 0x81, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x00};
        std::memcpy(hdr_bytes.data() + 4, bad_cmd, 12);
        // Length
        uint32_t len = static_cast<uint32_t>(payload.size());
        std::memcpy(hdr_bytes.data() + 16, &len, 4);
        // Checksum
        uint256 hash = Hash(payload);
        std::memcpy(hdr_bytes.data() + 20, hash.begin(), 4);

        std::vector<uint8_t> full;
        full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());
        try {
            asio::write(socket_, asio::buffer(full));
        } catch (const std::exception& e) {
            std::cout << "  Write failed: " << e.what() << std::endl;
        }

        std::cout << "Expected: Node should treat as unknown command" << std::endl;
    }

    // Attack: Rapid fire messages (1000/sec)
    void test_rapid_fire(int count = 500) {
        std::cout << "\n=== TEST: Rapid Fire (" << count << " messages) ===" << std::endl;
        std::cout << "Sending messages as fast as possible..." << std::endl;

        auto start = std::chrono::high_resolution_clock::now();

        for (int i = 0; i < count; i++) {
            // Send small PING-like messages
            std::vector<uint8_t> payload(8, 0x00);  // 8-byte nonce
            send_raw_message(protocol::commands::PING, payload);
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double rate = (count * 1000.0) / duration;

        std::cout << "Sent " << count << " messages in " << duration << "ms (" << rate << " msg/sec)" << std::endl;
        std::cout << "Expected: Node should handle without crashing" << std::endl;
    }

    // Attack: Connect but never send any message
    void test_silent_connection(int wait_seconds = 5) {
        std::cout << "\n=== TEST: Silent Connection ===" << std::endl;
        std::cout << "Connected but sending nothing for " << wait_seconds << " seconds..." << std::endl;

        std::this_thread::sleep_for(std::chrono::seconds(wait_seconds));

        std::cout << "Expected: Node should timeout and disconnect" << std::endl;
    }

    // Attack: Start handshake but never complete it (send VERSION, never VERACK)
    void test_stalled_handshake(int stall_seconds = 5) {
        std::cout << "\n=== TEST: Stalled Handshake ===" << std::endl;
        std::cout << "Sending VERSION but NOT sending VERACK..." << std::endl;

        send_version();
        std::cout << "Stalling for " << stall_seconds << " seconds (not sending VERACK)..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(stall_seconds));

        std::cout << "Expected: Node should timeout/cleanup stalled connection" << std::endl;
    }

    // Attack: Send duplicate VERSION after handshake complete
    void test_duplicate_version() {
        std::cout << "\n=== TEST: Duplicate VERSION ===" << std::endl;
        std::cout << "Sending second VERSION message after handshake..." << std::endl;

        send_version();

        std::cout << "Expected: Node should reject duplicate VERSION" << std::endl;
    }

    // Attack: Send VERSION with invalid fields
    void test_bad_version() {
        std::cout << "\n=== TEST: Bad VERSION Fields ===" << std::endl;

        message::VersionMessage msg;
        msg.version = 0;  // Invalid version
        msg.services = 0;
        msg.timestamp = 0;  // Invalid timestamp
        msg.addr_recv = protocol::NetworkAddress();
        msg.addr_from = protocol::NetworkAddress();
        msg.nonce = 0;
        msg.user_agent = std::string(1000, 'A');  // Oversized user agent
        msg.start_height = -1;  // Negative height

        auto payload = msg.serialize();
        send_raw_message(protocol::commands::VERSION, payload);

        std::cout << "Expected: Node should handle gracefully (may disconnect)" << std::endl;
    }

    // Attack: Send unknown command
    void test_unknown_command() {
        std::cout << "\n=== TEST: Unknown Command ===" << std::endl;

        std::vector<uint8_t> payload = {0x00, 0x01, 0x02, 0x03};
        send_raw_message("foobarxyz", payload);  // Unknown 9-char command

        std::cout << "Expected: Node should silently ignore unknown commands (Bitcoin Core parity)" << std::endl;
    }

    // Test: Flood unknown commands (should be silently ignored)
    void test_unknown_command_flood(int count = 25) {
        std::cout << "\n=== TEST: Unknown Command Flood (" << count << "x) ===" << std::endl;
        std::cout << "Sending " << count << " unknown commands rapidly..." << std::endl;

        std::vector<uint8_t> payload = {0x00};
        for (int i = 0; i < count; i++) {
            send_raw_message("unknown", payload);
        }

        std::cout << "Expected: Node should silently ignore all unknown commands (Bitcoin Core parity)" << std::endl;
    }

    // ========== Phase 2: Header Validation Attacks ==========

    // Attack: Send headers with timestamp far in the future
    void test_future_timestamp() {
        std::cout << "\n=== TEST: Future Timestamp Headers ===" << std::endl;
        std::cout << "Sending headers with timestamp > now + MAX_FUTURE_BLOCK_TIME (10 min)..." << std::endl;

        // Create header with timestamp 1 hour in the future
        CBlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock.SetNull();
        header.minerAddress.SetNull();
        header.nTime = std::time(nullptr) + 3600;  // 1 hour in future (exceeds 10 min limit)
        header.nBits = 0x207fffff;  // Regtest difficulty
        header.nNonce = 0;
        header.hashRandomX.SetNull();

        std::vector<CBlockHeader> headers = {header};
        message::HeadersMessage msg;
        msg.headers = headers;
        auto payload = msg.serialize();
        send_raw_message(protocol::commands::HEADERS, payload);

        std::cout << "Expected: Node should reject headers with future timestamps" << std::endl;
    }

    // Attack: Send headers with timestamp = 0
    void test_timestamp_zero() {
        std::cout << "\n=== TEST: Zero Timestamp Headers ===" << std::endl;
        std::cout << "Sending headers with timestamp = 0..." << std::endl;

        CBlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock.SetNull();
        header.minerAddress.SetNull();
        header.nTime = 0;  // Invalid - timestamp zero
        header.nBits = 0x207fffff;
        header.nNonce = 0;
        header.hashRandomX.SetNull();

        std::vector<CBlockHeader> headers = {header};
        message::HeadersMessage msg;
        msg.headers = headers;
        auto payload = msg.serialize();
        send_raw_message(protocol::commands::HEADERS, payload);

        std::cout << "Expected: Node should reject headers with zero timestamp" << std::endl;
    }

    // Attack: Send headers with nBits = 0 (impossible difficulty)
    void test_nbits_zero() {
        std::cout << "\n=== TEST: Zero nBits Headers ===" << std::endl;
        std::cout << "Sending headers with nBits = 0 (impossible difficulty)..." << std::endl;

        CBlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock.SetNull();
        header.minerAddress.SetNull();
        header.nTime = std::time(nullptr);
        header.nBits = 0;  // Invalid - impossible difficulty
        header.nNonce = 0;
        header.hashRandomX.SetNull();

        std::vector<CBlockHeader> headers = {header};
        message::HeadersMessage msg;
        msg.headers = headers;
        auto payload = msg.serialize();
        send_raw_message(protocol::commands::HEADERS, payload);

        std::cout << "Expected: Node should reject headers with invalid nBits" << std::endl;
    }

    // Attack: Send headers with nBits = max (trivial difficulty)
    void test_nbits_max() {
        std::cout << "\n=== TEST: Max nBits Headers ===" << std::endl;
        std::cout << "Sending headers with nBits = 0xFFFFFFFF (trivial difficulty)..." << std::endl;

        CBlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock.SetNull();
        header.minerAddress.SetNull();
        header.nTime = std::time(nullptr);
        header.nBits = 0xFFFFFFFF;  // Invalid - trivial difficulty
        header.nNonce = 0;
        header.hashRandomX.SetNull();

        std::vector<CBlockHeader> headers = {header};
        message::HeadersMessage msg;
        msg.headers = headers;
        auto payload = msg.serialize();
        send_raw_message(protocol::commands::HEADERS, payload);

        std::cout << "Expected: Node should reject headers with invalid nBits" << std::endl;
    }

    // Attack: Send header with self-referential prevblock (points to itself)
    void test_self_referential() {
        std::cout << "\n=== TEST: Self-Referential Header ===" << std::endl;
        std::cout << "Sending header where prevblock = own hash..." << std::endl;

        // Create a header first to get its hash
        CBlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock.SetNull();
        header.minerAddress.SetNull();
        header.nTime = std::time(nullptr);
        header.nBits = 0x207fffff;
        header.nNonce = 12345;
        header.hashRandomX.SetNull();

        // Calculate the header's hash
        uint256 header_hash = header.GetHash();

        // Now set prevblock to point to itself
        header.hashPrevBlock = header_hash;

        // Note: This changes the hash, so it's not truly self-referential anymore
        // But it's still an invalid chain structure attempt
        std::vector<CBlockHeader> headers = {header};
        message::HeadersMessage msg;
        msg.headers = headers;
        auto payload = msg.serialize();
        send_raw_message(protocol::commands::HEADERS, payload);

        std::cout << "Expected: Node should reject (orphan or invalid chain)" << std::endl;
    }

    // Attack: Send circular header chain (A->B->A)
    void test_circular_chain() {
        std::cout << "\n=== TEST: Circular Header Chain ===" << std::endl;
        std::cout << "Sending headers that form a cycle (A->B->A)..." << std::endl;

        // Create header A pointing to a fake "B" hash
        CBlockHeader headerA;
        headerA.nVersion = 1;
        headerA.minerAddress.SetNull();
        headerA.nTime = std::time(nullptr);
        headerA.nBits = 0x207fffff;
        headerA.nNonce = 1;
        headerA.hashRandomX.SetNull();

        // Create header B
        CBlockHeader headerB;
        headerB.nVersion = 1;
        headerB.minerAddress.SetNull();
        headerB.nTime = std::time(nullptr);
        headerB.nBits = 0x207fffff;
        headerB.nNonce = 2;
        headerB.hashRandomX.SetNull();

        // Set A's prevblock to B's hash (computed with null prevblock first)
        headerB.hashPrevBlock.SetNull();
        uint256 hashB = headerB.GetHash();
        headerA.hashPrevBlock = hashB;

        // Set B's prevblock to A's hash
        uint256 hashA = headerA.GetHash();
        headerB.hashPrevBlock = hashA;

        // Send both headers - they form a cycle
        std::vector<CBlockHeader> headers = {headerA, headerB};
        message::HeadersMessage msg;
        msg.headers = headers;
        auto payload = msg.serialize();
        send_raw_message(protocol::commands::HEADERS, payload);

        std::cout << "Expected: Node should reject circular chain" << std::endl;
    }

    // Attack: Send header with version = 0
    void test_version_zero_header() {
        std::cout << "\n=== TEST: Version Zero Header ===" << std::endl;
        std::cout << "Sending header with nVersion = 0..." << std::endl;

        CBlockHeader header;
        header.nVersion = 0;  // Invalid version
        header.hashPrevBlock.SetNull();
        header.minerAddress.SetNull();
        header.nTime = std::time(nullptr);
        header.nBits = 0x207fffff;
        header.nNonce = 0;
        header.hashRandomX.SetNull();

        std::vector<CBlockHeader> headers = {header};
        message::HeadersMessage msg;
        msg.headers = headers;
        auto payload = msg.serialize();
        send_raw_message(protocol::commands::HEADERS, payload);

        std::cout << "Expected: Node may reject invalid version" << std::endl;
    }

    // Attack: Send header with negative version
    void test_negative_version_header() {
        std::cout << "\n=== TEST: Negative Version Header ===" << std::endl;
        std::cout << "Sending header with nVersion = -1..." << std::endl;

        CBlockHeader header;
        header.nVersion = -1;  // Negative version (will be interpreted as large unsigned)
        header.hashPrevBlock.SetNull();
        header.minerAddress.SetNull();
        header.nTime = std::time(nullptr);
        header.nBits = 0x207fffff;
        header.nNonce = 0;
        header.hashRandomX.SetNull();

        std::vector<CBlockHeader> headers = {header};
        message::HeadersMessage msg;
        msg.headers = headers;
        auto payload = msg.serialize();
        send_raw_message(protocol::commands::HEADERS, payload);

        std::cout << "Expected: Node should handle gracefully" << std::endl;
    }

    // Attack: Flood with unconnecting headers (random prevblock hashes)
    // Tests that the node handles headers with unknown parents gracefully.
    // These headers trigger GETHEADERS requests but are not stored (no orphan pool).
    void test_orphan_flood(int count = 100) {
        std::cout << "\n=== TEST: Unconnecting Header Flood (" << count << " headers) ===" << std::endl;
        std::cout << "Sending headers with random prevblock hashes (unconnecting)..." << std::endl;

        std::mt19937_64 rng(static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));

        for (int i = 0; i < count; i++) {
            CBlockHeader header;
            header.nVersion = 1;
            // Random prevblock hash - won't connect to anything
            uint256 random_prev;
            for (int j = 0; j < 4; j++) {
                uint64_t r = rng();
                std::memcpy(random_prev.begin() + j * 8, &r, 8);
            }
            header.hashPrevBlock = random_prev;
            header.minerAddress.SetNull();
            header.nTime = std::time(nullptr);
            header.nBits = 0x207fffff;
            header.nNonce = static_cast<uint32_t>(i);
            header.hashRandomX.SetNull();

            std::vector<CBlockHeader> headers = {header};
            message::HeadersMessage msg;
            msg.headers = headers;
            auto payload = msg.serialize();
            send_raw_message(protocol::commands::HEADERS, payload);

            // Small delay to avoid overwhelming
            if (i % 10 == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }

        std::cout << "Expected: Node sends GETHEADERS for each, remains responsive" << std::endl;
    }

    // Attack: Send GETHEADERS rapidly (spam)
    void test_getheaders_spam(int count = 50) {
        std::cout << "\n=== TEST: GETHEADERS Spam (" << count << "x) ===" << std::endl;
        std::cout << "Sending rapid GETHEADERS requests..." << std::endl;

        for (int i = 0; i < count; i++) {
            message::GetHeadersMessage msg;
            msg.version = protocol::PROTOCOL_VERSION;
            msg.block_locator_hashes = {};  // Empty locator
            msg.hash_stop.SetNull();
            auto payload = msg.serialize();
            send_raw_message(protocol::commands::GETHEADERS, payload);
        }

        std::cout << "Expected: Node should rate-limit or handle gracefully" << std::endl;
    }

    // ========== Phase 4: Message Type Attacks ==========

    // Attack: Send large ADDR message
    void test_addr_flood(int count = 1000) {
        std::cout << "\n=== TEST: ADDR Flood (" << count << " addresses) ===" << std::endl;
        std::cout << "Sending ADDR message with many addresses..." << std::endl;

        // Build ADDR payload manually
        // Format: varint count + (time + services + ip + port) per address
        std::vector<uint8_t> payload;

        // Varint for count (use 3-byte encoding for 1000)
        if (count < 253) {
            payload.push_back(static_cast<uint8_t>(count));
        } else {
            payload.push_back(0xFD);
            payload.push_back(static_cast<uint8_t>(count & 0xFF));
            payload.push_back(static_cast<uint8_t>((count >> 8) & 0xFF));
        }

        // Each address entry: 4 bytes time + 8 bytes services + 16 bytes IP + 2 bytes port = 30 bytes
        for (int i = 0; i < count; i++) {
            // Time (4 bytes)
            uint32_t time = static_cast<uint32_t>(std::time(nullptr));
            payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&time), reinterpret_cast<uint8_t*>(&time) + 4);
            // Services (8 bytes)
            uint64_t services = 1;  // NODE_NETWORK
            payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&services), reinterpret_cast<uint8_t*>(&services) + 8);
            // IP address (16 bytes) - fake IPv4-mapped IPv6
            for (int j = 0; j < 10; j++) payload.push_back(0x00);
            payload.push_back(0xFF);
            payload.push_back(0xFF);
            payload.push_back(static_cast<uint8_t>((i >> 8) & 0xFF));  // Vary the IP
            payload.push_back(static_cast<uint8_t>(i & 0xFF));
            payload.push_back(0x01);
            payload.push_back(0x01);
            // Port (2 bytes, big-endian)
            payload.push_back(0x73);  // 29590 = 0x7396
            payload.push_back(0x96);
        }

        send_raw_message(protocol::commands::ADDR, payload);

        std::cout << "Expected: Node should accept up to MAX_ADDR_SIZE (1000) addresses" << std::endl;
    }

    // Attack: Spam INV messages
    void test_inv_spam(int count = 100) {
        std::cout << "\n=== TEST: INV Spam (" << count << " messages) ===" << std::endl;
        std::cout << "Sending many INV messages rapidly..." << std::endl;

        std::mt19937_64 rng(static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));

        for (int i = 0; i < count; i++) {
            std::vector<uint8_t> payload;
            // Count = 1
            payload.push_back(0x01);
            // Type = MSG_BLOCK (2)
            uint32_t type = 2;
            payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&type), reinterpret_cast<uint8_t*>(&type) + 4);
            // Random 32-byte hash
            for (int j = 0; j < 4; j++) {
                uint64_t r = rng();
                payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&r), reinterpret_cast<uint8_t*>(&r) + 8);
            }

            send_raw_message("inv", payload);
        }

        std::cout << "Expected: Node should handle INV spam gracefully" << std::endl;
    }

    // ========================================================================
    // ADDITIONAL ADVERSARIAL TESTS - Batch 2
    // ========================================================================

    // === VERSION Variants ===

    // Attack: VERSION with bad start_height
    void test_version_bad_startheight() {
        std::cout << "\n=== TEST: VERSION Bad Start Height ===" << std::endl;
        std::cout << "Sending VERSION with start_height = -1..." << std::endl;

        message::VersionMessage msg;
        msg.version = protocol::PROTOCOL_VERSION;
        msg.services = protocol::NODE_NETWORK;
        msg.timestamp = std::time(nullptr);
        msg.addr_recv = protocol::NetworkAddress();
        msg.addr_from = protocol::NetworkAddress();
        std::mt19937_64 rng(static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));
        msg.nonce = rng();
        msg.user_agent = "/NodeSimulator:0.1.0/";
        msg.start_height = -1;  // Invalid negative height

        auto payload = msg.serialize();
        send_raw_message(protocol::commands::VERSION, payload);

        std::cout << "Expected: Node should handle gracefully" << std::endl;
    }

    // Attack: VERSION with same nonce as node (self-connection)
    void test_version_same_nonce(uint64_t node_nonce) {
        std::cout << "\n=== TEST: VERSION Same Nonce ===" << std::endl;
        std::cout << "Sending VERSION with node's own nonce (self-connection detection)..." << std::endl;

        message::VersionMessage msg;
        msg.version = protocol::PROTOCOL_VERSION;
        msg.services = protocol::NODE_NETWORK;
        msg.timestamp = std::time(nullptr);
        msg.addr_recv = protocol::NetworkAddress();
        msg.addr_from = protocol::NetworkAddress();
        msg.nonce = node_nonce;  // Same as node's nonce
        msg.user_agent = "/NodeSimulator:0.1.0/";
        msg.start_height = 0;

        auto payload = msg.serialize();
        send_raw_message(protocol::commands::VERSION, payload);

        std::cout << "Expected: Node should disconnect (self-connection)" << std::endl;
    }

    // Attack: VERSION with very long user agent
    void test_version_long_useragent() {
        std::cout << "\n=== TEST: VERSION Long User Agent ===" << std::endl;
        std::cout << "Sending VERSION with 300-char user agent (max is 256)..." << std::endl;

        message::VersionMessage msg;
        msg.version = protocol::PROTOCOL_VERSION;
        msg.services = protocol::NODE_NETWORK;
        msg.timestamp = std::time(nullptr);
        msg.addr_recv = protocol::NetworkAddress();
        msg.addr_from = protocol::NetworkAddress();
        std::mt19937_64 rng(static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));
        msg.nonce = rng();
        msg.user_agent = "/" + std::string(300, 'A') + "/";  // Exceeds MAX_SUBVERSION_LENGTH
        msg.start_height = 0;

        auto payload = msg.serialize();
        send_raw_message(protocol::commands::VERSION, payload);

        std::cout << "Expected: Node should reject or truncate" << std::endl;
    }

    // Attack: VERSION with old protocol version
    void test_version_old_protocol() {
        std::cout << "\n=== TEST: VERSION Old Protocol ===" << std::endl;
        std::cout << "Sending VERSION with very old protocol version (209)..." << std::endl;

        message::VersionMessage msg;
        msg.version = 209;  // Very old Bitcoin protocol version
        msg.services = protocol::NODE_NETWORK;
        msg.timestamp = std::time(nullptr);
        msg.addr_recv = protocol::NetworkAddress();
        msg.addr_from = protocol::NetworkAddress();
        std::mt19937_64 rng(static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));
        msg.nonce = rng();
        msg.user_agent = "/OldNode:0.0.1/";
        msg.start_height = 0;

        auto payload = msg.serialize();
        send_raw_message(protocol::commands::VERSION, payload);

        std::cout << "Expected: Node should reject old protocol" << std::endl;
    }

    // Attack: VERSION with timestamp far in future
    void test_version_future_time() {
        std::cout << "\n=== TEST: VERSION Future Timestamp ===" << std::endl;
        std::cout << "Sending VERSION with timestamp 1 year in future..." << std::endl;

        message::VersionMessage msg;
        msg.version = protocol::PROTOCOL_VERSION;
        msg.services = protocol::NODE_NETWORK;
        msg.timestamp = std::time(nullptr) + 365 * 24 * 60 * 60;  // 1 year in future
        msg.addr_recv = protocol::NetworkAddress();
        msg.addr_from = protocol::NetworkAddress();
        std::mt19937_64 rng(static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));
        msg.nonce = rng();
        msg.user_agent = "/FutureNode:0.1.0/";
        msg.start_height = 0;

        auto payload = msg.serialize();
        send_raw_message(protocol::commands::VERSION, payload);

        std::cout << "Expected: Node should handle (may warn about clock skew)" << std::endl;
    }

    // === PING/PONG Variants ===

    // Attack: Send PONG without receiving PING
    void test_pong_no_ping() {
        std::cout << "\n=== TEST: PONG Without PING ===" << std::endl;
        std::cout << "Sending unsolicited PONG..." << std::endl;

        std::vector<uint8_t> payload(8);
        uint64_t nonce = 12345678;
        std::memcpy(payload.data(), &nonce, 8);
        send_raw_message(protocol::commands::PONG, payload);

        std::cout << "Expected: Node should ignore unsolicited PONG" << std::endl;
    }

    // Attack: Respond to PING with wrong nonce
    void test_pong_wrong_nonce() {
        std::cout << "\n=== TEST: PONG Wrong Nonce ===" << std::endl;
        std::cout << "Sending PONG with incorrect nonce..." << std::endl;

        // Send a PING first to trigger a response, then send wrong PONG
        std::vector<uint8_t> ping_payload(8);
        uint64_t ping_nonce = 11111111;
        std::memcpy(ping_payload.data(), &ping_nonce, 8);
        send_raw_message(protocol::commands::PING, ping_payload);

        // Send PONG with different nonce
        std::vector<uint8_t> pong_payload(8);
        uint64_t wrong_nonce = 99999999;
        std::memcpy(pong_payload.data(), &wrong_nonce, 8);
        send_raw_message(protocol::commands::PONG, pong_payload);

        std::cout << "Expected: Node should ignore mismatched PONG" << std::endl;
    }

    // Attack: PING with zero nonce
    void test_ping_zero_nonce() {
        std::cout << "\n=== TEST: PING Zero Nonce ===" << std::endl;
        std::cout << "Sending PING with nonce = 0..." << std::endl;

        std::vector<uint8_t> payload(8, 0x00);  // All zeros
        send_raw_message(protocol::commands::PING, payload);

        std::cout << "Expected: Node should respond with PONG" << std::endl;
    }

    // === Payload Boundary Tests ===

    // Attack: Message at exact MAX size
    void test_payload_exact_max() {
        std::cout << "\n=== TEST: Payload Exact Max ===" << std::endl;
        std::cout << "Sending message at exactly MAX_PROTOCOL_MESSAGE_LENGTH..." << std::endl;

        // MAX_PROTOCOL_MESSAGE_LENGTH is 8010000, but we need to account for header
        // This is too large to actually send, so we test near the boundary
        const size_t near_max = 1000000;  // 1MB test
        std::vector<uint8_t> payload(near_max, 0x00);

        // Build a valid-looking headers message with large payload
        std::cout << "  Sending " << near_max << " byte payload..." << std::endl;
        send_raw_message(protocol::commands::HEADERS, payload);

        std::cout << "Expected: Node should handle large (but valid size) message" << std::endl;
    }

    // Attack: GETHEADERS with empty locator
    void test_getheaders_empty() {
        std::cout << "\n=== TEST: GETHEADERS Empty Locator ===" << std::endl;
        std::cout << "Sending GETHEADERS with zero locator hashes..." << std::endl;

        std::vector<uint8_t> payload;
        // Version
        uint32_t version = protocol::PROTOCOL_VERSION;
        payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&version), reinterpret_cast<uint8_t*>(&version) + 4);
        // Hash count = 0 (empty locator)
        payload.push_back(0x00);
        // Stop hash (32 zeros)
        for (int i = 0; i < 32; i++) payload.push_back(0x00);

        send_raw_message(protocol::commands::GETHEADERS, payload);

        std::cout << "Expected: Node should handle empty locator" << std::endl;
    }

    // Attack: PING with oversized payload
    void test_ping_oversized() {
        std::cout << "\n=== TEST: PING Oversized ===" << std::endl;
        std::cout << "Sending PING with 100-byte payload (should be 8)..." << std::endl;

        std::vector<uint8_t> payload(100, 0x42);  // 100 bytes instead of 8
        send_raw_message(protocol::commands::PING, payload);

        std::cout << "Expected: Node should reject or ignore" << std::endl;
    }

    // Attack: INV with invalid type
    void test_inv_bad_type() {
        std::cout << "\n=== TEST: INV Bad Type ===" << std::endl;
        std::cout << "Sending INV with invalid inventory type (99)..." << std::endl;

        std::vector<uint8_t> payload;
        // Count = 1
        payload.push_back(0x01);
        // Invalid type = 99
        uint32_t type = 99;
        payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&type), reinterpret_cast<uint8_t*>(&type) + 4);
        // Random 32-byte hash
        for (int i = 0; i < 32; i++) payload.push_back(static_cast<uint8_t>(i));

        send_raw_message("inv", payload);

        std::cout << "Expected: Node should ignore invalid inventory type" << std::endl;
    }

    // === Header Chain Tests ===

    // Attack: Headers with obviously invalid merkle root
    void test_headers_bad_merkle() {
        std::cout << "\n=== TEST: Headers Bad Merkle Root ===" << std::endl;
        std::cout << "Sending header with merkle root = 0xFFFF..." << std::endl;

        std::vector<uint8_t> payload;
        // Count = 1 header
        payload.push_back(0x01);

        // Build a header (80 bytes)
        std::vector<uint8_t> header(80, 0x00);
        // Version
        int32_t version = 1;
        std::memcpy(header.data(), &version, 4);
        // Prev block (32 bytes) - genesis
        // Merkle root (32 bytes) - all 0xFF
        std::memset(header.data() + 36, 0xFF, 32);
        // Timestamp
        uint32_t ts = static_cast<uint32_t>(std::time(nullptr));
        std::memcpy(header.data() + 68, &ts, 4);
        // nBits - easy target
        uint32_t nbits = 0x207FFFFF;
        std::memcpy(header.data() + 72, &nbits, 4);

        payload.insert(payload.end(), header.begin(), header.end());
        // Tx count (varint) = 0
        payload.push_back(0x00);

        send_raw_message(protocol::commands::HEADERS, payload);

        std::cout << "Expected: Node should validate and possibly reject" << std::endl;
    }

    // Attack: Headers claiming to fork from very old block
    void test_headers_deep_fork() {
        std::cout << "\n=== TEST: Headers Deep Fork ===" << std::endl;
        std::cout << "Sending headers forking from block at height 'far back'..." << std::endl;

        std::vector<uint8_t> payload;
        // Count = 1 header
        payload.push_back(0x01);

        // Build a header with random prev_block (simulating deep fork)
        std::vector<uint8_t> header(80, 0x00);
        int32_t version = 1;
        std::memcpy(header.data(), &version, 4);
        // Random prev block hash
        for (int i = 4; i < 36; i++) header[i] = static_cast<uint8_t>(i * 7);
        // Merkle root
        for (int i = 36; i < 68; i++) header[i] = static_cast<uint8_t>(i * 3);
        // Timestamp
        uint32_t ts = static_cast<uint32_t>(std::time(nullptr));
        std::memcpy(header.data() + 68, &ts, 4);
        // nBits
        uint32_t nbits = 0x207FFFFF;
        std::memcpy(header.data() + 72, &nbits, 4);

        payload.insert(payload.end(), header.begin(), header.end());
        payload.push_back(0x00);

        send_raw_message(protocol::commands::HEADERS, payload);

        std::cout << "Expected: Node should handle as orphan" << std::endl;
    }

    // Attack: Send maximum allowed headers in one message
    void test_headers_max_batch() {
        std::cout << "\n=== TEST: Headers Max Batch ===" << std::endl;
        // MAX_HEADERS_SIZE is 80000, but that's huge - let's test with 2000
        const int header_count = 2000;
        std::cout << "Sending " << header_count << " headers in one message..." << std::endl;

        std::vector<uint8_t> payload;
        // Varint for count
        // For 2000, we need 0xFD followed by 2-byte LE
        payload.push_back(0xFD);
        uint16_t count16 = header_count;
        payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&count16), reinterpret_cast<uint8_t*>(&count16) + 2);

        // Add headers
        for (int i = 0; i < header_count; i++) {
            std::vector<uint8_t> header(80, 0x00);
            int32_t version = 1;
            std::memcpy(header.data(), &version, 4);
            // Make each header unique
            header[35] = static_cast<uint8_t>(i & 0xFF);
            header[34] = static_cast<uint8_t>((i >> 8) & 0xFF);
            // Timestamp
            uint32_t ts = static_cast<uint32_t>(std::time(nullptr));
            std::memcpy(header.data() + 68, &ts, 4);
            // nBits
            uint32_t nbits = 0x207FFFFF;
            std::memcpy(header.data() + 72, &nbits, 4);

            payload.insert(payload.end(), header.begin(), header.end());
            // Tx count = 0
            payload.push_back(0x00);
        }

        send_raw_message(protocol::commands::HEADERS, payload);

        std::cout << "Expected: Node should process batch" << std::endl;
    }

    // Attack: GETHEADERS with too many locator hashes
    void test_locator_overflow() {
        std::cout << "\n=== TEST: GETHEADERS Locator Overflow ===" << std::endl;
        // MAX_LOCATOR_SZ is 101
        const int locator_count = 150;
        std::cout << "Sending GETHEADERS with " << locator_count << " locator hashes (max is 101)..." << std::endl;

        std::vector<uint8_t> payload;
        // Version
        uint32_t version = protocol::PROTOCOL_VERSION;
        payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&version), reinterpret_cast<uint8_t*>(&version) + 4);
        // Hash count (varint)
        payload.push_back(0xFD);
        uint16_t count16 = locator_count;
        payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&count16), reinterpret_cast<uint8_t*>(&count16) + 2);
        // Hashes
        for (int i = 0; i < locator_count; i++) {
            for (int j = 0; j < 32; j++) {
                payload.push_back(static_cast<uint8_t>((i + j) & 0xFF));
            }
        }
        // Stop hash
        for (int i = 0; i < 32; i++) payload.push_back(0x00);

        send_raw_message(protocol::commands::GETHEADERS, payload);

        std::cout << "Expected: Node should reject (locator too large)" << std::endl;
    }

    // === Other Message Tests ===

    // Attack: GETADDR spam
    void test_getaddr_spam(int count = 50) {
        std::cout << "\n=== TEST: GETADDR Spam (" << count << "x) ===" << std::endl;
        std::cout << "Sending many GETADDR requests..." << std::endl;

        for (int i = 0; i < count; i++) {
            std::vector<uint8_t> payload;  // Empty payload
            send_raw_message(protocol::commands::GETADDR, payload);
        }

        std::cout << "Expected: Node should rate-limit or handle gracefully" << std::endl;
    }

    // Attack: SENDHEADERS before VERSION
    void test_sendheaders_pre() {
        std::cout << "\n=== TEST: SENDHEADERS Pre-Handshake ===" << std::endl;
        std::cout << "Sending SENDHEADERS before VERSION..." << std::endl;

        std::vector<uint8_t> payload;  // Empty payload
        send_raw_message("sendheaders", payload);

        std::cout << "Expected: Node should reject (pre-handshake)" << std::endl;
    }

    // Attack: SENDHEADERS twice
    void test_sendheaders_double() {
        std::cout << "\n=== TEST: SENDHEADERS Twice ===" << std::endl;
        std::cout << "Sending SENDHEADERS twice after handshake..." << std::endl;

        std::vector<uint8_t> payload;  // Empty
        send_raw_message("sendheaders", payload);
        send_raw_message("sendheaders", payload);

        std::cout << "Expected: Node should handle duplicate gracefully" << std::endl;
    }

    // Attack: Repeated INV with same hash
    void test_inv_repeat(int count = 100) {
        std::cout << "\n=== TEST: INV Repeat (" << count << "x same hash) ===" << std::endl;
        std::cout << "Sending same INV hash repeatedly..." << std::endl;

        // Fixed hash
        uint8_t fixed_hash[32];
        for (int i = 0; i < 32; i++) fixed_hash[i] = static_cast<uint8_t>(i);

        for (int i = 0; i < count; i++) {
            std::vector<uint8_t> payload;
            payload.push_back(0x01);  // Count = 1
            uint32_t type = 2;  // MSG_BLOCK
            payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&type), reinterpret_cast<uint8_t*>(&type) + 4);
            payload.insert(payload.end(), fixed_hash, fixed_hash + 32);
            send_raw_message("inv", payload);
        }

        std::cout << "Expected: Node should deduplicate/ignore repeats" << std::endl;
    }

    // Attack: Rapid connect/disconnect cycles
    // Note: This is handled differently - spawns multiple connections
    // For now, just document it here; actual test needs multi-connection support

    // Wait for and read messages (to see VERACK, potential disconnects, etc.)
    void receive_messages(int timeout_sec = 5) {
        std::cout << "\n--- Listening for responses (" << timeout_sec << "s) ---" << std::endl;

        socket_.non_blocking(true);
        auto start = std::chrono::steady_clock::now();

        while (true) {
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - start).count() >= timeout_sec) {
                break;
            }

            try {
                std::vector<uint8_t> header_buf(protocol::MESSAGE_HEADER_SIZE);
                asio::error_code ec;
                size_t n = socket_.read_some(asio::buffer(header_buf), ec);

                if (ec == asio::error::would_block) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                } else if (ec) {
                    std::cout << "✗ Connection closed: " << ec.message() << std::endl;
                    break;
                }

                if (n == protocol::MESSAGE_HEADER_SIZE) {
                    protocol::MessageHeader header;
                    if (message::deserialize_header(header_buf.data(), header_buf.size(), header)) {
                        std::cout << "← Received: " << header.get_command() << " (" << header.length << " bytes)" << std::endl;

                        // Read payload
                        std::vector<uint8_t> payload_buf(header.length);
                        asio::read(socket_, asio::buffer(payload_buf));
                    }
                }
            } catch (const std::exception& e) {
                std::cout << "✗ Read error: " << e.what() << std::endl;
                break;
            }
        }
    }

    void close() {
        socket_.close();
    }

private:
    asio::ip::tcp::socket socket_;
    std::string host_;
    uint16_t port_;
};

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]\n\n"
              << "Options:\n"
              << "  --host <host>        Target host (default: 127.0.0.1)\n"
              << "  --port <port>        Target port (default: 29590 regtest)\n"
              << "  --test <type>        Test scenario type:\n"
              << "\n  Header Attacks:\n"
              << "                         invalid-pow      : Send headers with invalid PoW\n"
              << "                         oversized        : Send oversized headers message\n"
              << "                         non-continuous   : Send non-continuous headers\n"
              << "                         spam-continuous  : Spam with non-continuous headers (5x)\n"
              << "\n  Framing Attacks:\n"
              << "                         slow-loris       : Drip a large payload slowly (chunked)\n"
              << "                         bad-magic        : Wrong 4-byte message magic\n"
              << "                         bad-checksum     : Corrupted header checksum\n"
              << "                         bad-length       : Declared length > actual then close\n"
              << "                         truncation       : Send half payload then close\n"
              << "                         empty-command    : Message with empty command field\n"
              << "                         length-short     : Declared length < actual payload\n"
              << "                         length-max       : Declared length > MAX (16MB)\n"
              << "                         command-null     : Command with embedded null bytes\n"
              << "                         command-non-ascii: Command with non-ASCII bytes\n"
              << "\n  Handshake Attacks:\n"
              << "                         pre-handshake    : Send HEADERS before VERSION/VERACK\n"
              << "                         pre-handshake-gh : Send GETHEADERS before handshake\n"
              << "                         pre-handshake-inv: Send INV before handshake\n"
              << "                         pre-handshake-gd : Send GETDATA before handshake\n"
              << "                         verack-first     : Send VERACK without VERSION\n"
              << "                         multi-verack     : Send VERACK twice\n"
              << "                         silent           : Connect but send nothing\n"
              << "                         stalled-handshake: Send VERSION, never send VERACK\n"
              << "                         duplicate-version: Send VERSION twice\n"
              << "                         bad-version      : VERSION with invalid fields\n"
              << "                         partial-version  : Send truncated VERSION message\n"
              << "\n  VERSION Variants:\n"
              << "                         ver-bad-height   : VERSION with start_height = -1\n"
              << "                         ver-long-ua      : VERSION with 300-char user agent\n"
              << "                         ver-old-proto    : VERSION with protocol version 209\n"
              << "                         ver-future-time  : VERSION timestamp 1 year in future\n"
              << "                         sendheaders-pre  : SENDHEADERS before VERSION\n"
              << "\n  Rate Limit Attacks:\n"
              << "                         unknown-cmd      : Send unknown command\n"
              << "                         unknown-cmd-flood: Flood unknown commands (25x)\n"
              << "\n  Header Validation Attacks:\n"
              << "                         future-timestamp : Headers with time > now + 10min\n"
              << "                         timestamp-zero   : Headers with timestamp = 0\n"
              << "                         nbits-zero       : Headers with nBits = 0\n"
              << "                         nbits-max        : Headers with nBits = 0xFFFFFFFF\n"
              << "                         self-ref         : Header with self-referential prevblock\n"
              << "                         circular-chain   : Circular header chain (A->B->A)\n"
              << "                         version-zero-hdr : Header with nVersion = 0\n"
              << "                         neg-version-hdr  : Header with nVersion = -1\n"
              << "                         orphan-flood     : Flood with unconnecting headers (100x)\n"
              << "                         getheaders-spam  : Rapid GETHEADERS requests (50x)\n"
              << "\n  Message Type Attacks:\n"
              << "                         addr-flood       : Large ADDR message (1000 addrs)\n"
              << "                         inv-spam         : Spam INV messages (100x)\n"
              << "                         inv-bad-type     : INV with invalid type (99)\n"
              << "                         inv-repeat       : Same INV hash 100 times\n"
              << "                         getaddr-spam     : 50 GETADDR requests\n"
              << "                         sendheaders-dbl  : SENDHEADERS twice\n"
              << "\n  PING/PONG Attacks:\n"
              << "                         pong-no-ping     : PONG without receiving PING\n"
              << "                         pong-wrong-nonce : PONG with wrong nonce\n"
              << "                         ping-zero-nonce  : PING with nonce = 0\n"
              << "                         ping-oversized   : PING with 100-byte payload\n"
              << "\n  Payload Boundary Tests:\n"
              << "                         payload-max      : 1MB payload message\n"
              << "                         getheaders-empty : GETHEADERS with empty locator\n"
              << "                         locator-overflow : GETHEADERS with 150 hashes (max 101)\n"
              << "\n  Header Chain Attacks:\n"
              << "                         headers-bad-merkle: Header with 0xFFFF merkle root\n"
              << "                         headers-deep-fork : Header forking from random block\n"
              << "                         headers-max-batch : 2000 headers in one message\n"
              << "\n  Resource Exhaustion:\n"
              << "                         rapid-reconnect  : Connect/disconnect rapidly (20x)\n"
              << "                         rapid-fire       : Send 500 PINGs as fast as possible\n"
              << "\n  Meta:\n"
              << "                         all              : Run all test scenarios\n"
              << "  --help               Show this help\n"
              << std::endl;
}

int main(int argc, char* argv[]) {
    std::string host = "127.0.0.1";
    uint16_t port = 29590;
    std::string test_type = "all";

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--host" && i + 1 < argc) {
            host = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            port = std::stoi(argv[++i]);
        } else if ((arg == "--test" || arg == "--attack") && i + 1 < argc) {
            test_type = argv[++i];
        } else {
            std::cerr << "Unknown argument: " << arg << std::endl;
            print_usage(argv[0]);
            return 1;
        }
    }

    std::cout << "=== Node Simulator ===" << std::endl;
    std::cout << "Target: " << host << ":" << port << std::endl;
    std::cout << "Test: " << test_type << std::endl;
    std::cout << "\nWARNING: This tool sends custom P2P messages for testing." << std::endl;
    std::cout << "Only use on private test networks!\n" << std::endl;

    // Get genesis hash for testing (in real test, we'd query via RPC)
    uint256 genesis_hash;
    genesis_hash.SetHex("0555faa88836f4ce189235a28279af4614432234b6f7e2f350e4fc0dadb1ffa7");

    // Helper lambda to perform handshake
    auto do_handshake = [](NodeSimulator& simulator) {
        std::cout << "\n--- Handshake ---" << std::endl;
        simulator.send_version();
        simulator.receive_messages(2);
        simulator.send_verack();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    };

    try {
        asio::io_context io_context;

        // If running "all" attacks, create separate connection for each to avoid
        // early disconnection affecting later tests
        if (test_type == "all") {
            // Test 1: Invalid PoW (instant disconnect - score=100)
            std::cout << "\n========== TEST 1: Invalid PoW ==========" << std::endl;
            {
                NodeSimulator simulator(io_context, host, port);
                if (!simulator.connect()) return 1;
                do_handshake(simulator);
                simulator.test_invalid_pow(genesis_hash);
                simulator.receive_messages(2);
                simulator.close();
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }

            // Test 2: Oversized headers (+20 score)
            std::cout << "\n========== TEST 2: Oversized Headers ==========" << std::endl;
            {
                NodeSimulator simulator(io_context, host, port);
                if (!simulator.connect()) return 1;
                do_handshake(simulator);
                simulator.test_oversized_headers();
                simulator.receive_messages(2);
                simulator.close();
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }

            // Test 3: Non-continuous headers (+20 score)
            std::cout << "\n========== TEST 3: Non-Continuous Headers ==========" << std::endl;
            {
                NodeSimulator simulator(io_context, host, port);
                if (!simulator.connect()) return 1;
                do_handshake(simulator);
                simulator.test_non_continuous_headers(genesis_hash);
                simulator.receive_messages(2);
                simulator.close();
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }

            // Test 4: Spam attack (5x non-continuous = 100 score, disconnect)
            std::cout << "\n========== TEST 4: Spam Non-Continuous (5x) ==========" << std::endl;
            {
                NodeSimulator simulator(io_context, host, port);
                if (!simulator.connect()) return 1;
                do_handshake(simulator);
                simulator.test_spam_non_continuous(genesis_hash, 5);
                simulator.receive_messages(3);
                simulator.close();
            }
        } else {
            // Single attack type - use one connection
            NodeSimulator simulator(io_context, host, port);

            if (!simulator.connect()) {
                return 1;
            }

            // Some tests must NOT perform handshake first
            bool skip_handshake = (test_type == "pre-handshake" ||
                                   test_type == "pre-handshake-gh" ||
                                   test_type == "pre-handshake-inv" ||
                                   test_type == "pre-handshake-gd" ||
                                   test_type == "verack-first" ||
                                   test_type == "multi-verack" ||
                                   test_type == "silent" ||
                                   test_type == "stalled-handshake" ||
                                   test_type == "bad-version" ||
                                   test_type == "partial-version" ||
                                   test_type == "ver-bad-height" ||
                                   test_type == "ver-long-ua" ||
                                   test_type == "ver-old-proto" ||
                                   test_type == "ver-future-time" ||
                                   test_type == "sendheaders-pre");

            if (!skip_handshake) {
                do_handshake(simulator);
            }

            // Run single attack
            if (test_type == "invalid-pow") {
                simulator.test_invalid_pow(genesis_hash);
                simulator.receive_messages(2);
            } else if (test_type == "oversized") {
                simulator.test_oversized_headers();
                simulator.receive_messages(2);
            } else if (test_type == "non-continuous") {
                simulator.test_non_continuous_headers(genesis_hash);
                simulator.receive_messages(2);
            } else if (test_type == "spam-continuous") {
                simulator.test_spam_non_continuous(genesis_hash, 5);
                simulator.receive_messages(3);
            } else if (test_type == "slow-loris") {
                std::cout << "\n========== TEST: Slow-Loris ==========" << std::endl;
                std::vector<uint8_t> payload(8192, 0x00);
                simulator.send_chunked(protocol::commands::HEADERS, payload, /*chunk_size=*/32, /*delay_ms=*/200, /*max_bytes=*/2048, /*close_early=*/true);
            } else if (test_type == "bad-magic") {
                simulator.test_bad_magic();
                simulator.receive_messages(1);
            } else if (test_type == "bad-checksum") {
                simulator.test_bad_checksum();
                simulator.receive_messages(1);
            } else if (test_type == "bad-length") {
                simulator.test_bad_length();
            } else if (test_type == "truncation") {
                simulator.test_truncation();
            }
            // New framing attacks
            else if (test_type == "empty-command") {
                simulator.test_empty_command();
                simulator.receive_messages(2);
            } else if (test_type == "length-short") {
                simulator.test_length_less_than_actual();
                simulator.receive_messages(2);
            } else if (test_type == "length-max") {
                simulator.test_length_exceeds_max();
                simulator.receive_messages(2);
            } else if (test_type == "command-null") {
                simulator.test_command_null_bytes();
                simulator.receive_messages(2);
            } else if (test_type == "command-non-ascii") {
                simulator.test_command_non_ascii();
                simulator.receive_messages(2);
            }
            // Phase 1: Handshake Attacks
            else if (test_type == "pre-handshake") {
                simulator.test_pre_handshake_headers();
                simulator.receive_messages(2);
            } else if (test_type == "pre-handshake-gh") {
                simulator.test_pre_handshake_getheaders();
                simulator.receive_messages(2);
            } else if (test_type == "pre-handshake-inv") {
                simulator.test_pre_handshake_inv();
                simulator.receive_messages(2);
            } else if (test_type == "pre-handshake-gd") {
                simulator.test_pre_handshake_getdata();
                simulator.receive_messages(2);
            } else if (test_type == "verack-first") {
                simulator.test_verack_without_version();
                simulator.receive_messages(2);
            } else if (test_type == "multi-verack") {
                simulator.test_multi_verack();
                simulator.receive_messages(2);
            } else if (test_type == "silent") {
                simulator.test_silent_connection(5);
                simulator.receive_messages(2);
            } else if (test_type == "stalled-handshake") {
                simulator.test_stalled_handshake(5);
                simulator.receive_messages(2);
            } else if (test_type == "duplicate-version") {
                simulator.test_duplicate_version();
                simulator.receive_messages(2);
            } else if (test_type == "bad-version") {
                simulator.test_bad_version();
                simulator.receive_messages(2);
            } else if (test_type == "partial-version") {
                simulator.test_partial_version();
                // Socket already closed in test - skip receive and close
                return 0;
            }
            // Rate Limit Attacks
            else if (test_type == "unknown-cmd") {
                simulator.test_unknown_command();
                simulator.receive_messages(2);
            } else if (test_type == "unknown-cmd-flood") {
                simulator.test_unknown_command_flood(25);
                simulator.receive_messages(2);
            }
            // Phase 2: Header Validation Attacks
            else if (test_type == "future-timestamp") {
                simulator.test_future_timestamp();
                simulator.receive_messages(2);
            } else if (test_type == "timestamp-zero") {
                simulator.test_timestamp_zero();
                simulator.receive_messages(2);
            } else if (test_type == "nbits-zero") {
                simulator.test_nbits_zero();
                simulator.receive_messages(2);
            } else if (test_type == "nbits-max") {
                simulator.test_nbits_max();
                simulator.receive_messages(2);
            } else if (test_type == "self-ref") {
                simulator.test_self_referential();
                simulator.receive_messages(2);
            } else if (test_type == "circular-chain") {
                simulator.test_circular_chain();
                simulator.receive_messages(2);
            } else if (test_type == "version-zero-hdr") {
                simulator.test_version_zero_header();
                simulator.receive_messages(2);
            } else if (test_type == "neg-version-hdr") {
                simulator.test_negative_version_header();
                simulator.receive_messages(2);
            } else if (test_type == "orphan-flood") {
                simulator.test_orphan_flood(100);
                simulator.receive_messages(3);
            } else if (test_type == "getheaders-spam") {
                simulator.test_getheaders_spam(50);
                simulator.receive_messages(3);
            }
            // Phase 4: Message Type Attacks
            else if (test_type == "addr-flood") {
                simulator.test_addr_flood(1000);
                simulator.receive_messages(2);
            } else if (test_type == "inv-spam") {
                simulator.test_inv_spam(100);
                simulator.receive_messages(2);
            }
            // Phase 3: Resource Exhaustion - rapid-reconnect needs special handling
            else if (test_type == "rapid-reconnect") {
                // Close the initial connection first
                simulator.close();

                std::cout << "\n=== TEST: Rapid Reconnect (20 cycles) ===" << std::endl;
                std::cout << "Rapidly connecting and disconnecting..." << std::endl;

                int success_count = 0;
                int fail_count = 0;
                const int cycles = 20;

                for (int i = 0; i < cycles; i++) {
                    NodeSimulator temp_sim(io_context, host, port);
                    if (temp_sim.connect()) {
                        temp_sim.send_version();
                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                        temp_sim.close();
                        success_count++;
                    } else {
                        fail_count++;
                    }
                    // Brief delay between cycles
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }

                std::cout << "Completed " << success_count << "/" << cycles << " connection cycles" << std::endl;
                if (fail_count > 0) {
                    std::cout << "  (" << fail_count << " connections rejected - rate limiting may be active)" << std::endl;
                }
                std::cout << "Expected: Node should handle rapid connections gracefully" << std::endl;

                // Skip the final close since we already closed
                return 0;
            } else if (test_type == "rapid-fire") {
                simulator.test_rapid_fire(500);
                simulator.receive_messages(3);
            }
            // === VERSION Variants ===
            else if (test_type == "ver-bad-height") {
                simulator.test_version_bad_startheight();
                simulator.receive_messages(2);
            } else if (test_type == "ver-long-ua") {
                simulator.test_version_long_useragent();
                simulator.receive_messages(2);
            } else if (test_type == "ver-old-proto") {
                simulator.test_version_old_protocol();
                simulator.receive_messages(2);
            } else if (test_type == "ver-future-time") {
                simulator.test_version_future_time();
                simulator.receive_messages(2);
            }
            // === PING/PONG Attacks ===
            else if (test_type == "pong-no-ping") {
                simulator.test_pong_no_ping();
                simulator.receive_messages(2);
            } else if (test_type == "pong-wrong-nonce") {
                simulator.test_pong_wrong_nonce();
                simulator.receive_messages(2);
            } else if (test_type == "ping-zero-nonce") {
                simulator.test_ping_zero_nonce();
                simulator.receive_messages(2);
            } else if (test_type == "ping-oversized") {
                simulator.test_ping_oversized();
                simulator.receive_messages(2);
            }
            // === Payload Boundary Tests ===
            else if (test_type == "payload-max") {
                simulator.test_payload_exact_max();
                simulator.receive_messages(3);
            } else if (test_type == "getheaders-empty") {
                simulator.test_getheaders_empty();
                simulator.receive_messages(2);
            } else if (test_type == "locator-overflow") {
                simulator.test_locator_overflow();
                simulator.receive_messages(2);
            }
            // === Header Chain Attacks ===
            else if (test_type == "headers-bad-merkle") {
                simulator.test_headers_bad_merkle();
                simulator.receive_messages(2);
            } else if (test_type == "headers-deep-fork") {
                simulator.test_headers_deep_fork();
                simulator.receive_messages(2);
            } else if (test_type == "headers-max-batch") {
                simulator.test_headers_max_batch();
                simulator.receive_messages(3);
            }
            // === Other Message Tests ===
            else if (test_type == "inv-bad-type") {
                simulator.test_inv_bad_type();
                simulator.receive_messages(2);
            } else if (test_type == "inv-repeat") {
                simulator.test_inv_repeat(100);
                simulator.receive_messages(2);
            } else if (test_type == "getaddr-spam") {
                simulator.test_getaddr_spam(50);
                simulator.receive_messages(2);
            } else if (test_type == "sendheaders-pre") {
                simulator.test_sendheaders_pre();
                simulator.receive_messages(2);
            } else if (test_type == "sendheaders-dbl") {
                simulator.test_sendheaders_double();
                simulator.receive_messages(2);
            } else {
                std::cerr << "Unknown test type: " << test_type << std::endl;
                print_usage(argv[0]);
                return 1;
            }

            simulator.close();
        }

        std::cout << "\n--- Test Complete ---" << std::endl;
        std::cout << "Check the target node's logs for misbehavior scores and disconnections." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
