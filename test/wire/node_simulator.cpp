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

    void send_raw_message(const std::string& command, const std::vector<uint8_t>& payload) {
        protocol::MessageHeader header(protocol::magic::REGTEST, command, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(header.checksum.data(), hash.begin(), 4);
        auto header_bytes = message::serialize_header(header);

        std::vector<uint8_t> full_message;
        full_message.insert(full_message.end(), header_bytes.begin(), header_bytes.end());
        full_message.insert(full_message.end(), payload.begin(), payload.end());

        asio::write(socket_, asio::buffer(full_message));
        std::cout << "→ Sent " << command << " (" << payload.size() << " bytes)" << std::endl;
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

    // Attack: Spam with repeated non-continuous headers
    void test_spam_non_continuous(const uint256& prev_hash, int count) {
        std::cout << "\n=== TEST: Spam Non-Continuous Headers (" << count << " times) ===" << std::endl;

        for (int i = 0; i < count; i++) {
            test_non_continuous_headers(prev_hash);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        std::cout << "Expected: After 5 violations (5*20=100), peer should be disconnected" << std::endl;
    }

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
              << "                         invalid-pow      : Send headers with invalid PoW\n"
              << "                         oversized        : Send oversized headers message\n"
              << "                         non-continuous   : Send non-continuous headers\n"
              << "                         spam-continuous  : Spam with non-continuous headers (5x)\n"
              << "                         slow-loris       : Drip a large payload slowly (chunked)\n"
              << "                         bad-magic        : Wrong 4-byte message magic\n"
              << "                         bad-checksum     : Corrupted header checksum\n"
              << "                         bad-length       : Declared length > actual then close\n"
              << "                         truncation       : Send half payload then close\n"
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
    genesis_hash.SetHex("0233b37bb6942bfb471cfd7fb95caab0e0f7b19cc8767da65fbef59eb49e45bd");

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

            do_handshake(simulator);

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
