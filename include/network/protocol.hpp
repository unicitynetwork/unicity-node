// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include "util/uint.hpp"

#include "version.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>

namespace unicity {
namespace protocol {

// Protocol version - increment when P2P protocol changes
constexpr uint32_t PROTOCOL_VERSION = 1;

// Minimum supported protocol version
// Peers with version < MIN_PROTOCOL_VERSION will be rejected
constexpr uint32_t MIN_PROTOCOL_VERSION = 1;

// Network magic bytes - unique identifier for the network
// ASCII encoding: "UNIC" (Unicity) for mainnet
namespace magic {
constexpr uint32_t MAINNET = 0x554E4943;  // "UNIC" - Unicity mainnet
constexpr uint32_t TESTNET = 0xA3F8D412;  // High bit separation from mainnet
constexpr uint32_t REGTEST = 0x4B7C2E91;  // High bit separation from mainnet/testnet
}  // namespace magic

namespace ports {
constexpr uint16_t MAINNET = 9590;
constexpr uint16_t TESTNET = 19590;  // MAINNET + 10000
constexpr uint16_t REGTEST = 29590;  // MAINNET + 20000
}  // namespace ports

// Service flags - what services this node provides
// NODE_NETWORK means we can serve headers which are the full blocks in a headers-only chain
enum ServiceFlags : uint64_t {
  NODE_NONE = 0,
  NODE_NETWORK = (1 << 0),  // Can serve blocks (headers) 
};

// Message types - 12 bytes, null-padded
// Headers-only chain: no transactions, compact blocks, bloom filters, or mempool
namespace commands {
// Handshake
constexpr const char* VERSION = "version";
constexpr const char* VERACK = "verack";

// Peer discovery
constexpr const char* ADDR = "addr";
constexpr const char* GETADDR = "getaddr";

// Block announcements and requests
constexpr const char* GETHEADERS = "getheaders";
constexpr const char* HEADERS = "headers";

// Keep-alive
constexpr const char* PING = "ping";
constexpr const char* PONG = "pong";
}  // namespace commands

// Message header constants
constexpr size_t MESSAGE_HEADER_SIZE = 24;
constexpr size_t COMMAND_SIZE = 12;
constexpr size_t CHECKSUM_SIZE = 4;

// ============================================================================
// SECURITY LIMITS
// ============================================================================

// Serialization limits
constexpr uint64_t MAX_SIZE = 0x02000000;                // 32 MB - Maximum serialized object size
constexpr size_t MAX_VECTOR_ALLOCATE = 5 * 1000 * 1000;  // 5 MB - Incremental allocation limit

// Network message limits
constexpr size_t MAX_PROTOCOL_MESSAGE_LENGTH = 8010000;  // 8.01 MB - Single message limit
constexpr size_t DEFAULT_SEND_QUEUE_SIZE = 10 * 1000 * 1000;     // 10 MB - Send queue limit per peer 
constexpr size_t DEFAULT_RECV_FLOOD_SIZE = 10 * 1000 * 1000;     // 10 MB - Flood protection (enforced)

// Protocol-specific limits
constexpr unsigned int MAX_LOCATOR_SZ = 101;  // GETHEADERS/GETBLOCKS locator limit
constexpr uint32_t MAX_HEADERS_SIZE = 80000;  // Headers per response
constexpr uint32_t MAX_ADDR_SIZE = 1000;      // Addresses per ADDR message

// Connection limits
// Full-relay outbound: normal connections with address/transaction relay
constexpr unsigned int DEFAULT_MAX_FULL_RELAY_OUTBOUND = 8;
// Block-relay-only outbound: eclipse attack resistance, no address relay
constexpr unsigned int DEFAULT_MAX_BLOCK_RELAY_OUTBOUND = 2;
// Total outbound = full-relay + block-relay
constexpr unsigned int DEFAULT_MAX_OUTBOUND_CONNECTIONS = DEFAULT_MAX_FULL_RELAY_OUTBOUND +
                                                          DEFAULT_MAX_BLOCK_RELAY_OUTBOUND;  // 10
constexpr unsigned int DEFAULT_MAX_INBOUND_CONNECTIONS = 125;

// Timeouts and intervals (in seconds)
constexpr int VERSION_HANDSHAKE_TIMEOUT_SEC = 60;  // 1 minute for handshake
constexpr int PING_INTERVAL_SEC = 120;             // 2 minutes between pings
constexpr int PING_TIMEOUT_SEC = 20 * 60;           // 20 minutes - peer must respond to ping
constexpr int INACTIVITY_TIMEOUT_SEC = 20 * 60;     // 20 minutes
constexpr int INACTIVITY_CHECK_INTERVAL_SEC = 60;   // Check every 60 seconds

// RPC/Mining statistics constants
constexpr int DEFAULT_HASHRATE_CALCULATION_BLOCKS = 4;  // Recent blocks for hashrate calculation

// Network address constants
constexpr size_t MAX_SUBVERSION_LENGTH = 256;

// User agent string (from version.hpp)
inline std::string GetUserAgent() {
  return unicity::GetUserAgent();
}

// Message header structure (24 bytes):
// magic (4 bytes), command (12 bytes null-padded), length (4 bytes), checksum (4 bytes)
struct MessageHeader {
  uint32_t magic;
  std::array<char, COMMAND_SIZE> command;
  uint32_t length;
  std::array<uint8_t, CHECKSUM_SIZE> checksum;

  MessageHeader() noexcept;
  MessageHeader(uint32_t magic, const std::string& cmd, uint32_t len);

  // Get command as string (strips null padding)
  [[nodiscard]] std::string get_command() const;

  // Set command from string (adds null padding)
  void set_command(const std::string& cmd);
};

// Network address structure (26 bytes on wire: 8 services + 16 IP + 2 port)
struct NetworkAddress {
  uint64_t services;
  std::array<uint8_t, 16> ip;  // IPv6 format (IPv4 mapped)
  uint16_t port;               // Host byte order (native endianness)

  NetworkAddress() noexcept;
  NetworkAddress(uint64_t svcs, const std::array<uint8_t, 16>& addr, uint16_t p) noexcept;

  // Helper to create from IPv4
  [[nodiscard]] static NetworkAddress from_ipv4(uint64_t services, uint32_t ipv4, uint16_t port) noexcept;

  // Helper to create from IP string (supports both IPv4 and IPv6)
  [[nodiscard]] static NetworkAddress from_string(const std::string& ip_str, uint16_t port,
                                                  uint64_t services = NODE_NETWORK);

  // Helper to get IPv4 (returns 0 if not IPv4-mapped)
  [[nodiscard]] uint32_t get_ipv4() const noexcept;

  // Check if this is IPv4-mapped
  [[nodiscard]] bool is_ipv4() const noexcept;

  // Check if this is a zeroed/invalid address (all bytes are 0)
  // Used to detect parse failures from from_string()
  [[nodiscard]] bool is_zero() const noexcept;

  // Check if this address is routable on the public internet
  // Rejects private, loopback, multicast, reserved, and documentation ranges
  // Works directly on bytes - no string conversion overhead
  [[nodiscard]] bool is_routable() const noexcept;

  // Get the network group for this address
  // IPv4: /16 prefix (e.g., "192.168"), IPv6: /32 prefix (e.g., "2001:0db8")
  [[nodiscard]] std::string get_netgroup() const noexcept;

  // Check if this is a loopback address (127.x.x.x or ::1)
  [[nodiscard]] bool is_loopback() const noexcept;

  // Convert to IP string (IPv4 or IPv6)
  // Returns std::nullopt if conversion fails
  [[nodiscard]] std::optional<std::string> to_string() const noexcept;

  // Comparison operators (compares IP + port only; services is metadata, not identity)
  [[nodiscard]] bool operator<(const NetworkAddress& other) const noexcept;
  [[nodiscard]] bool operator==(const NetworkAddress& other) const noexcept;
};

// Timestamped network address (30 bytes: 4 timestamp + 26 NetworkAddress)
struct TimestampedAddress {
  uint32_t timestamp;
  NetworkAddress address;

  TimestampedAddress() noexcept;
  TimestampedAddress(uint32_t ts, const NetworkAddress& addr) noexcept;
};

}  // namespace protocol
}  // namespace unicity
