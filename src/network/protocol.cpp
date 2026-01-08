// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "network/protocol.hpp"

#include "util/netaddress.hpp"

#include <algorithm>
#include <cstring>

#include <asio/ip/address.hpp>
#include <asio/ip/address_v4.hpp>
#include <asio/ip/address_v6.hpp>

namespace unicity {
namespace protocol {

// MessageHeader implementation
MessageHeader::MessageHeader() noexcept : magic(0), length(0) {
  command.fill(0);
  checksum.fill(0);
}

MessageHeader::MessageHeader(uint32_t magic, const std::string& cmd, uint32_t len) : magic(magic), length(len) {
  set_command(cmd);
  checksum.fill(0);  // Checksum set separately
}

std::string MessageHeader::get_command() const {
  // Find null terminator or end of array
  auto end = std::find(command.begin(), command.end(), '\0');
  return std::string(command.begin(), end);
}

void MessageHeader::set_command(const std::string& cmd) {
  command.fill(0);  // Null-pad the entire array
  size_t copy_len = std::min(cmd.length(), COMMAND_SIZE);
  std::memcpy(command.data(), cmd.data(), copy_len);
}

// NetworkAddress implementation
NetworkAddress::NetworkAddress() noexcept : services(0), port(0) {
  ip.fill(0);
}

NetworkAddress::NetworkAddress(uint64_t svcs, const std::array<uint8_t, 16>& addr, uint16_t p) noexcept
    : services(svcs), ip(addr), port(p) {}

NetworkAddress NetworkAddress::from_ipv4(uint64_t services, uint32_t ipv4, uint16_t port) noexcept {
  NetworkAddress addr;
  addr.services = services;
  addr.port = port;

  // IPv4-mapped IPv6 address format: ::ffff:x.x.x.x
  addr.ip.fill(0);
  addr.ip[10] = 0xff;
  addr.ip[11] = 0xff;

  // Store IPv4 in big-endian (network byte order)
  addr.ip[12] = (ipv4 >> 24) & 0xff;
  addr.ip[13] = (ipv4 >> 16) & 0xff;
  addr.ip[14] = (ipv4 >> 8) & 0xff;
  addr.ip[15] = ipv4 & 0xff;

  return addr;
}

NetworkAddress NetworkAddress::from_string(const std::string& ip_str, uint16_t port, uint64_t services) {
  NetworkAddress addr;
  addr.services = services;
  addr.port = port;

  // Parse IP address
  asio::error_code ec;
  auto ip_addr = asio::ip::make_address(ip_str, ec);

  if (ec) {
    // If parsing fails, return empty address
    addr.ip.fill(0);
    return addr;
  }

  // Convert to IPv6 format (IPv4 addresses are mapped to IPv6)
  if (ip_addr.is_v4()) {
    // Convert IPv4 to IPv4-mapped IPv6 (::ffff:x.x.x.x)
    auto v6_mapped = asio::ip::make_address_v6(asio::ip::v4_mapped, ip_addr.to_v4());
    auto bytes = v6_mapped.to_bytes();
    std::copy(bytes.begin(), bytes.end(), addr.ip.begin());
  } else {
    // Pure IPv6
    auto bytes = ip_addr.to_v6().to_bytes();
    std::copy(bytes.begin(), bytes.end(), addr.ip.begin());
  }

  return addr;
}

uint32_t NetworkAddress::get_ipv4() const noexcept {
  if (!is_ipv4()) {
    return 0;
  }

  // Extract IPv4 from the last 4 bytes (big-endian)
  return (static_cast<uint32_t>(ip[12]) << 24) | (static_cast<uint32_t>(ip[13]) << 16) |
         (static_cast<uint32_t>(ip[14]) << 8) | static_cast<uint32_t>(ip[15]);
}

bool NetworkAddress::is_ipv4() const noexcept {
  // Check for IPv4-mapped IPv6 prefix: ::ffff:x.x.x.x
  return ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 && ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
         ip[8] == 0 && ip[9] == 0 && ip[10] == 0xff && ip[11] == 0xff;
}

bool NetworkAddress::is_zero() const noexcept {
  // Check if all bytes are zero (indicates parse failure or uninitialized)
  for (uint8_t b : ip) {
    if (b != 0)
      return false;
  }
  return true;
}

bool NetworkAddress::is_loopback() const noexcept {
  if (is_ipv4()) {
    return util::IsIPv4Loopback(ip[12]);
  }
  return util::IsIPv6Loopback(ip.data());
}

bool NetworkAddress::is_routable() const noexcept {
  if (is_zero())
    return false;

  if (is_ipv4()) {
    return util::IsIPv4Routable(ip[12], ip[13], ip[14], ip[15]);
  }
  return util::IsIPv6Routable(ip.data());
}

std::string NetworkAddress::get_netgroup() const noexcept {
  if (is_zero())
    return "";

  if (is_ipv4()) {
    if (util::IsIPv4Loopback(ip[12]))
      return "local";
    return util::GetIPv4Netgroup(ip[12], ip[13]);
  }

  if (util::IsIPv6Loopback(ip.data()))
    return "local";
  return util::GetIPv6Netgroup(ip.data());
}

std::optional<std::string> NetworkAddress::to_string() const noexcept {
  try {
    asio::ip::address_v6::bytes_type bytes;
    std::copy(ip.begin(), ip.end(), bytes.begin());
    auto v6_addr = asio::ip::make_address_v6(bytes);

    if (v6_addr.is_v4_mapped()) {
      return asio::ip::make_address_v4(asio::ip::v4_mapped, v6_addr).to_string();
    }
    return v6_addr.to_string();
  } catch (const std::exception&) {
    return std::nullopt;
  }
}

bool NetworkAddress::operator<(const NetworkAddress& other) const noexcept {
  // Lexicographic comparison for std::set
  // Compare IP first, then port (services is metadata, not identity)
  if (ip != other.ip) {
    return ip < other.ip;
  }
  return port < other.port;
}

bool NetworkAddress::operator==(const NetworkAddress& other) const noexcept {
  // Peer identity is IP + port (services is metadata, not identity)
  return ip == other.ip && port == other.port;
}

// TimestampedAddress implementation
TimestampedAddress::TimestampedAddress() noexcept : timestamp(0) {}

TimestampedAddress::TimestampedAddress(uint32_t ts, const NetworkAddress& addr) noexcept
    : timestamp(ts), address(addr) {}

// InventoryVector implementation
InventoryVector::InventoryVector() noexcept : type(InventoryType::ERROR), hash() {}

InventoryVector::InventoryVector(InventoryType t, const uint256& h) noexcept : type(t), hash(h) {}

}  // namespace protocol
}  // namespace unicity
