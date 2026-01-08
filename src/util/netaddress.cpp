#include "util/netaddress.hpp"

#include "util/logging.hpp"
#include "util/string_parsing.hpp"

#include <array>
#include <cstdio>

#include <asio/ip/address.hpp>

namespace unicity {
namespace util {

// ============================================================================
// Byte-based helpers (shared implementation)
// ============================================================================

bool IsIPv4Loopback(uint8_t b0) noexcept {
  // 127.0.0.0/8 - Loopback (RFC 1122)
  // 0.0.0.0/8 - "This network" (RFC 1122) - treated as local
  return b0 == 127 || b0 == 0;
}

bool IsIPv6Loopback(const uint8_t* bytes) noexcept {
  for (int i = 0; i < 15; i++) {
    if (bytes[i] != 0)
      return false;
  }
  return bytes[15] == 1;
}

bool IsIPv4Routable(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3) noexcept {
  // 0.0.0.0/8 - "This network" (RFC 1122)
  if (b0 == 0)
    return false;

  // 10.0.0.0/8 - Private (RFC 1918)
  if (b0 == 10)
    return false;

  // 100.64.0.0/10 - Shared CGNAT (RFC 6598)
  if (b0 == 100 && (b1 >= 64 && b1 <= 127))
    return false;

  // 127.0.0.0/8 - Loopback (RFC 1122)
  if (b0 == 127)
    return false;

  // 169.254.0.0/16 - Link-local (RFC 3927)
  if (b0 == 169 && b1 == 254)
    return false;

  // 172.16.0.0/12 - Private (RFC 1918)
  if (b0 == 172 && (b1 >= 16 && b1 <= 31))
    return false;

  // 192.0.0.0/24 - IETF Protocol Assignments (RFC 6890)
  if (b0 == 192 && b1 == 0 && b2 == 0)
    return false;

  // 192.0.2.0/24 - Documentation TEST-NET-1 (RFC 5737)
  if (b0 == 192 && b1 == 0 && b2 == 2)
    return false;

  // 192.168.0.0/16 - Private (RFC 1918)
  if (b0 == 192 && b1 == 168)
    return false;

  // 198.18.0.0/15 - Benchmarking (RFC 2544)
  if (b0 == 198 && (b1 == 18 || b1 == 19))
    return false;

  // 198.51.100.0/24 - Documentation TEST-NET-2 (RFC 5737)
  if (b0 == 198 && b1 == 51 && b2 == 100)
    return false;

  // 203.0.113.0/24 - Documentation TEST-NET-3 (RFC 5737)
  if (b0 == 203 && b1 == 0 && b2 == 113)
    return false;

  // 224.0.0.0/4 - Multicast (RFC 5771)
  if ((b0 & 0xF0) == 224)
    return false;

  // 240.0.0.0/4 - Reserved (RFC 1112)
  if ((b0 & 0xF0) == 240)
    return false;

  // 255.255.255.255 - Broadcast
  if (b0 == 255 && b1 == 255 && b2 == 255 && b3 == 255)
    return false;

  return true;
}

bool IsIPv6Routable(const uint8_t* bytes) noexcept {
  // :: - Unspecified (all zeros)
  bool all_zero = true;
  for (int i = 0; i < 16; i++) {
    if (bytes[i] != 0) {
      all_zero = false;
      break;
    }
  }
  if (all_zero)
    return false;

  // ::1 - Loopback
  if (IsIPv6Loopback(bytes))
    return false;

  // fe80::/10 - Link-local (RFC 4291)
  if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80)
    return false;

  // fc00::/7 - Unique local (RFC 4193)
  if ((bytes[0] & 0xfe) == 0xfc)
    return false;

  // ff00::/8 - Multicast (RFC 4291)
  if (bytes[0] == 0xff)
    return false;

  // 2001:db8::/32 - Documentation (RFC 3849)
  if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8)
    return false;

  // 2001::/32 - Teredo (RFC 4380)
  if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x00 && bytes[3] == 0x00)
    return false;

  // 2002::/16 - 6to4 (RFC 3964)
  if (bytes[0] == 0x20 && bytes[1] == 0x02)
    return false;

  // 2001:10::/28 - ORCHID (RFC 4843)
  if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x00 && (bytes[3] & 0xf0) == 0x10)
    return false;

  // 2001:20::/28 - ORCHIDv2 (RFC 7343)
  if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x00 && (bytes[3] & 0xf0) == 0x20)
    return false;

  return true;
}

std::string GetIPv4Netgroup(uint8_t b0, uint8_t b1) noexcept {
  char buf[8];
  snprintf(buf, sizeof(buf), "%u.%u", b0, b1);
  return std::string(buf);
}

std::string GetIPv6Netgroup(const uint8_t* bytes) noexcept {
  char buf[16];
  snprintf(buf, sizeof(buf), "%02x%02x:%02x%02x", bytes[0], bytes[1], bytes[2], bytes[3]);
  return std::string(buf);
}

// ============================================================================
// String-based functions (parse then delegate to byte helpers)
// ============================================================================

std::optional<std::string> ValidateAndNormalizeIP(const std::string& address) {
  // Reject empty strings
  if (address.empty()) {
    return std::nullopt;
  }

  try {
    // Parse the address
    asio::error_code ec;
    auto ip = asio::ip::make_address(address, ec);

    // Reject invalid formats
    if (ec) {
      return std::nullopt;
    }

    // Normalize IPv4-mapped IPv6 addresses to IPv4 format
    // Example: ::ffff:192.168.1.1 -> 192.168.1.1
    if (ip.is_v6() && ip.to_v6().is_v4_mapped()) {
      auto v4 = asio::ip::make_address_v4(asio::ip::v4_mapped, ip.to_v6());
      return v4.to_string();
    }

    // Return canonical string representation
    return ip.to_string();

  } catch (const std::exception& e) {
    // Catch any unexpected exceptions during parsing
    LOG_TRACE("ValidateAndNormalizeIP: exception parsing address '{}': {}", address, e.what());
    return std::nullopt;
  }
}

bool IsValidIPAddress(const std::string& address) {
  return ValidateAndNormalizeIP(address).has_value();
}

// Helper function to parse port string (used internally by ParseIPPort)
static bool ParsePortString(const std::string& port_str, uint16_t& out_port) {
  // Use SafeParsePort for proper validation (rejects trailing characters, whitespace, etc.)
  auto port_opt = SafeParsePort(port_str);
  if (!port_opt) {
    return false;
  }
  out_port = *port_opt;
  return true;
}

bool ParseIPPort(const std::string& address_port, std::string& out_ip, uint16_t& out_port) {
  if (address_port.empty()) {
    return false;
  }

  // Check for IPv6 format: "[IPv6]:port"
  if (address_port[0] == '[') {
    size_t bracket_end = address_port.find(']');
    if (bracket_end == std::string::npos) {
      return false;  // Missing closing bracket
    }

    // Extract IPv6 address without brackets
    if (bracket_end < 2) {
      return false;  // Empty brackets
    }
    out_ip = address_port.substr(1, bracket_end - 1);

    // Check for port after bracket
    if (bracket_end + 1 >= address_port.length() || address_port[bracket_end + 1] != ':') {
      return false;  // Missing :port
    }

    std::string port_str = address_port.substr(bracket_end + 2);

    // Parse port using helper function
    if (!ParsePortString(port_str, out_port)) {
      return false;
    }

    // Validate and normalize IPv6 address
    auto normalized = ValidateAndNormalizeIP(out_ip);
    if (!normalized.has_value()) {
      return false;
    }
    out_ip = *normalized;
    return true;
  }

  // IPv4 format: "IP:port"
  // IMPORTANT: Check for multiple colons to detect unbracketed IPv6
  size_t first_colon = address_port.find(':');
  if (first_colon == std::string::npos) {
    return false;  // Missing port
  }

  size_t second_colon = address_port.find(':', first_colon + 1);
  if (second_colon != std::string::npos) {
    // Multiple colons found - this is IPv6 without brackets, which is invalid
    return false;
  }

  out_ip = address_port.substr(0, first_colon);
  std::string port_str = address_port.substr(first_colon + 1);

  if (out_ip.empty()) {
    return false;
  }

  // Parse port using helper function
  if (!ParsePortString(port_str, out_port)) {
    return false;
  }

  // Validate and normalize IPv4 address
  auto normalized = ValidateAndNormalizeIP(out_ip);
  if (!normalized.has_value()) {
    return false;
  }
  out_ip = *normalized;
  return true;
}

// Helper to get address object
static std::optional<asio::ip::address> ParseAddress(const std::string& address) {
  asio::error_code ec;
  auto ip = asio::ip::make_address(address, ec);
  if (ec)
    return std::nullopt;

  // Normalize mapped addresses for consistent checking
  if (ip.is_v6() && ip.to_v6().is_v4_mapped()) {
    return asio::ip::make_address_v4(asio::ip::v4_mapped, ip.to_v6());
  }
  return ip;
}

bool IsRFC1918(const std::string& address) {
  auto ip_opt = ParseAddress(address);
  if (!ip_opt || !ip_opt->is_v4())
    return false;
  auto bytes = ip_opt->to_v4().to_bytes();

  // 10.0.0.0/8
  if (bytes[0] == 10)
    return true;
  // 172.16.0.0/12
  if (bytes[0] == 172 && (bytes[1] >= 16 && bytes[1] <= 31))
    return true;
  // 192.168.0.0/16
  if (bytes[0] == 192 && bytes[1] == 168)
    return true;

  return false;
}

bool IsRFC2544(const std::string& address) {
  auto ip_opt = ParseAddress(address);
  if (!ip_opt || !ip_opt->is_v4())
    return false;
  auto bytes = ip_opt->to_v4().to_bytes();

  // 198.18.0.0/15
  if (bytes[0] == 198 && (bytes[1] == 18 || bytes[1] == 19))
    return true;

  return false;
}

bool IsRFC3927(const std::string& address) {
  auto ip_opt = ParseAddress(address);
  if (!ip_opt || !ip_opt->is_v4())
    return false;
  auto bytes = ip_opt->to_v4().to_bytes();

  // 169.254.0.0/16
  if (bytes[0] == 169 && bytes[1] == 254)
    return true;

  return false;
}

bool IsRFC6598(const std::string& address) {
  auto ip_opt = ParseAddress(address);
  if (!ip_opt || !ip_opt->is_v4())
    return false;
  auto bytes = ip_opt->to_v4().to_bytes();

  // 100.64.0.0/10
  if (bytes[0] == 100 && (bytes[1] >= 64 && bytes[1] <= 127))
    return true;

  return false;
}

bool IsRFC5737(const std::string& address) {
  auto ip_opt = ParseAddress(address);
  if (!ip_opt || !ip_opt->is_v4())
    return false;
  auto bytes = ip_opt->to_v4().to_bytes();

  // 192.0.2.0/24
  if (bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 2)
    return true;
  // 198.51.100.0/24
  if (bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100)
    return true;
  // 203.0.113.0/24
  if (bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113)
    return true;

  return false;
}

bool IsRFC3849(const std::string& address) {
  auto ip_opt = ParseAddress(address);
  if (!ip_opt || !ip_opt->is_v6())
    return false;
  auto bytes = ip_opt->to_v6().to_bytes();

  // 2001:0DB8::/32
  if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8)
    return true;

  return false;
}

bool IsRFC3964(const std::string& address) {
  auto ip_opt = ParseAddress(address);
  if (!ip_opt || !ip_opt->is_v6())
    return false;
  auto bytes = ip_opt->to_v6().to_bytes();

  // 2002::/16
  if (bytes[0] == 0x20 && bytes[1] == 0x02)
    return true;

  return false;
}

bool IsRFC6052(const std::string& address) {
  auto ip_opt = ParseAddress(address);
  if (!ip_opt || !ip_opt->is_v6())
    return false;
  auto bytes = ip_opt->to_v6().to_bytes();

  // 64:FF9B::/96
  if (bytes[0] == 0x00 && bytes[1] == 0x64 && bytes[2] == 0xff && bytes[3] == 0x9b && bytes[4] == 0x00 &&
      bytes[5] == 0x00 && bytes[6] == 0x00 && bytes[7] == 0x00 && bytes[8] == 0x00 && bytes[9] == 0x00 &&
      bytes[10] == 0x00 && bytes[11] == 0x00)
    return true;

  return false;
}

bool IsRFC4380(const std::string& address) {
  auto ip_opt = ParseAddress(address);
  if (!ip_opt || !ip_opt->is_v6())
    return false;
  auto bytes = ip_opt->to_v6().to_bytes();

  // 2001::/32 (Teredo)
  if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x00 && bytes[3] == 0x00)
    return true;

  return false;
}

bool IsRFC4862(const std::string& address) {
  auto ip_opt = ParseAddress(address);
  if (!ip_opt || !ip_opt->is_v6())
    return false;
  auto bytes = ip_opt->to_v6().to_bytes();

  // FE80::/64 (Link Local)
  if (bytes[0] == 0xfe && bytes[1] == 0x80 && bytes[2] == 0x00 && bytes[3] == 0x00 && bytes[4] == 0x00 &&
      bytes[5] == 0x00 && bytes[6] == 0x00 && bytes[7] == 0x00)
    return true;

  return false;
}

bool IsRFC4193(const std::string& address) {
  auto ip_opt = ParseAddress(address);
  if (!ip_opt || !ip_opt->is_v6())
    return false;
  auto bytes = ip_opt->to_v6().to_bytes();

  // FC00::/7 (Unique Local)
  if ((bytes[0] & 0xfe) == 0xfc)
    return true;

  return false;
}

bool IsRFC4843(const std::string& address) {
  auto ip_opt = ParseAddress(address);
  if (!ip_opt || !ip_opt->is_v6())
    return false;
  auto bytes = ip_opt->to_v6().to_bytes();

  // 2001:10::/28 (ORCHID)
  if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x00 && (bytes[3] & 0xf0) == 0x10)
    return true;

  return false;
}

bool IsLocal(const std::string& address) {
  auto ip_opt = ParseAddress(address);
  if (!ip_opt)
    return false;

  // Check loopback using our byte-based helpers (includes 0.0.0.0/8)
  if (ip_opt->is_v4()) {
    auto bytes = ip_opt->to_v4().to_bytes();
    if (IsIPv4Loopback(bytes[0]))
      return true;
  } else if (ip_opt->is_v6()) {
    auto bytes = ip_opt->to_v6().to_bytes();
    if (IsIPv6Loopback(bytes.data()))
      return true;
  }

  // IPv4 Link Local (RFC3927)
  if (IsRFC3927(address))
    return true;

  // IPv6 Link Local (RFC4862)
  if (IsRFC4862(address))
    return true;

  return false;
}

bool IsInternal(const std::string& address) {
  if (IsRFC1918(address))
    return true;
  if (IsRFC4193(address))
    return true;
  if (IsRFC6598(address))
    return true;
  if (IsRFC4862(address))
    return true;
  if (IsRFC4380(address))
    return true;
  if (IsRFC4843(address))
    return true;
  return false;
}

std::string GetNetgroup(const std::string& address) {
  auto ip_opt = ParseAddress(address);
  if (!ip_opt)
    return "";

  if (ip_opt->is_v4()) {
    auto bytes = ip_opt->to_v4().to_bytes();
    if (IsIPv4Loopback(bytes[0]))
      return "local";
    return GetIPv4Netgroup(bytes[0], bytes[1]);
  }

  if (ip_opt->is_v6()) {
    auto bytes = ip_opt->to_v6().to_bytes();
    if (IsIPv6Loopback(bytes.data()))
      return "local";
    return GetIPv6Netgroup(bytes.data());
  }

  return "";
}

bool IsRoutable(const std::string& address) {
  auto ip_opt = ParseAddress(address);
  if (!ip_opt)
    return false;

  if (ip_opt->is_v4()) {
    auto bytes = ip_opt->to_v4().to_bytes();
    return IsIPv4Routable(bytes[0], bytes[1], bytes[2], bytes[3]);
  }

  if (ip_opt->is_v6()) {
    auto bytes = ip_opt->to_v6().to_bytes();
    return IsIPv6Routable(bytes.data());
  }

  return false;
}

}  // namespace util
}  // namespace unicity
