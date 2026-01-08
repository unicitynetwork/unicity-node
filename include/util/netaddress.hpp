#pragma once

/*
 Network Address Utilities

 Purpose:
 - Validate and normalize IP address strings
 - Prevent invalid addresses from entering the system
 - Centralized address handling to avoid code duplication

 Key functions:
 - ValidateAndNormalizeIP: Validates address format and normalizes (IPv4-mapped -> IPv4)
 - IsValidIPAddress: Quick check if address string is valid
*/

#include <array>
#include <cstdint>
#include <optional>
#include <string>

namespace unicity {
namespace util {

/**
 * Validate and normalize an IP address string
 *
 * This function wraps asio::ip::make_address() with critical additions:
 * 1. Validates that the string is a valid IP address (IPv4 or IPv6)
 * 2. **Normalizes IPv4-mapped IPv6 addresses to IPv4 format (::ffff:1.2.3.4 -> 1.2.3.4)**
 * 3. Returns the canonical string representation
 *
 * Why not use boost directly?
 * - IPv4-mapped normalization is CRITICAL for security (prevents ban evasion, limit bypass)
 * - Without normalization: "192.168.1.1" and "::ffff:192.168.1.1" would be treated as different
 * - Used in 10+ locations: BanManager (ban storage/lookup), PeerRegistry (per-IP limits),
 *   RPC Server (API responses) - consistency is essential
 *
 * Security: Prevents malformed addresses from entering the system
 * - Rejects empty strings
 * - Rejects invalid IP formats
 * - Rejects hostnames (only numeric IPs accepted)
 * - Exception-safe wrapper
 *
 * @param address IP address string to validate and normalize
 * @return Normalized IP address string, or std::nullopt if invalid
 *
 * Examples:
 *   "192.168.1.1" -> "192.168.1.1"
 *   "::ffff:192.168.1.1" -> "192.168.1.1" (IPv4-mapped normalized - PREVENTS EVASION)
 *   "2001:db8::1" -> "2001:db8::1"
 *   "invalid" -> std::nullopt
 *   "" -> std::nullopt
 */
std::optional<std::string> ValidateAndNormalizeIP(const std::string& address);

/**
 * Check if a string is a valid IP address
 *
 * @param address String to validate
 * @return true if valid IP address, false otherwise
 */
bool IsValidIPAddress(const std::string& address);

/**
 * Parse "IP:port" string into separate IP and port components
 *
 * Supports both IPv4 and IPv6 formats:
 * - IPv4: "192.168.1.1:9590"
 * - IPv6: "[2001:db8::1]:9590"
 *
 * @param address_port String in "IP:port" or "[IPv6]:port" format
 * @param out_ip Output parameter for IP address string
 * @param out_port Output parameter for port number
 * @return true if successfully parsed, false otherwise
 */
bool ParseIPPort(const std::string& address_port, std::string& out_ip, uint16_t& out_port);

/**
 * Check if an address is routable on the public internet
 *
 * @param address IP address string
 * @return true if routable, false if reserved/private/local
 */
bool IsRoutable(const std::string& address);

/**
 * Check if an address is internal (private network, loopback, etc.)
 *
 * @param address IP address string
 * @return true if internal
 */
bool IsInternal(const std::string& address);

/**
 * Check if an address is local (loopback)
 *
 * @param address IP address string
 * @return true if local
 */
bool IsLocal(const std::string& address);

/**
 * Get the network group (netgroup) for an IP address
 * Addresses in the same netgroup are assumed to be controlled by the same entity.
 *
 * Netgroup assignment:
 * - IPv4: /16 prefix (first 2 octets), e.g., "192.168.1.5" -> "192.168"
 * - IPv6: /32 prefix (first 4 bytes), e.g., "2001:db8::1" -> "2001:0db8"
 * - IPv4-mapped IPv6: treated as IPv4, e.g., "::ffff:192.168.1.5" -> "192.168"
 * - Loopback/local: "local"
 * - Unroutable: "unroutable"
 *
 * Prevents attacker from filling peer slots with addresses from same /16.
 * Used in:
 * - Per-netgroup inbound connection limits
 * - Netgroup-aware eviction (protect diversity)
 * - Address bucketing in AddrManager
 *
 */
std::string GetNetgroup(const std::string& address);

// RFC Compliance Checks (string-based, for RPC/config input validation)
bool IsRFC1918(const std::string& address);  // Private IPv4
bool IsRFC2544(const std::string& address);  // Benchmark
bool IsRFC3927(const std::string& address);  // Link-local IPv4
bool IsRFC6598(const std::string& address);  // Shared CGNAT
bool IsRFC5737(const std::string& address);  // Documentation IPv4
bool IsRFC3849(const std::string& address);  // Documentation IPv6
bool IsRFC3964(const std::string& address);  // 6to4
bool IsRFC6052(const std::string& address);  // IPv4-embedded IPv6
bool IsRFC4380(const std::string& address);  // Teredo
bool IsRFC4862(const std::string& address);  // Link-local IPv6
bool IsRFC4193(const std::string& address);  // Unique Local IPv6
bool IsRFC4843(const std::string& address);  // ORCHID

// ============================================================================
// Byte-based helpers (shared by NetworkAddress methods and string functions)
// These operate directly on raw IP bytes - no parsing overhead
// ============================================================================

/**
 * Check if IPv4 address bytes represent a routable address
 * @param b0-b3 The 4 bytes of the IPv4 address in network order
 * @return true if routable on public internet
 */
bool IsIPv4Routable(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3) noexcept;

/**
 * Check if IPv6 address bytes represent a routable address
 * @param bytes Pointer to 16 bytes of IPv6 address
 * @return true if routable on public internet
 */
bool IsIPv6Routable(const uint8_t* bytes) noexcept;

/**
 * Check if IPv4 address is loopback (127.0.0.0/8)
 */
bool IsIPv4Loopback(uint8_t b0) noexcept;

/**
 * Check if IPv6 address is loopback (::1)
 */
bool IsIPv6Loopback(const uint8_t* bytes) noexcept;

/**
 * Get netgroup for IPv4 address (/16 prefix)
 * @param b0, b1 First two bytes of IPv4 address
 * @return Netgroup string like "192.168"
 */
std::string GetIPv4Netgroup(uint8_t b0, uint8_t b1) noexcept;

/**
 * Get netgroup for IPv6 address (/32 prefix)
 * @param bytes Pointer to 16 bytes of IPv6 address
 * @return Netgroup string like "2001:0db8"
 */
std::string GetIPv6Netgroup(const uint8_t* bytes) noexcept;

}  // namespace util
}  // namespace unicity
