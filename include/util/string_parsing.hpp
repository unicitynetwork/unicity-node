#pragma once

/*
 String Parsing Utilities

 Purpose:
 - Safe parsing of strings to numeric types with validation
 - Centralized input validation to prevent crashes from malformed input
 - Consistent error handling across the codebase

 Key functions:
 - SafeParseInt: Parse integer with bounds checking
 - SafeParsePort: Parse port number (1-65535)
 - SafeParseHash: Parse 64-character hexadecimal hash string
 - EscapeJSONString: Escape special characters for JSON output

 Security:
 - All functions validate entire input is consumed (no trailing garbage)
 - Bounds checking prevents overflow/underflow
 - Returns std::nullopt on any parsing error (no exceptions thrown)
 - Safe for use with untrusted input (RPC, command-line args, config files)
*/

#include <cstdint>
#include <optional>
#include <string>

// uint256 must be fully defined for std::optional<uint256>
#include "util/uint.hpp"

namespace unicity {
namespace util {

/**
 * Parse integer string with bounds checking
 *
 * Security:
 * - Validates entire string is consumed (no trailing characters)
 * - Checks value is within [min, max] range
 * - Returns std::nullopt on any error (never throws)
 *
 * @param str String to parse
 * @param min Minimum allowed value (inclusive)
 * @param max Maximum allowed value (inclusive)
 * @return Parsed integer or std::nullopt if invalid
 *
 * Examples:
 *   SafeParseInt("42", 0, 100) -> 42
 *   SafeParseInt("999", 0, 100) -> std::nullopt (out of range)
 *   SafeParseInt("42x", 0, 100) -> std::nullopt (trailing chars)
 *   SafeParseInt("", 0, 100) -> std::nullopt (empty string)
 */
std::optional<int> SafeParseInt(const std::string& str, int min, int max);

/**
 * Parse port number string (1-65535)
 *
 * Security:
 * - Validates entire string is consumed
 * - Checks value is valid port range [1, 65535]
 * - Returns std::nullopt on any error
 *
 * @param str String to parse (e.g., "9590")
 * @return Parsed port or std::nullopt if invalid
 *
 * Examples:
 *   SafeParsePort("9590") -> 9590
 *   SafeParsePort("0") -> std::nullopt (port 0 invalid)
 *   SafeParsePort("99999") -> std::nullopt (out of range)
 */
std::optional<uint16_t> SafeParsePort(const std::string& str);

/**
 * Parse int64_t string with bounds checking
 *
 * Security:
 * - Validates entire string is consumed (no trailing characters)
 * - Checks value is within [min, max] range
 * - Returns std::nullopt on any error (never throws)
 *
 * @param str String to parse
 * @param min Minimum allowed value (inclusive)
 * @param max Maximum allowed value (inclusive)
 * @return Parsed int64_t or std::nullopt if invalid
 *
 * Examples:
 *   SafeParseInt64("86400", 0, 1000000) -> 86400
 *   SafeParseInt64("-1", 0, 1000000) -> std::nullopt (out of range)
 *   SafeParseInt64("999999999999999999999", 0, INT64_MAX) -> std::nullopt (overflow)
 */
std::optional<int64_t> SafeParseInt64(const std::string& str, int64_t min, int64_t max);

/**
 * Validate hexadecimal string
 *
 * @param str String to validate
 * @return true if all characters are hex digits [0-9a-fA-F]
 *
 * Examples:
 *   IsValidHex("deadbeef") -> true
 *   IsValidHex("xyz") -> false
 *   IsValidHex("") -> false
 */
bool IsValidHex(const std::string& str);

/**
 * Parse 64-character hexadecimal hash string
 *
 * Security:
 * - Validates length is exactly 64 characters
 * - Validates all characters are hex digits [0-9a-fA-F]
 * - Returns std::nullopt on any error
 *
 * @param str Hash string to parse
 * @return Parsed hash or std::nullopt if invalid
 *
 * Examples:
 *   SafeParseHash("0123456789abcdef...") -> valid uint256
 *   SafeParseHash("xyz") -> std::nullopt (invalid chars)
 *   SafeParseHash("123") -> std::nullopt (wrong length)
 */
std::optional<uint256> SafeParseHash(const std::string& str);

/**
 * Escape special characters in string for JSON output
 *
 * Escapes: " \ / \b \f \n \r \t
 *
 * @param str String to escape
 * @return Escaped string safe for JSON
 *
 * Example:
 *   EscapeJSONString("hello\nworld") -> "hello\\nworld"
 */
std::string EscapeJSONString(const std::string& str);

/**
 * Create JSON error response (for RPC)
 *
 * @param message Error message
 * @return Formatted JSON error string with newline
 *
 * Example:
 *   JsonError("Invalid parameter") -> "{\"error\":\"Invalid parameter\"}\n"
 */
std::string JsonError(const std::string& message);

/**
 * Create JSON success response with single result field (for RPC)
 *
 * @param result Result value (will be escaped if needed)
 * @return Formatted JSON success string with newline
 *
 * Example:
 *   JsonSuccess("true") -> "{\"result\":\"true\"}\n"
 */
std::string JsonSuccess(const std::string& result);

}  // namespace util
}  // namespace unicity
