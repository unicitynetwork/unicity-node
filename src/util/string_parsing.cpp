// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "util/string_parsing.hpp"

#include "util/uint.hpp"

#include <cctype>
#include <format>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace unicity {
namespace util {

namespace {
uint8_t hexValue(char c) {
  if ('0' <= c && c <= '9')
    return c - '0';
  if ('a' <= c && c <= 'f')
    return c - 'a' + 10;
  if ('A' <= c && c <= 'F')
    return c - 'A' + 10;
  throw std::invalid_argument("Invalid hex character");
}
}  // namespace

std::optional<int> SafeParseInt(const std::string& str, int min, int max) {
  try {
    // Reject empty or whitespace-only strings
    if (str.empty() || std::isspace(static_cast<unsigned char>(str[0]))) {
      return std::nullopt;
    }

    size_t pos = 0;
    long value = std::stol(str, &pos);

    // Check entire string was consumed
    if (pos != str.size()) {
      return std::nullopt;
    }

    // Check bounds
    if (value < min || value > max) {
      return std::nullopt;
    }

    return static_cast<int>(value);
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<uint16_t> SafeParsePort(const std::string& str) {
  try {
    // Reject empty or whitespace-leading strings
    if (str.empty() || std::isspace(static_cast<unsigned char>(str[0]))) {
      return std::nullopt;
    }

    size_t pos = 0;
    long value = std::stol(str, &pos);

    // Check entire string was consumed
    if (pos != str.size()) {
      return std::nullopt;
    }

    // Check valid port range
    if (value < 1 || value > 65535) {
      return std::nullopt;
    }

    return static_cast<uint16_t>(value);
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<int64_t> SafeParseInt64(const std::string& str, int64_t min, int64_t max) {
  try {
    // Reject empty or whitespace-leading strings
    if (str.empty() || std::isspace(static_cast<unsigned char>(str[0]))) {
      return std::nullopt;
    }

    size_t pos = 0;
    long long value = std::stoll(str, &pos);

    // Check entire string was consumed
    if (pos != str.size()) {
      return std::nullopt;
    }

    // Check bounds
    if (value < min || value > max) {
      return std::nullopt;
    }

    return static_cast<int64_t>(value);
  } catch (...) {
    return std::nullopt;
  }
}

bool IsValidHex(const std::string& str) {
  if (str.empty()) {
    return false;
  }

  for (char c : str) {
    if (!std::isxdigit(static_cast<unsigned char>(c))) {
      return false;
    }
  }
  return true;
}

std::string ToHex(const std::span<const uint8_t> data) {
  static constexpr char hex_chars[] = "0123456789abcdef";
  std::string out;
  out.reserve(data.size() * 2);

  for (const uint8_t b : data) {
    out.push_back(hex_chars[b >> 4]);
    out.push_back(hex_chars[b & 0x0f]);
  }

  return out;
}

std::vector<uint8_t> ParseHex(const std::string_view hex) {
  if (hex.size() % 2 != 0) {
    throw std::invalid_argument("Hex string must have even length");
  }

  std::vector<uint8_t> out;
  out.reserve(hex.size() / 2);

  for (size_t i = 0; i < hex.size(); i += 2) {
    const uint8_t high = hexValue(hex[i]);
    const uint8_t low = hexValue(hex[i + 1]);
    out.push_back((high << 4) | low);
  }

  return out;
}

std::optional<uint256> SafeParseHash(const std::string& str) {
  // Check length
  if (str.size() != 64) {
    return std::nullopt;
  }

  // Validate hex characters using helper
  if (!IsValidHex(str)) {
    return std::nullopt;
  }

  uint256 hash;
  hash.SetHex(str);
  return hash;
}

std::string EscapeJSONString(const std::string& str) {
  std::ostringstream oss;
  for (char c : str) {
    switch (c) {
    case '"':
      oss << "\\\"";
      break;
    case '\\':
      oss << "\\\\";
      break;
    case '\b':
      oss << "\\b";
      break;
    case '\f':
      oss << "\\f";
      break;
    case '\n':
      oss << "\\n";
      break;
    case '\r':
      oss << "\\r";
      break;
    case '\t':
      oss << "\\t";
      break;
    default:
      if (c < 0x20) {
        oss << "\\u" << std::hex << std::setw(4) << std::setfill('0')
            << static_cast<int>(static_cast<unsigned char>(c));
      } else {
        oss << c;
      }
    }
  }
  return oss.str();
}

std::string JsonError(const std::string& message) {
  return "{\"error\":\"" + EscapeJSONString(message) + "\"}\n";
}

std::string JsonSuccess(const std::string& result) {
  return "{\"result\":\"" + EscapeJSONString(result) + "\"}\n";
}

}  // namespace util
}  // namespace unicity
