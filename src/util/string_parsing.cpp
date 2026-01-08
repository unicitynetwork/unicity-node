#include "util/string_parsing.hpp"

#include "util/uint.hpp"

#include <cctype>
#include <iomanip>
#include <sstream>

namespace unicity {
namespace util {

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
