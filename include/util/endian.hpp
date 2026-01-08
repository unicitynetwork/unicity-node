// Copyright (c) 2014-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#pragma once

#include <bit>
#include <cstdint>
#include <cstring>

namespace endian {

// Byteswap functions for C++20 (C++23 has std::byteswap)
inline uint16_t byteswap16(uint16_t x) {
  return (x >> 8) | (x << 8);
}

inline uint32_t byteswap32(uint32_t x) {
  return ((x >> 24) & 0x000000FF) | ((x >> 8) & 0x0000FF00) | ((x << 8) & 0x00FF0000) | ((x << 24) & 0xFF000000);
}

inline uint64_t byteswap64(uint64_t x) {
  return ((x >> 56) & 0x00000000000000FFULL) | ((x >> 40) & 0x000000000000FF00ULL) |
         ((x >> 24) & 0x0000000000FF0000ULL) | ((x >> 8) & 0x00000000FF000000ULL) | ((x << 8) & 0x000000FF00000000ULL) |
         ((x << 24) & 0x0000FF0000000000ULL) | ((x << 40) & 0x00FF000000000000ULL) |
         ((x << 56) & 0xFF00000000000000ULL);
}

// Read/Write Little Endian operations
inline uint16_t ReadLE16(const uint8_t* ptr) {
  uint16_t result;
  std::memcpy(&result, ptr, sizeof(result));
  if constexpr (std::endian::native == std::endian::big) {
    result = byteswap16(result);
  }
  return result;
}

inline uint32_t ReadLE32(const uint8_t* ptr) {
  uint32_t result;
  std::memcpy(&result, ptr, sizeof(result));
  if constexpr (std::endian::native == std::endian::big) {
    result = byteswap32(result);
  }
  return result;
}

inline uint64_t ReadLE64(const uint8_t* ptr) {
  uint64_t result;
  std::memcpy(&result, ptr, sizeof(result));
  if constexpr (std::endian::native == std::endian::big) {
    result = byteswap64(result);
  }
  return result;
}

inline void WriteLE16(uint8_t* ptr, uint16_t value) {
  if constexpr (std::endian::native == std::endian::big) {
    value = byteswap16(value);
  }
  std::memcpy(ptr, &value, sizeof(value));
}

inline void WriteLE32(uint8_t* ptr, uint32_t value) {
  if constexpr (std::endian::native == std::endian::big) {
    value = byteswap32(value);
  }
  std::memcpy(ptr, &value, sizeof(value));
}

inline void WriteLE64(uint8_t* ptr, uint64_t value) {
  if constexpr (std::endian::native == std::endian::big) {
    value = byteswap64(value);
  }
  std::memcpy(ptr, &value, sizeof(value));
}

// Read/Write Big Endian operations
inline uint16_t ReadBE16(const uint8_t* ptr) {
  uint16_t result;
  std::memcpy(&result, ptr, sizeof(result));
  if constexpr (std::endian::native == std::endian::little) {
    result = byteswap16(result);
  }
  return result;
}

inline uint32_t ReadBE32(const uint8_t* ptr) {
  uint32_t result;
  std::memcpy(&result, ptr, sizeof(result));
  if constexpr (std::endian::native == std::endian::little) {
    result = byteswap32(result);
  }
  return result;
}

inline uint64_t ReadBE64(const uint8_t* ptr) {
  uint64_t result;
  std::memcpy(&result, ptr, sizeof(result));
  if constexpr (std::endian::native == std::endian::little) {
    result = byteswap64(result);
  }
  return result;
}

inline void WriteBE16(uint8_t* ptr, uint16_t value) {
  if constexpr (std::endian::native == std::endian::little) {
    value = byteswap16(value);
  }
  std::memcpy(ptr, &value, sizeof(value));
}

inline void WriteBE32(uint8_t* ptr, uint32_t value) {
  if constexpr (std::endian::native == std::endian::little) {
    value = byteswap32(value);
  }
  std::memcpy(ptr, &value, sizeof(value));
}

inline void WriteBE64(uint8_t* ptr, uint64_t value) {
  if constexpr (std::endian::native == std::endian::little) {
    value = byteswap64(value);
  }
  std::memcpy(ptr, &value, sizeof(value));
}
}  // namespace endian
