// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "util/endian.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace detail {
/** Compile-time hex digit parser. Throws on invalid input (causes compile error in consteval). */
consteval uint8_t ConstevalHexDigit(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  throw "Invalid hex character";
}
}  // namespace detail

/** Template base class for fixed-sized opaque blobs. */
template <unsigned int BITS>
class base_blob {
protected:
  static constexpr int WIDTH = BITS / 8;
  static_assert(BITS % 8 == 0, "base_blob currently only supports whole bytes.");
  std::array<uint8_t, WIDTH> m_data;
  static_assert(WIDTH == sizeof(m_data), "Sanity check");

public:
  /* construct 0 value by default */
  constexpr base_blob() : m_data() {}

  /* constructor for constants between 1 and 255 */
  constexpr explicit base_blob(uint8_t v) : m_data{v} {}

  constexpr explicit base_blob(std::span<const unsigned char> vch) {
    assert(vch.size() == WIDTH);
    std::copy(vch.begin(), vch.end(), m_data.begin());
  }

  /** Compile-time constructor from hex string. Invalid hex causes compile error. */
  consteval explicit base_blob(std::string_view hex_str);

  constexpr bool IsNull() const {
    return std::all_of(m_data.begin(), m_data.end(), [](uint8_t val) { return val == 0; });
  }

  constexpr void SetNull() { std::fill(m_data.begin(), m_data.end(), 0); }

  /** Lexicographic ordering
   * @note Does NOT match the ordering on the corresponding \ref
   *       base_uint::CompareTo, which starts comparing from the end.
   */
  constexpr int Compare(const base_blob& other) const { return std::memcmp(m_data.data(), other.m_data.data(), WIDTH); }

  friend constexpr bool operator==(const base_blob& a, const base_blob& b) { return a.Compare(b) == 0; }
  friend constexpr bool operator!=(const base_blob& a, const base_blob& b) { return a.Compare(b) != 0; }
  friend constexpr bool operator<(const base_blob& a, const base_blob& b) { return a.Compare(b) < 0; }

  /** @name Hex representation
   *
   * The hex representation used by GetHex(), ToString(), and SetHex()
   * is unusual, since it shows bytes of the base_blob in reverse order.
   * For example, a 4-byte blob {0x12, 0x34, 0x56, 0x78} is represented
   * as "78563412" instead of the more typical "12345678" representation
   * that would be shown in a hex editor or used by typical
   * byte-array / hex conversion functions like python's bytes.hex() and
   * bytes.fromhex().
   *
   * The nice thing about the reverse-byte representation, even though it is
   * unusual, is that if a blob contains an arithmetic number in little endian
   * format (with least significant bytes first, and most significant bytes
   * last), the GetHex() output will match the way the number would normally
   * be written in base-16 (with most significant digits first and least
   * significant digits last).
   *
   * This means, for example, that ArithToUint256(num).GetHex() can be used to
   * display an arith_uint256 num value as a number, because
   * ArithToUint256() converts the number to a blob in little-endian format,
   * so the arith_uint256 class doesn't need to have its own number parsing
   * and formatting functions.
   *
   * @{*/
  std::string GetHex() const;
  std::string ToString() const;

  /** Set from hex string. Supports optional "0x" prefix. */
  void SetHex(const char* psz);
  void SetHex(std::string_view str);
  /**@}*/

  constexpr const unsigned char* data() const { return m_data.data(); }
  constexpr unsigned char* data() { return m_data.data(); }

  constexpr unsigned char* begin() { return m_data.data(); }
  constexpr unsigned char* end() { return m_data.data() + WIDTH; }

  constexpr const unsigned char* begin() const { return m_data.data(); }
  constexpr const unsigned char* end() const { return m_data.data() + WIDTH; }

  static constexpr unsigned int size() { return WIDTH; }

  constexpr uint64_t GetUint64(int pos) const { return endian::ReadLE64(m_data.data() + pos * 8); }

  // UNICITY EXTENSIONS
  // Additional method to read 32-bit integers at positions
  constexpr uint32_t GetUint32(int pos) const {
    assert(pos >= 0 && pos * 4 + 4 <= WIDTH);
    return endian::ReadLE32(m_data.data() + pos * 4);
  }
  // END UNICITY EXTENSIONS

  template <typename Stream>
  void Serialize(Stream& s) const {
    s.write(reinterpret_cast<const char*>(m_data.data()), WIDTH);
  }

  template <typename Stream>
  void Unserialize(Stream& s) {
    s.read(reinterpret_cast<char*>(m_data.data()), WIDTH);
  }
};

/** Compile-time hex string constructor implementation.
 * Parses hex in reverse byte order (matches GetHex() format).
 * Throws at compile time if hex string is wrong length or contains invalid chars.
 */
template <unsigned int BITS>
consteval base_blob<BITS>::base_blob(std::string_view hex_str) : m_data() {
  if (hex_str.length() != WIDTH * 2)
    throw "Hex string must be exactly WIDTH*2 characters";
  auto str_it = hex_str.rbegin();
  for (auto& elem : m_data) {
    auto lo = detail::ConstevalHexDigit(*(str_it++));
    elem = (detail::ConstevalHexDigit(*(str_it++)) << 4) | lo;
  }
}

/** 160-bit opaque blob.
 * @note This type is called uint160 for historical reasons only. It is an
 * opaque blob of 160 bits and has no integer operations.
 */
class uint160 : public base_blob<160> {
public:
  constexpr uint160() = default;
  constexpr explicit uint160(std::span<const unsigned char> vch) : base_blob<160>(vch) {}
};

/** 256-bit opaque blob.
 * @note This type is called uint256 for historical reasons only. It is an
 * opaque blob of 256 bits and has no integer operations. Use arith_uint256 if
 * those are required.
 */
class uint256 : public base_blob<256> {
public:
  constexpr uint256() = default;
  /** Compile-time construction from hex string. Invalid hex causes compile error. */
  consteval explicit uint256(std::string_view hex_str) : base_blob<256>(hex_str) {}
  constexpr explicit uint256(uint8_t v) : base_blob<256>(v) {}
  constexpr explicit uint256(std::span<const unsigned char> vch) : base_blob<256>(vch) {}

  static const uint256 ZERO;
  static const uint256 ONE;
};

/* uint256 from const char *.
 * This is a separate function because the constructor uint256(const char*) can
 * result in dangerously catching uint256(0).
 */
inline uint256 uint256S(const char* str) {
  uint256 rv;
  rv.SetHex(str);
  return rv;
}

/* uint256 from std::string.
 * This is a separate function because the constructor uint256(const std::string
 * &str) can result in dangerously catching uint256(0) via std::string(const
 * char*).
 */
inline uint256 uint256S(std::string_view str) {
  uint256 rv;
  rv.SetHex(str);
  return rv;
}
