// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "util/uint.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>

// Helper function to convert hex character to value
static inline int HexDigit(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

template <unsigned int BITS>
std::string base_blob<BITS>::GetHex() const {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  // Reverse byte order for display (little-endian to big-endian)
  for (int i = WIDTH - 1; i >= 0; --i) {
    ss << std::setw(2) << static_cast<unsigned int>(m_data[i]);
  }
  return ss.str();
}

template <unsigned int BITS>
void base_blob<BITS>::SetHex(const char* psz) {
  SetNull();

  // Skip 0x prefix if present
  if (psz[0] == '0' && (psz[1] == 'x' || psz[1] == 'X')) {
    psz += 2;
  }

  // Count hex digits
  const char* pbegin = psz;
  while (HexDigit(*psz) != -1) {
    psz++;
  }
  psz--;

  // Convert hex string to bytes (reverse order - most significant first in
  // string)
  unsigned char* p1 = begin();
  unsigned char* pend = end();
  while (psz >= pbegin && p1 < pend) {
    *p1 = HexDigit(*psz--);
    if (psz >= pbegin) {
      *p1 |= ((unsigned char)HexDigit(*psz--) << 4);
      p1++;
    }
  }
}

template <unsigned int BITS>
void base_blob<BITS>::SetHex(std::string_view str) {
  SetHex(str.data());
}

template <unsigned int BITS>
std::string base_blob<BITS>::ToString() const {
  return GetHex();
}

// Explicit instantiations for base_blob<160>
template std::string base_blob<160>::GetHex() const;
template void base_blob<160>::SetHex(const char*);
template void base_blob<160>::SetHex(std::string_view);
template std::string base_blob<160>::ToString() const;

// Explicit instantiations for base_blob<256>
template std::string base_blob<256>::GetHex() const;
template void base_blob<256>::SetHex(const char*);
template void base_blob<256>::SetHex(std::string_view);
template std::string base_blob<256>::ToString() const;

// UNICITY EXTENSION: Explicit instantiations for base_blob<512>
template std::string base_blob<512>::GetHex() const;
template void base_blob<512>::SetHex(const char*);
template void base_blob<512>::SetHex(std::string_view);
template std::string base_blob<512>::ToString() const;
// END UNICITY EXTENSION

// Static constants
const uint256 uint256::ZERO(0);
const uint256 uint256::ONE(1);
