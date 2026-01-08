// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "util/sha256.hpp"
#include "util/uint.hpp"

#include <cassert>
#include <span>
#include <vector>

/** A hasher class for Bitcoin's 256-bit hash (double SHA-256). */
class CHash256 {
private:
  CSHA256 sha;

public:
  static const size_t OUTPUT_SIZE = CSHA256::OUTPUT_SIZE;

  void Finalize(std::span<unsigned char> output) {
    assert(output.size() == OUTPUT_SIZE);
    unsigned char buf[CSHA256::OUTPUT_SIZE];
    sha.Finalize(buf);
    sha.Reset().Write(buf, CSHA256::OUTPUT_SIZE).Finalize(output.data());
  }

  void Finalize(uint256& output) {
    unsigned char buf[CSHA256::OUTPUT_SIZE];
    sha.Finalize(buf);
    sha.Reset().Write(buf, CSHA256::OUTPUT_SIZE).Finalize(output.begin());
  }

  CHash256& Write(const unsigned char* data, size_t len) {
    sha.Write(data, len);
    return *this;
  }

  CHash256& Reset() {
    sha.Reset();
    return *this;
  }
};

/** Compute the 256-bit hash of a byte vector (double SHA-256). */
inline uint256 Hash(const std::vector<uint8_t>& data) {
  uint256 result;
  CHash256().Write(data.data(), data.size()).Finalize(result);
  return result;
}

/** Compute the 256-bit hash of a byte span (double SHA-256). */
inline uint256 Hash(std::span<const uint8_t> data) {
  uint256 result;
  CHash256().Write(data.data(), data.size()).Finalize(result);
  return result;
}
