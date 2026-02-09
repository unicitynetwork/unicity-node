// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/block.hpp"

#include "util/endian.hpp"
#include "util/sha256.hpp"

#include <algorithm>
#include <cassert>
#include <iomanip>
#include <sstream>

namespace {
// Compile-time header size calculation
constexpr size_t kHeaderSize = 4 /*nVersion*/ + 32 /*hashPrevBlock*/ + 20 /*minerAddress*/ + 4 /*nTime*/ +
                               4 /*nBits*/ + 4 /*nNonce*/ + 32 /*hashRandomX*/;
static_assert(kHeaderSize == CBlockHeader::HEADER_SIZE, "HEADER_SIZE mismatch");
}  // namespace

uint256 CBlockHeader::GetHash() const noexcept {
  const auto s = Serialize();

  uint8_t tmp[CSHA256::OUTPUT_SIZE];
  CSHA256().Write(s.data(), s.size()).Finalize(tmp);

  uint256 out;
  CSHA256().Write(tmp, sizeof(tmp)).Finalize(out.begin());
  return out;
}

CBlockHeader::HeaderBytes CBlockHeader::Serialize() const noexcept {
  HeaderBytes data{};

  // nVersion (4 bytes, offset 0)
  endian::WriteLE32(data.data() + OFF_VERSION, static_cast<uint32_t>(nVersion));

  // hashPrevBlock (32 bytes, offset 4)
  std::copy(hashPrevBlock.begin(), hashPrevBlock.end(), data.begin() + OFF_PREV);

  // minerAddress (20 bytes, offset 36)
  std::copy(minerAddress.begin(), minerAddress.end(), data.begin() + OFF_MINER);

  // nTime (4 bytes, offset 56)
  endian::WriteLE32(data.data() + OFF_TIME, nTime);

  // nBits (4 bytes, offset 60)
  endian::WriteLE32(data.data() + OFF_BITS, nBits);

  // nNonce (4 bytes, offset 64)
  endian::WriteLE32(data.data() + OFF_NONCE, nNonce);

  // hashRandomX (32 bytes, offset 68)
  std::copy(hashRandomX.begin(), hashRandomX.end(), data.begin() + OFF_RANDOMX);

  return data;
}

bool CBlockHeader::Deserialize(const uint8_t* data, size_t size) noexcept {
  // Consensus-critical: Reject if size doesn't exactly match HEADER_SIZE
  if (size != HEADER_SIZE) {
    return false;
  }

  // nVersion (4 bytes, offset 0)
  nVersion = static_cast<int32_t>(endian::ReadLE32(data + OFF_VERSION));

  // hashPrevBlock (32 bytes, offset 4)
  std::copy(data + OFF_PREV, data + OFF_PREV + UINT256_BYTES, hashPrevBlock.begin());

  // minerAddress (20 bytes, offset 36)
  std::copy(data + OFF_MINER, data + OFF_MINER + UINT160_BYTES, minerAddress.begin());

  // nTime (4 bytes, offset 56)
  nTime = endian::ReadLE32(data + OFF_TIME);

  // nBits (4 bytes, offset 60)
  nBits = endian::ReadLE32(data + OFF_BITS);

  // nNonce (4 bytes, offset 64)
  nNonce = endian::ReadLE32(data + OFF_NONCE);

  // hashRandomX (32 bytes, offset 68)
  std::copy(data + OFF_RANDOMX, data + OFF_RANDOMX + UINT256_BYTES, hashRandomX.begin());

  return true;
}

std::string CBlockHeader::ToString() const {
  std::stringstream s;
  s << "CBlockHeader(\n";
  s << "  version=" << nVersion << "\n";
  s << "  hashPrevBlock=" << hashPrevBlock.GetHex() << "\n";
  s << "  minerAddress=" << minerAddress.GetHex() << "\n";
  s << "  nTime=" << nTime << "\n";
  s << "  nBits=0x" << std::hex << nBits << std::dec << "\n";
  s << "  nNonce=" << nNonce << "\n";
  s << "  hashRandomX=" << hashRandomX.GetHex() << "\n";
  s << "  hash=" << GetHash().GetHex() << "\n";
  s << ")\n";
  return s.str();
}
