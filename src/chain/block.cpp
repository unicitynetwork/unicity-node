// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/block.hpp"

#include "util/endian.hpp"
#include "util/hash.hpp"
#include "util/sha256.hpp"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace {
// Compile-time header size calculation
constexpr size_t kHeaderSize = 4 /*nVersion*/ + 32 /*hashPrevBlock*/ + 32 /*payloadRoot*/ + 4 /*nTime*/ +
                               4 /*nBits*/ + 4 /*nNonce*/ + 32 /*hashRandomX*/;
static_assert(kHeaderSize == CBlockHeader::HEADER_SIZE, "HEADER_SIZE mismatch");
}  // namespace

uint256 CBlockHeader::GetHash() const noexcept {
  return Hash(Serialize(false));
}

std::span<const uint8_t> CBlockHeader::GetUTB() const noexcept {
  if (vPayload.size() <= 32) {
    return {};
  }
  return std::span(vPayload.data() + 32, vPayload.size() - 32);
}

// payloadRoot = SHA256(leaf_0 || leaf_1)
// leaf_0 = SHA256(rewardTokenId)
// leaf_1 = SHA256(UTB)
uint256 CBlockHeader::ComputePayloadRoot(const uint256& leaf_0, const uint256& leaf_1) noexcept {
  uint256 root;
  CSHA256()
    .Write(leaf_0.begin(), 32)
    .Write(leaf_1.begin(), 32)
    .Finalize(root.begin());
  return root;
}

std::vector<uint8_t> CBlockHeader::Serialize(const bool includePayload) const noexcept {
  std::vector<uint8_t> data(HEADER_SIZE + (includePayload ? vPayload.size() : 0), 0);

  // nVersion (4 bytes, offset 0)
  endian::WriteLE32(data.data() + OFF_VERSION, static_cast<uint32_t>(nVersion));

  // hashPrevBlock (32 bytes, offset 4)
  std::copy(hashPrevBlock.begin(), hashPrevBlock.end(), data.begin() + OFF_PREV);

  // payloadRoot (32 bytes, offset 36)
  std::copy(payloadRoot.begin(), payloadRoot.end(), data.begin() + OFF_PAYLOAD_ROOT);

  // nTime (4 bytes, offset 68)
  endian::WriteLE32(data.data() + OFF_TIME, nTime);

  // nBits (4 bytes, offset 72)
  endian::WriteLE32(data.data() + OFF_BITS, nBits);

  // nNonce (4 bytes, offset 76)
  endian::WriteLE32(data.data() + OFF_NONCE, nNonce);

  // hashRandomX (32 bytes, offset 80)
  std::copy(hashRandomX.begin(), hashRandomX.end(), data.begin() + OFF_RANDOMX);

  // Append payload if requested
  if (includePayload && !vPayload.empty()) {
    std::copy(vPayload.begin(), vPayload.end(), data.begin() + HEADER_SIZE);
  }

  return data;
}

bool CBlockHeader::Deserialize(const uint8_t* data, size_t size) noexcept {
  // Consensus-critical: Reject if size doesn't at least match HEADER_SIZE
  if (size < HEADER_SIZE) {
    return false;
  }

  // nVersion (4 bytes, offset 0)
  nVersion = static_cast<int32_t>(endian::ReadLE32(data + OFF_VERSION));

  // hashPrevBlock (32 bytes, offset 4)
  std::copy(data + OFF_PREV, data + OFF_PREV + UINT256_BYTES, hashPrevBlock.begin());

  // payloadRoot (32 bytes, offset 36)
  std::copy(data + OFF_PAYLOAD_ROOT, data + OFF_PAYLOAD_ROOT + UINT256_BYTES, payloadRoot.begin());

  // nTime (4 bytes, offset 68)
  nTime = endian::ReadLE32(data + OFF_TIME);

  // nBits (4 bytes, offset 72)
  nBits = endian::ReadLE32(data + OFF_BITS);

  // nNonce (4 bytes, offset 76)
  nNonce = endian::ReadLE32(data + OFF_NONCE);

  // hashRandomX (32 bytes, offset 80)
  std::copy(data + OFF_RANDOMX, data + OFF_RANDOMX + UINT256_BYTES, hashRandomX.begin());

  // Read appended payload
  if (size > HEADER_SIZE) {
    vPayload.assign(data + HEADER_SIZE, data + size);
  } else {
    vPayload.clear();
  }

  return true;
}

std::string CBlockHeader::ToString() const {
  std::stringstream s;
  s << "CBlockHeader(\n";
  s << "  version=" << nVersion << "\n";
  s << "  hashPrevBlock=" << hashPrevBlock.GetHex() << "\n";
  s << "  payloadRoot=" << payloadRoot.GetHex() << "\n";
  s << "  nTime=" << nTime << "\n";
  s << "  nBits=0x" << std::hex << nBits << std::dec << "\n";
  s << "  nNonce=" << nNonce << "\n";
  s << "  hashRandomX=" << hashRandomX.GetHex() << "\n";
  s << "  hash=" << GetHash().GetHex() << "\n";
  s << "  payloadSize=" << vPayload.size() << "\n";
  s << ")\n";
  return s.str();
}
