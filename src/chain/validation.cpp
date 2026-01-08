// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "chain/validation.hpp"

#include "chain/block.hpp"
#include "chain/block_index.hpp"
#include "chain/chainparams.hpp"
#include "chain/pow.hpp"
#include "chain/randomx_pow.hpp"
#include "util/logging.hpp"
#include "util/time.hpp"
#include "util/uint.hpp"

#include <algorithm>
#include <ctime>

namespace unicity {
namespace validation {

bool CheckBlockHeader(const CBlockHeader& header, const chain::ChainParams& params, ValidationState& state) {
  // 1. Version validation (basic sanity, context-free)
  // Reject obviously invalid versions (negative or zero)
  // This is a context-free check - specific version requirements may be contextual
  if (header.nVersion < MIN_BLOCK_VERSION) {
    return state.Invalid("bad-version", "block version too old: " + std::to_string(header.nVersion));
  }

  // 2. Check that hashRandomX commitment is present (not null)
  // A null hashRandomX indicates a malformed block header, not just failed PoW
  if (header.hashRandomX.IsNull()) {
    return state.Invalid("bad-randomx-hash", "block header missing RandomX hash commitment");
  }

  // 3. Check proof of work (RandomX)
  if (!consensus::CheckProofOfWork(header, header.nBits, params, crypto::POWVerifyMode::FULL)) {
    return state.Invalid("high-hash", "proof of work failed");
  }

  return true;
}

bool ContextualCheckBlockHeader(const CBlockHeader& header, const chain::CBlockIndex* pindexPrev,
                                const chain::ChainParams& params, int64_t adjusted_time, ValidationState& state) {
  // Check that the block's difficulty matches the expected value
  uint32_t expected_bits = consensus::GetNextWorkRequired(pindexPrev, params);
  if (header.nBits != expected_bits) {
    return state.Invalid("bad-diffbits", "incorrect difficulty: expected " + std::to_string(expected_bits) + ", got " +
                                             std::to_string(header.nBits));
  }

  // Check timestamp against prev
  if (pindexPrev) {
    if (params.GetChainType() == chain::ChainType::REGTEST) {
      // Regtest: Use MTP rule (allows fast block generation)
      // Block timestamp must be after median time of last 11 blocks
      int64_t median_time_past = pindexPrev->GetMedianTimePast();
      if (header.nTime <= median_time_past) {
        return state.Invalid("time-too-old", "block's timestamp is too early: " + std::to_string(header.nTime) +
                                                 " <= MTP " + std::to_string(median_time_past));
      }
    } else {
      // Mainnet/Testnet: Strictly increasing timestamps
      if (header.nTime <= pindexPrev->nTime) {
        return state.Invalid("time-too-old",
                             "block's timestamp must be > predecessor: " + std::to_string(header.nTime) +
                                 " <= " + std::to_string(pindexPrev->nTime));
      }
    }
  }

  // Check timestamp is not too far in future (network-adjusted time)
  // This allows for network clock skew and peer time adjustments
  if (header.nTime > adjusted_time + MAX_FUTURE_BLOCK_TIME) {
    return state.Invalid("time-too-new", "block timestamp too far in future: " + std::to_string(header.nTime) + " > " +
                                             std::to_string(adjusted_time + MAX_FUTURE_BLOCK_TIME));
  }

  // Check against system time. This check ensures blocks
  // cannot be accepted with timestamps far beyond the local system clock, even if
  // the attacker controls all peer time offsets.
  int64_t system_time = util::GetTime();
  if (header.nTime > system_time + MAX_FUTURE_BLOCK_TIME) {
    return state.Invalid("time-too-new-absolute",
                         "block timestamp too far ahead of system time: " + std::to_string(header.nTime) + " > " +
                             std::to_string(system_time + MAX_FUTURE_BLOCK_TIME));
  }

  // Note: Version validation is done in CheckBlockHeader (context-free)
  // Additional contextual version requirements (e.g., soft forks) would go here

  return true;
}

int64_t GetAdjustedTime() {
  // Returns unadjusted system time (mockable for tests).
  // Network-adjusted time was removed following Bitcoin Core 27.0 (PR #28956).
  // Rationale: removes attack surface from malicious peers, relies on NTP.
  return ::unicity::util::GetTime();
}

// ============================================================================
// DoS Protection Functions
// ============================================================================

// NOTE: GetAntiDoSWorkThreshold and CalculateHeadersWork are currently UNUSED.
//
// These functions were intended to provide work-based DoS protection by rejecting
// header chains with insufficient cumulative work. However, the current implementation
// relies on different mechanisms:
//
//   1. Deep fork rejection (nSuspiciousReorgDepth) - rejects headers forking too far back
//   2. Side-chain pruning (PruneStaleSideChains) - cleans up stale side-chain headers
//   3. Unconnecting headers limit (MAX_UNCONNECTING_HEADERS) - limits orphan spam
//
// The assumption is that BFT will prevent forks entirely.
// These functions are retained for potential future use if work-based thresholds
// are needed (e.g., to accept deep forks that have significantly more work).

arith_uint256 GetAntiDoSWorkThreshold(const chain::CBlockIndex* tip, const chain::ChainParams& params) {
  arith_uint256 near_tip_work = 0;

  if (tip != nullptr) {
    // Calculate work of one block at current difficulty
    arith_uint256 block_proof = chain::GetBlockProof(*tip);

    // Calculate work buffer (chain-specific number of blocks)
    arith_uint256 buffer = block_proof * params.GetConsensus().nAntiDosWorkBufferBlocks;

    // Subtract buffer from tip work (but don't go negative)
    near_tip_work = tip->nChainWork - std::min(buffer, tip->nChainWork);
  }

  // Return the higher of: near-tip work OR configured minimum
  arith_uint256 min_chain_work = UintToArith256(params.GetConsensus().nMinimumChainWork);
  return std::max(near_tip_work, min_chain_work);
}

arith_uint256 CalculateHeadersWork(const std::vector<CBlockHeader>& headers) {
  arith_uint256 total_work = 0;

  for (const auto& header : headers) {
    // Get the proof-of-work (difficulty) for this header
    // Calculate: 2^256 / (target + 1)
    arith_uint256 bnTarget;
    bool fNegative, fOverflow;
    bnTarget.SetCompact(header.nBits, &fNegative, &fOverflow);

    // Reject invalid nBits encodings:
    // - fNegative: Sign bit set (0x00800000) with non-zero mantissa
    // - fOverflow: Exponent too large (size > 34 bytes for 256-bit value)
    // - bnTarget == 0: Zero mantissa (e.g., nBits = 0x00000000 or 0x01000000)
    //
    // Note on bnTarget == 0:
    // A zero target would represent infinite difficulty, which is nonsensical
    // and would cause division issues in work calculations. The Bitcoin compact
    // format allows encoding this (mantissa can be 0), but it's
    // consensus-invalid.
    //
    // While the formula (~bnTarget / (bnTarget + 1)) is mathematically safe
    // when bnTarget=0 (divides by 1), we still reject it as an invalid
    // difficulty target. Such blocks should never appear in a valid chain and
    // are filtered here.
    if (fNegative || fOverflow || bnTarget == 0) {
      // Skip invalid difficulty - contributes 0 work to total
      // These headers would fail full validation anyway
      continue;
    }

    // Work = ~target / (target + 1)
    // Approximates 2^256 / target for practical difficulty values
    arith_uint256 block_proof = (~bnTarget / (bnTarget + 1)) + 1;
    total_work += block_proof;
  }

  return total_work;
}

bool CheckHeadersPoW(const std::vector<CBlockHeader>& headers, const chain::ChainParams& params) {
  // Check all headers have valid proof-of-work
  // Use COMMITMENT_ONLY mode for cheap validation (no full RandomX hash)
  for (const auto& header : headers) {
    if (!consensus::CheckProofOfWork(header, header.nBits, params, crypto::POWVerifyMode::COMMITMENT_ONLY)) {
      LOG_CHAIN_TRACE("Header failed PoW commitment check: {}", header.GetHash().ToString().substr(0, 16));
      return false;
    }
  }

  return true;
}

bool CheckHeadersAreContinuous(const std::vector<CBlockHeader>& headers) {
  if (headers.empty()) {
    return true;
  }

  // Check each header's prevhash matches the previous header's hash
  for (size_t i = 1; i < headers.size(); i++) {
    if (headers[i].hashPrevBlock != headers[i - 1].GetHash()) {
      LOG_CHAIN_TRACE("Headers not continuous at index {}: prevhash={}, expected={}", i,
                      headers[i].hashPrevBlock.ToString().substr(0, 16),
                      headers[i - 1].GetHash().ToString().substr(0, 16));
      return false;
    }
  }

  return true;
}

}  // namespace validation
}  // namespace unicity
