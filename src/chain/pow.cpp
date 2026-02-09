// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2020 The Bitcoin Cash developers (ASERT DAA)
// Copyright (c) 2024 The Scash developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license
// ASERT reference: https://reference.cash/protocol/forks/2020-11-15-asert

#include "chain/pow.hpp"

#include "chain/block_index.hpp"
#include "chain/chainparams.hpp"
#include "chain/randomx_pow.hpp"
#include "util/logging.hpp"

#include <cassert>
#include <cstdlib>
#include <cstring>

#include <randomx.h>

namespace unicity {
namespace consensus {

/**
 * ASERT (Absolutely Scheduled Exponentially weighted Rising Targets)
 *
 * Compute the next required proof of work using an absolutely scheduled
 * exponentially weighted target (ASERT).
 *
 * With ASERT, we define an ideal schedule for block issuance (e.g. 1 block
 * every 600 seconds), and we calculate the difficulty based on how far the
 * most recent block's timestamp is ahead of or behind that schedule.
 * We set our targets (difficulty) exponentially. For every [nHalfLife] seconds
 * ahead of or behind schedule we get, we double or halve the difficulty.
 */
arith_uint256 CalculateASERT(const arith_uint256& refTarget, const int64_t nPowTargetSpacing, const int64_t nTimeDiff,
                             const int64_t nHeightDiff, const arith_uint256& powLimit,
                             const int64_t nHalfLife) noexcept {
  // Input target must never be zero nor exceed powLimit.
  assert(refTarget > 0 && refTarget <= powLimit);

  // We need some leading zero bits in powLimit in order to have room to handle
  // overflows easily. 32 leading zero bits is more than enough.
  // NOTE: Disabled for Unicity - we use 512-bit intermediate math instead.
  // assert((powLimit >> 224) == 0);

  // Height diff should NOT be negative.
  assert(nHeightDiff >= 0);

  // It will be helpful when reading what follows, to remember that
  // nextTarget is adapted from the anchor block's target value.

  // Ultimately, we want to approximate the following ASERT formula, using
  // only integer (fixed-point) math:
  //   new_target = old_target * 2^((blocks_time - IDEAL_BLOCK_TIME * (height_diff + 1)) / nHalfLife)

  // First, we'll calculate the exponent:
  assert(llabs(nTimeDiff - nPowTargetSpacing * nHeightDiff) < (1ll << (63 - 16)));
  const int64_t exponent = ((nTimeDiff - nPowTargetSpacing * (nHeightDiff + 1)) * 65536) / nHalfLife;

  // Next, we use the 2^x = 2 * 2^(x-1) identity to shift our exponent into the [0, 1) interval.
  // The truncated exponent tells us how many shifts we need to do.
  // Note1: This needs to be a right shift. Right shift rounds downward (floored division),
  //        whereas integer division in C++ rounds towards zero (truncated division).
  // Note2: This algorithm uses arithmetic shifts of negative numbers. This
  //        is unspecified but very common behavior for C++ compilers before
  //        C++20, and standard with C++20. We must check this behavior.
  static_assert(int64_t(-1) >> 1 == int64_t(-1), "ASERT algorithm needs arithmetic shift support");

  // Now we compute an approximated target * 2^(exponent/65536.0)

  // First decompose exponent into 'integer' and 'fractional' parts:
  int64_t shifts = exponent >> 16;
  const auto frac = uint16_t(exponent);
  assert(exponent == (shifts * 65536) + frac);

  // Multiply target by 65536 * 2^(fractional part)
  // 2^x ~= (1 + 0.695502049*x + 0.2262698*x**2 + 0.0782318*x**3) for 0 <= x < 1
  // Error versus actual 2^x is less than 0.013%.
  const uint32_t factor =
      65536 +
      ((+195766423245049ull * frac + 971821376ull * frac * frac + 5127ull * frac * frac * frac + (1ull << 47)) >> 48);

  // Intermediate computation uses 512-bit integers to avoid potential overflow
  // from chain parameters. This replaces the BCH assumption of (powLimit >> 224) == 0.
  arith_uint512 nextTarget512 = arith_uint512::from(refTarget) * factor;
  arith_uint512 powLimit512 = arith_uint512::from(powLimit);

  // Multiply by 2^(integer part) / 65536
  shifts -= 16;
  if (shifts <= 0) {
    nextTarget512 >>= -shifts;
  } else {
    // Detect overflow that would discard high bits
    const auto nextTarget512Shifted = nextTarget512 << shifts;
    if ((nextTarget512Shifted >> shifts) != nextTarget512) {
      // If we had wider integers, the final value of nextTarget would
      // be >= 2^256 so it would have just ended up as powLimit anyway.
      nextTarget512 = powLimit512;
    } else {
      // Shifting produced no overflow, can assign value
      nextTarget512 = nextTarget512Shifted;
    }
  }

  if (nextTarget512 > powLimit512) {
    nextTarget512 = powLimit512;
  }

  arith_uint256 nextTarget = arith_uint256::from(nextTarget512);

  if (nextTarget == 0) {
    // 0 is not a valid target, but 1 is.
    nextTarget = arith_uint256(1);
  } else if (nextTarget > powLimit) {
    nextTarget = powLimit;
  }

  // We return from only 1 place for copy elision
  return nextTarget;
}

/**
 * Get next required proof of work using ASERT
 *
 * @param pindexPrev Previous block index
 * @param params Chain parameters
 * @return Compact representation of next difficulty target
 */
uint32_t GetNextWorkRequired(const chain::CBlockIndex* pindexPrev, const chain::ChainParams& params) {
  const auto& consensus = params.GetConsensus();

  LOG_CHAIN_TRACE("GetNextWorkRequired: prev_height={}", pindexPrev ? pindexPrev->nHeight : -1);

  // Genesis block - use powLimit
  if (pindexPrev == nullptr) {
    uint32_t result = UintToArith256(consensus.powLimit).GetCompact();
    LOG_CHAIN_TRACE("GetNextWorkRequired: GENESIS, returning powLimit bits={:#x}", result);
    return result;
  }

  // Regtest: no difficulty adjustment, always use powLimit
  if (params.GetChainType() == chain::ChainType::REGTEST) {
    uint32_t result = UintToArith256(consensus.powLimit).GetCompact();
    LOG_CHAIN_TRACE("GetNextWorkRequired: REGTEST mode, returning powLimit bits={:#x}", result);
    return result;
  }

  // Before anchor height: use powLimit
  if (pindexPrev->nHeight < consensus.nASERTAnchorHeight) {
    uint32_t result = UintToArith256(consensus.powLimit).GetCompact();
    LOG_CHAIN_TRACE("GetNextWorkRequired: Before anchor (height {} < anchor {}), returning powLimit bits={:#x}",
                    pindexPrev->nHeight, consensus.nASERTAnchorHeight, result);
    return result;
  }

  // Find the anchor block (block at nASERTAnchorHeight)
  const chain::CBlockIndex* pindexAnchor = pindexPrev->GetAncestor(consensus.nASERTAnchorHeight);

  // Should never happen if chain is valid
  assert(pindexAnchor != nullptr);
  assert(pindexAnchor->nHeight == consensus.nASERTAnchorHeight);

  // Get reference target from anchor block
  const arith_uint256 refTarget = arith_uint256().SetCompact(pindexAnchor->nBits);
  const arith_uint256 powLimit = UintToArith256(consensus.powLimit);

  // Calculate time and height differences from anchor
  // nTimeDiff: time elapsed from anchor block to current block's parent
  // nHeightDiff: number of blocks from anchor to current block's parent
  const int64_t nTimeDiff = pindexPrev->nTime - pindexAnchor->nTime;
  // Use int64_t for height diff to match CalculateASERT() parameter type
  const int64_t nHeightDiff = static_cast<int64_t>(pindexPrev->nHeight) - consensus.nASERTAnchorHeight;

  LOG_CHAIN_TRACE("ASERT: anchor_h={} bits={:#x} dt={}s dh={} spacing={}s hl={}s",
                  pindexAnchor->nHeight, pindexAnchor->nBits, nTimeDiff, nHeightDiff,
                  consensus.nPowTargetSpacing, consensus.nASERTHalfLife);

  // Calculate next target using ASERT
  arith_uint256 nextTarget = CalculateASERT(refTarget, consensus.nPowTargetSpacing, nTimeDiff, nHeightDiff, powLimit,
                                            consensus.nASERTHalfLife);

  uint32_t result = nextTarget.GetCompact();
  LOG_CHAIN_TRACE("GetNextWorkRequired: ASERT result bits={:#x} (difficulty={})", result,
                  GetDifficulty(result, params));
  return result;
}

/**
 * Get difficulty as a floating point number
 *
 * @param nBits Compact representation of target
 * @param params Chain parameters
 * @return Difficulty value
 */
double GetDifficulty(uint32_t nBits, const chain::ChainParams& params) {
  const auto& consensus = params.GetConsensus();
  arith_uint256 powLimit = UintToArith256(consensus.powLimit);

  // Check for invalid nBits
  bool fNegative, fOverflow;
  arith_uint256 target;
  target.SetCompact(nBits, &fNegative, &fOverflow);

  if (fNegative || fOverflow || target == 0 || target > powLimit) {
    return 0.0;
  }

  // Extract exponent and mantissa from compact nBits format
  // nBits format: 0xMMEEEEEE where MM is exponent, EEEEEE is mantissa
  int nShift = (nBits >> 24) & 0xff;
  double dDiff = static_cast<double>(0x0000ffff) / static_cast<double>(nBits & 0x00ffffff);

  // Adjust for exponent (shift)
  // Standard difficulty uses shift=29 as baseline
  while (nShift < 29) {
    dDiff *= 256.0;
    nShift++;
  }
  while (nShift > 29) {
    dDiff /= 256.0;
    nShift--;
  }

  return dDiff;
}

/**
 * Get target from compact bits representation
 *
 * @param nBits Compact bits
 * @return Target as arith_uint256
 */
arith_uint256 GetTargetFromBits(uint32_t nBits) {
  arith_uint256 target;
  bool fNegative;
  bool fOverflow;
  target.SetCompact(nBits, &fNegative, &fOverflow);

  if (fNegative || fOverflow || target == 0) {
    return arith_uint256(0);
  }

  return target;
}

/**
 * Check if proof-of-work is valid
 *
 * @param block Block header to verify
 * @param nBits Difficulty target
 * @param params Chain parameters
 * @param mode Verification mode (FULL, COMMITMENT_ONLY, or MINING)
 * @param outHash Output parameter for RandomX hash (required for MINING mode)
 * @return true if PoW is valid
 */
bool CheckProofOfWork(const CBlockHeader& block, uint32_t nBits, const chain::ChainParams& params,
                      crypto::POWVerifyMode mode, uint256* outHash) {
  const auto& consensus = params.GetConsensus();
  uint32_t nEpochDuration = consensus.nRandomXEpochDuration;

  // Only log for non-mining modes
  if (mode != crypto::POWVerifyMode::MINING) {
    LOG_CHAIN_TRACE("CheckProofOfWork: block_hash={} nBits={:#x} mode={}", block.GetHash().ToString().substr(0, 16),
                    nBits, mode == crypto::POWVerifyMode::FULL ? "FULL" : "COMMITMENT");
  }

  // Validate consensus parameters (should never happen with hardcoded params, but defense in depth)
  if (nEpochDuration == 0) {
    LOG_CHAIN_ERROR("CheckProofOfWork: FAILED - invalid consensus params: epoch duration is zero");
    return false;
  }

  // Convert nBits to target
  bool fNegative, fOverflow;
  arith_uint256 bnTarget;
  bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

  // Check range
  if (fNegative || bnTarget == 0 || fOverflow) {
    LOG_CHAIN_TRACE("CheckProofOfWork: FAILED - invalid nBits (negative={} overflow={} zero={})", fNegative, fOverflow,
                    bnTarget == 0);
    return false;
  }

  uint256 hashRandomX;
  bool fHashVerified = false;
  bool fCommitmentVerified = false;

  // MINING mode validation - this is a programming error, not consensus failure
  // In production this should never happen (calling code enforces it)
  // But we can't return false (consensus function) for a programming error
  if (outHash == nullptr && mode == crypto::POWVerifyMode::MINING) {
    throw std::runtime_error("MINING mode requires outHash parameter");
  }

  // Do cheaper commitment verification first
  if (mode != crypto::POWVerifyMode::MINING) {
    if (block.hashRandomX.IsNull()) {
      LOG_CHAIN_TRACE("CheckProofOfWork: FAILED - hashRandomX is null");
      return false;
    }
    arith_uint256 commitment = UintToArith256(crypto::GetRandomXCommitment(block));
    if (commitment > bnTarget) {
      LOG_CHAIN_TRACE("CheckProofOfWork: FAILED - commitment {} > target {}", commitment.ToString().substr(0, 16),
                      bnTarget.ToString().substr(0, 16));
      return false;
    }
    hashRandomX = block.hashRandomX;
    fCommitmentVerified = true;
  }

  // Compute RandomX hash if necessary
  if (mode == crypto::POWVerifyMode::FULL || mode == crypto::POWVerifyMode::MINING) {
    uint32_t nEpoch = crypto::GetEpoch(block.nTime, nEpochDuration);

    std::shared_ptr<crypto::RandomXVMWrapper> vmRef = crypto::GetCachedVM(nEpoch);
    if (!vmRef) {
      LOG_CHAIN_ERROR("Could not obtain RandomX VM for epoch {}", nEpoch);
      return false;
    }

    char rx_hash[RANDOMX_HASH_SIZE];

    // Create copy of header with hashRandomX set to null
    CBlockHeader tmp(block);
    tmp.hashRandomX.SetNull();

    // Calculate hash (thread-safe via thread-local VM)
    randomx_calculate_hash(vmRef->vm, &tmp, sizeof(tmp), rx_hash);

    // If not mining, compare hash in block header with our computed value
    if (mode != crypto::POWVerifyMode::MINING) {
      if (memcmp(rx_hash, block.hashRandomX.begin(), RANDOMX_HASH_SIZE) != 0) {
        LOG_CHAIN_TRACE("CheckProofOfWork: FAILED - RandomX hash mismatch");
        return false;
      }

      // FULL mode optimization: both commitment and hash verified, return early
      if (mode == crypto::POWVerifyMode::FULL) {
        hashRandomX = block.hashRandomX;
        if (outHash != nullptr) {
          *outHash = hashRandomX;
        }
        LOG_CHAIN_TRACE("CheckProofOfWork: SUCCESS");
        return true;
      }
    } else {
      // If mining, check if commitment meets target
      hashRandomX = uint256(std::vector<unsigned char>(rx_hash, rx_hash + RANDOMX_HASH_SIZE));
      arith_uint256 commitment = UintToArith256(crypto::GetRandomXCommitment(block, &hashRandomX));
      if (commitment > bnTarget) {
        return false;
      }
      LOG_CHAIN_TRACE("CheckProofOfWork: Mining commitment check PASSED");
      fCommitmentVerified = true;
    }
    fHashVerified = true;
  }

  // Sanity check: verify we got expected verification for the mode
  bool valid = false;
  if (mode == crypto::POWVerifyMode::FULL || mode == crypto::POWVerifyMode::MINING) {
    // FULL and MINING modes must verify both hash and commitment
    valid = fHashVerified && fCommitmentVerified;
  } else if (mode == crypto::POWVerifyMode::COMMITMENT_ONLY) {
    // COMMITMENT_ONLY mode verifies commitment but NOT full hash
    valid = !fHashVerified && fCommitmentVerified;
  }

  if (!valid) {
    LOG_CHAIN_ERROR("CheckProofOfWork: Sanity check failed - mode={} hashVerified={} commitmentVerified={}",
                    static_cast<int>(mode), fHashVerified, fCommitmentVerified);
    return false;
  }

  if (outHash != nullptr) {
    *outHash = hashRandomX;
  }

  return true;
}

}  // namespace consensus
}  // namespace unicity
