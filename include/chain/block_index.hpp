// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include "chain/block.hpp"
#include "util/arith_uint256.hpp"
#include "util/uint.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <string>

namespace unicity {
namespace chain {

// Median Time Past calculation span (number of previous blocks)
// Used by GetMedianTimePast()
static constexpr int MEDIAN_TIME_SPAN = 11;
static_assert(MEDIAN_TIME_SPAN % 2 == 1, "MEDIAN_TIME_SPAN must be odd for proper median calculation");

// BlockStatus - Tracks validation progress and failure state of a block header
// Separates validation level (how far validated) from failure state (is it failed).
struct BlockStatus {
  // Validation progression (how far has this header been validated?)
  enum ValidationLevel : uint8_t {
    UNKNOWN = 0,  // Not yet validated
    HEADER = 1,   // Reserved (unused - we validate fully before inserting into index)
    TREE = 2      // Fully validated: PoW, context, ancestors all checked
  };

  // Failure state (is this block failed, and why?)
  enum FailureState : uint8_t {
    NOT_FAILED = 0,         // Block is not failed
    VALIDATION_FAILED = 1,  // This block itself failed validation
    ANCESTOR_FAILED = 2     // Descends from a failed ancestor
  };

  ValidationLevel validation{UNKNOWN};
  FailureState failure{NOT_FAILED};

  // Query methods (maintain same API surface as before)
  [[nodiscard]] bool IsFailed() const noexcept { return failure != NOT_FAILED; }

  [[nodiscard]] bool IsValid(ValidationLevel required = TREE) const noexcept {
    return !IsFailed() && validation >= required;
  }

  [[nodiscard]] bool RaiseValidity(ValidationLevel level) noexcept {
    if (IsFailed())
      return false;
    if (validation < level) {
      validation = level;
      return true;
    }
    return false;
  }

  void MarkFailed() noexcept { failure = VALIDATION_FAILED; }
  void MarkAncestorFailed() noexcept { failure = ANCESTOR_FAILED; }

  // For debugging
  [[nodiscard]] std::string ToString() const;
};

// CBlockIndex - Metadata for a single block header
class CBlockIndex {
public:
  BlockStatus status{};

  // Block hash
  // Set by BlockManager::AddToBlockIndex() or Load() after creation.
  uint256 m_block_hash{};

  // Pointer to previous block in chain (DOES NOT OWN).
  // Forms the blockchain tree structure by linking to parent.
  // nullptr for genesis block, otherwise points to parent block's CBlockIndex.
  CBlockIndex* pprev{nullptr};

  // Skip list pointer for O(log n) ancestor lookup.
  // Points to an ancestor at a strategically chosen height to enable
  // logarithmic-time traversal. Set by BuildSkip() when block is added to chain.
  CBlockIndex* pskip{nullptr};

  // Height of this block in the chain (genesis = 0)
  int nHeight{0};

  // Cumulative work up to and including this block
  arith_uint256 nChainWork{};

  // Block header fields (stored inline)
  int32_t nVersion{0};
  uint160 minerAddress{};  // Default-initialized (SetNull())
  uint32_t nTime{0};
  uint32_t nBits{0};
  uint32_t nNonce{0};
  uint256 hashRandomX{};  // Default-initialized (SetNull())

  // Time when we first learned about this block (for relay decisions)
  // Blocks received recently (< MAX_BLOCK_RELAY_AGE) are relayed to peers
  // Old blocks (from disk/reorgs) are not relayed (peers already know them)
  int64_t nTimeReceived{0};

  // Constructor
  CBlockIndex() = default;

  explicit CBlockIndex(const CBlockHeader& block)
      : nVersion{block.nVersion}, minerAddress{block.minerAddress}, nTime{block.nTime}, nBits{block.nBits},
        nNonce{block.nNonce}, hashRandomX{block.hashRandomX} {}

  // Returns block hash
  [[nodiscard]] const uint256& GetBlockHash() const noexcept { return m_block_hash; }

  // Reconstruct full block header (self-contained, safe to use if CBlockIndex destroyed)
  [[nodiscard]] CBlockHeader GetBlockHeader() const noexcept {
    CBlockHeader block;
    block.nVersion = nVersion;
    if (pprev)
      block.hashPrevBlock = pprev->GetBlockHash();
    block.minerAddress = minerAddress;
    block.nTime = nTime;
    block.nBits = nBits;
    block.nNonce = nNonce;
    block.hashRandomX = hashRandomX;
    return block;
  }

  [[nodiscard]] int64_t GetBlockTime() const noexcept { return static_cast<int64_t>(nTime); }

  // Calculate Median Time Past (MTP) for timestamp validation.
  // Takes median of last MEDIAN_TIME_SPAN blocks (11) or fewer if
  // near genesis. New block time must be > MTP.
  // NOTE: MTP is only used for regtest.
  // Mainnet/testnet use strictly increasing timestamps
  [[nodiscard]] int64_t GetMedianTimePast() const noexcept {
    std::array<int64_t, MEDIAN_TIME_SPAN> times{};
    int count = 0;

    for (const CBlockIndex* p = this; p && count < MEDIAN_TIME_SPAN; p = p->pprev) {
      times[static_cast<size_t>(count++)] = p->GetBlockTime();
    }

    std::sort(times.begin(), times.begin() + count);
    return times[static_cast<size_t>(count / 2)];
  }

  // Build skip list pointer
  // Must be called when adding block to chain, after pprev and nHeight are set
  void BuildSkip() noexcept;

  // Get ancestor at given height using skip list (O(log n) with skip list)
  [[nodiscard]] const CBlockIndex* GetAncestor(int height) const noexcept;
  [[nodiscard]] CBlockIndex* GetAncestor(int height) noexcept;

  [[nodiscard]] bool IsValid(BlockStatus::ValidationLevel level = BlockStatus::TREE) const noexcept {
    return status.IsValid(level);
  }

  // Raise validity level of this block, returns true if changed
  [[nodiscard]] bool RaiseValidity(BlockStatus::ValidationLevel level) noexcept { return status.RaiseValidity(level); }

  // For debugging/testing only - produces human-readable representation
  [[nodiscard]] std::string ToString() const;

  // Copy/move operations are DELETED to prevent dangling pointer bugs.
  // Use GetBlockHeader() to extract a self-contained copy of block data.
  CBlockIndex(const CBlockIndex&) = delete;
  CBlockIndex& operator=(const CBlockIndex&) = delete;
  CBlockIndex(CBlockIndex&&) = delete;
  CBlockIndex& operator=(CBlockIndex&&) = delete;
};

// Calculate proof-of-work for a block
// Returns work = ~target / (target + 1) + 1 (mathematically equivalent to 2^256
// / (target + 1)) Invalid targets return 0 work.
[[nodiscard]] arith_uint256 GetBlockProof(const CBlockIndex& block) noexcept;

// Find last common ancestor of two blocks (aligns heights, then walks backward
// until they meet) Returns nullptr if either input is nullptr. All valid chains
// share genesis.
[[nodiscard]] const CBlockIndex* LastCommonAncestor(const CBlockIndex* pa, const CBlockIndex* pb) noexcept;

}  // namespace chain
}  // namespace unicity
