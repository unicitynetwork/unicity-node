// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include "util/arith_uint256.hpp"

#include <cstdint>
#include <string>
#include <vector>

class CBlockHeader;

namespace unicity {

namespace chain {
class ChainParams;
class CBlockIndex;
}  // namespace chain

namespace validation {

// ============================================================================
// BLOCK HEADER VALIDATION ARCHITECTURE
// ============================================================================
//
// This module provides a layered validation approach for block headers:
//
// LAYER 1: Fast Pre-filtering (for P2P header sync)
// - CheckHeadersPoW()           : Commitment-only PoW check
// - CheckHeadersAreContinuous() : Chain structure validation
// Purpose: Quickly reject obviously invalid headers during sync
//
// LAYER 2: Full Context-Free Validation (before chain acceptance)
// - CheckBlockHeader()          : FULL RandomX PoW verification
// Purpose: Cryptographically verify the header is valid in isolation
// Security: Validates PoW meets header.nBits, but NOT that nBits is correct
//
// LAYER 3: Contextual Validation (requires parent block)
// - ContextualCheckBlockHeader(): Validates nBits, timestamps, version
// Purpose: CRITICAL - ensures header follows chain consensus rules
// Security: Without this, attackers can mine with artificially low difficulty
//
// INTEGRATION POINT:
// - ChainstateManager::AcceptBlockHeader() orchestrates all validation layers
//
// DoS PROTECTION: (NOTE NOT USED CURRENTLY AS LOW WORK IS REJECTED AT NETWORK LEVEL)
// - GetAntiDoSWorkThreshold(): Rejects low-work header spam
// - CalculateHeadersWork()    : Computes cumulative chain work
// ============================================================================

// Validation state - tracks why validation failed
class ValidationState {
public:
  enum class Result {
    VALID,
    INVALID,  // Invalid block
    ERROR     // System error
  };

  ValidationState() : result_(Result::VALID) {}

  bool IsValid() const { return result_ == Result::VALID; }
  bool IsInvalid() const { return result_ == Result::INVALID; }
  bool IsError() const { return result_ == Result::ERROR; }

  bool Invalid(const std::string& reject_reason, const std::string& debug_message = "") {
    result_ = Result::INVALID;
    reject_reason_ = reject_reason;
    debug_message_ = debug_message;
    return false;
  }

  bool Error(const std::string& reject_reason, const std::string& debug_message = "") {
    result_ = Result::ERROR;
    reject_reason_ = reject_reason;
    debug_message_ = debug_message;
    return false;
  }

  const std::string& GetRejectReason() const { return reject_reason_; }
  const std::string& GetDebugMessage() const { return debug_message_; }

private:
  Result result_;
  std::string reject_reason_;
  std::string debug_message_;
};

// Validates PoW meets difficulty target in header.nBits
// Uses FULL RandomX verification (computes hash AND verifies commitment)
// SECURITY: Does NOT validate that nBits is correct for chain position
// Always call ContextualCheckBlockHeader() afterward to verify nBits is
// expected value
bool CheckBlockHeader(const CBlockHeader& header, const chain::ChainParams& params, ValidationState& state);

// Validates header follows chain consensus rules
// Checks: nBits matches expected difficulty (ASERT), timestamps, version
// SECURITY: Prevents mining with artificially low difficulty
// Requires parent block for difficulty calculation and median time past
bool ContextualCheckBlockHeader(const CBlockHeader& header, const chain::CBlockIndex* pindexPrev,
                                const chain::ChainParams& params, int64_t adjusted_time, ValidationState& state);

// Returns network-adjusted time (wall clock + median peer offset)
int64_t GetAdjustedTime();

// Validation constants
static constexpr int64_t MAX_FUTURE_BLOCK_TIME = 10 * 60;  // 10 minutes

// Block version validation
static constexpr int32_t MIN_BLOCK_VERSION = 1;  // Minimum valid block version

// Returns minimum chainwork for DoS protection
// Dynamic threshold: max(nMinimumChainWork, tip->nChainWork - work_buffer_blocks)
// work_buffer_blocks is chain-specific
arith_uint256 GetAntiDoSWorkThreshold(const chain::CBlockIndex* tip, const chain::ChainParams& params);

// Calculate total cumulative PoW work for headers
// Invalid headers (bad nBits) are skipped and contribute 0 work
arith_uint256 CalculateHeadersWork(const std::vector<CBlockHeader>& headers);

// Fast PoW pre-filter using COMMITMENT_ONLY mode (~50x faster than full check)
// Verifies hashRandomX commitment meets header.nBits difficulty
// Does NOT compute full RandomX hash or validate nBits is correct for chain
// position Headers passing this still need CheckBlockHeader() +
// ContextualCheckBlockHeader()
bool CheckHeadersPoW(const std::vector<CBlockHeader>& headers, const chain::ChainParams& params);

// Validates headers form continuous chain: headers[i].hashPrevBlock ==
// headers[i-1].GetHash() Does NOT verify headers[0] links to existing chain
// (checked separately)
bool CheckHeadersAreContinuous(const std::vector<CBlockHeader>& headers);

}  // namespace validation
}  // namespace unicity
