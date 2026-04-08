// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include "chain/block.hpp"
#include "chain/token_generator.hpp"
#include "util/uint.hpp"

#include <filesystem>
#include <mutex>

namespace unicity {
namespace validation {
class ChainstateManager;
}

namespace mining {

/**
 * TokenManager - Management of miner reward tokens.
 */
class TokenManager {
public:
  explicit TokenManager(const std::filesystem::path& datadir, validation::ChainstateManager& chainstate);

  /**
   * Generates a new rewardTokenId.
   */
  uint256 GenerateNextTokenId() { return generator_.GenerateNextTokenId(); }

  /**
   * Records the reward token ID to the miner reward CSV file.
   */
  void RecordReward(const uint256& blockHash, const uint256& rewardTokenId);

private:
  std::filesystem::path datadir_;
  validation::ChainstateManager& chainstate_;
  TokenGenerator generator_;
  mutable std::mutex csv_mutex_;
};

}  // namespace mining
}  // namespace unicity
