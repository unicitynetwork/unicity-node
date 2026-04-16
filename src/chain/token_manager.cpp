// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "chain/token_manager.hpp"

#include "chain/chainstate_manager.hpp"
#include "util/hash.hpp"
#include "util/logging.hpp"

#include <fstream>
#include <span>

namespace unicity {
namespace mining {

TokenManager::TokenManager(const std::filesystem::path& datadir, 
                                         validation::ChainstateManager& chainstate)
    : datadir_(datadir), chainstate_(chainstate), generator_(datadir) {}


void TokenManager::RecordReward(const uint256& blockHash, const uint256& rewardTokenId) {
  const chain::CBlockIndex* index = chainstate_.LookupBlockIndex(blockHash);
  if (!index) {
    LOG_CHAIN_ERROR("RecordReward: Block {} not found in index", blockHash.GetHex());
    return;
  }

  if (!chainstate_.IsOnActiveChain(index)) {
    LOG_CHAIN_DEBUG("RecordReward: Block {} not on active chain, skipping reward logging", blockHash.GetHex());
    return;
  }

  LOG_CHAIN_INFO("Recording found block reward: Height={}, Hash={}, TokenID={}", index->nHeight, blockHash.GetHex(),
                 rewardTokenId.GetHex());

  std::lock_guard lock(csv_mutex_);
  std::filesystem::path reward_file = datadir_ / "reward_tokens.csv";
  bool is_new_file = !std::filesystem::exists(reward_file);

  std::ofstream out(reward_file, std::ios::app);
  if (out.is_open()) {
    if (is_new_file) {
      out << "Height,BlockHash,TokenID\n";
    }
    out << index->nHeight << "," << blockHash.GetHex() << "," << rewardTokenId.GetHex() << "\n";
  } else {
    LOG_CHAIN_ERROR("Failed to open {} for reward recording!", reward_file.string());
  }
}

}  // namespace mining
}  // namespace unicity
