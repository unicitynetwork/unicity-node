// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include "chain/block.hpp"
#include "chain/chainparams.hpp"
#include "chain/trust_base_manager.hpp"
#include "chain/mining/token_generator.hpp"
#include "util/uint.hpp"

#include <atomic>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace unicity {

// Forward declarations
namespace chain {
class BlockManager;
class CBlockIndex;
}  // namespace chain

namespace validation {
class ChainstateManager;
}

namespace mining {

// Block template for mining
struct BlockTemplate {
  CBlockHeader header;
  uint32_t nBits;
  int nHeight;
  uint256 hashPrevBlock;
  uint256 rewardTokenId;
};

// Single-threaded CPU miner for regtest testing
class CPUMiner {
public:
  CPUMiner(const chain::ChainParams& params, validation::ChainstateManager& chainstate, chain::TrustBaseManager& trust_base_manager, TokenGenerator& token_generator, const std::filesystem::path& datadir);
  ~CPUMiner();

  bool Start(int target_height = -1);  // -1 = mine forever
  void Stop();

  bool IsMining() const { return mining_.load(); }
  double GetHashrate() const;
  uint64_t GetTotalHashes() const { return total_hashes_.load(); }
  int GetBlocksFound() const { return blocks_found_.load(); }

  // Invalidate current block template (called when chain tip changes)
  void InvalidateTemplate() { template_invalidated_.store(true); }

  // Test-only methods
  bool DebugShouldRegenerateTemplate(const uint256& prev_hash) { return ShouldRegenerateTemplate(prev_hash); }
  BlockTemplate DebugCreateBlockTemplate() { return CreateBlockTemplate(); }

private:
  void MiningWorker();
  BlockTemplate CreateBlockTemplate();
  bool ShouldRegenerateTemplate(const uint256& prev_hash);
  void RecordReward(const chain::CBlockIndex* tip, const uint256& blockHash, const uint256& tokenId);

  const chain::ChainParams& params_;
  validation::ChainstateManager& chainstate_;
  chain::TrustBaseManager& trust_base_manager_;
  TokenGenerator& token_generator_;
  
  std::filesystem::path datadir_;

  std::atomic<bool> mining_{false};
  std::atomic<uint64_t> total_hashes_{0};
  std::atomic<int> blocks_found_{0};
  std::atomic<bool> template_invalidated_{false};
  std::atomic<int> target_height_{-1};

  std::chrono::steady_clock::time_point start_time_;
  mutable std::mutex time_mutex_;

  std::thread worker_;
  mutable std::mutex stop_mutex_;
};

}  // namespace mining
}  // namespace unicity
