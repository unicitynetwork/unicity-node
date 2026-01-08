// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include "chain/block.hpp"
#include "chain/chainparams.hpp"
#include "util/uint.hpp"

#include <atomic>
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
};

// Single-threaded CPU miner for regtest testing
class CPUMiner {
public:
  CPUMiner(const chain::ChainParams& params, validation::ChainstateManager& chainstate);
  ~CPUMiner();

  bool Start(int target_height = -1);  // -1 = mine forever
  void Stop();

  bool IsMining() const { return mining_.load(); }
  double GetHashrate() const;
  uint64_t GetTotalHashes() const { return total_hashes_.load(); }
  int GetBlocksFound() const { return blocks_found_.load(); }

  // Set/get mining address (thread-safe, sticky across sessions)
  void SetMiningAddress(const uint160& address) {
    std::lock_guard<std::mutex> lock(address_mutex_);
    mining_address_ = address;
  }

  uint160 GetMiningAddress() const {
    std::lock_guard<std::mutex> lock(address_mutex_);
    return mining_address_;
  }

  // Invalidate current block template (called when chain tip changes)
  void InvalidateTemplate() { template_invalidated_.store(true); }

  // Test-only methods
  bool DebugShouldRegenerateTemplate(const uint256& prev_hash) { return ShouldRegenerateTemplate(prev_hash); }
  BlockTemplate DebugCreateBlockTemplate() { return CreateBlockTemplate(); }

private:
  void MiningWorker();
  BlockTemplate CreateBlockTemplate();
  bool ShouldRegenerateTemplate(const uint256& prev_hash);

  const chain::ChainParams& params_;
  validation::ChainstateManager& chainstate_;

  uint160 mining_address_;
  mutable std::mutex address_mutex_;

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
