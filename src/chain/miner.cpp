// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license
// Simple single-threaded CPU miner for regtest testing
// This is NOT intended for production mining - it's a basic implementation
// for generating test blocks in regtest mode during development and testing.

#include "chain/miner.hpp"

#include "chain/chainstate_manager.hpp"
#include "chain/pow.hpp"
#include "chain/randomx_pow.hpp"
#include "chain/validation.hpp"
#include "util/arith_uint256.hpp"
#include "util/logging.hpp"
#include "util/time.hpp"

#include "randomx.h"

#include <ctime>
#include <thread>

namespace unicity {
namespace mining {

CPUMiner::CPUMiner(const chain::ChainParams& params, validation::ChainstateManager& chainstate)
    : params_(params), chainstate_(chainstate) {}

CPUMiner::~CPUMiner() {
  try {
    Stop();
  } catch (...) {
  }
}

bool CPUMiner::Start(int target_height) {
  // Atomically check and set mining_ flag to prevent race condition
  // If two threads call Start() simultaneously, only one will succeed
  bool expected = false;
  if (!mining_.compare_exchange_strong(expected, true)) {
    LOG_CHAIN_WARN("Miner: Already mining");
    return false;
  }

  // Join any previous thread if it finished
  if (worker_.joinable()) {
    worker_.join();
  }

  LOG_CHAIN_TRACE("Miner: Starting (chain: {}, target_height: {})", params_.GetChainTypeString(),
                  target_height == -1 ? "unlimited" : std::to_string(target_height));

  target_height_.store(target_height);
  total_hashes_.store(0);
  blocks_found_.store(0);  // Reset counter for this mining session

  {
    std::lock_guard<std::mutex> lock(time_mutex_);
    start_time_ = std::chrono::steady_clock::now();
  }

  // Start single mining thread (worker creates its own local template)
  worker_ = std::thread([this]() { MiningWorker(); });

  return true;
}

void CPUMiner::Stop() {
  // Set flag to stop mining (may already be false if worker stopped itself)
  mining_.store(false);

  // Use mutex to ensure only one thread can join the worker at a time
  // This prevents undefined behavior from concurrent Stop() calls
  std::lock_guard<std::mutex> lock(stop_mutex_);

  // ALWAYS join the thread if it exists
  // Even if mining_ was already false, the thread might still be exiting!
  if (worker_.joinable()) {
    worker_.join();

    int64_t elapsed;
    {
      std::lock_guard<std::mutex> time_lock(time_mutex_);
      elapsed =
          std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start_time_).count();
    }

    uint64_t hashes = total_hashes_.load();
    double hashrate = (elapsed > 0) ? (double)hashes / elapsed : 0.0;

    LOG_CHAIN_TRACE("Miner: Stopped");
    LOG_CHAIN_TRACE("  Total hashes: {}", hashes);
    LOG_CHAIN_TRACE("  Time: {}s", elapsed);
    LOG_CHAIN_TRACE("  Hashrate: {} H/s", hashrate);
    LOG_CHAIN_TRACE("  Blocks found: {}", blocks_found_.load());
  }
}

double CPUMiner::GetHashrate() const {
  if (!mining_.load()) {
    return 0.0;
  }

  int64_t elapsed;
  {
    std::lock_guard<std::mutex> lock(time_mutex_);
    elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start_time_).count();
  }

  if (elapsed == 0) {
    return 0.0;
  }

  return (double)total_hashes_.load() / elapsed;
}

void CPUMiner::MiningWorker() {
  uint32_t nonce = 0;

  // Create block template locally for this mining iteration
  BlockTemplate local_template = CreateBlockTemplate();
  uint256 template_prev_hash = local_template.hashPrevBlock;

  LOG_CHAIN_TRACE("Miner: Mining block at height {} (prev={}..., target=0x{:x})", local_template.nHeight,
                  local_template.hashPrevBlock.ToString().substr(0, 16), local_template.nBits);

  while (mining_.load()) {
    // Check if we need to regenerate template (chain tip changed)
    if (ShouldRegenerateTemplate(template_prev_hash)) {
      LOG_CHAIN_TRACE("Miner: Chain tip changed, regenerating template");
      local_template = CreateBlockTemplate();
      template_prev_hash = local_template.hashPrevBlock;
      nonce = 0;  // Restart nonce
    }

    // Update nonce
    local_template.header.nNonce = nonce;

    // Count this hash attempt (including successful ones)
    total_hashes_.fetch_add(1);

    // Try mining this nonce using RandomX
    uint256 rx_hash;
    bool found_block = consensus::CheckProofOfWork(local_template.header, local_template.nBits, params_,
                                                   crypto::POWVerifyMode::MINING, &rx_hash);

    // Check if we found a block
    if (found_block) {
      blocks_found_.fetch_add(1);

      CBlockHeader found_header = local_template.header;
      found_header.hashRandomX = rx_hash;

      LOG_CHAIN_TRACE("Miner: *** BLOCK FOUND *** Height: {}, Nonce: {}, Hash: {}...", local_template.nHeight, nonce,
                      found_header.GetHash().ToString().substr(0, 16));

      // Process block through chainstate manager
      validation::ValidationState state;
      if (!chainstate_.ProcessNewBlockHeader(found_header, state)) {
        LOG_CHAIN_ERROR("Miner: Failed to process mined block: {} - {}", state.GetRejectReason(),
                        state.GetDebugMessage());
        continue;
      }

      // Check if we've reached target height
      // Use ACTUAL chain height, not template height (template might be ahead if validation failed)
      int target = target_height_.load();
      const chain::CBlockIndex* tip = chainstate_.GetTip();
      int actual_height = tip ? tip->nHeight : -1;
      if (target != -1 && actual_height >= target) {
        LOG_CHAIN_TRACE("Miner: Reached target height {} (actual chain: {}), stopping", target, actual_height);
        mining_.store(false);
        break;
      }

      // Continue mining next block
      local_template = CreateBlockTemplate();
      template_prev_hash = local_template.hashPrevBlock;
      nonce = 0;
      continue;
    }

    // Next nonce
    nonce++;
    if (nonce == 0) {
      // Nonce space exhausted - increment timestamp for fresh search space
      uint32_t current_time = static_cast<uint32_t>(util::GetTime());
      uint32_t max_future_time = current_time + validation::MAX_FUTURE_BLOCK_TIME;

      if (local_template.header.nTime < max_future_time) {
        local_template.header.nTime++;
        LOG_CHAIN_TRACE("Miner: Nonce exhausted, incremented nTime to {}", local_template.header.nTime);
      } else {
        // Timestamp would exceed maximum future time - regenerate template
        LOG_CHAIN_TRACE("Miner: Timestamp at maximum, regenerating template");
        local_template = CreateBlockTemplate();
        template_prev_hash = local_template.hashPrevBlock;
        nonce = 0;
      }
    }
  }

  LOG_CHAIN_TRACE("Miner: Worker thread exiting normally");
}

BlockTemplate CPUMiner::CreateBlockTemplate() {
  BlockTemplate tmpl;

  // Get current chain tip
  const chain::CBlockIndex* tip = chainstate_.GetTip();
  if (!tip) {
    // No tip, use genesis
    tmpl.hashPrevBlock.SetNull();
    tmpl.nHeight = 0;
  } else {
    tmpl.hashPrevBlock = tip->GetBlockHash();
    tmpl.nHeight = tip->nHeight + 1;
  }

  // Calculate difficulty
  tmpl.nBits = consensus::GetNextWorkRequired(tip, params_);

  // Fill header
  tmpl.header.nVersion = 1;
  tmpl.header.hashPrevBlock = tmpl.hashPrevBlock;
  tmpl.header.minerAddress = GetMiningAddress();  // Thread-safe access via mutex
  tmpl.header.nTime = static_cast<uint32_t>(util::GetTime());
  tmpl.header.nBits = tmpl.nBits;
  tmpl.header.nNonce = 0;
  tmpl.header.hashRandomX.SetNull();

  // Ensure timestamp is strictly greater than previous block
  // (validation requires strictly increasing timestamps)
  if (tip) {
    if (tmpl.header.nTime <= tip->nTime) {
      tmpl.header.nTime = tip->nTime + 1;
    }
  }

  return tmpl;
}

bool CPUMiner::ShouldRegenerateTemplate(const uint256& prev_hash) {
  // Check atomic flag first (notification-based, fast)
  if (template_invalidated_.exchange(false)) {
    return true;
  }

  // Fallback to polling (slower, but ensures correctness)
  const chain::CBlockIndex* tip = chainstate_.GetTip();
  if (!tip) {
    // No tip AND prev is null -> nothing changed, don't regenerate
    // This prevents infinite regeneration at genesis
    return false;
  }

  return tip->GetBlockHash() != prev_hash;
}

}  // namespace mining
}  // namespace unicity
