// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "chain/chainstate_manager.hpp"

#include "chain/block_index.hpp"
#include "chain/block_manager.hpp"
#include "chain/chain.hpp"
#include "chain/chainparams.hpp"
#include "chain/notifications.hpp"
#include "chain/pow.hpp"
#include "chain/randomx_pow.hpp"
#include "chain/validation.hpp"
#include "network/protocol.hpp"
#include "util/arith_uint256.hpp"
#include "util/logging.hpp"
#include "util/time.hpp"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <compare>
#include <ctime>
#include <iomanip>
#include <set>
#include <sstream>
#include <utility>
#include <vector>

namespace unicity {
namespace validation {

// IBD (Initial Block Download) staleness threshold
static constexpr int64_t IBD_STALE_TIP_SECONDS = 5 * 24 * 3600;  // 5 days (432000 seconds)

ChainstateManager::ChainstateManager(const chain::ChainParams& params)
    : block_manager_()
    , params_(params)
{
}

chain::CBlockIndex* ChainstateManager::AcceptBlockHeader(const CBlockHeader& header, ValidationState& state) {
  std::lock_guard<std::recursive_mutex> lock(validation_mutex_);

  uint256 hash = header.GetHash();
  LOG_CHAIN_TRACE("AcceptBlockHeader: hash={} prev={}", hash.ToString().substr(0, 16),
                  header.hashPrevBlock.ToString().substr(0, 16));

  // Step 1: Check for duplicate
  chain::CBlockIndex* pindex = block_manager_.LookupBlockIndex(hash);
  if (pindex) {
    // Block header is already known
    if (pindex->status.IsFailed()) {
      LOG_CHAIN_DEBUG("AcceptBlockHeader: block {} is marked invalid", hash.ToString());
      state.Invalid("duplicate", "known invalid header re-announced");
      return nullptr;
    }
    LOG_CHAIN_TRACE("block header {} already exists and is valid, returning existing", hash.ToString().substr(0, 16));
    return pindex;
  }

  // Step 2: Cheap POW commitment check (anti-DoS prefilter)
  if (!CheckProofOfWork(header, crypto::POWVerifyMode::COMMITMENT_ONLY)) {
    state.Invalid("high-hash", "proof of work commitment failed");
    LOG_CHAIN_ERROR("block header {} failed POW commitment check", hash.ToString().substr(0, 16));
    return nullptr;
  }

  // Step 3: Check if this is a genesis block (must be initialized separately)
  if (header.hashPrevBlock.IsNull()) {
    if (hash != params_.GetConsensus().hashGenesisBlock) {
      state.Invalid("bad-genesis", "genesis block hash mismatch");
      LOG_CHAIN_ERROR("rejected fake genesis block: {} (expected: {})", hash.ToString(),
                      params_.GetConsensus().hashGenesisBlock.ToString());
      return nullptr;
    }
    state.Invalid("genesis-via-accept", "genesis block must be added via Initialize()");
    return nullptr;
  }

  // Step 4: Parent must exist in index
  chain::CBlockIndex* pindexPrev = block_manager_.LookupBlockIndex(header.hashPrevBlock);
  if (!pindexPrev) {
    LOG_CHAIN_DEBUG("AcceptBlockHeader: header {} has prev block not found: {}", hash.ToString(),
                    header.hashPrevBlock.ToString());
    state.Invalid("prev-blk-not-found", "parent block not found");
    return nullptr;
  }

  // Step 5: Parent must not be invalid
  if (pindexPrev->status.IsFailed()) {
    LOG_CHAIN_DEBUG("AcceptBlockHeader: header {} has prev block invalid: {}", hash.ToString(),
                    header.hashPrevBlock.ToString());
    state.Invalid("bad-prevblk", "previous block is invalid");
    return nullptr;
  }

  // All headers in the index are either TREE valid or failed (caught by Step 5).
  assert(pindexPrev->IsValid(chain::BlockStatus::TREE) && "Parent passed IsFailed check but is not TREE valid");

  // Step 6: Contextual checks (timestamp, difficulty) using parent
  int64_t adjusted_time = util::GetTime();
  if (!ContextualCheckBlockHeaderWrapper(header, pindexPrev, adjusted_time, state)) {
    LOG_CHAIN_ERROR("contextual check failed for {}: {} - {}", hash.ToString().substr(0, 16), state.GetRejectReason(),
                    state.GetDebugMessage());
    return nullptr;
  }

  // Step 7: Full PoW (RandomX) - expensive, so done after cheap contextual checks
  if (!CheckBlockHeaderWrapper(header, state)) {
    LOG_CHAIN_ERROR("full PoW check failed for {}: {} - {}", hash.ToString().substr(0, 16), state.GetRejectReason(),
                    state.GetDebugMessage());
    return nullptr;
  }

  // Step 8: Insert into block index
  pindex = block_manager_.AddToBlockIndex(header);
  if (!pindex) {
    state.Error("failed to add block to index");
    return nullptr;
  }
  pindex->nTimeReceived = util::GetTime();

  // Mark validity - must succeed for newly added block
  bool raised = pindex->RaiseValidity(chain::BlockStatus::TREE);
  assert(raised && "RaiseValidity failed for newly added block");

  LOG_CHAIN_TRACE("accepted new block header: hash={}, height={}, log2_work={:.6f}", hash.ToString().substr(0, 16),
                  pindex->nHeight, std::log(pindex->nChainWork.getdouble()) / std::log(2.0));

  return pindex;
}

bool ChainstateManager::ProcessNewBlockHeader(const CBlockHeader& header, ValidationState& state) {
  chain::CBlockIndex* pindex = AcceptBlockHeader(header, state);
  if (!pindex) {
    return false;
  }
  // Add to candidate set (if it's a viable tip)
  TryAddBlockIndexCandidate(pindex);
  // Block accepted - now try to activate best chain
  return ActivateBestChain(nullptr);
}

bool ChainstateManager::IsNetworkExpired() {
  uint32_t expiration = params_.GetConsensus().nNetworkExpirationInterval;
  if (expiration == 0) {
    return false;
  }

  const auto* tip = block_manager_.GetTip();
  if (!tip) {
    return false;
  }

  int32_t height = tip->nHeight;

  // Grace period warning before fatal expiration
  int32_t grace = params_.GetConsensus().nNetworkExpirationGracePeriod;
  if (grace > 0) {
    int32_t warning_start = static_cast<int32_t>(expiration) - grace;
    if (height >= warning_start && height < static_cast<int32_t>(expiration) &&
        height != last_expiration_warning_height_) {
      int32_t remaining = static_cast<int32_t>(expiration) - height;
      LOG_CHAIN_ERROR("WARNING: Network expires in {} block{}. "
                      "Please update to the latest version.",
                      remaining, remaining == 1 ? "" : "s");
      last_expiration_warning_height_ = height;
    }
  }

  if (height >= static_cast<int>(expiration)) {
    LOG_CHAIN_ERROR("Network expiration block {} reached. "
                    "Please update to the latest version.",
                    expiration);
    Notifications().NotifyFatalError(fmt::format("Network expiration block {} reached", expiration),
                                     "Please update to the latest version.");
    return true;
  }
  return false;
}


void ChainstateManager::DispatchNotifications(const std::vector<PendingNotification>& events) {
  for (const auto& ev : events) {
    switch (ev.type) {
    case NotifyType::BlockConnected:
      Notifications().NotifyBlockConnected(ev.block_event);
      break;
    case NotifyType::ChainTip:
      Notifications().NotifyChainTip(ev.tip_event);
      break;
    }
  }
}

bool ChainstateManager::ActivateBestChain(chain::CBlockIndex* pindexMostWork) {
  std::unique_lock<std::recursive_mutex> lock(validation_mutex_);
  std::vector<PendingNotification> pending_events;

  // Capture IBD state ONCE at batch start - all events in this batch get the same value.
  const bool is_initial_download = IsInitialBlockDownload();

  // Find best candidate if not provided
  if (!pindexMostWork) {
    pindexMostWork = FindMostWorkCandidate();
  }

  // Try to switch to best candidate (if any, and not already there)
  if (pindexMostWork && block_manager_.GetTip() != pindexMostWork) {
    if (TrySwitchToNewTip(pindexMostWork, pending_events, is_initial_download) != ActivateResult::OK) {
      lock.unlock();
      return false;
    }
  }

  // Check network expiration
  if (IsNetworkExpired()) {
    lock.unlock();
    return false;
  }

  // Release lock, then dispatch notifications
  lock.unlock();
  DispatchNotifications(pending_events);
  return true;
}

// Helper: format block for logging (hash prefix @ height)
static std::string LogBlock(const chain::CBlockIndex* block) {
  if (!block) return "null";
  return fmt::format("{} @ {}", block->GetBlockHash().ToString().substr(0, 16), block->nHeight);
}

std::optional<ChainstateManager::ActivateResult> ChainstateManager::ValidateReorg(
    const chain::CBlockIndex* oldTip,
    const chain::CBlockIndex* newTip,
    const chain::CBlockIndex* fork) {
  // No common ancestor with existing tip = database corruption
  if (!fork && oldTip) {
    LOG_CHAIN_ERROR("CRITICAL: No common ancestor - tip {} vs candidate {}", LogBlock(oldTip), LogBlock(newTip));
    Notifications().NotifyFatalError("No common ancestor between chains (database corruption)",
                                     "Node halted. Delete blockchain data and resync.");
    return ActivateResult::SYSTEM_ERROR;
  }

  // Reject suspiciously deep reorgs
  const int suspicious_reorg_depth = params_.GetConsensus().nSuspiciousReorgDepth;
  if (oldTip && fork && suspicious_reorg_depth > 0) {
    int reorg_depth = oldTip->nHeight - fork->nHeight;
    if (reorg_depth >= suspicious_reorg_depth) {
      LOG_CHAIN_ERROR("CRITICAL: Reorg of {} blocks refused (limit: {}) - tip {} -> candidate {}, fork @ {}",
                      reorg_depth, suspicious_reorg_depth - 1, LogBlock(oldTip), LogBlock(newTip), fork->nHeight);
      Notifications().NotifyFatalError(fmt::format("Deep reorg of {} blocks refused", reorg_depth),
                                       fmt::format("If legitimate, restart with --suspicious-reorg-depth={}",
                                                   reorg_depth + 1));
      return ActivateResult::SYSTEM_ERROR;
    }
  }

  return std::nullopt;  // OK to proceed
}

std::optional<ChainstateManager::ActivateResult> ChainstateManager::DisconnectToFork(
    const chain::CBlockIndex* fork) {
  // Disconnect blocks until tip equals fork
  while (block_manager_.GetTip() && block_manager_.GetTip() != fork) {
    const chain::CBlockIndex* tip = block_manager_.GetTip();
    if (!DisconnectTip()) {
      LOG_CHAIN_ERROR("CRITICAL: DisconnectTip failed at height {}", tip->nHeight);
      Notifications().NotifyFatalError(fmt::format("DisconnectTip failed at height {}", tip->nHeight),
                                       "Failed to disconnect block. Node must shut down.");
      return ActivateResult::SYSTEM_ERROR;
    }
  }
  return std::nullopt;
}

std::optional<ChainstateManager::ActivateResult> ChainstateManager::ConnectFromFork(
    const chain::CBlockIndex* fork,
    chain::CBlockIndex* newTip,
    std::vector<PendingNotification>& events,
    bool is_initial_download) {
  // Build path from fork to newTip (collected in reverse order)
  std::vector<chain::CBlockIndex*> path;
  for (chain::CBlockIndex* p = newTip; p && p != fork; p = p->pprev) {
    path.push_back(p);
  }

  // Connect in order: fork+1, fork+2, ..., newTip
  for (auto it = path.rbegin(); it != path.rend(); ++it) {
    if (!ConnectTip(*it, events, is_initial_download)) {
      LOG_CHAIN_ERROR("CRITICAL: ConnectTip failed at height {}", (*it)->nHeight);
      Notifications().NotifyFatalError(fmt::format("ConnectTip failed at height {}", (*it)->nHeight),
                                       "Failed to connect block. Node must shut down.");
      return ActivateResult::SYSTEM_ERROR;
    }
  }
  return std::nullopt;
}

ChainstateManager::ActivateResult ChainstateManager::TrySwitchToNewTip(chain::CBlockIndex* pindexMostWork,
                                                                       std::vector<PendingNotification>& events,
                                                                       bool is_initial_download) {
  // PRE: validation_mutex_ is held by caller
  if (!pindexMostWork) {
    return ActivateResult::OK;
  }

  const chain::CBlockIndex* pindexOldTip = block_manager_.GetTip();

  // Early exits: same tip or insufficient work
  if (pindexOldTip == pindexMostWork) {
    return ActivateResult::OK;
  }
  if (pindexOldTip && pindexMostWork->nChainWork <= pindexOldTip->nChainWork) {
    LOG_CHAIN_TRACE("candidate {} has less work than tip; skipping", LogBlock(pindexMostWork));
    return ActivateResult::OK;
  }

  // Find fork point and validate the reorg
  const chain::CBlockIndex* pindexFork = chain::LastCommonAncestor(pindexOldTip, pindexMostWork);
  if (auto err = ValidateReorg(pindexOldTip, pindexMostWork, pindexFork)) {
    return *err;
  }

  // Track whether this is a reorg (for logging)
  const bool is_reorg = pindexOldTip && pindexFork && pindexOldTip != pindexFork;
  const int disconnect_count = is_reorg ? (pindexOldTip->nHeight - pindexFork->nHeight) : 0;
  const int connect_count = pindexMostWork->nHeight - (pindexFork ? pindexFork->nHeight : -1);

  // Disconnect old chain to fork point
  if (auto err = DisconnectToFork(pindexFork)) {
    return *err;
  }

  // Connect new chain from fork to new tip
  if (auto err = ConnectFromFork(pindexFork, pindexMostWork, events, is_initial_download)) {
    return *err;
  }

  // Emit ChainTip notification - is_initial_download was captured at ActivateBestChain() entry
  events.push_back(PendingNotification{NotifyType::ChainTip, BlockConnectedEvent{{}, 0, 0, false},
                                       ChainTipEvent{pindexMostWork->GetBlockHash(), pindexMostWork->nHeight, is_initial_download}});

  if (is_reorg) {
    LOG_CHAIN_INFO("REORGANIZE: {} blocks disconnected, {} connected - old tip {}, new tip {}, fork @ {}",
                   disconnect_count, connect_count, LogBlock(pindexOldTip), LogBlock(pindexMostWork),
                   pindexFork->nHeight);
  } else {
    LOG_CHAIN_INFO("New best chain activated! Height: {}, Hash: {}, log2_work: {:.6f}", pindexMostWork->nHeight,
                   pindexMostWork->GetBlockHash().ToString().substr(0, 16),
                   std::log(pindexMostWork->nChainWork.getdouble()) / std::log(2.0));
  }

  PruneCandidates();
  return ActivateResult::OK;
}

const chain::CBlockIndex* ChainstateManager::GetTip() const {
  std::lock_guard<std::recursive_mutex> lock(validation_mutex_);
  return block_manager_.GetTip();
}

const chain::CBlockIndex* ChainstateManager::LookupBlockIndex(const uint256& hash) const {
  std::lock_guard<std::recursive_mutex> lock(validation_mutex_);
  return block_manager_.LookupBlockIndex(hash);
}

CBlockLocator ChainstateManager::GetLocator(const chain::CBlockIndex* pindex) const {
  std::lock_guard<std::recursive_mutex> lock(validation_mutex_);
  return pindex ? chain::GetLocator(pindex) : block_manager_.ActiveChain().GetLocator();
}

bool ChainstateManager::IsOnActiveChain(const chain::CBlockIndex* pindex) const {
  std::lock_guard<std::recursive_mutex> lock(validation_mutex_);
  return pindex && block_manager_.ActiveChain().Contains(pindex);
}

const chain::CBlockIndex* ChainstateManager::GetBlockAtHeight(int height) const {
  std::lock_guard<std::recursive_mutex> lock(validation_mutex_);
  if (height < 0 || height > block_manager_.ActiveChain().Height())
    return nullptr;
  return block_manager_.ActiveChain()[height];
}

bool ChainstateManager::ConnectTip(chain::CBlockIndex* pindexNew,
                                   std::vector<PendingNotification>& events,
                                   bool is_initial_download) {
  if (!pindexNew) {
    LOG_CHAIN_ERROR("ConnectTip: null block index");
    return false;
  }

  LOG_CHAIN_TRACE("ConnectTip: connecting block height={} hash={}", pindexNew->nHeight,
                  pindexNew->GetBlockHash().ToString().substr(0, 16));

  // Update tip
  block_manager_.SetActiveTip(*pindexNew);

  const std::string best_hash = pindexNew->GetBlockHash().ToString().substr(0, 16);
  const double log2_work = std::log(pindexNew->nChainWork.getdouble()) / std::log(2.0);
  const std::string date_str = util::FormatTime(pindexNew->GetBlockTime());
  const uint32_t version = static_cast<uint32_t>(pindexNew->nVersion);
  LOG_CHAIN_INFO("UpdateTip: new best={} height={} version=0x{:08x} log2_work={:.6f} date='{}' (in IBD={})", best_hash,
                 pindexNew->nHeight, version, log2_work, date_str, is_initial_download ? "true" : "false");

  // Queue block connected notification
  events.push_back(PendingNotification{
      NotifyType::BlockConnected,
      BlockConnectedEvent{pindexNew->GetBlockHash(), pindexNew->nHeight, pindexNew->nTime, is_initial_download},
      ChainTipEvent{}});  // unused for BlockConnected

  return true;
}

bool ChainstateManager::DisconnectTip() {
  chain::CBlockIndex* pindexDelete = block_manager_.GetTip();
  if (!pindexDelete) {
    LOG_CHAIN_ERROR("DisconnectTip: no tip to disconnect");
    return false;
  }

  if (!pindexDelete->pprev) {
    LOG_CHAIN_ERROR("DisconnectTip: cannot disconnect genesis block");
    return false;
  }

  LOG_CHAIN_TRACE("DisconnectTip: disconnecting block height={} hash={}", pindexDelete->nHeight,
                  pindexDelete->GetBlockHash().ToString().substr(0, 16));

  block_manager_.SetActiveTip(*pindexDelete->pprev);

  return true;
}

void ChainstateManager::TryAddBlockIndexCandidate(chain::CBlockIndex* pindex) {
  std::lock_guard<std::recursive_mutex> lock(validation_mutex_);
  if (!pindex || !pindex->IsValid(chain::BlockStatus::TREE) || pindex->nChainWork == arith_uint256(0)) {
    return;
  }
  // Remove parent from candidates (parent is no longer a leaf)
  if (pindex->pprev) {
    active_tip_candidates_.Remove(pindex->pprev->GetBlockHash());
  }
  active_tip_candidates_.Add(pindex->GetBlockHash());
}

bool ChainstateManager::IsInitialBlockDownload() const {
  // Fast path: check latch first (lock-free)
  if (m_cached_finished_ibd.load(std::memory_order_acquire)) {
    return false;
  }

  // No tip yet - definitely in IBD
  const chain::CBlockIndex* tip = GetTip();
  if (!tip) {
    return true;
  }

  // Genesis (height 0) is considered IBD regardless of time skew or min chain work.
  // This helps fresh networks and simulated environments with mocked time.
  if (tip->nHeight == 0) {
    return true;
  }

  // Tip too old
  int64_t now = util::GetTime();
  if (tip->nTime < now - IBD_STALE_TIP_SECONDS) {
    return true;
  }

  // MinimumChainWork check
  if (tip->nChainWork < UintToArith256(params_.GetConsensus().nMinimumChainWork)) {
    return true;
  }

  // All checks passed - we're synced!
  // Latch to false permanently
  LOG_CHAIN_INFO("leaving IBD (latching to false)");
  m_cached_finished_ibd.store(true, std::memory_order_release);

  return false;
}

bool ChainstateManager::Initialize(const CBlockHeader& genesis_header) {
  std::lock_guard<std::recursive_mutex> lock(validation_mutex_);

  if (!block_manager_.Initialize(genesis_header)) {
    return false;
  }

  // Initialize the candidate set with genesis block
  chain::CBlockIndex* genesis = block_manager_.GetTip();
  if (genesis) {
    // Mark genesis as valid to TREE level (it's pre-validated)
    [[maybe_unused]] bool raised = genesis->RaiseValidity(chain::BlockStatus::TREE);

    active_tip_candidates_.Add(genesis->GetBlockHash());
    LOG_CHAIN_TRACE("initialized with genesis as candidate: height={}, hash={}", genesis->nHeight,
                    genesis->GetBlockHash().ToString().substr(0, 16));
  }

  return true;
}

chain::LoadResult ChainstateManager::Load(const std::string& filepath, bool revalidate) {
  std::lock_guard<std::recursive_mutex> lock(validation_mutex_);

  chain::LoadResult result = block_manager_.Load(filepath, params_.GetConsensus().hashGenesisBlock);
  if (result != chain::LoadResult::SUCCESS) {
    return result;
  }

  // Build height-ordered list for traversal
  std::vector<chain::CBlockIndex*> by_height;
  by_height.reserve(block_manager_.GetBlockIndex().size());
  for (auto& [hash, block] : block_manager_.GetMutableBlockIndex()) {
    by_height.push_back(&block);
  }
  std::sort(by_height.begin(), by_height.end(),
            [](const chain::CBlockIndex* a, const chain::CBlockIndex* b) { return a->nHeight < b->nHeight; });

  // Always recompute chainwork and rebuild skip pointers
  for (chain::CBlockIndex* pindex : by_height) {
    if (pindex->pprev) {
      pindex->nChainWork = pindex->pprev->nChainWork + chain::GetBlockProof(*pindex);
    } else {
      pindex->nChainWork = chain::GetBlockProof(*pindex);
    }
    pindex->BuildSkip();
  }

  if (revalidate) {
    // Paranoid mode: re-validate PoW and propagate failures
    // Any validation failure is fatal - indicates data corruption
    for (chain::CBlockIndex* pindex : by_height) {
      // Propagate ancestor failure (already detected corruption earlier)
      if (pindex->pprev && pindex->pprev->status.IsFailed()) {
        LOG_CHAIN_ERROR("Load: Block {} has failed ancestor - data corrupted",
                        pindex->GetBlockHash().ToString().substr(0, 16));
        return chain::LoadResult::CORRUPTED;
      }

      // Re-validate to TREE level
      if (pindex->pprev) {
        const CBlockHeader hdr = pindex->GetBlockHeader();
        // Cheap PoW commitment check
        if (!CheckProofOfWork(hdr, crypto::POWVerifyMode::COMMITMENT_ONLY)) {
          LOG_CHAIN_ERROR("Load: Block {} failed PoW commitment check - data corrupted",
                          pindex->GetBlockHash().ToString().substr(0, 16));
          return chain::LoadResult::CORRUPTED;
        }
        // Contextual checks
        ValidationState st;
        if (!ContextualCheckBlockHeaderWrapper(hdr, pindex->pprev, util::GetTime(), st)) {
          LOG_CHAIN_ERROR("Load: Block {} failed contextual check: {} - data corrupted",
                          pindex->GetBlockHash().ToString().substr(0, 16), st.GetRejectReason());
          return chain::LoadResult::CORRUPTED;
        }
      }

      // Block passed validation
      [[maybe_unused]] bool _ = pindex->RaiseValidity(chain::BlockStatus::TREE);
      LOG_CHAIN_TRACE("Load: Block {} validation={} (valid)",
                      pindex->GetBlockHash().ToString().substr(0, 16), (int)pindex->status.validation);
    }
  } else {
    // Trust mode: mark all blocks as TREE valid
    for (chain::CBlockIndex* pindex : by_height) {
      [[maybe_unused]] bool _ = pindex->RaiseValidity(chain::BlockStatus::TREE);
    }
  }

  // Rebuild the candidate set after loading from disk
  // We need to find all leaf nodes (tips) in the block tree
  active_tip_candidates_.Clear();

  const auto& block_index = block_manager_.GetBlockIndex();

  // Find leaf nodes (blocks with no children)
  std::set<const chain::CBlockIndex*> blocks_with_children;
  for (const auto& [hash, block] : block_index) {
    if (block.pprev) {
      blocks_with_children.insert(block.pprev);
    }
  }

  size_t leaf_count = 0;
  size_t candidate_count = 0;
  for (auto& [hash, block] : block_manager_.GetMutableBlockIndex()) {
    if (blocks_with_children.find(&block) == blocks_with_children.end()) {
      leaf_count++;
      if (block.IsValid(chain::BlockStatus::TREE)) {
        active_tip_candidates_.Add(hash);
        candidate_count++;

        LOG_CHAIN_TRACE("added leaf as candidate: height={}, hash={}, log2_work={:.6f}", block.nHeight,
                        hash.ToString().substr(0, 16), std::log(block.nChainWork.getdouble()) / std::log(2.0));
      } else {
        LOG_CHAIN_TRACE("found invalid leaf (not added to candidates): height={}, "
                        "hash={}, status={}",
                        block.nHeight, hash.ToString().substr(0, 16), block.status.ToString());
      }
    }
  }

  chain::CBlockIndex* tip = block_manager_.GetTip();
  LOG_CHAIN_TRACE("loaded chain state: {} total blocks, {} leaf nodes, {} valid candidates", block_index.size(),
                  leaf_count, candidate_count);

  if (tip) {
    LOG_CHAIN_TRACE("active chain tip: height={}, hash={}", tip->nHeight, tip->GetBlockHash().ToString().substr(0, 16));
  }

  return chain::LoadResult::SUCCESS;
}

bool ChainstateManager::Save(const std::string& filepath) const {
  std::lock_guard<std::recursive_mutex> lock(validation_mutex_);
  return block_manager_.Save(filepath);
}

size_t ChainstateManager::GetBlockCount() const {
  std::lock_guard<std::recursive_mutex> lock(validation_mutex_);
  return block_manager_.GetBlockCount();
}

int ChainstateManager::GetChainHeight() const {
  std::lock_guard<std::recursive_mutex> lock(validation_mutex_);
  return block_manager_.ActiveChain().Height();
}

std::vector<ChainstateManager::ChainTip> ChainstateManager::GetChainTips() const {
  std::lock_guard<std::recursive_mutex> lock(validation_mutex_);

  std::vector<ChainTip> tips;
  const auto& active_chain = block_manager_.ActiveChain();
  const auto* active_tip = active_chain.Tip();

  if (!active_tip) {
    return tips;  // No chain yet
  }

  // Algorithm (from Bitcoin Core):
  // 1. Collect all blocks not on active chain (stale/side-chain blocks)
  // 2. Track which blocks have children (are parents of other stale blocks)
  // 3. Tips are stale blocks with no children, plus the active tip

  std::set<const chain::CBlockIndex*> stale_blocks;
  std::set<const chain::CBlockIndex*> has_children;

  for (const auto& [hash, block_index] : block_manager_.GetBlockIndex()) {
    if (!active_chain.Contains(&block_index)) {
      stale_blocks.insert(&block_index);
      if (block_index.pprev) {
        has_children.insert(block_index.pprev);
      }
    }
  }

  // Find tips: stale blocks that are not parents of other stale blocks
  std::vector<const chain::CBlockIndex*> tip_indices;
  for (const auto* block : stale_blocks) {
    if (has_children.find(block) == has_children.end()) {
      tip_indices.push_back(block);
    }
  }

  // Always include active tip
  tip_indices.push_back(active_tip);

  // Sort by height descending for consistent output
  std::sort(tip_indices.begin(), tip_indices.end(),
            [](const chain::CBlockIndex* a, const chain::CBlockIndex* b) { return a->nHeight > b->nHeight; });

  // Build result
  for (const auto* pindex : tip_indices) {
    ChainTip tip;
    tip.height = pindex->nHeight;
    tip.hash = pindex->GetBlockHash();

    if (active_chain.Contains(pindex)) {
      tip.branchlen = 0;
      tip.status = ChainTip::Status::ACTIVE;
    } else {
      // Find fork point and calculate branch length
      const auto* fork = active_chain.FindFork(pindex);
      tip.branchlen = fork ? (pindex->nHeight - fork->nHeight) : pindex->nHeight;

      if (pindex->status.IsFailed()) {
        tip.status = ChainTip::Status::INVALID;
      } else {
        tip.status = ChainTip::Status::VALID_FORK;
      }
    }

    tips.push_back(tip);
  }

  return tips;
}

bool ChainstateManager::CheckHeadersPoW(const std::vector<CBlockHeader>& headers) const {
  if (test_skip_pow_checks_.load(std::memory_order_acquire)) {
    return true;
  }
  return validation::CheckHeadersPoW(headers, params_);
}

bool ChainstateManager::CheckProofOfWork(const CBlockHeader& header, crypto::POWVerifyMode mode) const {
  if (test_skip_pow_checks_.load(std::memory_order_acquire)) {
    return true;
  }
  return consensus::CheckProofOfWork(header, header.nBits, params_, mode);
}

bool ChainstateManager::CheckBlockHeaderWrapper(const CBlockHeader& header, ValidationState& state) const {
  if (test_skip_pow_checks_.load(std::memory_order_acquire)) {
    return true;
  }
  return CheckBlockHeader(header, params_, state);
}

bool ChainstateManager::ContextualCheckBlockHeaderWrapper(const CBlockHeader& header,
                                                          const chain::CBlockIndex* pindexPrev, int64_t adjusted_time,
                                                          ValidationState& state) const {
  return ContextualCheckBlockHeader(header, pindexPrev, params_, adjusted_time, state);
}

bool ChainstateManager::InvalidateBlock(const uint256& hash) {
  std::lock_guard<std::recursive_mutex> lock(validation_mutex_);

  chain::CBlockIndex* pindex = block_manager_.LookupBlockIndex(hash);
  if (!pindex) {
    LOG_CHAIN_ERROR("InvalidateBlock: block {} not found", hash.ToString());
    return false;
  }

  if (pindex->nHeight == 0) {
    LOG_CHAIN_ERROR("InvalidateBlock: cannot invalidate genesis block");
    return false;
  }

  LOG_CHAIN_INFO("InvalidateBlock: {} at height {}", hash.ToString().substr(0, 16), pindex->nHeight);

  // Collect fork candidates before disconnecting
  std::vector<chain::CBlockIndex*> fork_candidates;
  for (auto& [block_hash, block] : block_manager_.GetMutableBlockIndex()) {
    if (!block_manager_.ActiveChain().Contains(&block) && pindex->pprev &&
        block.nChainWork >= pindex->pprev->nChainWork && block.IsValid(chain::BlockStatus::TREE)) {
      fork_candidates.push_back(&block);
    }
  }

  // Disconnect blocks from tip down to pindex
  while (block_manager_.ActiveChain().Contains(pindex)) {
    chain::CBlockIndex* tip = block_manager_.GetTip();
    if (!tip)
      break;

    if (!DisconnectTip()) {
      LOG_CHAIN_ERROR("InvalidateBlock: failed to disconnect tip");
      return false;
    }

    active_tip_candidates_.Remove(tip->GetBlockHash());
    if (tip->pprev) {
      active_tip_candidates_.Add(tip->pprev->GetBlockHash());
    }
  }

  if (block_manager_.ActiveChain().Contains(pindex)) {
    LOG_CHAIN_ERROR("InvalidateBlock: block still in active chain after disconnect");
    return false;
  }

  // Mark invalidated block as failed
  pindex->status.MarkFailed();
  active_tip_candidates_.Remove(pindex->GetBlockHash());

  // Mark descendants as ANCESTOR_FAILED
  size_t descendant_count = 0;
  for (auto& [block_hash, block] : block_manager_.GetMutableBlockIndex()) {
    if (&block != pindex && block.GetAncestor(pindex->nHeight) == pindex) {
      block.status.MarkAncestorFailed();
      active_tip_candidates_.Remove(block_hash);
      descendant_count++;
    }
  }

  // Add fork candidates
  for (chain::CBlockIndex* candidate : fork_candidates) {
    if (!candidate->status.IsFailed()) {
      active_tip_candidates_.Add(candidate->GetBlockHash());
    }
  }

  LOG_CHAIN_INFO("InvalidateBlock: invalidated {} descendants, {} fork candidates", descendant_count,
                 fork_candidates.size());

  // Caller should call ActivateBestChain() to switch to best fork
  return true;
}

void ChainstateManager::TestSetSkipPoWChecks(bool enabled) {
  if (params_.GetChainType() != chain::ChainType::REGTEST) {
    throw std::runtime_error("PoW skip is only allowed in regtest mode");
  }
  test_skip_pow_checks_.store(enabled, std::memory_order_release);
}

bool ChainstateManager::TestGetSkipPoWChecks() const {
  return test_skip_pow_checks_.load(std::memory_order_acquire);
}

size_t ChainstateManager::DebugCandidateCount() const {
  std::lock_guard<std::recursive_mutex> lock(validation_mutex_);
  return active_tip_candidates_.Size();
}

std::vector<uint256> ChainstateManager::DebugCandidateHashes() const {
  std::lock_guard<std::recursive_mutex> lock(validation_mutex_);
  std::vector<uint256> result;
  result.reserve(active_tip_candidates_.Size());
  for (const uint256& hash : active_tip_candidates_.All()) {
    result.push_back(hash);
  }
  return result;
}

chain::CBlockIndex* ChainstateManager::FindMostWorkCandidate() {
  // PRE: validation_mutex_ is held by caller
  chain::CBlockIndex* best = nullptr;

  for (const uint256& hash : active_tip_candidates_.All()) {
    chain::CBlockIndex* pindex = block_manager_.LookupBlockIndex(hash);
    if (!pindex) {
      // Hash no longer in index (pruned) - skip, will be cleaned by PruneCandidates
      continue;
    }
    if (pindex->status.IsFailed()) {
      continue;
    }
    if (!best || pindex->nChainWork > best->nChainWork) {
      best = pindex;
    }
  }

  return best;
}

void ChainstateManager::PruneCandidates() {
  // PRE: validation_mutex_ is held by caller
  const chain::CBlockIndex* tip = block_manager_.GetTip();

  std::vector<uint256> to_remove;
  for (const uint256& hash : active_tip_candidates_.All()) {
    chain::CBlockIndex* pindex = block_manager_.LookupBlockIndex(hash);

    // Remove if: not in index anymore, is the tip, or failed
    // NOTE: Do NOT remove lower-work candidates - they are kept for InvalidateBlock.
    // Lower-work candidates are naturally removed when descendants are added.
    if (!pindex) {
      to_remove.push_back(hash);
    } else if (tip && pindex == tip) {
      to_remove.push_back(hash);
    } else if (pindex->status.IsFailed()) {
      to_remove.push_back(hash);
    }
  }

  for (const uint256& hash : to_remove) {
    active_tip_candidates_.Remove(hash);
  }
}

}  // namespace validation
}  // namespace unicity
