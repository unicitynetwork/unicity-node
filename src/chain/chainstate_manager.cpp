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
    : block_manager_(), params_(params), suspicious_reorg_depth_(params.GetConsensus().nSuspiciousReorgDepth) {}

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
    LOG_CHAIN_TRACE("Block header {} already exists and is valid, returning existing", hash.ToString().substr(0, 16));
    return pindex;
  }

  // Step 2: Cheap POW commitment check (anti-DoS prefilter)
  if (!CheckProofOfWork(header, crypto::POWVerifyMode::COMMITMENT_ONLY)) {
    state.Invalid("high-hash", "proof of work commitment failed");
    LOG_CHAIN_ERROR("Block header {} failed POW commitment check", hash.ToString().substr(0, 16));
    return nullptr;
  }

  // Step 3: Check if this is a genesis block (must be initialized separately)
  if (header.hashPrevBlock.IsNull()) {
    if (hash != params_.GetConsensus().hashGenesisBlock) {
      state.Invalid("bad-genesis", "genesis block hash mismatch");
      LOG_CHAIN_ERROR("Rejected fake genesis block: {} (expected: {})", hash.ToString(),
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
  int64_t adjusted_time = GetAdjustedTime();
  if (!ContextualCheckBlockHeaderWrapper(header, pindexPrev, adjusted_time, state)) {
    LOG_CHAIN_ERROR("Contextual check failed for {}: {} - {}", hash.ToString().substr(0, 16), state.GetRejectReason(),
                    state.GetDebugMessage());
    return nullptr;
  }

  // Step 7: Full PoW (RandomX) - expensive, so done after cheap contextual checks
  if (!CheckBlockHeaderWrapper(header, state)) {
    LOG_CHAIN_ERROR("Full PoW check failed for {}: {} - {}", hash.ToString().substr(0, 16), state.GetRejectReason(),
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

  // Log at DEBUG during IBD (high volume), INFO after (notable event)
  if (IsInitialBlockDownload()) {
    LOG_CHAIN_DEBUG("Saw new header hash={} height={}", hash.ToString(), pindex->nHeight);
  } else {
    LOG_CHAIN_INFO("Saw new header hash={} height={}", hash.ToString(), pindex->nHeight);
  }

  LOG_CHAIN_TRACE("Accepted new block header: hash={}, height={}, log2_work={:.6f}", hash.ToString().substr(0, 16),
                  pindex->nHeight, std::log(pindex->nChainWork.getdouble()) / std::log(2.0));

  // Process orphan children now that parent exists
  ProcessOrphanHeaders(hash);

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
  if (tip && tip->nHeight >= static_cast<int>(expiration)) {
    LOG_CHAIN_ERROR("\033[1;31mNetwork expiration block {} reached. "
                    "Please update to the latest version.\033[0m",
                    expiration);
    Notifications().NotifyFatalError(fmt::format("Network expiration block {} reached", expiration),
                                     "Please update to the latest version.");
    return true;
  }
  return false;
}

void ChainstateManager::PruneStaleSideChains() {
  int reorg_depth = params_.GetConsensus().nSuspiciousReorgDepth;
  if (reorg_depth > 0) {
    block_manager_.PruneStaleSideChains(reorg_depth);
    PruneCandidates();
  }
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

  // Find best candidate if not provided
  if (!pindexMostWork) {
    pindexMostWork = FindMostWorkCandidate();
  }

  // Try to switch to best candidate (if any, and not already there)
  if (pindexMostWork && block_manager_.GetTip() != pindexMostWork) {
    if (TrySwitchToNewTip(pindexMostWork, pending_events) != ActivateResult::OK) {
      lock.unlock();
      return false;
    }
  }

  // Check network expiration
  if (IsNetworkExpired()) {
    lock.unlock();
    return false;
  }

  // Prune stale side-chain headers
  PruneStaleSideChains();

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
  if (oldTip && fork && suspicious_reorg_depth_ > 0) {
    int reorg_depth = oldTip->nHeight - fork->nHeight;
    if (reorg_depth >= suspicious_reorg_depth_) {
      LOG_CHAIN_ERROR("CRITICAL: Reorg of {} blocks refused (limit: {}) - tip {} -> candidate {}, fork @ {}",
                      reorg_depth, suspicious_reorg_depth_ - 1, LogBlock(oldTip), LogBlock(newTip), fork->nHeight);
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
    std::vector<PendingNotification>& events) {
  // Build path from fork to newTip (collected in reverse order)
  std::vector<chain::CBlockIndex*> path;
  for (chain::CBlockIndex* p = newTip; p && p != fork; p = p->pprev) {
    path.push_back(p);
  }

  // Connect in order: fork+1, fork+2, ..., newTip
  for (auto it = path.rbegin(); it != path.rend(); ++it) {
    if (!ConnectTip(*it, events)) {
      LOG_CHAIN_ERROR("CRITICAL: ConnectTip failed at height {}", (*it)->nHeight);
      Notifications().NotifyFatalError(fmt::format("ConnectTip failed at height {}", (*it)->nHeight),
                                       "Failed to connect block. Node must shut down.");
      return ActivateResult::SYSTEM_ERROR;
    }
  }
  return std::nullopt;
}

ChainstateManager::ActivateResult ChainstateManager::TrySwitchToNewTip(chain::CBlockIndex* pindexMostWork,
                                                                       std::vector<PendingNotification>& events) {
  // PRE: validation_mutex_ is held by caller
  if (!pindexMostWork) {
    return ActivateResult::OK;
  }

  chain::CBlockIndex* pindexOldTip = block_manager_.GetTip();

  // Early exits: same tip or insufficient work
  if (pindexOldTip == pindexMostWork) {
    return ActivateResult::OK;
  }
  if (pindexOldTip && pindexMostWork->nChainWork <= pindexOldTip->nChainWork) {
    LOG_CHAIN_TRACE("Candidate {} has less work than tip; skipping", LogBlock(pindexMostWork));
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
  if (auto err = ConnectFromFork(pindexFork, pindexMostWork, events)) {
    return *err;
  }

  // Emit ChainTip notification
  events.push_back(PendingNotification{NotifyType::ChainTip, BlockConnectedEvent{},
                                       ChainTipEvent{pindexMostWork->GetBlockHash(), pindexMostWork->nHeight}});

 
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

bool ChainstateManager::ConnectTip(chain::CBlockIndex* pindexNew, std::vector<PendingNotification>& events) {
  if (!pindexNew) {
    LOG_CHAIN_ERROR("ConnectTip: null block index");
    return false;
  }

  LOG_CHAIN_TRACE("ConnectTip: connecting block height={} hash={}", pindexNew->nHeight,
                  pindexNew->GetBlockHash().ToString().substr(0, 16));

  // Update tip BEFORE notifying
  block_manager_.SetActiveTip(*pindexNew);

  const std::string best_hash = pindexNew->GetBlockHash().ToString().substr(0, 16);
  const double log2_work = std::log(pindexNew->nChainWork.getdouble()) / std::log(2.0);
  const std::string date_str = util::FormatTime(pindexNew->GetBlockTime());
  const uint32_t version = static_cast<uint32_t>(pindexNew->nVersion);
  LOG_CHAIN_INFO("UpdateTip: new best={} height={} version=0x{:08x} log2_work={:.6f} date='{}'", best_hash,
                 pindexNew->nHeight, version, log2_work, date_str);

  // Queue block connected notification AFTER updating tip
  events.push_back(PendingNotification{
      NotifyType::BlockConnected,
      BlockConnectedEvent{pindexNew->GetBlockHash(), pindexNew->nHeight, pindexNew->nTime},
      ChainTipEvent{}});  // unused for BlockConnected

  return true;
}

bool ChainstateManager::AddOrphanHeader(const CBlockHeader& header, int peer_id) {
  std::lock_guard<std::recursive_mutex> lock(validation_mutex_);
  return TryAddOrphanHeader(header, peer_id);
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
  LOG_CHAIN_INFO("Leaving InitialBlockDownload (latching to false)");
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
    LOG_CHAIN_TRACE("Initialized with genesis as candidate: height={}, hash={}", genesis->nHeight,
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
        if (!ContextualCheckBlockHeaderWrapper(hdr, pindex->pprev, GetAdjustedTime(), st)) {
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

        LOG_CHAIN_TRACE("Added leaf as candidate: height={}, hash={}, log2_work={:.6f}", block.nHeight,
                        hash.ToString().substr(0, 16), std::log(block.nChainWork.getdouble()) / std::log(2.0));
      } else {
        LOG_CHAIN_TRACE("Found invalid leaf (not added to candidates): height={}, "
                        "hash={}, status={}",
                        block.nHeight, hash.ToString().substr(0, 16), block.status.ToString());
      }
    }
  }

  chain::CBlockIndex* tip = block_manager_.GetTip();
  LOG_CHAIN_TRACE("Loaded chain state: {} total blocks, {} leaf nodes, {} valid candidates", block_index.size(),
                  leaf_count, candidate_count);

  if (tip) {
    LOG_CHAIN_TRACE("Active chain tip: height={}, hash={}", tip->nHeight, tip->GetBlockHash().ToString().substr(0, 16));
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
  // 1. Collect all blocks not on active chain (orphans/forks)
  // 2. Track which blocks have children (are parents of other orphans)
  // 3. Tips are orphans with no children, plus the active tip

  std::set<const chain::CBlockIndex*> orphans;
  std::set<const chain::CBlockIndex*> has_children;

  for (const auto& [hash, block_index] : block_manager_.GetBlockIndex()) {
    if (!active_chain.Contains(&block_index)) {
      orphans.insert(&block_index);
      if (block_index.pprev) {
        has_children.insert(block_index.pprev);
      }
    }
  }

  // Find tips: orphans that are not parents of other orphans
  std::vector<const chain::CBlockIndex*> tip_indices;
  for (const auto* orphan : orphans) {
    if (has_children.find(orphan) == has_children.end()) {
      tip_indices.push_back(orphan);
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

void ChainstateManager::ProcessOrphanHeaders(const uint256& parentHash) {
  // NOTE: Assumes validation_mutex_ is already held by caller

  // Find all orphans waiting for this parent
  std::vector<uint256> orphansToProcess;
  for (const auto& [hash, orphan] : m_orphan_headers) {
    if (orphan.header.hashPrevBlock == parentHash) {
      orphansToProcess.push_back(hash);
    }
  }

  if (orphansToProcess.empty()) {
    return;
  }

  LOG_CHAIN_TRACE("Processing {} orphans waiting for parent {}", orphansToProcess.size(),
                  parentHash.ToString().substr(0, 16));

  for (const uint256& hash : orphansToProcess) {
    auto it = m_orphan_headers.find(hash);
    if (it == m_orphan_headers.end()) {
      continue;
    }

    // Copy before erasing - iterator invalidated by erase
    CBlockHeader orphan_header = it->second.header;
    int orphan_peer_id = it->second.peer_id;
    m_orphan_headers.erase(it);

    // Update peer orphan count
    auto peer_it = m_peer_orphan_count.find(orphan_peer_id);
    if (peer_it != m_peer_orphan_count.end()) {
      if (--peer_it->second == 0) {
        m_peer_orphan_count.erase(peer_it);
      }
    }

    ValidationState orphan_state;
    chain::CBlockIndex* pindex = AcceptBlockHeader(orphan_header, orphan_state);

    if (pindex) {
      m_orphan_metrics.total_resolved.fetch_add(1, std::memory_order_relaxed);
      TryAddBlockIndexCandidate(pindex);
    } else {
      // Orphan passed initial checks but failed re-validation (e.g., parent was invalidated)
      LOG_CHAIN_DEBUG("Orphan {} failed re-validation: {}", orphan_header.GetHash().ToString().substr(0, 16),
                      orphan_state.GetRejectReason());
    }
  }
}

bool ChainstateManager::TryAddOrphanHeader(const CBlockHeader& header, int peer_id) {
  // NOTE: Assumes validation_mutex_ is already held by caller
  uint256 hash = header.GetHash();

  // Already indexed or in orphan pool
  if (block_manager_.LookupBlockIndex(hash) != nullptr) {
    return false;
  }
  if (m_orphan_headers.count(hash)) {
    return true;
  }

  // DoS: per-peer limit
  auto peer_it = m_peer_orphan_count.find(peer_id);
  if (peer_it != m_peer_orphan_count.end() &&
      peer_it->second >= static_cast<int>(protocol::MAX_ORPHAN_HEADERS_PER_PEER)) {
    m_orphan_metrics.per_peer_limit_hits.fetch_add(1, std::memory_order_relaxed);
    LOG_CHAIN_WARN_RL("Peer {} exceeded orphan header limit ({}/{})", peer_id, peer_it->second,
                      protocol::MAX_ORPHAN_HEADERS_PER_PEER);
    return false;
  }

  // DoS: total limit - evict if full
  if (m_orphan_headers.size() >= protocol::MAX_ORPHAN_HEADERS) {
    m_orphan_metrics.global_limit_hits.fetch_add(1, std::memory_order_relaxed);
    LOG_CHAIN_DEBUG("Orphan pool full ({}/{}), triggering eviction", m_orphan_headers.size(),
                    protocol::MAX_ORPHAN_HEADERS);
    if (EvictOrphanHeaders() == 0) {
      return false;
    }
  }

  m_orphan_headers[hash] = OrphanHeader{header, util::GetTime(), peer_id};
  m_peer_orphan_count[peer_id]++;
  m_orphan_metrics.total_added.fetch_add(1, std::memory_order_relaxed);
  return true;
}

size_t ChainstateManager::EvictOrphanHeaders() {
  std::lock_guard<std::recursive_mutex> lock(validation_mutex_);

  if (m_orphan_headers.empty()) {
    return 0;
  }

  // Helper to decrement peer orphan count
  auto decrement_peer_count = [this](int peer_id) {
    auto it = m_peer_orphan_count.find(peer_id);
    if (it != m_peer_orphan_count.end() && --it->second == 0) {
      m_peer_orphan_count.erase(it);
    }
  };

  int64_t now = util::GetTime();
  int64_t expire_time = params_.GetConsensus().nOrphanHeaderExpireTime;
  size_t evicted_expired = 0;
  size_t evicted_oldest = 0;

  // Evict expired orphans
  for (auto it = m_orphan_headers.begin(); it != m_orphan_headers.end();) {
    if (now - it->second.nTimeReceived > expire_time) {
      decrement_peer_count(it->second.peer_id);
      it = m_orphan_headers.erase(it);
      evicted_expired++;
    } else {
      ++it;
    }
  }

  // If still at limit, evict oldest
  if (evicted_expired == 0 && m_orphan_headers.size() >= protocol::MAX_ORPHAN_HEADERS) {
    auto oldest = std::min_element(m_orphan_headers.begin(), m_orphan_headers.end(),
                                   [](const auto& a, const auto& b) { return a.second.nTimeReceived < b.second.nTimeReceived; });
    decrement_peer_count(oldest->second.peer_id);
    m_orphan_headers.erase(oldest);
    evicted_oldest++;
  }

  // Update metrics
  if (evicted_expired > 0) {
    m_orphan_metrics.total_evicted_expired.fetch_add(evicted_expired, std::memory_order_relaxed);
  }
  if (evicted_oldest > 0) {
    m_orphan_metrics.total_evicted_oldest.fetch_add(evicted_oldest, std::memory_order_relaxed);
  }

  size_t total_evicted = evicted_expired + evicted_oldest;
  if (total_evicted > 0) {
    LOG_CHAIN_DEBUG("Evicted {} orphan headers ({} expired, {} oldest), {} remaining", total_evicted, evicted_expired,
                    evicted_oldest, m_orphan_headers.size());
  }

  return total_evicted;
}

size_t ChainstateManager::GetOrphanHeaderCount() const {
  std::lock_guard<std::recursive_mutex> lock(validation_mutex_);
  return m_orphan_headers.size();
}

std::map<int, int> ChainstateManager::GetPeerOrphanCounts() const {
  std::lock_guard<std::recursive_mutex> lock(validation_mutex_);
  return m_peer_orphan_count;
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
  m_failed_blocks.insert(pindex);
  active_tip_candidates_.Remove(pindex->GetBlockHash());

  // Mark descendants as ANCESTOR_FAILED
  size_t descendant_count = 0;
  for (auto& [block_hash, block] : block_manager_.GetMutableBlockIndex()) {
    if (&block != pindex && block.GetAncestor(pindex->nHeight) == pindex) {
      block.status.MarkAncestorFailed();
      m_failed_blocks.insert(&block);
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
