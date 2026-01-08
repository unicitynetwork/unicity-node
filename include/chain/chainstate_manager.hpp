// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include "chain/block.hpp"
#include "chain/block_manager.hpp"
#include "chain/active_tip_candidates.hpp"
#include "chain/notifications.hpp"
#include "util/uint.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace unicity {

// Forward declarations
namespace chain {
class ChainParams;
class CBlockIndex;
}  // namespace chain

namespace crypto {
enum class POWVerifyMode;
}

namespace validation {
class ValidationState;
}

namespace validation {

// ChainstateManager - High-level coordinator for blockchain state
// Processes headers, activates best chain, emits notifications.
// Main entry point for adding blocks to the chain (mining or network).
class ChainstateManager {
public:
  // LIFETIME: ChainParams reference must outlive this ChainstateManager
  explicit ChainstateManager(const chain::ChainParams& params);

  // Accept a block header into the block index.
  // Returns pointer to CBlockIndex on success, nullptr on failure (check state).
  chain::CBlockIndex* AcceptBlockHeader(const CBlockHeader& header, ValidationState& state);

  // Process header: accept → activate best chain → notify if tip changed
  bool ProcessNewBlockHeader(const CBlockHeader& header, ValidationState& state);

  // Activate chain with most work, emit notifications if tip changed
  bool ActivateBestChain(chain::CBlockIndex* pindexMostWork = nullptr);

  // Return current active chain tip (nullptr if uninitialized)
  const chain::CBlockIndex* GetTip() const;

  // Get chain parameters 
  const chain::ChainParams& GetParams() const { return params_; }

  // Thread-safe block index lookup (read-only)
  const chain::CBlockIndex* LookupBlockIndex(const uint256& hash) const;

  // Get block locator (nullptr = tip)
  CBlockLocator GetLocator(const chain::CBlockIndex* pindex = nullptr) const;

  // Check if block is part of the current active chain
  bool IsOnActiveChain(const chain::CBlockIndex* pindex) const;

  // Return block at given height on active chain (nullptr if out of range)
  const chain::CBlockIndex* GetBlockAtHeight(int height) const;

  // Check if in IBD (no tip, tip too old, or low work)
  // Latches to false once IBD completes (no flapping)
  bool IsInitialBlockDownload() const;

  // Add block to candidate set (for batch processing workflows)
  void TryAddBlockIndexCandidate(chain::CBlockIndex* pindex);

  // Initialize chainstate with genesis block header
  bool Initialize(const CBlockHeader& genesis_header);

  // Load chainstate from JSON file
  // revalidate=false (default): Trust saved data, fast startup
  // revalidate=true: Full PoW checks, failure propagation (paranoid mode)
  chain::LoadResult Load(const std::string& filepath, bool revalidate = false);

  // Persist chainstate to JSON file
  bool Save(const std::string& filepath) const;

  // Return total number of blocks in index (all branches)
  size_t GetBlockCount() const;

  // Return height of active chain tip (-1 if uninitialized)
  int GetChainHeight() const;

  // Chain tip information for getchaintips RPC
  struct ChainTip {
    int height;
    uint256 hash;
    int branchlen;  // 0 for active tip, distance from fork point otherwise
    enum class Status { ACTIVE, VALID_FORK, INVALID } status;
  };

  // Get all chain tips (leaf nodes in the block tree)
  // Returns active tip plus any fork tips
  std::vector<ChainTip> GetChainTips() const;

  // Add orphan header (network-layer helper) with per-peer limits/DoS checks
  bool AddOrphanHeader(const CBlockHeader& header, int peer_id);

  // Remove expired orphan headers; returns count evicted
  size_t EvictOrphanHeaders();

  // Return number of cached orphan headers
  size_t GetOrphanHeaderCount() const;

  // Mark block and descendants invalid (for invalidateblock RPC)
  bool InvalidateBlock(const uint256& hash);

  // Verify PoW commitment for a batch of headers
  bool CheckHeadersPoW(const std::vector<CBlockHeader>& headers) const;

  // === Test/Diagnostic Methods ===
  // These methods are public for testing but should not be used in production.

  // Enable/disable PoW bypass (regtest only; throws on other networks)
  void TestSetSkipPoWChecks(bool enabled);

  // Return current PoW bypass setting
  bool TestGetSkipPoWChecks() const;

  // Return number of chain tip candidates
  size_t DebugCandidateCount() const;

  // Return hashes of all chain tip candidates
  std::vector<uint256> DebugCandidateHashes() const;

  // Return orphan count per peer (for DoS diagnostics)
  std::map<int, int> GetPeerOrphanCounts() const;

  // Orphan metrics for observability (lifetime counters)
  struct OrphanMetrics {
    std::atomic<uint64_t> total_added{0};            // Orphans ever added
    std::atomic<uint64_t> total_resolved{0};         // Orphans that found parent
    std::atomic<uint64_t> total_evicted_expired{0};  // Evicted due to time expiry
    std::atomic<uint64_t> total_evicted_oldest{0};   // Evicted as oldest (forced)
    std::atomic<uint64_t> per_peer_limit_hits{0};    // Times per-peer limit blocked add
    std::atomic<uint64_t> global_limit_hits{0};      // Times global limit triggered eviction
  };

  // Return orphan metrics (lifetime counters for observability)
  const OrphanMetrics& GetOrphanMetrics() const { return m_orphan_metrics; }

protected:
  // Verify PoW commitment (virtual for test mocking)
  virtual bool CheckProofOfWork(const CBlockHeader& header, crypto::POWVerifyMode mode) const;

  // Validate header fields (virtual for test mocking)
  virtual bool CheckBlockHeaderWrapper(const CBlockHeader& header, ValidationState& state) const;

  // Validate header against chain context (virtual for test mocking)
  virtual bool ContextualCheckBlockHeaderWrapper(const CBlockHeader& header, const chain::CBlockIndex* pindexPrev,
                                                 int64_t adjusted_time, ValidationState& state) const;

private:
  // Activation step result classification
  enum class ActivateResult {
    OK,           // activation complete or nothing to do
    SYSTEM_ERROR  // unexpected failure (I/O, corruption, or fatal policy violation)
  };

  // Deferred notification events (dispatched after releasing validation lock)
  // Uses value types - no pointers, safe after lock release
  enum class NotifyType { BlockConnected, ChainTip };
  struct PendingNotification {
    NotifyType type;
    BlockConnectedEvent block_event;  // for BlockConnected
    ChainTipEvent tip_event;          // for ChainTip
  };

  // Try to switch chain tip to pindexNewTip. Handles reorg if needed.
  // Assumes validation_mutex_ is held by caller. Appends events on success only.
  ActivateResult TrySwitchToNewTip(chain::CBlockIndex* pindexNewTip, std::vector<PendingNotification>& events);

  // Validate that a reorg from oldTip to newTip via fork is allowed.
  // Returns SYSTEM_ERROR on fatal conditions (no common ancestor, deep reorg), nullopt if OK.
  std::optional<ActivateResult> ValidateReorg(const chain::CBlockIndex* oldTip,
                                              const chain::CBlockIndex* newTip,
                                              const chain::CBlockIndex* fork);

  // Disconnect blocks from current tip back to fork point.
  // Returns SYSTEM_ERROR on failure, nullopt on success.
  std::optional<ActivateResult> DisconnectToFork(const chain::CBlockIndex* fork);

  // Connect blocks from fork point to newTip, appending BlockConnected events.
  // Returns SYSTEM_ERROR on failure, nullopt on success.
  std::optional<ActivateResult> ConnectFromFork(const chain::CBlockIndex* fork,
                                                chain::CBlockIndex* newTip,
                                                std::vector<PendingNotification>& events);

  // Advance tip to pindexNew; appends BlockConnected event
  bool ConnectTip(chain::CBlockIndex* pindexNew, std::vector<PendingNotification>& events);

  // Revert tip by one block
  bool DisconnectTip();

  // Find candidate with most work (returns nullptr if none valid)
  chain::CBlockIndex* FindMostWorkCandidate();

  // Remove stale candidates (less work than tip, tip itself, failed blocks)
  void PruneCandidates();

  // Check if network has expired; notifies fatal error if so
  bool IsNetworkExpired();

  // Prune stale side-chain headers that can never become active
  void PruneStaleSideChains();

  // Dispatch pending notifications (called after releasing lock)
  void DispatchNotifications(const std::vector<PendingNotification>& events);

  // Process orphan headers waiting for parent (recursive)
  void ProcessOrphanHeaders(const uint256& parentHash);

  // Try to add orphan header (checks DoS limits, evicts old orphans)
  bool TryAddOrphanHeader(const CBlockHeader& header, int peer_id);

  chain::BlockManager block_manager_;
  ActiveTipCandidates active_tip_candidates_;
  const chain::ChainParams& params_;
  int suspicious_reorg_depth_;

  // Orphan header storage (headers with missing parent, auto-processed when
  // parent arrives)
  struct OrphanHeader {
    CBlockHeader header;
    int64_t nTimeReceived;
    int peer_id;
  };

  // DoS Protection: limited size, time-based eviction, per-peer limits
  std::map<uint256, OrphanHeader> m_orphan_headers;
  std::map<int, int> m_peer_orphan_count;  // peer_id -> orphan count
  OrphanMetrics m_orphan_metrics;

  // Failed blocks (prevents reprocessing, marks descendants as BLOCK_FAILED_CHILD)
  std::set<chain::CBlockIndex*> m_failed_blocks;

  // Cached IBD status (latches false once complete, atomic for lock-free reads)
  mutable std::atomic<bool> m_cached_finished_ibd{false};

  // THREAD SAFETY: Recursive mutex serializes all validation operations
  // Protected: block_manager_, active_tip_candidates_, m_failed_blocks, m_orphan_headers
  // Not protected: m_cached_finished_ibd (atomic), params_ (const)
  // All public methods acquire lock, private methods assume lock held
  mutable std::recursive_mutex validation_mutex_;

  // Test-only (regtest): when true, bypass PoW checks in CheckProofOfWork and
  // CheckBlockHeaderWrapper for RPC-driven acceptance. Default false.
  mutable std::atomic<bool> test_skip_pow_checks_{false};
};

}  // namespace validation
}  // namespace unicity
