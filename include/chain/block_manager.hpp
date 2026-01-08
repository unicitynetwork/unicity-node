// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include "chain/block_index.hpp"
#include "chain/chain.hpp"
#include "util/uint.hpp"

#include <map>
#include <string>

#include <stddef.h>

// Forward declaration
class CBlockHeader;

namespace unicity {
namespace chain {

// Result of loading headers from disk
enum class LoadResult {
  SUCCESS,         // Loaded successfully
  FILE_NOT_FOUND,  // File doesn't exist (OK to start fresh)
  CORRUPTED        // File exists but is corrupted/invalid (FATAL - requires manual intervention)
};

// BlockManager - Manages all known block headers and the active chain
// Simplified from Bitcoin Core for headers-only chain
//
// THREAD SAFETY: NO internal synchronization - caller MUST serialize all access
// BlockManager is a PRIVATE member of ChainstateManager
// ChainstateManager::validation_mutex_ protects ALL BlockManager methods
// ALL public methods (Initialize, AddToBlockIndex, LookupBlockIndex, Save, Load, etc.)
// MUST be called while holding ChainstateManager::validation_mutex_
// m_block_index, m_active_chain, and m_initialized are NOT thread-safe
// Concurrent access without external locking will cause data races and undefined behavior

class BlockManager {
public:
  BlockManager();
  ~BlockManager();

  bool Initialize(const CBlockHeader& genesis);

  // Look up block by hash (returns nullptr if not found)
  CBlockIndex* LookupBlockIndex(const uint256& hash);
  const CBlockIndex* LookupBlockIndex(const uint256& hash) const;

  // Add new block header to index (returns pointer to CBlockIndex, existing or
  // new) Creates CBlockIndex, sets parent pointer, calculates height and chain
  // work
  CBlockIndex* AddToBlockIndex(const CBlockHeader& header);

  CChain& ActiveChain() { return m_active_chain; }
  const CChain& ActiveChain() const { return m_active_chain; }

  CBlockIndex* GetTip() { return m_active_chain.Tip(); }
  const CBlockIndex* GetTip() const { return m_active_chain.Tip(); }

  // Set new tip for active chain (populates entire vChain vector by walking backwards)
  void SetActiveTip(CBlockIndex& block) { m_active_chain.SetTip(block); }

  size_t GetBlockCount() const { return m_block_index.size(); }

  // Read-only access to block index (for iteration, checking children, etc.)
  const std::map<uint256, CBlockIndex>& GetBlockIndex() const { return m_block_index; }

  // Mutable access to block index (for internal mutation: chainwork, status, skip pointers)
  // Only ChainstateManager should use this - external code should use const version
  std::map<uint256, CBlockIndex>& GetMutableBlockIndex() { return m_block_index; }

  // O(1) check if a block has any children
  bool HasChildren(const CBlockIndex* pindex) const;

  // Prune stale side-chain headers that can never become active.
  // Removes headers that are:
  //   - NOT on the active chain
  //   - At height < (tip_height - max_depth)
  //   - Have no children (are leaf nodes)
  // Returns number of headers pruned.
  size_t PruneStaleSideChains(int max_depth);

  bool Save(const std::string& filepath) const;

  // Load headers from disk (reconstructs block index and active chain)
  // Returns:
  //   SUCCESS - loaded successfully
  //   FILE_NOT_FOUND - file doesn't exist (OK to initialize fresh chain)
  //   CORRUPTED - file exists but is invalid (FATAL - abort startup)
  LoadResult Load(const std::string& filepath, const uint256& expected_genesis_hash);

  // Rebuild all skip pointers in height order.
  // Must be called after any operation that invalidates skip pointers (e.g., pruning).
  // Iterates all blocks, sorts by height, and calls BuildSkip() on each.
  void RebuildSkipPointers();

private:
  // Map of all known blocks: hash -> CBlockIndex (map owns CBlockIndex objects)
  std::map<uint256, CBlockIndex> m_block_index;

  // Track parent->children relationships for O(1) HasChildren lookup
  // Multi-map allows multiple children per parent (fork branches)
  // Maintained by AddToBlockIndex() when adding new blocks
  std::multimap<const CBlockIndex*, const CBlockIndex*> m_children;

  // Active (best) chain (points to CBlockIndex objects owned by m_block_index)
  CChain m_active_chain;

  uint256 m_genesis_hash;  // Genesis block hash (for validation)
  bool m_initialized{false};
};

}  // namespace chain
}  // namespace unicity
