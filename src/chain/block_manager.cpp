// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "chain/block_manager.hpp"

#include "chain/block.hpp"
#include "util/arith_uint256.hpp"
#include "util/files.hpp"
#include "util/logging.hpp"

#include <algorithm>
#include <cmath>
#include <compare>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <type_traits>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

// DTC1

namespace unicity {
namespace chain {

BlockManager::BlockManager() = default;
BlockManager::~BlockManager() = default;

// Helper: Verify that pindex forms a continuous chain back to genesis
// Returns true if chain is valid, false otherwise
// Used for verification during Initialize and Load
static bool VerifyChainContinuity(const CBlockIndex* pindex, const uint256& expected_genesis_hash,
                                  std::string& error_msg) {
  if (!pindex) {
    error_msg = "null pointer";
    return false;
  }

  const CBlockIndex* walk = pindex;
  int blocks_walked = 0;

  // Walk backwards to genesis
  while (walk->pprev) {
    walk = walk->pprev;
    blocks_walked++;

    // Sanity: prevent infinite loop in case of circular reference bug
    if (blocks_walked > 1000000) {
      error_msg = "chain walk exceeded 1M blocks (circular reference?)";
      return false;
    }
  }

  // Reached a block with no parent - must be genesis
  if (walk->GetBlockHash() != expected_genesis_hash) {
    error_msg = "chain does not descend from expected genesis (found " + walk->GetBlockHash().ToString().substr(0, 16) +
                ", expected " + expected_genesis_hash.ToString().substr(0, 16) + ")";
    return false;
  }

  // Verify height consistency
  if (walk->nHeight != 0) {
    error_msg = "genesis block has non-zero height " + std::to_string(walk->nHeight);
    return false;
  }

  if (pindex->nHeight != blocks_walked) {
    error_msg = "height mismatch: pindex->nHeight=" + std::to_string(pindex->nHeight) + " but walked " +
                std::to_string(blocks_walked) + " blocks";
    return false;
  }

  return true;
}

bool BlockManager::Initialize(const CBlockHeader& genesis) {
  LOG_CHAIN_TRACE("Initialize: called with genesis hash={}", genesis.GetHash().ToString().substr(0, 16));

  if (m_initialized) {
    LOG_CHAIN_ERROR("BlockManager already initialized");
    return false;
  }

  // Add genesis block
  CBlockIndex* pindex = AddToBlockIndex(genesis);
  if (!pindex) {
    LOG_CHAIN_ERROR("Failed to add genesis block");
    return false;
  }

  // Set as active tip
  m_active_chain.SetTip(*pindex);

  // Remember genesis hash
  m_genesis_hash = genesis.GetHash();

  m_initialized = true;

  LOG_CHAIN_TRACE("BlockManager initialized with genesis: {}", m_genesis_hash.ToString().substr(0, 16));

  return true;
}

CBlockIndex* BlockManager::LookupBlockIndex(const uint256& hash) {
  auto it = m_block_index.find(hash);
  if (it == m_block_index.end())
    return nullptr;
  return &it->second;
}

const CBlockIndex* BlockManager::LookupBlockIndex(const uint256& hash) const {
  auto it = m_block_index.find(hash);
  if (it == m_block_index.end())
    return nullptr;
  return &it->second;
}

bool BlockManager::HasChildren(const CBlockIndex* pindex) const {
  if (!pindex) {
    return false;
  }
  return m_children.find(pindex) != m_children.end();
}

size_t BlockManager::PruneStaleSideChains(int max_depth) {
  if (!m_initialized || max_depth <= 0) {
    return 0;
  }

  const CBlockIndex* tip = m_active_chain.Tip();
  if (!tip) {
    return 0;
  }

  int cutoff_height = tip->nHeight - max_depth;
  if (cutoff_height <= 0) {
    return 0;  // Nothing to prune yet
  }

  size_t total_pruned = 0;
  bool found_prunable = true;

  // Iterate until no more prunable headers found
  // (removing a leaf may expose new leaves)
  while (found_prunable) {
    found_prunable = false;
    std::vector<uint256> to_remove;

    for (const auto& [hash, block_index] : m_block_index) {
      // Skip if on active chain
      if (m_active_chain.Contains(&block_index)) {
        continue;
      }

      // Skip if above cutoff height
      if (block_index.nHeight >= cutoff_height) {
        continue;
      }

      // Skip if has children (not a leaf)
      if (HasChildren(&block_index)) {
        continue;
      }

      // This header can be pruned
      to_remove.push_back(hash);
      found_prunable = true;
    }

    // Remove the prunable headers
    for (const uint256& hash : to_remove) {
      auto it = m_block_index.find(hash);
      if (it == m_block_index.end()) {
        continue;
      }

      // Save parent pointer before erasing (pindex becomes invalid after erase)
      const CBlockIndex* pprev = it->second.pprev;

      // Remove from children tracking (this block as child of its parent)
      if (pprev) {
        auto range = m_children.equal_range(pprev);
        for (auto child_it = range.first; child_it != range.second;) {
          if (child_it->second == &it->second) {
            child_it = m_children.erase(child_it);
          } else {
            ++child_it;
          }
        }
      }

      // Remove from block index
      m_block_index.erase(it);
      total_pruned++;
    }
  }

  if (total_pruned > 0) {
    LOG_CHAIN_DEBUG("Pruned {} stale side-chain headers (cutoff height={})", total_pruned, cutoff_height);

    // Rebuild skip pointers - some may have pointed to pruned blocks
    RebuildSkipPointers();
  }

  return total_pruned;
}

CBlockIndex* BlockManager::AddToBlockIndex(const CBlockHeader& header) {
  uint256 hash = header.GetHash();

  LOG_CHAIN_TRACE("AddToBlockIndex: hash={} prev={}", hash.ToString().substr(0, 16),
                  header.hashPrevBlock.ToString().substr(0, 16));

  // Already have it?
  auto it = m_block_index.find(hash);
  if (it != m_block_index.end()) {
    return &it->second;
  }

  // Find parent (nullptr for genesis)
  CBlockIndex* pprev = LookupBlockIndex(header.hashPrevBlock);

  // Reject orphans before inserting - parent must exist unless genesis
  if (!pprev && !header.hashPrevBlock.IsNull()) {
    LOG_CHAIN_ERROR("AddToBlockIndex: orphan header {} (parent {} not found)", hash.ToString().substr(0, 16),
                    header.hashPrevBlock.ToString().substr(0, 16));
    return nullptr;
  }

  // Create new entry
  auto [iter, _] = m_block_index.try_emplace(hash, header);
  CBlockIndex* pindex = &iter->second;
  pindex->m_block_hash = hash;
  pindex->pprev = pprev;

  // Set height and chainwork (immutable after insertion - used for std::set ordering)
  if (pprev) {
    pindex->nHeight = pprev->nHeight + 1;
    pindex->nChainWork = pprev->nChainWork + GetBlockProof(*pindex);
  } else {
    pindex->nHeight = 0;
    pindex->nChainWork = GetBlockProof(*pindex);
  }
  // Build Skip List
  pindex->BuildSkip();

  // Add children
  if (pindex->pprev) {
    m_children.insert({pindex->pprev, pindex});
  }

  return pindex;
}

bool BlockManager::Save(const std::string& filepath) const {
  using json = nlohmann::json;

  try {
    LOG_CHAIN_TRACE("Saving {} headers to {}", m_block_index.size(), filepath);

    json root;
    root["version"] = 1;  // Format version for future compatibility
    root["block_count"] = m_block_index.size();

    // Save tip hash
    if (m_active_chain.Tip()) {
      root["tip_hash"] = m_active_chain.Tip()->GetBlockHash().ToString();
    } else {
      root["tip_hash"] = "";
    }

    // Save genesis hash
    root["genesis_hash"] = m_genesis_hash.ToString();

    // Save all blocks in height order (topological order)
    // This makes the JSON file easier to read and diff for debugging
    std::vector<const CBlockIndex*> sorted_blocks;
    sorted_blocks.reserve(m_block_index.size());
    for (const auto& [hash, block_index] : m_block_index) {
      sorted_blocks.push_back(&block_index);
    }
    std::sort(sorted_blocks.begin(), sorted_blocks.end(),
              [](const CBlockIndex* a, const CBlockIndex* b) { return a->nHeight < b->nHeight; });

    json blocks = json::array();
    for (const CBlockIndex* block_index : sorted_blocks) {
      json block_data;

      // Block hash
      block_data["hash"] = block_index->GetBlockHash().ToString();

      // Header fields
      block_data["version"] = block_index->nVersion;
      block_data["miner_address"] = block_index->minerAddress.ToString();
      block_data["time"] = block_index->nTime;
      block_data["bits"] = block_index->nBits;
      block_data["nonce"] = block_index->nNonce;
      block_data["hash_randomx"] = block_index->hashRandomX.ToString();

      // Chain metadata
      block_data["height"] = block_index->nHeight;
      block_data["chainwork"] = block_index->nChainWork.GetHex();

      // Canonical status representation
      {
        nlohmann::json status_obj;
        status_obj["validation"] = block_index->status.validation;
        status_obj["failure"] = block_index->status.failure;
        block_data["status"] = status_obj;
      }

      // Previous block hash (for reconstruction)
      if (block_index->pprev) {
        block_data["prev_hash"] = block_index->pprev->GetBlockHash().ToString();
      } else {
        block_data["prev_hash"] = uint256().ToString();  // Genesis has null prev
      }

      blocks.push_back(block_data);
    }

    root["blocks"] = blocks;

    // Write atomically using temp file + fsync + rename pattern
    // This prevents data loss if crash occurs during write
    std::string data = root.dump(2);  // Pretty print with 2-space indent
    if (!util::atomic_write_file(std::filesystem::path(filepath), data)) {
      LOG_CHAIN_ERROR("Failed to atomically write headers to {}", filepath);
      return false;
    }

    LOG_CHAIN_TRACE("Successfully saved {} headers (atomic)", m_block_index.size());
    return true;

  } catch (const std::exception& e) {
    LOG_CHAIN_ERROR("Exception during Save: {}", e.what());
    return false;
  }
}

LoadResult BlockManager::Load(const std::string& filepath, const uint256& expected_genesis_hash) {
  using json = nlohmann::json;

  // Check if file exists first (distinguish missing from corrupted)
  if (!std::filesystem::exists(filepath)) {
    LOG_CHAIN_TRACE("Header file not found: {} (starting fresh)", filepath);
    return LoadResult::FILE_NOT_FOUND;
  }

  try {
    LOG_CHAIN_TRACE("Loading headers from {}", filepath);

    // Open file
    std::ifstream file(filepath);
    if (!file.is_open()) {
      LOG_CHAIN_ERROR("Header file exists but cannot be opened: {}", filepath);
      return LoadResult::CORRUPTED;
    }

    // Parse JSON
    json root;
    file >> root;
    file.close();

    // Validate format version
    int version = root.value("version", 0);
    if (version != 1) {
      LOG_CHAIN_ERROR("Unsupported header file version: {} (file: {})", version, filepath);
      return LoadResult::CORRUPTED;
    }

    size_t block_count = root.value("block_count", 0);
    std::string genesis_hash_str = root.value("genesis_hash", "");
    std::string tip_hash_str = root.value("tip_hash", "");

    LOG_CHAIN_TRACE("Loading {} headers, genesis: {}, tip: {}", block_count, genesis_hash_str, tip_hash_str);

    // Validate genesis block hash matches expected network
    uint256 loaded_genesis_hash;
    loaded_genesis_hash.SetHex(genesis_hash_str);
    if (loaded_genesis_hash != expected_genesis_hash) {
      LOG_CHAIN_ERROR("GENESIS MISMATCH: Loaded genesis {} does not match "
                      "expected genesis {}",
                      genesis_hash_str.substr(0, 16), expected_genesis_hash.ToString().substr(0, 16));
      LOG_CHAIN_ERROR("This datadir contains headers from a different network!");
      LOG_CHAIN_ERROR("Please delete the headers file or use a different datadir.");
      return LoadResult::CORRUPTED;
    }

    LOG_CHAIN_TRACE("Genesis block validation passed: {}", genesis_hash_str);

    // Clear existing state
    m_block_index.clear();
    m_children.clear();
    m_active_chain.Clear();

    // Validate blocks field exists and is an array
    if (!root.contains("blocks")) {
      LOG_CHAIN_ERROR("Header file missing 'blocks' field");
      return LoadResult::CORRUPTED;
    }
    if (!root["blocks"].is_array()) {
      LOG_CHAIN_ERROR("'blocks' field is not an array");
      return LoadResult::CORRUPTED;
    }

    const json& blocks = root["blocks"];

    // Verify block_count matches actual array size (detect corruption/truncation)
    if (blocks.size() != block_count) {
      LOG_CHAIN_WARN("Block count mismatch: header says {}, array has {}. "
                     "File may be corrupted or truncated. Using actual array size.",
                     block_count, blocks.size());
      block_count = blocks.size();
    }

    // First pass: Create all CBlockIndex objects (without connecting pprev)
    std::map<uint256, std::pair<CBlockIndex*, uint256>>
        block_map;  // hash -> (pindex, prev_hash), expected size: blocks.size()

    for (const auto& block_data : blocks) {
      // Validate required fields are present (canonical set)
      static const std::vector<std::string> required_fields_core = {"hash",   "prev_hash", "version", "miner_address",
                                                                    "time",   "bits",      "nonce",   "hash_randomx",
                                                                    "height", "chainwork", "status"};
      for (const auto& field : required_fields_core) {
        if (!block_data.contains(field)) {
          LOG_CHAIN_ERROR("Block entry missing required field '{}'. File corrupted.", field);
          return LoadResult::CORRUPTED;
        }
      }
      // Validate status object
      if (!block_data["status"].is_object() || !block_data["status"].contains("validation") ||
          !block_data["status"].contains("failure")) {
        LOG_CHAIN_ERROR("Block entry 'status' missing 'validation' or 'failure' fields.");
        return LoadResult::CORRUPTED;
      }

      // Parse block data
      uint256 hash;
      hash.SetHex(block_data["hash"].get<std::string>());

      uint256 prev_hash;
      prev_hash.SetHex(block_data["prev_hash"].get<std::string>());

      // Create header
      CBlockHeader header;
      header.nVersion = block_data["version"].get<int32_t>();
      header.minerAddress.SetHex(block_data["miner_address"].get<std::string>());
      header.nTime = block_data["time"].get<uint32_t>();
      header.nBits = block_data["bits"].get<uint32_t>();
      header.nNonce = block_data["nonce"].get<uint32_t>();
      header.hashRandomX.SetHex(block_data["hash_randomx"].get<std::string>());
      header.hashPrevBlock = prev_hash;

      // Verify reconstructed header hash matches stored hash
      // This detects corruption, tampering, or missing fields in the JSON
      uint256 recomputed_hash = header.GetHash();
      if (recomputed_hash != hash) {
        LOG_CHAIN_ERROR("CORRUPTION DETECTED: Stored hash {} does not match "
                        "recomputed hash {} for block at height {}. "
                        "The header file may be corrupted or tampered. "
                        "Please delete {} and resync.",
                        hash.ToString().substr(0, 16), recomputed_hash.ToString().substr(0, 16),
                        block_data.value("height", -1), filepath);
        return LoadResult::CORRUPTED;
      }

      // Add to block index 
      auto [iter, inserted] = m_block_index.try_emplace(hash, header);
      if (!inserted) {
        LOG_CHAIN_ERROR("Duplicate block in header file: {}", hash.ToString().substr(0, 16));
        return LoadResult::CORRUPTED;
      }

      // Restore status from canonical composite object
      const auto& st = block_data["status"];
      iter->second.status.validation = static_cast<BlockStatus::ValidationLevel>(st["validation"].get<int>());
      iter->second.status.failure = static_cast<BlockStatus::FailureState>(st["failure"].get<int>());

      CBlockIndex* pindex = &iter->second;
      pindex->m_block_hash = hash;

      // Restore metadata
      pindex->nHeight = block_data["height"].get<int>();
      pindex->nChainWork.SetHex(block_data["chainwork"].get<std::string>());

      // Store for second pass
      block_map[hash] = {pindex, prev_hash};
    }

    // Second pass: Connect pprev pointers
    for (auto& [hash, data] : block_map) {
      CBlockIndex* pindex = data.first;
      const uint256& prev_hash = data.second;

      if (!prev_hash.IsNull()) {
        pindex->pprev = LookupBlockIndex(prev_hash);
        if (!pindex->pprev) {
          LOG_CHAIN_ERROR("Parent block not found for {}: {}", hash.ToString().substr(0, 16),
                          prev_hash.ToString().substr(0, 16));
          return LoadResult::CORRUPTED;
        }
      } else {
        pindex->pprev = nullptr;  // Genesis
      }
    }

    // Validate genesis uniqueness: exactly one block with pprev == nullptr
    CBlockIndex* found_genesis = nullptr;
    int genesis_count = 0;
    for (auto& kv : m_block_index) {
      CBlockIndex* pindex = &kv.second;
      if (pindex->pprev == nullptr) {
        genesis_count++;
        found_genesis = pindex;
      }
    }

    if (genesis_count == 0) {
      LOG_CHAIN_ERROR("No genesis block found (no block with pprev == nullptr)");
      return LoadResult::CORRUPTED;
    }
    if (genesis_count > 1) {
      LOG_CHAIN_ERROR("Multiple genesis blocks found ({} blocks with pprev == nullptr). "
                      "File corrupted - should have exactly one genesis.",
                      genesis_count);
      return LoadResult::CORRUPTED;
    }

    // Verify the genesis block hash matches expected
    if (found_genesis->GetBlockHash() != expected_genesis_hash) {
      LOG_CHAIN_ERROR("Genesis block hash mismatch: found {} but expected {}",
                      found_genesis->GetBlockHash().ToString().substr(0, 16),
                      expected_genesis_hash.ToString().substr(0, 16));
      return LoadResult::CORRUPTED;
    }

    // Third pass: Validate heights and build skip pointers in height order
    std::vector<CBlockIndex*> by_height;
    by_height.reserve(m_block_index.size());
    for (auto& kv : m_block_index) {
      by_height.push_back(&kv.second);
    }
    std::sort(by_height.begin(), by_height.end(),
              [](const CBlockIndex* a, const CBlockIndex* b) { return a->nHeight < b->nHeight; });
    for (CBlockIndex* pindex : by_height) {
      // Height must be non-negative
      if (pindex->nHeight < 0) {
        LOG_CHAIN_ERROR("INVARIANT VIOLATION: Block {} has negative height {}",
                        pindex->GetBlockHash().ToString().substr(0, 16), pindex->nHeight);
        return LoadResult::CORRUPTED;
      }

      if (pindex->pprev) {
        // Defensive: Verify parent-child height invariant (exactly +1)
        // Because we're iterating in height order, parent must have lower height and be exactly one less
        if (pindex->pprev->nHeight + 1 != pindex->nHeight) {
          LOG_CHAIN_ERROR("INVARIANT VIOLATION: Block {} (height {}) has parent {} (height {}). "
                          "Expected parent height to be child-1.",
                          pindex->GetBlockHash().ToString().substr(0, 16), pindex->nHeight,
                          pindex->pprev->GetBlockHash().ToString().substr(0, 16), pindex->pprev->nHeight);
          return LoadResult::CORRUPTED;
        }
      } else {
        // Genesis must have height 0
        if (pindex->nHeight != 0) {
          LOG_CHAIN_ERROR("INVARIANT VIOLATION: Genesis block {} has non-zero height {}",
                          pindex->GetBlockHash().ToString().substr(0, 16), pindex->nHeight);
          return LoadResult::CORRUPTED;
        }
      }

      // Rebuild parent->child tracking for O(1) HasChildren lookup
      if (pindex->pprev) {
        m_children.insert({pindex->pprev, pindex});
      }
    }

    // Rebuild skip pointers for O(log n) ancestor lookup
    RebuildSkipPointers();

    // Restore genesis hash
    m_genesis_hash.SetHex(genesis_hash_str);

    // Use saved tip as initial tip (chainwork will be recomputed by ChainstateManager)
    CBlockIndex* initial_tip = nullptr;

    if (!tip_hash_str.empty()) {
      uint256 saved_tip_hash;
      saved_tip_hash.SetHex(tip_hash_str);
      initial_tip = LookupBlockIndex(saved_tip_hash);

      if (!initial_tip) {
        LOG_CHAIN_ERROR("Saved tip {} not found in loaded headers! Data may be corrupted.", tip_hash_str.substr(0, 16));
        return LoadResult::CORRUPTED;
      }

      if (initial_tip->status.IsFailed()) {
        LOG_CHAIN_ERROR(
            "Saved tip {} is marked as failed! Data may be corrupted or you need to resync after invalidateblock.",
            tip_hash_str.substr(0, 16));
        return LoadResult::CORRUPTED;
      }
    } else {
      LOG_CHAIN_ERROR("No saved tip found in headers file!");
      return LoadResult::CORRUPTED;
    }

    m_active_chain.SetTip(*initial_tip);
    LOG_CHAIN_TRACE("Set active chain to saved tip: height={} hash={}", initial_tip->nHeight,
                    initial_tip->GetBlockHash().ToString().substr(0, 16));

    // Verify chain continuity from initial_tip to genesis
    std::string error_msg;
    if (!VerifyChainContinuity(initial_tip, m_genesis_hash, error_msg)) {
      LOG_CHAIN_ERROR("Chain continuity verification failed during Load: {}", error_msg);
      LOG_CHAIN_ERROR("Initial tip does not form valid chain to genesis!");
      return LoadResult::CORRUPTED;
    }

    m_initialized = true;
    LOG_CHAIN_TRACE("Successfully loaded {} headers", m_block_index.size());
    return LoadResult::SUCCESS;

  } catch (const std::exception& e) {
    LOG_CHAIN_ERROR("Exception during Load: {}", e.what());
    m_block_index.clear();
    m_active_chain.Clear();
    m_initialized = false;
    return LoadResult::CORRUPTED;
  }
}

void BlockManager::RebuildSkipPointers() {
  // Collect all blocks and sort by height (parents before children)
  std::vector<CBlockIndex*> by_height;
  by_height.reserve(m_block_index.size());
  for (auto& [hash, block] : m_block_index) {
    by_height.push_back(&block);
  }
  std::sort(by_height.begin(), by_height.end(),
            [](const CBlockIndex* a, const CBlockIndex* b) { return a->nHeight < b->nHeight; });

  // Rebuild skip pointers in height order (ancestors must be processed first)
  for (CBlockIndex* pindex : by_height) {
    pindex->BuildSkip();
  }
}

}  // namespace chain
}  // namespace unicity
