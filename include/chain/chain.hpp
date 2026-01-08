// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include "chain/block.hpp"
#include "chain/block_index.hpp"

#include <vector>

namespace unicity {
namespace chain {

// CChain - In-memory indexed chain of blocks
// Represents single linear chain as vector of CBlockIndex pointers
// Used for active chain (best known) and tracking competing forks
// Fast O(1) access by height, does NOT own CBlockIndex objects

class CChain {
private:
  std::vector<CBlockIndex*> vChain;

public:
  CChain() = default;

  // Prevent copying (chains should be owned, not copied)
  CChain(const CChain&) = delete;
  CChain& operator=(const CChain&) = delete;

  CBlockIndex* Genesis() const { return vChain.size() > 0 ? vChain[0] : nullptr; }

  CBlockIndex* Tip() const { return vChain.size() > 0 ? vChain[vChain.size() - 1] : nullptr; }

  CBlockIndex* operator[](int nHeight) const {
    if (nHeight < 0 || nHeight >= (int)vChain.size())
      return nullptr;
    return vChain[nHeight];
  }

  // Check whether block is present in this chain
  bool Contains(const CBlockIndex* pindex) const {
    if (!pindex)
      return false;
    if (pindex->nHeight < 0 || pindex->nHeight >= (int)vChain.size()) {
      return false;
    }
    return vChain[pindex->nHeight] == pindex;
  }

  // Find successor of block in this chain (nullptr if not found or is tip)
  CBlockIndex* Next(const CBlockIndex* pindex) const {
    if (Contains(pindex))
      return (*this)[pindex->nHeight + 1];
    else
      return nullptr;
  }

  // Return maximal height in chain (equal to chain.Tip() ? chain.Tip()->nHeight: -1)
  int Height() const { return int(vChain.size()) - 1; }

  // Set/initialize chain with given tip (walks backwards using pprev to
  // populate entire vector)
  void SetTip(CBlockIndex& block);

  void Clear() { vChain.clear(); }

  // Return CBlockLocator that refers to tip of this chain (used for GETHEADERS messages)
  CBlockLocator GetLocator() const;

  // Find last common block between this chain and block index entry (fork point)
  const CBlockIndex* FindFork(const CBlockIndex* pindex) const;
};

// Get locator for block index entry (returns exponentially spaced hashes for
// efficient sync)
CBlockLocator GetLocator(const CBlockIndex* index);

// Construct list of hash entries for locator (step=1 for first 10, then doubles)
// Example for height 1000: [1000..991 (step=1), 990, 988, 984, 976, 960, 928, 864, 736, 480, 0]
std::vector<uint256> LocatorEntries(const CBlockIndex* index);

}  // namespace chain
}  // namespace unicity
