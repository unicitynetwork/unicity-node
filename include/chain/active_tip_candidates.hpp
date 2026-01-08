// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include "util/uint.hpp"

#include <set>
#include <vector>

namespace unicity {
namespace validation {

// ActiveTipCandidates - A simple set of candidate block hashes for potential active chain tips.
class ActiveTipCandidates {
public:
  void Add(const uint256& hash) { m_candidates.insert(hash); }
  void Remove(const uint256& hash) { m_candidates.erase(hash); }
  void Clear() { m_candidates.clear(); }

  size_t Size() const { return m_candidates.size(); }
  bool Contains(const uint256& hash) const { return m_candidates.count(hash) > 0; }
  const std::set<uint256>& All() const { return m_candidates; }

private:
  std::set<uint256> m_candidates;
};

}  // namespace validation
}  // namespace unicity
