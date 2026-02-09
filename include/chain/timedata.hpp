// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

// =============================================================================
// Time Data Module - Peer Clock Skew Detection (Diagnostic Only)
// =============================================================================
//
// PURPOSE: Detects if the local system clock is significantly different from
// network peers. Used ONLY for user warnings, NOT for consensus.
//
// BACKGROUND: Bitcoin historically used "network-adjusted time" where the node
// would adjust its clock based on peer reports. This was removed in Bitcoin
// Core 27.0 (PR #28956) because it created an attack surface - malicious peers
// could manipulate a node's perception of time.
//
// CURRENT BEHAVIOR:
// - AddTimeData() collects time offsets from outbound peers during handshake
// - GetTimeOffset() returns the median offset (for diagnostics only)
// - Consensus uses raw system time (util::GetTime()), not the peer offset
// - RPC getnetworkinfo uses GetTimeOffset() to warn users about clock skew
//
// This module is NOT dead code - it provides useful clock skew warnings without
// affecting consensus. If peers consistently report your clock is wrong, you
// should check your NTP configuration.
// =============================================================================

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <vector>

namespace unicity {

namespace protocol {
struct NetworkAddress;
}

namespace chain {

// Maximum time offset before warning (±1 minute). For warnings only, not consensus.
static constexpr int64_t DEFAULT_MAX_TIME_ADJUSTMENT = 60;

// Sliding window median filter (returns median of last N values)
template <typename T>
class CMedianFilter {
private:
  std::vector<T> vValues;
  std::vector<T> vSorted;
  unsigned int nSize;

public:
  CMedianFilter(unsigned int _size, T initial_value) : nSize(_size) {
    vValues.reserve(_size);
    vValues.push_back(initial_value);
    vSorted = vValues;
  }

  void input(T value) {
    if (vValues.size() == nSize) {
      vValues.erase(vValues.begin());
    }
    vValues.push_back(value);

    vSorted.resize(vValues.size());
    std::copy(vValues.begin(), vValues.end(), vSorted.begin());
    std::sort(vSorted.begin(), vSorted.end());
  }

  T median() const {
    size_t vSortedSize = vSorted.size();
    assert(vSortedSize > 0);
    if (vSortedSize & 1)  // Odd number of elements
    {
      return vSorted[vSortedSize / 2];
    } else {
      // Overflow-safe average: a/2 + b/2 + (a%2 + b%2)/2
      T a = vSorted[vSortedSize / 2 - 1];
      T b = vSorted[vSortedSize / 2];
      return a / 2 + b / 2 + (a % 2 + b % 2) / 2;
    }
  }

  size_t size() const { return vValues.size(); }
};

int64_t GetTimeOffset();
void AddTimeData(const protocol::NetworkAddress& ip, int64_t nOffsetSample);
void TestOnlyResetTimeData();

}  // namespace chain
}  // namespace unicity
