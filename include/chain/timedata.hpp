// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

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
    int vSortedSize = vSorted.size();
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

  int size() const { return vValues.size(); }

  const std::vector<T>& sorted() const { return vSorted; }
};

int64_t GetTimeOffset();
void AddTimeData(const protocol::NetworkAddress& ip, int64_t nOffsetSample);
void TestOnlyResetTimeData();

}  // namespace chain
}  // namespace unicity
