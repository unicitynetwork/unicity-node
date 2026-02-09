// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

// See timedata.hpp for module documentation.
// TL;DR: This tracks peer time offsets for DIAGNOSTIC WARNINGS only.
// The offset is NOT used for consensus.

#include "chain/timedata.hpp"

#include "network/protocol.hpp"
#include "util/logging.hpp"

#include <ctime>
#include <mutex>
#include <set>

namespace unicity {
namespace chain {

static std::mutex g_timeoffset_mutex;
static int64_t nTimeOffset = 0;  // Diagnostic only - not used for consensus
static constexpr size_t TIMEDATA_MAX_SAMPLES = 200;
static std::set<protocol::NetworkAddress> g_sources;
static CMedianFilter<int64_t> g_time_offsets{TIMEDATA_MAX_SAMPLES, 0};
static bool g_warning_emitted = false;
static size_t g_total_samples = 1;  // Starts at 1 (filter has initial value)

int64_t GetTimeOffset() {
  std::lock_guard<std::mutex> lock(g_timeoffset_mutex);
  return nTimeOffset;
}

void AddTimeData(const protocol::NetworkAddress& ip, int64_t nOffsetSample) {
  std::lock_guard<std::mutex> lock(g_timeoffset_mutex);

  if (g_sources.size() == TIMEDATA_MAX_SAMPLES)
    return;
  if (!g_sources.insert(ip).second)
    return;

  g_time_offsets.input(nOffsetSample);
  g_total_samples++;

  LOG_CHAIN_TRACE("added time data, samples {}, offset {:+d}s", g_time_offsets.size(), nOffsetSample);

  // Update on odd sample counts (deterministic median)
  if (g_total_samples >= 5 && g_total_samples % 2 == 1) {
    int64_t nMedian = g_time_offsets.median();
    if (nMedian >= -DEFAULT_MAX_TIME_ADJUSTMENT && nMedian <= DEFAULT_MAX_TIME_ADJUSTMENT) {
      nTimeOffset = nMedian;
    } else {
      nTimeOffset = 0;
      if (!g_warning_emitted) {
        g_warning_emitted = true;
        LOG_CHAIN_ERROR("Please check that your computer's date and time are correct!");
      }
    }
  }
}

void TestOnlyResetTimeData() {
  std::lock_guard<std::mutex> lock(g_timeoffset_mutex);
  nTimeOffset = 0;
  g_sources.clear();
  g_time_offsets = CMedianFilter<int64_t>{TIMEDATA_MAX_SAMPLES, 0};
  g_warning_emitted = false;
  g_total_samples = 1;
}

}  // namespace chain
}  // namespace unicity
