// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license
// Rate limiter implementation

#include "util/rate_limiter.hpp"

#include <algorithm>

namespace unicity {
namespace util {

bool RateLimiter::should_log(const std::string& callsite_key, int tokens_per_period, int period_seconds) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto now = GetSteadyTime();
  auto& bucket = buckets_[callsite_key];

  // Initialize bucket on first access with full capacity (burst)
  if (!bucket.initialized) {
    bucket.tokens = static_cast<double>(tokens_per_period);
    bucket.last_refill = now;
    bucket.initialized = true;
  }

  // Calculate time elapsed since last refill
  auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - bucket.last_refill).count();

  // Refill tokens based on elapsed time
  if (elapsed > 0) {
    double refill_rate = static_cast<double>(tokens_per_period) / period_seconds;
    bucket.tokens = std::min(bucket.tokens + (refill_rate * elapsed), static_cast<double>(tokens_per_period));
    bucket.last_refill = now;
  }

  // Check if we have tokens available
  if (bucket.tokens >= 1.0) {
    bucket.tokens -= 1.0;
    return true;  // Allow log
  }

  return false;  // Rate-limited
}

RateLimiter& RateLimiter::instance() {
  static RateLimiter instance;
  return instance;
}

}  // namespace util
}  // namespace unicity
