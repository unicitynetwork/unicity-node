// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license
// Rate limiter for logging to prevent disk exhaustion attacks

#pragma once

#include "util/time.hpp"

#include <chrono>
#include <mutex>
#include <string>
#include <unordered_map>

namespace unicity {
namespace util {

/**
 * RateLimiter - Token bucket rate limiter for logging
 *
 * Prevents disk exhaustion attacks by limiting log messages per callsite.
 * Uses token bucket algorithm: each callsite gets N tokens that refill over time.
 *
 * Security: Defends against malicious peers triggering excessive logging
 *
 * Example attack without rate limiting:
 * - Attacker sends 1000 malformed messages/sec
 * - Each triggers LOG_NET_ERROR
 * - 150 bytes/log × 1000/sec = 150 KB/sec = 9 MB/min
 * - Disk fills in minutes, node crashes
 *
 * With rate limiting (10 tokens, 60s period):
 * - First 10 errors logged (burst capacity)
 * - Sustained rate: 10 tokens / 60 sec = ~10 messages/min
 * - Disk usage reduced from 9 MB/min to ~1.5 KB/min
 */
class RateLimiter {
public:
  // Check if a log message should be allowed. Returns true if message should be logged,
  // false if rate-limited. callsite_key is unique identifier for log callsite (file:line),
  // tokens_per_period is number of messages allowed per period, period_seconds is time
  // period for token refill.
  bool should_log(const std::string& callsite_key, int tokens_per_period, int period_seconds);

  // Get singleton instance.
  static RateLimiter& instance();

private:
  struct TokenBucket {
    double tokens;
    std::chrono::steady_clock::time_point last_refill;
    bool initialized;

    TokenBucket() : tokens(0.0), last_refill(GetSteadyTime()), initialized(false) {}
  };

  std::mutex mutex_;
  std::unordered_map<std::string, TokenBucket> buckets_;
};

}  // namespace util
}  // namespace unicity
