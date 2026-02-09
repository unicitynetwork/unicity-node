// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include <memory>
#include <string>

#include <spdlog/spdlog.h>

namespace unicity {
namespace util {

/**
 * Logging utility wrapper around spdlog
 *
 * Provides centralized logging configuration and easy access
 * to loggers throughout the application.
 *
 * Thread-safety: All methods are thread-safe. Initialization is
 * performed exactly once using std::call_once. Logger access is
 * protected by mutex for safe concurrent use.
 */
class LogManager {
public:
  // Initialize logging system with the specified minimum log level.
  // Thread-safe: Uses std::call_once internally. Multiple calls are safe;
  // only the first call performs initialization.
  static void Initialize(const std::string& log_level = "off", bool log_to_file = false,
                         const std::string& log_file_path = "debug.log");

  // Shutdown logging system (flushes buffers).
  // Thread-safe: Protected by mutex. Safe to call from any thread.
  // Subsequent logging calls after shutdown will auto-reinitialize.
  static void Shutdown();

  // Get logger for specific component (e.g., "network", "sync", "chain").
  // Thread-safe: Protected by mutex. Auto-initializes if not initialized.
  // Returns cached logger for performance.
  static std::shared_ptr<spdlog::logger> GetLogger(const std::string& name = "default");

  // Set log level at runtime (all components).
  // Thread-safe: Protected by mutex.
  static void SetLogLevel(const std::string& level);

  // Set log level for a specific component (network, sync, chain, crypto, app, default).
  // Thread-safe: Protected by mutex.
  static void SetComponentLevel(const std::string& component, const std::string& level);

private:
  // No bool flag - using std::call_once for thread-safe initialization
};

}  // namespace util
}  // namespace unicity

// Convenience macros for logging
#define LOG_TRACE(...) unicity::util::LogManager::GetLogger()->trace(__VA_ARGS__)
#define LOG_DEBUG(...) unicity::util::LogManager::GetLogger()->debug(__VA_ARGS__)
#define LOG_INFO(...) unicity::util::LogManager::GetLogger()->info(__VA_ARGS__)
#define LOG_WARN(...) unicity::util::LogManager::GetLogger()->warn(__VA_ARGS__)
#define LOG_ERROR(...) unicity::util::LogManager::GetLogger()->error(__VA_ARGS__)

// Component-specific logging
#define LOG_NET_TRACE(...) unicity::util::LogManager::GetLogger("network")->trace(__VA_ARGS__)
#define LOG_NET_DEBUG(...) unicity::util::LogManager::GetLogger("network")->debug(__VA_ARGS__)
#define LOG_NET_INFO(...) unicity::util::LogManager::GetLogger("network")->info(__VA_ARGS__)
#define LOG_NET_WARN(...) unicity::util::LogManager::GetLogger("network")->warn(__VA_ARGS__)
#define LOG_NET_ERROR(...) unicity::util::LogManager::GetLogger("network")->error(__VA_ARGS__)

#define LOG_CHAIN_TRACE(...) unicity::util::LogManager::GetLogger("chain")->trace(__VA_ARGS__)
#define LOG_CHAIN_DEBUG(...) unicity::util::LogManager::GetLogger("chain")->debug(__VA_ARGS__)
#define LOG_CHAIN_INFO(...) unicity::util::LogManager::GetLogger("chain")->info(__VA_ARGS__)
#define LOG_CHAIN_WARN(...) unicity::util::LogManager::GetLogger("chain")->warn(__VA_ARGS__)
#define LOG_CHAIN_ERROR(...) unicity::util::LogManager::GetLogger("chain")->error(__VA_ARGS__)

#define LOG_CRYPTO_DEBUG(...) unicity::util::LogManager::GetLogger("crypto")->debug(__VA_ARGS__)
#define LOG_CRYPTO_INFO(...) unicity::util::LogManager::GetLogger("crypto")->info(__VA_ARGS__)

// ============================================================================
// RATE-LIMITED LOGGING MACROS
// ============================================================================
// Prevents disk exhaustion attacks by limiting log frequency per callsite
// Use these for messages triggered by untrusted input (peer messages, blocks)
//
// Attack scenario without rate limiting:
// - Malicious peer sends 1000 invalid messages/sec
// - Each triggers LOG_NET_ERROR → 1000 log lines/sec
// - 150 bytes/line × 1000/sec = 150 KB/sec = 9 MB/min
// - Disk fills in minutes, node crashes
//
// With rate limiting (200/hour per callsite):
// - First 200 errors logged (burst capacity)
// - Then rate-limited until hour window refills
//
// Rate limits (token bucket):
// - 200 messages per hour per callsite (~30KB at 150 bytes/msg)
//
// When to use:
// - ✓ Peer protocol errors (malformed messages, invalid headers)
// - ✓ Connection failures (can be spammed)
// - ✓ Validation errors from untrusted data
// - ✗ Startup/shutdown messages (always important)
// - ✗ Fatal errors (should always be logged)

#include "util/rate_limiter.hpp"

// Helper macro to generate callsite key from file:line
#define CALLSITE_KEY_ (std::string(__FILE__) + ":" + std::to_string(__LINE__))

// Rate-limited ERROR macros (200/hour per callsite)
#define LOG_ERROR_RL(...)                                                                                              \
  do {                                                                                                                 \
    if (unicity::util::RateLimiter::instance().should_log(CALLSITE_KEY_, 200, 3600)) {                                 \
      unicity::util::LogManager::GetLogger()->error(__VA_ARGS__);                                                      \
    }                                                                                                                  \
  } while (0)

#define LOG_NET_ERROR_RL(...)                                                                                          \
  do {                                                                                                                 \
    if (unicity::util::RateLimiter::instance().should_log(CALLSITE_KEY_, 200, 3600)) {                                 \
      unicity::util::LogManager::GetLogger("network")->error(__VA_ARGS__);                                             \
    }                                                                                                                  \
  } while (0)

#define LOG_CHAIN_ERROR_RL(...)                                                                                        \
  do {                                                                                                                 \
    if (unicity::util::RateLimiter::instance().should_log(CALLSITE_KEY_, 200, 3600)) {                                 \
      unicity::util::LogManager::GetLogger("chain")->error(__VA_ARGS__);                                               \
    }                                                                                                                  \
  } while (0)

// Rate-limited WARN macros (200/hour per callsite)
#define LOG_WARN_RL(...)                                                                                               \
  do {                                                                                                                 \
    if (unicity::util::RateLimiter::instance().should_log(CALLSITE_KEY_, 200, 3600)) {                                 \
      unicity::util::LogManager::GetLogger()->warn(__VA_ARGS__);                                                       \
    }                                                                                                                  \
  } while (0)

#define LOG_NET_WARN_RL(...)                                                                                           \
  do {                                                                                                                 \
    if (unicity::util::RateLimiter::instance().should_log(CALLSITE_KEY_, 200, 3600)) {                                 \
      unicity::util::LogManager::GetLogger("network")->warn(__VA_ARGS__);                                              \
    }                                                                                                                  \
  } while (0)

#define LOG_CHAIN_WARN_RL(...)                                                                                         \
  do {                                                                                                                 \
    if (unicity::util::RateLimiter::instance().should_log(CALLSITE_KEY_, 200, 3600)) {                                 \
      unicity::util::LogManager::GetLogger("chain")->warn(__VA_ARGS__);                                                \
    }                                                                                                                  \
  } while (0)
