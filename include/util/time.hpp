// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>

namespace unicity {
namespace util {

/**
 * Mockable time system for testing
 * Usage:
 * - Production code calls GetTime() or GetSteadyTime() instead of direct systemcalls
 * - Tests call SetMockTime() to control the current time
 * - When mock time is set, all time functions return the mocked value
 * - When mock time is 0 (default), time functions return real system time
 */

// Get current time as Unix timestamp (seconds since epoch).
// Returns mock time if set, otherwise returns real system time.
int64_t GetTime();

// Get current time as steady clock time point.
// Returns mock time if set, otherwise returns real steady clock time.
// Note: When mock time is active, steady clock is simulated using the mock value.
std::chrono::steady_clock::time_point GetSteadyTime();

// Set mock time for testing (Unix timestamp in seconds, 0 to disable mocking).
// When mock time is set to a non-zero value:
// - All GetTime*() functions return values based on the mock time
// - Time does not advance automatically - tests must call SetMockTime() again
// Set to 0 to return to real system time.
void SetMockTime(int64_t time);

// Get current mock time setting. Returns 0 if mock time is disabled (using real time).
int64_t GetMockTime();

// Format a Unix timestamp as a human-readable ISO 8601 UTC string.
// unix_time is 64-bit to avoid Y2038/Y2106. Returns formatted string like "2025-10-25 14:33:09 UTC".
// Example: FormatTime(1729868000) -> "2024-10-25 12:00:00 UTC"
std::string FormatTime(int64_t unix_time);

// RAII helper to set mock time and restore it when scope exits.
// Useful for tests that need to temporarily set mock time.
class MockTimeScope {
public:
  explicit MockTimeScope(int64_t time) : previous_time_(GetMockTime()) { SetMockTime(time); }

  ~MockTimeScope() { SetMockTime(previous_time_); }

  // Delete copy/move to prevent misuse
  MockTimeScope(const MockTimeScope&) = delete;
  MockTimeScope& operator=(const MockTimeScope&) = delete;
  MockTimeScope(MockTimeScope&&) = delete;
  MockTimeScope& operator=(MockTimeScope&&) = delete;

private:
  const int64_t previous_time_;
};

}  // namespace util
}  // namespace unicity
