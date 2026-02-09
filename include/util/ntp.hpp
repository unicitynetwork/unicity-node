// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace unicity {
namespace util {

// Check system clock against an NTP server via a single SNTP query.
// Returns the offset in seconds (ntp_time - system_time), or nullopt
// if the server is unreachable or the response is invalid.
// Blocks for up to timeout_sec. Uses a temporary io_context internally.
std::optional<int64_t> CheckNTPOffset(const std::string& server = "pool.ntp.org",
                                       int timeout_sec = 3);

}  // namespace util
}  // namespace unicity
