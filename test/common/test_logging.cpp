// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license
// Test logging initialization helpers

#include "util/logging.hpp"
#include <cstdio>
#include <string>

// Initialize logging for tests (console only, no file)
void InitializeTestLogging(const std::string& level) {
    // Initialize logging system with specified level
    unicity::util::LogManager::Initialize(level, false, "");

    // If level is "trace", also enable TRACE for all components
    // This ensures LOG_CHAIN_TRACE, LOG_NET_TRACE, etc. all work
    if (level == "trace") {
        unicity::util::LogManager::SetComponentLevel("chain", "trace");
        unicity::util::LogManager::SetComponentLevel("network", "trace");
        unicity::util::LogManager::SetComponentLevel("sync", "trace");
        unicity::util::LogManager::SetComponentLevel("crypto", "trace");
        unicity::util::LogManager::SetComponentLevel("app", "trace");
    }
}

// Shutdown logging system after tests complete
void ShutdownTestLogging() {
    unicity::util::LogManager::Shutdown();
}
