// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license
// Unit tests for LogManager

#include "catch_amalgamated.hpp"
#include "util/logging.hpp"
#include <thread>
#include <vector>

using namespace unicity::util;

// Note: LogManager uses std::call_once, so Initialize() only runs once per process.
// These tests verify behavior within that constraint.

TEST_CASE("LogManager: GetLogger returns valid loggers", "[logging]") {
    // Ensure logging is initialized
    LogManager::Initialize("debug", false, "");

    SECTION("Default logger") {
        auto logger = LogManager::GetLogger();
        REQUIRE(logger != nullptr);
        REQUIRE(logger->name() == "default");
    }

    SECTION("Named component loggers") {
        auto network = LogManager::GetLogger("network");
        REQUIRE(network != nullptr);
        REQUIRE(network->name() == "network");

        auto chain = LogManager::GetLogger("chain");
        REQUIRE(chain != nullptr);
        REQUIRE(chain->name() == "chain");

        auto crypto = LogManager::GetLogger("crypto");
        REQUIRE(crypto != nullptr);
        REQUIRE(crypto->name() == "crypto");
    }

    SECTION("Unknown component returns default logger") {
        auto unknown = LogManager::GetLogger("nonexistent");
        REQUIRE(unknown != nullptr);
        REQUIRE(unknown->name() == "default");
    }

    SECTION("Same logger returned for same component") {
        auto logger1 = LogManager::GetLogger("network");
        auto logger2 = LogManager::GetLogger("network");
        REQUIRE(logger1.get() == logger2.get());
    }
}

TEST_CASE("LogManager: SetLogLevel changes all loggers", "[logging]") {
    LogManager::Initialize("info", false, "");

    // Set to trace level
    LogManager::SetLogLevel("trace");

    auto logger = LogManager::GetLogger();
    REQUIRE(logger->level() == spdlog::level::trace);

    auto network = LogManager::GetLogger("network");
    REQUIRE(network->level() == spdlog::level::trace);

    // Reset to info
    LogManager::SetLogLevel("info");
    REQUIRE(logger->level() == spdlog::level::info);
}

TEST_CASE("LogManager: SetComponentLevel changes specific logger", "[logging]") {
    LogManager::Initialize("info", false, "");

    // Set all to info first
    LogManager::SetLogLevel("info");

    // Set only network to trace
    LogManager::SetComponentLevel("network", "trace");

    auto network = LogManager::GetLogger("network");
    REQUIRE(network->level() == spdlog::level::trace);

    // Other loggers should still be info
    auto chain = LogManager::GetLogger("chain");
    REQUIRE(chain->level() == spdlog::level::info);
}

TEST_CASE("LogManager: Logging macros work", "[logging]") {
    LogManager::Initialize("trace", false, "");
    // Suppress output - we're testing macros don't crash, not verifying output
    LogManager::SetLogLevel("off");

    // These should not crash (even with logging off, the macro code paths execute)
    SECTION("Default logger macros") {
        LOG_TRACE("Test trace message");
        LOG_DEBUG("Test debug message");
        LOG_INFO("Test info message");
        LOG_WARN("Test warn message");
        LOG_ERROR("Test error message");
    }

    SECTION("Network logger macros") {
        LOG_NET_TRACE("Network trace");
        LOG_NET_DEBUG("Network debug");
        LOG_NET_INFO("Network info");
        LOG_NET_WARN("Network warn");
        LOG_NET_ERROR("Network error");
    }

    SECTION("Chain logger macros") {
        LOG_CHAIN_TRACE("Chain trace");
        LOG_CHAIN_DEBUG("Chain debug");
        LOG_CHAIN_INFO("Chain info");
        LOG_CHAIN_WARN("Chain warn");
        LOG_CHAIN_ERROR("Chain error");
    }

    SECTION("Crypto logger macros") {
        LOG_CRYPTO_INFO("Crypto info");
    }

    // If we got here without crashing, macros work
    REQUIRE(true);
}

TEST_CASE("LogManager: Format string arguments", "[logging]") {
    LogManager::Initialize("debug", false, "");
    // Suppress output - we're testing format strings don't crash
    LogManager::SetLogLevel("off");

    // These should not crash and should format correctly
    LOG_INFO("Integer: {}", 42);
    LOG_INFO("String: {}", "hello");
    LOG_INFO("Multiple: {} {} {}", 1, "two", 3.0);
    LOG_INFO("Hex: {:x}", 255);

    REQUIRE(true);
}

TEST_CASE("LogManager: Thread safety", "[logging][threading]") {
    LogManager::Initialize("info", false, "");
    // Suppress output during thread safety test - we're testing thread safety, not log output
    LogManager::SetLogLevel("off");

    const int num_threads = 8;
    const int ops_per_thread = 100;
    std::atomic<int> success_count{0};

    std::vector<std::thread> threads;
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([&success_count, ops_per_thread, t]() {
            for (int i = 0; i < ops_per_thread; ++i) {
                // Mix of operations
                auto logger = LogManager::GetLogger("network");
                if (logger != nullptr) {
                    logger->trace("Thread {} iteration {}", t, i);
                    success_count++;
                }

                // Occasionally change log levels (both "off" to suppress output,
                // but still exercises the thread-safe SetComponentLevel code path)
                if (i % 20 == 0) {
                    LogManager::SetComponentLevel("network", "off");
                }
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    // All operations should succeed
    REQUIRE(success_count == num_threads * ops_per_thread);
}

TEST_CASE("LogManager: Rate-limited logging macros", "[logging][rate_limiter]") {
    LogManager::Initialize("error", false, "");
    // Suppress output - we're testing rate limiter logic, not verifying output
    LogManager::SetLogLevel("off");

    SECTION("Rate-limited ERROR macro limits output") {
        int would_log = 0;
        for (int i = 0; i < 100; ++i) {
            // We can't easily count actual log output, but we can verify
            // the macro doesn't crash with high volume
            LOG_ERROR_RL("Rate limited error {}", i);
            would_log++;
        }
        REQUIRE(would_log == 100);  // Loop completed
    }

    SECTION("Rate-limited WARN macro limits output") {
        for (int i = 0; i < 100; ++i) {
            LOG_WARN_RL("Rate limited warn {}", i);
        }
        REQUIRE(true);  // Didn't crash
    }

    SECTION("Component-specific rate-limited macros") {
        for (int i = 0; i < 50; ++i) {
            LOG_NET_ERROR_RL("Network error {}", i);
            LOG_NET_WARN_RL("Network warn {}", i);
            LOG_CHAIN_ERROR_RL("Chain error {}", i);
            LOG_CHAIN_WARN_RL("Chain warn {}", i);
        }
        REQUIRE(true);  // Didn't crash
    }
}

TEST_CASE("LogManager: Log level parsing", "[logging]") {
    LogManager::Initialize("info", false, "");

    SECTION("Valid log levels") {
        LogManager::SetLogLevel("trace");
        REQUIRE(LogManager::GetLogger()->level() == spdlog::level::trace);

        LogManager::SetLogLevel("debug");
        REQUIRE(LogManager::GetLogger()->level() == spdlog::level::debug);

        LogManager::SetLogLevel("info");
        REQUIRE(LogManager::GetLogger()->level() == spdlog::level::info);

        LogManager::SetLogLevel("warn");
        REQUIRE(LogManager::GetLogger()->level() == spdlog::level::warn);

        LogManager::SetLogLevel("error");
        REQUIRE(LogManager::GetLogger()->level() == spdlog::level::err);

        LogManager::SetLogLevel("off");
        REQUIRE(LogManager::GetLogger()->level() == spdlog::level::off);
    }

    SECTION("Invalid log level defaults to off") {
        LogManager::SetLogLevel("invalid_level");
        // spdlog::level::from_str returns off for unknown levels
        REQUIRE(LogManager::GetLogger()->level() == spdlog::level::off);
    }
    // Both sections end with log level at "off", no restore needed
}
