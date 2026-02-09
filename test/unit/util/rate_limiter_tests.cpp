// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license
// Tests for logging rate limiter

#include "catch_amalgamated.hpp"
#include "util/rate_limiter.hpp"
#include "util/time.hpp"
#include <thread>

using namespace unicity::util;

TEST_CASE("RateLimiter: Basic token bucket", "[rate_limiter]") {
    RateLimiter limiter;

    SECTION("First N messages allowed (burst capacity)") {
        // Token bucket: 200 tokens, refill over 3600 seconds (1 hour)
        for (int i = 0; i < 200; ++i) {
            REQUIRE(limiter.should_log("test:1", 200, 3600));
        }

        // 201st message should be rate-limited
        REQUIRE_FALSE(limiter.should_log("test:1", 200, 3600));
    }

    SECTION("Different callsites have independent buckets") {
        // Exhaust tokens for first callsite
        for (int i = 0; i < 200; ++i) {
            limiter.should_log("test:1", 200, 3600);
        }
        REQUIRE_FALSE(limiter.should_log("test:1", 200, 3600));

        // Second callsite should have full bucket
        REQUIRE(limiter.should_log("test:2", 200, 3600));
    }
}

TEST_CASE("RateLimiter: Token refill over time", "[rate_limiter]") {
    // Use mock time for deterministic, fast tests
    MockTimeScope mock_time(1000000);
    RateLimiter limiter;

    SECTION("Tokens refill after period") {
        // Use all tokens (10 tokens, refill at 1 per 10 seconds)
        for (int i = 0; i < 10; ++i) {
            limiter.should_log("test:refill", 10, 100);
        }
        REQUIRE_FALSE(limiter.should_log("test:refill", 10, 100));

        // Advance time by 10 seconds (enough to refill 1 token: 10 tokens / 100 seconds = 0.1/sec, 10 sec = 1 token)
        SetMockTime(1000010);

        // Should have 1 token available now
        REQUIRE(limiter.should_log("test:refill", 10, 100));

        // But only 1 token
        REQUIRE_FALSE(limiter.should_log("test:refill", 10, 100));
    }

    SECTION("Tokens cap at burst limit") {
        // Use all tokens
        for (int i = 0; i < 5; ++i) {
            limiter.should_log("test:cap", 5, 1);
        }

        // Advance time by 10 seconds (could theoretically refill 10 tokens)
        SetMockTime(1000010);

        // But bucket caps at 5 tokens
        for (int i = 0; i < 5; ++i) {
            REQUIRE(limiter.should_log("test:cap", 5, 1));
        }
        REQUIRE_FALSE(limiter.should_log("test:cap", 5, 1));
    }
}

TEST_CASE("RateLimiter: Realistic attack scenario", "[rate_limiter][security]") {
    RateLimiter limiter;

    SECTION("Malicious peer spam attack") {
        // Simulate attacker sending 1000 malformed messages
        // With rate limiting (200/hour): only first 200 logged, rest blocked

        int logged_count = 0;
        for (int i = 0; i < 1000; ++i) {
            if (limiter.should_log("peer_error:attack", 200, 3600)) {
                logged_count++;
            }
        }

        // Only 200 messages logged (burst capacity)
        REQUIRE(logged_count == 200);

        // 80% reduction in disk writes
        REQUIRE((1000 - logged_count) == 800);
    }
}

TEST_CASE("RateLimiter: Thread safety", "[rate_limiter][threading]") {
    RateLimiter& limiter = RateLimiter::instance();

    SECTION("Concurrent access from multiple threads") {
        const int num_threads = 4;
        const int attempts_per_thread = 100;
        std::atomic<int> logged_count{0};

        std::vector<std::thread> threads;
        for (int t = 0; t < num_threads; ++t) {
            threads.emplace_back([&limiter, &logged_count, attempts_per_thread]() {
                for (int i = 0; i < attempts_per_thread; ++i) {
                    if (limiter.should_log("thread_test", 200, 3600)) {
                        logged_count++;
                    }
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        // Total attempts: 4 threads × 100 attempts = 400
        // Burst capacity: 200 tokens
        // So at most 200 should be logged
        REQUIRE(logged_count <= 200);
        REQUIRE(logged_count > 0); // At least some got through
    }
}

TEST_CASE("RateLimiter: Production rate limit", "[rate_limiter]") {
    RateLimiter limiter;

    SECTION("200/hour rate limit") {
        int logged = 0;
        for (int i = 0; i < 300; ++i) {
            if (limiter.should_log("production_test", 200, 3600)) {
                logged++;
            }
        }
        REQUIRE(logged == 200);
    }
}
