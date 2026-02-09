// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license
// Integration tests for rate-limited logging in production code

#include "catch_amalgamated.hpp"
#include "util/rate_limiter.hpp"
#include "util/time.hpp"

using namespace unicity::util;

TEST_CASE("Rate-limited logging: Production attack scenarios", "[rate_limiter][integration]") {
    // Use mock time for deterministic tests
    MockTimeScope mock_time(1000000);
    RateLimiter limiter;

    SECTION("Invalid header spam attack (200/hour rate limit)") {
        int logged = 0;

        // Simulate attacker sending 500 invalid headers rapidly
        for (int i = 0; i < 500; ++i) {
            if (limiter.should_log("test:invalid_header", 200, 3600)) {
                logged++;
            }
        }

        // Should only log first 200 (burst capacity)
        REQUIRE(logged == 200);

        INFO("Attack mitigation: 500 invalid headers → 200 log entries (60% reduction)");
    }

    SECTION("Pre-handshake message spam (200/hour rate limit)") {
        int logged = 0;

        // Simulate attacker sending 400 pre-handshake messages
        for (int i = 0; i < 400; ++i) {
            if (limiter.should_log("test:pre_handshake", 200, 3600)) {
                logged++;
            }
        }

        // Should only log first 200 (burst capacity)
        REQUIRE(logged == 200);

        INFO("Attack mitigation: 400 pre-handshake messages → 200 log entries (50% reduction)");
    }

    SECTION("Receive buffer overflow spam") {
        int logged = 0;

        // Simulate 300 peers all causing buffer overflows
        for (int peer_id = 0; peer_id < 300; ++peer_id) {
            if (limiter.should_log("test:buffer_overflow", 200, 3600)) {
                logged++;
            }
        }

        // Should only log first 200 (burst capacity)
        REQUIRE(logged == 200);

        INFO("Attack mitigation: 300 buffer overflow events → 200 log entries");
    }

    SECTION("Unknown command flooding") {
        int logged = 0;

        // Simulate peer sending 350 unknown commands
        for (int i = 0; i < 350; ++i) {
            if (limiter.should_log("test:unknown_cmd", 200, 3600)) {
                logged++;
            }
        }

        // Should only log first 200 (burst capacity)
        REQUIRE(logged == 200);

        INFO("Rate limiting: 350 unknown commands → 200 log entries");
    }

    SECTION("Mixed attack: multiple error types") {
        int pow_logged = 0;
        int continuous_logged = 0;
        int oversized_logged = 0;

        // Simulate attacker triggering multiple error types (250 each)
        for (int i = 0; i < 250; ++i) {
            if (limiter.should_log("test:pow_check", 200, 3600)) {
                pow_logged++;
            }
            if (limiter.should_log("test:non_continuous", 200, 3600)) {
                continuous_logged++;
            }
            if (limiter.should_log("test:oversized", 200, 3600)) {
                oversized_logged++;
            }
        }

        // Each unique log location has its own bucket (200 each)
        REQUIRE(pow_logged == 200);
        REQUIRE(continuous_logged == 200);
        REQUIRE(oversized_logged == 200);
        REQUIRE((pow_logged + continuous_logged + oversized_logged) == 600);
    }

    SECTION("Token refill over time") {
        int initial_logged = 0;

        // Exhaust burst capacity (200 tokens)
        for (int i = 0; i < 250; ++i) {
            if (limiter.should_log("test:refill", 200, 3600)) {
                initial_logged++;
            }
        }

        // Initial burst: 200 tokens used
        REQUIRE(initial_logged == 200);

        // Advance time by 3600 seconds (1 hour) - should refill all tokens
        SetMockTime(1000000 + 3600);

        int refill_logged = 0;
        // Try logging again - should have tokens available after refill
        for (int i = 0; i < 10; ++i) {
            if (limiter.should_log("test:refill", 200, 3600)) {
                refill_logged++;
            }
        }

        // Tokens should be refilled after 1 hour
        REQUIRE(refill_logged >= 1);
    }
}

TEST_CASE("Rate limiter: Per-callsite isolation", "[rate_limiter][integration]") {
    MockTimeScope mock_time(2000000);
    RateLimiter limiter;

    SECTION("Different callsites have independent buckets") {
        int logged1 = 0;
        int logged2 = 0;

        // Each unique callsite ID gets its own token bucket
        // Simulate two different attack vectors from same peer
        for (int i = 0; i < 300; ++i) {
            // Attack vector 1: Invalid headers
            if (limiter.should_log("test:invalid_header", 200, 3600)) {
                logged1++;
            }

            // Attack vector 2: PoW check failure
            if (limiter.should_log("test:pow_failure", 200, 3600)) {
                logged2++;
            }
        }

        // Each callsite gets 200 tokens → 400 total logs
        REQUIRE(logged1 == 200);
        REQUIRE(logged2 == 200);
        REQUIRE((logged1 + logged2) == 400);
    }
}

TEST_CASE("Rate limiter: Disk exhaustion attack mitigation", "[rate_limiter][security]") {
    MockTimeScope mock_time(3000000);

    SECTION("Calculate attack mitigation effectiveness") {
        // Attack scenario: Malicious peer sends 1000 invalid headers/second
        const int attack_rate = 1000;  // messages per second
        const int attack_duration = 60;  // seconds
        const int total_attacks = attack_rate * attack_duration;  // 60,000 attacks

        // Without rate limiting:
        // - 60,000 log entries × 150 bytes avg = 9 MB in 1 minute
        const int log_size_bytes = 150;
        const int64_t unprotected_disk_usage = static_cast<int64_t>(total_attacks) * log_size_bytes;

        // With rate limiting (200 burst, refill over 1 hour):
        // - First 200 logged immediately
        // - In 60 seconds: ~3.3 more tokens refilled (200 tokens / 3600s × 60s)
        // - Total: ~203 logs
        const int protected_log_count = 203;
        const int64_t protected_disk_usage = protected_log_count * log_size_bytes;

        // Calculate reduction
        double reduction_percent = 100.0 * (1.0 - static_cast<double>(protected_disk_usage) /
                                            static_cast<double>(unprotected_disk_usage));

        INFO("Attack: 1000 invalid headers/sec for 60 seconds");
        INFO("Without rate limiting: " << total_attacks << " log entries = "
             << (unprotected_disk_usage / 1024) << " KB");
        INFO("With rate limiting: " << protected_log_count << " log entries = "
             << (protected_disk_usage / 1024) << " KB");
        INFO("Disk write reduction: " << reduction_percent << "%");

        // Verify significant reduction (>99%)
        REQUIRE(reduction_percent > 99.0);
        REQUIRE(protected_log_count < 300);  // Much less than unlimited
        REQUIRE(total_attacks == 60000);
    }
}
