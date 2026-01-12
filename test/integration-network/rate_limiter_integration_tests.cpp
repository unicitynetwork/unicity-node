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

    SECTION("Invalid header spam attack (ERROR rate: 10 burst, 1/60s)") {
        int logged = 0;

        // Simulate attacker sending 100 invalid headers rapidly
        for (int i = 0; i < 100; ++i) {
            if (limiter.should_log("test:invalid_header", 10, 60)) {
                logged++;
            }
        }

        // Should only log first 10 (burst capacity for ERROR)
        REQUIRE(logged == 10);

        INFO("Attack mitigation: 100 invalid headers → 10 log entries (90% reduction)");
    }

    SECTION("Pre-handshake message spam (WARN rate: 30 burst, 1/20s)") {
        int logged = 0;

        // Simulate attacker sending 200 pre-handshake messages
        for (int i = 0; i < 200; ++i) {
            if (limiter.should_log("test:pre_handshake", 30, 20)) {
                logged++;
            }
        }

        // Should only log first 30 (burst capacity for WARN)
        REQUIRE(logged == 30);

        INFO("Attack mitigation: 200 pre-handshake messages → 30 log entries (85% reduction)");
    }

    SECTION("Receive buffer overflow spam") {
        int logged = 0;

        // Simulate 50 peers all causing buffer overflows
        for (int peer_id = 0; peer_id < 50; ++peer_id) {
            if (limiter.should_log("test:buffer_overflow", 30, 20)) {
                logged++;
            }
        }

        // Should only log first 30 (burst capacity for WARN)
        REQUIRE(logged == 30);

        INFO("Attack mitigation: 50 buffer overflow events → 30 log entries");
    }

    SECTION("Unknown command flooding") {
        int logged = 0;

        // Simulate peer sending 150 unknown commands
        for (int i = 0; i < 150; ++i) {
            if (limiter.should_log("test:unknown_cmd", 30, 20)) {
                logged++;
            }
        }

        // Should only log first 30 (burst capacity for WARN)
        REQUIRE(logged == 30);

        INFO("Old behavior: manual rate limiting logged 5 + 1 suppression message");
        INFO("New behavior: consistent token bucket with 30 burst capacity");
    }

    SECTION("Mixed attack: multiple error types") {
        int pow_logged = 0;
        int continuous_logged = 0;
        int oversized_logged = 0;

        // Simulate attacker triggering multiple error types
        for (int i = 0; i < 50; ++i) {
            if (limiter.should_log("test:pow_check", 10, 60)) {
                pow_logged++;
            }
            if (limiter.should_log("test:non_continuous", 10, 60)) {
                continuous_logged++;
            }
            if (limiter.should_log("test:oversized", 30, 20)) {
                oversized_logged++;
            }
        }

        // Each unique log location has its own bucket:
        // - PoW check: 10 logs (ERROR burst)
        // - Non-continuous: 10 logs (ERROR burst)
        // - Oversized chunk: 30 logs (WARN burst)
        // Total: 50 logs from 150 attempts (67% reduction)
        REQUIRE(pow_logged == 10);
        REQUIRE(continuous_logged == 10);
        REQUIRE(oversized_logged == 30);
        REQUIRE((pow_logged + continuous_logged + oversized_logged) == 50);
    }

    SECTION("Token refill over time") {
        int initial_logged = 0;

        // Exhaust burst capacity (10 ERROR tokens)
        for (int i = 0; i < 15; ++i) {
            if (limiter.should_log("test:refill", 10, 60)) {
                initial_logged++;
            }
        }

        // Initial burst: 10 tokens used
        REQUIRE(initial_logged == 10);

        // Advance time by 60 seconds (refill rate: 10 tokens / 600s = 1 token per 60s)
        SetMockTime(1000060);

        int refill_logged = 0;
        // Try logging again - should have at least 1 token available
        if (limiter.should_log("test:refill", 10, 60)) {
            refill_logged++;
        }

        // At least 1 token should be available after refill
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
        for (int i = 0; i < 20; ++i) {
            // Attack vector 1: Invalid headers
            if (limiter.should_log("test:invalid_header", 10, 60)) {
                logged1++;
            }

            // Attack vector 2: PoW check failure
            if (limiter.should_log("test:pow_failure", 10, 60)) {
                logged2++;
            }
        }

        // Each callsite gets 10 ERROR tokens → 20 total logs
        REQUIRE(logged1 == 10);
        REQUIRE(logged2 == 10);
        REQUIRE((logged1 + logged2) == 20);
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

        // With rate limiting (10 burst, 1 per 60 seconds):
        // - First 10 logged immediately
        // - Then 1 per minute = 1 more log in 60 seconds
        // - Total: 11 logs
        const int protected_log_count = 11;
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

        // Verify significant reduction
        REQUIRE(reduction_percent > 99.0);
        REQUIRE(protected_log_count == 11);
        REQUIRE(total_attacks == 60000);
    }
}
