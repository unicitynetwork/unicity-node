// Regression tests for timer scheduling chrono arithmetic.
//
// These tests verify that schedule_next_feeler() and schedule_next_extra_block_relay()
// produce delays in the expected range. A bug was found where FEELER_INTERVAL.count()
// returned 2 (minutes) but was used in a seconds context, capping at 6s instead of 360s.
//
// The scheduling functions are private to NetworkManager, so we test the arithmetic
// directly using the same constants and formulas.

#include "catch_amalgamated.hpp"
#include "network/network_manager.hpp"

#include <chrono>
#include <random>

using namespace unicity::network;

// Replicate the scheduling arithmetic from NetworkManager::schedule_next_feeler()
// and schedule_next_extra_block_relay() so we can verify correctness.
namespace {

// These mirror the private constants in NetworkManager
constexpr std::chrono::minutes FEELER_INTERVAL{2};
constexpr std::chrono::minutes EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL{5};
constexpr double DEFAULT_MAX_DELAY_MULTIPLIER = 3.0;

struct ScheduleResult {
  double delay_s;
  double max_delay;
};

ScheduleResult compute_feeler_delay(std::mt19937& rng, double max_delay_multiplier) {
  std::exponential_distribution<double> exp(
      1.0 / std::chrono::duration_cast<std::chrono::seconds>(FEELER_INTERVAL).count());
  double delay_s = exp(rng);

  double max_delay = 0.0;
  if (max_delay_multiplier > 0.0) {
    max_delay = max_delay_multiplier *
                std::chrono::duration_cast<std::chrono::seconds>(FEELER_INTERVAL).count();
    delay_s = std::min(max_delay, delay_s);
  }

  return {delay_s, max_delay};
}

ScheduleResult compute_extra_block_relay_delay(std::mt19937& rng) {
  std::exponential_distribution<double> exp(
      1.0 / std::chrono::duration_cast<std::chrono::seconds>(EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL).count());
  double delay_s = exp(rng);

  double max_delay = 3.0 *
                     std::chrono::duration_cast<std::chrono::seconds>(EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL).count();
  delay_s = std::min(max_delay, delay_s);

  return {delay_s, max_delay};
}

}  // namespace

TEST_CASE("Chrono constants have correct second values", "[network][timer][chrono]") {
  // This is the core regression test: ensure .count() conversions produce
  // values in seconds, not minutes or other units.

  SECTION("FEELER_INTERVAL is 120 seconds") {
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(FEELER_INTERVAL).count();
    CHECK(seconds == 120);
    // The bug was: FEELER_INTERVAL.count() == 2 (minutes, not seconds)
    CHECK(FEELER_INTERVAL.count() == 2);  // Raw .count() is minutes - DON'T use this for seconds math
  }

  SECTION("EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL is 300 seconds") {
    auto seconds =
        std::chrono::duration_cast<std::chrono::seconds>(EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL).count();
    CHECK(seconds == 300);
    CHECK(EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL.count() == 5);  // Raw .count() is minutes
  }
}

TEST_CASE("Feeler timer cap is in correct range", "[network][timer][chrono]") {
  // The cap must be multiplier * interval_in_seconds.
  // With default multiplier 3.0 and interval 2 minutes: cap = 3.0 * 120 = 360 seconds.
  // The bug produced: 3.0 * 2 = 6 seconds.

  SECTION("Default cap is 360 seconds") {
    std::mt19937 rng(42);
    auto result = compute_feeler_delay(rng, DEFAULT_MAX_DELAY_MULTIPLIER);

    CHECK(result.max_delay == Catch::Approx(360.0));
    CHECK(result.max_delay > 300.0);  // Definitely not 6.0
  }

  SECTION("Cap is never less than the interval itself") {
    // Even with multiplier 1.0, cap should be >= 120s
    std::mt19937 rng(42);
    auto result = compute_feeler_delay(rng, 1.0);

    CHECK(result.max_delay == Catch::Approx(120.0));
    CHECK(result.max_delay > 60.0);  // Not 2.0
  }

  SECTION("Generated delays respect the cap over many samples") {
    std::mt19937 rng(12345);
    double max_observed = 0.0;

    for (int i = 0; i < 10000; ++i) {
      auto result = compute_feeler_delay(rng, DEFAULT_MAX_DELAY_MULTIPLIER);
      max_observed = std::max(max_observed, result.delay_s);
      REQUIRE(result.delay_s <= 360.0);
      REQUIRE(result.delay_s > 0.0);
    }

    // With 10000 samples from exp(1/120), we should see values near the 360s cap
    CHECK(max_observed > 100.0);  // Very unlikely to be < 100 with 10k samples
  }
}

TEST_CASE("Extra block relay timer cap is in correct range", "[network][timer][chrono]") {
  // Cap = 3.0 * 300 seconds = 900 seconds (15 minutes).
  // A manual * 60 bug would give 3.0 * 5 * 60 = 900 (happens to be correct,
  // but fragile). We now use duration_cast for consistency.

  SECTION("Cap is 900 seconds") {
    std::mt19937 rng(42);
    auto result = compute_extra_block_relay_delay(rng);

    CHECK(result.max_delay == Catch::Approx(900.0));
  }

  SECTION("Generated delays respect the cap over many samples") {
    std::mt19937 rng(99);
    for (int i = 0; i < 10000; ++i) {
      auto result = compute_extra_block_relay_delay(rng);
      REQUIRE(result.delay_s <= 900.0);
      REQUIRE(result.delay_s > 0.0);
    }
  }
}

TEST_CASE("Exponential distribution mean matches interval", "[network][timer][chrono]") {
  // The mean of exp(1/lambda) is lambda. For feeler, lambda = 120s.
  // Verify the mean over many samples is close to 120s.

  SECTION("Feeler mean is ~120 seconds") {
    std::mt19937 rng(777);
    double sum = 0.0;
    constexpr int N = 100000;

    // Use uncapped distribution to verify the mean
    std::exponential_distribution<double> exp(
        1.0 / std::chrono::duration_cast<std::chrono::seconds>(FEELER_INTERVAL).count());

    for (int i = 0; i < N; ++i) {
      sum += exp(rng);
    }

    double mean = sum / N;
    CHECK(mean == Catch::Approx(120.0).margin(5.0));  // Within 5s of expected 120s
  }

  SECTION("Extra block relay mean is ~300 seconds") {
    std::mt19937 rng(888);
    double sum = 0.0;
    constexpr int N = 100000;

    std::exponential_distribution<double> exp(
        1.0 / std::chrono::duration_cast<std::chrono::seconds>(EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL).count());

    for (int i = 0; i < N; ++i) {
      sum += exp(rng);
    }

    double mean = sum / N;
    CHECK(mean == Catch::Approx(300.0).margin(10.0));  // Within 10s of expected 300s
  }
}
