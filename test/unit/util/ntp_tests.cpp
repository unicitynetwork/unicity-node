// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "catch_amalgamated.hpp"
#include "util/ntp.hpp"

#include <cstdlib>

using namespace unicity::util;

TEST_CASE("NTP check returns plausible offset", "[util][ntp]") {
  auto offset = CheckNTPOffset("pool.ntp.org", 5);

  if (!offset.has_value()) {
    WARN("NTP server unreachable — skipping (firewall?)");
    return;
  }

  // System clock should be within 60 seconds of NTP
  CHECK(*offset > -60);
  CHECK(*offset < 60);
}

TEST_CASE("NTP check is consistent across multiple queries", "[util][ntp]") {
  auto offset1 = CheckNTPOffset("pool.ntp.org", 5);
  auto offset2 = CheckNTPOffset("pool.ntp.org", 5);

  if (!offset1.has_value() || !offset2.has_value()) {
    WARN("NTP server unreachable — skipping");
    return;
  }

  // Two queries seconds apart should agree within 5s
  auto delta = std::abs(*offset1 - *offset2);
  CHECK(delta <= 5);
}

TEST_CASE("NTP check returns nullopt for unreachable server", "[util][ntp]") {
  // Timeout after 1 second against a non-routable address
  auto offset = CheckNTPOffset("192.0.2.1", 1);

  REQUIRE_FALSE(offset.has_value());
}

TEST_CASE("NTP check returns nullopt for unresolvable hostname", "[util][ntp]") {
  auto offset = CheckNTPOffset("this.host.does.not.exist.invalid", 1);

  REQUIRE_FALSE(offset.has_value());
}
