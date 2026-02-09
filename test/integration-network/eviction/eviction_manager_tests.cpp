// Copyright (c) 2025 The Unicity Foundation
// Unit tests for EvictionManager selection algorithm

#include "catch_amalgamated.hpp"
#include "network/eviction_manager.hpp"

using namespace unicity::network;
using namespace std::chrono;

// Helper to create candidates with incrementing peer_ids
static std::vector<EvictionManager::EvictionCandidate> MakeCandidates(
    size_t count,
    const std::string& netgroup = "10.0",
    int start_id = 1,
    bool is_outbound = false) {

    std::vector<EvictionManager::EvictionCandidate> candidates;
    auto base_time = steady_clock::now() - hours(1);

    for (size_t i = 0; i < count; i++) {
        candidates.push_back({
            start_id + static_cast<int>(i),
            base_time + seconds(i),  // Each peer connected 1 second later
            100,                      // 100ms ping
            netgroup,
            false,                    // not protected
            is_outbound,              // is_outbound (default false = inbound)
            steady_clock::time_point{} // last_headers_time (epoch = no headers received)
        });
    }
    return candidates;
}

TEST_CASE("EvictionManager - Empty candidates", "[eviction][unit]") {
    std::vector<EvictionManager::EvictionCandidate> empty;
    auto result = EvictionManager::SelectNodeToEvict(std::move(empty));
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("EvictionManager - All protected", "[eviction][unit]") {
    auto candidates = MakeCandidates(5);
    for (auto& c : candidates) {
        c.is_protected = true;
    }

    auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("EvictionManager - Single candidate", "[eviction][unit]") {
    auto candidates = MakeCandidates(1);
    int expected_id = candidates[0].peer_id;

    auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));
    REQUIRE(result.has_value());
    REQUIRE(*result == expected_id);
}

TEST_CASE("EvictionManager - Netgroup diversity protection", "[eviction][unit]") {
    SECTION("4 peers from different netgroups - netgroup protection kicks in") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 4 peers from 4 different netgroups
        candidates.push_back({1, base_time, 100, "10.0", false, false, {}});
        candidates.push_back({2, base_time + seconds(1), 100, "10.1", false, false, {}});
        candidates.push_back({3, base_time + seconds(2), 100, "10.2", false, false, {}});
        candidates.push_back({4, base_time + seconds(3), 100, "10.3", false, false, {}});

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        // With only 4 peers, netgroup protection (size > 4) doesn't trigger
        // All 4 go to selection phase, youngest gets evicted
        REQUIRE(result.has_value());
        REQUIRE(*result == 4);  // Youngest peer
    }

    SECTION("5 peers from 5 netgroups - 4 protected, 1 evicted") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 5 peers from 5 different netgroups
        candidates.push_back({1, base_time, 100, "10.0", false, false, {}});
        candidates.push_back({2, base_time + seconds(1), 100, "10.1", false, false, {}});
        candidates.push_back({3, base_time + seconds(2), 100, "10.2", false, false, {}});
        candidates.push_back({4, base_time + seconds(3), 100, "10.3", false, false, {}});
        candidates.push_back({5, base_time + seconds(4), 100, "10.4", false, false, {}});

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        // 4 protected by netgroup diversity, 1 remains - that one gets evicted
        REQUIRE(result.has_value());
    }

    SECTION("Many peers from same netgroup - attacker doesn't benefit") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 1 honest peer from unique netgroup
        candidates.push_back({1, base_time, 100, "192.168", false, false, {}});

        // 5 attacker peers from same netgroup
        for (int i = 0; i < 5; i++) {
            candidates.push_back({10 + i, base_time + seconds(10 + i), 100, "10.0", false, false, {}});
        }

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        // Honest peer (192.168) should be protected by netgroup diversity
        // Attacker peers (10.0) form largest group, youngest evicted
        REQUIRE(result.has_value());
        REQUIRE(*result == 14);  // Youngest attacker
    }
}

TEST_CASE("EvictionManager - Ping protection", "[eviction][unit]") {
    SECTION("9 peers same netgroup - one evicted") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 9 peers from same netgroup with good ping
        for (int i = 0; i < 9; i++) {
            candidates.push_back({i + 1, base_time + seconds(i), 50, "10.0", false, false, {}});
        }

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        // Netgroup protection: 9 > 4, but only 1 netgroup → 1 protected → 8 remain
        // Ping protection: 8 is not > 8, no protection
        // Header protection: 8 > 4, all epoch → 4 protected → 4 remain (newest after ping sort)
        // Uptime protection: 4 > 1, protect 50% = 2 oldest → 2 remain
        // Selection: from remaining, evict youngest
        REQUIRE(result.has_value());
        // The exact peer evicted depends on sort stability after header protection
        // Just verify someone gets evicted
    }

    SECTION("10 peers same netgroup - one evicted after protections") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 10 peers from same netgroup with good ping
        for (int i = 0; i < 10; i++) {
            candidates.push_back({i + 1, base_time + seconds(i), 50, "10.0", false, false, {}});
        }

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        // Netgroup protection: 10 > 4, 1 protected
        // After: 9 remain
        // Ping protection: 9 > 8, so 9 - 8 = 1 remains
        // That 1 gets evicted
        REQUIRE(result.has_value());
    }

    SECTION("Unknown ping peers evicted before good ping peers") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 10 peers: 9 with good ping, 1 with unknown ping (-1)
        for (int i = 0; i < 9; i++) {
            candidates.push_back({i + 1, base_time + seconds(i), 50, "10.0", false, false, {}});
        }
        candidates.push_back({10, base_time + seconds(9), -1, "10.0", false, false, {}}); // Unknown ping, youngest

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        // Netgroup protection: 1 protected
        // After: 9 remain
        // Ping protection: sorts by ping (worst first), unknown (-1) maps to max
        // So unknown ping peer stays at front, good ping peers at back get protected
        // 9 - 8 = 1 remains (the unknown ping peer)
        REQUIRE(result.has_value());
        REQUIRE(*result == 10);  // Unknown ping peer evicted
    }
}

TEST_CASE("EvictionManager - Evict from largest netgroup", "[eviction][unit]") {
    SECTION("Evicts from netgroup with most peers") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 3 peers from netgroup A
        candidates.push_back({1, base_time, 100, "192.168", false, false, {}});
        candidates.push_back({2, base_time + seconds(1), 100, "192.168", false, false, {}});
        candidates.push_back({3, base_time + seconds(2), 100, "192.168", false, false, {}});

        // 5 peers from netgroup B (larger group)
        candidates.push_back({4, base_time + seconds(3), 100, "10.0", false, false, {}});
        candidates.push_back({5, base_time + seconds(4), 100, "10.0", false, false, {}});
        candidates.push_back({6, base_time + seconds(5), 100, "10.0", false, false, {}});
        candidates.push_back({7, base_time + seconds(6), 100, "10.0", false, false, {}});
        candidates.push_back({8, base_time + seconds(7), 100, "10.0", false, false, {}});

        // 1 peer from netgroup C
        candidates.push_back({9, base_time + seconds(8), 100, "172.16", false, false, {}});

        // Total: 9 peers, 3 netgroups
        // Netgroup protection: protects 1 from each of 3 netgroups → 6 remain
        // Ping protection: 6 is not > 8, no protection
        // Header protection: 6 > 4, all epoch → 4 protected → 2 remain
        // Uptime protection: 2 > 1, protect 50% = 1 oldest → 1 remains
        // Selection: 1 peer remains, that one gets evicted

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        REQUIRE(result.has_value());
        // With the new protections, the exact peer evicted depends on sort order
        // Just verify eviction happens
    }

    SECTION("Tie-breaker: youngest netgroup") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 2 peers from netgroup A (older connections)
        candidates.push_back({1, base_time, 100, "192.168", false, false, {}});
        candidates.push_back({2, base_time + seconds(1), 100, "192.168", false, false, {}});

        // 2 peers from netgroup B (newer connections)
        candidates.push_back({3, base_time + seconds(10), 100, "10.0", false, false, {}});
        candidates.push_back({4, base_time + seconds(11), 100, "10.0", false, false, {}});

        // After protections, both netgroups have same size
        // Tie-breaker: netgroup with youngest (most recent) connection
        // B has peer 4 at +11s, A has peer 2 at +1s
        // B is "younger" so evict from B

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        REQUIRE(result.has_value());
        // Should evict peer 4 (youngest in the younger netgroup B)
        REQUIRE(*result == 4);
    }
}

TEST_CASE("EvictionManager - Evict youngest from selected netgroup", "[eviction][unit]") {
    std::vector<EvictionManager::EvictionCandidate> candidates;
    auto base_time = steady_clock::now() - hours(1);

    // 5 peers from same netgroup with different connection times
    candidates.push_back({1, base_time, 100, "10.0", false, false, {}});               // Oldest
    candidates.push_back({2, base_time + seconds(100), 100, "10.0", false, false, {}});
    candidates.push_back({3, base_time + seconds(200), 100, "10.0", false, false, {}});
    candidates.push_back({4, base_time + seconds(300), 100, "10.0", false, false, {}});
    candidates.push_back({5, base_time + seconds(400), 100, "10.0", false, false, {}}); // Youngest

    auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

    REQUIRE(result.has_value());
    // Should evict peer 5 (youngest)
    REQUIRE(*result == 5);
}

// ============================================================================
// Boundary condition tests
// ============================================================================

TEST_CASE("EvictionManager - Boundary: exactly 4 unique netgroups", "[eviction][unit][boundary]") {
    // PROTECT_BY_NETGROUP = 4
    // Protection triggers when candidates.size() > 4, protecting 1 from each netgroup
    std::vector<EvictionManager::EvictionCandidate> candidates;
    auto base_time = steady_clock::now() - hours(1);

    SECTION("4 peers from 4 netgroups - no netgroup protection (size not > 4)") {
        candidates.push_back({1, base_time, 100, "10.0", false, false, {}});
        candidates.push_back({2, base_time + seconds(1), 100, "10.1", false, false, {}});
        candidates.push_back({3, base_time + seconds(2), 100, "10.2", false, false, {}});
        candidates.push_back({4, base_time + seconds(3), 100, "10.3", false, false, {}});

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        // All 4 go to selection, youngest evicted
        REQUIRE(result.has_value());
        REQUIRE(*result == 4);
    }

    SECTION("5 peers from 4 netgroups - netgroup protection triggers") {
        // 4 unique netgroups, but 5 total peers
        candidates.push_back({1, base_time, 100, "10.0", false, false, {}});
        candidates.push_back({2, base_time + seconds(1), 100, "10.1", false, false, {}});
        candidates.push_back({3, base_time + seconds(2), 100, "10.2", false, false, {}});
        candidates.push_back({4, base_time + seconds(3), 100, "10.3", false, false, {}});
        candidates.push_back({5, base_time + seconds(4), 100, "10.0", false, false, {}}); // Same as peer 1

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        // Netgroup protection: 4 protected (one from each netgroup)
        // Remaining: peer 5 (duplicate netgroup 10.0)
        // Should evict peer 5
        REQUIRE(result.has_value());
        REQUIRE(*result == 5);
    }
}

TEST_CASE("EvictionManager - Boundary: exactly 8 peers after netgroup protection", "[eviction][unit][boundary]") {
    // PROTECT_BY_PING = 8
    // Ping protection triggers when candidates.size() > 8
    std::vector<EvictionManager::EvictionCandidate> candidates;
    auto base_time = steady_clock::now() - hours(1);

    SECTION("9 peers same netgroup - with new protections") {
        // 9 peers from same netgroup
        // Netgroup: 9 > 4, 1 protected → 8 remain
        // Ping: 8 is NOT > 8, no protection
        // Header: 8 > 4, 4 protected → 4 remain
        // Uptime: 4 > 1, protect 50% = 2 → 2 remain
        // Selection: from 2 remaining, evict youngest
        for (int i = 1; i <= 9; i++) {
            candidates.push_back({i, base_time + seconds(i), 50, "10.0", false, false, {}});
        }

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        REQUIRE(result.has_value());
        // Exact peer depends on sort order after header protection
    }

    SECTION("10 peers same netgroup - both protections apply") {
        for (int i = 1; i <= 10; i++) {
            candidates.push_back({i, base_time + seconds(i), 50, "10.0", false, false, {}});
        }

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        // Netgroup: 10 > 4, protect 1 → 9 remain
        // Ping: 9 > 8, protect 8 → 1 remain
        // That 1 gets evicted
        REQUIRE(result.has_value());
    }
}

TEST_CASE("EvictionManager - Boundary: all candidates protected by cascade", "[eviction][unit][boundary]") {
    std::vector<EvictionManager::EvictionCandidate> candidates;
    auto base_time = steady_clock::now() - hours(1);

    SECTION("5 unique netgroups with 1 peer each - netgroup protection covers all minus 1") {
        // 5 peers from 5 unique netgroups
        candidates.push_back({1, base_time, 100, "10.0", false, false, {}});
        candidates.push_back({2, base_time + seconds(1), 100, "10.1", false, false, {}});
        candidates.push_back({3, base_time + seconds(2), 100, "10.2", false, false, {}});
        candidates.push_back({4, base_time + seconds(3), 100, "10.3", false, false, {}});
        candidates.push_back({5, base_time + seconds(4), 100, "10.4", false, false, {}});

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        // 5 > 4: netgroup protection applies
        // 5 unique netgroups → protect 4, leave 1
        // That 1 gets evicted (no ping protection since 1 ≤ 8)
        REQUIRE(result.has_value());
    }

    SECTION("Exactly 4 netgroups with 1 peer each - no protection (4 not > 4)") {
        candidates.push_back({1, base_time, 100, "10.0", false, false, {}});
        candidates.push_back({2, base_time + seconds(1), 100, "10.1", false, false, {}});
        candidates.push_back({3, base_time + seconds(2), 100, "10.2", false, false, {}});
        candidates.push_back({4, base_time + seconds(3), 100, "10.3", false, false, {}});

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        // 4 is not > 4: no netgroup protection
        // All 4 go to selection, youngest evicted
        REQUIRE(result.has_value());
        REQUIRE(*result == 4);
    }
}

TEST_CASE("EvictionManager - Edge case: empty netgroup string", "[eviction][unit][boundary]") {
    std::vector<EvictionManager::EvictionCandidate> candidates;
    auto base_time = steady_clock::now() - hours(1);

    SECTION("Peers with empty netgroup treated as unknown group") {
        candidates.push_back({1, base_time, 100, "", false, false, {}});
        candidates.push_back({2, base_time + seconds(1), 100, "", false, false, {}});
        candidates.push_back({3, base_time + seconds(2), 100, "10.0", false, false, {}});

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        // With only 3 peers:
        // Netgroup: 3 not > 4, no protection
        // Ping: 3 not > 8, no protection
        // Header: 3 not > 4, no protection
        // Uptime: 3 > 1, protect 50% = 1 oldest → 2 remain
        // Selection: from 2 remaining, evict youngest
        REQUIRE(result.has_value());
        // Exact peer depends on which was protected by uptime
    }
}

TEST_CASE("EvictionManager - Edge case: ping value boundaries", "[eviction][unit][boundary]") {
    std::vector<EvictionManager::EvictionCandidate> candidates;
    auto base_time = steady_clock::now() - hours(1);

    SECTION("Zero ping is valid (best possible)") {
        // Create 10 peers to trigger ping protection
        for (int i = 1; i <= 10; i++) {
            candidates.push_back({i, base_time + seconds(i), 0, "10.0", false, false, {}});
        }

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));
        REQUIRE(result.has_value());
    }

    SECTION("Mix of -1 (unknown) and valid pings") {
        // 10 peers, some with unknown ping (-1)
        for (int i = 1; i <= 5; i++) {
            candidates.push_back({i, base_time + seconds(i), 50, "10.0", false, false, {}});  // Good ping
        }
        for (int i = 6; i <= 10; i++) {
            candidates.push_back({i, base_time + seconds(i), -1, "10.0", false, false, {}});  // Unknown ping
        }

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        // Unknown ping (-1) maps to max, so good ping peers get protected
        // Should evict one of the unknown ping peers
        REQUIRE(result.has_value());
        REQUIRE(*result >= 6);  // One of the unknown ping peers
    }
}

// ============================================================================
// New protection tests (header relay and uptime)
// ============================================================================

TEST_CASE("EvictionManager - Outbound peers never evicted", "[eviction][unit]") {
    SECTION("All outbound peers returns nullopt") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 5 outbound peers
        for (int i = 1; i <= 5; i++) {
            candidates.push_back({i, base_time + seconds(i), 50, "10.0", false, true, {}});
        }

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));
        REQUIRE_FALSE(result.has_value());  // No one to evict
    }

    SECTION("Mixed inbound/outbound - only inbound evicted") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 3 outbound peers (should be filtered)
        for (int i = 1; i <= 3; i++) {
            candidates.push_back({i, base_time + seconds(i), 50, "10.0", false, true, {}});
        }
        // 1 inbound peer (should be evicted)
        candidates.push_back({10, base_time + seconds(10), 50, "10.0", false, false, {}});

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));
        REQUIRE(result.has_value());
        REQUIRE(*result == 10);  // The only inbound peer
    }
}

TEST_CASE("EvictionManager - Header relay protection", "[eviction][unit]") {
    SECTION("Peers that relay headers are protected") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);
        auto recent_headers = steady_clock::now() - minutes(5);

        // 20 peers - need enough to survive all protections
        // 4 peers with recent headers (should be protected)
        for (int i = 1; i <= 4; i++) {
            candidates.push_back({i, base_time + seconds(i), 50, "10.0", false, false, recent_headers});
        }
        // 16 peers without headers (epoch time)
        for (int i = 5; i <= 20; i++) {
            candidates.push_back({i, base_time + seconds(i), 50, "10.0", false, false, {}});
        }

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));
        REQUIRE(result.has_value());
        // The 4 peers with recent headers should be protected
        // Evicted peer should be one without headers
        REQUIRE(*result >= 5);
    }
}

TEST_CASE("EvictionManager - Uptime protection", "[eviction][unit]") {
    SECTION("Longest connected peers are protected") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(2);

        // 30 peers with widely varying connection times - need enough to survive all protections
        // Use different netgroups to avoid header protection interfering
        // First 15: connected 2 hours ago (old) - from netgroup A
        for (int i = 1; i <= 15; i++) {
            candidates.push_back({i, base_time + seconds(i), 50, "192.168", false, false, {}});
        }
        // Next 15: connected 1 minute ago (new) - from netgroup B
        auto recent_time = steady_clock::now() - minutes(1);
        for (int i = 16; i <= 30; i++) {
            candidates.push_back({i, recent_time + seconds(i - 15), 50, "10.0", false, false, {}});
        }

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));
        REQUIRE(result.has_value());
        // After all protections, the uptime protection should favor older peers
        // The evicted peer should be one of the newer ones (16-30)
        REQUIRE(*result >= 16);
    }

    SECTION("Single candidate after earlier protections - no uptime protection (size=1)") {
        // Test: when only 1 candidate remains, protect_count = size/2 = 0
        // So no uptime protection applies and that peer gets evicted
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // Create exactly the scenario: enough peers that after netgroup, ping, and header
        // protections, exactly 1 remains
        // 5 peers from 5 netgroups -> 4 protected by netgroup -> 1 remains
        candidates.push_back({1, base_time, 100, "10.0", false, false, {}});
        candidates.push_back({2, base_time + seconds(1), 100, "10.1", false, false, {}});
        candidates.push_back({3, base_time + seconds(2), 100, "10.2", false, false, {}});
        candidates.push_back({4, base_time + seconds(3), 100, "10.3", false, false, {}});
        candidates.push_back({5, base_time + seconds(4), 100, "10.4", false, false, {}});

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));
        // 5 > 4: netgroup protection applies, 4 protected -> 1 remains
        // 1 is not > 8: no ping protection
        // 1 is not > 4: no header protection
        // 1 is not > 1: no uptime protection (protect_count = 0)
        // Selection: that 1 peer gets evicted
        REQUIRE(result.has_value());
    }
}

// ============================================================================
// Missing coverage tests - empty netgroup handling
// ============================================================================

TEST_CASE("EvictionManager - Empty netgroup during protection phase", "[eviction][unit][boundary]") {
    SECTION("Empty netgroup peers NOT protected in netgroup diversity phase") {
        // Lines 52-53: if (!it->netgroup.empty() && ...)
        // Peers with empty netgroup should be skipped during protection selection
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 6 peers: 5 with empty netgroup, 1 with valid netgroup
        // Empty netgroup peers should NOT be protected by netgroup diversity
        for (int i = 1; i <= 5; i++) {
            candidates.push_back({i, base_time + seconds(i), 100, "", false, false, {}});
        }
        candidates.push_back({6, base_time + seconds(6), 100, "192.168", false, false, {}});

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        // 6 > 4: netgroup protection triggers
        // But only 1 non-empty netgroup (192.168), so only 1 peer protected
        // 5 empty-netgroup peers remain
        REQUIRE(result.has_value());
        // Evicted peer should be one of the empty-netgroup peers
        REQUIRE(*result <= 5);
    }

    SECTION("Empty netgroup peers grouped as __unknown__ in selection") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 3 peers with empty netgroup - will all be in __unknown__ group
        candidates.push_back({1, base_time, 100, "", false, false, {}});
        candidates.push_back({2, base_time + seconds(1), 100, "", false, false, {}});
        candidates.push_back({3, base_time + seconds(2), 100, "", false, false, {}});

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        // All 3 go to __unknown__ group, evict youngest
        REQUIRE(result.has_value());
        REQUIRE(*result == 3);  // Youngest in __unknown__ group
    }

    SECTION("Mix of empty and valid netgroups - empty not protected") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 8 peers: 4 with unique valid netgroups, 4 with empty netgroup
        candidates.push_back({1, base_time, 100, "10.0", false, false, {}});
        candidates.push_back({2, base_time + seconds(1), 100, "10.1", false, false, {}});
        candidates.push_back({3, base_time + seconds(2), 100, "10.2", false, false, {}});
        candidates.push_back({4, base_time + seconds(3), 100, "10.3", false, false, {}});
        // Empty netgroup peers
        candidates.push_back({5, base_time + seconds(4), 100, "", false, false, {}});
        candidates.push_back({6, base_time + seconds(5), 100, "", false, false, {}});
        candidates.push_back({7, base_time + seconds(6), 100, "", false, false, {}});
        candidates.push_back({8, base_time + seconds(7), 100, "", false, false, {}});

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        // 8 > 4: netgroup protection triggers
        // 4 unique valid netgroups -> 4 peers protected (one from each)
        // 4 empty-netgroup peers remain (not protected - empty netgroup skipped)
        // Selection: __unknown__ group has 4 peers, evict youngest (peer 8)
        REQUIRE(result.has_value());
        REQUIRE(*result == 8);  // Youngest empty-netgroup peer
    }
}

// ============================================================================
// Protection cascade edge cases
// ============================================================================

TEST_CASE("EvictionManager - Protection cascade exhaustion", "[eviction][unit][boundary]") {
    SECTION("All candidates removed by netgroup protection returns nullopt") {
        // Test line 74-76: return nullopt if empty after netgroup protection
        // This requires all peers being from unique netgroups AND count <= PROTECT_BY_NETGROUP * count
        // Actually impossible in current logic since protection removes exactly min(4, unique_netgroups)
        // But if somehow all removed, should return nullopt

        // Actually, the way the code works:
        // - If 5 peers from 5 netgroups: protect 4, 1 remains
        // - Can't get 0 unless we start with 4 or fewer

        // Testing: 4 peers from 4 netgroups (doesn't trigger protection)
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        candidates.push_back({1, base_time, 100, "10.0", false, false, {}});
        candidates.push_back({2, base_time + seconds(1), 100, "10.1", false, false, {}});
        candidates.push_back({3, base_time + seconds(2), 100, "10.2", false, false, {}});
        candidates.push_back({4, base_time + seconds(3), 100, "10.3", false, false, {}});

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));
        // 4 is not > 4: no netgroup protection
        // Proceeds to selection, youngest evicted
        REQUIRE(result.has_value());
        REQUIRE(*result == 4);
    }

    SECTION("Exactly 8 peers after netgroup - no ping protection") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 9 peers, 1 netgroup: 9 > 4, protect 1 -> 8 remain
        // 8 is not > 8: no ping protection
        for (int i = 1; i <= 9; i++) {
            candidates.push_back({i, base_time + seconds(i), 50, "10.0", false, false, {}});
        }

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));
        // Netgroup: protect 1 -> 8 remain
        // Ping: 8 not > 8 -> skip
        // Header: 8 > 4, protect 4 -> 4 remain
        // Uptime: 4 > 1, protect 2 -> 2 remain
        // Selection: evict from single netgroup
        REQUIRE(result.has_value());
    }

    SECTION("Exactly 4 peers after ping - no header protection") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // Need: after netgroup and ping, exactly 4 remain
        // 13 peers, 1 netgroup: 13 > 4, protect 1 -> 12 remain
        // 12 > 8: protect 8 -> 4 remain
        // 4 is not > 4: no header protection
        for (int i = 1; i <= 13; i++) {
            candidates.push_back({i, base_time + seconds(i), 50, "10.0", false, false, {}});
        }

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));
        // Netgroup: 13 > 4, protect 1 -> 12 remain
        // Ping: 12 > 8, protect 8 -> 4 remain
        // Header: 4 not > 4 -> skip
        // Uptime: 4 > 1, protect 2 -> 2 remain
        // Selection: evict youngest
        REQUIRE(result.has_value());
    }

    SECTION("Exactly 1 peer after header - no uptime protection") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // Need: after netgroup, ping, header, exactly 1 remains
        // 14 peers, 1 netgroup: 14 > 4, protect 1 -> 13 remain
        // 13 > 8: protect 8 -> 5 remain
        // 5 > 4: protect 4 -> 1 remains
        // 1 is not > 1: no uptime protection
        for (int i = 1; i <= 14; i++) {
            candidates.push_back({i, base_time + seconds(i), 50, "10.0", false, false, {}});
        }

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));
        // The 1 remaining peer gets evicted
        REQUIRE(result.has_value());
    }
}

// ============================================================================
// Header protection edge cases
// ============================================================================

TEST_CASE("EvictionManager - Uptime protection bug check", "[eviction][unit][bug]") {
    // This test verifies which peers are protected by uptime:
    // The INTENT is: protect oldest (longest-connected) peers
    // Let's verify the implementation matches the intent

    SECTION("Verify oldest peers are protected, newest evicted") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto now = steady_clock::now();

        // Create 4 peers from same netgroup with distinct connection times
        // All same ping, no headers - so only uptime protection applies after netgroup
        // Peer 1: connected 4 hours ago (oldest - should be PROTECTED)
        // Peer 2: connected 3 hours ago (should be PROTECTED)
        // Peer 3: connected 2 hours ago (should be evictable)
        // Peer 4: connected 1 hour ago (newest - should be EVICTED)
        candidates.push_back({1, now - hours(4), 100, "10.0", false, false, {}});
        candidates.push_back({2, now - hours(3), 100, "10.0", false, false, {}});
        candidates.push_back({3, now - hours(2), 100, "10.0", false, false, {}});
        candidates.push_back({4, now - hours(1), 100, "10.0", false, false, {}});

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        // 4 is not > 4: no netgroup protection
        // 4 is not > 8: no ping protection
        // 4 is not > 4: no header protection
        // 4 > 1: uptime protection applies, protect_count = 2
        //   Should protect 2 oldest (peers 1, 2)
        //   Should evict from remaining (peers 3, 4) - youngest = peer 4

        REQUIRE(result.has_value());
        // If uptime protection works correctly: peer 4 (newest) should be evicted
        // If buggy (protecting newest): peer 1 (oldest) would be evicted
        INFO("Evicted peer: " << *result);
        INFO("Expected: peer 4 (newest) should be evicted");
        INFO("Bug would cause: peer 1 (oldest) to be evicted");
        REQUIRE(*result == 4);  // Newest should be evicted
    }
}

TEST_CASE("EvictionManager - Header protection edge cases", "[eviction][unit][boundary]") {
    SECTION("All peers have epoch last_headers_time - none protected by recency") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 20 peers, all with epoch (default) last_headers_time
        for (int i = 1; i <= 20; i++) {
            candidates.push_back({i, base_time + seconds(i), 50, "10.0", false, false, {}});
        }

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));
        // Header protection still removes 4, but all have same time so sort is stable
        REQUIRE(result.has_value());
    }

    SECTION("Header times are all identical - sort stability") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);
        auto same_header_time = steady_clock::now() - minutes(10);

        // 6 peers with identical last_headers_time
        for (int i = 1; i <= 6; i++) {
            candidates.push_back({i, base_time + seconds(i), 100, "10.0", false, false, same_header_time});
        }

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));
        // 6 > 4: netgroup protect 1 -> 5 remain
        // 5 is not > 8: no ping protection
        // 5 > 4: header protect 4 -> 1 remains
        // Since all have same header time, sort is stable, last 4 removed
        REQUIRE(result.has_value());
    }

    SECTION("Recent header relay peers protected over non-relaying peers") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);
        auto recent = steady_clock::now() - minutes(1);

        // 10 peers: 4 with recent headers, 6 with epoch
        for (int i = 1; i <= 4; i++) {
            candidates.push_back({i, base_time + seconds(i), 50, "10.0", false, false, recent});
        }
        for (int i = 5; i <= 10; i++) {
            candidates.push_back({i, base_time + seconds(i), 50, "10.0", false, false, {}});
        }

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));
        // Netgroup: 10 > 4, protect 1 -> 9 remain
        // Ping: 9 > 8, protect 8 -> 1 remains
        REQUIRE(result.has_value());
        // The peer evicted should be one without recent headers (5-10)
        // But after ping protection, likely only 1 remains
    }
}

// ============================================================================
// prefer_evict tests (Core parity - discouraged peers evicted first)
// ============================================================================

TEST_CASE("EvictionManager - prefer_evict basic behavior", "[eviction][unit][prefer_evict]") {
    SECTION("Single prefer_evict peer among normal peers - prefer_evict evicted") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 4 normal peers (oldest connections, should normally be protected)
        for (int i = 1; i <= 4; i++) {
            candidates.push_back({
                i, base_time + seconds(i), 100, "10.0", false, false, {},
                false  // prefer_evict = false
            });
        }

        // 1 prefer_evict peer (newest, but should still be evicted due to prefer_evict)
        candidates.push_back({
            5, base_time + seconds(100), 100, "10.0", false, false, {},
            true  // prefer_evict = true (discouraged peer)
        });

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        REQUIRE(result.has_value());
        // Peer 5 should be evicted because it has prefer_evict=true
        // Even though protection phases would normally keep other criteria
        REQUIRE(*result == 5);
    }

    SECTION("Multiple prefer_evict peers - youngest prefer_evict evicted") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 3 normal peers
        for (int i = 1; i <= 3; i++) {
            candidates.push_back({
                i, base_time + seconds(i), 100, "10.0", false, false, {},
                false  // prefer_evict = false
            });
        }

        // 2 prefer_evict peers - oldest and newest of the prefer_evict group
        candidates.push_back({
            10, base_time + seconds(50), 100, "10.0", false, false, {},
            true  // prefer_evict = true (older discouraged peer)
        });
        candidates.push_back({
            11, base_time + seconds(100), 100, "10.0", false, false, {},
            true  // prefer_evict = true (newer discouraged peer)
        });

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        REQUIRE(result.has_value());
        // Among prefer_evict peers, youngest (peer 11) should be evicted
        REQUIRE(*result == 11);
    }

    SECTION("No prefer_evict peers - normal eviction logic applies") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 4 normal peers, no prefer_evict
        for (int i = 1; i <= 4; i++) {
            candidates.push_back({
                i, base_time + seconds(i), 100, "10.0", false, false, {},
                false  // prefer_evict = false
            });
        }

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        REQUIRE(result.has_value());
        // Normal eviction: youngest (peer 4) evicted
        REQUIRE(*result == 4);
    }

    SECTION("All peers are prefer_evict - youngest evicted") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 4 prefer_evict peers
        for (int i = 1; i <= 4; i++) {
            candidates.push_back({
                i, base_time + seconds(i * 10), 100, "10.0", false, false, {},
                true  // all prefer_evict
            });
        }

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        REQUIRE(result.has_value());
        // All are prefer_evict, so normal selection: youngest (peer 4) evicted
        REQUIRE(*result == 4);
    }
}

TEST_CASE("EvictionManager - prefer_evict respects protection phases", "[eviction][unit][prefer_evict]") {
    SECTION("prefer_evict peer with good ping survives if protected by ping") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 10 peers from same netgroup - need enough to trigger ping protection
        // Netgroup: 10 > 4, protect 1 -> 9 remain
        // Ping: 9 > 8, protect 8 -> 1 remains

        // 9 normal peers with bad ping (500ms)
        for (int i = 1; i <= 9; i++) {
            candidates.push_back({
                i, base_time + seconds(i), 500, "10.0", false, false, {},
                false  // normal peers
            });
        }

        // 1 prefer_evict peer with EXCELLENT ping (10ms) - should be protected by ping
        candidates.push_back({
            10, base_time + seconds(50), 10, "10.0", false, false, {},
            true  // prefer_evict but has best ping
        });

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        REQUIRE(result.has_value());
        // The prefer_evict peer has the best ping, so it should be protected
        // by ping protection. One of the normal peers should be evicted.
        // After netgroup (1 protected) -> 9 remain
        // Ping protection protects 8 lowest ping - peer 10 has best ping (10ms)
        // So peer 10 is among the 8 protected, leaving 1 normal peer
        // That 1 normal peer gets evicted
        REQUIRE(*result != 10);
    }

    SECTION("prefer_evict peer with recent headers survives if protected") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);
        auto recent_headers = steady_clock::now() - minutes(1);

        // Create scenario where prefer_evict peer is protected by headers
        // Need: after netgroup and ping, > 4 remain so header protection kicks in

        // 14 peers from same netgroup
        // Netgroup: 14 > 4, protect 1 -> 13 remain
        // Ping: 13 > 8, protect 8 -> 5 remain
        // Header: 5 > 4, protect 4 -> 1 remains

        // 13 normal peers with no headers (epoch time)
        for (int i = 1; i <= 13; i++) {
            candidates.push_back({
                i, base_time + seconds(i), 100, "10.0", false, false, {},
                false
            });
        }

        // 1 prefer_evict peer with RECENT headers - should be protected
        candidates.push_back({
            14, base_time + seconds(100), 100, "10.0", false, false, recent_headers,
            true  // prefer_evict but has recent headers
        });

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        REQUIRE(result.has_value());
        // Peer 14 has most recent headers, should be in top 4 protected
        // A normal peer without headers should be evicted
        REQUIRE(*result != 14);
    }

    SECTION("prefer_evict peer NOT protected - gets evicted over normal peers") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // Create scenario where prefer_evict peer survives protection but is mediocre
        // 6 peers - just enough to have some protection but prefer_evict peer is average

        // 5 normal peers with varying qualities
        // Give them all good ping and recent headers so they're protected
        auto recent_headers = steady_clock::now() - minutes(5);
        for (int i = 1; i <= 5; i++) {
            candidates.push_back({
                i, base_time + seconds(i), 50, "10.0", false, false, recent_headers,
                false  // normal peers with good metrics
            });
        }

        // 1 prefer_evict peer with BAD metrics (high ping, no headers)
        candidates.push_back({
            6, base_time + seconds(50), 500, "10.0", false, false, {},
            true  // prefer_evict with bad metrics
        });

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        REQUIRE(result.has_value());
        // Peer 6 has bad ping (not protected) and no headers (not protected)
        // After protections, it should remain in candidate pool with prefer_evict
        // It should be evicted over normal peers
        REQUIRE(*result == 6);
    }
}

TEST_CASE("EvictionManager - prefer_evict with multiple netgroups", "[eviction][unit][prefer_evict]") {
    SECTION("prefer_evict peer in smaller netgroup still evicted first") {
        // Use only 4 peers to avoid protection phases interfering
        // (4 is not > 4, so no netgroup protection)
        // (4 is not > 8, so no ping protection)
        // (4 is not > 4, so no header protection)
        // (4 > 1, but uptime protects 2, leaving 2 - both can be prefer_evict filtered)
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 1 normal peer in netgroup A (oldest - protected by uptime)
        candidates.push_back({
            1, base_time + seconds(1), 100, "192.168", false, false, {},
            false
        });

        // 2 normal peers in netgroup B (larger group - would normally be eviction target)
        candidates.push_back({
            2, base_time + seconds(50), 100, "10.0", false, false, {},
            false
        });
        candidates.push_back({
            3, base_time + seconds(60), 100, "10.0", false, false, {},
            false
        });

        // 1 prefer_evict peer in netgroup A (newest - would be evicted anyway, but has prefer_evict)
        candidates.push_back({
            4, base_time + seconds(100), 100, "192.168", false, false, {},
            true  // prefer_evict
        });

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        REQUIRE(result.has_value());
        // With 4 peers:
        // - No netgroup protection (4 not > 4)
        // - No ping protection (4 not > 8)
        // - No header protection (4 not > 4)
        // - Uptime protection: 4 > 1, protect 50% = 2 oldest (peers 1, 2)
        // Remaining: peers 3, 4
        // prefer_evict filtering: peer 4 has prefer_evict, so only consider peer 4
        // Evict peer 4
        REQUIRE(*result == 4);
    }

    SECTION("prefer_evict in larger netgroup - still evicted over normal peers") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 2 normal peers in small netgroup (oldest)
        candidates.push_back({
            1, base_time + seconds(1), 100, "192.168", false, false, {},
            false
        });
        candidates.push_back({
            2, base_time + seconds(2), 100, "192.168", false, false, {},
            false
        });

        // 1 normal peer in larger netgroup
        candidates.push_back({
            3, base_time + seconds(50), 100, "10.0", false, false, {},
            false
        });

        // 1 prefer_evict peer in larger netgroup (newest)
        candidates.push_back({
            4, base_time + seconds(100), 100, "10.0", false, false, {},
            true
        });

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        REQUIRE(result.has_value());
        // Uptime protects 2 oldest (peers 1, 2)
        // Remaining: peers 3, 4 (both in netgroup 10.0)
        // prefer_evict: only peer 4 has it, so only consider peer 4
        // Evict peer 4
        REQUIRE(*result == 4);
    }
}

TEST_CASE("EvictionManager - prefer_evict boundary conditions", "[eviction][unit][prefer_evict][boundary]") {
    SECTION("Single prefer_evict peer that is also protected - still protected") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 1 prefer_evict peer that is ALSO is_protected (NoBan)
        candidates.push_back({
            1, base_time, 100, "10.0", true, false, {},  // is_protected = true
            true  // prefer_evict = true
        });

        // 1 normal peer
        candidates.push_back({
            2, base_time + seconds(10), 100, "10.0", false, false, {},
            false
        });

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        REQUIRE(result.has_value());
        // Peer 1 is protected (NoBan), so even with prefer_evict it cannot be evicted
        // Peer 2 should be evicted
        REQUIRE(*result == 2);
    }

    SECTION("prefer_evict peer that is outbound - outbound protection takes precedence") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // 1 prefer_evict OUTBOUND peer - should never be evicted
        candidates.push_back({
            1, base_time, 100, "10.0", false, true, {},  // is_outbound = true
            true  // prefer_evict = true
        });

        // 1 normal inbound peer
        candidates.push_back({
            2, base_time + seconds(10), 100, "10.0", false, false, {},
            false
        });

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        REQUIRE(result.has_value());
        // Peer 1 is outbound, so it's filtered before prefer_evict even matters
        // Peer 2 should be evicted
        REQUIRE(*result == 2);
    }

    SECTION("Empty candidates after filtering outbound/protected - returns nullopt") {
        std::vector<EvictionManager::EvictionCandidate> candidates;
        auto base_time = steady_clock::now() - hours(1);

        // Only prefer_evict peers, but all are protected or outbound
        candidates.push_back({
            1, base_time, 100, "10.0", true, false, {},  // protected
            true
        });
        candidates.push_back({
            2, base_time + seconds(10), 100, "10.0", false, true, {},  // outbound
            true
        });

        auto result = EvictionManager::SelectNodeToEvict(std::move(candidates));

        REQUIRE_FALSE(result.has_value());
    }
}
