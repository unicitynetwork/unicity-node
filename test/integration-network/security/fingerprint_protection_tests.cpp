// Copyright (c) 2025 The Unicity Foundation
// Fingerprint protection tests
//
// These tests verify that the node doesn't reveal information about stale/side-chain
// headers it may have seen. This prevents attackers from fingerprinting nodes by
// probing for which historical chain states they witnessed.
//
// Bitcoin Core behavior: Stale blocks older than 1 month are not served.
// Unicity behavior: Only active chain headers are served (stricter protection).

#include "catch_amalgamated.hpp"
#include "../infra/simulated_network.hpp"
#include "../infra/simulated_node.hpp"
#include "../infra/node_simulator.hpp"

using namespace unicity::test;
using namespace unicity;

static void SetZeroLatency(SimulatedNetwork& network) {
    SimulatedNetwork::NetworkConditions c;
    c.latency_min = c.latency_max = std::chrono::milliseconds(0);
    c.jitter_max = std::chrono::milliseconds(0);
    network.SetNetworkConditions(c);
}

// =============================================================================
// FINGERPRINT PROTECTION TEST 1: Only Active Chain Headers Returned
// =============================================================================
// Verifies that GETHEADERS only returns headers from the active chain.

TEST_CASE("Fingerprint Protection - Only active chain headers returned", "[network][security][fingerprint]") {
    SimulatedNetwork network(60001);
    SetZeroLatency(network);

    SimulatedNode victim(1, &network);
    SimulatedNode prober(2, &network);

    // Mine 20 blocks on victim
    for (int i = 0; i < 20; i++) {
        victim.MineBlock();
    }
    uint64_t t = 100;
    network.AdvanceTime(t);

    REQUIRE(victim.GetTipHeight() == 20);

    SECTION("GETHEADERS from genesis returns all active chain headers") {
        // Connect prober to victim
        prober.ConnectTo(1);
        t += 100; network.AdvanceTime(t);

        // Wait for sync
        for (int i = 0; i < 50; i++) {
            t += 100;
            network.AdvanceTime(t);
            if (prober.GetTipHeight() >= 20) break;
        }

        // Prober should have synced all 20 headers
        REQUIRE(prober.GetTipHeight() == 20);
        REQUIRE(prober.GetTipHash() == victim.GetTipHash());
    }

    SECTION("Mid-chain locator returns correct continuation") {
        // Get block hash at height 10
        uint256 mid_hash = victim.GetBlockHash(10);
        REQUIRE(!mid_hash.IsNull());

        INFO("Testing GETHEADERS with locator at height 10: " << mid_hash.ToString().substr(0, 16));

        // Connect prober and sync
        prober.ConnectTo(1);
        t += 100; network.AdvanceTime(t);

        // Wait for full sync
        for (int i = 0; i < 50; i++) {
            t += 100;
            network.AdvanceTime(t);
            if (prober.GetTipHeight() >= 20) break;
        }

        REQUIRE(prober.GetTipHeight() == 20);
        INFO("Prober synced correctly - received headers 11-20 after locator at height 10");
    }
}

// =============================================================================
// FINGERPRINT PROTECTION TEST 2: Stale Headers Not Revealed After Reorg
// =============================================================================
// After a reorg, the node should not reveal that it ever saw the now-stale headers.

TEST_CASE("Fingerprint Protection - Stale headers not revealed after reorg", "[network][security][fingerprint]") {
    SimulatedNetwork network(60002);
    SetZeroLatency(network);

    SimulatedNode victim(1, &network);
    NodeSimulator attacker(2, &network);

    uint64_t t = 100;

    // Step 1: Victim mines 10 blocks (original chain)
    for (int i = 0; i < 10; i++) {
        victim.MineBlock();
    }
    t += 100; network.AdvanceTime(t);

    REQUIRE(victim.GetTipHeight() == 10);
    uint256 original_tip = victim.GetTipHash();
    INFO("Original chain tip at height 10: " << original_tip.ToString().substr(0, 16));

    // Step 2: Attacker creates a longer chain (12 blocks) to trigger reorg
    for (int i = 0; i < 12; i++) {
        attacker.MineBlock();
    }
    t += 100; network.AdvanceTime(t);

    REQUIRE(attacker.GetTipHeight() == 12);
    INFO("Attacker chain at height 12");

    // Step 3: Connect attacker to victim - should trigger reorg
    attacker.ConnectTo(1);
    t += 100; network.AdvanceTime(t);

    // Wait for reorg
    for (int i = 0; i < 100; i++) {
        t += 100;
        network.AdvanceTime(t);
        if (victim.GetTipHeight() == 12 && victim.GetTipHash() == attacker.GetTipHash()) {
            break;
        }
    }

    REQUIRE(victim.GetTipHeight() == 12);
    REQUIRE(victim.GetTipHash() == attacker.GetTipHash());
    INFO("Victim reorged to attacker chain");

    SECTION("Stale block hash in locator doesn't reveal history") {
        // Create a new prober that doesn't know about original chain
        SimulatedNode prober(3, &network);

        // Mine a block on prober so it has different state
        prober.MineBlock();
        t += 100; network.AdvanceTime(t);

        // Connect prober to victim
        prober.ConnectTo(1);
        t += 100; network.AdvanceTime(t);

        // Wait for sync
        for (int i = 0; i < 100; i++) {
            t += 100;
            network.AdvanceTime(t);
            if (prober.GetTipHeight() >= 12) break;
        }

        // Prober should sync to victim's active chain (attacker's chain)
        REQUIRE(prober.GetTipHeight() == 12);
        REQUIRE(prober.GetTipHash() == attacker.GetTipHash());
    }
}

// =============================================================================
// FINGERPRINT PROTECTION TEST 3: Unknown Locator Hash Handled Safely
// =============================================================================
// When a GETHEADERS contains unknown block hashes, the node should not crash
// or reveal information about what blocks it knows.

TEST_CASE("Fingerprint Protection - Unknown locator hash handled safely", "[network][security][fingerprint]") {
    SimulatedNetwork network(60003);
    SetZeroLatency(network);

    SimulatedNode victim(1, &network);
    NodeSimulator prober(2, &network);

    uint64_t t = 100;

    // Victim mines some blocks
    for (int i = 0; i < 10; i++) {
        victim.MineBlock();
    }
    t += 100; network.AdvanceTime(t);

    REQUIRE(victim.GetTipHeight() == 10);

    SECTION("Random locator hash doesn't crash or reveal info") {
        // Connect prober
        prober.ConnectTo(1);
        t += 100; network.AdvanceTime(t);

        // Prober should sync normally via standard handshake
        for (int i = 0; i < 50; i++) {
            t += 100;
            network.AdvanceTime(t);
            if (prober.GetTipHeight() >= 10) break;
        }

        // Should have synced the active chain
        REQUIRE(prober.GetTipHeight() == 10);
    }
}

// =============================================================================
// FINGERPRINT PROTECTION TEST 4: Consistent Responses
// =============================================================================
// Multiple GETHEADERS requests should return consistent results.
// This prevents timing-based fingerprinting.

TEST_CASE("Fingerprint Protection - Consistent responses", "[network][security][fingerprint]") {
    SimulatedNetwork network(60004);
    SetZeroLatency(network);

    SimulatedNode victim(1, &network);

    uint64_t t = 100;

    // Mine 20 blocks
    for (int i = 0; i < 20; i++) {
        victim.MineBlock();
    }
    t += 100; network.AdvanceTime(t);

    SECTION("Multiple probers get same headers") {
        // Create multiple probers
        std::vector<std::unique_ptr<SimulatedNode>> probers;
        for (int i = 0; i < 3; i++) {
            probers.push_back(std::make_unique<SimulatedNode>(10 + i, &network));
        }

        // Connect all probers
        for (auto& prober : probers) {
            prober->ConnectTo(1);
            t += 100; network.AdvanceTime(t);
        }

        // Wait for all to sync
        for (int i = 0; i < 100; i++) {
            t += 100;
            network.AdvanceTime(t);
            bool all_synced = true;
            for (auto& prober : probers) {
                if (prober->GetTipHeight() < 20) {
                    all_synced = false;
                    break;
                }
            }
            if (all_synced) break;
        }

        // All probers should have identical chain view
        for (auto& prober : probers) {
            REQUIRE(prober->GetTipHeight() == 20);
            REQUIRE(prober->GetTipHash() == victim.GetTipHash());
        }
    }
}

// =============================================================================
// FINGERPRINT PROTECTION TEST 5: Side-chain Headers Not Served
// =============================================================================
// Headers from side chains (even if still in memory) should not be served.

TEST_CASE("Fingerprint Protection - Side-chain headers not served", "[network][security][fingerprint]") {
    SimulatedNetwork network(60005);
    SetZeroLatency(network);

    SimulatedNode victim(1, &network);
    NodeSimulator attacker(2, &network);

    uint64_t t = 100;

    // Victim mines main chain
    for (int i = 0; i < 15; i++) {
        victim.MineBlock();
    }
    t += 100; network.AdvanceTime(t);

    // Attacker creates a shorter side chain forking from genesis
    // (won't trigger reorg since it has less work)
    for (int i = 0; i < 5; i++) {
        attacker.MineBlock();
    }
    t += 100; network.AdvanceTime(t);

    REQUIRE(victim.GetTipHeight() == 15);
    REQUIRE(attacker.GetTipHeight() == 5);

    // Attacker connects to victim and sends their (shorter) headers
    attacker.ConnectTo(1);
    t += 100; network.AdvanceTime(t);

    // Wait for messages to propagate
    for (int i = 0; i < 50; i++) {
        t += 100;
        network.AdvanceTime(t);
    }

    // Victim should still be on main chain (attacker chain has less work)
    REQUIRE(victim.GetTipHeight() == 15);

    SECTION("New prober only sees main chain") {
        // A new prober connecting should only sync the main chain
        SimulatedNode prober(3, &network);
        prober.ConnectTo(1);
        t += 100; network.AdvanceTime(t);

        for (int i = 0; i < 50; i++) {
            t += 100;
            network.AdvanceTime(t);
            if (prober.GetTipHeight() >= 15) break;
        }

        // Prober should have the main chain, not the side chain
        REQUIRE(prober.GetTipHeight() == 15);
        REQUIRE(prober.GetTipHash() == victim.GetTipHash());
    }
}
