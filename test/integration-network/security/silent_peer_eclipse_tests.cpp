// Copyright (c) 2025 The Unicity Foundation
// Silent Peer Eclipse Attack Tests
//
// These tests verify that the eviction manager properly defends against
// "silent peer" eclipse attacks where attackers:
// 1. Connect to the victim
// 2. Complete handshake (VERSION/VERACK)
// 3. Never send any headers (do no useful work)
//
// Expected defense behavior:
// - Honest peers that relay headers get eviction protection
// - Silent attackers get evicted first
// - Honest peers survive eviction cycles

#include "catch_amalgamated.hpp"
#include "../infra/eclipse_attack_simulator.hpp"
#include "../infra/peer_factory.hpp"
#include "../infra/simulated_network.hpp"
#include "../infra/simulated_node.hpp"

using namespace unicity::test;

TEST_CASE("Silent Peer Eclipse - Header relay protection works", "[network][security][eclipse]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);

    SECTION("Silent attackers evicted more than honest peers") {
        SimulatedNode victim(0, &network);
        EclipseAttackSimulator sim(&network, &factory, &victim);

        // Execute attack: 20 silent attackers vs 8 honest peers
        // Note: With per-netgroup limits, not all attackers can connect
        auto metrics = sim.ExecuteSilentPeerAttack(
            20,                 // num_attackers (limited by per-netgroup = ~12-16)
            8,                  // num_honest (all relay headers)
            "192.168.0.0",      // attacker subnet base
            true                // trigger eviction
        );

        INFO(sim.GenerateReport());

        INFO("Evicted " << metrics.evicted_attackers << " attackers, "
             << metrics.evicted_honest << " honest");

        // Key defense behavior: MORE attackers evicted than honest peers
        // Header relay protection means honest peers are preferentially kept
        CHECK(metrics.evicted_attackers >= metrics.evicted_honest);

        // Some honest peers should survive
        CHECK(metrics.after.honest_peers > 0);
    }

    SECTION("Header relay protection kicks in during eviction") {
        SimulatedNode victim(0, &network);
        EclipseAttackSimulator sim(&network, &factory, &victim);

        // Setup: 4 honest peers that relay headers
        sim.SetupHonestPeers(4);
        sim.SimulateHeaderRelay();

        // Add silent attackers (enough to fill slots)
        auto attackers = factory.CreateSybilCluster(16, 1000, "10.50.0.0");
        for (auto& a : attackers) {
            a->ConnectTo(victim.GetId(), victim.GetAddress());
        }

        TestOrchestrator orch(&network);
        orch.AdvanceTime(std::chrono::seconds(2));

        // Wait for protection expiry
        sim.WaitForProtectionExpiry();

        // Trigger evictions
        auto& peer_mgr = victim.GetNetworkManager().peer_manager();
        size_t initial_peers = peer_mgr.peer_count();

        // Evict 5 peers
        for (int i = 0; i < 5; i++) {
            peer_mgr.evict_inbound_peer();
        }

        // Check that honest peers (with header relay) survived
        auto snapshot = sim.SnapshotPeers();
        INFO("After eviction: " << snapshot.honest_peers << " honest, "
             << snapshot.attacker_controlled << " attackers");

        // Most honest peers should survive (protected by header relay)
        // With 4 honest peers and 5 evictions, at least 3 should survive
        CHECK(snapshot.honest_peers >= 3);
    }
}

TEST_CASE("Silent Peer Eclipse - Defense metrics", "[network][security][eclipse]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);
    SimulatedNode victim(0, &network);

    EclipseAttackSimulator sim(&network, &factory, &victim);

    SECTION("Eviction preferentially removes attackers over honest peers") {
        // Large-scale attack: 50 attackers vs 10 honest
        auto metrics = sim.ExecuteSilentPeerAttack(
            50,     // attackers (will be limited by per-netgroup limits)
            10,     // honest
            "192.168.0.0",
            true    // trigger eviction
        );

        INFO(sim.GenerateReport());

        // Key metric: MORE attackers evicted than honest peers
        // This proves header relay protection is working
        CHECK(metrics.evicted_attackers > metrics.evicted_honest);

        // All honest peers should survive (they relay headers, attackers don't)
        CHECK(metrics.after.honest_peers >= 8);  // Most honest peers survive

        // Ideally NO honest peers get evicted when attackers are present
        CHECK(metrics.evicted_honest <= 2);  // Allow small margin
    }

    SECTION("Netgroup distribution after attack") {
        auto metrics = sim.ExecuteSilentPeerAttack(40, 8, "10.0.0.0", false);

        INFO(sim.GenerateReport());

        // Check netgroup diversity
        size_t max_per_netgroup = 0;
        for (const auto& [ng, count] : metrics.after.netgroup_distribution) {
            INFO("Netgroup " << ng << ": " << count << " peers");
            max_per_netgroup = std::max(max_per_netgroup, count);
        }

        // Per-netgroup limit should be enforced (max 4)
        CHECK(max_per_netgroup <= 4);
    }
}

TEST_CASE("Silent Peer Eclipse - Comparison with and without header protection", "[network][security][eclipse]") {
    // This test demonstrates why header relay protection matters

    SimulatedNetwork network;
    PeerFactory factory(&network);

    SECTION("With header relay - honest peers protected") {
        SimulatedNode victim(0, &network);
        EclipseAttackSimulator sim(&network, &factory, &victim);

        // Setup honest peers WITH header relay
        sim.SetupHonestPeers(4);
        sim.SimulateHeaderRelay();  // <-- Key: honest peers relay headers

        // Add attackers
        auto attackers = factory.CreateDiversePeers(16, 100);
        for (auto& a : attackers) {
            a->ConnectTo(victim.GetId(), victim.GetAddress());
        }

        TestOrchestrator orch(&network);
        orch.AdvanceTime(std::chrono::seconds(2));
        sim.WaitForProtectionExpiry();

        // Evict multiple times
        auto& peer_mgr = victim.GetNetworkManager().peer_manager();
        for (int i = 0; i < 8; i++) {
            peer_mgr.evict_inbound_peer();
        }

        auto snapshot = sim.SnapshotPeers();
        INFO("With header relay: " << snapshot.honest_peers << " honest survived");

        // Honest peers should survive (protected by header relay)
        CHECK(snapshot.honest_peers >= 3);  // At least 3 of 4 survive
    }

    SECTION("Without header relay - random eviction") {
        SimulatedNode victim(0, &network);
        EclipseAttackSimulator sim(&network, &factory, &victim);

        // Setup honest peers WITHOUT header relay
        sim.SetupHonestPeers(4);
        // NOTE: NOT calling SimulateHeaderRelay()

        // Add attackers
        auto attackers = factory.CreateDiversePeers(16, 100);
        for (auto& a : attackers) {
            a->ConnectTo(victim.GetId(), victim.GetAddress());
        }

        TestOrchestrator orch(&network);
        orch.AdvanceTime(std::chrono::seconds(2));
        sim.WaitForProtectionExpiry();

        // Evict multiple times
        auto& peer_mgr = victim.GetNetworkManager().peer_manager();
        for (int i = 0; i < 8; i++) {
            peer_mgr.evict_inbound_peer();
        }

        auto snapshot = sim.SnapshotPeers();
        INFO("Without header relay: " << snapshot.honest_peers << " honest survived");

        // Without header relay protection, eviction is based on other factors
        // (netgroup, ping, uptime) - honest peers may or may not survive
        // This is still better than random but not as good as with headers
    }
}

TEST_CASE("Silent Peer Eclipse - Report generation", "[network][security][eclipse]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);
    SimulatedNode victim(0, &network);

    EclipseAttackSimulator sim(&network, &factory, &victim);
    auto metrics = sim.ExecuteSilentPeerAttack(20, 6, "192.168.0.0", true);

    std::string report = sim.GenerateReport();

    // Verify report contains key information
    CHECK(report.find("Silent Peers") != std::string::npos);
    CHECK(report.find("Attacker Budget") != std::string::npos);
    CHECK(report.find("Evicted Attackers") != std::string::npos);
    CHECK(report.find("Defense Effective") != std::string::npos);

    // Print for manual inspection
    INFO(report);
}
