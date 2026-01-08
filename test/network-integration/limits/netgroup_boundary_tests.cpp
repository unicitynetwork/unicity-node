// Copyright (c) 2025 The Unicity Foundation
// Boundary condition tests for per-netgroup limits
//
// These tests verify exact boundary conditions for security-critical limits,
// ensuring limits are enforced precisely at the threshold.

#include "catch_amalgamated.hpp"
#include "../infra/simulated_network.hpp"
#include "../infra/simulated_node.hpp"
#include "../infra/peer_factory.hpp"
#include "../test_orchestrator.hpp"
#include "network/peer_lifecycle_manager.hpp"

using namespace unicity::test;
using namespace unicity;

// Constants from peer_lifecycle_manager.hpp
// MAX_INBOUND_PER_NETGROUP = 4

TEST_CASE("Per-netgroup inbound - exact boundary at limit", "[network][limits][netgroup][boundary][unit]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    auto victim = factory.CreateNode(1);

    SECTION("Exactly 4 from same /16 should all succeed") {
        // Create exactly 4 attackers from same /16
        // Note: start_id must not conflict with victim (ID 1)
        auto attackers = factory.CreateSybilCluster(4, 10, "8.50.0.0");

        REQUIRE(PeerFactory::AllSameNetgroup(attackers));

        // All 4 should connect successfully
        for (auto& attacker : attackers) {
            attacker->ConnectTo(victim->GetId(), victim->GetAddress());
        }

        REQUIRE(orch.WaitForPeerCount(*victim, 4));
        REQUIRE(victim->GetInboundPeerCount() == 4);
    }

    SECTION("5th from same /16 should be rejected") {
        // Create 5 attackers from same /16
        auto attackers = factory.CreateSybilCluster(5, 10, "8.50.0.0");

        // Connect all 5
        for (auto& attacker : attackers) {
            attacker->ConnectTo(victim->GetId(), victim->GetAddress());
        }

        // Wait for connections to settle
        orch.AdvanceTime(std::chrono::milliseconds(500));

        // Should have exactly 4 (5th rejected)
        INFO("Inbound peer count: " << victim->GetInboundPeerCount());
        REQUIRE(victim->GetInboundPeerCount() == 4);
    }

    SECTION("4th peer at boundary - accept, then 5th rejected") {
        auto attackers = factory.CreateSybilCluster(5, 10, "8.60.0.0");

        // Connect first 3
        for (int i = 0; i < 3; i++) {
            attackers[i]->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        REQUIRE(orch.WaitForPeerCount(*victim, 3));
        REQUIRE(victim->GetInboundPeerCount() == 3);

        // Connect 4th - should succeed (at boundary)
        attackers[3]->ConnectTo(victim->GetId(), victim->GetAddress());
        REQUIRE(orch.WaitForPeerCount(*victim, 4));
        REQUIRE(victim->GetInboundPeerCount() == 4);

        // Connect 5th - should be rejected (beyond boundary)
        attackers[4]->ConnectTo(victim->GetId(), victim->GetAddress());
        orch.AdvanceTime(std::chrono::milliseconds(500));

        // Still exactly 4
        REQUIRE(victim->GetInboundPeerCount() == 4);
    }
}

TEST_CASE("Per-netgroup inbound - multiple netgroups at independent limits", "[network][limits][netgroup][boundary][unit]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    auto victim = factory.CreateNode(1);

    SECTION("Each /16 has independent limit of 4") {
        // Fill 4 slots from 8.1.x.x
        auto group1 = factory.CreateSybilCluster(4, 10, "8.1.0.0");
        for (auto& peer : group1) {
            peer->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        REQUIRE(orch.WaitForPeerCount(*victim, 4));

        // Fill 4 slots from 8.2.x.x (different /16)
        auto group2 = factory.CreateSybilCluster(4, 20, "8.2.0.0");
        for (auto& peer : group2) {
            peer->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        REQUIRE(orch.WaitForPeerCount(*victim, 8));

        // Verify both netgroups at limit
        REQUIRE(victim->GetInboundPeerCount() == 8);

        // 5th from 8.1.x.x should fail
        auto extra1 = factory.CreateSybilCluster(1, 30, "8.1.0.0");
        extra1[0]->ConnectTo(victim->GetId(), victim->GetAddress());
        orch.AdvanceTime(std::chrono::milliseconds(500));
        REQUIRE(victim->GetInboundPeerCount() == 8);

        // 5th from 8.2.x.x should fail
        auto extra2 = factory.CreateSybilCluster(1, 31, "8.2.0.0");
        extra2[0]->ConnectTo(victim->GetId(), victim->GetAddress());
        orch.AdvanceTime(std::chrono::milliseconds(500));
        REQUIRE(victim->GetInboundPeerCount() == 8);

        // But 1st from 8.3.x.x should succeed (new netgroup)
        auto group3 = factory.CreateSybilCluster(1, 40, "8.3.0.0");
        group3[0]->ConnectTo(victim->GetId(), victim->GetAddress());
        REQUIRE(orch.WaitForPeerCount(*victim, 9));
        REQUIRE(victim->GetInboundPeerCount() == 9);
    }
}

TEST_CASE("Per-netgroup inbound - diverse peers unaffected by attacker limit", "[network][limits][netgroup][boundary][unit]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    auto victim = factory.CreateNode(1);

    SECTION("Honest peers from diverse netgroups connect despite attacker saturation") {
        // Attacker fills their /16 limit (4 from 8.99.x.x)
        auto attackers = factory.CreateSybilCluster(4, 10, "8.99.0.0");
        for (auto& attacker : attackers) {
            attacker->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        REQUIRE(orch.WaitForPeerCount(*victim, 4));

        // More attackers from same /16 should fail
        auto more_attackers = factory.CreateSybilCluster(4, 20, "8.99.0.0");
        for (auto& attacker : more_attackers) {
            attacker->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        orch.AdvanceTime(std::chrono::milliseconds(500));
        REQUIRE(victim->GetInboundPeerCount() == 4);  // Still 4

        // Honest peers from different netgroups should ALL connect
        auto honest = factory.CreateDiversePeers(4, 30);
        REQUIRE(PeerFactory::CountUniqueNetgroups(honest) == 4);

        for (auto& peer : honest) {
            peer->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        REQUIRE(orch.WaitForPeerCount(*victim, 8));

        // Final count: 4 attackers + 4 honest = 8
        REQUIRE(victim->GetInboundPeerCount() == 8);
    }
}

TEST_CASE("Per-netgroup inbound - connection order doesn't affect limit", "[network][limits][netgroup][boundary][unit]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    auto victim = factory.CreateNode(1);

    SECTION("Interleaved connections from multiple netgroups") {
        // Create peers from two netgroups
        auto group_a = factory.CreateSybilCluster(6, 10, "8.10.0.0");  // 6 from /16 A
        auto group_b = factory.CreateSybilCluster(6, 20, "8.20.0.0");  // 6 from /16 B

        // Connect interleaved: A, B, A, B, A, B, ...
        for (int i = 0; i < 6; i++) {
            group_a[i]->ConnectTo(victim->GetId(), victim->GetAddress());
            group_b[i]->ConnectTo(victim->GetId(), victim->GetAddress());
            orch.AdvanceTime(std::chrono::milliseconds(50));
        }

        // Wait for all connections to settle
        orch.AdvanceTime(std::chrono::milliseconds(500));

        // Should have 4 from A + 4 from B = 8 total
        REQUIRE(victim->GetInboundPeerCount() == 8);
    }
}
