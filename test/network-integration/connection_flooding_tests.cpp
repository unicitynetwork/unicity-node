// Copyright (c) 2025 The Unicity Foundation
// Tests for Sybil attack resistance via connection flooding
//
// These tests verify current protections and document gaps in
// defending against connection flooding attacks.

#include "catch_amalgamated.hpp"
#include "../infra/peer_factory.hpp"
#include "../infra/simulated_network.hpp"
#include "../infra/simulated_node.hpp"
#include "../test_orchestrator.hpp"

using namespace unicity::test;

// =============================================================================
// CURRENT PROTECTIONS
// =============================================================================

TEST_CASE("Sybil - Connection limit protection", "[network][sybil][unit]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    SECTION("Inbound connections under limit succeed") {
        auto victim = factory.CreateNode(0);

        // Create 5 diverse peers (each in different /16) - all should connect
        auto peers = factory.CreateDiversePeers(5, 1);

        for (auto& p : peers) {
            p->ConnectTo(victim->GetId(), victim->GetAddress());
        }

        REQUIRE(orch.WaitForPeerCount(*victim, 5));

        // All should connect (5 < 125 default limit, and all in different netgroups)
        REQUIRE(victim->GetInboundPeerCount() == 5);
    }

    SECTION("Default limit is 125 inbound connections") {
        // Just document the limit
        INFO("Default max_inbound_peers = 125");
        INFO("Eviction triggered when at capacity and new inbound arrives");
        REQUIRE(unicity::protocol::DEFAULT_MAX_INBOUND_CONNECTIONS == 125);
    }
}

TEST_CASE("Sybil - Per-IP protection", "[network][sybil][unit]") {
    SimulatedNetwork network;
    TestOrchestrator orch(&network);

    SECTION("Different IPs can all connect") {
        SimulatedNode victim(0, &network);

        // Each node gets unique IP (127.0.0.X)
        SimulatedNode peer1(1, &network);
        SimulatedNode peer2(2, &network);
        SimulatedNode peer3(3, &network);

        peer1.ConnectTo(0);
        peer2.ConnectTo(0);
        peer3.ConnectTo(0);

        REQUIRE(orch.WaitForPeerCount(victim, 3));
        REQUIRE(victim.GetInboundPeerCount() == 3);

        INFO("MAX_INBOUND_PER_IP = 2 limits connections from single IP");
        INFO("Each SimulatedNode has unique IP, so all connect");
    }
}

// =============================================================================
// PER-NETGROUP INBOUND LIMITS (Bitcoin Core parity)
// =============================================================================

TEST_CASE("Sybil - Per-netgroup limit enforced", "[network][sybil][security][unit]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    SECTION("Multiple IPs from same /16 subnet limited to 4") {
        auto victim = factory.CreateNode(0);

        // Create 10 attackers all in same /16 subnet but different IPs
        auto attackers = factory.CreateSybilCluster(10, 100, "192.168.0.0");

        // Verify all attackers have different IPs but same netgroup
        REQUIRE(PeerFactory::AllSameNetgroup(attackers));
        std::set<std::string> unique_ips;
        for (const auto& a : attackers) {
            unique_ips.insert(a->GetAddress());
        }
        REQUIRE(unique_ips.size() == 10);  // All different IPs

        // Connect all attackers to victim
        for (auto& a : attackers) {
            a->ConnectTo(victim->GetId(), victim->GetAddress());
        }

        // Only 4 should connect (MAX_INBOUND_PER_NETGROUP = 4)
        REQUIRE(orch.WaitForPeerCount(*victim, 4));

        size_t connected = victim->GetInboundPeerCount();
        REQUIRE(connected == 4);
        INFO("Per-netgroup limit enforced: only " << connected << " of 10 attackers connected");
    }

    SECTION("Attacker cannot dominate victim's peer table from single /16") {
        auto victim = factory.CreateNode(0);

        // Honest peers from diverse subnets (4 different /16s)
        auto honest = factory.CreateDiversePeers(4, 1);

        // Attackers from same subnet (12 attackers, but only 4 can connect)
        auto attackers = factory.CreateSybilCluster(12, 100, "10.99.0.0");

        // Connect honest first - all 4 should succeed
        for (auto& h : honest) {
            h->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        REQUIRE(orch.WaitForPeerCount(*victim, 4));

        // Connect attackers - only 4 should succeed due to per-netgroup limit
        for (auto& a : attackers) {
            a->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        REQUIRE(orch.WaitForPeerCount(*victim, 8));  // 4 honest + 4 attackers

        size_t total = victim->GetInboundPeerCount();
        REQUIRE(total == 8);

        size_t attacker_count = 4;  // Limited by per-netgroup
        double attacker_ratio = 100.0 * attacker_count / total;

        // Attacker ratio is 50%, not 75% as it would be without protection
        REQUIRE(attacker_ratio == 50.0);
        INFO("Attacker ratio limited to " << attacker_ratio << "% by per-netgroup limit");
    }
}

TEST_CASE("Sybil - Per-netgroup limits prevent rapid churn", "[network][sybil][security][unit]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    // Bitcoin Core parity: no per-IP connection throttling
    // Protection comes from per-netgroup inbound limits (MAX_INBOUND_PER_NETGROUP = 4)
    // and netgroup-based eviction

    SECTION("Rapid connections from same netgroup - limited by netgroup") {
        auto victim = factory.CreateNode(0);

        // Create 5 attackers from same /16 - only 4 can connect due to netgroup limit
        auto attackers = factory.CreateSybilCluster(5, 100, "8.99.0.0");

        // Connect all 5 - only 4 succeed due to per-netgroup limit
        for (auto& a : attackers) {
            a->ConnectTo(victim->GetId(), victim->GetAddress());
        }

        REQUIRE(orch.WaitForPeerCount(*victim, 4));
        REQUIRE(victim->GetInboundPeerCount() == 4);

        INFO("Per-netgroup limit enforced: 4 of 5 attackers connected");
    }

    SECTION("Diverse peers not affected by netgroup limits") {
        auto victim = factory.CreateNode(0);

        // Create 4 diverse peers (each different IP/netgroup)
        auto peers = factory.CreateDiversePeers(4, 100);

        // All 4 should connect (different netgroups)
        for (auto& p : peers) {
            p->ConnectTo(victim->GetId(), victim->GetAddress());
        }

        REQUIRE(orch.WaitForPeerCount(*victim, 4));
        REQUIRE(victim->GetInboundPeerCount() == 4);

        INFO("4 diverse peers connected - different netgroups not limited");
    }

    SECTION("Netgroup limit persistent even after time") {
        auto victim = factory.CreateNode(0);

        // Create cluster of attackers from same /16
        auto attackers = factory.CreateSybilCluster(4, 100, "8.88.0.0");

        // Connect all 4 (at per-netgroup limit)
        for (auto& a : attackers) {
            a->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        REQUIRE(orch.WaitForPeerCount(*victim, 4));

        // Advance time
        orch.AdvanceTime(std::chrono::seconds(61));
        victim->ProcessPeriodic();

        // 5th attacker from same /16 should still be rejected due to netgroup limit
        auto extra = factory.CreateSybilCluster(1, 200, "8.88.0.0");
        extra[0]->ConnectTo(victim->GetId(), victim->GetAddress());
        orch.AdvanceTime(std::chrono::milliseconds(500));

        // Still 4 (netgroup limit is persistent while connections exist)
        REQUIRE(victim->GetInboundPeerCount() == 4);

        INFO("Per-netgroup limit is persistent while connections exist");
    }
}

// =============================================================================
// COMBINED ATTACK SCENARIOS
// =============================================================================

TEST_CASE("Sybil - Multiple /16 subnets behavior", "[network][sybil][security][unit]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    SECTION("Attacker with multiple /16 subnets - each limited to 4") {
        auto victim = factory.CreateNode(0);

        // Attackers from multiple /16 subnets (3 each, all should connect since < 4 per netgroup)
        auto attackers1 = factory.CreateSybilCluster(3, 100, "192.168.0.0");
        auto attackers2 = factory.CreateSybilCluster(3, 200, "10.10.0.0");
        auto attackers3 = factory.CreateSybilCluster(3, 300, "172.16.0.0");

        // Verify each cluster is in different /16
        REQUIRE(PeerFactory::AllSameNetgroup(attackers1));
        REQUIRE(PeerFactory::AllSameNetgroup(attackers2));
        REQUIRE(PeerFactory::AllSameNetgroup(attackers3));
        REQUIRE_FALSE(AddressFactory::SameNetgroup(
            attackers1[0]->GetAddress(), attackers2[0]->GetAddress()));

        // Connect all attackers - all 9 should connect (3 per netgroup, under limit of 4)
        for (auto& a : attackers1) {
            a->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        for (auto& a : attackers2) {
            a->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        for (auto& a : attackers3) {
            a->ConnectTo(victim->GetId(), victim->GetAddress());
        }

        REQUIRE(orch.WaitForPeerCount(*victim, 9));

        size_t total = victim->GetInboundPeerCount();
        REQUIRE(total == 9);

        // Note: Attacker with multiple /16s can still get significant presence
        // This is expected - full eclipse requires many diverse /16s
        // The protection limits damage from single-subnet attacks
        INFO("Attacker with 3 diverse /16s connected " << total << " peers (3 per netgroup)");
    }

    SECTION("Attacker with multiple /16 subnets - excess per netgroup rejected") {
        auto victim = factory.CreateNode(0);

        // Attackers: 6 from each /16, but only 4 per netgroup should connect
        auto attackers1 = factory.CreateSybilCluster(6, 100, "192.168.0.0");
        auto attackers2 = factory.CreateSybilCluster(6, 200, "10.10.0.0");

        // Connect all attackers
        for (auto& a : attackers1) {
            a->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        for (auto& a : attackers2) {
            a->ConnectTo(victim->GetId(), victim->GetAddress());
        }

        // Only 8 should connect (4 per netgroup)
        REQUIRE(orch.WaitForPeerCount(*victim, 8));

        size_t total = victim->GetInboundPeerCount();
        REQUIRE(total == 8);
        INFO("Per-netgroup limit enforced: 8 of 12 attackers connected (4 per /16)");
    }
}

TEST_CASE("Sybil - Honest network baseline", "[network][sybil][unit]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    SECTION("Diverse honest peers connect successfully") {
        auto victim = factory.CreateNode(0);

        // Create honest peers from diverse subnets
        auto honest = factory.CreateDiversePeers(8, 1);

        // All are in different /16 subnets
        REQUIRE(PeerFactory::AllDiverseNetgroups(honest));

        // Connect all
        for (auto& h : honest) {
            h->ConnectTo(victim->GetId(), victim->GetAddress());
        }

        REQUIRE(orch.WaitForPeerCount(*victim, 8));

        REQUIRE(victim->GetInboundPeerCount() == 8);
        REQUIRE(PeerFactory::CountUniqueNetgroups(honest) == 8);

        INFO("8 honest peers from 8 different /16 subnets connected");
    }
}
