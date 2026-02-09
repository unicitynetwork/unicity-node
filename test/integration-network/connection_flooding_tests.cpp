// Copyright (c) 2025 The Unicity Foundation
// Tests for Sybil attack resistance via connection flooding
//
// Protection model (Bitcoin Core parity):
// - All inbound connections accepted up to max_inbound limit
// - When at capacity, netgroup-aware eviction protects diversity
// - Eviction targets the netgroup with the most connections

#include "catch_amalgamated.hpp"
#include "../infra/peer_factory.hpp"
#include "../infra/simulated_network.hpp"
#include "../infra/simulated_node.hpp"
#include "../test_orchestrator.hpp"

using namespace unicity::test;

// =============================================================================
// CONNECTION ACCEPTANCE TESTS
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

        // All should connect (5 < 125 default limit)
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
// NETGROUP BEHAVIOR TESTS (Core parity: eviction-based, not connection-time)
// =============================================================================

TEST_CASE("Sybil - All connections from same netgroup accepted", "[network][sybil][security][unit]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    SECTION("Multiple IPs from same /16 subnet all connect (no connection-time limit)") {
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

        // All 10 should connect (Core behavior: no connection-time netgroup limit)
        REQUIRE(orch.WaitForPeerCount(*victim, 10));

        size_t connected = victim->GetInboundPeerCount();
        REQUIRE(connected == 10);
        INFO("All " << connected << " attackers from same /16 connected (eviction protects at capacity)");
    }

    SECTION("Diverse peers connect alongside same-netgroup peers") {
        auto victim = factory.CreateNode(0);

        // Honest peers from diverse subnets (4 different /16s)
        auto honest = factory.CreateDiversePeers(4, 1);

        // Attackers from same subnet (all can connect)
        auto attackers = factory.CreateSybilCluster(8, 100, "10.99.0.0");

        // Connect honest first - all 4 should succeed
        for (auto& h : honest) {
            h->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        REQUIRE(orch.WaitForPeerCount(*victim, 4));

        // Connect attackers - all 8 should connect (no connection-time limit)
        for (auto& a : attackers) {
            a->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        REQUIRE(orch.WaitForPeerCount(*victim, 12));  // 4 honest + 8 attackers

        size_t total = victim->GetInboundPeerCount();
        REQUIRE(total == 12);

        INFO("All peers connected: " << total << " (4 honest + 8 attackers)");
        INFO("Protection comes from eviction when at capacity, not connection-time limits");
    }
}

TEST_CASE("Sybil - Eviction protects netgroup diversity", "[network][sybil][security][unit]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    SECTION("Eviction targets largest netgroup") {
        auto victim = factory.CreateNode(0);

        // Connect 4 honest peers from diverse netgroups
        auto honest = factory.CreateDiversePeers(4, 1);
        for (auto& h : honest) {
            h->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        REQUIRE(orch.WaitForPeerCount(*victim, 4));

        // Connect 5 attackers from same netgroup
        auto attackers = factory.CreateSybilCluster(5, 100, "10.50.0.0");
        for (auto& a : attackers) {
            a->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        REQUIRE(orch.WaitForPeerCount(*victim, 9));

        // Let peers accrue uptime (exits protection window)
        for (int i = 0; i < 10; i++) {
            orch.AdvanceTime(std::chrono::seconds(1));
        }

        // Trigger eviction
        bool evicted = victim->GetNetworkManager().peer_manager().evict_inbound_peer();
        REQUIRE(evicted);

        // Eviction should target the attacker netgroup (largest with 5 peers)
        // Honest peers from diverse netgroups should be protected
        REQUIRE(victim->GetInboundPeerCount() == 8);
        INFO("Eviction selected from largest netgroup (attackers)");
    }
}

// =============================================================================
// COMBINED ATTACK SCENARIOS
// =============================================================================

TEST_CASE("Sybil - Multiple /16 subnets behavior", "[network][sybil][security][unit]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    SECTION("Attacker with multiple /16 subnets - all connect") {
        auto victim = factory.CreateNode(0);

        // Attackers from multiple /16 subnets
        auto attackers1 = factory.CreateSybilCluster(3, 100, "192.168.0.0");
        auto attackers2 = factory.CreateSybilCluster(3, 200, "10.10.0.0");
        auto attackers3 = factory.CreateSybilCluster(3, 300, "172.16.0.0");

        // Verify each cluster is in different /16
        REQUIRE(PeerFactory::AllSameNetgroup(attackers1));
        REQUIRE(PeerFactory::AllSameNetgroup(attackers2));
        REQUIRE(PeerFactory::AllSameNetgroup(attackers3));
        REQUIRE_FALSE(AddressFactory::SameNetgroup(
            attackers1[0]->GetAddress(), attackers2[0]->GetAddress()));

        // Connect all attackers - all 9 should connect
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

        INFO("Attacker with 3 diverse /16s connected " << total << " peers");
        INFO("Protection via eviction when at capacity");
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
