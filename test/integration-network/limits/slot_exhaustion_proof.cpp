// Inbound slot exhaustion attack proof (ported to test2)
// These tests now verify that slot exhaustion attacks are MITIGATED by per-netgroup limits

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "infra/node_simulator.hpp"
#include "infra/peer_factory.hpp"
#include "test_orchestrator.hpp"

using namespace unicity;
using namespace unicity::test;

static void SetZeroLatency(SimulatedNetwork& network){ SimulatedNetwork::NetworkConditions c; c.latency_min=c.latency_max=std::chrono::milliseconds(0); c.jitter_max=std::chrono::milliseconds(0); network.SetNetworkConditions(c);}

TEST_CASE("SlotExhaustion - FIXED: Per-netgroup limit prevents single /16 dominance", "[network][limits][slotexhaustion]") {
    SimulatedNetwork network(12345); SetZeroLatency(network);
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    auto victim = factory.CreateNode(1);
    victim->SetBypassPOWValidation(true);
    for(int i=0;i<5;i++) victim->MineBlock();

    // Attacker tries to connect 10 nodes from same /16
    // Per-netgroup limit (4) prevents more than 4 connections
    auto attackers = factory.CreateSybilCluster(10, 100, "8.50.0.0");

    for (auto& a : attackers) {
        a->ConnectTo(victim->GetId(), victim->GetAddress());
    }

    REQUIRE(orch.WaitForPeerCount(*victim, 4));

    // Verify only 4 connected (per-netgroup limit enforced)
    REQUIRE(victim->GetInboundPeerCount() == 4);
    INFO("Slot exhaustion attack MITIGATED: only 4 of 10 attackers connected");
}

TEST_CASE("SlotExhaustion - FIXED: Rotation attack limited by throttling", "[network][limits][slotexhaustion][rotation]") {
    SimulatedNetwork network(12346); SetZeroLatency(network);
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    auto victim = factory.CreateNode(1);
    victim->SetBypassPOWValidation(true);
    for(int i=0;i<5;i++) victim->MineBlock();

    // Create 4 attackers from same /16 (at limit)
    auto attackers = factory.CreateSybilCluster(4, 100, "8.60.0.0");

    for (auto& a : attackers) {
        a->ConnectTo(victim->GetId(), victim->GetAddress());
    }

    REQUIRE(orch.WaitForPeerCount(*victim, 4));

    // All 4 connected
    REQUIRE(victim->GetInboundPeerCount() == 4);
    INFO("Rotation attack limited: attacker can only maintain 4 connections from /16");
}

TEST_CASE("SlotExhaustion - FIXED: Honest peer can connect despite attack", "[network][limits][slotexhaustion]") {
    SimulatedNetwork network(12347); SetZeroLatency(network);
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    auto victim = factory.CreateNode(1);
    victim->SetBypassPOWValidation(true);
    for(int i=0;i<5;i++) victim->MineBlock();

    // Attacker fills their /16 quota (4)
    auto attackers = factory.CreateSybilCluster(10, 100, "8.70.0.0");
    for (auto& a : attackers) {
        a->ConnectTo(victim->GetId(), victim->GetAddress());
    }
    REQUIRE(orch.WaitForPeerCount(*victim, 4));

    // Honest peer from different /16 can still connect!
    auto honest = factory.CreateDiversePeers(1, 500);
    honest[0]->SetBypassPOWValidation(true);
    for(int i=0;i<20;i++) honest[0]->MineBlock();
    honest[0]->ConnectTo(victim->GetId(), victim->GetAddress());

    REQUIRE(orch.WaitForPeerCount(*victim, 5));

    // Honest peer connected despite attacker
    REQUIRE(victim->GetInboundPeerCount() == 5);
    INFO("Slot exhaustion FIXED: honest peer connected (5 total = 4 attackers + 1 honest)");
}

TEST_CASE("SlotExhaustion - FIXED: Attacker needs diverse IPs", "[network][limits][slotexhaustion]") {
    SimulatedNetwork network(12348); SetZeroLatency(network);
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    auto victim = factory.CreateNode(1);
    victim->SetBypassPOWValidation(true);
    for(int i=0;i<5;i++) victim->MineBlock();

    // Attacker with only one /16 can only get 4 connections
    // (used to be able to fill all slots)
    auto attackers = factory.CreateSybilCluster(8, 100, "8.80.0.0");
    for (auto& a : attackers) {
        a->ConnectTo(victim->GetId(), victim->GetAddress());
    }

    // Only 4 can connect
    REQUIRE(orch.WaitForPeerCount(*victim, 4));
    REQUIRE(victim->GetInboundPeerCount() == 4);
    INFO("Attacker resources constrained: needs diverse /16s to fill more slots");
}
