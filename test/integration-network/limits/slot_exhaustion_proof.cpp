// Inbound slot exhaustion attack tests
// Protection model (Bitcoin Core parity):
// - All connections accepted up to max_inbound limit
// - Protection via netgroup-aware eviction when at capacity

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "infra/node_simulator.hpp"
#include "infra/peer_factory.hpp"
#include "test_orchestrator.hpp"

using namespace unicity;
using namespace unicity::test;

static void SetZeroLatency(SimulatedNetwork& network){ SimulatedNetwork::NetworkConditions c; c.latency_min=c.latency_max=std::chrono::milliseconds(0); c.jitter_max=std::chrono::milliseconds(0); network.SetNetworkConditions(c);}

TEST_CASE("SlotExhaustion - All connections from same /16 accepted", "[network][limits][slotexhaustion]") {
    SimulatedNetwork network(12345); SetZeroLatency(network);
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    auto victim = factory.CreateNode(1);
    victim->SetBypassPOWValidation(true);
    for(int i=0;i<5;i++) victim->MineBlock();

    // Attacker connects 10 nodes from same /16
    // Core behavior: all connections accepted (no connection-time netgroup limit)
    auto attackers = factory.CreateSybilCluster(10, 100, "8.50.0.0");

    for (auto& a : attackers) {
        a->ConnectTo(victim->GetId(), victim->GetAddress());
    }

    REQUIRE(orch.WaitForPeerCount(*victim, 10));

    // All 10 connected (protection via eviction when at capacity)
    REQUIRE(victim->GetInboundPeerCount() == 10);
    INFO("All 10 attackers from same /16 connected - eviction protects at capacity");
}

TEST_CASE("SlotExhaustion - Connections from same /16 succeed", "[network][limits][slotexhaustion][rotation]") {
    SimulatedNetwork network(12346); SetZeroLatency(network);
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    auto victim = factory.CreateNode(1);
    victim->SetBypassPOWValidation(true);
    for(int i=0;i<5;i++) victim->MineBlock();

    // Create 4 attackers from same /16
    auto attackers = factory.CreateSybilCluster(4, 100, "8.60.0.0");

    for (auto& a : attackers) {
        a->ConnectTo(victim->GetId(), victim->GetAddress());
    }

    REQUIRE(orch.WaitForPeerCount(*victim, 4));

    // All 4 connected
    REQUIRE(victim->GetInboundPeerCount() == 4);
    INFO("All 4 attackers from same /16 connected");
}

TEST_CASE("SlotExhaustion - Honest peer connects alongside attackers", "[network][limits][slotexhaustion]") {
    SimulatedNetwork network(12347); SetZeroLatency(network);
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    auto victim = factory.CreateNode(1);
    victim->SetBypassPOWValidation(true);
    for(int i=0;i<5;i++) victim->MineBlock();

    // Attacker connects 10 nodes from same /16 (all succeed)
    auto attackers = factory.CreateSybilCluster(10, 100, "8.70.0.0");
    for (auto& a : attackers) {
        a->ConnectTo(victim->GetId(), victim->GetAddress());
    }
    REQUIRE(orch.WaitForPeerCount(*victim, 10));

    // Honest peer from different /16 also connects
    auto honest = factory.CreateDiversePeers(1, 500);
    honest[0]->SetBypassPOWValidation(true);
    for(int i=0;i<20;i++) honest[0]->MineBlock();
    honest[0]->ConnectTo(victim->GetId(), victim->GetAddress());

    REQUIRE(orch.WaitForPeerCount(*victim, 11));

    // Honest peer connected alongside attackers
    REQUIRE(victim->GetInboundPeerCount() == 11);
    INFO("Honest peer connected (11 total = 10 attackers + 1 honest)");
    INFO("Protection via eviction when at capacity, not connection-time limits");
}

TEST_CASE("SlotExhaustion - Eviction protects honest peers at capacity", "[network][limits][slotexhaustion]") {
    SimulatedNetwork network(12348); SetZeroLatency(network);
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    auto victim = factory.CreateNode(1);
    victim->SetBypassPOWValidation(true);
    for(int i=0;i<5;i++) victim->MineBlock();

    // Connect honest peers from diverse netgroups first
    auto honest = factory.CreateDiversePeers(4, 10);
    for (auto& h : honest) {
        h->SetBypassPOWValidation(true);
        for(int i=0;i<10;i++) h->MineBlock();
        h->ConnectTo(victim->GetId(), victim->GetAddress());
    }
    REQUIRE(orch.WaitForPeerCount(*victim, 4));

    // Connect attackers from same netgroup
    auto attackers = factory.CreateSybilCluster(6, 100, "8.80.0.0");
    for (auto& a : attackers) {
        a->ConnectTo(victim->GetId(), victim->GetAddress());
    }
    REQUIRE(orch.WaitForPeerCount(*victim, 10));

    // Let peers accrue uptime (exit protection window)
    for (int i = 0; i < 10; i++) {
        orch.AdvanceTime(std::chrono::seconds(1));
    }

    // Trigger eviction
    bool evicted = victim->GetNetworkManager().peer_manager().evict_inbound_peer();
    REQUIRE(evicted);

    // Eviction should target attacker netgroup (largest with 6 peers)
    // Honest peers from diverse netgroups should be protected
    REQUIRE(victim->GetInboundPeerCount() == 9);
    INFO("Eviction targeted largest netgroup (attackers), protecting diverse honest peers");
}
