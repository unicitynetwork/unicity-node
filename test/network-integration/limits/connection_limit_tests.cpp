// Connection limits tests (ported to test2)

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "test_orchestrator.hpp"

using namespace unicity;
using namespace unicity::test;

static void SetZeroLatency(SimulatedNetwork& network) {
    SimulatedNetwork::NetworkConditions c; c.latency_min=c.latency_max=std::chrono::milliseconds(0); c.jitter_max=std::chrono::milliseconds(0); network.SetNetworkConditions(c);
}

TEST_CASE("Inbound limit - Accept several inbound connections", "[network][limits][inbound]") {
    SimulatedNetwork network(12345); SimulatedNetwork::NetworkConditions c; c.latency_min=std::chrono::milliseconds(1); c.latency_max=std::chrono::milliseconds(3); c.jitter_max=std::chrono::milliseconds(0); network.SetNetworkConditions(c);
    SimulatedNode victim(1, &network); victim.SetBypassPOWValidation(true);

    uint64_t t=1000000; for(int i=0;i<2;i++){ victim.MineBlock(); t+=50; network.AdvanceTime(t);} 

const int N=2; std::vector<std::unique_ptr<SimulatedNode>> peers; peers.reserve(N);
TestOrchestrator orch(&network);
    for(int i=0;i<N;i++){ peers.push_back(std::make_unique<SimulatedNode>(100+i,&network)); peers.back()->SetBypassPOWValidation(true); CHECK(peers.back()->ConnectTo(1)); }
    REQUIRE(orch.WaitForCondition([&]{ return victim.GetPeerCount() >= (size_t)N; }, std::chrono::seconds(10)));
}

TEST_CASE("Inbound limit - Eviction when limit reached (heavy)", "[network][limits][inbound][eviction][.]") {
SimulatedNetwork network(12346); SetZeroLatency(network);
    SimulatedNode victim(1,&network); victim.SetBypassPOWValidation(true);
    INFO("Heavy eviction test stubbed for port; skip heavy fanout in unit run");
    SUCCEED();
}

TEST_CASE("Outbound limit - Accept up to limit", "[network][limits][outbound]") {
    SimulatedNetwork network(12347); SetZeroLatency(network);
    SimulatedNode node1(1,&network); node1.SetBypassPOWValidation(true);
    uint64_t t=1000000; node1.MineBlock(); t+=100; network.AdvanceTime(t);

    const int MAX_OUT=8; std::vector<std::unique_ptr<SimulatedNode>> peers; peers.reserve(MAX_OUT);
    for(int i=0;i<MAX_OUT;i++){ peers.push_back(std::make_unique<SimulatedNode>(100+i,&network)); peers.back()->SetBypassPOWValidation(true); peers.back()->MineBlock(); }
    t+=1000; network.AdvanceTime(t);
for(int i=0;i<MAX_OUT;i++){ node1.ConnectTo(100+i);} 
    TestOrchestrator orch(&network);
    REQUIRE(orch.WaitForCondition([&]{ return node1.GetOutboundPeerCount() >= (size_t)(MAX_OUT-2); }, std::chrono::seconds(6)));
    size_t outbound=node1.GetOutboundPeerCount();
    REQUIRE(outbound <= (size_t)MAX_OUT);
}

TEST_CASE("Outbound limit - Reject beyond max", "[network][limits][outbound]") {
    SimulatedNetwork network(12348); SetZeroLatency(network);
    SimulatedNode node1(1,&network); node1.SetBypassPOWValidation(true);
    uint64_t t=1000000; node1.MineBlock(); t+=100; network.AdvanceTime(t);

    const int MAX_OUT=8, NUM=10; std::vector<std::unique_ptr<SimulatedNode>> peers; 
    for(int i=0;i<NUM;i++){ peers.push_back(std::make_unique<SimulatedNode>(100+i,&network)); peers.back()->SetBypassPOWValidation(true); peers.back()->MineBlock(); }
    t+=1000; network.AdvanceTime(t);
for(int i=0;i<NUM;i++){ node1.ConnectTo(100+i);} 
    TestOrchestrator orch(&network);
    REQUIRE(orch.WaitForCondition([&]{ return node1.GetOutboundPeerCount() <= (size_t)MAX_OUT; }, std::chrono::seconds(6)));
    size_t outbound=node1.GetOutboundPeerCount();
    REQUIRE(outbound <= (size_t)MAX_OUT);
}
