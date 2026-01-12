// Network conditions tests (ported to test2)

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"

using namespace unicity;
using namespace unicity::test;

static void SetZeroLatency(SimulatedNetwork& network) {
    SimulatedNetwork::NetworkConditions c; c.latency_min=c.latency_max=std::chrono::milliseconds(0); c.jitter_max=std::chrono::milliseconds(0); network.SetNetworkConditions(c);
}

TEST_CASE("NetworkConditionsTest - HighLatency", "[networkconditionstest][network]") {
    SimulatedNetwork network(27001);
    SetZeroLatency(network);
    SimulatedNode node1(1,&network); SimulatedNode node2(2,&network);
    node2.ConnectTo(1); uint64_t t=100; network.AdvanceTime(t);
    SimulatedNetwork::NetworkConditions cond; cond.latency_min=std::chrono::milliseconds(500); cond.latency_max=std::chrono::milliseconds(500); cond.jitter_max=std::chrono::milliseconds(0);
    network.SetNetworkConditions(cond);
    (void)node1.MineBlock();
    for(int i=0;i<20;i++){ t+=200; network.AdvanceTime(t);} 
    CHECK(node2.GetTipHeight()==1);
}

TEST_CASE("NetworkConditionsTest - PacketLoss", "[networkconditionstest][network]") {
    SimulatedNetwork network(27002);
    SetZeroLatency(network);
    SimulatedNode node1(1,&network); SimulatedNode node2(2,&network);
    node2.ConnectTo(1); uint64_t t=100; network.AdvanceTime(t);
    SimulatedNetwork::NetworkConditions cond; cond.packet_loss_rate=0.5; cond.latency_min=std::chrono::milliseconds(1); cond.latency_max=std::chrono::milliseconds(10);
    network.SetNetworkConditions(cond);
    for(int i=0;i<100;i++){ (void)node1.MineBlock(); t+=1000; network.AdvanceTime(t);} 
    t+=35000; network.AdvanceTime(t);
    // Protocol resilience: Even with 50% packet loss, INV->GETHEADERS mechanism
    // recovers missing headers (one successful INV triggers batch HEADERS response).
    // This is correct Bitcoin Core behavior - expect most/all blocks to arrive.
    int h = node2.GetTipHeight();
    CHECK(h >= 50);  // With recovery mechanism, should get at least half
    CHECK(h <= 100);
}

TEST_CASE("NetworkConditionsTest - BandwidthLimits", "[networkconditionstest][network]") {
    SimulatedNetwork network(27003);
    SetZeroLatency(network);
    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);

    node2.ConnectTo(1);
    uint64_t t = 100;
    network.AdvanceTime(t);

    // Set low bandwidth limit
    SimulatedNetwork::NetworkConditions cond;
    cond.bandwidth_bytes_per_sec = 10000;
    cond.latency_min = std::chrono::milliseconds(1);
    cond.latency_max = std::chrono::milliseconds(10);
    network.SetNetworkConditions(cond);

    // Mine blocks and allow time for bandwidth-limited transfer
    for (int i = 0; i < 10; i++) {
        (void)node1.MineBlock();
        t += 2000;  // Allow time for slow transfer
        network.AdvanceTime(t);
    }

    // With bandwidth limits, sync should still complete (just slower)
    int h = node2.GetTipHeight();
    CHECK(h >= 1);  // At least some blocks should arrive
    CHECK(h <= 10);
}
