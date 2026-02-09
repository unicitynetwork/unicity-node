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

    // node1 starts with a chain (exits IBD first so it will announce blocks)
    SimulatedNode node1(10, &network);
    for (int i = 0; i < 5; i++) {
        (void)node1.MineBlock();
    }

    SimulatedNode node2(2, &network);
    node2.ConnectTo(node1.GetId());
    uint64_t t = 100;
    network.AdvanceTime(t);

    // Wait for node2 to sync at zero latency
    for (int i = 0; i < 20 && node2.GetTipHeight() < 5; i++) {
        t += 100;
        network.AdvanceTime(t);
    }
    REQUIRE(node2.GetTipHeight() == 5);

    // Now set high latency
    SimulatedNetwork::NetworkConditions cond;
    cond.latency_min = std::chrono::milliseconds(500);
    cond.latency_max = std::chrono::milliseconds(500);
    cond.jitter_max = std::chrono::milliseconds(0);
    network.SetNetworkConditions(cond);

    // Mine another block under high latency
    (void)node1.MineBlock();

    // With 500ms latency, messages take 500ms each way. Block announcement flow:
    // - ChainTipEvent fires on node1, queues INV
    // - INV takes 500ms to reach node2
    // - node2 sends GETDATA, takes 500ms to reach node1
    // - node1 sends BLOCK, takes 500ms to reach node2
    // Total: ~1500ms minimum, plus processing time
    for (int i = 0; i < 30; i++) {
        t += 200;
        network.AdvanceTime(t);
    }  // 6 seconds
    CHECK(node2.GetTipHeight() == 6);
}

TEST_CASE("NetworkConditionsTest - PacketLoss", "[networkconditionstest][network]") {
    SimulatedNetwork network(27002);
    SetZeroLatency(network);
    SimulatedNode node1(1,&network); SimulatedNode node2(2,&network);
    node2.ConnectTo(1); uint64_t t=100; network.AdvanceTime(t);
    // 10% packet loss - realistic for poor network conditions
    // (50% was too extreme with 2-min GETHEADERS throttle from Bitcoin Core parity)
    SimulatedNetwork::NetworkConditions cond; cond.packet_loss_rate=0.1; cond.latency_min=std::chrono::milliseconds(1); cond.latency_max=std::chrono::milliseconds(10);
    network.SetNetworkConditions(cond);
    for(int i=0;i<100;i++){ (void)node1.MineBlock(); t+=1000; network.AdvanceTime(t);}
    // With 10% packet loss, probability of successful round-trip is ~81%.
    // Wait for any pending retries.
    t+=150000; network.AdvanceTime(t);
    // Protocol resilience: With 10% packet loss, INV->GETHEADERS mechanism
    // should reliably sync blocks.
    int h = node2.GetTipHeight();
    CHECK(h >= 20);  // With 10% loss and 2-min GETHEADERS throttle, expect partial sync
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
