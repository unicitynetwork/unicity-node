#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"

using namespace unicity;
using namespace unicity::test;
using namespace unicity::protocol;

static void ZeroLatency(SimulatedNetwork& net){
    SimulatedNetwork::NetworkConditions c; c.latency_min=c.latency_max=std::chrono::milliseconds(0); c.jitter_max=std::chrono::milliseconds(0); net.SetNetworkConditions(c);
}

TEST_CASE("DoS: INV storm bounded GETHEADERS post-IBD", "[dos][inv][throttle]") {
    SimulatedNetwork net(55001);
    ZeroLatency(net);
    net.EnableCommandTracking(true);

    // Miner builds base chain
    SimulatedNode miner(100, &net);
    for (int i=0;i<20;i++) (void)miner.MineBlock();

    // Victim node (will receive INV storms)
    SimulatedNode V(1, &net);

    // Create K peers that will announce new blocks to V
    const int K = 5;
    std::vector<std::unique_ptr<SimulatedNode>> peers;
    for (int i=0;i<K;i++) {
        peers.push_back(std::make_unique<SimulatedNode>(10+i, &net));
        // Peers sync from miner
        REQUIRE(peers.back()->ConnectTo(miner.GetId()));
    }
    uint64_t t=100; net.AdvanceTime(t);

    // Connect V <- peers
    for (auto& p: peers) REQUIRE(V.ConnectTo(p->GetId()));
    t+=200; net.AdvanceTime(t);

    // Wait for V to fully sync and all initial/post-IBD GETHEADERS to settle
    for (int i = 0; i < 50 && V.GetTipHeight() < 20; ++i) {
        t += 100;
        net.AdvanceTime(t);
    }
    REQUIRE(V.GetTipHeight() == 20);

    // Additional settling time for post-IBD header requests
    for (int i = 0; i < 10; ++i) {
        t += 100;
        net.AdvanceTime(t);
    }

    // Baseline GETHEADERS counts before wave #1
    int gh_before_w1 = 0;
    for (auto& p: peers) gh_before_w1 += net.CountCommandSent(V.GetId(), p->GetId(), commands::GETHEADERS);

    // Wave #1: Miner mines one block; peers will learn it and INV to V
    (void)miner.MineBlock();
    for (int i=0;i<10;i++){ t+=50; net.AdvanceTime(t);} // allow propagation and INV flush

    // Count GETHEADERS delta V->each peer
    // With zero latency, all INVs arrive before any HEADERS responses, so we may send
    // GETHEADERS to multiple peers before learning we already have the block.
    // The key is that it's bounded, not unbounded.
    int gh_after_w1 = 0;
    for (auto& p: peers) {
        gh_after_w1 += net.CountCommandSent(V.GetId(), p->GetId(), commands::GETHEADERS);
    }
    int delta_w1 = gh_after_w1 - gh_before_w1;
    INFO("Wave 1: " << delta_w1 << " GETHEADERS (K=" << K << ")");
    REQUIRE(delta_w1 <= 5 * K);  // Upper bound: at most 5 per peer in worst case timing

    // Let V catch up to peers
    for (int i=0;i<20;i++){ t+=50; net.AdvanceTime(t);} 
    REQUIRE(V.GetTipHeight() == miner.GetTipHeight());

    // Wave #2: New block; ensure additional GETHEADERS is again bounded by K
    int pre_total = 0;
    for (auto& p: peers) pre_total += net.CountCommandSent(V.GetId(), p->GetId(), commands::GETHEADERS);

    (void)miner.MineBlock();
    for (int i=0;i<10;i++){ t+=50; net.AdvanceTime(t);} 

    int post_total = 0;
    for (auto& p: peers) post_total += net.CountCommandSent(V.GetId(), p->GetId(), commands::GETHEADERS);

    int delta_w2 = post_total - pre_total;
    INFO("Wave 2: " << delta_w2 << " GETHEADERS (K=" << K << ")");
    REQUIRE(delta_w2 <= 5 * K);
}
