// Reorg and network partition tests (ported to test2)

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"

using namespace unicity;
using namespace unicity::test;

static void SetZeroLatency(SimulatedNetwork& network) {
    SimulatedNetwork::NetworkConditions c; c.latency_min=c.latency_max=std::chrono::milliseconds(0); c.jitter_max=std::chrono::milliseconds(0); network.SetNetworkConditions(c);
}

TEST_CASE("ReorgTest - DeepReorg", "[reorgtest][network]") {
    SimulatedNetwork network(23401);
    SetZeroLatency(network);

    SimulatedNode miner_a(1, &network);
    SimulatedNode miner_b(2, &network);
    SimulatedNode observer(3, &network);

    // Build common ancestor
    for (int i = 0; i < 10; i++) (void)miner_a.MineBlock();

    // Sync miner_b to miner_a
    miner_b.ConnectTo(1);
    uint64_t t = 100; network.AdvanceTime(t);
    for (int i = 0; i < 20; i++) { t += 100; network.AdvanceTime(t); }
    CHECK(miner_b.GetTipHash() == miner_a.GetTipHash());

    // Partition: miner_b separate from miner_a
    miner_b.DisconnectFrom(1); t += 100; network.AdvanceTime(t);

    // A mines 20 more (height 30); B mines 25 more (height 35)
    for (int i = 0; i < 20; i++) (void)miner_a.MineBlock();
    CHECK(miner_a.GetTipHeight() == 30);
    for (int i = 0; i < 25; i++) (void)miner_b.MineBlock();
    CHECK(miner_b.GetTipHeight() == 35);

    // Observer syncs to A first
    observer.ConnectTo(1); t += 100; network.AdvanceTime(t);
    for (int i = 0; i < 20; i++) { t += 100; network.AdvanceTime(t); }
    CHECK(observer.GetTipHash() == miner_a.GetTipHash());

    // Observer learns about longer chain B and reorgs
    observer.ConnectTo(2); t += 100; network.AdvanceTime(t);
    for (int i = 0; i < 30; i++) { t += 100; network.AdvanceTime(t); }

    CHECK(observer.GetTipHash() == miner_b.GetTipHash());
    CHECK(observer.GetTipHeight() == miner_b.GetTipHeight());
}

TEST_CASE("ReorgTest - CompetingChainsEqualWork", "[reorgtest][network]") {
    SimulatedNetwork network(23402);
    SetZeroLatency(network);

    SimulatedNode miner_a(1, &network);
    SimulatedNode miner_b(2, &network);
    SimulatedNode observer(3, &network);

    for (int i = 0; i < 5; i++) (void)miner_a.MineBlock();

    miner_b.ConnectTo(1); uint64_t t = 100; network.AdvanceTime(t);
    for (int i = 0; i < 10; i++) { t += 100; network.AdvanceTime(t); }
    CHECK(miner_b.GetTipHash() == miner_a.GetTipHash());

    miner_b.DisconnectFrom(1); t += 100; network.AdvanceTime(t);

    for (int i = 0; i < 10; i++) { (void)miner_a.MineBlock(); (void)miner_b.MineBlock(); }
    CHECK(miner_a.GetTipHeight() == 15);
    CHECK(miner_b.GetTipHeight() == 15);

    observer.ConnectTo(1); t += 100; network.AdvanceTime(t);
    for (int i = 0; i < 15; i++) { t += 100; network.AdvanceTime(t); }
    uint256 chain_a_tip = observer.GetTipHash();

    observer.ConnectTo(2); t += 100; network.AdvanceTime(t);
    for (int i = 0; i < 15; i++) { t += 100; network.AdvanceTime(t); }

    CHECK(observer.GetTipHeight() == 15);
    CHECK(observer.GetTipHash() == chain_a_tip);
}

TEST_CASE("NetworkPartitionTest - SimpleSplit", "[networkpartitiontest][network]") {
    SimulatedNetwork network(23403);
    SetZeroLatency(network);

    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);

    node1.ConnectTo(2); uint64_t t=100; network.AdvanceTime(t);

    network.CreatePartition({1}, {2});
    (void)node1.MineBlock(); (void)node2.MineBlock();
    t += 1000; network.AdvanceTime(t);

    CHECK(node1.GetTipHeight() == 1);
    CHECK(node2.GetTipHeight() == 1);
    CHECK(node1.GetTipHash() != node2.GetTipHash());
}

TEST_CASE("NetworkPartitionTest - HealAndReorg", "[networkpartitiontest][network]") {
    SimulatedNetwork network(23404);
    SetZeroLatency(network);

    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);

    node1.ConnectTo(2); uint64_t t=100; network.AdvanceTime(t);

    network.CreatePartition({1}, {2});

    for (int i = 0; i < 5; i++) (void)node1.MineBlock();
    for (int i = 0; i < 3; i++) (void)node2.MineBlock();

    t += 1000; network.AdvanceTime(t);

    network.HealPartition();

    // Core-aligned: a new block triggers immediate INV announcements; simulate
    // a post-heal block on the longer chain to drive convergence without relying
    // on long periodic re-announce intervals.
    (void)node1.MineBlock();
    for (int i = 0; i < 50; ++i) { t += 100; network.AdvanceTime(t); }

    CHECK(node2.GetTipHeight() == node1.GetTipHeight());
    CHECK(node2.GetTipHeight() >= 5);
    CHECK(node1.GetTipHash() == node2.GetTipHash());
}

// Nested reorg sequence: A->B (reorg), then immediately B->C (longer) reorg
TEST_CASE("ReorgTest - NestedReorg", "[reorgtest][network]") {
    SimulatedNetwork network(23405);
    SetZeroLatency(network);

    SimulatedNode victim(1, &network);
    SimulatedNode miner_a(2, &network);
    SimulatedNode miner_b(3, &network);

    // Victim builds initial chain (50 blocks)
    for (int i = 0; i < 50; i++) (void)victim.MineBlock();

    // Miners sync to victim
    miner_a.ConnectTo(1); miner_b.ConnectTo(1);
    uint64_t t=100; network.AdvanceTime(t);
    for (int i=0;i<30;i++){ t+=100; network.AdvanceTime(t);} 

    CHECK(miner_a.GetTipHash()==victim.GetTipHash());
    CHECK(miner_b.GetTipHash()==victim.GetTipHash());

    uint256 common_ancestor = victim.GetTipHash(); (void)common_ancestor;

    // Disconnect miners and build competing chains
    miner_a.DisconnectFrom(1); miner_b.DisconnectFrom(1); t+=100; network.AdvanceTime(t);

    for (int i=0;i<5;i++) (void)miner_a.MineBlock();      // height 55
    for (int i=0;i<10;i++) (void)miner_b.MineBlock();     // height 60

    // Victim learns about chain B (height 60) and reorgs
    miner_b.ConnectTo(1); t+=100; network.AdvanceTime(t);
    t+=200; network.AdvanceTime(t);
    CHECK(victim.GetTipHeight()==60);
    CHECK(victim.GetTipHash()==miner_b.GetTipHash());

    // Disconnect miner B, now learn about miner C (simulate by extending miner_a to 65)
    miner_b.DisconnectFrom(1); t+=100; network.AdvanceTime(t);

    for (int i=0;i<5;i++) (void)miner_a.MineBlock();      // miner_a -> 60
    for (int i=0;i<5;i++) (void)miner_a.MineBlock();      // miner_a -> 65

    // Victim connects to miner_a and reorgs again
    miner_a.ConnectTo(1); t+=100; network.AdvanceTime(t);
    for (int i=0;i<30;i++){ t+=100; network.AdvanceTime(t);} 

    CHECK(victim.GetTipHeight()==miner_a.GetTipHeight());
    CHECK(victim.GetTipHash()==miner_a.GetTipHash());
}
