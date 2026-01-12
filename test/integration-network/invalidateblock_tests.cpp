// InvalidateBlock functional tests (ported to test2)

#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "chain/chainparams.hpp"
#include "catch_amalgamated.hpp"

using namespace unicity;
using namespace unicity::test;

static void SetZeroLatency(SimulatedNetwork& network) {
    SimulatedNetwork::NetworkConditions c; c.latency_min=c.latency_max=std::chrono::milliseconds(0); c.jitter_max=std::chrono::milliseconds(0); network.SetNetworkConditions(c);
}

struct InvalidateBlockTestSetup2 {
    InvalidateBlockTestSetup2() {
        unicity::chain::GlobalChainParams::Select(unicity::chain::ChainType::REGTEST);
    }
};
static InvalidateBlockTestSetup2 invalidate_block_test_setup2;

TEST_CASE("InvalidateBlock - Basic invalidation with reorg (test2)", "[invalidateblock][functional][network]") {
    SimulatedNetwork network(25001);
    SetZeroLatency(network);

    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);

    uint256 blockA = node1.MineBlock();
    uint256 blockB = node1.MineBlock();
    uint256 blockC = node1.MineBlock();

    network.AdvanceTime(network.GetCurrentTime() + 100);

    CHECK(node1.GetTipHeight() == 3);
    CHECK(node1.GetTipHash() == blockC);

    node2.ConnectTo(1);
    for (int i = 0; i < 20; i++) network.AdvanceTime(network.GetCurrentTime() + 100);
    CHECK(node2.GetTipHeight() == 3);
    CHECK(node2.GetTipHash() == blockC);

    node2.DisconnectFrom(1);
    network.AdvanceTime(network.GetCurrentTime() + 100);

    // Invalidate blockB on node2 and build D,E,F
    bool invalidated = node2.GetChainstate().InvalidateBlock(blockB);
    REQUIRE(invalidated);
    CHECK(node2.GetTipHeight() == 1);
    CHECK(node2.GetTipHash() == blockA);

    uint256 blockD = node2.MineBlock(); (void)blockD;
    uint256 blockE = node2.MineBlock(); (void)blockE;
    uint256 blockF = node2.MineBlock();
    network.AdvanceTime(network.GetCurrentTime() + 100);
    CHECK(node2.GetTipHeight() == 4);

    node2.ConnectTo(1);
    // With outbound-only header sync (Core parity), ensure the lagging node (node1)
    // also has an OUTBOUND connection to the announcer so it will initiate GETHEADERS.
    node1.ConnectTo(2);
    for (int i = 0; i < 100; i++) network.AdvanceTime(network.GetCurrentTime() + 100);

    CHECK(node1.GetTipHeight() == 4);
    CHECK(node1.GetTipHash() == blockF);
}

TEST_CASE("InvalidateBlock - Competing chains (test2)", "[invalidateblock][functional][network]") {
    SimulatedNetwork network(25002);
    SetZeroLatency(network);

    SimulatedNode miner1(1, &network);
    SimulatedNode miner2(2, &network);
    SimulatedNode observer(3, &network);

    for (int i = 0; i < 10; i++) (void)miner1.MineBlock();

    miner2.ConnectTo(1);
    observer.ConnectTo(1);
    uint64_t t=100; network.AdvanceTime(t);
    for (int i = 0; i < 30; i++) { t+=100; network.AdvanceTime(t);} 
    CHECK(miner2.GetTipHeight()==10); CHECK(observer.GetTipHeight()==10);

    miner2.DisconnectFrom(1); observer.DisconnectFrom(1); t+=100; network.AdvanceTime(t);

    std::vector<uint256> chainA; for (int i=0;i<5;i++) chainA.push_back(miner1.MineBlock());
    std::vector<uint256> chainB; for (int i=0;i<7;i++) chainB.push_back(miner2.MineBlock());

    observer.ConnectTo(1); t+=100; network.AdvanceTime(t);
    for (int i = 0; i < 20; i++) { t+=100; network.AdvanceTime(t);} 
    CHECK(observer.GetTipHeight()==15);

    observer.ConnectTo(2); t+=100; network.AdvanceTime(t);
    for (int i = 0; i < 30; i++) { t+=100; network.AdvanceTime(t);} 
    CHECK(observer.GetTipHeight()==17);
    CHECK(observer.GetTipHash()==miner2.GetTipHash());

    // Invalidate first block of chain B
    bool invalidated = observer.GetChainstate().InvalidateBlock(chainB[0]);
    REQUIRE(invalidated);
    CHECK(observer.GetTipHeight() <= 10);
    observer.GetChainstate().ActivateBestChain(nullptr);
    t+=100; network.AdvanceTime(t);
    CHECK(observer.GetTipHeight()==15);
    CHECK(observer.GetTipHash()==chainA.back());
}
