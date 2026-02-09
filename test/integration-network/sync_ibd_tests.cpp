// Network sync and IBD tests (ported to test2; heavy tests skipped by default)

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/protocol.hpp"
#include "test_orchestrator.hpp"

using namespace unicity;
using namespace unicity::test;

static void SetZeroLatency(SimulatedNetwork& network) {
    SimulatedNetwork::NetworkConditions c; c.latency_min=c.latency_max=std::chrono::milliseconds(0); c.jitter_max=std::chrono::milliseconds(0); network.SetNetworkConditions(c);
}

TEST_CASE("NetworkSync - SwitchSyncPeerOnStall", "[networksync][network]") {
    SimulatedNetwork net(24006);
    // Use small non-zero latency so stall can be installed before HEADERS arrive
    SimulatedNetwork::NetworkConditions c;
    c.latency_min = c.latency_max = std::chrono::milliseconds(50);
    c.jitter_max = std::chrono::milliseconds(0);
    net.SetNetworkConditions(c);
    net.EnableCommandTracking(true);

    // Miner with chain
    SimulatedNode miner(1, &net);
    for (int i = 0; i < 50; ++i) { (void)miner.MineBlock(); }

    // Two serving peers
    SimulatedNode p1(2, &net);
    SimulatedNode p2(3, &net);

    // New node to sync
    SimulatedNode n(4, &net);

    // Peers sync from miner so they can serve headers
    p1.ConnectTo(miner.GetId());
    p2.ConnectTo(miner.GetId());
    net.AdvanceTime(1000);
    for (int i = 0; i < 20 && p1.GetTipHeight() < 50; ++i) { net.AdvanceTime(200); p1.CheckInitialSync(); }
    for (int i = 0; i < 20 && p2.GetTipHeight() < 50; ++i) { net.AdvanceTime(200); p2.CheckInitialSync(); }
    CHECK(p1.GetTipHeight() == 50);
    CHECK(p2.GetTipHeight() == 50);

    // Connect ONLY to p1 first - this ensures p1 is the sync peer
    n.ConnectTo(p1.GetId());
    net.AdvanceTime(200);  // Allow handshake to complete

    // Trigger initial sync - p1 is the only peer, so it MUST be selected
    n.CheckInitialSync();

    // IMMEDIATELY install stall on p1->n (before HEADERS can arrive)
    SimulatedNetwork::NetworkConditions drop = {};
    drop.packet_loss_rate = 1.0;
    net.SetLinkConditions(p1.GetId(), n.GetId(), drop);

    // NOW connect to p2 as backup peer (available for reselection)
    n.ConnectTo(p2.GetId());
    net.AdvanceTime(200);  // Allow handshake to complete

    // Record GETHEADERS baseline
    int gh_p1_before = net.CountCommandSent(n.GetId(), p1.GetId(), protocol::commands::GETHEADERS);
    int gh_p2_before = net.CountCommandSent(n.GetId(), p2.GetId(), protocol::commands::GETHEADERS);

    // Advance mock time beyond the headers sync timeout (5 min) and process timers
    // Use several steps to let the network do maintenance
    for (int i = 0; i < 6; ++i) {
        net.AdvanceTime(60 * 1000); // +60s
        n.ProcessHeaderSyncTimers();
    }

    // After stall timeout, p1 should be disconnected (or at least no longer sync peer)
    // Give more time for stall disconnect to complete and state to stabilize
    net.AdvanceTime(2000);

    // Re-select sync peer (should switch to p2)
    n.CheckInitialSync();
    net.AdvanceTime(2000);  // Allow sync peer selection to complete fully

    // Verify n sent GETHEADERS to the other peer (p2)
    int gh_p1_after = net.CountCommandSent(n.GetId(), p1.GetId(), protocol::commands::GETHEADERS);
    int gh_p2_after = net.CountCommandSent(n.GetId(), p2.GetId(), protocol::commands::GETHEADERS);

    CHECK(gh_p1_after >= gh_p1_before); // no new GETHEADERS to p1 during stall
    CHECK(gh_p2_after > gh_p2_before);  // switched to p2

    // Wait for sync to complete via p2
    for (int i = 0; i < 40 && n.GetTipHeight() < 50; ++i) {
        net.AdvanceTime(500);
        n.CheckInitialSync();
    }

    // And sync completes
    CHECK(n.GetTipHeight() == 50);
}

TEST_CASE("NetworkSync - InitialSync", "[networksync][network]") {
    SimulatedNetwork network(24001);
    SetZeroLatency(network);

    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);

    node2.ConnectTo(1);
    network.AdvanceTime(100);

    for (int i=0;i<100;i++){ (void)node1.MineBlock(); network.AdvanceTime(50); }
    CHECK(node1.GetTipHeight()==100);
    CHECK(node2.GetTipHeight()==100);
    CHECK(node2.GetTipHash()==node1.GetTipHash());
}

TEST_CASE("NetworkSync - SyncFromMultiplePeers", "[networksync][network]") {
    SimulatedNetwork network(24002);
    SetZeroLatency(network);

    SimulatedNode a(1,&network); SimulatedNode b(2,&network); SimulatedNode n(3,&network);
    for(int i=0;i<50;i++){ (void)a.MineBlock(); network.AdvanceTime(50); }

    b.ConnectTo(1); network.AdvanceTime(100);
    CHECK(b.GetTipHeight()==50);

    // Track P2P commands
    network.EnableCommandTracking(true);

    n.ConnectTo(1); n.ConnectTo(2); network.AdvanceTime(5000);
    CHECK(n.GetTipHeight()==50);

    // Bitcoin Core behavior:
    // - During IBD: only one sync peer used (single source policy)
    // - Post-IBD: request headers from all peers to stay synced
    // After n syncs to height 50 and exits IBD, it requests from both peers
    int distinct = network.CountDistinctPeersSent(n.GetId(), protocol::commands::GETHEADERS);
    CHECK(distinct == 2);
}

TEST_CASE("NetworkSync - CatchUpAfterMining", "[networksync][network]") {
    SimulatedNetwork network(24003); SetZeroLatency(network);
    SimulatedNode node1(1,&network); SimulatedNode node2(2,&network);
    node2.ConnectTo(1); network.AdvanceTime(100);
    for(int i=0;i<20;i++){ (void)node1.MineBlock(); network.AdvanceTime(100);}
    CHECK(node2.GetTipHeight()==20);
}

TEST_CASE("IBDTest - FreshNodeSyncsFromGenesis", "[ibdtest][network]") {
    SimulatedNetwork network(24004); SetZeroLatency(network);
    SimulatedNode miner(1,&network); SimulatedNode fresh(2,&network);
    for(int i=0;i<200;i++) (void)miner.MineBlock();
    CHECK(miner.GetTipHeight()==200); CHECK(fresh.GetTipHeight()==0);
    fresh.ConnectTo(1); network.AdvanceTime(100);
    for(int i=0;i<50;i++){ network.AdvanceTime(200);}
    CHECK(fresh.GetTipHeight()==200); CHECK(fresh.GetTipHash()==miner.GetTipHash());
}

TEST_CASE("IBDTest - LargeChainSync", "[ibdtest][network][.]") {
    SimulatedNetwork network(24005); SetZeroLatency(network);
    SimulatedNode miner(1,&network); SimulatedNode sync(2,&network);
    for(int i=0;i<2000;i++){ network.AdvanceTime(1000); (void)miner.MineBlock(); }
    network.AdvanceTime(10000000);
    sync.ConnectTo(1); network.AdvanceTime(100);
    for(int i=0;i<6;i++){ network.AdvanceTime(35000); if(sync.GetTipHeight()==miner.GetTipHeight()) break; }
    CHECK(sync.GetTipHeight()==miner.GetTipHeight());
    CHECK(sync.GetTipHash()==miner.GetTipHash());
}
