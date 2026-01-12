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
    // DON'T use zero latency - we need time to install packet loss before HEADERS arrive
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
    uint64_t t = 1000; net.AdvanceTime(t);
    for (int i = 0; i < 20 && p1.GetTipHeight() < 50; ++i) { t += 200; net.AdvanceTime(t); p1.GetNetworkManager().test_hook_check_initial_sync(); }
    for (int i = 0; i < 20 && p2.GetTipHeight() < 50; ++i) { t += 200; net.AdvanceTime(t); p2.GetNetworkManager().test_hook_check_initial_sync(); }
    CHECK(p1.GetTipHeight() == 50);
    CHECK(p2.GetTipHeight() == 50);

    // New node connects to both peers
    n.ConnectTo(p1.GetId()); n.ConnectTo(p2.GetId());
    t += 200; net.AdvanceTime(t);

    // Start initial sync (single sync peer policy - should pick p1 first)
    n.GetNetworkManager().test_hook_check_initial_sync();
    t += 200; net.AdvanceTime(t);

    // Record GETHEADERS to each peer (initial sync has started)
    int gh_p1_before = net.CountCommandSent(n.GetId(), p1.GetId(), protocol::commands::GETHEADERS);
    int gh_p2_before = net.CountCommandSent(n.GetId(), p2.GetId(), protocol::commands::GETHEADERS);

    // NOW install stall: drop all messages from p1 to n so no HEADERS arrive
    SimulatedNetwork::NetworkConditions drop = {};
    drop.packet_loss_rate = 1.0;
    net.SetLinkConditions(p1.GetId(), n.GetId(), drop);

    // Advance mock time beyond the headers sync timeout (120s) and process timers
    // Use several steps to let the network do maintenance
    for (int i = 0; i < 4; ++i) {
        t += 60 * 1000; // +60s
        net.AdvanceTime(t);
        n.GetNetworkManager().test_hook_header_sync_process_timers();
    }

    // After stall timeout, p1 should be disconnected (or at least no longer sync peer)
    // Give more time for stall disconnect to complete and state to stabilize
    t += 2000; net.AdvanceTime(t);

    // Re-select sync peer (should switch to p2)
    n.GetNetworkManager().test_hook_check_initial_sync();
    t += 2000; net.AdvanceTime(t);  // Allow sync peer selection to complete fully

    // Verify n sent GETHEADERS to the other peer (p2)
    int gh_p1_after = net.CountCommandSent(n.GetId(), p1.GetId(), protocol::commands::GETHEADERS);
    int gh_p2_after = net.CountCommandSent(n.GetId(), p2.GetId(), protocol::commands::GETHEADERS);

    CHECK(gh_p1_after >= gh_p1_before); // no new GETHEADERS to p1 during stall
    CHECK(gh_p2_after > gh_p2_before);  // switched to p2

    // And sync completes
    CHECK(n.GetTipHeight() == 50);
}

TEST_CASE("NetworkSync - InitialSync", "[networksync][network]") {
    SimulatedNetwork network(24001);
    SetZeroLatency(network);

    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);

    node2.ConnectTo(1);
    uint64_t t=100; network.AdvanceTime(t);

    for (int i=0;i<100;i++){ (void)node1.MineBlock(); t+=50; network.AdvanceTime(t); }
    CHECK(node1.GetTipHeight()==100);
    CHECK(node2.GetTipHeight()==100);
    CHECK(node2.GetTipHash()==node1.GetTipHash());
}

TEST_CASE("NetworkSync - SyncFromMultiplePeers", "[networksync][network]") {
    SimulatedNetwork network(24002);
    SetZeroLatency(network);

    SimulatedNode a(1,&network); SimulatedNode b(2,&network); SimulatedNode n(3,&network);
    uint64_t t=100;
    for(int i=0;i<50;i++){ (void)a.MineBlock(); t+=50; }

    b.ConnectTo(1); t+=100; network.AdvanceTime(t);
    CHECK(b.GetTipHeight()==50);

    // Track P2P commands
    network.EnableCommandTracking(true);

    n.ConnectTo(1); n.ConnectTo(2); t+=5000; network.AdvanceTime(t);
    CHECK(n.GetTipHeight()==50);

    // During IBD, node n should only send GETHEADERS to a single sync peer
    int distinct = network.CountDistinctPeersSent(n.GetId(), protocol::commands::GETHEADERS);
    CHECK(distinct == 1);
}

TEST_CASE("NetworkSync - CatchUpAfterMining", "[networksync][network]") {
    SimulatedNetwork network(24003); SetZeroLatency(network);
    SimulatedNode node1(1,&network); SimulatedNode node2(2,&network);
    node2.ConnectTo(1); uint64_t t=100; network.AdvanceTime(t);
    for(int i=0;i<20;i++){ (void)node1.MineBlock(); t+=100; network.AdvanceTime(t);} 
    CHECK(node2.GetTipHeight()==20);
}

TEST_CASE("IBDTest - FreshNodeSyncsFromGenesis", "[ibdtest][network]") {
    SimulatedNetwork network(24004); SetZeroLatency(network);
    SimulatedNode miner(1,&network); SimulatedNode fresh(2,&network);
    for(int i=0;i<200;i++) (void)miner.MineBlock();
    CHECK(miner.GetTipHeight()==200); CHECK(fresh.GetTipHeight()==0);
    fresh.ConnectTo(1); uint64_t t=100; network.AdvanceTime(t);
    for(int i=0;i<50;i++){ t+=200; network.AdvanceTime(t);} 
    CHECK(fresh.GetTipHeight()==200); CHECK(fresh.GetTipHash()==miner.GetTipHash());
}

TEST_CASE("IBDTest - LargeChainSync", "[ibdtest][network][.]") {
    SimulatedNetwork network(24005); SetZeroLatency(network);
    SimulatedNode miner(1,&network); SimulatedNode sync(2,&network);
    uint64_t t=1000; for(int i=0;i<2000;i++){ t+=1000; network.AdvanceTime(t); (void)miner.MineBlock(); }
    t = 10000000; network.AdvanceTime(t);
    sync.ConnectTo(1); t+=100; network.AdvanceTime(t);
    for(int i=0;i<6;i++){ t+=35000; network.AdvanceTime(t); if(sync.GetTipHeight()==miner.GetTipHeight()) break; }
    CHECK(sync.GetTipHeight()==miner.GetTipHeight());
    CHECK(sync.GetTipHash()==miner.GetTipHash());
}
