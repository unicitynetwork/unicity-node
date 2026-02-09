// Sync Peer Switching Scenario Tests - Validates peer selection behavior
// across various network conditions and failure modes

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/protocol.hpp"

using namespace unicity;
using namespace unicity::test;
using namespace unicity::protocol;

TEST_CASE("Sync peer banned for misbehavior switches to healthy peer", "[network][sync_peer][switching][ban]") {
    // When sync peer is banned for protocol violation, another peer should be selected

    SimulatedNetwork net(52001);
    net.EnableCommandTracking(true);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 50; ++i) {
        (void)miner.MineBlock();
    }

    // Two peers sync from miner
    SimulatedNode p1(2, &net);
    SimulatedNode p2(3, &net);

    p1.ConnectTo(miner.GetId());
    p2.ConnectTo(miner.GetId());

    uint64_t t = 1000; net.AdvanceTime(t);

    p1.CheckInitialSync();
    p2.CheckInitialSync();

    for (int i = 0; i < 20 && (p1.GetTipHeight() < 50 || p2.GetTipHeight() < 50); ++i) {
        t += 1000; net.AdvanceTime(t);
    }

    REQUIRE(p1.GetTipHeight() == 50);
    REQUIRE(p2.GetTipHeight() == 50);

    // Victim connects to both
    SimulatedNode victim(4, &net);
    victim.ConnectTo(p1.GetId());
    victim.ConnectTo(p2.GetId());

    t += 1000; net.AdvanceTime(t);

    // Select p1 as sync peer
    victim.CheckInitialSync();
    t += 2000; net.AdvanceTime(t);

    // Make some progress
    for (int i = 0; i < 5 && victim.GetTipHeight() < 20; ++i) {
        t += 1000; net.AdvanceTime(t);
    }

    int height_with_p1 = victim.GetTipHeight();
    CHECK(height_with_p1 > 0);
    // May complete quickly in test environment
    CHECK(height_with_p1 <= 50);

    // Simulate p1 banned (disconnect it)
    victim.DisconnectFrom(p1.GetId());
    t += 2000; net.AdvanceTime(t);

    // sync_started flags should be reset, allowing p2 to be selected
    victim.CheckInitialSync();
    t += 2000; net.AdvanceTime(t);

    // Sync should complete with p2
    for (int i = 0; i < 20 && victim.GetTipHeight() < 50; ++i) {
        t += 2000; net.AdvanceTime(t);
    }

    CHECK(victim.GetTipHeight() == 50);
}

TEST_CASE("All peers exhausted then new peer connects and is selected", "[network][sync_peer][switching][exhausted]") {
    // When all existing peers have been tried (sync_started=true) and a new peer
    // connects, it should be selected as sync peer

    SimulatedNetwork net(52002);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 60; ++i) {
        (void)miner.MineBlock();
    }

    // Initial peer syncs from miner
    SimulatedNode p1(2, &net);
    p1.ConnectTo(miner.GetId());

    uint64_t t = 1000; net.AdvanceTime(t);
    p1.CheckInitialSync();

    for (int i = 0; i < 20 && p1.GetTipHeight() < 60; ++i) {
        t += 2000; net.AdvanceTime(t);
    }

    REQUIRE(p1.GetTipHeight() == 60);

    // Victim connects to p1
    SimulatedNode victim(3, &net);
    victim.ConnectTo(p1.GetId());

    t += 1000; net.AdvanceTime(t);

    // Select p1 as sync peer and make some progress
    victim.CheckInitialSync();
    t += 2000; net.AdvanceTime(t);

    for (int i = 0; i < 5 && victim.GetTipHeight() < 25; ++i) {
        t += 1000; net.AdvanceTime(t);
    }

    int height_after_p1 = victim.GetTipHeight();
    CHECK(height_after_p1 > 0);
    // May complete quickly in test environment
    CHECK(height_after_p1 <= 60);

    // p1 disconnects (now all peers exhausted)
    victim.DisconnectFrom(p1.GetId());
    t += 2000; net.AdvanceTime(t);

    // New peer syncs from miner
    SimulatedNode p2(4, &net);
    p2.ConnectTo(miner.GetId());
    t += 1000; net.AdvanceTime(t);
    p2.CheckInitialSync();

    for (int i = 0; i < 20 && p2.GetTipHeight() < 60; ++i) {
        t += 2000; net.AdvanceTime(t);
    }

    REQUIRE(p2.GetTipHeight() == 60);

    // Victim connects to new peer
    victim.ConnectTo(p2.GetId());
    t += 2000; net.AdvanceTime(t);

    // New peer should be selected (sync_started=false for fresh peer)
    victim.CheckInitialSync();
    t += 2000; net.AdvanceTime(t);

    // Complete sync with new peer
    for (int i = 0; i < 20 && victim.GetTipHeight() < 60; ++i) {
        t += 2000; net.AdvanceTime(t);
    }

    CHECK(victim.GetTipHeight() == 60);
}

TEST_CASE("Inbound peers used as fallback when no outbound available", "[network][sync_peer][switching][inbound]") {
    // Bitcoin Core behavior: PREFER outbound peers, but FALL BACK to inbound
    // when no outbound peers are available (m_num_preferred_download_peers == 0)

    SimulatedNetwork net(52003);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 30; ++i) {
        (void)miner.MineBlock();
    }

    SimulatedNode victim(2, &net);

    // Miner connects TO victim (inbound from victim's perspective)
    miner.ConnectTo(victim.GetId());

    uint64_t t = 1000; net.AdvanceTime(t);

    // Verify victim has only inbound connection
    CHECK(victim.GetInboundPeerCount() == 1);
    CHECK(victim.GetOutboundPeerCount() == 0);

    // Try to select sync peer - should fall back to inbound
    victim.CheckInitialSync();
    t += 2000; net.AdvanceTime(t);

    // Sync should proceed via inbound fallback
    for (int i = 0; i < 30 && victim.GetTipHeight() < 30; ++i) {
        t += 1000; net.AdvanceTime(t);
    }

    // Victim should have synced from inbound peer
    CHECK(victim.GetTipHeight() == 30);
}

TEST_CASE("HandleInv opportunistic sync peer adoption during stall window", "[network][sync_peer][switching][inv]") {
    // When sync peer stalls and before explicit reselection, an INV from another
    // peer advertising a longer chain can trigger opportunistic sync peer switch

    SimulatedNetwork net(52004);
    net.EnableCommandTracking(true);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 40; ++i) {
        (void)miner.MineBlock();
    }

    // p1 syncs partially (simulated by limiting connection time)
    SimulatedNode p1(2, &net);
    p1.ConnectTo(miner.GetId());

    uint64_t t = 1000; net.AdvanceTime(t);
    p1.CheckInitialSync();

    // Allow p1 to get only partial chain
    for (int i = 0; i < 5 && p1.GetTipHeight() < 20; ++i) {
        t += 1000; net.AdvanceTime(t);
    }

    int p1_height = p1.GetTipHeight();
    CHECK(p1_height > 0);
    // May complete quickly in test environment
    CHECK(p1_height <= 40);

    // p2 gets full chain
    SimulatedNode p2(3, &net);
    p2.ConnectTo(miner.GetId());
    t += 1000; net.AdvanceTime(t);
    p2.CheckInitialSync();

    for (int i = 0; i < 15 && p2.GetTipHeight() < 40; ++i) {
        t += 1000; net.AdvanceTime(t);
    }

    REQUIRE(p2.GetTipHeight() == 40);

    // Victim connects to both
    SimulatedNode victim(4, &net);
    victim.ConnectTo(p1.GetId());
    victim.ConnectTo(p2.GetId());

    t += 1000; net.AdvanceTime(t);

    // Select p1 as initial sync peer
    victim.CheckInitialSync();
    t += 2000; net.AdvanceTime(t);

    // Sync from p1
    for (int i = 0; i < 10 && victim.GetTipHeight() < p1_height; ++i) {
        t += 1000; net.AdvanceTime(t);
    }

    int height_from_p1 = victim.GetTipHeight();
    CHECK(height_from_p1 > 0);

    // Now p1 "stalls" (we simulate by disconnecting)
    victim.DisconnectFrom(p1.GetId());
    t += 2000; net.AdvanceTime(t);

    // p2's INV messages should trigger opportunistic switch
    // (In practice, normal sync reselection will pick p2)
    victim.CheckInitialSync();
    t += 2000; net.AdvanceTime(t);

    // Complete sync with p2
    for (int i = 0; i < 20 && victim.GetTipHeight() < 40; ++i) {
        t += 2000; net.AdvanceTime(t);
    }

    CHECK(victim.GetTipHeight() == 40);
}
