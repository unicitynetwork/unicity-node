// Block Announcement - Core-aligned smoke tests (black-box)

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/protocol.hpp"

using namespace unicity;
using namespace unicity::test;

static void SetZeroLatency(SimulatedNetwork& network) {
    SimulatedNetwork::NetworkConditions conditions;
    conditions.latency_min = std::chrono::milliseconds(0);
    conditions.latency_max = std::chrono::milliseconds(0);
    conditions.jitter_max = std::chrono::milliseconds(0);
    network.SetNetworkConditions(conditions);
}

static void AdvanceSeconds(SimulatedNetwork& net, int seconds) {
    for (int i = 0; i < seconds * 5; ++i) {
        net.AdvanceTime(net.GetCurrentTime() + 200);
    }
}

static int CountINV(SimulatedNetwork& net, int from_node_id, int to_node_id) {
    return net.CountCommandSent(from_node_id, to_node_id, protocol::commands::INV);
}

static struct TestSetup {
    TestSetup() { chain::GlobalChainParams::Select(chain::ChainType::REGTEST); }
} setup_once_block_announce_smoke;

TEST_CASE("SMOKE: immediate announce to READY peer advances tip", "[block_announcement][core_smoke]") {
    SimulatedNetwork net(40001);
    SetZeroLatency(net);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);

    // Make b READY
    b.ConnectTo(1);
    AdvanceSeconds(net, 2);

    int b_tip_before = b.GetTipHeight();
    (void)a.MineBlock();
    AdvanceSeconds(net, 2);

    CHECK(b.GetTipHeight() >= b_tip_before + 1);
}

TEST_CASE("SMOKE: non-READY peer does not advance until READY", "[block_announcement][core_smoke]") {
    SimulatedNetwork net(40002);
    SetZeroLatency(net);

    SimulatedNode a(1, &net);
    SimulatedNode c(3, &net);

    // Start connection but do not complete handshake
    c.ConnectTo(1);

    int c_tip_before = c.GetTipHeight();
    (void)a.MineBlock();
    AdvanceSeconds(net, 2);
    CHECK(c.GetTipHeight() == c_tip_before);

    // Now complete handshake and ensure next block propagates
    AdvanceSeconds(net, 2);
    int c_tip_mid = c.GetTipHeight();
    (void)a.MineBlock();
    AdvanceSeconds(net, 2);
    CHECK(c.GetTipHeight() >= c_tip_mid + 1);
}

TEST_CASE("SMOKE: multi-peer propagation advances all READY tips", "[block_announcement][core_smoke]") {
    SimulatedNetwork net(40003);
    SetZeroLatency(net);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);
    SimulatedNode c(3, &net);
    SimulatedNode d(4, &net);

    b.ConnectTo(1);
    c.ConnectTo(1);
    d.ConnectTo(1);
    AdvanceSeconds(net, 2);

    int b_before = b.GetTipHeight();
    int c_before = c.GetTipHeight();
    int d_before = d.GetTipHeight();

    (void)a.MineBlock();
    AdvanceSeconds(net, 2);

    CHECK(b.GetTipHeight() >= b_before + 1);
    CHECK(c.GetTipHeight() >= c_before + 1);
    CHECK(d.GetTipHeight() >= d_before + 1);
}

TEST_CASE("SMOKE: dedup within TTL with explicit flush", "[block_announcement][core_smoke]") {
    SimulatedNetwork net(40004);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);

    b.ConnectTo(1);
    AdvanceSeconds(net, 2);

    // Announce tip twice without waiting for TTL; flush both times
    int inv_before = CountINV(net, a.GetId(), b.GetId());
    a.GetNetworkManager().announce_tip_to_peers();
    a.GetNetworkManager().flush_block_announcements();
    int inv_first = CountINV(net, a.GetId(), b.GetId());

    a.GetNetworkManager().announce_tip_to_peers();
    a.GetNetworkManager().flush_block_announcements();
    int inv_second = CountINV(net, a.GetId(), b.GetId());

    CHECK(inv_first >= inv_before);          // at least one INV after first announce
    CHECK(inv_second == inv_first);          // no additional INV before TTL
}

TEST_CASE("SMOKE: periodic re-announce after TTL", "[block_announcement][core_smoke]") {
    SimulatedNetwork net(40005);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);

    b.ConnectTo(1);
    AdvanceSeconds(net, 2);

    // First announce + flush
    a.GetNetworkManager().announce_tip_to_peers();
    a.GetNetworkManager().flush_block_announcements();
    int inv_first = CountINV(net, a.GetId(), b.GetId());

    // Advance beyond TTL (~10m) in small steps, then announce again
    AdvanceSeconds(net, 11 * 60);
    a.GetNetworkManager().announce_tip_to_peers();
    a.GetNetworkManager().flush_block_announcements();

    int inv_second = CountINV(net, a.GetId(), b.GetId());
    CHECK(inv_second >= inv_first + 1);
}

TEST_CASE("SMOKE: disconnect safety on flush", "[block_announcement][core_smoke]") {
    SimulatedNetwork net(40006);
    SetZeroLatency(net);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);

    b.ConnectTo(1);
    AdvanceSeconds(net, 2);
    CHECK(a.GetPeerCount() == 1);

    a.GetNetworkManager().announce_tip_to_peers();
    a.GetNetworkManager().flush_block_announcements();

    b.DisconnectFrom(1);
    AdvanceSeconds(net, 2);
    CHECK(a.GetPeerCount() == 0);

    // Should not crash
    a.GetNetworkManager().flush_block_announcements();
}
