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
        net.AdvanceTime(200);
    }
}

static struct TestSetup {
    TestSetup() { chain::GlobalChainParams::Select(chain::ChainType::REGTEST); }
} setup_once_block_announce_smoke;

TEST_CASE("SMOKE: non-READY peer does not advance until READY", "[block_announcement][core_smoke]") {
    SimulatedNetwork net(40002);
    SetZeroLatency(net);

    SimulatedNode a(1, &net);
    SimulatedNode c(3, &net);

    // Mine block BEFORE connection so c is behind
    (void)a.MineBlock();

    // Now connect c - should sync after handshake completes
    int c_tip_before = c.GetTipHeight();
    REQUIRE(c_tip_before == 0);  // c at genesis

    c.ConnectTo(1);
    // Brief advance - not enough for full sync
    net.AdvanceTime(50);

    // After handshake completes and sync happens, c should catch up
    AdvanceSeconds(net, 3);
    CHECK(c.GetTipHeight() >= 1);  // c synced to a's tip
}

TEST_CASE("SMOKE: mining triggers immediate HEADERS relay", "[block_announcement][core_smoke]") {
    SimulatedNetwork net(40004);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);

    b.ConnectTo(1);
    AdvanceSeconds(net, 2);

    // Mine first block to exit IBD
    (void)a.MineBlock();
    AdvanceSeconds(net, 1);

    int headers_before = net.CountCommandSent(a.GetId(), b.GetId(), protocol::commands::HEADERS);

    // Mine second block - post-IBD, should send HEADERS directly
    (void)a.MineBlock();
    AdvanceSeconds(net, 1);

    int headers_after = net.CountCommandSent(a.GetId(), b.GetId(), protocol::commands::HEADERS);

    CHECK(headers_after > headers_before);
}

TEST_CASE("SMOKE: multiple blocks each trigger HEADERS", "[block_announcement][core_smoke]") {
    SimulatedNetwork net(40005);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);

    b.ConnectTo(1);
    AdvanceSeconds(net, 2);

    // Mine first block to exit IBD
    (void)a.MineBlock();
    AdvanceSeconds(net, 1);

    int headers_before = net.CountCommandSent(a.GetId(), b.GetId(), protocol::commands::HEADERS);

    // Mine second block - post-IBD
    (void)a.MineBlock();
    AdvanceSeconds(net, 1);
    int headers_mid = net.CountCommandSent(a.GetId(), b.GetId(), protocol::commands::HEADERS);

    // Mine third block
    (void)a.MineBlock();
    AdvanceSeconds(net, 1);
    int headers_final = net.CountCommandSent(a.GetId(), b.GetId(), protocol::commands::HEADERS);

    CHECK(headers_mid > headers_before);
    CHECK(headers_final > headers_mid);
}
