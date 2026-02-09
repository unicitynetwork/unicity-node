// BlockRelay comprehensive tests: READY gating for HEADERS announcements

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"
#include "network/connection_manager.hpp"
#include "network/peer.hpp"

using namespace unicity;
using namespace unicity::test;

static void SetZeroLatency(SimulatedNetwork& network) {
    SimulatedNetwork::NetworkConditions cond{};
    cond.latency_min = std::chrono::milliseconds(0);
    cond.latency_max = std::chrono::milliseconds(0);
    cond.jitter_max = std::chrono::milliseconds(0);
    network.SetNetworkConditions(cond);
}

static void AdvanceSeconds(SimulatedNetwork& net, int seconds) {
    for (int i = 0; i < seconds * 5; ++i) {
        net.AdvanceTime(200);
    }
}

TEST_CASE("BlockRelay: HEADERS announcement only to READY peers", "[block_relay][ready_gating]") {
    // Use non-zero latency so handshake doesn't complete instantly for node c
    SimulatedNetwork net(50003);
    SimulatedNetwork::NetworkConditions cond{};
    cond.latency_min = std::chrono::milliseconds(500);
    cond.latency_max = std::chrono::milliseconds(500);
    cond.jitter_max = std::chrono::milliseconds(0);
    net.SetNetworkConditions(cond);
    net.EnableCommandTracking(true);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);
    SimulatedNode c(3, &net);

    // b becomes READY (give enough time for handshake with 500ms latency)
    b.ConnectTo(1);
    AdvanceSeconds(net, 4);

    // Mine blocks to exit IBD (needs 2: first during IBD, second post-IBD)
    (void)a.MineBlock();
    AdvanceSeconds(net, 2);
    (void)a.MineBlock();
    AdvanceSeconds(net, 2);

    // Let everything settle
    AdvanceSeconds(net, 2);

    // Snapshot baseline
    int baseline_b = net.CountCommandSent(a.GetId(), b.GetId(), protocol::commands::HEADERS);

    // NOW connect c — handshake takes >1s with 500ms latency (VERSION+VERACK round trips)
    c.ConnectTo(1);

    // Mine a block immediately — c is still mid-handshake, should NOT receive announcement
    (void)a.MineBlock();
    // Only advance 100ms — not enough for c's handshake to complete at 500ms latency
    net.AdvanceTime(100);

    int delta_b = net.CountCommandSent(a.GetId(), b.GetId(), protocol::commands::HEADERS) - baseline_b;
    int headers_c = net.CountCommandSent(a.GetId(), c.GetId(), protocol::commands::HEADERS);

    // READY peer b should have received the announcement
    CHECK(delta_b == 1);
    // non-READY peer c should NOT have received any HEADERS (still mid-handshake)
    CHECK(headers_c == 0);
}

TEST_CASE("BlockRelay: multiple blocks each produce HEADERS", "[block_relay][multi_block]") {
    SimulatedNetwork net(50004);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);

    b.ConnectTo(1);
    AdvanceSeconds(net, 2);

    // Mine first to exit IBD
    (void)a.MineBlock();
    AdvanceSeconds(net, 1);

    int headers_before = net.CountCommandSent(a.GetId(), b.GetId(), protocol::commands::HEADERS);

    // Mine two more post-IBD blocks
    (void)a.MineBlock();
    AdvanceSeconds(net, 1);
    int headers_mid = net.CountCommandSent(a.GetId(), b.GetId(), protocol::commands::HEADERS);

    (void)a.MineBlock();
    AdvanceSeconds(net, 1);
    int headers_after = net.CountCommandSent(a.GetId(), b.GetId(), protocol::commands::HEADERS);

    // Each block should produce at least one HEADERS
    CHECK(headers_mid > headers_before);
    CHECK(headers_after > headers_mid);
}
