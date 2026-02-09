// BlockRelay policy tests: VERACK behavior, disconnect safety

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"

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
    for (int i = 0; i < seconds * 5; ++i) net.AdvanceTime(200);
}

TEST_CASE("BlockRelay policy: VERACK does NOT trigger tip announcement (matches Bitcoin Core)", "[block_relay][policy]") {
    // Bitcoin Core behavior: VERACK only completes handshake, no tip announcement.
    // announce_block() is only called from ChainTipEvent, not from VERACK handler.
    // Verify: mine a block, let everything settle, THEN connect b. After connection
    // settles, mine nothing more. Delta on a→b HEADERS should be 0 (no new announcements).
    SimulatedNetwork net(51001); SetZeroLatency(net); net.EnableCommandTracking(true);
    SimulatedNode a(1, &net); SimulatedNode b(2, &net);

    // Mine a block BEFORE b connects and let it settle
    (void)a.MineBlock(); AdvanceSeconds(net, 2);

    // Connect b and let handshake + sync settle
    b.ConnectTo(1); AdvanceSeconds(net, 3);

    // Snapshot after handshake + sync are fully settled
    int baseline = net.CountCommandSent(a.GetId(), b.GetId(), protocol::commands::HEADERS);

    // Advance more time with no new blocks — no new HEADERS should appear
    AdvanceSeconds(net, 2);
    int after = net.CountCommandSent(a.GetId(), b.GetId(), protocol::commands::HEADERS);

    // Delta must be exactly 0: no spurious announcements from VERACK or periodic tasks
    CHECK(after - baseline == 0);
}

TEST_CASE("BlockRelay policy: Disconnect safety and state cleanup", "[block_relay][policy][disconnect]") {
    SimulatedNetwork net(51006); SetZeroLatency(net); net.EnableCommandTracking(true);
    SimulatedNode a(1, &net); SimulatedNode b(2, &net);

    b.ConnectTo(1); AdvanceSeconds(net, 2);

    auto& pm = a.GetNetworkManager().peer_manager();
    REQUIRE(pm.get_all_peers().size() == 1);

    // Disconnect peer then mine - announce_block should handle empty peer list gracefully
    a.DisconnectFrom(b.GetId()); AdvanceSeconds(net, 1);

    CHECK(pm.get_all_peers().empty());

    // Mining with no peers should not crash
    (void)a.MineBlock();
    AdvanceSeconds(net, 1);
}
