#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "infra/test_access.hpp"
#include "test_orchestrator.hpp"
#include "network/peer.hpp"
#include <thread>

using namespace unicity;
using namespace unicity::test;
using unicity::test::PeerTestAccess;

namespace {
struct TimeoutGuard {
    TimeoutGuard(std::chrono::milliseconds hs, std::chrono::milliseconds idle) {
        PeerTestAccess::SetTimeouts(hs, idle);
    }
    ~TimeoutGuard() { PeerTestAccess::ResetTimeouts(); }
};

static void ZeroLatency(SimulatedNetwork& net){
    SimulatedNetwork::NetworkConditions c; c.latency_min=c.latency_max=std::chrono::milliseconds(0); c.jitter_max=std::chrono::milliseconds(0); net.SetNetworkConditions(c);
}
}

TEST_CASE("Handshake timeout disconnects when no VERSION/VERACK is exchanged", "[network][handshake][timeout]") {
    TimeoutGuard guard(std::chrono::milliseconds(100), std::chrono::milliseconds(0));

    SimulatedNetwork net(60001);
    ZeroLatency(net);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);

    // Initiate connection
    REQUIRE(a.ConnectTo(b.GetId()));

    // Immediately partition to block VERSION/VERACK exchange
    net.CreatePartition({1}, {2});

    // Allow handshake timer to expire (uses steady_timer)
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    a.ProcessEvents();
    b.ProcessEvents();
    // Run periodic maintenance to remove disconnected peers from manager
    a.ProcessPeriodic();
    b.ProcessPeriodic();

    // Expect disconnect due to handshake timeout
    REQUIRE(a.GetPeerCount() == 0);
}

TEST_CASE("Handshake timer is canceled after VERACK", "[network][handshake][timeout]") {
    TimeoutGuard guard(std::chrono::milliseconds(100), std::chrono::milliseconds(0));

    SimulatedNetwork net(60002);
    ZeroLatency(net);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);
    TestOrchestrator orch(&net);

    REQUIRE(a.ConnectTo(b.GetId()));
    REQUIRE(orch.WaitForConnection(a, b, std::chrono::seconds(3)));

    // Sleep beyond handshake timeout to ensure no spurious disconnect
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    a.ProcessEvents(); b.ProcessEvents();

    CHECK(a.GetPeerCount() == 1);
    CHECK(b.GetPeerCount() == 1);
}