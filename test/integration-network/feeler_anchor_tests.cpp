#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "infra/test_access.hpp"
#include "test_orchestrator.hpp"
#include "network/protocol.hpp"
#include "network/addr_relay_manager.hpp"

using namespace unicity;
using unicity::test::AddrRelayManagerTestAccess;
using namespace unicity::test;
using namespace unicity::protocol;

static protocol::NetworkAddress make_address(const std::string& ip, uint16_t port) {
    protocol::NetworkAddress addr;
    addr.services = NODE_NETWORK;
    addr.port = port;
    // IPv4-mapped IPv6
    for (int i = 0; i < 10; ++i) addr.ip[i] = 0;
    addr.ip[10] = 0xFF; addr.ip[11] = 0xFF;
    int a,b,c,d; sscanf(ip.c_str(), "%d.%d.%d.%d", &a,&b,&c,&d);
    addr.ip[12] = (uint8_t)a; addr.ip[13] = (uint8_t)b; addr.ip[14] = (uint8_t)c; addr.ip[15] = (uint8_t)d;
    return addr;
}

TEST_CASE("Feeler connects and auto-disconnects; no outbound slot consumed", "[network][feeler]") {
    SimulatedNetwork net(3601);
    TestOrchestrator orch(&net);

    SimulatedNode n1(1, &net);
    SimulatedNode n2(2, &net);

    // Seed n2 in n1's new table
    auto addr2 = make_address(n2.GetAddress(), n2.GetPort());
    AddrRelayManagerTestAccess::GetAddrManager(n1.GetNetworkManager().discovery_manager()).add(addr2);

    size_t outbound_before = n1.GetNetworkManager().outbound_peer_count();

    // Trigger feeler
    n1.AttemptFeelerConnection();

    // Process events/time for handshake to complete and feeler to disconnect
    for (int i = 0; i < 20; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    CHECK(n1.GetPeerCount() == 0);
    CHECK(n2.GetPeerCount() == 0);

    // Outbound peers should remain unchanged (feelers don't count)
    size_t outbound_after = n1.GetNetworkManager().outbound_peer_count();
    CHECK(outbound_after == outbound_before);
}

TEST_CASE("Successful feeler marks address good (NEW to TRIED promotion)", "[network][feeler]") {
    SimulatedNetwork net(3602);
    TestOrchestrator orch(&net);

    // Use custom routable address for n2 (loopback addresses aren't routable)
    SimulatedNode n1(1, &net);
    SimulatedNode n2(2, &net, "93.184.216.34");  // Routable public IP

    // Seed n2 in n1's NEW table using its routable address
    auto addr2 = make_address("93.184.216.34", n2.GetPort());
    auto& pdm = n1.GetNetworkManager().discovery_manager();
    REQUIRE(AddrRelayManagerTestAccess::GetAddrManager(pdm).add(addr2));

    // Verify address is in NEW table (not TRIED)
    size_t new_before = pdm.NewCount();
    size_t tried_before = pdm.TriedCount();
    REQUIRE(new_before >= 1);
    REQUIRE(tried_before == 0);

    // Trigger feeler connection
    n1.AttemptFeelerConnection();

    // Process events for handshake to complete and feeler to disconnect
    // Feeler receives VERSION -> sets successfully_connected_ -> disconnects
    // remove_peer() then marks address good
    for (int i = 0; i < 20; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    // Feeler should have disconnected
    CHECK(n1.GetPeerCount() == 0);
    CHECK(n2.GetPeerCount() == 0);

    // KEY CHECK: Address should now be in TRIED table (promoted from NEW)
    // This is the whole purpose of feeler connections - validate addresses
    size_t tried_after = pdm.TriedCount();
    CHECK(tried_after == 1);  // Address promoted to TRIED
}
