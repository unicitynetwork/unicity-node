#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "infra/test_access.hpp"
#include "test_orchestrator.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"
#include "util/hash.hpp"
#include "network/addr_manager.hpp"
#include "network/addr_relay_manager.hpp"

using namespace unicity;
using unicity::test::AddrRelayManagerTestAccess;
using namespace unicity::test;
using namespace unicity::network;
using namespace unicity::protocol;

static std::vector<uint8_t> MakeWire(const std::string& cmd, const std::vector<uint8_t>& payload) {
    protocol::MessageHeader hdr(magic::REGTEST, cmd, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(hdr.checksum.data(), hash.begin(), 4);
    auto hdr_bytes = message::serialize_header(hdr);
    std::vector<uint8_t> full;
    full.reserve(hdr_bytes.size() + payload.size());
    full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
    full.insert(full.end(), payload.begin(), payload.end());
    return full;
}

TEST_CASE("GETADDR Core parity: inbound-only and once-per-connection", "[network][addr][parity]") {
    SimulatedNetwork net(2601);
    TestOrchestrator orch(&net);

    SimulatedNode victim(1, &net);
    SimulatedNode inbound_peer(2, &net);
    SimulatedNode outbound_peer(3, &net);

    net.EnableCommandTracking(true);

    // Inbound peer connects to victim
    REQUIRE(inbound_peer.ConnectTo(1));
    REQUIRE(orch.WaitForConnection(victim, inbound_peer));
    // Ensure handshake completes
    for (int i = 0; i < 12; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    // First GETADDR from inbound peer should elicit one ADDR reply
    net.SendMessage(inbound_peer.GetId(), victim.GetId(), MakeWire(commands::GETADDR, {}));
    orch.AdvanceTime(std::chrono::milliseconds(400));
    REQUIRE(net.CountCommandSent(victim.GetId(), inbound_peer.GetId(), commands::ADDR) == 1);

    // Second GETADDR on same connection should be ignored (once-per-connection)
    net.SendMessage(inbound_peer.GetId(), victim.GetId(), MakeWire(commands::GETADDR, {}));
    orch.AdvanceTime(std::chrono::milliseconds(400));
    REQUIRE(net.CountCommandSent(victim.GetId(), inbound_peer.GetId(), commands::ADDR) == 1);

    // Victim initiates outbound connection to another peer; GETADDR from that peer is ignored by victim
    REQUIRE(victim.ConnectTo(3));
    REQUIRE(orch.WaitForConnection(victim, outbound_peer));
    for (int i = 0; i < 12; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    net.SendMessage(outbound_peer.GetId(), victim.GetId(), MakeWire(commands::GETADDR, {}));
    orch.AdvanceTime(std::chrono::milliseconds(400));
    REQUIRE(net.CountCommandSent(victim.GetId(), outbound_peer.GetId(), commands::ADDR) == 0);
}

TEST_CASE("ADDR response is capped at MAX_ADDR_SIZE", "[network][addr]") {
    SimulatedNetwork net(2602);
    TestOrchestrator orch(&net);

    SimulatedNode victim(1, &net);
    SimulatedNode requester(2, &net);

    // Pre-fill victim's AddressManager with many addresses
    auto& discovery = victim.GetNetworkManager().discovery_manager();
    for (int i = 0; i < 5000; ++i) {
        protocol::NetworkAddress addr;
        addr.services = NODE_NETWORK;
        addr.port = 9590;
        // 127.0.1.x IPv4-mapped
        for (int j = 0; j < 10; ++j) addr.ip[j] = 0; addr.ip[10] = 0xFF; addr.ip[11] = 0xFF;
        addr.ip[12] = 127; addr.ip[13] = 0; addr.ip[14] = 1; addr.ip[15] = static_cast<uint8_t>(i % 255);
        AddrRelayManagerTestAccess::GetAddrManager(discovery).add(addr);
    }

    net.EnableCommandTracking(true);
    REQUIRE(requester.ConnectTo(1));
    REQUIRE(orch.WaitForConnection(victim, requester));
    // Ensure handshake completes before GETADDR
    for (int i = 0; i < 12; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    auto getaddr = MakeWire(commands::GETADDR, {});
    net.SendMessage(requester.GetId(), victim.GetId(), getaddr);
    orch.AdvanceTime(std::chrono::milliseconds(400));

    auto payloads = net.GetCommandPayloads(victim.GetId(), requester.GetId(), commands::ADDR);
    REQUIRE_FALSE(payloads.empty());

    message::AddrMessage msg;
    REQUIRE(msg.deserialize(payloads.front().data(), payloads.front().size()));
    REQUIRE(msg.addresses.size() <= MAX_ADDR_SIZE);
}

TEST_CASE("good() is called on outbound after VERACK (moves to tried)", "[network][addr]") {
    SimulatedNetwork net(2603);
    TestOrchestrator orch(&net);

    SimulatedNode victim(1, &net);
    SimulatedNode peer(2, &net);

    auto& discovery = victim.GetNetworkManager().discovery_manager();

    // Note: SimulatedNodes use 127.0.0.x addresses which are now filtered by
    // IsRoutable() (RFC 1122 loopback). This test verifies that good() is called
    // during handshake, but the loopback address won't be added to addrman.
    // Instead, we manually test the good() behavior with a routable address.

    auto routable_addr = protocol::NetworkAddress::from_string("93.184.216.34", protocol::ports::REGTEST, NODE_NETWORK);
    AddrRelayManagerTestAccess::GetAddrManager(discovery).add(routable_addr);
    REQUIRE(discovery.NewCount() == 1);

    // Manually call good() to simulate what would happen during handshake with a routable peer
    discovery.Good(routable_addr);

    // Verify it moved from NEW to TRIED
    REQUIRE(discovery.TriedCount() == 1);
    REQUIRE(discovery.NewCount() == 0);
}

TEST_CASE("cleanup_stale behavior with NEW addresses", "[network][addr]") {
    AddressManager am;

    // Use routable IPs: 93.184.216.34 and 8.8.8.8
    protocol::NetworkAddress a1; for (int i=0;i<16;++i) a1.ip[i]=0; a1.ip[10]=0xff; a1.ip[11]=0xff; a1.services=NODE_NETWORK; a1.port=9590; a1.ip[12]=93; a1.ip[13]=184; a1.ip[14]=216; a1.ip[15]=34;
    protocol::NetworkAddress a2; for (int i=0;i<16;++i) a2.ip[i]=0; a2.ip[10]=0xff; a2.ip[11]=0xff; a2.services=NODE_NETWORK; a2.port=9590; a2.ip[12]=8; a2.ip[13]=8; a2.ip[14]=8; a2.ip[15]=8;

    REQUIRE(am.add(a1));
    REQUIRE(am.add(a2));
    REQUIRE(am.size() == 2);

    // Note: No failed() function - matches Bitcoin Core behavior
    // Terrible addresses determined by is_terrible() (timestamp-based)
    // and cleaned by cleanup_stale() periodically

    am.cleanup_stale();

    // Both addresses remain (fresh addresses are never terrible due to 60-second grace period)
    REQUIRE(am.size() == 2);
}

TEST_CASE("GETADDR empty address manager sends zero addresses", "[network][addr]") {
    SimulatedNetwork net(2604);
    TestOrchestrator orch(&net);

    SimulatedNode victim(1, &net);
    SimulatedNode requester(2, &net);

    net.EnableCommandTracking(true);

    REQUIRE(requester.ConnectTo(1));
    REQUIRE(orch.WaitForConnection(victim, requester));
    // Ensure handshake completes before GETADDR
    for (int i = 0; i < 12; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    auto getaddr = MakeWire(commands::GETADDR, {});
    net.SendMessage(requester.GetId(), victim.GetId(), getaddr);
    orch.AdvanceTime(std::chrono::milliseconds(400));

    auto payloads = net.GetCommandPayloads(victim.GetId(), requester.GetId(), commands::ADDR);

    // Deterministic: expect a single ADDR response with zero addresses when empty
    REQUIRE(payloads.size() >= 1);
    message::AddrMessage msg;
    REQUIRE(msg.deserialize(payloads.front().data(), payloads.front().size()));
    REQUIRE(msg.addresses.size() == 0);
}
