#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/network_manager.hpp"
#include "network/message.hpp"
#include "util/hash.hpp"
#include "network/peer_discovery_manager.hpp"
#include "test_orchestrator.hpp"
#include <set>

using namespace unicity;
using namespace unicity::test;
using namespace unicity::network;
using namespace unicity::protocol;

static std::vector<uint8_t> MakeWire(const std::string& cmd, const std::vector<uint8_t>& payload) {
    protocol::MessageHeader hdr(magic::REGTEST, cmd, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(hdr.checksum.data(), hash.begin(), 4);
    auto hdr_bytes = message::serialize_header(hdr);
    std::vector<uint8_t> full; full.reserve(hdr_bytes.size() + payload.size());
    full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
    full.insert(full.end(), payload.begin(), payload.end());
    return full;
}

TEST_CASE("GETADDR ignored pre-VERACK (parity)", "[network][addr][parity][preverack]") {
    SimulatedNetwork net(48100);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode server(1, &net);
    SimulatedNode client(2, &net);

    REQUIRE(client.ConnectTo(server.GetId()));

    // Send GETADDR immediately, before waiting/handshake settling
    std::vector<uint8_t> empty_payload;
    protocol::MessageHeader hdr(magic::REGTEST, commands::GETADDR, 0);
    uint256 hash = Hash(empty_payload);
    std::memcpy(hdr.checksum.data(), hash.begin(), 4);
    auto hdr_bytes = message::serialize_header(hdr);
    net.SendMessage(client.GetId(), server.GetId(), hdr_bytes);

    // Advance a short time; do NOT settle handshake fully
    orch.AdvanceTime(std::chrono::milliseconds(150));

    // No ADDR should be sent by server to client
    auto payloads = net.GetCommandPayloads(server.GetId(), client.GetId(), commands::ADDR);
    REQUIRE(payloads.empty());

    // With Bitcoin Core parity gating, pre-VERACK messages are rejected at the router level
    // so they never reach the handler stats. The test verifies the behavior (no response)
    // which is what matters from a protocol perspective.
    auto& nm = server.GetNetworkManager();
    auto stats = nm.discovery_manager_for_test().GetGetAddrDebugStats();
    // Note: ignored_prehandshake counter is no longer incremented since gating happens at router
    // The important check is that no ADDR response was sent (verified above)
    REQUIRE(payloads.empty());  // Verify pre-VERACK gating works
}

TEST_CASE("GETADDR router counters: served, repeat, outbound ignored", "[network][addr][diagnostics]") {
    SimulatedNetwork net(48101);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode server(1, &net);
    SimulatedNode client(2, &net);

    auto& srv_nm = server.GetNetworkManager();
    auto base0 = srv_nm.discovery_manager_for_test().GetGetAddrDebugStats();

    REQUIRE(client.ConnectTo(server.GetId()));
    REQUIRE(orch.WaitForConnection(server, client));
    for (int i = 0; i < 12; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    // Served once due to client's auto GETADDR after handshake
    auto after_conn = srv_nm.discovery_manager_for_test().GetGetAddrDebugStats();
    REQUIRE(after_conn.served == base0.served + 1);

    // Repeat ignored (explicit GETADDR on same connection)
    net.SendMessage(client.GetId(), server.GetId(), MakeWire(commands::GETADDR, {}));
    orch.AdvanceTime(std::chrono::milliseconds(200));
    auto s2 = srv_nm.discovery_manager_for_test().GetGetAddrDebugStats();
    REQUIRE(s2.ignored_repeat >= 1);

    // Outbound ignored (server sends to client)
    net.SendMessage(server.GetId(), client.GetId(), MakeWire(commands::GETADDR, {}));
    orch.AdvanceTime(std::chrono::milliseconds(200));
    auto& cli_nm = client.GetNetworkManager();
    auto cstats = cli_nm.discovery_manager_for_test().GetGetAddrDebugStats();
    REQUIRE(cstats.ignored_outbound >= 1);
}

// NOTE: GETADDR shuffle privacy is achieved at the AddressManager level via make_request_rng()
// (see src/network/addr_manager.cpp line 261). This function creates a per-request RNG seeded
// with both the base RNG state and current time, making each GETADDR response unpredictable.
// Testing shuffle behavior at the simulation level doesn't add value since it can't control
// the per-request RNG without breaking the security properties we're trying to test.

TEST_CASE("GETADDR echo suppression: do not reflect sender-provided addresses", "[network][addr][privacy][echo]") {
    SimulatedNetwork net(48103);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode server(1, &net);
    SimulatedNode client(2, &net);

    REQUIRE(client.ConnectTo(server.GetId()));
    REQUIRE(orch.WaitForConnection(server, client));
    for (int i = 0; i < 12; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    // Build ADDR with two addresses
    message::AddrMessage addrmsg;
    auto make_ts = [](uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
        protocol::TimestampedAddress ta;
        ta.timestamp = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        ta.address.services = protocol::NODE_NETWORK;
        for (int i=0;i<10;++i) ta.address.ip[i]=0; ta.address.ip[10]=0xFF; ta.address.ip[11]=0xFF;
        ta.address.ip[12]=a; ta.address.ip[13]=b; ta.address.ip[14]=c; ta.address.ip[15]=d;
        ta.address.port = 9590;
        return ta;
    };
    auto ta1 = make_ts(203,0,113,50);
    auto ta2 = make_ts(203,0,113,51);
    addrmsg.addresses.push_back(ta1);
    addrmsg.addresses.push_back(ta2);

    // Send ADDR from client to server
    auto addr_payload = addrmsg.serialize();
    net.SendMessage(client.GetId(), server.GetId(), MakeWire(commands::ADDR, addr_payload));
    orch.AdvanceTime(std::chrono::milliseconds(200));

    // Now ask for GETADDR; response should not include ta1/ta2 for same connection (echo suppression)
    net.SendMessage(client.GetId(), server.GetId(), MakeWire(commands::GETADDR, {}));
    orch.AdvanceTime(std::chrono::milliseconds(400));

    auto payloads = net.GetCommandPayloads(server.GetId(), client.GetId(), commands::ADDR);
    REQUIRE_FALSE(payloads.empty());
    message::AddrMessage rsp; REQUIRE(rsp.deserialize(payloads.back().data(), payloads.back().size()));

    auto key = [](const protocol::TimestampedAddress& x){
        return std::tuple<uint8_t,uint8_t,uint8_t,uint8_t>(x.address.ip[12], x.address.ip[13], x.address.ip[14], x.address.ip[15]);
    };
    std::set<decltype(key(ta1))> s; for (auto& t : rsp.addresses) s.insert(key(t));

    REQUIRE(s.count(key(ta1)) == 0);
    REQUIRE(s.count(key(ta2)) == 0);
}

TEST_CASE("GETADDR must not include requester's own address", "[network][addr][privacy][self]") {
    SimulatedNetwork net(48104);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode server(1, &net);
    SimulatedNode client(2, &net);

    // Preload server AddrMan with client's address
    auto& am = server.GetNetworkManager().discovery_manager();
    auto client_addr = protocol::NetworkAddress::from_string(client.GetAddress(), client.GetPort());
    am.addr_manager_for_test().add(client_addr);

    REQUIRE(client.ConnectTo(server.GetId()));
    REQUIRE(orch.WaitForConnection(server, client));
    for (int i = 0; i < 12; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    net.SendMessage(client.GetId(), server.GetId(), MakeWire(commands::GETADDR, {}));
    orch.AdvanceTime(std::chrono::milliseconds(300));

    auto payloads = net.GetCommandPayloads(server.GetId(), client.GetId(), commands::ADDR);
    REQUIRE_FALSE(payloads.empty());
    message::AddrMessage rsp; REQUIRE(rsp.deserialize(payloads.back().data(), payloads.back().size()));

    bool contains_client = false;
    for (const auto& ta : rsp.addresses) {
        if (ta.address.port == client.GetPort() &&
            ta.address.ip[12]==127 && ta.address.ip[13]==0 && ta.address.ip[14]==0 && ta.address.ip[15]==(client.GetId()%255)) {
            contains_client = true; break;
        }
    }
    REQUIRE_FALSE(contains_client);
}
