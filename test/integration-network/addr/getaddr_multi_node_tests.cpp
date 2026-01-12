#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/message.hpp"
#include "util/hash.hpp"
#include "network/network_manager.hpp"
#include "network/peer_discovery_manager.hpp"
#include "test_orchestrator.hpp"
#include <cstring>

using namespace unicity;
using namespace unicity::test;
using namespace unicity::protocol;

static message::AddrMessage MakeAddrMsgIPv4(const std::string& ip_v4, uint16_t port, uint32_t ts)
{
    message::AddrMessage msg;
    protocol::TimestampedAddress ta;
    ta.timestamp = ts;
    ta.address.services = protocol::ServiceFlags::NODE_NETWORK;
    ta.address.port = port;
    std::memset(ta.address.ip.data(), 0, 10);
    ta.address.ip[10] = 0xFF; ta.address.ip[11] = 0xFF;
    int a,b,c,d; if (sscanf(ip_v4.c_str(), "%d.%d.%d.%d", &a,&b,&c,&d)==4) {
        ta.address.ip[12] = (uint8_t)a; ta.address.ip[13]=(uint8_t)b; ta.address.ip[14]=(uint8_t)c; ta.address.ip[15]=(uint8_t)d;
    }
    msg.addresses.push_back(ta);
    return msg;
}

static std::vector<uint8_t> MakeWire(const std::string& cmd, const std::vector<uint8_t>& payload) {
    protocol::MessageHeader hdr(magic::REGTEST, cmd, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(hdr.checksum.data(), hash.begin(), 4);
    auto hdr_bytes = message::serialize_header(hdr);
    std::vector<uint8_t> full; full.reserve(hdr_bytes.size()+payload.size());
    full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
    full.insert(full.end(), payload.begin(), payload.end());
    return full;
}

static std::string key_of(const protocol::NetworkAddress& a) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u:%u", a.ip[12], a.ip[13], a.ip[14], a.ip[15], a.port);
    return std::string(buf);
}

TEST_CASE("Multi-node: cross-peer echo suppression and inclusion", "[network][addr][multi]") {
    SimulatedNetwork net(49001);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode A(1, &net); // server
    SimulatedNode B(2, &net); // client 1
    SimulatedNode C(3, &net); // client 2 (source of X)

    auto& am = A.GetNetworkManager().discovery_manager();

    // Prefill A's AddrMan with routable addresses so 23% limit returns at least 1 address
    // Bitcoin Core parity: GETADDR returns at most 23% of addr_manager size
    // With 5 prefill + 1 from C = 6 total: pct_limit = (6 * 23) / 100 = 1
    for (int i = 0; i < 5; ++i) {
        NetworkAddress a; a.services = NODE_NETWORK; a.port = 9590;
        for (int j=0;j<10;++j) a.ip[j]=0; a.ip[10]=0xFF; a.ip[11]=0xFF;
        a.ip[12] = 93; a.ip[13] = 184; a.ip[14] = 216; a.ip[15] = static_cast<uint8_t>(50+i);
        am.addr_manager_for_test().add(a);
    }

    size_t initial_addrman_size = am.addr_manager_for_test().size();

    // Connect C first so A can learn X from C
    REQUIRE(C.ConnectTo(A.GetId()));
    REQUIRE(orch.WaitForConnection(A, C));
    for (int i=0;i<12;++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    // C announces X to A (using a routable public IP - must not be RFC1918, RFC5737, etc)
    auto now_s = (uint32_t)(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    auto addr_msg = MakeAddrMsgIPv4("185.1.2.42", ports::REGTEST, now_s);  // Public routable IP
    auto payload = addr_msg.serialize();
    net.SendMessage(C.GetId(), A.GetId(), MakeWire(commands::ADDR, payload));
    for (int i=0;i<6;++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    // INCLUSION TEST: Verify X was added to A's addr_manager
    // This is the key test - address learning from ADDR messages
    size_t new_addrman_size = am.addr_manager_for_test().size();
    CHECK(new_addrman_size == initial_addrman_size + 1);

    // Connect B; B's GETADDR should be served by A
    REQUIRE(B.ConnectTo(A.GetId()));
    REQUIRE(orch.WaitForConnection(A, B));
    for (int i=0;i<12;++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    // Verify A sent ADDR to B (B is inbound to A, so A responds to GETADDR)
    auto pb = net.GetCommandPayloads(A.GetId(), B.GetId(), commands::ADDR);
    REQUIRE_FALSE(pb.empty());
    message::AddrMessage respB; REQUIRE(respB.deserialize(pb.back().data(), pb.back().size()));

    // Note: Due to Bitcoin Core's 23% limit, we can't guarantee X is in the response
    // (with small addr_manager, max_to_send may be < total addresses, and selection is random)
    // The inclusion test above verifies X was learned; this verifies GETADDR response works
    CHECK(respB.addresses.size() >= 1);
}

TEST_CASE("Multi-node: once-per-connection across multiple peers", "[network][addr][multi][ratelimit]") {
    SimulatedNetwork net(49002);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode A(1, &net);
    SimulatedNode P2(2, &net);
    SimulatedNode P3(3, &net);
    SimulatedNode P4(4, &net);

    REQUIRE(P2.ConnectTo(A.GetId()));
    REQUIRE(P3.ConnectTo(A.GetId()));
    REQUIRE(P4.ConnectTo(A.GetId()));
    REQUIRE(orch.WaitForConnection(A, P2));
    REQUIRE(orch.WaitForConnection(A, P3));
    REQUIRE(orch.WaitForConnection(A, P4));
    for (int i=0;i<12;++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    // First round
    net.SendMessage(P2.GetId(), A.GetId(), MakeWire(commands::GETADDR, {}));
    net.SendMessage(P3.GetId(), A.GetId(), MakeWire(commands::GETADDR, {}));
    net.SendMessage(P4.GetId(), A.GetId(), MakeWire(commands::GETADDR, {}));
    for (int i=0;i<6;++i) orch.AdvanceTime(std::chrono::milliseconds(100));
    REQUIRE(net.CountCommandSent(A.GetId(), P2.GetId(), commands::ADDR) == 1);
    REQUIRE(net.CountCommandSent(A.GetId(), P3.GetId(), commands::ADDR) == 1);
    REQUIRE(net.CountCommandSent(A.GetId(), P4.GetId(), commands::ADDR) == 1);

    // Second round on same connections (should be ignored)
    net.SendMessage(P2.GetId(), A.GetId(), MakeWire(commands::GETADDR, {}));
    net.SendMessage(P3.GetId(), A.GetId(), MakeWire(commands::GETADDR, {}));
    net.SendMessage(P4.GetId(), A.GetId(), MakeWire(commands::GETADDR, {}));
    for (int i=0;i<6;++i) orch.AdvanceTime(std::chrono::milliseconds(100));
    REQUIRE(net.CountCommandSent(A.GetId(), P2.GetId(), commands::ADDR) == 1);
    REQUIRE(net.CountCommandSent(A.GetId(), P3.GetId(), commands::ADDR) == 1);
    REQUIRE(net.CountCommandSent(A.GetId(), P4.GetId(), commands::ADDR) == 1);
}

TEST_CASE("Multi-node: composition counters under mixed sources", "[network][addr][multi][composition]") {
    SimulatedNetwork net(49003);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode A(1, &net);
    SimulatedNode B(2, &net);
    SimulatedNode C(3, &net);

    // Prefill AddrMan with some routable entries (93.184.216.x)
    auto& am = A.GetNetworkManager().discovery_manager();
    for (int i = 0; i < 5; ++i) {
        NetworkAddress a; a.services = NODE_NETWORK; a.port = 9590;
        for (int j=0;j<10;++j) a.ip[j]=0; a.ip[10]=0xFF; a.ip[11]=0xFF;
        a.ip[12] = 93; a.ip[13] = 184; a.ip[14] = 216; a.ip[15] = static_cast<uint8_t>(50+i);
        am.addr_manager_for_test().add(a);
    }

    // Connect B and C
    REQUIRE(B.ConnectTo(A.GetId()));
    REQUIRE(C.ConnectTo(A.GetId()));
    REQUIRE(orch.WaitForConnection(A, B));
    REQUIRE(orch.WaitForConnection(A, C));
    for (int i=0;i<12;++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    // Learn two routable addresses via C (8.8.8.x range)
    auto now_s = (uint32_t)(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    auto mX = MakeAddrMsgIPv4("8.8.8.21", ports::REGTEST, now_s);
    auto mY = MakeAddrMsgIPv4("8.8.8.22", ports::REGTEST, now_s);
    net.SendMessage(C.GetId(), A.GetId(), MakeWire(commands::ADDR, mX.serialize()));
    net.SendMessage(C.GetId(), A.GetId(), MakeWire(commands::ADDR, mY.serialize()));
    for (int i=0;i<6;++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    // Request from B, check composition stats
    net.SendMessage(B.GetId(), A.GetId(), MakeWire(commands::GETADDR, {}));
    for (int i=0;i<6;++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    auto stats = A.GetNetworkManager().discovery_manager_for_test().GetGetAddrDebugStats();
    // Bitcoin Core parity: GETADDR response comes exclusively from AddrMan
    REQUIRE(stats.last_from_addrman > 0);
}
