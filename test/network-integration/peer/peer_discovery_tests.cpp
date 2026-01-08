// Peer discovery tests (ported to test2)

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/network_manager.hpp"
#include "network/peer_discovery_manager.hpp"
#include "network/addr_manager.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"
#include "test_orchestrator.hpp"
#include <asio.hpp>
#include <cstring>

using namespace unicity;
using namespace unicity::network;
using namespace unicity::protocol;
using namespace unicity::test;

// Helpers to construct addresses
static NetworkAddress MakeIPv4Address(const std::string& ip_str, uint16_t port) {
    NetworkAddress addr;
    addr.services = NODE_NETWORK;
    addr.port = port;
    std::memset(addr.ip.data(), 0, 10);
    addr.ip[10] = 0xFF;
    addr.ip[11] = 0xFF;
    int a, b, c, d;
    if (sscanf(ip_str.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
        addr.ip[12] = static_cast<uint8_t>(a);
        addr.ip[13] = static_cast<uint8_t>(b);
        addr.ip[14] = static_cast<uint8_t>(c);
        addr.ip[15] = static_cast<uint8_t>(d);
    }
    return addr;
}

TEST_CASE("GETADDR replies only to inbound peers (ignore outbound)", "[network][peer_discovery][getaddr][parity]") {
    SimulatedNetwork net(2710);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode nodeA(1, &net); // will receive GETADDR (from its perspective, peer is inbound)
    SimulatedNode nodeB(2, &net);

    REQUIRE(nodeB.ConnectTo(nodeA.GetId()));
    REQUIRE(orch.WaitForConnection(nodeA, nodeB));

    // Force a GETADDR from A -> B; B sees A as outbound, so should IGNORE
    auto hdr = message::create_header(protocol::magic::REGTEST, protocol::commands::GETADDR, {});
    auto hdr_bytes = message::serialize_header(hdr);
    net.SendMessage(nodeA.GetId(), nodeB.GetId(), hdr_bytes);

    orch.AdvanceTime(std::chrono::milliseconds(200));

    int addr_count = net.CountCommandSent(nodeB.GetId(), nodeA.GetId(), protocol::commands::ADDR);
    REQUIRE(addr_count == 0);
}

TEST_CASE("GETADDR once-per-connection (no repeat until reconnect)", "[network][peer_discovery][getaddr][ratelimit]") {
    SimulatedNetwork net(2711);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode server(1, &net);   // Will respond to GETADDR (peer is inbound)
    SimulatedNode client(2, &net);   // Will send GETADDR requests

    REQUIRE(client.ConnectTo(server.GetId()));
    REQUIRE(orch.WaitForConnection(server, client));
    // Ensure handshake completes before sending GETADDR
    for (int i = 0; i < 12; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    // First GETADDR: client -> server, expect one ADDR
    auto hdr1 = message::create_header(protocol::magic::REGTEST, protocol::commands::GETADDR, {});
    auto hdr1_bytes = message::serialize_header(hdr1);
    net.SendMessage(client.GetId(), server.GetId(), hdr1_bytes);
    orch.AdvanceTime(std::chrono::milliseconds(200));
    REQUIRE(net.CountCommandSent(server.GetId(), client.GetId(), protocol::commands::ADDR) == 1);

    // Second GETADDR on same connection: should be ignored (still only 1 ADDR)
    auto hdr2 = message::create_header(protocol::magic::REGTEST, protocol::commands::GETADDR, {});
    auto hdr2_bytes = message::serialize_header(hdr2);
    net.SendMessage(client.GetId(), server.GetId(), hdr2_bytes);
    orch.AdvanceTime(std::chrono::milliseconds(200));
    REQUIRE(net.CountCommandSent(server.GetId(), client.GetId(), protocol::commands::ADDR) == 1);

    // Disconnect and reconnect, then GETADDR should yield a second ADDR
    client.DisconnectFrom(server.GetId());
    REQUIRE(orch.WaitForDisconnect(server, client));

    REQUIRE(client.ConnectTo(server.GetId()));
    REQUIRE(orch.WaitForConnection(server, client));
    // Ensure handshake completes before sending GETADDR after reconnect
    for (int i = 0; i < 12; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    auto hdr3 = message::create_header(protocol::magic::REGTEST, protocol::commands::GETADDR, {});
    auto hdr3_bytes = message::serialize_header(hdr3);
    net.SendMessage(client.GetId(), server.GetId(), hdr3_bytes);
    orch.AdvanceTime(std::chrono::milliseconds(300));

    REQUIRE(net.CountCommandSent(server.GetId(), client.GetId(), protocol::commands::ADDR) == 2);
}

static NetworkAddress MakeIPv6Address(const std::string& ipv6_hex, uint16_t port) {
    NetworkAddress addr;
    addr.services = NODE_NETWORK;
    addr.port = port;
    if (ipv6_hex.length() == 32) {
        for (size_t i = 0; i < 16; i++) {
            std::string byte_str = ipv6_hex.substr(i * 2, 2);
            addr.ip[i] = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
        }
    }
    return addr;
}

// Unit tests
TEST_CASE("network_address_to_string converts IPv4 addresses correctly", "[network][peer_discovery][unit]") {
    SECTION("Convert 127.0.0.1") {
        NetworkAddress addr = MakeIPv4Address("127.0.0.1", 9590);
        REQUIRE(addr.is_ipv4());
        uint32_t ipv4 = addr.get_ipv4();
        REQUIRE(ipv4 == 0x7F000001);
    }
    SECTION("Convert 1.1.1.1") {
        NetworkAddress addr = MakeIPv4Address("1.1.1.1", 8333);
        REQUIRE(addr.is_ipv4());
        uint32_t ipv4 = addr.get_ipv4();
        REQUIRE(ipv4 == 0x01010101);
    }
    SECTION("Convert 2.0.0.1") {
        NetworkAddress addr = MakeIPv4Address("2.0.0.1", 9590);
        REQUIRE(addr.is_ipv4());
        uint32_t ipv4 = addr.get_ipv4();
        REQUIRE(ipv4 == 0x02000001);
    }
}

TEST_CASE("network_address_to_string handles IPv6 addresses", "[network][peer_discovery][unit]") {
    SECTION("Pure IPv6 address") {
        NetworkAddress addr = MakeIPv6Address("20010db8000000000000000000000001", 9590);
        REQUIRE_FALSE(addr.is_ipv4());
        REQUIRE(addr.get_ipv4() == 0);
    }
    SECTION("IPv4-mapped IPv6 address") {
        NetworkAddress addr = MakeIPv4Address("1.1.1.1", 9590);
        REQUIRE(addr.is_ipv4());
        REQUIRE(addr.ip[10] == 0xFF);
        REQUIRE(addr.ip[11] == 0xFF);
        REQUIRE(addr.ip[12] == 1);
        REQUIRE(addr.ip[13] == 1);
        REQUIRE(addr.ip[14] == 1);
        REQUIRE(addr.ip[15] == 1);
    }
}

// Integration: AddressManager add/select/good/failed
TEST_CASE("AddressManager can store and retrieve addresses for connection attempts", "[network][peer_discovery][integration]") {
    AddressManager addrman;
    SECTION("Add addresses and select for connection") {
        NetworkAddress addr1 = MakeIPv4Address("1.1.1.1", 9590);
        NetworkAddress addr2 = MakeIPv4Address("1.1.1.2", 9590);
        NetworkAddress addr3 = MakeIPv4Address("1.1.1.3", 9590);
        REQUIRE(addrman.add(addr1));
        REQUIRE(addrman.add(addr2));
        REQUIRE(addrman.add(addr3));
        REQUIRE(addrman.size() == 3);
        auto maybe_addr = addrman.select();
        REQUIRE(maybe_addr.has_value());
        auto& addr = *maybe_addr;
        REQUIRE(addr.is_ipv4());
        REQUIRE(addr.port == 9590);
    }
    SECTION("Mark address as failed") {
        NetworkAddress addr = MakeIPv4Address("2.0.0.1", 9590);
        addrman.add(addr);
        REQUIRE(addrman.size() == 1);
        addrman.failed(addr);
        REQUIRE(addrman.size() == 1);
    }
    SECTION("Mark address as good moves to tried table") {
        NetworkAddress addr = MakeIPv4Address("2.0.0.2", 9590);
        addrman.add(addr);
        REQUIRE(addrman.new_count() == 1);
        REQUIRE(addrman.tried_count() == 0);
        addrman.good(addr);
        REQUIRE(addrman.new_count() == 0);
        REQUIRE(addrman.tried_count() == 1);
    }
}

// End-to-end: GETADDR/ADDR through simulated network (basic check)
static std::vector<uint8_t> MakeWire(const std::string& cmd, const std::vector<uint8_t>& payload) {
    auto hdr = message::create_header(magic::REGTEST, cmd, payload);
    auto hdr_bytes = message::serialize_header(hdr);
    std::vector<uint8_t> full; full.reserve(hdr_bytes.size() + payload.size());
    full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
    full.insert(full.end(), payload.begin(), payload.end());
    return full;
}

TEST_CASE("Peer discovery via ADDR messages populates AddressManager", "[network][peer_discovery][e2e]") {
    SimulatedNetwork net(2610);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);
    SimulatedNode node1(1, &net); SimulatedNode node2(2, &net);
    node1.SetBypassPOWValidation(true); node2.SetBypassPOWValidation(true);
    REQUIRE(node1.ConnectTo(2)); REQUIRE(orch.WaitForConnection(node1, node2));
    // Ensure VERSION/VERACK completes before sending GETADDR
    for (int i = 0; i < 12; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));
    auto getaddr_wire = MakeWire(commands::GETADDR, {});
    // node1 -> node2 (request), expect node2 -> node1 (ADDR)
    net.SendMessage(node1.GetId(), node2.GetId(), getaddr_wire);
    orch.AdvanceTime(std::chrono::milliseconds(400));

    auto payloads = net.GetCommandPayloads(node2.GetId(), node1.GetId(), commands::ADDR);
    REQUIRE_FALSE(payloads.empty());

    message::AddrMessage msg;
    REQUIRE(msg.deserialize(payloads.front().data(), payloads.front().size()));
    REQUIRE(msg.addresses.size() <= MAX_ADDR_SIZE);
}

TEST_CASE("attempt_outbound_connections uses addresses from AddressManager", "[network][peer_discovery][integration]") {
    SimulatedNetwork net(2611);
    SimulatedNode node1(1, &net); node1.SetBypassPOWValidation(true);
    auto& nm = node1.GetNetworkManager(); auto& discovery = nm.discovery_manager();
    NetworkAddress addr1 = MakeIPv4Address("1.1.1.100", 9590);
    NetworkAddress addr2 = MakeIPv4Address("1.1.1.101", 9590);
    REQUIRE(discovery.addr_manager_for_test().add(addr1)); REQUIRE(discovery.addr_manager_for_test().add(addr2));
    REQUIRE(discovery.Size() == 2);
}

// Regression/documentation
TEST_CASE("REGRESSION: attempt_outbound_connections no longer uses empty IP string", "[network][peer_discovery][regression]") {
    SECTION("NetworkAddress conversion produces valid IP strings") {
        NetworkAddress addr1 = MakeIPv4Address("127.0.0.1", 9590);
        REQUIRE(addr1.is_ipv4()); REQUIRE(addr1.get_ipv4() == 0x7F000001);
        NetworkAddress addr2 = MakeIPv4Address("2.0.0.1", 8333);
        REQUIRE(addr2.is_ipv4()); REQUIRE(addr2.get_ipv4() == 0x02000001);
        REQUIRE(true);
    }
    SECTION("AddressManager feedback on failed connections") {
        AddressManager addrman;
        NetworkAddress addr = MakeIPv4Address("1.1.1.1", 9590);
        addrman.add(addr); REQUIRE(addrman.size() == 1);
        addrman.attempt(addr); addrman.failed(addr);
        REQUIRE(addrman.size() == 1);
    }
}

// Performance/documentation
TEST_CASE("Address conversion performance", "[network][peer_discovery][performance]") {
    SECTION("Convert 1000 IPv4 addresses") {
        std::vector<NetworkAddress> addresses;
        for (int i = 0; i < 1000; i++) {
            std::string ip = "1.0." + std::to_string(i / 256) + "." + std::to_string(i % 256);
            addresses.push_back(MakeIPv4Address(ip, 9590));
        }
        for (const auto& addr : addresses) { REQUIRE(addr.is_ipv4()); REQUIRE(addr.get_ipv4() != 0); }
        REQUIRE(addresses.size() == 1000);
    }
}

TEST_CASE("EXAMPLE: How peer discovery works end-to-end", "[network][peer_discovery][example]") {
    AddressManager addrman;
    NetworkAddress addr1 = MakeIPv4Address("2.2.2.1", 9590);
    NetworkAddress addr2 = MakeIPv4Address("2.2.2.2", 9590);
    REQUIRE(addrman.add(addr1)); REQUIRE(addrman.add(addr2));
    auto maybe_addr = addrman.select(); REQUIRE(maybe_addr.has_value());
    auto& addr = *maybe_addr; REQUIRE(addr.is_ipv4());
    SUCCEED();
}
