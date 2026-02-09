// Copyright (c) 2025 The Unicity Foundation
// Tests for outbound connection netgroup diversity enforcement
//
// These tests verify that outbound connections are made to diverse /16 subnets,
// preventing eclipse attacks where an attacker controls a single /16.

#include "catch_amalgamated.hpp"
#include "../infra/simulated_network.hpp"
#include "../infra/simulated_node.hpp"
#include "infra/test_access.hpp"
#include "infra/mock_transport.hpp"
#include "../test_orchestrator.hpp"
#include "network/addr_manager.hpp"
#include "network/addr_relay_manager.hpp"
#include "network/connection_manager.hpp"
#include "network/protocol.hpp"
#include "util/netaddress.hpp"

#include <asio.hpp>
#include <set>

using namespace unicity::test;
using namespace unicity;
using unicity::test::AddrRelayManagerTestAccess;

namespace {

// Transport that records the address of each connect() call and always succeeds
class AddressTrackingTransport : public network::Transport {
public:
    struct Attempt { std::string address; uint16_t port; };

    const std::vector<Attempt>& attempts() const { return attempts_; }

    network::TransportConnectionPtr connect(const std::string& address, uint16_t port,
                                            network::ConnectCallback callback) override {
        attempts_.push_back({address, port});
        auto conn = std::make_shared<network::MockTransportConnection>(address, port);
        conn->set_inbound(false);
        if (callback) callback(true);
        return conn;
    }

    bool listen(uint16_t, std::function<void(network::TransportConnectionPtr)>) override { return true; }
    void stop_listening() override {}
    void run() override {}
    void stop() override {}
    bool is_running() const override { return true; }

private:
    std::vector<Attempt> attempts_;
};

} // namespace

// Helper to create a NetworkAddress from an IP string
static protocol::NetworkAddress MakeNetworkAddress(const std::string& ip_str, uint16_t port = 18444) {
    protocol::NetworkAddress addr;
    addr.services = protocol::ServiceFlags::NODE_NETWORK;
    addr.port = port;

    asio::error_code ec;
    auto ip_addr = asio::ip::make_address(ip_str, ec);
    if (ec) {
        throw std::runtime_error("Invalid IP: " + ip_str);
    }

    if (ip_addr.is_v4()) {
        auto v6_mapped = asio::ip::make_address_v6(asio::ip::v4_mapped, ip_addr.to_v4());
        auto bytes = v6_mapped.to_bytes();
        std::copy(bytes.begin(), bytes.end(), addr.ip.begin());
    } else {
        auto bytes = ip_addr.to_v6().to_bytes();
        std::copy(bytes.begin(), bytes.end(), addr.ip.begin());
    }

    return addr;
}

// NOTE: Tests use public routable IPs (8.x.x.x, 9.x.x.x etc.) because
// AddrManager correctly rejects RFC1918 (10.x.x.x, 192.168.x.x) addresses.
// This matches Bitcoin Core behavior where only routable addresses are stored.

TEST_CASE("Outbound diversity - same netgroup addresses rejected", "[network][outbound][security][unit]") {
    // Test that AttemptOutboundConnections skips addresses from netgroups
    // that already have outbound connections

    SECTION("AddrManager seeded with same /16 - only one selected per cycle") {
        asio::io_context io;
        network::ConnectionManager plm(io, network::ConnectionManager::Config{});
        network::AddrRelayManager pdm(&plm);
        auto& addr_mgr = AddrRelayManagerTestAccess::GetAddrManager(pdm);

        // Seed AddrManager with 10 addresses all from same /16 (8.50.x.x)
        // Using public routable IPs since AddrManager rejects RFC1918
        int added_count = 0;
        for (int i = 1; i <= 10; i++) {
            std::string ip = "8.50.0." + std::to_string(i);
            auto addr = MakeNetworkAddress(ip, 18444);
            if (addr_mgr.add(addr)) {
                added_count++;
            }
        }

        INFO("Added " << added_count << " addresses to AddrManager");
        REQUIRE(added_count == 10);

        // Verify they're all in the same netgroup
        REQUIRE(util::GetNetgroup("8.50.0.1") == "8.50");
        REQUIRE(util::GetNetgroup("8.50.0.10") == "8.50");

        auto transport = std::make_shared<AddressTrackingTransport>();
        plm.Init(transport, [](network::Peer*){}, [](){ return true; },
                 protocol::magic::REGTEST, /*local_nonce=*/42);

        plm.AttemptOutboundConnections(/*current_height=*/0);
        io.poll();
        io.restart();

        // Check connection attempts
        std::set<std::string> attempted_netgroups;
        for (const auto& a : transport->attempts()) {
            attempted_netgroups.insert(util::GetNetgroup(a.address));
        }

        // With outbound diversity enforcement:
        // - First address from 8.50.x.x should be attempted
        // - Subsequent addresses from same /16 should be SKIPPED
        INFO("Attempted " << transport->attempts().size() << " connections");
        INFO("Unique netgroups: " << attempted_netgroups.size());

        // Should only attempt ONE connection (all same netgroup)
        REQUIRE(transport->attempts().size() == 1);
        REQUIRE(attempted_netgroups.size() == 1);
        REQUIRE(attempted_netgroups.count("8.50") == 1);
    }

    SECTION("AddrManager seeded with diverse /16s - multiple selected") {
        asio::io_context io;
        network::ConnectionManager plm(io, network::ConnectionManager::Config{});
        network::AddrRelayManager pdm(&plm);
        auto& addr_mgr = AddrRelayManagerTestAccess::GetAddrManager(pdm);

        // Seed AddrManager with addresses from different /16 subnets
        REQUIRE(addr_mgr.add(MakeNetworkAddress("8.1.0.1", 18444)));
        REQUIRE(addr_mgr.add(MakeNetworkAddress("8.2.0.1", 18444)));
        REQUIRE(addr_mgr.add(MakeNetworkAddress("8.3.0.1", 18444)));
        REQUIRE(addr_mgr.add(MakeNetworkAddress("8.4.0.1", 18444)));

        // Verify they're in different netgroups
        REQUIRE(util::GetNetgroup("8.1.0.1") != util::GetNetgroup("8.2.0.1"));

        auto transport = std::make_shared<AddressTrackingTransport>();
        plm.Init(transport, [](network::Peer*){}, [](){ return true; },
                 protocol::magic::REGTEST, /*local_nonce=*/43);

        plm.AttemptOutboundConnections(/*current_height=*/0);
        io.poll();
        io.restart();

        std::set<std::string> attempted_netgroups;
        for (const auto& a : transport->attempts()) {
            attempted_netgroups.insert(util::GetNetgroup(a.address));
        }

        // Should attempt connections to multiple netgroups (up to max_outbound)
        INFO("Attempted connections to " << attempted_netgroups.size() << " unique netgroups");
        REQUIRE(attempted_netgroups.size() >= 2);
    }
}

TEST_CASE("Outbound diversity - existing outbound blocks same netgroup", "[network][outbound][security][unit]") {
    // This test verifies that when we already have an outbound connection to a netgroup,
    // we don't attempt additional connections to that same netgroup.
    //
    // Uses standalone PLM with AddressTrackingTransport: first connect to 8.50.x.x,
    // then attempt outbound to verify that netgroup is skipped.

    asio::io_context io;
    network::ConnectionManager plm(io, network::ConnectionManager::Config{});
    network::AddrRelayManager pdm(&plm);
    auto& addr_mgr = AddrRelayManagerTestAccess::GetAddrManager(pdm);

    auto transport = std::make_shared<AddressTrackingTransport>();
    plm.Init(transport, [](network::Peer*){}, [](){ return true; },
             protocol::magic::REGTEST, /*local_nonce=*/44);

    // First, establish an outbound connection to 8.50.x.x
    auto existing_addr = MakeNetworkAddress("8.50.0.100", 18444);
    auto rc = plm.ConnectTo(existing_addr, network::NetPermissionFlags::None, /*chain_height=*/0);
    REQUIRE(rc == network::ConnectionResult::Success);
    io.poll();
    io.restart();

    REQUIRE(plm.peer_count() == 1);

    // Seed AddrManager with more addresses from same /16 (8.50.x.x)
    int added = 0;
    for (int i = 1; i <= 5; i++) {
        std::string ip = "8.50.0." + std::to_string(i);
        if (addr_mgr.add(MakeNetworkAddress(ip, 18444))) {
            added++;
        }
    }
    INFO("Added " << added << " addresses from 8.50.x.x netgroup");

    // Record how many attempts before AttemptOutbound
    size_t attempts_before = transport->attempts().size();

    plm.AttemptOutboundConnections(/*current_height=*/0);
    io.poll();
    io.restart();

    // Check new connection attempts (skip the first one which was our manual ConnectTo)
    INFO("New attempts: " << (transport->attempts().size() - attempts_before));
    for (size_t i = attempts_before; i < transport->attempts().size(); i++) {
        auto ng = util::GetNetgroup(transport->attempts()[i].address);
        INFO("  Attempted " << transport->attempts()[i].address << " (netgroup: " << ng << ")");
        // Should NOT be in the 8.50 netgroup since we already have an outbound there
        REQUIRE(ng != "8.50");
    }
}

TEST_CASE("Outbound diversity - mixed netgroups prefer diverse selection", "[network][outbound][security][unit]") {
    // Test that when we have a mix of addresses from same and different netgroups,
    // we prefer diverse selection

    asio::io_context io;
    network::ConnectionManager plm(io, network::ConnectionManager::Config{});
    network::AddrRelayManager pdm(&plm);
    auto& addr_mgr = AddrRelayManagerTestAccess::GetAddrManager(pdm);

    // Add 5 addresses from 8.1.x.x
    for (int i = 1; i <= 5; i++) {
        addr_mgr.add(MakeNetworkAddress("8.1.0." + std::to_string(i), 18444));
    }

    // Add 5 addresses from 8.2.x.x
    for (int i = 1; i <= 5; i++) {
        addr_mgr.add(MakeNetworkAddress("8.2.0." + std::to_string(i), 18444));
    }

    // Add 5 addresses from 8.3.x.x
    for (int i = 1; i <= 5; i++) {
        addr_mgr.add(MakeNetworkAddress("8.3.0." + std::to_string(i), 18444));
    }

    auto transport = std::make_shared<AddressTrackingTransport>();
    plm.Init(transport, [](network::Peer*){}, [](){ return true; },
             protocol::magic::REGTEST, /*local_nonce=*/45);

    plm.AttemptOutboundConnections(/*current_height=*/0);
    io.poll();
    io.restart();

    std::set<std::string> attempted_netgroups;
    for (const auto& a : transport->attempts()) {
        attempted_netgroups.insert(util::GetNetgroup(a.address));
    }

    INFO("Total connection attempts: " << transport->attempts().size());
    INFO("Unique netgroups attempted: " << attempted_netgroups.size());

    // With 15 addresses across 3 netgroups and max_outbound=8:
    // Diversity enforcement means we should attempt at most 1 per netgroup = 3 attempts
    REQUIRE(attempted_netgroups.size() == 3);
    REQUIRE(transport->attempts().size() == 3);  // One from each netgroup, then stop
}

// Note: count_failures logic (Bitcoin Core parity net.cpp:2887) is tested via:
// 1. Unit tests in core_parity_tests.cpp verify fCountFailure=false doesn't increment attempts
// 2. The implementation in AttemptOutboundConnections passes count_failures based on
//    outbound netgroup diversity: count_failures = netgroups.size() >= min(max_outbound-1, 2)
