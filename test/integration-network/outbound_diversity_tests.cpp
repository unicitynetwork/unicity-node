// Copyright (c) 2025 The Unicity Foundation
// Tests for outbound connection netgroup diversity enforcement
//
// These tests verify that outbound connections are made to diverse /16 subnets,
// preventing eclipse attacks where an attacker controls a single /16.

#include "catch_amalgamated.hpp"
#include "../infra/simulated_network.hpp"
#include "../infra/simulated_node.hpp"
#include "../test_orchestrator.hpp"
#include "network/addr_manager.hpp"
#include "network/peer_discovery_manager.hpp"
#include "network/peer_lifecycle_manager.hpp"
#include "network/protocol.hpp"
#include "util/netaddress.hpp"

#include <asio.hpp>
#include <set>

using namespace unicity::test;
using namespace unicity;

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

    SimulatedNetwork network;
    SimulatedNode node(0, &network);
    TestOrchestrator orch(&network);

    // Access the AddrManager through the discovery manager
    auto& discovery = node.GetNetworkManager().discovery_manager_for_test();
    auto& addr_mgr = discovery.addr_manager_for_test();

    SECTION("AddrManager seeded with same /16 - only one selected per cycle") {
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

        // Track connection attempts
        std::vector<std::string> attempted_ips;
        std::set<std::string> attempted_netgroups;

        // Call AttemptOutboundConnections with a mock callback
        auto& peer_mgr = node.GetNetworkManager().peer_manager();
        peer_mgr.AttemptOutboundConnections(
            []() { return true; },  // is_running
            [&](const protocol::NetworkAddress& addr, network::ConnectionType /*conn_type*/) -> network::ConnectionResult {
                auto ip_opt = addr.to_string();
                if (ip_opt) {
                    attempted_ips.push_back(*ip_opt);
                    auto ng = util::GetNetgroup(*ip_opt);
                    attempted_netgroups.insert(ng);
                }
                // Return success so it counts as "connected"
                return network::ConnectionResult::Success;
            }
        );

        // With outbound diversity enforcement:
        // - First address from 8.50.x.x should be attempted
        // - Subsequent addresses from same /16 should be SKIPPED
        INFO("Attempted " << attempted_ips.size() << " connections");
        INFO("Unique netgroups: " << attempted_netgroups.size());

        // Should only attempt ONE connection (all same netgroup)
        REQUIRE(attempted_ips.size() == 1);
        REQUIRE(attempted_netgroups.size() == 1);
        REQUIRE(attempted_netgroups.count("8.50") == 1);
    }

    SECTION("AddrManager seeded with diverse /16s - multiple selected") {
        // Seed AddrManager with addresses from different /16 subnets
        // Using public routable IPs
        REQUIRE(addr_mgr.add(MakeNetworkAddress("8.1.0.1", 18444)));
        REQUIRE(addr_mgr.add(MakeNetworkAddress("8.2.0.1", 18444)));
        REQUIRE(addr_mgr.add(MakeNetworkAddress("8.3.0.1", 18444)));
        REQUIRE(addr_mgr.add(MakeNetworkAddress("8.4.0.1", 18444)));

        // Verify they're in different netgroups
        REQUIRE(util::GetNetgroup("8.1.0.1") != util::GetNetgroup("8.2.0.1"));

        std::set<std::string> attempted_netgroups;

        auto& peer_mgr = node.GetNetworkManager().peer_manager();
        peer_mgr.AttemptOutboundConnections(
            []() { return true; },
            [&](const protocol::NetworkAddress& addr, network::ConnectionType /*conn_type*/) -> network::ConnectionResult {
                auto ip_opt = addr.to_string();
                if (ip_opt) {
                    attempted_netgroups.insert(util::GetNetgroup(*ip_opt));
                }
                return network::ConnectionResult::Success;
            }
        );

        // Should attempt connections to multiple netgroups (up to max_outbound)
        INFO("Attempted connections to " << attempted_netgroups.size() << " unique netgroups");
        REQUIRE(attempted_netgroups.size() >= 2);
    }
}

TEST_CASE("Outbound diversity - existing outbound blocks same netgroup", "[network][outbound][security][unit]") {
    // This test verifies that when we already have an outbound connection to a netgroup,
    // we don't attempt additional connections to that same netgroup.
    //
    // Since the simulated network uses internal addresses for actual connections,
    // we test this by directly checking the peer_manager's behavior.

    SimulatedNetwork network;
    SimulatedNode nodeA(0, &network);
    // Node B with a public routable address
    SimulatedNode nodeB(1, &network, "8.50.0.100");
    TestOrchestrator orch(&network);

    // Connect nodeA -> nodeB (outbound from A's perspective)
    REQUIRE(nodeA.ConnectTo(1, "8.50.0.100"));
    REQUIRE(orch.WaitForConnection(nodeA, nodeB));

    // Verify nodeA has an outbound connection
    REQUIRE(nodeA.GetOutboundPeerCount() == 1);

    // Seed nodeA's AddrManager with more addresses from same /16 (8.50.x.x)
    auto& discovery = nodeA.GetNetworkManager().discovery_manager_for_test();
    auto& addr_mgr = discovery.addr_manager_for_test();

    int added = 0;
    for (int i = 1; i <= 5; i++) {
        std::string ip = "8.50.0." + std::to_string(i);
        if (addr_mgr.add(MakeNetworkAddress(ip, 18444))) {
            added++;
        }
    }
    INFO("Added " << added << " addresses from 8.50.x.x netgroup");

    // Track new connection attempts
    std::vector<std::string> new_attempts;

    auto& peer_mgr = nodeA.GetNetworkManager().peer_manager();
    peer_mgr.AttemptOutboundConnections(
        []() { return true; },
        [&](const protocol::NetworkAddress& addr, network::ConnectionType /*conn_type*/) -> network::ConnectionResult {
            auto ip_opt = addr.to_string();
            if (ip_opt) {
                new_attempts.push_back(*ip_opt);
            }
            return network::ConnectionResult::Success;
        }
    );

    // With existing outbound to 8.50.x.x, no NEW connections to that netgroup should be attempted
    INFO("New attempts: " << new_attempts.size());
    for (const auto& ip : new_attempts) {
        auto ng = util::GetNetgroup(ip);
        INFO("  Attempted " << ip << " (netgroup: " << ng << ")");
        // Should NOT be in the 8.50 netgroup since we already have an outbound there
        REQUIRE(ng != "8.50");
    }
}

TEST_CASE("Outbound diversity - mixed netgroups prefer diverse selection", "[network][outbound][security][unit]") {
    // Test that when we have a mix of addresses from same and different netgroups,
    // we prefer diverse selection

    SimulatedNetwork network;
    SimulatedNode node(0, &network);
    TestOrchestrator orch(&network);

    auto& discovery = node.GetNetworkManager().discovery_manager_for_test();
    auto& addr_mgr = discovery.addr_manager_for_test();

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

    std::set<std::string> attempted_netgroups;
    int total_attempts = 0;

    auto& peer_mgr = node.GetNetworkManager().peer_manager();
    peer_mgr.AttemptOutboundConnections(
        []() { return true; },
        [&](const protocol::NetworkAddress& addr, network::ConnectionType /*conn_type*/) -> network::ConnectionResult {
            auto ip_opt = addr.to_string();
            if (ip_opt) {
                attempted_netgroups.insert(util::GetNetgroup(*ip_opt));
                total_attempts++;
            }
            return network::ConnectionResult::Success;
        }
    );

    INFO("Total connection attempts: " << total_attempts);
    INFO("Unique netgroups attempted: " << attempted_netgroups.size());

    // With 15 addresses across 3 netgroups and max_outbound=8:
    // Diversity enforcement means we should attempt at most 1 per netgroup = 3 attempts
    REQUIRE(attempted_netgroups.size() == 3);
    REQUIRE(total_attempts == 3);  // One from each netgroup, then stop (all same-netgroup skipped)
}
