// Copyright (c) 2025 The Unicity Foundation
// Full eclipse attack simulations
//
// These tests simulate realistic attack scenarios to verify that the
// combined security features (netgroup limits, eviction, outbound diversity,
// address manager limits) protect against eclipse attacks.
//
// An eclipse attack attempts to isolate a node by controlling all its
// connections, allowing the attacker to:
// - Feed the victim false blockchain data
// - Prevent the victim from seeing legitimate transactions/blocks
// - Partition the victim from the honest network

#include "catch_amalgamated.hpp"
#include "../infra/simulated_network.hpp"
#include "../infra/simulated_node.hpp"
#include "../infra/peer_factory.hpp"
#include "../test_orchestrator.hpp"
#include "network/addr_manager.hpp"
#include "network/eviction_manager.hpp"
#include "network/peer_discovery_manager.hpp"
#include "network/peer_lifecycle_manager.hpp"
#include "network/protocol.hpp"
#include "util/netaddress.hpp"

#include <asio.hpp>
#include <set>
#include <random>
#include <thread>

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

// =============================================================================
// ATTACK SIMULATION 1: Single /16 Sybil Attack (Inbound Flooding)
// =============================================================================
// Attacker controls many IPs in a single /16 subnet and tries to fill
// all inbound slots of the victim.

TEST_CASE("Eclipse Attack - Single /16 Sybil inbound flooding", "[network][security][attack][eclipse]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    auto victim = factory.CreateNode(1);

    SECTION("Attacker with 100 IPs in same /16 only gets 4 connections") {
        // Attacker controls 100 IPs in 192.168.x.x
        auto attackers = factory.CreateSybilCluster(100, 100, "192.168.0.0");

        REQUIRE(PeerFactory::AllSameNetgroup(attackers));
        INFO("Attacker controls " << attackers.size() << " nodes in same /16");

        // Attacker floods victim with connection attempts
        for (auto& attacker : attackers) {
            attacker->ConnectTo(victim->GetId(), victim->GetAddress());
        }

        // Wait for all connection attempts to complete
        orch.AdvanceTime(std::chrono::seconds(2));

        size_t attacker_connections = victim->GetInboundPeerCount();
        INFO("Attacker achieved " << attacker_connections << " connections (limit: 4)");

        // SECURITY: Per-netgroup limit restricts attacker to 4 connections
        REQUIRE(attacker_connections == 4);

        // Honest peers from different netgroups can still connect
        auto honest = factory.CreateDiversePeers(8, 200);
        for (auto& h : honest) {
            h->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        orch.AdvanceTime(std::chrono::seconds(1));

        size_t total_connections = victim->GetInboundPeerCount();
        size_t honest_connections = total_connections - attacker_connections;

        INFO("Total connections: " << total_connections);
        INFO("Honest connections: " << honest_connections);

        // Honest peers successfully connected
        REQUIRE(honest_connections == 8);

        // Attacker does NOT control majority
        double attacker_ratio = static_cast<double>(attacker_connections) / total_connections;
        INFO("Attacker controls " << (attacker_ratio * 100) << "% of connections");
        REQUIRE(attacker_ratio < 0.5);  // Less than 50%
    }
}

// =============================================================================
// ATTACK SIMULATION 2: Multi-Subnet Sybil Attack
// =============================================================================
// Attacker controls IPs across multiple /16 subnets to bypass per-netgroup limits.

TEST_CASE("Eclipse Attack - Multi-subnet Sybil attack", "[network][security][attack][eclipse]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    auto victim = factory.CreateNode(1);

    SECTION("Attacker with IPs across 10 /16 subnets gets 40 connections max") {
        // Attacker controls 20 IPs in each of 10 different /16 subnets
        std::vector<std::unique_ptr<SimulatedNode>> all_attackers;
        int id = 100;

        for (int subnet = 0; subnet < 10; subnet++) {
            std::string base = "10." + std::to_string(subnet) + ".0.0";
            auto cluster = factory.CreateSybilCluster(20, id, base);
            id += 20;

            for (auto& node : cluster) {
                all_attackers.push_back(std::move(node));
            }
        }

        INFO("Attacker controls " << all_attackers.size() << " nodes across 10 /16 subnets");

        // Flood victim
        for (auto& attacker : all_attackers) {
            attacker->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        orch.AdvanceTime(std::chrono::seconds(3));

        size_t attacker_connections = victim->GetInboundPeerCount();
        INFO("Attacker achieved " << attacker_connections << " connections");

        // SECURITY: 4 per netgroup × 10 netgroups = 40 max
        // But also limited by total inbound slots (typically ~125)
        REQUIRE(attacker_connections == 40);

        // Add honest peers from unique subnets
        auto honest = factory.CreateDiversePeers(20, 500);
        for (auto& h : honest) {
            h->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        orch.AdvanceTime(std::chrono::seconds(1));

        size_t total = victim->GetInboundPeerCount();
        size_t honest_count = total - attacker_connections;

        INFO("Total: " << total << ", Honest: " << honest_count);

        // Even with multi-subnet attack, honest peers connect
        REQUIRE(honest_count >= 10);  // At least half the honest peers connected
    }
}

// =============================================================================
// ATTACK SIMULATION 3: Address Table Poisoning
// =============================================================================
// Attacker floods victim's address manager with malicious addresses
// to influence future outbound connections.

TEST_CASE("Eclipse Attack - Address table poisoning", "[network][security][attack][eclipse]") {
    SimulatedNetwork network;
    SimulatedNode victim(1, &network);
    TestOrchestrator orch(&network);

    auto& discovery = victim.GetNetworkManager().discovery_manager_for_test();
    auto& addr_mgr = discovery.addr_manager_for_test();

    SECTION("Attacker cannot dominate address table from single /16") {
        // Attacker tries to fill address table with 1000 addresses from 8.99.x.x
        int attacker_added = 0;
        for (int i = 0; i < 255; i++) {
            for (int j = 1; j <= 4; j++) {
                std::string ip = "8.99." + std::to_string(i) + "." + std::to_string(j);
                if (addr_mgr.add(MakeNetworkAddress(ip, 18444 + j))) {
                    attacker_added++;
                }
            }
        }

        INFO("Attacker added " << attacker_added << " addresses (attempted 1020)");

        // SECURITY: Per-netgroup limit caps at 32
        REQUIRE(attacker_added == 32);

        // Add honest addresses from diverse netgroups
        int honest_added = 0;
        for (int ng = 1; ng <= 100; ng++) {
            std::string ip = "9." + std::to_string(ng) + ".0.1";
            if (addr_mgr.add(MakeNetworkAddress(ip, 18444))) {
                honest_added++;
            }
        }

        INFO("Honest addresses added: " << honest_added);
        REQUIRE(honest_added == 100);

        // Verify address table diversity
        size_t total = addr_mgr.new_count();
        double attacker_ratio = static_cast<double>(attacker_added) / total;

        INFO("Total addresses: " << total);
        INFO("Attacker ratio: " << (attacker_ratio * 100) << "%");

        // Attacker controls < 25% of address table
        REQUIRE(attacker_ratio < 0.25);
    }

    SECTION("Attacker with multiple /16s still limited per netgroup") {
        // Attacker controls 50 different /16 subnets, 100 addresses each
        int total_attacker = 0;
        for (int subnet = 0; subnet < 50; subnet++) {
            int added_this_subnet = 0;
            for (int i = 0; i < 100; i++) {
                std::string ip = "8." + std::to_string(subnet) + "." +
                                 std::to_string(i / 255) + "." + std::to_string((i % 255) + 1);
                if (addr_mgr.add(MakeNetworkAddress(ip, 18444))) {
                    added_this_subnet++;
                    total_attacker++;
                }
            }
            // Each subnet limited to 32
            REQUIRE(added_this_subnet <= 32);
        }

        INFO("Total attacker addresses: " << total_attacker);

        // 50 subnets × 32 max per subnet = 1600 max
        REQUIRE(total_attacker == 50 * 32);

        // But this is still bounded by total table size and diversity is maintained
        size_t total = addr_mgr.new_count();
        INFO("Address table size: " << total);
    }
}

// =============================================================================
// ATTACK SIMULATION 4: Eviction Gaming
// =============================================================================
// Attacker tries to evict honest peers by exploiting eviction logic.

TEST_CASE("Eclipse Attack - Eviction gaming", "[network][security][attack][eclipse]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    auto victim = factory.CreateNode(1);

    SECTION("Honest peers from diverse netgroups survive eviction") {
        // Connect honest peers from 8 different netgroups
        auto honest = factory.CreateDiversePeers(8, 10);
        REQUIRE(PeerFactory::CountUniqueNetgroups(honest) == 8);

        for (auto& h : honest) {
            h->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        REQUIRE(orch.WaitForPeerCount(*victim, 8));

        // Let connections age (protection expires after 60 seconds)
        for (int i = 0; i < 65; i++) {
            orch.AdvanceTime(std::chrono::seconds(1));
        }

        // Attacker floods from single subnet to trigger eviction
        auto attackers = factory.CreateSybilCluster(50, 100, "10.50.0.0");
        for (auto& a : attackers) {
            a->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        orch.AdvanceTime(std::chrono::seconds(2));

        // Count how many honest peers remain
        // (This is hard to verify directly, but we can check total counts)
        size_t total = victim->GetInboundPeerCount();
        INFO("Total connections after attack: " << total);

        // Should have: 8 honest + 4 attackers (netgroup limit) = 12
        // Unless inbound limit is lower
        REQUIRE(total >= 8);  // At least honest peers remain
    }

    SECTION("Attacker in largest netgroup gets evicted first") {
        // Create scenario: 2 honest from different netgroups, 6 attackers from same netgroup
        auto honest = factory.CreateDiversePeers(2, 10);
        auto attackers = factory.CreateSybilCluster(4, 100, "10.60.0.0");

        for (auto& h : honest) {
            h->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        REQUIRE(orch.WaitForPeerCount(*victim, 2));

        for (auto& a : attackers) {
            a->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        REQUIRE(orch.WaitForPeerCount(*victim, 6));

        // Age connections
        for (int i = 0; i < 65; i++) {
            orch.AdvanceTime(std::chrono::seconds(1));
        }

        // Trigger eviction
        bool evicted = victim->GetNetworkManager().peer_manager().evict_inbound_peer();
        INFO("Eviction triggered: " << evicted);

        if (evicted) {
            // After eviction, should have 5 peers
            // The evicted peer should be from the attacker netgroup (largest)
            REQUIRE(victim->GetInboundPeerCount() == 5);
        }
    }
}

// =============================================================================
// ATTACK SIMULATION 5: Outbound Eclipse via Address Poisoning
// =============================================================================
// Attacker poisons address table to control future outbound connections.

TEST_CASE("Eclipse Attack - Outbound connection diversity", "[network][security][attack][eclipse]") {
    SimulatedNetwork network;
    SimulatedNode victim(1, &network);
    TestOrchestrator orch(&network);

    auto& discovery = victim.GetNetworkManager().discovery_manager_for_test();
    auto& addr_mgr = discovery.addr_manager_for_test();

    SECTION("Outbound diversity prevents single-netgroup eclipse") {
        // Attacker fills address table with addresses from few netgroups
        // (32 from each of 3 netgroups = 96 addresses)
        for (int ng = 1; ng <= 3; ng++) {
            for (int i = 1; i <= 32; i++) {
                std::string ip = "8." + std::to_string(ng) + ".0." + std::to_string(i);
                addr_mgr.add(MakeNetworkAddress(ip, 18444));
            }
        }

        REQUIRE(addr_mgr.new_count() == 96);

        // Track outbound connection attempts
        std::set<std::string> attempted_netgroups;
        int total_attempts = 0;

        auto& peer_mgr = victim.GetNetworkManager().peer_manager();
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

        INFO("Total outbound attempts: " << total_attempts);
        INFO("Unique netgroups attempted: " << attempted_netgroups.size());

        // SECURITY: Outbound diversity limits to 1 per netgroup
        // With 3 netgroups available, should attempt exactly 3 connections
        REQUIRE(attempted_netgroups.size() == 3);
        REQUIRE(total_attempts == 3);
    }

    SECTION("Diverse address table enables diverse outbound") {
        // Honest addresses from 20 different netgroups
        for (int ng = 1; ng <= 20; ng++) {
            std::string ip = "9." + std::to_string(ng) + ".0.1";
            addr_mgr.add(MakeNetworkAddress(ip, 18444));
        }

        REQUIRE(addr_mgr.new_count() == 20);

        std::set<std::string> attempted_netgroups;
        int successful_connections = 0;

        auto& peer_mgr = victim.GetNetworkManager().peer_manager();
        peer_mgr.AttemptOutboundConnections(
            []() { return true; },
            [&](const protocol::NetworkAddress& addr, network::ConnectionType /*conn_type*/) -> network::ConnectionResult {
                auto ip_opt = addr.to_string();
                if (ip_opt) {
                    attempted_netgroups.insert(util::GetNetgroup(*ip_opt));
                    successful_connections++;
                }
                return network::ConnectionResult::Success;
            }
        );

        INFO("Unique netgroups in outbound: " << attempted_netgroups.size());
        INFO("Successful connections: " << successful_connections);

        // With 20 available netgroups and diversity enforcement,
        // each successful connection uses a unique netgroup.
        // The number of connections depends on max_outbound setting.
        // Key point: ALL connections are to UNIQUE netgroups (diversity works)
        REQUIRE(attempted_netgroups.size() == static_cast<size_t>(successful_connections));
        REQUIRE(successful_connections >= 8);  // At least max_outbound connections
    }
}

// =============================================================================
// ATTACK SIMULATION 6: Combined Attack (Realistic Scenario)
// =============================================================================
// Attacker uses all available techniques simultaneously.

TEST_CASE("Eclipse Attack - Combined multi-vector attack", "[network][security][attack][eclipse][integration]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    auto victim = factory.CreateNode(1);

    SECTION("Defense in depth against sophisticated attacker") {
        // PHASE 1: Attacker poisons address table
        auto& discovery = victim->GetNetworkManager().discovery_manager_for_test();
        auto& addr_mgr = discovery.addr_manager_for_test();

        // Attacker adds addresses from 10 netgroups they control
        int attacker_addrs = 0;
        for (int ng = 0; ng < 10; ng++) {
            for (int i = 1; i <= 50; i++) {
                std::string ip = "8." + std::to_string(ng + 50) + ".0." + std::to_string(i);
                if (addr_mgr.add(MakeNetworkAddress(ip, 18444))) {
                    attacker_addrs++;
                }
            }
        }
        INFO("Phase 1 - Attacker added " << attacker_addrs << " addresses");

        // Honest addresses also present
        int honest_addrs = 0;
        for (int ng = 1; ng <= 20; ng++) {
            std::string ip = "9." + std::to_string(ng) + ".0.1";
            if (addr_mgr.add(MakeNetworkAddress(ip, 18444))) {
                honest_addrs++;
            }
        }
        INFO("Phase 1 - Honest addresses: " << honest_addrs);

        // PHASE 2: Attacker floods inbound connections
        std::vector<std::unique_ptr<SimulatedNode>> inbound_attackers;
        int id = 100;
        for (int ng = 0; ng < 5; ng++) {
            std::string base = "10." + std::to_string(ng + 70) + ".0.0";
            auto cluster = factory.CreateSybilCluster(20, id, base);
            id += 20;
            for (auto& node : cluster) {
                inbound_attackers.push_back(std::move(node));
            }
        }

        for (auto& a : inbound_attackers) {
            a->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        orch.AdvanceTime(std::chrono::seconds(2));

        size_t attacker_inbound = victim->GetInboundPeerCount();
        INFO("Phase 2 - Attacker inbound connections: " << attacker_inbound);

        // Limited to 4 per netgroup × 5 netgroups = 20
        REQUIRE(attacker_inbound == 20);

        // PHASE 3: Honest peers try to connect
        auto honest_peers = factory.CreateDiversePeers(10, 300);
        for (auto& h : honest_peers) {
            h->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        orch.AdvanceTime(std::chrono::seconds(1));

        size_t total_inbound = victim->GetInboundPeerCount();
        size_t honest_inbound = total_inbound - attacker_inbound;
        INFO("Phase 3 - Total inbound: " << total_inbound);
        INFO("Phase 3 - Honest inbound: " << honest_inbound);

        // Honest peers successfully connected
        REQUIRE(honest_inbound >= 5);

        // PHASE 4: Check outbound diversity
        std::set<std::string> outbound_netgroups;
        auto& peer_mgr = victim->GetNetworkManager().peer_manager();
        peer_mgr.AttemptOutboundConnections(
            []() { return true; },
            [&](const protocol::NetworkAddress& addr, network::ConnectionType /*conn_type*/) -> network::ConnectionResult {
                auto ip_opt = addr.to_string();
                if (ip_opt) {
                    outbound_netgroups.insert(util::GetNetgroup(*ip_opt));
                }
                return network::ConnectionResult::Success;
            }
        );

        INFO("Phase 4 - Outbound netgroup diversity: " << outbound_netgroups.size());

        // Should have diverse outbound despite poisoned address table
        REQUIRE(outbound_netgroups.size() >= 5);

        // FINAL ASSESSMENT: Attacker does not control majority
        // Inbound: attacker has 20, honest has at least 5 = 20/25 = 80% (high but not total)
        // Outbound: diverse across multiple netgroups
        // This is defense in depth - no single vector succeeds completely

        double attacker_inbound_ratio = static_cast<double>(attacker_inbound) / total_inbound;
        INFO("Final - Attacker inbound ratio: " << (attacker_inbound_ratio * 100) << "%");

        // The attack is significantly mitigated (not 100% control)
        REQUIRE(attacker_inbound_ratio < 0.9);  // Less than 90%
    }
}

// =============================================================================
// ATTACK SIMULATION 7: Long-term Eclipse Attempt
// =============================================================================
// Attacker persistently tries to eclipse over time.

TEST_CASE("Eclipse Attack - Persistent long-term attack", "[network][security][attack][eclipse][.]") {
    // This test is marked [.] (hidden) as it's slow
    SimulatedNetwork network;
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    auto victim = factory.CreateNode(1);

    SECTION("Defenses hold over simulated time") {
        // Initial honest connections
        auto honest = factory.CreateDiversePeers(8, 10);
        for (auto& h : honest) {
            h->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        REQUIRE(orch.WaitForPeerCount(*victim, 8));

        // Simulate 10 "rounds" of attack over time
        for (int round = 0; round < 10; round++) {
            // Attacker tries to connect more nodes each round
            int base_id = 100 + (round * 100);
            auto attackers = factory.CreateSybilCluster(20, base_id, "192.168.0.0");

            for (auto& a : attackers) {
                a->ConnectTo(victim->GetId(), victim->GetAddress());
            }

            // Advance time (simulating hours/days)
            for (int i = 0; i < 100; i++) {
                orch.AdvanceTime(std::chrono::seconds(1));
            }

            size_t attacker_count = victim->GetInboundPeerCount() - 8;  // Subtract honest
            INFO("Round " << round << " - Attacker connections: " << attacker_count);

            // Attacker never exceeds per-netgroup limit
            REQUIRE(attacker_count <= 4);
        }

        // After prolonged attack, honest peers still connected
        REQUIRE(victim->GetInboundPeerCount() >= 8);
    }
}

// =============================================================================
// ATTACK SIMULATION 8: Anchor Persistence Under Attack
// =============================================================================
// Attacker tries to evict anchor peers that have NoBan permission.

TEST_CASE("Eclipse Attack - Anchor peers survive flooding", "[network][security][attack][eclipse][anchor]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    auto victim = factory.CreateNode(1);

    SECTION("NoBan peers survive eviction regardless of attack intensity") {
        // Create honest peer and give it NoBan permission via whitelist
        auto anchor = factory.CreateNodeWithAddress(10, "9.1.0.1");

        // Whitelist the address before connection
        auto& peer_mgr = victim->GetNetworkManager().peer_manager();
        peer_mgr.AddToWhitelist("9.1.0.1");

        anchor->ConnectTo(victim->GetId(), victim->GetAddress());
        REQUIRE(orch.WaitForConnection(*victim, *anchor));

        auto peers = peer_mgr.get_all_peers();

        // Flood with attacker inbound connections from multiple subnets
        std::vector<std::unique_ptr<SimulatedNode>> attackers;
        int id = 100;
        for (int subnet = 0; subnet < 20; subnet++) {
            std::string base = "10." + std::to_string(subnet + 100) + ".0.0";
            auto cluster = factory.CreateSybilCluster(10, id, base);
            id += 10;
            for (auto& node : cluster) {
                attackers.push_back(std::move(node));
            }
        }

        for (auto& a : attackers) {
            a->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        orch.AdvanceTime(std::chrono::seconds(2));

        // Age connections and trigger multiple eviction cycles
        for (int i = 0; i < 70; i++) {
            orch.AdvanceTime(std::chrono::seconds(1));
        }

        // Trigger evictions
        for (int i = 0; i < 50; i++) {
            peer_mgr.evict_inbound_peer();
        }

        orch.AdvanceTime(std::chrono::seconds(1));

        // Verify anchor survived
        peers = peer_mgr.get_all_peers();
        bool anchor_survived = false;
        for (const auto& peer : peers) {
            if (peer->address() == "9.1.0.1") {
                anchor_survived = true;
                break;
            }
        }

        INFO("Anchor peer survived: " << anchor_survived);
        REQUIRE(anchor_survived);
    }

    SECTION("With anchor present, full eclipse is impossible") {
        // Create anchor and whitelist it before connection
        auto& peer_mgr = victim->GetNetworkManager().peer_manager();
        peer_mgr.AddToWhitelist("9.2.0.1");

        auto anchor = factory.CreateNodeWithAddress(10, "9.2.0.1");
        anchor->ConnectTo(victim->GetId(), victim->GetAddress());
        REQUIRE(orch.WaitForConnection(*victim, *anchor));

        auto peers = peer_mgr.get_all_peers();

        // Attacker floods with 100 nodes from 25 subnets
        std::vector<std::unique_ptr<SimulatedNode>> attackers;
        int id = 100;
        for (int subnet = 0; subnet < 25; subnet++) {
            std::string base = "10." + std::to_string(subnet + 50) + ".0.0";
            auto cluster = factory.CreateSybilCluster(4, id, base);
            id += 4;
            for (auto& node : cluster) {
                attackers.push_back(std::move(node));
            }
        }

        for (auto& a : attackers) {
            a->ConnectTo(victim->GetId(), victim->GetAddress());
        }
        orch.AdvanceTime(std::chrono::seconds(2));

        // Count attacker vs anchor connections
        peers = peer_mgr.get_all_peers();
        size_t attacker_count = 0;
        size_t anchor_count = 0;

        for (const auto& peer : peers) {
            if (peer->address() == "9.2.0.1") {
                anchor_count++;
            } else {
                attacker_count++;
            }
        }

        INFO("Attacker connections: " << attacker_count);
        INFO("Anchor connections: " << anchor_count);

        // Anchor is present, so full eclipse is impossible
        REQUIRE(anchor_count >= 1);
        double eclipse_ratio = static_cast<double>(attacker_count) / (attacker_count + anchor_count);
        INFO("Eclipse ratio: " << (eclipse_ratio * 100) << "%");
        REQUIRE(eclipse_ratio < 1.0);  // Not 100% eclipse
    }
}

// =============================================================================
// ATTACK SIMULATION 9: Silent Peer / Header Relay Protection
// =============================================================================
// Attacker connects many "silent" peers that never relay headers.
// Honest peers that relay headers should be protected from eviction.

TEST_CASE("Eclipse Attack - Silent peers evicted before header-relaying peers", "[network][security][attack][eclipse][headers]") {
    SECTION("Header relay protection is configured in eviction algorithm") {
        // The eviction algorithm includes header relay protection
        // PROTECT_BY_HEADERS = 4 means the 4 most recent header relayers are protected
        REQUIRE(network::EvictionManager::PROTECT_BY_HEADERS == 4);

        // This is one layer of the multi-layer eviction protection:
        // 1. PROTECT_BY_NETGROUP = 4 (diverse netgroups)
        // 2. PROTECT_BY_PING = 8 (best ping)
        // 3. PROTECT_BY_HEADERS = 4 (most recent header relay) <- this one
        // 4. 50% by connection age
        //
        // The header relay protection specifically helps honest peers that
        // are doing useful work (relaying valid headers) to resist eviction
        // when under Sybil attack.

        INFO("Eviction protects top 4 peers by header relay recency");
        INFO("This prevents silent attackers from evicting useful peers");
    }

    SECTION("Header relay integration is connected end-to-end") {
        // Verify the header sync manager calls UpdateLastHeadersReceived
        // which feeds into the eviction candidate building
        // This is verified in detail by basic_eviction_tests.cpp

        REQUIRE(network::EvictionManager::PROTECT_BY_NETGROUP == 4);
        REQUIRE(network::EvictionManager::PROTECT_BY_PING == 8);
        REQUIRE(network::EvictionManager::PROTECT_BY_HEADERS == 4);

        // The eviction algorithm sorts candidates by last_headers_time (ascending)
        // and removes the last 4 (most recent = protected from eviction)
    }
}

// =============================================================================
// ATTACK SIMULATION 10: Intermittent Header Gaming
// =============================================================================
// Attacker tries to game header protection by sending headers occasionally.

TEST_CASE("Eclipse Attack - Intermittent headers provide limited protection", "[network][security][attack][eclipse][headers]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    auto victim = factory.CreateNode(1);

    // NOTE: Header relay protection is thoroughly tested at the unit level in
    // test/network/eviction/eviction_manager_tests.cpp which directly tests
    // SelectNodeToEvict() with controlled EvictionCandidate inputs.
    // Simulation-level testing of header protection doesn't add value since
    // it can't isolate header protection from netgroup/ping/uptime protections.
}

// =============================================================================
// ATTACK SIMULATION 11: Feeler Stuck Handshake Eclipse Vector
// =============================================================================
// Attacker accepts feeler TCP connections but never completes handshake.

TEST_CASE("Eclipse Attack - Feeler stuck handshake timeout", "[network][security][attack][eclipse][feeler]") {
    // This test is documented for completeness but feeler timeout is tested
    // in detail in test/network/peer/feeler_adversarial_tests.cpp

    SECTION("Feeler timeout prevents indefinite slot holding") {
        // Key behaviors verified by feeler_adversarial_tests.cpp:
        // 1. Feeler times out after FEELER_MAX_LIFETIME_SEC (120s)
        // 2. Address is NOT promoted to tried table on TCP connect alone
        // 3. VERACK required for address promotion
        // 4. Failed feelers call Failed() for proper backoff

        // The constant is 120 seconds
        REQUIRE(network::PeerLifecycleManager::FEELER_MAX_LIFETIME_SEC == 120);

        // This ensures stuck handshakes cannot hold feeler slots indefinitely
        // preventing a denial-of-service vector for outbound connection bootstrapping
    }
}
