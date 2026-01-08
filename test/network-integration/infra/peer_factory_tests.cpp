// Copyright (c) 2025 The Unicity Foundation
// Tests for PeerFactory utility

#include "catch_amalgamated.hpp"
#include "peer_factory.hpp"
#include "address_factory.hpp"
#include "simulated_node.hpp"
#include "simulated_network.hpp"
#include "test_orchestrator.hpp"

using namespace unicity::test;

TEST_CASE("PeerFactory - Single node creation", "[network][peer_factory][unit]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);

    SECTION("CreateNode generates diverse addresses") {
        auto node1 = factory.CreateNode(1);
        auto node2 = factory.CreateNode(2);
        auto node3 = factory.CreateNode(3);

        REQUIRE(node1 != nullptr);
        REQUIRE(node2 != nullptr);
        REQUIRE(node3 != nullptr);

        // Each should have different netgroups
        REQUIRE_FALSE(AddressFactory::SameNetgroup(node1->GetAddress(), node2->GetAddress()));
        REQUIRE_FALSE(AddressFactory::SameNetgroup(node2->GetAddress(), node3->GetAddress()));
        REQUIRE_FALSE(AddressFactory::SameNetgroup(node1->GetAddress(), node3->GetAddress()));
    }

    SECTION("CreateNodeWithAddress uses specified address") {
        auto node = factory.CreateNodeWithAddress(10, "1.2.3.4");
        REQUIRE(node->GetAddress() == "1.2.3.4");
        REQUIRE(node->GetId() == 10);
    }

    SECTION("CreateNodeInSubnet generates addresses in same subnet") {
        auto node1 = factory.CreateNodeInSubnet(1, "192.168.0.0");
        auto node2 = factory.CreateNodeInSubnet(2, "192.168.0.0");
        auto node3 = factory.CreateNodeInSubnet(3, "192.168.0.0");

        // All should be in same /16
        REQUIRE(AddressFactory::SameNetgroup(node1->GetAddress(), node2->GetAddress()));
        REQUIRE(AddressFactory::SameNetgroup(node2->GetAddress(), node3->GetAddress()));

        // But different addresses
        REQUIRE(node1->GetAddress() != node2->GetAddress());
        REQUIRE(node2->GetAddress() != node3->GetAddress());
    }
}

TEST_CASE("PeerFactory - Configured node creation", "[network][peer_factory][unit]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);

    SECTION("CreateConfiguredNode with explicit address") {
        PeerFactory::PeerConfig config;
        config.address = "10.20.30.40";

        auto result = factory.CreateConfiguredNode(5, config);

        REQUIRE(result.node != nullptr);
        REQUIRE(result.address == "10.20.30.40");
        REQUIRE(result.netgroup == "10.20");
        REQUIRE(result.node_id == 5);
    }

    SECTION("CreateConfiguredNode with diverse subnet") {
        PeerFactory::PeerConfig config;
        config.diverse_subnet = true;

        auto result1 = factory.CreateConfiguredNode(1, config);
        auto result2 = factory.CreateConfiguredNode(2, config);

        REQUIRE_FALSE(AddressFactory::SameNetgroup(result1.address, result2.address));
    }

    SECTION("CreateConfiguredNode with specific subnet") {
        PeerFactory::PeerConfig config;
        config.diverse_subnet = false;
        config.subnet_base = "172.16.0.0";

        auto result1 = factory.CreateConfiguredNode(1, config);
        auto result2 = factory.CreateConfiguredNode(2, config);

        REQUIRE(AddressFactory::SameNetgroup(result1.address, result2.address));
        REQUIRE(result1.netgroup == "172.16");
        REQUIRE(result2.netgroup == "172.16");
    }
}

TEST_CASE("PeerFactory - Batch creation", "[network][peer_factory][unit]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);

    SECTION("CreateDiversePeers creates nodes with unique netgroups") {
        auto nodes = factory.CreateDiversePeers(10, 100);

        REQUIRE(nodes.size() == 10);

        // All should be in different /16 subnets
        REQUIRE(PeerFactory::AllDiverseNetgroups(nodes));
        REQUIRE(PeerFactory::CountUniqueNetgroups(nodes) == 10);

        // IDs should be 100-109
        for (size_t i = 0; i < nodes.size(); i++) {
            REQUIRE(nodes[i]->GetId() == 100 + static_cast<int>(i));
        }
    }

    SECTION("CreateSybilCluster creates nodes in same netgroup") {
        auto nodes = factory.CreateSybilCluster(20, 500, "192.168.0.0");

        REQUIRE(nodes.size() == 20);

        // All should be in same /16 subnet
        REQUIRE(PeerFactory::AllSameNetgroup(nodes));
        REQUIRE(PeerFactory::CountUniqueNetgroups(nodes) == 1);

        // All addresses should be unique
        std::set<std::string> addresses;
        for (const auto& node : nodes) {
            addresses.insert(node->GetAddress());
        }
        REQUIRE(addresses.size() == 20);

        // IDs should be 500-519
        for (size_t i = 0; i < nodes.size(); i++) {
            REQUIRE(nodes[i]->GetId() == 500 + static_cast<int>(i));
        }
    }

    SECTION("CreateMixedPeers creates diverse honest and clustered attackers") {
        auto [honest, attackers] = factory.CreateMixedPeers(
            5, 15,      // 5 honest, 15 attackers
            1, 1000,    // honest IDs 1-5, attacker IDs 1000-1014
            "10.99.0.0" // attacker subnet
        );

        REQUIRE(honest.size() == 5);
        REQUIRE(attackers.size() == 15);

        // Honest should be diverse
        REQUIRE(PeerFactory::AllDiverseNetgroups(honest));

        // Attackers should be clustered
        REQUIRE(PeerFactory::AllSameNetgroup(attackers));

        // No overlap between honest and attacker netgroups
        std::string attacker_netgroup = PeerFactory::GetNetgroup(*attackers[0]);
        for (const auto& h : honest) {
            REQUIRE(PeerFactory::GetNetgroup(*h) != attacker_netgroup);
        }
    }
}

TEST_CASE("PeerFactory - Eclipse scenario setup", "[network][peer_factory][unit]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);

    SECTION("CreateEclipseScenario creates correct topology") {
        auto scenario = factory.CreateEclipseScenario(
            8,   // 8 honest peers
            50,  // 50 attackers
            "192.168.0.0"
        );

        // Victim exists with unique netgroup
        REQUIRE(scenario.victim != nullptr);
        REQUIRE(scenario.victim->GetId() == 0);

        // Honest peers are diverse
        REQUIRE(scenario.honest_peers.size() == 8);
        REQUIRE(PeerFactory::AllDiverseNetgroups(scenario.honest_peers));

        // Attackers are clustered
        REQUIRE(scenario.attackers.size() == 50);
        REQUIRE(PeerFactory::AllSameNetgroup(scenario.attackers));

        // Victim's netgroup is different from all honest peers
        for (const auto& h : scenario.honest_peers) {
            REQUIRE_FALSE(AddressFactory::SameNetgroup(
                scenario.victim->GetAddress(), h->GetAddress()));
        }

        // Victim's netgroup is different from attackers
        REQUIRE_FALSE(AddressFactory::SameNetgroup(
            scenario.victim->GetAddress(), scenario.attackers[0]->GetAddress()));
    }
}

TEST_CASE("PeerFactory - Eviction scenario setup", "[network][peer_factory][unit]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);

    SECTION("CreateEvictionScenario with diverse peers") {
        auto scenario = factory.CreateEvictionScenario(
            10,   // slot limit (informational)
            15,   // 15 peers (exceeds limit)
            true  // diverse
        );

        REQUIRE(scenario.victim != nullptr);
        REQUIRE(scenario.peers.size() == 15);
        REQUIRE(PeerFactory::AllDiverseNetgroups(scenario.peers));
    }

    SECTION("CreateEvictionScenario with clustered peers") {
        auto scenario = factory.CreateEvictionScenario(
            10,   // slot limit
            15,   // 15 peers
            false, // not diverse (Sybil cluster)
            "172.16.0.0"
        );

        REQUIRE(scenario.victim != nullptr);
        REQUIRE(scenario.peers.size() == 15);
        REQUIRE(PeerFactory::AllSameNetgroup(scenario.peers));
    }
}

TEST_CASE("PeerFactory - Reset functionality", "[network][peer_factory][unit]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);

    // Create some nodes
    auto node1 = factory.CreateNode(1);
    auto sybil1 = factory.CreateNodeInSubnet(100, "5.5.0.0");

    std::string addr1 = node1->GetAddress();
    std::string sybil_addr1 = sybil1->GetAddress();

    // Reset factory
    factory.Reset();

    // Create new nodes - should get same addresses as before reset
    auto node2 = factory.CreateNode(2);
    auto sybil2 = factory.CreateNodeInSubnet(101, "5.5.0.0");

    REQUIRE(node2->GetAddress() == addr1);
    REQUIRE(sybil2->GetAddress() == sybil_addr1);
}

TEST_CASE("PeerFactory - Verification helpers", "[network][peer_factory][unit]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);

    SECTION("AllDiverseNetgroups returns true for diverse set") {
        auto diverse = factory.CreateDiversePeers(5, 1);
        REQUIRE(PeerFactory::AllDiverseNetgroups(diverse));
    }

    SECTION("AllDiverseNetgroups returns false for clustered set") {
        auto clustered = factory.CreateSybilCluster(5, 1, "10.10.0.0");
        REQUIRE_FALSE(PeerFactory::AllDiverseNetgroups(clustered));
    }

    SECTION("AllSameNetgroup returns true for clustered set") {
        auto clustered = factory.CreateSybilCluster(5, 1, "10.10.0.0");
        REQUIRE(PeerFactory::AllSameNetgroup(clustered));
    }

    SECTION("AllSameNetgroup returns false for diverse set") {
        auto diverse = factory.CreateDiversePeers(5, 1);
        REQUIRE_FALSE(PeerFactory::AllSameNetgroup(diverse));
    }

    SECTION("CountUniqueNetgroups counts correctly") {
        auto diverse = factory.CreateDiversePeers(7, 1);
        REQUIRE(PeerFactory::CountUniqueNetgroups(diverse) == 7);

        factory.Reset();
        auto clustered = factory.CreateSybilCluster(7, 1, "20.20.0.0");
        REQUIRE(PeerFactory::CountUniqueNetgroups(clustered) == 1);
    }

    SECTION("GetNetgroup extracts correct prefix") {
        auto node = factory.CreateNodeWithAddress(1, "192.168.5.10");
        REQUIRE(PeerFactory::GetNetgroup(*node) == "192.168");
    }
}

TEST_CASE("PeerFactory - Integration with SimulatedNode", "[network][peer_factory][integration]") {
    SimulatedNetwork network;
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    SECTION("Created nodes can connect to each other") {
        auto node1 = factory.CreateNode(1);
        auto node2 = factory.CreateNode(2);

        // Connect node1 -> node2
        bool connected = node1->ConnectTo(node2->GetId(), node2->GetAddress());
        REQUIRE(connected);

        // Wait for connection to establish using TestOrchestrator
        REQUIRE(orch.WaitForConnection(*node1, *node2));

        // Both should have 1 peer
        REQUIRE(node1->GetPeerCount() >= 1);
        REQUIRE(node2->GetPeerCount() >= 1);
    }

    SECTION("Sybil cluster nodes can all connect to victim") {
        auto victim = factory.CreateNode(0);
        auto attackers = factory.CreateSybilCluster(3, 100, "192.168.0.0");

        // First attacker connects to victim
        attackers[0]->ConnectTo(victim->GetId(), victim->GetAddress());
        REQUIRE(orch.WaitForConnection(*attackers[0], *victim));

        // Connect remaining attackers
        for (size_t i = 1; i < attackers.size(); i++) {
            attackers[i]->ConnectTo(victim->GetId(), victim->GetAddress());
        }

        // Wait for all connections
        REQUIRE(orch.WaitForPeerCount(*victim, attackers.size()));

        // Victim should have connections from all attackers
        REQUIRE(victim->GetPeerCount() == attackers.size());

        // All attackers should be in the same netgroup
        REQUIRE(PeerFactory::AllSameNetgroup(attackers));
    }
}
