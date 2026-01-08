// Copyright (c) 2025 The Unicity Foundation
// Tests for AddressFactory utility

#include "catch_amalgamated.hpp"
#include "address_factory.hpp"
#include "simulated_node.hpp"
#include "simulated_network.hpp"

using namespace unicity::test;

TEST_CASE("AddressFactory - Diverse address generation", "[network][address][unit]") {
    AddressFactory factory;

    SECTION("Generates addresses in different /16 subnets") {
        auto addr1 = factory.NextDiverseAddress();
        auto addr2 = factory.NextDiverseAddress();
        auto addr3 = factory.NextDiverseAddress();

        // Each should be in a different /16
        REQUIRE_FALSE(AddressFactory::SameNetgroup(addr1, addr2));
        REQUIRE_FALSE(AddressFactory::SameNetgroup(addr2, addr3));
        REQUIRE_FALSE(AddressFactory::SameNetgroup(addr1, addr3));

        // All should be in 10.x.0.1 format
        REQUIRE(addr1.substr(0, 3) == "10.");
        REQUIRE(addr2.substr(0, 3) == "10.");
        REQUIRE(addr3.substr(0, 3) == "10.");
    }

    SECTION("Batch generation returns diverse addresses") {
        auto addresses = factory.GenerateDiverseAddresses(10);

        REQUIRE(addresses.size() == 10);

        // Check all are in different /16 subnets
        for (size_t i = 0; i < addresses.size(); i++) {
            for (size_t j = i + 1; j < addresses.size(); j++) {
                REQUIRE_FALSE(AddressFactory::SameNetgroup(addresses[i], addresses[j]));
            }
        }
    }
}

TEST_CASE("AddressFactory - Subnet cluster generation", "[network][address][unit]") {
    AddressFactory factory;

    SECTION("Generates addresses in same /16 subnet") {
        auto addr1 = factory.NextInSubnet("192.168.0.0");
        auto addr2 = factory.NextInSubnet("192.168.0.0");
        auto addr3 = factory.NextInSubnet("192.168.0.0");

        // All should be in same /16
        REQUIRE(AddressFactory::SameNetgroup(addr1, addr2));
        REQUIRE(AddressFactory::SameNetgroup(addr2, addr3));

        // All should start with 192.168.
        REQUIRE(addr1.substr(0, 8) == "192.168.");
        REQUIRE(addr2.substr(0, 8) == "192.168.");
        REQUIRE(addr3.substr(0, 8) == "192.168.");

        // Each should be different
        REQUIRE(addr1 != addr2);
        REQUIRE(addr2 != addr3);
        REQUIRE(addr1 != addr3);
    }

    SECTION("Different subnet bases create independent clusters") {
        auto sybil1 = factory.NextInSubnet("1.2.0.0");
        auto sybil2 = factory.NextInSubnet("1.2.0.0");
        auto honest1 = factory.NextInSubnet("3.4.0.0");
        auto honest2 = factory.NextInSubnet("3.4.0.0");

        // Sybil cluster in same /16
        REQUIRE(AddressFactory::SameNetgroup(sybil1, sybil2));

        // Honest cluster in same (different) /16
        REQUIRE(AddressFactory::SameNetgroup(honest1, honest2));

        // Sybil and honest in different /16
        REQUIRE_FALSE(AddressFactory::SameNetgroup(sybil1, honest1));
    }

    SECTION("Batch generation creates cluster") {
        auto cluster = factory.GenerateSubnetCluster(50, "172.16.0.0");

        REQUIRE(cluster.size() == 50);

        // All in same /16
        for (size_t i = 1; i < cluster.size(); i++) {
            REQUIRE(AddressFactory::SameNetgroup(cluster[0], cluster[i]));
        }

        // All different addresses
        std::set<std::string> unique_addrs(cluster.begin(), cluster.end());
        REQUIRE(unique_addrs.size() == 50);
    }
}

TEST_CASE("AddressFactory - Static helpers", "[network][address][unit]") {
    SECTION("MakeAddress creates correct format") {
        auto addr = AddressFactory::MakeAddress(192, 168, 1, 100);
        REQUIRE(addr == "192.168.1.100");

        addr = AddressFactory::MakeAddress(10, 0, 0, 1);
        REQUIRE(addr == "10.0.0.1");
    }

    SECTION("GetNetgroupKey extracts /16") {
        REQUIRE(AddressFactory::GetNetgroupKey("192.168.1.100") == "192.168");
        REQUIRE(AddressFactory::GetNetgroupKey("10.20.30.40") == "10.20");
        REQUIRE(AddressFactory::GetNetgroupKey("1.2.3.4") == "1.2");
    }

    SECTION("SameNetgroup comparison works") {
        REQUIRE(AddressFactory::SameNetgroup("192.168.1.1", "192.168.255.254"));
        REQUIRE(AddressFactory::SameNetgroup("10.20.0.1", "10.20.99.99"));
        REQUIRE_FALSE(AddressFactory::SameNetgroup("192.168.1.1", "192.169.1.1"));
        REQUIRE_FALSE(AddressFactory::SameNetgroup("10.20.1.1", "10.21.1.1"));
    }
}

TEST_CASE("AddressFactory - Reset functionality", "[network][address][unit]") {
    AddressFactory factory;

    auto addr1 = factory.NextDiverseAddress();
    auto subnet1 = factory.NextInSubnet("5.5.0.0");

    factory.Reset();

    // After reset, should get same addresses again
    auto addr2 = factory.NextDiverseAddress();
    auto subnet2 = factory.NextInSubnet("5.5.0.0");

    REQUIRE(addr1 == addr2);
    REQUIRE(subnet1 == subnet2);
}

TEST_CASE("SimulatedNode - Custom address support", "[network][address][integration]") {
    SimulatedNetwork network;

    SECTION("Node with custom address reports correct address") {
        SimulatedNode node(1, &network, "10.50.0.1");
        REQUIRE(node.GetAddress() == "10.50.0.1");
    }

    SECTION("Default constructor uses 127.0.0.x pattern") {
        SimulatedNode node(5, &network);
        REQUIRE(node.GetAddress() == "127.0.0.5");
    }

    SECTION("Multiple nodes with different subnets") {
        AddressFactory factory;

        SimulatedNode victim(0, &network, factory.NextDiverseAddress());
        SimulatedNode honest1(1, &network, factory.NextDiverseAddress());
        SimulatedNode honest2(2, &network, factory.NextDiverseAddress());

        // All in different /16 subnets
        REQUIRE_FALSE(AddressFactory::SameNetgroup(victim.GetAddress(), honest1.GetAddress()));
        REQUIRE_FALSE(AddressFactory::SameNetgroup(victim.GetAddress(), honest2.GetAddress()));
        REQUIRE_FALSE(AddressFactory::SameNetgroup(honest1.GetAddress(), honest2.GetAddress()));
    }

    SECTION("Sybil cluster nodes in same subnet") {
        AddressFactory factory;
        auto cluster = factory.GenerateSubnetCluster(5, "192.168.0.0");

        std::vector<std::unique_ptr<SimulatedNode>> nodes;
        for (size_t i = 0; i < cluster.size(); i++) {
            nodes.push_back(std::make_unique<SimulatedNode>(
                static_cast<int>(i + 100), &network, cluster[i]));
        }

        // All nodes in same /16
        for (size_t i = 1; i < nodes.size(); i++) {
            REQUIRE(AddressFactory::SameNetgroup(nodes[0]->GetAddress(), nodes[i]->GetAddress()));
        }
    }
}
