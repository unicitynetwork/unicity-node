// NAT Manager tests (ported to test2)

#include <catch_amalgamated.hpp>
#include "network/nat_manager.hpp"
#include <thread>

using namespace unicity::network;

TEST_CASE("NAT Manager - Basic Construction", "[nat][network]") {
    SECTION("Can construct and destruct NAT manager") {
        NATManager manager;
        // Reaching here without crash = success. Verify valid initial state.
        REQUIRE_FALSE(manager.IsPortMapped());
    }
    SECTION("Initial state is not mapped") {
        NATManager manager;
        REQUIRE_FALSE(manager.IsPortMapped());
    }
    SECTION("Initial external IP is empty") {
        NATManager manager;
        REQUIRE(manager.GetExternalIP().empty());
    }
    SECTION("Initial external port is 0") {
        NATManager manager;
        REQUIRE(manager.GetExternalPort() == 0);
    }
}

TEST_CASE("NAT Manager - Stop without Start", "[nat][network]") {
    SECTION("Stop without Start is safe") {
        NATManager manager;
        manager.Stop();
        REQUIRE_FALSE(manager.IsPortMapped());
    }
    SECTION("Multiple stops are safe") {
        NATManager manager;
        manager.Stop(); manager.Stop(); manager.Stop();
        REQUIRE_FALSE(manager.IsPortMapped());
    }
}

TEST_CASE("NAT Manager - Destructor", "[nat][network]") {
    SECTION("Destructor does not crash") {
        NATManager* manager = new NATManager();
        REQUIRE_FALSE(manager->IsPortMapped());
        delete manager;
        // Reaching here without crash = destructor works correctly
    }
}

TEST_CASE("NAT Manager - Thread Safety", "[nat][network]") {
    SECTION("Concurrent stops are safe") {
        NATManager manager;
        std::vector<std::thread> threads;
        for (int i = 0; i < 5; ++i) threads.emplace_back([&manager]() { manager.Stop(); });
        for (auto& t : threads) t.join();
        REQUIRE_FALSE(manager.IsPortMapped());
    }
}

TEST_CASE("NAT Manager - UPnP Integration", "[nat][integration][.]") {
    NATManager manager;
    uint16_t test_port = 39994;
    SECTION("Full UPnP workflow") {
        bool started = manager.Start(test_port);
        if (!started) { SKIP("No UPnP-capable gateway found"); }
        REQUIRE(started);
        REQUIRE(manager.IsPortMapped());
        std::string external_ip = manager.GetExternalIP();
        REQUIRE_FALSE(external_ip.empty());
        uint16_t external_port = manager.GetExternalPort();
        REQUIRE(external_port > 0);
        REQUIRE(external_port == test_port);
        manager.Stop();
        REQUIRE_FALSE(manager.IsPortMapped());
    }
}

TEST_CASE("NAT Manager - Start Twice", "[nat][integration][.]") {
    SECTION("Cannot start twice") {
        NATManager manager; uint16_t test_port = 39998;
        bool first_start = manager.Start(test_port);
        bool second_start = manager.Start(test_port + 1);
        REQUIRE_FALSE(second_start);
        if (first_start) { manager.Stop(); }
    }
}

TEST_CASE("NAT Manager - Invalid Port Handling", "[nat][network]") {
    SECTION("Port 0 is rejected") {
        NATManager manager;
        bool started = manager.Start(0);
        REQUIRE_FALSE(started);
        REQUIRE_FALSE(manager.IsPortMapped());
        REQUIRE(manager.GetExternalPort() == 0);
    }

    SECTION("Port 0 does not affect state") {
        NATManager manager;
        manager.Start(0);
        // Should be safe to stop even after failed start
        manager.Stop();
        REQUIRE_FALSE(manager.IsPortMapped());
    }
}

