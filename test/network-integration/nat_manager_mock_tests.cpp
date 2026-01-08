// NAT Manager tests with mocked miniupnpc
// These tests use mock UPnP functions to test all code paths

#include "catch_amalgamated.hpp"
#include "network/nat_manager.hpp"
#include "mock_upnp.hpp"
#include <thread>
#include <chrono>

using namespace unicity::network;
using namespace unicity::test;

// Reset mock state before each test
struct MockReset {
    MockReset() { GetUPnPMock().reset(); }
    ~MockReset() { GetUPnPMock().reset(); }
};

TEST_CASE("NAT Mock - Successful UPnP flow", "[nat][mock]") {
    MockReset reset;
    auto& mock = GetUPnPMock();
    mock.configure_success();

    NATManager manager;

    SECTION("Start succeeds with valid gateway") {
        bool started = manager.Start(9590);
        REQUIRE(started);
        REQUIRE(manager.IsPortMapped());
        REQUIRE(manager.GetExternalPort() == 9590);
        REQUIRE(manager.GetExternalIP() == mock.external_ip);

        // Verify mock was called
        CHECK(mock.discover_calls == 1);
        CHECK(mock.get_igd_calls == 1);
        CHECK(mock.get_external_ip_calls >= 1);
        CHECK(mock.add_mapping_calls == 1);

        manager.Stop();
        REQUIRE_FALSE(manager.IsPortMapped());
        CHECK(mock.delete_mapping_calls == 1);
    }
}

TEST_CASE("NAT Mock - Discovery failure", "[nat][mock]") {
    MockReset reset;
    auto& mock = GetUPnPMock();
    mock.configure_no_gateway();

    NATManager manager;

    SECTION("Start fails when no gateway found") {
        bool started = manager.Start(9590);
        REQUIRE_FALSE(started);
        REQUIRE_FALSE(manager.IsPortMapped());
        CHECK(mock.discover_calls == 1);
        CHECK(mock.get_igd_calls == 0);  // Never called if discovery fails
    }
}

TEST_CASE("NAT Mock - IGD validation failure", "[nat][mock]") {
    MockReset reset;
    auto& mock = GetUPnPMock();
    mock.discover_success = true;
    mock.igd_result = 0;  // No valid IGD

    NATManager manager;

    SECTION("Start fails when IGD not valid") {
        bool started = manager.Start(9590);
        REQUIRE_FALSE(started);
        REQUIRE_FALSE(manager.IsPortMapped());
        CHECK(mock.discover_calls == 1);
        CHECK(mock.get_igd_calls == 1);
        CHECK(mock.add_mapping_calls == 0);  // Never called
    }
}

TEST_CASE("NAT Mock - Port mapping failure", "[nat][mock]") {
    MockReset reset;
    auto& mock = GetUPnPMock();
    mock.discover_success = true;
    mock.igd_result = 1;
    mock.get_external_ip_success = true;
    mock.add_mapping_success = false;
    mock.add_mapping_error = 718;  // ConflictInMappingEntry

    NATManager manager;

    SECTION("Start fails when mapping fails") {
        bool started = manager.Start(9590);
        REQUIRE_FALSE(started);
        REQUIRE_FALSE(manager.IsPortMapped());
        CHECK(mock.add_mapping_calls == 1);
    }
}

TEST_CASE("NAT Mock - External IP failure", "[nat][mock]") {
    MockReset reset;
    auto& mock = GetUPnPMock();
    mock.discover_success = true;
    mock.igd_result = 1;
    mock.get_external_ip_success = false;  // IP lookup fails
    mock.add_mapping_success = true;

    NATManager manager;

    SECTION("Start succeeds even if external IP lookup fails") {
        bool started = manager.Start(9590);
        REQUIRE(started);
        REQUIRE(manager.IsPortMapped());
        // External IP should be empty
        CHECK(manager.GetExternalIP().empty());
        manager.Stop();
    }
}

TEST_CASE("NAT Mock - Double start prevention", "[nat][mock]") {
    MockReset reset;
    auto& mock = GetUPnPMock();
    mock.configure_success();

    NATManager manager;

    SECTION("Second Start returns false") {
        bool first = manager.Start(9590);
        REQUIRE(first);

        bool second = manager.Start(9591);
        REQUIRE_FALSE(second);

        // Only one discovery should have happened
        CHECK(mock.discover_calls == 1);

        manager.Stop();
    }
}

TEST_CASE("NAT Mock - Port 0 rejection", "[nat][mock]") {
    MockReset reset;
    auto& mock = GetUPnPMock();
    mock.configure_success();

    NATManager manager;

    SECTION("Port 0 is rejected before discovery") {
        bool started = manager.Start(0);
        REQUIRE_FALSE(started);
        // Discovery should not be attempted
        CHECK(mock.discover_calls == 0);
    }
}

TEST_CASE("NAT Mock - Privileged port warning", "[nat][mock]") {
    MockReset reset;
    auto& mock = GetUPnPMock();
    mock.configure_success();

    NATManager manager;

    SECTION("Privileged port still works but logs warning") {
        // Port < 1024 should work but log a warning
        bool started = manager.Start(80);
        REQUIRE(started);
        REQUIRE(manager.GetExternalPort() == 80);
        manager.Stop();
    }
}

TEST_CASE("NAT Mock - Stop idempotence", "[nat][mock]") {
    MockReset reset;
    auto& mock = GetUPnPMock();
    mock.configure_success();

    NATManager manager;

    SECTION("Multiple stops are safe") {
        manager.Start(9590);
        manager.Stop();
        manager.Stop();
        manager.Stop();
        REQUIRE_FALSE(manager.IsPortMapped());
        // Only one delete should happen
        CHECK(mock.delete_mapping_calls == 1);
    }

    SECTION("Stop without start is safe") {
        manager.Stop();
        manager.Stop();
        REQUIRE_FALSE(manager.IsPortMapped());
        CHECK(mock.delete_mapping_calls == 0);
    }
}

TEST_CASE("NAT Mock - Destructor cleanup", "[nat][mock]") {
    MockReset reset;
    auto& mock = GetUPnPMock();
    mock.configure_success();

    SECTION("Destructor unmaps port") {
        {
            NATManager manager;
            manager.Start(9590);
            REQUIRE(manager.IsPortMapped());
            // Destructor called here
        }
        // Verify delete was called
        CHECK(mock.delete_mapping_calls == 1);
    }
}

TEST_CASE("NAT Mock - Thread safety", "[nat][mock]") {
    MockReset reset;
    auto& mock = GetUPnPMock();
    mock.configure_success();

    NATManager manager;

    SECTION("Concurrent operations are safe") {
        manager.Start(9590);

        std::vector<std::thread> threads;
        for (int i = 0; i < 5; ++i) {
            threads.emplace_back([&manager]() {
                manager.GetExternalIP();
                manager.GetExternalPort();
                manager.IsPortMapped();
            });
        }

        for (auto& t : threads) t.join();

        manager.Stop();
        REQUIRE_FALSE(manager.IsPortMapped());
    }

    SECTION("Concurrent stops are safe") {
        manager.Start(9590);

        std::vector<std::thread> threads;
        for (int i = 0; i < 5; ++i) {
            threads.emplace_back([&manager]() {
                manager.Stop();
            });
        }

        for (auto& t : threads) t.join();
        REQUIRE_FALSE(manager.IsPortMapped());
    }
}

TEST_CASE("NAT Mock - Getters return correct values", "[nat][mock]") {
    MockReset reset;
    auto& mock = GetUPnPMock();
    mock.configure_success();
    mock.external_ip = "198.51.100.42";

    NATManager manager;

    SECTION("Getters before start") {
        CHECK(manager.GetExternalIP().empty());
        CHECK(manager.GetExternalPort() == 0);
        CHECK_FALSE(manager.IsPortMapped());
    }

    SECTION("Getters after start") {
        manager.Start(12345);
        CHECK(manager.GetExternalIP() == "198.51.100.42");
        CHECK(manager.GetExternalPort() == 12345);
        CHECK(manager.IsPortMapped());
        manager.Stop();
    }

    SECTION("Getters after stop") {
        manager.Start(12345);
        manager.Stop();
        // IP may still be cached, but port mapped should be false
        CHECK_FALSE(manager.IsPortMapped());
    }
}
