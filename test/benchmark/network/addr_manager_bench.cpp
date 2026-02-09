// Copyright (c) 2025 The Unicity Foundation
// AddressManager benchmarks - Measures address operations performance

// CATCH_CONFIG_ENABLE_BENCHMARKING defined via CMake
#include "catch_amalgamated.hpp"

#include "network/addr_manager.hpp"
#include "network/protocol.hpp"
#include <asio.hpp>
#include <random>
#include <chrono>

using namespace unicity;
using namespace unicity::network;

namespace {

// Helper to create a NetworkAddress from an IP string (same as existing tests)
protocol::NetworkAddress MakeNetworkAddress(const std::string& ip_str, uint16_t port = 18444) {
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

std::string RandomIP() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    // Use public routable IPs (not RFC1918)
    static std::uniform_int_distribution<int> first_octet(1, 223);  // Avoid multicast
    static std::uniform_int_distribution<int> octet(1, 254);

    int first = first_octet(gen);
    // Skip RFC1918 ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
    while (first == 10 || first == 127) {
        first = first_octet(gen);
    }

    return std::to_string(first) + "." +
           std::to_string(octet(gen)) + "." +
           std::to_string(octet(gen)) + "." +
           std::to_string(octet(gen));
}

} // anonymous namespace

TEST_CASE("AddressManager add performance", "[benchmark][network][addr]") {
    SECTION("Sequential adds - diverse netgroups") {
        BENCHMARK("Add 1000 unique addresses") {
            AddressManager mgr;

            // Use different first octets to avoid netgroup limits
            for (int i = 0; i < 1000; i++) {
                std::string ip = std::to_string((i % 200) + 1) + "." +
                                 std::to_string((i / 200) % 256) + "." +
                                 std::to_string(i % 256) + ".1";
                mgr.add(MakeNetworkAddress(ip, 18444));
            }

            return mgr.size();
        };
    }

    SECTION("Random address adds") {
        BENCHMARK("Add 1000 random addresses") {
            AddressManager mgr;

            for (int i = 0; i < 1000; i++) {
                mgr.add(MakeNetworkAddress(RandomIP(), 18444));
            }

            return mgr.size();
        };
    }

    SECTION("Add with duplicates") {
        // Pre-generate addresses to test duplicate handling
        std::vector<std::string> ips;
        for (int i = 0; i < 100; i++) {
            ips.push_back(RandomIP());
        }

        BENCHMARK("Add 1000 addresses (100 unique, duplicates)") {
            AddressManager mgr;

            for (int i = 0; i < 1000; i++) {
                mgr.add(MakeNetworkAddress(ips[i % 100], 18444));
            }

            return mgr.size();
        };
    }
}

TEST_CASE("AddressManager select performance", "[benchmark][network][addr]") {
    // Pre-populate manager with diverse netgroups
    AddressManager mgr;
    for (int i = 0; i < 10000; i++) {
        std::string ip = std::to_string((i % 200) + 1) + "." +
                         std::to_string((i / 200) % 256) + "." +
                         std::to_string((i / 50000) % 256) + "." +
                         std::to_string(i % 256);
        mgr.add(MakeNetworkAddress(ip, 18444));
    }

    REQUIRE(mgr.size() >= 1000);  // Some may hit netgroup limits

    SECTION("Select from large pool") {
        BENCHMARK("Select address") {
            return mgr.select();
        };
    }

    SECTION("Select many addresses") {
        BENCHMARK("Select 100 addresses") {
            int count = 0;
            for (int i = 0; i < 100; i++) {
                auto addr = mgr.select();
                if (addr) count++;
            }
            return count;
        };
    }
}

TEST_CASE("AddressManager good/failed operations", "[benchmark][network][addr]") {
    SECTION("Mark addresses good (NEW -> TRIED)") {
        // Create addresses with diverse netgroups
        std::vector<protocol::NetworkAddress> addrs;
        for (int i = 0; i < 1000; i++) {
            std::string ip = std::to_string((i % 200) + 1) + "." +
                             std::to_string((i / 200) % 256) + "." +
                             std::to_string(i % 256) + ".1";
            addrs.push_back(MakeNetworkAddress(ip, 18444));
        }

        BENCHMARK("Mark 100 addresses good") {
            AddressManager mgr;

            // Add addresses
            for (const auto& addr : addrs) {
                mgr.add(addr);
            }

            // Mark first 100 as good
            for (int i = 0; i < 100; i++) {
                mgr.good(addrs[i]);
            }

            return mgr.tried_count();
        };
    }

    // Note: No "mark addresses failed" benchmark - Bitcoin Core has no Failed() function
    // Terrible addresses are filtered via GetChance() and cleaned by cleanup_stale()
}

TEST_CASE("AddressManager cleanup performance", "[benchmark][network][addr]") {
    SECTION("Cleanup with many stale addresses") {
        BENCHMARK("Cleanup 5000 addresses") {
            AddressManager mgr;

            // Add many addresses with diverse netgroups
            for (int i = 0; i < 5000; i++) {
                std::string ip = std::to_string((i % 200) + 1) + "." +
                                 std::to_string((i / 200) % 256) + "." +
                                 std::to_string((i / 50000) % 256) + "." +
                                 std::to_string(i % 256);
                mgr.add(MakeNetworkAddress(ip, 18444));
            }

            // Mark some as attempted (makes them "older")
            for (int i = 0; i < 1000; i++) {
                std::string ip = std::to_string((i % 200) + 1) + "." +
                                 std::to_string((i / 200) % 256) + "." +
                                 std::to_string((i / 50000) % 256) + "." +
                                 std::to_string(i % 256);
                mgr.attempt(MakeNetworkAddress(ip, 18444));
            }

            mgr.cleanup_stale();

            return mgr.size();
        };
    }
}

TEST_CASE("AddressManager scaling", "[benchmark][network][addr][scaling]") {
    SECTION("Performance vs size") {
        std::vector<size_t> sizes = {100, 500, 1000, 5000, 10000};

        for (size_t target_size : sizes) {
            AddressManager mgr;

            // Fill to target size with diverse netgroups
            for (size_t i = 0; i < target_size * 2; i++) {  // Add extra to account for limits
                std::string ip = std::to_string((i % 200) + 1) + "." +
                                 std::to_string((i / 200) % 256) + "." +
                                 std::to_string((i / 50000) % 256) + "." +
                                 std::to_string(i % 256);
                mgr.add(MakeNetworkAddress(ip, 18444));
            }

            // Measure select performance
            auto start = std::chrono::steady_clock::now();
            for (int i = 0; i < 1000; i++) {
                mgr.select();
            }
            auto end = std::chrono::steady_clock::now();
            auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

            INFO("Size " << mgr.size() << ": 1000 selects in " << elapsed_us << " us ("
                 << (elapsed_us / 1000.0) << " us/select)");

            // Sanity check - select should be fast regardless of size
            REQUIRE(elapsed_us < 100000);  // Less than 100ms for 1000 selects
        }
    }
}
