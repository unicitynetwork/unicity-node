// Copyright (c) 2025 The Unicity Foundation
// Header validation benchmarks - Hash computation performance
//
// Note: ChainstateManager benchmarks require headers with valid RandomX PoW
// which is expensive to generate. For chain validation benchmarks, use the
// RandomX benchmark suite instead.

// CATCH_CONFIG_ENABLE_BENCHMARKING defined via CMake
#include "catch_amalgamated.hpp"

#include "util/hash.hpp"
#include <random>

TEST_CASE("Hash computation performance", "[benchmark][util][hash]") {
    // Generate random data
    std::vector<uint8_t> data_80(80);   // Block header size
    std::vector<uint8_t> data_256(256);
    std::vector<uint8_t> data_1k(1024);

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint8_t> byte_dist(0, 255);

    for (auto& b : data_80) b = byte_dist(gen);
    for (auto& b : data_256) b = byte_dist(gen);
    for (auto& b : data_1k) b = byte_dist(gen);

    BENCHMARK("Hash - 80 bytes (header size)") {
        return Hash(data_80);
    };

    BENCHMARK("Hash - 256 bytes") {
        return Hash(data_256);
    };

    BENCHMARK("Hash - 1KB") {
        return Hash(data_1k);
    };
}
