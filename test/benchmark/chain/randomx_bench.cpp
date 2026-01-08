// Copyright (c) 2025 The Unicity Foundation
// RandomX benchmarks - Measures PoW hashing performance

// CATCH_CONFIG_ENABLE_BENCHMARKING defined via CMake
#include "catch_amalgamated.hpp"

#include "chain/randomx_pow.hpp"
#include "chain/pow.hpp"
#include "chain/chainparams.hpp"
#include "chain/block.hpp"
#include <random>
#include <chrono>

using namespace unicity::crypto;
using namespace unicity::consensus;

namespace {

// Helper to create a random block header
CBlockHeader CreateRandomHeader(uint32_t nTime) {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint32_t> nonce_dist;
    static std::uniform_int_distribution<uint8_t> byte_dist(0, 255);

    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.nTime = nTime;
    header.nBits = 0x207fffff;  // Easy target for regtest
    header.nNonce = nonce_dist(gen);
    header.hashRandomX.SetNull();

    for (int j = 0; j < 20; j++) {
        header.minerAddress.data()[j] = byte_dist(gen);
    }

    return header;
}

} // anonymous namespace

TEST_CASE("RandomX initialization", "[benchmark][randomx][init]") {
    SECTION("Cache and VM creation time") {
        // Shutdown if already initialized from previous test
        ShutdownRandomX();

        auto start_init = std::chrono::steady_clock::now();
        InitRandomX();
        auto end_init = std::chrono::steady_clock::now();
        auto init_us = std::chrono::duration_cast<std::chrono::microseconds>(end_init - start_init).count();

        INFO("RandomX InitRandomX(): " << init_us << " us");

        // First VM creation (includes cache creation)
        uint32_t epoch = 0;
        auto start_vm = std::chrono::steady_clock::now();
        auto vm = GetCachedVM(epoch);
        auto end_vm = std::chrono::steady_clock::now();
        auto vm_us = std::chrono::duration_cast<std::chrono::microseconds>(end_vm - start_vm).count();

        REQUIRE(vm != nullptr);
        INFO("First VM creation (epoch 0, includes cache): " << vm_us << " us (" << (vm_us / 1000.0) << " ms)");

        // Second VM access (should be cached)
        auto start_cached = std::chrono::steady_clock::now();
        auto vm2 = GetCachedVM(epoch);
        auto end_cached = std::chrono::steady_clock::now();
        auto cached_us = std::chrono::duration_cast<std::chrono::microseconds>(end_cached - start_cached).count();

        REQUIRE(vm2 != nullptr);
        INFO("Cached VM access: " << cached_us << " us");

        // Different epoch (creates new cache and VM)
        uint32_t epoch2 = 1;
        auto start_new = std::chrono::steady_clock::now();
        auto vm3 = GetCachedVM(epoch2);
        auto end_new = std::chrono::steady_clock::now();
        auto new_us = std::chrono::duration_cast<std::chrono::microseconds>(end_new - start_new).count();

        REQUIRE(vm3 != nullptr);
        INFO("New epoch VM creation: " << new_us << " us (" << (new_us / 1000.0) << " ms)");
    }
}

TEST_CASE("RandomX hashing performance", "[benchmark][randomx][hash]") {
    // Ensure RandomX is initialized
    InitRandomX();

    auto params = unicity::chain::ChainParams::CreateRegTest();
    uint32_t epoch = GetEpoch(params->GenesisBlock().nTime, params->GetConsensus().nRandomXEpochDuration);

    // Pre-warm the VM cache
    auto vm = GetCachedVM(epoch);
    REQUIRE(vm != nullptr);

    SECTION("Single hash computation") {
        auto header = CreateRandomHeader(params->GenesisBlock().nTime);

        BENCHMARK("randomx_calculate_hash - single") {
            char rx_hash[RANDOMX_HASH_SIZE];
            randomx_calculate_hash(vm->vm, &header, sizeof(header), rx_hash);
            return rx_hash[0];  // Return something to prevent optimization
        };
    }

    SECTION("Hash throughput - 10 hashes") {
        std::vector<CBlockHeader> headers;
        for (int i = 0; i < 10; i++) {
            headers.push_back(CreateRandomHeader(params->GenesisBlock().nTime + i));
        }

        BENCHMARK("10 RandomX hashes") {
            char rx_hash[RANDOMX_HASH_SIZE];
            int result = 0;
            for (const auto& header : headers) {
                randomx_calculate_hash(vm->vm, &header, sizeof(header), rx_hash);
                result += rx_hash[0];
            }
            return result;
        };
    }

    SECTION("Hash throughput - detailed timing") {
        auto header = CreateRandomHeader(params->GenesisBlock().nTime);

        constexpr int NUM_HASHES = 100;
        std::vector<int64_t> times;
        times.reserve(NUM_HASHES);

        for (int i = 0; i < NUM_HASHES; i++) {
            header.nNonce = i;  // Vary the input

            auto start = std::chrono::steady_clock::now();
            char rx_hash[RANDOMX_HASH_SIZE];
            randomx_calculate_hash(vm->vm, &header, sizeof(header), rx_hash);
            auto end = std::chrono::steady_clock::now();

            times.push_back(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count());
        }

        // Calculate statistics
        int64_t total = 0;
        int64_t min_time = times[0];
        int64_t max_time = times[0];
        for (auto t : times) {
            total += t;
            if (t < min_time) min_time = t;
            if (t > max_time) max_time = t;
        }
        double avg = static_cast<double>(total) / NUM_HASHES;
        double hashes_per_sec = 1000000.0 / avg;

        INFO("RandomX hash timing (" << NUM_HASHES << " samples):");
        INFO("  Average: " << avg << " us (" << (avg / 1000.0) << " ms)");
        INFO("  Min: " << min_time << " us");
        INFO("  Max: " << max_time << " us");
        INFO("  Throughput: " << hashes_per_sec << " hashes/sec");

        // Sanity check - RandomX should take at least 1ms per hash
        REQUIRE(avg > 1000);
    }
}

TEST_CASE("RandomX commitment verification", "[benchmark][randomx][commitment]") {
    InitRandomX();

    auto params = unicity::chain::ChainParams::CreateRegTest();
    auto header = CreateRandomHeader(params->GenesisBlock().nTime);

    // First compute a valid hash
    uint32_t epoch = GetEpoch(header.nTime, params->GetConsensus().nRandomXEpochDuration);
    auto vm = GetCachedVM(epoch);
    REQUIRE(vm != nullptr);

    char rx_hash[RANDOMX_HASH_SIZE];
    randomx_calculate_hash(vm->vm, &header, sizeof(header), rx_hash);
    header.hashRandomX = uint256(std::vector<unsigned char>(rx_hash, rx_hash + RANDOMX_HASH_SIZE));

    SECTION("Commitment calculation only") {
        BENCHMARK("GetRandomXCommitment") {
            auto commitment = GetRandomXCommitment(header);
            int result = commitment.IsNull() ? 0 : 1;
            return result;
        };
    }

    SECTION("Full PoW verification") {
        // This includes commitment check + full RandomX hash verification
        BENCHMARK("CheckProofOfWork - FULL mode") {
            uint256 outHash;
            bool success = CheckProofOfWork(header, header.nBits, *params, POWVerifyMode::FULL, &outHash);
            return success ? 1 : 0;
        };
    }

    SECTION("Commitment-only verification") {
        // Just commitment check, no RandomX hash
        BENCHMARK("CheckProofOfWork - COMMITMENT_ONLY") {
            bool success = CheckProofOfWork(header, header.nBits, *params, POWVerifyMode::COMMITMENT_ONLY, nullptr);
            return success ? 1 : 0;
        };
    }
}

TEST_CASE("RandomX epoch transition", "[benchmark][randomx][epoch]") {
    InitRandomX();

    auto params = unicity::chain::ChainParams::CreateRegTest();

    // Test epoch transitions
    std::vector<uint32_t> epochs = {0, 1, 2, 0, 1};  // Switch back and forth

    SECTION("Epoch switch timing") {
        for (size_t i = 0; i < epochs.size(); i++) {
            uint32_t epoch = epochs[i];

            auto start = std::chrono::steady_clock::now();
            auto vm = GetCachedVM(epoch);
            auto end = std::chrono::steady_clock::now();

            REQUIRE(vm != nullptr);
            auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

            INFO("Epoch " << epoch << " access #" << i << ": " << elapsed_us << " us");
        }
    }
}

TEST_CASE("ASERT difficulty calculation", "[benchmark][pow][asert]") {
    auto params = unicity::chain::ChainParams::CreateRegTest();
    const auto& consensus = params->GetConsensus();

    // Use genesis block's nBits as reference target in compact form
    arith_uint256 refTarget;
    refTarget.SetCompact(params->GenesisBlock().nBits);
    arith_uint256 powLimit = UintToArith256(consensus.powLimit);

    BENCHMARK("CalculateASERT - typical") {
        auto result = CalculateASERT(refTarget, consensus.nPowTargetSpacing,
                              86400,  // 1 day elapsed
                              10,     // 10 blocks
                              powLimit, consensus.nASERTHalfLife);
        uint32_t compact = result.GetCompact();
        return compact;
    };

    SECTION("ASERT with various time diffs") {
        std::vector<int64_t> time_diffs = {60, 600, 3600, 86400, 604800};  // 1min to 1week

        for (int64_t td : time_diffs) {
            auto start = std::chrono::steady_clock::now();
            for (int i = 0; i < 1000; i++) {
                CalculateASERT(refTarget, consensus.nPowTargetSpacing,
                              td, 10, powLimit, consensus.nASERTHalfLife);
            }
            auto end = std::chrono::steady_clock::now();
            auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

            INFO("ASERT with time_diff=" << td << "s: " << (elapsed_us / 1000.0) << " us/call");
        }
    }
}
