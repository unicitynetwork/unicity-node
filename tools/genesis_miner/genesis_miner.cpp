// Copyright (c) 2025 The Unicity Foundation
// Genesis Block Miner - Finds nonce for genesis block using RandomX

#include "chain/block.hpp"
#include "util/sha256.hpp"
#include "util/arith_uint256.hpp"
#include "randomx.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <atomic>
#include <thread>
#include <vector>

// Mining statistics
struct MiningStats {
    std::atomic<uint64_t> hashes{0};
    std::atomic<bool> found{false};
    std::atomic<uint32_t> winning_nonce{0};
    uint256 winning_rx_hash;
    uint256 winning_commitment;
    std::chrono::steady_clock::time_point start_time;
};

// Target difficulty (compact format)
// 0x1d00ffff = difficulty ~1 (Bitcoin genesis difficulty)
constexpr uint32_t TARGET_BITS = 0x1d00ffff;

// Calculate target from nBits
arith_uint256 GetTargetFromBits(uint32_t nBits) {
    int nShift = (nBits >> 24) & 0xff;
    arith_uint256 target;

    target = arith_uint256(nBits & 0x00ffffff);
    if (nShift <= 3) {
        target >>= (8 * (3 - nShift));
    } else {
        target <<= (8 * (nShift - 3));
    }

    return target;
}

// Mining worker thread - each thread gets its own RandomX VM
void MineWorker(randomx_vm* vm, CBlockHeader header, uint32_t start_nonce, uint32_t stride,
                MiningStats& stats, const arith_uint256& target) {
    uint32_t nonce = start_nonce;

    while (!stats.found.load(std::memory_order_acquire)) {
        header.nNonce = nonce;

        // Set hashRandomX to null for hashing
        CBlockHeader tmp(header);
        tmp.hashRandomX.SetNull();

        // Calculate RandomX hash
        char rx_hash[RANDOMX_HASH_SIZE];
        randomx_calculate_hash(vm, &tmp, sizeof(tmp), rx_hash);

        // Calculate commitment: BLAKE2b(block_header || rx_hash)
        char rx_cm[RANDOMX_HASH_SIZE];
        randomx_calculate_commitment(&tmp, sizeof(tmp), rx_hash, rx_cm);

        // Convert to uint256 and check against target
        uint256 commitment = uint256(std::vector<unsigned char>(rx_cm, rx_cm + RANDOMX_HASH_SIZE));

        if (UintToArith256(commitment) <= target) {
            // Found it!
            stats.found.store(true, std::memory_order_release);
            stats.winning_nonce.store(nonce, std::memory_order_release);
            stats.winning_rx_hash = uint256(std::vector<unsigned char>(rx_hash, rx_hash + RANDOMX_HASH_SIZE));
            stats.winning_commitment = commitment;

            std::cout << "\n🎉 FOUND GENESIS BLOCK! 🎉\n";
            std::cout << "Nonce: " << nonce << "\n";
            std::cout << "Hash: " << header.GetHash().GetHex() << "\n";
            std::cout << "RandomX Hash: " << stats.winning_rx_hash.GetHex() << "\n";
            std::cout << "Commitment: " << commitment.GetHex() << "\n";
            break;
        }

        // Update stats
        stats.hashes.fetch_add(1, std::memory_order_relaxed);

        // Next nonce (with stride for multi-threading)
        nonce += stride;
        if (nonce == 0) break; // Wrapped around
    }
}

// Progress reporter thread
void ReportProgress(MiningStats& stats) {
    while (!stats.found.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::seconds(5));

        if (stats.found.load(std::memory_order_acquire)) break;

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - stats.start_time
        ).count();

        if (elapsed > 0) {
            uint64_t hashes = stats.hashes.load(std::memory_order_relaxed);
            double hashrate = static_cast<double>(hashes) / elapsed;

            std::cout << "Mining... "
                      << hashes << " hashes"
                      << " (" << std::fixed << std::setprecision(2) << hashrate << " H/s)"
                      << " [" << elapsed << "s elapsed]"
                      << std::endl;
        }
    }
}

int main(int argc, char* argv[]) {
    std::cout << "Unicity Genesis Block Miner\n";
    std::cout << "==================================\n\n";

    // Parse command line arguments
    uint32_t nTime = 1234567890; // Default: 2009-02-13 (Bitcoin genesis)
    uint32_t nBits = TARGET_BITS;
    uint32_t nEpochDuration = 7200; // Default: 2 hours (like Unicity)
    int num_threads = std::thread::hardware_concurrency();

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--time" && i + 1 < argc) {
            nTime = std::stoul(argv[++i]);
        } else if (arg == "--bits" && i + 1 < argc) {
            nBits = std::stoul(argv[++i], nullptr, 16);
        } else if (arg == "--epoch-duration" && i + 1 < argc) {
            nEpochDuration = std::stoul(argv[++i]);
        } else if (arg == "--threads" && i + 1 < argc) {
            num_threads = std::stoi(argv[++i]);
        } else if (arg == "--help") {
            std::cout << "Usage: " << argv[0] << " [options]\n\n";
            std::cout << "Options:\n";
            std::cout << "  --time <timestamp>      Unix timestamp (default: 1234567890)\n";
            std::cout << "  --bits <hex>            Target difficulty in hex (default: 0x1d00ffff)\n";
            std::cout << "  --epoch-duration <sec>  Epoch duration in seconds (default: 7200)\n";
            std::cout << "  --threads <n>           Number of threads (default: " << num_threads << ")\n";
            std::cout << "  --help                  Show this help message\n";
            return 0;
        }
    }

    // Calculate epoch from timestamp
    uint32_t nEpoch = nTime / nEpochDuration;

    // Create RandomX seed for epoch
    std::cout << "Initializing RandomX for epoch " << nEpoch << " (time=" << nTime << ", duration=" << nEpochDuration << ")...\n";
    char seed_string[128];
    snprintf(seed_string, sizeof(seed_string), "Alpha/RandomX/Epoch/%d", nEpoch);

    // SHA256d of seed string
    uint256 h1, h2;
    CSHA256().Write((const unsigned char*)seed_string, strlen(seed_string)).Finalize(h1.begin());
    CSHA256().Write(h1.begin(), 32).Finalize(h2.begin());

    // Get RandomX flags
    randomx_flags flags = randomx_get_flags();

    // Allocate and initialize cache
    randomx_cache* cache = randomx_alloc_cache(flags);
    if (!cache) {
        std::cerr << "Failed to allocate RandomX cache\n";
        return 1;
    }
    randomx_init_cache(cache, h2.data(), h2.size());
    std::cout << "RandomX cache initialized\n";

    // Create genesis block header
    CBlockHeader genesis;
    genesis.nVersion = 1;
    genesis.hashPrevBlock.SetNull(); // Genesis has no previous block
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = 0;

    // Calculate target
    arith_uint256 target = GetTargetFromBits(nBits);

    std::cout << "Mining genesis block with:\n";
    std::cout << "  Time: " << nTime << "\n";
    std::cout << "  Bits: 0x" << std::hex << nBits << std::dec << "\n";
    std::cout << "  Target: " << target.GetHex() << "\n";
    std::cout << "  Threads: " << num_threads << "\n\n";

    // Mining stats
    MiningStats stats;
    stats.start_time = std::chrono::steady_clock::now();

    // Create VMs and start mining threads
    std::vector<randomx_vm*> vms;
    std::vector<std::thread> workers;

    for (int i = 0; i < num_threads; i++) {
        // Each thread gets its own VM (VMs are not thread-safe)
        randomx_vm* vm = randomx_create_vm(flags, cache, nullptr);
        if (!vm) {
            std::cerr << "Failed to create RandomX VM for thread " << i << "\n";
            return 1;
        }
        vms.push_back(vm);
        workers.emplace_back(MineWorker, vm, genesis, i, num_threads,
                            std::ref(stats), std::cref(target));
    }

    // Start progress reporter
    std::thread reporter(ReportProgress, std::ref(stats));

    // Wait for completion
    for (auto& worker : workers) {
        worker.join();
    }
    reporter.join();

    // Cleanup VMs
    for (auto vm : vms) {
        randomx_destroy_vm(vm);
    }
    randomx_release_cache(cache);

    // Print final stats
    auto end_time = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        end_time - stats.start_time
    ).count();

    uint64_t total_hashes = stats.hashes.load();

    std::cout << "\n=== Mining Complete ===\n";
    std::cout << "Total hashes: " << total_hashes << "\n";
    std::cout << "Time elapsed: " << elapsed << " seconds\n";
    if (elapsed > 0) {
        std::cout << "Average hashrate: "
                  << std::fixed << std::setprecision(2)
                  << (static_cast<double>(total_hashes) / elapsed) << " H/s\n";
    }

    if (stats.found) {
        uint32_t winning_nonce = stats.winning_nonce.load();
        genesis.nNonce = winning_nonce;

        std::cout << "\n=== Genesis Block Header ===\n";
        std::cout << "nVersion: " << genesis.nVersion << "\n";
        std::cout << "hashPrevBlock: " << genesis.hashPrevBlock.GetHex() << "\n";
        std::cout << "nTime: " << genesis.nTime << "\n";
        std::cout << "nBits: 0x" << std::hex << genesis.nBits << std::dec << "\n";
        std::cout << "nNonce: " << genesis.nNonce << "\n";
        std::cout << "Block Hash: " << genesis.GetHash().GetHex() << "\n";
        std::cout << "RandomX Hash: " << stats.winning_rx_hash.GetHex() << "\n";
        std::cout << "Commitment: " << stats.winning_commitment.GetHex() << "\n";

        // C++ code for chainparams.cpp
        std::cout << "\n=== Code for chainparams.cpp ===\n";
        std::cout << "genesis.nVersion = " << genesis.nVersion << ";\n";
        std::cout << "genesis.nTime = " << genesis.nTime << ";\n";
        std::cout << "genesis.nBits = 0x" << std::hex << genesis.nBits << std::dec << ";\n";
        std::cout << "genesis.nNonce = " << genesis.nNonce << ";\n";
        std::cout << "// Block hash: " << genesis.GetHash().GetHex() << "\n";
    }

    return stats.found ? 0 : 1;
}
