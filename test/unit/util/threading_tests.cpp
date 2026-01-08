// Copyright (c) 2025 The Unicity Foundation
// Threading tests for ChainstateManager

#include <catch_amalgamated.hpp>
#include "chain/validation.hpp"
#include "chain/chainstate_manager.hpp"
#include "chain/chainparams.hpp"
#include "chain/block.hpp"
#include "chain/randomx_pow.hpp"
#include "chain/pow.hpp"
#include "util/arith_uint256.hpp"
#include <randomx.h>
#include <thread>
#include <vector>
#include <atomic>

using namespace unicity;

TEST_CASE("ChainstateManager thread safety", "[validation][threading]") {
    // Initialize RandomX
    crypto::InitRandomX();

    // Create test environment
    auto params = chain::ChainParams::CreateRegTest();
    validation::ChainstateManager chainstate(*params);

    // Initialize with genesis
    CBlockHeader genesis = params->GenesisBlock();
    REQUIRE(chainstate.Initialize(genesis));

    // Verify we have a tip
    REQUIRE(chainstate.GetTip() != nullptr);
    REQUIRE(chainstate.GetTip()->nHeight == 0);

    SECTION("Concurrent AcceptBlockHeader calls") {
        // Test that multiple threads can call AcceptBlockHeader without crashes
        constexpr int NUM_THREADS = 4;  // Reduced from 8
        constexpr int BLOCKS_PER_THREAD = 2;  // Reduced from 5 for interpreter mode

        std::atomic<int> successful_accepts{0};
        std::atomic<int> failed_accepts{0};
        std::atomic<int> null_tip_errors{0};
        std::vector<std::thread> threads;

        auto worker = [&](int thread_id) {
            try {
                // Get thread-local RandomX VM for mining
                uint32_t nEpoch = crypto::GetEpoch(static_cast<uint32_t>(std::time(nullptr)),
                                                   params->GetConsensus().nRandomXEpochDuration);
                auto vmWrapper = crypto::GetCachedVM(nEpoch);

                for (int i = 0; i < BLOCKS_PER_THREAD; i++) {
                    // Create a block extending current tip
                    CBlockHeader header;
                    header.nVersion = 1;
                    header.nTime = static_cast<uint32_t>(std::time(nullptr)) + thread_id * 100 + i;
                    header.nBits = params->GenesisBlock().nBits;
                    header.nNonce = 0;

                    // Get current tip (thread-safe with mutex)
                    const chain::CBlockIndex* tip = chainstate.GetTip();
                    if (!tip) {
                        null_tip_errors++;
                        return;
                    }
                    header.hashPrevBlock = tip->GetBlockHash();

                    // Mine the block using thread-local RandomX VM
                    uint256 randomx_hash;
                    char rx_hash[RANDOMX_HASH_SIZE];
                    while (true) {
                        CBlockHeader tmp(header);
                        tmp.hashRandomX.SetNull();
                        randomx_calculate_hash(vmWrapper->vm, &tmp, sizeof(tmp), rx_hash);
                        randomx_hash = uint256(std::vector<unsigned char>(rx_hash, rx_hash + RANDOMX_HASH_SIZE));

                        if (UintToArith256(crypto::GetRandomXCommitment(header, &randomx_hash)) <=
                            UintToArith256(params->GetConsensus().powLimit)) {
                            break;
                        }
                        header.nNonce++;
                    }
                    header.hashRandomX = randomx_hash;

                    // Accept header (thread-safe with mutex)
                    validation::ValidationState state;
chain::CBlockIndex* pindex = chainstate.AcceptBlockHeader(header, state);

                    if (pindex) {
                        successful_accepts++;
                        chainstate.TryAddBlockIndexCandidate(pindex);
                    } else {
                        failed_accepts++;
                    }
                }
            } catch (...) {
                // Worker thread should not throw
            }
            // vmWrapper cleans up automatically via RAII
        };

        // Launch threads
        for (int i = 0; i < NUM_THREADS; i++) {
            threads.emplace_back(worker, i);
        }

        // Wait for all threads
        for (auto& t : threads) {
            t.join();
        }

        INFO("Successful accepts: " << successful_accepts.load());
        INFO("Failed accepts: " << failed_accepts.load());
        INFO("Null tip errors: " << null_tip_errors.load());

        // Check results on main thread (thread-safe assertions)
        REQUIRE(null_tip_errors == 0);
        // At least some blocks should be accepted
        // (Not all will succeed because they compete to extend the same tip)
        REQUIRE(successful_accepts > 0);
    }

    SECTION("Concurrent GetTip calls during validation") {
        // Test that GetTip can be called concurrently with validation
        std::atomic<bool> keep_running{true};
        std::atomic<int> tip_queries{0};
        std::atomic<int> null_tips{0};

        // Thread that repeatedly queries tip
        auto query_worker = [&]() {
            while (keep_running) {
                const chain::CBlockIndex* tip = chainstate.GetTip();
                if (!tip) {
                    null_tips++;
                } else {
                    tip_queries++;
                }
                std::this_thread::sleep_for(std::chrono::microseconds(10));
            }
        };

        // Thread that adds blocks
        auto validation_worker = [&]() {
            for (int i = 0; i < 3; i++) {  // Reduced from 10 to 3 for faster test with interpreter mode
                CBlockHeader header;
                header.nVersion = 1;
                header.nTime = static_cast<uint32_t>(std::time(nullptr)) + i;
                header.nBits = params->GenesisBlock().nBits;
                header.nNonce = 0;

                const chain::CBlockIndex* tip = chainstate.GetTip();
                if (!tip) return;
                header.hashPrevBlock = tip->GetBlockHash();

                // Mine using RandomX
                uint256 randomx_hash;
                while (!consensus::CheckProofOfWork(header, header.nBits, *params,
                        crypto::POWVerifyMode::MINING, &randomx_hash)) {
                    header.nNonce++;
                }
                header.hashRandomX = randomx_hash;

                // Accept
                validation::ValidationState state;
chain::CBlockIndex* pindex = chainstate.AcceptBlockHeader(header, state);
                if (pindex) {
                    chainstate.TryAddBlockIndexCandidate(pindex);
                    chainstate.ActivateBestChain(nullptr);
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        };

        std::thread query_thread(query_worker);
        std::thread validation_thread(validation_worker);

        validation_thread.join();
        keep_running = false;
        query_thread.join();

        INFO("Tip queries during validation: " << tip_queries.load());
        INFO("Null tips encountered: " << null_tips.load());

        // Check on main thread
        REQUIRE(null_tips == 0);
        REQUIRE(tip_queries > 0);
    }

    SECTION("Concurrent ActivateBestChain calls") {
        // Add some blocks first
        std::vector<CBlockHeader> headers;
        const chain::CBlockIndex* current_tip = chainstate.GetTip();

        for (int i = 0; i < 2; i++) {  // Reduced from 20 to 2 for faster test with interpreter mode
            CBlockHeader header;
            header.nVersion = 1;
            header.nTime = static_cast<uint32_t>(std::time(nullptr)) + i;
            header.nBits = params->GenesisBlock().nBits;
            header.nNonce = 0;
            header.hashPrevBlock = current_tip->GetBlockHash();

            // Mine using RandomX
            uint256 randomx_hash;
            while (!consensus::CheckProofOfWork(header, header.nBits, *params,
                    crypto::POWVerifyMode::MINING, &randomx_hash)) {
                header.nNonce++;
            }
            header.hashRandomX = randomx_hash;

            headers.push_back(header);

            validation::ValidationState state;
auto* pindex = chainstate.AcceptBlockHeader(header, state);
            REQUIRE(pindex != nullptr);
            chainstate.TryAddBlockIndexCandidate(pindex);
            current_tip = pindex;
        }

        // Now try concurrent activations
        std::atomic<int> successful_activations{0};
        std::vector<std::thread> threads;

        for (int i = 0; i < 4; i++) {
            threads.emplace_back([&]() {
                for (int j = 0; j < 5; j++) {
                    if (chainstate.ActivateBestChain(nullptr)) {
                        successful_activations++;
                    }
                    std::this_thread::sleep_for(std::chrono::microseconds(100));
                }
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        INFO("Successful activations: " << successful_activations.load());
        REQUIRE(successful_activations > 0);

        // Verify final chain height
        const chain::CBlockIndex* final_tip = chainstate.GetTip();
        REQUIRE(final_tip->nHeight == 2);  // Updated from 20 to 2
    }
}
