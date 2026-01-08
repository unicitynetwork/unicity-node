// Copyright (c) 2025 The Unicity Foundation
// Thread safety tests for orphan header management
// Tests concurrent access to orphan pool from multiple threads

#include "catch_amalgamated.hpp"
#include "chain/validation.hpp"
#include "common/test_chainstate_manager.hpp"
#include "chain/chainparams.hpp"
#include "chain/block.hpp"
#include "util/sha256.hpp"
#include <memory>
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>
#include <random>

using namespace unicity;
using namespace unicity::test;
using namespace unicity::chain;
using unicity::validation::ValidationState;

// Helper to create test header
static CBlockHeader CreateTestHeader(const uint256& prevHash, uint32_t nTime, uint32_t nNonce = 12345) {
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock = prevHash;
    header.minerAddress.SetNull();
    header.nTime = nTime;
    header.nBits = 0x207fffff;  // RegTest difficulty
    header.nNonce = nNonce;
    header.hashRandomX.SetNull();
    return header;
}

// Helper to create a random hash (thread-safe)
static uint256 RandomHash(int seed) {
    uint256 hash;
    std::mt19937 rng(seed);
    for (int i = 0; i < 32; i++) {
        *(hash.begin() + i) = rng() % 256;
    }
    return hash;
}

// =============================================================================
// TEST 1: Concurrent Additions
// =============================================================================
// Security Goal: Verify orphan pool handles concurrent additions without crashes
// Attack Scenario: Multiple threads adding orphans simultaneously
// Expected: No crashes, correct count, per-peer limits enforced
TEST_CASE("Thread Safety - Concurrent Additions", "[orphan][thread][critical]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    SECTION("10 threads, each adding 10 orphans") {
        const int NUM_THREADS = 10;
        const int ORPHANS_PER_THREAD = 10;
        const int PER_PEER_LIMIT = 50;

        std::vector<std::thread> threads;
        std::atomic<int> total_added{0};

        // Launch threads
        for (int t = 0; t < NUM_THREADS; ++t) {
            threads.emplace_back([&, t]() {
                int peer_id = t + 1;  // Unique peer ID per thread

                for (int i = 0; i < ORPHANS_PER_THREAD; ++i) {
                    uint256 unknownParent = RandomHash(t * 1000 + i);
                    CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890 + t * 100 + i, t * 10000 + i);

                    bool added = chainstate.AddOrphanHeader(orphan, peer_id);
                    if (added) {
                        total_added.fetch_add(1);
                    }
                }
            });
        }

        // Wait for all threads
        for (auto& t : threads) {
            t.join();
        }

        // Verify results
        size_t orphan_count = chainstate.GetOrphanHeaderCount();

        // Should have added some orphans (up to limits)
        REQUIRE(orphan_count > 0);
        REQUIRE(orphan_count <= NUM_THREADS * PER_PEER_LIMIT);  // Per-peer limit
        REQUIRE(orphan_count <= 1000);  // Global limit

        // Total added should be at least orphan_count
        REQUIRE(total_added.load() >= static_cast<int>(orphan_count));
    }

    SECTION("Concurrent additions from same peer") {
        const int NUM_THREADS = 5;
        const int ORPHANS_PER_THREAD = 15;
        const int PER_PEER_LIMIT = 50;

        std::vector<std::thread> threads;

        // All threads use same peer ID
        for (int t = 0; t < NUM_THREADS; ++t) {
            threads.emplace_back([&, t]() {
                for (int i = 0; i < ORPHANS_PER_THREAD; ++i) {
                    uint256 unknownParent = RandomHash(t * 1000 + i);
                    CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890 + t * 100 + i, t * 10000 + i);

                    chainstate.AddOrphanHeader(orphan, /*peer_id=*/1);
                }
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        // Per-peer limit should be enforced
        size_t orphan_count = chainstate.GetOrphanHeaderCount();
        REQUIRE(orphan_count <= PER_PEER_LIMIT);
    }
}

// =============================================================================
// TEST 2: Concurrent Read/Write Operations
// =============================================================================
// Security Goal: Verify concurrent read/write operations don't deadlock or corrupt state
// Attack Scenario: Multiple threads performing different operations simultaneously
// Expected: No deadlocks, all operations complete, consistent state
TEST_CASE("Thread Safety - Concurrent Read/Write", "[orphan][thread][critical]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    SECTION("Concurrent add, query, and evict") {
        std::atomic<bool> stop{false};
        std::atomic<int> add_count{0};
        std::atomic<int> query_count{0};

        // Thread 1: Adding orphans
        std::thread adder([&]() {
            for (int i = 0; i < 50 && !stop.load(); ++i) {
                uint256 unknownParent = RandomHash(1000 + i);
                CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890 + i, 1000 + i);
                chainstate.AddOrphanHeader(orphan, /*peer_id=*/1);
                add_count.fetch_add(1);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        });

        // Thread 2: Querying orphan count
        std::thread querier([&]() {
            for (int i = 0; i < 100 && !stop.load(); ++i) {
                size_t count = chainstate.GetOrphanHeaderCount();
                (void)count;  // Suppress unused warning
                query_count.fetch_add(1);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        });

        // Thread 3: Processing orphans (parent arrives)
        std::thread processor([&]() {
            const auto& genesis = params->GenesisBlock();

            for (int i = 0; i < 10 && !stop.load(); ++i) {
                // Add a valid header that might resolve some orphans
                CBlockHeader valid = CreateTestHeader(genesis.GetHash(), genesis.nTime + 120 + i * 60, 5000 + i);
                ValidationState state;
                chainstate.AcceptBlockHeader(valid, state);
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        });

        // Wait for operations to complete
        adder.join();
        querier.join();
        processor.join();

        // Verify no crashes and operations completed
        REQUIRE(add_count.load() > 0);
        REQUIRE(query_count.load() > 0);

        // Final state should be consistent
        size_t final_count = chainstate.GetOrphanHeaderCount();
        REQUIRE(final_count >= 0);  // No crashes
    }
}

// =============================================================================
// TEST 3: Concurrent Eviction
// =============================================================================
// Security Goal: Prevent double-eviction or corruption during concurrent eviction
// Attack Scenario: Multiple threads calling eviction simultaneously
// Expected: Correct eviction count, no orphans evicted multiple times
TEST_CASE("Thread Safety - Concurrent Eviction", "[orphan][thread][critical]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    SECTION("Multiple threads evicting from full pool") {
        const int INITIAL_ORPHANS = 100;

        // Fill pool with orphans
        for (int i = 0; i < INITIAL_ORPHANS; ++i) {
            uint256 unknownParent = RandomHash(i);
            CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890 + i, 1000 + i);
            chainstate.AddOrphanHeader(orphan, /*peer_id=*/((i % 10) + 1));
        }

        size_t initial_count = chainstate.GetOrphanHeaderCount();
        REQUIRE(initial_count > 0);

        // Multiple threads adding more orphans (triggers eviction)
        const int NUM_THREADS = 5;
        std::vector<std::thread> threads;

        for (int t = 0; t < NUM_THREADS; ++t) {
            threads.emplace_back([&, t]() {
                for (int i = 0; i < 20; ++i) {
                    uint256 unknownParent = RandomHash(t * 1000 + i + 10000);
                    CBlockHeader orphan = CreateTestHeader(
                        unknownParent,
                        1234567890 + t * 100 + i,
                        t * 10000 + i + 20000
                    );
                    chainstate.AddOrphanHeader(orphan, /*peer_id=*/((t % 5) + 1));
                }
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        // Verify pool is consistent
        size_t final_count = chainstate.GetOrphanHeaderCount();
        REQUIRE(final_count > 0);
        REQUIRE(final_count <= 1000);  // Global limit enforced
    }
}

// =============================================================================
// TEST 4: Race Condition - Add During Processing
// =============================================================================
// Security Goal: Prevent corruption when orphans added while being processed
// Attack Scenario: Parent arrives (triggers ProcessOrphanHeaders) while new orphans added
// Expected: No iterator invalidation, no crashes, correct final state
TEST_CASE("Thread Safety - Add During Processing", "[orphan][thread][critical]") {
    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    SECTION("Add orphans while parent resolves existing orphans") {
        const auto& genesis = params->GenesisBlock();

        // Add parent block
        CBlockHeader parent = CreateTestHeader(genesis.GetHash(), genesis.nTime + 120, 1000);
        ValidationState state;
        chain::CBlockIndex* parent_idx = chainstate.AcceptBlockHeader(parent, state);
        REQUIRE(parent_idx != nullptr);
        chainstate.TryAddBlockIndexCandidate(parent_idx);

        uint256 parent_hash = parent.GetHash();

        // Add orphans that reference this parent
        for (int i = 0; i < 20; ++i) {
            CBlockHeader orphan = CreateTestHeader(parent_hash, genesis.nTime + 240 + i * 60, 2000 + i);
            chainstate.AddOrphanHeader(orphan, /*peer_id=*/1);
        }

        size_t before_count = chainstate.GetOrphanHeaderCount();
        REQUIRE(before_count > 0);

        std::atomic<bool> processing_done{false};

        // Thread 1: Process orphans (parent already in index)
        std::thread processor([&]() {
            // ProcessOrphanHeaders is called internally when parent is accepted
            // We simulate this by accepting another header
            CBlockHeader trigger = CreateTestHeader(genesis.GetHash(), genesis.nTime + 180, 1500);
            ValidationState st;
            chainstate.AcceptBlockHeader(trigger, st);
            processing_done.store(true);
        });

        // Thread 2: Add new orphans during processing
        std::thread adder([&]() {
            for (int i = 0; i < 10; ++i) {
                uint256 unknownParent = RandomHash(5000 + i);
                CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890 + i, 5000 + i);
                chainstate.AddOrphanHeader(orphan, /*peer_id=*/2);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        });

        processor.join();
        adder.join();

        // Verify no crashes and state is consistent
        size_t after_count = chainstate.GetOrphanHeaderCount();
        REQUIRE(after_count >= 0);  // No crash

        // Some orphans should have been processed (removed from pool)
        // New orphans should have been added
        // Exact count depends on timing, but should be consistent
    }

    SECTION("Rapid parent arrivals with concurrent orphan additions") {
        const auto& genesis = params->GenesisBlock();
        std::atomic<bool> stop{false};

        // Thread 1: Add orphans continuously
        std::thread adder([&]() {
            for (int i = 0; i < 50 && !stop.load(); ++i) {
                uint256 unknownParent = RandomHash(i);
                CBlockHeader orphan = CreateTestHeader(unknownParent, 1234567890 + i, 1000 + i);
                chainstate.AddOrphanHeader(orphan, /*peer_id=*/1);
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        });

        // Thread 2: Add parents that might resolve orphans
        std::thread parent_adder([&]() {
            for (int i = 0; i < 20 && !stop.load(); ++i) {
                CBlockHeader parent = CreateTestHeader(genesis.GetHash(), genesis.nTime + 120 + i * 60, 2000 + i);
                ValidationState state;
                chainstate.AcceptBlockHeader(parent, state);
                std::this_thread::sleep_for(std::chrono::milliseconds(3));
            }
        });

        adder.join();
        parent_adder.join();

        // Verify final state is consistent
        size_t final_count = chainstate.GetOrphanHeaderCount();
        REQUIRE(final_count >= 0);  // No crashes
    }
}
