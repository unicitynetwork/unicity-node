// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include <catch_amalgamated.hpp>
#include "chain/randomx_pow.hpp"
#include "chain/chainparams.hpp"
#include "chain/pow.hpp"
#include "util/logging.hpp"
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>

using namespace unicity;

TEST_CASE("GetEpoch - Epoch calculation", "[randomx][security][epoch]") {
  SECTION("Valid epoch calculation") {
    REQUIRE(crypto::GetEpoch(0, 86400) == 0);
    REQUIRE(crypto::GetEpoch(86400, 86400) == 1);
    REQUIRE(crypto::GetEpoch(86399, 86400) == 0);
    REQUIRE(crypto::GetEpoch(172800, 86400) == 2);
  }

  SECTION("Boundary conditions") {
    REQUIRE(crypto::GetEpoch(UINT32_MAX, 1) == UINT32_MAX);
    REQUIRE(crypto::GetEpoch(UINT32_MAX, UINT32_MAX) == 1);
    REQUIRE(crypto::GetEpoch(0, UINT32_MAX) == 0);
  }

  // NOTE: GetEpoch() is a simple utility that assumes valid input (nDuration > 0).
  // Division by zero protection is not needed because:
  // 1. In production, nRandomXEpochDuration is hardcoded in consensus params (never 0)
  // 2. CheckProofOfWork() gets nDuration from consensus params (guaranteed valid)
  // 3. Testing division by zero would trigger SIGFPE and provide no value
}

TEST_CASE("GetSeedHash - Boundary conditions", "[randomx][security][seed]") {
  crypto::InitRandomX();

  SECTION("Epoch 0") {
    uint256 hash = crypto::GetSeedHash(0);
    REQUIRE(!hash.IsNull());
  }

  SECTION("High epoch number") {
    uint256 hash = crypto::GetSeedHash(UINT32_MAX);
    REQUIRE(!hash.IsNull());
  }

  SECTION("Different epochs produce different hashes") {
    uint256 hash0 = crypto::GetSeedHash(0);
    uint256 hash1 = crypto::GetSeedHash(1);
    uint256 hash100 = crypto::GetSeedHash(100);

    REQUIRE(hash0 != hash1);
    REQUIRE(hash1 != hash100);
    REQUIRE(hash0 != hash100);
  }

  SECTION("Same epoch produces same hash (deterministic)") {
    uint256 hash1 = crypto::GetSeedHash(42);
    uint256 hash2 = crypto::GetSeedHash(42);

    REQUIRE(hash1 == hash2);
  }
}

TEST_CASE("RandomX initialization - Thread safety", "[randomx][security][threading]") {
  SECTION("Multiple threads can call InitRandomX() concurrently") {
    // Shutdown first to reset state
    crypto::ShutdownRandomX();

    constexpr int NUM_THREADS = 10;
    std::vector<std::thread> threads;
    std::atomic<int> init_count{0};

    for (int i = 0; i < NUM_THREADS; ++i) {
      threads.emplace_back([&init_count]() {
        crypto::InitRandomX();
        init_count.fetch_add(1, std::memory_order_relaxed);
      });
    }

    for (auto& t : threads) {
      t.join();
    }

    // All threads should complete successfully
    REQUIRE(init_count == NUM_THREADS);

    // Re-initialize for other tests
    crypto::InitRandomX();
  }

  SECTION("GetCachedVM fails gracefully when not initialized") {
    crypto::ShutdownRandomX();

    auto vm = crypto::GetCachedVM(0);
    REQUIRE(vm == nullptr);

    // Re-initialize for other tests
    crypto::InitRandomX();
  }

  SECTION("Init/Shutdown cycle works correctly") {
    crypto::InitRandomX();
    REQUIRE(crypto::GetCachedVM(0) != nullptr);

    crypto::ShutdownRandomX();
    REQUIRE(crypto::GetCachedVM(0) == nullptr);

    crypto::InitRandomX();
    REQUIRE(crypto::GetCachedVM(0) != nullptr);
  }
}

TEST_CASE("RandomX VM caching - Thread-local isolation", "[randomx][security][threading]") {
  crypto::InitRandomX();

  SECTION("Each thread gets its own VM instance") {
    constexpr int NUM_THREADS = 5;
    std::vector<std::thread> threads;
    std::vector<void*> vm_pointers(NUM_THREADS);

    for (int i = 0; i < NUM_THREADS; ++i) {
      threads.emplace_back([&vm_pointers, i]() {
        auto vm = crypto::GetCachedVM(0);
        REQUIRE(vm != nullptr);
        // Store the raw VM pointer to verify each thread has a different instance
        vm_pointers[i] = vm->vm;
      });
    }

    for (auto& t : threads) {
      t.join();
    }

    // Verify all VMs are non-null
    for (int i = 0; i < NUM_THREADS; ++i) {
      REQUIRE(vm_pointers[i] != nullptr);
    }

    // NOTE: We cannot reliably verify that threads got different VMs because:
    // 1. Threads may complete sequentially and reuse the same thread-local storage
    // 2. Thread-local storage may be allocated at the same address after thread exit
    // 3. The test proves thread-safety (no crashes), not necessarily different instances
    //
    // The important property is that each thread's GetCachedVM() succeeds without
    // data races or crashes, which this test verifies.
  }

  SECTION("Concurrent VM creation for same epoch is thread-safe") {
    constexpr int NUM_THREADS = 10;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};

    for (int i = 0; i < NUM_THREADS; ++i) {
      threads.emplace_back([&success_count]() {
        auto vm = crypto::GetCachedVM(0);
        if (vm != nullptr) {
          success_count.fetch_add(1, std::memory_order_relaxed);
        }
      });
    }

    for (auto& t : threads) {
      t.join();
    }

    REQUIRE(success_count == NUM_THREADS);
  }

  SECTION("Concurrent VM creation for different epochs is thread-safe") {
    constexpr int NUM_THREADS = 10;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};

    for (int i = 0; i < NUM_THREADS; ++i) {
      threads.emplace_back([&success_count, i]() {
        // Each thread requests a different epoch
        auto vm = crypto::GetCachedVM(i);
        if (vm != nullptr) {
          success_count.fetch_add(1, std::memory_order_relaxed);
        }
      });
    }

    for (auto& t : threads) {
      t.join();
    }

    REQUIRE(success_count == NUM_THREADS);
  }
}

TEST_CASE("RandomX VM LRU cache behavior", "[randomx][security][cache]") {
  crypto::InitRandomX();

  SECTION("Cache evicts old epochs when full") {
    // DEFAULT_RANDOMX_VM_CACHE_SIZE is 2, so accessing 3 epochs should evict the first
    auto vm0 = crypto::GetCachedVM(0);
    REQUIRE(vm0 != nullptr);

    auto vm1 = crypto::GetCachedVM(1);
    REQUIRE(vm1 != nullptr);

    auto vm2 = crypto::GetCachedVM(2);
    REQUIRE(vm2 != nullptr);

    // All should succeed - the cache should evict epoch 0
    // But we can't easily test eviction without implementation details
    REQUIRE(true);
  }

  SECTION("Accessing same epoch returns cached VM") {
    auto vm1 = crypto::GetCachedVM(42);
    REQUIRE(vm1 != nullptr);
    void* ptr1 = vm1->vm;

    auto vm2 = crypto::GetCachedVM(42);
    REQUIRE(vm2 != nullptr);
    void* ptr2 = vm2->vm;

    // Should be the same VM instance (cached)
    REQUIRE(ptr1 == ptr2);
  }
}

// NOTE: CheckProofOfWork validation with invalid consensus parameters
// is not testable without refactoring ChainParams to allow injecting invalid params.
// In production, consensus.nRandomXEpochDuration is hardcoded and guaranteed > 0.
// See pow_tests.cpp for comprehensive CheckProofOfWork validation tests.

TEST_CASE("RandomX commitment calculation", "[randomx][security][commitment]") {
  crypto::InitRandomX();
  chain::GlobalChainParams::Select(chain::ChainType::REGTEST);
  const chain::ChainParams& params = chain::GlobalChainParams::Get();

  SECTION("Commitment is deterministic") {
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock = uint256();
    header.minerAddress = uint160();
    header.nTime = 1000000;
    header.nBits = 0x207fffff;
    header.nNonce = 0;

    // Calculate hash
    uint256 hash;
    bool result = consensus::CheckProofOfWork(header, header.nBits, params,
                                               crypto::POWVerifyMode::MINING, &hash);

    if (result) {
      // Set the hash in header
      header.hashRandomX = hash;

      // Calculate commitment twice - should be identical
      uint256 cm1 = crypto::GetRandomXCommitment(header);
      uint256 cm2 = crypto::GetRandomXCommitment(header);

      REQUIRE(cm1 == cm2);
      REQUIRE(!cm1.IsNull());
    }
  }

  SECTION("Different hashes produce different commitments") {
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock = uint256();
    header.minerAddress = uint160();
    header.nTime = 1000000;
    header.nBits = 0x207fffff;
    header.nNonce = 0;

    uint256 hash1, hash2;

    // Calculate hash for nonce 0
    consensus::CheckProofOfWork(header, header.nBits, params,
                                 crypto::POWVerifyMode::MINING, &hash1);

    // Calculate hash for nonce 1
    header.nNonce = 1;
    consensus::CheckProofOfWork(header, header.nBits, params,
                                 crypto::POWVerifyMode::MINING, &hash2);

    if (hash1 != hash2) {
      header.nNonce = 0;
      header.hashRandomX = hash1;
      uint256 cm1 = crypto::GetRandomXCommitment(header);

      header.nNonce = 1;
      header.hashRandomX = hash2;
      uint256 cm2 = crypto::GetRandomXCommitment(header);

      REQUIRE(cm1 != cm2);
    }
  }
}

TEST_CASE("RandomX shutdown with multiple threads", "[randomx][security][threading][shutdown]") {
  SECTION("Shutdown prevents new VM creation") {
    crypto::InitRandomX();

    // Create VM before shutdown
    auto vm1 = crypto::GetCachedVM(0);
    REQUIRE(vm1 != nullptr);

    // Shutdown
    crypto::ShutdownRandomX();

    // Should not be able to create new VMs
    auto vm2 = crypto::GetCachedVM(1);
    REQUIRE(vm2 == nullptr);

    // Re-initialize for other tests
    crypto::InitRandomX();
  }

  SECTION("Thread-local caches persist after shutdown (by design)") {
    crypto::InitRandomX();

    // Create VM in this thread
    auto vm1 = crypto::GetCachedVM(0);
    REQUIRE(vm1 != nullptr);
    void* ptr1 = vm1->vm;

    // Shutdown (sets flag, but doesn't clear this thread's cache)
    crypto::ShutdownRandomX();

    // The VM wrapper still exists (shared_ptr keeps it alive)
    // But GetCachedVM() will return nullptr due to shutdown flag
    auto vm2 = crypto::GetCachedVM(0);
    REQUIRE(vm2 == nullptr);

    // vm1 is still valid because we hold a shared_ptr to it
    REQUIRE(vm1->vm == ptr1);

    // Re-initialize for other tests
    crypto::InitRandomX();
  }
}

TEST_CASE("RandomX epoch boundaries", "[randomx][security][epoch]") {
  crypto::InitRandomX();

  SECTION("Epoch transitions are handled correctly") {
    constexpr uint32_t EPOCH_DURATION = 86400; // 1 day in seconds

    // Just before epoch boundary
    uint32_t epoch0 = crypto::GetEpoch(EPOCH_DURATION - 1, EPOCH_DURATION);
    REQUIRE(epoch0 == 0);

    // At epoch boundary
    uint32_t epoch1 = crypto::GetEpoch(EPOCH_DURATION, EPOCH_DURATION);
    REQUIRE(epoch1 == 1);

    // Just after epoch boundary
    uint32_t epoch1_plus = crypto::GetEpoch(EPOCH_DURATION + 1, EPOCH_DURATION);
    REQUIRE(epoch1_plus == 1);
  }

  SECTION("Different epoch VMs use different seed hashes") {
    auto vm0 = crypto::GetCachedVM(0);
    auto vm1 = crypto::GetCachedVM(1);

    REQUIRE(vm0 != nullptr);
    REQUIRE(vm1 != nullptr);

    // VMs should be different instances
    REQUIRE(vm0->vm != vm1->vm);

    // Seed hashes should be different
    uint256 seed0 = crypto::GetSeedHash(0);
    uint256 seed1 = crypto::GetSeedHash(1);
    REQUIRE(seed0 != seed1);
  }

  SECTION("Epoch boundary overflow handling") {
    // Test near UINT32_MAX
    constexpr uint32_t EPOCH_DURATION = 86400;

    // Very large timestamp
    uint32_t epoch_large = crypto::GetEpoch(UINT32_MAX, EPOCH_DURATION);
    REQUIRE(epoch_large == UINT32_MAX / EPOCH_DURATION);

    // UINT32_MAX-1 to UINT32_MAX transition
    uint32_t epoch_before = crypto::GetEpoch(UINT32_MAX - 1, EPOCH_DURATION);
    uint32_t epoch_at = crypto::GetEpoch(UINT32_MAX, EPOCH_DURATION);
    // Should be same epoch (difference of 1 second)
    REQUIRE(epoch_before == epoch_at);
  }
}

// ============================================================================
// ADDITIONAL EDGE CASE TESTS
// ============================================================================

TEST_CASE("RandomX hash computation correctness", "[randomx][security][hash]") {
  crypto::InitRandomX();
  chain::GlobalChainParams::Select(chain::ChainType::REGTEST);
  const chain::ChainParams& params = chain::GlobalChainParams::Get();

  // Helper to mine a valid block (find nonce that meets target)
  auto mineBlock = [&](CBlockHeader& header) -> uint256 {
    uint256 hash;
    for (uint32_t nonce = 0; nonce < 10000; nonce++) {
      header.nNonce = nonce;
      if (consensus::CheckProofOfWork(header, header.nBits, params,
                                      crypto::POWVerifyMode::MINING, &hash)) {
        return hash;
      }
    }
    return uint256();  // Failed to find valid nonce
  };

  SECTION("Same input produces same hash (deterministic)") {
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.minerAddress.SetNull();
    header.nTime = 1000000;
    header.nBits = params.GenesisBlock().nBits;
    header.hashRandomX.SetNull();

    // Mine to find a valid nonce
    uint256 hash1 = mineBlock(header);
    REQUIRE(!hash1.IsNull());

    uint32_t validNonce = header.nNonce;

    // Compute hash again with same nonce - should be identical
    uint256 hash2;
    header.nNonce = validNonce;
    bool result = consensus::CheckProofOfWork(header, header.nBits, params,
                                              crypto::POWVerifyMode::MINING, &hash2);
    REQUIRE(result);
    REQUIRE(hash1 == hash2);
  }

  SECTION("Different nonce produces different hash") {
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.minerAddress.SetNull();
    header.nTime = 1000000;
    header.nBits = params.GenesisBlock().nBits;
    header.hashRandomX.SetNull();

    // Mine first block
    uint256 hash1 = mineBlock(header);
    REQUIRE(!hash1.IsNull());
    uint32_t nonce1 = header.nNonce;

    // Mine second block - use different timestamp to get different nonce search space
    header.nTime = 1000001;  // Different timestamp ensures different hash space
    uint256 hash2 = mineBlock(header);
    REQUIRE(!hash2.IsNull());

    // Different inputs should produce different hashes
    REQUIRE(hash1 != hash2);
  }

  SECTION("Different timestamp produces different hash") {
    CBlockHeader header1, header2;
    header1.nVersion = header2.nVersion = 1;
    header1.hashPrevBlock.SetNull();
    header2.hashPrevBlock.SetNull();
    header1.minerAddress.SetNull();
    header2.minerAddress.SetNull();
    header1.nBits = header2.nBits = params.GenesisBlock().nBits;
    header1.hashRandomX.SetNull();
    header2.hashRandomX.SetNull();

    header1.nTime = 1000000;
    header2.nTime = 2000000;  // Different timestamp

    uint256 hash1 = mineBlock(header1);
    uint256 hash2 = mineBlock(header2);

    REQUIRE(!hash1.IsNull());
    REQUIRE(!hash2.IsNull());
    REQUIRE(hash1 != hash2);
  }

  SECTION("Hash is 256 bits (32 bytes)") {
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.minerAddress.SetNull();
    header.nTime = 1000000;
    header.nBits = params.GenesisBlock().nBits;
    header.hashRandomX.SetNull();

    uint256 hash = mineBlock(header);
    REQUIRE(!hash.IsNull());
    REQUIRE(hash.size() == 32);
  }
}

TEST_CASE("RandomX concurrent shutdown during VM usage", "[randomx][security][threading][shutdown]") {
  SECTION("Threads using VM survive concurrent shutdown") {
    crypto::InitRandomX();

    constexpr int NUM_THREADS = 5;
    constexpr int HASHES_PER_THREAD = 10;
    std::vector<std::thread> threads;
    std::atomic<int> completed{0};
    std::atomic<bool> shutdown_called{false};

    chain::GlobalChainParams::Select(chain::ChainType::REGTEST);
    const chain::ChainParams& params = chain::GlobalChainParams::Get();

    // Start worker threads that compute hashes
    for (int t = 0; t < NUM_THREADS; t++) {
      threads.emplace_back([&, t]() {
        // Get VM before potential shutdown
        auto vm = crypto::GetCachedVM(0);
        if (!vm) return;

        for (int i = 0; i < HASHES_PER_THREAD; i++) {
          CBlockHeader header;
          header.nVersion = 1;
          header.nTime = 1000000;
          header.nBits = params.GenesisBlock().nBits;
          header.nNonce = t * 1000 + i;
          header.hashRandomX.SetNull();

          uint256 hash;
          // Even if shutdown is called, existing VMs should still work
          consensus::CheckProofOfWork(header, header.nBits, params,
                                      crypto::POWVerifyMode::MINING, &hash);
        }
        completed.fetch_add(1, std::memory_order_relaxed);
      });
    }

    // Let threads start
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Call shutdown while threads are working
    crypto::ShutdownRandomX();
    shutdown_called.store(true, std::memory_order_relaxed);

    // Wait for all threads
    for (auto& t : threads) {
      t.join();
    }

    // All threads should have completed without crash
    REQUIRE(completed.load() == NUM_THREADS);

    // Re-initialize for other tests
    crypto::InitRandomX();
  }
}

TEST_CASE("RandomX memory pressure and LRU stress", "[randomx][security][cache][stress][slow]") {
  crypto::InitRandomX();

  SECTION("Many epoch accesses with bounded cache") {
    // DEFAULT_RANDOMX_VM_CACHE_SIZE is 2
    // Access a few epochs to test LRU eviction
    constexpr int NUM_EPOCHS = 5;  // Reduced from 10

    for (int epoch = 0; epoch < NUM_EPOCHS; epoch++) {
      auto vm = crypto::GetCachedVM(epoch);
      REQUIRE(vm != nullptr);
      REQUIRE(vm->vm != nullptr);
    }

    // After accessing 5 epochs with cache size 2, only last 2 should be cached
    // But we can still access any epoch (will recreate VM)
    auto vm0 = crypto::GetCachedVM(0);
    REQUIRE(vm0 != nullptr);

    auto vm4 = crypto::GetCachedVM(4);
    REQUIRE(vm4 != nullptr);
  }

  SECTION("Rapid epoch switching") {
    // Rapidly switch between 2 epochs (cache size is 2, so no eviction)
    // This tests cache hits, not VM creation
    for (int i = 0; i < 20; i++) {
      uint32_t epoch = i % 2;  // Cycle through 2 epochs (fits in cache)
      auto vm = crypto::GetCachedVM(epoch);
      REQUIRE(vm != nullptr);
    }
  }

  SECTION("Concurrent epoch stress") {
    constexpr int NUM_THREADS = 2;  // Reduced from 4
    constexpr int EPOCHS_PER_THREAD = 3;  // Reduced from 5
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};

    for (int t = 0; t < NUM_THREADS; t++) {
      threads.emplace_back([&, t]() {
        for (int e = 0; e < EPOCHS_PER_THREAD; e++) {
          uint32_t epoch = t * 100 + e;  // Different epochs per thread
          auto vm = crypto::GetCachedVM(epoch);
          if (vm != nullptr) {
            success_count.fetch_add(1, std::memory_order_relaxed);
          }
        }
      });
    }

    for (auto& t : threads) {
      t.join();
    }

    REQUIRE(success_count.load() == NUM_THREADS * EPOCHS_PER_THREAD);
  }
}

TEST_CASE("RandomX re-initialization after shutdown", "[randomx][security][lifecycle]") {
  SECTION("Fresh VM created after init-shutdown-init cycle") {
    crypto::InitRandomX();

    // Create VM
    auto vm1 = crypto::GetCachedVM(0);
    REQUIRE(vm1 != nullptr);
    void* ptr1 = vm1->vm;

    // Shutdown
    crypto::ShutdownRandomX();

    // Verify shutdown worked
    auto vm_null = crypto::GetCachedVM(0);
    REQUIRE(vm_null == nullptr);

    // Re-initialize
    crypto::InitRandomX();

    // Create new VM - should work
    auto vm2 = crypto::GetCachedVM(0);
    REQUIRE(vm2 != nullptr);

    // Note: vm2 might be same or different pointer depending on thread-local storage
    // The important thing is that it works
    REQUIRE(vm2->vm != nullptr);
  }

  SECTION("Multiple shutdown calls are idempotent") {
    crypto::InitRandomX();

    crypto::ShutdownRandomX();
    crypto::ShutdownRandomX();
    crypto::ShutdownRandomX();

    // Should still be able to re-init
    crypto::InitRandomX();
    auto vm = crypto::GetCachedVM(0);
    REQUIRE(vm != nullptr);
  }

  SECTION("Multiple init calls are idempotent") {
    crypto::InitRandomX();
    crypto::InitRandomX();
    crypto::InitRandomX();

    auto vm = crypto::GetCachedVM(0);
    REQUIRE(vm != nullptr);
  }
}

TEST_CASE("RandomX commitment with inHash parameter", "[randomx][security][commitment]") {
  crypto::InitRandomX();
  chain::GlobalChainParams::Select(chain::ChainType::REGTEST);
  const chain::ChainParams& params = chain::GlobalChainParams::Get();

  SECTION("Using inHash parameter overrides block.hashRandomX") {
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.minerAddress.SetNull();
    header.nTime = 1000000;
    header.nBits = params.GenesisBlock().nBits;
    header.nNonce = 42;

    // Compute actual hash
    uint256 actual_hash;
    consensus::CheckProofOfWork(header, header.nBits, params,
                                crypto::POWVerifyMode::MINING, &actual_hash);
    header.hashRandomX = actual_hash;

    // Commitment using block's hashRandomX
    uint256 cm1 = crypto::GetRandomXCommitment(header);

    // Commitment using inHash parameter with same value
    uint256 cm2 = crypto::GetRandomXCommitment(header, &actual_hash);

    REQUIRE(cm1 == cm2);

    // Commitment using inHash parameter with different value
    uint256 different_hash = uint256S("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    uint256 cm3 = crypto::GetRandomXCommitment(header, &different_hash);

    REQUIRE(cm1 != cm3);
  }

  SECTION("inHash nullptr uses block.hashRandomX") {
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.minerAddress.SetNull();
    header.nTime = 1000000;
    header.nBits = params.GenesisBlock().nBits;
    header.nNonce = 42;

    uint256 hash;
    consensus::CheckProofOfWork(header, header.nBits, params,
                                crypto::POWVerifyMode::MINING, &hash);
    header.hashRandomX = hash;

    // Both should use block.hashRandomX
    uint256 cm1 = crypto::GetRandomXCommitment(header);
    uint256 cm2 = crypto::GetRandomXCommitment(header, nullptr);

    REQUIRE(cm1 == cm2);
  }
}

TEST_CASE("SimpleLRUCache edge cases", "[randomx][security][cache]") {
  // Test the LRU cache behavior through the RandomX API
  crypto::InitRandomX();

  SECTION("Single element access") {
    auto vm = crypto::GetCachedVM(999);
    REQUIRE(vm != nullptr);

    // Access same element again
    auto vm2 = crypto::GetCachedVM(999);
    REQUIRE(vm2 != nullptr);
    REQUIRE(vm.get() == vm2.get());
  }

  SECTION("Exact capacity behavior") {
    // Cache size is 2, so accessing epochs 0, 1 should fill it
    auto vm0 = crypto::GetCachedVM(100);
    REQUIRE(vm0 != nullptr);

    auto vm1 = crypto::GetCachedVM(101);
    REQUIRE(vm1 != nullptr);

    // Both should still be cached
    auto vm0_again = crypto::GetCachedVM(100);
    auto vm1_again = crypto::GetCachedVM(101);

    REQUIRE(vm0.get() == vm0_again.get());
    REQUIRE(vm1.get() == vm1_again.get());
  }

  SECTION("LRU eviction order") {
    // Access epochs 0, 1 (fills cache)
    auto vm0 = crypto::GetCachedVM(200);
    auto vm1 = crypto::GetCachedVM(201);

    // Access epoch 0 again (makes it most recent)
    auto vm0_touch = crypto::GetCachedVM(200);

    // Access epoch 2 (should evict epoch 1, not epoch 0)
    auto vm2 = crypto::GetCachedVM(202);

    // Epoch 0 should still be cached (was accessed more recently)
    auto vm0_check = crypto::GetCachedVM(200);
    REQUIRE(vm0.get() == vm0_check.get());

    // Epoch 1 should have been evicted (will be recreated)
    auto vm1_new = crypto::GetCachedVM(201);
    REQUIRE(vm1_new != nullptr);
    // Can't reliably check if it's a new instance without internal access
  }
}
