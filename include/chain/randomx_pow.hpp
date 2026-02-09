// Copyright (c) 2018-2021 The Scash developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include "chain/block.hpp"

#include <cstdint>
#include <memory>
#include <mutex>

#include <randomx.h>

namespace unicity {
namespace crypto {

// RandomX Proof-of-Work Implementation

// POW verification modes
enum class POWVerifyMode {
  FULL = 0,         // Verify both RandomX hash and commitment
  COMMITMENT_ONLY,  // Only verify commitment (faster, for header sync)
  MINING            // Calculate hash and commitment (for miners)
};

struct RandomXCacheWrapper;

// RandomX VM Wrapper - Manages VM lifecycle
// Each thread gets its own VM instance (thread-local storage)
struct RandomXVMWrapper {
  randomx_vm* vm = nullptr;
  std::shared_ptr<RandomXCacheWrapper> cache;

  RandomXVMWrapper(randomx_vm* v, std::shared_ptr<RandomXCacheWrapper> c) : vm(v), cache(c) {}

  ~RandomXVMWrapper() {
    if (vm) {
      randomx_destroy_vm(vm);
      cache = nullptr;
    }
  }
};

// Number of epochs to cache (one VM per epoch, minimum 1)
static constexpr int DEFAULT_RANDOMX_VM_CACHE_SIZE = 2;

// Calculate epoch from timestamp: epoch = timestamp / duration (seconds)
uint32_t GetEpoch(uint32_t nTime, uint32_t nDuration);

// Calculate RandomX key (seed hash) for epoch:
// SHA256d("Alpha/RandomX/Epoch/N") - matches Unicity Alpha network
uint256 GetSeedHash(uint32_t nEpoch);

// Calculate RandomX commitment from block header
// inHash: optional pre-computed hash (nullptr = use block.hashRandomX)
uint256 GetRandomXCommitment(const CBlockHeader& block, uint256* inHash = nullptr);

// Initialize RandomX subsystem (call once at startup)
// Thread-safe and idempotent (safe to call multiple times)
void InitRandomX();

// Shutdown RandomX subsystem
// Marks subsystem as shutdown and prevents new VM creation
// Production usage: Call after stopping all validation/network/mining threads
// Test usage: Safe to call multiple times; each thread's cache persists until thread exits
void ShutdownRandomX();

// Get cached RandomX VM for epoch
// Each thread gets its own VM instance - no locking required
// Returns thread-local VM for the specified epoch
std::shared_ptr<RandomXVMWrapper> GetCachedVM(uint32_t nEpoch);

}  // namespace crypto
}  // namespace unicity
