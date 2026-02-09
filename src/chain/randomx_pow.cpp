// Copyright (c) 2018-2021 The Scash developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "chain/randomx_pow.hpp"

#include "util/arith_uint256.hpp"
#include "util/logging.hpp"
#include "util/sha256.hpp"

#include <atomic>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>

namespace unicity {
namespace crypto {

// RandomX epoch seed string
// - Same RandomX cache keys per epoch as Unicity Alpha network
// - Saves creating a separate RandomX fork

static const char* RANDOMX_EPOCH_SEED_STRING = "Alpha/RandomX/Epoch/%d";

// Mutex for initialization and shutdown
static std::mutex g_randomx_mutex;

// RAII wrappers for RandomX objects
struct RandomXCacheWrapper {
  randomx_cache* cache = nullptr;

  explicit RandomXCacheWrapper(randomx_cache* c) : cache(c) {}
  ~RandomXCacheWrapper() {
    if (cache)
      randomx_release_cache(cache);
  }
};

// Simple LRU cache for RandomX VMs and caches (per-thread, bounded)
template <typename Key, typename Value>
class SimpleLRUCache {
private:
  struct Entry {
    Key key;
    Value value;
  };

  std::vector<Entry> entries_;
  size_t max_size_;

public:
  explicit SimpleLRUCache(size_t max_size) : max_size_(max_size) {}

  // Get value if exists, returns nullptr if not found
  Value* get(const Key& key) {
    // Search from end (most recent) to beginning
    for (auto it = entries_.rbegin(); it != entries_.rend(); ++it) {
      if (it->key == key) {
        // Move to end (most recent)
        Entry entry = std::move(*it);
        entries_.erase(std::prev(it.base()));
        entries_.push_back(std::move(entry));
        return &entries_.back().value;
      }
    }
    return nullptr;
  }

  // Insert or update a value
  void insert(const Key& key, const Value& value) {
    // Remove if already exists
    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
      if (it->key == key) {
        entries_.erase(it);
        break;
      }
    }

    // If at capacity, remove oldest (first) entry
    if (entries_.size() >= max_size_) {
      entries_.erase(entries_.begin());
    }

    // Add to end (most recent)
    entries_.push_back({key, value});
  }

  void clear() { entries_.clear(); }

  size_t size() const { return entries_.size(); }
};

// Thread-local cache storage: LRU with bounded size
static thread_local SimpleLRUCache<uint32_t, std::shared_ptr<RandomXCacheWrapper>> t_cache_storage(
    DEFAULT_RANDOMX_VM_CACHE_SIZE);

// Thread-local VM storage: LRU with bounded size
static thread_local SimpleLRUCache<uint32_t, std::shared_ptr<RandomXVMWrapper>> t_vm_cache(
    DEFAULT_RANDOMX_VM_CACHE_SIZE);

// Thread-safe initialization flag
static std::atomic<bool> g_randomx_initialized{false};

uint32_t GetEpoch(uint32_t nTime, uint32_t nDuration) {
  return nTime / nDuration;
}

uint256 GetSeedHash(uint32_t nEpoch) {
  char buffer[128];
  snprintf(buffer, sizeof(buffer), RANDOMX_EPOCH_SEED_STRING, nEpoch);
  std::string s(buffer);

  uint256 h1, h2;
  CSHA256().Write((const unsigned char*)s.data(), s.size()).Finalize(h1.begin());
  CSHA256().Write(h1.begin(), 32).Finalize(h2.begin());
  return h2;
}

// Get or create thread-local VM for an epoch
std::shared_ptr<RandomXVMWrapper> GetCachedVM(uint32_t nEpoch) {
  // Atomic read with relaxed ordering (no synchronization needed, just visibility)
  if (!g_randomx_initialized.load(std::memory_order_relaxed)) {
    LOG_ERROR("RandomX not initialized");
    return nullptr;
  }

  // Check if this thread already has a VM for this epoch
  auto vmPtr = t_vm_cache.get(nEpoch);
  if (vmPtr) {
    return *vmPtr;
  }

  uint256 seedHash = GetSeedHash(nEpoch);
  randomx_flags flags = randomx_get_flags();

  // Get or create thread-local cache (each thread has isolated cache)
  std::shared_ptr<RandomXCacheWrapper> myCache;
  auto cachePtr = t_cache_storage.get(nEpoch);
  if (cachePtr) {
    myCache = *cachePtr;
  } else {
    randomx_cache* pCache = randomx_alloc_cache(flags);
    if (!pCache) {
      LOG_ERROR("Failed to allocate RandomX cache for epoch {}", nEpoch);
      return nullptr;
    }
    randomx_init_cache(pCache, seedHash.data(), seedHash.size());
    myCache = std::make_shared<RandomXCacheWrapper>(pCache);
    // LRU insert: automatically evicts oldest if at capacity
    t_cache_storage.insert(nEpoch, myCache);
  }

  // Create thread-local VM (no lock needed, each thread has its own cache and VM)
  randomx_vm* myVM = randomx_create_vm(flags, myCache->cache, nullptr);
  if (!myVM) {
    LOG_ERROR("Failed to create RandomX VM for epoch {}", nEpoch);
    return nullptr;
  }

  auto vmWrapper = std::make_shared<RandomXVMWrapper>(myVM, myCache);
  // LRU insert: automatically evicts oldest epoch if at capacity
  t_vm_cache.insert(nEpoch, vmWrapper);

  LOG_CRYPTO_DEBUG("RandomX VM ready (epoch={})", nEpoch);

  return vmWrapper;
}

uint256 GetRandomXCommitment(const CBlockHeader& block, uint256* inHash) {
  uint256 rx_hash = inHash == nullptr ? block.hashRandomX : *inHash;

  // Create copy of header with hashRandomX set to null
  CBlockHeader rx_blockHeader(block);
  rx_blockHeader.hashRandomX.SetNull();

  // Calculate commitment
  char rx_cm[RANDOMX_HASH_SIZE];
  randomx_calculate_commitment(&rx_blockHeader, sizeof(rx_blockHeader), rx_hash.data(), rx_cm);

  return uint256(std::vector<unsigned char>(rx_cm, rx_cm + sizeof(rx_cm)));
}

void InitRandomX() {
  std::lock_guard<std::mutex> lock(g_randomx_mutex);

  // Check if already initialized (protected by mutex)
  if (g_randomx_initialized.load(std::memory_order_relaxed)) {
    return;
  }
  g_randomx_initialized.store(true, std::memory_order_release);

  LOG_CRYPTO_INFO("RandomX initialized (cache_size={})", DEFAULT_RANDOMX_VM_CACHE_SIZE);
}

void ShutdownRandomX() {
  std::lock_guard<std::mutex> lock(g_randomx_mutex);

  // Check if already shutdown (protected by mutex)
  if (!g_randomx_initialized.load(std::memory_order_relaxed)) {
    return;
  }

  // Mark as shutdown - prevents GetCachedVM() from creating new VMs
  // Thread-local caches are cleaned up when threads terminate
  g_randomx_initialized.store(false, std::memory_order_release);

  LOG_CRYPTO_INFO("RandomX shutdown complete");
}

}  // namespace crypto
}  // namespace unicity
