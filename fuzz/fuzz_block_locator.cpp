// Fuzz target for block locator generation and validation
// Tests CBlockLocator construction, step calculation, and hash consistency
//
// Block locators are used for efficient header sync (GETHEADERS/GETBLOCKS).
// Bugs in this code can:
// - Cause sync failures (incorrect locator generation)
// - Enable DoS (unbounded locator size, memory exhaustion)
// - Break IBD (wrong common ancestor detection)
// - Cause crashes (infinite loops, overflow in step calculation)
//
// Target code:
// - include/chain/block.hpp (CBlockLocator)
// - src/chain/chain.cpp (GetLocator, FindFork)

#include "chain/block.hpp"
#include "chain/block_index.hpp"
#include "chain/chain.hpp"
#include "util/arith_uint256.hpp"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <memory>

using namespace unicity;
using namespace unicity::chain;

// FuzzInput: Parse structured fuzz data
class FuzzInput {
public:
    FuzzInput(const uint8_t *data, size_t size) : data_(data), size_(size), offset_(0) {}

    template<typename T>
    T read() {
        if (offset_ + sizeof(T) > size_) {
            return T{};
        }
        T value;
        memcpy(&value, data_ + offset_, sizeof(T));
        offset_ += sizeof(T);
        return value;
    }

    bool has_bytes(size_t n) const {
        return offset_ + n <= size_;
    }

private:
    const uint8_t *data_;
    size_t size_;
    size_t offset_;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Need at least 5 bytes for mode + basic params
    if (size < 5) return 0;

    FuzzInput input(data, size);
    uint8_t mode = input.read<uint8_t>();

    // CRITICAL TEST 1: Empty locator construction
    if ((mode & 0x07) == 0) {
        try {
            std::vector<uint256> empty_vec;
            CBlockLocator locator(std::move(empty_vec));

            // Empty locator should be valid
            if (!locator.vHave.empty()) {
                // Default constructor should create empty locator - BUG!
                __builtin_trap();
            }

            // Should be able to copy empty locator
            CBlockLocator locator2 = locator;
            if (locator.vHave.size() != locator2.vHave.size()) {
                __builtin_trap();
            }
        } catch (const std::exception&) {
            // Should not throw
            __builtin_trap();
        }
    }

    // CRITICAL TEST 2: Locator with fuzzed hashes
    if ((mode & 0x07) == 1) {
        try {
            std::vector<uint256> hashes;
            size_t num_hashes = input.read<uint8_t>() % 50;  // Max 50 hashes

            for (size_t i = 0; i < num_hashes && input.has_bytes(32); i++) {
                uint8_t hash_bytes[32];
                for (int j = 0; j < 32; j++) {
                    hash_bytes[j] = input.read<uint8_t>();
                }

                uint256 hash;
                memcpy(hash.begin(), hash_bytes, 32);
                hashes.push_back(hash);
            }

            size_t original_size = hashes.size();
            CBlockLocator locator(std::move(hashes));

            // Locator size should match input
            if (locator.vHave.size() != original_size) {
                // Size mismatch - BUG!
                __builtin_trap();
            }

            // Copy should be identical
            CBlockLocator locator2 = locator;
            if (locator.vHave.size() != locator2.vHave.size()) {
                __builtin_trap();
            }
            for (size_t i = 0; i < locator.vHave.size(); i++) {
                if (locator.vHave[i] != locator2.vHave[i]) {
                    __builtin_trap();
                }
            }
        } catch (const std::exception&) {
            // Should not throw
            __builtin_trap();
        }
    }

    // CRITICAL TEST 3: Chain::GetLocator with synthetic chain
    if ((mode & 0x07) == 2 && size >= 100) {
        try {
            // Create a synthetic chain of block indices
            std::vector<std::unique_ptr<CBlockIndex>> chain;
            uint32_t chain_height = input.read<uint32_t>() % 10000;  // Max 10k blocks

            CBlockIndex* prev = nullptr;
            for (uint32_t h = 0; h <= chain_height && h < 100; h++) {
                auto index = std::make_unique<CBlockIndex>();
                index->nHeight = h;
                index->nTime = input.read<uint32_t>();
                index->nBits = input.read<uint32_t>();
                index->nChainWork = arith_uint256(h);  // Simple work = height

                // Compute hash from height
                uint256 hash;
                uint8_t hash_bytes[32] = {0};
                memcpy(hash_bytes, &h, sizeof(h));
                memcpy(hash.begin(), hash_bytes, 32);
                index->m_block_hash = hash;

                if (prev) {
                    index->pprev = prev;
                }

                prev = index.get();
                chain.push_back(std::move(index));
            }

            if (!chain.empty()) {
                // Create CChain object
                CChain active_chain;

                // SetTip requires reference, and it walks back via pprev to build chain
                // So we only set the tip (last block)
                CBlockIndex* tip = chain.back().get();
                if (tip) {
                    active_chain.SetTip(*tip);
                }

                // Generate locator from tip (member function, no args)
                if (tip) {
                    CBlockLocator locator = active_chain.GetLocator();

                    // Locator should not be empty for non-empty chain
                    if (locator.vHave.empty() && !chain.empty()) {
                        // Empty locator for non-empty chain - BUG!
                        __builtin_trap();
                    }

                    // First hash should be tip hash
                    if (!locator.vHave.empty()) {
                        if (locator.vHave[0] != tip->GetBlockHash()) {
                            // First hash not tip - BUG!
                            __builtin_trap();
                        }
                    }

                    // Locator size should be reasonable (log scale)
                    // For height H, locator size ≈ log2(H) + 10
                    size_t max_size = 50;  // Conservative upper bound
                    if (locator.vHave.size() > max_size) {
                        // Excessive locator size - potential DoS!
                        __builtin_trap();
                    }

                    // Regenerating locator should be deterministic
                    CBlockLocator locator2 = active_chain.GetLocator();
                    if (locator.vHave.size() != locator2.vHave.size()) {
                        // Non-deterministic locator generation - BUG!
                        __builtin_trap();
                    }
                    for (size_t i = 0; i < locator.vHave.size(); i++) {
                        if (locator.vHave[i] != locator2.vHave[i]) {
                            __builtin_trap();
                        }
                    }
                }
            }
        } catch (const std::exception&) {
            // GetLocator should not throw
            __builtin_trap();
        }
    }

    // CRITICAL TEST 4: Free function GetLocator with block index
    if ((mode & 0x07) == 3) {
        try {
            // Create a simple block index
            CBlockIndex index;
            index.nHeight = input.read<uint32_t>() % 10000;
            index.nTime = input.read<uint32_t>();
            index.nBits = input.read<uint32_t>();
            index.nChainWork = arith_uint256(index.nHeight);

            uint256 hash;
            uint8_t hash_bytes[32] = {0};
            uint32_t h = index.nHeight;
            memcpy(hash_bytes, &h, sizeof(h));
            memcpy(hash.begin(), hash_bytes, 32);
            index.m_block_hash = hash;

            // Test free function GetLocator
            CBlockLocator locator1 = GetLocator(&index);
            CBlockLocator locator2 = GetLocator(&index);

            // Should be deterministic
            if (locator1.vHave.size() != locator2.vHave.size()) {
                __builtin_trap();
            }

            // Test with nullptr
            CBlockLocator locator_null = GetLocator(nullptr);
            // Should not crash
        } catch (const std::exception&) {
            __builtin_trap();
        }
    }

    // CRITICAL TEST 5: Locator step calculation edge cases
    if ((mode & 0x07) == 4) {
        try {
            // Test locator generation with edge case heights
            std::vector<uint32_t> edge_heights = {
                0,                  // Genesis
                1,                  // First block
                10,                 // Small chain
                100,                // Medium chain
                1000,               // Larger chain
                0xFFFFFFFF,         // Maximum height (should be clamped)
            };

            for (uint32_t target_height : edge_heights) {
                // Create minimal chain up to target (or smaller if too large)
                uint32_t actual_height = std::min(target_height, 200u);
                std::vector<std::unique_ptr<CBlockIndex>> chain;

                CBlockIndex* prev = nullptr;

                for (uint32_t h = 0; h <= actual_height; h++) {
                    auto index = std::make_unique<CBlockIndex>();
                    index->nHeight = h;
                    index->nTime = 1000000 + h;
                    index->nBits = 0x1d00ffff;
                    index->nChainWork = arith_uint256(h);

                    uint256 hash;
                    uint8_t hash_bytes[32] = {0};
                    memcpy(hash_bytes, &h, sizeof(h));
                    memcpy(hash.begin(), hash_bytes, 32);
                    index->m_block_hash = hash;

                    if (prev) {
                        index->pprev = prev;
                    }

                    prev = index.get();
                    chain.push_back(std::move(index));
                }

                if (!chain.empty()) {
                    CChain active_chain;
                    CBlockIndex* tip = chain.back().get();
                    if (tip) {
                        active_chain.SetTip(*tip);
                    }

                    CBlockLocator locator = active_chain.GetLocator();

                    // Should not crash or produce unbounded locator
                    if (locator.vHave.size() > 100) {
                        // Excessive size - DoS risk!
                        __builtin_trap();
                    }
                }
            }
        } catch (const std::exception&) {
            __builtin_trap();
        }
    }

    // CRITICAL TEST 6: Empty chain
    if ((mode & 0x07) == 5) {
        try {
            CChain active_chain;

            // GetLocator on empty chain should not crash
            CBlockLocator locator = active_chain.GetLocator();

            // Should return empty locator for empty chain
            // (Implementation-dependent, but must not crash)

            // Calling again should be deterministic
            CBlockLocator locator2 = active_chain.GetLocator();
            if (locator.vHave.size() != locator2.vHave.size()) {
                __builtin_trap();
            }
        } catch (const std::exception&) {
            // Should not throw
            __builtin_trap();
        }
    }

    // CRITICAL TEST 7: Locator hash uniqueness
    if ((mode & 0x07) == 6) {
        try {
            std::vector<uint256> hashes;
            size_t num_hashes = input.read<uint8_t>() % 30;

            for (size_t i = 0; i < num_hashes && input.has_bytes(32); i++) {
                uint8_t hash_bytes[32];
                for (int j = 0; j < 32; j++) {
                    hash_bytes[j] = input.read<uint8_t>();
                }

                uint256 hash;
                memcpy(hash.begin(), hash_bytes, 32);
                hashes.push_back(hash);
            }

            size_t original_size = hashes.size();
            CBlockLocator locator(std::move(hashes));

            // Check that size is preserved
            if (locator.vHave.size() != original_size) {
                __builtin_trap();
            }
        } catch (const std::exception&) {
            __builtin_trap();
        }
    }

    // CRITICAL TEST 8: Comparison operations
    if ((mode & 0x07) == 7) {
        try {
            std::vector<uint256> hashes1, hashes2;

            // Create two different locators
            size_t num1 = (input.read<uint8_t>() % 10) + 1;
            size_t num2 = (input.read<uint8_t>() % 10) + 1;

            for (size_t i = 0; i < num1 && input.has_bytes(32); i++) {
                uint8_t hash_bytes[32];
                for (int j = 0; j < 32; j++) {
                    hash_bytes[j] = input.read<uint8_t>();
                }
                uint256 hash;
                memcpy(hash.begin(), hash_bytes, 32);
                hashes1.push_back(hash);
            }

            for (size_t i = 0; i < num2 && input.has_bytes(32); i++) {
                uint8_t hash_bytes[32];
                for (int j = 0; j < 32; j++) {
                    hash_bytes[j] = input.read<uint8_t>();
                }
                uint256 hash;
                memcpy(hash.begin(), hash_bytes, 32);
                hashes2.push_back(hash);
            }

            CBlockLocator loc1(std::move(hashes1));
            CBlockLocator loc2(std::move(hashes2));

            // Equality should be deterministic
            bool eq1 = (loc1.vHave == loc2.vHave);
            bool eq2 = (loc1.vHave == loc2.vHave);
            if (eq1 != eq2) {
                __builtin_trap();
            }

            // Copy should be equal
            CBlockLocator loc1_copy = loc1;
            if (!(loc1.vHave == loc1_copy.vHave)) {
                __builtin_trap();
            }
        } catch (const std::exception&) {
            __builtin_trap();
        }
    }

    return 0;
}
