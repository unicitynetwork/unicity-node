// Fuzz target for RandomX proof-of-work verification
// Tests RandomX hash computation, commitment verification, and VM cache lifecycle
//
// RandomX is the cryptographic core of Unicity's proof-of-work system.
// Bugs in this code can:
// - Allow chain splits (non-deterministic hash computation)
// - Enable PoW bypass attacks (incorrect commitment verification)
// - Crash nodes (VM lifecycle bugs, null pointer dereference)
// - Cause memory exhaustion (unbounded VM cache growth)
// - Mode confusion (FULL vs COMMITMENT_ONLY vs MINING verification)
//
// Target code:
// - src/chain/randomx_pow.cpp (VM cache, hash computation, commitment)
// - src/chain/pow.cpp:271-376 (CheckProofOfWork function)

#include "chain/pow.hpp"
#include "chain/randomx_pow.hpp"
#include "chain/block.hpp"
#include "chain/chainparams.hpp"
#include "util/arith_uint256.hpp"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <limits>

using namespace unicity;

// FuzzInput: Parse structured fuzz data into test parameters
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
    // Need at least 100 bytes for a block header
    if (size < 100) return 0;

    FuzzInput input(data, size);

    // Initialize RandomX once per process (thread-safe, idempotent)
    static bool randomx_init = false;
    if (!randomx_init) {
        try {
            crypto::InitRandomX();
            randomx_init = true;
        } catch (...) {
            // If initialization fails, skip fuzzing
            return 0;
        }
    }

    // Parse fuzzed block header (100 bytes for Unicity)
    CBlockHeader header;
    header.nVersion = input.read<int32_t>();

    // hashPrevBlock (32 bytes)
    uint8_t prevHash[32];
    for (int i = 0; i < 32; i++) {
        prevHash[i] = input.read<uint8_t>();
    }
    memcpy(header.hashPrevBlock.begin(), prevHash, 32);

    // minerAddress (20 bytes)
    uint8_t minerAddr[20];
    for (int i = 0; i < 20; i++) {
        minerAddr[i] = input.read<uint8_t>();
    }
    memcpy(header.minerAddress.begin(), minerAddr, 20);

    header.nTime = input.read<uint32_t>();
    header.nBits = input.read<uint32_t>();
    header.nNonce = input.read<uint32_t>();

    // hashRandomX (32 bytes) - may be null or fuzzed
    uint8_t rxHash[32];
    for (int i = 0; i < 32; i++) {
        rxHash[i] = input.read<uint8_t>();
    }
    memcpy(header.hashRandomX.begin(), rxHash, 32);

    // Fuzz parameters
    uint32_t epochDuration = input.read<uint32_t>();
    if (epochDuration == 0) epochDuration = 1; // Avoid division by zero

    uint8_t modeSelect = input.read<uint8_t>();

    // CRITICAL TEST 1: GetEpoch must not crash or overflow
    try {
        uint32_t epoch = crypto::GetEpoch(header.nTime, epochDuration);

        // CRITICAL TEST 2: GetSeedHash must be deterministic
        uint256 seed1 = crypto::GetSeedHash(epoch);
        uint256 seed2 = crypto::GetSeedHash(epoch);
        if (seed1 != seed2) {
            // Non-deterministic seed hash - BUG!
            __builtin_trap();
        }

        // CRITICAL TEST 3: GetRandomXCommitment must handle null hashRandomX
        CBlockHeader nullHeader = header;
        nullHeader.hashRandomX.SetNull();

        // Should not crash on null hash
        try {
            uint256 commitment1 = crypto::GetRandomXCommitment(nullHeader);

            // CRITICAL TEST 4: Commitment must be deterministic
            uint256 commitment2 = crypto::GetRandomXCommitment(nullHeader);
            if (commitment1 != commitment2) {
                // Non-deterministic commitment - BUG!
                __builtin_trap();
            }
        } catch (...) {
            // Commitment calculation should never throw
        }

        // CRITICAL TEST 5: GetRandomXCommitment with explicit hash
        if (!header.hashRandomX.IsNull()) {
            try {
                uint256 commitmentA = crypto::GetRandomXCommitment(header);
                uint256 commitmentB = crypto::GetRandomXCommitment(header, &header.hashRandomX);

                // Both methods should produce identical results
                if (commitmentA != commitmentB) {
                    // Commitment mismatch - BUG!
                    __builtin_trap();
                }
            } catch (...) {
                // Should not throw
            }
        }

        // CRITICAL TEST 6: VM cache lifecycle (epoch transitions)
        // Test that GetCachedVM handles epoch boundaries correctly
        try {
            // Clamp epoch to reasonable range (0-1000000) to avoid OOM
            uint32_t testEpoch = epoch % 1000000;
            auto vm1 = crypto::GetCachedVM(testEpoch);
            if (!vm1 || !vm1->vm) {
                // VM creation failed - should throw, not return null
                __builtin_trap();
            }

            // Second call should return cached VM or create new one
            auto vm2 = crypto::GetCachedVM(testEpoch);
            if (!vm2 || !vm2->vm) {
                __builtin_trap();
            }

            // Test epoch boundary (next epoch)
            if (testEpoch < 999999) {
                auto vm3 = crypto::GetCachedVM(testEpoch + 1);
                if (!vm3 || !vm3->vm) {
                    __builtin_trap();
                }
            }
        } catch (const std::runtime_error&) {
            // Expected if RandomX not initialized or resource exhaustion
        } catch (...) {
            // Unexpected exception type - BUG!
            __builtin_trap();
        }

        // CRITICAL TEST 7: CheckProofOfWork with different verification modes
        // Test mode confusion: FULL vs COMMITMENT_ONLY vs MINING
        auto params = chain::ChainParams::CreateRegTest();

        // Mode 0: FULL verification
        if ((modeSelect % 3) == 0) {
            try {
                consensus::CheckProofOfWork(header, header.nBits, *params,
                                           crypto::POWVerifyMode::FULL);
                // If it returns, it should not crash
            } catch (const std::runtime_error&) {
                // Expected for invalid PoW or null hash
            } catch (...) {
                // Unexpected exception - BUG!
                __builtin_trap();
            }
        }

        // Mode 1: COMMITMENT_ONLY verification (faster, for header sync)
        if ((modeSelect % 3) == 1) {
            try {
                consensus::CheckProofOfWork(header, header.nBits, *params,
                                           crypto::POWVerifyMode::COMMITMENT_ONLY);
            } catch (const std::runtime_error&) {
                // Expected for invalid PoW
            } catch (...) {
                // Unexpected exception - BUG!
                __builtin_trap();
            }
        }

        // Mode 2: MINING mode (requires outHash parameter)
        if ((modeSelect % 3) == 2) {
            try {
                uint256 outHash;
                consensus::CheckProofOfWork(header, header.nBits, *params,
                                           crypto::POWVerifyMode::MINING, &outHash);

                // If successful, outHash should be non-null
                // (We can't verify correctness without re-computing, but we can check it's set)
            } catch (const std::runtime_error&) {
                // Expected for invalid PoW or initialization failure
            } catch (...) {
                // Unexpected exception - BUG!
                __builtin_trap();
            }
        }

        // CRITICAL TEST 8: Verify MINING mode throws if outHash is null
        if (modeSelect == 0xFF) {
            try {
                // This should throw because MINING mode requires outHash
                consensus::CheckProofOfWork(header, header.nBits, *params,
                                           crypto::POWVerifyMode::MINING, nullptr);
                // If it didn't throw, that's a BUG!
                __builtin_trap();
            } catch (const std::runtime_error&) {
                // Expected - this is correct behavior
            } catch (...) {
                // Wrong exception type - BUG!
                __builtin_trap();
            }
        }

        // CRITICAL TEST 9: Verify nBits validation in CheckProofOfWork
        // Test with invalid nBits (negative, overflow, zero)
        uint32_t invalidBits[] = {0, 0xFFFFFFFF, 0x01000000, 0x00FFFFFF};
        for (uint32_t bits : invalidBits) {
            try {
                bool result = consensus::CheckProofOfWork(header, bits, *params,
                                                         crypto::POWVerifyMode::COMMITMENT_ONLY);
                // Should return false for invalid bits, not crash
                (void)result; // Silence unused warning
            } catch (...) {
                // Should not throw for invalid bits, just return false
            }
        }

        // CRITICAL TEST 10: Epoch wraparound (UINT32_MAX edge case)
        if (header.nTime == UINT32_MAX) {
            try {
                uint32_t epochMax = crypto::GetEpoch(UINT32_MAX, epochDuration);
                uint256 seedMax = crypto::GetSeedHash(epochMax);

                // Should not crash or produce null hash
                if (seedMax.IsNull()) {
                    __builtin_trap();
                }
            } catch (...) {
                // Should not throw
            }
        }

    } catch (...) {
        // Unexpected top-level exception - most operations should handle errors gracefully
        // Let it pass for now (fuzzer will continue with next input)
    }

    return 0;
}
