// Fuzz target for ASERT difficulty calculation
// Tests the CalculateASERT algorithm for overflow, clamping, and determinism
//
// ASERT (Absolutely Scheduled Exponentially Rising Targets) is a consensus-critical
// difficulty adjustment algorithm that uses 512-bit arithmetic to prevent overflow.
// Bugs in this code can:
// - Allow chain splits (non-deterministic results)
// - Enable difficulty manipulation attacks (incorrect clamping)
// - Crash nodes (__int128 overflow, division by zero)
//
// Target code: src/chain/pow.cpp:40-129 (CalculateASERT function)

#include "chain/pow.hpp"
#include "chain/chainparams.hpp"
#include "util/arith_uint256.hpp"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <limits>

// FuzzInput: Parse structured fuzz data into test parameters
// Uses offset-based parsing to avoid O(n²) erase-from-front pattern
class FuzzInput {
public:
    FuzzInput(const uint8_t *data, size_t size) : data_(data), size_(size), offset_(0) {}

    // Read a T from fuzz input (returns default if not enough data)
    template<typename T>
    T read() {
        if (offset_ + sizeof(T) > size_) {
            // Not enough data - return zero-initialized value
            return T{};
        }
        T value;
        memcpy(&value, data_ + offset_, sizeof(T));
        offset_ += sizeof(T);
        return value;
    }

    // Check if we have at least N bytes remaining
    bool has_bytes(size_t n) const {
        return offset_ + n <= size_;
    }

    // Get remaining bytes as vector (for variable-length data)
    std::vector<uint8_t> remaining() const {
        if (offset_ >= size_) return {};
        return std::vector<uint8_t>(data_ + offset_, data_ + size_);
    }

private:
    const uint8_t *data_;
    size_t size_;
    size_t offset_;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Need at least 48 bytes for basic test:
    // refTarget (32 bytes) + nHeightDiff (8) + nTimeDiff (8)
    if (size < 48) return 0;

    FuzzInput input(data, size);

    // Parse fuzzed inputs for CalculateASERT
    // refTarget: Reference difficulty target (256-bit)
    arith_uint256 refTarget;
    uint8_t target_bytes[32];
    for (int i = 0; i < 32; i++) {
        target_bytes[i] = input.read<uint8_t>();
    }
    memcpy(&refTarget, target_bytes, 32);

    // nHeightDiff: Height difference from anchor (can be negative!)
    int64_t nHeightDiff = input.read<int64_t>();

    // nTimeDiff: Time difference from anchor (can be negative!)
    int64_t nTimeDiff = input.read<int64_t>();

    // Read optional parameters if available (else use defaults)
    int64_t nPowTargetSpacing = 120;  // 2 minutes (Unicity default)
    int64_t nHalfLife = 86400;        // 24 hours (Unicity default)

    if (input.has_bytes(16)) {
        nPowTargetSpacing = input.read<int64_t>();
        nHalfLife = input.read<int64_t>();
    }

    // powLimit: Maximum allowed target (easiest difficulty)
    // Use Unicity mainnet default: 0x00000000ffff0000000000000000000000000000000000000000000000000000
    arith_uint256 powLimit;
    powLimit.SetCompact(0x1d00ffff);

    // Allow fuzzer to override powLimit if more data available
    if (input.has_bytes(32)) {
        uint8_t limit_bytes[32];
        for (int i = 0; i < 32; i++) {
            limit_bytes[i] = input.read<uint8_t>();
        }
        memcpy(&powLimit, limit_bytes, 32);
    }

    // CRITICAL TEST 1: CalculateASERT must not crash on any input
    // This includes:
    // - Division by zero (nHalfLife = 0)
    // - __int128 overflow (extreme nTimeDiff/nHeightDiff)
    // - Bit shift overflow (exponent > 255)
    // - Invalid refTarget (> powLimit, = 0)
    //
    // The function should handle all these gracefully without crashing
    arith_uint256 result;
    try {
        result = unicity::consensus::CalculateASERT(
            refTarget, nPowTargetSpacing, nTimeDiff, nHeightDiff, powLimit, nHalfLife
        );
    } catch (...) {
        // CalculateASERT should NEVER throw exceptions
        // Consensus code must be deterministic and crash-free
        __builtin_trap();
    }

    // CRITICAL TEST 2: Result must always be within valid range
    // ASERT guarantees: 1 <= result <= powLimit
    // NOTE: Only enforce this when consensus parameters are valid
    // (powLimit > 0, nHalfLife > 0). Invalid params are unrealistic
    // since they come from hardcoded ChainParams, not user input.
    bool params_valid = (powLimit > arith_uint256(0) && nHalfLife > 0);

    if (params_valid) {
        if (result < arith_uint256(1)) {
            // Result is zero - difficulty calculation broken!
            // This would allow trivial PoW (hash = 0x0000...0001 always wins)
            __builtin_trap();
        }

        if (result > powLimit) {
            // Result exceeds maximum allowed target - clamping failed!
            // This would make blocks impossible to mine
            __builtin_trap();
        }
    }

    // CRITICAL TEST 3: Determinism - same inputs must produce same output
    // Run CalculateASERT twice with identical inputs
    arith_uint256 result2;
    try {
        result2 = unicity::consensus::CalculateASERT(
            refTarget, nPowTargetSpacing, nTimeDiff, nHeightDiff, powLimit, nHalfLife
        );
    } catch (...) {
        __builtin_trap();
    }

    if (result != result2) {
        // Non-deterministic behavior detected!
        // This would cause chain splits - different nodes compute different difficulties
        __builtin_trap();
    }

    // CRITICAL TEST 4: Monotonicity sanity checks
    // ASERT should increase difficulty (decrease target) when blocks are too fast
    // and decrease difficulty (increase target) when blocks are too slow
    //
    // Test: If nTimeDiff < expected time, difficulty should increase (target decrease)
    // Only test when inputs are in reasonable range to avoid clamping edge cases
    if (nHeightDiff > 0 && nHeightDiff < 1000 &&
        nPowTargetSpacing > 0 && nPowTargetSpacing < 86400 &&
        nHalfLife > 0 && nHalfLife < 86400 * 365 &&
        refTarget > arith_uint256(1) && refTarget <= powLimit) {

        // Expected time for nHeightDiff blocks
        int64_t expectedTime = nHeightDiff * nPowTargetSpacing;

        // If blocks came faster than expected (nTimeDiff < expectedTime)
        // then difficulty should increase (target should decrease)
        if (nTimeDiff > 0 && nTimeDiff < expectedTime && nTimeDiff < expectedTime / 2) {
            // Significant speedup - target should decrease (unless already at minimum)
            if (result > refTarget && refTarget > arith_uint256(1)) {
                // Target INCREASED when it should have DECREASED - broken monotonicity!
                // (Allow equality for edge cases near minimum difficulty)
                __builtin_trap();
            }
        }

        // If blocks came slower than expected (nTimeDiff > expectedTime)
        // then difficulty should decrease (target should increase)
        if (nTimeDiff > expectedTime * 2) {
            // Significant slowdown - target should increase (unless already at powLimit)
            if (result < refTarget && result < powLimit) {
                // Target DECREASED when it should have INCREASED - broken monotonicity!
                // (Allow equality for edge cases near maximum difficulty)
                __builtin_trap();
            }
        }
    }

    // CRITICAL TEST 5: Special case - zero height diff should preserve target
    // When nHeightDiff = 0 and nTimeDiff = 0, result should equal refTarget
    // (modulo clamping to [1, powLimit])
    // NOTE: Only test this when parameters are valid
    if (params_valid && nHeightDiff == 0 && nTimeDiff == 0) {
        arith_uint256 expected = refTarget;

        // Apply same clamping as CalculateASERT
        if (expected < arith_uint256(1)) expected = arith_uint256(1);
        if (expected > powLimit) expected = powLimit;

        if (result != expected) {
            // Zero adjustment should preserve target - broken!
            __builtin_trap();
        }
    }

    // CRITICAL TEST 6: Validate against known extreme cases
    // These are edge cases that have caused bugs in other difficulty algorithms

    // Case 1: refTarget = 0 (invalid input)
    // CalculateASERT should clamp to minimum (1) or use powLimit as fallback
    // Only test when params are valid
    if (params_valid) {
        arith_uint256 zero_target_result;
        try {
            zero_target_result = unicity::consensus::CalculateASERT(
                arith_uint256(0), nPowTargetSpacing, nTimeDiff, nHeightDiff, powLimit, nHalfLife
            );
        } catch (...) {
            __builtin_trap();
        }

        if (zero_target_result < arith_uint256(1) || zero_target_result > powLimit) {
            // Invalid result from zero refTarget - must be in valid range
            __builtin_trap();
        }
    }

    // Case 2: Negative nHeightDiff (before anchor)
    // Should not crash, result must be in valid range
    // Only test when params are valid
    if (params_valid && nHeightDiff > 1) {
        arith_uint256 neg_height_result;
        try {
            neg_height_result = unicity::consensus::CalculateASERT(
                refTarget, nPowTargetSpacing, nTimeDiff, -nHeightDiff, powLimit, nHalfLife
            );
        } catch (...) {
            __builtin_trap();
        }

        if (neg_height_result < arith_uint256(1) || neg_height_result > powLimit) {
            __builtin_trap();
        }
    }

    // Case 3: INT64_MAX height/time diff (extreme overflow test)
    // Only test when params are valid
    if (params_valid) {
        arith_uint256 extreme_result;
        try {
            extreme_result = unicity::consensus::CalculateASERT(
                refTarget, nPowTargetSpacing,
                std::numeric_limits<int64_t>::max(),
                std::numeric_limits<int64_t>::max(),
                powLimit, nHalfLife
            );
        } catch (...) {
            __builtin_trap();
        }

        if (extreme_result < arith_uint256(1) || extreme_result > powLimit) {
            __builtin_trap();
        }
    }

    // Case 4: INT64_MIN (negative overflow)
    // Only test when params are valid
    if (params_valid) {
        arith_uint256 extreme_result;
        try {
            extreme_result = unicity::consensus::CalculateASERT(
                refTarget, nPowTargetSpacing,
                std::numeric_limits<int64_t>::min(),
                std::numeric_limits<int64_t>::min(),
                powLimit, nHalfLife
            );
        } catch (...) {
            __builtin_trap();
        }

        if (extreme_result < arith_uint256(1) || extreme_result > powLimit) {
            __builtin_trap();
        }
    }

    return 0;  // Success - all invariants hold
}
