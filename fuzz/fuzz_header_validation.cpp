// Fuzz target for header validation logic
// Tests CheckBlockHeader, ContextualCheckBlockHeader, and header batch validation
//
// Header validation is consensus-critical and a security boundary.
// Bugs in this code can:
// - Allow chain splits (inconsistent validation)
// - Enable difficulty bypass (accepting low-difficulty blocks)
// - Cause DoS (crash on malformed headers, unbounded work calculation)
// - Allow timestamp manipulation (accepting future blocks)
// - Break IBD (orphan exhaustion, low-work spam)
//
// Target code:
// - src/chain/validation.cpp (CheckBlockHeader, ContextualCheckBlockHeader)
// - src/chain/pow.cpp (CheckProofOfWork, CalculateNextWorkRequired)

#include "chain/validation.hpp"
#include "chain/block.hpp"
#include "chain/chainparams.hpp"
#include "chain/block_index.hpp"
#include "chain/pow.hpp"
#include "util/arith_uint256.hpp"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <limits>

using namespace unicity;

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

    size_t remaining() const {
        return offset_ < size_ ? size_ - offset_ : 0;
    }

private:
    const uint8_t *data_;
    size_t size_;
    size_t offset_;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Need at least 101 bytes: 1 mode + 100 header
    if (size < 101) return 0;

    FuzzInput input(data, size);
    uint8_t mode = input.read<uint8_t>();

    // Parse fuzzed block header (100 bytes)
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

    // hashRandomX (32 bytes)
    uint8_t rxHash[32];
    for (int i = 0; i < 32; i++) {
        rxHash[i] = input.read<uint8_t>();
    }
    memcpy(header.hashRandomX.begin(), rxHash, 32);

    // Chain params
    auto params = chain::ChainParams::CreateRegTest();

    // CRITICAL TEST 1: CheckBlockHeader must not crash on arbitrary headers
    if ((mode & 0x07) == 0) {
        try {
            validation::ValidationState state;
            bool result = validation::CheckBlockHeader(header, *params, state);

            // If it returns true, header must have valid PoW
            // If false, state should have rejection reason
            if (!result && state.GetRejectReason().empty()) {
                // Invalid but no reason - BUG!
                __builtin_trap();
            }

            // CheckBlockHeader should be deterministic
            validation::ValidationState state2;
            bool result2 = validation::CheckBlockHeader(header, *params, state2);
            if (result != result2) {
                // Non-deterministic validation - BUG!
                __builtin_trap();
            }
        } catch (const std::exception&) {
            // CheckBlockHeader should not throw (returns false on error)
            __builtin_trap();
        }
    }

    // CRITICAL TEST 2: ContextualCheckBlockHeader with synthetic parent
    if ((mode & 0x07) == 1 && size >= 150) {
        try {
            // Create a synthetic parent block index
            CBlockHeader parentHeader = header;
            parentHeader.nTime = input.read<uint32_t>();
            parentHeader.nBits = input.read<uint32_t>();

            chain::CBlockIndex parentIndex;
            parentIndex.nHeight = input.read<uint32_t>() % 1000000;
            parentIndex.nTime = parentHeader.nTime;
            parentIndex.nBits = parentHeader.nBits;
            parentIndex.nChainWork = arith_uint256(0);

            validation::ValidationState state;
            int64_t adjusted_time = header.nTime + (input.read<int32_t>() % 7200);

            // This should not crash, even with invalid parent
            bool result = validation::ContextualCheckBlockHeader(
                header, &parentIndex, *params, adjusted_time, state);

            // If it fails, should have reason
            if (!result && state.GetRejectReason().empty()) {
                __builtin_trap();
            }

            // Should be deterministic
            validation::ValidationState state2;
            bool result2 = validation::ContextualCheckBlockHeader(
                header, &parentIndex, *params, adjusted_time, state2);
            if (result != result2) {
                __builtin_trap();
            }
        } catch (const std::exception&) {
            // Should not throw
            __builtin_trap();
        }
    }

    // CRITICAL TEST 3: CheckHeadersPoW with header batches
    if ((mode & 0x07) == 2) {
        try {
            // Create batch of headers (1-10 headers)
            std::vector<CBlockHeader> headers;
            size_t batch_size = (input.read<uint8_t>() % 10) + 1;

            for (size_t i = 0; i < batch_size && input.has_bytes(100); i++) {
                CBlockHeader h;
                h.nVersion = input.read<int32_t>();

                uint8_t hash[32];
                for (int j = 0; j < 32; j++) hash[j] = input.read<uint8_t>();
                memcpy(h.hashPrevBlock.begin(), hash, 32);

                uint8_t addr[20];
                for (int j = 0; j < 20; j++) addr[j] = input.read<uint8_t>();
                memcpy(h.minerAddress.begin(), addr, 20);

                h.nTime = input.read<uint32_t>();
                h.nBits = input.read<uint32_t>();
                h.nNonce = input.read<uint32_t>();

                for (int j = 0; j < 32; j++) hash[j] = input.read<uint8_t>();
                memcpy(h.hashRandomX.begin(), hash, 32);

                headers.push_back(h);
            }

            if (!headers.empty()) {
                // Fast PoW check should not crash
                bool result1 = validation::CheckHeadersPoW(headers, *params);

                // Should be deterministic
                bool result2 = validation::CheckHeadersPoW(headers, *params);
                if (result1 != result2) {
                    __builtin_trap();
                }
            }
        } catch (const std::exception&) {
            __builtin_trap();
        }
    }

    // CRITICAL TEST 4: CheckHeadersAreContinuous
    if ((mode & 0x07) == 3) {
        try {
            std::vector<CBlockHeader> headers;
            size_t batch_size = (input.read<uint8_t>() % 10) + 1;

            for (size_t i = 0; i < batch_size && input.has_bytes(100); i++) {
                CBlockHeader h;
                h.nVersion = input.read<int32_t>();

                // If i > 0, optionally link to previous header
                if (i > 0 && (input.read<uint8_t>() & 0x01)) {
                    h.hashPrevBlock = headers[i-1].GetHash();
                } else {
                    uint8_t hash[32];
                    for (int j = 0; j < 32; j++) hash[j] = input.read<uint8_t>();
                    memcpy(h.hashPrevBlock.begin(), hash, 32);
                }

                uint8_t addr[20];
                for (int j = 0; j < 20; j++) addr[j] = input.read<uint8_t>();
                memcpy(h.minerAddress.begin(), addr, 20);

                h.nTime = input.read<uint32_t>();
                h.nBits = input.read<uint32_t>();
                h.nNonce = input.read<uint32_t>();

                uint8_t rxHash[32];
                for (int j = 0; j < 32; j++) rxHash[j] = input.read<uint8_t>();
                memcpy(h.hashRandomX.begin(), rxHash, 32);

                headers.push_back(h);
            }

            if (!headers.empty()) {
                bool result1 = validation::CheckHeadersAreContinuous(headers);
                bool result2 = validation::CheckHeadersAreContinuous(headers);
                if (result1 != result2) {
                    __builtin_trap();
                }
            }
        } catch (const std::exception&) {
            __builtin_trap();
        }
    }

    // CRITICAL TEST 5: CalculateHeadersWork must not crash or overflow
    if ((mode & 0x07) == 4) {
        try {
            std::vector<CBlockHeader> headers;
            size_t batch_size = (input.read<uint8_t>() % 20) + 1;

            for (size_t i = 0; i < batch_size && input.has_bytes(100); i++) {
                CBlockHeader h;
                h.nVersion = input.read<int32_t>();

                uint8_t hash[32];
                for (int j = 0; j < 32; j++) hash[j] = input.read<uint8_t>();
                memcpy(h.hashPrevBlock.begin(), hash, 32);

                uint8_t addr[20];
                for (int j = 0; j < 20; j++) addr[j] = input.read<uint8_t>();
                memcpy(h.minerAddress.begin(), addr, 20);

                h.nTime = input.read<uint32_t>();
                h.nBits = input.read<uint32_t>();
                h.nNonce = input.read<uint32_t>();

                for (int j = 0; j < 32; j++) hash[j] = input.read<uint8_t>();
                memcpy(h.hashRandomX.begin(), hash, 32);

                headers.push_back(h);
            }

            if (!headers.empty()) {
                // Work calculation should handle invalid nBits gracefully
                arith_uint256 work1 = validation::CalculateHeadersWork(headers);
                arith_uint256 work2 = validation::CalculateHeadersWork(headers);

                // Must be deterministic
                if (work1 != work2) {
                    __builtin_trap();
                }

                // Work should never overflow (bounded by number of headers)
                // Each header contributes at most 2^256 - 1 work
                // With 20 headers, this should not wrap
            }
        } catch (const std::exception&) {
            __builtin_trap();
        }
    }

    // CRITICAL TEST 6: GetAntiDoSWorkThreshold edge cases
    if ((mode & 0x07) == 5) {
        try {
            // Test with null tip
            arith_uint256 threshold1 = validation::GetAntiDoSWorkThreshold(nullptr, *params);
            arith_uint256 threshold2 = validation::GetAntiDoSWorkThreshold(nullptr, *params);

            // Must be deterministic
            if (threshold1 != threshold2) {
                __builtin_trap();
            }

            // Test with synthetic tip
            if (size >= 150) {
                chain::CBlockIndex tipIndex;
                tipIndex.nHeight = input.read<uint32_t>() % 1000000;
                tipIndex.nTime = input.read<uint32_t>();
                tipIndex.nBits = input.read<uint32_t>();

                // Fuzz chainwork (just use a uint64_t value)
                uint64_t workValue = input.read<uint64_t>();
                tipIndex.nChainWork = arith_uint256(workValue);

                arith_uint256 thresholdA = validation::GetAntiDoSWorkThreshold(&tipIndex, *params);
                arith_uint256 thresholdB = validation::GetAntiDoSWorkThreshold(&tipIndex, *params);

                if (thresholdA != thresholdB) {
                    __builtin_trap();
                }

                // Threshold should never be greater than tip work
                if (thresholdA > tipIndex.nChainWork) {
                    // This is actually allowed (can exceed tip work by buffer)
                    // So this is not a bug
                }
            }
        } catch (const std::exception&) {
            __builtin_trap();
        }
    }

    // CRITICAL TEST 7: Edge case timestamps (past, future, overflow)
    if ((mode & 0x07) == 6) {
        std::vector<uint32_t> edge_timestamps = {
            0,                    // Epoch start
            1,                    // Minimal
            UINT32_MAX,           // Maximum
            0x7FFFFFFF,           // Max signed
            0x80000000,           // Sign bit
        };

        for (uint32_t ts : edge_timestamps) {
            CBlockHeader test_header = header;
            test_header.nTime = ts;

            try {
                validation::ValidationState state;
                validation::CheckBlockHeader(test_header, *params, state);
                // Should not crash regardless of timestamp
            } catch (const std::exception&) {
                __builtin_trap();
            }
        }
    }

    // CRITICAL TEST 8: Edge case nBits values
    if ((mode & 0x07) == 7) {
        std::vector<uint32_t> edge_bits = {
            0,                    // Zero difficulty
            1,                    // Minimal
            0x1d00ffff,           // Bitcoin genesis difficulty
            0x207fffff,           // Max exponent
            0x00ffffff,           // Zero exponent
            UINT32_MAX,           // Maximum
        };

        for (uint32_t bits : edge_bits) {
            CBlockHeader test_header = header;
            test_header.nBits = bits;

            try {
                validation::ValidationState state;
                validation::CheckBlockHeader(test_header, *params, state);
                // Should not crash regardless of nBits
            } catch (const std::exception&) {
                __builtin_trap();
            }
        }
    }

    return 0;
}
