// Fuzz target for CBlockHeader deserialization
// Tests block header parsing from untrusted network data

#include "chain/block.hpp"
#include <cstdint>
#include <cstddef>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Test block header deserialization
    CBlockHeader header;

    // Deserialize should handle any input gracefully without crashing
    bool success = header.Deserialize(data, size);

    // If deserialization succeeded, verify we can serialize it back
    if (success && !header.IsNull()) {
        auto serialized = header.Serialize();

        // CRITICAL: Validate serialized size is exactly BLOCK_HEADER_SIZE (100 bytes)
        // Unicity headers: 4 + 32 + 20 + 4 + 4 + 4 + 32 = 100 bytes
        // (version + prevHash + minerAddress + time + bits + nonce + hashRandomX)
        if (serialized.size() != CBlockHeader::HEADER_SIZE) {
            // Serialize() produced wrong size - BUG!
            __builtin_trap();
        }

        // Verify round-trip is consistent
        CBlockHeader header2;
        bool success2 = header2.Deserialize(serialized.data(), serialized.size());

        // CRITICAL: Re-deserialize must succeed on our own serialization
        if (!success2) {
            // Deserialize() failed on Serialize() output - BUG!
            __builtin_trap();
        }

        // CRITICAL: Verify all fields match after round-trip
        if (header.nVersion != header2.nVersion) {
            // Version changed during round-trip - BUG!
            __builtin_trap();
        }

        if (header.hashPrevBlock != header2.hashPrevBlock) {
            // Previous block hash changed during round-trip - BUG!
            __builtin_trap();
        }

        if (header.minerAddress != header2.minerAddress) {
            // Miner address changed during round-trip - BUG!
            __builtin_trap();
        }

        if (header.nTime != header2.nTime) {
            // Timestamp changed during round-trip - BUG!
            __builtin_trap();
        }

        if (header.nBits != header2.nBits) {
            // Difficulty bits changed during round-trip - BUG!
            __builtin_trap();
        }

        if (header.nNonce != header2.nNonce) {
            // Nonce changed during round-trip - BUG!
            __builtin_trap();
        }

        // CRITICAL: Verify hash computation is consistent
        uint256 hash1 = header.GetHash();
        uint256 hash2 = header2.GetHash();

        if (hash1 != hash2) {
            // Hash computation not deterministic - BUG!
            __builtin_trap();
        }

        // CRITICAL: Re-serialize header2 and verify byte-for-byte identical
        auto serialized2 = header2.Serialize();
        if (serialized2.size() != serialized.size()) {
            // Second serialization changed size - BUG!
            __builtin_trap();
        }

        if (serialized != serialized2) {
            // Serialization not deterministic - BUG!
            __builtin_trap();
        }
    }
    // If success == false or IsNull(), deserialize rejected input - that's fine

    return 0;
}
