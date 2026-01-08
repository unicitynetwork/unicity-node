// Fuzz target for VarInt decoding
// Tests variable-length integer parsing which is notorious for bugs

#include "network/message.hpp"
#include <cstdint>
#include <cstddef>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    using namespace unicity::message;

    // Test VarInt decoding
    VarInt vi;
    size_t consumed = vi.decode(data, size);

    // CRITICAL: Validate decode return value is sane
    if (consumed > size) {
        // Decode claims to have consumed more bytes than available - BUFFER OVERRUN!
        __builtin_trap();
    }

    // If decode succeeded, test round-trip and canonical encoding
    if (consumed > 0) {
        // Encode the value back (produces canonical encoding)
        uint8_t buffer[9];  // Max varint size
        size_t encoded_size = vi.encode(buffer);

        // CRITICAL: Validate encoded_size is in valid range
        if (encoded_size == 0 || encoded_size > 9) {
            // encode() returned invalid size - BUG!
            __builtin_trap();
        }

        // Verify encoded_size matches expected size based on value
        size_t expected_size;
        if (vi.value < 0xfd) expected_size = 1;
        else if (vi.value <= 0xffff) expected_size = 3;
        else if (vi.value <= 0xffffffff) expected_size = 5;
        else expected_size = 9;

        if (encoded_size != expected_size) {
            // encode() produced wrong size for value - BUG!
            __builtin_trap();
        }

        // CRITICAL: Verify input was canonical by checking sizes match
        // Non-canonical inputs will decode successfully but re-encode to different size
        // Example: 0xfd 0x05 0x00 (3 bytes) decodes to value=5, re-encodes to 0x05 (1 byte)
        if (consumed != encoded_size) {
            // Non-canonical encoding detected - this should have been rejected!
            __builtin_trap();
        }

        // Decode again and verify we get the same value
        VarInt vi2;
        size_t consumed2 = vi2.decode(buffer, encoded_size);

        // CRITICAL: Re-decode must succeed on canonical encoding
        if (consumed2 == 0) {
            // decode() failed on canonical encoding produced by encode() - BUG!
            __builtin_trap();
        }

        if (consumed2 > encoded_size) {
            // Re-decode overrun - BUG!
            __builtin_trap();
        }

        // Should consume exactly the encoded size and produce same value
        if (consumed2 != encoded_size) {
            // Re-decode consumed wrong number of bytes - BUG!
            __builtin_trap();
        }

        if (vi.value != vi2.value) {
            // Round-trip changed value - BUG!
            __builtin_trap();
        }
    }
    // If consumed == 0, decode rejected input - that's fine, nothing to test

    return 0;
}
