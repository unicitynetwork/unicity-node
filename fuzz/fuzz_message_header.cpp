// Fuzz target for message header parsing
// Tests parsing of the message header which includes magic bytes, command, length, and checksum

#include "network/message.hpp"
#include "network/protocol.hpp"
#include <cstdint>
#include <cstddef>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    using namespace unicity::message;
    using namespace unicity::protocol;

    // Test message header deserialization
    MessageHeader header;
    bool success = deserialize_header(data, size, header);

    if (success) {
        // CRITICAL: Validate header length is within protocol limits
        if (header.length > MAX_PROTOCOL_MESSAGE_LENGTH) {
            // deserialize_header() accepted oversized length - BUG!
            __builtin_trap();
        }

        // CRITICAL: Validate command string length is within limits
        // Command is 12 bytes max, should not contain excessive nulls
        size_t cmd_len = strnlen(header.command.data(), header.command.size());
        if (cmd_len > 12) {
            // Command string exceeds protocol limit - BUG!
            __builtin_trap();
        }

        // If deserialization succeeded, test serialization round-trip
        auto serialized = serialize_header(header);

        // CRITICAL: Validate serialized size is exactly MESSAGE_HEADER_SIZE
        if (serialized.size() != MESSAGE_HEADER_SIZE) {
            // serialize_header() produced wrong size - BUG!
            __builtin_trap();
        }

        MessageHeader header2;
        bool success2 = deserialize_header(serialized.data(), serialized.size(), header2);

        // CRITICAL: Re-deserialize must succeed on our own serialization
        if (!success2) {
            // deserialize_header() failed on serialize_header() output - BUG!
            __builtin_trap();
        }

        // CRITICAL: Verify fields match exactly after round-trip
        if (header.magic != header2.magic) {
            // Magic changed during round-trip - BUG!
            __builtin_trap();
        }

        if (header.command != header2.command) {
            // Command changed during round-trip - BUG!
            __builtin_trap();
        }

        if (header.length != header2.length) {
            // Length changed during round-trip - BUG!
            __builtin_trap();
        }

        if (header.checksum != header2.checksum) {
            // Checksum changed during round-trip - BUG!
            __builtin_trap();
        }
    }
    // If success == false, deserialize rejected input - that's fine, nothing to test

    return 0;
}
