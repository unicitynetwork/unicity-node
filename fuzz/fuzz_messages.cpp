// Fuzz target for network message deserialization
// Tests all message types for crash-free parsing of untrusted network data

#include "network/message.hpp"
#include "network/protocol.hpp"
#include <cstdint>
#include <cstddef>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    using namespace unicity::message;
    using namespace unicity::protocol;

    if (size < 1) return 0;

    // Use first byte to select message type
    uint8_t msg_type = data[0];
    const uint8_t* payload = data + 1;
    size_t payload_size = size - 1;

    std::unique_ptr<Message> msg;

    // Create message based on type selector
switch (msg_type % 9) {
        case 0:
            msg = std::make_unique<VersionMessage>();
            break;
        case 1:
            msg = std::make_unique<VerackMessage>();
            break;
        case 2:
            msg = std::make_unique<PingMessage>();
            break;
        case 3:
            msg = std::make_unique<PongMessage>();
            break;
        case 4:
            msg = std::make_unique<AddrMessage>();
            break;
        case 5:
            msg = std::make_unique<GetAddrMessage>();
            break;
        case 6:
            msg = std::make_unique<InvMessage>();
            break;
        case 7:
            msg = std::make_unique<GetHeadersMessage>();
            break;
        case 8:
            msg = std::make_unique<HeadersMessage>();
            break;
    }

    if (!msg) return 0;

    // Test deserialization - should handle any input gracefully
    bool success = msg->deserialize(payload, payload_size);

    // If deserialization succeeded, test serialization round-trip
    if (success) {
        try {
            auto serialized = msg->serialize();

            // CRITICAL: Validate serialized size is within protocol limits
            if (serialized.size() > MAX_PROTOCOL_MESSAGE_LENGTH) {
                // serialize() produced oversized message - BUG!
                __builtin_trap();
            }

            // Create new message of same type and deserialize
            std::unique_ptr<Message> msg2;
switch (msg_type % 9) {
                case 0: msg2 = std::make_unique<VersionMessage>(); break;
                case 1: msg2 = std::make_unique<VerackMessage>(); break;
                case 2: msg2 = std::make_unique<PingMessage>(); break;
                case 3: msg2 = std::make_unique<PongMessage>(); break;
                case 4: msg2 = std::make_unique<AddrMessage>(); break;
                case 5: msg2 = std::make_unique<GetAddrMessage>(); break;
                case 6: msg2 = std::make_unique<InvMessage>(); break;
case 7: msg2 = std::make_unique<GetHeadersMessage>(); break;
                case 8: msg2 = std::make_unique<HeadersMessage>(); break;
            }

            if (msg2) {
                bool success2 = msg2->deserialize(serialized.data(), serialized.size());

                // CRITICAL: Re-deserialize must succeed on our own serialization
                if (!success2) {
                    // deserialize() failed on serialize() output - BUG!
                    __builtin_trap();
                }

                // CRITICAL: Re-serialize and verify deterministic encoding
                auto serialized2 = msg2->serialize();

                if (serialized2.size() > MAX_PROTOCOL_MESSAGE_LENGTH) {
                    // Second serialization produced oversized message - BUG!
                    __builtin_trap();
                }

                // Verify byte-for-byte identical serialization
                if (serialized.size() != serialized2.size()) {
                    // Serialization size not deterministic - BUG!
                    __builtin_trap();
                }

                if (serialized != serialized2) {
                    // Serialization not deterministic - BUG!
                    // Same logical message must always serialize to same bytes
                    __builtin_trap();
                }
            }
        } catch (...) {
            // Serialization might throw on allocation - that's ok for OOM
            // But other exceptions should not happen
        }
    }

    return 0;
}
