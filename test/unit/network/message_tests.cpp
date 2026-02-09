// Copyright (c) 2025 The Unicity Foundation
// Unit tests for network/message.cpp - Message serialization/deserialization
//
// These tests verify:
// - VarInt encoding/decoding (all size ranges)
// - MessageSerializer primitive types
// - MessageDeserializer primitive types
// - Round-trip serialization
// - Error handling (buffer underflow, malformed data)
// - Network protocol structures

#include "catch_amalgamated.hpp"
#include "network/message.hpp"
#include "network/protocol.hpp"
#include <cstring>

using namespace unicity::message;
using namespace unicity::protocol;

TEST_CASE("VarInt - Encoding Size", "[network][message][varint][unit]") {
    SECTION("1-byte encoding (< 0xfd)") {
        REQUIRE(VarInt(0).encoded_size() == 1);
        REQUIRE(VarInt(0xfc).encoded_size() == 1);
    }

    SECTION("3-byte encoding (0xfd to 0xffff)") {
        REQUIRE(VarInt(0xfd).encoded_size() == 3);
        REQUIRE(VarInt(0xffff).encoded_size() == 3);
    }

    SECTION("5-byte encoding (0x10000 to 0xffffffff)") {
        REQUIRE(VarInt(0x10000).encoded_size() == 5);
        REQUIRE(VarInt(0xffffffff).encoded_size() == 5);
    }

    SECTION("9-byte encoding (> 0xffffffff)") {
        REQUIRE(VarInt(0x100000000ULL).encoded_size() == 9);
        REQUIRE(VarInt(0xffffffffffffffffULL).encoded_size() == 9);
    }
}

TEST_CASE("VarInt - Encode/Decode Round Trip", "[network][message][varint][unit]") {
    auto test_roundtrip = [](uint64_t value) {
        VarInt original(value);
        uint8_t buffer[9];
        size_t encoded_bytes = original.encode(buffer);

        REQUIRE(encoded_bytes == original.encoded_size());

        VarInt decoded;
        size_t decoded_bytes = decoded.decode(buffer, encoded_bytes);

        REQUIRE(decoded_bytes == encoded_bytes);
        REQUIRE(decoded.value == value);
    };

    SECTION("1-byte values") {
        test_roundtrip(0);
        test_roundtrip(1);
        test_roundtrip(0x7f);
        test_roundtrip(0xfc);
    }

    SECTION("3-byte values") {
        test_roundtrip(0xfd);
        test_roundtrip(0x100);
        test_roundtrip(0xffff);
    }

    SECTION("5-byte values") {
        test_roundtrip(0x10000);
        test_roundtrip(0x12345678);
        test_roundtrip(0xffffffff);
    }

    SECTION("9-byte values") {
        test_roundtrip(0x100000000ULL);
        test_roundtrip(0x123456789abcdefULL);
        test_roundtrip(0xffffffffffffffffULL);
    }
}

TEST_CASE("VarInt - Decode Error Handling", "[network][message][varint][unit]") {
    SECTION("Insufficient buffer for 1-byte") {
        uint8_t buffer[] = {0x42};
        VarInt vi;

        REQUIRE(vi.decode(buffer, 0) == 0);  // No data available
    }

    SECTION("Insufficient buffer for 3-byte") {
        uint8_t buffer[] = {0xfd, 0x00};  // Needs 3 bytes but only 2
        VarInt vi;

        REQUIRE(vi.decode(buffer, 2) == 0);
    }

    SECTION("Insufficient buffer for 5-byte") {
        uint8_t buffer[] = {0xfe, 0x00, 0x00, 0x00};  // Needs 5 bytes but only 4
        VarInt vi;

        REQUIRE(vi.decode(buffer, 4) == 0);
    }

    SECTION("Insufficient buffer for 9-byte") {
        uint8_t buffer[] = {0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};  // Needs 9 but only 8
        VarInt vi;

        REQUIRE(vi.decode(buffer, 8) == 0);
    }
}

TEST_CASE("MessageSerializer - Primitives", "[network][message][serializer][unit]") {
    MessageSerializer ser;

    SECTION("uint8") {
        ser.write_uint8(0x42);
        ser.write_uint8(0xff);

        auto data = ser.data();
        REQUIRE(data.size() == 2);
        REQUIRE(data[0] == 0x42);
        REQUIRE(data[1] == 0xff);
    }

    SECTION("uint16 (little-endian)") {
        ser.write_uint16(0x1234);

        auto data = ser.data();
        REQUIRE(data.size() == 2);
        REQUIRE(data[0] == 0x34);  // Little-endian
        REQUIRE(data[1] == 0x12);
    }

    SECTION("uint32 (little-endian)") {
        ser.write_uint32(0x12345678);

        auto data = ser.data();
        REQUIRE(data.size() == 4);
        REQUIRE(data[0] == 0x78);
        REQUIRE(data[1] == 0x56);
        REQUIRE(data[2] == 0x34);
        REQUIRE(data[3] == 0x12);
    }

    SECTION("uint64 (little-endian)") {
        ser.write_uint64(0x123456789abcdef0ULL);

        auto data = ser.data();
        REQUIRE(data.size() == 8);
        REQUIRE(data[0] == 0xf0);
        REQUIRE(data[1] == 0xde);
        REQUIRE(data[2] == 0xbc);
        REQUIRE(data[3] == 0x9a);
        REQUIRE(data[4] == 0x78);
        REQUIRE(data[5] == 0x56);
        REQUIRE(data[6] == 0x34);
        REQUIRE(data[7] == 0x12);
    }

    SECTION("int32") {
        ser.write_int32(-1);

        auto data = ser.data();
        REQUIRE(data.size() == 4);
        REQUIRE(data[0] == 0xff);
        REQUIRE(data[1] == 0xff);
        REQUIRE(data[2] == 0xff);
        REQUIRE(data[3] == 0xff);
    }

    SECTION("int64") {
        ser.write_int64(-1);

        auto data = ser.data();
        REQUIRE(data.size() == 8);
        for (int i = 0; i < 8; i++) {
            REQUIRE(data[i] == 0xff);
        }
    }

    SECTION("bool") {
        ser.write_bool(true);
        ser.write_bool(false);

        auto data = ser.data();
        REQUIRE(data.size() == 2);
        REQUIRE(data[0] == 1);
        REQUIRE(data[1] == 0);
    }
}

TEST_CASE("MessageSerializer - Variable Length", "[network][message][serializer][unit]") {
    MessageSerializer ser;

    SECTION("varint") {
        ser.write_varint(0);
        ser.write_varint(0xfc);
        ser.write_varint(0xfd);

        auto data = ser.data();
        REQUIRE(data.size() == 5);  // 1 + 1 + 3
        REQUIRE(data[0] == 0);
        REQUIRE(data[1] == 0xfc);
        REQUIRE(data[2] == 0xfd);  // Marker
        REQUIRE(data[3] == 0xfd);  // Low byte
        REQUIRE(data[4] == 0x00);  // High byte
    }

    SECTION("string") {
        ser.write_string("hello");

        auto data = ser.data();
        REQUIRE(data.size() == 6);  // 1 (varint length) + 5
        REQUIRE(data[0] == 5);  // Length
        REQUIRE(std::string((char*)&data[1], 5) == "hello");
    }

    SECTION("empty string") {
        ser.write_string("");

        auto data = ser.data();
        REQUIRE(data.size() == 1);
        REQUIRE(data[0] == 0);  // Zero length
    }

    SECTION("bytes from pointer") {
        uint8_t bytes[] = {0x01, 0x02, 0x03};
        ser.write_bytes(bytes, 3);

        auto data = ser.data();
        REQUIRE(data.size() == 3);
        REQUIRE(data[0] == 0x01);
        REQUIRE(data[1] == 0x02);
        REQUIRE(data[2] == 0x03);
    }

    SECTION("bytes from vector") {
        std::vector<uint8_t> bytes = {0xaa, 0xbb, 0xcc};
        ser.write_bytes(bytes);

        auto data = ser.data();
        REQUIRE(data.size() == 3);
        REQUIRE(data[0] == 0xaa);
        REQUIRE(data[1] == 0xbb);
        REQUIRE(data[2] == 0xcc);
    }
}

TEST_CASE("MessageSerializer - Clear", "[network][message][serializer][unit]") {
    MessageSerializer ser;

    ser.write_uint32(0x12345678);
    REQUIRE(ser.size() == 4);

    ser.clear();
    REQUIRE(ser.size() == 0);

    ser.write_uint8(0x42);
    REQUIRE(ser.size() == 1);
}

TEST_CASE("MessageDeserializer - Primitives", "[network][message][deserializer][unit]") {
    SECTION("uint8") {
        uint8_t data[] = {0x42, 0xff};
        MessageDeserializer des(data, 2);

        REQUIRE(des.read_uint8() == 0x42);
        REQUIRE(des.read_uint8() == 0xff);
        REQUIRE(des.bytes_remaining() == 0);
        REQUIRE_FALSE(des.has_error());
    }

    SECTION("uint16 (little-endian)") {
        uint8_t data[] = {0x34, 0x12};
        MessageDeserializer des(data, 2);

        REQUIRE(des.read_uint16() == 0x1234);
        REQUIRE_FALSE(des.has_error());
    }

    SECTION("uint32 (little-endian)") {
        uint8_t data[] = {0x78, 0x56, 0x34, 0x12};
        MessageDeserializer des(data, 4);

        REQUIRE(des.read_uint32() == 0x12345678);
        REQUIRE_FALSE(des.has_error());
    }

    SECTION("uint64 (little-endian)") {
        uint8_t data[] = {0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12};
        MessageDeserializer des(data, 8);

        REQUIRE(des.read_uint64() == 0x123456789abcdef0ULL);
        REQUIRE_FALSE(des.has_error());
    }

    SECTION("int32") {
        uint8_t data[] = {0xff, 0xff, 0xff, 0xff};
        MessageDeserializer des(data, 4);

        REQUIRE(des.read_int32() == -1);
        REQUIRE_FALSE(des.has_error());
    }

    SECTION("int64") {
        uint8_t data[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        MessageDeserializer des(data, 8);

        REQUIRE(des.read_int64() == -1);
        REQUIRE_FALSE(des.has_error());
    }

    SECTION("bool") {
        uint8_t data[] = {0x01, 0x00};
        MessageDeserializer des(data, 2);

        REQUIRE(des.read_bool() == true);
        REQUIRE(des.read_bool() == false);
        REQUIRE_FALSE(des.has_error());
    }
}

TEST_CASE("MessageDeserializer - Variable Length", "[network][message][deserializer][unit]") {
    SECTION("varint") {
        uint8_t data[] = {0x00, 0xfc, 0xfd, 0xfd, 0x00};
        MessageDeserializer des(data, 5);

        REQUIRE(des.read_varint() == 0);
        REQUIRE(des.read_varint() == 0xfc);
        REQUIRE(des.read_varint() == 0xfd);
        REQUIRE_FALSE(des.has_error());
    }

    SECTION("string") {
        uint8_t data[] = {0x05, 'h', 'e', 'l', 'l', 'o'};
        MessageDeserializer des(data, 6);

        REQUIRE(des.read_string() == "hello");
        REQUIRE_FALSE(des.has_error());
    }

    SECTION("empty string") {
        uint8_t data[] = {0x00};
        MessageDeserializer des(data, 1);

        REQUIRE(des.read_string() == "");
        REQUIRE_FALSE(des.has_error());
    }

    SECTION("bytes") {
        uint8_t data[] = {0x01, 0x02, 0x03};
        MessageDeserializer des(data, 3);

        auto bytes = des.read_bytes(3);
        REQUIRE(bytes.size() == 3);
        REQUIRE(bytes[0] == 0x01);
        REQUIRE(bytes[1] == 0x02);
        REQUIRE(bytes[2] == 0x03);
        REQUIRE_FALSE(des.has_error());
    }
}

TEST_CASE("MessageDeserializer - Error Handling", "[network][message][deserializer][unit]") {
    SECTION("uint8 buffer underflow") {
        uint8_t data[] = {0x42};
        MessageDeserializer des(data, 1);

        REQUIRE(des.read_uint8() == 0x42);
        REQUIRE_FALSE(des.has_error());

        // Try to read beyond buffer
        des.read_uint8();
        REQUIRE(des.has_error());
    }

    SECTION("uint32 buffer underflow") {
        uint8_t data[] = {0x01, 0x02};  // Only 2 bytes
        MessageDeserializer des(data, 2);

        des.read_uint32();  // Needs 4 bytes
        REQUIRE(des.has_error());
    }

    SECTION("string length overflow") {
        uint8_t data[] = {0x0a, 'h', 'i'};  // Says 10 bytes but only 2 available
        MessageDeserializer des(data, 3);

        des.read_string();
        REQUIRE(des.has_error());
    }

    SECTION("bytes count overflow") {
        uint8_t data[] = {0x01, 0x02};
        MessageDeserializer des(data, 2);

        des.read_bytes(10);  // Request more than available
        REQUIRE(des.has_error());
    }
}

TEST_CASE("Message Serialization - Round Trip", "[network][message][roundtrip][unit]") {
    SECTION("Multiple primitive types") {
        MessageSerializer ser;

        ser.write_uint8(0x42);
        ser.write_uint16(0x1234);
        ser.write_uint32(0x12345678);
        ser.write_uint64(0x123456789abcdef0ULL);
        ser.write_bool(true);
        ser.write_varint(0xfd);
        ser.write_string("test");

        auto data = ser.data();
        MessageDeserializer des(data);

        REQUIRE(des.read_uint8() == 0x42);
        REQUIRE(des.read_uint16() == 0x1234);
        REQUIRE(des.read_uint32() == 0x12345678);
        REQUIRE(des.read_uint64() == 0x123456789abcdef0ULL);
        REQUIRE(des.read_bool() == true);
        REQUIRE(des.read_varint() == 0xfd);
        REQUIRE(des.read_string() == "test");

        REQUIRE(des.bytes_remaining() == 0);
        REQUIRE_FALSE(des.has_error());
    }
}

TEST_CASE("MessageDeserializer - Position Tracking", "[network][message][deserializer][unit]") {
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    MessageDeserializer des(data, 4);

    REQUIRE(des.position() == 0);
    REQUIRE(des.bytes_remaining() == 4);

    des.read_uint8();
    REQUIRE(des.position() == 1);
    REQUIRE(des.bytes_remaining() == 3);

    des.read_uint8();
    REQUIRE(des.position() == 2);
    REQUIRE(des.bytes_remaining() == 2);

    des.read_uint16();
    REQUIRE(des.position() == 4);
    REQUIRE(des.bytes_remaining() == 0);
}


TEST_CASE("VarInt - Edge Cases", "[network][message][varint][unit]") {
    SECTION("Boundary values") {
        // Test exact boundary transitions
        REQUIRE(VarInt(0xfc).encoded_size() == 1);
        REQUIRE(VarInt(0xfd).encoded_size() == 3);

        REQUIRE(VarInt(0xffff).encoded_size() == 3);
        REQUIRE(VarInt(0x10000).encoded_size() == 5);

        REQUIRE(VarInt(0xffffffff).encoded_size() == 5);
        REQUIRE(VarInt(0x100000000ULL).encoded_size() == 9);
    }

    SECTION("Maximum value") {
        VarInt vi(0xffffffffffffffffULL);
        uint8_t buffer[9];
        size_t encoded = vi.encode(buffer);

        REQUIRE(encoded == 9);
        REQUIRE(buffer[0] == 0xff);

        VarInt decoded;
        size_t decoded_bytes = decoded.decode(buffer, 9);
        REQUIRE(decoded_bytes == 9);
        REQUIRE(decoded.value == 0xffffffffffffffffULL);
    }
}

TEST_CASE("MessageSerializer - Long String", "[network][message][serializer][unit]") {
    MessageSerializer ser;

    std::string long_str(1000, 'x');
    ser.write_string(long_str);

    auto data = ser.data();

    MessageDeserializer des(data);
    auto decoded = des.read_string();

    REQUIRE(decoded == long_str);
    REQUIRE(decoded.length() == 1000);
    REQUIRE_FALSE(des.has_error());
}

TEST_CASE("MessageDeserializer - Empty Buffer", "[network][message][deserializer][unit]") {
    uint8_t data[] = {};
    MessageDeserializer des(data, 0);

    REQUIRE(des.bytes_remaining() == 0);
    REQUIRE(des.position() == 0);

    des.read_uint8();
    REQUIRE(des.has_error());
}

TEST_CASE("Message - Ping/Pong", "[network][message][unit]") {
    SECTION("PingMessage serialize/deserialize") {
        PingMessage ping(0x123456789abcdef0ULL);

        auto data = ping.serialize();
        REQUIRE(data.size() == 8);

        PingMessage ping2;
        REQUIRE(ping2.deserialize(data.data(), data.size()));
        REQUIRE(ping2.nonce == 0x123456789abcdef0ULL);
    }

    SECTION("PongMessage serialize/deserialize") {
        PongMessage pong(0xfedcba9876543210ULL);

        auto data = pong.serialize();
        REQUIRE(data.size() == 8);

        PongMessage pong2;
        REQUIRE(pong2.deserialize(data.data(), data.size()));
        REQUIRE(pong2.nonce == 0xfedcba9876543210ULL);
    }

    SECTION("Ping command name") {
        PingMessage ping;
        REQUIRE(ping.command() == commands::PING);
    }

    SECTION("Pong command name") {
        PongMessage pong;
        REQUIRE(pong.command() == commands::PONG);
    }
}

TEST_CASE("Message - Verack", "[network][message][unit]") {
    VerackMessage verack;

    SECTION("Command name") {
        REQUIRE(verack.command() == commands::VERACK);
    }

    SECTION("Serialize") {
        auto data = verack.serialize();
        REQUIRE(data.size() == 0);  // Verack has no payload
    }

    SECTION("Deserialize") {
        uint8_t empty[] = {};
        REQUIRE(verack.deserialize(empty, 0));
    }
}

TEST_CASE("Message - GetAddr", "[network][message][unit]") {
    GetAddrMessage getaddr;

    SECTION("Command name") {
        REQUIRE(getaddr.command() == commands::GETADDR);
    }

    SECTION("Serialize") {
        auto data = getaddr.serialize();
        REQUIRE(data.size() == 0);  // GetAddr has no payload
    }

    SECTION("Deserialize") {
        uint8_t empty[] = {};
        REQUIRE(getaddr.deserialize(empty, 0));
    }
}

// ============================================================================
// DoS Protection Tests - Message Size Limits
// ============================================================================

TEST_CASE("VERSION Message - User Agent Length Enforcement", "[network][message][dos][security]") {
    // Tests for CVE fix: user_agent length must be enforced DURING deserialization
    // to prevent memory exhaustion attacks (max 256 bytes per Bitcoin Core)

    SECTION("Normal user agent - should succeed") {
        MessageSerializer s;
        s.write_int32(70015);  // version
        s.write_uint64(1);     // services
        s.write_int64(1234567890);  // timestamp

        // addr_recv (26 bytes)
        s.write_uint64(0);  // services
        std::array<uint8_t, 16> ipv6 = {0};
        s.write_bytes(ipv6.data(), 16);
        s.write_uint16(9590);  // port

        // addr_from (26 bytes)
        s.write_uint64(0);  // services
        s.write_bytes(ipv6.data(), 16);
        s.write_uint16(0);  // port

        s.write_uint64(0x123456789abcdef);  // nonce
        s.write_string("/Unicity:1.0.0/");  // user_agent (normal length)
        s.write_int32(0);  // start_height

        auto data = s.data();
        VersionMessage msg;
        REQUIRE(msg.deserialize(data.data(), data.size()));
        REQUIRE(msg.user_agent == "/Unicity:1.0.0/");
    }

    SECTION("User agent at MAX_SUBVERSION_LENGTH (256) - should succeed") {
        MessageSerializer s;
        s.write_int32(70015);
        s.write_uint64(1);
        s.write_int64(1234567890);

        // addr_recv
        s.write_uint64(0);
        std::array<uint8_t, 16> ipv6 = {0};
        s.write_bytes(ipv6.data(), 16);
        s.write_uint16(9590);

        // addr_from
        s.write_uint64(0);
        s.write_bytes(ipv6.data(), 16);
        s.write_uint16(0);

        s.write_uint64(0x123456789abcdef);

        // Create string exactly at limit (256 bytes)
        std::string max_user_agent(MAX_SUBVERSION_LENGTH, 'A');
        s.write_string(max_user_agent);
        s.write_int32(0);

        auto data = s.data();
        VersionMessage msg;
        REQUIRE(msg.deserialize(data.data(), data.size()));
        REQUIRE(msg.user_agent == max_user_agent);
        REQUIRE(msg.user_agent.length() == MAX_SUBVERSION_LENGTH);
    }

    SECTION("User agent over MAX_SUBVERSION_LENGTH - should fail") {
        MessageSerializer s;
        s.write_int32(70015);
        s.write_uint64(1);
        s.write_int64(1234567890);

        // addr_recv
        s.write_uint64(0);
        std::array<uint8_t, 16> ipv6 = {0};
        s.write_bytes(ipv6.data(), 16);
        s.write_uint16(9590);

        // addr_from
        s.write_uint64(0);
        s.write_bytes(ipv6.data(), 16);
        s.write_uint16(0);

        s.write_uint64(0x123456789abcdef);

        // Create string OVER limit (257 bytes)
        std::string oversized_user_agent(MAX_SUBVERSION_LENGTH + 1, 'A');
        s.write_string(oversized_user_agent);
        s.write_int32(0);

        auto data = s.data();
        VersionMessage msg;
        // Should fail deserialization due to limit enforcement
        REQUIRE_FALSE(msg.deserialize(data.data(), data.size()));
    }

    SECTION("Very large user agent (4KB) - should fail without OOM") {
        // This tests that we reject large strings BEFORE allocation
        MessageSerializer s;
        s.write_int32(70015);
        s.write_uint64(1);
        s.write_int64(1234567890);

        // addr_recv
        s.write_uint64(0);
        std::array<uint8_t, 16> ipv6 = {0};
        s.write_bytes(ipv6.data(), 16);
        s.write_uint16(9590);

        // addr_from
        s.write_uint64(0);
        s.write_bytes(ipv6.data(), 16);
        s.write_uint16(0);

        s.write_uint64(0x123456789abcdef);

        // Create very large string (4KB)
        std::string huge_user_agent(4096, 'B');
        s.write_string(huge_user_agent);
        s.write_int32(0);

        auto data = s.data();
        VersionMessage msg;
        // Should fail quickly without allocating 4KB
        REQUIRE_FALSE(msg.deserialize(data.data(), data.size()));
    }

    SECTION("Malformed varint for user_agent length - should fail") {
        MessageSerializer s;
        s.write_int32(70015);
        s.write_uint64(1);
        s.write_int64(1234567890);

        // addr_recv
        s.write_uint64(0);
        std::array<uint8_t, 16> ipv6 = {0};
        s.write_bytes(ipv6.data(), 16);
        s.write_uint16(9590);

        // addr_from
        s.write_uint64(0);
        s.write_bytes(ipv6.data(), 16);
        s.write_uint16(0);

        s.write_uint64(0x123456789abcdef);

        // Manually write a varint claiming huge size but with insufficient data
        s.write_uint8(0xfd);  // 3-byte varint prefix
        s.write_uint16(5000); // Claims 5000 bytes
        // But don't provide 5000 bytes - only provide a few
        s.write_string("short");
        s.write_int32(0);

        auto data = s.data();
        VersionMessage msg;
        REQUIRE_FALSE(msg.deserialize(data.data(), data.size()));
    }
}

// ============================================================================
// Network Address Serialization Tests
// ============================================================================

TEST_CASE("NetworkAddress - Serialization", "[network][message][netaddr][unit]") {
    MessageSerializer ser;

    SECTION("IPv4-mapped address serialization") {
        NetworkAddress addr;
        addr.services = 1;  // NODE_NETWORK
        // IPv4 127.0.0.1 mapped to IPv6 (::ffff:127.0.0.1)
        addr.ip = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x01};
        addr.port = 9590;

        ser.write_network_address(addr);

        auto data = ser.data();
        // Should be: 8 (services) + 16 (IP) + 2 (port BE) = 26 bytes
        REQUIRE(data.size() == 26);

        // Verify services (little-endian)
        REQUIRE(data[0] == 0x01);
        REQUIRE(data[1] == 0x00);

        // Verify IP bytes
        for (size_t i = 0; i < 16; i++) {
            REQUIRE(data[8 + i] == addr.ip[i]);
        }

        // Verify port (big-endian!)
        REQUIRE(data[24] == 0x25);  // 9590 = 0x2576
        REQUIRE(data[25] == 0x76);
    }

    SECTION("All-zeros address") {
        NetworkAddress addr;
        addr.services = 0;
        addr.ip.fill(0);
        addr.port = 0;

        ser.write_network_address(addr);

        auto data = ser.data();
        REQUIRE(data.size() == 26);

        // All bytes should be zero
        for (size_t i = 0; i < 26; i++) {
            REQUIRE(data[i] == 0);
        }
    }

    SECTION("Maximum values") {
        NetworkAddress addr;
        addr.services = 0xffffffffffffffffULL;
        addr.ip.fill(0xff);
        addr.port = 0xffff;

        ser.write_network_address(addr);

        auto data = ser.data();
        REQUIRE(data.size() == 26);

        // All bytes should be 0xff
        for (size_t i = 0; i < 26; i++) {
            REQUIRE(data[i] == 0xff);
        }
    }
}

TEST_CASE("NetworkAddress - Deserialization", "[network][message][netaddr][unit]") {
    SECTION("Valid network address") {
        // Manually construct a network address on wire
        std::vector<uint8_t> data;

        // Services (LE): 1
        data.insert(data.end(), {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});

        // IP: ::ffff:192.168.1.1
        data.insert(data.end(), {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0xff, 0xff, 0xc0, 0xa8, 0x01, 0x01});

        // Port (BE): 9333 = 0x2475
        data.insert(data.end(), {0x24, 0x75});

        MessageDeserializer des(data);
        auto addr = des.read_network_address();

        REQUIRE_FALSE(des.has_error());
        REQUIRE(addr.services == 1);
        REQUIRE(addr.port == 9333);

        // Verify IP
        std::array<uint8_t, 16> expected_ip = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                0x00, 0x00, 0xff, 0xff, 0xc0, 0xa8, 0x01, 0x01};
        REQUIRE(addr.ip == expected_ip);
    }

    SECTION("Buffer underflow - insufficient data") {
        std::vector<uint8_t> data(20);  // Need 26 bytes, only have 20

        MessageDeserializer des(data);
        des.read_network_address();

        REQUIRE(des.has_error());
    }
}

TEST_CASE("NetworkAddress - Round Trip", "[network][message][netaddr][unit]") {
    NetworkAddress original;
    original.services = 0x123456789abcdef0ULL;
    original.ip = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    original.port = 12345;

    MessageSerializer ser;
    ser.write_network_address(original);

    MessageDeserializer des(ser.data());
    auto decoded = des.read_network_address();

    REQUIRE_FALSE(des.has_error());
    REQUIRE(decoded.services == original.services);
    REQUIRE(decoded.ip == original.ip);
    REQUIRE(decoded.port == original.port);
}

TEST_CASE("TimestampedAddress - Round Trip", "[network][message][netaddr][unit]") {
    MessageSerializer ser;

    // Write timestamp manually
    uint32_t timestamp = 1234567890;
    ser.write_uint32(timestamp);

    // Write address
    NetworkAddress addr;
    addr.services = 1;
    addr.ip = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
               0x00, 0x00, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x01};
    addr.port = 9590;
    ser.write_network_address(addr);

    // Deserialize using read_timestamped_address
    MessageDeserializer des(ser.data());
    auto ts_addr = des.read_timestamped_address();

    REQUIRE_FALSE(des.has_error());
    REQUIRE(ts_addr.timestamp == timestamp);
    REQUIRE(ts_addr.address.services == addr.services);
    REQUIRE(ts_addr.address.ip == addr.ip);
    REQUIRE(ts_addr.address.port == addr.port);
}

// ============================================================================
// ADDR Message Tests
// ============================================================================

TEST_CASE("AddrMessage - Empty", "[network][message][addr][unit]") {
    AddrMessage msg;

    SECTION("Serialize empty") {
        auto data = msg.serialize();
        REQUIRE(data.size() == 1);  // Just varint 0
        REQUIRE(data[0] == 0);
    }

    SECTION("Deserialize empty") {
        uint8_t data[] = {0x00};  // Count = 0
        AddrMessage msg2;
        REQUIRE(msg2.deserialize(data, sizeof(data)));
        REQUIRE(msg2.addresses.empty());
    }
}

TEST_CASE("AddrMessage - Single Address", "[network][message][addr][unit]") {
    AddrMessage msg;

    TimestampedAddress ts_addr;
    ts_addr.timestamp = 1234567890;
    ts_addr.address.services = 1;
    ts_addr.address.ip = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x01};
    ts_addr.address.port = 9590;

    msg.addresses.push_back(ts_addr);

    auto data = msg.serialize();

    // Verify format: varint(1) + timestamp(4) + netaddr(26) = 1 + 4 + 26 = 31 bytes
    REQUIRE(data.size() == 31);
    REQUIRE(data[0] == 0x01);  // Count = 1

    // Deserialize
    AddrMessage msg2;
    REQUIRE(msg2.deserialize(data.data(), data.size()));
    REQUIRE(msg2.addresses.size() == 1);
    REQUIRE(msg2.addresses[0].timestamp == ts_addr.timestamp);
    REQUIRE(msg2.addresses[0].address.services == ts_addr.address.services);
    REQUIRE(msg2.addresses[0].address.ip == ts_addr.address.ip);
    REQUIRE(msg2.addresses[0].address.port == ts_addr.address.port);
}

TEST_CASE("AddrMessage - Multiple Addresses", "[network][message][addr][unit]") {
    AddrMessage msg;

    // Add 3 addresses
    for (int i = 0; i < 3; i++) {
        TimestampedAddress ts_addr;
        ts_addr.timestamp = 1000000 + i;
        ts_addr.address.services = i;
        ts_addr.address.ip.fill(i);
        ts_addr.address.port = 8000 + i;
        msg.addresses.push_back(ts_addr);
    }

    auto data = msg.serialize();

    // varint(3) + 3 * (timestamp(4) + netaddr(26)) = 1 + 3*30 = 91 bytes
    REQUIRE(data.size() == 91);
    REQUIRE(data[0] == 0x03);  // Count = 3

    // Deserialize and verify
    AddrMessage msg2;
    REQUIRE(msg2.deserialize(data.data(), data.size()));
    REQUIRE(msg2.addresses.size() == 3);

    for (int i = 0; i < 3; i++) {
        REQUIRE(msg2.addresses[i].timestamp == 1000000 + i);
        REQUIRE(msg2.addresses[i].address.services == i);
        REQUIRE(msg2.addresses[i].address.port == 8000 + i);

        std::array<uint8_t, 16> expected_ip;
        expected_ip.fill(i);
        REQUIRE(msg2.addresses[i].address.ip == expected_ip);
    }
}

TEST_CASE("AddrMessage - MAX_ADDR_SIZE Enforcement", "[network][message][addr][dos][unit]") {
    SECTION("At limit - should succeed") {
        MessageSerializer ser;
        ser.write_varint(MAX_ADDR_SIZE);  // 1000

        // Write 1000 minimal addresses
        for (size_t i = 0; i < MAX_ADDR_SIZE; i++) {
            ser.write_uint32(0);  // timestamp
            ser.write_network_address(NetworkAddress{});
        }

        AddrMessage msg;
        REQUIRE(msg.deserialize(ser.data().data(), ser.data().size()));
        REQUIRE(msg.addresses.size() == MAX_ADDR_SIZE);
    }

    SECTION("Over limit - should fail") {
        MessageSerializer ser;
        ser.write_varint(MAX_ADDR_SIZE + 1);  // 1001

        AddrMessage msg;
        REQUIRE_FALSE(msg.deserialize(ser.data().data(), ser.data().size()));
    }

    SECTION("Very large count - should fail without OOM") {
        MessageSerializer ser;
        ser.write_varint(1000000);  // 1 million

        AddrMessage msg;
        REQUIRE_FALSE(msg.deserialize(ser.data().data(), ser.data().size()));
    }
}

TEST_CASE("AddrMessage - Malformed Data", "[network][message][addr][unit]") {
    SECTION("Truncated address data") {
        MessageSerializer ser;
        ser.write_varint(2);  // Claims 2 addresses

        // Only write 1 complete address
        ser.write_uint32(1234567890);
        ser.write_network_address(NetworkAddress{});

        // Second address is incomplete (missing data)
        ser.write_uint32(1234567890);
        // Missing network address

        AddrMessage msg;
        REQUIRE_FALSE(msg.deserialize(ser.data().data(), ser.data().size()));
    }

    SECTION("Buffer underflow during count read") {
        uint8_t data[] = {};  // Empty buffer

        AddrMessage msg;
        REQUIRE_FALSE(msg.deserialize(data, sizeof(data)));
    }
}

TEST_CASE("AddrMessage - Command Name", "[network][message][addr][unit]") {
    AddrMessage msg;
    REQUIRE(msg.command() == commands::ADDR);
}

// ============================================================================
// Stream Compatibility Tests (base_blob::Serialize)
// ============================================================================

TEST_CASE("MessageSerializer - base_blob Stream Compatibility", "[network][message][serializer][stream][unit]") {
    SECTION("uint256::Serialize() works with MessageSerializer") {
        uint256 hash;
        // Set to known pattern
        for (size_t i = 0; i < 32; i++) {
            hash.data()[i] = static_cast<uint8_t>(i);
        }

        MessageSerializer ser;
        hash.Serialize(ser);  // Should compile and work!

        auto data = ser.data();
        REQUIRE(data.size() == 32);

        // Verify bytes match
        for (size_t i = 0; i < 32; i++) {
            REQUIRE(data[i] == static_cast<uint8_t>(i));
        }
    }

    SECTION("uint160::Serialize() works with MessageSerializer") {
        uint160 addr;
        // Set to known pattern
        for (size_t i = 0; i < 20; i++) {
            addr.data()[i] = static_cast<uint8_t>(0xff - i);
        }

        MessageSerializer ser;
        addr.Serialize(ser);  // Should compile and work!

        auto data = ser.data();
        REQUIRE(data.size() == 20);

        // Verify bytes match
        for (size_t i = 0; i < 20; i++) {
            REQUIRE(data[i] == static_cast<uint8_t>(0xff - i));
        }
    }

    SECTION("Manual write_bytes vs Serialize() produce identical output") {
        uint256 hash;
        for (size_t i = 0; i < 32; i++) {
            hash.data()[i] = static_cast<uint8_t>(i * 2);
        }

        // Method 1: Manual serialization (current approach)
        MessageSerializer ser1;
        ser1.write_bytes(hash.data(), hash.size());

        // Method 2: Using Serialize() (now possible!)
        MessageSerializer ser2;
        hash.Serialize(ser2);

        // Both should produce identical output
        REQUIRE(ser1.data() == ser2.data());
        REQUIRE(ser1.data().size() == 32);
    }
}

TEST_CASE("VarInt - Non-Canonical Encoding Rejection (CVE-2018-17144 class)", "[network][message][varint][security][unit]") {
    using namespace unicity::message;

    SECTION("Value 5 with 3-byte encoding should be rejected") {
        uint8_t non_canonical[] = {0xfd, 0x05, 0x00};  // value=5 in 3 bytes
        VarInt vi;
        size_t consumed = vi.decode(non_canonical, sizeof(non_canonical));
        REQUIRE(consumed == 0);  // Should reject non-canonical encoding
    }

    SECTION("Value 0 with 3-byte encoding should be rejected") {
        uint8_t non_canonical[] = {0xfd, 0x00, 0x00};  // value=0 in 3 bytes
        VarInt vi;
        size_t consumed = vi.decode(non_canonical, sizeof(non_canonical));
        REQUIRE(consumed == 0);  // Should reject non-canonical encoding
    }

    SECTION("Value 252 (0xfc) with 3-byte encoding should be rejected") {
        uint8_t non_canonical[] = {0xfd, 0xfc, 0x00};  // value=252 in 3 bytes
        VarInt vi;
        size_t consumed = vi.decode(non_canonical, sizeof(non_canonical));
        REQUIRE(consumed == 0);  // Should reject (252 < 253, must use 1 byte)
    }

    SECTION("Value 253 (0xfd) with 5-byte encoding should be rejected") {
        uint8_t non_canonical[] = {0xfe, 0xfd, 0x00, 0x00, 0x00};  // value=253 in 5 bytes
        VarInt vi;
        size_t consumed = vi.decode(non_canonical, sizeof(non_canonical));
        REQUIRE(consumed == 0);  // Should reject (253 <= 65535, must use 3 bytes)
    }

    SECTION("Value 65536 (0x10000) with 9-byte encoding should be rejected") {
        uint8_t non_canonical[] = {0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00};  // value=65536 in 9 bytes
        VarInt vi;
        size_t consumed = vi.decode(non_canonical, sizeof(non_canonical));
        REQUIRE(consumed == 0);  // Should reject (65536 <= 4294967295, must use 5 bytes)
    }

    SECTION("Canonical encodings should still work") {
        SECTION("Value 5 with 1-byte encoding (canonical)") {
            uint8_t canonical[] = {0x05};
            VarInt vi;
            size_t consumed = vi.decode(canonical, sizeof(canonical));
            REQUIRE(consumed == 1);
            REQUIRE(vi.value == 5);
        }

        SECTION("Value 253 with 3-byte encoding (canonical)") {
            uint8_t canonical[] = {0xfd, 0xfd, 0x00};
            VarInt vi;
            size_t consumed = vi.decode(canonical, sizeof(canonical));
            REQUIRE(consumed == 3);
            REQUIRE(vi.value == 253);
        }

        SECTION("Value 65536 with 5-byte encoding (canonical)") {
            uint8_t canonical[] = {0xfe, 0x00, 0x00, 0x01, 0x00};
            VarInt vi;
            size_t consumed = vi.decode(canonical, sizeof(canonical));
            REQUIRE(consumed == 5);
            REQUIRE(vi.value == 65536);
        }

        SECTION("Value 4294967296 (2^32) with 9-byte encoding (canonical)") {
            uint8_t canonical[] = {0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
            VarInt vi;
            size_t consumed = vi.decode(canonical, sizeof(canonical));
            REQUIRE(consumed == 9);
            REQUIRE(vi.value == 4294967296ULL);
        }
    }
}
