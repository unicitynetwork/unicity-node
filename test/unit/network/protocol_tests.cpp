// Unit tests for protocol structures and serialization
#include "catch_amalgamated.hpp"
#include "network/protocol.hpp"
#include "chain/validation.hpp"
#include <cstring>
#include <set>

using namespace unicity::protocol;

TEST_CASE("MessageHeader - Command parsing", "[network][protocol]") {
    SECTION("Empty command") {
        MessageHeader header(magic::MAINNET, "", 100);
        CHECK(header.magic == magic::MAINNET);
        CHECK(header.length == 100);
        CHECK(header.get_command() == "");
    }

    SECTION("Short command") {
        MessageHeader header(magic::MAINNET, "ping", 0);
        CHECK(header.get_command() == "ping");
    }

    SECTION("Maximum length command (12 bytes)") {
        std::string long_cmd = "123456789012"; // Exactly 12 bytes
        MessageHeader header(magic::MAINNET, long_cmd, 0);
        CHECK(header.get_command() == long_cmd);
    }

    SECTION("Command too long (truncated to 12 bytes)") {
        std::string too_long = "1234567890123456"; // 16 bytes
        MessageHeader header(magic::MAINNET, too_long, 0);
        std::string result = header.get_command();
        CHECK(result.length() == COMMAND_SIZE);
        CHECK(result == "123456789012");
    }

    SECTION("Command with null padding") {
        MessageHeader header;
        header.set_command("verack");
        CHECK(header.get_command() == "verack");
        // Verify null padding
        CHECK(header.command[6] == '\0');
        CHECK(header.command[11] == '\0');
    }

    SECTION("set_command replaces previous value") {
        MessageHeader header;
        header.set_command("getaddr");
        CHECK(header.get_command() == "getaddr");

        header.set_command("ping");
        CHECK(header.get_command() == "ping");
        CHECK(header.command[4] == '\0'); // Null padded after "ping"
    }

    SECTION("Default constructor initializes to zero") {
        MessageHeader header;
        CHECK(header.magic == 0);
        CHECK(header.length == 0);
        CHECK(header.get_command() == "");
        CHECK(header.checksum[0] == 0);
        CHECK(header.checksum[3] == 0);
    }
}

TEST_CASE("MessageHeader - Protocol constants", "[network][protocol]") {
    SECTION("Magic bytes are distinct") {
        CHECK(magic::MAINNET != magic::TESTNET);
        CHECK(magic::MAINNET != magic::REGTEST);
        CHECK(magic::TESTNET != magic::REGTEST);
    }

    SECTION("Ports are distinct and follow convention") {
        CHECK(ports::MAINNET == 9590);
        CHECK(ports::TESTNET == ports::MAINNET + 10000);
        CHECK(ports::REGTEST == ports::MAINNET + 20000);
    }

    SECTION("Message header size constants") {
        CHECK(MESSAGE_HEADER_SIZE == 24);
        CHECK(COMMAND_SIZE == 12);
        CHECK(CHECKSUM_SIZE == 4);
    }
}

TEST_CASE("NetworkAddress - IPv4 mapping", "[network][protocol]") {
    SECTION("Create from IPv4 address") {
        // 192.168.1.1 = 0xC0A80101
        uint32_t ipv4 = (192 << 24) | (168 << 16) | (1 << 8) | 1;
        NetworkAddress addr = NetworkAddress::from_ipv4(NODE_NETWORK, ipv4, 9590);

        CHECK(addr.services == NODE_NETWORK);
        CHECK(addr.port == 9590);
        CHECK(addr.is_ipv4());
        CHECK(addr.get_ipv4() == ipv4);

        // Verify IPv4-mapped IPv6 format: ::ffff:192.168.1.1
        CHECK(addr.ip[10] == 0xff);
        CHECK(addr.ip[11] == 0xff);
        CHECK(addr.ip[12] == 192);
        CHECK(addr.ip[13] == 168);
        CHECK(addr.ip[14] == 1);
        CHECK(addr.ip[15] == 1);
    }

    SECTION("Loopback 127.0.0.1") {
        uint32_t loopback = (127 << 24) | 1; // 127.0.0.1
        NetworkAddress addr = NetworkAddress::from_ipv4(0, loopback, 9590);

        CHECK(addr.is_ipv4());
        CHECK(addr.get_ipv4() == loopback);
        CHECK(addr.ip[12] == 127);
        CHECK(addr.ip[13] == 0);
        CHECK(addr.ip[14] == 0);
        CHECK(addr.ip[15] == 1);
    }

    SECTION("Broadcast 255.255.255.255") {
        uint32_t broadcast = 0xFFFFFFFF;
        NetworkAddress addr = NetworkAddress::from_ipv4(0, broadcast, 9590);

        CHECK(addr.is_ipv4());
        CHECK(addr.get_ipv4() == broadcast);
        CHECK(addr.ip[12] == 255);
        CHECK(addr.ip[13] == 255);
        CHECK(addr.ip[14] == 255);
        CHECK(addr.ip[15] == 255);
    }

    SECTION("Zero address 0.0.0.0") {
        uint32_t zero = 0;
        NetworkAddress addr = NetworkAddress::from_ipv4(0, zero, 0);

        CHECK(addr.is_ipv4());
        CHECK(addr.get_ipv4() == 0);
    }
}

TEST_CASE("NetworkAddress - IPv6 detection", "[network][protocol]") {
    SECTION("Pure IPv6 is not IPv4-mapped") {
        NetworkAddress addr;
        addr.services = NODE_NETWORK;
        addr.port = 9590;

        // Set to 2001:db8::1 (documentation IPv6)
        addr.ip[0] = 0x20;
        addr.ip[1] = 0x01;
        addr.ip[2] = 0x0d;
        addr.ip[3] = 0xb8;
        // Rest zeros
        for (int i = 4; i < 15; i++) addr.ip[i] = 0;
        addr.ip[15] = 1;

        CHECK_FALSE(addr.is_ipv4());
        CHECK(addr.get_ipv4() == 0); // Returns 0 for non-IPv4
    }

    SECTION("Invalid IPv4-mapped (wrong prefix)") {
        NetworkAddress addr;
        addr.ip.fill(0);
        addr.ip[10] = 0xfe; // Should be 0xff
        addr.ip[11] = 0xff;
        addr.ip[12] = 192;
        addr.ip[13] = 168;
        addr.ip[14] = 1;
        addr.ip[15] = 1;

        CHECK_FALSE(addr.is_ipv4());
    }
}

TEST_CASE("NetworkAddress - Default constructor", "[network][protocol]") {
    NetworkAddress addr;
    CHECK(addr.services == 0);
    CHECK(addr.port == 0);
    CHECK(addr.ip[0] == 0);
    CHECK(addr.ip[15] == 0);
}

TEST_CASE("NetworkAddress - Parameterized constructor", "[network][protocol]") {
    std::array<uint8_t, 16> test_ip;
    test_ip.fill(0);
    test_ip[0] = 0x20;
    test_ip[1] = 0x01;

    NetworkAddress addr(NODE_NETWORK, test_ip, 9590);
    CHECK(addr.services == NODE_NETWORK);
    CHECK(addr.port == 9590);
    CHECK(addr.ip[0] == 0x20);
    CHECK(addr.ip[1] == 0x01);
}

TEST_CASE("TimestampedAddress - Construction", "[network][protocol]") {
    SECTION("Default constructor") {
        TimestampedAddress taddr;
        CHECK(taddr.timestamp == 0);
        CHECK(taddr.address.services == 0);
        CHECK(taddr.address.port == 0);
    }

    SECTION("Parameterized constructor") {
        NetworkAddress addr = NetworkAddress::from_ipv4(NODE_NETWORK, 0xC0A80101, 9590);
        TimestampedAddress taddr(1234567890, addr);

        CHECK(taddr.timestamp == 1234567890);
        CHECK(taddr.address.services == NODE_NETWORK);
        CHECK(taddr.address.port == 9590);
        CHECK(taddr.address.is_ipv4());
    }
}

TEST_CASE("ServiceFlags - Values", "[network][protocol]") {
    SECTION("Service flag values") {
        CHECK(NODE_NONE == 0);
        CHECK(NODE_NETWORK == 1);
    }

    SECTION("Service flags can be combined") {
        uint64_t combined = NODE_NETWORK | NODE_NONE;
        CHECK(combined == NODE_NETWORK);

        uint64_t flags = NODE_NETWORK;
        CHECK((flags & NODE_NETWORK) != 0);
        CHECK((flags & NODE_NONE) == 0);
    }
}

TEST_CASE("Protocol limits - Security constants", "[network][protocol]") {
    SECTION("Message size limits") {
        CHECK(MAX_SIZE == 0x02000000); // 32 MB
        CHECK(MAX_PROTOCOL_MESSAGE_LENGTH == 8010000); // 8.01 MB (fits MAX_HEADERS_SIZE)
        CHECK(DEFAULT_RECV_FLOOD_SIZE == 10 * 1000 * 1000); // 10 MB
    }

    SECTION("Protocol-specific limits") {
        CHECK(MAX_LOCATOR_SZ == 101);
        CHECK(MAX_HEADERS_SIZE == 80000);  // ~22 years @ 10 blocks/day
        CHECK(MAX_ADDR_SIZE == 1000);
    }

    SECTION("Timeouts are reasonable") {
        CHECK(VERSION_HANDSHAKE_TIMEOUT_SEC == 60);
        CHECK(PING_INTERVAL_SEC == 120);
        CHECK(PING_TIMEOUT_SEC == 20 * 60);
        CHECK(INACTIVITY_TIMEOUT_SEC == 20 * 60);
    }

    SECTION("Time validation") {
        CHECK(unicity::validation::MAX_FUTURE_BLOCK_TIME == 10 * 60); // 10 minutes
    }
}

TEST_CASE("Protocol commands - String constants", "[network][protocol]") {
    SECTION("Command strings are valid") {
        CHECK(std::string(commands::VERSION) == "version");
        CHECK(std::string(commands::VERACK) == "verack");
        CHECK(std::string(commands::GETHEADERS) == "getheaders");
        CHECK(std::string(commands::HEADERS) == "headers");
// SENDHEADERS not supported in this implementation
        CHECK(std::string(commands::PING) == "ping");
        CHECK(std::string(commands::PONG) == "pong");
    }

    SECTION("Command strings fit in COMMAND_SIZE") {
        CHECK(std::strlen(commands::VERSION) <= COMMAND_SIZE);
        CHECK(std::strlen(commands::VERACK) <= COMMAND_SIZE);
        CHECK(std::strlen(commands::GETHEADERS) <= COMMAND_SIZE);
// SENDHEADERS not supported; no length check
    }
}

// ============================================================================
// NetworkAddress::from_string tests
// ============================================================================

TEST_CASE("NetworkAddress::from_string - IPv4 addresses", "[network][protocol][from_string]") {
    SECTION("Valid IPv4 address") {
        auto addr = NetworkAddress::from_string("192.168.1.100", 9590);
        CHECK_FALSE(addr.is_zero());
        CHECK(addr.is_ipv4());
        CHECK(addr.port == 9590);
        CHECK(addr.services == NODE_NETWORK);  // Default
        // Verify IPv4-mapped format
        CHECK(addr.ip[10] == 0xff);
        CHECK(addr.ip[11] == 0xff);
        CHECK(addr.ip[12] == 192);
        CHECK(addr.ip[13] == 168);
        CHECK(addr.ip[14] == 1);
        CHECK(addr.ip[15] == 100);
    }

    SECTION("Loopback address") {
        auto addr = NetworkAddress::from_string("127.0.0.1", 9590);
        CHECK_FALSE(addr.is_zero());
        CHECK(addr.is_ipv4());
        CHECK(addr.ip[12] == 127);
        CHECK(addr.ip[13] == 0);
        CHECK(addr.ip[14] == 0);
        CHECK(addr.ip[15] == 1);
    }

    SECTION("Custom services flag") {
        auto addr = NetworkAddress::from_string("10.0.0.1", 9590, 0);
        CHECK(addr.services == 0);

        auto addr2 = NetworkAddress::from_string("10.0.0.2", 9590, NODE_NETWORK);
        CHECK(addr2.services == NODE_NETWORK);
    }

    SECTION("Broadcast address") {
        auto addr = NetworkAddress::from_string("255.255.255.255", 9590);
        CHECK_FALSE(addr.is_zero());
        CHECK(addr.is_ipv4());
        CHECK(addr.ip[12] == 255);
        CHECK(addr.ip[13] == 255);
        CHECK(addr.ip[14] == 255);
        CHECK(addr.ip[15] == 255);
    }
}

TEST_CASE("NetworkAddress::from_string - IPv6 addresses", "[network][protocol][from_string]") {
    SECTION("Valid IPv6 address") {
        auto addr = NetworkAddress::from_string("2001:db8::1", 9590);
        CHECK_FALSE(addr.is_zero());
        CHECK_FALSE(addr.is_ipv4());
        CHECK(addr.port == 9590);
        // Verify first bytes of 2001:db8::
        CHECK(addr.ip[0] == 0x20);
        CHECK(addr.ip[1] == 0x01);
        CHECK(addr.ip[2] == 0x0d);
        CHECK(addr.ip[3] == 0xb8);
    }

    SECTION("IPv6 loopback") {
        auto addr = NetworkAddress::from_string("::1", 9590);
        CHECK_FALSE(addr.is_zero());
        CHECK_FALSE(addr.is_ipv4());
        // All zeros except last byte
        for (int i = 0; i < 15; i++) {
            CHECK(addr.ip[i] == 0);
        }
        CHECK(addr.ip[15] == 1);
    }

    SECTION("Full IPv6 address") {
        auto addr = NetworkAddress::from_string("fe80:1234:5678:9abc:def0:1234:5678:9abc", 9590);
        CHECK_FALSE(addr.is_zero());
        CHECK_FALSE(addr.is_ipv4());
        CHECK(addr.ip[0] == 0xfe);
        CHECK(addr.ip[1] == 0x80);
    }
}

TEST_CASE("NetworkAddress::from_string - Invalid inputs", "[network][protocol][from_string]") {
    SECTION("Empty string returns zeroed address") {
        auto addr = NetworkAddress::from_string("", 9590);
        CHECK(addr.is_zero());
    }

    SECTION("Invalid format returns zeroed address") {
        auto addr = NetworkAddress::from_string("not.an.ip", 9590);
        CHECK(addr.is_zero());
    }

    SECTION("Incomplete IPv4 returns zeroed address") {
        auto addr = NetworkAddress::from_string("192.168.1", 9590);
        CHECK(addr.is_zero());
    }

    SECTION("Out of range IPv4 octet returns zeroed address") {
        auto addr = NetworkAddress::from_string("192.168.1.999", 9590);
        CHECK(addr.is_zero());
    }

    SECTION("Hostname returns zeroed address") {
        auto addr = NetworkAddress::from_string("example.com", 9590);
        CHECK(addr.is_zero());
    }

    SECTION("Negative IPv4 returns zeroed address") {
        auto addr = NetworkAddress::from_string("-1.0.0.1", 9590);
        CHECK(addr.is_zero());
    }
}

// ============================================================================
// NetworkAddress::to_string tests
// ============================================================================

TEST_CASE("NetworkAddress::to_string - IPv4 round-trip", "[network][protocol][tostring]") {
    SECTION("Basic IPv4") {
        auto addr = NetworkAddress::from_string("192.168.1.100", 9590);
        auto result = addr.to_string();
        REQUIRE(result.has_value());
        CHECK(*result == "192.168.1.100");
    }

    SECTION("Loopback") {
        auto addr = NetworkAddress::from_string("127.0.0.1", 9590);
        auto result = addr.to_string();
        REQUIRE(result.has_value());
        CHECK(*result == "127.0.0.1");
    }

    SECTION("Public IP") {
        auto addr = NetworkAddress::from_string("8.8.8.8", 9590);
        auto result = addr.to_string();
        REQUIRE(result.has_value());
        CHECK(*result == "8.8.8.8");
    }

    SECTION("from_ipv4 round-trip") {
        // 192.168.1.1 = 0xC0A80101
        uint32_t ipv4 = (192 << 24) | (168 << 16) | (1 << 8) | 1;
        auto addr = NetworkAddress::from_ipv4(NODE_NETWORK, ipv4, 9590);
        auto result = addr.to_string();
        REQUIRE(result.has_value());
        CHECK(*result == "192.168.1.1");
    }
}

TEST_CASE("NetworkAddress::to_string - IPv6 round-trip", "[network][protocol][tostring]") {
    SECTION("IPv6 loopback") {
        auto addr = NetworkAddress::from_string("::1", 9590);
        auto result = addr.to_string();
        REQUIRE(result.has_value());
        CHECK(*result == "::1");
    }

    SECTION("Documentation IPv6") {
        auto addr = NetworkAddress::from_string("2001:db8::1", 9590);
        auto result = addr.to_string();
        REQUIRE(result.has_value());
        CHECK(*result == "2001:db8::1");
    }
}

TEST_CASE("NetworkAddress::to_string - Zeroed address", "[network][protocol][tostring]") {
    SECTION("Zeroed address returns :: (IPv6 unspecified)") {
        NetworkAddress addr;  // Default constructor zeros everything
        auto result = addr.to_string();
        REQUIRE(result.has_value());
        CHECK(*result == "::");
    }
}

// ============================================================================
// NetworkAddress::is_zero tests
// ============================================================================

TEST_CASE("NetworkAddress::is_zero", "[network][protocol][is_zero]") {
    SECTION("Default constructed is zero") {
        NetworkAddress addr;
        CHECK(addr.is_zero());
    }

    SECTION("Valid IPv4 is not zero") {
        auto addr = NetworkAddress::from_string("192.168.1.1", 9590);
        CHECK_FALSE(addr.is_zero());
    }

    SECTION("Valid IPv6 is not zero") {
        auto addr = NetworkAddress::from_string("2001:db8::1", 9590);
        CHECK_FALSE(addr.is_zero());
    }

    SECTION("IPv6 loopback (::1) is not zero") {
        auto addr = NetworkAddress::from_string("::1", 9590);
        CHECK_FALSE(addr.is_zero());
    }

    SECTION("Parse failure results in zero") {
        auto addr = NetworkAddress::from_string("invalid", 9590);
        CHECK(addr.is_zero());
    }

    SECTION("from_ipv4 with non-zero is not zero") {
        auto addr = NetworkAddress::from_ipv4(0, 1, 9590);  // IP = 0.0.0.1
        CHECK_FALSE(addr.is_zero());
    }

    SECTION("from_ipv4 with 0.0.0.0 is not zero (has ffff prefix)") {
        // Even 0.0.0.0 has the ::ffff: prefix, so ip[10] and ip[11] are 0xff
        auto addr = NetworkAddress::from_ipv4(0, 0, 9590);
        CHECK_FALSE(addr.is_zero());  // Has ffff prefix
    }
}

// ============================================================================
// NetworkAddress::is_loopback tests
// ============================================================================

TEST_CASE("NetworkAddress::is_loopback", "[network][protocol][is_loopback]") {
    SECTION("IPv4 loopback 127.0.0.1") {
        auto addr = NetworkAddress::from_string("127.0.0.1", 9590);
        CHECK(addr.is_loopback());
    }

    SECTION("IPv4 loopback 127.255.255.255") {
        auto addr = NetworkAddress::from_string("127.255.255.255", 9590);
        CHECK(addr.is_loopback());
    }

    SECTION("IPv6 loopback ::1") {
        auto addr = NetworkAddress::from_string("::1", 9590);
        CHECK(addr.is_loopback());
    }

    SECTION("Non-loopback IPv4") {
        auto addr = NetworkAddress::from_string("192.168.1.1", 9590);
        CHECK_FALSE(addr.is_loopback());
    }

    SECTION("Non-loopback IPv6") {
        auto addr = NetworkAddress::from_string("2001:db8::1", 9590);
        CHECK_FALSE(addr.is_loopback());
    }
}

// ============================================================================
// NetworkAddress::is_routable tests
// ============================================================================

TEST_CASE("NetworkAddress::is_routable - routable addresses", "[network][protocol][is_routable]") {
    SECTION("Public IPv4") {
        auto addr = NetworkAddress::from_string("8.8.8.8", 9590);
        CHECK(addr.is_routable());
    }

    SECTION("Public IPv4 edge case") {
        auto addr = NetworkAddress::from_string("1.1.1.1", 9590);
        CHECK(addr.is_routable());
    }

    SECTION("Public IPv6") {
        // Use a real-looking public IPv6 (not documentation range)
        auto addr = NetworkAddress::from_string("2607:f8b0:4004:800::200e", 9590);
        CHECK(addr.is_routable());
    }
}

TEST_CASE("NetworkAddress::is_routable - non-routable addresses", "[network][protocol][is_routable]") {
    SECTION("Private 10.x.x.x (RFC 1918)") {
        auto addr = NetworkAddress::from_string("10.0.0.1", 9590);
        CHECK_FALSE(addr.is_routable());
    }

    SECTION("Private 172.16.x.x (RFC 1918)") {
        auto addr = NetworkAddress::from_string("172.16.0.1", 9590);
        CHECK_FALSE(addr.is_routable());
    }

    SECTION("Private 192.168.x.x (RFC 1918)") {
        auto addr = NetworkAddress::from_string("192.168.1.1", 9590);
        CHECK_FALSE(addr.is_routable());
    }

    SECTION("Loopback 127.x.x.x") {
        auto addr = NetworkAddress::from_string("127.0.0.1", 9590);
        CHECK_FALSE(addr.is_routable());
    }

    SECTION("Link-local 169.254.x.x (RFC 3927)") {
        auto addr = NetworkAddress::from_string("169.254.1.1", 9590);
        CHECK_FALSE(addr.is_routable());
    }

    SECTION("CGNAT 100.64.x.x (RFC 6598)") {
        auto addr = NetworkAddress::from_string("100.64.0.1", 9590);
        CHECK_FALSE(addr.is_routable());
    }

    SECTION("Documentation 192.0.2.x (RFC 5737)") {
        auto addr = NetworkAddress::from_string("192.0.2.1", 9590);
        CHECK_FALSE(addr.is_routable());
    }

    SECTION("Multicast 224.x.x.x") {
        auto addr = NetworkAddress::from_string("224.0.0.1", 9590);
        CHECK_FALSE(addr.is_routable());
    }

    SECTION("Reserved 240.x.x.x") {
        auto addr = NetworkAddress::from_string("240.0.0.1", 9590);
        CHECK_FALSE(addr.is_routable());
    }

    SECTION("Broadcast 255.255.255.255") {
        auto addr = NetworkAddress::from_string("255.255.255.255", 9590);
        CHECK_FALSE(addr.is_routable());
    }

    SECTION("IPv6 loopback ::1") {
        auto addr = NetworkAddress::from_string("::1", 9590);
        CHECK_FALSE(addr.is_routable());
    }

    SECTION("IPv6 link-local fe80::") {
        auto addr = NetworkAddress::from_string("fe80::1", 9590);
        CHECK_FALSE(addr.is_routable());
    }

    SECTION("IPv6 unique local fc00::") {
        auto addr = NetworkAddress::from_string("fc00::1", 9590);
        CHECK_FALSE(addr.is_routable());
    }

    SECTION("IPv6 documentation 2001:db8::") {
        auto addr = NetworkAddress::from_string("2001:db8::1", 9590);
        CHECK_FALSE(addr.is_routable());
    }

    SECTION("Zeroed address") {
        NetworkAddress addr;
        CHECK_FALSE(addr.is_routable());
    }
}

// ============================================================================
// NetworkAddress::get_netgroup tests
// ============================================================================

TEST_CASE("NetworkAddress::get_netgroup", "[network][protocol][get_netgroup]") {
    SECTION("IPv4 netgroup is /16 prefix") {
        auto addr = NetworkAddress::from_string("192.168.1.100", 9590);
        CHECK(addr.get_netgroup() == "192.168");
    }

    SECTION("Different IPs in same /16 have same netgroup") {
        auto addr1 = NetworkAddress::from_string("10.20.1.1", 9590);
        auto addr2 = NetworkAddress::from_string("10.20.255.255", 9590);
        CHECK(addr1.get_netgroup() == addr2.get_netgroup());
        CHECK(addr1.get_netgroup() == "10.20");
    }

    SECTION("Different /16 have different netgroups") {
        auto addr1 = NetworkAddress::from_string("192.168.1.1", 9590);
        auto addr2 = NetworkAddress::from_string("192.169.1.1", 9590);
        CHECK(addr1.get_netgroup() != addr2.get_netgroup());
    }

    SECTION("IPv6 netgroup is /32 prefix") {
        auto addr = NetworkAddress::from_string("2001:db8:1234:5678::1", 9590);
        CHECK(addr.get_netgroup() == "2001:0db8");
    }

    SECTION("IPv4 loopback returns 'local'") {
        auto addr = NetworkAddress::from_string("127.0.0.1", 9590);
        CHECK(addr.get_netgroup() == "local");
    }

    SECTION("IPv6 loopback returns 'local'") {
        auto addr = NetworkAddress::from_string("::1", 9590);
        CHECK(addr.get_netgroup() == "local");
    }

    SECTION("Zeroed address returns empty") {
        NetworkAddress addr;
        CHECK(addr.get_netgroup() == "");
    }
}

// ============================================================================
// NetworkAddress comparison operator tests
// ============================================================================

TEST_CASE("NetworkAddress::operator== - identity is IP + port only", "[network][protocol][comparison]") {
    SECTION("Same IP and port are equal regardless of services") {
        auto addr1 = NetworkAddress::from_string("8.8.8.8", 9590, NODE_NETWORK);
        auto addr2 = NetworkAddress::from_string("8.8.8.8", 9590, NODE_NONE);
        CHECK(addr1 == addr2);  // services differs, but still equal
    }

    SECTION("Different IP are not equal") {
        auto addr1 = NetworkAddress::from_string("8.8.8.8", 9590);
        auto addr2 = NetworkAddress::from_string("8.8.4.4", 9590);
        CHECK_FALSE(addr1 == addr2);
    }

    SECTION("Different port are not equal") {
        auto addr1 = NetworkAddress::from_string("8.8.8.8", 9590);
        auto addr2 = NetworkAddress::from_string("8.8.8.8", 19590);
        CHECK_FALSE(addr1 == addr2);
    }

    SECTION("IPv4 and IPv6 loopback are not equal") {
        auto addr1 = NetworkAddress::from_string("127.0.0.1", 9590);
        auto addr2 = NetworkAddress::from_string("::1", 9590);
        CHECK_FALSE(addr1 == addr2);
    }
}

TEST_CASE("NetworkAddress::operator< - ordering for std::set", "[network][protocol][comparison]") {
    SECTION("Orders by IP first") {
        auto addr1 = NetworkAddress::from_string("8.8.4.4", 9999);
        auto addr2 = NetworkAddress::from_string("8.8.8.8", 1111);
        CHECK(addr1 < addr2);  // 8.8.4.4 < 8.8.8.8 regardless of port
    }

    SECTION("Orders by port when IP is same") {
        auto addr1 = NetworkAddress::from_string("8.8.8.8", 1111);
        auto addr2 = NetworkAddress::from_string("8.8.8.8", 9999);
        CHECK(addr1 < addr2);  // Same IP, 1111 < 9999
    }

    SECTION("Services does not affect ordering") {
        auto addr1 = NetworkAddress::from_string("8.8.8.8", 9590, NODE_NONE);
        auto addr2 = NetworkAddress::from_string("8.8.8.8", 9590, NODE_NETWORK);
        // Neither should be less than the other (they're equal)
        CHECK_FALSE(addr1 < addr2);
        CHECK_FALSE(addr2 < addr1);
    }

    SECTION("std::set deduplicates by IP + port") {
        std::set<NetworkAddress> addrs;
        addrs.insert(NetworkAddress::from_string("8.8.8.8", 9590, NODE_NETWORK));
        addrs.insert(NetworkAddress::from_string("8.8.8.8", 9590, NODE_NONE));  // Same IP:port, different services
        CHECK(addrs.size() == 1);  // Should deduplicate
    }
}
