#include "catch_amalgamated.hpp"
#include "util/netaddress.hpp"

using namespace unicity::util;

TEST_CASE("ValidateAndNormalizeIP", "[netaddress]") {
    // Valid IPv4
    auto ip1 = ValidateAndNormalizeIP("192.168.1.1");
    REQUIRE(ip1.has_value());
    CHECK(*ip1 == "192.168.1.1");

    // Valid IPv6
    auto ip2 = ValidateAndNormalizeIP("2001:db8::1");
    REQUIRE(ip2.has_value());
    CHECK(*ip2 == "2001:db8::1");

    // IPv4-mapped IPv6
    auto ip3 = ValidateAndNormalizeIP("::ffff:192.168.1.1");
    REQUIRE(ip3.has_value());
    CHECK(*ip3 == "192.168.1.1"); // Should be normalized

    // Invalid
    CHECK_FALSE(ValidateAndNormalizeIP("invalid").has_value());
    CHECK_FALSE(ValidateAndNormalizeIP("").has_value());
    CHECK_FALSE(ValidateAndNormalizeIP("256.256.256.256").has_value());
}

TEST_CASE("ParseIPPort", "[netaddress]") {
    std::string ip;
    uint16_t port;

    // IPv4
    CHECK(ParseIPPort("192.168.1.1:9590", ip, port));
    CHECK(ip == "192.168.1.1");
    CHECK(port == 9590);

    // IPv6
    CHECK(ParseIPPort("[2001:db8::1]:9590", ip, port));
    CHECK(ip == "2001:db8::1");
    CHECK(port == 9590);

    // Invalid
    CHECK_FALSE(ParseIPPort("192.168.1.1", ip, port)); // Missing port
    CHECK_FALSE(ParseIPPort("192.168.1.1:", ip, port)); // Empty port
    CHECK_FALSE(ParseIPPort(":9590", ip, port)); // Missing IP
    CHECK_FALSE(ParseIPPort("invalid:9590", ip, port)); // Invalid IP
}

TEST_CASE("RFC Checks", "[netaddress]") {
    // RFC1918 - Private IPv4
    CHECK(IsRFC1918("10.0.0.1"));
    CHECK(IsRFC1918("172.16.0.1"));
    CHECK(IsRFC1918("192.168.1.1"));
    CHECK_FALSE(IsRFC1918("8.8.8.8"));

    // RFC2544 - Benchmark
    CHECK(IsRFC2544("198.18.0.1"));
    CHECK_FALSE(IsRFC2544("198.17.0.1"));

    // RFC3927 - Link-local IPv4
    CHECK(IsRFC3927("169.254.1.1"));
    CHECK_FALSE(IsRFC3927("169.253.1.1"));

    // RFC6598 - Shared CGNAT
    CHECK(IsRFC6598("100.64.0.1"));
    CHECK_FALSE(IsRFC6598("100.63.0.1"));

    // RFC5737 - Documentation IPv4
    CHECK(IsRFC5737("192.0.2.1"));
    CHECK(IsRFC5737("198.51.100.1"));
    CHECK(IsRFC5737("203.0.113.1"));
    CHECK_FALSE(IsRFC5737("192.0.3.1"));

    // RFC3849 - Documentation IPv6
    CHECK(IsRFC3849("2001:0db8::1"));
    CHECK_FALSE(IsRFC3849("2001:0db9::1"));

    // RFC3964 - 6to4
    CHECK(IsRFC3964("2002::1"));
    CHECK_FALSE(IsRFC3964("2003::1"));

    // RFC4380 - Teredo
    CHECK(IsRFC4380("2001::1"));
    CHECK_FALSE(IsRFC4380("2001:1::1"));

    // RFC4862 - Link Local IPv6
    CHECK(IsRFC4862("fe80::1"));
    CHECK_FALSE(IsRFC4862("fe81::1"));

    // RFC4193 - Unique Local IPv6
    CHECK(IsRFC4193("fc00::1"));
    CHECK(IsRFC4193("fd00::1"));
    CHECK_FALSE(IsRFC4193("fb00::1"));

    // RFC4843 - ORCHID
    CHECK(IsRFC4843("2001:10::1"));
    CHECK_FALSE(IsRFC4843("2001:20::1"));  // This is ORCHIDv2, not ORCHID
}

TEST_CASE("IsRoutable - ORCHID and ORCHIDv2", "[netaddress]") {
    // RFC4843 - ORCHID (2001:10::/28)
    CHECK_FALSE(IsRoutable("2001:10::1"));
    CHECK_FALSE(IsRoutable("2001:1f::1"));  // Still in /28

    // RFC7343 - ORCHIDv2 (2001:20::/28)
    CHECK_FALSE(IsRoutable("2001:20::1"));
    CHECK_FALSE(IsRoutable("2001:2f::1"));  // Still in /28

    // Just outside the ranges
    CHECK(IsRoutable("2001:30::1"));  // After ORCHIDv2
}

TEST_CASE("IsLocal - 0.0.0.0/8 network", "[netaddress]") {
    // RFC 1122: 0.0.0.0/8 is "this network" - treated as local
    CHECK(IsLocal("0.0.0.0"));
    CHECK(IsLocal("0.0.0.1"));
    CHECK(IsLocal("0.255.255.255"));

    // These should NOT be local
    CHECK_FALSE(IsLocal("1.0.0.0"));
    CHECK_FALSE(IsLocal("8.8.8.8"));
}

TEST_CASE("IsRoutable - 0.0.0.0/8 is not routable", "[netaddress]") {
    CHECK_FALSE(IsRoutable("0.0.0.0"));
    CHECK_FALSE(IsRoutable("0.0.0.1"));
    CHECK_FALSE(IsRoutable("0.255.255.255"));
}

TEST_CASE("IsRoutable", "[netaddress]") {
    // Public IPs
    CHECK(IsRoutable("8.8.8.8"));
    CHECK(IsRoutable("2001:4860:4860::8888"));

    // Private/Reserved
    CHECK_FALSE(IsRoutable("10.0.0.1")); // RFC1918
    CHECK_FALSE(IsRoutable("127.0.0.1")); // Loopback
    CHECK_FALSE(IsRoutable("169.254.1.1")); // Link-local
    CHECK_FALSE(IsRoutable("::1")); // Loopback IPv6
    CHECK_FALSE(IsRoutable("fe80::1")); // Link-local IPv6
}

TEST_CASE("IsLocal", "[netaddress]") {
    CHECK(IsLocal("127.0.0.1"));
    CHECK(IsLocal("::1"));
    CHECK(IsLocal("169.254.1.1")); // Link-local is considered local
    CHECK(IsLocal("fe80::1")); // Link-local IPv6 is considered local
    
    CHECK_FALSE(IsLocal("8.8.8.8"));
}

TEST_CASE("IsPrivate", "[netaddress]") {
    // Note: This is NOT equivalent to Bitcoin Core's IsInternal() which checks for
    // Tor hidden service addresses (0xFD6B88C0 prefix). This checks for private ranges.
    CHECK(IsPrivate("10.0.0.1")); // RFC1918
    CHECK(IsPrivate("fc00::1")); // ULA (RFC4193)
    CHECK(IsPrivate("100.64.0.1")); // CGNAT (RFC6598)
    CHECK(IsPrivate("fe80::1")); // Link-local (RFC4862)

    CHECK_FALSE(IsPrivate("8.8.8.8")); // Public
    CHECK_FALSE(IsPrivate("2001:4860::8888")); // Public IPv6
}

// =============================================================================
// IPv6 COMPREHENSIVE TESTS
// =============================================================================

TEST_CASE("GetNetgroup IPv4", "[netaddress][netgroup]") {
    // IPv4 netgroup is /16 (first two octets)
    CHECK(GetNetgroup("192.168.1.1") == "192.168");
    CHECK(GetNetgroup("192.168.255.255") == "192.168");
    CHECK(GetNetgroup("10.0.0.1") == "10.0");
    CHECK(GetNetgroup("8.8.8.8") == "8.8");

    // Loopback is "local"
    CHECK(GetNetgroup("127.0.0.1") == "local");
    CHECK(GetNetgroup("127.255.255.255") == "local");

    // 0.0.0.0/8 is also "local"
    CHECK(GetNetgroup("0.0.0.0") == "local");
    CHECK(GetNetgroup("0.1.2.3") == "local");
}

TEST_CASE("GetNetgroup IPv6", "[netaddress][netgroup][ipv6]") {
    // IPv6 netgroup is /32 (first four bytes, formatted as xxxx:xxxx)
    CHECK(GetNetgroup("2001:db8::1") == "2001:0db8");
    CHECK(GetNetgroup("2001:db8:1234:5678::1") == "2001:0db8");
    CHECK(GetNetgroup("2001:4860:4860::8888") == "2001:4860");

    // Different /32 blocks
    CHECK(GetNetgroup("2a00:1450::1") == "2a00:1450");
    CHECK(GetNetgroup("2607:f8b0::1") == "2607:f8b0");

    // Same /32 block gives same netgroup
    CHECK(GetNetgroup("2001:db8::1") == GetNetgroup("2001:db8:ffff:ffff::1"));

    // Different /32 blocks give different netgroups
    CHECK(GetNetgroup("2001:db8::1") != GetNetgroup("2001:db9::1"));

    // Loopback is "local"
    CHECK(GetNetgroup("::1") == "local");
}

TEST_CASE("IPv6 Address Formats", "[netaddress][ipv6]") {
    // Compressed notation
    auto ip1 = ValidateAndNormalizeIP("2001:db8::1");
    REQUIRE(ip1.has_value());
    CHECK(*ip1 == "2001:db8::1");

    // Full notation (ASIO may normalize this)
    auto ip2 = ValidateAndNormalizeIP("2001:0db8:0000:0000:0000:0000:0000:0001");
    REQUIRE(ip2.has_value());
    // ASIO normalizes to compressed form
    CHECK((*ip2 == "2001:db8::1" || *ip2 == "2001:0db8:0000:0000:0000:0000:0000:0001"));

    // Mixed case should normalize
    auto ip3 = ValidateAndNormalizeIP("2001:DB8::1");
    REQUIRE(ip3.has_value());
    // ASIO normalizes to lowercase
    CHECK(*ip3 == "2001:db8::1");

    // Leading zeros compressed
    auto ip4 = ValidateAndNormalizeIP("2001:0db8:0:0:0:0:0:1");
    REQUIRE(ip4.has_value());

    // Invalid formats
    CHECK_FALSE(ValidateAndNormalizeIP("2001:db8:::1").has_value()); // Triple colon
    CHECK_FALSE(ValidateAndNormalizeIP("2001:db8:1").has_value()); // Too short without ::
    CHECK_FALSE(ValidateAndNormalizeIP("2001:gggg::1").has_value()); // Invalid hex
}

TEST_CASE("IPv6 Special Addresses", "[netaddress][ipv6]") {
    // Unspecified address
    auto unspec = ValidateAndNormalizeIP("::");
    REQUIRE(unspec.has_value());
    CHECK(*unspec == "::");
    CHECK_FALSE(IsRoutable("::"));

    // Loopback
    auto loopback = ValidateAndNormalizeIP("::1");
    REQUIRE(loopback.has_value());
    CHECK(*loopback == "::1");
    CHECK(IsLocal("::1"));
    CHECK_FALSE(IsRoutable("::1"));

    // Link-local
    CHECK(IsLocal("fe80::1"));
    CHECK_FALSE(IsRoutable("fe80::1"));
    CHECK(IsRFC4862("fe80::1"));

    // Unique local (ULA) - fc00::/7
    CHECK(IsRFC4193("fc00::1"));
    CHECK(IsRFC4193("fd00::1"));
    CHECK(IsPrivate("fc00::1"));
    CHECK_FALSE(IsRoutable("fc00::1"));

    // Multicast
    CHECK_FALSE(IsRoutable("ff02::1")); // All nodes
    CHECK_FALSE(IsRoutable("ff05::1")); // Site-local all nodes
}

TEST_CASE("IPv6 Transition Mechanisms", "[netaddress][ipv6]") {
    // 6to4 (RFC3964) - 2002::/16
    CHECK(IsRFC3964("2002::1"));
    CHECK(IsRFC3964("2002:c000:0204::1")); // Encapsulated 192.0.2.4
    CHECK_FALSE(IsRoutable("2002::1")); // 6to4 is not routable

    // Teredo (RFC4380) - 2001:0000::/32
    CHECK(IsRFC4380("2001::1"));
    CHECK(IsRFC4380("2001:0:4136:e378::1"));
    CHECK_FALSE(IsRoutable("2001::1"));

    // NAT64 (RFC6052) - 64:ff9b::/96
    CHECK(IsRFC6052("64:ff9b::192.0.2.1"));
    CHECK(IsRFC6052("64:ff9b::c000:0201")); // Same as above in hex

    // Documentation (RFC3849) - 2001:db8::/32
    CHECK(IsRFC3849("2001:db8::1"));
    CHECK(IsRFC3849("2001:db8:1234:5678:9abc:def0:1234:5678"));
    CHECK_FALSE(IsRoutable("2001:db8::1"));
}

TEST_CASE("IPv4-mapped IPv6 Addresses", "[netaddress][ipv6]") {
    // IPv4-mapped IPv6 (::ffff:0:0/96)
    auto mapped = ValidateAndNormalizeIP("::ffff:192.168.1.1");
    REQUIRE(mapped.has_value());
    // Should be normalized to pure IPv4
    CHECK(*mapped == "192.168.1.1");

    // Another format
    auto mapped2 = ValidateAndNormalizeIP("::ffff:c0a8:0101");
    REQUIRE(mapped2.has_value());
    CHECK(*mapped2 == "192.168.1.1");

    // Routable check should work on normalized address
    CHECK_FALSE(IsRoutable("::ffff:192.168.1.1")); // Private
    CHECK(IsRoutable("::ffff:8.8.8.8")); // Public
}

TEST_CASE("ParseIPPort IPv6 Edge Cases", "[netaddress][ipv6]") {
    std::string ip;
    uint16_t port;

    // Standard bracketed IPv6
    CHECK(ParseIPPort("[2001:db8::1]:9590", ip, port));
    CHECK(ip == "2001:db8::1");
    CHECK(port == 9590);

    // Full IPv6 in brackets
    CHECK(ParseIPPort("[2001:db8:85a3::8a2e:370:7334]:9590", ip, port));
    CHECK(ip == "2001:db8:85a3::8a2e:370:7334");
    CHECK(port == 9590);

    // Loopback
    CHECK(ParseIPPort("[::1]:9590", ip, port));
    CHECK(ip == "::1");
    CHECK(port == 9590);

    // Link-local with zone ID should fail (we don't support zone IDs)
    // CHECK_FALSE(ParseIPPort("[fe80::1%eth0]:9590", ip, port));

    // Invalid: IPv6 without brackets
    CHECK_FALSE(ParseIPPort("2001:db8::1:9590", ip, port));

    // Invalid: Missing closing bracket
    CHECK_FALSE(ParseIPPort("[2001:db8::1:9590", ip, port));

    // Invalid: Empty brackets
    CHECK_FALSE(ParseIPPort("[]:9590", ip, port));

    // Invalid: Missing port after bracket
    CHECK_FALSE(ParseIPPort("[2001:db8::1]", ip, port));
}

TEST_CASE("IsBadPort", "[netaddress]") {
    // Common service ports that ARE "bad" (in Bitcoin Core's list)
    CHECK(IsBadPort(22));   // SSH
    CHECK(IsBadPort(25));   // SMTP
    CHECK(IsBadPort(53));   // DNS
    CHECK(IsBadPort(3306)); // MySQL
    CHECK(IsBadPort(5432)); // PostgreSQL
    CHECK(IsBadPort(6667)); // IRC

    // HTTP/HTTPS are NOT in the bad port list
    CHECK_FALSE(IsBadPort(80));   // HTTP - allowed
    CHECK_FALSE(IsBadPort(443));  // HTTPS - allowed

    // Our ports should not be bad
    CHECK_FALSE(IsBadPort(9590));  // Bitcoin mainnet
    CHECK_FALSE(IsBadPort(19590)); // Bitcoin testnet
    CHECK_FALSE(IsBadPort(9590));  // Unicity

    // Edge cases
    CHECK_FALSE(IsBadPort(0));
    CHECK_FALSE(IsBadPort(65535));
}
