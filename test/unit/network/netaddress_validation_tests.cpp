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
    CHECK(ParseIPPort("192.168.1.1:8333", ip, port));
    CHECK(ip == "192.168.1.1");
    CHECK(port == 8333);

    // IPv6
    CHECK(ParseIPPort("[2001:db8::1]:8333", ip, port));
    CHECK(ip == "2001:db8::1");
    CHECK(port == 8333);

    // Invalid
    CHECK_FALSE(ParseIPPort("192.168.1.1", ip, port)); // Missing port
    CHECK_FALSE(ParseIPPort("192.168.1.1:", ip, port)); // Empty port
    CHECK_FALSE(ParseIPPort(":8333", ip, port)); // Missing IP
    CHECK_FALSE(ParseIPPort("invalid:8333", ip, port)); // Invalid IP
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

TEST_CASE("IsInternal", "[netaddress]") {
    CHECK(IsInternal("10.0.0.1")); // RFC1918
    CHECK(IsInternal("fc00::1")); // ULA
    
    CHECK_FALSE(IsInternal("8.8.8.8"));
}
