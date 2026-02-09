// Unit tests for network address parsing utilities
#include "catch_amalgamated.hpp"
#include "util/netaddress.hpp"

using namespace unicity::util;

TEST_CASE("IsValidIPAddress - valid IPv4", "[util][netaddress]") {
    SECTION("Standard IPv4 addresses") {
        REQUIRE(IsValidIPAddress("192.168.1.1"));
        REQUIRE(IsValidIPAddress("10.0.0.1"));
        REQUIRE(IsValidIPAddress("172.16.0.1"));
        REQUIRE(IsValidIPAddress("8.8.8.8"));
    }

    SECTION("Loopback address") {
        REQUIRE(IsValidIPAddress("127.0.0.1"));
    }

    SECTION("Broadcast address") {
        REQUIRE(IsValidIPAddress("255.255.255.255"));
    }

    SECTION("Zero address") {
        REQUIRE(IsValidIPAddress("0.0.0.0"));
    }

    SECTION("Edge case octets") {
        REQUIRE(IsValidIPAddress("1.2.3.4"));
        REQUIRE(IsValidIPAddress("192.0.2.1"));
        REQUIRE(IsValidIPAddress("198.51.100.1"));
    }
}

TEST_CASE("IsValidIPAddress - valid IPv6", "[util][netaddress]") {
    SECTION("Full IPv6 addresses") {
        REQUIRE(IsValidIPAddress("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
        REQUIRE(IsValidIPAddress("fe80:0000:0000:0000:0204:61ff:fe9d:f156"));
    }

    SECTION("Compressed IPv6 addresses") {
        REQUIRE(IsValidIPAddress("2001:db8:85a3::8a2e:370:7334"));
        REQUIRE(IsValidIPAddress("fe80::204:61ff:fe9d:f156"));
        REQUIRE(IsValidIPAddress("::1"));
        REQUIRE(IsValidIPAddress("::"));
    }

    SECTION("Loopback") {
        REQUIRE(IsValidIPAddress("::1"));
    }

    SECTION("IPv4-mapped IPv6") {
        REQUIRE(IsValidIPAddress("::ffff:192.168.1.1"));
        REQUIRE(IsValidIPAddress("::ffff:c0a8:0101"));
    }

    SECTION("Link-local addresses") {
        REQUIRE(IsValidIPAddress("fe80::1"));
        REQUIRE(IsValidIPAddress("fe80::204:61ff:fe9d:f156"));
    }
}

TEST_CASE("IsValidIPAddress - invalid inputs", "[util][netaddress]") {
    SECTION("Empty string") {
        REQUIRE_FALSE(IsValidIPAddress(""));
    }

    SECTION("Invalid IPv4") {
        REQUIRE_FALSE(IsValidIPAddress("256.1.1.1"));
        REQUIRE_FALSE(IsValidIPAddress("1.1.1"));
        REQUIRE_FALSE(IsValidIPAddress("1.1.1.1.1"));
        REQUIRE_FALSE(IsValidIPAddress("abc.def.ghi.jkl"));
        REQUIRE_FALSE(IsValidIPAddress("192.168.-1.1"));
    }

    SECTION("Invalid IPv6") {
        REQUIRE_FALSE(IsValidIPAddress("gggg::1"));
        REQUIRE_FALSE(IsValidIPAddress("2001:db8:::1"));
        REQUIRE_FALSE(IsValidIPAddress("2001:db8:85a3::8a2e:370g:7334"));
    }

    SECTION("Hostnames") {
        REQUIRE_FALSE(IsValidIPAddress("localhost"));
        REQUIRE_FALSE(IsValidIPAddress("example.com"));
        REQUIRE_FALSE(IsValidIPAddress("www.google.com"));
    }

    SECTION("With port") {
        REQUIRE_FALSE(IsValidIPAddress("192.168.1.1:8080"));
        REQUIRE_FALSE(IsValidIPAddress("[::1]:8080"));
    }
}

TEST_CASE("ValidateAndNormalizeIP - IPv4", "[util][netaddress]") {
    SECTION("Standard IPv4 normalization") {
        auto result = ValidateAndNormalizeIP("192.168.1.1");
        REQUIRE(result.has_value());
        REQUIRE(*result == "192.168.1.1");
    }

    SECTION("Loopback normalization") {
        auto result = ValidateAndNormalizeIP("127.0.0.1");
        REQUIRE(result.has_value());
        REQUIRE(*result == "127.0.0.1");
    }
}

TEST_CASE("ValidateAndNormalizeIP - IPv6", "[util][netaddress]") {
    SECTION("Full form normalization") {
        auto result = ValidateAndNormalizeIP("2001:0db8:0000:0000:0000:0000:0000:0001");
        REQUIRE(result.has_value());
        REQUIRE(*result == "2001:db8::1");
    }

    SECTION("Already compressed") {
        auto result = ValidateAndNormalizeIP("2001:db8::1");
        REQUIRE(result.has_value());
        REQUIRE(*result == "2001:db8::1");
    }

    SECTION("Loopback") {
        auto result = ValidateAndNormalizeIP("::1");
        REQUIRE(result.has_value());
        REQUIRE(*result == "::1");
    }

    SECTION("Zero address") {
        auto result = ValidateAndNormalizeIP("::");
        REQUIRE(result.has_value());
        REQUIRE(*result == "::");
    }

    SECTION("IPv4-mapped IPv6 normalization") {
        auto result = ValidateAndNormalizeIP("::ffff:192.168.1.1");
        REQUIRE(result.has_value());
        // Should normalize to canonical form
        REQUIRE(result->find("192.168.1.1") != std::string::npos);
    }
}

TEST_CASE("ValidateAndNormalizeIP - invalid inputs", "[util][netaddress]") {
    SECTION("Empty string") {
        REQUIRE_FALSE(ValidateAndNormalizeIP("").has_value());
    }

    SECTION("Invalid IPv4") {
        REQUIRE_FALSE(ValidateAndNormalizeIP("256.1.1.1").has_value());
        REQUIRE_FALSE(ValidateAndNormalizeIP("1.1.1").has_value());
    }

    SECTION("Invalid IPv6") {
        REQUIRE_FALSE(ValidateAndNormalizeIP("gggg::1").has_value());
    }

    SECTION("Hostname") {
        REQUIRE_FALSE(ValidateAndNormalizeIP("example.com").has_value());
    }
}

TEST_CASE("ParseIPPort - IPv4 format", "[util][netaddress]") {
    SECTION("Standard IPv4:port") {
        std::string ip;
        uint16_t port;
        REQUIRE(ParseIPPort("192.168.1.1:8080", ip, port));
        REQUIRE(ip == "192.168.1.1");
        REQUIRE(port == 8080);
    }

    SECTION("Loopback with port") {
        std::string ip;
        uint16_t port;
        REQUIRE(ParseIPPort("127.0.0.1:9590", ip, port));
        REQUIRE(ip == "127.0.0.1");
        REQUIRE(port == 9590);
    }

    SECTION("Minimum port") {
        std::string ip;
        uint16_t port;
        REQUIRE(ParseIPPort("10.0.0.1:1", ip, port));
        REQUIRE(ip == "10.0.0.1");
        REQUIRE(port == 1);
    }

    SECTION("Maximum port") {
        std::string ip;
        uint16_t port;
        REQUIRE(ParseIPPort("10.0.0.1:65535", ip, port));
        REQUIRE(ip == "10.0.0.1");
        REQUIRE(port == 65535);
    }

    SECTION("Common ports") {
        std::string ip;
        uint16_t port;

        REQUIRE(ParseIPPort("8.8.8.8:53", ip, port));
        REQUIRE(port == 53);

        REQUIRE(ParseIPPort("1.1.1.1:80", ip, port));
        REQUIRE(port == 80);

        REQUIRE(ParseIPPort("192.168.1.1:443", ip, port));
        REQUIRE(port == 443);
    }
}

TEST_CASE("ParseIPPort - IPv6 format", "[util][netaddress]") {
    SECTION("Bracketed IPv6 with port") {
        std::string ip;
        uint16_t port;
        REQUIRE(ParseIPPort("[2001:db8::1]:8080", ip, port));
        REQUIRE(ip == "2001:db8::1");
        REQUIRE(port == 8080);
    }

    SECTION("Loopback with port") {
        std::string ip;
        uint16_t port;
        REQUIRE(ParseIPPort("[::1]:9590", ip, port));
        REQUIRE(ip == "::1");
        REQUIRE(port == 9590);
    }

    SECTION("Full form IPv6 with port") {
        std::string ip;
        uint16_t port;
        REQUIRE(ParseIPPort("[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:9590", ip, port));
        REQUIRE(ip == "2001:db8:85a3::8a2e:370:7334");
        REQUIRE(port == 9590);
    }

    SECTION("Link-local with port") {
        std::string ip;
        uint16_t port;
        REQUIRE(ParseIPPort("[fe80::1]:8080", ip, port));
        REQUIRE(ip == "fe80::1");
        REQUIRE(port == 8080);
    }

    SECTION("IPv4-mapped IPv6 with port") {
        std::string ip;
        uint16_t port;
        REQUIRE(ParseIPPort("[::ffff:192.168.1.1]:8080", ip, port));
        REQUIRE(port == 8080);
    }
}

TEST_CASE("ParseIPPort - invalid formats", "[util][netaddress]") {
    std::string ip;
    uint16_t port;

    SECTION("Empty string") {
        REQUIRE_FALSE(ParseIPPort("", ip, port));
    }

    SECTION("IP without port") {
        REQUIRE_FALSE(ParseIPPort("192.168.1.1", ip, port));
        REQUIRE_FALSE(ParseIPPort("2001:db8::1", ip, port));
    }

    SECTION("Invalid port - zero") {
        REQUIRE_FALSE(ParseIPPort("192.168.1.1:0", ip, port));
    }

    SECTION("Invalid port - negative") {
        REQUIRE_FALSE(ParseIPPort("192.168.1.1:-1", ip, port));
    }

    SECTION("Invalid port - too large") {
        REQUIRE_FALSE(ParseIPPort("192.168.1.1:65536", ip, port));
        REQUIRE_FALSE(ParseIPPort("192.168.1.1:99999", ip, port));
    }

    SECTION("Invalid port - non-numeric") {
        REQUIRE_FALSE(ParseIPPort("192.168.1.1:abc", ip, port));
        REQUIRE_FALSE(ParseIPPort("192.168.1.1:80x", ip, port));
    }

    SECTION("Missing colon") {
        REQUIRE_FALSE(ParseIPPort("192.168.1.1 8080", ip, port));
    }

    SECTION("Multiple colons (IPv4)") {
        REQUIRE_FALSE(ParseIPPort("192.168.1.1:8080:9590", ip, port));
    }

    SECTION("IPv6 without brackets") {
        REQUIRE_FALSE(ParseIPPort("2001:db8::1:8080", ip, port));
    }

    SECTION("Mismatched brackets") {
        REQUIRE_FALSE(ParseIPPort("[2001:db8::1:8080", ip, port));
        REQUIRE_FALSE(ParseIPPort("2001:db8::1]:8080", ip, port));
    }

    SECTION("Invalid IPv4") {
        REQUIRE_FALSE(ParseIPPort("256.1.1.1:8080", ip, port));
        REQUIRE_FALSE(ParseIPPort("1.1.1:8080", ip, port));
    }

    SECTION("Invalid IPv6") {
        REQUIRE_FALSE(ParseIPPort("[gggg::1]:8080", ip, port));
        REQUIRE_FALSE(ParseIPPort("[2001:db8:::1]:8080", ip, port));
    }

    SECTION("Hostname instead of IP") {
        REQUIRE_FALSE(ParseIPPort("localhost:8080", ip, port));
        REQUIRE_FALSE(ParseIPPort("example.com:8080", ip, port));
    }

    SECTION("URL format") {
        REQUIRE_FALSE(ParseIPPort("http://192.168.1.1:8080", ip, port));
        REQUIRE_FALSE(ParseIPPort("192.168.1.1:8080/path", ip, port));
    }
}

TEST_CASE("ParseIPPort - edge cases", "[util][netaddress]") {
    std::string ip;
    uint16_t port;

    SECTION("Empty brackets") {
        REQUIRE_FALSE(ParseIPPort("[]:8080", ip, port));
    }

    SECTION("Whitespace") {
        REQUIRE_FALSE(ParseIPPort(" 192.168.1.1:8080", ip, port));
        REQUIRE_FALSE(ParseIPPort("192.168.1.1:8080 ", ip, port));
        REQUIRE_FALSE(ParseIPPort("192.168.1.1 : 8080", ip, port));
    }

    SECTION("Leading zeros in port") {
        REQUIRE(ParseIPPort("192.168.1.1:0080", ip, port));
        REQUIRE(port == 80);
    }

    SECTION("Extremely long invalid input") {
        std::string invalid(10000, 'x');
        REQUIRE_FALSE(ParseIPPort(invalid, ip, port));
    }
}

TEST_CASE("ParseIPPort - normalization", "[util][netaddress]") {
    std::string ip;
    uint16_t port;

    SECTION("IPv6 normalization in parsing") {
        REQUIRE(ParseIPPort("[2001:0db8:0000:0000:0000:0000:0000:0001]:8080", ip, port));
        REQUIRE(ip == "2001:db8::1");
        REQUIRE(port == 8080);
    }
}

TEST_CASE("Combined scenarios", "[util][netaddress]") {
    SECTION("Parse and validate multiple addresses") {
        std::vector<std::string> addresses = {
            "192.168.1.1:8080",
            "[::1]:9590",
            "10.0.0.1:443",
            "[2001:db8::1]:9590"
        };

        for (const auto& addr : addresses) {
            std::string ip;
            uint16_t port;
            REQUIRE(ParseIPPort(addr, ip, port));
            REQUIRE(IsValidIPAddress(ip));
            REQUIRE(port > 0);
            REQUIRE(port <= 65535);
        }
    }

    SECTION("Reject multiple invalid addresses") {
        std::vector<std::string> invalid = {
            "256.1.1.1:8080",
            "192.168.1.1",
            "[::1]",
            "example.com:8080",
            "192.168.1.1:99999",
            "[gggg::1]:8080"
        };

        for (const auto& addr : invalid) {
            std::string ip;
            uint16_t port;
            REQUIRE_FALSE(ParseIPPort(addr, ip, port));
        }
    }
}

// ============================================================================
// IsBadPort tests (Bitcoin Core parity: net.cpp IsBadPort)
// ============================================================================

TEST_CASE("IsBadPort - known bad ports", "[util][netaddress]") {
    SECTION("Well-known system service ports") {
        REQUIRE(IsBadPort(1));      // tcpmux
        REQUIRE(IsBadPort(7));      // echo
        REQUIRE(IsBadPort(21));     // ftp
        REQUIRE(IsBadPort(22));     // ssh
        REQUIRE(IsBadPort(23));     // telnet
        REQUIRE(IsBadPort(25));     // smtp
        REQUIRE(IsBadPort(53));     // domain (DNS)
    }

    SECTION("Mail-related ports") {
        REQUIRE(IsBadPort(110));    // pop3
        REQUIRE(IsBadPort(143));    // imap2
        REQUIRE(IsBadPort(465));    // smtp+ssl
        REQUIRE(IsBadPort(587));    // submission
        REQUIRE(IsBadPort(993));    // imaps
        REQUIRE(IsBadPort(995));    // pop3s
    }

    SECTION("Database ports") {
        REQUIRE(IsBadPort(3306));   // mysql
        REQUIRE(IsBadPort(5432));   // postgresql
        REQUIRE(IsBadPort(27017));  // mongodb
    }

    SECTION("IRC ports") {
        REQUIRE(IsBadPort(6665));   // irc (alt)
        REQUIRE(IsBadPort(6666));   // irc (alt)
        REQUIRE(IsBadPort(6667));   // irc (default)
        REQUIRE(IsBadPort(6668));   // irc (alt)
        REQUIRE(IsBadPort(6669));   // irc (alt)
        REQUIRE(IsBadPort(6697));   // irc+tls
    }

    SECTION("Other commonly abused ports") {
        REQUIRE(IsBadPort(5060));   // sip
        REQUIRE(IsBadPort(5061));   // sips
        REQUIRE(IsBadPort(5900));   // vnc
        REQUIRE(IsBadPort(6000));   // x11
        REQUIRE(IsBadPort(3389));   // rdp
    }
}

TEST_CASE("IsBadPort - allowed ports", "[util][netaddress]") {
    SECTION("Bitcoin standard ports") {
        REQUIRE_FALSE(IsBadPort(9590));   // Bitcoin mainnet
        REQUIRE_FALSE(IsBadPort(19590));  // Bitcoin testnet
        REQUIRE_FALSE(IsBadPort(18444));  // Bitcoin regtest
        REQUIRE_FALSE(IsBadPort(9590));   // Our default port
    }

    SECTION("Common web ports (not in bad list)") {
        REQUIRE_FALSE(IsBadPort(80));     // http - NOT in bad list
        REQUIRE_FALSE(IsBadPort(443));    // https - NOT in bad list
    }

    SECTION("Random high ports") {
        REQUIRE_FALSE(IsBadPort(12345));
        REQUIRE_FALSE(IsBadPort(50000));
        REQUIRE_FALSE(IsBadPort(65535));
    }

    SECTION("Port 0 (edge case)") {
        REQUIRE_FALSE(IsBadPort(0));      // Not in bad list (though invalid)
    }
}

TEST_CASE("IsBadPort - boundary conditions", "[util][netaddress]") {
    SECTION("Ports around FTP (20-21)") {
        REQUIRE_FALSE(IsBadPort(18));
        REQUIRE(IsBadPort(20));           // ftp data - BAD
        REQUIRE(IsBadPort(21));           // ftp access - BAD
        REQUIRE(IsBadPort(22));           // ssh - BAD
        REQUIRE(IsBadPort(23));           // telnet - BAD
    }

    SECTION("Ports around SMTP (25)") {
        REQUIRE_FALSE(IsBadPort(24));
        REQUIRE(IsBadPort(25));           // smtp - BAD
        REQUIRE_FALSE(IsBadPort(26));
    }

    SECTION("Ports around MySQL (3306)") {
        REQUIRE_FALSE(IsBadPort(3305));
        REQUIRE(IsBadPort(3306));         // mysql - BAD
        REQUIRE_FALSE(IsBadPort(3307));
    }
}
