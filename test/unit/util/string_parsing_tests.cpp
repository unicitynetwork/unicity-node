// Unit tests for string parsing utilities
#include "catch_amalgamated.hpp"
#include "util/string_parsing.hpp"
#include <limits>

using namespace unicity::util;

TEST_CASE("SafeParseInt - valid inputs", "[util][string_parsing]") {
    SECTION("Parse valid positive integer") {
        auto result = SafeParseInt("42", 0, 100);
        REQUIRE(result.has_value());
        REQUIRE(*result == 42);
    }

    SECTION("Parse valid negative integer") {
        auto result = SafeParseInt("-50", -100, 100);
        REQUIRE(result.has_value());
        REQUIRE(*result == -50);
    }

    SECTION("Parse zero") {
        auto result = SafeParseInt("0", -10, 10);
        REQUIRE(result.has_value());
        REQUIRE(*result == 0);
    }

    SECTION("Parse at minimum bound") {
        auto result = SafeParseInt("0", 0, 100);
        REQUIRE(result.has_value());
        REQUIRE(*result == 0);
    }

    SECTION("Parse at maximum bound") {
        auto result = SafeParseInt("100", 0, 100);
        REQUIRE(result.has_value());
        REQUIRE(*result == 100);
    }

    SECTION("Parse large integer within bounds") {
        auto result = SafeParseInt("999999", 0, 1000000);
        REQUIRE(result.has_value());
        REQUIRE(*result == 999999);
    }
}

TEST_CASE("SafeParseInt - invalid inputs", "[util][string_parsing]") {
    SECTION("Empty string") {
        auto result = SafeParseInt("", 0, 100);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Non-numeric string") {
        auto result = SafeParseInt("abc", 0, 100);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Trailing characters") {
        auto result = SafeParseInt("42x", 0, 100);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Leading characters") {
        auto result = SafeParseInt("x42", 0, 100);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Mixed characters") {
        auto result = SafeParseInt("4x2", 0, 100);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Below minimum bound") {
        auto result = SafeParseInt("-1", 0, 100);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Above maximum bound") {
        auto result = SafeParseInt("101", 0, 100);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Overflow") {
        auto result = SafeParseInt("999999999999999999999", 0, 100);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Whitespace") {
        auto result = SafeParseInt(" 42", 0, 100);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Floating point") {
        auto result = SafeParseInt("42.5", 0, 100);
        REQUIRE_FALSE(result.has_value());
    }
}

TEST_CASE("SafeParsePort - valid inputs", "[util][string_parsing]") {
    SECTION("Parse minimum valid port") {
        auto result = SafeParsePort("1");
        REQUIRE(result.has_value());
        REQUIRE(*result == 1);
    }

    SECTION("Parse maximum valid port") {
        auto result = SafeParsePort("65535");
        REQUIRE(result.has_value());
        REQUIRE(*result == 65535);
    }

    SECTION("Parse common ports") {
        REQUIRE(*SafeParsePort("80") == 80);
        REQUIRE(*SafeParsePort("443") == 443);
        REQUIRE(*SafeParsePort("8080") == 8080);
        REQUIRE(*SafeParsePort("9590") == 9590);
    }
}

TEST_CASE("SafeParsePort - invalid inputs", "[util][string_parsing]") {
    SECTION("Port zero") {
        auto result = SafeParsePort("0");
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Negative port") {
        auto result = SafeParsePort("-1");
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Port too large") {
        auto result = SafeParsePort("65536");
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Empty string") {
        auto result = SafeParsePort("");
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Non-numeric") {
        auto result = SafeParsePort("abc");
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Trailing characters") {
        auto result = SafeParsePort("8080x");
        REQUIRE_FALSE(result.has_value());
    }
}

TEST_CASE("SafeParseInt64 - valid inputs", "[util][string_parsing]") {
    SECTION("Parse small positive number") {
        auto result = SafeParseInt64("100", 0, 1000);
        REQUIRE(result.has_value());
        REQUIRE(*result == 100);
    }

    SECTION("Parse large positive number") {
        auto result = SafeParseInt64("4294967295", 0, 4294967295LL);
        REQUIRE(result.has_value());
        REQUIRE(*result == 4294967295LL);
    }

    SECTION("Parse zero") {
        auto result = SafeParseInt64("0", 0, 1000);
        REQUIRE(result.has_value());
        REQUIRE(*result == 0);
    }

    SECTION("Parse negative number") {
        auto result = SafeParseInt64("-100", -1000, 1000);
        REQUIRE(result.has_value());
        REQUIRE(*result == -100);
    }

    SECTION("Parse at bounds") {
        auto result = SafeParseInt64("86400", 0, 1000000);
        REQUIRE(result.has_value());
        REQUIRE(*result == 86400);
    }
}

TEST_CASE("SafeParseInt64 - invalid inputs", "[util][string_parsing]") {
    SECTION("Empty string") {
        auto result = SafeParseInt64("", 0, 1000);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Below minimum") {
        auto result = SafeParseInt64("-1", 0, 1000);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Above maximum") {
        auto result = SafeParseInt64("4294967296", 0, 4294967295LL);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Overflow") {
        auto result = SafeParseInt64("999999999999999999999", 0, INT64_MAX);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Trailing characters") {
        auto result = SafeParseInt64("100x", 0, 1000);
        REQUIRE_FALSE(result.has_value());
    }
}

TEST_CASE("IsValidHex - valid inputs", "[util][string_parsing]") {
    SECTION("Lowercase hex") {
        REQUIRE(IsValidHex("deadbeef"));
        REQUIRE(IsValidHex("0123456789abcdef"));
    }

    SECTION("Uppercase hex") {
        REQUIRE(IsValidHex("DEADBEEF"));
        REQUIRE(IsValidHex("0123456789ABCDEF"));
    }

    SECTION("Mixed case hex") {
        REQUIRE(IsValidHex("DeAdBeEf"));
        REQUIRE(IsValidHex("0123456789AbCdEf"));
    }

    SECTION("Single character") {
        REQUIRE(IsValidHex("a"));
        REQUIRE(IsValidHex("F"));
        REQUIRE(IsValidHex("0"));
    }

    SECTION("Very long hex string") {
        std::string long_hex(1000, 'a');
        REQUIRE(IsValidHex(long_hex));
    }
}

TEST_CASE("IsValidHex - invalid inputs", "[util][string_parsing]") {
    SECTION("Empty string") {
        REQUIRE_FALSE(IsValidHex(""));
    }

    SECTION("Non-hex characters") {
        REQUIRE_FALSE(IsValidHex("xyz"));
        REQUIRE_FALSE(IsValidHex("g"));
        REQUIRE_FALSE(IsValidHex("deadbeefg"));
    }

    SECTION("Special characters") {
        REQUIRE_FALSE(IsValidHex("dead-beef"));
        REQUIRE_FALSE(IsValidHex("dead beef"));
        REQUIRE_FALSE(IsValidHex("0x123"));
    }

    SECTION("Mixed valid and invalid") {
        REQUIRE_FALSE(IsValidHex("123xyz"));
        REQUIRE_FALSE(IsValidHex("abc!def"));
    }
}

TEST_CASE("SafeParseHash - valid inputs", "[util][string_parsing]") {
    SECTION("Valid 64-character hex hash") {
        std::string hash = "0000000000000000000000000000000000000000000000000000000000000000";
        auto result = SafeParseHash(hash);
        REQUIRE(result.has_value());
    }

    SECTION("Valid hash with mixed case") {
        std::string hash = "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF";
        auto result = SafeParseHash(hash);
        REQUIRE(result.has_value());
    }

    SECTION("Valid hash all F's") {
        std::string hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        auto result = SafeParseHash(hash);
        REQUIRE(result.has_value());
    }

    SECTION("Valid hash typical pattern") {
        std::string hash = "00000000000000000001e3d0c625c15b9e7e8d9f3c0b2a1f8e7d6c5b4a3d2e1f";
        auto result = SafeParseHash(hash);
        REQUIRE(result.has_value());
    }
}

TEST_CASE("SafeParseHash - invalid inputs", "[util][string_parsing]") {
    SECTION("Empty string") {
        auto result = SafeParseHash("");
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Too short") {
        std::string hash = "123";
        auto result = SafeParseHash(hash);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("63 characters (one short)") {
        std::string hash = "000000000000000000000000000000000000000000000000000000000000000";
        auto result = SafeParseHash(hash);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("65 characters (one too long)") {
        std::string hash = "00000000000000000000000000000000000000000000000000000000000000000";
        auto result = SafeParseHash(hash);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Invalid hex characters") {
        std::string hash = "000000000000000000000000000000000000000000000000000000000000000g";
        auto result = SafeParseHash(hash);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Special characters") {
        std::string hash = "0000000000000000000000000000000000000000000000000000000000000-00";
        auto result = SafeParseHash(hash);
        REQUIRE_FALSE(result.has_value());
    }
}

TEST_CASE("EscapeJSONString - basic escaping", "[util][string_parsing]") {
    SECTION("No escaping needed") {
        REQUIRE(EscapeJSONString("hello") == "hello");
        REQUIRE(EscapeJSONString("world123") == "world123");
    }

    SECTION("Escape double quote") {
        REQUIRE(EscapeJSONString("hello\"world") == "hello\\\"world");
    }

    SECTION("Escape backslash") {
        REQUIRE(EscapeJSONString("hello\\world") == "hello\\\\world");
    }

    SECTION("Escape newline") {
        REQUIRE(EscapeJSONString("hello\nworld") == "hello\\nworld");
    }

    SECTION("Escape carriage return") {
        REQUIRE(EscapeJSONString("hello\rworld") == "hello\\rworld");
    }

    SECTION("Escape tab") {
        REQUIRE(EscapeJSONString("hello\tworld") == "hello\\tworld");
    }

    SECTION("Escape backspace") {
        REQUIRE(EscapeJSONString("hello\bworld") == "hello\\bworld");
    }

    SECTION("Escape form feed") {
        REQUIRE(EscapeJSONString("hello\fworld") == "hello\\fworld");
    }

    SECTION("Multiple escapes") {
        REQUIRE(EscapeJSONString("\"hello\"\n\"world\"") == "\\\"hello\\\"\\n\\\"world\\\"");
    }

    SECTION("Empty string") {
        REQUIRE(EscapeJSONString("") == "");
    }
}

TEST_CASE("EscapeJSONString - control characters", "[util][string_parsing]") {
    SECTION("Control character below 0x20") {
        std::string input = "\x01\x02\x03";
        std::string output = EscapeJSONString(input);
        REQUIRE(output == "\\u0001\\u0002\\u0003");
    }

    SECTION("Mixed control and normal") {
        std::string input = "hello\x01world";
        std::string output = EscapeJSONString(input);
        REQUIRE(output == "hello\\u0001world");
    }
}

TEST_CASE("JsonError - format validation", "[util][string_parsing]") {
    SECTION("Simple error message") {
        std::string result = JsonError("Test error");
        REQUIRE(result == "{\"error\":\"Test error\"}\n");
    }

    SECTION("Error with special characters") {
        std::string result = JsonError("Error: \"invalid\"");
        REQUIRE(result == "{\"error\":\"Error: \\\"invalid\\\"\"}\n");
    }

    SECTION("Error with newline") {
        std::string result = JsonError("Line1\nLine2");
        REQUIRE(result == "{\"error\":\"Line1\\nLine2\"}\n");
    }

    SECTION("Empty error message") {
        std::string result = JsonError("");
        REQUIRE(result == "{\"error\":\"\"}\n");
    }

    SECTION("Error with backslash") {
        std::string result = JsonError("Path: C:\\test");
        REQUIRE(result == "{\"error\":\"Path: C:\\\\test\"}\n");
    }
}

TEST_CASE("JsonSuccess - format validation", "[util][string_parsing]") {
    SECTION("Simple success message") {
        std::string result = JsonSuccess("OK");
        REQUIRE(result == "{\"result\":\"OK\"}\n");
    }

    SECTION("Success with special characters") {
        std::string result = JsonSuccess("Status: \"done\"");
        REQUIRE(result == "{\"result\":\"Status: \\\"done\\\"\"}\n");
    }

    SECTION("Success with newline") {
        std::string result = JsonSuccess("Line1\nLine2");
        REQUIRE(result == "{\"result\":\"Line1\\nLine2\"}\n");
    }

    SECTION("Empty success message") {
        std::string result = JsonSuccess("");
        REQUIRE(result == "{\"result\":\"\"}\n");
    }
}

TEST_CASE("SafeParse - edge cases", "[util][string_parsing]") {
    SECTION("Leading zeros") {
        auto result = SafeParseInt("0042", 0, 100);
        REQUIRE(result.has_value());
        REQUIRE(*result == 42);
    }

    SECTION("Positive sign") {
        auto result = SafeParseInt("+42", 0, 100);
        REQUIRE(result.has_value());
        REQUIRE(*result == 42);
    }

    SECTION("Multiple signs") {
        auto result = SafeParseInt("--42", -100, 100);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Hexadecimal notation") {
        auto result = SafeParseInt("0x10", 0, 100);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Scientific notation") {
        auto result = SafeParseInt64("1e10", 0, INT64_MAX);
        REQUIRE_FALSE(result.has_value());
    }
}
