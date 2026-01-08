// Fuzz target for IPv4/IPv6 address parsing
// Tests ValidateAndNormalizeIP, ParseIPPort, and IsValidIPAddress
//
// Network address parsing is a common DoS vector and security boundary.
// Bugs in this code can:
// - Allow DoS via malformed addresses (infinite loops, unbounded allocation)
// - Enable ban evasion (IPv4-mapped normalization bypass)
// - Cause silent failures (accepted invalid addresses)
// - Trigger crashes (null pointer, buffer overflow, exception leaks)
//
// Target code:
// - src/util/netaddress.cpp (ValidateAndNormalizeIP, ParseIPPort)

#include "util/netaddress.hpp"
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <cstring>

using namespace unicity::util;

// FuzzInput: Parse structured fuzz data
class FuzzInput {
public:
    FuzzInput(const uint8_t *data, size_t size) : data_(data), size_(size), offset_(0) {}

    // Read a string of specified length
    std::string read_string(size_t len) {
        if (offset_ + len > size_) {
            return "";
        }
        std::string result(reinterpret_cast<const char*>(data_ + offset_), len);
        offset_ += len;
        return result;
    }

    // Read remaining data as string
    std::string read_remaining() {
        if (offset_ >= size_) {
            return "";
        }
        std::string result(reinterpret_cast<const char*>(data_ + offset_), size_ - offset_);
        offset_ = size_;
        return result;
    }

    template<typename T>
    T read() {
        if (offset_ + sizeof(T) > size_) {
            return T{};
        }
        T value;
        memcpy(&value, data_ + offset_, sizeof(T));
        offset_ += sizeof(T);
        return value;
    }

    bool has_bytes(size_t n) const {
        return offset_ + n <= size_;
    }

private:
    const uint8_t *data_;
    size_t size_;
    size_t offset_;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Need at least 2 bytes: 1 for length, 1 for data
    if (size < 2) return 0;

    FuzzInput input(data, size);

    // Read test mode selector
    uint8_t mode = input.read<uint8_t>();

    // CRITICAL TEST 1: ValidateAndNormalizeIP with arbitrary strings
    // Must handle: empty, very long, malformed, special chars, overflow, etc.
    if ((mode & 0x03) == 0) {
        std::string address = input.read_remaining();

        try {
            auto result = ValidateAndNormalizeIP(address);

            // CRITICAL: If it accepted the address, verify normalization is consistent
            if (result.has_value()) {
                auto result2 = ValidateAndNormalizeIP(*result);

                // Normalizing a normalized address should be idempotent
                if (!result2.has_value() || *result != *result2) {
                    // Non-idempotent normalization - BUG!
                    __builtin_trap();
                }

                // CRITICAL: If original was normalized, second normalization must match
                auto result3 = ValidateAndNormalizeIP(address);
                if (!result3.has_value() || *result != *result3) {
                    // Non-deterministic validation - BUG!
                    __builtin_trap();
                }
            }
        } catch (...) {
            // ValidateAndNormalizeIP should never throw (has exception handler)
            // If it throws, that's a BUG!
            __builtin_trap();
        }
    }

    // CRITICAL TEST 2: IsValidIPAddress consistency with ValidateAndNormalizeIP
    if ((mode & 0x03) == 1) {
        std::string address = input.read_remaining();

        try {
            bool is_valid = IsValidIPAddress(address);
            auto validated = ValidateAndNormalizeIP(address);

            // CRITICAL: IsValidIPAddress must agree with ValidateAndNormalizeIP
            if (is_valid != validated.has_value()) {
                // Inconsistent validation - BUG!
                __builtin_trap();
            }
        } catch (...) {
            // Should never throw
            __builtin_trap();
        }
    }

    // CRITICAL TEST 3: ParseIPPort with arbitrary strings
    if ((mode & 0x03) == 2) {
        std::string address_port = input.read_remaining();

        try {
            std::string out_ip;
            uint16_t out_port = 0;

            bool success = ParseIPPort(address_port, out_ip, out_port);

            if (success) {
                // CRITICAL: If parsing succeeded, IP must be valid
                if (!IsValidIPAddress(out_ip)) {
                    // ParseIPPort accepted invalid IP - BUG!
                    __builtin_trap();
                }

                // CRITICAL: Port must be in valid range (1-65535)
                // Note: Port 0 is technically invalid for network use
                // But we accept it here (fuzzer doesn't enforce semantic validity)

                // CRITICAL: Verify round-trip consistency
                // Re-parse the same string, should get same result
                std::string out_ip2;
                uint16_t out_port2 = 0;
                bool success2 = ParseIPPort(address_port, out_ip2, out_port2);

                if (!success2 || out_ip != out_ip2 || out_port != out_port2) {
                    // Non-deterministic parsing - BUG!
                    __builtin_trap();
                }
            }
        } catch (...) {
            // ParseIPPort should not throw (returns false on error)
            __builtin_trap();
        }
    }

    // CRITICAL TEST 4: IPv4-mapped IPv6 normalization bypass detection
    // Test that ::ffff:X.X.X.X is normalized to X.X.X.X (prevents ban evasion)
    if ((mode & 0x03) == 3 && size >= 20) {
        // Generate IPv4 address from fuzz data
        uint8_t oct1 = input.read<uint8_t>();
        uint8_t oct2 = input.read<uint8_t>();
        uint8_t oct3 = input.read<uint8_t>();
        uint8_t oct4 = input.read<uint8_t>();

        char ipv4[32];
        snprintf(ipv4, sizeof(ipv4), "%u.%u.%u.%u", oct1, oct2, oct3, oct4);

        char ipv4_mapped[64];
        snprintf(ipv4_mapped, sizeof(ipv4_mapped), "::ffff:%u.%u.%u.%u", oct1, oct2, oct3, oct4);

        try {
            auto result_v4 = ValidateAndNormalizeIP(ipv4);
            auto result_mapped = ValidateAndNormalizeIP(ipv4_mapped);

            // CRITICAL: Both should produce the same normalized form (prevents ban evasion)
            if (result_v4.has_value() && result_mapped.has_value()) {
                if (*result_v4 != *result_mapped) {
                    // IPv4-mapped normalization failed - SECURITY BUG!
                    __builtin_trap();
                }
            }
        } catch (...) {
            __builtin_trap();
        }
    }

    // CRITICAL TEST 5: ParseIPPort bracket handling (IPv6)
    // Test various bracket edge cases
    if ((mode & 0x0F) == 4) {
        std::string address_port = input.read_remaining();

        // Inject common bracket edge cases
        std::vector<std::string> test_cases;
        test_cases.push_back("[" + address_port + "]:1234");  // Wrap in brackets
        test_cases.push_back("[" + address_port);              // Missing closing bracket
        test_cases.push_back(address_port + "]");              // Missing opening bracket
        test_cases.push_back("[]:" + address_port);            // Empty brackets
        test_cases.push_back("[:" + address_port);             // Malformed

        for (const auto& test : test_cases) {
            try {
                std::string out_ip;
                uint16_t out_port = 0;
                ParseIPPort(test, out_ip, out_port);
                // Should not crash, may succeed or fail
            } catch (...) {
                // Should not throw
                __builtin_trap();
            }
        }
    }

    // CRITICAL TEST 6: Port number edge cases
    if ((mode & 0x0F) == 5 && size >= 10) {
        // Generate base IP
        std::string base_ip = "127.0.0.1";

        // Test edge case ports
        std::vector<std::string> test_cases;
        test_cases.push_back(base_ip + ":0");          // Port 0
        test_cases.push_back(base_ip + ":65535");      // Max port
        test_cases.push_back(base_ip + ":65536");      // Overflow
        test_cases.push_back(base_ip + ":99999");      // Large invalid
        test_cases.push_back(base_ip + ":-1");         // Negative
        test_cases.push_back(base_ip + ":1a");         // Trailing chars
        test_cases.push_back(base_ip + ": 1");         // Leading space
        test_cases.push_back(base_ip + ":1 ");         // Trailing space

        for (const auto& test : test_cases) {
            try {
                std::string out_ip;
                uint16_t out_port = 0;
                bool result = ParseIPPort(test, out_ip, out_port);

                // Verify invalid cases are rejected
                if (test.find("65536") != std::string::npos ||
                    test.find("99999") != std::string::npos ||
                    test.find("-1") != std::string::npos ||
                    test.find("1a") != std::string::npos ||
                    test.find(" ") != std::string::npos) {
                    if (result) {
                        // Accepted invalid port - BUG!
                        __builtin_trap();
                    }
                }
            } catch (...) {
                __builtin_trap();
            }
        }
    }

    // CRITICAL TEST 7: Multiple colon detection (unbracketed IPv6)
    if ((mode & 0x0F) == 6) {
        // IPv6 without brackets should be rejected by ParseIPPort
        std::string unbracketed_ipv6 = "2001:db8::1:9590";

        try {
            std::string out_ip;
            uint16_t out_port = 0;
            bool result = ParseIPPort(unbracketed_ipv6, out_ip, out_port);

            // This should be rejected (multiple colons without brackets)
            if (result) {
                // Accepted unbracketed IPv6 - BUG!
                __builtin_trap();
            }
        } catch (...) {
            __builtin_trap();
        }
    }

    // CRITICAL TEST 8: Empty string and null character handling
    if ((mode & 0x0F) == 7) {
        std::vector<std::string> test_cases;
        test_cases.push_back("");                          // Empty
        test_cases.push_back(std::string("\0", 1));       // Null char
        test_cases.push_back("127.0.0.1\0:9590");         // Embedded null
        test_cases.push_back(std::string(1000, 'A'));     // Very long

        for (const auto& test : test_cases) {
            try {
                auto result = ValidateAndNormalizeIP(test);
                // Empty should be rejected
                if (test.empty() && result.has_value()) {
                    __builtin_trap();
                }
            } catch (...) {
                __builtin_trap();
            }

            try {
                std::string out_ip;
                uint16_t out_port = 0;
                ParseIPPort(test, out_ip, out_port);
            } catch (...) {
                __builtin_trap();
            }
        }
    }

    // CRITICAL TEST 9: Verify all accepted addresses are valid after normalization
    if ((mode & 0x0F) == 8) {
        std::string address = input.read_remaining();

        try {
            auto normalized = ValidateAndNormalizeIP(address);
            if (normalized.has_value()) {
                // Re-validate the normalized form
                auto revalidated = ValidateAndNormalizeIP(*normalized);

                // Must still be valid
                if (!revalidated.has_value()) {
                    // Normalized form is invalid - BUG!
                    __builtin_trap();
                }

                // Must be byte-for-byte identical (fully normalized)
                if (*normalized != *revalidated) {
                    // Further normalization occurred - BUG!
                    __builtin_trap();
                }
            }
        } catch (...) {
            __builtin_trap();
        }
    }

    return 0;
}
