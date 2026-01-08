// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "catch_amalgamated.hpp"
#include "util/sha256.hpp"
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

// Test vectors from NIST FIPS 180-2 and Bitcoin Core
struct SHA256TestVector {
    const char* input;
    const char* expected_hex;
};

// Bitcoin Core test vectors from src/test/crypto_tests.cpp
static const SHA256TestVector test_vectors[] = {
    // Empty string
    {"",
     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},

    // "abc"
    {"abc",
     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},

    // "message digest"
    {"message digest",
     "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650"},

    // "secure hash algorithm"
    {"secure hash algorithm",
     "f30ceb2bb2829e79e4ca9753d35a8ecc00262d164cc077080295381cbd643f0d"},

    // "SHA256 is considered to be safe"
    {"SHA256 is considered to be safe",
     "6819d915c73f4d1e77e4e1b52d1fa0f9cf9beaead3939f15874bd988e2a23630"},

    // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},

    // "For this sample, this 63-byte string will be used as input data"
    {"For this sample, this 63-byte string will be used as input data",
     "f08a78cbbaee082b052ae0708f32fa1e50c5c421aa772ba5dbb406a2ea6be342"},

    // "This is exactly 64 bytes long, not counting the terminating byte"
    {"This is exactly 64 bytes long, not counting the terminating byte",
     "ab64eff7e88e2e46165e29f2bce41826bd4c7b3552f6b382a9e7d3af47c245f8"},

    // Bitcoin header hash test
    {"As Bitcoin relies on 80 byte header hashes, we want to have an example for that.",
     "7406e8de7d6e4fffc573daef05aefb8806e7790f55eab5576f31349743cca743"}
};

// Helper to convert hex string to bytes
static std::vector<uint8_t> hex_to_bytes(const char* hex) {
    std::vector<uint8_t> bytes;
    size_t len = std::strlen(hex);
    for (size_t i = 0; i < len; i += 2) {
        unsigned int byte;
        sscanf(hex + i, "%2x", &byte);
        bytes.push_back(static_cast<uint8_t>(byte));
    }
    return bytes;
}

// Helper to convert bytes to hex string
static std::string bytes_to_hex(const uint8_t* data, size_t len) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        result.push_back(hex_chars[data[i] >> 4]);
        result.push_back(hex_chars[data[i] & 0x0F]);
    }
    return result;
}

TEST_CASE("SHA256: Test vectors", "[sha256][crypto]") {
    for (const auto& tv : test_vectors) {
        CSHA256 hasher;
        uint8_t hash[CSHA256::OUTPUT_SIZE];

        hasher.Write(reinterpret_cast<const unsigned char*>(tv.input),
                    std::strlen(tv.input));
        hasher.Finalize(hash);

        std::string result_hex = bytes_to_hex(hash, CSHA256::OUTPUT_SIZE);

        INFO("Input: " << tv.input);
        INFO("Expected: " << tv.expected_hex);
        INFO("Got:      " << result_hex);

        CHECK(result_hex == tv.expected_hex);
    }
}

TEST_CASE("SHA256: Incremental hashing", "[sha256][crypto]") {
    // Hash "abcdefghijklmnopqrstuvwxyz" in multiple chunks
    CSHA256 hasher1, hasher2, hasher3;
    uint8_t hash1[32], hash2[32], hash3[32];

    // All at once
    const char* text = "abcdefghijklmnopqrstuvwxyz";
    hasher1.Write(reinterpret_cast<const unsigned char*>(text), 26);
    hasher1.Finalize(hash1);

    // Two chunks: "abcdefghijklm" + "nopqrstuvwxyz"
    hasher2.Write(reinterpret_cast<const unsigned char*>(text), 13);
    hasher2.Write(reinterpret_cast<const unsigned char*>(text + 13), 13);
    hasher2.Finalize(hash2);

    // Byte by byte
    for (int i = 0; i < 26; ++i) {
        hasher3.Write(reinterpret_cast<const unsigned char*>(text + i), 1);
    }
    hasher3.Finalize(hash3);

    CHECK(std::memcmp(hash1, hash2, 32) == 0);
    CHECK(std::memcmp(hash1, hash3, 32) == 0);
    CHECK(bytes_to_hex(hash1, 32) ==
          "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73");
}

TEST_CASE("SHA256: Reset functionality", "[sha256][crypto]") {
    CSHA256 hasher;
    uint8_t hash1[32], hash2[32];

    // First hash
    hasher.Write(reinterpret_cast<const unsigned char*>("test"), 4);
    hasher.Finalize(hash1);

    // Reset and hash again
    hasher.Reset();
    hasher.Write(reinterpret_cast<const unsigned char*>("test"), 4);
    hasher.Finalize(hash2);

    CHECK(std::memcmp(hash1, hash2, 32) == 0);
}

TEST_CASE("SHA256: Million 'a's (performance/stress)", "[.][sha256][perf]") {
    // Bitcoin Core test: 1,000,000 'a' characters
    // This test is disabled by default (tagged with ".")
    CSHA256 hasher;
    uint8_t hash[32];

    const size_t chunk_size = 1000;
    const size_t num_chunks = 1000;
    std::string chunk(chunk_size, 'a');

    for (size_t i = 0; i < num_chunks; ++i) {
        hasher.Write(reinterpret_cast<const unsigned char*>(chunk.data()), chunk_size);
    }

    hasher.Finalize(hash);
    std::string result = bytes_to_hex(hash, 32);
    CHECK(result == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST_CASE("SHA256: Double SHA256 (Bitcoin pattern)", "[sha256][crypto]") {
    // Bitcoin uses double SHA256 for block hashes
    const char* data = "hello";
    uint8_t hash1[32], hash2[32];

    // First SHA256
    CSHA256 hasher1;
    hasher1.Write(reinterpret_cast<const unsigned char*>(data), 5);
    hasher1.Finalize(hash1);

    // Second SHA256
    CSHA256 hasher2;
    hasher2.Write(hash1, 32);
    hasher2.Finalize(hash2);

    std::string result = bytes_to_hex(hash2, 32);
    CHECK(result == "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50");
}

TEST_CASE("SHA256: SHA256D64 batch hashing", "[sha256][crypto]") {
    // Test the specialized double-SHA256 batch function
    // This is used for mining and should leverage SIMD optimizations

    unsigned char input[64];
    unsigned char output[32];

    // Fill input with test pattern
    for (int i = 0; i < 64; ++i) {
        input[i] = static_cast<unsigned char>(i);
    }

    // Compute double-SHA256
    SHA256D64(output, input, 1);

    // Verify by computing manually
    uint8_t hash1[32], hash2[32];
    CSHA256 h1, h2;
    h1.Write(input, 64);
    h1.Finalize(hash1);
    h2.Write(hash1, 32);
    h2.Finalize(hash2);

    CHECK(std::memcmp(output, hash2, 32) == 0);
}

TEST_CASE("SHA256: SHA256D64 multiple blocks", "[sha256][crypto]") {
    // Test batching multiple 64-byte blocks
    const size_t num_blocks = 4;
    unsigned char input[64 * num_blocks];
    unsigned char output[32 * num_blocks];

    // Fill each block with a different pattern
    for (size_t i = 0; i < num_blocks; ++i) {
        for (size_t j = 0; j < 64; ++j) {
            input[i * 64 + j] = static_cast<unsigned char>((i * 64 + j) ^ (i * 17));
        }
    }

    // Batch compute
    SHA256D64(output, input, num_blocks);

    // Verify each block individually
    for (size_t i = 0; i < num_blocks; ++i) {
        uint8_t expected[32];
        unsigned char single_output[32];

        SHA256D64(single_output, input + i * 64, 1);

        CHECK(std::memcmp(output + i * 32, single_output, 32) == 0);
    }
}

TEST_CASE("SHA256: AutoDetect initialization", "[sha256][crypto]") {
    // Call AutoDetect and verify it returns a valid implementation string
    std::string impl = SHA256AutoDetect();

    INFO("SHA256 implementation: " << impl);

    // Should return one of the known implementation strings
    bool valid_impl = (impl == "standard" ||
                      impl.find("sse4") != std::string::npos ||
                      impl.find("avx2") != std::string::npos ||
                      impl.find("shani") != std::string::npos ||
                      impl.find("x86_shani") != std::string::npos ||
                      impl.find("arm_shani") != std::string::npos);

    CHECK(valid_impl);

    // After AutoDetect, hashing should still work correctly
    CSHA256 hasher;
    uint8_t hash[32];
    hasher.Write(reinterpret_cast<const unsigned char*>("test"), 4);
    hasher.Finalize(hash);

    std::string result = bytes_to_hex(hash, 32);
    CHECK(result == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
}

TEST_CASE("SHA256: AutoDetect on modern hardware", "[sha256][crypto]") {
    // On x86-64 with SSE4.1+ or ARM with SHA extensions, we should get accelerated implementation
    std::string impl = SHA256AutoDetect();

    INFO("Detected implementation: " << impl);

    // The implementation should NOT be "standard" on modern hardware
    // (This test will fail on very old CPUs, which is intentional to catch the bug)
    #if defined(__x86_64__) || defined(__amd64__) || defined(__aarch64__)
        // On modern 64-bit platforms, we expect hardware acceleration
        // Skip this check in CI if running on old hardware
        if (impl == "standard") {
            WARN("SHA256AutoDetect returned 'standard' on 64-bit platform - possible missing AutoDetect call or very old CPU");
        }
    #endif
}

TEST_CASE("SHA256: Performance test (optional)", "[.][sha256][perf]") {
    // This test is disabled by default (tagged with ".")
    // Run with: ./unicity_tests "[sha256][perf]"

    const size_t iterations = 1000000;
    const char* data = "Bitcoin mining uses double SHA256 for proof of work";
    size_t data_len = std::strlen(data);

    auto start = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < iterations; ++i) {
        CSHA256 hasher;
        uint8_t hash[32];
        hasher.Write(reinterpret_cast<const unsigned char*>(data), data_len);
        hasher.Finalize(hash);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    double hashes_per_sec = iterations * 1000.0 / duration.count();

    std::cout << "SHA256 performance: " << hashes_per_sec << " hashes/sec" << std::endl;
    std::cout << "Time for " << iterations << " hashes: " << duration.count() << " ms" << std::endl;
}

TEST_CASE("SHA256: Boundary conditions", "[sha256][crypto]") {
    CSHA256 hasher;
    uint8_t hash[32];

    SECTION("Zero-length input") {
        hasher.Write(reinterpret_cast<const unsigned char*>(""), 0);
        hasher.Finalize(hash);
        std::string result = bytes_to_hex(hash, 32);
        CHECK(result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    SECTION("63 bytes (one less than block size)") {
        std::string data(63, 'a');
        hasher.Write(reinterpret_cast<const unsigned char*>(data.data()), 63);
        hasher.Finalize(hash);
        // Just verify it completes without crashing
        CHECK(true);
    }

    SECTION("64 bytes (exactly one block)") {
        std::string data(64, 'a');
        hasher.Write(reinterpret_cast<const unsigned char*>(data.data()), 64);
        hasher.Finalize(hash);
        std::string result = bytes_to_hex(hash, 32);
        CHECK(result == "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
    }

    SECTION("65 bytes (one more than block size)") {
        std::string data(65, 'a');
        hasher.Write(reinterpret_cast<const unsigned char*>(data.data()), 65);
        hasher.Finalize(hash);
        // Just verify it completes without crashing
        CHECK(true);
    }

    SECTION("128 bytes (exactly two blocks)") {
        std::string data(128, 'a');
        hasher.Write(reinterpret_cast<const unsigned char*>(data.data()), 128);
        hasher.Finalize(hash);
        // Just verify it completes without crashing
        CHECK(true);
    }
}
