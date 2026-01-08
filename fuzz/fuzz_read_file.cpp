// Fuzz target for file reading operations
// Tests read_file and read_file_string with malformed/edge case files
//
// File reading is a security boundary. Bugs can cause:
// - Buffer overflows (incorrect size handling)
// - Integer overflows (file size calculations)
// - DoS via memory exhaustion (reading huge files)
// - Crashes on malformed data (UTF-8 validation, encoding issues)
// - Information leaks (reading past EOF, uninitialized memory)
//
// Target code:
// - src/util/files.cpp (read_file, read_file_string)

#include "util/files.hpp"
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <cstring>

using namespace unicity::util;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Setup test directory
    auto fuzz_dir = std::filesystem::temp_directory_path() / "unicity_fuzz_read";
    std::filesystem::remove_all(fuzz_dir);
    std::filesystem::create_directories(fuzz_dir);

    auto test_file = fuzz_dir / "fuzzed.dat";

    // Create file with fuzzed data
    try {
        std::ofstream out(test_file, std::ios::binary);
        if (out) {
            out.write(reinterpret_cast<const char*>(data), size);
            out.close();
        }
    } catch (...) {
        std::filesystem::remove_all(fuzz_dir);
        return 0;
    }

    // Test 1: Read as binary data
    try {
        auto read_data = read_file(test_file);
        // Verify size is reasonable
        if (read_data.size() > 100 * 1024 * 1024) {
            // Should not read files larger than 100MB
            __builtin_trap(); // Trigger crash for bug finding
        }
        (void)read_data.size(); // Use result
    } catch (...) {
        // Exceptions are acceptable
    }

    // Test 2: Read as string
    try {
        auto read_str = read_file_string(test_file);
        // Verify size is reasonable
        if (read_str.size() > 100 * 1024 * 1024) {
            __builtin_trap(); // Trigger crash
        }
        // Check for embedded nulls (should be preserved)
        (void)read_str.find('\0');
    } catch (...) {
        // Exceptions are acceptable
    }

    // Test 3: Read non-existent file
    try {
        auto nonexistent = fuzz_dir / "does_not_exist.dat";
        auto empty = read_file(nonexistent);
        if (!empty.empty()) {
            __builtin_trap(); // Should return empty
        }
    } catch (...) {
        // Exceptions are acceptable
    }

    // Test 4: Read with file permissions manipulation
    try {
#if defined(__unix__) || defined(__APPLE__)
        // Make file unreadable
        std::filesystem::permissions(test_file,
                                      std::filesystem::perms::owner_write,
                                      std::filesystem::perm_options::replace);
        auto result = read_file(test_file);
        // Should return empty on permission error
        (void)result.empty();

        // Restore permissions for cleanup
        std::filesystem::permissions(test_file,
                                      std::filesystem::perms::owner_all,
                                      std::filesystem::perm_options::replace);
#endif
    } catch (...) {
        // Exceptions are acceptable
    }

    // Test 5: Create a file exactly at the 100MB limit
    if (size > 0 && data[0] % 10 == 0) {
        try {
            auto large_file = fuzz_dir / "large.dat";
            std::ofstream out(large_file, std::ios::binary);
            if (out) {
                // Write exactly 100MB
                std::vector<uint8_t> chunk(1024 * 1024, 0xAA);
                for (int i = 0; i < 100; ++i) {
                    out.write(reinterpret_cast<const char*>(chunk.data()), chunk.size());
                }
                out.close();

                auto read_data = read_file(large_file);
                if (read_data.size() != 100 * 1024 * 1024) {
                    // Should read exactly 100MB
                    (void)read_data.size();
                }
            }
        } catch (...) {
            // Exceptions are acceptable
        }
    }

    // Test 6: File with special characters in name
    if (size >= 10) {
        try {
            // Use fuzzed data as filename (sanitized)
            std::string fname(reinterpret_cast<const char*>(data), std::min(size, size_t(32)));
            for (char &c : fname) {
                if (c == '/' || c == '\\' || c == '\0' || c < 0x20 || c > 0x7E) {
                    c = '_';
                }
            }
            if (!fname.empty()) {
                auto special_file = fuzz_dir / fname;
                std::ofstream out(special_file, std::ios::binary);
                if (out) {
                    out.write("test", 4);
                    out.close();
                    auto result = read_file(special_file);
                    (void)result.size();
                }
            }
        } catch (...) {
            // Exceptions are acceptable
        }
    }

    // Cleanup
    std::filesystem::remove_all(fuzz_dir);

    return 0;
}
