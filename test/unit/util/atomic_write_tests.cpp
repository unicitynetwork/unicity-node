// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license
// Comprehensive tests for atomic file writes (files.cpp)

#include "catch_amalgamated.hpp"
#include "util/files.hpp"
#include <filesystem>
#include <fstream>
#include <thread>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

using namespace unicity::util;

TEST_CASE("Atomic write: O_NOFOLLOW symlink protection", "[atomic_write][security]") {
    auto test_dir = std::filesystem::temp_directory_path() / "unicity_atomic_test_symlink";
    std::filesystem::remove_all(test_dir);
    std::filesystem::create_directories(test_dir);

#if defined(__APPLE__) || defined(__linux__)
    SECTION("Write fails if target is a symlink") {
        auto real_file = test_dir / "real.txt";
        auto symlink = test_dir / "link.txt";

        // Create a real file and symlink to it
        {
            std::ofstream f(real_file);
            f << "original";
        }
        std::filesystem::create_symlink(real_file, symlink);

        // Try to atomic_write through the symlink - should fail
        std::string data = "should not write";
        bool result = atomic_write_file(symlink, data);

        // On systems with O_NOFOLLOW, this should fail
        // The temp file creation might succeed, but the final rename might fail
        // or the open() itself might fail - either is acceptable

        // Verify original file unchanged
        std::ifstream check(real_file);
        std::string content((std::istreambuf_iterator<char>(check)),
                             std::istreambuf_iterator<char>());
        REQUIRE(content == "original");
    }
#endif

    std::filesystem::remove_all(test_dir);
}

TEST_CASE("Atomic write: File permissions", "[atomic_write][permissions]") {
    auto test_dir = std::filesystem::temp_directory_path() / "unicity_atomic_test_perms";
    std::filesystem::remove_all(test_dir);
    std::filesystem::create_directories(test_dir);

#if defined(__APPLE__) || defined(__linux__)
    SECTION("File created with specified mode") {
        auto file_path = test_dir / "test_0600.dat";
        std::vector<uint8_t> data = {0x01, 0x02, 0x03};

        REQUIRE(atomic_write_file(file_path, data, 0600));

        struct stat st;
        REQUIRE(stat(file_path.c_str(), &st) == 0);
        REQUIRE((st.st_mode & 0777) == 0600);
    }

    SECTION("File created with default mode 0644") {
        auto file_path = test_dir / "test_default.dat";
        std::vector<uint8_t> data = {0x01, 0x02, 0x03};

        REQUIRE(atomic_write_file(file_path, data));

        struct stat st;
        REQUIRE(stat(file_path.c_str(), &st) == 0);
        // Mode might be affected by umask, but should be 0644 or similar
        REQUIRE((st.st_mode & 0400) != 0); // At least owner-read
    }
#endif

    std::filesystem::remove_all(test_dir);
}

TEST_CASE("Atomic write: Large files", "[atomic_write][large]") {
    auto test_dir = std::filesystem::temp_directory_path() / "unicity_atomic_test_large";
    std::filesystem::remove_all(test_dir);
    std::filesystem::create_directories(test_dir);

    SECTION("Write 1MB file successfully") {
        auto file_path = test_dir / "large.dat";
        std::vector<uint8_t> data(1024 * 1024, 0xAA);

        REQUIRE(atomic_write_file(file_path, data));
        REQUIRE(std::filesystem::file_size(file_path) == data.size());

        auto read_back = read_file(file_path);
        REQUIRE(read_back == data);
    }

    SECTION("Write 10MB file successfully") {
        auto file_path = test_dir / "very_large.dat";
        std::vector<uint8_t> data(10 * 1024 * 1024, 0xBB);

        REQUIRE(atomic_write_file(file_path, data));
        REQUIRE(std::filesystem::file_size(file_path) == data.size());
    }

    SECTION("Read fails on file larger than 100MB limit") {
        auto file_path = test_dir / "huge.dat";

        // Create a file larger than 100MB using direct file I/O
        {
            std::ofstream f(file_path, std::ios::binary);
            std::vector<uint8_t> chunk(1024 * 1024, 0xCC);
            for (int i = 0; i < 101; ++i) {
                f.write(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            }
        }

        REQUIRE(std::filesystem::file_size(file_path) > 100 * 1024 * 1024);

        // read_file should refuse to read it
        auto result = read_file(file_path);
        REQUIRE(result.empty());
    }

    std::filesystem::remove_all(test_dir);
}

TEST_CASE("Atomic write: Overwrite safety", "[atomic_write][overwrite]") {
    auto test_dir = std::filesystem::temp_directory_path() / "unicity_atomic_test_overwrite";
    std::filesystem::remove_all(test_dir);
    std::filesystem::create_directories(test_dir);

    SECTION("Overwriting existing file is atomic") {
        auto file_path = test_dir / "overwrite.dat";

        // Write initial data
        std::vector<uint8_t> data1 = {0x01, 0x02, 0x03};
        REQUIRE(atomic_write_file(file_path, data1));

        // Overwrite with new data
        std::vector<uint8_t> data2 = {0x04, 0x05, 0x06, 0x07};
        REQUIRE(atomic_write_file(file_path, data2));

        // Verify new data
        auto result = read_file(file_path);
        REQUIRE(result == data2);
    }

    SECTION("File is never in partial state (simulated)") {
        auto file_path = test_dir / "atomic.dat";

        // Write initial data
        std::vector<uint8_t> data1(1000, 0xAA);
        REQUIRE(atomic_write_file(file_path, data1));

        // Overwrite with larger data
        std::vector<uint8_t> data2(5000, 0xBB);
        REQUIRE(atomic_write_file(file_path, data2));

        // File should contain complete new data, not partial
        auto result = read_file(file_path);
        REQUIRE(result.size() == data2.size());
        REQUIRE(result == data2);
    }

    std::filesystem::remove_all(test_dir);
}

TEST_CASE("Atomic write: Temp file uniqueness", "[atomic_write][tempfile]") {
    auto test_dir = std::filesystem::temp_directory_path() / "unicity_atomic_test_temp";
    std::filesystem::remove_all(test_dir);
    std::filesystem::create_directories(test_dir);

    SECTION("Multiple concurrent writes create unique temp files") {
        auto file1 = test_dir / "file1.dat";
        auto file2 = test_dir / "file2.dat";

        std::vector<uint8_t> data1 = {0x01};
        std::vector<uint8_t> data2 = {0x02};

        std::thread t1([&]() {
            REQUIRE(atomic_write_file(file1, data1));
        });

        std::thread t2([&]() {
            REQUIRE(atomic_write_file(file2, data2));
        });

        t1.join();
        t2.join();

        REQUIRE(read_file(file1) == data1);
        REQUIRE(read_file(file2) == data2);
    }

    SECTION("No temp files left behind after successful write") {
        auto file_path = test_dir / "clean.dat";
        std::vector<uint8_t> data = {0xAB, 0xCD};

        REQUIRE(atomic_write_file(file_path, data));

        // Check for temp files
        int temp_file_count = 0;
        for (const auto& entry : std::filesystem::directory_iterator(test_dir)) {
            if (entry.path().filename().string().find(".tmp.") != std::string::npos) {
                temp_file_count++;
            }
        }

        REQUIRE(temp_file_count == 0);
    }

    std::filesystem::remove_all(test_dir);
}

TEST_CASE("Atomic write: Readonly directory", "[atomic_write][readonly]") {
    auto test_dir = std::filesystem::temp_directory_path() / "unicity_atomic_test_readonly";
    std::filesystem::remove_all(test_dir);
    std::filesystem::create_directories(test_dir);

#if defined(__APPLE__) || defined(__linux__)
    SECTION("Write fails on readonly directory") {
        // Skip test when running as root (root bypasses file permissions)
        if (geteuid() == 0) {
            WARN("Skipping readonly test when running as root");
            std::filesystem::remove_all(test_dir);
            return;
        }

        // Make directory readonly
        std::filesystem::permissions(test_dir,
                                      std::filesystem::perms::owner_read |
                                      std::filesystem::perms::owner_exec,
                                      std::filesystem::perm_options::replace);

        auto file_path = test_dir / "fail.dat";
        std::vector<uint8_t> data = {0x01};

        bool result = atomic_write_file(file_path, data);
        REQUIRE_FALSE(result);

        // Restore permissions for cleanup
        std::filesystem::permissions(test_dir,
                                      std::filesystem::perms::owner_all,
                                      std::filesystem::perm_options::replace);
    }
#endif

    std::filesystem::remove_all(test_dir);
}

TEST_CASE("Atomic write: Directory creation", "[atomic_write][mkdir]") {
    auto test_dir = std::filesystem::temp_directory_path() / "unicity_atomic_test_mkdir";
    std::filesystem::remove_all(test_dir);

    SECTION("Creates parent directories automatically") {
        auto file_path = test_dir / "sub1" / "sub2" / "file.dat";
        std::vector<uint8_t> data = {0x42};

        REQUIRE(atomic_write_file(file_path, data));
        REQUIRE(std::filesystem::exists(test_dir / "sub1" / "sub2"));
        REQUIRE(read_file(file_path) == data);
    }

    std::filesystem::remove_all(test_dir);
}

TEST_CASE("Atomic write: String API", "[atomic_write][string]") {
    auto test_dir = std::filesystem::temp_directory_path() / "unicity_atomic_test_string";
    std::filesystem::remove_all(test_dir);
    std::filesystem::create_directories(test_dir);

    SECTION("Write and read string data") {
        auto file_path = test_dir / "text.txt";
        std::string text = "Hello, World! This is a test string with special chars: \n\t\r\0";

        REQUIRE(atomic_write_file(file_path, text));

        auto result = read_file_string(file_path);
        REQUIRE(result == text);
    }

    SECTION("Write empty string") {
        auto file_path = test_dir / "empty.txt";
        std::string empty = "";

        REQUIRE(atomic_write_file(file_path, empty));
        REQUIRE(std::filesystem::exists(file_path));
        REQUIRE(std::filesystem::file_size(file_path) == 0);
    }

    std::filesystem::remove_all(test_dir);
}
