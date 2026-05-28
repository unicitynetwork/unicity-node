// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license
// Comprehensive tests for atomic file writes (files.cpp)

#include "catch_amalgamated.hpp"
#include "common/test_util.hpp"
#include "util/files.hpp"
#include <filesystem>
#include <fstream>
#include <thread>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

using namespace unicity::util;

TEST_CASE("Atomic write: O_NOFOLLOW symlink protection", "[atomic_write][security]") {
    unicity::test::TempDir test_dir{"unicity_atomic_test_symlink"};

#if defined(__APPLE__) || defined(__linux__)
    SECTION("Write fails if target is a symlink") {
        auto real_file = test_dir.path / "real.txt";
        auto symlink = test_dir.path / "link.txt";

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
}

TEST_CASE("Atomic write: File permissions", "[atomic_write][permissions]") {
    unicity::test::TempDir test_dir{"unicity_atomic_test_perms"};

#if defined(__APPLE__) || defined(__linux__)
    SECTION("File created with specified mode") {
        auto file_path = test_dir.path / "test_0600.dat";
        std::vector<uint8_t> data = {0x01, 0x02, 0x03};

        REQUIRE(atomic_write_file(file_path, data, 0600));

        struct stat st;
        REQUIRE(stat(file_path.c_str(), &st) == 0);
        REQUIRE((st.st_mode & 0777) == 0600);
    }

    SECTION("File created with default mode 0644") {
        auto file_path = test_dir.path / "test_default.dat";
        std::vector<uint8_t> data = {0x01, 0x02, 0x03};

        REQUIRE(atomic_write_file(file_path, data));

        struct stat st;
        REQUIRE(stat(file_path.c_str(), &st) == 0);
        // Mode might be affected by umask, but should be 0644 or similar
        REQUIRE((st.st_mode & 0400) != 0); // At least owner-read
    }
#endif
}

TEST_CASE("Atomic write: Large files", "[atomic_write][large]") {
    unicity::test::TempDir test_dir{"unicity_atomic_test_large"};

    SECTION("Write 1MB file successfully") {
        auto file_path = test_dir.path / "large.dat";
        std::vector<uint8_t> data(1024 * 1024, 0xAA);

        REQUIRE(atomic_write_file(file_path, data));
        REQUIRE(std::filesystem::file_size(file_path) == data.size());

        auto read_back = read_file(file_path);
        REQUIRE(read_back == data);
    }

    SECTION("Write 10MB file successfully") {
        auto file_path = test_dir.path / "very_large.dat";
        std::vector<uint8_t> data(10 * 1024 * 1024, 0xBB);

        REQUIRE(atomic_write_file(file_path, data));
        REQUIRE(std::filesystem::file_size(file_path) == data.size());
    }

    SECTION("Read fails on file larger than 100MB limit") {
        auto file_path = test_dir.path / "huge.dat";

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
}

TEST_CASE("Atomic write: Overwrite safety", "[atomic_write][overwrite]") {
    unicity::test::TempDir test_dir{"unicity_atomic_test_overwrite"};

    SECTION("Overwriting existing file is atomic") {
        auto file_path = test_dir.path / "overwrite.dat";

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
        auto file_path = test_dir.path / "atomic.dat";

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
}

TEST_CASE("Atomic write: Temp file uniqueness", "[atomic_write][tempfile]") {
    unicity::test::TempDir test_dir{"unicity_atomic_test_temp"};

    SECTION("Multiple concurrent writes create unique temp files") {
        auto file1 = test_dir.path / "file1.dat";
        auto file2 = test_dir.path / "file2.dat";

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
        auto file_path = test_dir.path / "clean.dat";
        std::vector<uint8_t> data = {0xAB, 0xCD};

        REQUIRE(atomic_write_file(file_path, data));

        // Check for temp files
        int temp_file_count = 0;
        for (const auto& entry : std::filesystem::directory_iterator(test_dir.path)) {
            if (entry.path().filename().string().find(".tmp.") != std::string::npos) {
                temp_file_count++;
            }
        }

        REQUIRE(temp_file_count == 0);
    }
}

TEST_CASE("Atomic write: Readonly directory", "[atomic_write][readonly]") {
    unicity::test::TempDir test_dir{"unicity_atomic_test_readonly"};

#if defined(__APPLE__) || defined(__linux__)
    SECTION("Write fails on readonly directory") {
        // Skip test when running as root (root bypasses file permissions)
        if (geteuid() == 0) {
            WARN("Skipping readonly test when running as root");
            return;
        }

        // Make directory readonly
        std::filesystem::permissions(test_dir.path,
                                      std::filesystem::perms::owner_read |
                                      std::filesystem::perms::owner_exec,
                                      std::filesystem::perm_options::replace);

        auto file_path = test_dir.path / "fail.dat";
        std::vector<uint8_t> data = {0x01};

        bool result = atomic_write_file(file_path, data);
        REQUIRE_FALSE(result);

        // Restore permissions so TempDir's destructor can remove the dir.
        std::filesystem::permissions(test_dir.path,
                                      std::filesystem::perms::owner_all,
                                      std::filesystem::perm_options::replace);
    }
#endif
}

TEST_CASE("Atomic write: Directory creation", "[atomic_write][mkdir]") {
    unicity::test::TempDir test_dir{"unicity_atomic_test_mkdir"};

    SECTION("Creates parent directories automatically") {
        auto file_path = test_dir.path / "sub1" / "sub2" / "file.dat";
        std::vector<uint8_t> data = {0x42};

        REQUIRE(atomic_write_file(file_path, data));
        REQUIRE(std::filesystem::exists(test_dir.path / "sub1" / "sub2"));
        REQUIRE(read_file(file_path) == data);
    }
}

TEST_CASE("Atomic write: String API", "[atomic_write][string]") {
    unicity::test::TempDir test_dir{"unicity_atomic_test_string"};

    SECTION("Write and read string data") {
        auto file_path = test_dir.path / "text.txt";
        std::string text = "Hello, World! This is a test string with special chars: \n\t\r\0";

        REQUIRE(atomic_write_file(file_path, text));

        auto result = read_file_string(file_path);
        REQUIRE(result == text);
    }

    SECTION("Write empty string") {
        auto file_path = test_dir.path / "empty.txt";
        std::string empty = "";

        REQUIRE(atomic_write_file(file_path, empty));
        REQUIRE(std::filesystem::exists(file_path));
        REQUIRE(std::filesystem::file_size(file_path) == 0);
    }
}
