#include "catch_amalgamated.hpp"
#include "util/files.hpp"
#include <filesystem>

using namespace unicity::util;

TEST_CASE("File utilities", "[files]") {
    // Create a temporary test directory
    auto test_dir = std::filesystem::temp_directory_path() / "unicity_test";
    std::filesystem::remove_all(test_dir);

    SECTION("ensure_directory creates directories") {
        auto subdir = test_dir / "sub" / "nested";
        REQUIRE(ensure_directory(subdir));
        REQUIRE(std::filesystem::exists(subdir));
        REQUIRE(std::filesystem::is_directory(subdir));
    }

    SECTION("atomic_write_file creates file") {
        ensure_directory(test_dir);
        auto file_path = test_dir / "test.dat";

        std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
        REQUIRE(atomic_write_file(file_path, data));
        REQUIRE(std::filesystem::exists(file_path));
    }

    SECTION("read_file retrieves written data") {
        ensure_directory(test_dir);
        auto file_path = test_dir / "test2.dat";

        std::vector<uint8_t> original = {0xDE, 0xAD, 0xBE, 0xEF};
        REQUIRE(atomic_write_file(file_path, original));

        auto read_data = read_file(file_path);
        REQUIRE(read_data == original);
    }

    SECTION("atomic_write_file overwrites existing file") {
        ensure_directory(test_dir);
        auto file_path = test_dir / "test3.dat";

        std::vector<uint8_t> data1 = {0x01, 0x02};
        std::vector<uint8_t> data2 = {0x03, 0x04, 0x05};

        REQUIRE(atomic_write_file(file_path, data1));
        REQUIRE(atomic_write_file(file_path, data2));

        auto result = read_file(file_path);
        REQUIRE(result == data2);
    }

    SECTION("atomic_write_file with string") {
        ensure_directory(test_dir);
        auto file_path = test_dir / "test4.txt";

        std::string text = "Hello, World!";
        REQUIRE(atomic_write_file(file_path, text));

        auto result = read_file_string(file_path);
        REQUIRE(result == text);
    }

    SECTION("read_file returns empty on non-existent file") {
        auto file_path = test_dir / "nonexistent.dat";
        auto result = read_file(file_path);
        REQUIRE(result.empty());
    }

    SECTION("get_default_datadir returns valid path") {
        auto datadir = get_default_datadir();
        REQUIRE(!datadir.empty());
        auto filename = datadir.filename().string();
        // Platform-specific: Linux uses ".unicity", macOS uses "Unicity"
        bool valid_name = (filename == "Unicity" || filename == ".unicity");
        REQUIRE(valid_name);
    }

    // Cleanup
    std::filesystem::remove_all(test_dir);
}
