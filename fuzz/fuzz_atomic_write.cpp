// Fuzz target for atomic file writes
// Tests atomic_write_file with random data, filenames, and edge cases
//
// File I/O is a critical security boundary. Bugs can cause:
// - Data corruption (partial writes, lost updates)
// - DoS via disk exhaustion (unbounded write sizes)
// - Path traversal (../../etc/passwd)
// - Symlink attacks (write to attacker-controlled file)
// - Temp file leaks (disk space exhaustion)
// - Race conditions (concurrent writes)
//
// Target code:
// - src/util/files.cpp (atomic_write_file, read_file)

#include "util/files.hpp"
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <filesystem>
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
        std::memcpy(&value, data_ + offset_, sizeof(T));
        offset_ += sizeof(T);
        return value;
    }

    bool has_data() const { return offset_ < size_; }
    size_t remaining() const { return size_ - offset_; }

private:
    const uint8_t *data_;
    size_t size_;
    size_t offset_;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Require minimum input size
    if (size < 4) {
        return 0;
    }

    FuzzInput input(data, size);

    // Read filename length (limit to reasonable size)
    uint16_t filename_len = input.read<uint16_t>() % 256;
    std::string filename = input.read_string(filename_len);

    // Read file mode (0-0777)
    uint16_t mode = input.read<uint16_t>() % 01000;

    // Read write data
    std::vector<uint8_t> write_data;
    if (input.has_data()) {
        size_t data_len = std::min(input.remaining(), size_t(10 * 1024)); // Cap at 10KB for fuzzing
        std::string data_str = input.read_string(data_len);
        write_data.assign(data_str.begin(), data_str.end());
    }

    // Setup test directory
    auto fuzz_dir = std::filesystem::temp_directory_path() / "unicity_fuzz_atomic";
    std::filesystem::remove_all(fuzz_dir);
    std::filesystem::create_directories(fuzz_dir);

    // Sanitize filename to prevent path traversal
    // Replace dangerous chars with underscores
    for (char &c : filename) {
        if (c == '/' || c == '\\' || c == '\0' || c == '.' || c < 0x20 || c > 0x7E) {
            c = '_';
        }
    }

    // Ensure filename is not empty
    if (filename.empty()) {
        filename = "fuzz";
    }

    auto file_path = fuzz_dir / filename;

    // Test 1: Write with vector data
    try {
        (void)atomic_write_file(file_path, write_data, mode);
    } catch (...) {
        // Catch any exceptions - should not crash
    }

    // Test 2: Write with string data
    try {
        std::string str_data(write_data.begin(), write_data.end());
        (void)atomic_write_file(file_path, str_data, mode);
    } catch (...) {
        // Catch any exceptions
    }

    // Test 3: Read back (should not crash on any file content)
    try {
        auto read_data = read_file(file_path);
        (void)read_data.size(); // Use result
    } catch (...) {
        // Catch any exceptions
    }

    // Test 4: Read as string
    try {
        auto read_str = read_file_string(file_path);
        (void)read_str.size(); // Use result
    } catch (...) {
        // Catch any exceptions
    }

    // Test 5: Overwrite with different data
    if (input.has_data()) {
        try {
            std::vector<uint8_t> overwrite_data(input.remaining());
            std::string remaining = input.read_remaining();
            std::copy(remaining.begin(), remaining.end(), overwrite_data.begin());
            (void)atomic_write_file(file_path, overwrite_data, mode);
        } catch (...) {
            // Catch any exceptions
        }
    }

    // Cleanup
    std::filesystem::remove_all(fuzz_dir);

    return 0;
}
