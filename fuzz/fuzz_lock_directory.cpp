// Fuzz target for directory locking
// Tests LockDirectory, UnlockDirectory with malicious/malformed inputs
//
// File locking is critical for preventing data corruption. Bugs can cause:
// - Race conditions (multiple instances corrupting shared state)
// - DoS via lock exhaustion (never release locks)
// - Lock bypass (incorrect permission checks)
// - Crashes (malformed lock files, path traversal)
// - Deadlocks (circular lock dependencies)
//
// Target code:
// - src/util/fs_lock.cpp (LockDirectory, UnlockDirectory, FileLock)

#include "util/fs_lock.hpp"
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <filesystem>
#include <cstring>
#include <fstream>

using namespace unicity::util;

// FuzzInput: Parse structured fuzz data
class FuzzInput {
public:
    FuzzInput(const uint8_t *data, size_t size) : data_(data), size_(size), offset_(0) {}

    std::string read_string(size_t len) {
        if (offset_ + len > size_) {
            return "";
        }
        std::string result(reinterpret_cast<const char*>(data_ + offset_), len);
        offset_ += len;
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

private:
    const uint8_t *data_;
    size_t size_;
    size_t offset_;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0;
    }

    FuzzInput input(data, size);

    // Setup test directory
    auto fuzz_dir = std::filesystem::temp_directory_path() / "unicity_fuzz_lock";
    std::filesystem::remove_all(fuzz_dir);
    std::filesystem::create_directories(fuzz_dir);

    // Read lock filename length
    uint8_t filename_len = input.read<uint8_t>() % 64;
    std::string lockfile_name = input.read_string(filename_len);

    // Sanitize lock filename
    if (lockfile_name.empty()) {
        lockfile_name = ".lock";
    }
    for (char &c : lockfile_name) {
        if (c == '/' || c == '\\' || c == '\0' || c < 0x20 || c > 0x7E) {
            c = '_';
        }
    }

    // Test 1: Normal lock/unlock cycle
    try {
        auto result = LockDirectory(fuzz_dir, lockfile_name);
        (void)result; // Use result
        if (result == LockResult::Success) {
            UnlockDirectory(fuzz_dir, lockfile_name);
        }
    } catch (...) {
        // Should not throw
        __builtin_trap();
    }

    // Test 2: Double lock (should return Success due to g_dir_locks check)
    try {
        auto result1 = LockDirectory(fuzz_dir, lockfile_name);
        auto result2 = LockDirectory(fuzz_dir, lockfile_name);
        (void)result1;
        (void)result2;
        UnlockDirectory(fuzz_dir, lockfile_name);
    } catch (...) {
        __builtin_trap();
    }

    // Test 3: Lock with pre-existing malformed lock file
    if (input.has_data()) {
        try {
            auto lock_path = fuzz_dir / lockfile_name;
            std::ofstream malformed(lock_path, std::ios::binary);
            if (malformed) {
                // Write fuzzed garbage data
                malformed.write(reinterpret_cast<const char*>(data), std::min(size, size_t(1024)));
                malformed.close();
            }

            // Should either lock successfully or fail gracefully
            auto result = LockDirectory(fuzz_dir, lockfile_name);
            (void)result;
            if (result == LockResult::Success) {
                UnlockDirectory(fuzz_dir, lockfile_name);
            }
        } catch (...) {
            __builtin_trap();
        }
    }

    // Test 4: Lock non-existent directory
    try {
        auto nonexist = fuzz_dir / "does_not_exist";
        auto result = LockDirectory(nonexist, lockfile_name);
        // Should return ErrorWrite
        if (result == LockResult::Success) {
            // Unexpected success on non-existent dir
            (void)result;
        }
    } catch (...) {
        __builtin_trap();
    }

    // Test 5: Unlock without lock
    try {
        auto unlock_dir = fuzz_dir / "unlocked";
        std::filesystem::create_directories(unlock_dir);
        UnlockDirectory(unlock_dir, lockfile_name);
        // Should not crash
    } catch (...) {
        __builtin_trap();
    }

    // Test 6: Lock with path traversal attempts
    if (size >= 8) {
        try {
            std::string traversal_name = "../../../etc/" + lockfile_name;
            for (char &c : traversal_name) {
                if (c < 0x20 || c > 0x7E) c = '_';
            }
            auto result = LockDirectory(fuzz_dir, traversal_name);
            (void)result;
            if (result == LockResult::Success) {
                UnlockDirectory(fuzz_dir, traversal_name);
            }
        } catch (...) {
            // Path traversal might cause exceptions - acceptable
        }
    }

    // Test 7: ReleaseAllDirectoryLocks
    try {
        // Acquire multiple locks
        auto dir1 = fuzz_dir / "dir1";
        auto dir2 = fuzz_dir / "dir2";
        std::filesystem::create_directories(dir1);
        std::filesystem::create_directories(dir2);

        (void)LockDirectory(dir1, lockfile_name);
        (void)LockDirectory(dir2, lockfile_name);

        // Release all at once
        ReleaseAllDirectoryLocks();

        // Should be able to lock again
        auto result = LockDirectory(dir1, lockfile_name);
        (void)result;
    } catch (...) {
        __builtin_trap();
    }

    // Test 8: Lock with readonly parent directory
#if defined(__unix__) || defined(__APPLE__)
    if (input.has_data()) {
        try {
            auto readonly_dir = fuzz_dir / "readonly";
            std::filesystem::create_directories(readonly_dir);
            std::filesystem::permissions(readonly_dir,
                                          std::filesystem::perms::owner_read |
                                          std::filesystem::perms::owner_exec,
                                          std::filesystem::perm_options::replace);

            auto result = LockDirectory(readonly_dir, lockfile_name);
            // Should return ErrorWrite
            (void)result;

            // Restore permissions for cleanup
            std::filesystem::permissions(readonly_dir,
                                          std::filesystem::perms::owner_all,
                                          std::filesystem::perm_options::replace);
        } catch (...) {
            // Permission errors are acceptable
        }
    }
#endif

    // Cleanup - release all locks before removing files
    try {
        ReleaseAllDirectoryLocks();
        std::filesystem::remove_all(fuzz_dir);
    } catch (...) {
        // Cleanup failures are acceptable
    }

    return 0;
}
