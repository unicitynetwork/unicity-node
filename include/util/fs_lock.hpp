// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <string>

namespace unicity {
namespace util {

namespace fs = std::filesystem;

/**
 * POSIX file lock (Linux/macOS only)
 * Uses fcntl() for exclusive file locking
 */
class FileLock {
public:
  FileLock() = delete;
  FileLock(const FileLock&) = delete;
  FileLock(FileLock&&) = delete;

  explicit FileLock(const fs::path& file);
  ~FileLock();

  // Try to acquire exclusive lock on file. Returns true if lock acquired, false otherwise.
  bool TryLock();

  // Get reason for lock failure.
  const std::string& GetReason() const { return reason_; }

  // POSIX file descriptor (public for error checking in LockDirectory)
  std::string reason_;
  int fd_{-1};
};

/**
 * Result of directory lock attempt
 */
enum class LockResult {
  Success,     // Lock acquired successfully
  ErrorWrite,  // Could not create lock file
  ErrorLock,   // Lock already held by another process
};

// Lock a directory to prevent multiple instances from using it.
// Creates a .lock file in the directory and acquires an exclusive lock.
// The lock is held until UnlockDirectory is called or the program exits.
// Design: locks are held for the lifetime of the process.
// Returns LockResult indicating success or failure.
LockResult LockDirectory(const fs::path& directory, const std::string& lockfile_name = ".lock");

// Release a directory lock.
void UnlockDirectory(const fs::path& directory, const std::string& lockfile_name = ".lock");

// Release all directory locks. Used for cleanup during shutdown.
void ReleaseAllDirectoryLocks();

}  // namespace util
}  // namespace unicity
