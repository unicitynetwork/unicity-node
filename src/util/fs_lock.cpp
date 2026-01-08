// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license
// Unix/POSIX implementation (Linux/macOS only)

#include "util/fs_lock.hpp"

#include "util/logging.hpp"

#include <cerrno>
#include <cstring>

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

namespace unicity {
namespace util {

// Global mutex to protect dir_locks map
static std::mutex g_dir_locks_mutex;

// Map of currently held directory locks
// Key: full path to lock file
// Value: FileLock object
static std::map<std::string, std::unique_ptr<FileLock>> g_dir_locks;

// ============================================================================
// FileLock implementation (POSIX fcntl)
// ============================================================================

static std::string GetErrorReason() {
  return std::strerror(errno);
}

FileLock::FileLock(const fs::path& file) {
  // O_CREAT: Create file if it doesn't exist (fixes race condition)
  // O_CLOEXEC: Don't leak fd to child processes (prevents lock inheritance)
  // 0644: rw-r--r-- permissions
  fd_ = open(file.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0644);
  if (fd_ == -1) {
    reason_ = GetErrorReason();
  }
}

FileLock::~FileLock() {
  if (fd_ != -1) {
    // Closing the fd automatically releases the fcntl lock
    close(fd_);
  }
}

bool FileLock::TryLock() {
  if (fd_ == -1) {
    return false;
  }

  struct flock lock;
  lock.l_type = F_WRLCK;  // Exclusive write lock
  lock.l_whence = SEEK_SET;
  lock.l_start = 0;
  lock.l_len = 0;  // Lock entire file

  if (fcntl(fd_, F_SETLK, &lock) == -1) {
    reason_ = GetErrorReason();
    return false;
  }

  return true;
}

// ============================================================================
// Directory locking functions
// ============================================================================

LockResult LockDirectory(const fs::path& directory, const std::string& lockfile_name) {
  std::lock_guard<std::mutex> lock(g_dir_locks_mutex);

  fs::path lockfile_path = directory / lockfile_name;
  std::string lockfile_str = lockfile_path.string();

  // Check if we already have a lock on this directory
  if (g_dir_locks.find(lockfile_str) != g_dir_locks.end()) {
    return LockResult::Success;
  }

  // Create and lock the file atomically
  // FileLock constructor uses O_CREAT, so no separate creation step needed
  auto file_lock = std::make_unique<FileLock>(lockfile_path);

  // Check if file was opened successfully
  if (file_lock->fd_ == -1) {
    LOG_CHAIN_ERROR("Failed to open lock file {}: {}", lockfile_path.string(), file_lock->GetReason());
    return LockResult::ErrorWrite;
  }

  // Try to acquire lock
  if (!file_lock->TryLock()) {
    LOG_CHAIN_ERROR("Failed to lock directory {}: {}", directory.string(), file_lock->GetReason());
    return LockResult::ErrorLock;
  }

  // Lock acquired successfully - store the lock to keep it held
  g_dir_locks.emplace(lockfile_str, std::move(file_lock));
  LOG_CHAIN_TRACE("Acquired directory lock: {}", directory.string());
  return LockResult::Success;
}

void UnlockDirectory(const fs::path& directory, const std::string& lockfile_name) {
  std::lock_guard<std::mutex> lock(g_dir_locks_mutex);

  fs::path lockfile_path = directory / lockfile_name;
  std::string lockfile_str = lockfile_path.string();

  auto it = g_dir_locks.find(lockfile_str);
  if (it != g_dir_locks.end()) {
    LOG_CHAIN_TRACE("Released directory lock: {}", directory.string());
    g_dir_locks.erase(it);
  }
}

void ReleaseAllDirectoryLocks() {
  std::lock_guard<std::mutex> lock(g_dir_locks_mutex);
  LOG_CHAIN_TRACE("Releasing all directory locks ({} locks)", g_dir_locks.size());
  g_dir_locks.clear();
}

}  // namespace util
}  // namespace unicity
