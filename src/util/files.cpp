#include "util/files.hpp"

#include "util/logging.hpp"

#include <cstdlib>
#include <fstream>
#include <random>

#include <fcntl.h>
#include <unistd.h>

namespace unicity {
namespace util {

namespace {

bool sync_file(int fd) {
#if defined(__APPLE__)
  // macOS: fsync() doesn't guarantee data reaches physical disk.
  // F_FULLFSYNC bypasses disk write cache for true durability.
  return fcntl(fd, F_FULLFSYNC, 0) == 0;
#else
  return fsync(fd) == 0;
#endif
}

bool sync_directory(const std::filesystem::path& dir) {
#if defined(__APPLE__)
  // macOS doesn't have O_DIRECTORY flag
  int fd = open(dir.c_str(), O_RDONLY);
  if (fd < 0)
    return false;
  // Use F_FULLFSYNC for true durability on macOS
  bool result = fcntl(fd, F_FULLFSYNC, 0) == 0;
  close(fd);
  return result;
#else
  int fd = open(dir.c_str(), O_RDONLY | O_DIRECTORY);
  if (fd < 0)
    return false;
  bool result = fsync(fd) == 0;
  close(fd);
  return result;
#endif
}

// Generate random suffix for temp file
// Uses thread_local static to avoid expensive RNG recreation
std::string random_suffix() {
  static thread_local std::mt19937_64 gen(std::random_device{}());
  static thread_local std::uniform_int_distribution<uint64_t> dis;
  char buf[20];
  // Cast to unsigned long long for portable printf formatting
  snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(dis(gen)));
  return std::string(buf);
}

}  // anonymous namespace

bool atomic_write_file(const std::filesystem::path& path, const std::vector<uint8_t>& data, int mode) {
  // Create parent directory if needed
  auto parent = path.parent_path();
  if (!parent.empty() && !ensure_directory(parent)) {
    LOG_ERROR("atomic_write_file: Failed to create parent directory: {}", parent.string());
    return false;
  }

  // Generate temp file path
  auto temp_path = path;
  temp_path += ".tmp." + random_suffix();

  // SECURITY: O_EXCL prevents race condition where attacker pre-creates temp file
  // SECURITY: O_NOFOLLOW prevents symlink attacks (fail if path is symlink)
  int fd = open(temp_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode);
  if (fd < 0) {
    LOG_ERROR("atomic_write_file: Failed to create temp file {}: {} (errno={})", temp_path.string(),
              std::strerror(errno), errno);
    return false;
  }

  // Write data (handle partial writes)
  size_t total = 0;
  while (total < data.size()) {
    ssize_t n = write(fd, data.data() + total, data.size() - total);
    if (n <= 0) {
      LOG_ERROR("atomic_write_file: Failed to write to temp file {}: {} (errno={}, written {}/{})", temp_path.string(),
                std::strerror(errno), errno, total, data.size());
      close(fd);
      std::filesystem::remove(temp_path);
      return false;
    }
    total += static_cast<size_t>(n);
  }

  // Sync to disk
  if (!sync_file(fd)) {
    LOG_ERROR("atomic_write_file: Failed to fsync temp file {}: {} (errno={})", temp_path.string(),
              std::strerror(errno), errno);
    close(fd);
    std::filesystem::remove(temp_path);
    return false;
  }

  close(fd);

  // Sync directory to ensure rename will be durable
  if (!parent.empty() && !sync_directory(parent)) {
    // Directory sync failed - clean up temp file
    LOG_ERROR("atomic_write_file: Failed to fsync parent directory {} for atomic write of {}: {} (errno={})",
              parent.string(), path.string(), std::strerror(errno), errno);
    std::filesystem::remove(temp_path);
    return false;
  }

  // Atomic rename
  std::error_code ec;
  std::filesystem::rename(temp_path, path, ec);
  if (ec) {
    LOG_ERROR("atomic_write_file: Failed to rename {} to {}: {} (code={})", temp_path.string(), path.string(),
              ec.message(), ec.value());
    std::filesystem::remove(temp_path);
    return false;
  }

  return true;
}

bool atomic_write_file(const std::filesystem::path& path, const std::vector<uint8_t>& data) {
  return atomic_write_file(path, data, 0644);
}

bool atomic_write_file(const std::filesystem::path& path, const std::string& data, int mode) {
  std::vector<uint8_t> vec(data.begin(), data.end());
  return atomic_write_file(path, vec, mode);
}

bool atomic_write_file(const std::filesystem::path& path, const std::string& data) {
  return atomic_write_file(path, data, 0644);
}

std::vector<uint8_t> read_file(const std::filesystem::path& path) {
  std::ifstream file(path, std::ios::binary | std::ios::ate);
  if (!file) {
    LOG_ERROR("read_file: Failed to open file {}: {} (errno={})", path.string(), std::strerror(errno), errno);
    return {};
  }

  // Get file size with proper error checking
  std::streampos pos = file.tellg();
  if (pos == std::streampos(-1)) {
    LOG_ERROR("read_file: Failed to get file size for {}: {} (errno={})", path.string(), std::strerror(errno), errno);
    return {};
  }

  std::streamsize size = static_cast<std::streamsize>(pos);
  if (size < 0) {
    LOG_ERROR("read_file: Invalid file size ({}) for {}", size, path.string());
    return {};
  }

  // Sanity check: refuse to read files larger than 100MB
  // Prevents accidental memory exhaustion
  constexpr std::streamsize MAX_FILE_SIZE = 100 * 1024 * 1024;
  if (size > MAX_FILE_SIZE) {
    LOG_ERROR("read_file: File {} exceeds max size limit ({}MB > {}MB). "
              "This likely indicates database corruption or misuse. "
              "Consider splitting large files or increasing MAX_FILE_SIZE.",
              path.string(), size / 1024 / 1024, MAX_FILE_SIZE / 1024 / 1024);
    return {};
  }

  std::vector<uint8_t> data(size);
  file.seekg(0);
  file.read(reinterpret_cast<char*>(data.data()), size);

  if (!file) {
    LOG_ERROR("read_file: Failed to read {} bytes from {}: {} (errno={})", size, path.string(), std::strerror(errno),
              errno);
    return {};
  }

  return data;
}

std::string read_file_string(const std::filesystem::path& path) {
  auto data = read_file(path);
  return std::string(data.begin(), data.end());
}

bool ensure_directory(const std::filesystem::path& dir) {
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  return !ec || std::filesystem::exists(dir);
}

std::filesystem::path get_default_datadir() {
  // Platform-specific default data directory locations
  // Only Linux and macOS are supported

#if defined(__APPLE__)
  // macOS: ~/Library/Application Support/Unicity
  const char* home = std::getenv("HOME");
  if (home) {
    return std::filesystem::path(home) / "Library" / "Application Support" / "Unicity";
  }

#elif defined(__linux__) || defined(__unix__)
  // Linux/Unix: ~/.unicity
  const char* home = std::getenv("HOME");
  if (home) {
    return std::filesystem::path(home) / ".unicity";
  }

#else
// Unsupported platform - should never reach here due to CMakeLists.txt check
#  error "Unicity only supports Linux and macOS"
#endif

  // If HOME is not set (should never happen in normal environments),
  // abort rather than using unpredictable CWD fallback
  LOG_ERROR("get_default_datadir: HOME environment variable not set. "
            "Cannot determine default data directory. "
            "Please set HOME or use --datadir flag explicitly.");

  // Return empty path to signal error - caller must handle this
  return std::filesystem::path();
}

}  // namespace util
}  // namespace unicity
