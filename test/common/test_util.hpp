#pragma once

#include <cstring>
#include <filesystem>
#include <string>

#include <unistd.h>

namespace unicity::test {

struct TempDir {
  std::filesystem::path path;

  explicit TempDir(const std::string& prefix) {
    std::filesystem::path temp_base = std::filesystem::temp_directory_path() / (prefix + "_XXXXXX");
    char dir_template[1024];
    std::strncpy(dir_template, temp_base.string().c_str(), sizeof(dir_template));
    if (mkdtemp(dir_template)) {
      path = dir_template;
    } else {
      // Fallback if mkdtemp fails
      path = std::filesystem::temp_directory_path() / prefix;
      std::filesystem::create_directories(path);
    }
  }

  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
  }

  // Prevent copying
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;

  // Allow moving
  TempDir(TempDir&& other) noexcept : path(std::move(other.path)) {}
  TempDir& operator=(TempDir&& other) noexcept {
    path = std::move(other.path);
    return *this;
  }

  operator const std::filesystem::path&() const { return path; }
};

}  // namespace unicity::test
