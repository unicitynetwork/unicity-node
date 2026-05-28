// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include "util/uint.hpp"

#include <filesystem>
#include <mutex>
#include <optional>

namespace unicity::mining {

// Generates Token IDs for mined blocks
// TokenID = Hash(seed || counter)
class TokenGenerator {
public:
  struct State {
    uint256 seed;
    uint64_t counter;
  };

  explicit TokenGenerator(const std::filesystem::path& datadir);

  // Generate the next unique Token ID and persist the state.
  [[nodiscard]] uint256 GenerateNextTokenId();

  // Get current counter value
  [[nodiscard]] uint64_t GetCounter() const;

  // Snapshot current state
  [[nodiscard]] State GetState() const;

  // Reload state from disk (overwrites in-memory state)
  bool LoadState();

  // Persist current in-memory state
  [[nodiscard]] bool SaveState() const;

  private:
  // Create fresh seed + reset counter
  void InitializeFreshState();

  // Persistence helpers
  std::optional<State> ReadStateFile() const;

  bool WriteStateFile(const State& state) const;


  std::filesystem::path datadir_;
  std::filesystem::path state_file_;

  mutable std::mutex mutex_;

  uint256 seed_;
  uint64_t counter_;
};

}  // namespace unicity::mining