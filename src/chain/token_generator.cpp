// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "chain/token_generator.hpp"

#include "util/endian.hpp"
#include "util/files.hpp"
#include "util/logging.hpp"
#include "util/sha256.hpp"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include <random>

namespace unicity::mining {

namespace {

/**
 * Fill a buffer with random bytes using OS-native primitives.
 * On modern systems, std::random_device is typically non-deterministic and 
 * backed by /dev/urandom or equivalent (like BCryptGenRandom on Windows).
 */
void RandomBytes(uint8_t* data, size_t len) {
  std::random_device rd;
  for (size_t i = 0; i < len; ++i) {
    data[i] = static_cast<uint8_t>(rd() & 0xFF);
  }
}

}  // namespace

TokenGenerator::TokenGenerator(const std::filesystem::path& datadir)
    : datadir_(datadir),
      state_file_(datadir / "miner_state.json"),
      counter_(0) {
  util::ensure_directory(datadir_);

  if (!LoadState()) {
    LOG_INFO("TokenGenerator: No valid state found, generating new seed");
    InitializeFreshState();
  }
}

uint256 TokenGenerator::GenerateNextTokenId() {
  std::lock_guard lock(mutex_);

  // Increment counter and store locally
  const uint64_t next_counter = ++counter_;
  const uint256 current_seed = seed_;

  // Persist state FIRST to ensure we never reuse a counter value after a crash.
  // We throw an exception if I/O fails to avoid returning an ID that isn't safe.
  if (!WriteStateFile({current_seed, next_counter})) {
    throw std::runtime_error("TokenGenerator: Failed to persist incremented counter to disk");
  }

  // TokenID = Hash(seed || counter_le)
  std::array<uint8_t, 8> counter_le;
  endian::WriteLE64(counter_le.data(), next_counter);

  uint256 token_id;
  CSHA256()
      .Write(current_seed.begin(), current_seed.size())
      .Write(counter_le.data(), counter_le.size())
      .Finalize(token_id.begin());

  return token_id;
}

uint64_t TokenGenerator::GetCounter() const {
  std::lock_guard lock(mutex_);
  return counter_;
}

bool TokenGenerator::LoadState() {
  std::lock_guard lock(mutex_);

  const auto loaded = ReadStateFile();
  if (!loaded) {
    return false;
  }

  seed_ = loaded->seed;
  counter_ = loaded->counter;

  LOG_INFO("TokenGenerator: Loaded state with counter = {}", counter_);
  return true;
}

bool TokenGenerator::SaveState() const {
  std::lock_guard lock(mutex_);
  return WriteStateFile({seed_, counter_});
}

void TokenGenerator::InitializeFreshState() {
  // Generate secure seed and reset counter
  RandomBytes(seed_.begin(), seed_.size());
  counter_ = 0;

  if (!WriteStateFile({seed_, counter_})) {
    throw std::runtime_error("TokenGenerator: Failed to persist fresh state during initialization");
  }
}

TokenGenerator::State TokenGenerator::GetState() const {
  std::lock_guard lock(mutex_);
  return {seed_, counter_};
}

std::optional<TokenGenerator::State> TokenGenerator::ReadStateFile() const {
  if (!std::filesystem::exists(state_file_)) {
    return std::nullopt;
  }

  std::vector<uint8_t> data = util::read_file(state_file_);
  if (data.empty()) {
    LOG_ERROR("TokenGenerator: Failed to read state file or file is empty");
    return std::nullopt;
  }

  try {
    std::string content(data.begin(), data.end());
    auto json = nlohmann::json::parse(content);

    if (!json.contains("seed") || !json["seed"].is_string()) {
      LOG_ERROR("TokenGenerator: Missing or invalid seed in state file");
      return std::nullopt;
    }

    State s;
    s.seed.SetHex(json["seed"].get<std::string>());
    if (s.seed.IsNull()) {
      LOG_ERROR("TokenGenerator: Invalid seed encoding in state file");
      return std::nullopt;
    }

    s.counter = json.value("counter", uint64_t{0});
    return s;

  } catch (const std::exception& e) {
    LOG_ERROR("TokenGenerator: Failed to parse state file: {}", e.what());
    return std::nullopt;
  }
}

bool TokenGenerator::WriteStateFile(const State& state) const {
  nlohmann::json json;
  json["seed"] = state.seed.GetHex();
  json["counter"] = state.counter;

  std::string content = json.dump(2) + "\n";

  if (!util::atomic_write_file(state_file_, content, 0600)) {
    LOG_ERROR("TokenGenerator: Failed to write state file");
    return false;
  }

  return true;
}

} // namespace unicity::mining
