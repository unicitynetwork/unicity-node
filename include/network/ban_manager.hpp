// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

/*
 BanManager — manages banned and discouraged peers

 Purpose
 - Track banned peers (persistent, saved to disk)
 - Track discouraged peers (temporary, in-memory)
 - Persist ban state across restarts

 Key responsibilities
 1. Ban/unban peers by IP address
 2. Discourage peers temporarily
 3. Save/load ban state to/from disk
 4. Sweep expired bans and discouragements
*/

#include <cstdint>
#include <map>
#include <mutex>
#include <string>

namespace unicity {
namespace network {

class BanManager {
public:
  struct BanEntry {
    static constexpr int CURRENT_VERSION = 1;
    int version{CURRENT_VERSION};
    int64_t create_time{0};  // Unix timestamp when ban was created
    int64_t ban_until{0};    // Unix timestamp when ban expires

    BanEntry() = default;
    BanEntry(int64_t created, int64_t until) : create_time(created), ban_until(until) {}

    bool IsExpired(int64_t now) const {
      return ban_until < now;
    }
  };

  explicit BanManager(const std::string& datadir = "");
  ~BanManager() = default;

  // Non-copyable
  BanManager(const BanManager&) = delete;
  BanManager& operator=(const BanManager&) = delete;

  // Default ban duration (24 hours)
  static constexpr int64_t DEFAULT_BAN_TIME_SEC = 24 * 60 * 60;

  // Maximum discouraged addresses (memory cap)
  static constexpr size_t MAX_DISCOURAGED = 50000;

  // Ban an address (persistent).
  // If ban_time_offset <= 0, uses DEFAULT_BAN_TIME_SEC 
  // Otherwise, ban lasts for ban_time_offset seconds from now.
  void Ban(const std::string& address, int64_t ban_time_offset = 0);

  void Unban(const std::string& address);

  // Check if address is banned. Returns true if banned and not expired.
  bool IsBanned(const std::string& address) const;

  // Get all currently banned addresses. Returns map of banned addresses to ban entries.
  std::map<std::string, BanEntry> GetBanned() const;

  // Clear all bans (used for testing and RPC).
  void ClearBanned();

  // Remove expired bans from the ban list.
  void SweepBanned();

  // Discourage an address temporarily. Discouraged peers are rejected for new connections
  // but existing connections remain.
  void Discourage(const std::string& address);

  // Check if address is discouraged. Returns true if discouraged and not expired.
  bool IsDiscouraged(const std::string& address) const;

  // Clear all discouragements (used for testing and RPC).
  void ClearDiscouraged();

  // Remove expired discouragements.
  void SweepDiscouraged();

  // Load bans from disk. Returns true on success (including "no file found" case).
  bool LoadBans(const std::string& datadir);

  // Save bans to disk. Returns true on success.
  bool SaveBans();

  // Get banlist file path. Returns path to banlist.json file.
  std::string GetBanlistPath() const;

private:
  // Banned addresses (persistent, stored on disk)
  mutable std::mutex banned_mutex_;
  std::map<std::string, BanEntry> banned_;

  // Discouraged addresses (in-memory, no expiry - evicted when at capacity)
  mutable std::mutex discouraged_mutex_;
  std::map<std::string, int64_t> discouraged_;  // address -> insertion time (for eviction ordering)

  // Persistence
  std::string ban_file_path_;
  bool ban_auto_save_{true};
  bool is_dirty_{false};  // Tracks if in-memory state differs from disk

  // Internal helper: Save bans (must be called with banned_mutex_ held)
  bool SaveBansInternal();
};

}  // namespace network
}  // namespace unicity
