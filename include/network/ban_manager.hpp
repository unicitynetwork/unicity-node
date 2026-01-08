#pragma once

/*
 BanManager — manages banned, discouraged, and whitelisted peers

 Purpose
 - Track banned peers (persistent, saved to disk)
 - Track discouraged peers (temporary, in-memory)
 - Track whitelisted peers (immune to bans)
 - Persist ban state across restarts

 Key responsibilities
 1. Ban/unban peers by IP address
 2. Discourage peers temporarily
 3. Whitelist peers (bypass ban/discourage checks)
 4. Save/load ban state to/from disk
 5. Sweep expired bans and discouragements
*/

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <unordered_set>

namespace unicity {
namespace network {

class BanManager {
public:
  // Ban entry structure (persistent bans)
  struct CBanEntry {
    static constexpr int CURRENT_VERSION = 1;
    int nVersion{CURRENT_VERSION};
    int64_t nCreateTime{0};  // Unix timestamp when ban was created
    int64_t nBanUntil{0};    // Unix timestamp when ban expires (0 = permanent)

    CBanEntry() = default;
    CBanEntry(int64_t create_time, int64_t ban_until) : nCreateTime(create_time), nBanUntil(ban_until) {}

    // Check if ban has expired
    bool IsExpired(int64_t now) const {
      // nBanUntil == 0 means permanent ban
      return nBanUntil != 0 && nBanUntil < now;
    }
  };

  explicit BanManager(const std::string& datadir = "");
  ~BanManager() = default;

  // Non-copyable
  BanManager(const BanManager&) = delete;
  BanManager& operator=(const BanManager&) = delete;

  // Ban an address (persistent). ban_time_offset is seconds from now until ban expires (0 = permanent).
  void Ban(const std::string& address, int64_t ban_time_offset = 0);

  // Unban an address.
  void Unban(const std::string& address);

  // Check if address is banned. Returns true if banned and not expired.
  bool IsBanned(const std::string& address) const;

  // Get all currently banned addresses. Returns map of banned addresses to ban entries.
  std::map<std::string, CBanEntry> GetBanned() const;

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

  // Add address to whitelist (immune to bans).
  void AddToWhitelist(const std::string& address);

  // Remove address from whitelist.
  void RemoveFromWhitelist(const std::string& address);

  // Check if address is whitelisted. Returns true if whitelisted.
  bool IsWhitelisted(const std::string& address) const;

  // Load bans from disk. Returns true on success (including "no file found" case).
  bool LoadBans(const std::string& datadir);

  // Save bans to disk. Returns true on success.
  bool SaveBans();

  // Get banlist file path. Returns path to banlist.json file.
  std::string GetBanlistPath() const;

private:
  // Discourage duration
  static constexpr int64_t DISCOURAGE_DURATION_SEC = 24 * 60 * 60;

  // Banned addresses (persistent, stored on disk)
  mutable std::mutex banned_mutex_;
  std::map<std::string, CBanEntry> banned_;

  // Discouraged addresses (temporary, in-memory with expiry times)
  mutable std::mutex discouraged_mutex_;
  std::map<std::string, int64_t> discouraged_;  // address -> expiry time

  // Whitelist (NoBan) state
  mutable std::mutex whitelist_mutex_;
  std::unordered_set<std::string> whitelist_;

  // Persistence
  std::string ban_file_path_;
  bool ban_auto_save_{true};
  bool is_dirty_{false};  // Tracks if in-memory state differs from disk )

  // Internal helper: Save bans (must be called with banned_mutex_ held)
  bool SaveBansInternal();
};

}  // namespace network
}  // namespace unicity
