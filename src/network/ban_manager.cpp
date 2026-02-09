// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "network/ban_manager.hpp"

#include "util/files.hpp"
#include "util/logging.hpp"
#include "util/netaddress.hpp"
#include "util/time.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <limits>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace unicity {
namespace network {

BanManager::BanManager(const std::string& datadir) {
  if (!datadir.empty()) {
    std::filesystem::path dir(datadir);
    ban_file_path_ = (dir / "banlist.json").string();
  }
}

std::string BanManager::GetBanlistPath() const {
  if (ban_file_path_.empty()) {
    return "";
  }
  return ban_file_path_;
}

bool BanManager::LoadBans(const std::string& datadir) {
  std::lock_guard<std::mutex> lock(banned_mutex_);

  if (ban_file_path_.empty()) {
    if (datadir.empty()) {
      LOG_NET_TRACE("BanManager: no datadir specified, skipping ban load");
      return true;
    }
    std::filesystem::path dir(datadir);
    ban_file_path_ = (dir / "banlist.json").string();
  }

  std::ifstream file(ban_file_path_);
  if (!file.is_open()) {
    LOG_NET_TRACE("BanManager: no existing banlist found at {}", ban_file_path_);
    return true;  // Not an error - first run
  }

  try {
    json j;
    file >> j;

    int64_t now = util::GetTime();
    size_t loaded = 0;
    size_t expired = 0;

    for (const auto& [address, ban_data] : j.items()) {
      BanEntry entry;
      entry.version = ban_data.value("version", BanEntry::CURRENT_VERSION);
      entry.create_time = ban_data.value("create_time", int64_t(0));
      entry.ban_until = ban_data.value("ban_until", int64_t(0));

      // Skip expired bans
      if (entry.IsExpired(now)) {
        expired++;
        continue;
      }

      banned_[address] = entry;
      loaded++;
    }

    LOG_NET_TRACE("BanManager: loaded {} bans from {} (skipped {} expired)", loaded, ban_file_path_, expired);

    // Mark dirty if we skipped expired entries, clear otherwise
    is_dirty_ = (expired > 0);

    // Persist cleaned list if we skipped expired entries and autosave is enabled
    if (expired > 0 && ban_auto_save_ && !ban_file_path_.empty()) {
      SaveBansInternal();
    }
    return true;

  } catch (const std::exception& e) {
    LOG_NET_ERROR("BanManager: failed to parse {}: {}", ban_file_path_, e.what());
    return false;
  }
}

bool BanManager::SaveBansInternal() {
  if (ban_file_path_.empty()) {
    LOG_NET_TRACE("BanManager: no ban file path set, skipping save");
    return true;
  }

  // Defensive sweep: remove expired entries before writing to ensure clean data.
  // Note: We intentionally do NOT set is_dirty_ here. If is_dirty_ is false,
  // we skip the save entirely. Expired entries remain on disk but are skipped
  // on next LoadBans() which handles cleanup. Use SweepBanned() for active cleanup.
  int64_t now = util::GetTime();
  for (auto it = banned_.begin(); it != banned_.end();) {
    if (it->second.IsExpired(now)) {
      it = banned_.erase(it);
    } else {
      ++it;
    }
  }

  if (!is_dirty_) {
    return true;
  }

  try {
    json j;
    for (const auto& [address, entry] : banned_) {
      j[address] = {{"version", entry.version}, {"create_time", entry.create_time}, {"ban_until", entry.ban_until}};
    }

    std::string data = j.dump(2);

    // Use centralized atomic write with 0600 permissions (owner-only)
    // This provides: temp file creation, partial write handling, fsync,
    // directory sync, and atomic rename - more robust than previous implementation
    if (!util::atomic_write_file(ban_file_path_, data, 0600)) {
      LOG_NET_ERROR("BanManager: failed to save {}", ban_file_path_);
      // Keep is_dirty_ = true so save will be retried
      return false;
    }

    LOG_NET_TRACE("BanManager: saved {} bans to {}", banned_.size(), ban_file_path_);
    is_dirty_ = false;  // Clear dirty flag on successful save
    return true;

  } catch (const std::exception& e) {
    LOG_NET_ERROR("BanManager: failed to save {}: {}", ban_file_path_, e.what());
    // Keep is_dirty_ = true so save will be retried
    return false;
  }
}

bool BanManager::SaveBans() {
  std::lock_guard<std::mutex> lock(banned_mutex_);
  return SaveBansInternal();
}

void BanManager::Ban(const std::string& address, int64_t ban_time_offset) {
  auto normalized = util::ValidateAndNormalizeIP(address);
  if (!normalized.has_value()) {
    LOG_NET_ERROR("BanManager: refusing to ban invalid IP address: {}", address);
    return;
  }

  // The whitelist is only checked at connection time, not ban time.
  std::lock_guard<std::mutex> lock(banned_mutex_);

  int64_t now = util::GetTime();

  // ban_time_offset <= 0 means "use default ban time"
  int64_t actual_duration = ban_time_offset > 0 ? ban_time_offset : DEFAULT_BAN_TIME_SEC;
  int64_t ban_until = now + actual_duration;

  // only update if new ban extends the existing ban
  auto it = banned_.find(*normalized);
  if (it != banned_.end() && it->second.ban_until >= ban_until) {
    LOG_NET_TRACE("BanManager: {} already banned until {} (not shortening to {})", *normalized, it->second.ban_until,
                  ban_until);
    return;
  }

  BanEntry entry(now, ban_until);
  banned_[*normalized] = entry;
  is_dirty_ = true;  // Mark as modified

  LOG_NET_WARN("BanManager: banned {} until {} ({}s)", *normalized, ban_until, actual_duration);
  // Auto-save
  if (ban_auto_save_ && !ban_file_path_.empty()) {
    SaveBansInternal();
  }
}

void BanManager::Unban(const std::string& address) {
  auto normalized = util::ValidateAndNormalizeIP(address);
  if (!normalized.has_value()) {
    LOG_NET_ERROR("BanManager: refusing to unban invalid IP address: {}", address);
    return;
  }

  std::lock_guard<std::mutex> lock(banned_mutex_);

  auto it = banned_.find(*normalized);
  if (it != banned_.end()) {
    banned_.erase(it);
    is_dirty_ = true;  // Mark as modified
    LOG_NET_INFO("BanManager: unbanned {}", *normalized);

    // Auto-save
    if (ban_auto_save_ && !ban_file_path_.empty()) {
      SaveBansInternal();
    }
  } else {
    LOG_NET_TRACE("BanManager: address {} was not banned", *normalized);
  }
}

bool BanManager::IsBanned(const std::string& address) const {
  auto normalized = util::ValidateAndNormalizeIP(address);
  if (!normalized.has_value()) {
    return false;
  }

  // Return the actual ban status regardless of whitelist.
  // The whitelist is checked separately at connection time, not when querying ban status.
  std::lock_guard<std::mutex> lock(banned_mutex_);

  auto it = banned_.find(*normalized);
  if (it == banned_.end()) {
    return false;
  }

  // Check if expired
  int64_t now = util::GetTime();
  return !it->second.IsExpired(now);
}

void BanManager::Discourage(const std::string& address) {
  // Validate and normalize the address
  auto normalized = util::ValidateAndNormalizeIP(address);
  if (!normalized.has_value()) {
    LOG_NET_ERROR("BanManager: refusing to discourage invalid IP address: {}", address);
    return;
  }

  // The whitelist is only checked at connection time, not at discourage time.
  std::lock_guard<std::mutex> lock(discouraged_mutex_);

  int64_t now = util::GetTime();

  // Check if already discouraged - if so, don't update insertion time
  // (preserves eviction ordering based on first discouragement)
  if (discouraged_.find(*normalized) != discouraged_.end()) {
    return;  // Already discouraged
  }

  // Enforce upper bound BEFORE insertion - evict oldest entry
  if (discouraged_.size() >= MAX_DISCOURAGED) {
    auto victim = discouraged_.end();
    int64_t oldest_time = std::numeric_limits<int64_t>::max();
    for (auto it = discouraged_.begin(); it != discouraged_.end(); ++it) {
      if (it->second < oldest_time) {
        oldest_time = it->second;
        victim = it;
      }
    }
    if (victim != discouraged_.end()) {
      LOG_NET_TRACE("BanManager: evicting oldest discouraged entry {} to enforce size cap ({} >= {})", victim->first,
                    discouraged_.size(), MAX_DISCOURAGED);
      discouraged_.erase(victim);
    }
  }

  // Insert with current time (for eviction ordering - oldest first)
  discouraged_[*normalized] = now;
  LOG_NET_INFO("BanManager: discouraged {}", *normalized);
}

bool BanManager::IsDiscouraged(const std::string& address) const {
  // Validate and normalize the address
  auto normalized = util::ValidateAndNormalizeIP(address);
  if (!normalized.has_value()) {
    // Invalid address cannot be discouraged
    return false;
  }

  std::lock_guard<std::mutex> lock(discouraged_mutex_);

  // No expiry - entries persist until evicted by capacity pressure
  return discouraged_.find(*normalized) != discouraged_.end();
}

void BanManager::ClearDiscouraged() {
  std::lock_guard<std::mutex> lock(discouraged_mutex_);
  discouraged_.clear();
  LOG_NET_TRACE("BanManager: cleared all discouraged addresses");
}

void BanManager::SweepDiscouraged() {
  // No-op: discouraged entries no longer expire
  // Entries are only removed when evicted due to capacity pressure
  // Keep method for API compatibility
}

std::map<std::string, BanManager::BanEntry> BanManager::GetBanned() const {
  std::lock_guard<std::mutex> lock(banned_mutex_);
  return banned_;
}

void BanManager::ClearBanned() {
  std::lock_guard<std::mutex> lock(banned_mutex_);
  banned_.clear();
  is_dirty_ = true;  // Mark as modified
  LOG_NET_TRACE("BanManager: cleared all bans");

  // Auto-save
  if (ban_auto_save_ && !ban_file_path_.empty()) {
    SaveBansInternal();
  }
}

void BanManager::SweepBanned() {
  std::lock_guard<std::mutex> lock(banned_mutex_);

  int64_t now = util::GetTime();
  size_t before = banned_.size();

  for (auto it = banned_.begin(); it != banned_.end();) {
    if (it->second.IsExpired(now)) {
      LOG_NET_TRACE("BanManager: sweeping expired ban for {}", it->first);
      it = banned_.erase(it);
    } else {
      ++it;
    }
  }

  size_t removed = before - banned_.size();
  if (removed > 0) {
    is_dirty_ = true;  // Mark as modified
    LOG_NET_TRACE("BanManager: swept {} expired bans", removed);

    // Auto-save
    if (ban_auto_save_ && !ban_file_path_.empty()) {
      SaveBansInternal();
    }
  }
}

}  // namespace network
}  // namespace unicity
