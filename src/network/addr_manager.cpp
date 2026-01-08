// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "network/addr_manager.hpp"

#include "util/files.hpp"
#include "util/logging.hpp"
#include "util/netaddress.hpp"
#include "util/time.hpp"

#include <algorithm>
#include <cmath>
#include <filesystem>
#include <fstream>

#include <nlohmann/json.hpp>

namespace unicity {
namespace network {

// How old addresses can maximally be
static constexpr uint32_t ADDRMAN_HORIZON_DAYS = 30;

// After how many failed attempts we give up on a new node
static constexpr uint32_t ADDRMAN_RETRIES = 3;

// How many successive failures over ADDRMAN_MIN_FAIL_DAYS before an address
// with prior success (last_success > 0) is considered "terrible"
// Used in: is_terrible() to filter out repeatedly failing previously-good addresses
static constexpr uint32_t ADDRMAN_MAX_FAILURES = 10;

// In at least this duration
static constexpr uint32_t ADDRMAN_MIN_FAIL_DAYS = 7;

// After this many consecutive failures, demote a TRIED address back to NEW table
//   - ADDRMAN_MAX_FAILURES: marks address as "terrible" (for filtering)
//   - TRIED_DEMOTION_THRESHOLD: triggers table movement (tried→new)
static constexpr uint32_t TRIED_DEMOTION_THRESHOLD = 10;

// An address in the NEW table is considered "stale" if we haven't heard about it for this many days.
// Stale NEW entries are removed by cleanup_stale(); TRIED entries are retained even if old (they worked before).
static constexpr uint32_t STALE_AFTER_DAYS = 30;

static constexpr uint32_t SECONDS_PER_DAY = 86400;  // Seconds in one day (utility for time math)

// Selection tuning constants:
// - SELECT_TRIED_BIAS_PERCENT: initial probability (0..100) to draw from TRIED vs NEW,
//   preferring known-good peers while still exploring NEW.
static constexpr int SELECT_TRIED_BIAS_PERCENT = 50;

// Probabilistic selection constants for GetChance():
// - GETCHANCE_RECENT_ATTEMPT_SEC: if address was tried within this window, reduce selection
//   probability to 1% (deprioritize but don't eliminate recently-tried addresses)
static constexpr uint32_t GETCHANCE_RECENT_ATTEMPT_SEC = 600;  // 10 minutes

// Time-based filtering constants for is_terrible():
// - TERRIBLE_GRACE_PERIOD_SEC: never mark an address as terrible if tried within this window
//   (gives addresses a brief grace period after connection attempts)
static constexpr uint32_t TERRIBLE_GRACE_PERIOD_SEC = 60;  // 1 minute

// - TERRIBLE_FUTURE_TIMESTAMP_SEC: reject addresses with timestamps this far in the future
//   (protects against "flying DeLorean" timestamp attacks)
static constexpr uint32_t TERRIBLE_FUTURE_TIMESTAMP_SEC = 600;  // 10 minutes

// SECURITY: Per-netgroup limits to prevent single /16 from dominating address tables
// These limits ensure address diversity even without full bucket-based implementation.
// An attacker controlling a single /16 subnet cannot fill more than these slots.
static constexpr size_t MAX_PER_NETGROUP_NEW = 32;   // Max addresses from same /16 in NEW table
static constexpr size_t MAX_PER_NETGROUP_TRIED = 8;  // Max addresses from same /16 in TRIED table

// AddrInfo implementation
bool AddrInfo::is_stale(uint32_t now) const {
  if (timestamp == 0 || timestamp > now)
    return false;  // avoid underflow and treat future/zero as not stale
  return (now - timestamp) > (STALE_AFTER_DAYS * SECONDS_PER_DAY);
}

bool AddrInfo::is_terrible(uint32_t now) const {
  if (last_try > 0 && now > last_try && (now - last_try) < TERRIBLE_GRACE_PERIOD_SEC) {
    return false;
  }

  // Reject addresses with timestamps too far future
  if (timestamp > now && (timestamp - now) > TERRIBLE_FUTURE_TIMESTAMP_SEC) {
    return true;
  }

  // NOT SEEN IN RECENT HISTORY: Remove addresses not seen in ADDRMAN_HORIZON
  // This applies to BOTH tried and new addresses
  if (timestamp > 0 && now > timestamp) {
    if ((now - timestamp) > (ADDRMAN_HORIZON_DAYS * SECONDS_PER_DAY)) {
      return true;
    }
  }

  // TRIED N TIMES AND NEVER A SUCCESS:
  // NEW addresses: terrible after ADDRMAN_RETRIES (3) failed attempts with no success
  if (last_success == 0 && attempts >= ADDRMAN_RETRIES) {
    return true;
  }

  // N SUCCESSIVE FAILURES IN THE LAST WEEK:
  // Applies to addresses that have succeeded before (last_success > 0)
  // terrible after ADDRMAN_MAX_FAILURES (10) attempts over ADDRMAN_MIN_FAIL_DAYS (7 days)
  // Compare in seconds to avoid integer division truncation
  if (last_success > 0 && now > last_success && attempts >= ADDRMAN_MAX_FAILURES) {
    if ((now - last_success) >= (ADDRMAN_MIN_FAIL_DAYS * SECONDS_PER_DAY)) {
      return true;
    }
  }

  return false;
}

double AddrInfo::GetChance(uint32_t now) const {
  // Probabilistic address selection
  double fChance = 1.0;

  // Deprioritize very recent attempts
  if (last_try > 0 && now > last_try && (now - last_try) < GETCHANCE_RECENT_ATTEMPT_SEC) {
    fChance *= 0.01;  // 1% chance if tried in last 10 minutes
  }

  // Deprioritize after each failed attempt: 0.66^attempts
  // Core caps at 8 attempts: pow(0.66, std::min(nAttempts, 8))
  // This gives: 1 fail=66%, 2=44%, 3=29%, 4=19%, 5=13%, 6=8%, 7=5%, 8+=3.6%
  fChance *= std::pow(0.66, std::min(attempts, 8));

  return fChance;
}

namespace {
// Helper: Normalize IPv4-compatible addresses to IPv4-mapped
// IPv4-compatible (deprecated): ::w.x.y.z (12 zeros, then 4-byte IPv4)
// IPv4-mapped (canonical):     ::ffff:w.x.y.z (10 zeros, 0xff 0xff, then 4-byte IPv4)
protocol::NetworkAddress NormalizeAddress(const protocol::NetworkAddress& addr) {
  protocol::NetworkAddress normalized = addr;

  // Check if it's IPv4-compatible format: first 12 bytes zero, last 4 non-zero
  bool is_ipv4_compatible = std::all_of(addr.ip.begin(), addr.ip.begin() + 12, [](uint8_t b) { return b == 0; }) &&
                            !std::all_of(addr.ip.begin() + 12, addr.ip.end(), [](uint8_t b) { return b == 0; });

  if (is_ipv4_compatible) {
    // Convert to IPv4-mapped format
    std::fill(normalized.ip.begin(), normalized.ip.begin() + 10, 0);
    normalized.ip[10] = 0xff;
    normalized.ip[11] = 0xff;
    // Last 4 bytes (IPv4 address) remain unchanged
  }

  return normalized;
}

// Helper: Serialize AddrInfo to JSON
nlohmann::json SerializeAddrInfo(const AddrInfo& info) {
  using json = nlohmann::json;
  json addr;

  // Serialize IP address
  addr["ip"] = json::array();
  for (size_t i = 0; i < 16; ++i) {
    addr["ip"].push_back(info.address.ip[i]);
  }

  // Serialize other fields
  addr["port"] = info.address.port;
  addr["services"] = info.address.services;
  addr["timestamp"] = info.timestamp;
  addr["last_try"] = info.last_try;
  addr["last_count_attempt"] = info.last_count_attempt;
  addr["last_success"] = info.last_success;
  addr["attempts"] = info.attempts;

  // Serialize source 
  if (info.has_source()) {
    addr["source_ip"] = json::array();
    for (size_t i = 0; i < 16; ++i) {
      addr["source_ip"].push_back(info.source.ip[i]);
    }
    addr["source_port"] = info.source.port;
  }

  return addr;
}

// Helper: Deserialize AddrInfo from JSON
// Returns true on success, false if validation fails
bool DeserializeAddrInfo(const nlohmann::json& addr_json, AddrInfo& info) {
  try {
    protocol::NetworkAddress addr;

    // Deserialize IP address
    if (addr_json["ip"].size() != 16) {
      return false;
    }
    for (size_t i = 0; i < 16; ++i) {
      addr.ip[i] = addr_json["ip"][i].get<uint8_t>();
    }

    // Deserialize other fields
    addr.port = addr_json["port"].get<uint16_t>();
    addr.services = addr_json["services"].get<uint64_t>();

    info.address = addr;
    info.timestamp = addr_json["timestamp"].get<uint32_t>();
    info.last_try = addr_json["last_try"].get<uint32_t>();
    info.last_count_attempt = addr_json.value("last_count_attempt", uint32_t{0});
    info.last_success = addr_json["last_success"].get<uint32_t>();
    info.attempts = addr_json["attempts"].get<int>();

    // Deserialize source 
    if (addr_json.contains("source_ip") && addr_json["source_ip"].size() == 16) {
      for (size_t i = 0; i < 16; ++i) {
        info.source.ip[i] = addr_json["source_ip"][i].get<uint8_t>();
      }
      info.source.port = addr_json.value("source_port", uint16_t{0});
    }
    // If source_ip not present, info.source remains default (all zeros = no source tracking)

    return true;
  } catch (...) {
    return false;
  }
}
}  // anonymous namespace

// AddressManager implementation
AddressManager::AddressManager() : rng_(std::random_device{}()) {}

uint32_t AddressManager::now() const {
  return static_cast<uint32_t>(util::GetTime());
}

void AddressManager::rebuild_key_vectors() {
  // Performance optimization: Rebuild O(1) lookup vectors and netgroup caches after map modifications
  // Called after: cleanup, Load (bulk operations where incremental updates aren't feasible)
  tried_keys_.clear();
  tried_keys_.reserve(tried_.size());
  tried_netgroup_counts_.clear();
  for (const auto& [key, info] : tried_) {
    tried_keys_.push_back(key);
    std::string netgroup = info.address.get_netgroup();
    if (!netgroup.empty()) {
      tried_netgroup_counts_[netgroup]++;
    }
  }

  new_keys_.clear();
  new_keys_.reserve(new_.size());
  new_netgroup_counts_.clear();
  source_counts_.clear();  // Rebuild source counts (only for NEW table addresses with source tracking)
  for (const auto& [key, info] : new_) {
    new_keys_.push_back(key);
    std::string netgroup = info.address.get_netgroup();
    if (!netgroup.empty()) {
      new_netgroup_counts_[netgroup]++;
    }
    // Rebuild source counts for addresses with source tracking
    if (info.has_source()) {
      std::string source_group = info.source.get_netgroup();
      if (!source_group.empty()) {
        source_counts_[source_group]++;
      }
    }
  }
}

std::mt19937 AddressManager::make_request_rng() {
  // Per-request entropy prevents offline seed brute-force attacks

  std::seed_seq seq{static_cast<uint32_t>(rng_()),
                    static_cast<uint32_t>(std::chrono::steady_clock::now().time_since_epoch().count())};
  return std::mt19937(seq);
}

bool AddressManager::add(const protocol::NetworkAddress& addr,
                         const protocol::NetworkAddress& source,
                         uint32_t timestamp) {
  std::lock_guard<std::mutex> lock(mutex_);
  return add_internal(addr, source, timestamp);
}

bool AddressManager::add_internal(const protocol::NetworkAddress& addr,
                                  const protocol::NetworkAddress& source,
                                  uint32_t timestamp) {
  // Normalize IPv4-compatible addresses to IPv4-mapped
  protocol::NetworkAddress normalized = NormalizeAddress(addr);

  // Validate address is routable
  if (!normalized.is_routable()) {
    return false;
  }

  const uint32_t now_s = now();
  // Clamp future or absurdly old timestamps to now
  const uint32_t TEN_YEARS = 10u * 365u * 24u * 60u * 60u;
  uint32_t eff_ts = (timestamp == 0 ? now_s : timestamp);
  if (eff_ts > now_s || now_s - eff_ts > TEN_YEARS)
    eff_ts = now_s;

  AddrInfo info(normalized, eff_ts);
  info.source = source;  
  AddrKey key(normalized);

  // Check if already in tried table
  if (auto it = tried_.find(key); it != tried_.end()) {
    // Update timestamp if newer
    if (eff_ts > it->second.timestamp) {
      it->second.timestamp = eff_ts;
    }
    return false;  // Already have it
  }

  // Check if already in new table
  if (auto it = new_.find(key); it != new_.end()) {
    // Update timestamp if newer
    if (eff_ts > it->second.timestamp) {
      it->second.timestamp = eff_ts;
    }
    return false;  // Already have it
  }

  // Filter out terrible addresses
  if (info.is_terrible(now_s)) {
    return false;
  }

  // Check per-netgroup limit to prevent single /16 from dominating NEW table
  std::string netgroup = normalized.get_netgroup();
  if (!netgroup.empty()) {
    size_t netgroup_count = new_netgroup_counts_[netgroup];  // defaults to 0 if not present
    if (netgroup_count >= MAX_PER_NETGROUP_NEW) {
      LOG_NET_TRACE("Rejecting address from netgroup {} (limit {} reached)", netgroup, MAX_PER_NETGROUP_NEW);
      return false;
    }
  }

  // Check per-source limit
  // Only applies when source was provided (has_source() == true)
  if (info.has_source()) {
    std::string source_group = source.get_netgroup();
    if (!source_group.empty()) {
      size_t source_count = source_counts_[source_group];  // defaults to 0 if not present
      if (source_count >= MAX_ADDRESSES_PER_SOURCE) {
        LOG_NET_TRACE("Rejecting address from source {} (per-source limit {} reached)", source_group,
                      MAX_ADDRESSES_PER_SOURCE);
        return false;
      }
    }
  }

  // Check capacity and evict if needed
  if (new_.size() >= MAX_NEW_ADDRESSES) {
    evict_worst_new_address();
  }

  // Add to new table
  new_[key] = info;
  new_keys_.push_back(key);  // O(1) append to key vector

  // Update netgroup count cache
  if (!netgroup.empty()) {
    new_netgroup_counts_[netgroup]++;
  }

  // Update source count cache 
  if (info.has_source()) {
    std::string source_group = source.get_netgroup();
    if (!source_group.empty()) {
      source_counts_[source_group]++;
    }
  }

  return true;
}

size_t AddressManager::add_multiple(const std::vector<protocol::TimestampedAddress>& addresses,
                                    const protocol::NetworkAddress& source) {
  std::lock_guard<std::mutex> lock(mutex_);
  size_t added = 0;
  for (const auto& ts_addr : addresses) {
    if (add_internal(ts_addr.address, source, ts_addr.timestamp)) {
      added++;
    }
  }

  return added;
}

void AddressManager::attempt(const protocol::NetworkAddress& addr, bool fCountFailure) {
  std::lock_guard<std::mutex> lock(mutex_);
  protocol::NetworkAddress normalized = NormalizeAddress(addr);
  AddrKey key(normalized);
  uint32_t t = now();

  // Try new table first
  if (auto it = new_.find(key); it != new_.end()) {
    it->second.last_try = t;

    if (fCountFailure && it->second.last_count_attempt < m_last_good_) {
      it->second.last_count_attempt = t;
      it->second.attempts++;
    }
    return;
  }

  // Update tried table
  if (auto it = tried_.find(key); it != tried_.end()) {
    it->second.last_try = t;

    // Same logic for tried addresses
    if (fCountFailure && it->second.last_count_attempt < m_last_good_) {
      it->second.last_count_attempt = t;
      it->second.attempts++;
    }
    return;
  }

  // Address not found - this is normal for manual connections, DNS seeds, anchors
  LOG_NET_TRACE("AddressManager::attempt() called for unknown address");
}

void AddressManager::good(const protocol::NetworkAddress& addr) {
  std::lock_guard<std::mutex> lock(mutex_);
  protocol::NetworkAddress normalized = NormalizeAddress(addr);
  AddrKey key(normalized);
  uint32_t current_time = now();

  // This is used in attempt() to prevent double-counting attempts
  m_last_good_ = current_time;

  // Check if in new table
  auto new_it = new_.find(key);
  if (new_it != new_.end()) {
    // SECURITY: Check per-netgroup limit before moving to TRIED table
    std::string netgroup = normalized.get_netgroup();
    if (!netgroup.empty()) {
      // O(1) lookup using cached netgroup counts
      size_t netgroup_count = tried_netgroup_counts_[netgroup];  // defaults to 0 if not present
      if (netgroup_count >= MAX_PER_NETGROUP_TRIED) {
        // Don't move to tried, but still update success info in NEW table
        new_it->second.last_success = current_time;
        new_it->second.last_try = current_time;
        new_it->second.attempts = 0;
        LOG_NET_TRACE("Address kept in NEW (netgroup {} has {} in TRIED, limit {})", netgroup, netgroup_count,
                      MAX_PER_NETGROUP_TRIED);
        return;
      }
    }

    // Check tried table capacity and evict if needed
    if (tried_.size() >= MAX_TRIED_ADDRESSES) {
      evict_worst_tried_address();
    }

    // Move from new to tried
    new_it->second.tried = true;
    new_it->second.last_success = current_time;
    new_it->second.last_try = current_time;
    new_it->second.attempts = 0;  // Reset failure count

    // Decrement source count before moving 
    if (new_it->second.has_source()) {
      std::string source_group = new_it->second.source.get_netgroup();
      if (!source_group.empty() && source_counts_[source_group] > 0) {
        source_counts_[source_group]--;
      }
    }

    tried_[key] = std::move(new_it->second);
    new_.erase(new_it);

    // Performance: Incremental vector updates (O(n) removal, O(1) append)
    new_keys_.erase(std::remove(new_keys_.begin(), new_keys_.end(), key), new_keys_.end());
    tried_keys_.push_back(key);

    // Update netgroup count caches (move from new to tried)
    if (!netgroup.empty()) {
      if (new_netgroup_counts_[netgroup] > 0) {
        new_netgroup_counts_[netgroup]--;
      }
      tried_netgroup_counts_[netgroup]++;
    }

    LOG_NET_TRACE("Address moved from 'new' to 'tried'. New size: {}, Tried size: {}", new_.size(), tried_.size());
    return;
  }

  // Already in tried table
  auto tried_it = tried_.find(key);
  if (tried_it != tried_.end()) {
    tried_it->second.last_success = current_time;
    tried_it->second.last_try = current_time;
    tried_it->second.attempts = 0;  // Reset failure count
    return;
  }

  LOG_NET_WARN("AddressManager::good() called for unknown address");
}

void AddressManager::failed(const protocol::NetworkAddress& addr) {
  std::lock_guard<std::mutex> lock(mutex_);
  protocol::NetworkAddress normalized = NormalizeAddress(addr);
  AddrKey key(normalized);

  // Update in new table
  auto new_it = new_.find(key);
  if (new_it != new_.end()) {
    new_it->second.attempts++;

    // Remove if too many failures
    if (new_it->second.is_terrible(now())) {
      // Update netgroup count cache before removing
      std::string netgroup = normalized.get_netgroup();
      if (!netgroup.empty() && new_netgroup_counts_[netgroup] > 0) {
        new_netgroup_counts_[netgroup]--;
      }

      // Decrement source count if this address had source tracking
      if (new_it->second.has_source()) {
        std::string source_group = new_it->second.source.get_netgroup();
        if (!source_group.empty() && source_counts_[source_group] > 0) {
          source_counts_[source_group]--;
        }
      }

      new_.erase(new_it);
      // Performance: Incremental vector update (O(n) removal)
      new_keys_.erase(std::remove(new_keys_.begin(), new_keys_.end(), key), new_keys_.end());
    }
    return;
  }

  // Update in tried table
  auto tried_it = tried_.find(key);
  if (tried_it != tried_.end()) {
    tried_it->second.attempts++;

    // Move back to new table if too many failures
    if (tried_it->second.attempts >= TRIED_DEMOTION_THRESHOLD) {
      // Update netgroup count caches (move from tried to new)
      std::string netgroup = normalized.get_netgroup();
      if (!netgroup.empty()) {
        if (tried_netgroup_counts_[netgroup] > 0) {
          tried_netgroup_counts_[netgroup]--;
        }
        new_netgroup_counts_[netgroup]++;
      }

      tried_it->second.tried = false;
      new_[key] = std::move(tried_it->second);
      tried_.erase(tried_it);
      // Performance: Incremental vector updates (O(n) removal, O(1) append)
      tried_keys_.erase(std::remove(tried_keys_.begin(), tried_keys_.end(), key), tried_keys_.end());
      new_keys_.push_back(key);
    }
    return;
  }

  // Address not found - this is normal for manual connections, DNS seeds, anchors
  LOG_NET_TRACE("AddressManager::failed() called for unknown address");
}

std::optional<protocol::NetworkAddress> AddressManager::select() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (tried_.empty() && new_.empty()) {
    return std::nullopt;
  }

  // Use per-request RNG to prevent seed prediction attacks
  auto local_rng = make_request_rng();

  const uint32_t now_ts = now();

  // Escalating chance_factor for probabilistic selection
  // Start with chance_factor = 1.0, multiply by 1.2 after each failed selection
  // This ensures we eventually select something even if all addresses have low GetChance()
  double chance_factor = 1.0;
  std::uniform_real_distribution<double> chance_dist(0.0, 1.0);
  std::uniform_int_distribution<int> bias_dist(0, 99);

  // Escalating chance_factor, We'll use a reasonable iteration limit
  // to prevent infinite loops in edge cases
  const size_t max_iterations = 200;

  for (size_t iteration = 0; iteration < max_iterations; ++iteration) {
    // Decide which table to search THIS iteration (allows alternation)
    // Prefer tried addresses (SELECT_TRIED_BIAS_PERCENT% of the time)
    bool use_tried = !tried_keys_.empty() && (new_keys_.empty() || bias_dist(local_rng) < SELECT_TRIED_BIAS_PERCENT);

    // Pick random entry from selected table (O(1) using key vectors)
    if (use_tried) {
      if (tried_keys_.empty())
        continue;
      std::uniform_int_distribution<size_t> idx_dist(0, tried_keys_.size() - 1);
      size_t idx = idx_dist(local_rng);
      const AddrKey& key = tried_keys_[idx];
      auto it = tried_.find(key);
      if (it == tried_.end())
        continue;  // Key vector out of sync, skip
      const AddrInfo& info = it->second;

      // Core uses: if (randbits(30) < chance_factor * GetChance() * (1<<30))
      // We use: if (rand(0,1) < chance_factor * GetChance())
      double effective_chance = std::min(1.0, chance_factor * info.GetChance(now_ts));
      if (chance_dist(local_rng) < effective_chance) {
        return info.address;
      }
    } else {
      if (new_keys_.empty())
        continue;
      std::uniform_int_distribution<size_t> idx_dist(0, new_keys_.size() - 1);
      size_t idx = idx_dist(local_rng);
      const AddrKey& key = new_keys_[idx];
      auto it = new_.find(key);
      if (it == new_.end())
        continue;  // Key vector out of sync, skip
      const AddrInfo& info = it->second;

      double effective_chance = std::min(1.0, chance_factor * info.GetChance(now_ts));
      if (chance_dist(local_rng) < effective_chance) {
        return info.address;
      }
    }

    // Failed to select - increase chance_factor for next iteration
    chance_factor *= 1.2;
  }

  // Escalating chance_factor guarantees selection before 200 iterations.
  LOG_WARN("select() exhausted {} iterations - bug in key vector sync", max_iterations);
  return std::nullopt;
}

std::optional<protocol::NetworkAddress> AddressManager::select_new_for_feeler() {
  std::lock_guard<std::mutex> lock(mutex_);
  // FEELER connections test addresses from "new" table (never connected before)
  // This helps move working addresses from "new" to "tried"
  if (new_keys_.empty()) {
    return std::nullopt;
  }

  // Use per-request RNG to prevent seed prediction attacks
  auto local_rng = make_request_rng();

  // Prefer addresses not tried in the last 10 minutes
  // This prevents wasting feeler connections on recently-probed peers
  static constexpr uint32_t FEELER_MIN_RETRY_SECONDS = 600;  // 10 minutes
  const uint32_t now_ts = now();

  // Try up to 50 random selections to find an address not recently tried
  // If all addresses were recently tried, fall back to any address
  for (int attempts = 0; attempts < 50; ++attempts) {
    if (new_keys_.empty())
      return std::nullopt;  // Defense-in-depth
    std::uniform_int_distribution<size_t> idx_dist(0, new_keys_.size() - 1);
    size_t idx = idx_dist(local_rng);
    const AddrKey& key = new_keys_[idx];
    auto it = new_.find(key);
    if (it == new_.end())
      continue;  // Key vector out of sync, skip
    const AddrInfo& info = it->second;

    // Prefer addresses never tried or tried more than 10 minutes ago
    if (info.last_try == 0 || now_ts < info.last_try || (now_ts - info.last_try) >= FEELER_MIN_RETRY_SECONDS) {
      return info.address;
    }
  }

  // Fallback: all addresses were recently tried, return any address
  if (new_keys_.empty())
    return std::nullopt;
  std::uniform_int_distribution<size_t> idx_dist(0, new_keys_.size() - 1);
  size_t idx = idx_dist(local_rng);
  const AddrKey& key = new_keys_[idx];
  auto it = new_.find(key);
  if (it == new_.end())
    return std::nullopt;  // Key vector out of sync
  return it->second.address;
}

std::vector<protocol::TimestampedAddress> AddressManager::get_addresses(size_t max_count) {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<protocol::TimestampedAddress> result;
  result.reserve(std::min(max_count, tried_.size() + new_.size()));

  const uint32_t now_s = now();

  // Add tried addresses first (filter invalid/terrible defensively)
  for (const auto& [key, info] : tried_) {
    if (result.size() >= max_count)
      break;
    if (!info.address.is_routable())
      continue;
    if (info.is_terrible(now_s))
      continue;
    result.push_back({info.timestamp, info.address});
  }

  // Add new addresses (skip invalid/terrible)
  for (const auto& [key, info] : new_) {
    if (result.size() >= max_count)
      break;
    if (!info.address.is_routable())
      continue;
    if (info.is_terrible(now_s))
      continue;
    result.push_back({info.timestamp, info.address});
  }

  // Shuffle for privacy (prevents enumeration of address table order)
  auto local_rng = make_request_rng();
  std::shuffle(result.begin(), result.end(), local_rng);

  return result;
}

size_t AddressManager::size() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return tried_.size() + new_.size();
}

size_t AddressManager::tried_count() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return tried_.size();
}

size_t AddressManager::new_count() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return new_.size();
}

void AddressManager::cleanup_stale() {
  std::lock_guard<std::mutex> lock(mutex_);
  uint32_t current_time = now();

  size_t removed = 0;
  // Remove stale addresses from new table
  for (auto it = new_.begin(); it != new_.end();) {
    if (it->second.is_stale(current_time) || it->second.is_terrible(current_time)) {
      it = new_.erase(it);
      removed++;
    } else {
      ++it;
    }
  }

  // Rebuild new_keys_ if any entries were removed
  if (removed > 0) {
    rebuild_key_vectors();
  }

  // Keep tried addresses even if old (they worked before)
}

bool AddressManager::Save(const std::string& filepath) {
  std::lock_guard<std::mutex> lock(mutex_);
  using json = nlohmann::json;

  try {
    size_t total_size = tried_.size() + new_.size();
    LOG_NET_TRACE("saving {} peer addresses to {}", total_size, filepath);

    json root;
    root["version"] = 2;  // v2 adds source tracking for Sybil resistance
    root["tried_count"] = tried_.size();
    root["new_count"] = new_.size();
    root["m_last_good"] = m_last_good_;

    // Save tried addresses
    json tried_array = json::array();
    for (const auto& [key, info] : tried_) {
      tried_array.push_back(SerializeAddrInfo(info));
    }
    root["tried"] = tried_array;

    // Save new addresses
    json new_array = json::array();
    for (const auto& [key, info] : new_) {
      new_array.push_back(SerializeAddrInfo(info));
    }
    root["new"] = new_array;

    // Atomic write: write to temp then rename (with fsync for durability)
    std::string data = root.dump(2);

    // Use centralized atomic write with 0600 permissions (owner-only)
    if (!util::atomic_write_file(filepath, data, 0600)) {
      LOG_NET_ERROR("Failed to save addresses to {}", filepath);
      return false;
    }

    LOG_NET_TRACE("successfully saved {} addresses ({} tried, {} new)", total_size, tried_.size(), new_.size());
    return true;

  } catch (const std::exception& e) {
    LOG_NET_ERROR("Exception during Save: {}", e.what());
    return false;
  }
}

bool AddressManager::Load(const std::string& filepath) {
  std::lock_guard<std::mutex> lock(mutex_);
  using json = nlohmann::json;

  try {
    LOG_NET_TRACE("loading peer addresses from {}", filepath);

    // Open file
    std::ifstream file(filepath);
    if (!file.is_open()) {
      LOG_NET_TRACE("peer address file not found: {} (starting fresh)", filepath);
      return false;
    }

    // Parse JSON
    json root;
    file >> root;
    file.close();

    // Validate version (v1 = original, v2 = source tracking)
    int version = root.value("version", 0);
    if (version < 1 || version > 2) {
      LOG_NET_ERROR("Unsupported peers file version: {}", version);
      return false;
    }
    // v1 files will load fine - source field will be all zeros (no source tracking)

    // Rely on nlohmann::json parser error detection for corruption
    // (manual checksums over JSON text are fragile to whitespace/key-order changes)

    // Load m_last_good_
    m_last_good_ = root.value("m_last_good", 1);  // Default to 1 if not present

    // Clear existing data
    tried_.clear();
    new_.clear();

    // Load tried addresses
    if (root.contains("tried")) {
      for (const auto& addr_json : root["tried"]) {
        AddrInfo info;
        if (!DeserializeAddrInfo(addr_json, info)) {
          LOG_NET_TRACE("invalid address in tried table, skipping");
          continue;
        }
        info.tried = true;
        tried_[AddrKey(info.address)] = info;
      }
    }

    // Load new addresses
    if (root.contains("new")) {
      for (const auto& addr_json : root["new"]) {
        AddrInfo info;
        if (!DeserializeAddrInfo(addr_json, info)) {
          LOG_NET_TRACE("invalid address in new table, skipping");
          continue;
        }
        info.tried = false;
        new_[AddrKey(info.address)] = info;
      }
    }

    // Performance: Rebuild key vectors after loading
    // Exception safety: If rebuild throws, clear everything to maintain invariants
    try {
      rebuild_key_vectors();
    } catch (const std::bad_alloc& e) {
      LOG_NET_ERROR("Failed to rebuild key vectors (out of memory): {}", e.what());
      tried_.clear();
      new_.clear();
      tried_keys_.clear();
      new_keys_.clear();
      throw;  // Re-throw to outer catch
    }

    // Calculate total size without calling size() to avoid recursive lock
    size_t total_size = tried_.size() + new_.size();
    LOG_NET_INFO("Successfully loaded {} addresses ({} tried, {} new)", total_size, tried_.size(), new_.size());
    return true;

  } catch (const std::exception& e) {
    LOG_NET_ERROR("Exception during Load: {}", e.what());
    tried_.clear();
    new_.clear();
    tried_keys_.clear();
    new_keys_.clear();
    return false;
  }
}

// Evict the worst address from the NEW table to make room for incoming gossip.
//
// The NEW table contains addresses we've heard about but never successfully
// connected to. When at capacity (MAX_NEW_ADDRESSES), we must evict before
// adding new addresses.
//
// Eviction priority (different from TRIED table):
//   1. "Terrible" addresses first - too many failed attempts, too old, etc.
//   2. Oldest timestamp as tie-breaker among non-terrible addresses
//
// Rationale: NEW contains unverified rumors, so oldest/terrible are least valuable.
void AddressManager::evict_worst_new_address() {
  if (new_.empty()) {
    return;
  }

  const uint32_t current_time = now();
  std::optional<AddrKey> worst_key;
  uint32_t oldest_timestamp = UINT32_MAX;

  // Find the worst address to evict
  // Priority: terrible addresses > oldest timestamp
  for (const auto& [key, info] : new_) {
    // Terrible addresses are evicted first
    if (info.is_terrible(current_time)) {
      worst_key = key;
      break;  // Immediately evict any terrible address
    }

    // Among non-terrible addresses, evict oldest timestamp
    if (info.timestamp < oldest_timestamp) {
      oldest_timestamp = info.timestamp;
      worst_key = key;
    }
  }

  if (!worst_key.has_value()) {
    // Should never happen, but safety check
    return;
  }

  // Update netgroup and source count caches before removing
  auto it = new_.find(*worst_key);
  if (it != new_.end()) {
    std::string netgroup = it->second.address.get_netgroup();
    if (!netgroup.empty() && new_netgroup_counts_[netgroup] > 0) {
      new_netgroup_counts_[netgroup]--;
    }

    // Decrement source count if this address had source tracking
    if (it->second.has_source()) {
      std::string source_group = it->second.source.get_netgroup();
      if (!source_group.empty() && source_counts_[source_group] > 0) {
        source_counts_[source_group]--;
      }
    }
  }

  // Remove from new table
  new_.erase(*worst_key);
  new_keys_.erase(std::remove(new_keys_.begin(), new_keys_.end(), *worst_key), new_keys_.end());

  LOG_NET_TRACE("Evicted address from new table (capacity limit). New size: {}", new_.size());
}

// Evict the worst address from the TRIED table to make room for a newly-proven address.
//
// The TRIED table contains addresses we've successfully connected to at least once.
// When at capacity (MAX_TRIED_ADDRESSES) and we need to promote an address from NEW,
// we must evict before adding.
//
// Eviction priority (different from NEW table):
//   1. Most failed connection attempts - indicates the address may no longer be valid
//   2. Oldest last_success as tie-breaker among addresses with equal attempt counts
//
// Rationale: TRIED contains verified-good addresses. Addresses with many failed
// reconnection attempts are likely offline/invalid, so evict those first to keep
// the table populated with actually-reachable peers.
void AddressManager::evict_worst_tried_address() {
  if (tried_.empty()) {
    return;
  }

  std::optional<AddrKey> worst_key;
  uint32_t worst_last_success = UINT32_MAX;
  int worst_attempts = -1;

  // Find the worst address to evict from tried table
  // Priority: most failed attempts > oldest last_success (tie-breaker)
  for (const auto& [key, info] : tried_) {
    // Compare: higher attempts is worse, or same attempts with older last_success
    bool is_worse = (info.attempts > worst_attempts) ||
                    (info.attempts == worst_attempts && info.last_success < worst_last_success);
    if (is_worse) {
      worst_attempts = info.attempts;
      worst_last_success = info.last_success;
      worst_key = key;
    }
  }

  if (!worst_key.has_value()) {
    // Should never happen, but safety check
    return;
  }

  // Update netgroup count cache before removing
  auto it = tried_.find(*worst_key);
  if (it != tried_.end()) {
    std::string netgroup = it->second.address.get_netgroup();
    if (!netgroup.empty() && tried_netgroup_counts_[netgroup] > 0) {
      tried_netgroup_counts_[netgroup]--;
    }
  }

  // Remove from tried table
  tried_.erase(*worst_key);
  tried_keys_.erase(std::remove(tried_keys_.begin(), tried_keys_.end(), *worst_key), tried_keys_.end());

  LOG_NET_TRACE("Evicted address from tried table (capacity limit). Tried size: {}", tried_.size());
}

}  // namespace network
}  // namespace unicity
