// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

/*
 AddressManager (AddrMan) — simplified peer address manager for Unicity

 Purpose
 - Maintain two tables of peer addresses:
   • "new": learned but never successfully connected
   • "tried": previously successful connections
 - Select addresses for outbound and feeler dials with 50% "tried" bias
   and a cooldown to avoid immediate re-dials
 - Apply basic hygiene: minimal address validation, timestamp clamping,
   and stale/"terrible" eviction

 How this differs from Bitcoin Core's addrman
 - No bucketization/source-grouping: does NOT implement Core's bucket model.
   Selection is simpler (tried/new + cooldown). However, per-netgroup limits
   prevent any single /16 from dominating either table (MAX_PER_NETGROUP_NEW=32,
   MAX_PER_NETGROUP_TRIED=8).
 - Simpler scoring: implements GetChance() with 0.66^attempts decay (capped at 8),
   but no bucket-based privacy scoring.

 Security features
 - Per-netgroup limits: max 32 addresses per /16 in NEW, max 8 per /16 in TRIED
 - Routable address validation: rejects RFC1918, loopback, multicast, etc.
 - Timestamp clamping: rejects timestamps >10min in future (TERRIBLE_FUTURE_TIMESTAMP_SEC)
 - Terrible address filtering: removes addresses not seen in 30 days (ADDRMAN_HORIZON_DAYS),
   or with too many failures (ADDRMAN_RETRIES=3 for new, ADDRMAN_MAX_FAILURES=10 for tried)

*/

#include "network/protocol.hpp"

#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <vector>

namespace unicity {
namespace network {

/**
 * AddrKey - Binary key for address lookups (16-byte IP + 2-byte port)
 *
 * Port is stored big-endian for consistent ordering across platforms.
 * IP bytes are copied as-is (already network byte order in NetworkAddress).
 * Fixed 18-byte struct avoids std::string heap allocations and provides
 * better cache locality for map lookups.
 */
struct AddrKey {
  std::array<uint8_t, 18> data;  // 16-byte IPv6 + 2-byte port (port is big-endian)

  // IPv4 addresses are stored in IPv4-mapped format (::ffff:a.b.c.d)
  explicit AddrKey(const protocol::NetworkAddress& addr) {
    std::copy(addr.ip.begin(), addr.ip.end(), data.begin());
    // Store port as big-endian for consistent ordering across platforms
    data[16] = static_cast<uint8_t>((addr.port >> 8) & 0xFF);
    data[17] = static_cast<uint8_t>(addr.port & 0xFF);
  }

  // Comparison for std::map
  bool operator<(const AddrKey& other) const { return data < other.data; }

  // Equality for testing
  bool operator==(const AddrKey& other) const { return data == other.data; }
};

// AddrInfo - Extended address information with connection history
struct AddrInfo {
  protocol::NetworkAddress address;
  protocol::NetworkAddress source;  // Peer who sent us this address 
  uint32_t timestamp;           // Last time we heard about this address via gossip
  uint32_t last_try;            // Last connection attempt timestamp
  uint32_t last_count_attempt;  // Last counted failure (used with m_last_good_ to prevent double-counting)
  uint32_t last_success;        // Last successful connection timestamp
  int attempts;                 // Number of counted connection failures
  bool tried;                   // Currently in TRIED table (false = in NEW table, can change on demotion)

  AddrInfo() : timestamp(0), last_try(0), last_count_attempt(0), last_success(0), attempts(0), tried(false) {}
  AddrInfo(const protocol::NetworkAddress& addr, uint32_t ts = 0)
      : address(addr), timestamp(ts), last_try(0), last_count_attempt(0), last_success(0), attempts(0), tried(false) {}

  // Check if source was provided (non-zero IP means source tracking is active)
  bool has_source() const {
    static const std::array<uint8_t, 16> zero_ip{};
    return source.ip != zero_ip;
  }

  bool is_stale(uint32_t now) const;
  bool is_terrible(uint32_t now) const;
  double GetChance(uint32_t now) const;
};


// AddressManager - Manages peer addresses for peer discovery and connection
class AddressManager {
public:
  AddressManager();

  // Add a new address from peer discovery
  // source: the peer who sent us this address (optional)
  // If not provided, per-source limits are not enforced.
  bool add(const protocol::NetworkAddress& addr,
           const protocol::NetworkAddress& source,
           uint32_t timestamp = 0);

  // Overload for backwards compatibility (no source tracking)
  bool add(const protocol::NetworkAddress& addr, uint32_t timestamp) { return add(addr, {}, timestamp); }
  bool add(const protocol::NetworkAddress& addr) { return add(addr, {}, 0); }

  // Add multiple addresses (e.g., from ADDR message)
  // source: the peer who sent us these addresses (optional, for Sybil resistance)
  // time_penalty_seconds: penalty subtracted from timestamps 
  // Self-announcements (addr == source) are exempt from penalty.
  size_t add_multiple(const std::vector<protocol::TimestampedAddress>& addresses,
                      const protocol::NetworkAddress& source,
                      uint32_t time_penalty_seconds = 0);

  // Overload for backwards compatibility (no source tracking, no penalty)
  size_t add_multiple(const std::vector<protocol::TimestampedAddress>& addresses) {
    return add_multiple(addresses, {}, 0);
  }

  // Mark address as a connection attempt
  // count_failure: if true, count this attempt towards failure count (prevents double-counting)
  void attempt(const protocol::NetworkAddress& addr, bool count_failure = true);

  // Mark address as successfully connected (moves NEW→TRIED)
  void good(const protocol::NetworkAddress& addr);

  // Update timestamp for long-running connection (called on graceful disconnect)
  void connected(const protocol::NetworkAddress& addr);

  // Get a random address to connect to
  std::optional<protocol::NetworkAddress> select();

  // Select address from "new" table for feeler connection
  std::optional<protocol::NetworkAddress> select_new_for_feeler();

  // Get multiple addresses for ADDR message
  // max_count: absolute maximum addresses to return 
  // max_pct: percentage of total addresses (0-100, 0 = no percentage limit)
  // Actual limit is min(max_count, total * max_pct / 100) when max_pct > 0
  std::vector<protocol::TimestampedAddress> get_addresses(size_t max_count = protocol::MAX_ADDR_SIZE,
                                                          size_t max_pct = 0);

  // Get statistics
  size_t size() const;
  size_t tried_count() const;
  size_t new_count() const;

  // Get all entries from a table (for debugging/RPC)
  // Returns copies of AddrInfo for all addresses in the specified table
  std::vector<AddrInfo> GetEntries(bool from_tried) const;

  // Remove stale addresses
  void cleanup_stale();

  // Persistence
  bool Save(const std::string& filepath);
  bool Load(const std::string& filepath);

private:
 
  static constexpr size_t MAX_NEW_ADDRESSES = 65536;
  static constexpr size_t MAX_TRIED_ADDRESSES = 16384;

  // Per-source limit: max addresses any single peer can contribute 
  // This limits how much any single peer can pollute our address tables
  static constexpr size_t MAX_ADDRESSES_PER_SOURCE = 64;

  // "tried" table: addresses we've successfully connected to
  std::map<AddrKey, AddrInfo> tried_;

  // "new" table: addresses we've heard about but haven't connected to
  std::map<AddrKey, AddrInfo> new_;

  // These vectors mirror the map keys to avoid O(n) std::advance() during selection
  // Invariant: tried_keys_[i] exists in tried_ for all i
  std::vector<AddrKey> tried_keys_;
  std::vector<AddrKey> new_keys_;

  // Maps netgroup string (e.g., "192.168") to count of addresses in that netgroup
  // Invariant: sum of all counts equals table size
  std::map<std::string, size_t> new_netgroup_counts_;
  std::map<std::string, size_t> tried_netgroup_counts_;

  // Maps source netgroup to count of addresses from that source (Sybil resistance)
  // Only counts addresses where source was provided (has_source() == true)
  std::map<std::string, size_t> source_counts_;

  // Random number generator for selection (base entropy source)
  std::mt19937 rng_;

  // Initialized to 1 to ensure first Good() call always updates last_count_attempt
  uint32_t m_last_good_{1};

  // Thread safety: protects all member state from concurrent access
  // Required because RPC threads may call add()/size() while io_context handles ADDR messages
  mutable std::mutex mutex_;

  // Get current time as unix timestamp
  uint32_t now() const;

  // Internal helpers
  // Create RNG with per-request entropy
  std::mt19937 make_request_rng();

  // Add address to table (internal helper)
  bool add_internal(const protocol::NetworkAddress& addr,
                    const protocol::NetworkAddress& source,
                    uint32_t timestamp);

  // Evict worst address from new table when at capacity
  void evict_worst_new_address();

  // Evict worst address from tried table when at capacity
  void evict_worst_tried_address();

  // Rebuild key vectors from maps (called after modifications)
  void rebuild_key_vectors();
};

}  // namespace network
}  // namespace unicity
