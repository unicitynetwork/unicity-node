// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "network/addr_relay_manager.hpp"

#include "chain/chainparams.hpp"
#include "network/addr_manager.hpp"
#include "network/anchor_manager.hpp"
#include "network/connection_manager.hpp"
#include "network/protocol.hpp"
#include "util/logging.hpp"
#include "util/netaddress.hpp"
#include "util/siphash.hpp"
#include "util/time.hpp"

#include <algorithm>
#include <cassert>
#include <filesystem>
#include <random>
#include <unordered_set>

#include <asio/ip/address.hpp>
#include <asio/ip/address_v6.hpp>

namespace unicity {
namespace network {

AddrRelayManager::AddrRelayManager(ConnectionManager* connman, const std::string& datadir)
    : datadir_(datadir),
      connman_(connman),
      addr_manager_(std::make_unique<AddressManager>()),
      rng_(std::random_device{}()) {
  assert(connman && "AddrRelayManager requires valid ConnectionManager");

  // Initialize deterministic randomizer seeds for ADDR relay peer selection
  std::random_device rd;
  addr_relay_seed0_ = (static_cast<uint64_t>(rd()) << 32) | rd();
  addr_relay_seed1_ = (static_cast<uint64_t>(rd()) << 32) | rd();

  anchor_manager_ = std::make_unique<AnchorManager>(*connman);

  // Inject self into ConnectionManager for address lifecycle tracking
  connman->SetAddrRelayManager(this);
}

AddrRelayManager::~AddrRelayManager() {}

namespace {

// Hash a NetworkAddress to a 64-bit value for deterministic relay selection
uint64_t HashNetworkAddress(const protocol::NetworkAddress& addr) {
  util::SipHasher hasher(0, 0);  
  hasher.Write(addr.port);
  hasher.Write(addr.ip.data(), addr.ip.size());
  return hasher.Finalize();
}

}  // namespace

std::vector<PeerPtr> AddrRelayManager::SelectAddrRelayTargets(
    const protocol::NetworkAddress& addr,
    const std::vector<PeerPtr>& candidates) {
  if (candidates.empty()) {
    return {};
  }

  // Compute address hash
  const uint64_t addr_hash = HashNetworkAddress(addr);

  const int64_t now_sec = util::GetTime();
  const uint64_t time_bucket = (static_cast<uint64_t>(now_sec) + addr_hash)
                                / ROTATE_ADDR_RELAY_DEST_INTERVAL_SEC;

  // Create deterministic hasher for this (address, time_bucket) pair
  util::SipHasher base_hasher(addr_relay_seed0_, addr_relay_seed1_);
  base_hasher.Write(RANDOMIZER_ID_ADDRESS_RELAY);
  base_hasher.Write(addr_hash);
  base_hasher.Write(time_bucket);

  // Keep top N candidates by hash key using fixed-size insertion 
  std::array<std::pair<uint64_t, const PeerPtr*>, ADDR_RELAY_TO_DESTINATIONS> best{};
  const size_t n = std::min(candidates.size(), ADDR_RELAY_TO_DESTINATIONS);

  for (const auto& peer : candidates) {
    util::SipHasher peer_hasher = base_hasher;
    peer_hasher.Write(static_cast<uint64_t>(peer->id()));
    uint64_t hash_key = peer_hasher.Finalize();

    for (size_t i = 0; i < n; ++i) {
      if (hash_key > best[i].first) {
        // Shift lower entries down
        for (size_t j = n - 1; j > i; --j) {
          best[j] = best[j - 1];
        }
        best[i] = {hash_key, &peer};
        break;
      }
    }
  }

  std::vector<PeerPtr> result;
  result.reserve(n);
  for (size_t i = 0; i < n && best[i].second; ++i) {
    result.push_back(*best[i].second);
  }
  return result;
}

void AddrRelayManager::Start(ConnectToAnchorsCallback connect_anchors) {
  // Anchors are the last outbound peers we connected to before shutdown
  if (!datadir_.empty()) {
    std::string anchors_path = datadir_ + "/anchors.json";
    if (std::filesystem::exists(anchors_path)) {
      auto anchor_addrs = LoadAnchors(anchors_path);
      if (!anchor_addrs.empty()) {
        LOG_NET_TRACE("loaded {} anchors, connecting to them first", anchor_addrs.size());
        connect_anchors(anchor_addrs);
      } else {
        LOG_NET_DEBUG("No anchors loaded from {}", anchors_path);
      }
    }
  }
  // Load persistent address book (peers.dat)
  if (!datadir_.empty()) {
    std::string peers_path = datadir_ + "/peers.json";
    if (std::filesystem::exists(peers_path)) {
      if (LoadAddresses(peers_path)) {
        LOG_NET_INFO("Loaded {} addresses from {}", addr_manager_->size(), peers_path);
      } else {
        LOG_NET_WARN("Failed to load addresses from {}", peers_path);
      }
    }
  }

  // Bootstrap from fixed seeds if AddressManager is empty
  if (addr_manager_->size() == 0) {
    BootstrapFromFixedSeeds(chain::GlobalChainParams::Get());
  }
}

// === Peer Lifecycle Callbacks (called directly by ConnectionManager) ===

void AddrRelayManager::OnPeerConnected(int peer_id,
                                       const std::string& address,
                                       uint16_t port,
                                       ConnectionType connection_type) {
  // Only add full-relay outbound connections to AddrMan (not block-relay, feelers, or inbound)
  // Block-relay peers are intentionally kept out of AddrMan for eclipse attack resistance
  if (connection_type == ConnectionType::OUTBOUND_FULL_RELAY) {
    protocol::NetworkAddress net_addr = protocol::NetworkAddress::from_string(address, port);
    addr_manager_->add(net_addr);
    LOG_NET_DEBUG("recorded outbound full-relay peer {}:{} to addrman", address, port);
  } else if (connection_type == ConnectionType::BLOCK_RELAY) {
    LOG_NET_TRACE("Not adding block-relay peer {}:{} to addrman", address, port);
  }
}

void AddrRelayManager::OnPeerDisconnected(int peer_id,
                                          const std::string& address,
                                          uint16_t port,
                                          bool mark_addr_good,
                                          bool mark_addr_connected) {
  // Clean up ADDR rate limiting state for this peer
  addr_rate_limit_.erase(peer_id);

  // Clean up pending ADDR relay state for this peer
  peer_addr_send_state_.erase(peer_id);

  if (port == 0 || address.empty()) {
    return;
  }

  protocol::NetworkAddress net_addr = protocol::NetworkAddress::from_string(address, port);

  // Mark address as good for feelers (moves NEW→TRIED)
  // Feelers disconnect before VERACK, so they need good() called here
  if (mark_addr_good) {
    addr_manager_->good(net_addr);
    LOG_NET_TRACE("marked feeler {}:{} as good in address manager", address, port);
  }

  // Update timestamp for regular outbound peers (keeps address looking fresh)
  // Regular outbound peers already had good() called at VERACK
  if (mark_addr_connected) {
    addr_manager_->connected(net_addr);
    LOG_NET_TRACE("updated timestamp for disconnected peer {}:{}", address, port);
  }
}

bool AddrRelayManager::HandleAddr(PeerPtr peer, message::AddrMessage* msg) {
  stats_handleaddr_calls_.fetch_add(1, std::memory_order_relaxed);

  if (!msg) {
    return false;
  }

  // Gate ADDR on post-VERACK
  if (!peer || !peer->successfully_connected()) {
    LOG_NET_TRACE("ignoring addr from non-connected peer");
    return true;  // Not an error, just gated
  }

  // Block-relay-only peers don't participate in address relay
  // Silently ignore ADDR from these peers - not a protocol violation
  if (!peer->relays_addr()) {
    LOG_NET_TRACE("ignoring addr from block-relay-only peer {}", peer->id());
    return true;  // Not an error, just gated by connection type
  }

  if (!addr_manager_) {
    return false;
  }

  // Note: Oversized ADDR messages (>MAX_ADDR_SIZE) are rejected at deserialization
  // layer (see AddrMessage::deserialize), so we don't need to check here.
  const int peer_id = peer->id();
  const int64_t now_s = util::GetTime();

  // Rate limit addresses using token bucket (DoS protection)
  // Check if peer has Addr permission to bypass rate limiting
  const bool rate_limited = connman_
                                ? !HasPermission(connman_->GetPeerPermissions(peer_id), NetPermissionFlags::Addr)
                                : true;

  std::vector<protocol::TimestampedAddress> accepted_addrs;
  accepted_addrs.reserve(msg->addresses.size());

  uint64_t num_rate_limited = 0;

  // Update token bucket based on elapsed time 
  // Timestamp initialized at peer creation, bucket starts at 1.0
  const auto current_time = util::GetSteadyTime();

  // Get or create rate state for this peer
  auto it = addr_rate_limit_.find(peer_id);
  if (it == addr_rate_limit_.end()) {
    // First interaction with this peer - initialize timestamp to now
    AddrRateLimitState new_state;
    new_state.last_update = current_time;
    new_state.token_bucket = 1.0;  // Start with 1 for self-announcement
    it = addr_rate_limit_.emplace(peer_id, new_state).first;
  }
  auto& rate_state = it->second;

  if (rate_state.token_bucket < MAX_ADDR_PROCESSING_TOKEN_BUCKET) {
    // Refill bucket based on elapsed time since last update
    const auto time_diff = current_time - rate_state.last_update;
    const double elapsed_seconds = std::chrono::duration<double>(time_diff).count();
    if (elapsed_seconds > 0) {
      const double increment = elapsed_seconds * MAX_ADDR_RATE_PER_SECOND;
      rate_state.token_bucket = std::min(rate_state.token_bucket + increment, MAX_ADDR_PROCESSING_TOKEN_BUCKET);
    }
  }
  rate_state.last_update = current_time;

  // Shuffle addresses for fairness
  // This ensures that if rate limiting kicks in, it doesn't consistently favor
  // addresses at the beginning of the message
  std::vector<protocol::TimestampedAddress> shuffled_addrs = msg->addresses;
  std::shuffle(shuffled_addrs.begin(), shuffled_addrs.end(), rng_);

  // Process each address with rate limiting
  for (const auto& ta : shuffled_addrs) {
    const bool has_tokens = rate_state.token_bucket >= 1.0;

    // Rate limit check: skip if no tokens and peer doesn't have bypass permission
    if (!has_tokens && rate_limited) {
      ++num_rate_limited;
      ++rate_state.addr_rate_limited;
      continue;
    }

    // Consume token if available (bypass peers don't consume tokens)
    if (has_tokens) {
      rate_state.token_bucket -= 1.0;
    }

    // Skip banned/discouraged addresses (token still consumed to penalize sender)
    if (connman_) {
      auto addr_str = ta.address.to_string();
      if (addr_str && (connman_->IsBanned(*addr_str) || connman_->IsDiscouraged(*addr_str))) {
        continue;
      }
    }

    ++rate_state.addr_processed;

    // If timestamp is missing (0) or >10min in future, default to 5 days ago
    protocol::TimestampedAddress sanitized = ta;
    if (sanitized.timestamp == 0 ||
        static_cast<int64_t>(sanitized.timestamp) > now_s + TIMESTAMP_FUTURE_LIMIT_SEC) {
      sanitized.timestamp = static_cast<uint32_t>(now_s - TIMESTAMP_PENALTY_DAYS * 24 * 60 * 60);
    }
    accepted_addrs.push_back(sanitized);
  }

  LOG_NET_DEBUG("Received addr: {} addresses ({} processed, {} rate-limited) from peer={}", msg->addresses.size(),
                accepted_addrs.size(), num_rate_limited, peer_id);

  // Feed AddressManager with accepted addresses only
  // Pass peer's address as source
  // Apply 2-hour time penalty self-announcements (where addr == source) are exempt from penalty
  if (!accepted_addrs.empty()) {
    auto source = protocol::NetworkAddress::from_string(peer->address(), peer->port());
    addr_manager_->add_multiple(accepted_addrs, source, ADDR_TIME_PENALTY_SEC);
  }

  // Update learned addresses via ConnectionManager (only accepted addresses)
  if (connman_) {
    connman_->ModifyLearnedAddresses(peer_id, [&](LearnedMap& learned) {
      // Prune old entries by TTL
      for (auto it = learned.begin(); it != learned.end();) {
        const int64_t age = now_s - it->second.last_seen_s;
        if (age > ECHO_SUPPRESS_TTL_SEC) {
          it = learned.erase(it);
        } else {
          ++it;
        }
      }

      // Insert/update learned entries (only accepted addresses)
      for (const auto& ta : accepted_addrs) {
        AddressKey k(ta.address);
        auto& e = learned[k];
        if (e.last_seen_s == 0 || ta.timestamp >= e.ts_addr.timestamp) {
          e.ts_addr = ta;  // preserve services + latest timestamp
        }
        e.last_seen_s = now_s;
      }

      // Enforce per-peer cap with batched eviction
      // Hysteresis: trigger at EVICTION_TRIGGER_RATIO, evict down to EVICTION_TARGET_RATIO
      const size_t trigger_threshold = static_cast<size_t>(MAX_LEARNED_PER_PEER * EVICTION_TRIGGER_RATIO);
      if (learned.size() > trigger_threshold) {
        // Collect all entries with timestamps
        std::vector<std::pair<int64_t, AddressKey>> by_time;
        by_time.reserve(learned.size());
        for (const auto& [key, entry] : learned) {
          by_time.emplace_back(entry.last_seen_s, key);
        }

        // Evict down to target capacity in one pass
        const size_t target_keep = static_cast<size_t>(MAX_LEARNED_PER_PEER * EVICTION_TARGET_RATIO);
        if (by_time.size() > target_keep) {
          size_t evict_count = by_time.size() - target_keep;

          // Partial sort: find the evict_count oldest elements
          std::nth_element(by_time.begin(), by_time.begin() + evict_count, by_time.end(),
                           [](const auto& a, const auto& b) { return a.first < b.first; });

          // Remove the oldest entries (first evict_count elements are now the oldest)
          for (size_t i = 0; i < evict_count; ++i) {
            learned.erase(by_time[i].second);
          }

          LOG_NET_DEBUG("evicted {} old learned addresses for peer={} (capacity management, {} remaining)", evict_count,
                        peer_id, learned.size());
        }
      }
    });
  }

  // === Address Relay (gossip protocol) ===
  // Only relay addresses that meet ALL of these conditions:
  // 1. Timestamp within last 10 minutes (fresh addresses only)
  // 2. Not a response to our GETADDR (!peer->has_sent_getaddr())
  // 3. Original message was small (≤10 addresses) - prevents relay amplification
  // 4. Address is routable
  //
  // These conditions prevent relay loops and amplification attacks where a peer
  // sends us a large ADDR message that we then relay to multiple peers.

  // Check relay eligibility conditions (must pass ALL)
  const bool is_getaddr_response = peer->has_sent_getaddr();
  const bool is_small_message = msg->addresses.size() <= 10;

  // Only consider relay if: not a GETADDR response AND small message
  if (!is_getaddr_response && is_small_message && !accepted_addrs.empty() && connman_) {
    // Filter addresses eligible for relay:
    // - Timestamp within last 10 minutes
    // - Routable (not private/reserved)
    std::vector<protocol::TimestampedAddress> relay_addrs;
    relay_addrs.reserve(accepted_addrs.size());

    for (const auto& ta : accepted_addrs) {
      // Only relay fresh addresses (Core: nTimePenalty check)
      // Future timestamps >10min were already sanitized to 5-days-ago above
      const int64_t addr_age = now_s - static_cast<int64_t>(ta.timestamp);
      if (addr_age > RELAY_FRESHNESS_SEC)
        continue;

      // Check routable
      auto ip_str = ta.address.to_string();
      if (!ip_str || !util::IsRoutable(*ip_str))
        continue;  // Not routable

      relay_addrs.push_back(ta);
    }

    if (!relay_addrs.empty()) {
      // Get all connected peers that participate in address relay
      auto all_peers = connman_->get_all_peers();

      // Build candidate list for deterministic selection:
      // - Exclude sender (originator) 
      // - Full-relay peers only (block-relay-only peers don't participate in addr relay)
      // - Successfully connected (post-VERACK)
      std::vector<PeerPtr> relay_candidates;
      relay_candidates.reserve(all_peers.size());

      for (const auto& p : all_peers) {
        if (!p)
          continue;
        if (p->id() == peer_id)
          continue;  // Skip sender/originator (no echo)
        if (!p->relays_addr())
          continue;  // Skip block-relay-only peers
        if (!p->successfully_connected())
          continue;  // Skip pre-handshake peers
        if (!p->is_connected())
          continue;  // Skip disconnected peers
        relay_candidates.push_back(p);
      }

      if (!relay_candidates.empty()) {
        // Phase 1: Build target → [addresses] mapping
        // Deterministic relay: each address hashes to 2 target peers (24h rotation)
        std::unordered_map<int, std::vector<const protocol::TimestampedAddress*>> target_addrs;
        for (const auto& ta : relay_addrs) {
          auto targets = SelectAddrRelayTargets(ta.address, relay_candidates);
          for (const auto& target : targets) {
            target_addrs[target->id()].push_back(&ta);
          }
        }

        // Phase 2: Process each unique target once (prune once, dedup + mark inside lock)
        std::exponential_distribution<double> delay_dist(1.0 / ADDR_TRICKLE_MEAN_MS);
        auto now_tp = util::GetSteadyTime();
        size_t queued_count = 0;

        for (auto& [target_id, addrs] : target_addrs) {
          // Single lock: prune, dedup check, and mark known — no separate copy needed
          std::vector<protocol::TimestampedAddress> to_queue;
          connman_->ModifyLearnedAddresses(target_id, [&](LearnedMap& learned) {
            // Prune expired entries once per target
            for (auto it = learned.begin(); it != learned.end();) {
              if (now_s - it->second.last_seen_s > ECHO_SUPPRESS_TTL_SEC) {
                it = learned.erase(it);
              } else {
                ++it;
              }
            }

            // Dedup + mark known for all addresses destined for this target
            for (const auto* ta : addrs) {
              AddressKey key(ta->address);
              if (learned.count(key))
                continue;  // Target already knows this address
              auto& e = learned[key];
              e.ts_addr = *ta;
              e.last_seen_s = now_s;
              to_queue.push_back(*ta);
            }
          });

          // Queue for send (outside the lock)
          if (!to_queue.empty()) {
            auto& state = peer_addr_send_state_[target_id];
            if (state.next_send_time == std::chrono::steady_clock::time_point{}) {
              auto delay_ms = static_cast<int64_t>(delay_dist(rng_));
              state.next_send_time = now_tp + std::chrono::milliseconds(delay_ms);
            }

            for (const auto& ta : to_queue) {
              if (state.addrs_to_send.size() >= MAX_ADDR_TO_SEND) {
                // Queue full - reservoir sampling for fair representation
                std::uniform_int_distribution<size_t> dist(0, state.addrs_to_send.size() - 1);
                state.addrs_to_send[dist(rng_)] = ta;
              } else {
                state.addrs_to_send.push_back(ta);
              }
              ++queued_count;
            }
          }
        }

        if (queued_count > 0) {
          LOG_NET_DEBUG("addr relay: queued {} address entries from peer={} to {} target(s)",
                        queued_count, peer_id, target_addrs.size());
        }
      }
    }
  } else if (!accepted_addrs.empty()) {
    // Log why we didn't relay
    if (is_getaddr_response) {
      LOG_NET_TRACE("addr relay skipped: response to our getaddr (peer={})", peer_id);
    } else if (!is_small_message) {
      LOG_NET_TRACE("addr relay skipped: message too large ({} > 10) from peer={}", msg->addresses.size(), peer_id);
    }
  }

  // Reset getaddr flag after receiving non-full ADDR
  // This allows relaying subsequent ADDR messages from this peer
  if (msg->addresses.size() < protocol::MAX_ADDR_SIZE) {
    peer->reset_sent_getaddr();
  }

  return true;
}

void AddrRelayManager::NotifyGetAddrSent(int peer_id) {
  // Boost the ADDR rate limiting bucket to allow full response
  // When we request addresses, the peer should be able to send up to MAX_ADDR_TO_SEND
  // without being rate limited
  auto it = addr_rate_limit_.find(peer_id);
  if (it == addr_rate_limit_.end()) {
    // First interaction - initialize with current time and boosted bucket
    AddrRateLimitState new_state;
    new_state.last_update = util::GetSteadyTime();
    new_state.token_bucket = 1.0 + MAX_ADDR_PROCESSING_TOKEN_BUCKET;
    addr_rate_limit_.emplace(peer_id, new_state);
    LOG_NET_TRACE("getaddr sent to peer={}, initialized bucket with {} tokens", peer_id, new_state.token_bucket);
  } else {
    it->second.token_bucket += MAX_ADDR_PROCESSING_TOKEN_BUCKET;
    LOG_NET_TRACE("getaddr sent to peer={}, boosted token bucket by {} (now: {})", peer_id,
                  MAX_ADDR_PROCESSING_TOKEN_BUCKET, it->second.token_bucket);
  }
}

bool AddrRelayManager::HandleGetAddr(PeerPtr peer) {
  // Gate GETADDR on post-VERACK check before other logic
  if (!peer || !peer->successfully_connected()) {
    stats_getaddr_ignored_prehandshake_.fetch_add(1, std::memory_order_relaxed);
    LOG_NET_TRACE("ignoring getaddr from pre-verack peer");
    return true;
  }

  // Block-relay-only peers don't participate in address relay
  // Do NOT respond to GETADDR from these peers - keeps them invisible
  if (!peer->relays_addr()) {
    LOG_NET_TRACE("ignoring getaddr from block-relay-only peer {}", peer->id());
    return true;  // Not an error, just gated by connection type
  }

  if (!addr_manager_) {
    return false;
  }

  stats_getaddr_total_.fetch_add(1, std::memory_order_relaxed);

  // Respond only to INBOUND peers (fingerprinting protection)
  // This asymmetric behavior prevents attackers from fingerprinting nodes by:
  // 1. Sending fake addresses to victim's AddrMan
  // 2. Later requesting GETADDR to check if those addresses are returned
  if (!peer->is_inbound()) {
    stats_getaddr_ignored_outbound_.fetch_add(1, std::memory_order_relaxed);
    LOG_NET_DEBUG("GETADDR ignored: outbound peer={} (inbound-only policy)", peer->id());
    return true;  // Not an error; just ignore
  }

  const int peer_id = peer->id();
  const int64_t now_s = util::GetTime();

  // Once-per-connection gating (reply to GETADDR only once per connection)
  // Use ConnectionManager accessor
  if (connman_ && connman_->HasRepliedToGetAddr(peer_id)) {
    stats_getaddr_ignored_repeat_.fetch_add(1, std::memory_order_relaxed);
    LOG_NET_DEBUG("GETADDR ignored: repeat on same connection peer={}", peer_id);
    return true;
  }
  if (connman_) {
    connman_->MarkGetAddrReplied(peer_id);
  }

  // Copy suppression map for this peer (TTL filtering done in is_suppressed lambda)
  LearnedMap suppression_map_copy;
  if (connman_) {
    auto learned_opt = connman_->GetLearnedAddresses(peer_id);
    if (learned_opt) {
      suppression_map_copy = std::move(*learned_opt);
    }
  }

  auto response = std::make_unique<message::AddrMessage>();

  // Don't reflect peer's own address back to them
  AddressKey peer_self_key{};
  bool have_self = false;
  protocol::NetworkAddress peer_na = protocol::NetworkAddress::from_string(peer->address(), peer->port());
  if (!peer_na.is_zero()) {
    peer_self_key = AddressKey(peer_na);
    have_self = true;
  }

  // Echo suppression: don't send addresses the peer already knows
  auto is_suppressed = [&](const AddressKey& key) -> bool {
    auto it = suppression_map_copy.find(key);
    if (it != suppression_map_copy.end()) {
      const int64_t age = now_s - it->second.last_seen_s;
      if (age >= 0 && age <= ECHO_SUPPRESS_TTL_SEC)
        return true;
    }
    if (have_self && key == peer_self_key)
      return true;
    return false;
  };

  std::unordered_set<AddressKey, AddressKey::Hasher> included;

  size_t added_count = 0;
  size_t suppressed_count = 0;

  // Limit response to 23% of AddrMan size to prevent enumeration attacks
  const size_t addrman_size = addr_manager_->size();
  if (addrman_size == 0) {
    peer->send_message(std::make_unique<message::AddrMessage>());
    stats_getaddr_served_.fetch_add(1, std::memory_order_relaxed);
    return true;
  }
  const size_t pct_limit = (addrman_size * MAX_PCT_ADDR_TO_SEND) / 100;
  const size_t max_to_send = std::min(pct_limit, static_cast<size_t>(protocol::MAX_ADDR_SIZE));

  // Get addresses from cache (or refresh if expired)
  // All peers in a 21-27 hour window get the same sample
  const auto now = util::GetSteadyTime();
  if (addr_response_cache_.addresses.empty() || addr_response_cache_.expiration <= now) {
    addr_response_cache_.addresses = addr_manager_->get_addresses(protocol::MAX_ADDR_SIZE);
    std::uniform_int_distribution<int64_t> jitter_dist(0, ADDR_RESPONSE_CACHE_JITTER.count());
    auto jitter = std::chrono::hours(jitter_dist(rng_));
    addr_response_cache_.expiration = now + ADDR_RESPONSE_CACHE_BASE + jitter;
    LOG_NET_DEBUG("GETADDR cache refresh: {} addresses, expires in {}h",
                  addr_response_cache_.addresses.size(),
                  std::chrono::duration_cast<std::chrono::hours>(
                      addr_response_cache_.expiration - now).count());
  }

  for (const auto& ta : addr_response_cache_.addresses) {
    if (response->addresses.size() >= max_to_send)
      break;
    AddressKey k(ta.address);
    if (is_suppressed(k)) {
      suppressed_count++;
      continue;
    }
    if (!included.insert(k).second)
      continue;
    response->addresses.push_back(ta);
    added_count++;
  }

  // Stats for logging and test introspection
  last_resp_from_addrman_.store(added_count, std::memory_order_relaxed);
  last_resp_suppressed_.store(suppressed_count, std::memory_order_relaxed);
  LOG_NET_DEBUG("getaddr served peer={} addrs={} (limit={}, addrman_size={}, suppressed={})", peer_id,
                response->addresses.size(), max_to_send, addrman_size, suppressed_count);

  // Verify peer still connected before sending (TOCTOU protection)
  if (!peer->is_connected()) {
    LOG_NET_TRACE("peer {} disconnected before getaddr response could be sent", peer_id);
    return true;  // Not an error, just too late
  }

  // Privacy: randomize order to avoid recency leaks
  if (!response->addresses.empty()) {
    std::shuffle(response->addresses.begin(), response->addresses.end(), rng_);
  }

  peer->send_message(std::move(response));
  stats_getaddr_served_.fetch_add(1, std::memory_order_relaxed);
  return true;
}

// Test/diagnostic methods (accessible only via friend class NetworkManager)
AddrRelayManager::GetAddrDebugStats AddrRelayManager::GetGetAddrDebugStats() const {
  GetAddrDebugStats s;
  s.total = stats_getaddr_total_.load(std::memory_order_relaxed);
  s.served = stats_getaddr_served_.load(std::memory_order_relaxed);
  s.ignored_outbound = stats_getaddr_ignored_outbound_.load(std::memory_order_relaxed);
  s.ignored_prehandshake = stats_getaddr_ignored_prehandshake_.load(std::memory_order_relaxed);
  s.ignored_repeat = stats_getaddr_ignored_repeat_.load(std::memory_order_relaxed);
  s.last_from_addrman = last_resp_from_addrman_.load(std::memory_order_relaxed);
  s.last_suppressed = last_resp_suppressed_.load(std::memory_order_relaxed);
  return s;
}

// === Bootstrap and Discovery Methods ===

void AddrRelayManager::BootstrapFromFixedSeeds(const chain::ChainParams& params) {
  // Bootstrap AddressManager from hardcoded seed nodes

  const auto& fixed_seeds = params.FixedSeeds();

  if (fixed_seeds.empty()) {
    LOG_NET_TRACE("no fixed seeds available for bootstrap");
    return;
  }

  LOG_NET_INFO("bootstrapping from {} fixed seed nodes", fixed_seeds.size());

  uint32_t current_time = static_cast<uint32_t>(util::GetTime());
  size_t added_count = 0;

  // Parse each "IP:port" string and add to AddressManager
  for (const auto& seed_str : fixed_seeds) {
    // Parse IP:port format using robust helper that handles IPv6 brackets
    std::string ip_str;
    uint16_t port = 0;
    if (!util::ParseIPPort(seed_str, ip_str, port)) {
      LOG_NET_WARN("Invalid seed format: {}", seed_str);
      continue;
    }

    // Convert IP string to NetworkAddress (from_string returns zeroed IP on error, doesn't throw)
    protocol::NetworkAddress addr = protocol::NetworkAddress::from_string(ip_str, port,
                                                                          protocol::ServiceFlags::NODE_NETWORK);

    // Check if conversion failed
    if (addr.is_zero()) {
      LOG_NET_WARN("Failed to parse IP in seed {}", seed_str);
      continue;
    }

    // Add to AddressManager with current timestamp
    // Empty source = no per-source limit (seed nodes bypass Sybil protection)
    if (addr_manager_->add(addr, {}, current_time)) {
      added_count++;
      LOG_NET_DEBUG("added seed node: {}", seed_str);
    }
  }

  LOG_NET_INFO("successfully added {} seed nodes to AddressManager", added_count);
}

// === AddressManager Forwarding Methods ===

void AddrRelayManager::Attempt(const protocol::NetworkAddress& addr, bool count_failures) {
  assert(addr_manager_);
  addr_manager_->attempt(addr, count_failures);
}

void AddrRelayManager::Good(const protocol::NetworkAddress& addr) {
  assert(addr_manager_);
  addr_manager_->good(addr);
}

std::optional<protocol::NetworkAddress> AddrRelayManager::Select() {
  assert(addr_manager_);
  return addr_manager_->select();
}

std::optional<protocol::NetworkAddress> AddrRelayManager::SelectNewForFeeler() {
  assert(addr_manager_);
  return addr_manager_->select_new_for_feeler();
}

size_t AddrRelayManager::Size() const {
  assert(addr_manager_);
  return addr_manager_->size();
}

size_t AddrRelayManager::TriedCount() const {
  assert(addr_manager_);
  return addr_manager_->tried_count();
}

size_t AddrRelayManager::NewCount() const {
  assert(addr_manager_);
  return addr_manager_->new_count();
}

bool AddrRelayManager::AddPeerAddress(const std::string& address, uint16_t port) {
  assert(addr_manager_);
  auto na = protocol::NetworkAddress::from_string(address, port);
  if (na.is_zero()) {
    LOG_NET_WARN("AddrRelayManager::AddPeerAddress: invalid address {}:{}", address, port);
    return false;
  }

  uint32_t now = static_cast<uint32_t>(util::GetTime());
  return addr_manager_->add(na, {}, now);
}

bool AddrRelayManager::SaveAddresses(const std::string& filepath) {
  assert(addr_manager_);
  return addr_manager_->Save(filepath);
}

bool AddrRelayManager::LoadAddresses(const std::string& filepath) {
  assert(addr_manager_);
  return addr_manager_->Load(filepath);
}

// === AnchorManager Forwarding Methods ===

std::vector<protocol::NetworkAddress> AddrRelayManager::GetAnchors() const {
  assert(anchor_manager_);
  return anchor_manager_->GetAnchors();
}

bool AddrRelayManager::SaveAnchors(const std::string& filepath) {
  assert(anchor_manager_);
  return anchor_manager_->SaveAnchors(filepath);
}

std::vector<protocol::NetworkAddress> AddrRelayManager::LoadAnchors(const std::string& filepath) {
  assert(anchor_manager_);
  return anchor_manager_->LoadAnchors(filepath);
}

// === ADDR Trickle Relay Processing ===

void AddrRelayManager::ProcessPendingAddrRelays() {
  if (peer_addr_send_state_.empty() || !connman_) {
    return;
  }

  auto now = util::GetSteadyTime();
  std::exponential_distribution<double> delay_dist(1.0 / ADDR_TRICKLE_MEAN_MS);
  size_t sent_count = 0;
  std::vector<int> peers_to_remove;

  // Process all peers whose send timer has fired
  for (auto& [peer_id, state] : peer_addr_send_state_) {
    // Skip if no addresses queued or timer hasn't fired yet
    if (state.addrs_to_send.empty()) {
      peers_to_remove.push_back(peer_id);
      continue;
    }
    if (state.next_send_time > now) {
      continue;  // Timer not ready yet
    }

    // Time to send - get the peer
    auto peer = connman_->get_peer(peer_id);
    if (peer && peer->is_connected() && peer->relays_addr()) {
      auto msg = std::make_unique<message::AddrMessage>();
      msg->addresses = std::move(state.addrs_to_send);
      peer->send_message(std::move(msg));
      ++sent_count;
    }

    // Clear queue and reset timer for next batch
    state.addrs_to_send.clear();
    // Reset timer with new random delay (for next batch)
    auto delay_ms = static_cast<int64_t>(delay_dist(rng_));
    state.next_send_time = now + std::chrono::milliseconds(delay_ms);
  }

  // Clean up entries with empty queues
  for (int peer_id : peers_to_remove) {
    peer_addr_send_state_.erase(peer_id);
  }

  if (sent_count > 0) {
    LOG_NET_TRACE("ADDR trickle: sent {} batch(es), {} peers with pending addresses", sent_count,
                  peer_addr_send_state_.size());
  }
}

}  // namespace network
}  // namespace unicity
