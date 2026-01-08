// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "network/peer_discovery_manager.hpp"

#include "chain/chainparams.hpp"
#include "network/addr_manager.hpp"
#include "network/anchor_manager.hpp"
#include "network/peer_lifecycle_manager.hpp"
#include "network/protocol.hpp"
#include "util/logging.hpp"
#include "util/netaddress.hpp"
#include "util/time.hpp"

#include <algorithm>
#include <filesystem>
#include <unordered_set>

#include <asio/ip/address.hpp>
#include <asio/ip/address_v6.hpp>

namespace unicity {
namespace network {

PeerDiscoveryManager::PeerDiscoveryManager(PeerLifecycleManager* peer_manager, const std::string& datadir)
    : datadir_(datadir), peer_manager_(peer_manager), rng_(std::random_device{}()) {
  // Create and own AddressManager
  addr_manager_ = std::make_unique<AddressManager>();
  LOG_NET_INFO("PeerDiscoveryManager created AddressManager");

  // Create and own AnchorManager
  if (!peer_manager) {
    LOG_NET_ERROR("PeerDiscoveryManager: peer_manager is null, cannot create AnchorManager");
  } else {
    anchor_manager_ = std::make_unique<AnchorManager>(*peer_manager);
    LOG_NET_INFO("PeerDiscoveryManager created AnchorManager");

    // Inject self into PeerLifecycleManager for address lifecycle tracking
    peer_manager->SetDiscoveryManager(this);
  }

  LOG_NET_INFO("PeerDiscoveryManager initialized");
}

PeerDiscoveryManager::~PeerDiscoveryManager() {
  // Don't log in destructor - logger may already be shut down
}

void PeerDiscoveryManager::Start(ConnectToAnchorsCallback connect_anchors) {
  // Anchors are the last 2-3 outbound peers we connected to before shutdown
  if (!datadir_.empty()) {
    std::string anchors_path = datadir_ + "/anchors.json";
    if (std::filesystem::exists(anchors_path)) {
      auto anchor_addrs = LoadAnchors(anchors_path);
      if (!anchor_addrs.empty()) {
        LOG_NET_TRACE("Loaded {} anchors, connecting to them first", anchor_addrs.size());
        connect_anchors(anchor_addrs);
      } else {
        LOG_NET_DEBUG("No anchors loaded from {}", anchors_path);
      }
    }
  }

  // Bootstrap from fixed seeds if AddressManager is empty
  if (addr_manager_->size() == 0) {
    BootstrapFromFixedSeeds(chain::GlobalChainParams::Get());
  }
}

// === Peer Lifecycle Callbacks (called directly by PeerLifecycleManager) ===

void PeerDiscoveryManager::OnPeerConnected(int peer_id, const std::string& address, uint16_t port,
                                           ConnectionType connection_type) {
  // Only add full-relay outbound connections to AddrMan (not block-relay, feelers, or inbound)
  // Block-relay peers are intentionally kept out of AddrMan for eclipse attack resistance
  if (connection_type == ConnectionType::OUTBOUND_FULL_RELAY) {
    protocol::NetworkAddress net_addr = protocol::NetworkAddress::from_string(address, port);
    addr_manager_->add(net_addr);
    LOG_NET_DEBUG("Recorded outbound full-relay peer {}:{} to addrman", address, port);
  } else if (connection_type == ConnectionType::BLOCK_RELAY) {
    LOG_NET_TRACE("Not adding block-relay peer {}:{} to addrman", address, port);
  }
}

void PeerDiscoveryManager::OnPeerDisconnected(int peer_id, const std::string& address, uint16_t port,
                                              bool mark_addr_good) {
  // Clean up ADDR rate limiting state for this peer
  addr_rate_limit_.erase(peer_id);

  // Mark address as good if flagged by PeerLifecycleManager
  if (mark_addr_good && port != 0 && !address.empty()) {
    protocol::NetworkAddress net_addr = protocol::NetworkAddress::from_string(address, port);
    addr_manager_->good(net_addr);
    LOG_NET_TRACE("Marked disconnected peer {}:{} as good in address manager", address, port);
  }
}

bool PeerDiscoveryManager::HandleAddr(PeerPtr peer, message::AddrMessage* msg) {
  if (!msg) {
    return false;
  }

  // Gate ADDR on post-VERACK
  if (!peer || !peer->successfully_connected()) {
    LOG_NET_TRACE("Ignoring ADDR from non-connected peer");
    return true;  // Not an error, just gated
  }

  // Block-relay-only peers don't participate in address relay (eclipse attack resistance)
  // Silently ignore ADDR from these peers - not a protocol violation
  if (!peer->relays_addr()) {
    LOG_NET_TRACE("Ignoring ADDR from block-relay-only peer {}", peer->id());
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
  const bool rate_limited = peer_manager_
                                ? !HasPermission(peer_manager_->GetPeerPermissions(peer_id), NetPermissionFlags::Addr)
                                : true;

  std::vector<protocol::TimestampedAddress> accepted_addrs;
  accepted_addrs.reserve(msg->addresses.size());

  uint64_t num_rate_limited = 0;

  // Update token bucket based on elapsed time (using steady_clock for reliability)
  // Timestamp initialized at peer creation, bucket starts at 1.0
  const auto current_time = util::GetSteadyTime();  // Mockable for testing

  // Get or create rate state for this peer
  auto it = addr_rate_limit_.find(peer_id);
  if (it == addr_rate_limit_.end()) {
    // First interaction with this peer - initialize timestamp to now
    // This ensures elapsed time is measured from peer creation, not from epoch
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

    ++rate_state.addr_processed;
    accepted_addrs.push_back(ta);
  }

  // Log rate limiting stats
  if (num_rate_limited > 0) {
    LOG_NET_DEBUG("ADDR rate limiting: peer={} total={} accepted={} rate_limited={}", peer_id, msg->addresses.size(),
                  accepted_addrs.size(), num_rate_limited);
  }

  // Feed AddressManager with accepted addresses only
  // Pass peer's address as source
  if (!accepted_addrs.empty()) {
    auto source = protocol::NetworkAddress::from_string(peer->address(), peer->port());
    addr_manager_->add_multiple(accepted_addrs, source);
  }

  // Update learned addresses via ConnectionManager (only accepted addresses)
  if (peer_manager_) {
    peer_manager_->ModifyLearnedAddresses(peer_id, [&](LearnedMap& learned) {
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

      // Enforce per-peer cap with batched eviction (O(n) instead of O(k*n))
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

          LOG_NET_DEBUG("Evicted {} old learned addresses for peer={} (capacity management, {} remaining)", evict_count,
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
  if (!is_getaddr_response && is_small_message && !accepted_addrs.empty() && peer_manager_) {
    // Filter addresses eligible for relay:
    // - Timestamp within last 10 minutes
    // - Routable (not private/reserved)
    constexpr int64_t RELAY_FRESHNESS_SEC = 600;  // 10 minutes
    std::vector<protocol::TimestampedAddress> relay_addrs;
    relay_addrs.reserve(accepted_addrs.size());

    for (const auto& ta : accepted_addrs) {
      // Check timestamp freshness (addr.nTime within delta current_time)
      // Negative age means future timestamp - reject if too far ahead
      const int64_t addr_age = now_s - static_cast<int64_t>(ta.timestamp);
      if (addr_age > RELAY_FRESHNESS_SEC || addr_age < -RELAY_FRESHNESS_SEC)
        continue;  // Too old or too far in future

      // Check routable
      auto ip_str = ta.address.to_string();
      if (!ip_str || !util::IsRoutable(*ip_str))
        continue;  // Not routable

      relay_addrs.push_back(ta);
    }

    if (!relay_addrs.empty()) {
      // Get all connected peers that participate in address relay
      auto all_peers = peer_manager_->get_all_peers();

      // Filter to eligible relay targets:
      // - Not the sender (avoid echo)
      // - Full-relay peers only (block-relay-only peers don't participate in addr relay)
      // - Successfully connected (post-VERACK)
      std::vector<PeerPtr> relay_candidates;
      relay_candidates.reserve(all_peers.size());

      for (auto& p : all_peers) {
        if (!p || p->id() == peer_id)
          continue;  // Skip sender
        if (!p->relays_addr())
          continue;  // Skip block-relay-only peers
        if (!p->successfully_connected())
          continue;  // Skip pre-handshake peers
        if (!p->is_connected())
          continue;  // Skip disconnected peers
        relay_candidates.push_back(p);
      }

      if (!relay_candidates.empty()) {
        // Select 1-2 random peers to relay to
        // Using 2 peers provides redundancy while limiting bandwidth
        std::shuffle(relay_candidates.begin(), relay_candidates.end(), rng_);
        size_t relay_count = std::min(relay_candidates.size(), size_t{2});

        size_t sent_count = 0;
        for (size_t i = 0; i < relay_count; ++i) {
          auto& target = relay_candidates[i];
          const int target_id = target->id();

          // Mark addresses as "known" by target to prevent relay loops
          peer_manager_->ModifyLearnedAddresses(target_id, [&](LearnedMap& learned) {
            for (const auto& ta : relay_addrs) {
              AddressKey k(ta.address);
              auto& e = learned[k];
              e.ts_addr = ta;
              e.last_seen_s = now_s;
            }
          });

          // Send the addresses
          auto msg_copy = std::make_unique<message::AddrMessage>();
          msg_copy->addresses = relay_addrs;
          target->send_message(std::move(msg_copy));
          ++sent_count;
        }

        LOG_NET_DEBUG("ADDR relay: relayed {} addresses (of {} accepted) from peer={} to {} peers", relay_addrs.size(),
                      accepted_addrs.size(), peer_id, sent_count);
      }
    }
  } else if (!accepted_addrs.empty()) {
    // Log why we didn't relay
    if (is_getaddr_response) {
      LOG_NET_TRACE("ADDR relay skipped: response to our GETADDR (peer={})", peer_id);
    } else if (!is_small_message) {
      LOG_NET_TRACE("ADDR relay skipped: message too large ({} > 10) from peer={}", msg->addresses.size(), peer_id);
    }
  }

  return true;
}

void PeerDiscoveryManager::NotifyGetAddrSent(int peer_id) {
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
    LOG_NET_TRACE("GETADDR sent to peer={}, initialized bucket with {} tokens", peer_id, new_state.token_bucket);
  } else {
    it->second.token_bucket += MAX_ADDR_PROCESSING_TOKEN_BUCKET;
    LOG_NET_TRACE("GETADDR sent to peer={}, boosted token bucket by {} (now: {})", peer_id,
                  MAX_ADDR_PROCESSING_TOKEN_BUCKET, it->second.token_bucket);
  }
}

bool PeerDiscoveryManager::HandleGetAddr(PeerPtr peer) {
  // Gate GETADDR on post-VERACK check before other logic
  if (!peer || !peer->successfully_connected()) {
    LOG_NET_TRACE("Ignoring GETADDR from pre-VERACK peer");
    return true;
  }

  // Block-relay-only peers don't participate in address relay
  // Do NOT respond to GETADDR from these peers - keeps them invisible
  if (!peer->relays_addr()) {
    LOG_NET_TRACE("Ignoring GETADDR from block-relay-only peer {}", peer->id());
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
  if (peer_manager_ && peer_manager_->HasRepliedToGetAddr(peer_id)) {
    stats_getaddr_ignored_repeat_.fetch_add(1, std::memory_order_relaxed);
    LOG_NET_DEBUG("GETADDR ignored: repeat on same connection peer={}", peer_id);
    return true;
  }
  if (peer_manager_) {
    peer_manager_->MarkGetAddrReplied(peer_id);
  }

  // Copy suppression map for this peer while pruning old entries
  // Use ConnectionManager accessor
  LearnedMap suppression_map_copy;
  if (peer_manager_) {
    auto learned_opt = peer_manager_->GetLearnedAddresses(peer_id);
    if (learned_opt) {
      // Prune TTL before copying
      for (auto it = learned_opt->begin(); it != learned_opt->end();) {
        const int64_t age = now_s - it->second.last_seen_s;
        if (age > ECHO_SUPPRESS_TTL_SEC) {
          it = learned_opt->erase(it);
        } else {
          ++it;
        }
      }
      suppression_map_copy = *learned_opt;  // copy after pruning
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
  constexpr size_t MAX_PCT_ADDR_TO_SEND = 23;
  const size_t addrman_size = addr_manager_->size();
  const size_t pct_limit = (addrman_size * MAX_PCT_ADDR_TO_SEND) / 100;
  const size_t max_to_send = std::min(pct_limit, static_cast<size_t>(protocol::MAX_ADDR_SIZE));

  auto addrs = addr_manager_->get_addresses(protocol::MAX_ADDR_SIZE);
  for (const auto& ta : addrs) {
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
  LOG_NET_DEBUG("GETADDR served peer={} addrs={} (limit={}, addrman_size={}, suppressed={})", peer_id,
                response->addresses.size(), max_to_send, addrman_size, suppressed_count);

  // Verify peer still connected before sending (TOCTOU protection)
  if (!peer->is_connected()) {
    LOG_NET_TRACE("Peer {} disconnected before GETADDR response could be sent", peer_id);
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
PeerDiscoveryManager::GetAddrDebugStats PeerDiscoveryManager::GetGetAddrDebugStats() const {
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

void PeerDiscoveryManager::TestSeedRng(uint64_t seed) {
  rng_.seed(seed);
}

// === Bootstrap and Discovery Methods ===

void PeerDiscoveryManager::BootstrapFromFixedSeeds(const chain::ChainParams& params) {
  // Bootstrap AddressManager from hardcoded seed nodes

  const auto& fixed_seeds = params.FixedSeeds();

  if (fixed_seeds.empty()) {
    LOG_NET_TRACE("no fixed seeds available for bootstrap");
    return;
  }

  LOG_NET_INFO("Bootstrapping from {} fixed seed nodes", fixed_seeds.size());

  // Use AddressManager's time format (seconds since epoch)
  // Use util::GetTime() for consistency and testability (supports mock time)
  uint32_t current_time = static_cast<uint32_t>(util::GetTime());
  size_t added_count = 0;

  // Parse each "IP:port" string and add to AddressManager
  for (const auto& seed_str : fixed_seeds) {
    // Parse IP:port format (e.g., "178.18.251.16:9590")
    size_t colon_pos = seed_str.find(':');
    if (colon_pos == std::string::npos) {
      LOG_NET_WARN("Invalid seed format (missing port): {}", seed_str);
      continue;
    }

    std::string ip_str = seed_str.substr(0, colon_pos);
    std::string port_str = seed_str.substr(colon_pos + 1);

    // Parse port
    uint16_t port = 0;
    try {
      int port_int = std::stoi(port_str);
      if (port_int <= 0 || port_int > 65535) {
        LOG_NET_WARN("Invalid port in seed: {}", seed_str);
        continue;
      }
      port = static_cast<uint16_t>(port_int);
    } catch (const std::exception& e) {
      LOG_NET_WARN("Failed to parse port in seed {}: {}", seed_str, e.what());
      continue;
    }

    // Convert IP string to NetworkAddress (from_string returns zeroed IP on error, doesn't throw)
    protocol::NetworkAddress addr = protocol::NetworkAddress::from_string(ip_str, port,
                                                                          protocol::ServiceFlags::NODE_NETWORK);

    // Check if conversion failed
    bool is_zero = std::all_of(addr.ip.begin(), addr.ip.end(), [](uint8_t b) { return b == 0; });
    if (is_zero) {
      LOG_NET_WARN("Failed to parse IP in seed {}", seed_str);
      continue;
    }

    // Add to AddressManager with current timestamp
    // Empty source = no per-source limit (seed nodes bypass Sybil protection)
    if (addr_manager_->add(addr, {}, current_time)) {
      added_count++;
      LOG_NET_DEBUG("Added seed node: {}", seed_str);
    }
  }

  LOG_NET_INFO("Successfully added {} seed nodes to AddressManager", added_count);
}

// === AddressManager Forwarding Methods ===

void PeerDiscoveryManager::Attempt(const protocol::NetworkAddress& addr) {
  if (!addr_manager_) {
    LOG_NET_ERROR("PeerDiscoveryManager::Attempt: addr_manager_ is null");
    return;
  }
  addr_manager_->attempt(addr);
}

void PeerDiscoveryManager::Good(const protocol::NetworkAddress& addr) {
  if (!addr_manager_) {
    LOG_NET_ERROR("PeerDiscoveryManager::Good: addr_manager_ is null");
    return;
  }
  addr_manager_->good(addr);
}

void PeerDiscoveryManager::Failed(const protocol::NetworkAddress& addr) {
  if (!addr_manager_) {
    LOG_NET_ERROR("PeerDiscoveryManager::Failed: addr_manager_ is null");
    return;
  }
  addr_manager_->failed(addr);
}

std::optional<protocol::NetworkAddress> PeerDiscoveryManager::Select() {
  if (!addr_manager_) {
    LOG_NET_ERROR("PeerDiscoveryManager::Select: addr_manager_ is null");
    return std::nullopt;
  }
  return addr_manager_->select();
}

std::optional<protocol::NetworkAddress> PeerDiscoveryManager::SelectNewForFeeler() {
  if (!addr_manager_) {
    LOG_NET_ERROR("PeerDiscoveryManager::SelectNewForFeeler: addr_manager_ is null");
    return std::nullopt;
  }
  return addr_manager_->select_new_for_feeler();
}

void PeerDiscoveryManager::CleanupStale() {
  if (!addr_manager_) {
    LOG_NET_ERROR("PeerDiscoveryManager::CleanupStale: addr_manager_ is null");
    return;
  }
  addr_manager_->cleanup_stale();
}

size_t PeerDiscoveryManager::Size() const {
  return addr_manager_ ? addr_manager_->size() : 0;
}

size_t PeerDiscoveryManager::TriedCount() const {
  return addr_manager_ ? addr_manager_->tried_count() : 0;
}

size_t PeerDiscoveryManager::NewCount() const {
  return addr_manager_ ? addr_manager_->new_count() : 0;
}

bool PeerDiscoveryManager::AddPeerAddress(const std::string& address, uint16_t port) {
  if (!addr_manager_) {
    LOG_NET_ERROR("PeerDiscoveryManager::AddPeerAddress: addr_manager_ is null");
    return false;
  }

  auto na = protocol::NetworkAddress::from_string(address, port);
  if (na.is_zero()) {
    LOG_NET_WARN("PeerDiscoveryManager::AddPeerAddress: invalid address {}:{}", address, port);
    return false;
  }

  uint32_t now = static_cast<uint32_t>(util::GetTime());
  // Empty source = no per-source limit 
  return addr_manager_->add(na, {}, now);
}

bool PeerDiscoveryManager::SaveAddresses(const std::string& filepath) {
  if (!addr_manager_) {
    LOG_NET_ERROR("PeerDiscoveryManager::SaveAddresses: addr_manager_ is null");
    return false;
  }
  return addr_manager_->Save(filepath);
}

bool PeerDiscoveryManager::LoadAddresses(const std::string& filepath) {
  if (!addr_manager_) {
    LOG_NET_ERROR("PeerDiscoveryManager::LoadAddresses: addr_manager_ is null");
    return false;
  }
  return addr_manager_->Load(filepath);
}

// === AnchorManager Forwarding Methods ===

std::vector<protocol::NetworkAddress> PeerDiscoveryManager::GetAnchors() const {
  if (!anchor_manager_) {
    LOG_NET_WARN("PeerDiscoveryManager::GetAnchors: anchor_manager_ is null");
    return {};
  }
  return anchor_manager_->GetAnchors();
}

bool PeerDiscoveryManager::SaveAnchors(const std::string& filepath) {
  if (!anchor_manager_) {
    LOG_NET_ERROR("PeerDiscoveryManager::SaveAnchors: anchor_manager_ is null");
    return false;
  }
  return anchor_manager_->SaveAnchors(filepath);
}

std::vector<protocol::NetworkAddress> PeerDiscoveryManager::LoadAnchors(const std::string& filepath) {
  if (!anchor_manager_) {
    LOG_NET_ERROR("PeerDiscoveryManager::LoadAnchors: anchor_manager_ is null");
    return {};
  }
  return anchor_manager_->LoadAnchors(filepath);
}

}  // namespace network
}  // namespace unicity
