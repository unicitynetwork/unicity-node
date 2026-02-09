// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "network/connection_manager.hpp"

#include "network/eviction_manager.hpp"
#include "network/header_sync_manager.hpp"
#include "network/network_manager.hpp"  // For ConnectionResult enum
#include "network/protocol.hpp"
#include "util/logging.hpp"
#include "util/netaddress.hpp"
#include "util/time.hpp"

#include <algorithm>
#include <set>
#include <utility>  // for std::move

namespace unicity {
namespace network {

namespace {
// Max connection attempts per cycle
constexpr int MAX_CONNECTION_ATTEMPTS_PER_CYCLE = 100;

}  // namespace

ConnectionManager::ConnectionManager(
    asio::io_context& io_context,
    const Config& config,
    const std::string& datadir)
    : io_context_(io_context)
    , config_(config)
    , ban_manager_(std::make_unique<BanManager>(datadir))
    , misbehavior_manager_(std::make_unique<MisbehaviorManager>(peer_states_))
{
  // Load persistent bans from disk if datadir is provided
  if (!datadir.empty()) {
    ban_manager_->LoadBans(datadir);
  }
}

void ConnectionManager::SetAddrRelayManager(PeerDiscoveryInterface* addr_relay_mgr) {
  addr_relay_mgr_ = addr_relay_mgr;
  if (addr_relay_mgr_) {
    LOG_NET_DEBUG("ConnectionManager: AddrRelayManager injected for address lifecycle tracking");
  } else {
    LOG_NET_WARN("ConnectionManager: SetAddrRelayManager called with nullptr - address tracking disabled");
  }
}

void ConnectionManager::SetHeaderSyncManager(HeaderSyncManager* sync_mgr) {
  header_sync_manager_ = sync_mgr;
  if (header_sync_manager_) {
    LOG_NET_DEBUG("ConnectionManager: HeaderSyncManager injected for sync peer tracking");
  }
}

void ConnectionManager::Init(std::shared_ptr<Transport> transport,
                                std::function<void(Peer*)> setup_message_handler,
                                std::function<bool()> is_running,
                                uint32_t network_magic,
                                uint64_t local_nonce) {
  transport_ = std::move(transport);
  setup_message_handler_ = std::move(setup_message_handler);
  is_running_ = std::move(is_running);
  network_magic_ = network_magic;
  local_nonce_ = local_nonce;
}

ConnectionManager::~ConnectionManager() {
  try {
    Shutdown();
    disconnect_all();
  } catch (...) {
  }
}

void ConnectionManager::Shutdown() {
  shutting_down_ = true;
}

int ConnectionManager::add_peer(PeerPtr peer,
                                NetPermissionFlags permissions,
                                const std::string& address,
                                bool prefer_evict,
                                bool bypass_slot_limit) {
  if (!peer) {
    return -1;
  }

  // Reject additions during bulk shutdown (single-threaded check)
  if (stopping_all_) {
    LOG_NET_TRACE("add_peer: rejected while disconnect_all in progress");
    return -1;
  }

  // Cache peer properties and compute address once
  const bool is_inbound = peer->is_inbound();
  const bool is_feeler = peer->is_feeler();
  const bool is_manual = peer->is_manual();
  const bool is_block_relay = peer->is_block_relay_only();
  const bool is_full_relay = peer->is_full_relay();
  const bool has_noban = HasPermission(permissions, NetPermissionFlags::NoBan);

  // Compute and normalize address once (used for ban checks, netgroup, and storage)
  const std::string peer_addr_raw = address.empty() ? peer->address() : address;
  auto normalized_addr_opt = util::ValidateAndNormalizeIP(peer_addr_raw);
  if (!normalized_addr_opt.has_value()) {
    LOG_NET_TRACE("add_peer: rejecting invalid IP address {}", peer_addr_raw);
    return -1;
  }
  const std::string& peer_addr = *normalized_addr_opt;

  // Check bans BEFORE slot accounting (unless peer has NoBan permission)
  if (!has_noban) {
    if (IsBanned(peer_addr)) {
      LOG_NET_TRACE("add_peer: rejecting banned address {}", peer_addr);
      return -1;
    }

    // For outbound connections only: reject discouraged addresses unconditionally
    // For inbound connections: HandleInboundConnection already did the conditional check
    if (!is_inbound && IsDiscouraged(peer_addr)) {
      LOG_NET_TRACE("add_peer: rejecting discouraged outbound address {}", peer_addr);
      return -1;
    }
  }

  // Count current connections in single pass
  size_t current_inbound = 0;
  size_t current_full_relay = 0;
  size_t current_block_relay = 0;

  peer_states_.ForEach([&](int /*id*/, const PeerPtr& p) {
    if (p->is_inbound()) {
      current_inbound++;
    } else if (p->is_full_relay()) {
      current_full_relay++;
    } else if (p->is_block_relay_only()) {
      current_block_relay++;
    }
    // Feelers and manual don't consume outbound slots
  });

  // Check outbound limits by type (no eviction for outbound)
  // Do not count feeler connections against outbound capacity, and do not gate them here
  if (!is_inbound && !is_feeler && !is_manual) {
    if (is_full_relay && current_full_relay >= config_.max_full_relay_outbound) {
      LOG_NET_TRACE("add_peer: reject full-relay outbound (current={} >= max={}) address={}", current_full_relay,
                    config_.max_full_relay_outbound, peer_addr);
      return -1;  // Too many full-relay connections
    }
    if (is_block_relay && !bypass_slot_limit && current_block_relay >= config_.max_block_relay_outbound) {
      LOG_NET_TRACE("add_peer: reject block-relay outbound (current={} >= max={}) address={}", current_block_relay,
                    config_.max_block_relay_outbound, peer_addr);
      return -1;  // Too many block-relay connections
    }
  }

  // Check inbound limit - try eviction if at capacity
  if (is_inbound && current_inbound >= config_.max_inbound_peers) {
    bool evicted = evict_inbound_peer();

    if (!evicted) {
      LOG_NET_TRACE(
          "add_peer: inbound at capacity and eviction failed (likely all peers protected by recent-connection window)");
      return -1;  // Couldn't evict anyone, reject connection
    }
    // Recompute inbound counts after eviction 
    size_t inbound_now = 0;
    peer_states_.ForEach([&](int /*id*/, const PeerPtr& p) {
      if (p->is_inbound())
        inbound_now++;
    });
    if (inbound_now >= config_.max_inbound_peers) {
      LOG_NET_TRACE("add_peer: inbound still at capacity after eviction, rejecting");
      return -1;
    }
    // Successfully evicted and capacity confirmed; continue
  }

  // Allocate peer ID (simple monotonic counter via member counter)
  int peer_id = next_peer_id_.fetch_add(1, std::memory_order_relaxed);
  peer->set_id(peer_id);  // Set the ID on the peer object

  // Set peer state (now consolidated in Peer object)
  peer->set_created_at(util::GetSteadyTime());
  peer->set_permissions(permissions);
  peer->misbehavior().address = peer_addr;  // Store normalized address
  peer->set_prefer_evict(prefer_evict);     // Discouraged peers evicted first
  peer_states_.InsertOrUpdate(peer_id, peer);

  LOG_NET_DEBUG("added connection peer={} ({}:{})", peer_id, peer_addr, peer->port());

  // Notify AddrRelayManager directly for address tracking
  if (addr_relay_mgr_) {
    addr_relay_mgr_->OnPeerConnected(peer_id, peer_addr, peer->port(), peer->connection_type());
  }

  return peer_id;  // Return the assigned ID
}

void ConnectionManager::remove_peer(int peer_id) {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  // Extract data from peer state before erasing
  PeerPtr peer;
  std::string peer_address;  // Normalized address (consistent with add_peer)
  uint16_t peer_port = 0;
  bool mark_addr_good = false;       // Only for feelers: moves NEW→TRIED
  bool mark_addr_connected = false;  // For regular outbound: timestamp freshness

  bool found = peer_states_.Read(peer_id, [&](const PeerPtr& p) {
    peer = p;

    // Use stored normalized address for consistency with add_peer/OnPeerConnected
    peer_address = peer->misbehavior().address;
    peer_port = peer->port();

    if (peer->misbehavior().should_discourage) {
      // Don't discourage NoBan peers (Manual peers get NoBan at grant time)
      // Don't discourage local peers — would block all localhost connections
      if (!HasPermission(peer->permissions(), NetPermissionFlags::NoBan)) {
        if (!peer_address.empty()) {
          if (util::IsLocal(peer_address)) {
            LOG_NET_DEBUG("remove_peer: disconnecting but not discouraging local peer {}", peer_address);
          } else {
            Discourage(peer_address);
            LOG_NET_TRACE("remove_peer: discouraged {} due to misbehavior", peer_address);
          }
        }
      }
    }

    // Decide whether to mark as good or update connected timestamp in addrman
    // Block-relay peers are excluded from timestamp updates to prevent info leaks
    // (fingerprinting when we last connected to a block-relay peer)
    if (!peer->misbehavior().should_discourage && !peer->is_inbound() && !peer->is_block_relay_only()) {
      bool has_valid_addr = !peer_address.empty() && peer_port != 0;

      if (peer->is_feeler()) {
        // Feelers: mark_addr_good moves NEW→TRIED (their purpose is to validate addresses)
        // Feelers disconnect after VERSION (before VERACK), so check version() > 0
        if (peer->version() > 0 && has_valid_addr) {
          mark_addr_good = true;
        }
      } else {
        // Regular outbound (full-relay, manual): update timestamp for long-running connections
        // Good() already called at VERACK so only update timestamp
        if (peer->successfully_connected() && has_valid_addr) {
          mark_addr_connected = true;
        }
      }
    }

    // Update success/failure metrics for outbound/feeler peers
    if (!peer->is_inbound()) {
      if (peer->is_feeler()) {
        // Feelers succeed if they received VERSION (they disconnect before VERACK by design)
        if (peer->version() > 0) {
          ++metrics_feeler_successes_;
        } else {
          ++metrics_feeler_failures_;
        }
      } else if (!peer->successfully_connected()) {
        ++metrics_outbound_failures_;
      }
    }
  });

  if (!found) {
    // Peer already removed - this is OK, just return silently
    LOG_NET_TRACE("remove_peer({}): peer NOT FOUND in map", peer_id);
    return;
  }

  bool skip_notifications = shutting_down_;

  LOG_NET_DEBUG("peer {} disconnected ({}:{})", peer_id, peer_address, peer_port);

  // Clean up manual_addresses_ for manual peers
  // Without this, addresses added via addnode would be permanently blocked from automatic selection
  if (peer->is_manual() && !peer_address.empty() && peer_port != 0) {
    auto na = protocol::NetworkAddress::from_string(peer_address, peer_port);
    if (!na.is_zero()) {
      manual_addresses_.erase(AddressKey(na));
      LOG_NET_TRACE("remove_peer: removed {} from manual_addresses_", peer_address);
    }
  }

  // Notify managers BEFORE erasing from peer_states_ so that callbacks
  // (e.g. HeaderSyncManager::OnPeerDisconnected) can still look up the peer
  // via get_peer() to read its chain_sync_state (protected_outbound_count_ decrement).
  if (!skip_notifications && addr_relay_mgr_) {
    addr_relay_mgr_->OnPeerDisconnected(peer_id, peer_address, peer_port, mark_addr_good, mark_addr_connected);
  }
  if (!skip_notifications && header_sync_manager_) {
    header_sync_manager_->OnPeerDisconnected(peer_id);
  }

  // Erase from peer_states_ (after notifications so callbacks can still read peer state)
  peer_states_.Erase(peer_id);

  // Disconnect the peer (idempotent - logs only if not already disconnected)
  peer->disconnect();
}

PeerPtr ConnectionManager::get_peer(int peer_id) {
  PeerPtr result;
  peer_states_.Read(peer_id, [&](const PeerPtr& peer) { result = peer; });
  return result;
}

int ConnectionManager::find_peer_by_address(const std::string& address, uint16_t port) {
  // Validate and normalize the search address
  auto needle_addr_opt = util::ValidateAndNormalizeIP(address);
  if (!needle_addr_opt.has_value()) {
    return -1;  // Invalid address
  }
  const std::string& needle_addr = *needle_addr_opt;
  int result = -1;

  peer_states_.ForEach([&](int id, const PeerPtr& peer) {
    if (result != -1)
      return;  // Already found (ForEach doesn't support early break)
    if (!peer)
      return;

    // Use stored normalized address (set in add_peer) - no redundant normalization
    if (peer->misbehavior().address != needle_addr)
      return;

    // Match port if specified (0 = any port)
    if (port == 0 || peer->port() == port) {
      result = id;
    }
  });

  return result;
}

std::vector<PeerPtr> ConnectionManager::get_all_peers() {
  std::vector<PeerPtr> result;
  result.reserve(peer_states_.Size());  // Reserve capacity to avoid reallocations

  peer_states_.ForEach([&](int id, const PeerPtr& peer) { result.push_back(peer); });

  // Sort by peer ID to ensure deterministic iteration order
  // Use stable_sort for consistent ordering when IDs are equal (shouldn't happen, but defensive)
  std::stable_sort(result.begin(), result.end(), [](const PeerPtr& a, const PeerPtr& b) { return a->id() < b->id(); });

  return result;
}

std::vector<PeerPtr> ConnectionManager::get_outbound_peers() {
  std::vector<PeerPtr> result;
  result.reserve(peer_states_.Size());  // Reserve capacity (worst case: all outbound)

  peer_states_.ForEach([&](int id, const PeerPtr& peer) {
    if (!peer->is_inbound()) {
      result.push_back(peer);
    }
  });

  // Sort by peer ID to ensure deterministic iteration order
  // (unordered_map iteration is non-deterministic)
  std::stable_sort(result.begin(), result.end(), [](const PeerPtr& a, const PeerPtr& b) { return a->id() < b->id(); });

  return result;
}

std::vector<PeerPtr> ConnectionManager::get_inbound_peers() {
  std::vector<PeerPtr> result;
  result.reserve(peer_states_.Size());  // Reserve capacity (worst case: all inbound)

  peer_states_.ForEach([&](int id, const PeerPtr& peer) {
    if (peer->is_inbound()) {
      result.push_back(peer);
    }
  });

  // Sort by peer ID to ensure deterministic iteration order
  // (unordered_map iteration is non-deterministic)
  std::stable_sort(result.begin(), result.end(), [](const PeerPtr& a, const PeerPtr& b) { return a->id() < b->id(); });

  return result;
}

size_t ConnectionManager::peer_count() const {
  return peer_states_.Size();
}

size_t ConnectionManager::outbound_count() const {
  // Total outbound = full-relay + block-relay (excludes feeler/manual)
  return full_relay_outbound_count() + block_relay_outbound_count();
}

size_t ConnectionManager::full_relay_outbound_count() const {
  size_t count = 0;
  peer_states_.ForEach([&](int id, const PeerPtr& peer) {
    if (!peer->is_inbound() && peer->is_full_relay()) {
      count++;
    }
  });
  return count;
}

size_t ConnectionManager::block_relay_outbound_count() const {
  size_t count = 0;
  peer_states_.ForEach([&](int id, const PeerPtr& peer) {
    if (!peer->is_inbound() && peer->is_block_relay_only()) {
      count++;
    }
  });
  return count;
}

size_t ConnectionManager::pending_full_relay_count() const {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  size_t count = 0;
  for (const auto& [key, type] : pending_outbound_) {
    if (type == ConnectionType::OUTBOUND_FULL_RELAY) {
      count++;
    }
  }
  return count;
}

size_t ConnectionManager::pending_block_relay_count() const {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  size_t count = 0;
  for (const auto& [key, type] : pending_outbound_) {
    if (type == ConnectionType::BLOCK_RELAY) {
      count++;
    }
  }
  return count;
}

size_t ConnectionManager::inbound_count() const {
  size_t count = 0;

  peer_states_.ForEach([&](int id, const PeerPtr& peer) {
    if (peer->is_inbound()) {
      count++;
    }
  });

  return count;
}

bool ConnectionManager::needs_more_outbound() const {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  // Include pending (in-flight) automatic connections to avoid over-subscription
  // Manual connections are excluded (they don't consume automatic outbound slots)
  size_t total_wanted = config_.target_full_relay_outbound + config_.target_block_relay_outbound;
  size_t total_have = outbound_count() + pending_full_relay_count() + pending_block_relay_count();
  return total_have < total_wanted;
}

bool ConnectionManager::needs_more_full_relay_outbound() const {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  // Include pending connections of this type to avoid over-subscription
  return (full_relay_outbound_count() + pending_full_relay_count()) < config_.target_full_relay_outbound;
}

bool ConnectionManager::needs_more_block_relay_outbound() const {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  // Include pending connections of this type to avoid over-subscription
  return (block_relay_outbound_count() + pending_block_relay_count()) < config_.target_block_relay_outbound;
}

ConnectionType ConnectionManager::next_outbound_type() const {
  // Priority: block-relay connections first (security critical for eclipse resistance)
  // Once block-relay slots are filled, fill full-relay slots
  if (needs_more_block_relay_outbound()) {
    return ConnectionType::BLOCK_RELAY;
  }
  return ConnectionType::OUTBOUND_FULL_RELAY;
}

bool ConnectionManager::can_accept_inbound() const {
  return inbound_count() < config_.max_inbound_peers;
}

bool ConnectionManager::evict_inbound_peer() {
  // Collect eviction candidates from ALL peers
  // EvictionManager handles filtering (outbound, NoBan) as defense-in-depth
  // Selection logic is delegated to EvictionManager

  std::vector<EvictionManager::EvictionCandidate> candidates;

  peer_states_.ForEach([&](int id, const PeerPtr& peer) {
    // Defensive null check (shouldn't happen - add_peer rejects null, remove_peer erases)
    if (!peer)
      return;

    // Check NoBan protection
    bool is_protected = HasPermission(peer->permissions(), NetPermissionFlags::NoBan);

    // All peers are candidates - EvictionManager applies protection criteria
    // (netgroup diversity, ping time, header relay, 50% uptime protection)
    auto connected_time = peer->stats().connected_time.load(std::memory_order_relaxed);
    auto ping_ms = peer->stats().min_ping_time_ms.load(std::memory_order_relaxed);
    auto connected_tp = std::chrono::steady_clock::time_point(connected_time);

    // Get netgroup using stored normalized address (set in add_peer)
    const std::string& addr = peer->misbehavior().address;
    std::string netgroup = addr.empty() ? "" : util::GetNetgroup(addr);

    // is_outbound: EvictionManager will filter these as defense-in-depth
    bool is_outbound = !peer->is_inbound();

    candidates.push_back({
        id, connected_tp, ping_ms.count(), netgroup, is_protected, is_outbound,
        peer->last_headers_received(),  // For header relay protection
        peer->prefer_evict()            // Discouraged peers evicted first 
    });
  });

  // Delegate selection to EvictionManager
  auto to_evict = EvictionManager::SelectNodeToEvict(std::move(candidates));

  if (to_evict.has_value()) {
    remove_peer(*to_evict);
    return true;
  }

  return false;
}

void ConnectionManager::disconnect_all() {
  // Set stopping flag to prevent new peers from being added
  stopping_all_ = true;  // Single-threaded - direct assignment

  bool skip_notifications = shutting_down_;

  // Get all peers to disconnect (capture normalized address for notifications)
  struct DisconnectInfo {
    PeerPtr peer;
    std::string address;  // Normalized (from state.misbehavior.address)
  };
  std::map<int, DisconnectInfo> peers_to_disconnect;
  peer_states_.ForEach([&](int id, const PeerPtr& peer) {
    peers_to_disconnect[id] = {peer, peer->misbehavior().address};
  });

  // Notify AddrRelayManager directly for cleanup (no addr marking during shutdown)
  if (!skip_notifications && addr_relay_mgr_) {
    for (const auto& [id, info] : peers_to_disconnect) {
      if (info.peer) {
        addr_relay_mgr_->OnPeerDisconnected(id, info.address, info.peer->port(), false, false);
      }
    }
  }

  // Notify HeaderSyncManager directly for sync peer tracking
  if (!skip_notifications && header_sync_manager_) {
    for (const auto& [id, info] : peers_to_disconnect) {
      header_sync_manager_->OnPeerDisconnected(id);
    }
  }

  // Clear all peer states
  peer_states_.Clear();

  // Disconnect all peers
  for (auto& [id, info] : peers_to_disconnect) {
    if (info.peer) {
      info.peer->disconnect();
    }
  }

  // Allow add_peer() after bulk disconnect completes
  stopping_all_ = false;  // Single-threaded - direct assignment
}

void ConnectionManager::process_periodic() {
  std::vector<int> to_remove;
  std::vector<int> protected_misbehaving;  // NoBan peers with should_discourage set

  // Find disconnected peers and peers marked for disconnection
  peer_states_.ForEach([&](int id, const PeerPtr& peer) {
    // Defensive null check (shouldn't happen - add_peer rejects null, remove_peer erases)
    if (!peer)
      return;

    if (!peer->is_connected()) {
      LOG_NET_TRACE("process_periodic: peer={} not connected, marking for removal", id);
      to_remove.push_back(id);
      return;
    }

    // Enforce feeler max lifetime (safety net for stuck handshakes)
    // Normal path: feelers disconnect immediately after VERSION in Peer::handle_version()
    // This timeout catches pathological cases where handshake stalls (e.g., peer never
    // sends VERSION). Without this, a malicious peer could hold a feeler slot
    // indefinitely by never completing the handshake.
    // Timeout: 120s (2x handshake timeout of 60s)
    if (peer->is_feeler()) {
      auto age = std::chrono::duration_cast<std::chrono::seconds>(util::GetSteadyTime() - peer->created_at());
      if (age.count() >= FEELER_MAX_LIFETIME_SEC) {
        LOG_NET_DEBUG("feeler peer={} ({}:{}) timeout ({}s) - safety net for stuck handshake", id,
                      peer->misbehavior().address, peer->port(), age.count());
        to_remove.push_back(id);
        return;
      }
    }

    // Check for peers marked for disconnection due to misbehavior
    if (peer->misbehavior().should_discourage) {
      // Never disconnect peers with NoBan permission (Manual peers get NoBan at grant time)
      if (HasPermission(peer->permissions(), NetPermissionFlags::NoBan)) {
        LOG_NET_WARN("misbehaving NoBan peer={} (protected, not disconnecting)", id);
        protected_misbehaving.push_back(id);  // Clear flag after loop
        return;
      }

      // Add to removal list if not already there
      if (std::find(to_remove.begin(), to_remove.end(), id) == to_remove.end()) {
        to_remove.push_back(id);
        LOG_NET_INFO("disconnecting misbehaving peer {} ({}:{})", id, peer->misbehavior().address, peer->port());
      }
    }
  });

  // Clear should_discourage flag for NoBan peers
  for (int id : protected_misbehaving) {
    peer_states_.Modify(id, [](PeerPtr& peer) { peer->misbehavior().should_discourage = false; });
  }

  // Remove disconnected peers
  for (int peer_id : to_remove) {
    remove_peer(peer_id);
  }

  LOG_NET_TRACE("metrics: outbound attempts={} successes={} failures={} | feeler attempts={} successes={} failures={}",
                metrics_outbound_attempts_.load(), metrics_outbound_successes_.load(), metrics_outbound_failures_.load(),
                metrics_feeler_attempts_.load(), metrics_feeler_successes_.load(), metrics_feeler_failures_.load());
}

// === Misbehavior Tracking (delegated to MisbehaviorManager) ===

void ConnectionManager::ReportInvalidPoW(int peer_id) {
  misbehavior_manager_->ReportInvalidPoW(peer_id);
}

void ConnectionManager::ReportOversizedMessage(int peer_id) {
  misbehavior_manager_->ReportOversizedMessage(peer_id);
}

void ConnectionManager::ReportNonContinuousHeaders(int peer_id) {
  misbehavior_manager_->ReportNonContinuousHeaders(peer_id);
}

void ConnectionManager::ReportLowWorkHeaders(int peer_id) {
  misbehavior_manager_->ReportLowWorkHeaders(peer_id);
}

void ConnectionManager::ReportInvalidHeader(int peer_id, const std::string& reason) {
  misbehavior_manager_->ReportInvalidHeader(peer_id, reason);
}

void ConnectionManager::ReportPreVerackMessage(int peer_id) {
  misbehavior_manager_->ReportPreVerackMessage(peer_id);
}

bool ConnectionManager::ShouldDisconnect(int peer_id) const {
  return misbehavior_manager_->ShouldDisconnect(peer_id);
}

bool ConnectionManager::IsMisbehaving(int peer_id) const {
  return misbehavior_manager_->IsMisbehaving(peer_id);
}

NetPermissionFlags ConnectionManager::GetPeerPermissions(int peer_id) const {
  NetPermissionFlags result = NetPermissionFlags::None;
  peer_states_.Read(peer_id, [&](const PeerPtr& peer) { result = peer->permissions(); });
  return result;
}

void ConnectionManager::NoteInvalidHeaderHash(int peer_id, const uint256& hash) {
  misbehavior_manager_->NoteInvalidHeaderHash(peer_id, hash);
}

bool ConnectionManager::HasInvalidHeaderHash(int peer_id, const uint256& hash) const {
  return misbehavior_manager_->HasInvalidHeaderHash(peer_id, hash);
}

// === Peer State Accessors ===

bool ConnectionManager::HasRepliedToGetAddr(int peer_id) const {
  bool result = false;
  peer_states_.Read(peer_id, [&](const PeerPtr& peer) { result = peer->has_replied_to_getaddr(); });
  return result;
}

void ConnectionManager::MarkGetAddrReplied(int peer_id) {
  peer_states_.Modify(peer_id, [](PeerPtr& peer) { peer->mark_getaddr_replied(); });
}

void ConnectionManager::AddLearnedAddress(int peer_id, const AddressKey& key, const LearnedEntry& entry) {
  peer_states_.Modify(peer_id, [&](PeerPtr& peer) { peer->add_learned_address(key, entry); });
}

std::optional<LearnedMap> ConnectionManager::GetLearnedAddresses(int peer_id) const {
  std::optional<LearnedMap> result;
  peer_states_.Read(peer_id, [&](const PeerPtr& peer) { result = peer->learned_addresses(); });
  return result;
}

void ConnectionManager::ClearLearnedAddresses(int peer_id) {
  peer_states_.Modify(peer_id, [](PeerPtr& peer) { peer->clear_learned_addresses(); });
}

void ConnectionManager::UpdateLastHeadersReceived(int peer_id) {
  peer_states_.Modify(peer_id, [](PeerPtr& peer) { peer->update_last_headers_received(); });
}

size_t ConnectionManager::GetExtraBlockRelayCount() const {
  size_t current = block_relay_outbound_count();
  size_t target = config_.target_block_relay_outbound;
  return (current > target) ? (current - target) : 0;
}

int ConnectionManager::GetOldestBlockRelayPeer() const {
  int oldest_id = -1;
  auto oldest_time = std::chrono::steady_clock::time_point::max();

  peer_states_.ForEach([&](int id, const PeerPtr& peer) {
    if (peer && peer->is_block_relay_only() && !peer->is_inbound() && peer->successfully_connected()) {
      auto t = peer->last_headers_received();
      if (t < oldest_time) {
        oldest_time = t;
        oldest_id = id;
      }
    }
  });

  return oldest_id;
}

// === Ban Management (delegated to BanManager) ===

bool ConnectionManager::LoadBans(const std::string& datadir) {
  return ban_manager_->LoadBans(datadir);
}

bool ConnectionManager::SaveBans() {
  return ban_manager_->SaveBans();
}

void ConnectionManager::Ban(const std::string& address, int64_t ban_time_offset) {
  ban_manager_->Ban(address, ban_time_offset);
}

void ConnectionManager::Unban(const std::string& address) {
  ban_manager_->Unban(address);
}

bool ConnectionManager::IsBanned(const std::string& address) const {
  return ban_manager_->IsBanned(address);
}

void ConnectionManager::Discourage(const std::string& address) {
  ban_manager_->Discourage(address);
}

bool ConnectionManager::IsDiscouraged(const std::string& address) const {
  return ban_manager_->IsDiscouraged(address);
}

void ConnectionManager::ClearDiscouraged() {
  ban_manager_->ClearDiscouraged();
}

void ConnectionManager::SweepDiscouraged() {
  ban_manager_->SweepDiscouraged();
}

std::map<std::string, BanManager::BanEntry> ConnectionManager::GetBanned() const {
  return ban_manager_->GetBanned();
}

void ConnectionManager::ClearBanned() {
  ban_manager_->ClearBanned();
}

void ConnectionManager::SweepBanned() {
  ban_manager_->SweepBanned();
}

// === Connection Management ===

void ConnectionManager::AttemptOutboundConnections(int32_t current_height) {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  if (is_running_ && !is_running_()) {
    return;
  }

  if (!addr_relay_mgr_) {
    LOG_NET_WARN("AttemptOutboundConnections called but addr_relay_mgr not set");
    return;
  }

  // SECURITY: Collect netgroups of existing outbound connections
  // This prevents eclipse attacks where attacker controls one /16 subnet
  std::set<std::string> outbound_netgroups;
  peer_states_.ForEach([&](int id, const PeerPtr& peer) {
    if (!peer)
      return;
    if (peer->is_inbound())
      return;
    // Use stored normalized address (set in add_peer)
    const std::string& addr = peer->misbehavior().address;
    if (!addr.empty()) {
      std::string netgroup = util::GetNetgroup(addr);
      if (!netgroup.empty()) {
        outbound_netgroups.insert(netgroup);
      }
    }
  });

  // Track addresses selected in current cycle to avoid re-dialing the same addr repeatedly
  std::unordered_set<AddressKey, AddressKey::Hasher> selected_this_cycle;

  // Try multiple addresses per cycle to fill outbound connection slots quickly
  size_t skipped_duplicates = 0;
  std::string sample_dup_ip;
  uint16_t sample_dup_port = 0;
  for (int i = 0; i < MAX_CONNECTION_ATTEMPTS_PER_CYCLE && needs_more_outbound(); i++) {
    // Select an address from the address manager
    auto maybe_addr = addr_relay_mgr_->Select();
    if (!maybe_addr) {
      break;  // No addresses available
    }

    auto& addr = *maybe_addr;
    AddressKey key(addr);

    // Per-cycle dedup: skip the same address within this loop
    if (selected_this_cycle.find(key) != selected_this_cycle.end()) {
      ++skipped_duplicates;
      if (sample_dup_ip.empty()) {
        if (auto ip_opt = addr.to_string(); ip_opt) {
          sample_dup_ip = *ip_opt;
          sample_dup_port = addr.port;
        }
      }
      continue;
    }

    // Convert NetworkAddress to IP string for logging
    auto maybe_ip_str = addr.to_string();
    if (!maybe_ip_str) {
      LOG_NET_WARN("Failed to convert address to string, skipping");
      continue;
    }

    const std::string& ip_str = *maybe_ip_str;

    // Do not connect to bad ports for the first 50 iterations.
    // After 50 attempts (including skips), bad ports are allowed
    // to ensure we can still connect if no other addresses are available.
    if (i < 50 && util::IsBadPort(addr.port)) {
      continue;
    }

    // Require outbound connections to be to distinct netgroups
    auto addr_normalized = util::ValidateAndNormalizeIP(ip_str);
    std::string addr_netgroup;
    if (addr_normalized.has_value()) {
      addr_netgroup = util::GetNetgroup(*addr_normalized);
      if (!addr_netgroup.empty() && outbound_netgroups.count(addr_netgroup)) {
        continue;
      }
    }

    // Check if already connected to this address (IP-only, ignore port)
    // inbound peers have ephemeral source ports, not listening ports
    if (find_peer_by_address(ip_str, 0) != -1) {
      continue;
    }

    // Do not make automatic outbound connections to addnode peers
    // This ensures manual connections use their dedicated slots and receive their
    // intended protections (NoBan, etc.).
    if (manual_addresses_.find(key) != manual_addresses_.end()) {
      LOG_NET_TRACE("skipping automatic connection to manually-added peer {}:{}", ip_str, addr.port);
      continue;
    }

    selected_this_cycle.insert(key);

    // Track netgroup for this cycle (to avoid selecting multiple from same /16)
    if (!addr_netgroup.empty()) {
      outbound_netgroups.insert(addr_netgroup);
    }

    // Determine connection type for this slot
    // Priority: fill block-relay slots first (security), then full-relay
    ConnectionType conn_type = next_outbound_type();

    LOG_NET_TRACE("attempting {} outbound connection to {}:{}", ConnectionTypeAsString(conn_type), ip_str, addr.port);

    // Try to connect with appropriate connection type
    // Attempt() is called inside ConnectTo() before transport_->connect()
    auto result = ConnectTo(addr, NetPermissionFlags::None, current_height, conn_type);
    if (result != ConnectionResult::Success) {
      if (result == ConnectionResult::AddressBanned || result == ConnectionResult::AddressDiscouraged) {
        LOG_NET_DEBUG("Connection to {}:{} failed ({})", ip_str, addr.port,
                      result == ConnectionResult::AddressBanned ? "banned" : "discouraged");
      } else if (result != ConnectionResult::NoSlotsAvailable && result != ConnectionResult::AlreadyConnected) {
        LOG_NET_DEBUG("Connection initiation failed to {}:{}", ip_str, addr.port);
      }
    }
  }

  // Summarize duplicate skips for this cycle at trace level
  if (skipped_duplicates > 0) {
    LOG_NET_TRACE("AttemptOutboundConnections: skipped {} duplicate selections in cycle{}", skipped_duplicates,
                  sample_dup_ip.empty()
                      ? std::string("")
                      : (std::string(" (e.g., ") + sample_dup_ip + ":" + std::to_string(sample_dup_port) + ")"));
  }
}

void ConnectionManager::AttemptFeelerConnection(int32_t current_height) {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  if (is_running_ && !is_running_()) {
    return;
  }

  if (!addr_relay_mgr_) {
    LOG_NET_WARN("AttemptFeelerConnection called but addr_relay_mgr not set");
    return;
  }

  // Enforce single feeler 
  bool have_feeler = false;
  peer_states_.ForEach([&](int, const PeerPtr& peer) {
    if (peer && peer->is_feeler())
      have_feeler = true;
  });
  if (have_feeler) {
    return;  // one feeler at a time
  }

  // Get address from "new" table (addresses we've heard about but never connected to)
  auto addr = addr_relay_mgr_->SelectNewForFeeler();
  if (!addr) {
    LOG_NET_TRACE("Feeler: no addresses available in NEW table");
    return;
  }

  // Convert NetworkAddress to IP string
  auto addr_str_opt = addr->to_string();
  if (!addr_str_opt) {
    return;
  }

  std::string address = *addr_str_opt;
  uint16_t port = addr->port;

  // Check if already connected to this address (IP-only, ignore port)
  if (find_peer_by_address(address, 0) != -1) {
    LOG_NET_TRACE("Feeler: Already connected to {}, skipping", address);
    return;
  }

  // Check bans/discouragement before wasting a TCP handshake
  if (IsBanned(address) || IsDiscouraged(address)) {
    LOG_NET_TRACE("Feeler: skipping banned/discouraged address {}", address);
    return;
  }

  // Get transport layer
  if (!transport_) {
    LOG_NET_ERROR("Failed to get transport for feeler connection");
    return;
  }

  // Allocate peer ID AFTER connection succeeds
  auto holder = std::make_shared<TransportConnectionPtr>();
  auto callback = [this, address, port, addr, current_height, holder](bool success) {
    // Post to io_context to decouple from transport callback and ensure holder is assigned
    asio::post(io_context_, [this, address, port, addr, success, current_height, holder]() {
      auto connection_cb = *holder;
      if (!success || !connection_cb) {
        // Connection failed - no peer created, no ID allocated
        ++metrics_feeler_failures_;
        return;
      }

      // Connection succeeded - NOW create the feeler peer and allocate ID
      auto peer = Peer::create_outbound(io_context_, connection_cb, network_magic_, current_height, address, port,
                                        ConnectionType::FEELER);
      if (!peer) {
        LOG_NET_ERROR("Failed to create feeler peer for {}:{}", address, port);
        connection_cb->close();
        ++metrics_feeler_failures_;
        return;
      }

      // Set local nonce
      peer->set_local_nonce(local_nonce_);

      // Setup message handler
      if (setup_message_handler_) {
        setup_message_handler_(peer.get());
      }

      // Add to peer manager (allocates ID here)
      int peer_id = add_peer(peer);
      if (peer_id < 0) {
        LOG_NET_DEBUG("Failed to add feeler peer {} to manager (limit reached)", address);
        // Clean up transient peer to avoid destructor warning
        peer->disconnect();
        ++metrics_feeler_failures_;
        return;
      }

      // Get peer and start it
      auto peer_ptr = get_peer(peer_id);
      if (peer_ptr) {
        LOG_NET_DEBUG("feeler connection to {}:{} (peer_id={})", address, port, peer_id);
        // Feelers disconnect after VERSION (before VERACK) - see Peer::handle_version()
        // Good() is called in remove_peer() when version() > 0 (received VERSION)
        // This promotes the address from NEW to TRIED table
        peer_ptr->start();
      }
    });
  };

  // Record attempt in AddrMan before initiating transport connection.
  // Sets last_try (prevents re-selection) and increments failure count.
  // On success, Good() is called in remove_peer() when version() > 0.
  addr_relay_mgr_->Attempt(*addr);

  ++metrics_feeler_attempts_;

  auto connection = transport_->connect(address, port, callback);
  *holder = connection;

  if (!connection) {
    LOG_NET_TRACE("Failed to initiate feeler connection to {}:{}", address, port);
    ++metrics_feeler_failures_;
    // terrible addresses filtered lazily at select time
    return;
  }
}

void ConnectionManager::ConnectToAnchors(const std::vector<protocol::NetworkAddress>& anchors,
                                            int32_t current_height) {
  if (anchors.empty()) {
    return;
  }

  LOG_NET_TRACE("connecting to {} anchor peers (eclipse attack resistance)", anchors.size());

  for (const auto& addr : anchors) {
    // Connect anchors as BLOCK_RELAY, not FULL_RELAY
    auto result = ConnectTo(addr, NetPermissionFlags::None, current_height, ConnectionType::BLOCK_RELAY);
    if (result != ConnectionResult::Success) {
      auto ip_opt = addr.to_string();
      LOG_NET_DEBUG("Failed to connect to anchor {}:{}", ip_opt ? *ip_opt : "unknown", addr.port);
    }
  }
}

bool ConnectionManager::CheckIncomingNonce(uint64_t nonce) {
  // Check 1: Against our own local nonce (self-connection)
  if (nonce == local_nonce_) {
    LOG_NET_INFO("self-connection detected (nonce match), disconnecting");
    return false;
  }

  // Check 2: Against all existing peers' remote nonces (duplicate connection or collision)
  // This catches cases where two nodes behind NAT accidentally choose the same nonce,
  // or where a peer tries to connect twice
  auto peers = get_all_peers();
  for (const auto& peer : peers) {
    // Check against the peer's remote nonce (the nonce they sent in their VERSION)
    // Skip peers that haven't completed handshake (no remote nonce yet)
    if (!peer->successfully_connected()) {
      continue;
    }

    // remote nonce of ALL peers (both inbound and outbound)
    if (peer->peer_nonce() == nonce) {
      LOG_NET_INFO("nonce collision: incoming connection duplicates peer={} ({}), disconnecting",
                   peer->id(), peer->address());
      return false;
    }
  }

  return true;  // Unique nonce, OK to proceed
}

ConnectionResult ConnectionManager::ConnectTo(const protocol::NetworkAddress& addr,
                                              NetPermissionFlags permissions,
                                              int32_t chain_height,
                                              ConnectionType conn_type,
                                              bool bypass_slot_limit) {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  // Convert NetworkAddress to IP string for transport layer
  auto ip_opt = addr.to_string();
  if (!ip_opt) {
    LOG_NET_ERROR("Failed to convert NetworkAddress to IP string");
    return ConnectionResult::TransportFailed;
  }
  const std::string& address = *ip_opt;
  uint16_t port = addr.port;

  // Check if this is a manual/NoBan connection - affects ban checking and dedup behavior
  bool has_noban = HasPermission(permissions, NetPermissionFlags::NoBan);
  bool is_manual = HasPermission(permissions, NetPermissionFlags::Manual);
  // Determine effective connection type: Manual permission overrides to MANUAL
  ConnectionType effective_conn_type = is_manual ? ConnectionType::MANUAL : conn_type;

  // Check if address is banned (NoBan peers exempt - admin explicitly trusts this address)
  if (!has_noban && IsBanned(address)) {
    return ConnectionResult::AddressBanned;
  }

  // Check if address is discouraged (NoBan peers exempt)
  if (!has_noban && IsDiscouraged(address)) {
    return ConnectionResult::AddressDiscouraged;
  }

  // Prevent duplicate outbound connections to same peer
  // This allows multiple manual connections to same IP on different ports (for testing)
  if (is_manual) {
    // Manual (addnode): check by exact IP:port match
    if (find_peer_by_address(address, port) != -1) {
      return ConnectionResult::AlreadyConnected;
    }
  } else {
    // Automatic: check by IP only
    if (find_peer_by_address(address, 0) != -1) {
      return ConnectionResult::AlreadyConnected;
    }
  }

  // Check if we can add more outbound connections
  // Manual connections (addnode RPC) and extra block-relay rotation bypass this limit
  if (!is_manual && !bypass_slot_limit && !needs_more_outbound()) {
    return ConnectionResult::NoSlotsAvailable;
  }

  // In-flight dedup at connect-time: insert pending, skip if already pending
  AddressKey key(addr);
  if (pending_outbound_.find(key) != pending_outbound_.end()) {
    return ConnectionResult::AlreadyConnected;
  }
  pending_outbound_.emplace(key, effective_conn_type);

  // Track manually-added addresses
  // This prevents automatic outbound connections from selecting this address
  if (is_manual) {
    manual_addresses_.insert(key);
    LOG_NET_TRACE("added {} to manual addresses set", address);
  }

  LOG_NET_DEBUG("trying connection {}:{}", address, port);

  // Increment attempt counter immediately when connection is initiated
  ++metrics_outbound_attempts_;

  // Record attempt in AddrMan before initiating transport connection.
  // Sets last_try timestamp (prevents rapid re-selection by select()).
  // On success, Good() at VERACK resets the failure count.
  if (addr_relay_mgr_) {
    addr_relay_mgr_->Attempt(addr);
  }

  // Create async transport connection with callback (deliver connection via holder)
  auto holder = std::make_shared<TransportConnectionPtr>();
  auto cb = [this, address, port, addr, permissions, chain_height,
             holder, effective_conn_type, bypass_slot_limit](bool success) {
    // Post to io_context to decouple from transport callback and ensure
    // *holder assignment completes before we access it.
    // This also guarantees pending_outbound_ modifications are serialized.
    asio::post(io_context_, [this, address, port, addr, success, permissions,
                             chain_height, holder, effective_conn_type,
                             bypass_slot_limit]() {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      // Remove from pending set (now safe - running on io_context thread)
      pending_outbound_.erase(AddressKey(addr));

      auto connection_cb = *holder;

      if (!success || !connection_cb) {
        // Connection failed - no peer created, no ID allocated
        // Attempt() already called before transport_->connect()
        ++metrics_outbound_failures_;
        return;
      }

      // Connection succeeded - now create the peer and allocate ID
      auto peer = Peer::create_outbound(io_context_, connection_cb, network_magic_, chain_height, address, port,
                                        effective_conn_type);
      if (!peer) {
        LOG_NET_ERROR("Failed to create peer for {}:{}", address, port);
        // No peer created; close the raw connection held by holder
        connection_cb->close();
        // Attempt() already called before transport_->connect()
        ++metrics_outbound_failures_;
        return;
      }

      // Set local nonce
      peer->set_local_nonce(local_nonce_);

      // Setup message handler
      if (setup_message_handler_) {
        setup_message_handler_(peer.get());
      }

      // Add to peer manager (bypass_slot_limit for extra block-relay rotation)
      int peer_id = add_peer(peer, permissions, address, /*prefer_evict=*/false, bypass_slot_limit);
      if (peer_id < 0) {
        LOG_NET_DEBUG("Failed to add outbound peer {} to manager (limit reached)", address);
        // Clean up transient peer to avoid destructor warning
        peer->disconnect();
        // Attempt() already called before transport_->connect()
        ++metrics_outbound_failures_;
        return;
      }

      // Get peer and start it
      auto peer_ptr = get_peer(peer_id);
      if (peer_ptr) {
        LOG_NET_DEBUG("connected to {}:{} (peer_id={})", address, port, peer_id);
        // Good() deferred to HandleVerack (post-handshake)
        peer_ptr->start();
      }
    });
  };

  auto connection = transport_->connect(address, port, cb);
  *holder = connection;

  if (!connection) {
    if (is_manual) {
      LOG_NET_INFO("Failed to initiate connection to {}:{}", address, port);
    } else {
      LOG_NET_DEBUG("Failed to initiate connection to {}:{}", address, port);
    }
    pending_outbound_.erase(AddressKey(addr));
    // Attempt() already called before transport_->connect()
    ++metrics_outbound_failures_;
    return ConnectionResult::TransportFailed;
  }

  return ConnectionResult::Success;
}

void ConnectionManager::HandleInboundConnection(TransportConnectionPtr connection,
                                                int32_t current_height,
                                                NetPermissionFlags permissions) {
  if ((is_running_ && !is_running_()) || !connection) {
    return;
  }

  // Get remote address for ban checking
  std::string remote_address = connection->remote_address();
  bool has_noban = HasPermission(permissions, NetPermissionFlags::NoBan);

  // Check if address is banned (NoBan peers exempt)
  if (!has_noban && IsBanned(remote_address)) {
    LOG_NET_INFO("rejected banned address: {}", remote_address);
    connection->close();
    return;
  }

  // Check if address is discouraged
  // Only reject discouraged peers if inbound slots are (almost) full
  // This allows discouraged peers a second chance if we have capacity
  bool is_discouraged = IsDiscouraged(remote_address);
  if (is_discouraged && !has_noban) {
    size_t current_inbound = inbound_count();
    if (current_inbound + 1 >= config_.max_inbound_peers) {
      LOG_NET_INFO("rejected discouraged address {} (inbound slots almost full: {}/{})", remote_address,
                   current_inbound, config_.max_inbound_peers);
      connection->close();
      return;
    }
    // Accept discouraged peer but log it (will be prioritized for eviction)
    LOG_NET_DEBUG("accepting discouraged peer {} (slots available: {}/{})", remote_address, current_inbound,
                  config_.max_inbound_peers);
  }

  // At capacity: try eviction before rejecting 
  if (!can_accept_inbound()) {
    if (!evict_inbound_peer()) {
      LOG_NET_TRACE("rejecting inbound connection from {} (inbound limit reached, eviction failed)", remote_address);
      connection->close();
      return;
    }
  }

  // Create inbound peer
  auto peer = Peer::create_inbound(io_context_, connection, network_magic_, current_height);
  if (peer) {
    // Set local nonce (in test mode where process-wide nonce is not set)
    peer->set_local_nonce(local_nonce_);

    // Setup message handler
    if (setup_message_handler_) {
      setup_message_handler_(peer.get());
    }

    // Add to peer manager FIRST (sets peer ID)
    // Pass prefer_evict for discouraged peers 
    bool mark_prefer_evict = is_discouraged && !has_noban;
    int peer_id = add_peer(peer, permissions, "", mark_prefer_evict);
    if (peer_id < 0) {
      LOG_NET_DEBUG("Failed to add inbound peer to manager (limit reached)");
      // Clean up the transient inbound peer to avoid destructor warning
      peer->disconnect();
      return;
    }

    // Retrieve peer and start it
    peer_states_.Read(peer_id, [](const PeerPtr& peer) {
      if (peer) {
        peer->start();
      }
    });
  }
}

// === Protocol Message Handlers ===

bool ConnectionManager::HandleVerack(PeerPtr peer) {
  // Verify peer is still connected
  if (!peer || !peer->is_connected()) {
    LOG_NET_TRACE("ignoring verack from disconnected peer");
    return true;
  }

  // Normally, Peer::handle_verack() sets successfully_connected_ before this is called.
  // However, if a disconnect was initiated (e.g., feeler, self-connection) and VERACK
  // still reaches us (defense-in-depth), skip processing rather than assert.
  if (!peer->successfully_connected()) {
    LOG_NET_TRACE("ignoring verack for peer {} (not successfully connected)", peer->id());
    return true;
  }

  // Mark address as good after handshake for outbound peers
  // Note: Feelers disconnect after VERSION (before VERACK) and are marked good in remove_peer
  // Note: Block-relay peers ARE included - not calling Good() would cause addresses to be
  // evicted from NEW table. Info-leak is mitigated by not calling Connected() instead.
  // This moves the address from NEW to TRIED table, confirming protocol compatibility
  if (!peer->is_inbound() && !peer->is_feeler() && addr_relay_mgr_) {
    auto na = protocol::NetworkAddress::from_string(peer->address(), peer->port());
    if (!na.is_zero()) {
      addr_relay_mgr_->Good(na);
    } else {
      LOG_NET_WARN("HandleVerack: failed to parse address {}:{}", peer->address(), peer->port());
    }
  }

  // GETADDR policy: send exactly once to outbound full-relay peers
  // do NOT send GETADDR to:
  // - Feelers (they disconnect immediately after handshake)
  // - Block-relay-only peers (they don't participate in address relay)
  if (!peer->is_inbound() && peer->relays_addr() && !peer->has_sent_getaddr()) {
    auto getaddr = std::make_unique<message::GetAddrMessage>();
    peer->send_message(std::move(getaddr));
    peer->mark_getaddr_sent();
    LOG_NET_DEBUG("sent getaddr to {}:{} to populate address manager", peer->address(), peer->port());

    // Notify AddrRelayManager to boost ADDR rate limit bucket
    // This allows the peer to send up to 1000 addresses in response without being rate limited
    if (addr_relay_mgr_) {
      addr_relay_mgr_->NotifyGetAddrSent(peer->id());
    }
  }

  // Update connection success metrics for regular outbound peers
  // NOTE: Feeler success is counted in remove_peer() since feelers disconnect before VERACK
  if (!peer->is_inbound() && !peer->is_feeler()) {
    ++metrics_outbound_successes_;
  }

  return true;
}

}  // namespace network
}  // namespace unicity
