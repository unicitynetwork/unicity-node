// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "network/peer_lifecycle_manager.hpp"

#include "network/eviction_manager.hpp"
#include "network/header_sync_manager.hpp"
#include "network/network_manager.hpp"  // For ConnectionResult enum
#include "network/peer_discovery_manager.hpp"
#include "network/protocol.hpp"
#include "util/logging.hpp"
#include "util/netaddress.hpp"
#include "util/time.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <limits>
#include <set>
#include <utility>  // for std::exchange

#include <fcntl.h>
#include <nlohmann/json.hpp>
#include <unistd.h>

using json = nlohmann::json;

namespace unicity {
namespace network {

namespace {
// Max connection attempts per cycle
static constexpr int MAX_CONNECTION_ATTEMPTS_PER_CYCLE = 100;

}  // namespace

PeerLifecycleManager::PeerLifecycleManager(asio::io_context& io_context, const Config& config,
                                           const std::string& datadir)
    : io_context_(io_context), config_(config), ban_manager_(std::make_unique<BanManager>(datadir)),
      misbehavior_manager_(std::make_unique<MisbehaviorManager>(peer_states_)) {
  // Load persistent bans from disk if datadir is provided
  if (!datadir.empty()) {
    ban_manager_->LoadBans(datadir);
  }
}

void PeerLifecycleManager::SetDiscoveryManager(PeerDiscoveryManager* disc_mgr) {
  discovery_manager_ = disc_mgr;
  if (discovery_manager_) {
    LOG_NET_DEBUG("PeerLifecycleManager: PeerDiscoveryManager injected for address lifecycle tracking");
  } else {
    LOG_NET_WARN("PeerLifecycleManager: SetDiscoveryManager called with nullptr - address tracking disabled");
  }
}

void PeerLifecycleManager::SetHeaderSyncManager(HeaderSyncManager* sync_mgr) {
  header_sync_manager_ = sync_mgr;
  if (header_sync_manager_) {
    LOG_NET_DEBUG("PeerLifecycleManager: HeaderSyncManager injected for sync peer tracking");
  }
}

PeerLifecycleManager::~PeerLifecycleManager() {
  Shutdown();
  disconnect_all();
}

void PeerLifecycleManager::Shutdown() {
  shutting_down_ = true;
}

int PeerLifecycleManager::add_peer(PeerPtr peer, NetPermissionFlags permissions, const std::string& address) {
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

  peer_states_.ForEach([&](int /*id*/, const PeerTrackingData& state) {
    if (state.peer->is_inbound()) {
      current_inbound++;
    } else if (state.peer->is_full_relay()) {
      current_full_relay++;
    } else if (state.peer->is_block_relay_only()) {
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
    if (is_block_relay && current_block_relay >= config_.max_block_relay_outbound) {
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
    // Recompute inbound counts after eviction to avoid TOCTOU
    size_t inbound_now = 0;
    peer_states_.ForEach([&](int id, const PeerTrackingData& state) {
      if (state.peer && state.peer->is_inbound())
        inbound_now++;
    });
    if (inbound_now >= config_.max_inbound_peers) {
      LOG_NET_TRACE("add_peer: inbound still at capacity after eviction, rejecting");
      return -1;
    }
    // Successfully evicted and capacity confirmed; continue
  }

  // Per-netgroup inbound limit
  if (is_inbound) {
    // peer_addr already normalized above
    std::string new_netgroup = util::GetNetgroup(peer_addr);
    if (!new_netgroup.empty()) {
      int same_netgroup_inbound = 0;
      peer_states_.ForEach([&](int /*id*/, const PeerTrackingData& state) {
        if (!state.peer->is_inbound())
          return;
        // Use stored normalized address from misbehavior.address
        std::string peer_netgroup = util::GetNetgroup(state.misbehavior.address);
        if (peer_netgroup == new_netgroup) {
          same_netgroup_inbound++;
        }
      });
      if (same_netgroup_inbound >= MAX_INBOUND_PER_NETGROUP) {
        LOG_NET_TRACE("add_peer: reject inbound per-netgroup limit netgroup={} count={} limit={}", new_netgroup,
                      same_netgroup_inbound, MAX_INBOUND_PER_NETGROUP);
        return -1;  // Reject new inbound from same netgroup
      }
    }
  }

  // Allocate peer ID (simple monotonic counter via member counter)
  int peer_id = next_peer_id_.fetch_add(1, std::memory_order_relaxed);
  peer->set_id(peer_id);  // Set the ID on the peer object

  // Create and insert PeerTrackingData (store normalized address)
  auto creation_time = util::GetSteadyTime();
  PeerTrackingData state(peer, creation_time);
  state.misbehavior.permissions = permissions;
  state.misbehavior.address = peer_addr;  // Store normalized address
  peer_states_.InsertOrUpdate(peer_id, std::move(state));

  LOG_NET_DEBUG("Added connection peer={}", peer_id);

  // Notify PeerDiscoveryManager directly for address tracking
  if (discovery_manager_) {
    discovery_manager_->OnPeerConnected(peer_id, peer_addr, peer->port(), peer->connection_type());
  }

  return peer_id;  // Return the assigned ID
}

void PeerLifecycleManager::remove_peer(int peer_id) {
  // Extract data from peer state before erasing
  PeerPtr peer;
  std::string peer_address;  // Normalized address (consistent with add_peer)
  uint16_t peer_port = 0;
  bool mark_addr_good = false;

  bool found = peer_states_.Read(peer_id, [&](const PeerTrackingData& state) {
    peer = state.peer;

    // Use stored normalized address for consistency with add_peer/OnPeerConnected
    peer_address = state.misbehavior.address;
    if (peer) {
      peer_port = peer->port();
    }

    if (state.misbehavior.should_discourage) {
      // Discourage using already-normalized address (NoBan checked when setting should_discourage)
      if (!peer_address.empty()) {
        Discourage(peer_address);
        LOG_NET_TRACE("remove_peer: discouraged {} due to misbehavior", peer_address);
      }
    }

    // Decide whether to mark as good in addrman
    // Block-relay peers are excluded to maintain eclipse attack resistance -
    // their addresses should NOT be promoted in AddrMan (keeps them invisible)
    // Feelers ARE included - their purpose is to validate addresses (NEW→TRIED promotion)
    if (peer && !state.misbehavior.should_discourage && !peer->is_inbound() && !peer->is_block_relay_only()) {
      // Feelers disconnect after VERSION (before VERACK), so check version() > 0 instead of successfully_connected()
      // Regular outbound peers must complete full handshake (VERACK)
      bool connection_succeeded = peer->is_feeler() ? (peer->version() > 0) : peer->successfully_connected();
      if (connection_succeeded) {
        // Use normalized address that matches what was added to addr_manager
        mark_addr_good = (!peer_address.empty() && peer_port != 0);
      }
    }

    // Update failure metrics for outbound/feeler peers that failed to complete handshake
    if (peer && !peer->is_inbound()) {
      if (peer->is_feeler()) {
        // Feelers succeed if they received VERSION (they disconnect before VERACK by design)
        if (peer->version() == 0) {
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

  // Erase from peer_states_ (thread-safe)
  peer_states_.Erase(peer_id);
  LOG_NET_TRACE("remove_peer: erased peer {} from map", peer_id);

  // Notify PeerDiscoveryManager directly for address tracking
  if (!skip_notifications && discovery_manager_) {
    discovery_manager_->OnPeerDisconnected(peer_id, peer_address, peer_port, mark_addr_good);
  }

  // Notify HeaderSyncManager directly for sync peer tracking
  if (!skip_notifications && header_sync_manager_) {
    header_sync_manager_->OnPeerDisconnected(static_cast<uint64_t>(peer_id));
  }

  // Disconnect the peer (idempotent - logs only if not already disconnected)
  if (peer) {
    peer->disconnect();
  }
}

PeerPtr PeerLifecycleManager::get_peer(int peer_id) {
  PeerPtr result;
  peer_states_.Read(peer_id, [&](const PeerTrackingData& state) { result = state.peer; });
  return result;
}

int PeerLifecycleManager::find_peer_by_address(const std::string& address, uint16_t port) {
  // Validate and normalize the search address
  auto needle_addr_opt = util::ValidateAndNormalizeIP(address);
  if (!needle_addr_opt.has_value()) {
    return -1;  // Invalid address
  }
  const std::string& needle_addr = *needle_addr_opt;
  int result = -1;

  peer_states_.ForEach([&](int id, const PeerTrackingData& state) {
    if (result != -1)
      return;  // Already found (ForEach doesn't support early break)
    if (!state.peer)
      return;

    // Use stored normalized address (set in add_peer) - no redundant normalization
    if (state.misbehavior.address != needle_addr)
      return;

    // Match port if specified (0 = any port)
    if (port == 0 || state.peer->port() == port) {
      result = id;
    }
  });

  return result;
}

std::vector<PeerPtr> PeerLifecycleManager::get_all_peers() {
  std::vector<PeerPtr> result;
  result.reserve(peer_states_.Size());  // Reserve capacity to avoid reallocations

  peer_states_.ForEach([&](int id, const PeerTrackingData& state) { result.push_back(state.peer); });

  // Sort by peer ID to ensure deterministic iteration order
  // (unordered_map iteration is non-deterministic)
  // Use stable_sort for consistent ordering when IDs are equal (shouldn't happen, but defensive)
  std::stable_sort(result.begin(), result.end(), [](const PeerPtr& a, const PeerPtr& b) { return a->id() < b->id(); });

  return result;
}

std::vector<PeerPtr> PeerLifecycleManager::get_outbound_peers() {
  std::vector<PeerPtr> result;
  result.reserve(peer_states_.Size());  // Reserve capacity (worst case: all outbound)

  peer_states_.ForEach([&](int id, const PeerTrackingData& state) {
    if (!state.peer->is_inbound()) {
      result.push_back(state.peer);
    }
  });

  // Sort by peer ID to ensure deterministic iteration order
  // (unordered_map iteration is non-deterministic)
  std::stable_sort(result.begin(), result.end(), [](const PeerPtr& a, const PeerPtr& b) { return a->id() < b->id(); });

  return result;
}

std::vector<PeerPtr> PeerLifecycleManager::get_inbound_peers() {
  std::vector<PeerPtr> result;
  result.reserve(peer_states_.Size());  // Reserve capacity (worst case: all inbound)

  peer_states_.ForEach([&](int id, const PeerTrackingData& state) {
    if (state.peer->is_inbound()) {
      result.push_back(state.peer);
    }
  });

  // Sort by peer ID to ensure deterministic iteration order
  // (unordered_map iteration is non-deterministic)
  std::stable_sort(result.begin(), result.end(), [](const PeerPtr& a, const PeerPtr& b) { return a->id() < b->id(); });

  return result;
}

size_t PeerLifecycleManager::peer_count() const {
  return peer_states_.Size();
}

size_t PeerLifecycleManager::outbound_count() const {
  // Total outbound = full-relay + block-relay (excludes feeler/manual)
  return full_relay_outbound_count() + block_relay_outbound_count();
}

size_t PeerLifecycleManager::full_relay_outbound_count() const {
  size_t count = 0;
  peer_states_.ForEach([&](int id, const PeerTrackingData& state) {
    if (!state.peer->is_inbound() && state.peer->is_full_relay()) {
      count++;
    }
  });
  return count;
}

size_t PeerLifecycleManager::block_relay_outbound_count() const {
  size_t count = 0;
  peer_states_.ForEach([&](int id, const PeerTrackingData& state) {
    if (!state.peer->is_inbound() && state.peer->is_block_relay_only()) {
      count++;
    }
  });
  return count;
}

size_t PeerLifecycleManager::pending_full_relay_count() const {
  size_t count = 0;
  for (const auto& [key, type] : pending_outbound_) {
    if (type == ConnectionType::OUTBOUND_FULL_RELAY) {
      count++;
    }
  }
  return count;
}

size_t PeerLifecycleManager::pending_block_relay_count() const {
  size_t count = 0;
  for (const auto& [key, type] : pending_outbound_) {
    if (type == ConnectionType::BLOCK_RELAY) {
      count++;
    }
  }
  return count;
}

size_t PeerLifecycleManager::inbound_count() const {
  size_t count = 0;

  peer_states_.ForEach([&](int id, const PeerTrackingData& state) {
    if (state.peer->is_inbound()) {
      count++;
    }
  });

  return count;
}

bool PeerLifecycleManager::needs_more_outbound() const {
  // Include pending (in-flight) connections to avoid over-subscription
  // This matches Bitcoin Core's approach of checking limits BEFORE attempting connections
  size_t total_wanted = config_.target_full_relay_outbound + config_.target_block_relay_outbound;
  size_t total_have = outbound_count() + pending_outbound_.size();
  return total_have < total_wanted;
}

bool PeerLifecycleManager::needs_more_full_relay_outbound() const {
  // Include pending connections of this type to avoid over-subscription
  return (full_relay_outbound_count() + pending_full_relay_count()) < config_.target_full_relay_outbound;
}

bool PeerLifecycleManager::needs_more_block_relay_outbound() const {
  // Include pending connections of this type to avoid over-subscription
  return (block_relay_outbound_count() + pending_block_relay_count()) < config_.target_block_relay_outbound;
}

ConnectionType PeerLifecycleManager::next_outbound_type() const {
  // Priority: block-relay connections first (security critical for eclipse resistance)
  // Once block-relay slots are filled, fill full-relay slots
  if (needs_more_block_relay_outbound()) {
    return ConnectionType::BLOCK_RELAY;
  }
  return ConnectionType::OUTBOUND_FULL_RELAY;
}

bool PeerLifecycleManager::can_accept_inbound() const {
  return inbound_count() < config_.max_inbound_peers;
}

bool PeerLifecycleManager::evict_inbound_peer() {
  // Collect eviction candidates from ALL peers
  // EvictionManager handles filtering (outbound, NoBan) as defense-in-depth
  // Selection logic is delegated to EvictionManager

  std::vector<EvictionManager::EvictionCandidate> candidates;
  auto now = util::GetSteadyTime();

  peer_states_.ForEach([&](int id, const PeerTrackingData& state) {
    // Defensive null check (shouldn't happen - add_peer rejects null, remove_peer erases)
    if (!state.peer)
      return;

    // Check NoBan protection
    bool is_protected = HasPermission(state.misbehavior.permissions, NetPermissionFlags::NoBan);

    // Check recently connected protection (within 60 seconds)
    // Skip these entirely - they don't even become candidates
    auto connected_time = state.peer->stats().connected_time.load(std::memory_order_relaxed);
    auto now_duration = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch());
    auto connection_age = now_duration - connected_time;
    if (connection_age.count() < 60) {
      return;  // Skip recently connected peers entirely
    }

    auto ping_ms = state.peer->stats().ping_time_ms.load(std::memory_order_relaxed);
    auto connected_tp = std::chrono::steady_clock::time_point(connected_time);

    // Get netgroup using stored normalized address (set in add_peer)
    std::string netgroup = state.misbehavior.address.empty() ? "" : util::GetNetgroup(state.misbehavior.address);

    // is_outbound: EvictionManager will filter these as defense-in-depth
    bool is_outbound = !state.peer->is_inbound();

    candidates.push_back({
        id, connected_tp, ping_ms.count(), netgroup, is_protected, is_outbound,
        state.last_headers_received  // For header relay protection
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

void PeerLifecycleManager::disconnect_all() {
  // Set stopping flag to prevent new peers from being added
  stopping_all_ = true;  // Single-threaded - direct assignment

  bool skip_notifications = shutting_down_;

  // Get all peers to disconnect (capture normalized address for notifications)
  struct DisconnectInfo {
    PeerPtr peer;
    std::string address;  // Normalized (from state.misbehavior.address)
  };
  std::map<int, DisconnectInfo> peers_to_disconnect;
  peer_states_.ForEach([&](int id, const PeerTrackingData& state) {
    peers_to_disconnect[id] = {state.peer, state.misbehavior.address};
  });

  // Notify PeerDiscoveryManager directly for cleanup (no addr marking during shutdown)
  if (!skip_notifications && discovery_manager_) {
    for (const auto& [id, info] : peers_to_disconnect) {
      if (info.peer) {
        discovery_manager_->OnPeerDisconnected(id, info.address, info.peer->port(), false);
      }
    }
  }

  // Notify HeaderSyncManager directly for sync peer tracking
  if (!skip_notifications && header_sync_manager_) {
    for (const auto& [id, info] : peers_to_disconnect) {
      header_sync_manager_->OnPeerDisconnected(static_cast<uint64_t>(id));
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

// Test-only method (intentionally available in all builds for testing)
void PeerLifecycleManager::TestOnlySetPeerCreatedAt(int peer_id, std::chrono::steady_clock::time_point tp) {
  peer_states_.Modify(peer_id, [&](PeerTrackingData& state) { state.created_at = tp; });
}

void PeerLifecycleManager::process_periodic() {
  std::vector<int> to_remove;

  // Find disconnected peers and peers marked for disconnection
  peer_states_.ForEach([&](int id, const PeerTrackingData& state) {
    // Defensive null check (shouldn't happen - add_peer rejects null, remove_peer erases)
    if (!state.peer)
      return;

    if (!state.peer->is_connected()) {
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
    if (state.peer->is_feeler()) {
      auto age = std::chrono::duration_cast<std::chrono::seconds>(util::GetSteadyTime() - state.created_at);
      if (age.count() >= FEELER_MAX_LIFETIME_SEC) {
        LOG_NET_DEBUG("feeler peer={} timeout ({}s) - safety net for stuck handshake", id, age.count());
        to_remove.push_back(id);
        return;
      }
    }

    // Check for peers marked for disconnection due to misbehavior
    if (state.misbehavior.should_discourage) {
      // Never disconnect peers with NoBan permission
      if (HasPermission(state.misbehavior.permissions, NetPermissionFlags::NoBan)) {
        LOG_NET_TRACE("process_periodic: skipping NoBan peer={} (protected)", id);
        return;
      }

      // Add to removal list if not already there
      if (std::find(to_remove.begin(), to_remove.end(), id) == to_remove.end()) {
        to_remove.push_back(id);
        LOG_NET_INFO("Disconnecting misbehaving peer {}", id);
      }
    }
  });

  // Remove disconnected peers
  for (int peer_id : to_remove) {
    remove_peer(peer_id);
  }

  // Cleanup stale addresses in AddressManager
  if (discovery_manager_) {
    discovery_manager_->CleanupStale();
  }

  LOG_NET_TRACE("metrics: outbound attempts={} successes={} failures={} | feeler attempts={} successes={} failures={}",
                metrics_outbound_attempts_, metrics_outbound_successes_, metrics_outbound_failures_,
                metrics_feeler_attempts_, metrics_feeler_successes_, metrics_feeler_failures_);
}

// === Misbehavior Tracking Public API ===

// === Misbehavior Tracking (delegated to MisbehaviorManager) ===

void PeerLifecycleManager::ReportInvalidPoW(int peer_id) {
  misbehavior_manager_->ReportInvalidPoW(peer_id);
}

void PeerLifecycleManager::ReportOversizedMessage(int peer_id) {
  misbehavior_manager_->ReportOversizedMessage(peer_id);
}

void PeerLifecycleManager::ReportNonContinuousHeaders(int peer_id) {
  misbehavior_manager_->ReportNonContinuousHeaders(peer_id);
}

void PeerLifecycleManager::ReportLowWorkHeaders(int peer_id) {
  misbehavior_manager_->ReportLowWorkHeaders(peer_id);
}

void PeerLifecycleManager::ReportInvalidHeader(int peer_id, const std::string& reason) {
  misbehavior_manager_->ReportInvalidHeader(peer_id, reason);
}

void PeerLifecycleManager::ReportTooManyOrphans(int peer_id) {
  misbehavior_manager_->ReportTooManyOrphans(peer_id);
}

void PeerLifecycleManager::ReportPreVerackMessage(int peer_id) {
  misbehavior_manager_->ReportPreVerackMessage(peer_id);
}

bool PeerLifecycleManager::ShouldDisconnect(int peer_id) const {
  return misbehavior_manager_->ShouldDisconnect(peer_id);
}

bool PeerLifecycleManager::IsMisbehaving(int peer_id) const {
  return misbehavior_manager_->IsMisbehaving(peer_id);
}

NetPermissionFlags PeerLifecycleManager::GetPeerPermissions(int peer_id) const {
  NetPermissionFlags result = NetPermissionFlags::None;
  peer_states_.Read(peer_id, [&](const PeerTrackingData& state) { result = state.misbehavior.permissions; });
  return result;
}

void PeerLifecycleManager::NoteInvalidHeaderHash(int peer_id, const uint256& hash) {
  misbehavior_manager_->NoteInvalidHeaderHash(peer_id, hash);
}

bool PeerLifecycleManager::HasInvalidHeaderHash(int peer_id, const uint256& hash) const {
  return misbehavior_manager_->HasInvalidHeaderHash(peer_id, hash);
}

void PeerLifecycleManager::IncrementUnconnectingHeaders(int peer_id) {
  misbehavior_manager_->IncrementUnconnectingHeaders(peer_id);
}

void PeerLifecycleManager::ResetUnconnectingHeaders(int peer_id) {
  misbehavior_manager_->ResetUnconnectingHeaders(peer_id);
}

int PeerLifecycleManager::GetUnconnectingHeadersCount(int peer_id) const {
  return misbehavior_manager_->GetUnconnectingHeadersCount(peer_id);
}

// === PeerTrackingData Accessors ===

std::optional<std::pair<uint256, int64_t>> PeerLifecycleManager::GetLastAnnouncement(int peer_id) const {
  std::optional<std::pair<uint256, int64_t>> result;
  peer_states_.Read(peer_id, [&](const PeerTrackingData& state) {
    result = std::make_pair(state.last_announced_block, state.last_announce_time_s);
  });
  return result;
}

void PeerLifecycleManager::SetLastAnnouncedBlock(int peer_id, const uint256& hash, int64_t time_s) {
  peer_states_.Modify(peer_id, [&](PeerTrackingData& state) {
    state.last_announced_block = hash;
    state.last_announce_time_s = time_s;
  });
}

// Block announcement queue operations

std::vector<uint256> PeerLifecycleManager::GetBlocksForInvRelay(int peer_id) const {
  std::vector<uint256> result;
  peer_states_.Read(peer_id, [&](const PeerTrackingData& state) { result = state.blocks_for_inv_relay; });
  return result;
}

void PeerLifecycleManager::AddBlockForInvRelay(int peer_id, const uint256& hash) {
  peer_states_.Modify(peer_id, [&](PeerTrackingData& state) {
    // Simple dedup: only add if not already present
    if (std::find(state.blocks_for_inv_relay.begin(), state.blocks_for_inv_relay.end(), hash) ==
        state.blocks_for_inv_relay.end()) {
      state.blocks_for_inv_relay.push_back(hash);
    }
  });
}

void PeerLifecycleManager::RemoveBlockForInvRelay(int peer_id, const uint256& hash) {
  peer_states_.Modify(peer_id, [&](PeerTrackingData& state) {
    auto& queue = state.blocks_for_inv_relay;
    queue.erase(std::remove(queue.begin(), queue.end(), hash), queue.end());
  });
}

std::vector<uint256> PeerLifecycleManager::MoveBlocksForInvRelay(int peer_id) {
  std::vector<uint256> result;
  peer_states_.Modify(peer_id,
                      [&](PeerTrackingData& state) { result = std::exchange(state.blocks_for_inv_relay, {}); });
  return result;
}

void PeerLifecycleManager::ClearBlocksForInvRelay(int peer_id) {
  peer_states_.Modify(peer_id, [](PeerTrackingData& state) { state.blocks_for_inv_relay.clear(); });
}

bool PeerLifecycleManager::HasRepliedToGetAddr(int peer_id) const {
  bool result = false;
  peer_states_.Read(peer_id, [&](const PeerTrackingData& state) { result = state.getaddr_replied; });
  return result;
}

void PeerLifecycleManager::MarkGetAddrReplied(int peer_id) {
  peer_states_.Modify(peer_id, [](PeerTrackingData& state) { state.getaddr_replied = true; });
}

void PeerLifecycleManager::AddLearnedAddress(int peer_id, const AddressKey& key, const LearnedEntry& entry) {
  peer_states_.Modify(peer_id, [&](PeerTrackingData& state) { state.learned_addresses[key] = entry; });
}

std::optional<LearnedMap> PeerLifecycleManager::GetLearnedAddresses(int peer_id) const {
  std::optional<LearnedMap> result;
  peer_states_.Read(peer_id, [&](const PeerTrackingData& state) { result = state.learned_addresses; });
  return result;
}

void PeerLifecycleManager::ClearLearnedAddresses(int peer_id) {
  peer_states_.Modify(peer_id, [](PeerTrackingData& state) { state.learned_addresses.clear(); });
}

void PeerLifecycleManager::UpdateLastHeadersReceived(int peer_id) {
  peer_states_.Modify(peer_id, [](PeerTrackingData& state) { state.last_headers_received = util::GetSteadyTime(); });
}

// === Ban Management (delegated to BanManager) ===

bool PeerLifecycleManager::LoadBans(const std::string& datadir) {
  return ban_manager_->LoadBans(datadir);
}

bool PeerLifecycleManager::SaveBans() {
  return ban_manager_->SaveBans();
}

void PeerLifecycleManager::Ban(const std::string& address, int64_t ban_time_offset) {
  ban_manager_->Ban(address, ban_time_offset);
}

void PeerLifecycleManager::Unban(const std::string& address) {
  ban_manager_->Unban(address);
}

bool PeerLifecycleManager::IsBanned(const std::string& address) const {
  return ban_manager_->IsBanned(address);
}

void PeerLifecycleManager::Discourage(const std::string& address) {
  ban_manager_->Discourage(address);
}

bool PeerLifecycleManager::IsDiscouraged(const std::string& address) const {
  return ban_manager_->IsDiscouraged(address);
}

void PeerLifecycleManager::ClearDiscouraged() {
  ban_manager_->ClearDiscouraged();
}

void PeerLifecycleManager::SweepDiscouraged() {
  ban_manager_->SweepDiscouraged();
}

std::map<std::string, BanManager::CBanEntry> PeerLifecycleManager::GetBanned() const {
  return ban_manager_->GetBanned();
}

void PeerLifecycleManager::ClearBanned() {
  ban_manager_->ClearBanned();
}

void PeerLifecycleManager::SweepBanned() {
  ban_manager_->SweepBanned();
}

void PeerLifecycleManager::AddToWhitelist(const std::string& address) {
  ban_manager_->AddToWhitelist(address);
}

void PeerLifecycleManager::RemoveFromWhitelist(const std::string& address) {
  ban_manager_->RemoveFromWhitelist(address);
}

bool PeerLifecycleManager::IsWhitelisted(const std::string& address) const {
  return ban_manager_->IsWhitelisted(address);
}

// === Protocol Message Handlers ===

// === Connection Management ===

void PeerLifecycleManager::AttemptOutboundConnections(IsRunningCallback is_running, ConnectCallback connect_fn) {
  if (!is_running()) {
    return;
  }

  if (!discovery_manager_) {
    LOG_NET_WARN("AttemptOutboundConnections called but discovery_manager not set");
    return;
  }

  // SECURITY: Collect netgroups of existing outbound connections
  // This prevents eclipse attacks where attacker controls one /16 subnet
  std::set<std::string> outbound_netgroups;
  peer_states_.ForEach([&](int id, const PeerTrackingData& state) {
    if (!state.peer)
      return;
    if (state.peer->is_inbound())
      return;
    // Use stored normalized address (set in add_peer)
    if (!state.misbehavior.address.empty()) {
      std::string netgroup = util::GetNetgroup(state.misbehavior.address);
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
    auto maybe_addr = discovery_manager_->Select();
    if (!maybe_addr) {
      break;  // No addresses available
    }

    auto& addr = *maybe_addr;
    AddressKey key(addr);

    // Per-cycle dedup: skip the same address within this loop
    if (selected_this_cycle.find(key) != selected_this_cycle.end()) {
      ++skipped_duplicates;
      if (sample_dup_ip.empty()) {
        if (auto _ip_opt = addr.to_string(); _ip_opt) {
          sample_dup_ip = *_ip_opt;
          sample_dup_port = addr.port;
        }
      }
      continue;
    }

    // Convert NetworkAddress to IP string for logging
    auto maybe_ip_str = addr.to_string();
    if (!maybe_ip_str) {
      LOG_NET_WARN("Failed to convert address to string, marking as failed");
      discovery_manager_->Failed(addr);
      continue;
    }

    const std::string& ip_str = *maybe_ip_str;

    // SECURITY: Require outbound connections to be to distinct netgroups
    // This prevents eclipse attacks where all outbound connections go to same /16
    auto addr_normalized = util::ValidateAndNormalizeIP(ip_str);
    if (addr_normalized.has_value()) {
      std::string addr_netgroup = util::GetNetgroup(*addr_normalized);
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
      LOG_NET_TRACE("Skipping automatic connection to manually-added peer {}:{}", ip_str, addr.port);
      continue;
    }

    selected_this_cycle.insert(key);

    // Track netgroup for this cycle (to avoid selecting multiple from same /16)
    if (addr_normalized.has_value()) {
      std::string addr_netgroup = util::GetNetgroup(*addr_normalized);
      if (!addr_netgroup.empty()) {
        outbound_netgroups.insert(addr_netgroup);
      }
    }

    // Determine connection type for this slot
    // Priority: fill block-relay slots first (security), then full-relay
    ConnectionType conn_type = next_outbound_type();

    LOG_NET_TRACE("Attempting {} outbound connection to {}:{}", ConnectionTypeAsString(conn_type), ip_str, addr.port);

    // Mark as attempt (connection may still fail)
    discovery_manager_->Attempt(addr);

    // Try to connect via callback with appropriate connection type
    // Note: Attempt counter is incremented inside ConnectTo() to avoid double-counting
    auto result = connect_fn(addr, conn_type);
    if (result != ConnectionResult::Success) {
      // Mark as failed for persistent error conditions (prevents infinite retry)
      if (result == ConnectionResult::AddressBanned || result == ConnectionResult::AddressDiscouraged) {
        LOG_NET_DEBUG("Connection to {}:{} failed ({}) - marking as failed to trigger backoff", ip_str, addr.port,
                      result == ConnectionResult::AddressBanned ? "banned" : "discouraged");
        discovery_manager_->Failed(addr);
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

void PeerLifecycleManager::AttemptFeelerConnection(IsRunningCallback is_running, GetTransportCallback get_transport,
                                                   SetupMessageHandlerCallback setup_handler, uint32_t network_magic,
                                                   int32_t current_height, uint64_t local_nonce) {
  if (!is_running()) {
    return;
  }

  if (!discovery_manager_) {
    LOG_NET_WARN("AttemptFeelerConnection called but discovery_manager not set");
    return;
  }

  // Enforce single feeler (Core parity)
  bool have_feeler = false;
  peer_states_.ForEach([&](int, const PeerTrackingData& st) {
    if (st.peer && st.peer->is_feeler())
      have_feeler = true;
  });
  if (have_feeler) {
    return;  // one feeler at a time
  }

  // Get address from "new" table (addresses we've heard about but never connected to)
  auto addr = discovery_manager_->SelectNewForFeeler();
  if (!addr) {
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

  // Get transport layer
  auto transport = get_transport();
  if (!transport) {
    LOG_NET_ERROR("Failed to get transport for feeler connection");
    return;
  }

  // Allocate peer ID AFTER connection succeeds
  auto holder = std::make_shared<TransportConnectionPtr>();
  auto callback = [this, address, port, addr, network_magic, current_height, local_nonce, setup_handler,
                   holder](bool success) {
    // Post to io_context to decouple from transport callback and ensure holder is assigned
    asio::post(io_context_, [this, address, port, addr, success, network_magic, current_height, local_nonce,
                             setup_handler, holder]() {
      auto connection_cb = *holder;
      if (!success || !connection_cb) {
        // Connection failed - no peer created, no ID allocated
        ++metrics_feeler_failures_;
        // Mark as failed to trigger backoff
        if (discovery_manager_) {
          discovery_manager_->Failed(*addr);
        }
        return;
      }

      // Connection succeeded - NOW create the feeler peer and allocate ID
      auto peer = Peer::create_outbound(io_context_, connection_cb, network_magic, current_height, address, port,
                                        ConnectionType::FEELER);
      if (!peer) {
        LOG_NET_ERROR("Failed to create feeler peer for {}:{}", address, port);
        connection_cb->close();
        ++metrics_feeler_failures_;
        if (discovery_manager_) {
          discovery_manager_->Failed(*addr);
        }
        return;
      }

      // Set local nonce
      peer->set_local_nonce(local_nonce);

      // Setup message handler
      setup_handler(peer.get());

      // Add to peer manager (allocates ID here)
      int peer_id = add_peer(peer);
      if (peer_id < 0) {
        LOG_NET_DEBUG("Failed to add feeler peer {} to manager (limit reached)", address);
        // Clean up transient peer to avoid destructor warning
        peer->disconnect();
        ++metrics_feeler_failures_;
        if (discovery_manager_) {
          discovery_manager_->Failed(*addr);
        }
        return;
      }

      // Get peer and start it
      auto peer_ptr = get_peer(peer_id);
      if (peer_ptr) {
        LOG_NET_DEBUG("Feeler connection to {}:{} (peer_id={})", address, port, peer_id);
        // Feelers disconnect after VERSION (before VERACK) - see Peer::handle_version()
        // Good() is called in remove_peer() when version() > 0 (received VERSION)
        // This promotes the address from NEW to TRIED table
        peer_ptr->start();
      }
    });
  };

  // Increment attempt counter immediately when connection is initiated
  // (matches pattern in ConnectTo() - count attempt before knowing result)
  ++metrics_feeler_attempts_;

  auto connection = transport->connect(address, port, callback);
  *holder = connection;

  if (!connection) {
    LOG_NET_TRACE("Failed to initiate feeler connection to {}:{}", address, port);
    ++metrics_feeler_failures_;
    if (discovery_manager_) {
      discovery_manager_->Failed(*addr);
    }
    return;
  }
}

void PeerLifecycleManager::ConnectToAnchors(const std::vector<protocol::NetworkAddress>& anchors,
                                            ConnectCallback connect_fn) {
  if (anchors.empty()) {
    return;
  }

  LOG_NET_TRACE("Connecting to {} anchor peers (eclipse attack resistance)", anchors.size());

  for (const auto& addr : anchors) {
    // Convert NetworkAddress to IP string for whitelist
    auto ip_opt = addr.to_string();
    if (ip_opt) {
      // Whitelist anchor peers (they get NoBan permission in connect callback)
      AddToWhitelist(*ip_opt);
    }

    // connect anchors as BLOCK_RELAY, not FULL_RELAY
    auto result = connect_fn(addr, ConnectionType::BLOCK_RELAY);
    if (result != ConnectionResult::Success) {
      LOG_NET_DEBUG("Failed to connect to anchor {}:{}", ip_opt ? *ip_opt : "unknown", addr.port);
    }
  }
}

bool PeerLifecycleManager::CheckIncomingNonce(uint64_t nonce, uint64_t local_nonce) {
  // Check 1: Against our own local nonce (self-connection)
  if (nonce == local_nonce) {
    LOG_NET_INFO("Self-connection detected: incoming nonce {} matches our local nonce", nonce);
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
      LOG_NET_INFO("Nonce collision detected: incoming nonce {} matches existing peer {} ({})", nonce, peer->id(),
                   peer->address());
      return false;
    }
  }

  return true;  // Unique nonce, OK to proceed
}

ConnectionResult PeerLifecycleManager::ConnectTo(const protocol::NetworkAddress& addr, NetPermissionFlags permissions,
                                                 std::shared_ptr<Transport> transport, OnGoodCallback on_good,
                                                 OnAttemptCallback on_attempt,
                                                 SetupMessageHandlerCallback setup_message_handler,
                                                 uint32_t network_magic, int32_t chain_height, uint64_t local_nonce,
                                                 ConnectionType conn_type) {
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

  // Check if address is banned (NoBan peers exempt - admin explicitly trusts this address)
  if (!has_noban && IsBanned(address)) {
    return ConnectionResult::AddressBanned;
  }

  // Check if address is discouraged (NoBan peers exempt)
  if (!has_noban && IsDiscouraged(address)) {
    return ConnectionResult::AddressDiscouraged;
  }

  // SECURITY: Prevent duplicate outbound connections to same peer
  // This allows multiple manual connections to same IP on different ports (for testing
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
  // IMPORTANT: Manual connections (addnode RPC) bypass this limit
  if (!is_manual && !needs_more_outbound()) {
    return ConnectionResult::NoSlotsAvailable;
  }

  // In-flight dedup at connect-time: insert pending, skip if already pending
  // Single-threaded network - no mutex needed
  AddressKey key(addr);
  if (pending_outbound_.find(key) != pending_outbound_.end()) {
#ifdef UNICITY_TESTS
    // Allow replacing a stale pending attempt only in tests (io.poll() nests callbacks)
    LOG_NET_TRACE("ConnectTo: replacing pending outbound entry for addr:{}:{} (test mode)", address, port);
    pending_outbound_.erase(key);
#else
    return ConnectionResult::AlreadyConnected;
#endif
  }
  pending_outbound_.emplace(key, conn_type);

  // Track manually-added addresses
  // This prevents automatic outbound connections from selecting this address
  if (is_manual) {
    manual_addresses_.insert(key);
    LOG_NET_TRACE("Added {} to manual addresses set", address);
  }

  LOG_NET_DEBUG("trying connection {}:{}", address, port);

  // Increment attempt counter immediately when connection is initiated
  ++metrics_outbound_attempts_;

  // Create async transport connection with callback (deliver connection via holder)
  auto holder = std::make_shared<TransportConnectionPtr>();
  // Determine effective connection type: Manual permission overrides to MANUAL
  ConnectionType effective_conn_type = is_manual ? ConnectionType::MANUAL : conn_type;
  auto cb = [this, address, port, addr, on_good, on_attempt, permissions, network_magic, chain_height, local_nonce,
             setup_message_handler, holder, effective_conn_type](bool success) {
    // Post to io_context to decouple from transport callback and ensure
    // *holder assignment completes before we access it.
    // This also guarantees pending_outbound_ modifications are serialized.
    asio::post(io_context_, [this, address, port, addr, success, on_good, on_attempt, permissions, network_magic,
                             chain_height, local_nonce, setup_message_handler, holder, effective_conn_type]() {
      // Remove from pending set (now safe - running on io_context thread)
      pending_outbound_.erase(AddressKey(addr));

      auto connection_cb = *holder;

      if (!success || !connection_cb) {
        // Connection failed - no peer created, no ID allocated
        // Increment failure counter (no peer object exists, so remove_peer() won't be called)
        ++metrics_outbound_failures_;

        if (on_attempt) {
          on_attempt(addr);
        }
        // Mark as failed to back off in addrman
        if (discovery_manager_) {
          discovery_manager_->Failed(addr);
        }
        return;
      }

      // Connection succeeded - now create the peer and allocate ID
      auto peer = Peer::create_outbound(io_context_, connection_cb, network_magic, chain_height, address, port,
                                        effective_conn_type);
      if (!peer) {
        LOG_NET_ERROR("Failed to create peer for {}:{}", address, port);
        // No peer created; close the raw connection held by holder
        connection_cb->close();
        // Increment failure counter (no peer object exists, so remove_peer() won't be called)
        ++metrics_outbound_failures_;
        if (on_attempt) {
          on_attempt(addr);
        }
        return;
      }

      // Set local nonce
      peer->set_local_nonce(local_nonce);

      // Setup message handler
      if (setup_message_handler) {
        setup_message_handler(peer.get());
      }

      // Add to peer manager
      int peer_id = add_peer(peer, permissions, address);
      if (peer_id < 0) {
        LOG_NET_DEBUG("Failed to add outbound peer {} to manager (limit reached)", address);
        // Clean up transient peer to avoid destructor warning
        peer->disconnect();
        // Increment failure counter (peer was not added to manager, so remove_peer() won't be called)
        ++metrics_outbound_failures_;
        if (on_attempt) {
          on_attempt(addr);
        }
        return;
      }

      // Get peer and start it
      auto peer_ptr = get_peer(peer_id);
      if (peer_ptr) {
        LOG_NET_DEBUG("Connected to {}:{} (peer_id={})", address, port, peer_id);
        if (on_good) {
          on_good(addr);
        }
        peer_ptr->start();
      }
    });
  };

  auto connection = transport->connect(address, port, cb);
  *holder = connection;

  if (!connection) {
    if (is_manual) {
      LOG_NET_INFO("Failed to initiate connection to {}:{}", address, port);
    } else {
      LOG_NET_DEBUG("Failed to initiate connection to {}:{}", address, port);
    }
    // Remove pending and backoff (single-threaded, no lock needed)
    pending_outbound_.erase(AddressKey(addr));
    // Increment failure counter (connection failed immediately, callback won't be called)
    ++metrics_outbound_failures_;
    // Track attempt before marking as failed (addrman contract)
    if (on_attempt) {
      on_attempt(addr);
    }
    if (discovery_manager_) {
      discovery_manager_->Failed(addr);
    }
    return ConnectionResult::TransportFailed;
  }

  return ConnectionResult::Success;
}

void PeerLifecycleManager::HandleInboundConnection(TransportConnectionPtr connection, IsRunningCallback is_running,
                                                   SetupMessageHandlerCallback setup_handler, uint32_t network_magic,
                                                   int32_t current_height, uint64_t local_nonce,
                                                   NetPermissionFlags permissions) {
  if (!is_running() || !connection) {
    return;
  }

  // Get remote address for ban checking
  std::string remote_address = connection->remote_address();

  // Check if address is banned
  if (IsBanned(remote_address)) {
    LOG_NET_INFO("Rejected banned address: {}", remote_address);
    connection->close();
    return;
  }

  // Check if address is discouraged
  // Only reject discouraged peers if inbound slots are (almost) full
  // This allows discouraged peers a second chance if we have capacity
  bool is_discouraged = IsDiscouraged(remote_address);
  bool has_noban = HasPermission(permissions, NetPermissionFlags::NoBan);
  if (is_discouraged && !has_noban) {
    size_t current_inbound = inbound_count();
    if (current_inbound + 1 >= config_.max_inbound_peers) {
      LOG_NET_INFO("Rejected discouraged address {} (inbound slots almost full: {}/{})", remote_address,
                   current_inbound, config_.max_inbound_peers);
      connection->close();
      return;
    }
    // Accept discouraged peer but log it (will be prioritized for eviction)
    LOG_NET_DEBUG("Accepting discouraged peer {} (slots available: {}/{})", remote_address, current_inbound,
                  config_.max_inbound_peers);
  }

  // Check if we can accept more inbound connections (global limit)
  if (!can_accept_inbound()) {
    LOG_NET_TRACE("Rejecting inbound connection from {} (inbound limit reached)", remote_address);
    connection->close();
    return;
  }

  // Create inbound peer
  auto peer = Peer::create_inbound(io_context_, connection, network_magic, current_height);
  if (peer) {
    // Set local nonce (in test mode where process-wide nonce is not set)
    peer->set_local_nonce(local_nonce);

    // Setup message handler via callback
    setup_handler(peer.get());

    // Add to peer manager FIRST (sets peer ID)
    int peer_id = add_peer(peer, permissions);
    if (peer_id < 0) {
      LOG_NET_DEBUG("Failed to add inbound peer to manager (limit reached)");
      // Clean up the transient inbound peer to avoid destructor warning
      peer->disconnect();
      return;
    }

    // Retrieve peer and start it
    peer_states_.Read(peer_id, [](const PeerTrackingData& state) {
      if (state.peer) {
        state.peer->start();
      }
    });
  }
}

// === Protocol Message Handlers ===

bool PeerLifecycleManager::HandleVerack(PeerPtr peer) {
  // Verify peer is still connected
  if (!peer || !peer->is_connected()) {
    LOG_NET_TRACE("Ignoring VERACK from disconnected peer");
    return true;
  }

  // Sanity check: by this point, the peer must be successfully_connected()
  // (Peer::handle_verack() marks the peer as successfully connected before this is called)
  assert(peer->successfully_connected() && "VERACK routed before peer marked successfully connected");
  if (!peer->successfully_connected()) {
    return true;  // Defensive in release builds
  }

  // Mark address as good after handshake for outbound peers
  // Note: Feelers disconnect after VERSION (before VERACK) and are marked good in remove_peer
  // Note: Block-relay peers ARE included - not calling Good() would cause addresses to be
  // evicted from NEW table. Info-leak is mitigated by not calling Connected() instead.
  // This moves the address from NEW to TRIED table, confirming protocol compatibility
  if (!peer->is_inbound() && !peer->is_feeler() && discovery_manager_) {
    auto na = protocol::NetworkAddress::from_string(peer->address(), peer->port());
    if (!na.is_zero()) {
      discovery_manager_->Good(na);
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
    LOG_NET_DEBUG("Sent GETADDR to {}:{} to populate address manager", peer->address(), peer->port());

    // Notify PeerDiscoveryManager to boost ADDR rate limit bucket
    // This allows the peer to send up to 1000 addresses in response without being rate limited
    if (discovery_manager_) {
      discovery_manager_->NotifyGetAddrSent(peer->id());
    }
  }

  // Update connection success metrics for outbound/feeler peers
  // This is called after VERACK, so the connection is fully established
  if (!peer->is_inbound()) {
    if (peer->is_feeler()) {
      ++metrics_feeler_successes_;
    } else {
      ++metrics_outbound_successes_;
    }
  }

  return true;
}

}  // namespace network
}  // namespace unicity
