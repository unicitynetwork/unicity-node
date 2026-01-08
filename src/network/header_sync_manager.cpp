// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "network/header_sync_manager.hpp"

#include "chain/block.hpp"
#include "chain/chainparams.hpp"
#include "chain/chainstate_manager.hpp"
#include "chain/validation.hpp"
#include "network/block_relay_manager.hpp"
#include "network/peer.hpp"
#include "network/peer_lifecycle_manager.hpp"
#include "network/peer_misbehavior.hpp"
#include "network/protocol.hpp"
#include "util/logging.hpp"
#include "util/time.hpp"

#include <chrono>
#include <cmath>
#include <cstring>

// File-scoped constants for HeaderSync behavior and time conversions
namespace {
// Time conversion: microseconds per second. We store sync timestamps in microseconds.
static constexpr int64_t kMicrosPerSecond = 1'000'000;

// Headers sync stall timeout (microseconds). If no headers are received from the sync peer within
// this window, we disconnect it to allow reselection.
static constexpr int64_t kHeadersSyncTimeoutUs = 120 * kMicrosPerSecond;  // 120 seconds

// During IBD we accept small unsolicited HEADERS announcements (e.g., INV-triggered) from any peer,
// but gate larger batches to the designated sync peer. This bounds wasted processing on multiple peers.
static constexpr size_t kMaxUnsolicitedAnnouncement = 2;
}  // namespace

namespace unicity {
namespace network {

HeaderSyncManager::HeaderSyncManager(validation::ChainstateManager& chainstate, PeerLifecycleManager& peer_mgr)
    : chainstate_manager_(chainstate), peer_manager_(peer_mgr) {
  // PeerLifecycleManager will call OnPeerDisconnected directly
}

uint64_t HeaderSyncManager::GetSyncPeerId() const {
  return sync_state_.sync_peer_id;
}

void HeaderSyncManager::SetSyncPeer(uint64_t peer_id) {
  // Thread-safety: Called only from io_context thread
  int64_t now_us = util::GetTime() * kMicrosPerSecond;
  // Invariant: at most one sync peer at a time (enforced by HasSyncPeer() check)
  sync_state_.sync_peer_id = peer_id;
  sync_state_.sync_start_time_us = now_us;
  sync_state_.last_headers_received_us = now_us;
}

void HeaderSyncManager::ClearSyncPeer() {
  // Thread-safety: Called only from io_context thread (single-threaded networking)
  // Clear current sync peer and allow re-selection on next maintenance.
  // NOTE: We do NOT clear peer->sync_started() here. That flag persists for the
  // lifetime of the connection to indicate "we've already attempted sync with this peer"
  // This prevents re-selecting the same peer that just gave us empty headers.
  sync_state_.sync_peer_id = NO_SYNC_PEER;
  sync_state_.sync_start_time_us = 0;
}

void HeaderSyncManager::OnPeerDisconnected(uint64_t peer_id) {
  // If this was our sync peer, reset sync state to allow retry with another peer
  if (sync_state_.sync_peer_id == peer_id) {
    LOG_NET_DEBUG("Sync peer {} disconnected, clearing sync state", peer_id);
    ClearSyncPeer();

    // Reset sync_started on all remaining outbound peers to allow retry after stall.
    // This ensures that if the sync peer failed/stalled, we can select another peer
    // even if it was previously attempted.
    auto outbound_peers = peer_manager_.get_outbound_peers();
    for (const auto& peer : outbound_peers) {
      if (peer && peer->sync_started()) {
        LOG_NET_TRACE("Resetting sync_started for peer {} to allow retry", peer->id());
        peer->set_sync_started(false);
      }
    }
  }
}

void HeaderSyncManager::ProcessTimers() {
  // Basic headers sync stall detection
  // If initial sync is running and we haven't received headers for a while,
  // disconnect the sync peer to allow retrying another peer.
  uint64_t sync_id = sync_state_.sync_peer_id;
  int64_t last_us = sync_state_.last_headers_received_us;

  if (sync_id == NO_SYNC_PEER)
    return;

  // Use mockable wall-clock time for determinism in tests
  const int64_t now_us = util::GetTime() * kMicrosPerSecond;

  // Stall handling: if our designated sync peer hasn't delivered HEADERS within the timeout,
  // disconnect it and allow reselection. This avoids getting stuck forever on a slow or unresponsive
  // peer. We don't trigger reselection inline; the normal SendMessages/maintenance loop handles it,
  // keeping control flow simple and testable.
  //
  // IMPORTANT: Only enforce stall timeout during IBD. Post-IBD, the node is already synced;
  // timeout enforcement would incorrectly disconnect peers during normal operation.
  if (last_us > 0 && (now_us - last_us) > kHeadersSyncTimeoutUs && chainstate_manager_.IsInitialBlockDownload()) {
    LOG_NET_INFO("Headers sync stalled for {:.1f}s with peer {}, disconnecting",
                 static_cast<double>(now_us - last_us) / static_cast<double>(kMicrosPerSecond), sync_id);
    // Ask ConnectionManager to drop the peer. This triggers OnPeerDisconnected() via callback
    peer_manager_.remove_peer(static_cast<int>(sync_id));
    // Do NOT call CheckInitialSync() here; SendMessages/maintenance cadence will do reselection.
  }
}

void HeaderSyncManager::CheckInitialSync() {
  // Select a sync peer if we don't have one. Called periodically from maintenance.
  // The resulting GETHEADERS is harmless if already synced (peer replies with empty headers).
  if (HasSyncPeer()) {
    return;
  }

  LOG_NET_TRACE("CheckInitialSync: selecting new sync peer");

  // Outbound-only sync peer selection
  auto outbound_peers = peer_manager_.get_outbound_peers();
  LOG_NET_TRACE("CheckInitialSync: found {} outbound peers", outbound_peers.size());
  for (const auto& peer : outbound_peers) {
    if (!peer)
      continue;
    LOG_NET_TRACE("CheckInitialSync: checking peer {}, sync_started={}", peer->id(), peer->sync_started());
    if (peer->sync_started()) {
      continue;  // Already started with this peer
    }
    if (peer->is_feeler())
      continue;  // Skip feelers - they auto-disconnect
    // Gate initial sync on completed handshake to avoid protocol violations
    if (!peer->successfully_connected())
      continue;  // Wait until VERACK

    SetSyncPeer(peer->id());
    peer->set_sync_started(true);  // CNodeState::fSyncStarted

    // Send GETHEADERS to initiate sync
    RequestHeadersFromPeer(peer);
    return;  // Only one sync peer
  }
}

void HeaderSyncManager::RequestHeadersFromPeer(PeerPtr peer, const chain::CBlockIndex* pindexLast) {
  if (!peer) {
    return;
  }

  // Build block locator from pindexLast (continuation) or current tip (initial request).
  // For continuation requests after receiving headers, pindexLast points to the last
  // header we processed, ensuring GETHEADERS walks the chain we just received.
  // For initial requests, we use our active tip.
  CBlockLocator locator = pindexLast ? chainstate_manager_.GetLocator(pindexLast) : chainstate_manager_.GetLocator();

  // Create GETHEADERS message
  auto msg = std::make_unique<message::GetHeadersMessage>();
  msg->version = protocol::PROTOCOL_VERSION;

  // Copy locator hashes directly (both are uint256)
  msg->block_locator_hashes = locator.vHave;

  // hash_stop is all zeros (get as many as possible)
  msg->hash_stop.SetNull();

  bool is_initial = !peer->sync_started();
  int start_height = peer->start_height();

  if (is_initial) {
    LOG_NET_DEBUG("initial getheaders ({}) to peer={} (startheight:{})", msg->block_locator_hashes.size(), peer->id(),
                  start_height);
  } else {
    LOG_NET_DEBUG("more getheaders ({}) to end to peer={} (startheight:{})", msg->block_locator_hashes.size(),
                  peer->id(), start_height);
  }

  LOG_NET_TRACE("requesting headers from peer={} (locator size: {})", peer->id(), msg->block_locator_hashes.size());

  peer->send_message(std::move(msg));
}

bool HeaderSyncManager::HandleHeadersMessage(PeerPtr peer, message::HeadersMessage* msg) {
  if (!peer || !msg) {
    return false;
  }

  // Reject protocol messages before handshake completion
  if (!peer->successfully_connected()) {
    peer_manager_.ReportPreVerackMessage(peer->id());
    return false;
  }

  const auto& headers = msg->headers;
  int peer_id = peer->id();

  // Snapshot IBD state once for this handler invocation
  const bool in_ibd = chainstate_manager_.IsInitialBlockDownload();

  // During IBD, only process large (batch) headers from the
  // designated sync peer. Allow small unsolicited announcements (1-2 headers)
  // from any peer.
  if (in_ibd) {
    uint64_t sync_id = GetSyncPeerId();
    if (!headers.empty() && headers.size() > kMaxUnsolicitedAnnouncement &&
        (sync_id == NO_SYNC_PEER || static_cast<uint64_t>(peer_id) != sync_id)) {
      LOG_NET_TRACE("Ignoring unsolicited large headers batch from non-sync peer during IBD: peer={} size={}", peer_id,
                    headers.size());
      // Do not penalize; just ignore
      return true;
    }
  }

  // Skip duplicate-header penalties if batch ends on our active chain.
  // Avoids false positives after invalidateblock RPC re-requests known headers.
  // Active chain only (not side chains) prevents attacker exploitation.
  bool skip_dos_checks = false;
  if (!headers.empty()) {
    const chain::CBlockIndex* last_header_index = chainstate_manager_.LookupBlockIndex(headers.back().GetHash());
    if (last_header_index && chainstate_manager_.IsOnActiveChain(last_header_index)) {
      skip_dos_checks = true;
      LOG_NET_TRACE("Peer {} sent {} headers, last header on active chain (log2_work={:.6f}), skipping DoS checks",
                    peer_id, headers.size(), std::log(last_header_index->nChainWork.getdouble()) / std::log(2.0));
    }
  }

  LOG_NET_TRACE("Processing {} headers from peer {}, skip_dos_checks={}", headers.size(), peer_id, skip_dos_checks);

  // NOTE: Timestamp update moved to AFTER validation to prevent
  // low-work headers from resetting the timeout and enabling infinite loops.
  uint64_t current_sync_id = GetSyncPeerId();
  bool is_from_sync_peer = (current_sync_id != NO_SYNC_PEER && static_cast<uint64_t>(peer_id) == current_sync_id);

  // Empty reply: peer has no more headers to offer from our locator.
  // Keep the sync peer - we're now synced with them and they can announce new blocks.
  // No penalty for empty replies.
  if (headers.empty()) {
    LOG_NET_DEBUG("received headers (0) peer={} - keeping as sync peer", peer_id);
    return true;
  }

  // DoS Protection: Check headers message size limit
  if (headers.size() > protocol::MAX_HEADERS_SIZE) {
    LOG_NET_ERROR_RL("Rejecting oversized headers message from peer {} (size={}, max={})", peer_id, headers.size(),
                     protocol::MAX_HEADERS_SIZE);
    peer_manager_.ReportOversizedMessage(peer_id);
    // Check if peer should be disconnected
    if (peer_manager_.ShouldDisconnect(peer_id)) {
      peer_manager_.remove_peer(peer_id);
    }
    ClearSyncPeer();
    return false;
  }

  LOG_NET_DEBUG("received headers ({}) peer={}", headers.size(), peer_id);

  // DoS Protection: Check if first header connects to known chain
  const uint256& first_prev = headers[0].hashPrevBlock;
  bool prev_exists = chainstate_manager_.LookupBlockIndex(first_prev) != nullptr;

  if (!prev_exists) {
    uint256 first_hash = headers[0].GetHash();

    // Reject full unconnecting batches: can't verify chainwork without parent,
    // exceeds orphan limit (50), likely DoS or divergent chain.
    // Partial batches (< 2000) allowed - handled as orphans below.
    if (headers.size() == protocol::MAX_HEADERS_SIZE) {
      LOG_NET_WARN_RL("Rejecting full batch ({} headers) that doesn't connect to known chain from peer={} (first "
                      "header: {}, missing parent: {})",
                      headers.size(), peer_id, first_hash.ToString().substr(0, 16),
                      first_prev.ToString().substr(0, 16));
      peer_manager_.IncrementUnconnectingHeaders(peer_id);
      if (peer_manager_.ShouldDisconnect(peer_id)) {
        peer_manager_.remove_peer(peer_id);
      }
      ClearSyncPeer();
      return false;
    }

    // Small unconnecting batch: normal for block announcements or out-of-order delivery.
    // Track count for DoS protection, but continue processing as orphans.
    int unconnecting_count = peer_manager_.GetUnconnectingHeadersCount(peer_id);
    LOG_NET_DEBUG("small unconnecting batch ({} headers) from peer={}, caching as orphans (count={})", headers.size(),
                  peer_id, unconnecting_count + 1);
    peer_manager_.IncrementUnconnectingHeaders(peer_id);
    if (peer_manager_.ShouldDisconnect(peer_id)) {
      peer_manager_.remove_peer(peer_id);
    }
    // Continue processing - don't clear sync peer or return
  }

  // DoS Protection: Cheap PoW commitment check
  bool pow_ok = chainstate_manager_.CheckHeadersPoW(headers);
  if (!pow_ok) {
    LOG_NET_ERROR_RL("headers failed PoW commitment check from peer={}", peer_id);
    peer_manager_.ReportInvalidPoW(peer_id);
    if (peer_manager_.ShouldDisconnect(peer_id)) {
      peer_manager_.remove_peer(peer_id);
    }
    ClearSyncPeer();
    return false;
  }

  // DoS Protection: Check headers are continuous
  // IMPORTANT: Check continuity BEFORE resetting unconnecting counter to prevent
  // attackers from gaming the system by alternating between unconnecting batches
  // and batches that connect but have internal gaps.
  bool continuous_ok = validation::CheckHeadersAreContinuous(headers);
  if (!continuous_ok) {
    LOG_NET_ERROR_RL("non-continuous headers from peer={}", peer_id);
    peer_manager_.ReportNonContinuousHeaders(peer_id);
    if (peer_manager_.ShouldDisconnect(peer_id)) {
      peer_manager_.remove_peer(peer_id);
    }
    ClearSyncPeer();
    return false;
  }

  // Headers connect AND are continuous - reset unconnecting counter
  if (prev_exists) {
    int old_count = peer_manager_.GetUnconnectingHeadersCount(peer_id);
    if (old_count > 0) {
      LOG_NET_DEBUG("peer={}: resetting m_num_unconnecting_headers_msgs ({} -> 0)", peer_id, old_count);
    }
    peer_manager_.ResetUnconnectingHeaders(peer_id);
  }


  // DoS Protection: Work-threshold check for headers that connect to known chain
  // With single-batch IBD we can verify total work immediately.
  // Reject batches with insufficient work to prevent low-work header spam.
  if (prev_exists && !skip_dos_checks) {
    const auto& params = chainstate_manager_.GetParams();
    arith_uint256 min_work = UintToArith256(params.GetConsensus().nMinimumChainWork);
    if (min_work > 0) {
      const chain::CBlockIndex* pindexPrev = chainstate_manager_.LookupBlockIndex(first_prev);
      if (pindexPrev) {
        arith_uint256 batch_work = validation::CalculateHeadersWork(headers);
        arith_uint256 total_work = pindexPrev->nChainWork + batch_work;
        if (total_work < min_work) {
          LOG_NET_WARN_RL("Rejecting low-work headers from peer {}: batch_work={}, total_work={}, min_work={}", peer_id,
                         batch_work.GetLow64(), total_work.GetLow64(), min_work.GetLow64());
          peer_manager_.ReportLowWorkHeaders(peer_id);
          if (peer_manager_.ShouldDisconnect(peer_id)) {
            peer_manager_.remove_peer(peer_id);
          }
          ClearSyncPeer();
          return false;
        }
      }
    }
  }

  // Store batch size
  last_batch_size_ = headers.size();

  // Track last successfully processed header for continuation requests
  const chain::CBlockIndex* pindexLast = nullptr;

  // Accept all headers into block index
  for (const auto& header : headers) {
    validation::ValidationState state;
    chain::CBlockIndex* pindex = chainstate_manager_.AcceptBlockHeader(header, state);

    if (!pindex) {
      const std::string& reason = state.GetRejectReason();

      // Missing parent: cache as orphan (network-layer decision)
      if (reason == "prev-blk-not-found") {
        if (chainstate_manager_.AddOrphanHeader(header, peer_id)) {
          LOG_NET_TRACE("header from peer={} cached as orphan: {}", peer_id, header.GetHash().ToString().substr(0, 16));
          continue;
        } else {
          LOG_NET_TRACE("peer={} exceeded orphan limit while caching prev-missing header", peer_id);
          peer_manager_.ReportTooManyOrphans(peer_id);
          if (peer_manager_.ShouldDisconnect(peer_id)) {
            peer_manager_.remove_peer(peer_id);
          }
          ClearSyncPeer();
          return false;
        }
      }

      // Duplicate header
      if (reason == "duplicate") {
        const chain::CBlockIndex* existing = chainstate_manager_.LookupBlockIndex(header.GetHash());
        LOG_NET_TRACE("Duplicate header from peer {}: {} (existing={}, valid={}, skip_dos_checks={})", peer_id,
                      header.GetHash().ToString().substr(0, 16), existing ? "yes" : "no",
                      existing ? existing->IsValid() : false, skip_dos_checks);

        // - If we're skipping DoS checks (ancestor on active chain), do not penalize duplicates.
        if (skip_dos_checks) {
          LOG_NET_TRACE("Skipping DoS check for duplicate header (batch contains ancestors)");
          continue;
        }
        // - If the duplicate refers to a valid-known header, it's benign; ignore.
        if (existing && existing->IsValid()) {
          LOG_NET_TRACE("Duplicate header already known valid; ignoring without penalty");
          continue;
        }
        // Duplicate of known-invalid header - penalize once per unique hash
        const uint256 h = header.GetHash();
        if (peer_manager_.HasInvalidHeaderHash(peer_id, h)) {
          LOG_NET_TRACE("peer {} re-sent invalid header {}, ignoring duplicate penalty", peer_id,
                        h.ToString().substr(0, 16));
          continue;
        }
        LOG_NET_WARN_RL("Peer {} sent duplicate of KNOWN-INVALID header: {}", peer_id, h.ToString().substr(0, 16));
        peer_manager_.ReportInvalidHeader(peer_id, "duplicate-invalid");
        peer_manager_.NoteInvalidHeaderHash(peer_id, h);
        if (peer_manager_.ShouldDisconnect(peer_id)) {
          peer_manager_.remove_peer(peer_id);
        }
        ClearSyncPeer();
        return false;
      }

      // All other rejections are invalid headers - penalize once per unique hash
      const uint256 h = header.GetHash();
      if (peer_manager_.HasInvalidHeaderHash(peer_id, h)) {
        LOG_NET_TRACE("peer {} re-sent previously invalid header {}, ignoring duplicate penalty", peer_id,
                      h.ToString().substr(0, 16));
        continue;
      }
      LOG_NET_ERROR_RL("peer={} sent invalid header: {} (debug: {})", peer_id, reason, state.GetDebugMessage());
      peer_manager_.ReportInvalidHeader(peer_id, reason);
      peer_manager_.NoteInvalidHeaderHash(peer_id, h);
      if (peer_manager_.ShouldDisconnect(peer_id)) {
        peer_manager_.remove_peer(peer_id);
      }
      ClearSyncPeer();
      return false;
    }

    // Add to candidate set for batch activation
    chainstate_manager_.TryAddBlockIndexCandidate(pindex);

    // Track last successfully processed header
    pindexLast = pindex;
  }

  // Activate best chain ONCE for the entire batch
  LOG_NET_TRACE("calling ActivateBestChain for batch of {} headers", headers.size());
  bool activate_result = chainstate_manager_.ActivateBestChain(nullptr);
  LOG_NET_TRACE("ActivateBestChain returned {}", activate_result ? "true" : "FALSE");
  if (!activate_result) {
    // DoS Protection: Don't reset timeout for full batches that fail activation.
    // Full batches of low-work headers would otherwise reset the timeout indefinitely.
    // Partial batches (< MAX_HEADERS_SIZE) DO reset timeout - peer exhausted their chain.
    if (headers.size() < protocol::MAX_HEADERS_SIZE) {
      if (is_from_sync_peer || !in_ibd) {
        sync_state_.last_headers_received_us = util::GetTime() * kMicrosPerSecond;
        LOG_NET_TRACE("Updated timestamp for partial batch that failed activation (peer exhausted)");
      }
    }
    LOG_NET_DEBUG("failed to activate chain (ActivateBestChain returned false)");
    ClearSyncPeer();
    return false;
  }

  // Success: Update timestamp (allows timeout to reset for productive peers)
  if (is_from_sync_peer || !in_ibd) {
    sync_state_.last_headers_received_us = util::GetTime() * kMicrosPerSecond;
  }

  // Track header relay for eviction protection (peers that do useful work)
  // This is the key defense against eclipse attacks - attackers can't fake relaying valid headers
  peer_manager_.UpdateLastHeadersReceived(peer_id);

  // Show progress during IBD or new block notification
  if (chainstate_manager_.IsInitialBlockDownload()) {
    const chain::CBlockIndex* tip = chainstate_manager_.GetTip();
    if (tip) {
      LOG_NET_TRACE("synchronizing block headers, height: {}", tip->nHeight);
    }
  } else {
    const chain::CBlockIndex* tip = chainstate_manager_.GetTip();
    if (tip) {
      LOG_NET_TRACE("new block header: height={} hash={}...", tip->nHeight,
                    tip->GetBlockHash().ToString().substr(0, 16));
    }
  }

  // Full batch indicates peer has more - request continuation.
  // Use pindexLast for the locator so we continue from where peer left off,
  if (last_batch_size_ == protocol::MAX_HEADERS_SIZE) {
    uint64_t sync_id = GetSyncPeerId();
    bool is_sync_peer = (sync_id != NO_SYNC_PEER && static_cast<uint64_t>(peer_id) == sync_id);

    if (in_ibd) {
      // During IBD: only continue with designated sync peer
      if (is_sync_peer) {
        RequestHeadersFromPeer(peer, pindexLast);
      } else {
        LOG_NET_DEBUG("Not requesting more headers from non-sync peer {} during IBD", peer_id);
      }
    } else {
      // Post-IBD: continue with any peer
      RequestHeadersFromPeer(peer, pindexLast);
    }
  }

  return true;
}

bool HeaderSyncManager::HandleGetHeadersMessage(PeerPtr peer, message::GetHeadersMessage* msg) {
  if (!peer || !msg) {
    return false;
  }

  // Reject protocol messages before handshake completion
  if (!peer->successfully_connected()) {
    peer_manager_.ReportPreVerackMessage(peer->id());
    return false;
  }

  int peer_id = peer->id();

  LOG_NET_TRACE("peer={} requested headers (locator size: {})", peer_id, msg->block_locator_hashes.size());

  const chain::CBlockIndex* active_tip = chainstate_manager_.GetTip();

  NetPermissionFlags permissions = peer_manager_.GetPeerPermissions(peer_id);
  if ((!active_tip ||
       (active_tip->nChainWork < UintToArith256(chainstate_manager_.GetParams().GetConsensus().nMinimumChainWork))) &&
      !HasPermission(permissions, NetPermissionFlags::Download)) {
    LOG_NET_DEBUG("Ignoring getheaders from peer={} because active chain has too little work; sending empty response",
                  peer_id);

    // Send empty HEADERS response to indicate we're aware but can't help
    auto response = std::make_unique<message::HeadersMessage>();
    peer->send_message(std::move(response));
    return true;
  }

  // Find the fork point using the block locator
  // Only consider blocks on the ACTIVE chain, not side chains
  const chain::CBlockIndex* fork_point = nullptr;
  for (const auto& hash_array : msg->block_locator_hashes) {
    // Convert std::array<uint8_t, 32> to uint256
    uint256 hash;
    std::memcpy(hash.data(), hash_array.data(), 32);

    const chain::CBlockIndex* pindex = chainstate_manager_.LookupBlockIndex(hash);
    if (chainstate_manager_.IsOnActiveChain(pindex)) {
      // Found a block that exists AND is on our active chain
      fork_point = pindex;
      LOG_NET_TRACE("found fork point at height {} (hash={}) on active chain", fork_point->nHeight,
                    hash.ToString().substr(0, 16));
      break;
    }
  }

  // In practice, fork_point should never be null because genesis is hardcoded
  // and should always be in the locator. If it is null (peer on different network),
  // we send an empty headers message.
  if (!fork_point) {
    LOG_NET_TRACE("no common blocks in locator from peer={} - sending empty headers", peer->id());
    auto response = std::make_unique<message::HeadersMessage>();
    peer->send_message(std::move(response));
    return true;
  }

  const chain::CBlockIndex* tip = chainstate_manager_.GetTip();
  LOG_NET_TRACE("preparing headers: fork_point height={} tip height={}", fork_point->nHeight, tip ? tip->nHeight : -1);

  // Build HEADERS response
  auto response = std::make_unique<message::HeadersMessage>();

  // Start from the block after fork point and collect headers
  const chain::CBlockIndex* pindex = chainstate_manager_.GetBlockAtHeight(fork_point->nHeight + 1);

  // Respect hash_stop (0 = no limit)
  uint256 stop_hash;
  bool has_stop = false;
  {
    // Convert std::array<uint8_t, 32> to uint256
    std::memcpy(stop_hash.data(), msg->hash_stop.data(), 32);
    has_stop = !stop_hash.IsNull();
  }

  while (pindex && response->headers.size() < protocol::MAX_HEADERS_SIZE) {
    CBlockHeader hdr = pindex->GetBlockHeader();
    response->headers.push_back(hdr);

    // If caller requested a stop-hash, include it and then stop
    if (has_stop && pindex->GetBlockHash() == stop_hash) {
      break;
    }

    if (pindex == tip) {
      break;
    }

    // Get next block in active chain
    pindex = chainstate_manager_.GetBlockAtHeight(pindex->nHeight + 1);
  }

  LOG_NET_TRACE("sending headers ({}) peer={}", response->headers.size(), peer->id());

  peer->send_message(std::move(response));
  return true;
}

bool HeaderSyncManager::IsSynced(int64_t max_age_seconds) const {
  const chain::CBlockIndex* tip = chainstate_manager_.GetTip();
  if (!tip) {
    return false;
  }

  // Check if tip is recent (use util::GetTime() to support mock time in tests)
  int64_t now = util::GetTime();
  int64_t tip_age = now - tip->nTime;

  return tip_age < max_age_seconds;
}

}  // namespace network
}  // namespace unicity
