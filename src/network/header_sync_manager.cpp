// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "network/header_sync_manager.hpp"

#include "chain/block.hpp"
#include "chain/chainparams.hpp"
#include "chain/chainstate_manager.hpp"
#include "chain/validation.hpp"
#include "network/peer.hpp"
#include "network/connection_manager.hpp"
#include "network/peer_misbehavior.hpp"
#include "network/protocol.hpp"
#include "util/logging.hpp"
#include "util/time.hpp"

#include <cassert>
#include <chrono>
#include <cstring>

namespace {

// Helper to get peer address for logging (returns "unknown" if peer not found)
std::string GetPeerAddr(unicity::network::ConnectionManager& mgr, int peer_id) {
  auto peer = mgr.get_peer(peer_id);
  if (peer) {
    return peer->address() + ":" + std::to_string(peer->port());
  }
  return "unknown";
}

// Headers sync timeout constants
// Deadline = base + (per_header_ms * expected_headers) / 1000
// The deadline is set once when sync starts and NOT reset when headers arrive.
constexpr int64_t HEADERS_DOWNLOAD_TIMEOUT_BASE_SEC = 5 * 60;   // 5 minutes
constexpr int64_t HEADERS_DOWNLOAD_TIMEOUT_PER_HEADER_MS = 1;    // 1ms per expected header

// During IBD we accept small unsolicited HEADERS announcements from any peer,
// but gate larger batches to the designated sync peer. This bounds wasted processing on multiple peers.
constexpr size_t MAX_UNSOLICITED_ANNOUNCEMENT = 2;

}  // namespace

namespace unicity {
namespace network {

HeaderSyncManager::HeaderSyncManager(
    validation::ChainstateManager& chainstate,
    ConnectionManager& peer_mgr)
    : chainstate_manager_(chainstate),
      peer_manager_(peer_mgr) {}

int HeaderSyncManager::GetSyncPeerId() const {
  return sync_state_.sync_peer_id;
}

void HeaderSyncManager::SetSyncPeer(int peer_id) {
  // Thread-safety: Called only from io_context thread
  auto now = util::GetSteadyTime();

  // Invariant: at most one sync peer at a time (enforced by HasSyncPeer() check)
  sync_state_.sync_peer_id = peer_id;
  sync_state_.sync_start_time = now;

  // Calculate deadline using base + (per_header_ms * expected_headers) / 1000
  // expected_headers = seconds_behind / block_spacing
  const auto& consensus = chain::GlobalChainParams::Get().GetConsensus();
  const chain::CBlockIndex* best_header = chainstate_manager_.GetTip();

  int64_t seconds_behind = 0;
  if (best_header) {
    int64_t wall_now = util::GetTime();
    seconds_behind = wall_now - best_header->GetBlockTime();
    if (seconds_behind < 0) seconds_behind = 0;
  }

  int64_t expected_headers = seconds_behind / consensus.nPowTargetSpacing;
  int64_t extra_time_ms = expected_headers * HEADERS_DOWNLOAD_TIMEOUT_PER_HEADER_MS;
  auto extra_time = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::milliseconds(extra_time_ms));

  sync_state_.sync_deadline = now + std::chrono::seconds(HEADERS_DOWNLOAD_TIMEOUT_BASE_SEC) + extra_time;

  LOG_NET_DEBUG("sync peer {} selected, deadline in {}s (expected {} headers)",
                peer_id, HEADERS_DOWNLOAD_TIMEOUT_BASE_SEC + extra_time.count(), expected_headers);
}

void HeaderSyncManager::ClearSyncPeer() {
  // Clear current sync peer and allow re-selection on next maintenance.
  // NOTE: We do not clear peer->sync_started() here. That flag persists for the
  // lifetime of the connection to indicate "we've already attempted sync with this peer"
  // This prevents re-selecting the same peer that just gave us empty headers.
  sync_state_.sync_peer_id = NO_SYNC_PEER;
  sync_state_.sync_start_time = {};
  sync_state_.sync_deadline = {};
}

void HeaderSyncManager::OnPeerDisconnected(int peer_id) {
  // Decrement protected peer count if this peer was protected
  auto peer = peer_manager_.get_peer(peer_id);
  if (peer && peer->chain_sync_state().protect) {
    assert(protected_outbound_count_ > 0 && "underflow: protected peer without count");
    if (protected_outbound_count_ > 0) {
      --protected_outbound_count_;
    }
  }

  // If this was our sync peer, clear sync state to allow selection of a new sync peer.
  if (sync_state_.sync_peer_id == peer_id) {
    LOG_NET_DEBUG("sync peer {} disconnected, clearing sync state", peer_id);
    ClearSyncPeer();
  }
}

void HeaderSyncManager::ProcessTimers() {
  auto now = util::GetSteadyTime();
  const bool in_ibd = chainstate_manager_.IsInitialBlockDownload();

  // During IBD: deadline-based headers sync stall detection
  if (in_ibd) {
    int sync_id = sync_state_.sync_peer_id;
    if (sync_id != NO_SYNC_PEER) {
      // Deadline check: if past deadline, disconnect sync peer to allow reselection.
      if (sync_state_.sync_deadline != std::chrono::steady_clock::time_point{} &&
          now > sync_state_.sync_deadline) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - sync_state_.sync_start_time).count();
        LOG_NET_INFO("headers sync deadline exceeded after {}s with peer {}, disconnecting",
                     elapsed, sync_id);
        peer_manager_.remove_peer(sync_id);
        return;
      }
    }
  } else {
    // Post-IBD: check outbound peers for stale chains
    for (const auto& peer : peer_manager_.get_outbound_peers()) {
      ConsiderEviction(peer, now);
    }
  }
}

void HeaderSyncManager::CheckInitialSync() {
  // Select a sync peer if we don't have one. Called frequently from message processing loop.
  // The resulting GETHEADERS is harmless if already synced (peer replies with empty headers).
  //
  // During IBD: only sync from one peer (return early if we have a sync peer)
  // Post-IBD: sync from ALL new outbound peers 
  const bool in_ibd = chainstate_manager_.IsInitialBlockDownload();

  if (HasSyncPeer() && in_ibd) {
    return;
  }

  // Helper to try syncing from a peer
  // During IBD: sets sync peer and sends GETHEADERS
  // Post-IBD: just sends GETHEADERS without changing sync peer (peer already has one)
  auto try_sync_from_peer = [this, in_ibd](const PeerPtr& peer) -> bool {
    if (!peer)
      return false;
    if (peer->sync_started())
      return false;  // Already started with this peer
    if (peer->is_feeler())
      return false;  // Skip feelers - they auto-disconnect
    // Gate initial sync on completed handshake to avoid protocol violations
    if (!peer->successfully_connected())
      return false;  // Wait until VERACK

    LOG_NET_TRACE("CheckInitialSync: starting sync with peer {}", peer->id());

    // During IBD: set this peer as the designated sync peer
    // Post-IBD: don't change the sync peer, just request headers
    if (in_ibd) {
      SetSyncPeer(peer->id());
    }
    peer->set_sync_started(true);  

    // Send GETHEADERS to initiate sync
    RequestHeadersFromPeer(peer);
    return true;
  };

  // Prefer outbound peers for sync
  auto outbound_peers = peer_manager_.get_outbound_peers();
  for (const auto& peer : outbound_peers) {
    if (try_sync_from_peer(peer)) {
      if (in_ibd) {
        return;  // During IBD: only one sync peer
      }
      // Post-IBD: continue to sync from all new peers
    }
  }

  // Fallback to inbound peers if no outbound peers available
  if (outbound_peers.empty()) {
    auto inbound_peers = peer_manager_.get_inbound_peers();
    LOG_NET_TRACE("CheckInitialSync: trying {} inbound peers as fallback", inbound_peers.size());
    for (const auto& peer : inbound_peers) {
      if (try_sync_from_peer(peer)) {
        if (in_ibd) {
          return;  // During IBD: only one sync peer
        }
        // Post-IBD: continue to sync from all new peers
      }
    }
  }
}

void HeaderSyncManager::RequestHeadersFromPeer(
    PeerPtr peer,
    const chain::CBlockIndex* pindexLast) {
  if (!peer) {
    return;
  }

  // GETHEADERS throttling: Only send if enough time has elapsed since last request.
  auto now = util::GetSteadyTime();
  auto last_request = peer->last_getheaders_time();
  if (last_request != std::chrono::steady_clock::time_point{} &&
      (now - last_request) < std::chrono::seconds(HEADERS_RESPONSE_TIME_SEC)) {
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_request).count();
    LOG_NET_TRACE("throttling getheaders to peer={} ({}s since last request, need {}s)",
                  peer->id(), elapsed, HEADERS_RESPONSE_TIME_SEC);
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

  int start_height = peer->start_height();

  // Get height of first locator hash for logging
  int locator_height = -1;
  if (!msg->block_locator_hashes.empty()) {
    const chain::CBlockIndex* first_block = chainstate_manager_.LookupBlockIndex(msg->block_locator_hashes[0]);
    if (first_block) {
      locator_height = first_block->nHeight;
    }
  }

  // Log based on whether this is a continuation (pindexLast provided) or initial request
  if (pindexLast) {
    LOG_NET_DEBUG("more getheaders ({}) to end to peer={} (startheight:{})", locator_height, peer->id(), start_height);
  } else {
    LOG_NET_DEBUG("initial getheaders ({}) to peer={} (startheight:{})", locator_height, peer->id(), start_height);
  }

  // Record timestamp for throttling (before send to avoid race)
  peer->set_last_getheaders_time(now);

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
    int sync_id = GetSyncPeerId();
    if (!headers.empty() && headers.size() > MAX_UNSOLICITED_ANNOUNCEMENT &&
        (sync_id == NO_SYNC_PEER || peer_id != sync_id)) {
      LOG_NET_TRACE("ignoring unsolicited large headers batch from non-sync peer during IBD: peer={} size={}", peer_id,
                    headers.size());
      // Do not penalize; just ignore
      return true;
    }
  }

  // If the batch ends on our active chain, we trust it implicitly.
  // This prevents banning honest peers who re-send headers we already have (e.g., due to
  // network race conditions, stale locators, or reorgs).
  // This exemption applies ONLY to the active chain. Side chains must still prove
  // they exceed nMinimumChainWork to be processed, preventing low-work spam attacks.

  bool already_validated_work = false;
  if (!headers.empty()) {
    const chain::CBlockIndex* last_header_index = chainstate_manager_.LookupBlockIndex(headers.back().GetHash());
    if (last_header_index && chainstate_manager_.IsOnActiveChain(last_header_index)) {
      already_validated_work = true;
      LOG_NET_TRACE("peer {} sent {} headers ending on active chain (height={}), skipping low-work check",
                    peer_id, headers.size(), last_header_index->nHeight);
    }
  }

  LOG_NET_TRACE("processing {} headers from peer {}, already_validated_work={}", headers.size(), peer_id, already_validated_work);

  int current_sync_id = GetSyncPeerId();
  bool is_from_sync_peer = (current_sync_id != NO_SYNC_PEER && peer_id == current_sync_id);

  // Empty reply: peer has no more headers to offer from our locator.
  // No penalty for empty replies. Clear GETHEADERS throttle timestamp - this is a valid response.
  if (headers.empty()) {
    if (is_from_sync_peer) {
      LOG_NET_DEBUG("received headers (0) peer={} - sync peer has no new headers", peer_id);
    } else {
      LOG_NET_DEBUG("received headers (0) peer={} - peer fully synced", peer_id);
    }
    peer->clear_last_getheaders_time();
    return true;
  }

  // DoS Protection: Check headers message size limit
  if (headers.size() > protocol::MAX_HEADERS_SIZE) {
    LOG_NET_ERROR_RL("rejecting oversized headers message from peer {} (size={}, max={})", peer_id, headers.size(),
                     protocol::MAX_HEADERS_SIZE);
    peer_manager_.ReportOversizedMessage(peer_id);
    // Check if peer should be disconnected
    if (peer_manager_.ShouldDisconnect(peer_id)) {
      peer_manager_.remove_peer(peer_id);
      // OnPeerDisconnected will call ClearSyncPeer if needed
    }
    // Don't call ClearSyncPeer here - if peer stays connected, let sync continue
    return false;
  }

  LOG_NET_DEBUG("received headers ({}) peer={}", headers.size(), peer_id);

  // DoS Protection: Check if first header connects to known chain
  const uint256& first_prev = headers[0].hashPrevBlock;
  bool prev_exists = chainstate_manager_.LookupBlockIndex(first_prev) != nullptr;

  if (!prev_exists) {
    // Unconnecting headers: send GETHEADERS to try to fill the gap, no penalty, return
    uint256 first_hash = headers[0].GetHash();
    LOG_NET_DEBUG("received header {}: missing prev block {}, sending getheaders to fill gap, peer={}",
                  first_hash.ToString().substr(0, 16), first_prev.ToString().substr(0, 16), peer_id);
    RequestHeadersFromPeer(peer, nullptr);
    return false;  // return without processing unconnecting headers
  }

  // DoS Protection: Cheap PoW commitment check
  bool pow_ok = chainstate_manager_.CheckHeadersPoW(headers);
  if (!pow_ok) {
    LOG_NET_ERROR_RL("headers failed PoW commitment check from peer={} ({})", peer_id, GetPeerAddr(peer_manager_, peer_id));
    peer_manager_.ReportInvalidPoW(peer_id);
    if (peer_manager_.ShouldDisconnect(peer_id)) {
      peer_manager_.remove_peer(peer_id);
    }
    return false;
  }

  // DoS Protection: Check headers are continuous
  bool continuous_ok = validation::CheckHeadersAreContinuous(headers);
  if (!continuous_ok) {
    LOG_NET_ERROR_RL("non-continuous headers from peer={} ({})", peer_id, GetPeerAddr(peer_manager_, peer_id));
    peer_manager_.ReportNonContinuousHeaders(peer_id);
    if (peer_manager_.ShouldDisconnect(peer_id)) {
      peer_manager_.remove_peer(peer_id);
    }
    return false;
  }

  // Headers connect AND are continuous - clear GETHEADERS throttle timestamp
  // (prev_exists is guaranteed true here - we returned early at line 349 if false)
  peer->clear_last_getheaders_time();

  // DoS Protection: Work-threshold check for headers that connect to known chain
  // With single-batch IBD we can verify total work immediately.
  // Reject batches with insufficient work to prevent low-work header spam.
  if (prev_exists && !already_validated_work) {
    const auto& params = chainstate_manager_.GetParams();
    arith_uint256 min_work = UintToArith256(params.GetConsensus().nMinimumChainWork);
    if (min_work > 0) {
      const chain::CBlockIndex* pindexPrev = chainstate_manager_.LookupBlockIndex(first_prev);
      if (pindexPrev) {
        arith_uint256 batch_work = validation::CalculateHeadersWork(headers);
        arith_uint256 total_work = pindexPrev->nChainWork + batch_work;
        if (total_work < min_work) {
          LOG_NET_WARN_RL("rejecting low-work headers from peer {}: batch_work={}, total_work={}, min_work={}", peer_id,
                         batch_work.GetLow64(), total_work.GetLow64(), min_work.GetLow64());
          peer_manager_.ReportLowWorkHeaders(peer_id);
          if (peer_manager_.ShouldDisconnect(peer_id)) {
            peer_manager_.remove_peer(peer_id);
          }
          return false;
        }
      }
    }
  }

  // Store batch size
  last_batch_size_ = headers.size();

  // Capture tip before processing for "received new header with more work" check
  const chain::CBlockIndex* tip_before = chainstate_manager_.GetTip();

  // Track last successfully processed header for continuation requests
  const chain::CBlockIndex* pindexLast = nullptr;

  // Accept all headers into block index
  for (const auto& header : headers) {
    validation::ValidationState state;
    chain::CBlockIndex* pindex = chainstate_manager_.AcceptBlockHeader(header, state);

    if (!pindex) {
      const std::string& reason = state.GetRejectReason();

      // Note: "prev-blk-not-found" should not occur here because:
      // 1. We already checked that headers[0] connects (prev_exists check above)
      // 2. Headers are continuous (each links to the previous)
      // So all headers should connect. If we somehow get here, treat as invalid.

      // Duplicate header
      if (reason == "duplicate") {
        const chain::CBlockIndex* existing = chainstate_manager_.LookupBlockIndex(header.GetHash());
        LOG_NET_TRACE("duplicate header from peer {}: {} (existing={}, valid={}, already_validated_work={})", peer_id,
                      header.GetHash().ToString().substr(0, 16), existing ? "yes" : "no",
                      existing ? existing->IsValid() : false, already_validated_work);

        // - If headers end on active chain, these are re-requested headers we already have.
        //   Don't penalize - this is normal after chain reorgs or due to stale locators.
        if (already_validated_work) {
          LOG_NET_TRACE("duplicate header in already-validated batch, skipping penalty");
          continue;
        }
        // - If the duplicate refers to a valid-known header, it's benign; ignore.
        if (existing && existing->IsValid()) {
          LOG_NET_TRACE("duplicate header already known valid; ignoring without penalty");
          continue;
        }
        // Duplicate of known-invalid header - penalize once per unique hash
        const uint256 h = header.GetHash();
        if (peer_manager_.HasInvalidHeaderHash(peer_id, h)) {
          LOG_NET_TRACE("peer {} re-sent invalid header {}, ignoring duplicate penalty", peer_id,
                        h.ToString().substr(0, 16));
          continue;
        }
        LOG_NET_WARN_RL("peer {} sent duplicate of known-invalid header: {}", peer_id, h.ToString().substr(0, 16));
        peer_manager_.ReportInvalidHeader(peer_id, "duplicate-invalid");
        peer_manager_.NoteInvalidHeaderHash(peer_id, h);
        if (peer_manager_.ShouldDisconnect(peer_id)) {
          peer_manager_.remove_peer(peer_id);
        }
        return false;
      }

      // All other rejections are invalid headers - penalize once per unique hash
      const uint256 h = header.GetHash();
      if (peer_manager_.HasInvalidHeaderHash(peer_id, h)) {
        LOG_NET_TRACE("peer {} re-sent previously invalid header {}, ignoring duplicate penalty", peer_id,
                      h.ToString().substr(0, 16));
        continue;
      }
      LOG_NET_ERROR_RL("peer={} ({}) sent invalid header: {} (debug: {})", peer_id, GetPeerAddr(peer_manager_, peer_id),
                       reason, state.GetDebugMessage());
      peer_manager_.ReportInvalidHeader(peer_id, reason);
      peer_manager_.NoteInvalidHeaderHash(peer_id, h);
      if (peer_manager_.ShouldDisconnect(peer_id)) {
        peer_manager_.remove_peer(peer_id);
      }
      return false;
    }

    // Add to candidate set for batch activation
    chainstate_manager_.TryAddBlockIndexCandidate(pindex);

    // Track last successfully processed header
    pindexLast = pindex;

    // Log new header with peer info
    // INFO outside IBD (notable event), DEBUG during IBD (high volume)
    if (!in_ibd) {
      LOG_NET_INFO("saw new header hash={} height={} peer={}", pindex->GetBlockHash().ToString(), pindex->nHeight,
                   peer_id);
    } else {
      LOG_NET_DEBUG("saw new header hash={} height={} peer={}", pindex->GetBlockHash().ToString(), pindex->nHeight,
                    peer_id);
    }
  }

  // Activate best chain ONCE for the entire batch
  LOG_NET_TRACE("calling ActivateBestChain for batch of {} headers", headers.size());
  bool activate_result = chainstate_manager_.ActivateBestChain(nullptr);
  LOG_NET_TRACE("ActivateBestChain returned {}", activate_result ? "true" : "FALSE");
  if (!activate_result) {
    // ActivateBestChain can fail for internal reasons (e.g., disk space, etc.)
    // Don't disconnect, don't clear sync peer - failure is transient.
    // Sync peer remains, next headers message will be processed normally.
    LOG_NET_DEBUG("ActivateBestChain returned false (transient failure), peer={}", peer_id);
    return false;
  }

  // Track header relay for eviction protection (peers that do useful work).
  // Only update if we received a NEW header (pindexLast != nullptr means AcceptBlockHeader
  // succeeded for at least one header) AND it has more work than our tip before processing.
  bool received_new_header = (pindexLast != nullptr);
  bool has_more_work = tip_before && pindexLast && pindexLast->nChainWork > tip_before->nChainWork;
  if (received_new_header && has_more_work) {
    peer_manager_.UpdateLastHeadersReceived(peer_id);

    // Extra block-relay peer rotation (OUTBOUND ONLY)
    // Contrast with EvictionManager, which handles INBOUND slot exhaustion.
    //
    // Only evict when we have EXTRA block-relay peers (above target). The extra peer is
    // a temporary connection made to verify our tip. Once it proves useful (or doesn't),
    // we evict it to return to our target count.
    //
    // Logic: Find the two peers with highest IDs among block-relay peers
    // (higher peer ID is used as a proxy for most recent connection).
    // Evict whichever of those two has the older last_headers_received time.
    // This keeps peers that are actively providing headers.
    if (peer_manager_.GetExtraBlockRelayCount() > 0) {
      // Find youngest and second-youngest by peer ID (higher ID = more recent connection)
      int youngest_id = -1, second_youngest_id = -1;
      auto youngest_time = std::chrono::steady_clock::time_point{};
      auto second_youngest_time = std::chrono::steady_clock::time_point{};

      for (const auto& p : peer_manager_.get_all_peers()) {
        if (p && p->is_block_relay_only() && !p->is_inbound() && p->successfully_connected()) {
          if (p->id() > youngest_id) {
            second_youngest_id = youngest_id;
            second_youngest_time = youngest_time;
            youngest_id = p->id();
            youngest_time = p->last_headers_received();
          } else if (p->id() > second_youngest_id) {
            second_youngest_id = p->id();
            second_youngest_time = p->last_headers_received();
          }
        }
      }

      // Evict whichever of the two youngest has older last_headers_received
      if (youngest_id != -1 && second_youngest_id != -1) {
        int to_evict = youngest_id;
        if (youngest_time > second_youngest_time) {
          // Youngest peer has more recent headers - evict second youngest instead
          to_evict = second_youngest_id;
        }
        // If we would evict the sender, evict the other candidate instead.
        // This handles the edge case where the youngest peer has the oldest headers
        // timestamp but is also the peer that just sent us useful headers.
        if (to_evict == peer_id) {
          to_evict = (to_evict == youngest_id) ? second_youngest_id : youngest_id;
        }
        LOG_NET_DEBUG("evicting extra block-relay peer {} (youngest={}, second_youngest={})",
                      to_evict, youngest_id, second_youngest_id);
        peer_manager_.remove_peer(to_evict);
      }
    }
  }

  // Update peer's best known block info (for chain sync timeout and stale chain eviction)
  if (pindexLast) {
    peer->set_best_known_block_height(pindexLast->nHeight);
    peer->set_best_known_chain_work(pindexLast->nChainWork);
  }

  // During IBD, disconnect outbound peers with insufficient chain work.
  // If this was a non-full batch, the peer has no more headers - this is their tip.
  // NoBan peers are exempt (admin explicitly trusts this peer).
  bool may_have_more_headers = (last_batch_size_ == continuation_threshold_);
  if (in_ibd && !may_have_more_headers && pindexLast && !peer->is_inbound() &&
      !HasPermission(peer->permissions(), NetPermissionFlags::NoBan)) {
    const auto& params = chainstate_manager_.GetParams();
    arith_uint256 min_work = UintToArith256(params.GetConsensus().nMinimumChainWork);
    if (min_work > 0 && pindexLast->nChainWork < min_work) {
      LOG_NET_INFO("disconnecting outbound peer {} - chain has insufficient work", peer_id);
      peer_manager_.remove_peer(peer_id);
      return true;
    }
  }

  // Protect up to MAX_PROTECTED_OUTBOUND_PEERS full-relay outbound peers that have proven useful.
  // Block-relay-only peers are excluded from protection  - they should
  // remain subject to eviction under the bad/lagging chain logic for eclipse attack resistance.
  const chain::CBlockIndex* our_tip = chainstate_manager_.GetTip();
  if (peer->is_full_relay() && !peer->chain_sync_state().protect && our_tip) {
    if (pindexLast && pindexLast->nHeight >= our_tip->nHeight &&
        protected_outbound_count_ < MAX_PROTECTED_OUTBOUND_PEERS) {
      peer->chain_sync_state().protect = true;
      ++protected_outbound_count_;
      LOG_NET_DEBUG("protecting outbound peer {} from eviction (height={})", peer_id, pindexLast->nHeight);
    }
  }

  // Show progress during IBD or new block notification
  if (in_ibd) {
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
  // Use pindexLast for the locator so we continue from where peer left off.
  // Only continue if pindexLast is beyond our pre-processing tip height.
  // This prevents infinite loops when a peer re-sends headers we already have.
  bool should_continue = last_batch_size_ == continuation_threshold_ &&
                         pindexLast && tip_before &&
                         pindexLast->nHeight > tip_before->nHeight;
  if (should_continue) {
    int sync_id = GetSyncPeerId();
    bool is_sync_peer = (sync_id != NO_SYNC_PEER && peer_id == sync_id);

    if (in_ibd) {
      // During IBD: only continue with designated sync peer
      if (is_sync_peer) {
        RequestHeadersFromPeer(peer, pindexLast);
      } else {
        LOG_NET_DEBUG("not requesting more headers from non-sync peer {} during IBD", peer_id);
      }
    } else {
      // Post-IBD: continue with any peer
      RequestHeadersFromPeer(peer, pindexLast);
    }
  }

  return true;
}

bool HeaderSyncManager::HandleGetHeadersMessage(
    PeerPtr peer,
    message::GetHeadersMessage* msg) {
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
    LOG_NET_DEBUG("ignoring getheaders from peer={} because active chain has too little work; sending empty response",
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
  // NOTE: If hash_stop refers to a block on a fork (not active chain), we won't
  // find it since we only iterate the active chain. This is intentional - we only
  // serve active chain headers. The peer will receive up to MAX_HEADERS_SIZE headers.
  uint256 stop_hash;
  std::memcpy(stop_hash.data(), msg->hash_stop.data(), 32);
  bool has_stop = !stop_hash.IsNull();

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

  // Check if tip is recent
  int64_t now = util::GetTime();
  int64_t tip_age = std::max<int64_t>(0, now - tip->nTime);
  return tip_age < max_age_seconds;
}

void HeaderSyncManager::ConsiderEviction(
    PeerPtr peer,
    std::chrono::steady_clock::time_point now) {
  // Check if outbound peer should be evicted for stale chain
  if (!peer) return;

  auto& state = peer->chain_sync_state();

  // Only check unprotected outbound peers that have started sync
  if (state.protect) return;
  if (peer->is_inbound()) return;
  if (HasPermission(peer->permissions(), NetPermissionFlags::NoBan)) return;
  if (!peer->sync_started()) return;

  const chain::CBlockIndex* our_tip = chainstate_manager_.GetTip();
  if (!our_tip) return;

  int peer_best_height = peer->best_known_block_height();
  const arith_uint256& peer_best_work = peer->best_known_chain_work();

  // Peer has caught up? Use chain WORK, not height, to prevent low-work spam attacks.
  // An attacker could send a long low-work chain (high height, low work) to bypass
  // stall detection if we only checked height.
  if (peer_best_work >= our_tip->nChainWork) {
    // Clear timeout - peer is caught up (verified by work, not just height)
    if (state.timeout != std::chrono::steady_clock::time_point{}) {
      state.timeout = {};
      state.work_header_height = -1;
      state.sent_getheaders = false;
    }
    return;
  }

  // Peer is behind - manage timeout
  // Note: work_header_height uses height as a benchmark for "progress" since we're
  // comparing against our own chain (not trusting peer's claims).
  if (state.timeout == std::chrono::steady_clock::time_point{} ||
      (state.work_header_height >= 0 && peer_best_height >= state.work_header_height)) {
    // Set new timeout (first time noticing peer is behind, or peer caught up to old benchmark but not current tip)
    state.timeout = now + std::chrono::seconds(CHAIN_SYNC_TIMEOUT_SEC);
    state.work_header_height = our_tip->nHeight;
    state.sent_getheaders = false;
  } else if (state.timeout != std::chrono::steady_clock::time_point{} && now > state.timeout) {
    // Timeout expired
    if (state.sent_getheaders) {
      // Already gave them a chance - disconnect
      LOG_NET_INFO("disconnecting stale outbound peer {} (best_height={}, our_tip={})",
                   peer->id(), peer_best_height, our_tip->nHeight);
      peer_manager_.remove_peer(peer->id());
    } else {
      // Send GETHEADERS to give peer a chance to prove they have blocks.
      // Use locator from work_header's parent so peer can send the benchmark block.
      const chain::CBlockIndex* work_header_parent = nullptr;
      if (state.work_header_height > 0) {
        work_header_parent = chainstate_manager_.GetBlockAtHeight(state.work_header_height - 1);
      }
      LOG_NET_DEBUG("sending getheaders to verify chain work for peer {} (best_height={}, benchmark={})",
                    peer->id(), peer_best_height, state.work_header_height);
      RequestHeadersFromPeer(peer, work_header_parent);
      state.sent_getheaders = true;
      // Shorter timeout for response
      state.timeout = now + std::chrono::seconds(HEADERS_RESPONSE_TIME_SEC);
    }
  }
}

}  // namespace network
}  // namespace unicity
