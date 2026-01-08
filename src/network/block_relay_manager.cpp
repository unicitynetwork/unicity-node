// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "network/block_relay_manager.hpp"

#include "chain/chainstate_manager.hpp"
#include "network/header_sync_manager.hpp"
#include "network/peer_lifecycle_manager.hpp"
#include "network/protocol.hpp"
#include "util/logging.hpp"
#include "util/time.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>

namespace unicity {
namespace network {

BlockRelayManager::BlockRelayManager(validation::ChainstateManager& chainstate, PeerLifecycleManager& peer_mgr,
                                     HeaderSyncManager& header_sync)
    : chainstate_manager_(chainstate), peer_manager_(peer_mgr), header_sync_manager_(header_sync),
      inv_chunk_size_(protocol::MAX_INV_SIZE) {}

void BlockRelayManager::AnnounceTipToAllPeers() {
  // Periodic re-announcement to all connected peers
  // This is called from run_maintenance() every 30 seconds
  // Re-announce periodically to handle partition healing, but avoid storms during active header sync

  const chain::CBlockIndex* tip = chainstate_manager_.GetTip();
  if (!tip || tip->nHeight == 0) {
    return;  // No tip to announce
  }

  uint256 current_tip_hash = tip->GetBlockHash();

  LOG_NET_TRACE("Adding tip to all peers' announcement queues (height={}, hash={})", tip->nHeight,
                current_tip_hash.GetHex().substr(0, 16));

  // Time now (mocked unix seconds)
  const int64_t now_s = util::GetTime();
  // Re-announce interval (10 minutes)
  static constexpr int64_t REANNOUNCE_INTERVAL_SEC = 10LL * 60;  // 10 min
  // TTL semantics: we only update last_announce_time_s_ when we enqueue.
  // If the tip remains in the peer's queue, we do not refresh TTL here.
  // With 1s flushing this is harmless; if flush cadence lengthens, we may
  // re-enqueue after TTL even if a duplicate sat in-queue. This is acceptable
  // and keeps logic simple.

  // Add to all ready peers' announcement queues with per-peer deduplication + TTL
  auto all_peers = peer_manager_.get_all_peers();
  for (const auto& peer : all_peers) {
    if (peer && peer->is_connected() && peer->state() == PeerConnectionState::READY) {
      // Check per-peer TTL; suppress re-announce of same tip within TTL regardless of queue state
      // Use atomic getter to prevent race condition between hash and timestamp reads
      auto last_announcement = peer_manager_.GetLastAnnouncement(peer->id());
      bool same_tip = last_announcement && (last_announcement->first == current_tip_hash);
      bool within_ttl = same_tip && last_announcement->second > 0 &&
                        (now_s - last_announcement->second < REANNOUNCE_INTERVAL_SEC);

      if (same_tip && within_ttl) {
        // TTL suppression: do not refresh last_announce_time_s_ unless we enqueue
        // (suppression window stays fixed until a new enqueue occurs)
        continue;
      }

      // Add to queue with dedup check (simple std::find is fine for queue size 0-1)
      // TTL refresh policy: we refresh last_announce_time_s_ ONLY when we enqueue;
      // if already present, we leave timestamps unchanged to avoid extending TTL spuriously.
      peer_manager_.AddBlockForInvRelay(peer->id(), current_tip_hash);
      peer_manager_.SetLastAnnouncedBlock(peer->id(), current_tip_hash, now_s);
    }
  }
}

void BlockRelayManager::AnnounceTipToPeer(Peer* peer) {
  // Announce current tip to a single peer (called when peer becomes READY)

  if (!peer || !peer->is_connected() || peer->state() != PeerConnectionState::READY) {
    return;
  }

  const chain::CBlockIndex* tip = chainstate_manager_.GetTip();
  if (!tip || tip->nHeight == 0) {
    return;
  }

  uint256 current_tip_hash = tip->GetBlockHash();

  LOG_NET_TRACE("Adding tip to peer {} announcement queue (height={}, hash={})", peer->id(), tip->nHeight,
                current_tip_hash.GetHex().substr(0, 16));

  const int64_t now_s = util::GetTime();

  // Add to peer's announcement queue with dedup check
  // For per-peer READY event, ignore TTL and ensure the current tip is queued once.
  peer_manager_.AddBlockForInvRelay(peer->id(), current_tip_hash);
  peer_manager_.SetLastAnnouncedBlock(peer->id(), current_tip_hash, now_s);
}

void BlockRelayManager::FlushBlockAnnouncements() {
  // Flush pending block announcements from all peers' queues
  // This is called periodically (like Bitcoin's SendMessages loop)
  auto all_peers = peer_manager_.get_all_peers();

  for (const auto& peer : all_peers) {
    if (!peer || !peer->is_connected() || peer->state() != PeerConnectionState::READY) {
      continue;
    }

    // Get and clear this peer's pending blocks
    std::vector<uint256> blocks_to_announce = peer_manager_.MoveBlocksForInvRelay(peer->id());

    // Skip if no blocks to announce
    if (blocks_to_announce.empty()) {
      continue;
    }

    // Create and send INV message(s) with pending blocks
    // Chunked to inv_chunk_size_ to respect wire limits and avoid overlarge messages.
    const size_t total = blocks_to_announce.size();
    const size_t chunk = inv_chunk_size_;
    size_t sent_items = 0;
    size_t chunk_idx = 0;
    while (sent_items < total) {
      size_t end = std::min(total, sent_items + chunk);
      auto inv_msg = std::make_unique<message::InvMessage>();
      inv_msg->inventory.reserve(end - sent_items);
      for (size_t j = sent_items; j < end; ++j) {
        protocol::InventoryVector inv;
        inv.type = protocol::InventoryType::MSG_BLOCK;
        inv.hash = blocks_to_announce[j];
        inv_msg->inventory.push_back(inv);
      }
      ++chunk_idx;
      LOG_NET_TRACE("Flushing {} block announcement(s) to peer {} (chunk {}/{})", (end - sent_items), peer->id(),
                    chunk_idx, (total + chunk - 1) / chunk);
      peer->send_message(std::move(inv_msg));
      sent_items = end;
    }
  }
}

void BlockRelayManager::RelayBlock(const uint256& block_hash) {
  // Create INV message with the new block
  auto inv_msg = std::make_unique<message::InvMessage>();

  protocol::InventoryVector inv;
  inv.type = protocol::InventoryType::MSG_BLOCK;
  inv.hash = block_hash;

  inv_msg->inventory.push_back(inv);

  // Time now for TTL bookkeeping
  const int64_t now_s = util::GetTime();

  // Send to all connected peers
  // Policy: IBD checks are enforced by the caller (Application's BlockConnected subscription)
  // before invoking relay_block(). This function focuses on  deduplication
  auto all_peers = peer_manager_.get_all_peers();
  size_t ready_count = 0;
  for (const auto& peer : all_peers) {
    if (peer && peer->is_connected()) {
      if (peer->state() == PeerConnectionState::READY) {
        // Drop any pending duplicate of this block from the peer's INV queue before immediate relay
        peer_manager_.RemoveBlockForInvRelay(peer->id(), block_hash);

        // Clone the message for each peer
        auto msg_copy = std::make_unique<message::InvMessage>();
        msg_copy->inventory = inv_msg->inventory;
        peer->send_message(std::move(msg_copy));
        // Record last announcement (hash + time) so periodic reannounce TTL suppresses duplicates
        peer_manager_.SetLastAnnouncedBlock(peer->id(), block_hash, now_s);
        ready_count++;
      }
    }
  }

  LOG_NET_INFO("Relayed block {} to {} ready peers", block_hash.GetHex(), ready_count);
}

bool BlockRelayManager::HandleInvMessage(PeerPtr peer, message::InvMessage* msg) {
  if (!peer || !msg) {
    return false;
  }

  LOG_NET_DEBUG("Received INV with {} items from peer {}", msg->inventory.size(), peer->id());

  // Track whether we need to fetch headers and whether we found any new blocks.
  bool should_request_headers = false;
  bool found_new_block = false;

  // Process each inventory item
  for (const auto& inv : msg->inventory) {
    if (inv.type == protocol::InventoryType::MSG_BLOCK) {
      // Check if we already have this block
      const chain::CBlockIndex* pindex = chainstate_manager_.LookupBlockIndex(inv.hash);

      LOG_NET_DEBUG("got inv: block {}  {} peer={}", inv.hash.GetHex(), pindex ? "have" : "new", peer->id());

      if (pindex) {
        continue;
      }

      found_new_block = true;

      // Determine if we should request headers based on IBD status and sync peer
      const bool in_ibd = chainstate_manager_.IsInitialBlockDownload();
      if (in_ibd) {
        // During IBD, only request from our designated sync peer
        bool has_sync = header_sync_manager_.HasSyncPeer();
        uint64_t sync_id = header_sync_manager_.GetSyncPeerId();
        LOG_NET_TRACE("HandleInv: IBD mode, peer={}, has_sync={}, sync_id={}, peer_is_inbound={}", peer->id(), has_sync,
                      sync_id, peer->is_inbound());
        if (has_sync) {
          if (sync_id == static_cast<uint64_t>(peer->id())) {
            should_request_headers = true;
          } else {
            LOG_NET_TRACE("HandleInv: (IBD) peer {} is NOT sync peer (sync={}), ignoring INV", peer->id(), sync_id);
            // Ignore INV-driven requests from non-sync peers during IBD
          }
        } else {
          // No sync peer yet: adopt announcer as sync peer ONLY if outbound
          if (!peer->is_inbound()) {
            LOG_NET_TRACE("HandleInv: (IBD) adopting OUTBOUND peer={}", peer->id());
            header_sync_manager_.SetSyncPeer(peer->id());
            peer->set_sync_started(true);
            should_request_headers = true;
          } else {
            LOG_NET_TRACE("HandleInv: (IBD) ignoring INBOUND announcer peer={} for sync adoption", peer->id());
          }
        }
      } else {
        // Post-IBD: Request headers from any peer that announces a new block
        // we request from ALL peers that announce a block.
        should_request_headers = true;
        LOG_NET_TRACE("HandleInv: (post-IBD) requesting headers from peer={} for block {}", peer->id(),
                      inv.hash.GetHex());
      }

      // Once we've decided to request headers, no need to keep checking
      if (should_request_headers) {
        break;
      }
    }
  }

  // Send at most ONE GETHEADERS per INV message
  // Note: found_new_block is always true when should_request_headers is true
  if (should_request_headers) {
    header_sync_manager_.RequestHeadersFromPeer(peer);
  }

  return true;
}

}  // namespace network
}  // namespace unicity
