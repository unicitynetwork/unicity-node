#pragma once

/*
 * HeaderSyncManager — headers-only synchronization coordinator
 *
 * Functionality:
 * - Headers-only network: HEADERS payloads contain only fixed-size 100-byte headers
 *   (no per-header txcount like Bitcoin Core). GETHEADERS/HEADERS is the only sync path.
 * - Single sync peer at a time; selection is outbound-only.
 * - During IBD, accept large batches only from the designated sync peer; allow small
 *   unsolicited announcements (≤2 headers) from any peer. Post-IBD, unsolicited gating is
 *   relaxed but batch processing remains identical.
 * - Simplified DoS protection: Headers are accepted if they have valid PoW.
 * - DoS-check skip heuristic: if the batch's last header is already on the ACTIVE chain, we
 *   skip duplicate-header penalties to avoid false positives after local invalidations.
 *   Side chains do NOT qualify.
 * - Stall detection: a fixed 120s timeout disconnects an unresponsive sync peer; reselection
 *   occurs via the regular SendMessages/maintenance cadence (simpler than Core’s dynamic timers).
 */

#include "chain/block.hpp"
#include "network/message.hpp"
#include "network/peer.hpp"

#include <cstdint>
#include <limits>
#include <memory>

namespace unicity {

// Forward declarations
namespace chain {
class CBlockIndex;
}

namespace validation {
class ChainstateManager;
}

namespace network {

// Forward declarations
class PeerLifecycleManager;
class BlockRelayManager;


// HeaderSyncManager - Manages blockchain header synchronization
class HeaderSyncManager {
public:
  static constexpr uint64_t NO_SYNC_PEER = std::numeric_limits<uint64_t>::max();
  HeaderSyncManager(validation::ChainstateManager& chainstate, PeerLifecycleManager& peer_mgr);

  // Non-copyable
  HeaderSyncManager(const HeaderSyncManager&) = delete;
  HeaderSyncManager& operator=(const HeaderSyncManager&) = delete;

  // Non-movable (reference members prevent safe moving)
  HeaderSyncManager(HeaderSyncManager&&) = delete;
  HeaderSyncManager& operator=(HeaderSyncManager&&) = delete;

  // Message handlers. peer and msg must not be null. Returns true if handled successfully, false on error.
  bool HandleHeadersMessage(PeerPtr peer, message::HeadersMessage* msg);
  bool HandleGetHeadersMessage(PeerPtr peer, message::GetHeadersMessage* msg);

  // Request headers from peer. If pindexLast is provided, builds locator from that block index
  // (continuation request). If nullptr, builds locator from current active tip (initial request).
  void RequestHeadersFromPeer(PeerPtr peer, const chain::CBlockIndex* pindexLast = nullptr);
  void CheckInitialSync();

  // Periodic maintenance (timeouts, retries)
  void ProcessTimers();

  // State queries
  bool IsSynced(int64_t max_age_seconds = 3600) const;

  // Sync tracking
  uint64_t GetSyncPeerId() const;
  bool HasSyncPeer() const { return GetSyncPeerId() != NO_SYNC_PEER; }
  void SetSyncPeer(uint64_t peer_id);
  void ClearSyncPeer();

  // Peer lifecycle handler (called by PeerLifecycleManager)
  void OnPeerDisconnected(uint64_t peer_id);

private:
  // Component references
  validation::ChainstateManager& chainstate_manager_;
  PeerLifecycleManager& peer_manager_;

  // Sync state (single-threaded: accessed only from io_context thread)
  struct SyncState {
    uint64_t sync_peer_id = NO_SYNC_PEER;  // NO_SYNC_PEER = no sync peer
    int64_t sync_start_time_us = 0;        // When sync started (microseconds since epoch)
    int64_t last_headers_received_us = 0;  // Last time we received headers (microseconds)
  };

  SyncState sync_state_{};

  // Header batch tracking (io_context thread only)
  size_t last_batch_size_{0};  // Size of last headers batch received
};

}  // namespace network
}  // namespace unicity
