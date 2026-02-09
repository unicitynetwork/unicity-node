// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

/*
 * HeaderSyncManager — headers-only synchronization coordinator
 *
 * Functionality:
 * - Headers-only network: HEADERS payloads contain only fixed-size headers
 *   (no per-header txcount like Bitcoin Core). GETHEADERS/HEADERS is the only sync path.
 * - Single sync peer at a time; selection is outbound-only.
 * - During IBD, accept large batches only from the designated sync peer; allow small
 *   unsolicited announcements (≤2 headers) from any peer. Post-IBD, unsolicited gating is
 *   relaxed but batch processing remains identical.
 * - Simplified DoS protection: Headers are accepted if they have valid PoW.
 * - DoS-check skip heuristic: if the batch's last header is already on the ACTIVE chain, we
 *   skip duplicate-header penalties to avoid false positives after local invalidations.
 *   Side chains do NOT qualify.
 * - Stall detection: deadline-based timeout. If headers sync doesn't complete by the
 *   deadline, the sync peer is disconnected and another is selected.
 */

#include "chain/block.hpp"
#include "network/message.hpp"
#include "network/peer.hpp"
#include "network/protocol.hpp"

#include <chrono>
#include <cstdint>
#include <memory>

namespace unicity {

// Forward declaration for test access
namespace test {
class HeaderSyncManagerTestAccess;
}  // namespace test

// Forward declarations
namespace chain {
class CBlockIndex;
}

namespace validation {
class ChainstateManager;
}

namespace network {

// Forward declarations
class ConnectionManager;

// HeaderSyncManager - Manages header synchronization
class HeaderSyncManager {
public:
  static constexpr int NO_SYNC_PEER = -1;
  HeaderSyncManager(
      validation::ChainstateManager& chainstate,
      ConnectionManager& peer_mgr);

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
  static constexpr int64_t DEFAULT_SYNC_AGE_LIMIT_SEC = 3600;
  bool IsSynced(int64_t max_age_seconds = DEFAULT_SYNC_AGE_LIMIT_SEC) const;

  // Sync tracking
  int GetSyncPeerId() const;
  bool HasSyncPeer() const { return GetSyncPeerId() != NO_SYNC_PEER; }
  void SetSyncPeer(int peer_id);
  void ClearSyncPeer();

  // Peer lifecycle handler (called by ConnectionManager)
  void OnPeerDisconnected(int peer_id);

private:
  friend class test::HeaderSyncManagerTestAccess;

  // Component references
  validation::ChainstateManager& chainstate_manager_;
  ConnectionManager& peer_manager_;

  // Chain sync timeout constants 
  static constexpr int64_t CHAIN_SYNC_TIMEOUT_SEC = 20 * 60;   // 20 minutes
  static constexpr int64_t HEADERS_RESPONSE_TIME_SEC = 2 * 60; // 2 minutes
  static constexpr int MAX_PROTECTED_OUTBOUND_PEERS = 4;

  // Sync state (single-threaded: accessed only from io_context thread)
  struct SyncState {
    int sync_peer_id = NO_SYNC_PEER;  // NO_SYNC_PEER (-1) = no sync peer
    std::chrono::steady_clock::time_point sync_start_time{};   // When sync started (monotonic)
    std::chrono::steady_clock::time_point sync_deadline{};     // Deadline for completing headers sync
  };

  SyncState sync_state_{};

  // Header batch tracking (io_context thread only)
  size_t last_batch_size_{0};  // Size of last headers batch received

  // Continuation threshold (defaults to MAX_HEADERS_SIZE, can be overridden for testing)
  size_t continuation_threshold_{protocol::MAX_HEADERS_SIZE};

  // Work-based peer protection counter
  int protected_outbound_count_{0};

  // Check if outbound peer should be evicted for stale chain (called from ProcessTimers)
  void ConsiderEviction(PeerPtr peer, std::chrono::steady_clock::time_point now);
};

}  // namespace network
}  // namespace unicity
