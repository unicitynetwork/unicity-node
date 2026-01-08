#pragma once

/*
 MisbehaviorManager — manages peer misbehavior tracking

 Purpose
 - Mark misbehaving peers for disconnection/discouragement
 - Track duplicate invalid headers and unconnecting header sequences
 - Respect NetPermissionFlags (NoBan peers are not disconnected)

 Key responsibilities
 1. Mark peers as misbehaving (instant discourage, no score accumulation)
 2. Respect NetPermissionFlags (NoBan peers tracked but not disconnected)
 3. Track unconnecting headers with threshold-based penalty
 4. Prevent duplicate reports for the same invalid header

 Architecture
 Extracted from PeerLifecycleManager to separate DoS protection logic.
 Operates on per-peer state (PeerTrackingData) owned by PeerLifecycleManager.
*/

#include "network/peer_tracking.hpp"
#include "util/threadsafe_containers.hpp"
#include "util/uint.hpp"

#include <string>

namespace unicity {
namespace network {

class MisbehaviorManager {
public:
  // Constructor. peer_states is reference to the peer states map (owned by PeerLifecycleManager).
  explicit MisbehaviorManager(util::ThreadSafeMap<int, PeerTrackingData>& peer_states);

  ~MisbehaviorManager() = default;

  // Non-copyable
  MisbehaviorManager(const MisbehaviorManager&) = delete;
  MisbehaviorManager& operator=(const MisbehaviorManager&) = delete;

  // Report invalid proof of work from peer.
  void ReportInvalidPoW(int peer_id);

  // Report oversized message from peer.
  void ReportOversizedMessage(int peer_id);

  // Report non-continuous headers sequence from peer.
  void ReportNonContinuousHeaders(int peer_id);

  // Report low-work / deep-fork headers. Used when peer sends headers that fork from too deep
  // in the chain (beyond nSuspiciousReorgDepth). Such headers have insufficient cumulative
  // work to ever become the active chain.
  void ReportLowWorkHeaders(int peer_id);

  // Report invalid header with reason describing why header is invalid.
  void ReportInvalidHeader(int peer_id, const std::string& reason);

  // Report too many orphan headers from peer.
  void ReportTooManyOrphans(int peer_id);

  // Report protocol message received before handshake completion (before VERACK).
  void ReportPreVerackMessage(int peer_id);

  // === Unconnecting Headers Tracking ===

  // Increment unconnecting headers counter. Applies penalty if threshold is exceeded.
  void IncrementUnconnectingHeaders(int peer_id);

  // Reset unconnecting headers counter (when progress is made).
  void ResetUnconnectingHeaders(int peer_id);

  // === Duplicate Invalid Header Tracking ===

  // Record that a peer sent a specific invalid header. Used to prevent double-penalizing the same header.
  void NoteInvalidHeaderHash(int peer_id, const uint256& hash);

  // Check if peer has already been penalized for this invalid header.
  // Returns true if peer has already sent this invalid header.
  bool HasInvalidHeaderHash(int peer_id, const uint256& hash) const;

  // === Query Methods (for testing/debugging) ===

  // Check if peer should be disconnected due to misbehavior.
  // Respects NoBan permission (always returns false for NoBan peers).
  // Returns true if peer should be disconnected.
  bool ShouldDisconnect(int peer_id) const;

  // Check if peer has been marked as misbehaving (ignores NoBan permission).
  // For testing - allows checking if NoBan peers misbehaved without disconnecting.
  // Returns true if peer has misbehaved.
  bool IsMisbehaving(int peer_id) const;

  // Get unconnecting headers count for a peer (for logging).
  // Returns number of unconnecting headers messages (0 if peer not found).
  int GetUnconnectingHeadersCount(int peer_id) const;

private:
  // Mark a peer as misbehaving (will be disconnected and discouraged).
  // Internal method - not exposed to external code.
  // Returns true if peer should be disconnected (false for NoBan peers).
  bool Misbehaving(int peer_id, const std::string& reason);

  // Reference to peer states (owned by PeerLifecycleManager)
  util::ThreadSafeMap<int, PeerTrackingData>& peer_states_;
};

}  // namespace network
}  // namespace unicity
