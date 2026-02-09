// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

/*
 MisbehaviorManager — manages peer misbehavior tracking

 Purpose
 - Mark misbehaving peers for disconnection/discouragement
 - Track duplicate invalid headers to prevent double-penalizing
 - Respect NetPermissionFlags (NoBan peers are not disconnected)

 Key responsibilities
 1. Mark peers as misbehaving (instant discourage, no score accumulation)
 2. Respect NetPermissionFlags (NoBan peers tracked but not disconnected)
 3. Prevent duplicate reports for the same invalid header

 Architecture
 Extracted from ConnectionManager to separate DoS protection logic.
 Operates on per-peer state (PeerTrackingData) owned by ConnectionManager.
*/

#include "network/peer.hpp"
#include "util/threadsafe_containers.hpp"
#include "util/uint.hpp"

#include <string>

namespace unicity {
namespace network {

class MisbehaviorManager {
public:
  // Constructor. peer_states is reference to the peer states map (owned by ConnectionManager).
  explicit MisbehaviorManager(util::ThreadSafeMap<int, PeerPtr>& peer_states);

  ~MisbehaviorManager() = default;

  // Non-copyable
  MisbehaviorManager(const MisbehaviorManager&) = delete;
  MisbehaviorManager& operator=(const MisbehaviorManager&) = delete;

  void ReportInvalidPoW(int peer_id);

  void ReportOversizedMessage(int peer_id);

  void ReportNonContinuousHeaders(int peer_id);

  void ReportLowWorkHeaders(int peer_id);

  void ReportInvalidHeader(int peer_id, const std::string& reason);

  void ReportPreVerackMessage(int peer_id);

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

private:
  // Mark a peer as misbehaving (will be disconnected and discouraged).
  // Internal method - not exposed to external code.
  // Returns true if peer should be disconnected (false for NoBan peers).
  bool Misbehaving(int peer_id, const std::string& reason);

  // Reference to peer states (owned by ConnectionManager)
  util::ThreadSafeMap<int, PeerPtr>& peer_states_;
};

}  // namespace network
}  // namespace unicity
