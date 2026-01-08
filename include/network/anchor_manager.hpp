#pragma once

#include "network/protocol.hpp"

#include <string>
#include <vector>

namespace unicity {
namespace network {

// Forward declarations
class PeerLifecycleManager;

/**
 * AnchorManager - Manages anchor peer persistence for eclipse attack resistance
 *
 * Responsibilities:
 * - Select high-quality anchor peers from current connections
 * - Save anchor peers to disk for restart recovery
 * - Load anchor addresses from disk (passive - returns addresses, doesn't initiate connections)
 *
 * Design: AnchorManager is passive - it manages address selection and persistence,
 * but NetworkManager is responsible for initiating connections to anchor addresses.
 */
class AnchorManager {
public:
  explicit AnchorManager(PeerLifecycleManager& peer_mgr);

  // Get current anchor peers from connected outbound peers.
  // Selects up to 2 high-quality outbound peers based on connection age and ping time.
  std::vector<protocol::NetworkAddress> GetAnchors() const;

  // Save current anchors to file.
  // Atomically writes anchor addresses to disk for recovery after restart.
  bool SaveAnchors(const std::string& filepath);

  // Load anchor addresses from file. Returns list of anchor addresses for NetworkManager
  // to connect to. Deletes the anchors file after reading
  // Returns empty vector if file not found or invalid.
  std::vector<protocol::NetworkAddress> LoadAnchors(const std::string& filepath);

private:
  PeerLifecycleManager& peer_manager_;
};

}  // namespace network
}  // namespace unicity
