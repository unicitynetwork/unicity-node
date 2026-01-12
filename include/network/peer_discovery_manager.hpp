#pragma once

/*
 Peer DiscoveryManager — peer discovery coordinator 

 Purpose
 - Own and coordinate AddressManager (peer address database) and AnchorManager (eclipse resistance)
 - Handle peer discovery protocol messages (ADDR/GETADDR)
 - Provide unified interface for address management and anchor persistence
 - Consolidate discovery-related components under one manager

 Key responsibilities
 1. Own AddressManager and AnchorManager
 2. Handle ADDR/GETADDR protocol messages
 3. Implement echo suppression (don't send addresses back to source)
 4. Provide forwarding methods for address operations
 5. Provide forwarding methods for anchor operations
*/

#include "network/connection_types.hpp"
#include "network/message.hpp"
#include "network/peer.hpp"
#include "network/peer_tracking.hpp"
#include "network/protocol.hpp"

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <vector>

namespace unicity {

// Forward declarations for chain types
namespace chain {
class ChainParams;
}

namespace network {

// Forward declarations
class AddressManager;
class AnchorManager;
class PeerLifecycleManager;

// Peer discovery coordinator - owns AddressManager and AnchorManager
class PeerDiscoveryManager {
public:
  explicit PeerDiscoveryManager(PeerLifecycleManager* peer_manager, const std::string& datadir = "");
  ~PeerDiscoveryManager();

  // Non-copyable
  PeerDiscoveryManager(const PeerDiscoveryManager&) = delete;
  PeerDiscoveryManager& operator=(const PeerDiscoveryManager&) = delete;

  // Lifecycle
  using ConnectToAnchorsCallback = std::function<void(const std::vector<protocol::NetworkAddress>&)>;

  // Load anchors and bootstrap from fixed seeds if needed
  void Start(ConnectToAnchorsCallback connect_anchors);

  // === Protocol Message Handlers ===

  bool HandleAddr(PeerPtr peer, message::AddrMessage* msg);
  bool HandleGetAddr(PeerPtr peer);

  // Boost peer's ADDR rate limit bucket after we send GETADDR
  void NotifyGetAddrSent(int peer_id);

  // === Peer Lifecycle Callbacks (called by PeerLifecycleManager) ===

  void OnPeerConnected(int peer_id, const std::string& address, uint16_t port, ConnectionType connection_type);
  void OnPeerDisconnected(int peer_id, const std::string& address, uint16_t port, bool mark_addr_good);

  // === AddressManager Forwarding Methods ===

  void Attempt(const protocol::NetworkAddress& addr);
  void Good(const protocol::NetworkAddress& addr);
  void Failed(const protocol::NetworkAddress& addr);
  std::optional<protocol::NetworkAddress> Select();
  std::optional<protocol::NetworkAddress> SelectNewForFeeler();
  void CleanupStale();

  size_t Size() const;
  size_t TriedCount() const;
  size_t NewCount() const;

  // Add a peer address directly to AddrMan (for testing/RPC)
  bool AddPeerAddress(const std::string& address, uint16_t port);

  bool SaveAddresses(const std::string& filepath);
  bool LoadAddresses(const std::string& filepath);

  // === AnchorManager Forwarding Methods ===

  std::vector<protocol::NetworkAddress> GetAnchors() const;
  bool SaveAnchors(const std::string& filepath);
  std::vector<protocol::NetworkAddress> LoadAnchors(const std::string& filepath);

  // === Test/Diagnostic Methods ===

  struct GetAddrDebugStats {
    uint64_t total{0};
    uint64_t served{0};
    uint64_t ignored_outbound{0};
    uint64_t ignored_prehandshake{0};
    uint64_t ignored_repeat{0};
    size_t last_from_addrman{0};
    size_t last_suppressed{0};
  };
  GetAddrDebugStats GetGetAddrDebugStats() const;

  void TestSeedRng(uint64_t seed);
  AddressManager& addr_manager_for_test() { return *addr_manager_; }
  AnchorManager& anchor_manager_for_test() { return *anchor_manager_; }

private:
  std::string datadir_;
  PeerLifecycleManager* peer_manager_;
  std::unique_ptr<AddressManager> addr_manager_;
  std::unique_ptr<AnchorManager> anchor_manager_;

  static constexpr int64_t ECHO_SUPPRESS_TTL_SEC = 600;
  static constexpr size_t MAX_LEARNED_PER_PEER = 2000;
  static constexpr double EVICTION_TRIGGER_RATIO = 1.1;
  static constexpr double EVICTION_TARGET_RATIO = 0.9;

  // ADDR trickle delay constants 
  static constexpr int64_t ADDR_TRICKLE_MEAN_MS = 5000;  // Mean delay before relay (Poisson)

  std::atomic<uint64_t> stats_getaddr_total_{0};
  std::atomic<uint64_t> stats_getaddr_served_{0};
  std::atomic<uint64_t> stats_getaddr_ignored_outbound_{0};
  std::atomic<uint64_t> stats_getaddr_ignored_prehandshake_{0};
  std::atomic<uint64_t> stats_getaddr_ignored_repeat_{0};
  std::atomic<size_t> last_resp_from_addrman_{0};
  std::atomic<size_t> last_resp_suppressed_{0};

  std::mt19937 rng_;

  struct AddrRateLimitState {
    double token_bucket{1.0};
    std::chrono::steady_clock::time_point last_update{};
    uint64_t addr_processed{0};
    uint64_t addr_rate_limited{0};
  };
  std::unordered_map<int, AddrRateLimitState> addr_rate_limit_;
  static constexpr double MAX_ADDR_RATE_PER_SECOND = 0.1;
  static constexpr double MAX_ADDR_PROCESSING_TOKEN_BUCKET = protocol::MAX_ADDR_SIZE;

  void BootstrapFromFixedSeeds(const chain::ChainParams& params);

  // Pending ADDR relay queue 
  struct PendingAddrRelay {
    std::chrono::steady_clock::time_point send_time;
    int target_peer_id;
    std::vector<protocol::TimestampedAddress> addresses;
  };
  std::vector<PendingAddrRelay> pending_addr_relays_;

public:
  // Process pending ADDR relays (called periodically from NetworkManager)
  void ProcessPendingAddrRelays();

  // Test-only: get pending relay queue size
  size_t PendingAddrRelayCountForTest() const { return pending_addr_relays_.size(); }
};

}  // namespace network
}  // namespace unicity
