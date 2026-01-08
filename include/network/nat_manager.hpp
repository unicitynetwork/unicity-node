// Copyright (c) 2025 The Unicity Foundation
// NAT traversal manager using UPnP

#pragma once

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace unicity {
namespace network {

class NATManager {
public:
  NATManager();
  ~NATManager() noexcept;

  // Start NAT traversal (discovery + port mapping)
  // Returns true if a mapping was created, false otherwise
  bool Start(uint16_t internal_port);

  // Stop and cleanup port mappings
  void Stop(bool silent = false) noexcept;

  // Get discovered external IP (may be updated during refresh)
  std::string GetExternalIP() const;

  // Get mapped external port
  uint16_t GetExternalPort() const;

  // Check if port mapping is active
  bool IsPortMapped() const { return port_mapped_; }

private:
  void DiscoverUPnPDevice();
  bool MapPort(uint16_t internal_port);  // Uses cached device info
  void UnmapPort(bool silent = false);   // Uses cached device info
  void RefreshMapping();                 // Periodic refresh thread

  // Cached gateway/device state
  std::string control_url_;       // IGD control URL
  std::string igd_service_type_;  // IGD service type
  std::string lanaddr_;           // Local LAN address detected by UPnP

  // Mapping state
  std::string external_ip_;
  uint16_t internal_port_{0};
  uint16_t external_port_{0};

  std::atomic<bool> port_mapped_{false};
  std::atomic<bool> running_{false};

  std::thread refresh_thread_;
  std::condition_variable refresh_cv_;
  std::mutex refresh_mutex_;

  // Serializes Map/Unmap/Refresh operations and protects mapping state
  mutable std::mutex mapping_mutex_;
};

}  // namespace network
}  // namespace unicity
