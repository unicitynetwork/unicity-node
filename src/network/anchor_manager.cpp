// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "network/anchor_manager.hpp"

#include "network/peer.hpp"
#include "network/peer_lifecycle_manager.hpp"
#include "util/files.hpp"
#include "util/logging.hpp"
#include "util/time.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <limits>
#include <random>

#include <asio.hpp>
#include <nlohmann/json.hpp>

namespace unicity {
namespace network {

AnchorManager::AnchorManager(PeerLifecycleManager& peer_mgr) : peer_manager_(peer_mgr) {}

std::vector<protocol::NetworkAddress> AnchorManager::GetAnchors() const {
  std::vector<protocol::NetworkAddress> anchors;

  // Get all outbound peers
  auto outbound_peers = peer_manager_.get_outbound_peers();

  struct Candidate {
    PeerPtr peer;
    protocol::NetworkAddress addr;
    int64_t age_s{0};
    int64_t ping_ms{std::numeric_limits<int64_t>::max()};
  };

  std::vector<Candidate> candidates;
  const auto now = util::GetSteadyTime();

  for (const auto& peer : outbound_peers) {
    if (!peer)
      continue;
    if (!peer->is_connected() || peer->state() != PeerConnectionState::READY)
      continue;
    if (peer->is_feeler())
      continue;  // never anchor a feeler

    // Block-relay connections are invisible to the network (no ADDR relay),
    // making them harder to eclipse. If an attacker eclipses all full-relay
    // connections, anchors provide a hidden path for receiving blocks.
    if (!peer->is_block_relay_only())
      continue;

    // Use centralized NetworkAddress::from_string() for IP conversion
    std::string ip_str = peer->address();
    protocol::NetworkAddress addr = protocol::NetworkAddress::from_string(ip_str, peer->port(), peer->services());

    // Check if conversion failed (from_string returns zeroed IP on error)
    bool is_zero = std::all_of(addr.ip.begin(), addr.ip.end(), [](uint8_t b) { return b == 0; });
    if (is_zero) {
      LOG_NET_WARN("Failed to parse IP address '{}'", ip_str);
      continue;
    }

    try {
      Candidate c;
      c.peer = peer;
      c.addr = addr;
      // Load atomic durations
      auto connected_time = peer->stats().connected_time.load(std::memory_order_relaxed);
      auto connected_tp = std::chrono::steady_clock::time_point(connected_time);
      auto age = std::chrono::duration_cast<std::chrono::seconds>(now - connected_tp).count();
      c.age_s = std::max<int64_t>(0, age);
      auto ping_ms_val = peer->stats().ping_time_ms.load(std::memory_order_relaxed);
      c.ping_ms = (ping_ms_val.count() >= 0) ? ping_ms_val.count() : std::numeric_limits<int64_t>::max();
      candidates.push_back(std::move(c));
    } catch (const std::exception& e) {
      LOG_NET_WARN("Exception parsing IP address '{}': {}", ip_str, e.what());
      continue;
    }
  }

  if (candidates.empty()) {
    LOG_NET_INFO("Selected 0 anchor peers");
    return anchors;
  }

  // Randomize then favor older connections and lower ping
  std::mt19937 rng{std::random_device{}()};
  std::shuffle(candidates.begin(), candidates.end(), rng);
  std::sort(candidates.begin(), candidates.end(), [](const Candidate& a, const Candidate& b) {
    if (a.age_s != b.age_s)
      return a.age_s > b.age_s;    // older first
    return a.ping_ms < b.ping_ms;  // lower ping first
  });

  // Take top 2
  const size_t MAX_ANCHORS = 2;
  const size_t count = std::min(candidates.size(), MAX_ANCHORS);
  for (size_t i = 0; i < count; ++i) {
    anchors.push_back(candidates[i].addr);
  }

  LOG_NET_INFO("Selected {} anchor peers", anchors.size());
  return anchors;
}

bool AnchorManager::SaveAnchors(const std::string& filepath) {
  using json = nlohmann::json;

  try {
    auto anchors = GetAnchors();

    if (anchors.empty()) {
      LOG_NET_DEBUG("No anchors to save");
      return true;  // Not an error
    }

    LOG_NET_INFO("Saving {} anchor addresses to {}", anchors.size(), filepath);

    json root;
    root["version"] = 1;
    root["count"] = anchors.size();

    json anchors_array = json::array();
    for (const auto& addr : anchors) {
      json anchor;
      anchor["ip"] = json::array();
      for (size_t i = 0; i < 16; ++i) {
        anchor["ip"].push_back(addr.ip[i]);
      }
      anchor["port"] = addr.port;
      anchor["services"] = addr.services;
      anchors_array.push_back(anchor);
    }
    root["anchors"] = anchors_array;

    std::string data = root.dump(2);

    // Use centralized atomic write with 0600 permissions (owner-only)
    // This provides: temp file creation, partial write handling, fsync,
    // directory sync, and atomic rename - more robust than previous implementation
    if (!util::atomic_write_file(filepath, data, 0600)) {
      LOG_NET_ERROR("Failed to save anchors to {}", filepath);
      return false;
    }

    LOG_NET_DEBUG("Successfully saved {} anchors (atomic)", anchors.size());
    return true;

  } catch (const std::exception& e) {
    LOG_NET_ERROR("Exception during SaveAnchors: {}", e.what());
    return false;
  }
}

std::vector<protocol::NetworkAddress> AnchorManager::LoadAnchors(const std::string& filepath) {
  using json = nlohmann::json;

  try {
    // Check if file exists
    std::ifstream file(filepath);
    if (!file.is_open()) {
      LOG_NET_DEBUG("No anchors file found at {}", filepath);
      return {};  // No anchors to load
    }

    // Parse JSON
    json root;
    try {
      file >> root;
    } catch (const std::exception& e) {
      LOG_NET_WARN("Failed to parse anchors file {}: {}", filepath, e.what());
      file.close();
      std::filesystem::remove(filepath);
      return {};
    }
    file.close();

    // Validate version and structure
    const int version = root.value("version", 0);
    if (version != 1 || !root.contains("anchors") || !root["anchors"].is_array()) {
      LOG_NET_WARN("Invalid anchors file format/version, deleting {}", filepath);
      std::filesystem::remove(filepath);
      return {};
    }

    const json& anchors_array = root["anchors"];
    std::vector<protocol::NetworkAddress> anchors;
    anchors.reserve(std::min<size_t>(2, anchors_array.size()));

    auto valid_ip_array = [](const json& ip) {
      if (!ip.is_array() || ip.size() != 16)
        return false;
      for (const auto& v : ip) {
        if (!v.is_number_integer())
          return false;
        int x = v.get<int>();
        if (x < 0 || x > 255)
          return false;
      }
      return true;
    };

    for (const auto& anchor_json : anchors_array) {
      if (!anchor_json.is_object()) {
        LOG_NET_WARN("Skipping malformed anchor (not object)");
        continue;
      }

      if (!anchor_json.contains("ip") || !anchor_json.contains("port") || !anchor_json.contains("services")) {
        LOG_NET_WARN("Skipping malformed anchor (missing fields)");
        continue;
      }

      const auto& ip_array = anchor_json["ip"];
      if (!valid_ip_array(ip_array)) {
        LOG_NET_WARN("Skipping anchor with invalid IP array");
        continue;
      }

      if (!anchor_json["port"].is_number_unsigned() || !anchor_json["services"].is_number_unsigned()) {
        LOG_NET_WARN("Skipping anchor with invalid port/services types");
        continue;
      }

      protocol::NetworkAddress addr;
      for (size_t i = 0; i < 16; ++i) {
        addr.ip[i] = static_cast<uint8_t>(ip_array[i].get<int>());
      }
      addr.port = anchor_json["port"].get<uint16_t>();
      addr.services = anchor_json["services"].get<uint64_t>();

      anchors.push_back(addr);
      if (anchors.size() == 2)
        break;  // cap attempts
    }

    LOG_NET_INFO("Loaded {} anchor addresses from {} (passive - caller will connect)", anchors.size(), filepath);

    // Single-use file: delete after reading
    std::error_code ec;
    std::filesystem::remove(filepath, ec);
    if (ec) {
      LOG_NET_WARN("Failed to delete anchors file {}: {}", filepath, ec.message());
    } else {
      LOG_NET_DEBUG("Deleted anchors file after reading");
    }

    return anchors;

  } catch (const std::exception& e) {
    LOG_NET_ERROR("Exception during LoadAnchors: {}", e.what());
    try {
      std::filesystem::remove(filepath);
    } catch (...) {
    }
    return {};
  }
}

}  // namespace network
}  // namespace unicity
