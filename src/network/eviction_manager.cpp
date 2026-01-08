// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license.

#include "network/eviction_manager.hpp"

#include "util/logging.hpp"

#include <algorithm>
#include <limits>
#include <map>
#include <set>

namespace unicity {
namespace network {

std::optional<int> EvictionManager::SelectNodeToEvict(std::vector<EvictionCandidate> candidates) {
  // Remove outbound peers - NEVER evict outbound connections
  candidates.erase(std::remove_if(candidates.begin(), candidates.end(),
                                  [](const EvictionCandidate& c) { return c.is_outbound; }),
                   candidates.end());

  // Remove protected peers (NoBan, etc.)
  candidates.erase(std::remove_if(candidates.begin(), candidates.end(),
                                  [](const EvictionCandidate& c) { return c.is_protected; }),
                   candidates.end());

  if (candidates.empty()) {
    return std::nullopt;
  }

  // --- Protection Phase ---

  // Protect 4 peers by netgroup diversity
  // Sort by netgroup, then protect one peer from each of up to 4 different netgroups
  if (candidates.size() > PROTECT_BY_NETGROUP) {
    std::sort(candidates.begin(), candidates.end(),
              [](const EvictionCandidate& a, const EvictionCandidate& b) { return a.netgroup < b.netgroup; });

    // Find up to 4 unique netgroups to protect
    std::set<std::string> protected_netgroups;
    for (auto it = candidates.rbegin(); it != candidates.rend() && protected_netgroups.size() < PROTECT_BY_NETGROUP;
         ++it) {
      if (!it->netgroup.empty() && protected_netgroups.find(it->netgroup) == protected_netgroups.end()) {
        protected_netgroups.insert(it->netgroup);
      }
    }

    // Remove one peer from each protected netgroup
    std::set<std::string> removed_netgroups;
    candidates.erase(std::remove_if(candidates.begin(), candidates.end(),
                                    [&](const EvictionCandidate& c) {
                                      if (!c.netgroup.empty() && protected_netgroups.count(c.netgroup) &&
                                          !removed_netgroups.count(c.netgroup)) {
                                        removed_netgroups.insert(c.netgroup);
                                        return true;
                                      }
                                      return false;
                                    }),
                     candidates.end());
  }

  if (candidates.empty()) {
    return std::nullopt;
  }

  // Protect 8 peers with lowest ping time
  if (candidates.size() > PROTECT_BY_PING) {
    // Map unknown ping (-1) to large value so they're not protected
    auto map_ping = [](int64_t p) { return p < 0 ? std::numeric_limits<int64_t>::max() : p; };

    std::sort(candidates.begin(), candidates.end(), [&](const EvictionCandidate& a, const EvictionCandidate& b) {
      return map_ping(a.ping_time_ms) > map_ping(b.ping_time_ms);
    });

    // Remove last 8 (lowest ping)
    candidates.resize(candidates.size() - PROTECT_BY_PING);
  }

  if (candidates.empty()) {
    return std::nullopt;
  }

  // Protect 4 peers that most recently sent us valid headers
  if (candidates.size() > PROTECT_BY_HEADERS) {
    // Sort by last_headers_time descending (most recent first = best)
    // Peers that never sent headers have epoch time (very old) - not protected
    std::sort(candidates.begin(), candidates.end(), [](const EvictionCandidate& a, const EvictionCandidate& b) {
      return a.last_headers_time < b.last_headers_time;
    });

    // Remove last 4 (most recent header relay)
    candidates.resize(candidates.size() - PROTECT_BY_HEADERS);
  }

  if (candidates.empty()) {
    return std::nullopt;
  }

  // Protect 50% of remaining peers by longest connection uptime
  if (candidates.size() > 1) {
    size_t protect_count = candidates.size() / 2;
    if (protect_count > 0) {
      // Sort by connected_time descending (newest first at front, oldest at back)
      std::sort(candidates.begin(), candidates.end(), [](const EvictionCandidate& a, const EvictionCandidate& b) {
        return a.connected_time > b.connected_time;
      });

      // Remove last N (oldest connections = protected, newest remain as eviction candidates)
      candidates.resize(candidates.size() - protect_count);
    }
  }

  if (candidates.empty()) {
    return std::nullopt;
  }

  // --- Selection Phase ---
  // Group remaining candidates by netgroup, find the group with most connections
  std::map<std::string, std::vector<EvictionCandidate>> by_netgroup;
  for (const auto& c : candidates) {
    std::string key = c.netgroup.empty() ? "__unknown__" : c.netgroup;
    by_netgroup[key].push_back(c);
  }

  // Find netgroup with most candidates (ties broken by youngest connection)
  std::string worst_netgroup;
  size_t most_connections = 0;
  std::chrono::steady_clock::time_point youngest_time = std::chrono::steady_clock::time_point::min();

  for (const auto& [ng, group] : by_netgroup) {
    // Find youngest (most recent) connection in this group
    auto youngest_in_group = std::max_element(group.begin(), group.end(),
                                              [](const EvictionCandidate& a, const EvictionCandidate& b) {
                                                return a.connected_time < b.connected_time;
                                              });

    if (group.size() > most_connections ||
        (group.size() == most_connections && youngest_in_group->connected_time > youngest_time)) {
      most_connections = group.size();
      youngest_time = youngest_in_group->connected_time;
      worst_netgroup = ng;
    }
  }

  // From the worst netgroup, evict the youngest (most recently connected)
  const auto& evict_group = by_netgroup[worst_netgroup];
  auto to_evict = std::max_element(evict_group.begin(), evict_group.end(),
                                   [](const EvictionCandidate& a, const EvictionCandidate& b) {
                                     return a.connected_time < b.connected_time;
                                   });

  if (to_evict != evict_group.end()) {
    LOG_NET_DEBUG("SelectNodeToEvict: peer={} from netgroup={} (group_size={})", to_evict->peer_id, worst_netgroup,
                  most_connections);
    return to_evict->peer_id;
  }

  return std::nullopt;
}

}  // namespace network
}  // namespace unicity
