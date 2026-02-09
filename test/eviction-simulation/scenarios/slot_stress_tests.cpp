// Copyright (c) 2025 The Unicity Foundation
// Connection slot stress simulation tests
//
// These tests verify that connection slot management remains correct
// under high-volume connection churn and stress conditions.

#include "catch_amalgamated.hpp"
#include "eviction_test_network.hpp"

#include <set>

using namespace unicity::test::evicsim;

// =============================================================================
// SLOT STRESS: Basic Slot Limits
// =============================================================================

TEST_CASE("Stress: Inbound slot limit enforced", "[evicsim][stress][slots][inbound]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Set small inbound limit for testing
  victim->max_inbound = 20;

  // Create many peers from diverse netgroups
  std::vector<int> peers;
  for (int i = 1; i <= 50; ++i) {
    std::string ng = "9." + std::to_string(i);
    peers.push_back(net.CreateNode(ng + ".0.1"));
  }

  // Try to connect all
  size_t connected = 0;
  for (int peer_id : peers) {
    if (net.Connect(peer_id, victim_id, SimConnectionType::INBOUND)) {
      connected++;
    }
  }

  INFO("Attempted: 50, Connected: " << connected);

  // Should be capped at max_inbound
  REQUIRE(victim->InboundCount() <= victim->max_inbound);

  // Most should have connected (eviction allows new connections)
  REQUIRE(connected > victim->max_inbound / 2);
}

TEST_CASE("Stress: Outbound slot limits enforced", "[evicsim][stress][slots][outbound]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Create targets from diverse netgroups
  std::vector<int> targets;
  for (int i = 1; i <= 20; ++i) {
    std::string ng = "9." + std::to_string(i);
    targets.push_back(net.CreateNode(ng + ".0.1"));
  }

  // Try full-relay connections
  size_t full_relay_connected = 0;
  for (int target_id : targets) {
    if (net.Connect(victim_id, target_id, SimConnectionType::OUTBOUND_FULL_RELAY)) {
      full_relay_connected++;
    }
    if (full_relay_connected >= victim->max_full_relay_outbound) break;
  }

  REQUIRE(victim->OutboundFullRelayCount() == victim->max_full_relay_outbound);

  // Try more full-relay - should fail
  auto extra_id = net.CreateNode("9.100.0.1");
  REQUIRE_FALSE(net.Connect(victim_id, extra_id, SimConnectionType::OUTBOUND_FULL_RELAY));

  // Block-relay slots should still be available
  REQUIRE(victim->NeedsMoreBlockRelayOutbound());

  // Fill block-relay slots
  for (int i = 0; i < 2; ++i) {
    auto br_id = net.CreateNode("10." + std::to_string(i + 1) + ".0.1");
    REQUIRE(net.Connect(victim_id, br_id, SimConnectionType::BLOCK_RELAY));
  }

  REQUIRE(victim->BlockRelayCount() == victim->max_block_relay_outbound);
  REQUIRE_FALSE(victim->NeedsMoreOutbound());
}

// =============================================================================
// SLOT STRESS: High-Volume Churn
// =============================================================================

TEST_CASE("Stress: 1000 connect/disconnect cycles", "[evicsim][stress][churn]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Pre-create a pool of peers
  std::vector<int> peer_pool;
  for (int i = 1; i <= 200; ++i) {
    std::string ng = "9." + std::to_string((i % 100) + 1);
    peer_pool.push_back(net.CreateNode(ng + "." + std::to_string(i / 100) + ".1"));
  }

  std::mt19937 rng(42);

  for (int cycle = 0; cycle < 1000; ++cycle) {
    // Random action: connect or disconnect
    bool do_connect = rng() % 2 == 0;

    if (do_connect && victim->InboundCount() < victim->max_inbound) {
      // Pick random peer not already connected
      std::uniform_int_distribution<size_t> dist(0, peer_pool.size() - 1);
      int peer_id = peer_pool[dist(rng)];
      net.Connect(peer_id, victim_id, SimConnectionType::INBOUND);
    } else if (victim->InboundCount() > 0) {
      // Disconnect random peer
      auto peers = victim->GetConnectedPeerIds();
      if (!peers.empty()) {
        auto it = peers.begin();
        std::uniform_int_distribution<size_t> dist(0, peers.size() - 1);
        std::advance(it, dist(rng));
        net.Disconnect(victim_id, *it);
      }
    }

    // Invariants must hold at all times
    REQUIRE(victim->InboundCount() <= victim->max_inbound);
    REQUIRE(victim->OutboundFullRelayCount() <= victim->max_full_relay_outbound);
    REQUIRE(victim->BlockRelayCount() <= victim->max_block_relay_outbound);
  }

  INFO("Final inbound count: " << victim->InboundCount());
  INFO("Connections accepted: " << victim->connections_accepted);
}

TEST_CASE("Stress: Rapid concurrent outbound attempts", "[evicsim][stress][outbound][concurrent]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Create many targets
  std::vector<int> targets;
  for (int i = 1; i <= 50; ++i) {
    std::string ng = "9." + std::to_string(i);
    targets.push_back(net.CreateNode(ng + ".0.1"));
  }

  // Attempt all outbound connections in rapid succession
  size_t total_attempts = 0;
  size_t successful = 0;

  for (int target_id : targets) {
    total_attempts++;

    // Try full-relay first, then block-relay
    if (net.Connect(victim_id, target_id, SimConnectionType::OUTBOUND_FULL_RELAY)) {
      successful++;
    } else if (net.Connect(victim_id, target_id, SimConnectionType::BLOCK_RELAY)) {
      successful++;
    }
  }

  INFO("Attempts: " << total_attempts);
  INFO("Successful: " << successful);
  INFO("Full-relay: " << victim->OutboundFullRelayCount());
  INFO("Block-relay: " << victim->BlockRelayCount());

  // Should have exactly max slots filled
  REQUIRE(victim->OutboundFullRelayCount() == victim->max_full_relay_outbound);
  REQUIRE(victim->BlockRelayCount() == victim->max_block_relay_outbound);

  // Total outbound should be sum of both
  REQUIRE(victim->TotalOutboundCount() == victim->max_full_relay_outbound + victim->max_block_relay_outbound);
}

// =============================================================================
// SLOT STRESS: Eviction Under Pressure
// =============================================================================

TEST_CASE("Stress: Continuous eviction pressure", "[evicsim][stress][eviction]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Inbound limit large enough for eviction to work with protection phases
  // Protection: 4 netgroup + 8 ping + 4 headers + 50% uptime
  // Need ~30+ peers before eviction can find candidates
  victim->max_inbound = 30;

  // Create waves of connecting peers
  size_t total_evictions = 0;
  size_t prev_evictions = 0;

  for (int wave = 0; wave < 10; ++wave) {
    // Create new peers for this wave (different netgroups)
    std::vector<int> wave_peers;
    for (int i = 0; i < 20; ++i) {
      std::string ng = std::to_string(wave * 30 + i + 1) + ".1";
      wave_peers.push_back(net.CreateNode(ng + ".0.1"));
    }

    // Connect all
    for (int peer_id : wave_peers) {
      net.Connect(peer_id, victim_id, SimConnectionType::INBOUND);
    }

    // Check eviction stats (accumulate delta to avoid double counting)
    size_t new_evictions = victim->evictions_triggered - prev_evictions;
    prev_evictions = victim->evictions_triggered;
    total_evictions += new_evictions;

    // Advance time (affects eviction decisions)
    net.AdvanceTime(std::chrono::seconds(60));
  }

  INFO("Total evictions: " << total_evictions);
  INFO("Final inbound: " << victim->InboundCount());

  // Invariant: never exceed max
  REQUIRE(victim->InboundCount() <= victim->max_inbound);

  // Should have triggered many evictions
  REQUIRE(total_evictions > 0);
}

// =============================================================================
// SLOT STRESS: Slot Accounting Correctness
// =============================================================================

TEST_CASE("Stress: Slot counts remain consistent", "[evicsim][stress][accounting]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  std::mt19937 rng(42);

  // Pre-create peers
  std::vector<int> inbound_peers;
  std::vector<int> outbound_targets;

  for (int i = 1; i <= 100; ++i) {
    inbound_peers.push_back(net.CreateNode("9." + std::to_string(i) + ".0.1"));
    outbound_targets.push_back(net.CreateNode("10." + std::to_string(i) + ".0.1"));
  }

  for (int cycle = 0; cycle < 500; ++cycle) {
    int action = rng() % 4;

    if (action == 0) {
      // Connect inbound
      int peer_id = inbound_peers[rng() % inbound_peers.size()];
      net.Connect(peer_id, victim_id, SimConnectionType::INBOUND);
    } else if (action == 1) {
      // Connect outbound
      int target_id = outbound_targets[rng() % outbound_targets.size()];
      if (rng() % 2 == 0) {
        net.Connect(victim_id, target_id, SimConnectionType::OUTBOUND_FULL_RELAY);
      } else {
        net.Connect(victim_id, target_id, SimConnectionType::BLOCK_RELAY);
      }
    } else if (action == 2) {
      // Disconnect random
      auto peers = victim->GetConnectedPeerIds();
      if (!peers.empty()) {
        auto it = peers.begin();
        std::advance(it, rng() % peers.size());
        net.Disconnect(victim_id, *it);
      }
    } else {
      // Verify counts
      size_t counted_inbound = 0;
      size_t counted_full_relay = 0;
      size_t counted_block_relay = 0;

      for (const auto& [peer_id, info] : victim->connections) {
        if (info.type == SimConnectionType::INBOUND) counted_inbound++;
        else if (info.type == SimConnectionType::OUTBOUND_FULL_RELAY) counted_full_relay++;
        else if (info.type == SimConnectionType::BLOCK_RELAY) counted_block_relay++;
      }

      REQUIRE(victim->InboundCount() == counted_inbound);
      REQUIRE(victim->OutboundFullRelayCount() == counted_full_relay);
      REQUIRE(victim->BlockRelayCount() == counted_block_relay);
    }

    // Invariants
    REQUIRE(victim->InboundCount() <= victim->max_inbound);
    REQUIRE(victim->OutboundFullRelayCount() <= victim->max_full_relay_outbound);
    REQUIRE(victim->BlockRelayCount() <= victim->max_block_relay_outbound);
  }
}

// =============================================================================
// SLOT STRESS: Large Scale Test
// =============================================================================

TEST_CASE("Stress: 10000 operations large scale", "[evicsim][stress][largescale]") {
  EvictionTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  // Create large peer pool
  std::vector<int> peer_pool;
  for (int i = 1; i <= 500; ++i) {
    std::string ng = std::to_string((i % 200) + 1) + ".1";
    peer_pool.push_back(net.CreateNode(ng + "." + std::to_string(i / 200) + ".1"));
  }

  std::mt19937 rng(42);
  size_t violations = 0;

  for (int op = 0; op < 10000; ++op) {
    int action = rng() % 3;

    if (action == 0) {
      // Connect
      int peer_id = peer_pool[rng() % peer_pool.size()];
      int type_choice = rng() % 3;
      if (type_choice == 0) {
        net.Connect(peer_id, victim_id, SimConnectionType::INBOUND);
      } else if (type_choice == 1) {
        net.Connect(victim_id, peer_id, SimConnectionType::OUTBOUND_FULL_RELAY);
      } else {
        net.Connect(victim_id, peer_id, SimConnectionType::BLOCK_RELAY);
      }
    } else if (action == 1) {
      // Disconnect
      auto peers = victim->GetConnectedPeerIds();
      if (!peers.empty()) {
        auto it = peers.begin();
        std::advance(it, rng() % peers.size());
        net.Disconnect(victim_id, *it);
      }
    } else {
      // Time advance
      net.AdvanceTime(std::chrono::seconds(rng() % 60));
    }

    // Check invariants
    if (victim->InboundCount() > victim->max_inbound ||
        victim->OutboundFullRelayCount() > victim->max_full_relay_outbound ||
        victim->BlockRelayCount() > victim->max_block_relay_outbound) {
      violations++;
    }
  }

  INFO("Total operations: 10000");
  INFO("Invariant violations: " << violations);
  INFO("Final connections: " << victim->TotalConnectionCount());

  REQUIRE(violations == 0);
}
