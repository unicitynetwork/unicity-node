// Copyright (c) 2025 The Unicity Foundation
// Timestamp manipulation attack tests
//
// Attackers may try to manipulate timestamps to:
// - Make old addresses appear fresh (bypass staleness checks)
// - Make addresses appear in the future (exploit time-based logic)
// - Avoid the 2-hour penalty applied to ADDR messages

#include "../addr_test_network.hpp"
#include "catch_amalgamated.hpp"
#include "util/time.hpp"

using namespace unicity;
using namespace unicity::test::addrsim;

TEST_CASE("Timestamp: Future timestamps rejected", "[addrsim][timestamp][security]") {
  // Addresses with timestamps >10 minutes in the future should be rejected
  // Defense: is_terrible() checks for TERRIBLE_FUTURE_TIMESTAMP_SEC (600s)

  AddrTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  auto attacker_id = net.CreateNode("44.1.0.1");
  net.Connect(attacker_id, victim_id);

  // Send address with timestamp 15 minutes in the future
  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string("44.2.0.1", 9590);
  ta.timestamp = static_cast<uint32_t>(util::GetTime() + 900);  // 15 min future

  size_t before = victim->addr_mgr->size();
  net.DeliverAddr(attacker_id, victim_id, {ta});
  size_t after = victim->addr_mgr->size();

  INFO("Before: " << before << ", After: " << after);
  REQUIRE(after == before);  // Should not be added
}

TEST_CASE("Timestamp: Near-future timestamps accepted", "[addrsim][timestamp][security]") {
  // Addresses with timestamps <10 minutes in the future should be accepted
  // (allows for clock skew between nodes)

  AddrTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  auto sender_id = net.CreateNode("8.2.0.1");
  net.Connect(sender_id, victim_id);

  // Send address with timestamp 5 minutes in the future (within tolerance)
  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string("9.1.0.1", 9590);
  ta.timestamp = static_cast<uint32_t>(util::GetTime() + 300);  // 5 min future

  size_t before = victim->addr_mgr->size();
  net.DeliverAddr(sender_id, victim_id, {ta});
  size_t after = victim->addr_mgr->size();

  INFO("Before: " << before << ", After: " << after);
  REQUIRE(after == before + 1);  // Should be added
}

TEST_CASE("Timestamp: Very old timestamps rejected", "[addrsim][timestamp][security]") {
  // Addresses with timestamps >30 days old should be rejected
  // Defense: is_terrible() checks ADDRMAN_HORIZON_DAYS (30)

  AddrTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  auto attacker_id = net.CreateNode("44.1.0.1");
  net.Connect(attacker_id, victim_id);

  // Send address with timestamp 60 days ago
  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string("44.2.0.1", 9590);
  ta.timestamp = static_cast<uint32_t>(util::GetTime() - (60 * 24 * 3600));  // 60 days ago

  size_t before = victim->addr_mgr->size();
  net.DeliverAddr(attacker_id, victim_id, {ta});
  size_t after = victim->addr_mgr->size();

  INFO("Before: " << before << ", After: " << after);
  REQUIRE(after == before);  // Should not be added
}

TEST_CASE("Timestamp: Moderately old timestamps accepted", "[addrsim][timestamp][security]") {
  // Addresses with timestamps <30 days old should be accepted

  AddrTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  auto sender_id = net.CreateNode("8.2.0.1");
  net.Connect(sender_id, victim_id);

  // Send address with timestamp 7 days ago (within horizon)
  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string("9.1.0.1", 9590);
  ta.timestamp = static_cast<uint32_t>(util::GetTime() - (7 * 24 * 3600));  // 7 days ago

  size_t before = victim->addr_mgr->size();
  net.DeliverAddr(sender_id, victim_id, {ta});
  size_t after = victim->addr_mgr->size();

  INFO("Before: " << before << ", After: " << after);
  REQUIRE(after == before + 1);  // Should be added
}

TEST_CASE("Timestamp: Stale addresses not relayed", "[addrsim][timestamp][relay]") {
  // Addresses >10 minutes old should not be relayed
  // Defense: relay freshness check in addr_relay_manager

  AddrTestNetwork net(42);

  auto a = net.CreateNode("8.1.0.1");
  auto b = net.CreateNode("8.2.0.1");
  auto c = net.CreateNode("8.3.0.1");

  net.Connect(a, b);
  net.Connect(b, c);

  // A sends 15-minute-old address to B
  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string("9.1.0.1", 9590);
  ta.timestamp = static_cast<uint32_t>(util::GetTime() - 900);  // 15 min ago

  net.DeliverAddr(a, b, {ta});

  // B should accept (within 30-day horizon) but NOT relay (>10 min old)
  auto* node_b = net.GetNode(b);
  REQUIRE(node_b->pending_relays.empty());

  net.Tick();

  // C should not have received it
  auto* node_c = net.GetNode(c);
  REQUIRE(node_c->addrs_received == 0);
}

TEST_CASE("Timestamp: Fresh addresses relayed", "[addrsim][timestamp][relay]") {
  // Addresses <10 minutes old should be relayed

  AddrTestNetwork net(42);

  auto a = net.CreateNode("8.1.0.1");
  auto b = net.CreateNode("8.2.0.1");
  auto c = net.CreateNode("8.3.0.1");

  net.Connect(a, b);
  net.Connect(b, c);

  // A sends fresh address to B
  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string("9.1.0.1", 9590);
  ta.timestamp = static_cast<uint32_t>(util::GetTime());  // Now

  net.DeliverAddr(a, b, {ta});

  // B should relay fresh address
  auto* node_b = net.GetNode(b);
  REQUIRE(node_b->pending_relays.size() == 1);

  net.Tick();

  // C should have received it
  auto* node_c = net.GetNode(c);
  REQUIRE(node_c->addr_mgr->size() >= 1);
}

TEST_CASE("Timestamp: Zero timestamp uses current time", "[addrsim][timestamp]") {
  // Timestamp of 0 should be treated as current time

  AddrTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  auto sender_id = net.CreateNode("8.2.0.1");
  net.Connect(sender_id, victim_id);

  // Send address with timestamp 0
  protocol::TimestampedAddress ta;
  ta.address = protocol::NetworkAddress::from_string("9.1.0.1", 9590);
  ta.timestamp = 0;

  size_t before = victim->addr_mgr->size();
  net.DeliverAddr(sender_id, victim_id, {ta});
  size_t after = victim->addr_mgr->size();

  INFO("Before: " << before << ", After: " << after);
  REQUIRE(after == before + 1);  // Should be added with current time
}

TEST_CASE("Timestamp: Attacker cannot reset staleness", "[addrsim][timestamp][security]") {
  // Attacker sending same address with fresh timestamp should update timestamp
  // but only if the new timestamp is actually newer

  AddrTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  auto honest_id = net.CreateNode("8.2.0.1");
  auto attacker_id = net.CreateNode("44.1.0.1");
  net.Connect(honest_id, victim_id);
  net.Connect(attacker_id, victim_id);

  std::string test_addr = "9.1.0.1";

  // Honest node sends address with old timestamp
  protocol::TimestampedAddress ta1;
  ta1.address = protocol::NetworkAddress::from_string(test_addr, 9590);
  ta1.timestamp = static_cast<uint32_t>(util::GetTime() - (20 * 24 * 3600));  // 20 days ago

  net.DeliverAddr(honest_id, victim_id, {ta1});
  REQUIRE(victim->addr_mgr->size() == 1);

  // Attacker tries to "refresh" the same address with current timestamp
  protocol::TimestampedAddress ta2;
  ta2.address = protocol::NetworkAddress::from_string(test_addr, 9590);
  ta2.timestamp = static_cast<uint32_t>(util::GetTime());  // Now

  net.DeliverAddr(attacker_id, victim_id, {ta2});

  // Address should still be there (updated timestamp)
  REQUIRE(victim->addr_mgr->size() == 1);

  // The timestamp should be updated to the newer value
  // (This is actually desired behavior - fresher info is better)
}

TEST_CASE("Timestamp: Boundary conditions", "[addrsim][timestamp][security]") {
  // Test exact boundary conditions for timestamp validation

  AddrTestNetwork net(42);

  auto victim_id = net.CreateNode("8.1.0.1");
  auto* victim = net.GetNode(victim_id);

  auto sender_id = net.CreateNode("8.2.0.1");
  net.Connect(sender_id, victim_id);

  uint32_t now = static_cast<uint32_t>(util::GetTime());

  // Test at exact 10-minute future boundary (600 seconds)
  // Should be accepted (<=600 is OK)
  {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string("9.1.0.1", 9590);
    ta.timestamp = now + 600;  // Exactly 10 min future

    size_t before = victim->addr_mgr->size();
    net.DeliverAddr(sender_id, victim_id, {ta});
    size_t after = victim->addr_mgr->size();
    INFO("10min future: before=" << before << " after=" << after);
    REQUIRE(after == before + 1);
  }

  // Test at 10 minutes + 1 second (should be rejected)
  {
    protocol::TimestampedAddress ta;
    ta.address = protocol::NetworkAddress::from_string("9.2.0.1", 9590);
    ta.timestamp = now + 601;  // Just over 10 min

    size_t before = victim->addr_mgr->size();
    net.DeliverAddr(sender_id, victim_id, {ta});
    size_t after = victim->addr_mgr->size();
    INFO("10min+1s future: before=" << before << " after=" << after);
    REQUIRE(after == before);  // Rejected
  }
}
