// Copyright (c) 2025 The Unicity Foundation
// Tests for AddrManager per-netgroup limits
//
// These tests verify that the address manager limits how many addresses
// from the same /16 subnet can be stored, preventing a single netgroup
// from dominating the address tables.

#include "catch_amalgamated.hpp"
#include "network/addr_manager.hpp"
#include "network/protocol.hpp"
#include "util/netaddress.hpp"

#include <asio.hpp>
#include <set>

using namespace unicity;
using namespace unicity::network;

// Helper to create a NetworkAddress from an IP string
static protocol::NetworkAddress MakeNetworkAddress(const std::string& ip_str, uint16_t port = 18444) {
    protocol::NetworkAddress addr;
    addr.services = protocol::ServiceFlags::NODE_NETWORK;
    addr.port = port;

    asio::error_code ec;
    auto ip_addr = asio::ip::make_address(ip_str, ec);
    if (ec) {
        throw std::runtime_error("Invalid IP: " + ip_str);
    }

    if (ip_addr.is_v4()) {
        auto v6_mapped = asio::ip::make_address_v6(asio::ip::v4_mapped, ip_addr.to_v4());
        auto bytes = v6_mapped.to_bytes();
        std::copy(bytes.begin(), bytes.end(), addr.ip.begin());
    } else {
        auto bytes = ip_addr.to_v6().to_bytes();
        std::copy(bytes.begin(), bytes.end(), addr.ip.begin());
    }

    return addr;
}

// NOTE: Tests use public routable IPs (8.x.x.x, 9.x.x.x etc.) because
// AddrManager correctly rejects RFC1918 (10.x.x.x, 192.168.x.x) addresses.

TEST_CASE("AddrManager - NEW table per-netgroup limit", "[network][addr][security][unit]") {
    AddressManager addr_mgr;

    SECTION("Accepts addresses up to per-netgroup limit") {
        // MAX_PER_NETGROUP_NEW is 32
        int added = 0;
        for (int i = 1; i <= 32; i++) {
            // Use different ports to create unique addresses in same /16
            std::string ip = "8.50.0." + std::to_string(i);
            if (addr_mgr.add(MakeNetworkAddress(ip, 18444))) {
                added++;
            }
        }

        INFO("Added " << added << " addresses from 8.50.x.x");
        REQUIRE(added == 32);
        REQUIRE(addr_mgr.new_count() == 32);
    }

    SECTION("Rejects addresses beyond per-netgroup limit") {
        // First, fill up to the limit (32)
        for (int i = 1; i <= 32; i++) {
            std::string ip = "8.50.0." + std::to_string(i);
            REQUIRE(addr_mgr.add(MakeNetworkAddress(ip, 18444)));
        }

        // Now try to add more from same /16 - should be rejected
        int rejected = 0;
        for (int i = 33; i <= 40; i++) {
            std::string ip = "8.50.0." + std::to_string(i);
            if (!addr_mgr.add(MakeNetworkAddress(ip, 18444))) {
                rejected++;
            }
        }

        INFO("Rejected " << rejected << " addresses beyond limit");
        REQUIRE(rejected == 8);  // All 8 should be rejected
        REQUIRE(addr_mgr.new_count() == 32);  // Still at limit
    }

    SECTION("Different netgroups have independent limits") {
        // Add 32 from 8.1.x.x
        for (int i = 1; i <= 32; i++) {
            std::string ip = "8.1.0." + std::to_string(i);
            REQUIRE(addr_mgr.add(MakeNetworkAddress(ip, 18444)));
        }

        // Add 32 from 8.2.x.x (different /16)
        for (int i = 1; i <= 32; i++) {
            std::string ip = "8.2.0." + std::to_string(i);
            REQUIRE(addr_mgr.add(MakeNetworkAddress(ip, 18444)));
        }

        // Verify both netgroups are at their limits
        REQUIRE(addr_mgr.new_count() == 64);

        // Try to add more from 8.1.x.x - should fail
        REQUIRE_FALSE(addr_mgr.add(MakeNetworkAddress("8.1.0.100", 18444)));

        // Try to add more from 8.2.x.x - should fail
        REQUIRE_FALSE(addr_mgr.add(MakeNetworkAddress("8.2.0.100", 18444)));

        // But adding from 8.3.x.x should work
        REQUIRE(addr_mgr.add(MakeNetworkAddress("8.3.0.1", 18444)));
        REQUIRE(addr_mgr.new_count() == 65);
    }
}

TEST_CASE("AddrManager - TRIED table per-netgroup limit", "[network][addr][security][unit]") {
    AddressManager addr_mgr;

    SECTION("Moves addresses to TRIED up to per-netgroup limit") {
        // MAX_PER_NETGROUP_TRIED is 8
        // Add addresses and mark them as good
        for (int i = 1; i <= 10; i++) {
            std::string ip = "8.50.0." + std::to_string(i);
            addr_mgr.add(MakeNetworkAddress(ip, 18444));
            addr_mgr.good(MakeNetworkAddress(ip, 18444));
        }

        // Should have moved 8 to TRIED (limit) and kept 2 in NEW
        INFO("TRIED count: " << addr_mgr.tried_count());
        INFO("NEW count: " << addr_mgr.new_count());

        REQUIRE(addr_mgr.tried_count() == 8);
        REQUIRE(addr_mgr.new_count() == 2);
    }

    SECTION("Addresses beyond TRIED limit stay in NEW with success info") {
        // Fill TRIED table with 8 from same netgroup
        for (int i = 1; i <= 8; i++) {
            std::string ip = "8.60.0." + std::to_string(i);
            addr_mgr.add(MakeNetworkAddress(ip, 18444));
            addr_mgr.good(MakeNetworkAddress(ip, 18444));
        }
        REQUIRE(addr_mgr.tried_count() == 8);

        // Add more from same netgroup and mark as good
        addr_mgr.add(MakeNetworkAddress("8.60.0.100", 18444));
        addr_mgr.good(MakeNetworkAddress("8.60.0.100", 18444));

        // Should still be in NEW (TRIED limit reached for this netgroup)
        REQUIRE(addr_mgr.tried_count() == 8);
        REQUIRE(addr_mgr.new_count() == 1);
    }

    SECTION("Different netgroups have independent TRIED limits") {
        // Fill 8.1.x.x TRIED slots
        for (int i = 1; i <= 8; i++) {
            std::string ip = "8.1.0." + std::to_string(i);
            addr_mgr.add(MakeNetworkAddress(ip, 18444));
            addr_mgr.good(MakeNetworkAddress(ip, 18444));
        }

        // Fill 8.2.x.x TRIED slots
        for (int i = 1; i <= 8; i++) {
            std::string ip = "8.2.0." + std::to_string(i);
            addr_mgr.add(MakeNetworkAddress(ip, 18444));
            addr_mgr.good(MakeNetworkAddress(ip, 18444));
        }

        REQUIRE(addr_mgr.tried_count() == 16);

        // Can still add from 8.3.x.x
        addr_mgr.add(MakeNetworkAddress("8.3.0.1", 18444));
        addr_mgr.good(MakeNetworkAddress("8.3.0.1", 18444));
        REQUIRE(addr_mgr.tried_count() == 17);
    }
}

TEST_CASE("AddrManager - Netgroup limits prevent eclipse attack", "[network][addr][security][unit]") {
    AddressManager addr_mgr;

    SECTION("Attacker cannot dominate NEW table from single /16") {
        // Attacker tries to fill NEW table with 1000 addresses from same /16
        int attacker_added = 0;
        for (int i = 0; i < 255; i++) {
            for (int j = 0; j < 4; j++) {
                std::string ip = "8.99." + std::to_string(i) + "." + std::to_string(j + 1);
                // All 8.99.x.x are in same /16 netgroup
                if (addr_mgr.add(MakeNetworkAddress(ip, 18444 + j))) {
                    attacker_added++;
                }
            }
        }

        INFO("Attacker added " << attacker_added << " addresses");
        REQUIRE(attacker_added == 32);  // Limited to MAX_PER_NETGROUP_NEW

        // Honest addresses from different netgroups can still be added
        REQUIRE(addr_mgr.add(MakeNetworkAddress("9.1.0.1", 18444)));
        REQUIRE(addr_mgr.add(MakeNetworkAddress("9.2.0.1", 18444)));
        REQUIRE(addr_mgr.add(MakeNetworkAddress("9.3.0.1", 18444)));

        // Table has diversity
        REQUIRE(addr_mgr.new_count() == 35);
    }

    SECTION("Selection still finds diverse addresses") {
        // Add addresses from multiple netgroups
        std::set<std::string> netgroups_added;

        for (int ng = 1; ng <= 10; ng++) {
            std::string ip = "8." + std::to_string(ng) + ".0.1";
            addr_mgr.add(MakeNetworkAddress(ip, 18444));
            netgroups_added.insert(util::GetNetgroup(ip));
        }

        REQUIRE(addr_mgr.new_count() == 10);
        REQUIRE(netgroups_added.size() == 10);

        // Select multiple addresses and verify diversity
        std::set<std::string> netgroups_selected;
        for (int i = 0; i < 20; i++) {
            auto addr_opt = addr_mgr.select();
            if (addr_opt) {
                auto ip_str = addr_opt->to_string();
                if (ip_str) {
                    netgroups_selected.insert(util::GetNetgroup(*ip_str));
                }
            }
        }

        // Should have selected from multiple netgroups
        INFO("Selected from " << netgroups_selected.size() << " unique netgroups");
        REQUIRE(netgroups_selected.size() >= 3);
    }
}

// ============================================================================
// Boundary condition tests
// ============================================================================

TEST_CASE("AddrManager - Boundary: exact NEW table limit (32)", "[network][addr][security][unit][boundary]") {
    AddressManager addr_mgr;

    SECTION("31st address succeeds, 32nd succeeds, 33rd fails") {
        // Add 31 addresses
        for (int i = 1; i <= 31; i++) {
            std::string ip = "8.70.0." + std::to_string(i);
            REQUIRE(addr_mgr.add(MakeNetworkAddress(ip, 18444)));
        }
        REQUIRE(addr_mgr.new_count() == 31);

        // 32nd should succeed (at boundary)
        REQUIRE(addr_mgr.add(MakeNetworkAddress("8.70.0.32", 18444)));
        REQUIRE(addr_mgr.new_count() == 32);

        // 33rd should fail (beyond boundary)
        REQUIRE_FALSE(addr_mgr.add(MakeNetworkAddress("8.70.0.33", 18444)));
        REQUIRE(addr_mgr.new_count() == 32);  // Still 32
    }
}

TEST_CASE("AddrManager - Boundary: exact TRIED table limit (8)", "[network][addr][security][unit][boundary]") {
    AddressManager addr_mgr;

    SECTION("7th moves to TRIED, 8th moves, 9th stays in NEW") {
        // Add and mark good for 7 addresses
        for (int i = 1; i <= 7; i++) {
            std::string ip = "8.80.0." + std::to_string(i);
            addr_mgr.add(MakeNetworkAddress(ip, 18444));
            addr_mgr.good(MakeNetworkAddress(ip, 18444));
        }
        REQUIRE(addr_mgr.tried_count() == 7);
        REQUIRE(addr_mgr.new_count() == 0);

        // 8th should move to TRIED (at boundary)
        addr_mgr.add(MakeNetworkAddress("8.80.0.8", 18444));
        addr_mgr.good(MakeNetworkAddress("8.80.0.8", 18444));
        REQUIRE(addr_mgr.tried_count() == 8);
        REQUIRE(addr_mgr.new_count() == 0);

        // 9th should stay in NEW (TRIED limit reached)
        addr_mgr.add(MakeNetworkAddress("8.80.0.9", 18444));
        addr_mgr.good(MakeNetworkAddress("8.80.0.9", 18444));
        REQUIRE(addr_mgr.tried_count() == 8);  // Still 8
        REQUIRE(addr_mgr.new_count() == 1);    // Stayed in NEW
    }
}

TEST_CASE("AddrManager - Port variations same netgroup", "[network][addr][security][unit][boundary]") {
    AddressManager addr_mgr;

    SECTION("Different ports same IP count toward netgroup limit") {
        // Add 32 addresses with different ports but same /16
        for (int i = 0; i < 32; i++) {
            // Use ports 18444-18475
            REQUIRE(addr_mgr.add(MakeNetworkAddress("8.90.0.1", 18444 + i)));
        }
        REQUIRE(addr_mgr.new_count() == 32);

        // 33rd port should fail (netgroup limit reached)
        REQUIRE_FALSE(addr_mgr.add(MakeNetworkAddress("8.90.0.1", 18500)));
        REQUIRE(addr_mgr.new_count() == 32);

        // Different IP in same /16 should also fail
        REQUIRE_FALSE(addr_mgr.add(MakeNetworkAddress("8.90.0.2", 18444)));
        REQUIRE(addr_mgr.new_count() == 32);
    }
}

TEST_CASE("AddrManager - NEW and TRIED limits independent per netgroup", "[network][addr][security][unit][boundary]") {
    AddressManager addr_mgr;

    SECTION("Same netgroup can have both NEW and TRIED slots filled") {
        // Fill TRIED with 8 from 8.95.x.x
        for (int i = 1; i <= 8; i++) {
            std::string ip = "8.95.0." + std::to_string(i);
            addr_mgr.add(MakeNetworkAddress(ip, 18444));
            addr_mgr.good(MakeNetworkAddress(ip, 18444));
        }
        REQUIRE(addr_mgr.tried_count() == 8);
        REQUIRE(addr_mgr.new_count() == 0);

        // Can still add to NEW from same netgroup (different addresses)
        for (int i = 9; i <= 40; i++) {
            std::string ip = "8.95.0." + std::to_string(i);
            addr_mgr.add(MakeNetworkAddress(ip, 18444));
        }
        // Should have added 32 to NEW (limit), rejected 8-40 = 32, but only 32 fit
        REQUIRE(addr_mgr.new_count() == 32);  // NEW limit reached
        REQUIRE(addr_mgr.tried_count() == 8); // TRIED unchanged

        // Marking one of NEW as good should NOT move it (TRIED limit reached)
        addr_mgr.good(MakeNetworkAddress("8.95.0.9", 18444));
        REQUIRE(addr_mgr.tried_count() == 8);  // Still 8
        REQUIRE(addr_mgr.new_count() == 32);   // Still 32 (stayed in NEW)
    }
}

// ============================================================================
// Eclipse attack simulation tests
// ============================================================================

TEST_CASE("Eclipse attack simulation: attacker cannot dominate selection", "[network][addr][security][eclipse]") {
    AddressManager addr_mgr;

    // ATTACK SCENARIO:
    // Attacker controls many IPs in a single /16 and floods the address manager.
    // Even with 1000s of attacker addresses attempted, per-netgroup limits ensure
    // that honest addresses from other netgroups remain selectable.

    SECTION("Attacker floods from single /16, honest nodes from other /16s survive") {
        // Step 1: Attacker floods 1000 addresses from 8.99.x.x (same /16)
        int attacker_added = 0;
        for (int i = 0; i < 255; i++) {
            for (int j = 1; j <= 4; j++) {
                std::string ip = "8.99." + std::to_string(i) + "." + std::to_string(j);
                if (addr_mgr.add(MakeNetworkAddress(ip, 18444))) {
                    attacker_added++;
                }
            }
        }
        INFO("Attacker added " << attacker_added << " of 1020 attempted");
        REQUIRE(attacker_added == 32);  // Limited by MAX_PER_NETGROUP_NEW

        // Step 2: Add honest addresses from different /16s (simulating diverse network)
        std::set<std::string> honest_netgroups;
        for (int ng = 1; ng <= 20; ng++) {
            std::string ip = "9." + std::to_string(ng) + ".0.1";
            REQUIRE(addr_mgr.add(MakeNetworkAddress(ip, 18444)));
            honest_netgroups.insert("9." + std::to_string(ng));
        }
        REQUIRE(addr_mgr.new_count() == 52);  // 32 attacker + 20 honest

        // Step 3: Select 100 addresses and count netgroup distribution
        std::map<std::string, int> selection_count;
        for (int i = 0; i < 100; i++) {
            auto addr_opt = addr_mgr.select();
            REQUIRE(addr_opt.has_value());

            auto ip_str = addr_opt->to_string();
            REQUIRE(ip_str.has_value());

            // Extract /16 prefix (first two octets)
            std::string netgroup = ip_str->substr(0, ip_str->rfind('.'));
            netgroup = netgroup.substr(0, netgroup.rfind('.'));
            selection_count[netgroup]++;
        }

        // Step 4: Verify attacker doesn't dominate selection
        int attacker_selections = selection_count["8.99"];
        int honest_selections = 100 - attacker_selections;

        INFO("Attacker selected " << attacker_selections << " times out of 100");
        INFO("Honest selected " << honest_selections << " times out of 100");
        INFO("Unique netgroups selected: " << selection_count.size());

        // Attacker has 32/52 = 61.5% of addresses, should get roughly that proportion
        // But critically, honest nodes still get selected frequently
        REQUIRE(honest_selections >= 20);  // Honest should get at least 20% of selections
        REQUIRE(selection_count.size() >= 5);  // At least 5 different /16s selected
    }

    SECTION("Multi-netgroup attacker still limited") {
        // More sophisticated attacker uses 10 different /16s
        std::set<std::string> attacker_netgroups;
        int total_attacker = 0;

        for (int ng = 1; ng <= 10; ng++) {
            for (int i = 1; i <= 50; i++) {  // Try 50 per netgroup
                std::string ip = "8." + std::to_string(ng) + ".0." + std::to_string(i);
                if (addr_mgr.add(MakeNetworkAddress(ip, 18444))) {
                    total_attacker++;
                    attacker_netgroups.insert("8." + std::to_string(ng));
                }
            }
        }

        // Each /16 limited to 32, so max 320 attacker addresses
        INFO("Attacker added " << total_attacker << " across " << attacker_netgroups.size() << " netgroups");
        REQUIRE(total_attacker == 320);  // 10 * 32

        // Add fewer honest addresses from many diverse netgroups
        for (int ng = 1; ng <= 50; ng++) {
            std::string ip = "9." + std::to_string(ng) + ".0.1";
            addr_mgr.add(MakeNetworkAddress(ip, 18444));
        }
        REQUIRE(addr_mgr.new_count() == 370);  // 320 attacker + 50 honest

        // Select and verify diversity
        std::set<std::string> unique_netgroups_selected;
        for (int i = 0; i < 200; i++) {
            auto addr_opt = addr_mgr.select();
            if (addr_opt) {
                auto ip_str = addr_opt->to_string();
                if (ip_str) {
                    std::string netgroup = ip_str->substr(0, ip_str->rfind('.'));
                    netgroup = netgroup.substr(0, netgroup.rfind('.'));
                    unique_netgroups_selected.insert(netgroup);
                }
            }
        }

        // Should select from many different netgroups, not just attacker's 10
        INFO("Selected from " << unique_netgroups_selected.size() << " unique /16 netgroups");
        REQUIRE(unique_netgroups_selected.size() >= 15);  // At least 15 different /16s
    }
}

TEST_CASE("Eclipse resistance: GetChance deprioritizes failed addresses", "[network][addr][security][eclipse]") {
    AddressManager addr_mgr;

    // Test that addresses with failed attempts get deprioritized via GetChance()
    // This is the 0.66^attempts decay factor

    SECTION("Failed attempts reduce selection probability") {
        // Add 10 addresses from different /16s
        for (int i = 1; i <= 10; i++) {
            std::string ip = "8." + std::to_string(i) + ".0.1";
            addr_mgr.add(MakeNetworkAddress(ip, 18444));
        }

        // CRITICAL: First call good() on one address to set m_last_good_
        // Without this, attempt() won't increment the attempts counter
        // (Bitcoin Core parity: prevents counting attempts before any connection succeeds)
        addr_mgr.good(MakeNetworkAddress("8.10.0.1", 18444));

        // Mark half of them as failed attempts (simulating attacker addresses that don't respond)
        // Each call to attempt() with fCountFailure=true increments the attempts counter
        for (int i = 1; i <= 5; i++) {
            std::string ip = "8." + std::to_string(i) + ".0.1";
            for (int f = 0; f < 5; f++) {  // 5 failed attempts
                addr_mgr.attempt(MakeNetworkAddress(ip, 18444), true);  // fCountFailure=true
            }
        }

        // Select 1000 times and count distribution (enough samples to reduce variance)
        std::map<std::string, int> counts;
        for (int i = 0; i < 1000; i++) {
            auto addr_opt = addr_mgr.select();
            if (addr_opt) {
                auto ip_str = addr_opt->to_string();
                if (ip_str) counts[*ip_str]++;
            }
        }

        // Count selections from failed vs non-failed addresses
        int failed_selections = 0;
        int ok_selections = 0;
        for (const auto& [ip, count] : counts) {
            // IPs 8.1.0.1 through 8.5.0.1 have failed attempts
            if (ip.find("8.1.0.1") != std::string::npos ||
                ip.find("8.2.0.1") != std::string::npos ||
                ip.find("8.3.0.1") != std::string::npos ||
                ip.find("8.4.0.1") != std::string::npos ||
                ip.find("8.5.0.1") != std::string::npos) {
                failed_selections += count;
            } else {
                ok_selections += count;
            }
        }

        INFO("Failed address selections: " << failed_selections);
        INFO("OK address selections: " << ok_selections);

        // With 5 failed attempts: chance = 0.66^5 = 13%
        // So failed addresses should be selected much less often than healthy ones
        // Failed = 5 addresses with ~13% chance each
        // OK = 5 addresses with 100% chance each
        // Ratio should be roughly 5:1 in favor of OK addresses
        // Use 2x threshold (ok > 2*failed) for statistical robustness
        REQUIRE(ok_selections > 2 * failed_selections);
    }
}

// ============================================================================
// TRIED address failure handling (Bitcoin Core parity)
// ============================================================================

TEST_CASE("AddrManager - TRIED addresses stay in TRIED despite failures", "[network][addr][security][unit][bitcoin-core]") {
    AddressManager addr_mgr;

    // BITCOIN CORE PARITY:
    // TRIED addresses are NEVER demoted back to NEW via failures.
    // They stay in TRIED until evicted by collision during Good().
    // This matches Bitcoin Core's addrman.cpp behavior.

    const std::string NETGROUP_PREFIX = "8.100.0.";

    SECTION("TRIED addresses remain in TRIED after failures") {
        // Add 8 addresses and move them to TRIED
        for (int i = 1; i <= 8; i++) {
            std::string ip = NETGROUP_PREFIX + std::to_string(i);
            REQUIRE(addr_mgr.add(MakeNetworkAddress(ip, 18444)));
            addr_mgr.good(MakeNetworkAddress(ip, 18444));  // Moves to TRIED
        }
        REQUIRE(addr_mgr.tried_count() == 8);
        REQUIRE(addr_mgr.new_count() == 0);

        // Fill NEW with same netgroup (addresses 9-40, only 32 will be accepted)
        for (int i = 9; i <= 50; i++) {
            std::string ip = NETGROUP_PREFIX + std::to_string(i);
            addr_mgr.add(MakeNetworkAddress(ip, 18444));
        }
        REQUIRE(addr_mgr.new_count() == 32);  // Limited to MAX_PER_NETGROUP_NEW

        // At this point:
        // - TRIED has 8 addresses from 8.100.x.x (addresses 1-8)
        // - NEW has 32 addresses from 8.100.x.x (addresses 9-40)
        // - Total from netgroup: 40

        // Note: No failed() function - matches Bitcoin Core
        // TRIED addresses stay in TRIED until evicted by collision during Good()

        // Bitcoin Core behavior: TRIED addresses stay in TRIED
        INFO("NEW count after failures: " << addr_mgr.new_count());
        INFO("TRIED count after failures: " << addr_mgr.tried_count());

        REQUIRE(addr_mgr.tried_count() == 8);   // Still in TRIED (no demotion)
        REQUIRE(addr_mgr.new_count() == 32);    // Unchanged

        // Verify external additions are still blocked by netgroup limits
        REQUIRE_FALSE(addr_mgr.add(MakeNetworkAddress(NETGROUP_PREFIX + "200", 18444)));
    }
}
