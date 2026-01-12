#include "catch_amalgamated.hpp"
#include "network/peer_lifecycle_manager.hpp"
#include "network/peer_discovery_manager.hpp"
#include "network/network_manager.hpp" // for ConnectionResult enum
#include "network/protocol.hpp"
#include <asio.hpp>
#include <atomic>

using namespace unicity;
using namespace unicity::network;

TEST_CASE("Outbound per-cycle and in-flight dedup", "[network][limits][dedup]") {
    asio::io_context io;
    PeerLifecycleManager plm(io, PeerLifecycleManager::Config{});
    PeerDiscoveryManager pdm(&plm);

    // Seed a single routable address so Select() would otherwise keep returning it
    protocol::NetworkAddress addr = protocol::NetworkAddress::from_string("93.184.216.34", protocol::ports::REGTEST);
    REQUIRE(pdm.addr_manager_for_test().add(addr));

    // Connect function that reports how many times it was invoked
    std::atomic<int> calls{0};

    auto is_running = [](){ return true; };
    auto connect_fn_success = [&](const protocol::NetworkAddress& a, ConnectionType /*conn_type*/){
        calls.fetch_add(1, std::memory_order_relaxed);
        // Simulate "initiated" (pending): Success means pending flag remains until callback clears it
        return ConnectionResult::Success;
    };

    // First cycle: we should attempt once (per-cycle dedup prevents multiple dials to same addr within the cycle)
    plm.AttemptOutboundConnections(is_running, connect_fn_success);
    REQUIRE(calls.load(std::memory_order_relaxed) == 1);

    // Second cycle: without in-flight dedup in the selector, we will attempt again
    plm.AttemptOutboundConnections(is_running, connect_fn_success);
    REQUIRE(calls.load(std::memory_order_relaxed) == 2);

    // Reset manager to isolate discouraged phase (pending from success phase shouldn't interfere)
    PeerLifecycleManager plm2(io, PeerLifecycleManager::Config{});
    PeerDiscoveryManager pdm2(&plm2);
    REQUIRE(pdm2.addr_manager_for_test().add(addr));

    // Now simulate immediate failure path which erases pending: discouraged result
    auto connect_fn_discouraged = [&](const protocol::NetworkAddress& a, ConnectionType /*conn_type*/){
        calls.fetch_add(1, std::memory_order_relaxed);
        return ConnectionResult::AddressDiscouraged; // immediate failure => pending cleared
    };

    // First discouraged cycle: attempt once (pending will be cleared by immediate failure)
    plm2.AttemptOutboundConnections(is_running, connect_fn_discouraged);
    REQUIRE(calls.load(std::memory_order_relaxed) == 3);

    // Second discouraged cycle: pending was cleared, so we can attempt again
    plm2.AttemptOutboundConnections(is_running, connect_fn_discouraged);
    REQUIRE(calls.load(std::memory_order_relaxed) == 4);
}
