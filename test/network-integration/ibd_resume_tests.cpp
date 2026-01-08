#include "catch_amalgamated.hpp"
#include "network/protocol.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include <filesystem>
#include <chrono>

using namespace unicity;
using namespace unicity::test;

TEST_CASE("Chainstate persistence - save and load headers", "[ibd][network][persistence]") {
    // NOTE: Mid-sync resume with timing constraints is tested in the functional test
    // (feature_ibd_restart_resume.py) which uses real nodes and log parsing.
    // This unit test validates that the save/load mechanism itself works correctly.

    SimulatedNetwork net(/*seed=*/424242);

    // Miner with a moderate chain
    SimulatedNode miner(1, &net);
    const auto& consensus = miner.GetChainstate().GetParams().GetConsensus();
    const int expiration = consensus.nNetworkExpirationInterval;
    // Use a reasonable chain length that stays under expiration limits
    const int CHAIN_LEN = (expiration > 0) ? (expiration * 8 / 10) : 500;

    for (int i = 0; i < CHAIN_LEN; ++i) {
        (void)miner.MineBlock();
    }
    REQUIRE(miner.GetTipHeight() == CHAIN_LEN);

    // Syncing node - let it fully sync
    auto sync = std::make_unique<SimulatedNode>(2, &net);
    REQUIRE(sync->ConnectTo(miner.GetId()));

    uint64_t t = 1000;
    t += 2000; net.AdvanceTime(t);  // Handshake

    // Advance time to allow full sync
    for (int i = 0; i < 20 && sync->GetTipHeight() < CHAIN_LEN; ++i) {
        t += 10'000;
        net.AdvanceTime(t);
    }

    int synced_height = sync->GetTipHeight();
    REQUIRE(synced_height > 0);  // Should have synced something
    uint256 synced_tip = sync->GetTipHash();

    // Save chainstate
    const std::filesystem::path tmp_path =
        std::filesystem::temp_directory_path() / "cbc_chainstate_persist.json";
    REQUIRE(sync->GetChainstate().Save(tmp_path.string()));

    // Destroy and recreate node
    sync.reset();
    sync = std::make_unique<SimulatedNode>(3, &net);

    // Load saved state
    REQUIRE(sync->GetChainstate().Load(tmp_path.string()) == chain::LoadResult::SUCCESS);

    // Verify restored state matches
    REQUIRE(sync->GetTipHeight() == synced_height);
    REQUIRE(sync->GetTipHash() == synced_tip);

    // Cleanup
    std::filesystem::remove(tmp_path);
}
