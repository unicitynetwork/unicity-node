// Chain threading stress tests (ported to test2)

#include <catch_amalgamated.hpp>
#include "chain/chainstate_manager.hpp"
#include "chain/chainparams.hpp"
#include "chain/block.hpp"
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>

using namespace unicity;

TEST_CASE("Stress test: High concurrency validation", "[stress][threading]") {
    auto params = chain::ChainParams::CreateRegTest();
    validation::ChainstateManager chainstate(*params);
    CBlockHeader genesis = params->GenesisBlock();
    REQUIRE(chainstate.Initialize(genesis));

    const auto* genesis_index = chainstate.GetTip();
    REQUIRE(genesis_index != nullptr);
    chainstate.TryAddBlockIndexCandidate(const_cast<chain::CBlockIndex*>(genesis_index));

    SECTION("Hammer GetTip from many threads") {
        constexpr int NUM_THREADS = 16; constexpr int QUERIES_PER_THREAD = 1000;
        std::atomic<int> ok{0}, fail{0}; std::vector<std::thread> ts;
        for (int i=0;i<NUM_THREADS;i++) ts.emplace_back([&]{ for(int j=0;j<QUERIES_PER_THREAD;j++){ try{ auto* tip=chainstate.GetTip(); if(tip){ ok++; volatile int h=tip->nHeight; (void)h; } else fail++; } catch(...){ fail++; } } });
        for(auto& t:ts) t.join(); REQUIRE(ok == NUM_THREADS*QUERIES_PER_THREAD); REQUIRE(fail==0);
    }
}
