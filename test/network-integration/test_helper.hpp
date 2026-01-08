#ifndef UNICITY_TEST2_HELPER_HPP
#define UNICITY_TEST2_HELPER_HPP

#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "infra/node_simulator.hpp"
#include "chain/chainparams.hpp"
#include <catch_amalgamated.hpp>

namespace unicity {
namespace test {

static struct Test2Setup {
    Test2Setup() {
        chain::GlobalChainParams::Select(chain::ChainType::REGTEST);
    }
} test2_setup;

} // namespace test
} // namespace unicity

#endif
