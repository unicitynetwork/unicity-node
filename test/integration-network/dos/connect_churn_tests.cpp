#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/protocol.hpp"

using namespace unicity;
using namespace unicity::test;
using namespace unicity::protocol;

TEST_CASE("DoS: connect/disconnect churn does not ban", "[dos][churn]") {
    SimulatedNetwork net(59001);
    SimulatedNode victim(1, &net);

    // Repeatedly connect/disconnect from same address; ensure future connections allowed
    for (int i=0;i<30;i++) {
        SimulatedNode temp(100+i, &net);
        REQUIRE(temp.ConnectTo(victim.GetId()));
        uint64_t t=100; net.AdvanceTime(t);
        // Now disconnect temp by tearing down object scope at end of loop iteration
    }

    // Final attempt should still succeed (not banned)
    SimulatedNode last(999, &net);
    REQUIRE(last.ConnectTo(victim.GetId()));
}
