// Unit tests for ConnectionType enum and helper functions
#include "catch_amalgamated.hpp"
#include "network/connection_types.hpp"

using namespace unicity::network;

TEST_CASE("ConnectionType - String conversion", "[network][connection_types]") {
    SECTION("INBOUND converts to 'inbound'") {
        CHECK(ConnectionTypeAsString(ConnectionType::INBOUND) == "inbound");
    }

    SECTION("OUTBOUND_FULL_RELAY converts to 'outbound-full-relay'") {
        CHECK(ConnectionTypeAsString(ConnectionType::OUTBOUND_FULL_RELAY) == "outbound-full-relay");
    }

    SECTION("BLOCK_RELAY converts to 'block-relay-only'") {
        CHECK(ConnectionTypeAsString(ConnectionType::BLOCK_RELAY) == "block-relay-only");
    }

    SECTION("MANUAL converts to 'manual'") {
        CHECK(ConnectionTypeAsString(ConnectionType::MANUAL) == "manual");
    }

    SECTION("FEELER converts to 'feeler'") {
        CHECK(ConnectionTypeAsString(ConnectionType::FEELER) == "feeler");
    }

    SECTION("Invalid value converts to 'unknown'") {
        // Cast to an invalid enum value
        ConnectionType invalid = static_cast<ConnectionType>(999);
        CHECK(ConnectionTypeAsString(invalid) == "unknown");
    }
}

TEST_CASE("ConnectionType - Enum values", "[network][connection_types]") {
    SECTION("Enum values are distinct") {
        CHECK(ConnectionType::INBOUND != ConnectionType::OUTBOUND_FULL_RELAY);
        CHECK(ConnectionType::INBOUND != ConnectionType::BLOCK_RELAY);
        CHECK(ConnectionType::INBOUND != ConnectionType::MANUAL);
        CHECK(ConnectionType::INBOUND != ConnectionType::FEELER);
        CHECK(ConnectionType::OUTBOUND_FULL_RELAY != ConnectionType::BLOCK_RELAY);
        CHECK(ConnectionType::OUTBOUND_FULL_RELAY != ConnectionType::MANUAL);
        CHECK(ConnectionType::OUTBOUND_FULL_RELAY != ConnectionType::FEELER);
        CHECK(ConnectionType::BLOCK_RELAY != ConnectionType::MANUAL);
        CHECK(ConnectionType::BLOCK_RELAY != ConnectionType::FEELER);
        CHECK(ConnectionType::MANUAL != ConnectionType::FEELER);
    }

    SECTION("Can assign and compare enum values") {
        ConnectionType type1 = ConnectionType::INBOUND;
        ConnectionType type2 = ConnectionType::INBOUND;
        ConnectionType type3 = ConnectionType::OUTBOUND_FULL_RELAY;

        CHECK(type1 == type2);
        CHECK(type1 != type3);
    }
}

TEST_CASE("ConnectionType - Usage patterns", "[network][connection_types]") {
    SECTION("Can use in switch statements") {
        auto get_description = [](ConnectionType type) -> std::string {
            switch (type) {
            case ConnectionType::INBOUND:
                return "Connection initiated by peer";
            case ConnectionType::OUTBOUND_FULL_RELAY:
                return "Default full-relay connection";
            case ConnectionType::BLOCK_RELAY:
                return "Block-relay-only connection";
            case ConnectionType::MANUAL:
                return "User-requested connection";
            case ConnectionType::FEELER:
                return "Short-lived test connection";
            default:
                return "Unknown";
            }
        };

        CHECK(get_description(ConnectionType::INBOUND) == "Connection initiated by peer");
        CHECK(get_description(ConnectionType::OUTBOUND_FULL_RELAY) == "Default full-relay connection");
        CHECK(get_description(ConnectionType::BLOCK_RELAY) == "Block-relay-only connection");
        CHECK(get_description(ConnectionType::MANUAL) == "User-requested connection");
        CHECK(get_description(ConnectionType::FEELER) == "Short-lived test connection");
    }

    SECTION("String representation is consistent") {
        // Calling multiple times should give same result
        CHECK(ConnectionTypeAsString(ConnectionType::INBOUND) ==
              ConnectionTypeAsString(ConnectionType::INBOUND));
        CHECK(ConnectionTypeAsString(ConnectionType::FEELER) ==
              ConnectionTypeAsString(ConnectionType::FEELER));
    }
}

TEST_CASE("ConnectionType - RelaysAddr helper", "[network][connection_types]") {
    SECTION("Full-relay and inbound connections relay addresses") {
        CHECK(RelaysAddr(ConnectionType::OUTBOUND_FULL_RELAY) == true);
        CHECK(RelaysAddr(ConnectionType::INBOUND) == true);
    }

    SECTION("Block-relay, manual, and feeler connections do NOT relay addresses") {
        CHECK(RelaysAddr(ConnectionType::BLOCK_RELAY) == false);
        CHECK(RelaysAddr(ConnectionType::MANUAL) == false);
        CHECK(RelaysAddr(ConnectionType::FEELER) == false);
    }
}

TEST_CASE("ConnectionType - Helper functions", "[network][connection_types]") {
    SECTION("IsFullRelayConn") {
        CHECK(IsFullRelayConn(ConnectionType::OUTBOUND_FULL_RELAY) == true);
        CHECK(IsFullRelayConn(ConnectionType::BLOCK_RELAY) == false);
        CHECK(IsFullRelayConn(ConnectionType::INBOUND) == false);
        CHECK(IsFullRelayConn(ConnectionType::MANUAL) == false);
        CHECK(IsFullRelayConn(ConnectionType::FEELER) == false);
    }

    SECTION("IsBlockRelayConn") {
        CHECK(IsBlockRelayConn(ConnectionType::BLOCK_RELAY) == true);
        CHECK(IsBlockRelayConn(ConnectionType::OUTBOUND_FULL_RELAY) == false);
        CHECK(IsBlockRelayConn(ConnectionType::INBOUND) == false);
        CHECK(IsBlockRelayConn(ConnectionType::MANUAL) == false);
        CHECK(IsBlockRelayConn(ConnectionType::FEELER) == false);
    }

    SECTION("IsOutboundConn") {
        CHECK(IsOutboundConn(ConnectionType::OUTBOUND_FULL_RELAY) == true);
        CHECK(IsOutboundConn(ConnectionType::BLOCK_RELAY) == true);
        CHECK(IsOutboundConn(ConnectionType::MANUAL) == true);
        CHECK(IsOutboundConn(ConnectionType::FEELER) == true);
        CHECK(IsOutboundConn(ConnectionType::INBOUND) == false);
    }
}
