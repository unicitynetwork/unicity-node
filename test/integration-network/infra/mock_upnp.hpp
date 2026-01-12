// Mock implementation of miniupnpc for NAT manager testing
#pragma once

#include <atomic>
#include <cstring>
#include <string>

namespace unicity {
namespace test {

// Mock control structure - configure before calling NATManager methods
struct UPnPMockState {
    // Discovery behavior
    bool discover_success = false;
    int discover_error_code = 0;

    // IGD validation - 1 = valid IGD found
    int igd_result = 0;
    std::string control_url = "http://192.168.1.1:5000/ctl/IPConn";
    std::string service_type = "urn:schemas-upnp-org:service:WANIPConnection:1";
    std::string lan_addr = "192.168.1.100";

    // External IP
    bool get_external_ip_success = false;
    std::string external_ip = "203.0.113.1";

    // Port mapping
    bool add_mapping_success = false;
    int add_mapping_error = 0;
    bool delete_mapping_success = false;

    // Call counters
    std::atomic<int> discover_calls{0};
    std::atomic<int> get_igd_calls{0};
    std::atomic<int> get_external_ip_calls{0};
    std::atomic<int> add_mapping_calls{0};
    std::atomic<int> delete_mapping_calls{0};

    void reset() {
        discover_success = false;
        igd_result = 0;
        get_external_ip_success = false;
        add_mapping_success = false;
        delete_mapping_success = false;
        discover_calls = 0;
        get_igd_calls = 0;
        get_external_ip_calls = 0;
        add_mapping_calls = 0;
        delete_mapping_calls = 0;
    }

    void configure_success() {
        discover_success = true;
        igd_result = 1;
        get_external_ip_success = true;
        add_mapping_success = true;
        delete_mapping_success = true;
    }

    void configure_no_gateway() {
        discover_success = false;
        discover_error_code = -1;
    }
};

inline UPnPMockState& GetUPnPMock() {
    static UPnPMockState state;
    return state;
}

}  // namespace test
}  // namespace unicity
