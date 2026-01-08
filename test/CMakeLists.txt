# test2 - Rewritten tests using improved framework

# Network test infrastructure
add_library(test2_network_infra
    network-integration/infra/simulated_network.cpp
    network-integration/infra/simulated_node.cpp
    network-integration/infra/node_simulator.cpp
    network-integration/infra/network_bridged_transport.cpp
)

target_include_directories(test2_network_infra PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/test/network-integration/infra
    ${CMAKE_SOURCE_DIR}/test/network-integration
    ${CMAKE_SOURCE_DIR}/test
    ${CMAKE_SOURCE_DIR}/test/common
    ${Boost_INCLUDE_DIRS}
)

target_link_libraries(test2_network_infra PUBLIC
    network
)

# Enable test-only hooks for test infrastructure
target_compile_definitions(test2_network_infra PUBLIC UNICITY_TESTS=1)
# Enable test-only hooks in network library (PRIVATE - does not propagate to production)
target_compile_definitions(network PRIVATE UNICITY_TESTS=1)

# Transport-only minimalist library (to run RealTransport tests without building full network stack)
add_library(transport_only STATIC
    ${CMAKE_SOURCE_DIR}/src/network/real_transport.cpp
)

target_include_directories(transport_only PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(transport_only PUBLIC
    util
    asio
)

# Enable test-only hooks for transport-only build
 target_compile_definitions(transport_only PUBLIC UNICITY_TESTS=1)

# Minimal transport test executable
add_executable(transport_tests
    ${CMAKE_SOURCE_DIR}/test/common/catch_amalgamated.cpp
    common/test_logging.cpp
    network-integration/real_transport_tests.cpp
)

target_include_directories(transport_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/test
    ${CMAKE_SOURCE_DIR}/test/common
    ${Boost_INCLUDE_DIRS}
)

target_link_libraries(transport_tests PRIVATE
    transport_only
)

set_target_properties(transport_tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

add_test(NAME transport_tests COMMAND $<TARGET_FILE:transport_tests>)

# Test executable
add_executable(unicity_tests
    ${CMAKE_SOURCE_DIR}/test/common/catch_amalgamated.cpp  # Use existing Catch2
    common/test_logging.cpp
    network-integration/simple_test.cpp
    network-integration/malformed_message_tests.cpp
    network-integration/headers_sync_tests.cpp
    network-integration/multi_peer_sync_tests.cpp
    network-integration/dos/invalid_pow_tests.cpp
    network-integration/dos/orphan_spam_tests.cpp
    network-integration/dos/oversized_headers_tests.cpp
    network-integration/dos/low_work_headers_tests.cpp
    network-integration/dos/stalling_peer_tests.cpp
    network-integration/dos/out_of_order_headers_tests.cpp
    network-integration/dos/overflow_compactsize_tests.cpp
    network-integration/dos/reserve_guard_tests.cpp
    network-integration/dos/oversized_inv_tests.cpp
    network-integration/dos/oversized_addr_tests.cpp
    network-integration/dos/getheaders_oversize_tests.cpp
    network-integration/dos/per_peer_buffer_tests.cpp
    network-integration/dos/flood_buffer_overflow_tests.cpp
    network-integration/dos/inv_storm_throttling_tests.cpp
    network-integration/dos/addr_valid_flood_tests.cpp
    network-integration/dos/addr_echo_suppression_tests.cpp
    network-integration/dos/addr_rate_limiting_tests.cpp
    network-integration/dos/addr_eviction_performance_tests.cpp
    network-integration/dos/ping_pong_tests.cpp
    network-integration/dos/connect_churn_tests.cpp
    network-integration/dos/reannounce_ttl_tests.cpp
    network-integration/dos/dos_simulator_tests.cpp
    network-integration/dos/dos_portfolio_tests.cpp
    network-integration/dos/unknown_command_rate_limit_tests.cpp
    network-integration/dos/pre_verack_message_tests.cpp
    network-integration/dos/unconnecting_headers_tests.cpp
    network-integration/dos/misbehavior_overflow_tests.cpp
    network-integration/dos/subversion_length_tests.cpp
    network-integration/dos/timeout_dos_tests.cpp
    network-integration/block_announcement/basic_tests.cpp
    network-integration/block_announcement/edge_case_tests.cpp
    network-integration/block_announcement/peer_states_tests.cpp
    network-integration/block_announcement/block_relay_comprehensive_tests.cpp
    network-integration/block_announcement/block_relay_policy_tests.cpp
    network-integration/handshake/edge_case_tests.cpp
    network-integration/handshake/timeout_tests.cpp
    network-integration/handshake/handshake_session_attacks.cpp
    network-integration/limits/connection_limit_tests.cpp
    network-integration/limits/netgroup_boundary_tests.cpp
    network-integration/limits/slot_exhaustion_proof.cpp
    network-integration/limits/manual_slot_exclusion_tests.cpp
    network-integration/limits/outbound_dedup_tests.cpp
    network-integration/penalty_tests.cpp
    network-integration/peer/connection_tests.cpp
    network-integration/peer/peer_unit_tests.cpp
    network-integration/peer/adversarial_tests.cpp
    network-integration/peer/peer_regression_tests.cpp
    network-integration/peer/duplicate_connection_tests.cpp
    network-integration/peer/feeler_id_allocation_tests.cpp
    network-integration/peer/feeler_adversarial_tests.cpp
    network-integration/peer/sync_callback_connect_tests.cpp
    network-integration/peer/inbound_reject_cleanup_tests.cpp
    network-integration/peer/namespace_consistency_tests.cpp
    network-integration/peer/single_use_start_tests.cpp
    network-integration/peer/connection_metrics_tests.cpp
    network-integration/edge_case_tests.cpp
    network-integration/reorg_partition_tests.cpp
    network-integration/sync_ibd_tests.cpp
    network-integration/nat_manager_tests.cpp
    network-integration/invalidateblock_tests.cpp
    network-integration/conditions_tests.cpp
    network-integration/peer/peer_discovery_tests.cpp
    network-integration/banman_adversarial_tests.cpp
    network-integration/manager/header_sync_adversarial_tests.cpp
    network-integration/manager/header_sync_ibd_gating_tests.cpp
    network-integration/manager/header_sync_reselection_regression_tests.cpp
    network-integration/manager/ibd_gating_tests.cpp
    network-integration/manager/sync_started_reset_tests.cpp
    network-integration/manager/sync_peer_switching_tests.cpp
    integration-chain/orphan_dos_tests.cpp
    integration-chain/orphan_edge_case_tests.cpp
    integration-chain/orphan_integration_tests.cpp
    integration-chain/orphan_thread_safety_tests.cpp
    integration-chain/orphan_time_eviction_tests.cpp
    integration-chain/invalidateblock_chain_tests.cpp
    integration-chain/chain_e2e_tests.cpp
    network-integration/security/eclipse_attack_simulations.cpp
    network-integration/security/silent_peer_eclipse_tests.cpp
    network-integration/addr_manager_tests2.cpp
    network-integration/feeler_anchor_tests.cpp
    network-integration/anchors_integration_tests.cpp
    network-integration/addr/getaddr_router_tests.cpp
    network-integration/addr/getaddr_multi_node_tests.cpp
    network-integration/addr/addr_manager_netgroup_tests.cpp
    network-integration/addr/self_advertisement_integration_tests.cpp
    network-integration/addr/address_promotion_e2e_tests.cpp
    network-integration/self_advertisement_tests.cpp
    network-integration/real_transport_tests.cpp
    network-integration/real_transport_dos_tests.cpp
    network-integration/idle_timeout_tests.cpp
    network-integration/message_dispatcher_tests.cpp
    network-integration/rpc_integration_tests.cpp
    network-integration/infra/address_factory_tests.cpp
    network-integration/infra/peer_factory_tests.cpp
    network-integration/eviction/basic_eviction_tests.cpp
    network-integration/eviction/eviction_manager_tests.cpp
    network-integration/connection_flooding_tests.cpp
    network-integration/outbound_diversity_tests.cpp
)

target_include_directories(unicity_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/test/network-integration/infra
    ${CMAKE_SOURCE_DIR}/test/network-integration
    ${CMAKE_SOURCE_DIR}/test
    ${CMAKE_SOURCE_DIR}/test/common  # For catch_amalgamated.hpp
    ${Boost_INCLUDE_DIRS}
)

target_link_libraries(unicity_tests PRIVATE
    test2_network_infra
    network
)

# Define test-only macro to enable debug hooks in production code (tests only)
 target_compile_definitions(unicity_tests PRIVATE UNICITY_TESTS=1)

# Set output directory
set_target_properties(unicity_tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Enable testing
enable_testing()
add_test(NAME unicity_tests COMMAND $<TARGET_FILE:unicity_tests>)

# Wire-level Node Simulator (real TCP sockets) built under test tree
add_executable(node_simulator
    ${CMAKE_SOURCE_DIR}/test/wire/node_simulator.cpp
)

target_include_directories(node_simulator PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(node_simulator PRIVATE
    network
    asio
)

set_target_properties(node_simulator PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Stress test executable (separate to avoid killing machines by default)
add_executable(unicity_tests_stress
    ${CMAKE_SOURCE_DIR}/test/common/catch_amalgamated.cpp
    common/test_logging.cpp
    integration-chain/stress_threading_tests.cpp
    network-integration/startup_shutdown_tests.cpp
    unit/chain/timedata_stress_tests.cpp
    unit/chain/randomx_threading_stress_tests.cpp
)

target_include_directories(unicity_tests_stress PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/test
    ${CMAKE_SOURCE_DIR}/test/common
    ${Boost_INCLUDE_DIRS}
)

target_link_libraries(unicity_tests_stress PRIVATE
    network  # Transitively links chain and util
)

set_target_properties(unicity_tests_stress PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Include all unit tests EXCEPT stress tests (which are in unicity_tests_stress)
file(GLOB_RECURSE UNIT_TEST_SOURCES "${CMAKE_SOURCE_DIR}/test/unit/*.cpp")
# Exclude stress test files from main test executable
list(FILTER UNIT_TEST_SOURCES EXCLUDE REGEX ".*randomx_threading_stress_tests\\.cpp$")
list(FILTER UNIT_TEST_SOURCES EXCLUDE REGEX ".*timedata_stress_tests\\.cpp$")
if(UNIT_TEST_SOURCES)
 target_sources(unicity_tests PRIVATE ${UNIT_TEST_SOURCES})
endif()

# Custom test targets for different test suites
add_custom_target(test
    COMMAND ${CMAKE_BINARY_DIR}/bin/unicity_tests "~[stress]"
    DEPENDS unicity_tests
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running fast tests (excluding stress tests)"
)

add_custom_target(test-all
    COMMAND ${CMAKE_BINARY_DIR}/bin/unicity_tests
    DEPENDS unicity_tests
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running ALL tests (including stress tests - slow!)"
)

add_custom_target(test-stress
    COMMAND ${CMAKE_BINARY_DIR}/bin/unicity_tests "[stress]"
    DEPENDS unicity_tests
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running ONLY stress tests"
)

# =============================================================================
# Benchmark executable - Uses Catch2's built-in benchmarking support
# =============================================================================
add_executable(unicity_bench
    ${CMAKE_SOURCE_DIR}/test/common/catch_amalgamated.cpp
    ${CMAKE_SOURCE_DIR}/test/common/test_logging.cpp
    ${CMAKE_SOURCE_DIR}/test/benchmark/benchmark_main.cpp
    ${CMAKE_SOURCE_DIR}/test/benchmark/chain/header_validation_bench.cpp
    ${CMAKE_SOURCE_DIR}/test/benchmark/chain/randomx_bench.cpp
    ${CMAKE_SOURCE_DIR}/test/benchmark/network/addr_manager_bench.cpp
)

target_include_directories(unicity_bench PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/test
    ${CMAKE_SOURCE_DIR}/test/common
    ${Boost_INCLUDE_DIRS}
)

target_link_libraries(unicity_bench PRIVATE
    network  # Transitively links chain and util
)

# Enable benchmarking in Catch2
target_compile_definitions(unicity_bench PRIVATE
    CATCH_CONFIG_ENABLE_BENCHMARKING
    UNICITY_TESTS=1
)

set_target_properties(unicity_bench PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# =============================================================================
# NAT Manager Mock Tests - Tests nat_manager.cpp with mocked miniupnpc
# =============================================================================
# This builds nat_manager.cpp separately with mock UPnP functions to enable
# testing all code paths without requiring actual UPnP hardware.

add_executable(nat_manager_mock_tests
    ${CMAKE_SOURCE_DIR}/test/common/catch_amalgamated.cpp
    common/test_logging.cpp
    network-integration/infra/mock_upnp.cpp
    network-integration/nat_manager_mock_tests.cpp
    # Compile nat_manager.cpp directly (not via network library)
    ${CMAKE_SOURCE_DIR}/src/network/nat_manager.cpp
)

target_include_directories(nat_manager_mock_tests PRIVATE
    # Mock headers FIRST - so miniupnpc includes resolve to mocks
    ${CMAKE_SOURCE_DIR}/test/network-integration/infra
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/test
    ${CMAKE_SOURCE_DIR}/test/common
    ${Boost_INCLUDE_DIRS}
)

# Link against util (for logging) but NOT network or miniupnpc
# The mock_upnp.cpp provides the UPnP function implementations
target_link_libraries(nat_manager_mock_tests PRIVATE
    util
)

target_compile_definitions(nat_manager_mock_tests PRIVATE UNICITY_TESTS=1)

set_target_properties(nat_manager_mock_tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

add_test(NAME nat_manager_mock_tests COMMAND $<TARGET_FILE:nat_manager_mock_tests>)

# Custom targets for running benchmarks
add_custom_target(bench
    COMMAND ${CMAKE_BINARY_DIR}/bin/unicity_bench "[benchmark]"
    DEPENDS unicity_bench
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running all benchmarks"
)

add_custom_target(bench-chain
    COMMAND ${CMAKE_BINARY_DIR}/bin/unicity_bench "[benchmark][chain]"
    DEPENDS unicity_bench
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running chain benchmarks (header validation, orphans, reorgs)"
)

add_custom_target(bench-network
    COMMAND ${CMAKE_BINARY_DIR}/bin/unicity_bench "[benchmark][network]"
    DEPENDS unicity_bench
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running network benchmarks (AddressManager)"
)
