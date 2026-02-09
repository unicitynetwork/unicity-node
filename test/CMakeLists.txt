# test2 - Rewritten tests using improved framework

# Network test infrastructure
add_library(test2_network_infra
    integration-network/infra/simulated_network.cpp
    integration-network/infra/simulated_node.cpp
    integration-network/infra/node_simulator.cpp
    integration-network/infra/network_bridged_transport.cpp
    integration-network/infra/test_access.cpp
)

target_include_directories(test2_network_infra PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/test/integration-network/infra
    ${CMAKE_SOURCE_DIR}/test/integration-network
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
    integration-network/real_transport_tests.cpp
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
    integration-network/simple_test.cpp
    integration-network/network_component_tests.cpp
    integration-network/network_header_sync_tests.cpp
    integration-network/network_header_sync_edge_tests.cpp
    integration-network/permission_tests.cpp
    integration-network/post_ibd_inv_sync_tests.cpp
    integration-network/rate_limiter_integration_tests.cpp
    integration-network/malformed_message_tests.cpp
    integration-network/headers_sync_tests.cpp
    integration-network/multi_peer_sync_tests.cpp
    integration-network/dos/oversized_headers_tests.cpp
    integration-network/dos/stalling_peer_tests.cpp
    integration-network/dos/header_withholding_tests.cpp
    integration-network/dos/overflow_compactsize_tests.cpp
    integration-network/dos/reserve_guard_tests.cpp
    integration-network/dos/oversized_addr_tests.cpp
    integration-network/dos/getheaders_oversize_tests.cpp
    integration-network/dos/per_peer_buffer_tests.cpp
    integration-network/dos/flood_buffer_overflow_tests.cpp
    integration-network/dos/inv_storm_throttling_tests.cpp
    integration-network/dos/addr_valid_flood_tests.cpp
    integration-network/dos/addr_echo_suppression_tests.cpp
    integration-network/dos/addr_rate_limiting_tests.cpp
    integration-network/dos/ping_pong_tests.cpp
    integration-network/dos/connect_churn_tests.cpp
    integration-network/dos/dos_simulator_tests.cpp
    integration-network/dos/dos_portfolio_tests.cpp
    integration-network/dos/pre_verack_message_tests.cpp
    integration-network/dos/misbehavior_overflow_tests.cpp
    integration-network/dos/subversion_length_tests.cpp
    integration-network/dos/timeout_dos_tests.cpp
    integration-network/block_announcement/basic_tests.cpp
    integration-network/block_announcement/block_relay_comprehensive_tests.cpp
    integration-network/block_announcement/block_relay_policy_tests.cpp
    integration-network/block_announcement/core_aligned_smoke_tests.cpp
    integration-network/block_announcement/integration_tests.cpp
    integration-network/block_announcement/ibd_relay_suppression_tests.cpp
    integration-network/block_announcement/extra_block_relay_rotation_tests.cpp
    integration-network/handshake/edge_case_tests.cpp
    integration-network/handshake/timeout_tests.cpp
    integration-network/handshake/handshake_session_attacks.cpp
    integration-network/limits/connection_limit_tests.cpp
    integration-network/limits/slot_exhaustion_proof.cpp
    integration-network/limits/manual_slot_exclusion_tests.cpp
    integration-network/limits/outbound_dedup_tests.cpp
    integration-network/penalty_tests.cpp
    integration-network/peer/connection_tests.cpp
    integration-network/peer/peer_unit_tests.cpp
    integration-network/peer/adversarial_tests.cpp
    integration-network/peer/peer_regression_tests.cpp
    integration-network/peer/duplicate_connection_tests.cpp
    integration-network/peer/feeler_id_allocation_tests.cpp
    integration-network/peer/feeler_adversarial_tests.cpp
    integration-network/peer/sync_callback_connect_tests.cpp
    integration-network/peer/inbound_reject_cleanup_tests.cpp
    integration-network/peer/single_use_start_tests.cpp
    integration-network/peer/connection_metrics_tests.cpp
    integration-network/edge_case_tests.cpp
    integration-network/reorg_partition_tests.cpp
    integration-network/sync_ibd_tests.cpp
    integration-network/ibd_resume_tests.cpp
    integration-network/nat_manager_tests.cpp
    integration-network/invalidateblock_tests.cpp
    integration-network/conditions_tests.cpp
    integration-network/peer/peer_discovery_tests.cpp
    integration-network/banman_adversarial_tests.cpp
    integration-network/bitcoin_core_parity_tests.cpp
    integration-network/manager/header_sync_adversarial_tests.cpp
    integration-network/manager/header_sync_ibd_gating_tests.cpp
    integration-network/manager/header_sync_reselection_regression_tests.cpp
    integration-network/manager/ibd_gating_tests.cpp
    integration-network/manager/sync_started_reset_tests.cpp
    integration-network/manager/sync_peer_switching_tests.cpp
    integration-network/manager/sync_peer_edge_case_tests.cpp
    integration-network/manager/getheaders_throttling_tests.cpp
    integration-network/manager/getheaders_throttle_bypass_tests.cpp
    integration-network/manager/timeout_interaction_tests.cpp
    integration-network/manager/chain_sync_timeout_tests.cpp
    integration-chain/invalidateblock_chain_tests.cpp
    integration-chain/chain_e2e_tests.cpp
    integration-chain/reorg_multi_node_tests.cpp
    integration-network/security/eclipse_attack_simulations.cpp
    integration-network/security/silent_peer_eclipse_tests.cpp
    integration-network/security/fingerprint_protection_tests.cpp
    integration-network/addr_manager_tests2.cpp
    integration-network/feeler_anchor_tests.cpp
    integration-network/anchors_integration_tests.cpp
    integration-network/addr/getaddr_router_tests.cpp
    integration-network/addr/getaddr_multi_node_tests.cpp
    integration-network/addr/getaddr_cache_adversarial_tests.cpp
    integration-network/addr/topology_privacy_tests.cpp
    integration-network/addr/addr_relay_timing_tests.cpp
    integration-network/addr/addr_relay_dedup_tests.cpp
    integration-network/addr/addr_relay_coordinated_attack_tests.cpp
    integration-network/addr/addr_relay_prediction_tests.cpp
    integration-network/addr/addr_manager_netgroup_tests.cpp
    integration-network/addr/self_advertisement_integration_tests.cpp
    integration-network/addr/address_promotion_e2e_tests.cpp
    integration-network/self_advertisement_tests.cpp
    integration-network/nat_integration_tests.cpp
    integration-network/real_transport_tests.cpp
    integration-network/real_transport_dos_tests.cpp
    integration-network/tcp_fragmentation_tests.cpp
    integration-network/idle_timeout_tests.cpp
    integration-network/message_dispatcher_tests.cpp
    integration-network/rpc_integration_tests.cpp
    integration-network/infra/address_factory_tests.cpp
    integration-network/infra/peer_factory_tests.cpp
    integration-network/eviction/basic_eviction_tests.cpp
    integration-network/eviction/eviction_manager_tests.cpp
    integration-network/connection_flooding_tests.cpp
    integration-network/outbound_diversity_tests.cpp
)

target_include_directories(unicity_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/test/integration-network/infra
    ${CMAKE_SOURCE_DIR}/test/integration-network
    ${CMAKE_SOURCE_DIR}/test
    ${CMAKE_SOURCE_DIR}/test/common  # For catch_amalgamated.hpp
    ${Boost_INCLUDE_DIRS}
)

target_link_libraries(unicity_tests PRIVATE
    test2_network_infra
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
    integration-network/startup_shutdown_tests.cpp
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

# Address simulation executable (separate tool for large-scale address relay testing)
add_executable(addr_simulation
    ${CMAKE_SOURCE_DIR}/test/common/catch_amalgamated.cpp
    common/test_logging.cpp
    addr-simulation/scenarios/propagation_tests.cpp
    addr-simulation/scenarios/eclipse_attack_tests.cpp
    addr-simulation/scenarios/sybil_attack_tests.cpp
    addr-simulation/scenarios/timestamp_attack_tests.cpp
    addr-simulation/scenarios/eviction_attack_tests.cpp
    addr-simulation/scenarios/fingerprinting_tests.cpp
    addr-simulation/scenarios/feeler_tests.cpp
    addr-simulation/scenarios/longrun_health_tests.cpp
    addr-simulation/scenarios/topology_tests.cpp
    addr-simulation/scenarios/mixed_network_tests.cpp
    addr-simulation/scenarios/attempt_tracking_tests.cpp
    addr-simulation/scenarios/time_penalty_tests.cpp
    addr-simulation/scenarios/memory_limits_tests.cpp
    addr-simulation/scenarios/ipv6_netgroup_tests.cpp
    addr-simulation/scenarios/bucketization_gap_tests.cpp
    addr-simulation/scenarios/multi_source_tests.cpp
    addr-simulation/scenarios/network_scale_tests.cpp
)

target_include_directories(addr_simulation PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/test
    ${CMAKE_SOURCE_DIR}/test/common
    ${CMAKE_SOURCE_DIR}/test/addr-simulation
    ${Boost_INCLUDE_DIRS}
)

target_link_libraries(addr_simulation PRIVATE
    network
)

set_target_properties(addr_simulation PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Eviction simulation executable (large-scale eviction behavior testing)
add_executable(eviction_simulation
    ${CMAKE_SOURCE_DIR}/test/common/catch_amalgamated.cpp
    common/test_logging.cpp
    eviction-simulation/scenarios/eclipse_resistance_tests.cpp
    eviction-simulation/scenarios/block_relay_rotation_tests.cpp
    eviction-simulation/scenarios/slot_stress_tests.cpp
    eviction-simulation/scenarios/netgroup_diversity_tests.cpp
    eviction-simulation/scenarios/eviction_protection_tests.cpp
    eviction-simulation/scenarios/network_scale_tests.cpp
    eviction-simulation/scenarios/advanced_eviction_tests.cpp
)

target_include_directories(eviction_simulation PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/test
    ${CMAKE_SOURCE_DIR}/test/common
    ${CMAKE_SOURCE_DIR}/test/eviction-simulation
    ${Boost_INCLUDE_DIRS}
)

target_link_libraries(eviction_simulation PRIVATE
    util
    network  # For real EvictionManager
)

set_target_properties(eviction_simulation PROPERTIES
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
    integration-network/infra/mock_upnp.cpp
    integration-network/nat_manager_mock_tests.cpp
    # Compile nat_manager.cpp directly (not via network library)
    ${CMAKE_SOURCE_DIR}/src/network/nat_manager.cpp
)

target_include_directories(nat_manager_mock_tests PRIVATE
    # Mock headers FIRST - so miniupnpc includes resolve to mocks
    ${CMAKE_SOURCE_DIR}/test/integration-network/infra
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
    COMMENT "Running chain benchmarks (header validation, reorgs)"
)

add_custom_target(bench-network
    COMMAND ${CMAKE_BINARY_DIR}/bin/unicity_bench "[benchmark][network]"
    DEPENDS unicity_bench
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running network benchmarks (AddressManager)"
)
