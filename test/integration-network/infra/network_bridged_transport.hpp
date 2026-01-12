#ifndef UNICITY_TEST_NETWORK_BRIDGED_TRANSPORT_HPP
#define UNICITY_TEST_NETWORK_BRIDGED_TRANSPORT_HPP

#include "network/transport.hpp"
#include "network/protocol.hpp"
#include "simulated_network.hpp"
#include <atomic>
#include <map>
#include <mutex>
#include <memory>

namespace unicity {
namespace test {

/**
 * NetworkBridgedTransport - Routes Transport calls to SimulatedNetwork
 *
 * This transport routes messages through SimulatedNetwork to support:
 * - Simulated latency
 * - Packet loss
 * - Network partitions
 * - Deterministic message delivery
 *
 * Each SimulatedNode gets its own NetworkBridgedTransport instance.
 */
class NetworkBridgedTransport : public network::Transport {
public:
    NetworkBridgedTransport(int node_id, SimulatedNetwork* sim_network);
    ~NetworkBridgedTransport() override;

    // Transport interface
    network::TransportConnectionPtr connect(
        const std::string& address,
        uint16_t port,
        network::ConnectCallback callback
    ) override;

    bool listen(
        uint16_t port,
        std::function<void(network::TransportConnectionPtr)> accept_callback
    ) override;

    void stop_listening() override;
    void run() override;
    void stop() override;
    bool is_running() const override { return running_; }

    // Process incoming message from SimulatedNetwork
    void deliver_message(int from_node_id, const std::vector<uint8_t>& data);

    // Notify peer of disconnect
    void notify_peer_disconnect(int peer_node_id, int disconnecting_node_id);

    // Handle remote disconnect notification (called by SimulatedNetwork)
    void handle_remote_disconnect(int disconnecting_node_id);

private:
    class BridgedConnection;
    friend class BridgedConnection;

    int node_id_;
    SimulatedNetwork* sim_network_;
    std::atomic<bool> running_{false};

    // Listening state
    uint16_t listen_port_ = 0;
    std::function<void(network::TransportConnectionPtr)> accept_callback_;

    // Connections registry
    std::mutex connections_mutex_;
    std::map<uint64_t, std::weak_ptr<BridgedConnection>> connections_;
    std::atomic<uint64_t> next_connection_id_{1};

    // Map peer node_id -> connection_id (for incoming messages)
    std::mutex peer_map_mutex_;
    std::map<int, uint64_t> peer_to_connection_;
};

/**
 * BridgedConnection - Individual connection that routes through SimulatedNetwork
 */
class NetworkBridgedTransport::BridgedConnection
    : public network::TransportConnection,
      public std::enable_shared_from_this<BridgedConnection> {
public:
    BridgedConnection(
        uint64_t id,
        bool is_inbound,
        int peer_node_id,
        NetworkBridgedTransport* transport
    );

    ~BridgedConnection() override;

    // TransportConnection interface
    void start() override;
    bool send(const std::vector<uint8_t>& data) override;
    void close() override;
    bool is_open() const override { return open_; }
    std::string remote_address() const override;
    uint16_t remote_port() const override { return protocol::ports::REGTEST + peer_node_id_; }
    bool is_inbound() const override { return is_inbound_; }
    uint64_t connection_id() const override { return id_; }
    void set_receive_callback(network::ReceiveCallback callback) override;
    void set_disconnect_callback(network::DisconnectCallback callback) override;

    // Deliver data from SimulatedNetwork
    void deliver_data(const std::vector<uint8_t>& data);

    // Handle remote disconnect (close without notifying peer again)
    void close_from_remote();

    int peer_node_id() const { return peer_node_id_; }

private:
    uint64_t id_;
    bool is_inbound_;
    int peer_node_id_;  // Node ID of the peer
    NetworkBridgedTransport* transport_;
    std::atomic<bool> open_{true};

    network::ReceiveCallback receive_callback_;
    network::DisconnectCallback disconnect_callback_;
};

} // namespace test
} // namespace unicity

#endif // UNICITY_TEST_NETWORK_BRIDGED_TRANSPORT_HPP
