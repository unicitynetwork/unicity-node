#pragma once

#include "network/transport.hpp"
#include "util/logging.hpp"
#include <mutex>
#include <vector>
#include <memory>
#include <string>

namespace unicity {
namespace network {

// Simple transport mock for unit tests
class MockTransportConnection : public TransportConnection,
                                public std::enable_shared_from_this<MockTransportConnection> {
public:
    MockTransportConnection() : open_(true) {}
    MockTransportConnection(const std::string& address, uint16_t port = 9590)
        : open_(true), remote_address_(address), remote_port_(port) {}

    void start() override {}

    bool send(const std::vector<uint8_t>& data) override {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!open_) return false;
        sent_messages_.push_back(data);
        return true;
    }

    void close() override {
        open_ = false;
        if (disconnect_callback_) {
            disconnect_callback_();
        }
    }

    bool is_open() const override { return open_; }
    std::string remote_address() const override { return remote_address_; }
    uint16_t remote_port() const override { return remote_port_; }
    bool is_inbound() const override { return is_inbound_; }

    void set_receive_callback(ReceiveCallback callback) override { receive_callback_ = callback; }
    void set_disconnect_callback(DisconnectCallback callback) override { disconnect_callback_ = callback; }

    void set_inbound(bool inbound) { is_inbound_ = inbound; }

    void simulate_receive(const std::vector<uint8_t>& data) {
        if (receive_callback_) {
            receive_callback_(data);
        }
    }

    std::vector<std::vector<uint8_t>> get_sent_messages() {
        std::lock_guard<std::mutex> lock(mutex_);
        return sent_messages_;
    }

    void clear_sent_messages() {
        std::lock_guard<std::mutex> lock(mutex_);
        sent_messages_.clear();
    }

    size_t sent_message_count() {
        std::lock_guard<std::mutex> lock(mutex_);
        return sent_messages_.size();
    }

private:
    bool open_;
    bool is_inbound_ = false;
    std::string remote_address_ = "127.0.0.1";
    uint16_t remote_port_ = 9590;
    ReceiveCallback receive_callback_;
    DisconnectCallback disconnect_callback_;
    std::mutex mutex_;
    std::vector<std::vector<uint8_t>> sent_messages_;
};

} // namespace network
} // namespace unicity