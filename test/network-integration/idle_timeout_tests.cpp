#include "catch_amalgamated.hpp"
#include "util/hash.hpp"
#include "network/peer.hpp"
#include "network/message.hpp"
#include "infra/mock_transport.hpp"
#include <thread>

using namespace unicity;
using namespace unicity::network;
using namespace unicity::protocol;

namespace {
struct TimeoutGuard {
    TimeoutGuard(std::chrono::milliseconds hs, std::chrono::milliseconds idle) {
        Peer::SetTimeoutsForTest(hs, idle);
    }
    ~TimeoutGuard() { Peer::ResetTimeoutsForTest(); }
};

static std::vector<uint8_t> make_msg(const std::string& cmd, const std::vector<uint8_t>& payload){
    protocol::MessageHeader hdr(magic::REGTEST, cmd, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(hdr.checksum.data(), hash.begin(), 4);
    auto hdr_bytes = message::serialize_header(hdr);
    std::vector<uint8_t> full; full.reserve(hdr_bytes.size()+payload.size());
    full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
    full.insert(full.end(), payload.begin(), payload.end());
    return full;
}
}

TEST_CASE("Idle timeout disconnects after no activity", "[peer][idle][timeout][fast]") {
    TimeoutGuard guard(std::chrono::milliseconds(0), std::chrono::milliseconds(150));

    asio::io_context io;
    auto conn = std::make_shared<MockTransportConnection>();
    auto peer = Peer::create_outbound(io, conn, magic::REGTEST, 0);

    // Complete handshake
    peer->start();
    io.poll();
    message::VersionMessage ver; ver.version=PROTOCOL_VERSION; ver.services=NODE_NETWORK; ver.timestamp=123; ver.nonce=42; ver.user_agent="/t/"; ver.start_height=0;
    conn->simulate_receive(make_msg(commands::VERSION, ver.serialize()));
    io.poll();
    conn->simulate_receive(make_msg(commands::VERACK, {}));
    io.poll();
    REQUIRE(peer->state() == PeerConnectionState::READY);

    // No further activity -> expect disconnect after timeout
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    io.poll();
    CHECK(peer->state() == PeerConnectionState::DISCONNECTED);
}

TEST_CASE("Idle timer resets on activity and does not disconnect", "[peer][idle][timeout][fast]") {
    TimeoutGuard guard(std::chrono::milliseconds(0), std::chrono::milliseconds(300));

    asio::io_context io;
    auto conn = std::make_shared<MockTransportConnection>();
    auto peer = Peer::create_outbound(io, conn, magic::REGTEST, 0);

    // Complete handshake
    peer->start();
    io.poll();
    message::VersionMessage ver; ver.version=PROTOCOL_VERSION; ver.services=NODE_NETWORK; ver.timestamp=123; ver.nonce=42; ver.user_agent="/t/"; ver.start_height=0;
    conn->simulate_receive(make_msg(commands::VERSION, ver.serialize()));
    io.poll();
    conn->simulate_receive(make_msg(commands::VERACK, {}));
    io.poll();
    REQUIRE(peer->state() == PeerConnectionState::READY);

    // Keep activity: send small pings below threshold interval
    for (int i = 0; i < 5; ++i) {
        auto ping = std::make_unique<message::PingMessage>(static_cast<uint64_t>(i));
        peer->send_message(std::move(ping));
        io.poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // Sleep a bit less than timeout and process
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    io.poll();

    CHECK(peer->is_connected());
}
