#include "catch_amalgamated.hpp"
#include "network/peer.hpp"
#include "infra/mock_transport.hpp"
#include "util/logging.hpp"
#include <asio.hpp>
#include <memory>
#include <sstream>
#include <spdlog/sinks/ostream_sink.h>

using namespace unicity;
using namespace unicity::network;

TEST_CASE("Peer start() is single-use: duplicate and restart attempts are ignored", "[peer][lifecycle][single_use]") {
    // Outbound peer with an open mock connection starts in CONNECTED state
    asio::io_context io;
    auto conn = std::make_shared<MockTransportConnection>();
    const uint32_t magic = protocol::magic::REGTEST;
    auto peer = Peer::create_outbound(io, conn, magic, /*start_height=*/0);

    // Attach a temporary sink to capture network logs (and suppress console output)
    auto net_logger = unicity::util::LogManager::GetLogger("network");
    auto old_level = net_logger->level();
    std::ostringstream oss;
    auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(oss);
    sink->set_level(spdlog::level::err);
    auto& sinks = net_logger->sinks();
    // Temporarily disable all existing sinks by setting logger to off, add our sink, then set to err
    net_logger->set_level(spdlog::level::off);
    sinks.push_back(sink);
    // Set our sink to capture errors, but set other sinks to off via pattern
    for (size_t i = 0; i < sinks.size() - 1; ++i) {
        sinks[i]->set_level(spdlog::level::off);
    }
    net_logger->set_level(spdlog::level::err);

    // 1) First start() should send exactly one VERSION
    peer->start();
    io.poll();
    io.restart();
    REQUIRE(conn->sent_message_count() == 1);

    // 2) Second start() while still connected should be ignored (no extra send)
    peer->start();
    io.poll();
    io.restart();
    CHECK(conn->sent_message_count() == 1);

    // 3) After disconnect, start() again should be rejected and log an error mentioning single-use
    peer->disconnect();
    io.poll();
    io.restart();
    REQUIRE(peer->state() == PeerConnectionState::DISCONNECTED);

    peer->start();
    io.poll();
    io.restart();

    // Verify error log emitted
    auto logs = oss.str();
    CHECK(logs.find("single-use") != std::string::npos);

    // Cleanup: restore original sink levels and remove our sink
    for (size_t i = 0; i < sinks.size() - 1; ++i) {
        sinks[i]->set_level(spdlog::level::trace);  // Restore default sink level
    }
    sinks.pop_back();
    net_logger->set_level(old_level);
}