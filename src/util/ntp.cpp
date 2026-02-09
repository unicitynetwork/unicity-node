// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "util/ntp.hpp"

#include <array>
#include <chrono>
#include <cstring>
#include <ctime>

#include <asio.hpp>

namespace unicity {
namespace util {

// NTP epoch starts 1900-01-01, Unix epoch starts 1970-01-01.
// Difference: 70 years including 17 leap years = 2208988800 seconds.
static constexpr uint32_t NTP_UNIX_EPOCH_DIFF = 2208988800U;

// SNTP packet size (RFC 4330)
static constexpr size_t NTP_PACKET_SIZE = 48;

std::optional<int64_t> CheckNTPOffset(const std::string& server, int timeout_sec) {
  try {
    asio::io_context io;

    // Resolve NTP server
    asio::ip::udp::resolver resolver(io);
    auto endpoints = resolver.resolve(asio::ip::udp::v4(), server, "123");

    asio::ip::udp::socket socket(io, asio::ip::udp::v4());

    // Build SNTP request: 48 bytes, byte 0 = 0x1B (LI=0, VN=3, Mode=3/client)
    std::array<uint8_t, NTP_PACKET_SIZE> request{};
    request[0] = 0x1B;

    // Record system time just before sending
    auto t1 = std::time(nullptr);

    // Send to first resolved endpoint
    socket.send_to(asio::buffer(request), *endpoints.begin());

    // Set up receive with timeout
    std::array<uint8_t, NTP_PACKET_SIZE> response{};
    bool received = false;
    std::size_t bytes_received = 0;

    // Use async receive with a deadline timer for timeout
    asio::ip::udp::endpoint sender;
    asio::steady_timer deadline(io, std::chrono::seconds(timeout_sec));

    deadline.async_wait([&](const asio::error_code&) {
      if (!received) {
        socket.cancel();
      }
    });

    socket.async_receive_from(
        asio::buffer(response), sender,
        [&](const asio::error_code& ec, std::size_t len) {
          if (!ec && len >= NTP_PACKET_SIZE) {
            received = true;
            bytes_received = len;
          }
          deadline.cancel();
        });

    io.run();

    if (!received || bytes_received < NTP_PACKET_SIZE) {
      return std::nullopt;
    }

    // Record system time just after receiving
    auto t2 = std::time(nullptr);

    // Extract transmit timestamp (bytes 40-43): seconds since 1900-01-01, big-endian
    uint32_t ntp_seconds = (static_cast<uint32_t>(response[40]) << 24) |
                           (static_cast<uint32_t>(response[41]) << 16) |
                           (static_cast<uint32_t>(response[42]) << 8) |
                           (static_cast<uint32_t>(response[43]));

    // Sanity check: timestamp should be after Unix epoch in NTP terms
    if (ntp_seconds < NTP_UNIX_EPOCH_DIFF) {
      return std::nullopt;
    }

    // Convert to Unix epoch
    auto ntp_unix = static_cast<int64_t>(ntp_seconds - NTP_UNIX_EPOCH_DIFF);

    // Use midpoint of send/receive as our best estimate of local time
    auto local_time = (t1 + t2) / 2;

    return ntp_unix - local_time;
  } catch (...) {
    return std::nullopt;
  }
}

}  // namespace util
}  // namespace unicity
