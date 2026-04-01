#pragma once

#include "chain/trust_base.hpp"

#include <optional>
#include <string>
#include <vector>

#include <httplib.h>

namespace unicity::chain {

class BFTClient {
public:
  virtual ~BFTClient() = default;

  // Fetches a single trust base for the given epoch.
  virtual std::optional<RootTrustBaseV1> FetchTrustBase(uint64_t epoch) = 0;

  // Fetches all trust bases starting from the given epoch.
  virtual std::vector<RootTrustBaseV1> FetchTrustBases(uint64_t from_epoch) = 0;
};

class RegtestBFTClient : public BFTClient {
public:
  RegtestBFTClient() = default;
  explicit RegtestBFTClient(RootTrustBaseV1 genesis_utb) : genesis_utb_(std::move(genesis_utb)) {}

  std::optional<RootTrustBaseV1> FetchTrustBase(uint64_t epoch) override {
    if (epoch == 1) {
      return genesis_utb_;
    }
    return std::nullopt;
  }
  std::vector<RootTrustBaseV1> FetchTrustBases(uint64_t from_epoch) override { return {}; }

private:
  std::optional<RootTrustBaseV1> genesis_utb_;
};

class HttpBFTClient : public BFTClient {
public:
  explicit HttpBFTClient(std::string bftaddr);

  std::optional<RootTrustBaseV1> FetchTrustBase(uint64_t epoch) override;
  std::vector<RootTrustBaseV1> FetchTrustBases(uint64_t from_epoch) override;

  static std::vector<RootTrustBaseV1> ParseTrustBasesResponse(const std::vector<uint8_t>& data);

  // Maximum size for an HTTP response from the BFT server.
  static constexpr size_t MAX_BFT_RESPONSE_SIZE = 1024 * 1024;  // 1 MB

private:
  std::string bftaddr_;
  httplib::Client cli_;

  std::vector<uint8_t> FetchHttp(const std::string& target);
};

}  // namespace unicity::chain
