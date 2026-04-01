#include "chain/bft_client.hpp"

#include <stdexcept>

#include <httplib.h>

namespace unicity::chain {

HttpBFTClient::HttpBFTClient(std::string bftaddr) : bftaddr_(std::move(bftaddr)), cli_(bftaddr_) {
  cli_.set_connection_timeout(5, 0);
  cli_.set_read_timeout(5, 0);
  cli_.set_write_timeout(5, 0);
}

std::optional<RootTrustBaseV1> HttpBFTClient::FetchTrustBase(const uint64_t epoch) {
  const std::string target = "/api/v1/trustbases?from=" + std::to_string(epoch) + "&to=" + std::to_string(epoch);
  auto tbs = ParseTrustBasesResponse(FetchHttp(target));
  if (tbs.empty()) {
    return std::nullopt;
  }
  return tbs.front();
}

std::vector<RootTrustBaseV1> HttpBFTClient::FetchTrustBases(const uint64_t from_epoch) {
  const std::string target = "/api/v1/trustbases?from=" + std::to_string(from_epoch);
  return ParseTrustBasesResponse(FetchHttp(target));
}

std::vector<RootTrustBaseV1> HttpBFTClient::ParseTrustBasesResponse(const std::vector<uint8_t>& data) {
  if (data.empty()) {
    return {};
  }

  const nlohmann::json j = nlohmann::json::from_cbor(data, true, true, nlohmann::json::cbor_tag_handler_t::ignore);

  // The response is serialized as an array of 1 element due to the struct{} field in the BFT API.
  // The inner element is the array of RootTrustBaseV1.
  if (!j.is_array() || j.size() != 1) {
    throw std::runtime_error("ParseTrustBasesResponse: Expected an array of 1 element");
  }

  const auto& trust_bases_json = j.at(0);
  if (!trust_bases_json.is_array()) {
    throw std::runtime_error("ParseTrustBasesResponse: Inner element is not an array");
  }

  std::vector<RootTrustBaseV1> result;
  result.reserve(trust_bases_json.size());

  for (const auto& tb_json : trust_bases_json) {
    RootTrustBaseV1 tb;
    from_json(tb_json, tb);
    result.push_back(std::move(tb));
  }

  return result;
}

std::vector<uint8_t> HttpBFTClient::FetchHttp(const std::string& target) {
  if (auto res = cli_.Get(target)) {
    if (res->body.size() > MAX_BFT_RESPONSE_SIZE) {
      throw std::runtime_error("BFT response too large: " + std::to_string(res->body.size()));
    }
    if (res->status == 200) {
      return std::vector<uint8_t>(res->body.begin(), res->body.end());
    }
    const std::string truncated = res->body.substr(0, 4096);
    throw std::runtime_error("HTTP request failed with status code " + std::to_string(res->status) +
                             ". Response body (truncated): " + truncated);
  } else {
    throw std::runtime_error("HTTP request failed: " + httplib::to_string(res.error()));
  }
}

}  // namespace unicity::chain
