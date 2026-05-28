#pragma once

#include "chain/bft_client.hpp"

#include <map>
#include <vector>

namespace unicity::test {

class MockBFTClient : public chain::BFTClient {
public:
  std::optional<chain::RootTrustBaseV1> FetchTrustBase(uint64_t epoch) override {
    if (auto it = trust_bases_.find(epoch); it != trust_bases_.end()) {
      return it->second;
    }
    return std::nullopt;
  }

  std::vector<chain::RootTrustBaseV1> FetchTrustBases(uint64_t from_epoch) override {
    std::vector<chain::RootTrustBaseV1> result;
    for (auto it = trust_bases_.lower_bound(from_epoch); it != trust_bases_.end(); ++it) {
      result.push_back(it->second);
    }
    return result;
  }

  void SetTrustBase(const chain::RootTrustBaseV1& tb) { trust_bases_[tb.epoch] = tb; }

  void Clear() { trust_bases_.clear(); }

private:
  std::map<uint64_t, chain::RootTrustBaseV1> trust_bases_;
};

}  // namespace unicity::test
