#pragma once

#include "chain/trust_base_manager.hpp"
#include "chain/chainparams.hpp"
#include "chain/trust_base.hpp"

#include <filesystem>
#include <memory>
#include <vector>
#include <optional>

namespace unicity::test {

class MockTrustBaseManager : public chain::TrustBaseManager {
public:
  MockTrustBaseManager() {
        const auto params = chain::ChainParams::CreateRegTest();
        const auto utb_span = params->GenesisBlock().GetUTB();
        trust_bases_[1] = chain::RootTrustBaseV1::FromCBOR(utb_span);
      }

  ~MockTrustBaseManager() override = default;

  void Initialize(const std::vector<uint8_t>& /*genesis_utb_data*/) override {}

  std::vector<chain::RootTrustBaseV1> SyncTrustBases() override { return {}; }

  void Load() override {}

  std::optional<chain::RootTrustBaseV1> GetLatestTrustBase() const override { 
      if (trust_bases_.empty()) return std::nullopt;
      return trust_bases_.rbegin()->second;
  }

  std::vector<chain::RootTrustBaseV1> SyncToEpoch(uint64_t /*target_epoch*/) override { return {}; }

  std::optional<chain::RootTrustBaseV1> GetTrustBase(uint64_t epoch) const override { 
      auto it = trust_bases_.find(epoch);
      if (it != trust_bases_.end()) {
          return it->second;
      }
      return std::nullopt;
  }

  std::optional<chain::RootTrustBaseV1> ProcessTrustBase(const chain::RootTrustBaseV1& tb) override { 
      trust_bases_[tb.epoch] = tb;
      return tb;
  }

  // Test helper to inject trust bases
  void SetTrustBase(uint64_t epoch, const chain::RootTrustBaseV1& tb) {
      trust_bases_[epoch] = tb;
  }

private:
  std::map<uint64_t, chain::RootTrustBaseV1> trust_bases_;
};

}  // namespace unicity::test
