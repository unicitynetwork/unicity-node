#pragma once

#include "chain/bft_client.hpp"
#include "chain/trust_base.hpp"

#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

namespace unicity::chain {

class TrustBaseManager {
public:
  explicit TrustBaseManager(const std::filesystem::path& data_dir, std::shared_ptr<BFTClient> bft_client);

  // Loads the locally stored trust bases into memory.
  // Verifies and stores the genesis UTB if not already stored.
  void Initialize(const std::vector<uint8_t>& genesis_utb_data);

  // Loads all trust bases from last seen trust base, stores them locally and returns them.
  std::vector<RootTrustBaseV1> SyncTrustBases();

  // Loads the locally stored trust bases into memory.
  void Load();

  // Returns the latest locally stored trust base.
  std::optional<RootTrustBaseV1> GetLatestTrustBase() const;

  // Syncs trust bases from the BFT node up to the specified target epoch.
  // Stores them locally and returns the synced trust bases.
  std::vector<RootTrustBaseV1> SyncToEpoch(uint64_t target_epoch);

  // Returns trust base by epoch from local cache.
  std::optional<RootTrustBaseV1> GetTrustBase(uint64_t epoch) const;

  // Verifies and stores the trust base.
  std::optional<RootTrustBaseV1> ProcessTrustBase(const RootTrustBaseV1& tb);

private:
  std::filesystem::path data_dir_;
  std::shared_ptr<BFTClient> bft_client_;
  mutable std::mutex mutex_;
  std::map<uint64_t, RootTrustBaseV1> trust_bases_;

  void SaveToDisk(const RootTrustBaseV1& tb) const;

  // Returns pointer to latest trust base if any, or nullptr. Must be called with mutex_ held.
  const RootTrustBaseV1* GetLatestLocked() const {
    return trust_bases_.empty() ? nullptr : &trust_bases_.rbegin()->second;
  }
};

}  // namespace unicity::chain
