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
  virtual ~TrustBaseManager() = default;

  // Loads the locally stored trust bases into memory.
  // Verifies and stores the genesis UTB if not already stored.
  virtual void Initialize(const std::vector<uint8_t>& genesis_utb_data) = 0;

  // Loads all trust bases from last seen trust base, stores them locally and returns them.
  virtual std::vector<RootTrustBaseV1> SyncTrustBases() = 0;

  // Loads the locally stored trust bases into memory.
  virtual void Load() = 0;

  // Returns the latest locally stored trust base.
  virtual std::optional<RootTrustBaseV1> GetLatestTrustBase() const = 0;

  // Syncs trust bases from the BFT node up to the specified target epoch.
  // Stores them locally and returns the synced trust bases.
  virtual std::vector<RootTrustBaseV1> SyncToEpoch(uint64_t target_epoch) = 0;

  // Returns trust base by epoch from local cache.
  virtual std::optional<RootTrustBaseV1> GetTrustBase(uint64_t epoch) const = 0;

  // Verifies and stores the trust base.
  virtual std::optional<RootTrustBaseV1> ProcessTrustBase(const RootTrustBaseV1& tb) = 0;
};

class LocalTrustBaseManager : public TrustBaseManager {
public:
  explicit LocalTrustBaseManager(const std::filesystem::path& data_dir, std::shared_ptr<BFTClient> bft_client);
  ~LocalTrustBaseManager() override = default;

  void Initialize(const std::vector<uint8_t>& genesis_utb_data) override;
  std::vector<RootTrustBaseV1> SyncTrustBases() override;
  void Load() override;
  std::optional<RootTrustBaseV1> GetLatestTrustBase() const override;
  std::vector<RootTrustBaseV1> SyncToEpoch(uint64_t target_epoch) override;
  std::optional<RootTrustBaseV1> GetTrustBase(uint64_t epoch) const override;
  std::optional<RootTrustBaseV1> ProcessTrustBase(const RootTrustBaseV1& tb) override;

private:
  std::filesystem::path data_dir_;
  std::shared_ptr<BFTClient> bft_client_;
  mutable std::mutex mutex_;
  std::map<uint64_t, RootTrustBaseV1> trust_bases_;

  void SaveToDisk(const RootTrustBaseV1& tb) const;

  // Returns pointer to latest trust base if any, or nullptr. Must be called with mutex_ held.
  const RootTrustBaseV1* GetLatest() const {
    return trust_bases_.empty() ? nullptr : &trust_bases_.rbegin()->second;
  }
};

}  // namespace unicity::chain
