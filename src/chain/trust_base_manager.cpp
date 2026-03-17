#include "chain/trust_base_manager.hpp"

#include <algorithm>
#include <fstream>
#include <stdexcept>

#include <spdlog/spdlog.h>

namespace unicity::chain {

TrustBaseManager::TrustBaseManager(const std::filesystem::path& data_dir, std::shared_ptr<BFTClient> bft_client)
    : data_dir_(data_dir / "trustbases"), bft_client_(std::move(bft_client)) {
  if (!bft_client_) {
    throw std::invalid_argument("TrustBaseManager: BFTClient cannot be null");
  }
  std::filesystem::create_directories(data_dir_);
}

void TrustBaseManager::Load() {
  std::lock_guard lock(mutex_);

  // Load all .cbor files in data_dir_
  for (const auto& entry : std::filesystem::directory_iterator(data_dir_)) {
    if (entry.path().extension() == ".cbor") {
      std::ifstream file(entry.path(), std::ios::binary);
      if (!file) {
        spdlog::error("Failed to open trust base file for reading: {}", entry.path().string());
        continue;
      }

      std::vector<uint8_t> data((std::istreambuf_iterator(file)), std::istreambuf_iterator<char>());
      try {
        RootTrustBaseV1 tb = RootTrustBaseV1::FromCBOR(data);
        trust_bases_[tb.epoch] = tb;
        if (!latest_trust_base_ || tb.epoch > latest_trust_base_->epoch) {
          latest_trust_base_ = tb;
        }
      } catch (const std::exception& e) {
        spdlog::error("Failed to parse local trust base file {}: {}", entry.path().string(), e.what());
      }
    }
  }

  spdlog::info("Loaded {} trust bases. Latest epoch: {}", trust_bases_.size(),
               latest_trust_base_ ? std::to_string(latest_trust_base_->epoch) : "None");
}

// Initialize loads the stored trust base files to memory and creates trust base file for genesis trust base, if needed.
void TrustBaseManager::Initialize(const std::vector<uint8_t>& genesis_utb_data) {
  Load();

  {
    std::lock_guard lock(mutex_);
    if (trust_bases_.contains(1)) {
      return;  // Already loaded, skipping verification
    }
  }

  const auto tb_opt = bft_client_->FetchTrustBase(1);
  if (!tb_opt) {
    throw std::runtime_error("Failed to fetch epoch 1 trust base from network");
  }

  const RootTrustBaseV1 tb = *tb_opt;
  if (tb.epoch != 1) {
    throw std::runtime_error("Fetched UTB is not epoch 1 (got " + std::to_string(tb.epoch) + ")");
  }

  const RootTrustBaseV1 genesis_tb = RootTrustBaseV1::FromCBOR(genesis_utb_data);
  if (tb.Hash() != genesis_tb.Hash()) {
    throw std::runtime_error("Genesis UTB hash does not match fetched UTB hash");
  }

  if (!ProcessTrustBase(tb)) {
    throw std::runtime_error("Failed to process and store fetched genesis UTB");
  }
}

std::optional<RootTrustBaseV1> TrustBaseManager::GetLatestTrustBase() const {
  std::lock_guard lock(mutex_);
  return latest_trust_base_;
}

std::optional<RootTrustBaseV1> TrustBaseManager::GetTrustBase(const uint64_t epoch) const {
  std::lock_guard lock(mutex_);
  if (const auto it = trust_bases_.find(epoch); it != trust_bases_.end()) {
    return it->second;
  }
  return std::nullopt;
}

std::optional<RootTrustBaseV1> TrustBaseManager::ProcessTrustBase(const RootTrustBaseV1& tb) {
  std::lock_guard lock(mutex_);

  const RootTrustBaseV1* prev_tb = nullptr;
  if (latest_trust_base_) {
    prev_tb = &(*latest_trust_base_);
    if (tb.epoch <= prev_tb->epoch) {
      spdlog::debug("Ignoring trust base for epoch {}, already have {}", tb.epoch, prev_tb->epoch);
      return std::nullopt;
    }
  }

  if (!tb.IsValid(prev_tb)) {
    throw std::invalid_argument("Invalid trust base content for epoch " + std::to_string(tb.epoch));
  }

  if (!tb.VerifySignatures(prev_tb)) {
    throw std::invalid_argument("Invalid signatures for trust base epoch " + std::to_string(tb.epoch));
  }

  SaveToDisk(tb);

  trust_bases_[tb.epoch] = tb;
  latest_trust_base_ = tb;

  spdlog::info("Processed and saved new trust base for epoch {}", tb.epoch);
  return tb;
}

void TrustBaseManager::SaveToDisk(const RootTrustBaseV1& tb) const {
  const std::filesystem::path file_path = data_dir_ / ("epoch_" + std::to_string(tb.epoch) + ".cbor");
  std::ofstream file(file_path, std::ios::binary);
  if (!file) {
    throw std::runtime_error("Failed to open " + file_path.string() + " for writing");
  }
  const auto data = tb.ToCBOR();
  file.write(reinterpret_cast<const char*>(data.data()), data.size());
  if (!file) {
    throw std::runtime_error("Failed to write data to " + file_path.string());
  }
}

std::vector<RootTrustBaseV1> TrustBaseManager::SyncTrustBases() {
  try {
    uint64_t from_epoch = 1;
    if (const auto latest = GetLatestTrustBase()) {
      from_epoch = latest->epoch;
    }

    const auto record_blobs = bft_client_->FetchTrustBases(from_epoch);

    std::vector<RootTrustBaseV1> new_tbs;
    for (const auto& tb : record_blobs) {
      if (auto processed = ProcessTrustBase(tb)) {
        new_tbs.push_back(std::move(*processed));
      }
    }
    return new_tbs;
  } catch (const std::exception& e) {
    spdlog::error("SyncTrustBases failed: {}", e.what());
    return {};
  }
}

}  // namespace unicity::chain
