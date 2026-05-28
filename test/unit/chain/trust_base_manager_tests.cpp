#include "chain/trust_base_manager.hpp"
#include "util/string_parsing.hpp"

#include "catch_amalgamated.hpp"
#include "common/mock_bft_client.hpp"
#include "common/test_trust_base_data.hpp"
#include "common/test_util.hpp"

#include <fstream>
#include <vector>

using namespace unicity;
using namespace unicity::chain;
using namespace unicity::test;

namespace {

RootTrustBaseV1 ParseHex(const std::string_view hex) {
  return RootTrustBaseV1::FromCBOR(util::ParseHex(hex));
}

}  // namespace

TEST_CASE("TrustBaseManager tests", "[chain][trustbase]") {
  TempDir temp_dir("trustbase_manager_test");
  const auto& test_dir = temp_dir.path;

  RootTrustBaseV1 tb1 = ParseHex(epoch1_cbor);
  RootTrustBaseV1 tb2 = ParseHex(epoch2_cbor);

  SECTION("Process_HigherEpoch_UpdatesLatest") {
    LocalTrustBaseManager manager(test_dir, std::make_shared<MockBFTClient>());
    REQUIRE(manager.ProcessTrustBase(tb1).has_value());

    REQUIRE(manager.ProcessTrustBase(tb2).has_value());
    auto latest = manager.GetLatestTrustBase();
    REQUIRE(latest.has_value());
    REQUIRE(latest->epoch == 2);
  }

  SECTION("Process_LowerEpoch_Ignored") {
    LocalTrustBaseManager manager(test_dir, std::make_shared<MockBFTClient>());
    REQUIRE(manager.ProcessTrustBase(tb1).has_value());
    REQUIRE(manager.ProcessTrustBase(tb2).has_value());
    REQUIRE_FALSE(manager.ProcessTrustBase(tb1).has_value());

    auto latest = manager.GetLatestTrustBase();
    REQUIRE(latest->epoch == 2);
  }

  SECTION("Load_MultipleFiles_SetsCorrectLatest") {
    {
      // Create a manager, process two epochs to save them to disk
      LocalTrustBaseManager manager(test_dir, std::make_shared<MockBFTClient>());
      REQUIRE(manager.ProcessTrustBase(tb1).has_value());
      REQUIRE(manager.ProcessTrustBase(tb2).has_value());
    }

    // Create a new manager instance and load from the same directory
    LocalTrustBaseManager manager2(test_dir, std::make_shared<MockBFTClient>());
    REQUIRE_NOTHROW(manager2.Load());

    auto latest = manager2.GetLatestTrustBase();
    REQUIRE(latest.has_value());
    REQUIRE(latest->epoch == 2);

    auto e1 = manager2.GetTrustBase(1);
    REQUIRE(e1.has_value());
    REQUIRE(e1->epoch == 1);
  }

  // S5 (CONFIRMED OPEN, INVESTIGATIONS.md F-snapshots): LocalTrustBaseManager::Load()
  // deserializes .cbor files with FromCBOR() and stores them WITHOUT calling
  // IsValid()/VerifySignatures(). A tampered/corrupt-but-parseable file therefore
  // loads silently. This is a gap-repro: it PASSES today by demonstrating the
  // invalid TB is accepted. When Load() is hardened to validate on load, flip the
  // final assertions (the invalid TB must be rejected / not become latest).
  SECTION("Load accepts an invalid-but-parseable trust base (S5 — no validation on disk load)") {
    // Build a parseable but INVALID trust base: quorum_threshold == 0 makes
    // IsValid() false, but ToCBOR()/FromCBOR() round-trip fine.
    RootTrustBaseV1 bad = tb1;
    bad.epoch = 7;             // distinct, higher epoch so it would be "latest"
    bad.quorum_threshold = 0;  // invalid per IsValid() (trust_base.cpp:158)
    REQUIRE_FALSE(bad.IsValid(std::nullopt));

    // Construct the manager first — its ctor creates the actual storage subdir
    // (data_dir/"trustbases", file names "epoch_<N>.cbor"). Then write the
    // tampered file straight into that subdir, bypassing ProcessTrustBase
    // (which validates). Simulates a tampered/corrupt on-disk file.
    LocalTrustBaseManager manager(test_dir, std::make_shared<MockBFTClient>());

    const std::filesystem::path tb_dir = test_dir / "trustbases";
    const std::vector<uint8_t> cbor = bad.ToCBOR();
    {
      std::ofstream f(tb_dir / "epoch_7.cbor", std::ios::binary);
      REQUIRE(f.good());
      f.write(reinterpret_cast<const char*>(cbor.data()),
              static_cast<std::streamsize>(cbor.size()));
    }

    REQUIRE_NOTHROW(manager.Load());

    // GAP: the invalid TB loaded silently and became the latest.
    auto latest = manager.GetLatestTrustBase();
    REQUIRE(latest.has_value());
    REQUIRE(latest->epoch == 7);             // invalid TB accepted as latest
    REQUIRE(latest->quorum_threshold == 0);  // ...and it's the invalid one
    // When Load() validates on load, the above flips to: the tampered file is
    // skipped/rejected and epoch 7 never becomes latest.
  }
}
