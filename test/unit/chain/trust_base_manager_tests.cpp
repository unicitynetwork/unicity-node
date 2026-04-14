#include "chain/trust_base_manager.hpp"
#include "util/string_parsing.hpp"

#include "catch_amalgamated.hpp"
#include "common/mock_bft_client.hpp"
#include "common/test_trust_base_data.hpp"
#include "common/test_util.hpp"

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
}
