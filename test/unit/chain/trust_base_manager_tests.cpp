#include "chain/trust_base_manager.hpp"
#include "util/string_parsing.hpp"

#include "catch_amalgamated.hpp"
#include "common/test_util.hpp"
#include "common/mock_bft_client.hpp"

#include <vector>

using namespace unicity;
using namespace unicity::chain;
using namespace unicity::test;

namespace {

const std::string epoch1_hex =
    "d903f58a010301018383783531365569753248416b776456513347774234586f4b554c624b733174504b7671386e6664385941594450415a39"
    "5341766d61427663582102d23be5a4932867088fd6fbf12cbc2744ff1393ec1cc7eb47addcec6d908a9e710183783531365569753248416d47"
    "6b734c324674316d3156506a3774326463484c59343661686a6d726245483655316873486d346e72473268582103411c106956451afa8a596f"
    "9d3ef443c073f6d6d40c5d4539fa3e140465301f3e0183783531365569753248416d514d7052575343736b576773486e415071484363554871"
    "65396848533353787461337a6941737a37795531685821027f0fe7ba12dc544fe9d4f8bdc8f71de106b97d234e769c87a938cc7c5f95875701"
    "03f6f6f6a3783531365569753248416b776456513347774234586f4b554c624b733174504b7671386e6664385941594450415a395341766d61"
    "4276635841dde5ce121337851277214f4cfdb12e1470115987bab6d66cc754df325a8b1ee21fbc022514dcafd8aa73e1b95a599a684a2d2c2f"
    "6b373c66becc7975af84588d00783531365569753248416d476b734c324674316d3156506a3774326463484c59343661686a6d726245483655"
    "316873486d346e724732685841027cc807c54a74c6530be68d4797b9d1e1154a34559a0f5c608d402db074ef6b71b26c04e16594ca7f63a82b"
    "f26b4253e94b987c2b92ac4ff72667f5b56d0ac601783531365569753248416d514d7052575343736b576773486e4150714843635548716539"
    "6848533353787461337a6941737a377955316858413ddb9ce2a7f1ee255966b91f06409a791cd101ce865c2c5ff1054ff8ca0dc7db145de2c7"
    "1a0b5ed7776532a6581e3fe6b685ea5d48568f898a9193bb0444c3ab01";

const std::string epoch2_hex =
    "d903f58a01030218648483783531365569753248416b776456513347774234586f4b554c624b733174504b7671386e6664385941594450415a"
    "395341766d61427663582102d23be5a4932867088fd6fbf12cbc2744ff1393ec1cc7eb47addcec6d908a9e710183783531365569753248416d"
    "34504469796269337572455a4245796f324d4e423571636758675633693535487576486b784777746a677959582102ca80e240b1b1b812f404"
    "2104fdbb341f857e36eaca3985f4bb17f1e61c29bed20183783531365569753248416d476b734c324674316d3156506a3774326463484c5934"
    "3661686a6d726245483655316873486d346e72473268582103411c106956451afa8a596f9d3ef443c073f6d6d40c5d4539fa3e140465301f3e"
    "0183783531365569753248416d514d7052575343736b576773486e41507148436355487165396848533353787461337a6941737a3779553168"
    "5821027f0fe7ba12dc544fe9d4f8bdc8f71de106b97d234e769c87a938cc7c5f9587570103f6f6582030e6a16a4aefc85a5ee9f8516b00e624"
    "e8d6cb17c5dba3bbf16cc5959077865ca3783531365569753248416b776456513347774234586f4b554c624b733174504b7671386e66643859"
    "41594450415a395341766d614276635841dd24a0500bdd88aa6137cd1ab4ae442ebd1c2b4e3e630a09d7e6254d968ffe9a2d3e82b4da93ebf3"
    "bc27ae6e95f67b020d1cbecc7015a50929d6ea68393f439500783531365569753248416d476b734c324674316d3156506a3774326463484c59"
    "343661686a6d726245483655316873486d346e724732685841f4f0ff9976fbbd1898d331a3914a9c3cddafdd2af559bcee25ca6455775b85f7"
    "050000b54139f6abc8dfdd1a73973327c0e8a6a0da7205d79b558be13430c76300783531365569753248416d514d7052575343736b57677348"
    "6e41507148436355487165396848533353787461337a6941737a377955316858416e02eb6f1c8395aa20a31ddf625faa4694c5034cb6f32689"
    "489e965c8772633944bdc3f7d67a7215d5fb497e4ec4e94048e66fd956fd6f69ce2415fec3b9b36001";

RootTrustBaseV1 ParseHex(const std::string& hex) {
  auto data = util::ParseHex(hex);
  return RootTrustBaseV1::FromCBOR(data);
}

}  // namespace

TEST_CASE("TrustBaseManager tests", "[chain][trustbase]") {
  TempDir temp_dir("trustbase_manager_test");
  const auto& test_dir = temp_dir.path;

  RootTrustBaseV1 tb1 = ParseHex(epoch1_hex);
  RootTrustBaseV1 tb2 = ParseHex(epoch2_hex);

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
