#include "chain/trust_base.hpp"
#include "util/sha256.hpp"
#include "util/string_parsing.hpp"

#include "catch_amalgamated.hpp"
#include "common/test_trust_base_data.hpp"

#include <string>
#include <vector>

using namespace unicity;
using namespace unicity::chain;
using namespace unicity::test;

namespace {
RootTrustBaseV1 ParseTB(std::string_view hex) {
  std::vector<uint8_t> data = util::ParseHex(hex);
  const nlohmann::json j = nlohmann::json::from_cbor(data, true, true, nlohmann::json::cbor_tag_handler_t::ignore);
  RootTrustBaseV1 tb;
  from_json(j, tb);
  return tb;
}
}  // namespace

TEST_CASE("Trust Base Tests", "[chain][trustbase]") {
  SECTION("Verify Epoch 1") {
    RootTrustBaseV1 tb = ParseTB(epoch1_cbor);
    REQUIRE(tb.epoch == 1);
    REQUIRE(util::ToHex(tb.Hash()) == epoch1_hash);
    REQUIRE(util::ToHex(tb.ToCBOR()) == epoch1_cbor);
    REQUIRE(tb.Verify(std::nullopt));
  }

  SECTION("Verify Epoch 2") {
    RootTrustBaseV1 tb1 = ParseTB(epoch1_cbor);
    RootTrustBaseV1 tb2 = ParseTB(epoch2_cbor);
    REQUIRE(tb2.epoch == 2);
    REQUIRE(util::ToHex(tb2.Hash()) == epoch2_hash);
    REQUIRE(util::ToHex(tb2.ToCBOR()) == epoch2_cbor);
    REQUIRE(tb2.Verify(tb1));
  }

  SECTION("Verify Epoch 3") {
    RootTrustBaseV1 tb2 = ParseTB(epoch2_cbor);
    RootTrustBaseV1 tb3 = ParseTB(epoch3_cbor);
    REQUIRE(tb3.epoch == 3);
    REQUIRE(util::ToHex(tb3.Hash()) == epoch3_hash);
    REQUIRE(util::ToHex(tb3.ToCBOR()) == epoch3_cbor);
    REQUIRE(tb3.Verify(tb2));
  }

  SECTION("Verify Epoch 3 Invalid (Insufficent signatures)") {
    RootTrustBaseV1 tb2 = ParseTB(epoch2_cbor);
    RootTrustBaseV1 tb3_inv = ParseTB(epoch3_invalid_cbor);
    REQUIRE(tb3_inv.epoch == 3);
    REQUIRE(util::ToHex(tb3_inv.Hash()) == epoch3_invalid_hash);
    REQUIRE(util::ToHex(tb3_inv.ToCBOR()) == epoch3_invalid_cbor);
    // Should fail because it only has 1 signature but threshold is 4
    REQUIRE_FALSE(tb3_inv.Verify(tb2));
  }

  SECTION("IsValid checks") {
    RootTrustBaseV1 tb = ParseTB(epoch1_cbor);
    
    SECTION("Reject zero quorum threshold") {
      tb.quorum_threshold = 0;
      REQUIRE_FALSE(tb.IsValid(std::nullopt));
    }

    SECTION("Reject empty root nodes") {
      tb.root_nodes.clear();
      REQUIRE_FALSE(tb.IsValid(std::nullopt));
    }

    SECTION("Reject stake overflow") {
      tb.root_nodes.push_back({"huge", {}, std::numeric_limits<uint64_t>::max()});
      tb.root_nodes.push_back({"more", {}, 1});
      REQUIRE_FALSE(tb.IsValid(std::nullopt));
    }

    SECTION("Reject impossible quorum threshold") {
      uint64_t total = 0;
      for (const auto& n : tb.root_nodes) total += n.stake;
      tb.quorum_threshold = total + 1;
      REQUIRE_FALSE(tb.IsValid(std::nullopt));
    }
    
    SECTION("Reject epoch mismatch for genesis") {
      tb.epoch = 2;
      REQUIRE_FALSE(tb.IsValid(std::nullopt));
    }

    SECTION("Valid genesis") {
      REQUIRE(tb.IsValid(std::nullopt));
    }
  }
}
