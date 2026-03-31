// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "chain/token_generator.hpp"
#include "util/endian.hpp"
#include "util/files.hpp"
#include "util/sha256.hpp"

#include "catch_amalgamated.hpp"
#include "common/test_util.hpp"

#include <filesystem>
#include <fstream>

#include <nlohmann/json.hpp>

using namespace unicity;
using namespace unicity::mining;

namespace {

nlohmann::json readStateJSON(const std::filesystem::path& state_file) {
  auto data = util::read_file(state_file);
  return nlohmann::json::parse(std::string(data.begin(), data.end()));
}

}  // namespace

TEST_CASE("TokenGenerator basic operations", "[mining][token]") {
  test::TempDir temp_dir("token_gen_test");
  const auto& test_dir = temp_dir.path;
  auto state_file = test_dir / "miner_state.json";

  SECTION("Initial creation generates seed and saves it") {
    TokenGenerator gen(test_dir);
    auto state = gen.GetState();
    REQUIRE_FALSE(state.seed.IsNull());
    REQUIRE(state.counter == 0);
    REQUIRE(gen.GetCounter() == 0);
    REQUIRE(std::filesystem::exists(state_file));

    auto data = util::read_file(state_file);
    auto json = nlohmann::json::parse(std::string(data.begin(), data.end()));
    REQUIRE(json["seed"].get<std::string>() == state.seed.GetHex());
    REQUIRE(json["counter"].get<uint64_t>() == 0);
  }

  SECTION("GenerateNextTokenId increments counter and persists") {
    TokenGenerator gen(test_dir);
    uint256 id1 = gen.GenerateNextTokenId();

    REQUIRE(gen.GetCounter() == 1);
    REQUIRE(gen.GetState().counter == 1);

    auto json = readStateJSON(state_file);
    REQUIRE(json["counter"].get<uint64_t>() == 1);

    auto id2 = gen.GenerateNextTokenId();
    REQUIRE(gen.GetCounter() == 2);
    REQUIRE(id1 != id2);
  }

  SECTION("Loading existing state works") {
    uint256 manual_seed;
    manual_seed.SetHex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    uint64_t manual_counter = 42;

    {
      nlohmann::json json;
      json["seed"] = manual_seed.GetHex();
      json["counter"] = manual_counter;
      std::ofstream f(test_dir / "miner_state.json");
      f << json.dump() << std::endl;
    }

    TokenGenerator gen(test_dir);
    REQUIRE(gen.GetCounter() == 42);
    auto state = gen.GetState();
    REQUIRE(state.seed == manual_seed);
    REQUIRE(state.counter == 42);

    auto id = gen.GenerateNextTokenId();
    REQUIRE(gen.GetCounter() == 43);

    uint8_t counter_le[8];
    endian::WriteLE64(counter_le, 43);
    uint256 expected_id;
    CSHA256().Write(manual_seed.begin(), manual_seed.size()).Write(counter_le, 8).Finalize(expected_id.begin());
    REQUIRE(id == expected_id);
  }
}
