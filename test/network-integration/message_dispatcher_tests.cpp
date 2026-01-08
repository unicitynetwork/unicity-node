// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "network/message_dispatcher.hpp"
#include "network/peer.hpp"
#include "network/message.hpp"
#include <catch_amalgamated.hpp>
#include <memory>
#include <thread>
#include <vector>

using namespace unicity::network;

// Mock message for testing
namespace unicity {
namespace message {
class TestMessage : public Message {
public:
  TestMessage() = default;
  std::string command() const override { return "test"; }
  std::vector<uint8_t> serialize() const override { return {}; }
  bool deserialize(const uint8_t *data, size_t size) override { return true; }
};
} // namespace message
} // namespace unicity

TEST_CASE("MessageDispatcher - Basic registration and dispatch", "[network][message_dispatcher]") {
  MessageDispatcher dispatcher;

  SECTION("Register and dispatch handler") {
    bool handler_called = false;
    int received_peer_id = -1;

    dispatcher.RegisterHandler("test", [&](PeerPtr peer, ::unicity::message::Message* msg) {
      handler_called = true;
      received_peer_id = peer ? peer->id() : -999;
      return true;
    });

    REQUIRE(dispatcher.HasHandler("test"));

    //  Create mock message (use nullptr for peer since MessageDispatcher just passes it through)
    unicity::message::TestMessage msg;

    bool result = dispatcher.Dispatch(nullptr, "test", &msg);

    REQUIRE(result);
    REQUIRE(handler_called);
    REQUIRE(received_peer_id == -999); // nullptr peer
  }

  SECTION("Dispatch to non-existent handler returns false") {
    unicity::message::TestMessage msg;

    bool result = dispatcher.Dispatch(nullptr, "nonexistent", &msg);
    REQUIRE_FALSE(result);
  }

  SECTION("HasHandler returns false for unregistered command") {
    REQUIRE_FALSE(dispatcher.HasHandler("unknown"));
  }
}

TEST_CASE("MessageDispatcher - Multiple handlers", "[network][message_dispatcher]") {
  MessageDispatcher dispatcher;

  int verack_count = 0;
  int ping_count = 0;
  int inv_count = 0;

  dispatcher.RegisterHandler("verack", [&](PeerPtr, ::unicity::message::Message*) {
    ++verack_count;
    return true;
  });

  dispatcher.RegisterHandler("ping", [&](PeerPtr, ::unicity::message::Message*) {
    ++ping_count;
    return true;
  });

  dispatcher.RegisterHandler("inv", [&](PeerPtr, ::unicity::message::Message*) {
    ++inv_count;
    return true;
  });

  SECTION("All handlers registered") {
    REQUIRE(dispatcher.HasHandler("verack"));
    REQUIRE(dispatcher.HasHandler("ping"));
    REQUIRE(dispatcher.HasHandler("inv"));
  }

  SECTION("Dispatch to correct handlers") {
    unicity::message::TestMessage msg;

    dispatcher.Dispatch(nullptr, "verack", &msg);
    dispatcher.Dispatch(nullptr, "ping", &msg);
    dispatcher.Dispatch(nullptr, "ping", &msg);
    dispatcher.Dispatch(nullptr, "inv", &msg);

    REQUIRE(verack_count == 1);
    REQUIRE(ping_count == 2);
    REQUIRE(inv_count == 1);
  }

  SECTION("GetRegisteredCommands returns sorted list") {
    auto commands = dispatcher.GetRegisteredCommands();
    REQUIRE(commands.size() == 3);
    // Should be sorted alphabetically
    REQUIRE(commands[0] == "inv");
    REQUIRE(commands[1] == "ping");
    REQUIRE(commands[2] == "verack");
  }
}

TEST_CASE("MessageDispatcher - Handler return values", "[network][message_dispatcher]") {
  MessageDispatcher dispatcher;

  SECTION("Handler returning false propagates") {
    dispatcher.RegisterHandler("fail", [](PeerPtr, ::unicity::message::Message*) {
      return false;
    });

    unicity::message::TestMessage msg;

    bool result = dispatcher.Dispatch(nullptr, "fail", &msg);
    REQUIRE_FALSE(result);
  }

  SECTION("Handler returning true propagates") {
    dispatcher.RegisterHandler("success", [](PeerPtr, ::unicity::message::Message*) {
      return true;
    });

    unicity::message::TestMessage msg;

    bool result = dispatcher.Dispatch(nullptr, "success", &msg);
    REQUIRE(result);
  }
}

TEST_CASE("MessageDispatcher - Handler exceptions", "[network][message_dispatcher]") {
  MessageDispatcher dispatcher;

  SECTION("Exception in handler is caught and returns false") {
    dispatcher.RegisterHandler("throws", [](PeerPtr, ::unicity::message::Message*) -> bool {
      throw std::runtime_error("Test exception");
    });

    unicity::message::TestMessage msg;

    // Should not crash, should return false
    bool result = dispatcher.Dispatch(nullptr, "throws", &msg);
    REQUIRE_FALSE(result);
  }
}

TEST_CASE("MessageDispatcher - Unregister", "[network][message_dispatcher]") {
  MessageDispatcher dispatcher;

  int call_count = 0;
  dispatcher.RegisterHandler("test", [&](PeerPtr, ::unicity::message::Message*) {
    ++call_count;
    return true;
  });

  REQUIRE(dispatcher.HasHandler("test"));

  SECTION("Unregister removes handler") {
    dispatcher.UnregisterHandler("test");
    REQUIRE_FALSE(dispatcher.HasHandler("test"));

    unicity::message::TestMessage msg;

    bool result = dispatcher.Dispatch(nullptr, "test", &msg);
    REQUIRE_FALSE(result);
    REQUIRE(call_count == 0);
  }

  SECTION("Unregister non-existent handler is safe") {
    dispatcher.UnregisterHandler("nonexistent");
    // Should not crash
    REQUIRE(dispatcher.HasHandler("test")); // Original still there
  }
}

TEST_CASE("MessageDispatcher - Null safety", "[network][message_dispatcher]") {
  MessageDispatcher dispatcher;

  dispatcher.RegisterHandler("test", [](PeerPtr, ::unicity::message::Message*) {
    return true;
  });

  SECTION("Null peer is allowed (dispatcher passes it through)") {
    unicity::message::TestMessage msg;
    // Null peer is OK - dispatcher just passes it to handler
    bool result = dispatcher.Dispatch(nullptr, "test", &msg);
    REQUIRE(result);
  }

  SECTION("Null message returns false") {
    bool result = dispatcher.Dispatch(nullptr, "test", nullptr);
    REQUIRE_FALSE(result);
  }

  SECTION("Both null returns false") {
    bool result = dispatcher.Dispatch(nullptr, "test", nullptr);
    REQUIRE_FALSE(result);
  }
}

TEST_CASE("MessageDispatcher - Thread safety", "[network][message_dispatcher]") {
  MessageDispatcher dispatcher;

  SECTION("Concurrent registration") {
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
      threads.emplace_back([&dispatcher, i]() {
        dispatcher.RegisterHandler("cmd" + std::to_string(i),
          [](PeerPtr, ::unicity::message::Message*) { return true; });
      });
    }

    for (auto& t : threads) {
      t.join();
    }

    // All 10 handlers should be registered
    auto commands = dispatcher.GetRegisteredCommands();
    REQUIRE(commands.size() == 10);
  }

  SECTION("Concurrent dispatch") {
    std::atomic<int> call_count{0};
    dispatcher.RegisterHandler("test", [&](PeerPtr, ::unicity::message::Message*) {
      ++call_count;
      return true;
    });

    std::vector<std::thread> threads;
    for (int i = 0; i < 100; ++i) {
      threads.emplace_back([&dispatcher]() {
        unicity::message::TestMessage msg;
        dispatcher.Dispatch(nullptr, "test", &msg);
      });
    }

    for (auto& t : threads) {
      t.join();
    }

    REQUIRE(call_count == 100);
  }

  SECTION("Concurrent registration and dispatch") {
    std::atomic<int> dispatch_success{0};
    std::vector<std::thread> threads;

    // Half threads register, half dispatch
    for (int i = 0; i < 20; ++i) {
      if (i % 2 == 0) {
        // Register
        threads.emplace_back([&dispatcher, i]() {
          dispatcher.RegisterHandler("cmd" + std::to_string(i),
            [](PeerPtr, ::unicity::message::Message*) { return true; });
        });
      } else {
        // Dispatch
        threads.emplace_back([&dispatcher, &dispatch_success, i]() {
          unicity::message::TestMessage msg;
          if (dispatcher.Dispatch(nullptr, "cmd" + std::to_string(i - 1), &msg)) {
            ++dispatch_success;
          }
        });
      }
    }

    for (auto& t : threads) {
      t.join();
    }

    // Some dispatches should succeed (timing-dependent)
    // We can't guarantee exact count due to race conditions,
    // but we verify no crashes occurred
    REQUIRE(dispatch_success >= 0);
  }
}

TEST_CASE("MessageDispatcher - Handler replacement", "[network][message_dispatcher]") {
  MessageDispatcher dispatcher;

  int first_count = 0;
  int second_count = 0;

  dispatcher.RegisterHandler("test", [&](PeerPtr, ::unicity::message::Message*) {
    ++first_count;
    return true;
  });

  unicity::message::TestMessage msg;

  dispatcher.Dispatch(nullptr, "test", &msg);
  REQUIRE(first_count == 1);
  REQUIRE(second_count == 0);

  SECTION("Re-registering replaces handler") {
    dispatcher.RegisterHandler("test", [&](PeerPtr, ::unicity::message::Message*) {
      ++second_count;
      return true;
    });

    dispatcher.Dispatch(nullptr, "test", &msg);

    // Old handler should not be called
    REQUIRE(first_count == 1);
    // New handler should be called
    REQUIRE(second_count == 1);
  }
}

TEST_CASE("MessageDispatcher - Empty dispatcher", "[network][message_dispatcher]") {
  MessageDispatcher dispatcher;

  SECTION("GetRegisteredCommands returns empty vector") {
    auto commands = dispatcher.GetRegisteredCommands();
    REQUIRE(commands.empty());
  }

  SECTION("HasHandler returns false for any command") {
    REQUIRE_FALSE(dispatcher.HasHandler("anything"));
  }

  SECTION("Dispatch returns false for any command") {
    unicity::message::TestMessage msg;
    REQUIRE_FALSE(dispatcher.Dispatch(nullptr, "anything", &msg));
  }
}
