// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "catch_amalgamated.hpp"
#include "util/threadsafe_containers.hpp"
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>

using namespace unicity::util;

// ============================================================================
// ThreadSafeMap Tests
// ============================================================================

TEST_CASE("ThreadSafeMap: Basic operations", "[util][threadsafe][map]") {
    ThreadSafeMap<int, std::string> map;

    SECTION("InsertOrUpdate and Read") {
        REQUIRE(map.InsertOrUpdate(1, "one"));
        std::string result;
        REQUIRE(map.Read(1, [&](const std::string& value) { result = value; }));
        REQUIRE(result == "one");
    }

    SECTION("InsertOrUpdate duplicate returns false and updates") {
        REQUIRE(map.InsertOrUpdate(1, "one"));
        REQUIRE(!map.InsertOrUpdate(1, "ONE"));  // Returns false (updated, not inserted)
        std::string result;
        REQUIRE(map.Read(1, [&](const std::string& value) { result = value; }));
        REQUIRE(result == "ONE");  // Value updated
    }

    SECTION("TryInsert doesn't overwrite") {
        REQUIRE(map.TryInsert(1, "one"));
        REQUIRE(!map.TryInsert(1, "ONE"));  // Fails, doesn't overwrite
        std::string result;
        REQUIRE(map.Read(1, [&](const std::string& value) { result = value; }));
        REQUIRE(result == "one");  // Original value preserved
    }

    SECTION("Read non-existent key") {
        std::string result;
        REQUIRE(!map.Read(999, [&](const std::string& value) { result = value; }));
    }

    SECTION("Contains") {
        map.InsertOrUpdate(1, "one");
        REQUIRE(map.Contains(1));
        REQUIRE(!map.Contains(999));
    }

    SECTION("Size and Empty") {
        REQUIRE(map.Empty());
        REQUIRE(map.Size() == 0);

        map.InsertOrUpdate(1, "one");
        REQUIRE(!map.Empty());
        REQUIRE(map.Size() == 1);

        map.InsertOrUpdate(2, "two");
        REQUIRE(map.Size() == 2);
    }

    SECTION("Erase") {
        map.InsertOrUpdate(1, "one");
        REQUIRE(map.Erase(1));
        REQUIRE(!map.Contains(1));
        REQUIRE(!map.Erase(1));  // Second erase returns false
    }

    SECTION("Clear") {
        map.InsertOrUpdate(1, "one");
        map.InsertOrUpdate(2, "two");
        map.Clear();
        REQUIRE(map.Empty());
        REQUIRE(map.Size() == 0);
    }
}

TEST_CASE("ThreadSafeMap: Advanced operations", "[util][threadsafe][map]") {
    ThreadSafeMap<int, int> map;

    SECTION("GetOrInsert") {
        // Key doesn't exist, inserts and returns default
        int val = map.GetOrInsert(1, 100);
        REQUIRE(val == 100);
        int result;
        REQUIRE(map.Read(1, [&](int value) { result = value; }));
        REQUIRE(result == 100);

        // Key exists, returns existing value
        val = map.GetOrInsert(1, 999);
        REQUIRE(val == 100);  // Returns existing, not new value
    }

    SECTION("UpdateIf") {
        map.InsertOrUpdate(1, 10);

        // Update succeeds when predicate returns true
        bool updated = map.UpdateIf(1, [](int old_val) { return old_val == 10; }, 20);
        REQUIRE(updated);
        int result;
        REQUIRE(map.Read(1, [&](int value) { result = value; }));
        REQUIRE(result == 20);

        // Update fails when predicate returns false
        updated = map.UpdateIf(1, [](int old_val) { return old_val == 999; }, 30);
        REQUIRE(!updated);
        REQUIRE(map.Read(1, [&](int value) { result = value; }));
        REQUIRE(result == 20);  // Unchanged

        // Update fails for non-existent key
        updated = map.UpdateIf(999, [](int) { return true; }, 40);
        REQUIRE(!updated);
    }

    SECTION("GetKeys") {
        map.InsertOrUpdate(1, 10);
        map.InsertOrUpdate(2, 20);
        map.InsertOrUpdate(3, 30);

        auto keys = map.GetKeys();
        REQUIRE(keys.size() == 3);

        // Keys should contain 1, 2, 3 (order may vary)
        std::sort(keys.begin(), keys.end());
        REQUIRE(keys[0] == 1);
        REQUIRE(keys[1] == 2);
        REQUIRE(keys[2] == 3);
    }

    SECTION("GetAll") {
        map.InsertOrUpdate(1, 10);
        map.InsertOrUpdate(2, 20);
        map.InsertOrUpdate(3, 30);

        auto entries = map.GetAll();
        REQUIRE(entries.size() == 3);

        // Sort by key for deterministic testing
        std::sort(entries.begin(), entries.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });

        REQUIRE(entries[0].first == 1);
        REQUIRE(entries[0].second == 10);
        REQUIRE(entries[1].first == 2);
        REQUIRE(entries[1].second == 20);
        REQUIRE(entries[2].first == 3);
        REQUIRE(entries[2].second == 30);
    }

    SECTION("ForEach") {
        map.InsertOrUpdate(1, 10);
        map.InsertOrUpdate(2, 20);
        map.InsertOrUpdate(3, 30);

        int sum = 0;
        map.ForEach([&sum](int key, int value) {
            sum += value;
        });
        REQUIRE(sum == 60);
    }
}

TEST_CASE("ThreadSafeMap: Concurrent access", "[util][threadsafe][map][concurrent]") {
    ThreadSafeMap<int, int> map;
    constexpr int num_threads = 10;
    constexpr int ops_per_thread = 100;

    SECTION("Concurrent inserts") {
        std::vector<std::thread> threads;

        for (int t = 0; t < num_threads; ++t) {
            threads.emplace_back([&map, t]() {
                for (int i = 0; i < ops_per_thread; ++i) {
                    int key = t * ops_per_thread + i;
                    map.InsertOrUpdate(key, key * 10);
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        // Verify all entries inserted
        REQUIRE(map.Size() == num_threads * ops_per_thread);

        // Verify some random values
        int val;
        REQUIRE(map.Read(0, [&](int value) { val = value; }));
        REQUIRE(val == 0);
        REQUIRE(map.Read(50, [&](int value) { val = value; }));
        REQUIRE(val == 500);
        REQUIRE(map.Read(999, [&](int value) { val = value; }));
        REQUIRE(val == 9990);
    }

    SECTION("Concurrent reads and writes") {
        // Pre-populate
        for (int i = 0; i < 100; ++i) {
            map.InsertOrUpdate(i, i);
        }

        std::atomic<int> read_sum{0};
        std::vector<std::thread> threads;

        // Reader threads
        for (int t = 0; t < num_threads / 2; ++t) {
            threads.emplace_back([&map, &read_sum]() {
                for (int i = 0; i < ops_per_thread; ++i) {
                    map.Read(i % 100, [&](int val) {
                        read_sum += val;
                    });
                }
            });
        }

        // Writer threads
        for (int t = 0; t < num_threads / 2; ++t) {
            threads.emplace_back([&map]() {
                for (int i = 0; i < ops_per_thread; ++i) {
                    map.InsertOrUpdate(i % 100, i);
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        // No crashes = success for thread safety
        REQUIRE(map.Size() == 100);
    }

    SECTION("Concurrent erases") {
        // Pre-populate
        for (int i = 0; i < 1000; ++i) {
            map.InsertOrUpdate(i, i);
        }

        std::atomic<int> erase_count{0};
        std::vector<std::thread> threads;

        for (int t = 0; t < num_threads; ++t) {
            threads.emplace_back([&map, &erase_count, t]() {
                for (int i = 0; i < ops_per_thread; ++i) {
                    int key = t * ops_per_thread + i;
                    if (map.Erase(key)) {
                        erase_count++;
                    }
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        // All erases should succeed (each thread erases unique keys)
        REQUIRE(erase_count == num_threads * ops_per_thread);
        REQUIRE(map.Empty());
    }
}

// ============================================================================
// ThreadSafeSet Tests
// ============================================================================

TEST_CASE("ThreadSafeSet: Basic operations", "[util][threadsafe][set]") {
    ThreadSafeSet<int> set;

    SECTION("Insert and Contains") {
        REQUIRE(set.Insert(1));
        REQUIRE(set.Contains(1));
    }

    SECTION("Insert duplicate") {
        REQUIRE(set.Insert(1));
        REQUIRE(!set.Insert(1));  // Returns false
        REQUIRE(set.Contains(1));
    }

    SECTION("Contains non-existent") {
        REQUIRE(!set.Contains(999));
    }

    SECTION("Size and Empty") {
        REQUIRE(set.Empty());
        REQUIRE(set.Size() == 0);

        set.Insert(1);
        REQUIRE(!set.Empty());
        REQUIRE(set.Size() == 1);

        set.Insert(2);
        REQUIRE(set.Size() == 2);

        set.Insert(2);  // Duplicate
        REQUIRE(set.Size() == 2);  // Size unchanged
    }

    SECTION("Erase") {
        set.Insert(1);
        REQUIRE(set.Erase(1));
        REQUIRE(!set.Contains(1));
        REQUIRE(!set.Erase(1));  // Second erase returns false
    }

    SECTION("Clear") {
        set.Insert(1);
        set.Insert(2);
        set.Clear();
        REQUIRE(set.Empty());
        REQUIRE(set.Size() == 0);
    }
}

TEST_CASE("ThreadSafeSet: Iteration", "[util][threadsafe][set]") {
    ThreadSafeSet<int> set;
    set.Insert(1);
    set.Insert(2);
    set.Insert(3);

    SECTION("GetAll") {
        auto elements = set.GetAll();
        REQUIRE(elements.size() == 3);

        // Sort for deterministic testing
        std::sort(elements.begin(), elements.end());
        REQUIRE(elements[0] == 1);
        REQUIRE(elements[1] == 2);
        REQUIRE(elements[2] == 3);
    }

    SECTION("ForEach") {
        int sum = 0;
        set.ForEach([&sum](int value) {
            sum += value;
        });
        REQUIRE(sum == 6);
    }
}

TEST_CASE("ThreadSafeSet: Concurrent access", "[util][threadsafe][set][concurrent]") {
    ThreadSafeSet<int> set;
    constexpr int num_threads = 10;
    constexpr int ops_per_thread = 100;

    SECTION("Concurrent inserts") {
        std::vector<std::thread> threads;

        for (int t = 0; t < num_threads; ++t) {
            threads.emplace_back([&set, t]() {
                for (int i = 0; i < ops_per_thread; ++i) {
                    int value = t * ops_per_thread + i;
                    set.Insert(value);
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        // Verify all entries inserted
        REQUIRE(set.Size() == num_threads * ops_per_thread);

        // Verify some random values
        REQUIRE(set.Contains(0));
        REQUIRE(set.Contains(500));
        REQUIRE(set.Contains(999));
    }

    SECTION("Concurrent reads and writes") {
        // Pre-populate
        for (int i = 0; i < 100; ++i) {
            set.Insert(i);
        }

        std::atomic<int> contains_count{0};
        std::vector<std::thread> threads;

        // Reader threads
        for (int t = 0; t < num_threads / 2; ++t) {
            threads.emplace_back([&set, &contains_count]() {
                for (int i = 0; i < ops_per_thread; ++i) {
                    if (set.Contains(i % 100)) {
                        contains_count++;
                    }
                }
            });
        }

        // Writer threads
        for (int t = 0; t < num_threads / 2; ++t) {
            threads.emplace_back([&set]() {
                for (int i = 0; i < ops_per_thread; ++i) {
                    set.Insert(100 + (i % 50));
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        // No crashes = success for thread safety
        REQUIRE(set.Size() == 150);  // 100 original + 50 new unique
    }

    SECTION("Concurrent erases") {
        // Pre-populate
        for (int i = 0; i < 1000; ++i) {
            set.Insert(i);
        }

        std::atomic<int> erase_count{0};
        std::vector<std::thread> threads;

        for (int t = 0; t < num_threads; ++t) {
            threads.emplace_back([&set, &erase_count, t]() {
                for (int i = 0; i < ops_per_thread; ++i) {
                    int value = t * ops_per_thread + i;
                    if (set.Erase(value)) {
                        erase_count++;
                    }
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        // All erases should succeed (each thread erases unique values)
        REQUIRE(erase_count == num_threads * ops_per_thread);
        REQUIRE(set.Empty());
    }
}

// ============================================================================
// Edge Cases and Special Scenarios
// ============================================================================

TEST_CASE("ThreadSafeMap: Complex value types", "[util][threadsafe][map]") {
    struct ComplexValue {
        int id;
        std::string name;
        std::vector<int> data;

        bool operator==(const ComplexValue& other) const {
            return id == other.id && name == other.name && data == other.data;
        }
    };

    ThreadSafeMap<int, ComplexValue> map;

    ComplexValue val1{1, "test", {1, 2, 3}};
    map.InsertOrUpdate(1, val1);

    ComplexValue retrieved;
    REQUIRE(map.Read(1, [&](const ComplexValue& value) { retrieved = value; }));
    REQUIRE(retrieved == val1);
}

TEST_CASE("ThreadSafeMap: Read() efficiency - no copy verification", "[util][threadsafe][map]") {
    // Verify that Read() passes by const reference, not by copy
    struct CopyCounter {
        int value;
        mutable int copy_count = 0;
        mutable int move_count = 0;

        CopyCounter(int v = 0) : value(v) {}

        CopyCounter(const CopyCounter& other)
            : value(other.value), copy_count(0), move_count(0) {
            other.copy_count++;
        }

        CopyCounter(CopyCounter&& other) noexcept
            : value(other.value), copy_count(0), move_count(0) {
            other.move_count++;
        }

        CopyCounter& operator=(const CopyCounter& other) {
            if (this != &other) {
                value = other.value;
                other.copy_count++;
            }
            return *this;
        }

        CopyCounter& operator=(CopyCounter&& other) noexcept {
            if (this != &other) {
                value = other.value;
                other.move_count++;
            }
            return *this;
        }
    };

    ThreadSafeMap<int, CopyCounter> map;

    // Insert a value
    CopyCounter original(42);
    map.InsertOrUpdate(1, original);

    // Use Read() and verify no copies of the map's internal value
    int read_value = 0;
    int initial_copy_count = 0;

    bool found = map.Read(1, [&](const CopyCounter& value) {
        read_value = value.value;
        initial_copy_count = value.copy_count;
        // The callback receives a const reference to the value in the map
        // No copy should have been made to pass it to this callback
    });

    REQUIRE(found);
    REQUIRE(read_value == 42);

    // Verify the value in the map wasn't copied during Read()
    int final_copy_count = 0;
    map.Read(1, [&](const CopyCounter& value) {
        final_copy_count = value.copy_count;
    });

    // The copy count should be the same - Read() doesn't copy the value from the map
    REQUIRE(final_copy_count == initial_copy_count);
}

TEST_CASE("ThreadSafeMap: Read() and Modify() interaction", "[util][threadsafe][map]") {
    ThreadSafeMap<int, std::vector<int>> map;

    // Insert initial value
    map.InsertOrUpdate(1, {10, 20, 30});

    SECTION("Read sees modifications") {
        // Modify the value
        map.Modify(1, [](std::vector<int>& vec) {
            vec.push_back(40);
        });

        // Read should see the modification
        std::vector<int> result;
        map.Read(1, [&](const std::vector<int>& vec) {
            result = vec;
        });

        REQUIRE(result.size() == 4);
        REQUIRE(result[3] == 40);
    }

    SECTION("Multiple reads are consistent") {
        std::vector<int> read1, read2;

        map.Read(1, [&](const std::vector<int>& vec) { read1 = vec; });
        map.Read(1, [&](const std::vector<int>& vec) { read2 = vec; });

        REQUIRE(read1 == read2);
    }
}

TEST_CASE("ThreadSafeMap: Read() vs Modify() - extract single field", "[util][threadsafe][map]") {
    struct PeerData {
        int id;
        std::string address;
        std::vector<int> large_data;

        PeerData(int i, std::string addr) : id(i), address(std::move(addr)) {
            // Simulate large data structure
            large_data.resize(1000, 42);
        }
    };

    ThreadSafeMap<int, PeerData> map;
    map.InsertOrUpdate(1, PeerData(1, "192.168.1.1"));

    SECTION("Read() extracts only needed field - no full copy") {
        // Extract just the address without copying the entire PeerData
        std::string address;
        map.Read(1, [&](const PeerData& peer) {
            address = peer.address;  // Only copy the string, not the whole object
        });

        REQUIRE(address == "192.168.1.1");
    }

    SECTION("Read() can extract multiple fields") {
        int id;
        std::string address;
        size_t data_size;

        map.Read(1, [&](const PeerData& peer) {
            id = peer.id;
            address = peer.address;
            data_size = peer.large_data.size();
        });

        REQUIRE(id == 1);
        REQUIRE(address == "192.168.1.1");
        REQUIRE(data_size == 1000);
    }
}

TEST_CASE("ThreadSafeMap: Read() return value semantics", "[util][threadsafe][map]") {
    ThreadSafeMap<int, std::string> map;

    SECTION("Read() returns true when key exists") {
        map.InsertOrUpdate(1, "exists");

        std::string result;
        bool found = map.Read(1, [&](const std::string& value) {
            result = value;
        });

        REQUIRE(found);
        REQUIRE(result == "exists");
    }

    SECTION("Read() returns false when key doesn't exist") {
        std::string result = "unchanged";
        bool found = map.Read(999, [&](const std::string& value) {
            result = value;
        });

        REQUIRE(!found);
        REQUIRE(result == "unchanged");  // Callback not called
    }
}

TEST_CASE("ThreadSafeMap: Modify() with const callback (read-only modification)", "[util][threadsafe][map]") {
    ThreadSafeMap<int, int> map;
    map.InsertOrUpdate(1, 100);

    // You can use Modify() with a const reference for read-only access
    // This is useful when you need the return value of Modify() to know if key exists
    int result = 0;
    bool found = map.Modify(1, [&](const int& value) {
        result = value * 2;
        // Not modifying the value, just reading it
    });

    REQUIRE(found);
    REQUIRE(result == 200);

    // Verify original value unchanged
    int original = 0;
    map.Read(1, [&](const int& value) { original = value; });
    REQUIRE(original == 100);
}
