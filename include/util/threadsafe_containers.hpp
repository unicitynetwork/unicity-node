#pragma once

#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace unicity {
namespace util {

/**
 * ThreadSafeMap - Thread-safe wrapper around std::map or std::unordered_map
 *
 * Purpose:
 * - Eliminate repeated mutex + map patterns across the codebase
 * - Provide safe, atomic operations on key-value storage
 * - Support both ordered (std::map) and unordered (std::unordered_map) variants
 *
 * Usage:
 *   ThreadSafeMap<int, PeerPtr> peers_;
 *   peers_.Insert(id, peer);
 *
 *   // Read data without expensive copies
 *   PeerPtr peer;
 *   peers_.Read(id, [&](const PeerPtr& p) { peer = p; });
 *
 *   // Modify data in-place
 *   peers_.Modify(id, [](PeerPtr& p) { p->disconnect(); });
 *
 *   peers_.Erase(id);
 *
 * Design decisions:
 * - All operations are atomic (single lock per operation)
 * - Read() and Modify() use callbacks to avoid expensive copies and ensure lock safety
 * - Iteration uses callbacks to avoid holding lock during user code
 * - No iterator-based API to avoid lock lifetime issues
 *
 * Thread Safety:
 * This class uses std::recursive_mutex, which allows safe nested calls from the
 * same thread.
 *
 * Template Parameters:
 * - Key: Key type (must be copyable)
 * - Value: Value type (must be copyable)
 * - MapType: Underlying map type (std::map or std::unordered_map)
 */
template <typename Key, typename Value, template <typename...> class MapType = std::unordered_map>
class ThreadSafeMap {
public:
  ThreadSafeMap() = default;

  // Non-copyable and non-movable (mutex cannot be moved)
  ThreadSafeMap(const ThreadSafeMap&) = delete;
  ThreadSafeMap& operator=(const ThreadSafeMap&) = delete;
  ThreadSafeMap(ThreadSafeMap&&) = delete;
  ThreadSafeMap& operator=(ThreadSafeMap&&) = delete;

  /**
   * Insert or update a key-value pair (upsert semantics)
   * Returns true if a new key was inserted, false if existing key was updated
   *
   * This method uses insert_or_assign() which always succeeds:
   * - If key doesn't exist: inserts new entry and returns true
   * - If key exists: updates existing entry and returns false
   *
   * Use TryInsert() if you only want insert-only semantics.
   */
  bool InsertOrUpdate(const Key& key, const Value& value) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto [it, inserted] = map_.insert_or_assign(key, value);
    return inserted;
  }

  /**
   * Insert only if key doesn't exist (insert-only semantics)
   * Returns true if inserted, false if key already exists
   *
   * Unlike InsertOrUpdate(), this method will NOT modify existing entries.
   */
  bool TryInsert(const Key& key, const Value& value) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return map_.insert({key, value}).second;
  }

  /**
   * Read value by key with a callback
   * Calls reader(const Value&) under lock if key exists
   * Returns true if key exists and was read, false otherwise
   *
   * Unlike Get(), this does not copy the entire Value - it passes a const reference.
   * Use this for reading data without expensive copies.
   *
   * Example:
   *   PeerPtr peer;
   *   map.Read(peer_id, [&](const PeerTrackingData& state) {
   *     peer = state.peer;  // Extract only what you need
   *   });
   */
  template <typename Func>
  bool Read(const Key& key, Func&& reader) const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto it = map_.find(key);
    if (it != map_.end()) {
      reader(it->second);
      return true;
    }
    return false;
  }

  /**
   * Check if key exists
   */
  bool Contains(const Key& key) const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return map_.count(key) > 0;
  }

  /**
   * Remove entry by key
   * Returns true if removed, false if key didn't exist
   */
  bool Erase(const Key& key) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return map_.erase(key) > 0;
  }

  /**
   * Get size
   */
  size_t Size() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return map_.size();
  }

  /**
   * Check if empty
   */
  bool Empty() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return map_.empty();
  }

  /**
   * Clear all entries
   */
  void Clear() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    map_.clear();
  }

  /**
   * Iterate over all entries with a callback
   * Callback signature: void(const Key&, const Value&)
   *
   * IMPORTANT: The lock is held during iteration. Keep callbacks fast!
   * For expensive operations, use GetAll() to get a snapshot first.
   */
  template <typename Func>
  void ForEach(Func&& callback) const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (const auto& [key, value] : map_) {
      // IMPORTANT: Pass by const reference to avoid copying Value objects
      // This ensures shared_ptr members point to the same underlying object
      callback(key, value);  // structured binding already gives us const references
    }
  }

  /**
   * Get snapshot of all entries
   * Returns vector of key-value pairs (safe to iterate without lock)
   */
  std::vector<std::pair<Key, Value>> GetAll() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return std::vector<std::pair<Key, Value>>(map_.begin(), map_.end());
  }

  /**
   * Get all keys
   */
  std::vector<Key> GetKeys() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<Key> keys;
    keys.reserve(map_.size());
    for (const auto& [key, _] : map_) {
      keys.push_back(key);
    }
    return keys;
  }

  /**
   * Atomic get-or-insert
   * If key exists, returns existing value
   * If key doesn't exist, inserts default_value and returns it
   */
  Value GetOrInsert(const Key& key, const Value& default_value) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto [it, inserted] = map_.try_emplace(key, default_value);
    return it->second;
  }

  /**
   * Conditional update
   * Calls predicate(old_value) under lock, updates if predicate returns true
   * Returns true if updated, false otherwise
   */
  bool UpdateIf(const Key& key, std::function<bool(const Value&)> predicate, const Value& new_value) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto it = map_.find(key);
    if (it != map_.end() && predicate(it->second)) {
      it->second = new_value;
      return true;
    }
    return false;
  }

  /**
   * In-place modification
   * Calls modifier(value) under lock to modify value in-place
   * Returns true if key exists and was modified, false otherwise
   */
  template <typename Func>
  bool Modify(const Key& key, Func&& modifier) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto it = map_.find(key);
    if (it != map_.end()) {
      modifier(it->second);
      return true;
    }
    return false;
  }

private:
  mutable std::recursive_mutex mutex_;
  MapType<Key, Value> map_;
};

/**
 * ThreadSafeSet - Thread-safe wrapper around std::unordered_set
 *
 * Purpose:
 * - Eliminate repeated mutex + set patterns
 * - Provide safe, atomic operations on unique element storage
 *
 * Usage:
 *   ThreadSafeSet<int> processed_peers_;
 *   processed_peers_.Insert(peer_id);
 *   bool seen = processed_peers_.Contains(peer_id);
 *   processed_peers_.Erase(peer_id);
 *
 * Thread Safety:
 * This class uses std::recursive_mutex, allowing safe nested calls from the
 * same thread (e.g., calling methods from within ForEach callbacks).
 */
template <typename T>
class ThreadSafeSet {
public:
  ThreadSafeSet() = default;

  // Non-copyable and non-movable (mutex cannot be moved)
  ThreadSafeSet(const ThreadSafeSet&) = delete;
  ThreadSafeSet& operator=(const ThreadSafeSet&) = delete;
  ThreadSafeSet(ThreadSafeSet&&) = delete;
  ThreadSafeSet& operator=(ThreadSafeSet&&) = delete;

  /**
   * Insert element
   * Returns true if inserted, false if already exists
   */
  bool Insert(const T& value) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return set_.insert(value).second;
  }

  /**
   * Check if element exists
   */
  bool Contains(const T& value) const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return set_.count(value) > 0;
  }

  /**
   * Remove element
   * Returns true if removed, false if didn't exist
   */
  bool Erase(const T& value) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return set_.erase(value) > 0;
  }

  /**
   * Get size
   */
  size_t Size() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return set_.size();
  }

  /**
   * Check if empty
   */
  bool Empty() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return set_.empty();
  }

  /**
   * Clear all elements
   */
  void Clear() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    set_.clear();
  }

  /**
   * Iterate over all elements with a callback
   * Callback signature: void(const T&)
   */
  template <typename Func>
  void ForEach(Func&& callback) const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (const auto& value : set_) {
      callback(value);
    }
  }

  /**
   * Get snapshot of all elements
   */
  std::vector<T> GetAll() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return std::vector<T>(set_.begin(), set_.end());
  }

private:
  mutable std::recursive_mutex mutex_;
  std::unordered_set<T> set_;
};

}  // namespace util
}  // namespace unicity
