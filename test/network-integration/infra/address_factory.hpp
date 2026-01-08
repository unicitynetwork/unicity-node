#ifndef UNICITY_TEST_ADDRESS_FACTORY_HPP
#define UNICITY_TEST_ADDRESS_FACTORY_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace unicity {
namespace test {

/**
 * AddressFactory - Generate IP addresses for testing peer eviction and address bucketing
 *
 * Use cases:
 * - Netgroup diversity testing: Generate addresses in different /16 subnets
 * - Sybil attack simulation: Generate many addresses in same /16 subnet
 * - Eclipse attack testing: Create attacker-controlled address clusters
 * - Bucket distribution testing: Generate addresses that hash to specific buckets
 *
 * Example usage:
 *   AddressFactory factory;
 *
 *   // Create victim node with unique subnet
 *   auto victim = SimulatedNode(0, &net, factory.NextDiverseAddress());
 *
 *   // Create honest peers in different subnets
 *   for (int i = 0; i < 8; i++) {
 *       honest_peers.push_back(SimulatedNode(i+1, &net, factory.NextDiverseAddress()));
 *   }
 *
 *   // Create Sybil attacker nodes all in same /16
 *   auto sybil_base = "192.168.0.0";
 *   for (int i = 0; i < 50; i++) {
 *       attackers.push_back(SimulatedNode(100+i, &net, factory.NextInSubnet(sybil_base)));
 *   }
 */
class AddressFactory {
public:
    AddressFactory() : diverse_counter_(1), subnet_counters_() {}

    /**
     * Generate next address in a different /16 subnet
     * Each call returns an address in a new /16 (10.X.0.1, 11.X.0.1, etc.)
     * Use for creating diverse, honest peer sets
     */
    std::string NextDiverseAddress() {
        // Use 10.0.0.0/8 private range, varying the second octet for /16 diversity
        // Format: 10.X.0.1 where X increments
        uint8_t second_octet = diverse_counter_++;
        if (diverse_counter_ > 255) {
            diverse_counter_ = 1;  // Wrap around (unlikely to need >255 diverse subnets)
        }

        std::ostringstream oss;
        oss << "10." << static_cast<int>(second_octet) << ".0.1";
        return oss.str();
    }

    /**
     * Generate next address within a specific /16 subnet
     * Addresses increment within the subnet: base → base+1 → base+2
     * Use for creating Sybil attack clusters
     *
     * @param subnet_base Base address like "192.168.0.0" or "1.2.0.0"
     * @return Next available address in that /16
     */
    std::string NextInSubnet(const std::string& subnet_base) {
        // Parse the base to get first two octets
        auto [first, second] = ParseSubnetBase(subnet_base);

        // Get or create counter for this subnet
        std::string key = std::to_string(first) + "." + std::to_string(second);
        uint16_t& counter = subnet_counters_[key];

        // Increment counter first (starts at 0, so first address will use counter=1)
        counter++;
        if (counter > 65534) {
            throw std::runtime_error("Subnet exhausted: " + subnet_base);
        }

        // Generate address: first.second.third.fourth
        // Use counter directly - starts at 1, so fourth octet is 1, 2, 3...
        // When fourth reaches 255, we skip to next third octet
        uint8_t third = (counter - 1) / 254;  // How many full /24 blocks we've used
        uint8_t fourth = ((counter - 1) % 254) + 1;  // 1-254, skips 0 and 255

        std::ostringstream oss;
        oss << static_cast<int>(first) << "."
            << static_cast<int>(second) << "."
            << static_cast<int>(third) << "."
            << static_cast<int>(fourth);
        return oss.str();
    }

    /**
     * Generate a batch of addresses in the same /16 subnet
     * Convenient for creating attacker clusters
     *
     * @param count Number of addresses to generate
     * @param subnet_base Base subnet like "192.168.0.0"
     * @return Vector of addresses in that subnet
     */
    std::vector<std::string> GenerateSubnetCluster(size_t count, const std::string& subnet_base) {
        std::vector<std::string> addresses;
        addresses.reserve(count);
        for (size_t i = 0; i < count; i++) {
            addresses.push_back(NextInSubnet(subnet_base));
        }
        return addresses;
    }

    /**
     * Generate a batch of addresses in different /16 subnets
     * Convenient for creating diverse honest peer sets
     *
     * @param count Number of addresses to generate
     * @return Vector of addresses, each in a different /16
     */
    std::vector<std::string> GenerateDiverseAddresses(size_t count) {
        std::vector<std::string> addresses;
        addresses.reserve(count);
        for (size_t i = 0; i < count; i++) {
            addresses.push_back(NextDiverseAddress());
        }
        return addresses;
    }

    /**
     * Generate address with specific /16 for deterministic testing
     * Format: first.second.third.fourth
     *
     * @param first First octet (0-255)
     * @param second Second octet (0-255) - defines /16 netgroup
     * @param third Third octet (0-255)
     * @param fourth Fourth octet (1-254, avoids network/broadcast)
     */
    static std::string MakeAddress(uint8_t first, uint8_t second, uint8_t third, uint8_t fourth) {
        std::ostringstream oss;
        oss << static_cast<int>(first) << "."
            << static_cast<int>(second) << "."
            << static_cast<int>(third) << "."
            << static_cast<int>(fourth);
        return oss.str();
    }

    /**
     * Get the /16 subnet key for an address (for verification)
     * Returns "first.second" string
     */
    static std::string GetNetgroupKey(const std::string& address) {
        size_t first_dot = address.find('.');
        if (first_dot == std::string::npos) return "";

        size_t second_dot = address.find('.', first_dot + 1);
        if (second_dot == std::string::npos) return "";

        return address.substr(0, second_dot);
    }

    /**
     * Check if two addresses are in the same /16 netgroup
     */
    static bool SameNetgroup(const std::string& addr1, const std::string& addr2) {
        return GetNetgroupKey(addr1) == GetNetgroupKey(addr2);
    }

    /**
     * Reset all counters (for test isolation)
     */
    void Reset() {
        diverse_counter_ = 1;
        subnet_counters_.clear();
    }

private:
    uint8_t diverse_counter_;
    std::map<std::string, uint16_t> subnet_counters_;

    std::pair<uint8_t, uint8_t> ParseSubnetBase(const std::string& base) {
        size_t first_dot = base.find('.');
        if (first_dot == std::string::npos) {
            throw std::invalid_argument("Invalid subnet base: " + base);
        }

        size_t second_dot = base.find('.', first_dot + 1);
        if (second_dot == std::string::npos) {
            throw std::invalid_argument("Invalid subnet base: " + base);
        }

        int first = std::stoi(base.substr(0, first_dot));
        int second = std::stoi(base.substr(first_dot + 1, second_dot - first_dot - 1));

        if (first < 0 || first > 255 || second < 0 || second > 255) {
            throw std::invalid_argument("Invalid subnet base octets: " + base);
        }

        return {static_cast<uint8_t>(first), static_cast<uint8_t>(second)};
    }
};

} // namespace test
} // namespace unicity

#endif // UNICITY_TEST_ADDRESS_FACTORY_HPP
