// Copyright (c) 2025 The Unicity Foundation
// Test helper for ChainstateManager with PoW bypass

#ifndef UNICITY_TEST_CHAINSTATE_MANAGER_HPP
#define UNICITY_TEST_CHAINSTATE_MANAGER_HPP

#include "chain/chainstate_manager.hpp"
#include "chain/chainparams.hpp"
#include "chain/randomx_pow.hpp"
#include "mock_trust_base_manager.hpp"
#include <memory>

namespace unicity {
namespace test {

/**
 * TestChainstateManager - Test version that bypasses PoW validation
 *
 * This allows unit tests to run without expensive RandomX mining.
 * Inherits from ChainstateManager and overrides CheckProofOfWork
 * to always return true.
 *
 * Usage:
 *   TestChainstateManager chainstate(*params);
 *   chainstate.Initialize(params->GenesisBlock());
 *   // Now headers can be accepted without valid PoW
 */
class TestChainstateManager : public validation::ChainstateManager {
public:
    /**
     * Constructor - initializes its own MockTrustBaseManager
     */
    explicit TestChainstateManager(const chain::ChainParams& params)
        : TestChainstateManager(params, std::make_unique<MockTrustBaseManager>())
    {}

    /**
    * Constructor - same as ChainstateManager
    */
    TestChainstateManager(const chain::ChainParams& params, chain::TrustBaseManager& tbm)
        : ChainstateManager(params, tbm)
        , bypass_pow_validation_(true)
        , bypass_contextual_validation_(true)
    {
        // Also set base class skip flag for CheckHeadersPoW which delegates to validation
        // Only set for regtest - TestSetSkipPoWChecks throws for other networks
        if (params.GetChainType() == chain::ChainType::REGTEST) {
            TestSetSkipPoWChecks(true);
        }
    }

    /**
     * Enable or disable PoW validation bypass
     *
     * When bypass_pow_validation is true (default), CheckProofOfWork always returns true.
     * When false, it calls the real ChainstateManager::CheckProofOfWork.
     *
     * This allows misbehavior tests to detect invalid PoW while keeping most tests fast.
     */
    void SetBypassPOWValidation(bool bypass) {
        bypass_pow_validation_ = bypass;
        // Sync with base class (only for regtest - throws for other networks)
        if (GetParams().GetChainType() == chain::ChainType::REGTEST) {
            TestSetSkipPoWChecks(bypass);
        }
    }

    /**
     * Enable or disable contextual validation bypass (difficulty/timestamp)
     * Default: true (bypass). Set to false to exercise contextual checks in tests.
     */
    void SetBypassContextualValidation(bool bypass) {
        bypass_contextual_validation_ = bypass;
    }

    MockTrustBaseManager* GetMockTBM() const { return owned_tbm_.get(); }

protected:
    /**
     * Override CheckProofOfWork to conditionally bypass validation
     *
     * When bypass_pow_validation_ is true (default), returns true without checking.
     * When false, calls real ChainstateManager::CheckProofOfWork for actual validation.
     * This is ONLY safe for unit tests where we control all inputs.
     */
    bool CheckProofOfWork(const CBlockHeader& header,
                         crypto::POWVerifyMode mode) const override
    {
        if (bypass_pow_validation_) {
            // Bypass PoW validation for tests
            return true;
        }
        // Use real PoW validation (for misbehavior tests)
        return ChainstateManager::CheckProofOfWork(header, mode);
    }

  /**
   * Override CheckBlockHeaderWrapper to conditionally bypass validation
   *
   * When bypass_pow_validation_ is true (default), returns true without checking.
   * When false, calls real ChainstateManager::CheckBlockHeaderWrapper for actual validation.
   * This is ONLY safe for unit tests where we control all inputs.
   */
    bool CheckBlockHeaderWrapper(const CBlockHeader& header,
                                 validation::ValidationState& state) const override
    {
        if (bypass_pow_validation_) {
            // Bypass all header validation for tests
            return true;
        }
        // Use real header validation (for misbehavior tests)
        return ChainstateManager::CheckBlockHeaderWrapper(header, state);
    }

    /**
     * Override ContextualCheckBlockHeaderWrapper to optionally bypass contextual validation
     */
    bool ContextualCheckBlockHeaderWrapper(const CBlockHeader& header,
                                           const chain::CBlockIndex* pindexPrev,
                                           int64_t adjusted_time,
                                           validation::ValidationState& state) const override
    {
        if (bypass_contextual_validation_) {
            // Bypass contextual validation for unit tests
            // This allows tests to create arbitrary header chains without
            // worrying about difficulty adjustments or timestamp constraints
            return true;
        }
        return ChainstateManager::ContextualCheckBlockHeaderWrapper(header, pindexPrev, adjusted_time, state);
    }

private:
    TestChainstateManager(const chain::ChainParams& params, std::unique_ptr<MockTrustBaseManager> tbm)
        : ChainstateManager(params, *tbm)
        , owned_tbm_(std::move(tbm))
        , bypass_pow_validation_(true)
        , bypass_contextual_validation_(true)
    {
        if (params.GetChainType() == chain::ChainType::REGTEST) {
            TestSetSkipPoWChecks(true);
        }
    }

    std::unique_ptr<MockTrustBaseManager> owned_tbm_;
    bool bypass_pow_validation_;
    bool bypass_contextual_validation_;
};

} // namespace test
} // namespace unicity

#endif // UNICITY_TEST_CHAINSTATE_MANAGER_HPP
