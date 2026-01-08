// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license
// Multi-node scenario tests for chain reorganization
//
// NOTE: These tests use multiple independent TestChainstateManager instances
// to simulate multi-node scenarios, but they do NOT test the P2P layer.
// All communication is done via direct API calls (AcceptBlockHeader).
// For true P2P integration tests, see test/network/

#include "catch_amalgamated.hpp"
#include "chain/validation.hpp"
#include "common/test_chainstate_manager.hpp"
#include "chain/chainstate_manager.hpp"
#include "chain/chainparams.hpp"
#include "chain/chain.hpp"
#include "chain/block_index.hpp"
#include "chain/block.hpp"
#include "util/time.hpp"
#include <memory>
#include <vector>
#include <map>

using namespace unicity;
using namespace unicity::test;
using namespace unicity::chain;
using unicity::validation::ValidationState;

// Helper: Simple node that mines and syncs headers
class TestNode {
public:
    int node_id;
    std::shared_ptr<ChainParams> params;  // Each node owns its params
    std::unique_ptr<TestChainstateManager> chainstate;

    explicit TestNode(int id, int suspicious_reorg_depth = 100)
        : node_id(id)
        , params(ChainParams::CreateRegTest())
    {
        if (suspicious_reorg_depth != 100) {
            params->SetSuspiciousReorgDepth(suspicious_reorg_depth);
        }
        chainstate = std::make_unique<TestChainstateManager>(*params);
        chainstate->Initialize(params->GenesisBlock());
    }

    // Mine a block on this node's chain
    uint256 MineBlock() {
        const auto* tip = chainstate->GetTip();
        uint256 prev_hash = tip ? tip->GetBlockHash() : params->GenesisBlock().GetHash();

        CBlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock = prev_hash;
        header.minerAddress.SetNull();
        header.nTime = util::GetTime() + (node_id * 1000); // Offset by node_id to ensure unique hashes
        header.nBits = 0x207fffff;
        header.nNonce = node_id + (tip ? tip->nHeight : 0);
        header.hashRandomX.SetNull();

        ValidationState state;
        auto pindex = chainstate->AcceptBlockHeader(header, state);
        if (pindex) {
            chainstate->TryAddBlockIndexCandidate(pindex);
            chainstate->ActivateBestChain();
            return header.GetHash();
        }
        return uint256();
    }

    // Send a header to another node (simulates P2P)
    bool SendHeaderTo(TestNode& other, const uint256& hash) {
        auto pindex = chainstate->LookupBlockIndex(hash);
        if (!pindex) return false;

        CBlockHeader header = pindex->GetBlockHeader();
        ValidationState state;
        auto other_pindex = other.chainstate->AcceptBlockHeader(header, state);
        if (other_pindex) {
            other.chainstate->TryAddBlockIndexCandidate(other_pindex);
            return true;
        }
        return false;
    }

    // Send all headers from this node to another (simulates initial sync)
    bool SyncTo(TestNode& other) {
        const auto* tip = chainstate->GetTip();
        if (!tip) return false;

        // Walk backwards from tip to genesis, collecting headers
        std::vector<const CBlockIndex*> headers;
        const CBlockIndex* pindex = tip;
        while (pindex && pindex->nHeight > 0) {
            headers.push_back(pindex);
            pindex = pindex->pprev;
        }

        // Send in forward order (genesis to tip)
        for (auto it = headers.rbegin(); it != headers.rend(); ++it) {
            CBlockHeader header = (*it)->GetBlockHeader();
            ValidationState state;
            auto other_pindex = other.chainstate->AcceptBlockHeader(header, state);
            if (other_pindex) {
                other.chainstate->TryAddBlockIndexCandidate(other_pindex);
            }
        }

        other.chainstate->ActivateBestChain();
        return true;
    }

    int GetHeight() const {
        const auto* tip = chainstate->GetTip();
        return tip ? tip->nHeight : 0;
    }

    uint256 GetTipHash() const {
        const auto* tip = chainstate->GetTip();
        return tip ? tip->GetBlockHash() : params->GenesisBlock().GetHash();
    }
};

TEST_CASE("Reorg Multi-Node - Two miners split network", "[reorg][multi_node]") {
    // Scenario: Two miners find blocks simultaneously, network splits
    // Alice: Genesis -> A1 -> A2 -> A3
    // Bob:   Genesis -> B1 -> B2 -> B3 -> B4
    // Then they sync: Bob's chain wins (more work)

    TestNode alice(1);
    TestNode bob(2);

    // Alice mines 3 blocks
    alice.MineBlock();
    alice.MineBlock();
    alice.MineBlock();
    REQUIRE(alice.GetHeight() == 3);

    // Bob mines 4 blocks (doesn't know about Alice)
    bob.MineBlock();
    bob.MineBlock();
    bob.MineBlock();
    bob.MineBlock();
    REQUIRE(bob.GetHeight() == 4);

    // Verify they're on different chains
    REQUIRE(alice.GetTipHash() != bob.GetTipHash());

    // Now they sync: Alice receives Bob's chain
    uint256 alice_old_tip = alice.GetTipHash();
    bob.SyncTo(alice);

    // Alice should reorg to Bob's chain (4 blocks > 3 blocks)
    REQUIRE(alice.GetHeight() == 4);
    REQUIRE(alice.GetTipHash() == bob.GetTipHash());
    REQUIRE(alice.GetTipHash() != alice_old_tip);
}

TEST_CASE("Reorg Multi-Node - Three nodes network partition", "[reorg][multi_node]") {
    // Scenario: 3 nodes, network partitions into 2 groups
    // Group A: Alice, Bob mine together
    // Group B: Charlie mines alone
    // Charlie mines faster, network heals, everyone reorgs to Charlie

    TestNode alice(1);
    TestNode bob(2);
    TestNode charlie(3);

    // Group A: Alice and Bob collaborate, mine 3 blocks
    for (int i = 0; i < 3; i++) {
        uint256 hash = alice.MineBlock();
        alice.SendHeaderTo(bob, hash);
        bob.chainstate->ActivateBestChain();
    }
    REQUIRE(alice.GetHeight() == 3);
    REQUIRE(bob.GetHeight() == 3);
    REQUIRE(alice.GetTipHash() == bob.GetTipHash());

    // Group B: Charlie mines 5 blocks alone
    for (int i = 0; i < 5; i++) {
        charlie.MineBlock();
    }
    REQUIRE(charlie.GetHeight() == 5);

    // Verify different chains
    REQUIRE(alice.GetTipHash() != charlie.GetTipHash());

    // Network heals: Charlie syncs to Alice and Bob
    uint256 alice_old_tip = alice.GetTipHash();
    uint256 bob_old_tip = bob.GetTipHash();

    charlie.SyncTo(alice);
    charlie.SyncTo(bob);

    // Everyone should be on Charlie's chain (5 > 3)
    REQUIRE(alice.GetHeight() == 5);
    REQUIRE(bob.GetHeight() == 5);
    REQUIRE(charlie.GetHeight() == 5);
    REQUIRE(alice.GetTipHash() == charlie.GetTipHash());
    REQUIRE(bob.GetTipHash() == charlie.GetTipHash());
    REQUIRE(alice.GetTipHash() != alice_old_tip);
    REQUIRE(bob.GetTipHash() != bob_old_tip);
}

TEST_CASE("Reorg Multi-Node - Selfish mining attempt", "[reorg][multi_node]") {
    // Scenario: Attacker tries selfish mining
    // Honest nodes: Genesis -> H1 -> H2 -> H3 -> H4 -> H5
    // Attacker: Genesis -> A1 -> A2 -> A3 (withheld)
    // Attacker reveals chain, but honest chain is longer (honest wins)

    TestNode honest1(1);
    TestNode honest2(2);
    TestNode attacker(3);

    // Honest nodes mine 5 blocks together
    for (int i = 0; i < 5; i++) {
        uint256 hash = honest1.MineBlock();
        honest1.SendHeaderTo(honest2, hash);
        honest2.chainstate->ActivateBestChain();
    }
    REQUIRE(honest1.GetHeight() == 5);
    REQUIRE(honest2.GetHeight() == 5);

    // Attacker mines 3 blocks in secret
    for (int i = 0; i < 3; i++) {
        attacker.MineBlock();
    }
    REQUIRE(attacker.GetHeight() == 3);

    // Attacker reveals their chain to honest nodes
    attacker.SyncTo(honest1);
    attacker.SyncTo(honest2);

    // Honest chain should win (5 > 3)
    REQUIRE(honest1.GetHeight() == 5);
    REQUIRE(honest2.GetHeight() == 5);

    // Now attacker syncs honest chain (realizes they lost)
    honest1.SyncTo(attacker);

    // Attacker should accept defeat and reorg to honest chain
    REQUIRE(attacker.GetHeight() == 5);
    REQUIRE(attacker.GetTipHash() == honest1.GetTipHash());
}

TEST_CASE("Reorg Multi-Node - Deep reorg rejected", "[reorg][multi_node]") {
    // Scenario: Test suspicious_reorg_depth protection
    // Node1: Genesis -> [7 blocks]
    // Node2: Genesis -> [8 blocks]
    // Node1 has suspicious_reorg_depth=7, should reject Node2's chain

    TestNode node1(1, 7);  // suspicious_reorg_depth=7
    TestNode node2(2);

    // Node1 mines 7 blocks
    for (int i = 0; i < 7; i++) {
        node1.MineBlock();
    }
    REQUIRE(node1.GetHeight() == 7);
    uint256 node1_tip = node1.GetTipHash();

    // Node2 mines 8 blocks (different chain)
    for (int i = 0; i < 8; i++) {
        node2.MineBlock();
    }
    REQUIRE(node2.GetHeight() == 8);

    // Node2 tries to sync to Node1
    node2.SyncTo(node1);

    // Node1 should REJECT the reorg (depth 7 >= suspicious_reorg_depth=7)
    REQUIRE(node1.GetHeight() == 7);
    REQUIRE(node1.GetTipHash() == node1_tip); // Still on original chain
}

TEST_CASE("Reorg Multi-Node - Longest chain always wins", "[reorg][multi_node]") {
    // Scenario: 5 nodes, each mines different length chains
    // Node1: 2 blocks
    // Node2: 3 blocks
    // Node3: 5 blocks  <- Winner
    // Node4: 4 blocks
    // Node5: 1 block
    // After full sync, everyone converges to Node3's 5-block chain

    std::vector<std::unique_ptr<TestNode>> nodes;
    std::vector<int> block_counts = {2, 3, 5, 4, 1};

    // Create nodes and mine different amounts
    for (int i = 0; i < 5; i++) {
        nodes.push_back(std::make_unique<TestNode>(i + 1));
        for (int j = 0; j < block_counts[i]; j++) {
            nodes[i]->MineBlock();
        }
        REQUIRE(nodes[i]->GetHeight() == block_counts[i]);
    }

    // Verify all on different chains
    for (size_t i = 0; i < nodes.size() - 1; i++) {
        REQUIRE(nodes[i]->GetTipHash() != nodes[i+1]->GetTipHash());
    }

    // Full mesh sync: everyone syncs with everyone
    for (size_t i = 0; i < nodes.size(); i++) {
        for (size_t j = 0; j < nodes.size(); j++) {
            if (i != j) {
                nodes[i]->SyncTo(*nodes[j]);
            }
        }
    }

    // Everyone should converge to node3's chain (5 blocks)
    uint256 winner_hash = nodes[2]->GetTipHash();
    for (const auto& node : nodes) {
        REQUIRE(node->GetHeight() == 5);
        REQUIRE(node->GetTipHash() == winner_hash);
    }
}

TEST_CASE("Reorg Multi-Node - Stale block handling", "[reorg][multi_node]") {
    // Scenario: Node receives blocks out of order, then reorgs correctly
    // Main chain: Genesis -> A -> B -> C
    // Side chain: Genesis -> X -> Y -> Z -> W (longer, but received later)

    TestNode miner(1);
    TestNode receiver(2);

    // Miner builds main chain: Genesis -> A -> B -> C
    std::vector<uint256> main_chain;
    for (int i = 0; i < 3; i++) {
        main_chain.push_back(miner.MineBlock());
    }

    // Send main chain to receiver
    for (const auto& hash : main_chain) {
        miner.SendHeaderTo(receiver, hash);
    }
    receiver.chainstate->ActivateBestChain();
    REQUIRE(receiver.GetHeight() == 3);
    uint256 old_tip = receiver.GetTipHash();

    // Miner creates longer side chain from genesis
    TestNode side_miner(3);
    for (int i = 0; i < 4; i++) {
        side_miner.MineBlock();
    }
    REQUIRE(side_miner.GetHeight() == 4);

    // Side chain syncs to receiver (should trigger reorg)
    side_miner.SyncTo(receiver);

    // Receiver should reorg to longer chain
    REQUIRE(receiver.GetHeight() == 4);
    REQUIRE(receiver.GetTipHash() == side_miner.GetTipHash());
    REQUIRE(receiver.GetTipHash() != old_tip);
}

TEST_CASE("Reorg Multi-Node - Equal work no reorg", "[reorg][multi_node]") {
    // Scenario: Two chains with equal work, first-seen wins
    // Alice: Genesis -> A -> B
    // Bob:   Genesis -> X -> Y (equal work, but received later)
    // Alice should stay on her chain (first-seen rule)

    TestNode alice(1);
    TestNode bob(2);

    // Alice mines 2 blocks
    alice.MineBlock();
    alice.MineBlock();
    REQUIRE(alice.GetHeight() == 2);
    uint256 alice_tip = alice.GetTipHash();

    // Bob mines 2 blocks (different chain, equal work)
    bob.MineBlock();
    bob.MineBlock();
    REQUIRE(bob.GetHeight() == 2);

    // Bob syncs to Alice (should NOT reorg - equal work)
    bob.SyncTo(alice);

    // Alice should stay on original chain
    REQUIRE(alice.GetHeight() == 2);
    REQUIRE(alice.GetTipHash() == alice_tip);
}

TEST_CASE("Reorg Multi-Node - Multiple reorgs in sequence", "[reorg][multi_node]") {
    // Scenario: Node experiences multiple reorgs as better chains arrive
    // Start: Genesis -> A
    // Reorg 1: Genesis -> B -> C (2 > 1)
    // Reorg 2: Genesis -> X -> Y -> Z (3 > 2)
    // Reorg 3: Genesis -> P -> Q -> R -> S (4 > 3)

    TestNode node(1);

    // Start with 1 block
    node.MineBlock();
    REQUIRE(node.GetHeight() == 1);

    // Reorg 1: Receive 2-block chain
    TestNode miner2(2);
    miner2.MineBlock();
    miner2.MineBlock();
    miner2.SyncTo(node);
    REQUIRE(node.GetHeight() == 2);
    uint256 tip_after_reorg1 = node.GetTipHash();

    // Reorg 2: Receive 3-block chain
    TestNode miner3(3);
    miner3.MineBlock();
    miner3.MineBlock();
    miner3.MineBlock();
    miner3.SyncTo(node);
    REQUIRE(node.GetHeight() == 3);
    REQUIRE(node.GetTipHash() != tip_after_reorg1);
    uint256 tip_after_reorg2 = node.GetTipHash();

    // Reorg 3: Receive 4-block chain
    TestNode miner4(4);
    miner4.MineBlock();
    miner4.MineBlock();
    miner4.MineBlock();
    miner4.MineBlock();
    miner4.SyncTo(node);
    REQUIRE(node.GetHeight() == 4);
    REQUIRE(node.GetTipHash() != tip_after_reorg2);
}
