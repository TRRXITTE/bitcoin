// Copyright (c) 2014-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <core_io.h>
#include <hash.h>
#include <net.h>
#include <signet.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <validation.h>

#include <string>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(validation_tests, TestingSetup)

static void TestBlockSubsidyPhases(const Consensus::Params& consensusParams)
{
    // Test genesis block
    BOOST_CHECK_EQUAL(GetBlockSubsidy(0, consensusParams), 0);

    // Test phase boundaries
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1, consensusParams), 1000 * COIN);       // Phase 1 start
    BOOST_CHECK_EQUAL(GetBlockSubsidy(10000, consensusParams), 1000 * COIN);     // Phase 1 end
    BOOST_CHECK_EQUAL(GetBlockSubsidy(10001, consensusParams), 100 * COIN);      // Phase 2 start
    BOOST_CHECK_EQUAL(GetBlockSubsidy(179500, consensusParams), 100 * COIN);   // Phase 2 end
    BOOST_CHECK_EQUAL(GetBlockSubsidy(179501, consensusParams), 50 * COIN);    // Phase 3 start
    BOOST_CHECK_EQUAL(GetBlockSubsidy(349000, consensusParams), 50 * COIN);    // Phase 3 end
    BOOST_CHECK_EQUAL(GetBlockSubsidy(349001, consensusParams), 25 * COIN);    // Phase 4 start
    BOOST_CHECK_EQUAL(GetBlockSubsidy(518500, consensusParams), 25 * COIN);    // Phase 4 end
    BOOST_CHECK_EQUAL(GetBlockSubsidy(518501, consensusParams), 15 * COIN);    // Phase 5 start
    BOOST_CHECK_EQUAL(GetBlockSubsidy(688000, consensusParams), 15 * COIN);    // Phase 5 end
    BOOST_CHECK_EQUAL(GetBlockSubsidy(688001, consensusParams), 14 * COIN);    // Phase 6 start
    BOOST_CHECK_EQUAL(GetBlockSubsidy(857500, consensusParams), 14 * COIN);    // Phase 6 end
    BOOST_CHECK_EQUAL(GetBlockSubsidy(857501, consensusParams), 13 * COIN);    // Phase 7 start
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1027000, consensusParams), 13 * COIN);   // Phase 7 end
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1027001, consensusParams), 12 * COIN);   // Phase 8 start
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1196500, consensusParams), 12 * COIN);   // Phase 8 end
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1196501, consensusParams), 11 * COIN);   // Phase 9 start
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1366000, consensusParams), 11 * COIN);   // Phase 9 end
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1366001, consensusParams), 10 * COIN);   // Phase 10 start
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1535500, consensusParams), 10 * COIN);   // Phase 10 end
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1535501, consensusParams), 9 * COIN);    // Phase 11 start
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1705000, consensusParams), 9 * COIN);    // Phase 11 end
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1705001, consensusParams), 8 * COIN);    // Phase 12 start
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1874500, consensusParams), 8 * COIN);    // Phase 12 end
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1874501, consensusParams), 7 * COIN);    // Phase 13 start
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2044000, consensusParams), 7 * COIN);    // Phase 13 end
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2044001, consensusParams), 6 * COIN);    // Phase 14 start
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2213500, consensusParams), 6 * COIN);    // Phase 14 end
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2213501, consensusParams), 5 * COIN);    // Phase 15 start
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2383000, consensusParams), 5 * COIN);    // Phase 15 end
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2383001, consensusParams), 4 * COIN);    // Phase 16 start
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2552500, consensusParams), 4 * COIN);    // Phase 16 end
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2552501, consensusParams), 3 * COIN);    // Phase 17 start
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2722000, consensusParams), 3 * COIN);    // Phase 17 end
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2722001, consensusParams), 2 * COIN);    // Phase 18 start
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2891500, consensusParams), 2 * COIN);    // Phase 18 end
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2891501, consensusParams), 1 * COIN);    // Phase 19 start
    BOOST_CHECK_EQUAL(GetBlockSubsidy(3061000, consensusParams), 1 * COIN);    // Phase 19 end
    BOOST_CHECK_EQUAL(GetBlockSubsidy(3061001, consensusParams), 25 * COIN / 10); // Phase 20 start
    BOOST_CHECK_EQUAL(GetBlockSubsidy(19060400, consensusParams), 25 * COIN / 10); // Phase 20 end
    BOOST_CHECK_EQUAL(GetBlockSubsidy(19060401, consensusParams), 0);          // Post-phases

    // Test mid-phase values
    BOOST_CHECK_EQUAL(GetBlockSubsidy(50, consensusParams), 1000 * COIN);      // Mid-phase 1
    BOOST_CHECK_EQUAL(GetBlockSubsidy(94750, consensusParams), 100 * COIN);    // Mid-phase 2
    BOOST_CHECK_EQUAL(GetBlockSubsidy(264250, consensusParams), 50 * COIN);    // Mid-phase 3
    BOOST_CHECK_EQUAL(GetBlockSubsidy(433750, consensusParams), 25 * COIN);    // Mid-phase 4
    BOOST_CHECK_EQUAL(GetBlockSubsidy(603250, consensusParams), 15 * COIN);    // Mid-phase 5
    BOOST_CHECK_EQUAL(GetBlockSubsidy(772750, consensusParams), 14 * COIN);    // Mid-phase 6
    BOOST_CHECK_EQUAL(GetBlockSubsidy(942250, consensusParams), 13 * COIN);    // Mid-phase 7
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1111750, consensusParams), 12 * COIN);   // Mid-phase 8
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1281250, consensusParams), 11 * COIN);   // Mid-phase 9
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1450750, consensusParams), 10 * COIN);   // Mid-phase 10
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1620250, consensusParams), 9 * COIN);    // Mid-phase 11
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1789750, consensusParams), 8 * COIN);    // Mid-phase 12
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1959250, consensusParams), 7 * COIN);    // Mid-phase 13
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2128750, consensusParams), 6 * COIN);    // Mid-phase 14
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2298250, consensusParams), 5 * COIN);    // Mid-phase 15
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2467750, consensusParams), 4 * COIN);    // Mid-phase 16
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2637250, consensusParams), 3 * COIN);    // Mid-phase 17
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2806750, consensusParams), 2 * COIN);    // Mid-phase 18
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2976250, consensusParams), 1 * COIN);    // Mid-phase 19
    BOOST_CHECK_EQUAL(GetBlockSubsidy(10810700, consensusParams), 25 * COIN / 10); // Mid-phase 20
}

BOOST_AUTO_TEST_CASE(block_subsidy_phases)
{
    const CChainParams& chainparams = Params();
    TestBlockSubsidyPhases(chainparams.GetConsensus());
}

BOOST_AUTO_TEST_CASE(subsidy_limit_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    CAmount nSum = 0;
    for (int nHeight = 0; nHeight <= 19060400; nHeight += 1000) {
        CAmount nSubsidy = GetBlockSubsidy(nHeight, chainParams->GetConsensus());
        BOOST_CHECK(nSubsidy <= 1000 * COIN);
        nSum += nSubsidy * 1000;
        BOOST_CHECK(MoneyRange(nSum));
    }
    BOOST_CHECK_EQUAL(nSum, CAmount{6723860000000000}); // ~67,238,600 coins
}

BOOST_AUTO_TEST_CASE(signet_parse_tests)
{
    ArgsManager signet_argsman;
    signet_argsman.ForceSetArg("-signetchallenge", "51"); // set challenge to OP_TRUE
    const auto signet_params = CreateChainParams(signet_argsman, ChainType::SIGNET);
    CBlock block;
    BOOST_CHECK(signet_params->GetConsensus().signet_challenge == std::vector<uint8_t>{OP_TRUE});
    CScript challenge{OP_TRUE};

    // empty block is invalid
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no witness commitment
    CMutableTransaction cb;
    cb.vout.emplace_back(0, CScript{});
    block.vtx.push_back(MakeTransactionRef(cb));
    block.vtx.push_back(MakeTransactionRef(cb)); // Add dummy tx to exercise merkle root code
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no header is treated valid
    std::vector<uint8_t> witness_commitment_section_141{0xaa, 0x21, 0xa9, 0xed};
    for (int i = 0; i < 32; ++i) {
        witness_commitment_section_141.push_back(0xff);
    }
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no data after header, valid
    std::vector<uint8_t> witness_commitment_section_325{0xec, 0xc7, 0xda, 0xa2};
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // Premature end of data, invalid
    witness_commitment_section_325.push_back(0x01);
    witness_commitment_section_325.push_back(0x51);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // has data, valid
    witness_commitment_section_325.push_back(0x00);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // Extraneous data, invalid
    witness_commitment_section_325.push_back(0x00);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));
}

//! Test retrieval of valid assumeutxo values.
BOOST_AUTO_TEST_CASE(test_assumeutxo)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::REGTEST);

    // These heights don't have assumeutxo configurations associated, per the contents
    // of kernel/chainparams.cpp.
    std::vector<int> bad_heights{0, 100, 111, 115, 209, 211};

    for (auto empty : bad_heights) {
        const auto out = params->AssumeutxoForHeight(empty);
        BOOST_CHECK(!out);
    }

    const auto out110 = *params->AssumeutxoForHeight(110);
    BOOST_CHECK_EQUAL(out110.hash_serialized.ToString(), "6657b736d4fe4db0cbc796789e812d5dba7f5c143764b1b6905612f1830609d1");
    BOOST_CHECK_EQUAL(out110.m_chain_tx_count, 111U);

    const auto out110_2 = *params->AssumeutxoForBlockhash(uint256{"696e92821f65549c7ee134edceeeeaaa4105647a3c4fd9f298c0aec0ab50425c"});
    BOOST_CHECK_EQUAL(out110_2.hash_serialized.ToString(), "6657b736d4fe4db0cbc796789e812d5dba7f5c143764b1b6905612f1830609d1");
    BOOST_CHECK_EQUAL(out110_2.m_chain_tx_count, 111U);
}

BOOST_AUTO_TEST_CASE(block_malleation)
{
    // Test utilities that calls `IsBlockMutated` and then clears the validity
    // cache flags on `CBlock`.
    auto is_mutated = [](CBlock& block, bool check_witness_root) {
        bool mutated{IsBlockMutated(block, check_witness_root)};
        block.fChecked = false;
        block.m_checked_witness_commitment = false;
        block.m_checked_merkle_root = false;
        return mutated;
    };
    auto is_not_mutated = [&is_mutated](CBlock& block, bool check_witness_root) {
        return !is_mutated(block, check_witness_root);
    };

    // Test utilities to create coinbase transactions and insert witness
    // commitments.
    //
    // Note: this will not include the witness stack by default to avoid
    // triggering the "no witnesses allowed for blocks that don't commit to
    // witnesses" rule when testing other malleation vectors.
    auto create_coinbase_tx = [](bool include_witness = false) {
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        if (include_witness) {
            coinbase.vin[0].scriptWitness.stack.resize(1);
            coinbase.vin[0].scriptWitness.stack[0] = std::vector<unsigned char>(32, 0x00);
        }

        coinbase.vout.resize(1);
        coinbase.vout[0].scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT);
        coinbase.vout[0].scriptPubKey[0] = OP_RETURN;
        coinbase.vout[0].scriptPubKey[1] = 0x24;
        coinbase.vout[0].scriptPubKey[2] = 0xaa;
        coinbase.vout[0].scriptPubKey[3] = 0x21;
        coinbase.vout[0].scriptPubKey[4] = 0xa9;
        coinbase.vout[0].scriptPubKey[5] = 0xed;

        auto tx = MakeTransactionRef(coinbase);
        assert(tx->IsCoinBase());
        return tx;
    };
    auto insert_witness_commitment = [](CBlock& block, uint256 commitment) {
        assert(!block.vtx.empty() && block.vtx[0]->IsCoinBase() && !block.vtx[0]->vout.empty());

        CMutableTransaction mtx{*block.vtx[0]};
        CHash256().Write(commitment).Write(std::vector<unsigned char>(32, 0x00)).Finalize(commitment);
        memcpy(&mtx.vout[0].scriptPubKey[6], commitment.begin(), 32);
        block.vtx[0] = MakeTransactionRef(mtx);
    };

    {
        CBlock block;

        // Empty block is expected to have merkle root of 0x0.
        BOOST_CHECK(block.vtx.empty());
        block.hashMerkleRoot = uint256{1};
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        block.hashMerkleRoot = uint256{};
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with a single coinbase tx is mutated if the merkle root is not
        // equal to the coinbase tx's hash.
        block.vtx.push_back(create_coinbase_tx());
        BOOST_CHECK(block.vtx[0]->GetHash() != block.hashMerkleRoot);
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        block.hashMerkleRoot = block.vtx[0]->GetHash();
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with two transactions is mutated if the merkle root does not
        // match the double sha256 of the concatenation of the two transaction
        // hashes.
        block.vtx.push_back(MakeTransactionRef(CMutableTransaction{}));
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        HashWriter hasher;
        hasher.write(block.vtx[0]->GetHash());
        hasher.write(block.vtx[1]->GetHash());
        block.hashMerkleRoot = hasher.GetHash();
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with two transactions is mutated if any node is duplicate.
        {
            block.vtx[1] = block.vtx[0];
            HashWriter hasher;
            hasher.write(block.vtx[0]->GetHash());
            hasher.write(block.vtx[1]->GetHash());
            block.hashMerkleRoot = hasher.GetHash();
            BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        }

        // Blocks with 64-byte coinbase transactions are not considered mutated
        block.vtx.clear();
        {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            mtx.vout.resize(1);
            mtx.vout[0].scriptPubKey.resize(4);
            block.vtx.push_back(MakeTransactionRef(mtx));
            block.hashMerkleRoot = block.vtx.back()->GetHash();
            assert(block.vtx.back()->IsCoinBase());
            assert(GetSerializeSize(TX_NO_WITNESS(block.vtx.back())) == 64);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));
    }

    {
        // Test merkle root malleation

        // Pseudo code to mine transactions tx{1,2,3}:
        //
        // ```
        // loop {
        //   tx1 = random_tx()
        //   tx2 = random_tx()
        //   tx3 = deserialize_tx(txid(tx1) || txid(tx2));
        //   if serialized_size_without_witness(tx3) == 64 {
        //     print(hex(tx3))
        //     break
        //   }
        // }
        // ```
        //
        // The `random_tx` function used to mine the txs below simply created
        // empty transactions with a random version field.
        CMutableTransaction tx1;
        BOOST_CHECK(DecodeHexTx(tx1, "ff204bd0000000000000", /*try_no_witness=*/true, /*try_witness=*/false));
        CMutableTransaction tx2;
        BOOST_CHECK(DecodeHexTx(tx2, "8ae53c92000000000000", /*try_no_witness=*/true, /*try_witness=*/false));
        CMutableTransaction tx3;
        BOOST_CHECK(DecodeHexTx(tx3, "cdaf22d00002c6a7f848f8ae4d30054e61dcf3303d6fe01d282163341f06feecc10032b3160fcab87bdfe3ecfb769206ef2d991b92f8a268e423a6ef4d485f06", /*try_no_witness=*/true, /*try_witness=*/false));
        {
            // Verify that double_sha256(txid1||txid2) == txid3
            HashWriter hasher;
            hasher.write(tx1.GetHash());
            hasher.write(tx2.GetHash());
            assert(hasher.GetHash() == tx3.GetHash());
            // Verify that tx3 is 64 bytes in size (without witness).
            assert(GetSerializeSize(TX_NO_WITNESS(tx3)) == 64);
        }

        CBlock block;
        block.vtx.push_back(MakeTransactionRef(tx1));
        block.vtx.push_back(MakeTransactionRef(tx2));
        uint256 merkle_root = block.hashMerkleRoot = BlockMerkleRoot(block);
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Mutate the block by replacing the two transactions with one 64-byte
        // transaction that serializes into the concatenation of the txids of
        // the transactions in the unmutated block.
        block.vtx.clear();
        block.vtx.push_back(MakeTransactionRef(tx3));
        BOOST_CHECK(!block.vtx.back()->IsCoinBase());
        BOOST_CHECK(BlockMerkleRoot(block) == merkle_root);
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
    }

    {
        CBlock block;
        block.vtx.push_back(create_coinbase_tx(/*include_witness=*/true));
        {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            mtx.vin[0].scriptWitness.stack.resize(1);
            mtx.vin[0].scriptWitness.stack[0] = {0};
            block.vtx.push_back(MakeTransactionRef(mtx));
        }
        block.hashMerkleRoot = BlockMerkleRoot(block);
        // Block with witnesses is considered mutated if the witness commitment
        // is not validated.
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        // Block with invalid witness commitment is considered mutated.
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));

        // Block with valid commitment is not mutated
        {
            auto commitment{BlockWitnessMerkleRoot(block)};
            insert_witness_commitment(block, commitment);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/true));

        // Malleating witnesses should be caught by `IsBlockMutated`.
        {
            CMutableTransaction mtx{*block.vtx[1]};
            assert(!mtx.vin[0].scriptWitness.stack[0].empty());
            ++mtx.vin[0].scriptWitness.stack[0][0];
            block.vtx[1] = MakeTransactionRef(mtx);
        }
        // Without also updating the witness commitment, the merkle root should
        // not change when changing one of the witnesses.
        BOOST_CHECK(block.hashMerkleRoot == BlockMerkleRoot(block));
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));
        {
            auto commitment{BlockWitnessMerkleRoot(block)};
            insert_witness_commitment(block, commitment);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/true));

        // Test malleating the coinbase witness reserved value
        {
            CMutableTransaction mtx{*block.vtx[0]};
            mtx.vin[0].scriptWitness.stack.resize(0);
            block.vtx[0] = MakeTransactionRef(mtx);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));
    }
}

BOOST_AUTO_TEST_SUITE_END()