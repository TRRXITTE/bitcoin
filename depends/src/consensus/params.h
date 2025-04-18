// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <uint256.h>

#include <chrono>
#include <limits>
#include <map>
#include <vector>

namespace Consensus {


enum BuriedDeployment : int16_t {
    DEPLOYMENT_HEIGHTINCB = std::numeric_limits<int16_t>::min(),
    DEPLOYMENT_CLTV,
    DEPLOYMENT_DERSIG,
    DEPLOYMENT_CSV,
    DEPLOYMENT_SEGWIT,
};
constexpr bool ValidDeployment(BuriedDeployment dep) { return dep <= DEPLOYMENT_SEGWIT; }

enum DeploymentPos : uint16_t {
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_TAPROOT,
    MAX_VERSION_BITS_DEPLOYMENTS
};
constexpr bool ValidDeployment(DeploymentPos dep) { return dep < MAX_VERSION_BITS_DEPLOYMENTS; }

struct BIP9Deployment {
    int bit{28};
    int64_t nStartTime{NEVER_ACTIVE};
    int64_t nTimeout{NEVER_ACTIVE};
    int min_activation_height{0};

    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();
    static constexpr int64_t ALWAYS_ACTIVE = -1;
    static constexpr int64_t NEVER_ACTIVE = -2;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    std::map<uint256, uint32_t> script_flag_exceptions;
    int BIP34Height;
    uint256 BIP34Hash;
    int BIP65Height;
    int BIP66Height;
    int CSVHeight;
    int SegwitHeight;
    int MinBIP9WarningHeight;
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool enforce_BIP94;
    bool fPowNoRetargeting;
    int64_t nPowTargetTimespan;

    /**
     * Target block spacing, varying by height:
     * - 10 seconds for blocks <= 100,000
     * - 60 seconds for blocks > 100,000
     */
     int64_t GetPowTargetSpacing(int nHeight) const {
        return (nHeight <= 100000) ? 10 : 60;
    }

    std::chrono::seconds PowTargetSpacing(int nHeight) const {
        return std::chrono::seconds{GetPowTargetSpacing(nHeight)};
    }

    int64_t DifficultyAdjustmentInterval(int nHeight) const {
        return nPowTargetTimespan / GetPowTargetSpacing(nHeight);
    }

    uint256 nMinimumChainWork;
    uint256 defaultAssumeValid;

    bool signet_blocks{false};
    std::vector<uint8_t> signet_challenge;

    int DeploymentHeight(BuriedDeployment dep) const {
        switch (dep) {
        case DEPLOYMENT_HEIGHTINCB:
            return BIP34Height;
        case DEPLOYMENT_CLTV:
            return BIP65Height;
        case DEPLOYMENT_DERSIG:
            return BIP66Height;
        case DEPLOYMENT_CSV:
            return CSVHeight;
        case DEPLOYMENT_SEGWIT:
            return SegwitHeight;
        }
        return std::numeric_limits<int>::max();
    }
};

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H