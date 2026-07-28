// SPDX-License-Identifier: Apache2.0
pragma solidity 0.8.4;

struct RedeemRecord {
    // Redeem action time
    uint256 redeemTime;

    // Redeem unlock time
    uint256 unlockTime;

    // Amount of CORE the user recieves
    uint256 amount;

    // Amount of stCORE burnt 
    uint256 stCore;

    // Amount of CORE the protocol recieves
    uint256 protocolFee;
}

// Definition from CandidateHub
struct Candidate {
    address operateAddr;
    address consensusAddr;
    address payable feeAddr;
    uint256 commissionThousandths;
    uint256 margin;
    uint256 status;
    uint256 commissionLastChangeRound;
    uint256 commissionLastRoundValue;
}