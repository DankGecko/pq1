// SPDX-License-Identifier: Apache2.0
pragma solidity 0.8.4;

interface IEarnErrors {
    error EarnZeroSTCore(address stCORE);
    error EarnTransferAmountProhibit(address sender);

    // operator related errors
    error EarnZeroOperator(address operator);
    error EarnLockDayMustGreaterThanZero();
    error EarnBalanceThresholdMustGreaterThanZero();
    error EarnMintMinLimitMustGreaterThan1Core();
    error EarnRedeemMinLimitMustGreaterThan1Core();
    error EarnPledgeAgentLimitMustGreaterThan1Core();
    error EarnRedeemCountLimitMustGreaterThanZero();
    error EarnExchangeRateQueryLimitMustGreaterThanZero();
    
    // protocol fee related errors
    error EarnProtocolFeePointMoreThanRateBase(uint256 protocolFeePoint);
    error EarnZeroProtocolFeeReceiver(address protocolFeeReceiver);

    // rebalance related errors
    error EarnReBalanceTransferFailed(address from, address to, uint256 amount);
    error EarnReBalanceInsufficientAmount(address from, uint256 amount, uint256 transferAmount);
    error EarnReBalanceInvalidTransferAmount(address from, uint256 amount, uint256 transferAmount);
    error EarnReBalanceNoNeed(address from, address to);
    error EarnReBalanceAmountDifferenceLessThanThreshold(address from, address to, uint256 fromAmount, uint256 toAmount, uint256 threshold);

    // mint related errors
    error EarnZeroValidator(address validator);
    error EarnMintAmountTooSmall(address account, uint256 amount);
    error EarnCallStCoreMintFailed(address account, uint256 amount, uint256 stCore);

    // redeem related errors
    error EarnSTCoreTooSmall(address account, uint256 stCore);
    error EarnCallStCoreBurnFailed(address account, uint256 amount, uint256 stCore);
    error EarnUnDelegateFailedFinally(address validator, uint256 amount);
    error EarnEmptyValidator();
    error EarnRedeemCountOverLimit(address account, uint256 redeemCount, uint256 limit);

    // withdraw related errors
    error EarnEmptyRedeemRecord();
    error EarnRedeemRecordNotFound(address account);
    error EarnInsufficientBalance(uint256 balance, uint256 amount);

    // after turn round related errors
    error EarnValidatorsAllOffline();
}

interface ISTCoreErrors {
    error STCoreZeroEarn(address earns);
}

