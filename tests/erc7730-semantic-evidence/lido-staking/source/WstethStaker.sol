// SPDX-FileCopyrightText: 2025 Lido <info@lido.fi>
// SPDX-License-Identifier: GPL-3.0

// See contracts/COMPILERS.md
pragma solidity 0.8.25;

import {Math} from "@openzeppelin/contracts-v5.2/utils/math/Math.sol";

import {IERC20} from "@openzeppelin/contracts-v5.2/token/ERC20/IERC20.sol";

interface IWstETH is IERC20 {
    function wrap(uint256) external returns (uint256);

    function stETH() external view returns (address);
}

interface IStETH is IERC20 {
    function submit(address _referral) external payable returns (uint256);

    function getTotalShares() external view returns (uint256);

    function getTotalPooledEther() external view returns (uint256);
}

contract WstETHReferralStaker {
    IWstETH public immutable wstETH;
    IStETH public immutable stETH;

    /// @notice error on direct eth transfers to contract
    error EthTransferNotAllowed();

    constructor(IWstETH _wstETH) {
        wstETH = _wstETH;
        stETH = IStETH(wstETH.stETH());
        stETH.approve(address(wstETH), type(uint256).max);
    }

    /**
     * @notice stakes ETH directly into wstETH with stETH referral
     * @param _referral The address used for the stETH referral program, can be zero address
     * @return amount of wstETH received
     */
    function stakeETH(address _referral) external payable returns (uint256) {
        // 1. stake ETH and receive stETH
        // referral event and 0 values check inside
        uint256 stethAmount = _getPooledEthBySharesRoundUp(stETH.submit{value: msg.value}(_referral));

        // 2. wrap stETH to wstETH
        // unlimited approval is set in constructor, 0 wstETH check inside
        // stethAmount can be > stETH.balanceOf(this) due to rounding up in _getPooledEthBySharesRoundUp
        // but this ensures correct amount of stETH shares are wrapped to wstETH
        uint256 wstETHAmount = wstETH.wrap(stethAmount);

        // 3. transfer wstETH to the caller
        wstETH.transfer(msg.sender, wstETHAmount);

        // 4. return the amount of wstETH
        return wstETHAmount;
    }

    /**
     * @notice fallback function to prevent sending ETH directly
     */
    receive() external payable {
        revert EthTransferNotAllowed();
    }

    /**
     * @notice Get the amount of pooled ETH for a given amount of stETH shares rounded up
     * @param _sharesAmount The amount of stETH shares to convert
     */
    function _getPooledEthBySharesRoundUp(uint256 _sharesAmount) internal view returns (uint256) {
        uint256 numeratorInEther = stETH.getTotalPooledEther();
        uint256 denominatorInShares = stETH.getTotalShares();

        return Math.ceilDiv(_sharesAmount * numeratorInEther, denominatorInShares);
    }
}
