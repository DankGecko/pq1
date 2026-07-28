// SPDX-License-Identifier: BUSL-1.1
// SPDX-FileCopyrightText: 2024 Kiln <contact@kiln.fi>
//
// ██╗  ██╗██╗██╗     ███╗   ██╗
// ██║ ██╔╝██║██║     ████╗  ██║
// █████╔╝ ██║██║     ██╔██╗ ██║
// ██╔═██╗ ██║██║     ██║╚██╗██║
// ██║  ██╗██║███████╗██║ ╚████║
// ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═══╝
//
pragma solidity 0.8.22;

import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/// @title Operator
/// @notice The Operator contract is used to store a commission distribution scheme for one or several Splitter instances
/// @notice It stores a list of recipients alongside their respective percentages, and a fee that is taken on each Splitter
/// @notice It then handles the dispatching of the commission between the configured recipient
contract Operator is Ownable2Step {
    /// @notice The fee that is taken on each Splitter
    uint256 public operatorFee;

    /// @notice The maximum fee that can be configured on the Operator
    // solhint-disable-next-line immutable-vars-naming
    uint256 public immutable maximumOperatorFee;

    /// @notice The list of recipients
    address[] public recipients;

    /// @notice The list of percentages for each recipient
    uint256[] public percents;

    /// @notice The name of the operator
    string public name;

    /// @notice The maximum value for a percentage in bps
    uint256 internal constant MAX_BPS = 10000;

    /// @notice Emitted when the recipients are updated
    /// @param recipients The new list of recipients
    /// @param percentsBps The new list of percentages
    event UpdatedRecipients(address[] recipients, uint256[] percentsBps);

    /// @notice Emitted when the operator fee is updated
    /// @param operatorFee The new operator fee
    event UpdatedOperatorFee(uint256 operatorFee);

    /// @notice Emitted when the operator name is updated
    /// @param name The new operator name
    event UpdatedOperatorName(string name);

    /// @notice Emitted when the maximum operator fee is updated
    /// @param maximumOperatorFee The new maximum operator fee
    event UpdatedMaximumOperatorFee(uint256 maximumOperatorFee);

    /// @notice Emitted when the commission is claimed
    /// @param amount The amount that was claimed
    event Claimed(uint256 amount);

    /// @notice Thrown when the provided recipient list is empty
    error NoRecipients();

    /// @notice Thrown when the provided recipient is null
    error ZeroAddress();

    /// @notice Thrown when the provided percent value is zero
    error ZeroPercentBps();

    /// @notice Thrown when the transfer to a recipient fails
    /// @param recipient The recipient that failed to receive the funds
    /// @param errorData The error data returned by the transfer
    error RecipientTransferFailed(address recipient, bytes errorData);

    /// @notice Thrown when the provided recipient list is empty
    error EmptyRecipientArguments();

    /// @notice Thrown when the provided recipient list and percentage list have different lengths
    error InvalidArgumentLengths();

    /// @notice Thrown when the provided percentages do not sum up to 10000
    error InvalidPercentSum();

    /// @notice Thrown when the provided fee is invalid
    /// @param feeBps The provided fee
    error InvalidFeeBps(uint256 feeBps);

    /// @notice Thrown when the provided name is empty
    error InvalidEmptyString();

    /// @notice Thrown when the provided recipients are not sorted
    error InvalidUnsortedRecipients();

    /// @param _owner The owner of the contract
    /// @param _operatorFee The fee that is taken on each Splitter
    /// @param _recipients The list of recipients, sorted in ascending order without duplicates
    /// @param _percents The list of percentages for each recipient
    constructor(
        address _owner,
        string memory _name,
        uint256 _operatorFee,
        uint256 _maximumOperatorFee,
        address[] memory _recipients,
        uint256[] memory _percents
    ) Ownable(_owner) {
        if (_maximumOperatorFee > MAX_BPS) {
            revert InvalidFeeBps(_maximumOperatorFee);
        }
        maximumOperatorFee = _maximumOperatorFee;
        emit UpdatedMaximumOperatorFee(_maximumOperatorFee);

        _setOperatorFee(_operatorFee);
        _setRecipients(_recipients, _percents);
        _setName(_name);
    }

    /// @notice The receive function is used to receive ETH
    receive() external payable {
        // do nothing
    }

    /// @notice The fallback function is used to receive ETH when there is additional calldata
    fallback() external payable {
        // do nothing
    }

    /// @notice Changes the operator fee
    /// @param _operatorFee The new operator fee
    function setOperatorFee(uint256 _operatorFee) external onlyOwner {
        _setOperatorFee(_operatorFee);
    }

    /// @notice Changes the recipients and their respective percentages
    /// @param _recipients The new list of recipients, sorted in ascending order without duplicates
    /// @param _percents The new list of percentages
    function setRecipients(address[] calldata _recipients, uint256[] calldata _percents) external onlyOwner {
        _setRecipients(_recipients, _percents);
    }

    /// @notice Changes the operator name
    /// @param _name The new operator name
    function setName(string calldata _name) external onlyOwner {
        _setName(_name);
    }

    /// @notice Claims the commission for all the recipients
    function claim() external {
        uint256 balance = address(this).balance;
        uint256 totalSent = 0;
        for (uint256 i = 0; i < recipients.length - 1;) {
            uint256 value = Math.mulDiv(balance, percents[i], MAX_BPS);
            (bool success, bytes memory rdata) = recipients[i].call{value: value}("");
            if (!success) {
                revert RecipientTransferFailed(recipients[i], rdata);
            }
            totalSent += value;
            unchecked {
                ++i;
            }
        }
        {
            (bool success, bytes memory rdata) = recipients[recipients.length - 1].call{value: balance - totalSent}("");
            if (!success) {
                revert RecipientTransferFailed(recipients[recipients.length - 1], rdata);
            }
        }
        emit Claimed(balance);
    }

    /// @notice Internal utility function to set the operator fee
    /// @param _operatorFee The new operator fee
    function _setOperatorFee(uint256 _operatorFee) internal {
        if (_operatorFee > maximumOperatorFee) {
            revert InvalidFeeBps(_operatorFee);
        }
        operatorFee = _operatorFee;
        emit UpdatedOperatorFee(_operatorFee);
    }

    /// @notice Internal utility function to set the recipients and their respective percentages
    /// @param _recipients The new list of recipients, sorted in ascending order without duplicates
    /// @param _percentsBps The new list of percentages
    function _setRecipients(address[] memory _recipients, uint256[] memory _percentsBps) internal {
        uint256 recipientsLength = _recipients.length;
        if (recipientsLength == 0) {
            revert EmptyRecipientArguments();
        }
        if (recipientsLength != _percentsBps.length) {
            revert InvalidArgumentLengths();
        }
        uint256 totalPercentsBps = 0;
        for (uint256 i = 0; i < recipientsLength; ++i) {
            totalPercentsBps += _percentsBps[i];
            if (i > 0 && uint160(_recipients[i]) <= uint160(_recipients[i - 1])) {
                revert InvalidUnsortedRecipients();
            }
            if (_recipients[i] == address(0)) {
                revert ZeroAddress();
            }
            if (_percentsBps[i] == 0) {
                revert ZeroPercentBps();
            }
        }
        if (totalPercentsBps != MAX_BPS) {
            revert InvalidPercentSum();
        }
        recipients = _recipients;
        percents = _percentsBps;
        emit UpdatedRecipients(_recipients, _percentsBps);
    }

    /// @notice Internal utility function to set the operator name
    /// @param _name The new operator name
    function _setName(string memory _name) internal {
        if (bytes(_name).length == 0) {
            revert InvalidEmptyString();
        }
        name = _name;
        emit UpdatedOperatorName(_name);
    }
}
